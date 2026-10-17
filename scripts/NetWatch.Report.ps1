# NetWatch.Report.ps1 - 自动分析：读取原始数据 -> 生成结论报告（Markdown / HTML / JSON）
# 原则：只陈述数据支持的事实，区分"被支持 / 被否定 / 仍未知"

# ============================================================ 数据读取

function Parse-Ts {
    param([string]$Text)
    if (-not $Text) { return $null }
    try { return [datetime]::ParseExact($Text, 'yyyy-MM-dd HH:mm:ss.fff', $null) } catch { }
    try { return [datetime]::Parse($Text) } catch { }
    return $null
}

function Get-CsvSafe {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    try { return @(Import-Csv -LiteralPath $Path -Encoding UTF8) } catch { return @() }
}

function Get-JsonlSafe {
    param([string]$Path)
    $out = New-Object System.Collections.ArrayList
    if (-not (Test-Path -LiteralPath $Path)) { return $out }
    try {
        Get-Content -LiteralPath $Path -Encoding UTF8 | ForEach-Object {
            if (-not $_) { return }
            try { [void]$out.Add(($_ | ConvertFrom-Json)) } catch { }
        }
    } catch { }
    return $out
}

function Import-NetWatchData {
    param([Parameter(Mandatory = $true)][string]$SessionDir)
    $d = [pscustomobject]@{
        Dir       = $SessionDir
        Session   = $null
        Markers   = @()
        Icmp      = @()
        Wifi      = @()
        Neighbors = @()
        Sys       = @()
        Proc      = @()
        Dns       = @()
        L7        = @()
        Proxy     = @()
        Events    = @()
    }
    $sj = Join-Path $SessionDir 'session.json'
    if (Test-Path -LiteralPath $sj) {
        try { $d.Session = Get-Content -LiteralPath $sj -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
    }
    $d.Markers = Get-CsvSafe (Join-Path $SessionDir 'markers.csv')
    $d.Icmp = Get-CsvSafe (Join-Path $SessionDir 'latency_icmp.csv')
    $d.Wifi = Get-CsvSafe (Join-Path $SessionDir 'wifi.csv')
    $d.Neighbors = Get-CsvSafe (Join-Path $SessionDir 'neighbors.csv')
    $d.Sys = Get-CsvSafe (Join-Path $SessionDir 'sys.csv')
    $d.Proc = Get-CsvSafe (Join-Path $SessionDir 'proc.csv')
    $d.Dns = Get-CsvSafe (Join-Path $SessionDir 'dns.csv')
    $d.L7 = Get-CsvSafe (Join-Path $SessionDir 'l7.csv')
    $d.Proxy = Get-CsvSafe (Join-Path $SessionDir 'proxy.csv')
    $d.Events = Get-JsonlSafe (Join-Path $SessionDir 'events.jsonl')
    return $d
}

# ============================================================ 统计

function Get-TargetStats {
    param($IcmpRows)
    $byTarget = @{}
    foreach ($r in $IcmpRows) {
        $t = [string]$r.target
        if (-not $byTarget.ContainsKey($t)) { $byTarget[$t] = New-Object System.Collections.ArrayList }
        [void]$byTarget[$t].Add($r)
    }
    $out = New-Object System.Collections.ArrayList
    foreach ($t in $byTarget.Keys) {
        $rows = $byTarget[$t]
        $rtts = New-Object System.Collections.ArrayList
        $lost = 0
        foreach ($r in $rows) {
            if ([string]$r.status -eq 'Success' -and $r.rtt_ms -ne '') {
                [void]$rtts.Add([double]$r.rtt_ms)
            } else { $lost++ }
        }
        $arr = @($rtts | ForEach-Object { [double]$_ })
        $med = Get-Median -Values $arr
        $p99 = Get-Percentile -Values $arr -P 99
        $thr = $null
        if ($null -ne $p99 -and $null -ne $med) { $thr = [math]::Max($p99, $med * 2.5) }
        [void]$out.Add([pscustomobject]@{
            Target  = $t
            Host    = $(if ($rows.Count) { [string]$rows[0].host } else { '' })
            Layer   = $(if ($rows.Count) { [string]$rows[0].layer } else { '' })
            Samples = $rows.Count
            Lost    = $lost
            LossPct = $(if ($rows.Count) { [math]::Round(100.0 * $lost / $rows.Count, 2) } else { 0 })
            Min     = $(if ($arr.Count) { ($arr | Measure-Object -Minimum).Minimum } else { $null })
            P50     = $med
            P95     = Get-Percentile -Values $arr -P 95
            P99     = $p99
            Max     = $(if ($arr.Count) { ($arr | Measure-Object -Maximum).Maximum } else { $null })
            Avg     = $(if ($arr.Count) { [math]::Round(($arr | Measure-Object -Average).Average, 1) } else { $null })
            Jitter  = $(if ($arr.Count -gt 1) { Get-Jitter $arr } else { $null })
            Threshold = $thr
            Rows    = $rows
        })
    }
    return @($out | Sort-Object Layer, Target)
}

function Find-AnomalyWindows {
    param($Stats, [int]$MergeGapSec = 15, [int]$MaxWindows = 12)

    $bad = New-Object System.Collections.ArrayList
    foreach ($s in $Stats) {
        $thr = $s.Threshold
        # 有些目标（IPv6 DNS、被 ICMP 限速的公网站）本来就长期丢几个包。
        # 对这类目标，单次丢包不算异常，只有连续 >=3 次丢包才算突发。
        $chronicLoss = ($s.LossPct -ge 3.0)
        $run = 0
        foreach ($r in $s.Rows) {
            $t = Parse-Ts $r.ts
            if ($null -eq $t) { continue }
            $isBad = $false
            $reason = ''
            if ([string]$r.status -ne 'Success') {
                $run++
                if (-not $chronicLoss -or $run -ge 3) { $isBad = $true; $reason = 'loss' }
            } else {
                $run = 0
                if ($r.rtt_ms -ne '' -and $null -ne $thr -and [double]$r.rtt_ms -ge [double]$thr) {
                    # 再加一个绝对下限，避免把 "3ms -> 12ms" 这种纯抖动当成异常
                    $floor = 25.0
                    if ($null -ne $s.P50) { $floor = [double]$s.P50 + 25.0 }
                    if ([double]$r.rtt_ms -ge $floor) { $isBad = $true; $reason = 'spike' }
                }
            }
            if ($isBad) {
                [void]$bad.Add([pscustomobject]@{ t = $t; target = $s.Target; layer = $s.Layer; rtt = $r.rtt_ms; status = $r.status; reason = $reason })
            }
        }
    }
    if ($bad.Count -eq 0) { return @() }
    $sorted = @($bad | Sort-Object t)

    $windows = New-Object System.Collections.ArrayList
    $cur = $null
    foreach ($b in $sorted) {
        if ($null -eq $cur) {
            $cur = [pscustomobject]@{
                start = $b.t; end = $b.t; targets = @{}; layers = @{}
                maxRtt = 0.0; losses = 0; samples = 0; spike = 0
            }
            $cur.targets[$b.target] = $true
            $cur.layers[$b.layer] = $true
            $cur.samples++
            if ($b.status -ne 'Success') { $cur.losses++ } else { $cur.spike++; if ($b.rtt -ne '' -and [double]$b.rtt -gt $cur.maxRtt) { $cur.maxRtt = [double]$b.rtt } }
            continue
        }
        if (($b.t - $cur.end).TotalSeconds -le $MergeGapSec) {
            $cur.end = $b.t
            $cur.targets[$b.target] = $true
            $cur.layers[$b.layer] = $true
            $cur.samples++
            if ($b.status -ne 'Success') { $cur.losses++ } else { $cur.spike++; if ($b.rtt -ne '' -and [double]$b.rtt -gt $cur.maxRtt) { $cur.maxRtt = [double]$b.rtt } }
        } else {
            [void]$windows.Add($cur)
            $cur = [pscustomobject]@{
                start = $b.t; end = $b.t; targets = @{}; layers = @{}
                maxRtt = 0.0; losses = 0; samples = 0; spike = 0
            }
            $cur.targets[$b.target] = $true
            $cur.layers[$b.layer] = $true
            $cur.samples++
            if ($b.status -ne 'Success') { $cur.losses++ } else { $cur.spike++; if ($b.rtt -ne '' -and [double]$b.rtt -gt $cur.maxRtt) { $cur.maxRtt = [double]$b.rtt } }
        }
    }
    if ($null -ne $cur) { [void]$windows.Add($cur) }

    # 只保留"确实有丢包"或"至少 3 个坏样本"的窗口，避免单点抖动把报告刷满
    $windows = @($windows | Where-Object { $_.losses -ge 1 -or $_.samples -ge 3 })
    if ($windows.Count -eq 0) { return @() }

    $ranked = @($windows | Sort-Object -Property @{Expression = { ($_.end - $_.start).TotalSeconds }; Descending = $true } | Select-Object -First $MaxWindows)
    return $ranked
}

function Get-RowsInWindow {
    param($Rows, [datetime]$From, [datetime]$To, [string]$TsField = 'ts')
    $out = New-Object System.Collections.ArrayList
    foreach ($r in $Rows) {
        $t = Parse-Ts ([string]$r.$TsField)
        if ($null -eq $t) { continue }
        if ($t -ge $From -and $t -le $To) { [void]$out.Add($r) }
    }
    return $out
}

function Get-NumSafe {
    param($Value)
    if ($null -eq $Value -or $Value -eq '') { return $null }
    $d = 0.0
    if ([double]::TryParse([string]$Value, [ref]$d)) { return $d }
    return $null
}

function Test-RealMac {
    # 全零 MAC = ARP 未解析（链路丢包时的正常现象），不是"MAC 变了"，更不是 ARP 欺骗
    param([string]$Mac)
    if (-not $Mac) { return $false }
    $m = $Mac.Trim()
    if ($m -eq '') { return $false }
    if ($m -match '^(00[-:]){5}00$') { return $false }
    if ($m -match '^0{12}$') { return $false }
    return $true
}

# ============================================================ 图表（内联 SVG，无外部依赖）

function New-SvgChart {
    param(
        [string]$Title,
        $Series,                # @( @{ name; color; points = @( ,@(xSec,yVal) ) } )
        [int]$Width = 1120,
        [int]$Height = 240,
        [string]$Unit = '',
        [double]$XMax = 0,
        [double]$YMin = $null,
        [double]$YMax = $null,
        $Bands = @()            # @( @{ from; to; color } )  单位秒
    )
    $padL = 62; $padR = 16; $padT = 26; $padB = 26
    $plotW = $Width - $padL - $padR
    $plotH = $Height - $padT - $padB

    if ($XMax -le 0) {
        foreach ($s in $Series) { foreach ($p in $s.points) { if ($p[0] -gt $XMax) { $XMax = $p[0] } } }
        if ($XMax -le 0) { $XMax = 1 }
    }
    $vals = New-Object System.Collections.ArrayList
    foreach ($s in $Series) { foreach ($p in $s.points) { if ($null -ne $p[1]) { [void]$vals.Add([double]$p[1]) } } }
    if ($YMin -eq $null) { if ($vals.Count) { $YMin = ($vals | Measure-Object -Minimum).Minimum } else { $YMin = 0 } }
    if ($YMax -eq $null) { if ($vals.Count) { $YMax = ($vals | Measure-Object -Maximum).Maximum } else { $YMax = 1 } }
    if ($YMax -le $YMin) { $YMax = $YMin + 1 }
    $pad = ($YMax - $YMin) * 0.08
    $YMin = $YMin - $pad; $YMax = $YMax + $pad

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<svg xmlns="http://www.w3.org/2000/svg" width="' + $Width + '" height="' + $Height + '" viewBox="0 0 ' + $Width + ' ' + $Height + '" font-family="Segoe UI,Microsoft YaHei,sans-serif" font-size="11">')
    [void]$sb.Append('<rect x="0" y="0" width="' + $Width + '" height="' + $Height + '" fill="#fbfbfd"/>')
    [void]$sb.Append('<text x="' + $padL + '" y="16" font-size="13" font-weight="600" fill="#222">' + (HtmlEnc $Title) + '</text>')

    # 背景带
    foreach ($b in $Bands) {
        $x1 = $padL + ($b.from / $XMax) * $plotW
        $x2 = $padL + ($b.to / $XMax) * $plotW
        if ($x2 -lt $x1) { $x2 = $x1 + 1 }
        [void]$sb.Append('<rect x="' + ([math]::Round($x1, 1)) + '" y="' + $padT + '" width="' + ([math]::Round($x2 - $x1, 1)) + '" height="' + $plotH + '" fill="' + $b.color + '" opacity="0.55"/>')
    }

    # 网格与 Y 轴刻度
    for ($i = 0; $i -le 4; $i++) {
        $y = $padT + ($plotH * $i / 4)
        $v = $YMax - (($YMax - $YMin) * $i / 4)
        [void]$sb.Append('<line x1="' + $padL + '" y1="' + ([math]::Round($y, 1)) + '" x2="' + ($padL + $plotW) + '" y2="' + ([math]::Round($y, 1)) + '" stroke="#e3e3ea" stroke-width="1"/>')
        [void]$sb.Append('<text x="' + ($padL - 6) + '" y="' + ([math]::Round($y + 4, 1)) + '" text-anchor="end" fill="#666">' + ([math]::Round($v, 0)) + '</text>')
    }
    # X 轴刻度（分钟）
    $mins = [math]::Max(1, [int][math]::Ceiling($XMax / 60))
    $stepMin = [math]::Max(1, [int][math]::Ceiling($mins / 8))
    for ($m = 0; $m -le $mins; $m += $stepMin) {
        $x = $padL + (($m * 60) / $XMax) * $plotW
        [void]$sb.Append('<text x="' + ([math]::Round($x, 1)) + '" y="' + ($padT + $plotH + 16) + '" text-anchor="middle" fill="#666">' + $m + 'm</text>')
    }

    $clip = { param($v) if ($v -lt $YMin) { return $YMin } if ($v -gt $YMax) { return $YMax } return $v }
    foreach ($s in $Series) {
        $seg = New-Object System.Collections.ArrayList
        $prevX = $null
        foreach ($p in $s.points) {
            if ($null -eq $p[1]) {
                if ($seg.Count -gt 1) { [void]$sb.Append('<polyline fill="none" stroke="' + $s.color + '" stroke-width="1.6" points="' + ($seg -join ' ') + '"/>') }
                $seg.Clear(); $prevX = $null
                continue
            }
            $x = $padL + ($p[0] / $XMax) * $plotW
            $vv = & $clip ([double]$p[1])
            $y = $padT + $plotH - (($vv - $YMin) / ($YMax - $YMin)) * $plotH
            if ($null -ne $prevX -and ($x - $prevX) -gt ($plotW * 0.05)) {
                if ($seg.Count -gt 1) { [void]$sb.Append('<polyline fill="none" stroke="' + $s.color + '" stroke-width="1.6" points="' + ($seg -join ' ') + '"/>') }
                $seg.Clear()
            }
            [void]$seg.Add(([math]::Round($x, 1).ToString() + ',' + [math]::Round($y, 1).ToString()))
            $prevX = $x
        }
        if ($seg.Count -gt 1) { [void]$sb.Append('<polyline fill="none" stroke="' + $s.color + '" stroke-width="1.6" points="' + ($seg -join ' ') + '"/>') }
    }

    # 图例
    $lx = $padL
    foreach ($s in $Series) {
        [void]$sb.Append('<rect x="' + $lx + '" y="' + ($Height - 14) + '" width="10" height="4" fill="' + $s.color + '"/>')
        [void]$sb.Append('<text x="' + ($lx + 14) + '" y="' + ($Height - 9) + '" fill="#444">' + (HtmlEnc $s.name) + '</text>')
        $lx += 22 + (([string]$s.name).Length * 7)
    }
    [void]$sb.Append('</svg>')
    return $sb.ToString()
}

function HtmlEnc {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;')
}

# ============================================================ 主分析

function Add-Block {
    param($Block)
    if ($null -eq $Script:NW_Blocks) { $Script:NW_Blocks = New-Object System.Collections.ArrayList }
    [void]$Script:NW_Blocks.Add($Block)
}

function Invoke-NetWatchAnalysis {
    param([Parameter(Mandatory = $true)][string]$SessionDir)

    $d = Import-NetWatchData -SessionDir $SessionDir
    $Script:NW_Blocks = New-Object System.Collections.ArrayList
    $blocks = $Script:NW_Blocks
    $summary = [ordered]@{}

    # ---------- 会话元信息 ----------
    $startedAt = $null
    $endedAt = Get-Date
    if ($d.Session) {
        $startedAt = Parse-Ts ([string]$d.Session.started_at)
        $endedAt = Parse-Ts ([string]$d.Session.ended_at)
        if ($null -eq $endedAt) { $endedAt = Get-Date }
    }
    if ($null -eq $startedAt) { $startedAt = (Get-Date).AddMinutes(-1) }
    $durationSec = [math]::Max(1, ($endedAt - $startedAt).TotalSeconds)

    $stats = Get-TargetStats -IcmpRows $d.Icmp
    $windows = Find-AnomalyWindows -Stats $stats

    # 事件索引（按时间）
    $evIndex = New-Object System.Collections.ArrayList
    foreach ($e in $d.Events) {
        $t = Parse-Ts ([string]$e.ts)
        if ($null -eq $t) { continue }
        [void]$evIndex.Add([pscustomobject]@{ t = $t; provider = [string]$e.provider; id = [int]$e.id; props = (@($e.props) -join ','); msg = [string]$e.message })
    }

    $driverEvents = @($evIndex | Where-Object { $_.provider -like 'Netwtw*' })
    $wlanEvents = @($evIndex | Where-Object { $_.provider -like '*WLAN*' })
    $ndisEvents = @($evIndex | Where-Object { $_.provider -like '*NDIS*' -or $_.provider -like '*TCPIP*' })

    $add = $null   # 使用 Add-Block 收集报告块

    # ============================================================ 结论
    $concl = New-Object System.Collections.ArrayList
    $gwStats = @($stats | Where-Object { $_.Target -eq 'gateway' })
    $campusStats = @($stats | Where-Object { $_.Target -like '*campus*' })
    $pubStats = @($stats | Where-Object { $_.Target -notlike '*campus*' -and $_.Target -ne 'gateway' })
    $gwBad = $(if ($gwStats.Count) { $gwStats[0].LossPct -gt 0.5 -or ($null -ne $gwStats[0].Max -and $null -ne $gwStats[0].P50 -and $gwStats[0].Max -gt [math]::Max(3 * $gwStats[0].P50, 60)) } else { $false })
    $pubBad = @($pubStats | Where-Object { $_.LossPct -gt 1 -or ($null -ne $_.Max -and $null -ne $_.P99 -and $_.Max -gt 2 * $_.P99) }).Count -gt 0

    if ($windows.Count -eq 0) {
        [void]$concl.Add('本次采集窗口内**没有**出现明显的延迟尖峰或丢包（按各目标 p99 判定）。说明启用期间网络是正常的，或异常发生在窗口之外。')
    } else {
        $tot = 0.0
        foreach ($w in $windows) { $tot += ($w.end - $w.start).TotalSeconds }
        [void]$concl.Add(('本次采集共识别出 ' + $windows.Count + ' 个异常时间窗，累计约 ' + [math]::Round($tot, 0) + ' 秒。'))
        if ($gwBad) { [void]$concl.Add('**本地网关同时也劣化** → 问题在"你的电脑 ↔ AP"这一段（无线链路/驱动），而不是校园网出口。') }
        elseif ($pubBad -and $campusStats.Count -gt 0) { [void]$concl.Add('网关与校园内网保持干净，**只有公网方向劣化** → 问题在校园网出口或上游，不在你的无线链路。') }
        else { [void]$concl.Add('异常影响范围见下方"异常时间窗"与"假设评估"。') }
    }

    Add-Block(@{ type = 'h'; level = 1; text = 'NetWatch 会话报告' })
    Add-Block(@{ type = 'table'; header = @('项目', '值'); rows = @(
        ,@('会话名', [string]$d.Session.name)
        ,@('开始', (Get-Stamp $startedAt))
        ,@('结束', (Get-Stamp $endedAt))
        ,@('实际时长', ([math]::Round($durationSec / 60, 1).ToString() + ' 分钟'))
        ,@('计划时长', ([string]$d.Session.planned_minutes + ' 分钟'))
        ,@('停止原因', [string]$d.Session.stop_reason)
        ,@('异常快照次数', [string]$d.Session.incidents)
        ,@('数据目录', $SessionDir)
    ) })
    Add-Block(@{ type = 'h'; level = 2; text = '0. 结论速览' })
    foreach ($c in $concl) { Add-Block(@{ type = 'p'; text = $c }) }

    # ============================================================ 数据覆盖
    Add-Block(@{ type = 'h'; level = 2; text = '1. 数据覆盖与完整性' })
    $covRows = New-Object System.Collections.ArrayList
    $covAlias = @{ 'latency_icmp' = @('latency_icmp', 'icmp') }
    foreach ($k in @('latency_icmp', 'wifi', 'sys', 'proc', 'dns', 'l7', 'proxy', 'neighbors', 'markers')) {
        $cnt = 0
        $cands = @($k)
        if ($covAlias.ContainsKey($k)) { $cands = $covAlias[$k] }
        if ($d.Session -and $d.Session.csv_rows) {
            foreach ($cand in $cands) {
                if ($d.Session.csv_rows.PSObject.Properties.Match($cand).Count -gt 0) {
                    $cnt = [int]$d.Session.csv_rows.$cand
                    break
                }
            }
        }
        # 以磁盘上实际存在的行数为准（元数据可能来自旧版本或写入时点不同）
        if ($cnt -le 0) {
            $csvPath = Join-Path $SessionDir ($k + '.csv')
            if (Test-Path -LiteralPath $csvPath) {
                try { $cnt = @((Get-Content -LiteralPath $csvPath -Encoding UTF8) | Select-Object -Skip 1).Count } catch { }
            }
        }
        [void]$covRows.Add(@($k, [string]$cnt))
    }
    [void]$covRows.Add(@('events.jsonl', [string]$d.Events.Count))
    Add-Block(@{ type = 'table'; header = @('数据文件', '记录数'); rows = @($covRows) })

    $pk = $d.Session.pktmon
    if ($pk) {
        $pkTxt = '未启用'
        if ($pk.started) { $pkTxt = '仍在运行（异常）' }
        elseif ($pk.etl_mb -gt 0) {
            $pkTxt = ('已停止；ETL ' + $pk.etl_mb + ' MB；pcapng ' + $pk.pcapng_mb + ' MB；组件 ID ' + $pk.component_id)
            if ($pk.pcapng) { $pkTxt += ('；文件: ' + $pk.pcapng) }
        } elseif ($pk.note) { $pkTxt = ('未采集（' + $pk.note + '）' + $pk.error) }
        Add-Block(@{ type = 'p'; text = ('**抓包（pktmon，环形缓冲）**：' + $pkTxt) })
        Add-Block(@{ type = 'p'; text = '提示：环形缓冲只保留"最近的"流量，因此抓包覆盖的是本次会话的尾部窗口。' })
    }
    if ([string]$d.Session.stop_reason -like 'data-cap*') {
        Add-Block(@{ type = 'p'; text = '⚠ 本次会话因为**达到数据量上限**而提前结束，采集时长可能不足。' })
    }

    # ============================================================ 分层延迟
    Add-Block(@{ type = 'h'; level = 2; text = '2. 分层延迟总览' })
    $latRows = New-Object System.Collections.ArrayList
    foreach ($s in $stats) {
        [void]$latRows.Add(@(
            $s.Target, $s.Host, $s.Layer, [string]$s.Samples,
            ([string]$s.LossPct + '%'),
            (Num $s.Min 0), (Num $s.P50 1), (Num $s.P95 1), (Num $s.P99 1), (Num $s.Max 0), (Num $s.Jitter 1)
        ))
    }
    Add-Block(@{ type = 'table'; header = @('目标', '地址', '层级', '样本', '丢包', 'min', 'p50', 'p95', 'p99', 'max', '抖动'); rows = @($latRows) })

    # 图表：RTT
    $palette = @('#1f77b4', '#d62728', '#2ca02c', '#ff7f0e', '#9467bd', '#17becf', '#8c564b')
    $bands = New-Object System.Collections.ArrayList
    foreach ($w in $windows) {
        [void]$bands.Add(@{ from = ($w.start - $startedAt).TotalSeconds; to = ($w.end - $startedAt).TotalSeconds; color = '#ffdddd' })
    }
    $series = New-Object System.Collections.ArrayList
    $ci = 0
    foreach ($s in $stats) {
        $pts = New-Object System.Collections.ArrayList
        foreach ($r in $s.Rows) {
            $t = Parse-Ts $r.ts
            if ($null -eq $t) { continue }
            $v = $null
            if ([string]$r.status -eq 'Success') { $v = Get-NumSafe $r.rtt_ms }
            [void]$pts.Add(@(($t - $startedAt).TotalSeconds, $v))
        }
        [void]$series.Add(@{ name = $s.Target; color = $palette[$ci % $palette.Count]; points = @($pts) })
        $ci++
    }
    $rttSvg = New-SvgChart -Title '各目标 RTT（ms，粉色带=异常窗口）' -Series @($series) -Unit 'ms' -XMax $durationSec -YMin 0 -Bands @($bands)
    Add-Block(@{ type = 'chart'; title = 'RTT 时间线'; svg = $rttSvg })

    # ============================================================ 异常窗口
    Add-Block(@{ type = 'h'; level = 2; text = '3. 异常时间窗与伴随证据' })
    if ($windows.Count -eq 0) {
        Add-Block(@{ type = 'p'; text = '无异常窗口。' })
    } else {
        $wRows = New-Object System.Collections.ArrayList
        $winDetail = New-Object System.Collections.ArrayList
        $i = 0
        foreach ($w in $windows) {
            $i++
            $dur = [math]::Round(($w.end - $w.start).TotalSeconds, 0)
            $tgt = (@($w.targets.Keys) -join '/')
            [void]$wRows.Add(@(
                ('#' + $i), $w.start.ToString('HH:mm:ss'), $w.end.ToString('HH:mm:ss'),
                ($dur.ToString() + 's'), $tgt, [string]$w.losses, [string]$w.spike, (Num $w.maxRtt 0)
            ))

            $wf = $w.start.AddSeconds(-30); $wt = $w.end.AddSeconds(30)
            $wifiIn = Get-RowsInWindow -Rows $d.Wifi -From $wf -To $wt
            $sysIn = Get-RowsInWindow -Rows $d.Sys -From $wf -To $wt
            $evIn = @($evIndex | Where-Object { $_.t -ge $w.start.AddSeconds(-60) -and $_.t -le $w.end.AddSeconds(60) })
            $mkIn = @($d.Markers | Where-Object { $t = Parse-Ts ([string]$_.ts); $null -ne $t -and $t -ge $w.start.AddSeconds(-30) -and $t -le $w.end.AddSeconds(30) })
            $scanOverlap = $false
            foreach ($r in $mkIn) { if ([string]$r.kind -like '*scan*') { $scanOverlap = $true } }

            $rssiVals = @($wifiIn | ForEach-Object { Get-NumSafe $_.rssi } | Where-Object { $null -ne $_ })
            $rssiMin = $(if ($rssiVals.Count) { ($rssiVals | Measure-Object -Minimum).Minimum } else { $null })
            $bssids = @($wifiIn | ForEach-Object { [string]$_.bssid } | Sort-Object -Unique)
            $gwMacs = @($wifiIn | ForEach-Object { [string]$_.gw_mac } | Where-Object { Test-RealMac $_ } | Sort-Object -Unique)
            $rxVals = @($sysIn | ForEach-Object { Get-NumSafe $_.wlan_rx_Bps } | Where-Object { $null -ne $_ })
            $txVals = @($sysIn | ForEach-Object { Get-NumSafe $_.wlan_tx_Bps } | Where-Object { $null -ne $_ })
            $cpuVals = @($sysIn | ForEach-Object { Get-NumSafe $_.cpu_pct } | Where-Object { $null -ne $_ })
            $dqv = @($sysIn | ForEach-Object { Get-NumSafe $_.disk_queue } | Where-Object { $null -ne $_ })
            $retrV = @($sysIn | ForEach-Object { Get-NumSafe $_.tcp_retrans_ps } | Where-Object { $null -ne $_ })
            $drv = @($evIn | Where-Object { $_.provider -like 'Netwtw*' })
            $drvIds = @($drv | ForEach-Object { [string]$_.id } | Group-Object | ForEach-Object { ($_.Name + '×' + $_.Count) }) -join ' '

            $bits = New-Object System.Collections.ArrayList
            [void]$bits.Add(('RSSI 最低 ' + (Num $rssiMin 0) + ' dBm'))
            [void]$bits.Add(('BSSID 数 ' + $bssids.Count + $(if ($bssids.Count -gt 1) { '（发生了 AP 切换）' } else { '' })))
            if ($gwMacs.Count -gt 1) { [void]$bits.Add('⚠ 网关 MAC 发生变化') }
            [void]$bits.Add(('入口流量峰值 ' + (Num ((@($rxVals) | Measure-Object -Maximum).Maximum) 0) + ' B/s，出口 ' + (Num ((@($txVals) | Measure-Object -Maximum).Maximum) 0) + ' B/s'))
            [void]$bits.Add(('CPU 峰值 ' + (Num ((@($cpuVals) | Measure-Object -Maximum).Maximum) 0) + '%，磁盘队列峰值 ' + (Num ((@($dqv) | Measure-Object -Maximum).Maximum) 0)))
            [void]$bits.Add(('TCP 重传峰值 ' + (Num ((@($retrV) | Measure-Object -Maximum).Maximum) 2) + '/s'))
            [void]$bits.Add(('无线驱动事件 ' + $(if ($drv.Count) { $drv.Count.ToString() + ' 条 (' + $drvIds + ')' } else { '0 条' })))
            if ($scanOverlap) { [void]$bits.Add('⚠ 本工具的邻近 AP 扫描与该窗口重叠，存在自测干扰可能') }

            [void]$winDetail.Add([pscustomobject]@{ idx = $i; text = $bits })
        }
        Add-Block(@{ type = 'table'; header = @('窗口', '开始', '结束', '持续', '涉及目标', '丢包样本', '尖峰样本', '最大RTT'); rows = @($wRows) })
        foreach ($wd in $winDetail) {
            Add-Block(@{ type = 'h'; level = 3; text = ('窗口 #' + $wd.idx + ' 伴随证据') })
            Add-Block(@{ type = 'bullets'; items = @($wd.text) })
        }
    }

    Add-Block(@{ type = 'h'; level = 3; text = '各目标最差样本（每目标 Top 3 + 前 3 次丢包）' })
    $worst = New-Object System.Collections.ArrayList
    foreach ($s in $stats) {
        $okRows = @($s.Rows | Where-Object { [string]$_.status -eq 'Success' -and $_.rtt_ms -ne '' } |
                   Sort-Object -Property @{Expression = { [double]$_.rtt_ms }; Descending = $true } | Select-Object -First 3)
        foreach ($t in $okRows) {
            [void]$worst.Add(@($s.Target, ((Num ([double]$t.rtt_ms) 0) + ' ms'), [string]$t.ts, [string]$t.phase))
        }
        $badRows = @($s.Rows | Where-Object { [string]$_.status -ne 'Success' } | Select-Object -First 3)
        foreach ($t in $badRows) {
            [void]$worst.Add(@($s.Target, ('丢包 (' + [string]$t.status + ')'), [string]$t.ts, [string]$t.phase))
        }
    }
    Add-Block(@{ type = 'table'; header = @('目标', '值', '时间', '相位'); rows = @($worst) })

    # ============================================================ 无线链路
    Add-Block(@{ type = 'h'; level = 2; text = '4. 无线链路层' })
    if ($d.Wifi.Count -eq 0) {
        Add-Block(@{ type = 'p'; text = '无无线数据。' })
    } else {
        $rssiAll = @($d.Wifi | ForEach-Object { Get-NumSafe $_.rssi } | Where-Object { $null -ne $_ })
        $bssidAll = @($d.Wifi | ForEach-Object { [string]$_.bssid } | Group-Object | Sort-Object Count -Descending)
        $gwmacAll = @($d.Wifi | ForEach-Object { [string]$_.gw_mac } | Where-Object { Test-RealMac $_ } | Group-Object)
        $rxAll = @($d.Wifi | ForEach-Object { Get-NumSafe $_.rx_mbps } | Where-Object { $null -ne $_ })
        Add-Block(@{ type = 'table'; header = @('指标', '值'); rows = @(
            ,@('样本数', [string]$d.Wifi.Count)
            ,@('SSID', $(($d.Wifi | ForEach-Object { [string]$_.ssid } | Sort-Object -Unique) -join ', '))
            ,@('信道', $(($d.Wifi | ForEach-Object { [string]$_.channel } | Sort-Object -Unique) -join ', '))
            ,@('频段/协议', $(($d.Wifi | ForEach-Object { ([string]$_.band + ' ' + [string]$_.radio) } | Sort-Object -Unique) -join ' | '))
            ,@('RSSI 最低', ((Num ((@($rssiAll) | Measure-Object -Minimum).Minimum) 0) + ' dBm'))
            ,@('RSSI 最高', ((Num ((@($rssiAll) | Measure-Object -Maximum).Maximum) 0) + ' dBm'))
            ,@('RSSI 波动', (Num ((@($rssiAll) | Measure-Object -Maximum).Maximum - (@($rssiAll) | Measure-Object -Minimum).Minimum) 0))
            ,@('协商速率最低', ((Num ((@($rxAll) | Measure-Object -Minimum).Minimum) 0) + ' Mbps'))
            ,@('出现过的 BSSID', (($bssidAll | ForEach-Object { $_.Name + '(' + $_.Count + ')' }) -join ', '))
            ,@('网关 MAC', (($gwmacAll | ForEach-Object { $_.Name + '(' + $_.Count + ')' }) -join ', '))
        ) })
        if ($bssidAll.Count -gt 1) {
            Add-Block(@{ type = 'p'; text = '⚠ 会话期间发生了 **AP 切换**（BSSID 变化）。在共享校园网上，切换到负载更高的 AP 会直接表现为延迟飙升。' })
        }
        if ($gwmacAll.Count -gt 1) {
            Add-Block(@{ type = 'p'; text = '⚠ 网关 MAC 发生过变化。若这不是 AP 切换导致的正常变化，则需要警惕同一网段内的 ARP 异常（开放认证的校园网上是可能的）。' })
        }

        $wifiPts = New-Object System.Collections.ArrayList
        foreach ($r in $d.Wifi) {
            $t = Parse-Ts $r.ts
            if ($null -eq $t) { continue }
            [void]$wifiPts.Add(@(($t - $startedAt).TotalSeconds, (Get-NumSafe $r.rssi)))
        }
        $svg = New-SvgChart -Title '无线信号强度 RSSI（dBm，越靠上越好）' -Series @(@{ name = 'RSSI'; color = '#2ca02c'; points = @($wifiPts) }) -XMax $durationSec -YMin -95 -YMax -20 -Bands @($bands)
        Add-Block(@{ type = 'chart'; title = 'RSSI 时间线'; svg = $svg })
    }

    # ============================================================ 本机资源
    Add-Block(@{ type = 'h'; level = 2; text = '5. 本机资源与流量占用' })
    if ($d.Sys.Count -gt 0) {
        $cpuA = @($d.Sys | ForEach-Object { Get-NumSafe $_.cpu_pct } | Where-Object { $null -ne $_ })
        $rxA = @($d.Sys | ForEach-Object { Get-NumSafe $_.wlan_rx_Bps } | Where-Object { $null -ne $_ })
        $txA = @($d.Sys | ForEach-Object { Get-NumSafe $_.wlan_tx_Bps } | Where-Object { $null -ne $_ })
        $dqA = @($d.Sys | ForEach-Object { Get-NumSafe $_.disk_queue } | Where-Object { $null -ne $_ })
        $rtA = @($d.Sys | ForEach-Object { Get-NumSafe $_.tcp_retrans_ps } | Where-Object { $null -ne $_ })
        $cfA = @($d.Sys | ForEach-Object { Get-NumSafe $_.tcp_connfail_ps } | Where-Object { $null -ne $_ })
        $twA = @($d.Sys | ForEach-Object { Get-NumSafe $_.tcp_timewait } | Where-Object { $null -ne $_ })
        Add-Block(@{ type = 'table'; header = @('指标', '平均', '最大'); rows = @(
            ,@('CPU %', (Num ((@($cpuA) | Measure-Object -Average).Average) 1), (Num ((@($cpuA) | Measure-Object -Maximum).Maximum) 0))
            ,@('WLAN 入口 B/s', (Num ((@($rxA) | Measure-Object -Average).Average) 0), (Num ((@($rxA) | Measure-Object -Maximum).Maximum) 0))
            ,@('WLAN 出口 B/s', (Num ((@($txA) | Measure-Object -Average).Average) 0), (Num ((@($txA) | Measure-Object -Maximum).Maximum) 0))
            ,@('磁盘队列', (Num ((@($dqA) | Measure-Object -Average).Average) 2), (Num ((@($dqA) | Measure-Object -Maximum).Maximum) 0))
            ,@('TCP 重传/s', (Num ((@($rtA) | Measure-Object -Average).Average) 2), (Num ((@($rtA) | Measure-Object -Maximum).Maximum) 2))
            ,@('TCP 连接失败/s', (Num ((@($cfA) | Measure-Object -Average).Average) 2), (Num ((@($cfA) | Measure-Object -Maximum).Maximum) 2))
            ,@('TIME_WAIT 峰值', '', (Num ((@($twA) | Measure-Object -Maximum).Maximum) 0))
        ) })
        $thrPts = New-Object System.Collections.ArrayList
        $rtt2 = New-Object System.Collections.ArrayList
        foreach ($r in $d.Sys) {
            $t = Parse-Ts $r.ts
            if ($null -eq $t) { continue }
            $x = ($t - $startedAt).TotalSeconds
            [void]$thrPts.Add(@($x, (Get-NumSafe $r.wlan_rx_Bps)))
            $rtt2.Add(@($x, (Get-NumSafe $r.tcp_retrans_ps)))
        }
        $svg = New-SvgChart -Title 'WLAN 入口吞吐（B/s）' -Series @(@{ name = 'rx B/s'; color = '#ff7f0e'; points = @($thrPts) }) -XMax $durationSec -YMin 0 -Bands @($bands)
        Add-Block(@{ type = 'chart'; title = '吞吐时间线'; svg = $svg })
        $svg2 = New-SvgChart -Title 'TCP 重传速率（次/秒）' -Series @(@{ name = 'retrans/s'; color = '#d62728'; points = @($rtt2) }) -XMax $durationSec -YMin 0 -Bands @($bands)
        Add-Block(@{ type = 'chart'; title = '重传时间线'; svg = $svg2 })
    } else {
        Add-Block(@{ type = 'p'; text = '无系统数据。' })
    }

    if ($d.Proc.Count -gt 0) {
        $agg = @{}
        foreach ($r in $d.Proc) {
            $n = [string]$r.name
            if (-not $agg.ContainsKey($n)) { $agg[$n] = [pscustomobject]@{ name = $n; maxconn = 0; maxio = 0.0; samples = 0 } }
            $e = $agg[$n]
            $e.samples++
            $c = Get-NumSafe $r.tcp_conns; if ($null -ne $c -and $c -gt $e.maxconn) { $e.maxconn = [int]$c }
            $io = Get-NumSafe $r.iobytes_ps; if ($null -ne $io -and $io -gt $e.maxio) { $e.maxio = [double]$io }
        }
        $topConn = @($agg.Values | Sort-Object -Property @{Expression = 'maxconn'; Descending = $true} | Select-Object -First 10)
        $topIo = @($agg.Values | Sort-Object -Property @{Expression = 'maxio'; Descending = $true} | Select-Object -First 10)
        $pr = New-Object System.Collections.ArrayList
        foreach ($x in $topConn) { [void]$pr.Add(@('连接数最多', $x.name, [string]$x.maxconn, (Num $x.maxio 0))) }
        foreach ($x in $topIo) { [void]$pr.Add(@('IO 最高', $x.name, [string]$x.maxconn, (Num $x.maxio 0))) }
        Add-Block(@{ type = 'table'; header = @('维度', '进程', '最大TCP连接数', '最大 IO B/s'); rows = @($pr) })
        Add-Block(@{ type = 'p'; text = '注：Windows 不提供精确的"每进程网络字节数"，这里的 IO 含磁盘读写，仅用于发现"哪个进程在猛跑"。' })
    }

    # ============================================================ 事件
    Add-Block(@{ type = 'h'; level = 2; text = '6. 系统事件（无线驱动 / WLAN 服务 / NDIS / DHCP）' })
    if ($evIndex.Count -eq 0) {
        Add-Block(@{ type = 'p'; text = '无事件记录（可能未启用事件采集，或窗口内确实没有相关事件）。' })
    } else {
        $grp = @($evIndex | Group-Object provider, id | Sort-Object Count -Descending | Select-Object -First 20)
        $er = New-Object System.Collections.ArrayList
        foreach ($g in $grp) {
            $first = ($g.Group | Sort-Object t | Select-Object -First 1).t
            $last = ($g.Group | Sort-Object t | Select-Object -Last 1).t
            [void]$er.Add(@($g.Group[0].provider, [string]$g.Group[0].id, [string]$g.Count, $first.ToString('HH:mm:ss'), $last.ToString('HH:mm:ss')))
        }
        Add-Block(@{ type = 'table'; header = @('提供程序', '事件ID', '次数', '最早', '最晚'); rows = @($er) })

        if ($driverEvents.Count -gt 0) {
            $inWin = 0
            foreach ($w in $windows) {
                $inWin += @($driverEvents | Where-Object { $_.t -ge $w.start.AddSeconds(-60) -and $_.t -le $w.end.AddSeconds(60) }).Count
            }
            Add-Block(@{ type = 'p'; text = ('无线驱动事件共 ' + $driverEvents.Count + ' 条，其中 **' + $inWin + ' 条落在异常窗口前后 60 秒内**。') })
            $bssidInEvents = @{}
            foreach ($e in $driverEvents) {
                foreach ($m in [regex]::Matches([string]$e.props, '([0-9]{1,3},){5}[0-9]{1,3}')) { $bssidInEvents[$m.Value] = $true }
            }
            if ($bssidInEvents.Count -gt 0) {
                Add-Block(@{ type = 'p'; text = '驱动事件载荷中出现的 MAC 序列（十进制，逗号分隔；可用于确认驱动当时在评估哪些 AP）：' })
                Add-Block(@{ type = 'bullets'; items = @($bssidInEvents.Keys | Select-Object -First 8) })
            }
        }
        if ($ndisEvents.Count -gt 0) {
            Add-Block(@{ type = 'p'; text = ('NDIS/TCPIP 层事件 ' + $ndisEvents.Count + ' 条，详见 events.jsonl。') })
        }
        $wlanSeen = @($wlanEvents | Group-Object id | Sort-Object Count -Descending | Select-Object -First 6)
        if ($wlanSeen.Count -gt 0) {
            Add-Block(@{ type = 'p'; text = ('WLAN 服务事件：' + (($wlanSeen | ForEach-Object { $_.Name + '×' + $_.Count }) -join '，') + '。') })
        }
    }

    # ============================================================ 代理相位
    Add-Block(@{ type = 'h'; level = 2; text = '7. 代理相位对照（系统代理 开 / 关）' })
    $phases = @($d.Icmp | Group-Object phase | Sort-Object Name)
    if ($phases.Count -ge 2) {
        $pr = New-Object System.Collections.ArrayList
        foreach ($ph in $phases) {
            foreach ($s in $stats) {
                $sub = @($ph.Group | Where-Object { $_.target -eq $s.Target })
                if ($sub.Count -eq 0) { continue }
                $vals = @($sub | Where-Object { $_.status -eq 'Success' -and $_.rtt_ms -ne '' } | ForEach-Object { [double]$_.rtt_ms })
                $lost = @($sub | Where-Object { $_.status -ne 'Success' }).Count
                [void]$pr.Add(@(
                    $ph.Name, $s.Target, [string]$sub.Count,
                    ([string]([math]::Round(100.0 * $lost / $sub.Count, 1)) + '%'),
                    (Num (Get-Percentile -Values $vals -P 50) 1),
                    (Num (Get-Percentile -Values $vals -P 95) 1)
                ))
            }
        }
        Add-Block(@{ type = 'table'; header = @('相位', '目标', '样本', '丢包', 'p50', 'p95'); rows = @($pr) })
        Add-Block(@{ type = 'p'; text = '相位由系统代理开关自动切换（p0-unknown 为启动初期）。对比同一目标在不同相位的 p50/p95，可以判断"慢"是否由代理引入。' })
    } else {
        Add-Block(@{ type = 'p'; text = '本次会话只观察到单一代理相位（未切换），无法做开/关对照。' })
    }
    if ($d.Proxy.Count -gt 0) {
        $upN = @($d.Proxy | Where-Object { [string]$_.listener_up -eq '1' }).Count
        $srv = (@($d.Proxy | ForEach-Object { [string]$_.system_proxy_server } | Sort-Object -Unique) -join ' / ')
        Add-Block(@{ type = 'p'; text = ('本地代理端口存活采样：' + $upN + ' / ' + $d.Proxy.Count + ' 次可达；系统代理设置值：' + $srv) })
    }
    if ($d.L7.Count -gt 0) {
        $lr = New-Object System.Collections.ArrayList
        foreach ($g in @($d.L7 | Group-Object mode, name)) {
            $vals = @($g.Group | ForEach-Object { Get-NumSafe $_.ms } | Where-Object { $null -ne $_ })
            $fails = @($g.Group | Where-Object { [string]$_.status -notmatch '^\d+$' }).Count
            [void]$lr.Add(@($g.Group[0].mode, $g.Group[0].name, [string]$g.Count, (Num (Get-Percentile -Values $vals -P 50) 0), (Num ((@($vals) | Measure-Object -Maximum).Maximum) 0), [string]$fails))
        }
        Add-Block(@{ type = 'table'; header = @('模式', '目标', '次数', 'p50(ms)', 'max(ms)', '失败次数'); rows = @($lr) })
    }

    # ============================================================ DNS
    Add-Block(@{ type = 'h'; level = 2; text = '8. DNS 解析' })
    if ($d.Dns.Count -gt 0) {
        $dr = New-Object System.Collections.ArrayList
        foreach ($g in @($d.Dns | Group-Object server)) {
            $vals = @($g.Group | ForEach-Object { Get-NumSafe $_.ms } | Where-Object { $null -ne $_ })
            $bad = @($g.Group | Where-Object { [string]$_.status -ne 'OK' -and [string]$_.status -ne 'NoAnswer' }).Count
            [void]$dr.Add(@($g.Name, [string]$g.Count, (Num (Get-Percentile -Values $vals -P 50) 0), (Num (Get-Percentile -Values $vals -P 95) 0), (Num ((@($vals) | Measure-Object -Maximum).Maximum) 0), [string]$bad))
        }
        Add-Block(@{ type = 'table'; header = @('DNS 服务器', '查询数', 'p50(ms)', 'p95(ms)', 'max(ms)', '失败数'); rows = @($dr) })
    } else {
        Add-Block(@{ type = 'p'; text = '无 DNS 数据。' })
    }

    # ============================================================ 假设评估
    Add-Block(@{ type = 'h'; level = 2; text = '9. 假设评估' })
    $hyp = New-Object System.Collections.ArrayList

    # H1 无线链路/驱动
    $drvInWin = 0
    foreach ($w in $windows) { $drvInWin += @($driverEvents | Where-Object { $_.t -ge $w.start.AddSeconds(-60) -and $_.t -le $w.end.AddSeconds(60) }).Count }
    if ($windows.Count -gt 0 -and $gwBad) {
        [void]$hyp.Add('**H1 无线链路/驱动层（被支持）**：异常窗口内本地网关同样劣化，说明瓶颈在"网卡 ↔ AP"这一段。')
    } elseif ($windows.Count -gt 0 -and -not $gwBad) {
        [void]$hyp.Add('**H1 无线链路/驱动层（被否定）**：异常窗口内本地网关保持干净，问题不在无线链路。')
    } else {
        [void]$hyp.Add('**H1 无线链路/驱动层（未知）**：本次窗口未捕捉到异常，无法判断。')
    }
    if ($driverEvents.Count -gt 0) {
        [void]$hyp.Add(('**H2 无线驱动行为（' + $(if ($drvInWin -gt 0) { '被支持' } else { '证据不足' }) + '）**：驱动事件 ' + $driverEvents.Count + ' 条，与异常窗口有时间重叠的 ' + $drvInWin + ' 条。'))
    }

    # H3 本机流量饱和
    $satHit = 0
    foreach ($w in $windows) {
        $sysIn = Get-RowsInWindow -Rows $d.Sys -From $w.start.AddSeconds(-15) -To $w.end.AddSeconds(15)
        $mx = (@($sysIn | ForEach-Object { Get-NumSafe $_.wlan_rx_Bps } | Where-Object { $null -ne $_ }) | Measure-Object -Maximum).Maximum
        if ($null -ne $mx -and $mx -gt 20000000) { $satHit++ }
    }
    if ($satHit -gt 0) {
        [void]$hyp.Add(('**H3 本机后台流量饱和（被支持）**：有 ' + $satHit + ' 个异常窗口内 WLAN 入口吞吐超过 20 MB/s，链路被打满会造成缓冲区膨胀。'))
    } else {
        [void]$hyp.Add('**H3 本机后台流量饱和（本窗口内未见支持）**：异常窗口内没有观察到链路吞吐被打满。')
    }

    # H4 代理
    if ($d.L7.Count -gt 0) {
        $pRows = @($d.L7 | Where-Object { [string]$_.mode -eq 'proxy' })
        $dRows = @($d.L7 | Where-Object { [string]$_.mode -eq 'direct' })
        $pOk = @($pRows | Where-Object { [string]$_.status -match '^\d+$' -and [int]$_.status -lt 500 })
        $dOk = @($dRows | Where-Object { [string]$_.status -match '^\d+$' -and [int]$_.status -lt 500 })
        $proxyVals = @($pOk | ForEach-Object { Get-NumSafe $_.ms } | Where-Object { $null -ne $_ })
        $directVals = @($dOk | ForEach-Object { Get-NumSafe $_.ms } | Where-Object { $null -ne $_ })
        $pFail = 0; $dFail = 0
        if ($pRows.Count -gt 0) { $pFail = [math]::Round(100.0 * ($pRows.Count - $pOk.Count) / $pRows.Count, 0) }
        if ($dRows.Count -gt 0) { $dFail = [math]::Round(100.0 * ($dRows.Count - $dOk.Count) / $dRows.Count, 0) }

        if ($pRows.Count -gt 0 -and $pFail -ge 50 -and $dFail -lt 50) {
            [void]$hyp.Add(('**H4 本地代理（被否定为"变慢"，实为"不可用"）**：经代理的请求 ' + $pFail + '% 连接失败，而直连只有 ' + $dFail + '% 失败。这说明采集时代理进程根本没在监听（比如已退出），属于"代理没开"，不是"代理慢"。'))
        } elseif ($proxyVals.Count -gt 0 -and $directVals.Count -gt 0) {
            $pv = Get-Percentile -Values $proxyVals -P 50
            $dv = Get-Percentile -Values $directVals -P 50
            if ($null -ne $pv -and $null -ne $dv) {
                if ($pv -gt ($dv * 3)) {
                    [void]$hyp.Add(('**H4 本地代理（被支持）**：经代理的 L7 中位耗时 ' + (Num $pv 0) + ' ms，直连 ' + (Num $dv 0) + ' ms，代理放大了 ' + [math]::Round($pv / [math]::Max($dv, 1), 1) + ' 倍。'))
                } else {
                    [void]$hyp.Add(('**H4 本地代理（本窗口内未见明显放大）**：经代理中位 ' + (Num $pv 0) + ' ms，直连 ' + (Num $dv 0) + ' ms。'))
                }
            }
        } else {
            [void]$hyp.Add('**H4 本地代理（数据不足）**：两类路径都没有成功的 L7 样本，无法比较。')
        }
    }

    # H5 校园网出口
    if ($windows.Count -gt 0) {
        if ($pubBad -and -not $gwBad) {
            [void]$hyp.Add('**H5 校园网出口/上游（被支持）**：只有公网方向劣化，网关与校园内网正常。')
        } elseif ($gwBad) {
            [void]$hyp.Add('**H5 校园网出口/上游（被否定为本窗口主因）**：网关本身也劣化，出口不是唯一原因。')
        }
    }

    # H6 安全
    $macChanged = $false
    if ($d.Wifi.Count -gt 0) {
        $macChanged = (@($d.Wifi | ForEach-Object { [string]$_.gw_mac } | Where-Object { Test-RealMac $_ } | Sort-Object -Unique).Count -gt 1)
    }
    if ($macChanged) {
        [void]$hyp.Add('**H6 同网段 ARP 异常（需要关注）**：网关 MAC 在会话期间出现过变化。若排除了正常 AP 切换，应检查是否存在 ARP 欺骗。')
    }
    foreach ($h in $hyp) { Add-Block(@{ type = 'p'; text = $h }) }

    # ============================================================ 原始数据
    Add-Block(@{ type = 'h'; level = 2; text = '10. 原始数据清单' })
    $fl = New-Object System.Collections.ArrayList
    try {
        Get-ChildItem -LiteralPath $SessionDir -Recurse -File | Sort-Object FullName | ForEach-Object {
            [void]$fl.Add(@($_.FullName.Substring($SessionDir.Length).TrimStart('\'), ([math]::Round($_.Length / 1KB, 1).ToString() + ' KB')))
        }
    } catch { }
    Add-Block(@{ type = 'table'; header = @('文件', '大小'); rows = @($fl) })

    # ============================================================ 渲染
    $md = Render-ReportMarkdown -Blocks $blocks -Title 'NetWatch 会话报告'
    $html = Render-ReportHtml -Blocks $blocks -Title 'NetWatch 会话报告'

    $outDir = Join-Path $SessionDir 'report'
    if (-not (Test-Path -LiteralPath $outDir)) { [void](New-Item -ItemType Directory -Path $outDir -Force) }
    $mdPath = Join-Path $outDir 'report.md'
    $htmlPath = Join-Path $outDir 'report.html'
    Set-Content -LiteralPath $mdPath -Value $md -Encoding UTF8
    Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8

    $summary = [ordered]@{
        session         = [string]$d.Session.name
        started_at      = (Get-Stamp $startedAt)
        ended_at        = (Get-Stamp $endedAt)
        duration_min    = [math]::Round($durationSec / 60, 2)
        stop_reason     = [string]$d.Session.stop_reason
        icmp_samples    = $d.Icmp.Count
        anomaly_windows = $windows.Count
        gateway_bad     = $gwBad
        public_bad      = $pubBad
        driver_events   = $driverEvents.Count
        driver_events_in_windows = $drvInWin
        bssid_changes   = $(if ($d.Wifi.Count) { @($d.Wifi | ForEach-Object { [string]$_.bssid } | Sort-Object -Unique).Count - 1 } else { 0 })
        gateway_mac_changed = $macChanged
        targets         = @($stats | ForEach-Object {
            [ordered]@{ target = $_.Target; loss_pct = $_.LossPct; p50 = $_.P50; p95 = $_.P95; p99 = $_.P99; max = $_.Max; jitter = $_.Jitter }
        })
        pktmon          = $d.Session.pktmon
        report_md       = $mdPath
        report_html     = $htmlPath
    }
    $jsonPath = Join-Path $outDir 'summary.json'
    ($summary | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $jsonPath -Encoding UTF8

    return [pscustomobject]@{ Markdown = $mdPath; Html = $htmlPath; Summary = $jsonPath; Data = $summary }
}

# ============================================================ 渲染器

function Render-ReportMarkdown {
    param($Blocks, [string]$Title)
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $Blocks) {
        switch ($b.type) {
            'h' {
                $hashes = '#' * [int]$b.level
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine($hashes + ' ' + $b.text)
                [void]$sb.AppendLine('')
            }
            'p' { [void]$sb.AppendLine($b.text); [void]$sb.AppendLine('') }
            'bullets' {
                foreach ($it in $b.items) { [void]$sb.AppendLine('- ' + $it) }
                [void]$sb.AppendLine('')
            }
            'table' {
                $hdr = @($b.header)
                [void]$sb.AppendLine('| ' + ($hdr -join ' | ') + ' |')
                [void]$sb.AppendLine('|' + (($hdr | ForEach-Object { ' --- ' }) -join '|') + '|')
                foreach ($r in $b.rows) {
                    $cells = @($r | ForEach-Object { $s = [string]$_; if ($s -match '\|') { $s = $s -replace '\|', '\|' }; $s })
                    [void]$sb.AppendLine('| ' + ($cells -join ' | ') + ' |')
                }
                [void]$sb.AppendLine('')
            }
            'chart' { [void]$sb.AppendLine('*(图表见 report.html：' + $b.title + ')*'); [void]$sb.AppendLine('') }
            'code' {
                [void]$sb.AppendLine('```')
                foreach ($l in $b.lines) { [void]$sb.AppendLine($l) }
                [void]$sb.AppendLine('```')
            }
        }
    }
    return $sb.ToString()
}

function Render-ReportHtml {
    param($Blocks, [string]$Title)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<title>' + (HtmlEnc $Title) + '</title>')
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine('body{font-family:Segoe UI,Microsoft YaHei,sans-serif;margin:24px auto;max-width:1180px;color:#1d1d1f;background:#fff;line-height:1.6}')
    [void]$sb.AppendLine('h1{font-size:24px;border-bottom:2px solid #eee;padding-bottom:8px}')
    [void]$sb.AppendLine('h2{font-size:19px;margin-top:28px;border-left:4px solid #1f77b4;padding-left:10px}')
    [void]$sb.AppendLine('h3{font-size:15px;margin-top:18px;color:#333}')
    [void]$sb.AppendLine('table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px}')
    [void]$sb.AppendLine('th,td{border:1px solid #e3e3ea;padding:5px 8px;text-align:left}')
    [void]$sb.AppendLine('th{background:#f5f6fa;font-weight:600}')
    [void]$sb.AppendLine('tr:nth-child(even) td{background:#fafbfd}')
    [void]$sb.AppendLine('.chart{margin:16px 0;overflow-x:auto;border:1px solid #eee;border-radius:6px;padding:6px;background:#fff}')
    [void]$sb.AppendLine('ul{margin:6px 0 6px 18px}')
    [void]$sb.AppendLine('code{background:#f4f4f8;padding:1px 4px;border-radius:3px}')
    [void]$sb.AppendLine('</style></head><body>')
    foreach ($b in $Blocks) {
        switch ($b.type) {
            'h' {
                $tag = 'h' + [math]::Min(3, [int]$b.level + 0)
                if ([int]$b.level -eq 1) { $tag = 'h1' } elseif ([int]$b.level -eq 2) { $tag = 'h2' } else { $tag = 'h3' }
                [void]$sb.AppendLine('<' + $tag + '>' + (HtmlEnc $b.text) + '</' + $tag + '>')
            }
            'p' { [void]$sb.AppendLine('<p>' + (Convert-InlineMdToHtml $b.text) + '</p>') }
            'bullets' {
                [void]$sb.AppendLine('<ul>')
                foreach ($it in $b.items) { [void]$sb.AppendLine('<li>' + (Convert-InlineMdToHtml $it) + '</li>') }
                [void]$sb.AppendLine('</ul>')
            }
            'table' {
                [void]$sb.AppendLine('<table><thead><tr>')
                foreach ($h in $b.header) { [void]$sb.AppendLine('<th>' + (HtmlEnc ([string]$h)) + '</th>') }
                [void]$sb.AppendLine('</tr></thead><tbody>')
                foreach ($r in $b.rows) {
                    [void]$sb.AppendLine('<tr>')
                    foreach ($c in $r) { [void]$sb.AppendLine('<td>' + (HtmlEnc ([string]$c)) + '</td>') }
                    [void]$sb.AppendLine('</tr>')
                }
                [void]$sb.AppendLine('</tbody></table>')
            }
            'chart' { [void]$sb.AppendLine('<div class="chart">' + $b.svg + '</div>') }
        }
    }
    [void]$sb.AppendLine('</body></html>')
    return $sb.ToString()
}

function Convert-InlineMdToHtml {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $s = HtmlEnc $Text
    $s = [regex]::Replace($s, '\*\*(.+?)\*\*', '<strong>$1</strong>')
    $s = [regex]::Replace($s, '`(.+?)`', '<code>$1</code>')
    return $s
}
