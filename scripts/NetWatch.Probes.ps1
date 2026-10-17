# NetWatch.Probes.ps1 - 分层网络探测（ICMP / DNS / L7 / 代理对照）
# 全部为只读探测，不修改任何系统配置

# ---------------------------------------------------------------- ICMP

function New-IcmpProbeSet {
    param([Parameter(Mandatory = $true)]$Config)

    $set = New-Object System.Collections.ArrayList
    foreach ($t in $Config.IcmpTargets) {
        if (-not $t.host -or $t.host -eq '') { continue }
        $p = New-Object System.Net.NetworkInformation.Ping
        [void]$set.Add([pscustomobject]@{
            Name      = [string]$t.name
            Host      = [string]$t.host
            Layer     = [string]$t.layer
            Warn      = [double]$t.warn
            Crit      = [double]$t.crit
            Pinger    = $p
            Task      = $null
            SentAt    = $null
            NextDue   = (Get-Date)
            Pending   = 0
            ConsecFail = 0
            ConsecSlow = 0
            Sent      = 0
            Recv      = 0
            Lost      = 0
            Rtts      = New-Object System.Collections.ArrayList
        })
    }
    return $set
}

function Start-IcmpDue {
    param([Parameter(Mandatory = $true)]$ProbeSet, [Parameter(Mandatory = $true)]$Session)
    $now = Get-Date
    if ($now -lt $Session.BurstUntil) {
        $interval = [double]$Session.Config.BurstIcmpIntervalSec
    } else {
        $interval = [double]$Session.Config.IcmpIntervalSec
    }
    foreach ($p in $ProbeSet) {
        if ($null -ne $p.Task) { continue }        # 上一发还没回来，跳过（避免堆积）
        if ($now -lt $p.NextDue) { continue }
        try {
            $p.SentAt = $now
            $p.Task = $p.Pinger.SendPingAsync($p.Host, 3000)
            $p.Sent++
        } catch {
            $p.Task = $null
            $p.ConsecFail++
        }
        $p.NextDue = $now.AddSeconds($interval)
    }
}

function Complete-IcmpProbes {
    # 返回本次采集到的样本数组
    param([Parameter(Mandatory = $true)]$ProbeSet, [Parameter(Mandatory = $true)]$Session)

    $samples = New-Object System.Collections.ArrayList
    foreach ($p in $ProbeSet) {
        if ($null -eq $p.Task) { continue }
        if (-not $p.Task.IsCompleted) { continue }

        $rtt = -1.0
        $status = 'Unknown'
        $ttl = ''
        $src = ''
        try {
            $reply = $p.Task.Result
            if ($null -ne $reply) {
                $status = [string]$reply.Status
                if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                    $rtt = [double]$reply.RoundtripTime
                    $p.Recv++
                    [void]$p.Rtts.Add($rtt)
                    $p.ConsecFail = 0
                    if ($rtt -ge $p.Crit) { $p.ConsecSlow++ } else { $p.ConsecSlow = 0 }
                } else {
                    $p.Lost++
                    $p.ConsecFail++
                    $p.ConsecSlow = 0
                }
                try { $ttl = [string]$reply.Options.Ttl } catch { }
                try { if ($reply.Address) { $src = [string]$reply.Address } } catch { }
            } else {
                $status = 'NullReply'
                $p.Lost++
                $p.ConsecFail++
            }
        } catch {
            $status = 'Exception'
            $p.Lost++
            $p.ConsecFail++
        }

        $ts = Get-Stamp
        $sentTs = ''
        if ($p.SentAt) { $sentTs = Get-Stamp $p.SentAt }
        $phase = Get-CurrentPhase -Session $Session
        $incident = '0'
        if ((Get-Date) -lt $Session.BurstUntil) { $incident = '1' }

        Write-CsvRow -Writer $Session.Writers['latency_icmp'] `
            -Values @($ts, $sentTs, $phase, $incident, $p.Name, $p.Host, $p.Layer, (Num $rtt 1), $status, $ttl, $src)

        $peakKey = $p.Name
        if (-not $Session.Peak.MaxRtt.ContainsKey($peakKey)) { $Session.Peak.MaxRtt[$peakKey] = 0.0 }
        if ($rtt -gt [double]$Session.Peak.MaxRtt[$peakKey]) { $Session.Peak.MaxRtt[$peakKey] = $rtt }

        $s = [pscustomobject]@{
            Target = $p.Name; Host = $p.Host; Layer = $p.Layer
            Rtt = $rtt; Status = $status; Warn = $p.Warn; Crit = $p.Crit
            ConsecFail = $p.ConsecFail; ConsecSlow = $p.ConsecSlow; Ts = $ts
        }
        [void]$samples.Add($s)
        if ($status -ne 'Success') { $Session.Peak.LossEvents++ }

        $p.Task = $null
    }
    return $samples
}

function Get-IcmpSummary {
    param($ProbeSet)
    $out = New-Object System.Collections.ArrayList
    foreach ($p in $ProbeSet) {
        $rtts = @($p.Rtts | ForEach-Object { [double]$_ })
        [void]$out.Add([pscustomobject]@{
            Name    = $p.Name
            Host    = $p.Host
            Layer   = $p.Layer
            Sent    = $p.Sent
            Recv    = $p.Recv
            Lost    = $p.Lost
            LossPct = $(if ($p.Sent -gt 0) { [math]::Round(100.0 * $p.Lost / $p.Sent, 2) } else { 0 })
            Min     = $(if ($rtts.Count) { ($rtts | Measure-Object -Minimum).Minimum } else { $null })
            P50     = Get-Percentile -Values $rtts -P 50
            P95     = Get-Percentile -Values $rtts -P 95
            P99     = Get-Percentile -Values $rtts -P 99
            Max     = $(if ($rtts.Count) { ($rtts | Measure-Object -Maximum).Maximum } else { $null })
            Avg     = $(if ($rtts.Count) { [math]::Round(($rtts | Measure-Object -Average).Average, 1) } else { $null })
            Jitter  = $(if ($rtts.Count -gt 1) { Get-Jitter $rtts } else { $null })
        })
    }
    return $out
}

# Get-Jitter 定义在 NetWatch.Util.ps1（报告模块也需要它）

# ---------------------------------------------------------------- Phase（代理相位）

function Get-CurrentPhase {
    param([Parameter(Mandatory = $true)]$Session)
    if ($null -eq $Session.ProxyOn) { return 'p0-unknown' }
    if ($Session.ProxyOn) { return 'pN-proxy-on' }
    return 'pN-proxy-off'
}

# ---------------------------------------------------------------- DNS（异步运行空间，避免阻塞主循环）

$Script:DnsScriptBlock = {
    param($servers, $names, $types)
    $out = New-Object System.Collections.ArrayList
    foreach ($s in $servers) {
        foreach ($n in $names) {
            foreach ($t in $types) {
                $sw = [Diagnostics.Stopwatch]::StartNew()
                $st = 'OK'; $ans = ''
                try {
                    $r = Resolve-DnsName -Name $n -Type $t -Server $s -DnsOnly -QuickTimeout -ErrorAction Stop
                    $ans = (@($r | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress }) -join '|')
                    if (-not $ans) { $st = 'NoAnswer' }
                } catch {
                    $st = 'FAIL'
                    $ans = [string]$_.Exception.Message
                    if ($ans -match 'timed out|超时|Timeout') { $st = 'TIMEOUT' }
                }
                $sw.Stop()
                if ($ans.Length -gt 120) { $ans = $ans.Substring(0, 120) }
                [void]$out.Add([pscustomobject]@{
                    server = $s; name = $n; type = $t
                    ms = $sw.ElapsedMilliseconds; status = $st; answers = $ans
                })
            }
        }
    }
    return $out
}

function Start-DnsProbeAsync {
    param([Parameter(Mandatory = $true)]$Session)
    if ($null -ne $Session.DnsJob) { return }
    $now = Get-Date
    if ($now -lt $Session.DnsNextDue) { return }
    try {
        $ps = [PowerShell]::Create()
        [void]$ps.AddScript($Script:DnsScriptBlock).
            AddArgument($Session.Config.DnsServers).
            AddArgument($Session.Config.DnsNames).
            AddArgument(@('A'))
        $h = $ps.BeginInvoke()
        $Session.DnsJob = [pscustomobject]@{ PS = $ps; Handle = $h; Started = $now }
        $Session.DnsNextDue = $now.AddSeconds([double]$Session.Config.DnsIntervalSec)
    } catch {
        $Session.DnsJob = $null
        $Session.DnsNextDue = $now.AddSeconds([double]$Session.Config.DnsIntervalSec)
    }
}

function Complete-DnsProbeAsync {
    param([Parameter(Mandatory = $true)]$Session)
    $job = $Session.DnsJob
    if ($null -eq $job) { return }

    $overdue = ((Get-Date) - $job.Started).TotalSeconds -gt 15
    if (-not $job.Handle.IsCompleted -and -not $overdue) { return }

    $phase = Get-CurrentPhase -Session $Session
    $rows = @()
    if ($job.Handle.IsCompleted) {
        try {
            $res = $job.PS.EndInvoke($job.Handle)
            # 注意：PSCustomObject 本身就继承自 PSObject，绝对不能用
            # "-is [PSObject]" 去"解包" BaseObject —— 那会拿到 $null 并把整行静默丢掉。
            foreach ($item in $res) {
                if ($null -eq $item) { continue }
                if ($item -is [System.Array]) {
                    foreach ($x in $item) { if ($null -ne $x) { $rows += $x } }
                } else {
                    $rows += $item
                }
            }
        } catch {
            $rows += [pscustomobject]@{ server = 'all'; name = 'all'; type = 'A'; ms = -1; status = 'RUNSPACE-ERR'; answers = [string]$_.Exception.Message }
        }
    } else {
        try { $job.PS.Stop() } catch { }
        $rows += [pscustomobject]@{ server = 'all'; name = 'all'; type = 'A'; ms = -1; status = 'ABORTED-TIMEOUT'; answers = 'dns probe exceeded 15s' }
    }

    foreach ($r in $rows) {
        Write-CsvRow -Writer $Session.Writers['dns'] `
            -Values @((Get-Stamp), $phase, $r.server, $r.name, $r.type, (Num $r.ms 0), $r.status, $r.answers)
    }

    try { $job.PS.Dispose() } catch { }
    $Session.DnsJob = $null
}

# ---------------------------------------------------------------- 代理存活与系统代理状态

function Invoke-ProxyProbe {
    param([Parameter(Mandatory = $true)]$Session)
    $cfg = $Session.Config
    $phase = Get-CurrentPhase -Session $Session
    $sp = Get-SystemProxyState

    $listenerUp = $false
    $listenerMs = -1
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $iar = $c.BeginConnect('127.0.0.1', [int]$cfg.ProxyPort, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne(1500, $false)) {
            try { $c.EndConnect($iar); $listenerUp = $true } catch { $listenerUp = $false }
        }
        $sw.Stop()
        $listenerMs = $sw.ElapsedMilliseconds
        try { $c.Close() } catch { }
    } catch { }

    Write-CsvRow -Writer $Session.Writers['proxy'] `
        -Values @((Get-Stamp), $phase, $(if ($sp.Enabled) { '1' } else { '0' }), $sp.Server, $(if ($listenerUp) { '1' } else { '0' }), (Num $listenerMs 0), $sp.Raw)

    # 代理开关变化 -> 记录相位切换标记
    $prev = $Session.ProxyOn
    if ($null -eq $prev) { $prev = $false }
    if ([bool]$prev -ne [bool]$sp.Enabled) {
        Add-NetWatchMarker -Session $Session -Kind 'proxy-change' -Detail ('system_proxy ' + $prev + ' -> ' + $sp.Enabled + ' ; server=' + $sp.Server)
        Write-Host ("    [相位切换] 系统代理 " + $prev + " -> " + $sp.Enabled) -ForegroundColor Magenta
    }
    $Session.ProxyOn = [bool]$sp.Enabled

    return $sp
}

# ---------------------------------------------------------------- L7（HTTP 计时，代理 / 直连对照）
# 为什么放在独立运行空间、且不用 HttpClient：
#   1) System.Net.Http.HttpClientHandler 在 PS 5.1 全新会话里并没有加载（"找不到类型"），
#      用它会让整个 L7 模块静默失效。改用 System.dll 里的 HttpWebRequest，永远可用。
#   2) 在主循环里停表会把"邻近 AP 扫描 / CIM 采样"这些阻塞模块的耗时算进去，
#      测出几秒的假延迟。放到子运行空间里自己停表，得到的是真实往返时间。

$Script:L7ScriptBlock = {
    param($items, $proxyPort, $timeoutMs)

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor `
            [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    } catch { }

    $out = New-Object System.Collections.ArrayList
    $jobs = New-Object System.Collections.ArrayList

    foreach ($s in $items) {
        $parts = $s -split '\|', 4
        if ($parts.Count -lt 4) { continue }
        $j = [pscustomobject]@{
            mode = $parts[0]; name = $parts[1]; layer = $parts[2]; url = $parts[3]
            req = $null; ar = $null; sw = $null; done = $false
            ms = -1; status = 'PENDING'; note = ''
        }
        try {
            $req = [System.Net.WebRequest]::Create($j.url)
            $req.Method = 'GET'
            $req.Timeout = $timeoutMs
            $req.ReadWriteTimeout = $timeoutMs
            $req.AllowAutoRedirect = $false
            $req.UserAgent = 'NetWatch/1.0'
            if ($j.mode -eq 'proxy') {
                $req.Proxy = New-Object System.Net.WebProxy(('http://127.0.0.1:' + $proxyPort), $false)
            } else {
                $req.Proxy = $null      # $null = 明确不使用代理
            }
            $j.req = $req
            $j.sw = [Diagnostics.Stopwatch]::StartNew()
            $j.ar = $req.BeginGetResponse($null, $null)
        } catch {
            $j.done = $true
            $j.status = 'START-ERR'
            $j.note = [string]$_.Exception.Message
        }
        [void]$jobs.Add($j)
    }

    $deadline = (Get-Date).AddMilliseconds($timeoutMs + 3000)
    while ((Get-Date) -lt $deadline) {
        $pending = 0
        foreach ($j in $jobs) {
            if ($j.done) { continue }
            if ($j.ar.AsyncWaitHandle.WaitOne(0)) {
                $j.sw.Stop()
                $j.ms = $j.sw.ElapsedMilliseconds
                $j.done = $true
                try {
                    $resp = $j.req.EndGetResponse($j.ar)
                    if ($null -ne $resp) {
                        $j.status = [string]([int]$resp.StatusCode)
                        try { $resp.Close() } catch { }
                    } else { $j.status = 'NULLRESP' }
                } catch [System.Net.WebException] {
                    $we = $_.Exception
                    if ($null -ne $we.Response) {
                        $j.status = [string]([int]$we.Response.StatusCode)
                        $j.note = 'webex:' + [string]$we.Status
                        try { $we.Response.Close() } catch { }
                    } else {
                        $j.status = 'WEBEX'
                        $j.note = [string]$we.Status + ' ' + [string]$we.Message
                    }
                } catch {
                    $j.status = 'EXC'
                    $j.note = [string]$_.Exception.Message
                }
            } else {
                $pending++
                if ($j.sw.ElapsedMilliseconds -gt ($timeoutMs + 500)) {
                    $j.sw.Stop(); $j.ms = $j.sw.ElapsedMilliseconds
                    $j.done = $true; $j.status = 'TIMEOUT'
                    try { $j.req.Abort() } catch { }
                }
            }
        }
        if ($pending -eq 0) { break }
        Start-Sleep -Milliseconds 20
    }

    foreach ($j in $jobs) {
        if (-not $j.done) {
            $j.status = 'ABORTED'
            try { $j.sw.Stop(); $j.ms = $j.sw.ElapsedMilliseconds } catch { }
            try { $j.req.Abort() } catch { }
        }
        $note = [string]$j.note
        if ($note.Length -gt 160) { $note = $note.Substring(0, 160) }
        [void]$out.Add([pscustomobject]@{
            mode = $j.mode; name = $j.name; layer = $j.layer; url = $j.url
            ms = $j.ms; status = $j.status; note = $note
        })
    }
    return $out
}

function Start-L7ProbeAsync {
    param([Parameter(Mandatory = $true)]$Session)
    if ($null -ne $Session.L7Job) { return }
    $now = Get-Date
    if ($now -lt $Session.L7NextDue) { return }
    $cfg = $Session.Config

    $items = New-Object System.Collections.ArrayList
    foreach ($t in $cfg.L7Targets) {
        foreach ($mode in @('direct', 'proxy')) {
            if ($mode -eq 'proxy' -and -not $cfg.EnableProxyProbe) { continue }
            [void]$items.Add($mode + '|' + [string]$t.name + '|' + [string]$t.layer + '|' + [string]$t.url)
        }
    }
    $Session.L7NextDue = $now.AddSeconds([double]$cfg.L7IntervalSec)
    if ($items.Count -eq 0) { return }

    try {
        $ps = [PowerShell]::Create()
        [void]$ps.AddScript($Script:L7ScriptBlock)
        [void]$ps.AddArgument([string[]]@($items))
        [void]$ps.AddArgument([int]$cfg.ProxyPort)
        [void]$ps.AddArgument([int]([double]$cfg.L7TimeoutSec * 1000))
        $h = $ps.BeginInvoke()
        $Session.L7Job = [pscustomobject]@{ PS = $ps; Handle = $h; Started = $now }
    } catch {
        $Session.L7Job = $null
    }
}

function Complete-L7ProbeAsync {
    param([Parameter(Mandatory = $true)]$Session)
    $job = $Session.L7Job
    if ($null -eq $job) { return }
    $budget = [double]$Session.Config.L7TimeoutSec + 20
    $overdue = ((Get-Date) - $job.Started).TotalSeconds -gt $budget
    if (-not $job.Handle.IsCompleted -and -not $overdue) { return }

    $phase = Get-CurrentPhase -Session $Session
    $rows = @()
    if ($job.Handle.IsCompleted) {
        try {
            $res = $job.PS.EndInvoke($job.Handle)
            foreach ($item in $res) {
                if ($null -eq $item) { continue }
                if ($item -is [System.Array]) {
                    foreach ($x in $item) { if ($null -ne $x) { $rows += $x } }
                } else { $rows += $item }
            }
        } catch {
            $rows += [pscustomobject]@{ mode = 'n/a'; name = 'n/a'; layer = 'n/a'; url = ''; ms = -1; status = 'RUNSPACE-ERR'; note = [string]$_.Exception.Message }
        }
    } else {
        try { $job.PS.Stop() } catch { }
        $rows += [pscustomobject]@{ mode = 'n/a'; name = 'n/a'; layer = 'n/a'; url = ''; ms = -1; status = 'ABORTED-TIMEOUT'; note = 'l7 probe exceeded budget' }
    }
    foreach ($r in $rows) {
        Write-CsvRow -Writer $Session.Writers['l7'] `
            -Values @((Get-Stamp), $phase, $r.mode, $r.name, $r.layer, $r.url, (Num $r.ms 0), $r.status, $r.note)
    }
    try { $job.PS.Dispose() } catch { }
    $Session.L7Job = $null
}
