# NetWatch.ps1 - 主入口：有界会话采集 + 自动分析 + 自动退出
# 兼容 Windows PowerShell 5.1
#
# 设计要点：
#   1) 一切都有上限：时长上限、数据量上限、抓包上限、快照上限
#   2) 到点或到限自动收尾，自动生成报告，然后自己退出
#   3) 全程只读探测；唯一的系统级动作是 pktmon 被动抓包（已获用户批准）
#   4) 数据只写在脚本同级目录（data\ 与 reports\），不写系统盘或用户目录

[CmdletBinding()]
param(
    [int]$Minutes = 0,               # 本次采集分钟数（0=用配置默认）
    [int]$MaxMinutes = 0,            # 时长硬上限（0=用配置默认，最大 240）
    [string]$Label = '',             # 会话标签，便于事后识别
    [double]$LookbackHours = 0,      # >0 时覆盖事件补采窗口（小时）
    [switch]$Quick,                  # 快速自检：5 分钟
    [switch]$ForceSnapshot,          # 启动后立刻抓一次快照
    [switch]$NoPktmon,
    [switch]$NoNeighborScan,
    [switch]$NoProxyProbe,
    [switch]$NoL7,
    [switch]$NoEvents,
    [switch]$NoProc,
    [switch]$NoReport,
    [switch]$OpenReport,
    [switch]$CheckOnly,              # 只做环境自检，不采集
    [switch]$StopPktmon,             # 只收尾残留的 pktmon 捕获，不采集
    [string]$ConfigPath = '',
    [string]$DataRoot = '',
    [string]$ReportRoot = '',
    [int]$StartDelaySec = 0
)

$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------- 路径与模块

$Script:NWRoot = Split-Path -Parent $PSScriptRoot
if (-not $DataRoot) { $DataRoot = Join-Path $Script:NWRoot 'data' }
if (-not $ReportRoot) { $ReportRoot = Join-Path $Script:NWRoot 'reports' }
if (-not $ConfigPath) { $ConfigPath = Join-Path $Script:NWRoot 'config.json' }

foreach ($m in @('NetWatch.Util.ps1', 'NetWatch.Config.ps1', 'NetWatch.Session.ps1',
                 'NetWatch.Probes.ps1', 'NetWatch.Wifi.ps1', 'NetWatch.System.ps1',
                 'NetWatch.Events.ps1', 'NetWatch.Pktmon.ps1', 'NetWatch.Incident.ps1',
                 'NetWatch.Report.ps1')) {
    $p = Join-Path $PSScriptRoot $m
    if (-not (Test-Path -LiteralPath $p)) { Write-Host ("[FATAL] 缺少模块: " + $p) -ForegroundColor Red; exit 2 }
    . $p
}

# TLS：PS 5.1 默认不含 TLS1.2，会让 L7 探测误判失败
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor `
        [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
} catch { }

# ---------------------------------------------------------------- 配置

$overrides = @{}
if ($Minutes -gt 0) { $overrides['DurationMinutes'] = $Minutes }
if ($Quick) { $overrides['DurationMinutes'] = 5 }
if ($NoPktmon) { $overrides['EnablePktmon'] = $false }
if ($NoNeighborScan) { $overrides['EnableNeighborScan'] = $false }
if ($NoProxyProbe) { $overrides['EnableProxyProbe'] = $false }
if ($NoL7) { $overrides['EnableL7Probe'] = $false }
if ($NoEvents) { $overrides['EnableEventLog'] = $false }
if ($NoProc) { $overrides['EnableProcessProbe'] = $false }
if ($LookbackHours -gt 0) { $overrides['EventLookbackMinutes'] = [int]($LookbackHours * 60) }
if ($MaxMinutes -gt 0) { $cfgMax = $MaxMinutes } else { $cfgMax = 0 }
if ($OpenReport) { $overrides['OpenReportOnFinish'] = $true }

$Config = Get-NetWatchConfig -ConfigPath $ConfigPath -Override $overrides
if ($cfgMax -gt 0) {
    $Config.MaxDurationMinutes = [math]::Min($cfgMax, 240)
    if ($Config.DurationMinutes -gt $Config.MaxDurationMinutes) { $Config.DurationMinutes = $Config.MaxDurationMinutes }
}

# ---------------------------------------------------------------- 自检

$isAdmin = Test-IsAdmin
$dataDrive = Get-DriveOfPath $DataRoot
$freeD = Get-FreeSpaceGB $dataDrive
$pktmonOk = $false
try { $pktmonOk = ((Get-Command pktmon -ErrorAction SilentlyContinue) -ne $null) } catch { }

if ($CheckOnly) {
    Write-Host ''
    Write-Host '=== NetWatch 环境自检 ===' -ForegroundColor Cyan
    Write-Host ('PowerShell 版本      : ' + $PSVersionTable.PSVersion.ToString())
    Write-Host ('数据目录             : ' + $DataRoot)
    Write-Host ('报告目录             : ' + $ReportRoot)
    Write-Host ('配置文件             : ' + $ConfigPath + $(if (Test-Path $ConfigPath) { ' (已加载)' } else { ' (不存在, 用内置默认)' }))
    Write-Host ('管理员权限           : ' + $isAdmin)
    Write-Host ('数据盘可用空间       : ' + $dataDrive + ': ' + $freeD + ' GB  (启动要求 >= ' + $Config.MinFreeDiskGB + ' GB)')
    Write-Host ('pktmon 可用          : ' + $pktmonOk)
    Write-Host ('默认网关             : ' + $Config.GatewayHost)
    Write-Host ('无线接口             : ' + $Config.WlanInterface)
    Write-Host ('ICMP 目标            : ' + (@($Config.IcmpTargets | ForEach-Object { ($_.name + '(' + $_.host + ')') }) -join ', '))
    $tcpv4 = Get-CimSafe -Class 'Win32_PerfRawData_Tcpip_TCPv4'
    Write-Host ('TCP 计数器可用       : ' + ($null -ne $tcpv4))
    $w = Get-WlanInterfaceState
    Write-Host ('WLAN 读取            : ' + $(if ($w.Ok) { ('OK  SSID=' + $w.Ssid + ' RSSI=' + $w.Rssi + ' CH=' + $w.Channel) } else { 'FAIL ' + $w.Error }))
    Write-Host ''
    exit 0
}

if ($StopPktmon) {
    Write-Host ''
    Write-Host '=== 收尾残留的 pktmon 捕获 ===' -ForegroundColor Cyan
    if (-not (Test-IsAdmin)) { Write-Host '需要管理员权限。' -ForegroundColor Red; exit 3 }
    if (-not (Test-PktmonRunning)) { Write-Host 'pktmon 当前没有运行，无需处理。' -ForegroundColor Green; exit 0 }
    $prevLog = Get-PktmonLogFile
    Write-Host ('当前捕获日志: ' + $prevLog)
    [void](Invoke-Native -Exe 'pktmon' -Arguments @('stop') -TimeoutMs 40000)
    Start-Sleep -Milliseconds 1200
    if ($prevLog -and (Test-Path -LiteralPath $prevLog)) {
        $pc = [System.IO.Path]::ChangeExtension($prevLog, '.pcapng')
        if (-not (Test-Path -LiteralPath $pc)) {
            $r = Invoke-Native -Exe 'pktmon' -Arguments @('etl2pcap', $prevLog, '--out', $pc) -TimeoutMs 180000
            Write-Host ('已转换为 pcapng: ' + $pc + '  (exit=' + $r.ExitCode + ')') -ForegroundColor Green
        } else {
            Write-Host ('pcapng 已存在: ' + $pc) -ForegroundColor Green
        }
    }
    Write-Host 'pktmon 已停止。' -ForegroundColor Green
    exit 0
}

# ---------------------------------------------------------------- 启动横幅

$totalMB = $Config.MaxDataMB + $Config.PktmonMaxMB

Write-Host ''
Write-Host '===================================================================' -ForegroundColor Cyan
Write-Host ' NetWatch  有界网络故障取证采集器' -ForegroundColor Cyan
Write-Host '===================================================================' -ForegroundColor Cyan
Write-Host (' 计划采集时长   : ' + $Config.DurationMinutes + ' 分钟   (到点自动收尾并生成报告)')
Write-Host (' 时长硬上限     : ' + $Config.MaxDurationMinutes + ' 分钟')
Write-Host (' 数据量上限     : ' + $Config.MaxDataMB + ' MB (CSV/JSON)，到限立即收尾')
Write-Host (' 抓包上限       : ' + $(if ($Config.EnablePktmon) { ($Config.PktmonMaxMB.ToString() + ' MB (pktmon 环形缓冲, 保留最近流量)') } else { '已禁用' }))
Write-Host (' 单次会话总量   : 约 ' + $totalMB + ' MB 以内；历史会话只保留最近 ' + $Config.KeepRuns + ' 次')
Write-Host (' 异常快照       : 最多 ' + $Config.MaxIncidents + ' 次，每次 <= ' + $Config.MaxIncidentDirMB + ' MB')
Write-Host (' 数据目录       : ' + $DataRoot)
Write-Host (' 报告目录       : ' + $ReportRoot)
Write-Host (' 管理员权限     : ' + $isAdmin + $(if (-not $isAdmin) { '  (pktmon 将被跳过)' } else { '' }))
Write-Host (' 数据盘可用     : ' + $dataDrive + ': ' + $freeD + ' GB')
Write-Host '-------------------------------------------------------------------' -ForegroundColor DarkGray

# 预检
$abort = $false
if ($freeD -ge 0 -and $freeD -lt $Config.MinFreeDiskGB) {
    Write-Host ('[FATAL] 数据盘 ' + $dataDrive + ': 可用空间仅 ' + $freeD + ' GB，低于阈值 ' + $Config.MinFreeDiskGB + ' GB，拒绝启动以免写满。') -ForegroundColor Red
    $abort = $true
}
if (-not (Test-Path -LiteralPath $DataRoot)) {
    try { [void](New-Item -ItemType Directory -Path $DataRoot -Force) } catch { Write-Host ('[FATAL] 无法创建 ' + $DataRoot) -ForegroundColor Red; $abort = $true }
}
if (-not (Test-Path -LiteralPath $ReportRoot)) {
    try { [void](New-Item -ItemType Directory -Path $ReportRoot -Force) } catch { Write-Host ('[FATAL] 无法创建 ' + $ReportRoot) -ForegroundColor Red; $abort = $true }
}
if ($abort) { exit 3 }

if ($StartDelaySec -gt 0) {
    Write-Host ('将在 ' + $StartDelaySec + ' 秒后开始，按 Ctrl+C 取消 ...')
    Start-Sleep -Seconds $StartDelaySec
}

# ---------------------------------------------------------------- 会话初始化

$Session = New-NetWatchSession -Config $Config -DataRoot $DataRoot -ReportRoot $ReportRoot -Minutes $Config.DurationMinutes -Label $Label
$logPath = Join-Path $Session.DataDir 'netwatch.log'

Add-NetWatchMarker -Session $Session -Kind 'start' -Detail ('minutes=' + $Config.DurationMinutes + ' pktmon=' + $Config.EnablePktmon + ' admin=' + $isAdmin)
Write-Host (' 会话目录 : ' + $Session.DataDir) -ForegroundColor Green
Write-Host (' 数据日志 : ' + $logPath)
Write-Host '-------------------------------------------------------------------' -ForegroundColor DarkGray

# 事件基线
$Session.EventState = New-EventState
if ($Config.EnableEventLog) {
    Write-Host (' 事件提供程序: 本机可用 ' + $Session.EventState.AvailableProviderCount + ' 个，本次监听 ' + @($Session.EventState.ResolvedProviders).Count + ' 个')
    Write-Host ('   监听列表: ' + (@($Session.EventState.ResolvedProviders) -join ', '))
    Add-NetWatchMarker -Session $Session -Kind 'event-providers' -Detail (@($Session.EventState.ResolvedProviders) -join ',')
    try {
        $n = Write-EventLookback -Session $Session -Minutes $Config.EventLookbackMinutes
        Write-Host (' 事件补采 : 最近 ' + $Config.EventLookbackMinutes + ' 分钟，共 ' + $n + ' 条')
    } catch { Write-Host (' 事件补采失败: ' + $_.Exception.Message) -ForegroundColor Yellow }
}

# 探针
$Session.ProbeSet = New-IcmpProbeSet -Config $Config
if (-not $Config.EnableL7Probe -and -not $Config.EnableProxyProbe) { $Config.L7Targets = @() }

# 抓包（唯一系统级动作）
if ($Config.EnablePktmon) {
    Write-Host ' 正在启动 pktmon 被动抓包（内置工具，环形缓冲，不修改任何网络配置）...' -ForegroundColor DarkYellow
    [void](Start-PktmonCapture -Session $Session)
    $pk = $Session.Pktmon
    if ($pk.started) {
        Write-Host ('   pktmon 已启动: comp=' + $pk.component_id + ' 上限=' + $Config.PktmonMaxMB + 'MB 文件=' + $pk.etl) -ForegroundColor DarkYellow
    } else {
        Write-Host ('   pktmon 未启动: ' + $pk.note + ' ' + $pk.error) -ForegroundColor Yellow
    }
}

# 首轮采样
try { [void](Invoke-ProxyProbe -Session $Session) } catch { }
try { [void](Invoke-WifiSample -Session $Session) } catch { }
try { [void](Invoke-SystemSample -Session $Session) } catch { }

if ($ForceSnapshot) {
    [void](Request-Incident -Session $Session -Reason '启动即取证' -Force)
}

# ---------------------------------------------------------------- 主循环

$script:Interactive = $false
try {
    if ([Console]::IsInputRedirected -eq $false) {
        [Console]::TreatControlCAsInput = $true
        $script:Interactive = $true
        Write-Host ' 交互键 : [M]标记  [S]立即快照  [E]延长5分钟  [Q]立即结束' -ForegroundColor DarkGray
    }
} catch { }

$nextWifi = (Get-Date).AddSeconds([double]$Config.WifiIntervalSec)
$nextScan = (Get-Date).AddSeconds([double]$Config.NeighborScanSec)
$nextSys = (Get-Date).AddSeconds([double]$Config.SysIntervalSec)
$nextProc = (Get-Date).AddSeconds([double]$Config.ProcIntervalSec)
$nextProxy = (Get-Date).AddSeconds([double]$Config.ProxyCheckSec)
$nextEvent = (Get-Date).AddSeconds([double]$Config.EventIntervalSec)
$nextPktmonChk = (Get-Date).AddSeconds(10)
$nextStatus = (Get-Date)

$stopReason = ''
$exitCode = 0

while ($true) {
    $now = Get-Date

    # ---- 限额与结束条件 ----
    $lim = Test-NetWatchLimits -Session $Session
    if ($lim) { $stopReason = $lim; break }

    $flag = Join-Path $Session.DataDir 'stop.flag'
    if (Test-Path -LiteralPath $flag) { $stopReason = 'stop-flag'; break }

    # ---- 键盘 ----
    if ($script:Interactive) {
        try {
            while ([Console]::KeyAvailable) {
                $k = [Console]::ReadKey($true)
                $ch = [string]$k.Key
                if ($k.Key -eq [ConsoleKey]::C -and ($k.Modifiers -band [ConsoleModifiers]::Control)) {
                    $stopReason = 'user-ctrl-c'; break
                }
                switch ($ch) {
                    'M' { [void](Add-NetWatchMarker -Session $Session -Kind 'manual-mark' -Detail ('t+' + [int](($now - $Session.StartedAt).TotalSeconds) + 's')); Write-Host '  [已标记]' -ForegroundColor Magenta }
                    'S' { [void](Request-Incident -Session $Session -Reason '手动快照' -Force) }
                    'E' {
                        $Session.Deadline = $Session.Deadline.AddMinutes(5)
                        $cap = $Session.StartedAt.AddMinutes([double]$Config.MaxDurationMinutes)
                        if ($Session.Deadline -gt $cap) { $Session.Deadline = $cap }
                        Write-Host ('  [已延长] 新的结束时间 ' + $Session.Deadline.ToString('HH:mm:ss')) -ForegroundColor Magenta
                        [void](Add-NetWatchMarker -Session $Session -Kind 'extend' -Detail $Session.Deadline.ToString('HH:mm:ss'))
                    }
                    'Q' { $stopReason = 'user-quit'; break }
                }
                if ($stopReason) { break }
            }
        } catch { $script:Interactive = $false }
    }
    if ($stopReason) { break }

    # ---- 各模块调度 ----
    if ($now -ge $nextProxy) {
        try { [void](Invoke-ProxyProbe -Session $Session) } catch { }
        $nextProxy = $now.AddSeconds([double]$Config.ProxyCheckSec)
    }
    try { Start-L7ProbeAsync -Session $Session; Complete-L7ProbeAsync -Session $Session } catch { }
    try { Start-IcmpDue -ProbeSet $Session.ProbeSet -Session $Session } catch { }
    $samples = @()
    try { $samples = @(Complete-IcmpProbes -ProbeSet $Session.ProbeSet -Session $Session) } catch { }
    if ($samples.Count -gt 0) {
        $why = Test-IncidentTrigger -Session $Session -Samples $samples
        if ($why) { [void](Request-Incident -Session $Session -Reason $why) }
    }

    if ($now -ge $nextWifi) {
        try { [void](Invoke-WifiSample -Session $Session) } catch { }
        $nextWifi = $now.AddSeconds([double]$Config.WifiIntervalSec)
    }
    if ($Config.EnableNeighborScan -and $now -ge $nextScan) {
        try { Invoke-NeighborScan -Session $Session } catch { }
        $nextScan = $now.AddSeconds([double]$Config.NeighborScanSec)
    }
    if ($now -ge $nextSys) {
        try { [void](Invoke-SystemSample -Session $Session) } catch { }
        $nextSys = $now.AddSeconds([double]$Config.SysIntervalSec)
    }
    if ($Config.EnableProcessProbe -and $now -ge $nextProc) {
        try { Invoke-ProcessSample -Session $Session } catch { }
        $nextProc = $now.AddSeconds([double]$Config.ProcIntervalSec)
    }
    if ($Config.EnableEventLog -and $now -ge $nextEvent) {
        try { [void](Invoke-EventScan -Session $Session) } catch { }
        $nextEvent = $now.AddSeconds([double]$Config.EventIntervalSec)
    }
    try { Start-DnsProbeAsync -Session $Session; Complete-DnsProbeAsync -Session $Session } catch { }
    if ($now -ge $nextPktmonChk) {
        try { Update-PktmonCapture -Session $Session } catch { }
        $nextPktmonChk = $now.AddSeconds(10)
    }

    Flush-CsvWriters -Writers $Session.Writers

    # ---- 状态行 ----
    if ($now -ge $nextStatus) {
        $nextStatus = $now.AddSeconds(2)
        $parts = New-Object System.Collections.ArrayList
        foreach ($p in $Session.ProbeSet) {
            $last = 'n/a'
            if ($p.Rtts.Count -gt 0) { $last = [string][int]$p.Rtts[$p.Rtts.Count - 1] + 'ms' }
            $lossTxt = ''
            if ($p.Sent -gt 0 -and $p.Lost -gt 0) { $lossTxt = '/' + $p.Lost + 'lost' }
            [void]$parts.Add($p.Name + ' ' + $last + $lossTxt)
        }
        $remain = [int][math]::Floor(($Session.Deadline - $now).TotalSeconds)
        if ($remain -lt 0) { $remain = 0 }
        $wifiTxt = ''
        if ($Session.WifiState -and $Session.WifiState.Rssi) { $wifiTxt = ' | RSSI ' + $Session.WifiState.Rssi + ' rssi' }
        $burst = ''
        if ($now -lt $Session.BurstUntil) { $burst = ' [高频]' }
        Write-Host ('[' + $now.ToString('HH:mm:ss') + '] ' + (($parts) -join '  ') + $wifiTxt + $burst + '  剩余 ' + [int][math]::Floor($remain / 60) + ':' + ('{0:d2}' -f [int][math]::Floor($remain % 60))) -ForegroundColor Gray
    }

    Start-Sleep -Milliseconds 120
}

# ---------------------------------------------------------------- 收尾

Write-Host ''
Write-Host '-------------------------------------------------------------------' -ForegroundColor DarkGray
Write-Host (' 采集结束，原因: ' + $stopReason) -ForegroundColor Yellow

Add-NetWatchMarker -Session $Session -Kind 'stop' -Detail $stopReason

# 最后一次采样
try { [void](Invoke-WifiSample -Session $Session) } catch { }
try { [void](Invoke-SystemSample -Session $Session) } catch { }
try { [void](Invoke-EventScan -Session $Session) } catch { }

# 停抓包并转换
if ($Session.Pktmon -and $Session.Pktmon.started) {
    Write-Host ' 正在停止 pktmon 并转换 pcapng ...' -ForegroundColor DarkYellow
    Stop-PktmonCapture -Session $Session -Reason $stopReason
    if ($Session.Pktmon.pcapng) {
        Write-Host ('   pcapng: ' + $Session.Pktmon.pcapng + '  (' + $Session.Pktmon.pcapng_mb + ' MB)') -ForegroundColor DarkYellow
    }
}

Flush-CsvWriters -Writers $Session.Writers -Force $true
Close-CsvWriters -Writers $Session.Writers
if ($Session.DnsJob) { try { $Session.DnsJob.PS.Stop(); $Session.DnsJob.PS.Dispose() } catch { } }
if ($Session.L7Job) { try { $Session.L7Job.PS.Stop(); $Session.L7Job.PS.Dispose() } catch { } }

$sessionJson = Save-NetWatchSessionJson -Session $Session -Reason $stopReason
Write-Host (' 会话元数据: ' + $sessionJson)

# 自动分析
$reportPath = ''
if (-not $NoReport) {
    Write-Host ' 正在分析数据并生成报告 ...' -ForegroundColor Cyan
    try {
        $res = Invoke-NetWatchAnalysis -SessionDir $Session.DataDir
        $reportPath = $res.Markdown
        Write-Host ('  Markdown: ' + $res.Markdown) -ForegroundColor Green
        Write-Host ('  HTML    : ' + $res.Html) -ForegroundColor Green
        Write-Host ('  摘要 JSON: ' + $res.Summary) -ForegroundColor Green

        # 打包证据（默认不含 pcapng，避免压缩包过大）
        try {
            $zip = Join-Path $Session.ReportDir 'evidence.zip'
            $items = New-Object System.Collections.ArrayList
            $seenPaths = @{}
            foreach ($p0 in @($res.Markdown, $res.Html, $res.Summary, $sessionJson)) {
                if ($p0 -and -not $seenPaths.ContainsKey($p0)) { $seenPaths[$p0] = $true; [void]$items.Add($p0) }
            }
            Get-ChildItem -LiteralPath $Session.DataDir -File | Where-Object {
                $_.Extension -notin @('.etl', '.pcapng')
            } | ForEach-Object {
                if (-not $seenPaths.ContainsKey($_.FullName)) { $seenPaths[$_.FullName] = $true; [void]$items.Add($_.FullName) }
            }
            if ($Config.IncludePcapInZip -and $Session.Pktmon -and $Session.Pktmon.pcapng) { [void]$items.Add($Session.Pktmon.pcapng) }
            if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
            $itemArr = [string[]]@($items)
            Compress-Archive -LiteralPath $itemArr -DestinationPath $zip -CompressionLevel Optimal -ErrorAction Stop
            Write-Host ('  证据包  : ' + $zip + '  (' + [math]::Round((Get-Item $zip).Length / 1KB, 0) + ' KB)') -ForegroundColor Green
        } catch {
            Write-Host ('  证据包打包失败: ' + $_.Exception.Message) -ForegroundColor Yellow
        }

        if ($Config.OpenReportOnFinish -and (Test-Path -LiteralPath $res.Html)) {
            try { Start-Process $res.Html } catch { }
        }
    } catch {
        Write-Host ('[ERROR] 报告生成失败: ' + $_.Exception.Message) -ForegroundColor Red
        Write-Host ($_.ScriptStackTrace) -ForegroundColor DarkRed
        $exitCode = 4
    }
}

# 清理旧会话
try {
    $removed = Remove-OldSessions -DataRoot $DataRoot -ReportRoot $ReportRoot -KeepRuns $Config.KeepRuns -MaxGlobalDataMB $Config.MaxGlobalDataMB
    if ($removed.Count -gt 0) { Write-Host (' 已清理旧会话 ' + $removed.Count + ' 个') -ForegroundColor DarkGray }
} catch { }

Write-Host '-------------------------------------------------------------------' -ForegroundColor DarkGray
Write-Host (' 本次数据量: ' + (Get-DirSizeMB $Session.DataDir) + ' MB   数据目录: ' + $Session.DataDir) -ForegroundColor Green
if ($reportPath) { Write-Host (' 报告: ' + $reportPath) -ForegroundColor Green }
Write-Host ' NetWatch 已退出。' -ForegroundColor Cyan
Write-Host ''

exit $exitCode
