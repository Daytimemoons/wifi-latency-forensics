# NetWatch.Session.ps1 - 会话目录、写入器、限额与标记

function New-NetWatchSession {
    param(
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)][string]$DataRoot,
        [Parameter(Mandatory = $true)][string]$ReportRoot,
        [int]$Minutes,
        [string]$Label = ''
    )

    $name = 'session-' + (Get-StampFile)
    if ($Label) {
        $safe = ($Label -replace '[^0-9A-Za-z_\-\u4e00-\u9fa5]', '_')
        if ($safe.Length -gt 24) { $safe = $safe.Substring(0, 24) }
        $name = $name + '-' + $safe
    }
    $dataDir = Join-Path $DataRoot $name
    $reportDir = Join-Path $ReportRoot $name
    foreach ($d in @($dataDir, $reportDir, (Join-Path $dataDir 'incidents'), (Join-Path $dataDir 'snapshots'))) {
        if (-not (Test-Path -LiteralPath $d)) { [void](New-Item -ItemType Directory -Path $d -Force) }
    }

    $w = @{}
    $w['markers'] = New-CsvWriter -Path (Join-Path $dataDir 'markers.csv') -Header @('ts','kind','detail') -MaxRows $Config.MaxRowsPerFile
    $w['latency_icmp'] = New-CsvWriter -Path (Join-Path $dataDir 'latency_icmp.csv') -Header @('ts','sent_ts','phase','incident','target','host','layer','rtt_ms','status','ttl','src') -MaxRows $Config.MaxRowsPerFile
    $w['dns'] = New-CsvWriter -Path (Join-Path $dataDir 'dns.csv') -Header @('ts','phase','server','name','type','ms','status','answers') -MaxRows $Config.MaxRowsPerFile
    $w['l7'] = New-CsvWriter -Path (Join-Path $dataDir 'l7.csv') -Header @('ts','phase','mode','name','layer','url','ms','status','note') -MaxRows $Config.MaxRowsPerFile
    $w['proxy'] = New-CsvWriter -Path (Join-Path $dataDir 'proxy.csv') -Header @('ts','phase','system_proxy_on','system_proxy_server','listener_up','listener_ms','note') -MaxRows $Config.MaxRowsPerFile
    $w['wifi'] = New-CsvWriter -Path (Join-Path $dataDir 'wifi.csv') -Header @('ts','phase','state','ssid','bssid','band','channel','radio','auth','cipher','rssi','signal_pct','rx_mbps','tx_mbps','local_ip','gw_mac','profile') -MaxRows $Config.MaxRowsPerFile
    $w['neighbors'] = New-CsvWriter -Path (Join-Path $dataDir 'neighbors.csv') -Header @('ts','ssid','bssid','signal_pct','channel','band','radio') -MaxRows $Config.MaxRowsPerFile
    $w['sys'] = New-CsvWriter -Path (Join-Path $dataDir 'sys.csv') -Header @('ts','phase','cpu_pct','mem_free_mb','mem_used_pct','disk_queue','disk_busy_pct','tcp_retrans_ps','tcp_connfail_ps','tcp_connreset_ps','tcp_established','tcp_timewait','wlan_rx_Bps','wlan_tx_Bps','rx_discards','rx_errors','tx_discards','tx_errors','d_free_gb','note') -MaxRows $Config.MaxRowsPerFile
    $w['proc'] = New-CsvWriter -Path (Join-Path $dataDir 'proc.csv') -Header @('ts','phase','pid','name','tcp_conns','timewait','synsent','listen','iobytes_ps') -MaxRows $Config.MaxRowsPerFile

    $session = [pscustomobject]@{
        Name        = $name
        DataDir     = $dataDir
        ReportDir   = $reportDir
        IncidentDir = Join-Path $dataDir 'incidents'
        StartedAt   = Get-Date
        Deadline    = (Get-Date).AddMinutes($Minutes)
        PlannedMin  = $Minutes
        Writers     = $w
        Config      = $Config
        Markers     = New-Object System.Collections.ArrayList
        IncidentCount = 0
        LastIncidentAt = [datetime]::MinValue
        StopReason  = ''
        Pktmon      = $null
        EventState  = $null
        WifiState   = [pscustomobject]@{ Bssid = ''; Rssi = $null; GwMac = ''; LocalIp = '' }
        SysPrev     = $null
        Alerts      = New-Object System.Collections.ArrayList
        BurstUntil  = [datetime]::MinValue
        ScanWindows = New-Object System.Collections.ArrayList
        EventCounts = @{}
        ProbeSet    = $null
        ProxyOn     = $null
        DnsJob      = $null
        DnsNextDue  = (Get-Date)
        L7Job       = $null
        L7NextDue   = (Get-Date)
        LastLimitCheck = [datetime]::MinValue
        LastDataMB  = 0
        Peak        = [pscustomobject]@{
            MaxRtt = @{}; MaxCpu = 0; MaxDiskQueue = 0; MaxRx = 0; MaxTx = 0
            MinRssi = $null; MinRssiAt = $null; LossEvents = 0; SpikeWindows = New-Object System.Collections.ArrayList
            PhaseStats = @{}
        }
    }
    return $session
}

function Add-NetWatchMarker {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$Kind,
        [string]$Detail = ''
    )
    $ts = Get-Stamp
    $enc = [pscustomobject]@{ ts = $ts; kind = $Kind; detail = $Detail }
    [void]$Session.Markers.Add($enc)
    Write-CsvRow -Writer $Session.Writers['markers'] -Values @($ts, $Kind, $Detail)
    try { $Session.Writers['markers'].Writer.Flush() } catch { }
    # 故意不返回对象：避免污染调用者的管道输出
}

function Test-NetWatchLimits {
    # 返回 $null 表示正常；否则返回收尾原因字符串
    param([Parameter(Mandatory = $true)]$Session)

    $now = Get-Date
    if ($now -ge $Session.Deadline) { return 'planned-duration-reached' }

    # 目录扫描与磁盘查询较贵，最多每 10 秒做一次
    if (($now - $Session.LastLimitCheck).TotalSeconds -lt 10) { return $null }
    $Session.LastLimitCheck = $now

    $cfg = $Session.Config
    $sizeMB = Get-TextDataSizeMB $Session.DataDir
    $Session.LastDataMB = $sizeMB
    if ($sizeMB -gt $cfg.MaxDataMB) { return ('data-cap-reached(' + $sizeMB + 'MB>' + $cfg.MaxDataMB + 'MB)') }
    $free = Get-FreeSpaceGB (Get-DriveOfPath $Session.DataDir)
    if ($free -ge 0 -and $free -lt $cfg.MinFreeDiskGB) { return ('low-disk(' + $free + 'GB)') }
    return $null
}

function Save-NetWatchSessionJson {
    param([Parameter(Mandatory = $true)]$Session, [string]$Reason = '')
    $cfg = $Session.Config
    $obj = [pscustomobject]@{
        name            = $Session.Name
        started_at      = (Get-Stamp $Session.StartedAt)
        ended_at        = (Get-Stamp)
        planned_minutes = $Session.PlannedMin
        stop_reason     = $Reason
        data_dir        = $Session.DataDir
        incidents       = $Session.IncidentCount
        data_mb         = (Get-DirSizeMB $Session.DataDir)
        pktmon          = $Session.Pktmon
        gateway         = $cfg.GatewayHost
        icmp_targets    = @($cfg.IcmpTargets | ForEach-Object { $_.name + '=' + $_.host })
        config_effective = [pscustomobject]@{
            duration_minutes = $cfg.DurationMinutes
            max_data_mb      = $cfg.MaxDataMB
            pktmon_max_mb    = $cfg.PktmonMaxMB
            icmp_interval    = $cfg.IcmpIntervalSec
            wifi_interval    = $cfg.WifiIntervalSec
            neighbor_scan_sec = $cfg.NeighborScanSec
            event_interval   = $cfg.EventIntervalSec
            pktmon_enabled   = $cfg.EnablePktmon
            neighbor_scan    = $cfg.EnableNeighborScan
            proxy_probe      = $cfg.EnableProxyProbe
        }
        csv_rows        = @{}
        file_sizes      = @{}
    }
    foreach ($k in $Session.Writers.Keys) { $obj.csv_rows[$k] = $Session.Writers[$k].Rows }
    try {
        Get-ChildItem -LiteralPath $Session.DataDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $obj.file_sizes[$_.Name] = [math]::Round($_.Length / 1KB, 1)
        }
    } catch { }
    $path = Join-Path $Session.DataDir 'session.json'
    $obj | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
    return $path
}

function Remove-OldSessions {
    param(
        [Parameter(Mandatory = $true)][string]$DataRoot,
        [Parameter(Mandatory = $true)][string]$ReportRoot,
        [int]$KeepRuns = 6,
        [int]$MaxGlobalDataMB = 2048
    )
    $removed = New-Object System.Collections.ArrayList
    foreach ($root in @($DataRoot, $ReportRoot)) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $dirs = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
        if ($dirs.Count -gt $KeepRuns) {
            foreach ($d in $dirs[$KeepRuns..($dirs.Count - 1)]) {
                try { Remove-Item -LiteralPath $d.FullName -Recurse -Force -ErrorAction Stop; [void]$removed.Add($d.FullName) } catch { }
            }
        }
    }
    # 全局容量保险
    $guard = 0
    while ($guard -lt 50) {
        $guard++
        $total = (Get-DirSizeMB $DataRoot) + (Get-DirSizeMB $ReportRoot)
        if ($total -le $MaxGlobalDataMB) { break }
        $oldest = @(Get-ChildItem -LiteralPath $DataRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -First 1)
        if ($oldest.Count -eq 0) { break }
        try { Remove-Item -LiteralPath $oldest[0].FullName -Recurse -Force -ErrorAction Stop; [void]$removed.Add($oldest[0].FullName) } catch { break }
    }
    return $removed
}
