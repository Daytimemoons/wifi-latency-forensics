# NetWatch.System.ps1 - 本机资源、网卡吞吐、TCP 全局计数、进程占用

function Get-CimSafe {
    param([string]$Class, [string]$Filter = $null)
    try {
        if ($Filter) { return Get-CimInstance -ClassName $Class -Filter $Filter -ErrorAction Stop }
        return Get-CimInstance -ClassName $Class -ErrorAction Stop
    } catch { return $null }
}

function Get-TcpConnectionGroups {
    # 返回按 PID 聚合的连接信息；失败返回 $null
    param()
    try {
        $conns = Get-NetTCPConnection -ErrorAction Stop
    } catch {
        return $null
    }
    $map = @{}
    foreach ($c in $conns) {
        $pid_ = [int]$c.OwningProcess
        if (-not $map.ContainsKey($pid_)) {
            $map[$pid_] = [pscustomobject]@{ Pid = $pid_; Total = 0; TimeWait = 0; SynSent = 0; Listen = 0; Established = 0 }
        }
        $e = $map[$pid_]
        $e.Total++
        switch ([string]$c.State) {
            'TimeWait'    { $e.TimeWait++ }
            'SynSent'     { $e.SynSent++ }
            'Listen'      { $e.Listen++ }
            'Established' { $e.Established++ }
        }
    }
    return [pscustomobject]@{ Map = $map; All = $conns }
}

function Invoke-SystemSample {
    param([Parameter(Mandatory = $true)]$Session)
    $cfg = $Session.Config
    $now = Get-Date
    $ts = Get-Stamp
    $phase = Get-CurrentPhase -Session $Session
    $note = ''

    # ---- CPU / 内存 ----
    $cpu = ''
    $c = Get-CimSafe -Class 'Win32_PerfFormattedData_PerfOS_Processor' -Filter "Name='_Total'"
    if ($c) { $cpu = [int]$c.PercentProcessorTime }
    $memFreeMB = ''; $memUsedPct = ''
    $os = Get-CimSafe -Class 'Win32_OperatingSystem'
    if ($os) {
        $memFreeMB = [math]::Round([double]$os.FreePhysicalMemory / 1024, 0)
        $memUsedPct = [math]::Round(100.0 * (1 - ([double]$os.FreePhysicalMemory / [double]$os.TotalVisibleMemorySize)), 1)
    }

    # ---- 磁盘 ----
    $diskQueue = ''; $diskBusy = ''
    $d = Get-CimSafe -Class 'Win32_PerfFormattedData_PerfDisk_PhysicalDisk' -Filter "Name='_Total'"
    if ($d) { $diskQueue = [int]$d.CurrentDiskQueueLength; $diskBusy = [int]$d.PercentDiskTime }

    # ---- TCP 全局（原始累计值 -> 自己算速率） ----
    $retransPs = ''; $connFailPs = ''; $connResetPs = ''; $tcpEstablished = ''
    $t4 = Get-CimSafe -Class 'Win32_PerfRawData_Tcpip_TCPv4'
    if ($t4) {
        $cur = [pscustomobject]@{
            at = $now
            retrans = [double]$t4.SegmentsRetransmittedPersec
            connfail = [double]$t4.ConnectionFailures
            connreset = [double]$t4.ConnectionsReset
            established = [double]$t4.ConnectionsEstablished
        }
        if ($Session.SysPrev -and $Session.SysPrev.Tcp4) {
            $p = $Session.SysPrev.Tcp4
            $dt = ($now - $p.at).TotalSeconds
            if ($dt -gt 0.5) {
                $retransPs = [math]::Round(($cur.retrans - $p.retrans) / $dt, 2)
                $connFailPs = [math]::Round(($cur.connfail - $p.connfail) / $dt, 2)
                $connResetPs = [math]::Round(($cur.connreset - $p.connreset) / $dt, 2)
                if ($retransPs -lt 0) { $retransPs = 0 }
                if ($connFailPs -lt 0) { $connFailPs = 0 }
                if ($connResetPs -lt 0) { $connResetPs = 0 }
            }
        }
        $tcpEstablished = [int]$cur.established
        if ($null -eq $Session.SysPrev) { $Session.SysPrev = [pscustomobject]@{} }
        $Session.SysPrev | Add-Member -NotePropertyName Tcp4 -NotePropertyValue $cur -Force
    }

    # ---- 网卡吞吐 ----
    $rxBps = ''; $txBps = ''
    $rxDisc = ''; $rxErr = ''; $txDisc = ''; $txErr = ''
    try {
        $a = Get-NetAdapterStatistics -Name $cfg.WlanInterface -ErrorAction Stop
        $curA = [pscustomobject]@{
            at = $now
            rx = [double]$a.ReceivedBytes; tx = [double]$a.SentBytes
            rxDisc = [double]$a.ReceivedDiscardedPackets; rxErr = [double]$a.ReceivedPacketErrors
            txDisc = [double]$a.OutboundDiscardedPackets; txErr = [double]$a.OutboundPacketErrors
        }
        if ($Session.SysPrev -and $Session.SysPrev.Adapter) {
            $pa = $Session.SysPrev.Adapter
            $dt = ($now - $pa.at).TotalSeconds
            if ($dt -gt 0.5) {
                $rxBps = [math]::Round(($curA.rx - $pa.rx) / $dt, 0)
                $txBps = [math]::Round(($curA.tx - $pa.tx) / $dt, 0)
                if ($rxBps -lt 0) { $rxBps = 0 }
                if ($txBps -lt 0) { $txBps = 0 }
                $rxDisc = [math]::Round($curA.rxDisc - $pa.rxDisc, 0)
                $rxErr = [math]::Round($curA.rxErr - $pa.rxErr, 0)
                $txDisc = [math]::Round($curA.txDisc - $pa.txDisc, 0)
                $txErr = [math]::Round($curA.txErr - $pa.txErr, 0)
            }
        }
        if ($null -eq $Session.SysPrev) { $Session.SysPrev = [pscustomobject]@{} }
        $Session.SysPrev | Add-Member -NotePropertyName Adapter -NotePropertyValue $curA -Force
    } catch {
        $note = 'adapter-stats-fail'
    }

    # ---- TCP 连接状态（缓存供进程模块复用） ----
    $tcpTimeWait = ''
    $tcpGroups = Get-TcpConnectionGroups
    if ($tcpGroups) {
        $tcpTimeWait = @($tcpGroups.All | Where-Object { [string]$_.State -eq 'TimeWait' }).Count
        $Session.SysPrev | Add-Member -NotePropertyName TcpGroups -NotePropertyValue $tcpGroups -Force
        $Session.SysPrev | Add-Member -NotePropertyName TcpGroupsAt -NotePropertyValue $now -Force
    }

    $freeGB = Get-FreeSpaceGB 'D'

    Write-CsvRow -Writer $Session.Writers['sys'] -Values @(
        $ts, $phase, $cpu, $memFreeMB, $memUsedPct, $diskQueue, $diskBusy,
        $retransPs, $connFailPs, $connResetPs, $tcpEstablished, $tcpTimeWait,
        $rxBps, $txBps, $rxDisc, $rxErr, $txDisc, $txErr, $freeGB, $note
    )

    # 峰值记录
    if ($cpu -ne '' -and [int]$cpu -gt [int]$Session.Peak.MaxCpu) { $Session.Peak.MaxCpu = [int]$cpu }
    if ($diskQueue -ne '' -and [int]$diskQueue -gt [int]$Session.Peak.MaxDiskQueue) { $Session.Peak.MaxDiskQueue = [int]$diskQueue }
    if ($rxBps -ne '' -and [double]$rxBps -gt [double]$Session.Peak.MaxRx) { $Session.Peak.MaxRx = [double]$rxBps }
    if ($txBps -ne '' -and [double]$txBps -gt [double]$Session.Peak.MaxTx) { $Session.Peak.MaxTx = [double]$txBps }

    return [pscustomobject]@{ RxBps = $rxBps; TxBps = $txBps; RetransPs = $retransPs; Cpu = $cpu }
}

function Invoke-ProcessSample {
    param([Parameter(Mandatory = $true)]$Session)
    $now = Get-Date
    $ts = Get-Stamp
    $phase = Get-CurrentPhase -Session $Session

    $groups = $null
    if ($Session.SysPrev -and $Session.SysPrev.TcpGroups -and $Session.SysPrev.TcpGroupsAt -and
        ($now - $Session.SysPrev.TcpGroupsAt).TotalSeconds -lt 12) {
        $groups = $Session.SysPrev.TcpGroups
    } else {
        $groups = Get-TcpConnectionGroups
        if ($groups -and $Session.SysPrev) {
            $Session.SysPrev | Add-Member -NotePropertyName TcpGroups -NotePropertyValue $groups -Force
            $Session.SysPrev | Add-Member -NotePropertyName TcpGroupsAt -NotePropertyValue $now -Force
        }
    }
    if (-not $groups) { return }

    # 进程 IO（粗粒度：含磁盘 IO，仅用于发现"谁在猛跑"）
    $ioMap = @{}
    try {
        $procs = Get-CimInstance -ClassName 'Win32_PerfFormattedData_PerfProc_Process' -ErrorAction Stop
        foreach ($p in $procs) {
            $pn = [string]$p.Name
            if ($pn -eq '_Total' -or $pn -eq 'Idle') { continue }
            $key = [int]$p.IDProcess
            $io = 0.0
            try { $io = [double]$p.IODataBytesPerSec } catch { $io = 0.0 }
            if ($io -gt 0) { $ioMap[$key] = $io }
        }
    } catch { }

    $rows = New-Object System.Collections.ArrayList
    foreach ($pid_ in $groups.Map.Keys) {
        $e = $groups.Map[$pid_]
        $name = ''
        try { $name = (Get-Process -Id $pid_ -ErrorAction Stop).ProcessName } catch { $name = 'pid' + $pid_ }
        $io = 0.0
        if ($ioMap.ContainsKey($pid_)) { $io = $ioMap[$pid_] }
        [void]$rows.Add([pscustomobject]@{
            pid = $pid_; name = $name; conns = $e.Total; timewait = $e.TimeWait
            synsent = $e.SynSent; listen = $e.Listen; io = $io
        })
    }

    $top = @($rows | Sort-Object -Property @{Expression = 'conns'; Descending = $true} | Select-Object -First 15)
    $topIo = @($rows | Sort-Object -Property @{Expression = 'io'; Descending = $true} | Select-Object -First 8)
    $seen = @{}
    foreach ($r in ($top + $topIo)) {
        $k = [string]$r.pid
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        Write-CsvRow -Writer $Session.Writers['proc'] -Values @(
            $ts, $phase, $r.pid, $r.name, $r.conns, $r.timewait, $r.synsent, $r.listen, (Num $r.io 0)
        )
    }
}
