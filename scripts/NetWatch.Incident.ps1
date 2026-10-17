# NetWatch.Incident.ps1 - 异常判定与触发式快照

function Get-SafeName {
    param([string]$Text, [int]$Max = 28)
    if (-not $Text) { return 'incident' }
    $s = ($Text -replace '[^0-9A-Za-z_\-\u4e00-\u9fa5]', '_')
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) }
    if (-not $s) { $s = 'incident' }
    return $s
}

function Test-IncidentTrigger {
    param([Parameter(Mandatory = $true)]$Session, $Samples)
    foreach ($s in $Samples) {
        if ($s.ConsecFail -ge 3) { return ($s.Target + '-连续' + $s.ConsecFail + '次不通') }
        if ($s.ConsecSlow -ge 3) { return ($s.Target + '-连续' + $s.ConsecSlow + '次超阈值') }
    }
    return ''
}

function Request-Incident {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$Reason,
        [switch]$Force
    )
    if (-not $Force) {
        if (((Get-Date) - $Session.LastIncidentAt).TotalSeconds -lt [double]$Session.Config.IncidentCooldownSec) { return $null }
    }
    if ($Session.IncidentCount -ge [int]$Session.Config.MaxIncidents) {
        Add-NetWatchMarker -Session $Session -Kind 'incident-suppressed' -Detail ('上限已达; ' + $Reason)
        return $null
    }
    try {
        return (Invoke-IncidentSnapshot -Session $Session -Reason $Reason)
    } catch {
        Add-NetWatchMarker -Session $Session -Kind 'incident-error' -Detail $_.Exception.Message
        return $null
    }
}

function Invoke-IncidentSnapshot {
    param([Parameter(Mandatory = $true)]$Session, [Parameter(Mandatory = $true)][string]$Reason)

    $Session.IncidentCount++
    $Session.LastIncidentAt = Get-Date
    $dir = Join-Path $Session.IncidentDir ('{0:d2}-{1}-{2}' -f $Session.IncidentCount, (Get-StampFile), (Get-SafeName $Reason))
    if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }

    Add-NetWatchMarker -Session $Session -Kind 'incident' -Detail ('#' + $Session.IncidentCount + ' ' + $Reason + ' -> ' + (Split-Path -Leaf $dir))
    Write-Host ''
    Write-Host ('  >>> 检测到异常，正在抓取快照 #' + $Session.IncidentCount + ' : ' + $Reason) -ForegroundColor Red

    $maxBytes = [double]$Session.Config.MaxIncidentDirMB * 1MB
    $written = 0.0
    $budgetHit = $false

    $save = {
        param([string]$FileName, [string[]]$Lines)
        if ($script:__nw_budgetHit) { return }
        if ($null -eq $Lines) { $Lines = @() }
        if ($Lines.Count -gt 1200) { $Lines = $Lines[0..1199] + @('... (截断)') }
        $p = Join-Path $dir $FileName
        try {
            Set-Content -LiteralPath $p -Value $Lines -Encoding UTF8
            $script:__nw_written += (Get-Item -LiteralPath $p).Length
            if ($script:__nw_written -gt $maxBytes) { $script:__nw_budgetHit = $true }
        } catch { }
    }
    $script:__nw_written = 0.0
    $script:__nw_budgetHit = $false

    # --- 原始快照（全部只读命令） ---
    & $save 'netsh-wlan-interfaces.txt'  (Invoke-Native -Exe 'netsh' -Arguments @('wlan', 'show', 'interfaces') -TimeoutMs 10000).Output
    & $save 'netsh-wlan-networks.txt'    (Invoke-Native -Exe 'netsh' -Arguments @('wlan', 'show', 'networks', 'mode=bssid') -TimeoutMs 20000).Output
    & $save 'ipconfig-all.txt'           (Invoke-Native -Exe 'ipconfig' -Arguments @('/all') -TimeoutMs 10000).Output
    & $save 'arp-a.txt'                  (Invoke-Native -Exe 'arp' -Arguments @('-a') -TimeoutMs 10000).Output
    & $save 'route-print.txt'            (Invoke-Native -Exe 'route' -Arguments @('print') -TimeoutMs 10000).Output
    & $save 'netstat-ano.txt'            (Invoke-Native -Exe 'netstat' -Arguments @('-ano') -TimeoutMs 15000).Output

    try { & $save 'adapter-stats.txt' (@(Get-NetAdapterStatistics | Format-List | Out-String) -split "`r?`n") } catch { }
    try {
        $cs = Get-NetTCPConnection -ErrorAction Stop
        $lines = @()
        $lines += '== 状态分布 =='
        $lines += ($cs | Group-Object State | Sort-Object Count -Descending | ForEach-Object { '{0,-12} {1}' -f $_.Name, $_.Count })
        $lines += ''
        $lines += '== 按进程 =='
        $lines += ($cs | Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 25 | ForEach-Object {
            $p = Get-Process -Id $_.Name -ErrorAction SilentlyContinue
            '{0,6}  {1,-24} {2}' -f $_.Count, ([string]$_.Name), $(if ($p) { $p.ProcessName } else { '?' })
        })
        & $save 'tcp-connections.txt' $lines
    } catch { }
    try { & $save 'dns-client-cache.txt' (@(Get-DnsClientCache -ErrorAction Stop | Select-Object -First 300 | Format-Table -AutoSize | Out-String) -split "`r?`n") } catch { }
    try { & $save 'ip-config.txt' (@(Get-NetIPConfiguration | Format-List | Out-String) -split "`r?`n") } catch { }
    try { & $save 'neighbors.txt' (@(Get-NetNeighbor -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String) -split "`r?`n") } catch { }
    try { & $save 'pktmon-status.txt' (Invoke-Native -Exe 'pktmon' -Arguments @('status') -TimeoutMs 10000).Output } catch { }
    try { & $save 'events-recent.txt' (Get-RecentEventLines -Session $Session -Minutes 30 -MaxLines 300) } catch { }

    # --- 摘要 ---
    $sum = New-Object System.Collections.ArrayList
    [void]$sum.Add('NetWatch 异常快照 #' + $Session.IncidentCount)
    [void]$sum.Add('触发原因 : ' + $Reason)
    [void]$sum.Add('触发时间 : ' + (Get-Stamp))
    [void]$sum.Add('会话开始 : ' + (Get-Stamp $Session.StartedAt))
    [void]$sum.Add('计划结束 : ' + (Get-Stamp $Session.Deadline))
    [void]$sum.Add('当前相位 : ' + (Get-CurrentPhase -Session $Session) + '  (系统代理=' + $Session.ProxyOn + ')')
    [void]$sum.Add('网关     : ' + $Session.Config.GatewayHost + '  MAC=' + $Session.WifiState.GwMac)
    [void]$sum.Add('无线     : SSID=' + $Session.WifiState.Ssid + ' BSSID=' + $Session.WifiState.Bssid + ' RSSI=' + $Session.WifiState.Rssi)
    [void]$sum.Add('本机 IP  : ' + $Session.WifiState.LocalIp)
    [void]$sum.Add('抓包     : ' + $(if ($Session.Pktmon -and $Session.Pktmon.started) { '运行中 ' + $Session.Pktmon.etl } else { '未运行' }))
    [void]$sum.Add('')
    [void]$sum.Add('== 快照时各目标累计统计 ==')
    try {
        foreach ($s in (Get-IcmpSummary -ProbeSet $Session.ProbeSet)) {
            [void]$sum.Add(('  {0,-12} {1,-20} 发送={2} 收到={3} 丢={4}({5}%) p50={6} p95={7} max={8}' -f `
                $s.Name, $s.Host, $s.Sent, $s.Recv, $s.Lost, $s.LossPct, (Num $s.P50 1), (Num $s.P95 1), (Num $s.Max 1)))
        }
    } catch { }
    & $save 'summary.txt' @($sum)

    # --- 进入高频模式 ---
    $Session.BurstUntil = (Get-Date).AddSeconds([double]$Session.Config.BurstSeconds)
    Write-Host ('      已进入 ' + $Session.Config.BurstSeconds + ' 秒高频采集 (' + $Session.Config.BurstIcmpIntervalSec + 's/次)') -ForegroundColor Red
    Write-Host ''

    return $dir
}
