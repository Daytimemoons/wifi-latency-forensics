# NetWatch.Wifi.ps1 - 无线链路层采集（RSSI / 速率 / BSSID / 邻近 AP / 网关 MAC）

function Get-KvValue {
    param($Kv, [string[]]$Aliases)
    foreach ($a in $Aliases) {
        foreach ($k in $Kv.Keys) { if ($k -ieq $a) { return [string]$Kv[$k] } }
    }
    foreach ($a in $Aliases) {
        foreach ($k in $Kv.Keys) { if ($k -like ('*' + $a + '*')) { return [string]$Kv[$k] } }
    }
    return ''
}

function ConvertFrom-NetshLines {
    param([string[]]$Lines)
    $kv = @{}
    foreach ($l in $Lines) {
        # 兼容英文与中文 netsh 输出，以及全角冒号
        $m = [regex]::Match($l, '^\s{2,}([^:：]+?)\s*[:：]\s*(.*)$')
        if ($m.Success) {
            $k = $m.Groups[1].Value.Trim()
            $v = $m.Groups[2].Value.Trim()
            if ($k -ne '' -and -not $kv.ContainsKey($k)) { $kv[$k] = $v }
        }
    }
    return $kv
}

function Get-WlanInterfaceState {
    param([string]$LogPath = $null)
    $r = Invoke-Native -Exe 'netsh' -Arguments @('wlan', 'show', 'interfaces') -TimeoutMs 8000
    if ($r.ExitCode -ne 0 -and $r.Output.Count -eq 0) {
        return [pscustomobject]@{ Ok = $false; Error = ('netsh exit ' + $r.ExitCode + ' ' + $r.Error) }
    }
    $kv = ConvertFrom-NetshLines -Lines $r.Output

    # 注意：netsh 的字段名会随调用环境在英文/中文之间变化，两套别名都要覆盖
    $state = Get-KvValue $kv @('State', '状态')
    $ssid = Get-KvValue $kv @('SSID')
    $bssid = Get-KvValue $kv @('AP BSSID', 'BSSID')
    $band = Get-KvValue $kv @('Band', '波段', '频带')
    $channel = Get-KvValue $kv @('Channel', '通道', '信道')
    $radio = Get-KvValue $kv @('Radio type', '无线电类型', '无线电')
    $auth = Get-KvValue $kv @('Authentication', '身份验证', '验证')
    $cipher = Get-KvValue $kv @('Cipher', '密码')
    $signal = Get-KvValue $kv @('Signal', '信号')
    $rssi = Get-KvValue $kv @('Rssi', 'RSSI', '信号强度')
    $rx = Get-KvValue $kv @('Receive rate (Mbps)', '接收速率(Mbps)', '接收速率')
    $tx = Get-KvValue $kv @('Transmit rate (Mbps)', '传输速率 (Mbps)', '传输速率')
    $profile = Get-KvValue $kv @('Profile', '配置文件')

    $sigPct = ''
    if ($signal -match '(\d+)') { $sigPct = $Matches[1] }
    if ($rssi -match '(-?\d+)') { $rssi = $Matches[1] } else { $rssi = '' }

    return [pscustomobject]@{
        Ok = $true; Error = ''
        State = $state; Ssid = $ssid; Bssid = $bssid; Band = $band
        Channel = $channel; Radio = $radio; Auth = $auth; Cipher = $cipher
        SignalPct = $sigPct; Rssi = $rssi; RxMbps = $rx; TxMbps = $tx; Profile = $profile
        Raw = $r.Output
    }
}

function Format-MacOrEmpty {
    # 全零 / 空 表示 ARP 未解析（链路丢包时常见），不能当成"MAC 变了"
    param([string]$Mac)
    if (-not $Mac) { return '' }
    $m = $Mac.Trim()
    if ($m -match '^(00[-:]){5}00$') { return '' }
    if ($m -match '^0{12}$') { return '' }
    return $m
}

function Get-GatewayMac {
    param([string]$GatewayHost)
    try {
        $n = Get-NetNeighbor -IPAddress $GatewayHost -ErrorAction Stop | Select-Object -First 1
        if ($n) {
            $v = Format-MacOrEmpty ([string]$n.LinkLayerAddress)
            if ($v) { return $v }
        }
    } catch { }
    try {
        $out = (arp -a $GatewayHost) 2>$null
        foreach ($l in $out) {
            if ($l -match ([regex]::Escape($GatewayHost) + '\s+([0-9a-fA-F\-]{17})')) {
                $v = Format-MacOrEmpty $Matches[1]
                if ($v) { return $v }
            }
        }
    } catch { }
    return ''
}

function Get-LocalWlanIPv4 {
    param([string]$IfAlias)
    try {
        $a = Get-NetIPAddress -InterfaceAlias $IfAlias -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 1
        if ($a) { return [string]$a.IPAddress }
    } catch { }
    return ''
}

function Invoke-WifiSample {
    param([Parameter(Mandatory = $true)]$Session)

    $st = Get-WlanInterfaceState
    $cfg = $Session.Config
    $gwMac = Get-GatewayMac -GatewayHost $cfg.GatewayHost
    $localIp = Get-LocalWlanIPv4 -IfAlias $cfg.WlanInterface

    if (-not $st.Ok) {
        Add-NetWatchMarker -Session $Session -Kind 'wifi-read-fail' -Detail $st.Error
    }

    $phase = Get-CurrentPhase -Session $Session
    Write-CsvRow -Writer $Session.Writers['wifi'] -Values @(
        (Get-Stamp), $phase, $st.State, $st.Ssid, $st.Bssid, $st.Band, $st.Channel, $st.Radio,
        $st.Auth, $st.Cipher, $st.Rssi, $st.SignalPct, $st.RxMbps, $st.TxMbps, $localIp, $gwMac, $st.Profile
    )

    # --- 变化检测 ---
    $prev = $Session.WifiState
    $alerts = New-Object System.Collections.ArrayList

    if ($st.Rssi -match '^-?\d+$') {
        $r = [int]$st.Rssi
        if ($null -eq $prev.Rssi -or $r -lt [int]$prev.Rssi) {
            $Session.Peak.MinRssi = $r
            $Session.Peak.MinRssiAt = (Get-Stamp)
        }
        $prev.Rssi = $r
    }

    if ($st.Bssid -and $prev.Bssid -and ($st.Bssid -ne $prev.Bssid)) {
        [void]$alerts.Add([pscustomobject]@{ Kind = 'bssid-change'; Detail = ($prev.Bssid + ' -> ' + $st.Bssid + ' ch=' + $st.Channel) })
    }
    if ($st.Bssid) { $prev.Bssid = $st.Bssid }

    if ($gwMac -and $prev.GwMac -and ($gwMac -ne $prev.GwMac)) {
        [void]$alerts.Add([pscustomobject]@{ Kind = 'gateway-mac-change'; Detail = ($prev.GwMac + ' -> ' + $gwMac + ' (可能是 AP 切换, 也可能是 ARP 异常)') })
    }
    if ($gwMac) { $prev.GwMac = $gwMac }
    if ($localIp) { $prev.LocalIp = $localIp }

    if ($st.State -and $st.State -notmatch 'connected|已连接') {
        [void]$alerts.Add([pscustomobject]@{ Kind = 'wlan-not-connected'; Detail = ('state=' + $st.State) })
    }

    foreach ($a in $alerts) {
        Add-NetWatchMarker -Session $Session -Kind $a.Kind -Detail $a.Detail
        Write-Host ('    [链路事件] ' + $a.Kind + ' : ' + $a.Detail) -ForegroundColor Yellow
        [void]$Session.Alerts.Add([pscustomobject]@{ ts = (Get-Stamp); kind = $a.Kind; detail = $a.Detail })
    }

    return $st
}

function Invoke-NeighborScan {
    param([Parameter(Mandatory = $true)]$Session)
    $started = Get-Stamp
    $r = Invoke-Native -Exe 'netsh' -Arguments @('wlan', 'show', 'networks', 'mode=bssid') -TimeoutMs 15000
    $ended = Get-Stamp

    $rows = New-Object System.Collections.ArrayList
    $curSsid = ''
    $curBssid = ''
    $curSignal = ''
    $curChannel = ''
    $curBand = ''
    $curRadio = ''
    $flush = {
        if ($curBssid -ne '') {
            [void]$rows.Add([pscustomobject]@{
                ssid = $curSsid; bssid = $curBssid; signal = $curSignal
                channel = $curChannel; band = $curBand; radio = $curRadio
            })
        }
    }

    foreach ($l in $r.Output) {
        if ($l -match '^SSID\s+\d+\s*[:：]\s*(.*)$') {
            & $flush
            $curSsid = $Matches[1].Trim(); $curBssid = ''; $curSignal = ''; $curChannel = ''; $curBand = ''; $curRadio = ''
            continue
        }
        if ($l -match '^\s*BSSID\s+\d+\s*[:：]\s*(\S+)') {
            & $flush
            $curBssid = $Matches[1].Trim(); $curSignal = ''; $curChannel = ''; $curBand = ''; $curRadio = ''
            continue
        }
        if ($l -match '^\s*(Signal|信号)\s*[:：]\s*(\d+)%') { $curSignal = $Matches[2]; continue }
        if ($l -match '^\s*(Channel|通道|信道|频道)\s*[:：]\s*(\d+)') { $curChannel = $Matches[2]; continue }
        if ($l -match '^\s*(Band|波段|频带)\s*[:：]\s*(.*)$') { $curBand = $Matches[2].Trim(); continue }
        if ($l -match '^\s*(Radio type|无线电类型|无线电)\s*[:：]\s*(.*)$') { $curRadio = $Matches[2].Trim(); continue }
    }
    & $flush

    $ts = Get-Stamp
    $phase = Get-CurrentPhase -Session $Session
    $count = 0
    foreach ($row in $rows) {
        if ($count -ge 40) { break }
        Write-CsvRow -Writer $Session.Writers['neighbors'] `
            -Values @($ts, $row.ssid, $row.bssid, $row.signal, $row.channel, $row.band, $row.radio)
        $count++
    }
    # 记录扫描窗口，供报告排除"自测造成的干扰"
    [void]$Session.ScanWindows.Add([pscustomobject]@{ start = $started; end = $ended; ap_count = $rows.Count })
}
