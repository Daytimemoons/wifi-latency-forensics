# NetWatch.Events.ps1 - Windows 事件日志增量采集（无线驱动 / WLAN 服务 / NDIS / DHCP / 电源）
#
# 关键教训：Get-WinEvent 的 ProviderName 过滤里只要有一个提供程序在本机不存在，
# 整条查询就会直接失败（"没有与 X 匹配的事件提供程序"）——而且是静默丢数据。
# 因此这里必须：先枚举本机真实存在的提供程序做交集；查询失败再退化为
# "只按日志+时间取回来，再在内存里按 provider 过滤"。

$Script:EventSpecs = @(
    @{ Log = 'System'
       Providers = @('Netwtw14', 'Netwtw16', 'Netwtw12', 'Netwtw10',
                     'Microsoft-Windows-NDIS', 'Microsoft-Windows-TCPIP',
                     'Microsoft-Windows-Kernel-Power', 'Microsoft-Windows-Dhcp-Client',
                     'Microsoft-Windows-WLAN-Driver', 'Microsoft-Windows-WLAN-AutoConfig',
                     'Wlansvc', 'Tcpip', 'Tcpip6') },
    @{ Log = 'Microsoft-Windows-WLAN-AutoConfig/Operational'; Providers = $null },
    @{ Log = 'Microsoft-Windows-Dhcp-Client/Admin'; Providers = $null },
    @{ Log = 'Microsoft-Windows-NetworkProfile/Operational'; Providers = $null }
)

function Get-AvailableProviderSet {
    # 注意：必须用 SilentlyContinue —— 本机存在个别损坏的提供程序
    # (Microsoft-Windows-DxgKrnl-SysMm)，一旦 -ErrorAction Stop 会中断整个枚举，得到 0 个。
    $set = @{}
    try {
        foreach ($p in (Get-WinEvent -ListProvider * -ErrorAction SilentlyContinue)) {
            if ($p.Name) { $set[[string]$p.Name] = $true }
        }
    } catch { }
    return $set
}

function New-EventState {
    $avail = Get-AvailableProviderSet
    $specs = New-Object System.Collections.ArrayList
    $used = New-Object System.Collections.ArrayList
    foreach ($s in $Script:EventSpecs) {
        $provs = $null
        if ($s.Providers) {
            if ($avail.Count -gt 0) {
                $keep = @($s.Providers | Where-Object { $avail.ContainsKey([string]$_) })
                if ($keep.Count -eq 0) { continue }
                $provs = $keep
            } else {
                $provs = $s.Providers
            }
            foreach ($k in $provs) { [void]$used.Add($k) }
        }
        [void]$specs.Add(@{ Log = $s.Log; Providers = $provs })
    }
    $st = [pscustomobject]@{
        Seen                   = @{}
        Specs                  = $specs
        LastScan               = (Get-Date).AddSeconds(-2)
        Count                  = 0
        ResolvedProviders      = @($used)
        AvailableProviderCount = $avail.Count
    }
    return $st
}

function Convert-EventProperties {
    param($Event)
    $props = New-Object System.Collections.ArrayList
    try {
        foreach ($p in $Event.Properties) {
            if ($props.Count -ge 256) { break }
            $v = $null
            try { $v = $p.Value } catch { $v = $null }
            if ($null -eq $v) { $s = '' }
            elseif ($v -is [System.Array]) {
                $s = (@($v | ForEach-Object { [string]$_ }) -join ',')
            } else { $s = [string]$v }
            if ($s.Length -gt 96) { $s = $s.Substring(0, 96) }
            [void]$props.Add($s)
        }
    } catch { }
    return @($props)
}

function Get-EventsRaw {
    # 单条查询；失败返回 $null；带 provider 过滤失败时自动退化为无过滤查询
    param($Spec, [datetime]$Since, [int]$MaxEvents = 400)

    $fh = @{ LogName = $Spec.Log; StartTime = $Since }
    if ($Spec.Providers) { $fh['ProviderName'] = $Spec.Providers }
    try {
        return @(Get-WinEvent -FilterHashtable $fh -MaxEvents $MaxEvents -ErrorAction Stop)
    } catch { }

    try {
        $all = @(Get-WinEvent -FilterHashtable @{ LogName = $Spec.Log; StartTime = $Since } -MaxEvents ($MaxEvents * 3) -ErrorAction Stop)
        if ($Spec.Providers) {
            $all = @($all | Where-Object { $Spec.Providers -contains [string]$_.ProviderName })
        }
        return @($all | Select-Object -First $MaxEvents)
    } catch { }
    return $null
}

function Get-NewEventRecords {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][datetime]$Since,
        [int]$MaxEvents = 400
    )
    $out = New-Object System.Collections.ArrayList
    $st = $Session.EventState
    foreach ($spec in $st.Specs) {
        $evs = Get-EventsRaw -Spec $spec -Since $Since -MaxEvents $MaxEvents
        if ($null -eq $evs) { continue }
        foreach ($e in $evs) {
            $key = ($spec.Log + ':' + $e.RecordId)
            if ($st.Seen.ContainsKey($key)) { continue }
            $st.Seen[$key] = $true
            [void]$out.Add([pscustomobject]@{ Log = $spec.Log; Event = $e })
        }
    }
    if ($st.Seen.Count -gt 40000) { $st.Seen = @{} }
    return $out
}

function Write-EventRecords {
    param(
        [Parameter(Mandatory = $true)]$Session,
        $Records
    )
    $path = Join-Path $Session.DataDir 'events.jsonl'
    $n = 0
    foreach ($r in $Records) {
        $e = $r.Event
        $props = Convert-EventProperties -Event $e
        $msg = ''
        try { $msg = [string]$e.Message } catch { $msg = '' }
        if ($msg.Length -gt 4000) { $msg = $msg.Substring(0, 4000) }
        $obj = [pscustomobject]@{
            ts        = (Get-Stamp $e.TimeCreated)
            log       = $r.Log
            provider  = [string]$e.ProviderName
            id        = [int]$e.Id
            level     = [string]$e.LevelDisplayName
            record_id = [int]$e.RecordId
            message   = $msg
            props     = @($props)
        }
        Write-JsonLine -Path $path -Object $obj
        $ck = ([string]$e.ProviderName + '#' + [string]$e.Id)
        if (-not $Session.EventCounts.ContainsKey($ck)) { $Session.EventCounts[$ck] = 0 }
        $Session.EventCounts[$ck] = $Session.EventCounts[$ck] + 1
        $n++
    }
    return $n
}

function Invoke-EventScan {
    param([Parameter(Mandatory = $true)]$Session)
    $st = $Session.EventState
    $since = $st.LastScan
    $st.LastScan = (Get-Date).AddSeconds(-2)
    $recs = Get-NewEventRecords -Session $Session -Since $since
    $n = 0
    if ($recs.Count -gt 0) { $n = Write-EventRecords -Session $Session -Records $recs }
    return $n
}

function Write-EventLookback {
    # 会话开始时补采一段历史事件
    param([Parameter(Mandatory = $true)]$Session, [int]$Minutes = 30)
    $since = (Get-Date).AddMinutes(-1 * $Minutes)
    $recs = Get-NewEventRecords -Session $Session -Since $since -MaxEvents 1200
    $n = 0
    if ($recs.Count -gt 0) { $n = Write-EventRecords -Session $Session -Records $recs }
    Add-NetWatchMarker -Session $Session -Kind 'event-lookback' -Detail ($Minutes.ToString() + 'min -> ' + $n + ' records')
    return $n
}

function Get-RecentEventLines {
    param([Parameter(Mandatory = $true)]$Session, [int]$Minutes = 30, [int]$MaxLines = 200)
    $since = (Get-Date).AddMinutes(-1 * $Minutes)
    $lines = New-Object System.Collections.ArrayList
    foreach ($spec in $Session.EventState.Specs) {
        $evs = Get-EventsRaw -Spec $spec -Since $since -MaxEvents $MaxLines
        if ($null -eq $evs) { continue }
        foreach ($e in $evs) {
            [void]$lines.Add(('{0}  {1}  id={2}  {3}' -f $e.TimeCreated.ToString('MM-dd HH:mm:ss'), $e.ProviderName, $e.Id, (($e.Message -split "`r?`n")[0])))
            if ($lines.Count -ge $MaxLines) { break }
        }
        if ($lines.Count -ge $MaxLines) { break }
    }
    return $lines
}
