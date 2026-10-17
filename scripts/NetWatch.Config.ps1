# NetWatch.Config.ps1 - 配置加载与默认值
# 所有默认值都可被 config.json 覆盖；命令行参数优先级最高

function Get-DefaultConfig {
    return [pscustomobject]@{
        # ---------- 会话上限（硬性） ----------
        DurationMinutes        = 20      # 默认运行时长
        MaxDurationMinutes     = 120     # 绝对上限，超过会被拒绝
        MaxDataMB              = 300     # 单次会话数据上限（不含抓包），超限立即收尾
        PktmonMaxMB            = 64      # pktmon 环形缓冲上限（MB），同时约束其内核缓冲占用
        MaxGlobalDataMB        = 2048    # data+reports 总量上限，超出最旧会话
        KeepRuns               = 6       # 保留最近 N 次会话
        MinFreeDiskGB          = 3       # D 盘可用空间低于此值不启动/立即收尾
        MaxIncidents           = 10      # 单次会话最多几次触发式快照
        MaxIncidentDirMB       = 40      # 单个快照目录上限
        MaxRowsPerFile         = 400000  # 单个 CSV 行数保险丝

        # ---------- 采集频率（秒） ----------
        IcmpIntervalSec        = 1
        BurstIcmpIntervalSec   = 0.25
        BurstSeconds           = 60
        WifiIntervalSec        = 5
        NeighborScanSec        = 120
        DnsIntervalSec         = 15
        L7IntervalSec          = 30
        SysIntervalSec         = 10
        ProcIntervalSec        = 15
        EventIntervalSec       = 5
        ProxyCheckSec          = 10

        # ---------- 开关 ----------
        EnablePktmon           = $true
        EnableNeighborScan     = $true
        EnableProxyProbe       = $true
        EnableL7Probe          = $true
        EnableEventLog         = $true
        EnableProcessProbe     = $true
        EventLookbackMinutes   = 30      # 启动时补采的历史事件窗口
        IncidentCooldownSec    = 180
        OpenReportOnFinish     = $false
        IncludePcapInZip       = $false

        # ---------- 网卡与网关 ----------
        WlanInterface          = 'WLAN'
        GatewayHost            = ''       # 留空则自动探测默认网关
        DetectedDns            = @()      # 运行时自动填充：本机系统 DNS（只读探测，不修改）

        # ---------- ICMP 目标（分层） ----------
        # host 留空 = 运行时自动填充（gateway 用默认网关，local-dns 用系统 DNS）。
        # 默认目标全部是中立、全球可达的地址；换成你自己的网关/内网地址也无妨。
        IcmpTargets            = @(
            @{ name = 'gateway';       host = '';                       layer = 'L2/L3 本地网关'; warn = 50;  crit = 150 },
            @{ name = 'local-dns';     host = '';                       layer = '内网 DNS';       warn = 100; crit = 300 },
            @{ name = 'cloudflare';    host = '1.1.1.1';                layer = '公网 IPv4';      warn = 80;  crit = 300 },
            @{ name = 'alidns';        host = '223.5.5.5';              layer = '公网 IPv4';      warn = 80;  crit = 300 },
            @{ name = 'google-dns';    host = '8.8.8.8';                layer = '公网 IPv4 海外'; warn = 250; crit = 800 },
            @{ name = 'quad9';         host = '9.9.9.9';                layer = '公网 IPv4';      warn = 80;  crit = 300 },
            @{ name = 'cloudflare-v6'; host = '2606:4700:4700::1111';   layer = '公网 IPv6';      warn = 100; crit = 400 }
        )

        # ---------- DNS 探测 ----------
        # 用全球可解析、不被区域性屏蔽的域名；服务器列表会在运行时并入本机系统 DNS
        DnsNames               = @('www.microsoft.com', 'www.cloudflare.com', 'www.apple.com')
        DnsServers             = @('1.1.1.1')

        # ---------- L7 / 代理对照 ----------
        ProxyPort              = 0          # 0 = 自动从系统代理设置读取；也可写死端口号
        L7Targets              = @(
            @{ name = 'baidu';        url = 'https://www.baidu.com/';                layer = 'L7 国内' },
            @{ name = 'gstatic-204';  url = 'https://www.gstatic.com/generate_204';  layer = 'L7 海外' }
        )
        L7TimeoutSec           = 8
    }
}

function Merge-ConfigObject {
    param($Base, $Override)
    if ($null -eq $Override) { return $Base }
    foreach ($p in $Override.PSObject.Properties) {
        $name = $p.Name
        if ($Base.PSObject.Properties.Match($name).Count -gt 0) {
            $Base.$name = $p.Value
        } else {
            $Base | Add-Member -NotePropertyName $name -NotePropertyValue $p.Value -Force
        }
    }
    return $Base
}

function Get-NetWatchConfig {
    param(
        [string]$ConfigPath = $null,
        [hashtable]$Override = @{}
    )
    $cfg = Get-DefaultConfig
    if ($ConfigPath -and (Test-Path -LiteralPath $ConfigPath)) {
        try {
            $json = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $cfg = Merge-ConfigObject -Base $cfg -Override $json
        } catch {
            Write-Host ("[WARN] config.json 解析失败，使用内置默认值: " + $_.Exception.Message) -ForegroundColor Yellow
        }
    }
    foreach ($k in $Override.Keys) {
        if ($null -ne $Override[$k]) { $cfg.$k = $Override[$k] }
    }

    # 网关自动探测
    if (-not $cfg.GatewayHost -or $cfg.GatewayHost -eq '') {
        $gw = ''
        try {
            $r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                 Where-Object { $_.NextHop -ne '0.0.0.0' } |
                 Sort-Object RouteMetric | Select-Object -First 1
            if ($r) { $gw = [string]$r.NextHop }
        } catch { }
        if (-not $gw) { $gw = '192.168.1.1' }
        $cfg.GatewayHost = $gw
    }
    # 把网关填进第一个 ICMP 目标
    if ($cfg.IcmpTargets.Count -gt 0 -and (-not $cfg.IcmpTargets[0].host -or $cfg.IcmpTargets[0].host -eq '')) {
        $cfg.IcmpTargets[0].host = $cfg.GatewayHost
    }

    # ---- 自动探测本机 DNS（发布版不硬编码任何内网地址）----
    $sysDns = New-Object System.Collections.ArrayList
    try {
        $raw = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
                 Where-Object { $_.InterfaceAlias -eq $cfg.WlanInterface -and $_.ServerAddresses } |
                 ForEach-Object { $_.ServerAddresses })
        if ($raw.Count -eq 0) {
            $raw = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
                     Where-Object { $_.ServerAddresses } | ForEach-Object { $_.ServerAddresses })
        }
        foreach ($d in $raw) {
            if ($d -and ([string]$d) -match '^\d{1,3}(\.\d{1,3}){3}$') { [void]$sysDns.Add([string]$d) }
        }
    } catch { }
    $sysDns = @($sysDns | Select-Object -Unique)
    $cfg.DetectedDns = $sysDns

    # 用探测到的 DNS 填充 local-dns 目标
    if ($sysDns.Count -gt 0) {
        foreach ($t in $cfg.IcmpTargets) {
            if ($t.name -eq 'local-dns' -and (-not $t.host -or $t.host -eq '')) { $t.host = $sysDns[0] }
        }
    }

    # DNS 探测目标 = 系统 DNS + 配置里的公共 DNS（去重）
    $dnsList = New-Object System.Collections.ArrayList
    foreach ($d in $sysDns) { if ($d) { [void]$dnsList.Add([string]$d) } }
    foreach ($d in @($cfg.DnsServers)) { if ($d) { [void]$dnsList.Add([string]$d) } }
    $cfg.DnsServers = @($dnsList | Select-Object -Unique)

    # 代理端口：配置为 0 时从系统代理设置里自动读取
    if ([int]$cfg.ProxyPort -le 0) {
        $cfg.ProxyPort = 7892
        try {
            $sp0 = Get-SystemProxyState
            if ($sp0.Server -match ':(\d{2,5})') { $cfg.ProxyPort = [int]$Matches[1] }
        } catch { }
    }
    $cfg.ProxyPort = [int]$cfg.ProxyPort

    # 硬性边界校验
    if ($cfg.MaxDurationMinutes -gt 240) { $cfg.MaxDurationMinutes = 240 }
    if ($cfg.DurationMinutes -gt $cfg.MaxDurationMinutes) { $cfg.DurationMinutes = $cfg.MaxDurationMinutes }
    if ($cfg.DurationMinutes -lt 1) { $cfg.DurationMinutes = 1 }

    return $cfg
}
