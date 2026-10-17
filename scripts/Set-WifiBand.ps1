# Set-WifiBand.ps1 - 无线频段偏好 / 漫游积极性 切换与回退
#
# 背景（真实案例，见 docs/case-study-2026-10-18.md）：
#       一台笔记本长时间粘在 2.4 GHz 的 AP 上，其接收协商速率只有 6.5 Mbps，
#       导致本地网关 p50 297 ms、丢包 13.8%、TCP 重传 16.9/s；
#       一旦漫游到同 SSID 的 5 GHz AP（360 Mbps），这些数字立刻变成
#       p50 4 ms、丢包 0%、重传 <1.4/s。改这两个属性可显著降低复发概率。
#
# 本脚本只改网卡驱动的两个高级属性（HKLM 下驱动参数），不改网络配置、不动防火墙。
# 默认行为：首选 5GHz + 漫游中高。  -Revert 恢复出厂默认（无首选项 + 中间）。
#
# 用法：
#   .\scripts\Set-WifiBand.ps1            # 应用 5GHz 优先
#   .\scripts\Set-WifiBand.ps1 -Revert    # 回退到默认
#   .\scripts\Set-WifiBand.ps1 -Show      # 只看当前值

[CmdletBinding()]
param(
    [switch]$Revert,
    [switch]$Show,
    [string]$Interface = 'WLAN'
)

$ErrorActionPreference = 'Stop'

function Show-One {
    param([string]$Keyword)
    $p = Get-NetAdapterAdvancedProperty -Name $Interface -RegistryKeyword $Keyword -ErrorAction SilentlyContinue
    if ($p) { '  {0,-12} = {1}' -f $p.DisplayName, $p.DisplayValue }
    else { '  {0,-12} = (不存在)' -f $Keyword }
}

function Show-All {
    '当前值：'
    Show-One 'RoamingPreferredBandType'
    Show-One 'RoamAggressiveness'
}

if ($Show) { Show-All; exit 0 }

try {
    if ($Revert) {
        Set-NetAdapterAdvancedProperty -Name $Interface -RegistryKeyword 'RoamingPreferredBandType' -DisplayValue '1. 无首选项' -NoRestart
        Set-NetAdapterAdvancedProperty -Name $Interface -RegistryKeyword 'RoamAggressiveness' -DisplayValue '3. 中间' -NoRestart
        '已回退：首选频带 = 无首选项，漫游主动性 = 3.中间'
    } else {
        Set-NetAdapterAdvancedProperty -Name $Interface -RegistryKeyword 'RoamingPreferredBandType' -DisplayValue '3. 首选 5GHz 频带' -NoRestart
        Set-NetAdapterAdvancedProperty -Name $Interface -RegistryKeyword 'RoamAggressiveness' -DisplayValue '4. 中高' -NoRestart
        '已应用：首选频带 = 首选 5GHz，漫游主动性 = 4.中高'
    }
} catch {
    "[FAIL] $($_.Exception.Message)"
    exit 1
}

''
Show-All
''
'设置会在下次关联时生效。想立刻生效：'
'  netsh wlan disconnect'
'  netsh wlan connect name="<your Wi-Fi profile>"    # see: netsh wlan show profiles'
''
'注意：这两项是网卡驱动的持久配置，重装驱动会恢复默认。'
