# Forensics.ps1 - 事后取证：异常刚刚过去时使用
# 作用：补采最近若干小时的事件日志 + 立即抓一次完整快照 + 短时高频采集，然后自动出报告

[CmdletBinding()]
param(
    [double]$Hours = 6,       # 回溯事件日志的小时数
    [int]$Minutes = 3,        # 短时采集分钟数
    [string]$Label = 'forensics'
)

$scripts = $PSScriptRoot
$main = Join-Path $scripts 'NetWatch.ps1'
if (-not (Test-Path -LiteralPath $main)) { Write-Host '缺少 NetWatch.ps1' -ForegroundColor Red; exit 2 }

& $main -Minutes $Minutes -LookbackHours $Hours -ForceSnapshot -Label $Label @args
exit $LASTEXITCODE
