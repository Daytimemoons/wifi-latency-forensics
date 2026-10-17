# Report-Only.ps1 - 只重新生成报告（不采集）
# 用途：如果采集进程被强制关闭、没来得及出报告，用这个补出报告

[CmdletBinding()]
param(
    [string]$SessionDir = '',   # 指定会话目录；留空则自动取 data\ 下最新的一个
    [switch]$Open
)

$Script:NWRoot = Split-Path -Parent $PSScriptRoot
$dataRoot = Join-Path $Script:NWRoot 'data'

foreach ($m in @('NetWatch.Util.ps1', 'NetWatch.Config.ps1', 'NetWatch.Report.ps1')) {
    $p = Join-Path $PSScriptRoot $m
    if (-not (Test-Path -LiteralPath $p)) { Write-Host ("[FATAL] 缺少模块: " + $p) -ForegroundColor Red; exit 2 }
    . $p
}

if (-not $SessionDir) {
    $cand = @(Get-ChildItem -LiteralPath $dataRoot -Directory -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -like 'session-*' } | Sort-Object Name -Descending)
    if ($cand.Count -eq 0) { Write-Host ('未找到任何会话目录: ' + $dataRoot) -ForegroundColor Red; exit 3 }
    $SessionDir = $cand[0].FullName
}

Write-Host ('正在分析: ' + $SessionDir) -ForegroundColor Cyan
try {
    $res = Invoke-NetWatchAnalysis -SessionDir $SessionDir
    Write-Host ('Markdown : ' + $res.Markdown) -ForegroundColor Green
    Write-Host ('HTML     : ' + $res.Html) -ForegroundColor Green
    Write-Host ('摘要 JSON: ' + $res.Summary) -ForegroundColor Green
    if ($Open) { try { Start-Process $res.Html } catch { } }
} catch {
    Write-Host ('[ERROR] ' + $_.Exception.Message) -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
    exit 4
}
exit 0
