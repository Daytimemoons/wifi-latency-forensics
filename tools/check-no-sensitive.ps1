# check-no-sensitive.ps1 - refuse to publish your own network data
#
# NetWatch writes real traffic captures, event logs and connection tables into
# data/ and reports/. Once such a file is committed it is in the git history
# forever and a public repository is indexed within minutes.
#
# Run this before every commit:
#     .\tools\check-no-sensitive.ps1            # checks tracked files
#     .\tools\check-no-sensitive.ps1 -All       # checks the whole working tree
#
# Exit code 1 means "something matched". Fix or remove the file, do not commit.
#
# Conventions that let the guard tell documentation from real data:
#   * placeholder MACs must start with  aa:bb:cc:
#   * placeholder private IPs must be 192.168.1.1 or 192.168.0.1
#   * placeholder SSIDs should be generic names such as CampusWiFi

[CmdletBinding()]
param(
    [switch]$All,
    [string]$Root = ''
)

$ErrorActionPreference = 'Stop'

if (-not $Root) { $Root = Split-Path -Parent $PSScriptRoot }
if (-not (Test-Path -LiteralPath $Root)) { 'Root not found: ' + $Root; exit 2 }

# Files whose own text legitimately contains the patterns below.
$selfSkip = @('tools/check-no-sensitive.ps1')

$pathRules = @(
    @{ name = 'session data directory'; re = '^(data|reports)(/|\\|$)' },
    @{ name = 'packet capture / archive'; re = '\.(etl|pcapng|pcap|zip)$' },
    @{ name = 'per-machine config'; re = '^config\.json$' }
)

$contentRules = @(
    @{ name = 'private IPv4 address'; re = '\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b' },
    @{ name = 'MAC address';          re = '\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b' },
    @{ name = 'GitHub token';         re = '\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b' },
    @{ name = 'user profile path';    re = '[A-Za-z]:\\Users\\[A-Za-z0-9._-]+' }
)

function Test-Exempt {
    param([string]$Rule, [string]$Value)
    if ($Rule -eq 'private IPv4 address') {
        if ($Value -eq '192.168.1.1' -or $Value -eq '192.168.0.1') { return $true }
        return $false
    }
    if ($Rule -eq 'MAC address') {
        if ($Value -match '^aa:bb:cc:') { return $true }
        if ($Value -match '^(00[:-]){5}00$') { return $true }
        return $false
    }
    return $false
}

function Get-TargetFiles {
    if ($All) {
        return @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force -ErrorAction SilentlyContinue |
                 Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' } |
                 ForEach-Object { $_.FullName.Substring($Root.Length).TrimStart('\', '/').Replace('\', '/') })
    }
    $prev = Get-Location
    try {
        Set-Location -LiteralPath $Root
        $out = @(& git ls-files 2>$null)
        if ($LASTEXITCODE -ne 0 -or $out.Count -eq 0) {
            Write-Host '[warn] git ls-files returned nothing; falling back to -All' -ForegroundColor Yellow
            return Get-TargetFiles
        }
        return $out
    } finally {
        Set-Location $prev
    }
}

$binaryExt = @('.png', '.jpg', '.jpeg', '.gif', '.ico', '.zip', '.gz', '.7z',
               '.pcapng', '.pcap', '.etl', '.exe', '.dll', '.pdf')
$hits = New-Object System.Collections.ArrayList
$files = @(Get-TargetFiles)
$scanned = 0

foreach ($rel in $files) {
    $relNorm = ([string]$rel).Replace('\', '/')

    foreach ($r in $pathRules) {
        if ($relNorm -match $r.re) {
            [void]$hits.Add([pscustomobject]@{ file = $relNorm; line = 0; rule = $r.name; text = '(file path)' })
        }
    }

    if ($selfSkip -contains $relNorm) { continue }
    $ext = [System.IO.Path]::GetExtension($relNorm).ToLowerInvariant()
    if ($binaryExt -contains $ext) { continue }

    $full = Join-Path $Root $relNorm
    if (-not (Test-Path -LiteralPath $full)) { continue }
    $scanned++

    $lineNo = 0
    foreach ($line in (Get-Content -LiteralPath $full -Encoding UTF8 -ErrorAction SilentlyContinue)) {
        $lineNo++
        foreach ($r in $contentRules) {
            foreach ($m in [regex]::Matches($line, $r.re)) {
                if (Test-Exempt -Rule $r.name -Value $m.Value) { continue }
                $text = $line.Trim()
                if ($text.Length -gt 120) { $text = $text.Substring(0, 120) + '…' }
                [void]$hits.Add([pscustomobject]@{ file = $relNorm; line = $lineNo; rule = $r.name; text = $text })
            }
        }
    }
}

Write-Host ''
Write-Host ('checked ' + $scanned + ' text file(s) out of ' + $files.Count + ' path(s)') -ForegroundColor DarkGray

if ($hits.Count -eq 0) {
    Write-Host 'PASS - nothing sensitive found.' -ForegroundColor Green
    exit 0
}

Write-Host ''
Write-Host ('FAIL - ' + $hits.Count + ' problem(s) found:') -ForegroundColor Red
$hits | ForEach-Object {
    Write-Host ('  {0}:{1}  [{2}]' -f $_.file, $_.line, $_.rule) -ForegroundColor Red
    if ($_.text) { Write-Host ('      ' + $_.text) -ForegroundColor DarkGray }
}
Write-Host ''
Write-Host 'Do not commit this. Remove the file, or replace the value with a documented placeholder:' -ForegroundColor Yellow
Write-Host '  MAC -> aa:bb:cc:00:00:01    private IP -> 192.168.1.1    SSID -> CampusWiFi' -ForegroundColor Yellow
exit 1
