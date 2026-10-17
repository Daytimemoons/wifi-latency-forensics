# NetWatch.Util.ps1 - 通用工具函数
# 兼容 Windows PowerShell 5.1

# 注意：故意不启用 Set-StrictMode —— 采集器必须永不因属性缺失而中断

function Get-Stamp {
    param([datetime]$Time = (Get-Date))
    return $Time.ToString('yyyy-MM-dd HH:mm:ss.fff')
}

function Get-StampFile {
    param([datetime]$Time = (Get-Date))
    return $Time.ToString('yyyyMMdd-HHmmss')
}

# 数字格式化（强制不变文化，避免区域设置影响 CSV）
function Num {
    param($Value, [int]$Decimals = 2)
    if ($null -eq $Value) { return '' }
    $d = 0.0
    if (-not [double]::TryParse([string]$Value, [ref]$d)) { return '' }
    if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { return '' }
    return $d.ToString('F' + $Decimals, [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-CsvLine {
    param([object[]]$Values)
    $parts = New-Object System.Collections.ArrayList
    foreach ($v in $Values) {
        if ($null -eq $v) { [void]$parts.Add(''); continue }
        $s = [string]$v
        if ($s -match '[",\r\n]') {
            [void]$parts.Add('"' + ($s -replace '"', '""') + '"')
        } else {
            [void]$parts.Add($s)
        }
    }
    return ($parts -join ',')
}

function New-CsvWriter {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Header,
        [int]$MaxRows = 0
    )
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }

    $enc = New-Object System.Text.UTF8Encoding($false)
    $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
    $sw = New-Object System.IO.StreamWriter($fs, $enc)
    $sw.AutoFlush = $false
    $sw.WriteLine((ConvertTo-CsvLine $Header))

    return [pscustomobject]@{
        Path     = $Path
        Writer   = $sw
        Stream   = $fs
        Header   = $Header
        Rows     = 0
        MaxRows  = $MaxRows
        Overflow = $false
        LastFlush = Get-Date
    }
}

function Write-CsvRow {
    param(
        [Parameter(Mandatory = $true)]$Writer,
        [Parameter(Mandatory = $true)][object[]]$Values
    )
    if ($null -eq $Writer) { return }
    if ($Writer.Overflow) { return }
    if ($Writer.MaxRows -gt 0 -and $Writer.Rows -ge $Writer.MaxRows) {
        $Writer.Overflow = $true
        return
    }
    $Writer.Writer.WriteLine((ConvertTo-CsvLine $Values))
    $Writer.Rows++
}

function Flush-CsvWriters {
    param($Writers, [bool]$Force = $false)
    $now = Get-Date
    foreach ($w in $Writers.Values) {
        if ($null -eq $w) { continue }
        try {
            if ($Force -or ($now - $w.LastFlush).TotalSeconds -ge 2) {
                $w.Writer.Flush()
                $w.LastFlush = $now
            }
        } catch { }
    }
}

function Close-CsvWriters {
    param($Writers)
    foreach ($w in $Writers.Values) {
        if ($null -eq $w) { continue }
        try { $w.Writer.Flush() } catch { }
        try { $w.Writer.Dispose() } catch { }
        try { $w.Stream.Dispose() } catch { }
    }
}

function Write-JsonLine {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Object
    )
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    $json = $Object | ConvertTo-Json -Compress -Depth 5
    Add-Content -LiteralPath $Path -Value $json -Encoding UTF8
}

function Get-DirSizeBytes {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $sum = 0
    try {
        Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $sum += $_.Length }
    } catch { }
    return $sum
}

function Get-DirSizeMB {
    param([string]$Path)
    return [math]::Round((Get-DirSizeBytes $Path) / 1MB, 2)
}

function Get-TextDataSizeMB {
    # 数据量限额只统计文本/结构化数据，不把抓包文件算进去（抓包另有独立上限）
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $sum = 0
    try {
        Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -ne '.etl' -and $_.Extension -ne '.pcapng' } |
            ForEach-Object { $sum += $_.Length }
    } catch { }
    return [math]::Round($sum / 1MB, 2)
}

function Get-DriveOfPath {
    # 从任意路径推导盘符，避免把工具写死成只能跑在某个盘上
    param([string]$Path)
    try {
        $full = [System.IO.Path]::GetFullPath($Path)
        $root = [System.IO.Path]::GetPathRoot($full)
        if ($root) { return $root.TrimEnd('\').TrimEnd(':') }
    } catch { }
    return 'C'
}

function Get-FreeSpaceGB {
    param([string]$DriveLetter = 'C')
    try {
        $d = Get-PSDrive -Name $DriveLetter -ErrorAction Stop
        return [math]::Round($d.Free / 1GB, 2)
    } catch { return -1 }
}

function Invoke-Native {
    # 运行原生程序并把 stdout/stderr 合并为字符串数组；永不抛出
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [string[]]$Arguments = @(),
        [int]$TimeoutMs = 20000,
        [string]$WorkingDirectory = $null
    )
    $result = [pscustomobject]@{ ExitCode = -1; Output = @(); TimedOut = $false; Error = $null }
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Exe
        if ($Arguments.Count -gt 0) { $psi.Arguments = ($Arguments -join ' ') }
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi
        [void]$p.Start()
        $outTask = $p.StandardOutput.ReadToEndAsync()
        $errTask = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutMs)) {
            try { $p.Kill() } catch { }
            $result.TimedOut = $true
            $result.ExitCode = -2
        } else {
            $result.ExitCode = $p.ExitCode
        }
        $txt = ''
        try { $txt = $outTask.Result } catch { }
        $etxt = ''
        try { $etxt = $errTask.Result } catch { }
        $lines = @()
        if ($txt) { $lines += ($txt -split "`r?`n") }
        if ($etxt) { $lines += ($etxt -split "`r?`n") }
        $result.Output = @($lines | Where-Object { $_ -ne '' })
        try { $p.Dispose() } catch { }
    } catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-SystemProxyState {
    # 只读：读取 IE/WinINET 系统代理设置
    $state = [pscustomobject]@{ Enabled = $false; Server = ''; Raw = '' }
    try {
        $k = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        $state.Enabled = ([int]$k.ProxyEnable -eq 1)
        $state.Server = [string]$k.ProxyServer
        $state.Raw = ('ProxyEnable=' + [string]$k.ProxyEnable + ';ProxyServer=' + [string]$k.ProxyServer)
    } catch { }
    return $state
}

function Get-Median {
    param([double[]]$Values)
    if ($null -eq $Values -or $Values.Count -eq 0) { return $null }
    $s = @($Values | Sort-Object)
    $n = $s.Count
    if ($n % 2 -eq 1) { return [double]$s[[int](($n - 1) / 2)] }
    return ([double]$s[$n / 2 - 1] + [double]$s[$n / 2]) / 2.0
}

function Get-Percentile {
    param([double[]]$Values, [double]$P)
    if ($null -eq $Values -or $Values.Count -eq 0) { return $null }
    $s = @($Values | Sort-Object)
    $n = $s.Count
    if ($n -eq 1) { return [double]$s[0] }
    $rank = ($P / 100.0) * ($n - 1)
    $lo = [math]::Floor($rank)
    $hi = [math]::Ceiling($rank)
    if ($lo -eq $hi) { return [double]$s[[int]$lo] }
    $frac = $rank - $lo
    return ([double]$s[[int]$lo] * (1 - $frac)) + ([double]$s[[int]$hi] * $frac)
}

function Get-Jitter {
    # 相邻样本差值的平均绝对值（平均绝对偏差的简化版）
    param([double[]]$Values)
    if ($null -eq $Values -or $Values.Count -lt 2) { return $null }
    $sum = 0.0; $n = 0
    for ($i = 1; $i -lt $Values.Count; $i++) {
        $sum += [math]::Abs($Values[$i] - $Values[$i - 1]); $n++
    }
    if ($n -eq 0) { return $null }
    return [math]::Round($sum / $n, 2)
}

function Write-LogLine {
    param([string]$Message, [string]$Level = 'INFO', [string]$LogPath = $null)
    $line = ('[{0}] [{1}] {2}' -f (Get-Date).ToString('HH:mm:ss'), $Level, $Message)
    Write-Host $line
    if ($LogPath) {
        try { Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8 } catch { }
    }
}
