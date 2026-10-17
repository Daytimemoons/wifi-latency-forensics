# NetWatch.Pktmon.ps1 - 内置 pktmon 有界抓包（环形缓冲，天然带上限）
# 仅在用户已批准 pktmon 的前提下启用；不改任何网络配置，只做被动拷贝

function Get-PktmonComponentId {
    param([string]$InterfaceDescription)
    $r = Invoke-Native -Exe 'pktmon' -Arguments @('list') -TimeoutMs 15000
    if ($r.ExitCode -ne 0) { return '' }
    foreach ($l in $r.Output) {
        if ($InterfaceDescription -and $l -like ('*' + $InterfaceDescription + '*')) {
            $m = [regex]::Match($l, '^\s*(\d+)\s')
            if ($m.Success) { return $m.Groups[1].Value }
        }
    }
    return ''
}

function Test-PktmonRunning {
    $r = Invoke-Native -Exe 'pktmon' -Arguments @('status') -TimeoutMs 10000
    $txt = ($r.Output -join "`n")
    if ($txt -match '没有运行|not running|未运行') { return $false }
    if ($txt -match '记录程序名称|Logger name|日志文件|Log file') { return $true }
    return $false
}

function Get-PktmonLogFile {
    # 从 pktmon status 里取出当前捕获的日志文件路径（中英文两种措辞）
    $r = Invoke-Native -Exe 'pktmon' -Arguments @('status') -TimeoutMs 10000
    foreach ($l in $r.Output) {
        if ($l -match '(日志文件|Log file)\s*[:：]\s*(.+)$') { return $Matches[2].Trim() }
    }
    return ''
}

function Start-PktmonCapture {
    param([Parameter(Mandatory = $true)]$Session)

    $cfg = $Session.Config
    $info = [pscustomobject]@{
        enabled = [bool]$cfg.EnablePktmon
        started = $false
        started_at = ''
        stopped_at = ''
        component_id = ''
        etl = ''
        etl_mb = 0
        pcapng = ''
        pcapng_mb = 0
        note = ''
        error = ''
        truncated_early = $false
    }
    $Session.Pktmon = $info
    if (-not $cfg.EnablePktmon) { $info.note = 'disabled-by-config'; return $info }

    if (-not (Test-IsAdmin)) {
        $info.note = 'not-admin'
        Add-NetWatchMarker -Session $Session -Kind 'pktmon-skip' -Detail 'not-admin'
        return $info
    }

    try {
        if (Test-PktmonRunning) {
            # 已经有一个 pktmon 在跑。它可能是上一次会话被强杀后残留的 ——
            # 那种情况必须收掉，否则会一直占内存并写向即将被清理的旧目录。
            $prevLog = Get-PktmonLogFile
            $dataRoot = Split-Path -Parent $Session.DataDir
            $isOurs = ($prevLog -and $dataRoot -and $prevLog.ToLower().StartsWith($dataRoot.ToLower()))
            if ($isOurs) {
                Add-NetWatchMarker -Session $Session -Kind 'pktmon-stale' -Detail ('发现残留捕获, 先收尾: ' + $prevLog)
                Write-Host ('   发现上次残留的 pktmon 捕获，正在收尾: ' + $prevLog) -ForegroundColor Yellow
                [void](Invoke-Native -Exe 'pktmon' -Arguments @('stop') -TimeoutMs 40000)
                Start-Sleep -Milliseconds 1200
                if (Test-Path -LiteralPath $prevLog) {
                    $prevPcap = [System.IO.Path]::ChangeExtension($prevLog, '.pcapng')
                    if (-not (Test-Path -LiteralPath $prevPcap)) {
                        $cr0 = Invoke-Native -Exe 'pktmon' -Arguments @('etl2pcap', $prevLog, '--out', $prevPcap) -TimeoutMs 120000
                        Add-NetWatchMarker -Session $Session -Kind 'pktmon-stale-convert' -Detail ($prevPcap + ' exit=' + $cr0.ExitCode)
                    }
                }
            } else {
                $info.note = 'pktmon-in-use-by-others'
                Add-NetWatchMarker -Session $Session -Kind 'pktmon-skip' -Detail ('已被其他程序占用: ' + $prevLog)
                return $info
            }
        }

        $desc = ''
        try { $desc = (Get-NetAdapter -Name $cfg.WlanInterface -ErrorAction Stop).InterfaceDescription } catch { }
        $comp = Get-PktmonComponentId -InterfaceDescription $desc
        $info.component_id = $comp

        $etl = Join-Path $Session.DataDir 'capture.etl'
        $info.etl = $etl

        $a = @('start', '--capture', '--pkt-size', '96',
               '--file-name', $etl,
               '--file-size', [string][int]$cfg.PktmonMaxMB,
               '--log-mode', 'circular')
        if ($comp -ne '') { $a += @('--comp', $comp) }

        $r = Invoke-Native -Exe 'pktmon' -Arguments $a -TimeoutMs 40000 -WorkingDirectory $Session.DataDir
        if ($r.ExitCode -eq 0) {
            $info.started = $true
            $info.started_at = Get-Stamp
            Add-NetWatchMarker -Session $Session -Kind 'pktmon-start' -Detail ('comp=' + $comp + ' maxMB=' + $cfg.PktmonMaxMB + ' pktSize=96 circular')
        } else {
            $info.note = 'start-failed'
            $info.error = (($r.Output | Select-Object -First 4) -join ' | ')
            Add-NetWatchMarker -Session $Session -Kind 'pktmon-error' -Detail $info.error
        }
    } catch {
        $info.note = 'exception'
        $info.error = $_.Exception.Message
    }
    return $info
}

function Update-PktmonCapture {
    param([Parameter(Mandatory = $true)]$Session)
    $p = $Session.Pktmon
    if ($null -eq $p -or -not $p.started) { return }
    try {
        if ($p.etl -and (Test-Path -LiteralPath $p.etl)) {
            $fi = Get-Item -LiteralPath $p.etl
            $p.etl_mb = [math]::Round($fi.Length / 1MB, 2)
            # 环形缓冲理论上不会超；这里只是保险丝
            if ($p.etl_mb -gt ([double]$Session.Config.PktmonMaxMB * 1.25)) {
                Stop-PktmonCapture -Session $Session -Reason 'size-guard'
                $p.truncated_early = $true
            }
        }
    } catch { }
}

function Stop-PktmonCapture {
    param([Parameter(Mandatory = $true)]$Session, [string]$Reason = 'session-end')
    $p = $Session.Pktmon
    if ($null -eq $p -or -not $p.started) { return }
    try {
        $r = Invoke-Native -Exe 'pktmon' -Arguments @('stop') -TimeoutMs 40000
        $p.stopped_at = Get-Stamp
        $p.started = $false
        Add-NetWatchMarker -Session $Session -Kind 'pktmon-stop' -Detail $Reason
        Start-Sleep -Milliseconds 800

        if ($p.etl -and (Test-Path -LiteralPath $p.etl)) {
            $fi = Get-Item -LiteralPath $p.etl
            $p.etl_mb = [math]::Round($fi.Length / 1MB, 2)
            $pcap = [System.IO.Path]::ChangeExtension($p.etl, '.pcapng')
            $ca = @('etl2pcap', $p.etl, '--out', $pcap)
            if ($p.component_id -ne '') { $ca += @('--component-id', $p.component_id) }
            $cr = Invoke-Native -Exe 'pktmon' -Arguments $ca -TimeoutMs 120000 -WorkingDirectory $Session.DataDir
            if ($cr.ExitCode -eq 0 -and (Test-Path -LiteralPath $pcap)) {
                $p.pcapng = $pcap
                $p.pcapng_mb = [math]::Round((Get-Item -LiteralPath $pcap).Length / 1MB, 2)
            } else {
                $p.note = (($p.note + ' convert-failed:' + (($cr.Output | Select-Object -First 3) -join ' ')).Trim())
            }
        }
    } catch {
        $p.error = $_.Exception.Message
    }
}
