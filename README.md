# wifi-latency-forensics

**Your Wi-Fi suddenly goes to 2-second latency for a few minutes, then recovers — and by the time you open a network tool, everything looks fine again.**

This is a bounded, self-contained Windows collector for exactly that failure mode. You launch it *while* it is happening; it records the link layer, the driver event log, per-process load and the packet path for a fixed amount of time, then writes a correlation report and exits on its own.

```
Run-NetWatch.cmd     →  20 minutes of recording  →  report.md / report.html  →  exited
```

No installer, no service, no telemetry, no cloud account. Windows PowerShell 5.1 is enough.

> 中文说明见 **[README.zh-CN.md](README.zh-CN.md)**.
> A worked example of the failure this was built for: **[docs/case-study-2026-10-18.md](docs/case-study-2026-10-18.md)**.

---

## The problem it solves

"Sudden high latency" has at least five unrelated causes that look identical from a browser:

1. the client is parked on a weak or congested radio (2.4 GHz, low MCS, 6.5 Mbps link);
2. a driver keeps evaluating neighbouring APs and never leaves a bad one;
3. a local proxy / VPN client degrades its upstream;
4. a background process saturates your uplink and the AP buffers;
5. the campus/ISP uplink is genuinely congested.

A single `ping` cannot separate these, because "everything is slow" is the common symptom. What separates them is **which layer fails first, and what else changes at the same second**.

This tool records all of those on one clock, so the report can say e.g. *"at 00:27:22 all seven targets — including the local gateway — returned the identical 2128 ms"*, which is only possible if packets were queued **locally**, not lost upstream.

## What makes it different from a ping plotter

| Typical monitor | This tool |
|---|---|
| pings one host every 60 s | 7 targets across 3 layers at 1 Hz, 0.25 s during a trigger |
| ignores the radio | records BSSID / band / channel / negotiated rate every 5 s |
| ignores the OS | correlates Intel `Netwtw*` + `WLAN-AutoConfig` + `NDIS` + `DHCP` events |
| no exit condition | hard time cap, data cap, capture cap — always terminates |
| "here's a graph" | writes a report with anomaly windows, correlated evidence and a hypotheses table |
| runs forever | bounded session, keeps the last N sessions, deletes the rest |

## Requirements

- Windows 10 / 11, **Windows PowerShell 5.1** (built in — PowerShell 7 not required)
- Administrator rights **only** for the optional packet capture (`pktmon`). Everything else is read-only and works as a normal user.
- ~400 MB of free disk at most (defaults: 300 MB text cap + 64 MB capture ring)

**Note on language:** the console output and the generated report are in Simplified Chinese. The scripts, config keys and CSV headers are English/ASCII, so the data itself is language-neutral.

## Quick start

```powershell
# 1. sanity check: permissions, pktmon, event log, WLAN access
.\Run-Check.cmd

# 2. when it starts lagging, run the collector
.\Run-NetWatch.cmd
```

Or from a PowerShell prompt:

```powershell
.\scripts\NetWatch.ps1                 # 20 minutes (default)
.\scripts\NetWatch.ps1 -Minutes 40     # longer window
.\scripts\NetWatch.ps1 -Quick          # 5-minute smoke test
.\scripts\NetWatch.ps1 -NoPktmon       # skip packet capture entirely
```

The `.cmd` wrappers already pass `-ExecutionPolicy Bypass`, so script execution policy will not block them.

### Was the spike a minute ago?

```powershell
.\Run-Forensics.cmd
```

That replays the last **6 hours** of relevant event-log records, takes an immediate snapshot, records for 3 minutes, and reports. Useful when you only notice the problem after it ends.

### While it runs

| Key | Action |
|---|---|
| `M` | drop a time marker ("it started lagging now") |
| `S` | take a full snapshot immediately |
| `E` | extend by 5 minutes (still bounded by `MaxDurationMinutes`) |
| `Q` | stop and write the report now |
| `Ctrl+C` | same as `Q` — the session finalises cleanly |

## What it records

| Module | Content | Default rate |
|---|---|---|
| ICMP ladder | gateway / local DNS / 3 public IPv4 / 1 public IPv6 — RTT, status, TTL, source | 1 s (0.25 s in burst) |
| Wi-Fi link | `netsh wlan show interfaces` → state, SSID, **BSSID**, band, channel, radio, RSSI, signal %, tx/rx negotiated rate, gateway MAC | 5 s |
| Neighbour APs | every BSSID of the same SSID + signal, so you can see a better AP that was available | 120 s |
| Event log | `Netwtw*`, `WLAN-AutoConfig`, `NDIS`, `TCPIP`, `Dhcp-Client`, `Kernel-Power` — with raw event payload | 5 s |
| TCP / system | retransmit rate, connection failures/resets, TIME_WAIT, CPU, memory, disk queue, WLAN bytes/s, discards, errors | 10 s |
| Processes | per-PID TCP connection counts + total I/O (top 15) | 15 s |
| DNS | resolution timing per server per name (in a child runspace, never blocks the loop) | 15 s |
| Proxy A/B | system proxy state, listener liveness, same URL fetched *through* proxy and *direct* | 30 s |
| Packet capture | `pktmon`, 96 bytes/packet, ring buffer, WLAN adapter only | continuous |

## Hard limits — it cannot run away

| Limit | Default | Behaviour |
|---|---|---|
| Session wall clock | 20 min (hard cap 120) | stops and reports |
| Text data (`data/`) | 300 MB | stops and reports, marked "ended early" |
| Packet capture | 64 MB ring buffer | oldest data overwritten; hard-capped |
| Disk free | aborts below 3 GB | refuses to start / stops |
| Trigger snapshots | 10 per session, 40 MB each | further triggers only log a marker |
| History | last 6 sessions | older ones deleted; 2 GB global cap |

Everything except the packet capture counts against a single text budget, and the capture uses a ring buffer, so a session has a known upper bound.

## What the report contains

`data\session-<timestamp>\report\`:

- **`report.md`** — the human summary (fastest to read)
- **`report.html`** — same content + 4 inline SVG timelines (RTT, RSSI, throughput, retransmits) with anomaly windows highlighted. Fully self-contained, no external assets.
- **`summary.json`** — compact machine-readable metrics
- **`evidence.zip`** — report + every CSV, one file to share

Sections: session metadata → data coverage → per-target latency distribution (min/p50/p95/p99/max/jitter/loss) → **anomaly windows with correlated evidence** (RSSI, BSSID changes, gateway MAC, throughput peak, CPU/disk, retransmits, matched driver events) → wireless layer → local resources → event summary → proxy phase comparison → DNS → **hypotheses marked supported / refuted / unknown** → file inventory.

## The one signal to look for first

If **every target returns the same inflated RTT at the same instant** — including the local gateway — the packets never left the machine on time. That is a local send-side / airtime stall (bad radio, driver queue, power save), not an upstream problem.

Real example from the bundled case study:

```
00:27:22   gateway 2126 | local-dns 2128 | cloudflare 2128 | alidns 2128
           google-dns 2175 | quad9 2128 | cloudflare-v6 2128      ← 2 ms apart
```

If instead only the public targets degrade while the gateway stays at 4 ms, the bottleneck is upstream, and no amount of local tweaking will help.

See **[docs/how-it-works.md](docs/how-it-works.md)** for the detection rules and the measurement caveats.

## A fix that often follows from the report

If the report shows the client stuck on a 2.4 GHz AP with a low negotiated rate while a 5 GHz AP of the same SSID was visible and stronger, the adapter's band preference is the first thing to change:

```powershell
.\scripts\Set-WifiBand.ps1 -Show      # current values
.\scripts\Set-WifiBand.ps1            # prefer 5 GHz + medium-high roaming aggressiveness
.\scripts\Set-WifiBand.ps1 -Revert    # back to driver defaults
```

Only two Intel driver advanced properties are touched (`RoamingPreferredBandType`,
`RoamAggressiveness`). Reversible, and a driver update restores the defaults.

## Configuration

Copy `config.example.json` to `config.json` and edit. All keys are optional.
An empty `host` in `IcmpTargets` means "auto-detect at runtime": `gateway` uses
the default gateway, `local-dns` uses the host's own DNS server. `ProxyPort: 0`
means "read the port from the current system proxy setting".

Command-line switches override the file: `-Minutes`, `-MaxMinutes`, `-Label`,
`-LookbackHours`, `-ForceSnapshot`, `-NoPktmon`, `-NoNeighborScan`,
`-NoProxyProbe`, `-NoL7`, `-NoEvents`, `-NoProc`, `-NoReport`, `-OpenReport`,
`-CheckOnly`, `-StopPktmon`, `-StartDelaySec`, `-ConfigPath`, `-DataRoot`, `-ReportRoot`.

## Safety and privacy

- **Read-only by default.** ICMP, DNS queries, HTTPS HEAD-like GETs, performance
  counters, `Get-WinEvent`, `netsh wlan show *`, `ipconfig/arp/route/netstat`,
  read-only `HKCU` proxy state.
- **No configuration is changed** except when you explicitly run
  `Set-WifiBand.ps1`. No firewall, DNS, proxy, power-plan or registry edits.
- **The only privileged action** is the optional `pktmon` capture. It is a
  built-in Windows diagnostic tool: it loads the PktMon filter driver and makes a
  passive copy of packets. It does not modify, block or inject traffic. Files are
  written under the repository's own `data/` directory. Without admin rights the
  capture is skipped and everything else still runs. `-NoPktmon` turns it off.
- **Nothing is uploaded.** No telemetry, no analytics, no outbound reporting.
- **Data stays local.** `data/`, `reports/`, `config.json` and captures are
  gitignored. Never publish your own capture: it contains your traffic.
- A neighbour scan (`netsh wlan show networks`) triggers an active scan that can
  cause sub-millisecond disruption. Scan windows are recorded so the report can
  flag overlap, and `-NoNeighborScan` disables it.

**Never commit the output of a run.** A `.pcapng` contains DNS queries, TLS SNI
and any unencrypted HTTP traffic. `tools/check-no-sensitive.ps1` refuses to let
session data, captures, private IPs or MACs be staged — run it before every commit.

## Known limitations

- Reports are Chinese-only (see the note above). PRs adding an English output
  localization are very welcome — the strings are concentrated in
  `scripts/NetWatch.Report.ps1`.
- It observes one host. It cannot see inside the AP, the ISP, or other devices.
- The ring-buffered capture keeps only the most recent traffic; the report states
  the coverage.
- `pktmon etl2pcap` excludes dropped packets by default
  (`--drop-only` produces a separate file).
- Windows has no per-process network byte counters; the process table is a
  connection-count + I/O approximation.
- DNS and L7 probes run in child runspaces. If one wedges, that cycle is recorded
  as `ABORTED-TIMEOUT` rather than stalling the main loop.

## Repository layout

```
├─ README.md / README.zh-CN.md
├─ LICENSE  CHANGELOG.md  .gitignore  .gitattributes
├─ config.example.json
├─ docs/
│  ├─ case-study-2026-10-18.md    worked example
│  └─ how-it-works.md            detection rules & caveats
├─ scripts/                       PowerShell modules
│  ├─ NetWatch.ps1                entry point + main loop
│  ├─ NetWatch.Config.ps1         defaults, auto-detection
│  ├─ NetWatch.Session.ps1        session dir, writers, limits
│  ├─ NetWatch.Probes.ps1         ICMP / DNS / L7 / proxy
│  ├─ NetWatch.Wifi.ps1           wireless + neighbours + gateway MAC
│  ├─ NetWatch.System.ps1         counters, processes
│  ├─ NetWatch.Events.ps1         event-log acquisition
│  ├─ NetWatch.Pktmon.ps1         bounded capture
│  ├─ NetWatch.Incident.ps1       trigger + snapshot
│  ├─ NetWatch.Report.ps1         analysis + report rendering
│  ├─ NetWatch.Util.ps1           helpers
│  ├─ Forensics.ps1  Report-Only.ps1  Set-WifiBand.ps1
├─ tools/
│  └─ check-no-sensitive.ps1
└─ Run-*.cmd                      double-click entry points
```

## Contributing

Issues with a **sanitized** report excerpt are the most useful bug reports.
Before opening a PR:

```powershell
.\tools\check-no-sensitive.ps1     # must pass
```

All `.ps1` files must be saved as **UTF-8 with BOM** — PowerShell 5.1 otherwise
decodes them using the ANSI code page and fails to parse non-ASCII literals.

## License

[MIT](LICENSE) © 2026 Micheal Zi
