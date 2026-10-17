# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-10-18

First public release. The tool had already run on one real incident before
being open-sourced, so this version includes the fixes that incident exposed.

### Added

- **Bounded collection sessions.** A session has a hard wall-clock limit, a
  text-data cap, a packet-capture cap and an absolute disk floor. When any limit
  is hit the collector stops itself, writes the report and exits — no daemon left
  running, no unbounded growth.
- **Layered ICMP ladder** (gateway → local DNS → public IPv4/IPv6, 1 Hz) so you
  can tell "my link" apart from "upstream".
- **Wi-Fi link-layer recorder**: state, SSID, BSSID, band, channel, radio type,
  RSSI, negotiated tx/rx rate, gateway MAC — samples every 5 s, so BSSID/band
  switches are visible on a timeline.
- **Neighbour AP scan** (same SSID, all BSSIDs + signal) at a configurable
  interval, with scan windows written to `markers.csv` so the report can flag
  self-interference.
- **Windows event-log correlation**: Intel `Netwtw*` driver events,
  `WLAN-AutoConfig`, `NDIS`, `TCPIP`, `Dhcp-Client`, `Kernel-Power` —
  stored with raw event payload, deduplicated by record id.
- **Proxy phase tracking**: samples the system proxy state and measures the same
  URL both *through* the local proxy and *direct*, so "proxy slow" can be told
  apart from "network slow".
- **Automatic anomaly detection** with a trigger-driven snapshot: on 3 consecutive
  failures / 3 consecutive over-threshold samples / BSSID change / gateway MAC
  change, it drops to a 0.25 s burst for 60 s and dumps a full snapshot
  (netsh, ipconfig, arp, route, netstat, TCP table, DNS cache, neighbours,
  recent events).
- **Optional bounded packet capture** via the built-in `pktmon`, ring-buffered,
  converted to `.pcapng`. Stale captures left behind by a killed session are
  detected and cleaned up on the next start.
- **Self-generated report** (`report.md`, `report.html` with inline SVG charts,
  `summary.json`, `evidence.zip`) including per-target latency distributions,
  anomaly windows with correlated evidence, and a hypotheses table marked
  supported / refuted / unknown.
- **`Set-WifiBand.ps1`** helper to flip the Intel adapter's *Preferred Band* and
  *Roaming Aggressiveness*, with `-Show` and `-Revert`.

### Fixed

- Event-log queries silently returned nothing when the provider list contained a
  name that does not exist on the host (`Get-WinEvent` fails the whole query).
  Providers are now resolved against the host first, with a fallback path.
- DNS probe wrote no rows at all: the result objects are `PSCustomObject`, which
  *is* a `PSObject`, so the unwrapping logic replaced them with `$null`.
- Layer-7 probe could never run in a fresh PowerShell 5.1 session
  (`System.Net.Http.HttpClientHandler` is not loaded by default) and its timings
  included main-loop stalls. Rewritten on `HttpWebRequest` inside a child
  runspace that stops its own stopwatch.
- `latency_icmp` row count was reported as 0 in the coverage table (internal
  writer key did not match the file name).
- An all-zero gateway MAC (an unresolved ARP entry during packet loss) was
  reported as "gateway MAC changed", i.e. a false ARP-spoofing alarm.
- Neighbour-AP scan did not parse the channel field on non-English Windows.
- `*.ps1` files must be saved as UTF-8 **with BOM**; PowerShell 5.1 otherwise
  decodes them as the ANSI code page and fails to parse Chinese string literals.
- Free-space checks and the default capture directory were hard-coded to `D:`.
  They now derive from the data path, so the tool runs from any drive.

### Known limitations

- Console output, report text and hypothesis wording are in Simplified Chinese.
  English localization is a welcome contribution.
- The report cannot see inside the AP or the ISP; it infers from both ends of
  one host.
- `pktmon etl2pcap` excludes dropped packets by default.
- Windows exposes no per-process network byte counters; the process table uses
  connection counts plus total I/O as a proxy.

[1.1.0]: https://github.com/Daytimemoons/wifi-latency-forensics/releases/tag/v1.1.0
