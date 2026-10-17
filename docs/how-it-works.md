# How it works

## 1. The measurement model

Everything is recorded against one clock in one process. That is the whole point:
a latency spike is only explainable if you can say what else changed in the same
second.

### Why seven ICMP targets

A ladder from "closest" to "furthest":

| Target | What it proves |
|---|---|
| default gateway | your NIC ↔ AP link is healthy *right now* |
| local DNS (auto-detected) | the LAN path beyond the gateway |
| public IPv4 × 3 | your uplink and the wider internet |
| public IPv6 | the other stack — often fails differently |

The comparison between these is the diagnostic. If the gateway is clean while the
public targets spike, your radio is fine and the problem is upstream. If the
gateway spikes too, the problem is at or below your NIC.

### The discriminant: identical RTTs

When several pending probes all complete with nearly the same inflated RTT, the
packets were released as a batch. That happens when a queue in **front of** them
drained — i.e. locally. This is the single most useful signal in the report, and
it is why the probe set is sampled at 1 Hz rather than 60 s: at 60 s you cannot
see a batch release at all.

## 2. Detection rules

### Anomaly windows

For each target, over the whole session:

1. `p99` of successful RTTs is computed, and a threshold
   `max(p99, median × 2.5)` is derived.
2. An **absolute floor** of `median + 25 ms` is applied on top, so a
   `3 ms → 12 ms` wobble is not called an anomaly.
3. A sample is *bad* if it failed, or if it exceeded **both** the threshold and
   the floor.
4. Targets whose overall loss is ≥ 3 % are treated as **chronically lossy**
   (some public hosts deprioritise ICMP, and some IPv6 paths are ugly). For those,
   an isolated loss is not an anomaly — only runs of **three or more** consecutive
   losses are.
5. Bad samples are merged into windows with a 15 s gap tolerance.
6. A window is kept only if it contains at least one loss **or** at least three
   samples; single-sample blips are dropped.
7. Windows are ranked by duration and the top 12 are reported.

Each window is then annotated with everything else recorded ±30 s (±60 s for
event-log records): minimum RSSI, number of distinct BSSIDs, gateway MAC changes,
throughput peaks, CPU/disk peaks, TCP retransmit peaks, matched driver events, and
whether one of our own neighbour scans overlapped (to avoid blaming ourselves).

### Runtime triggers

A session that only records quietly will miss a short glitch. So the collector
also reacts, using three conditions:

- any target failing **3 consecutive** probes;
- any target exceeding its critical threshold **3 consecutive** times;
- a BSSID change, a gateway MAC change, or the WLAN leaving the connected state.

On trigger (with a 180 s cooldown, max 10 per session):

1. a snapshot directory is written — `netsh wlan show interfaces` and
   `show networks mode=bssid`, `ipconfig /all`, `arp -a`, `route print`,
   `netstat -ano`, adapter statistics, TCP table grouped by process, DNS client
   cache, neighbour table, `pktmon status`, and the last 30 minutes of events;
2. the ICMP cadence drops to **0.25 s for 60 s**, because the event may only last
   a couple of minutes;
3. the trigger reason, timestamp and current counters are recorded in
   `markers.csv` and `incidents/<n>/summary.txt`.

## 3. Why some probes run in a child runspace

`Resolve-DnsName` and the layer-7 HTTP timings are synchronous by nature. Running
them in the main loop would stall the scheduler for however long the network takes
— and during an outage that is exactly when you least want the loop to stall, and
exactly when a "stopwatch around a blocking call" turns into a fake multi-second
latency number.

So both run in an isolated PowerShell runspace:

- the DNS probe returns rows to be written, no shared state;
- the layer-7 probe starts all requests, polls at 20 ms inside the runspace, and
  stops each stopwatch **when that request completes** — not when the main loop
  happens to notice. That is why a 2 s figure in `l7.csv` is real, not scheduler
  skew.

Each has a hard budget; a wedged cycle is recorded as `ABORTED-TIMEOUT` instead of
blocking collection.

## 4. Event-log acquisition caveats

`Get-WinEvent -FilterHashtable @{ ProviderName = @(...) }` **fails the entire
query** if any provider in the list does not exist on the host. On a machine
without `Netwtw12`, asking for it silently yields zero rows for *all* providers.
The collector therefore:

1. enumerates the host's providers once (`Get-WinEvent -ListProvider *` with
   `-ErrorAction SilentlyContinue`, because a single corrupt provider aborts the
   enumeration otherwise);
2. intersects the wanted list with what exists;
3. falls back to "query by log + time, then filter by provider in memory" if the
   filtered query still fails.

Events are deduplicated by `(log, RecordId)` and stored raw in `events.jsonl`,
including the full `Properties` payload — that payload is how the driver's AP
evaluation reports were reconstructed.

## 5. Packet capture semantics

`pktmon` is a built-in Windows diagnostic tool. The collector starts it with:

```
pktmon start --capture --comp <wlan adapter id> --pkt-size 96 `
             --file-name <session>\capture.etl --file-size <M> --log-mode circular
```

Consequences worth knowing:

- **`circular`** means the file never exceeds `--file-size`; when full it
  overwrites the oldest data. The capture therefore covers the **tail** of the
  session, which is normally what you want (the glitch is what made you run it),
  but it is not a complete record.
- **`--pkt-size 96`** truncates each packet to 96 bytes: headers plus a little
  payload. Enough for TCP flags, sequence numbers, TLS SNI and DNS question
  sections; not enough for bodies. That keeps volume manageable.
- **`pktmon etl2pcap` excludes dropped packets by default.** To see what the
  driver dropped, convert again with `--drop-only`.
- If a previous session was killed before it could stop the capture, the next
  start detects that the running capture belongs to this repository (its log path
  is under `data/`), stops it, converts it, and starts fresh. A capture owned by
  something else is left untouched and skipped with a note.

## 6. Data files

| File | Contents |
|---|---|
| `latency_icmp.csv` | `ts, sent_ts, phase, incident, target, host, layer, rtt_ms, status, ttl, src` |
| `wifi.csv` | state, SSID, BSSID, band, channel, radio, auth, cipher, RSSI, signal%, tx/rx rate, local IP, gateway MAC |
| `neighbors.csv` | SSID, BSSID, signal%, channel, band, radio (per scan) |
| `sys.csv` | CPU, memory, disk queue/busy, TCP retransmits & failures (per second, derived from raw counters), TIME_WAIT, WLAN bytes/s, discards/errors, free disk |
| `proc.csv` | per-PID TCP connection counts, TIME_WAIT, SYN_SENT, listen, total I/O |
| `dns.csv` | server, name, type, elapsed ms, status, answers |
| `l7.csv` | mode (`direct`/`proxy`), target, URL, elapsed ms, HTTP status or failure |
| `proxy.csv` | system proxy on/off, proxy server string, listener liveness |
| `events.jsonl` | raw event records with provider, id, level, message and full property payload |
| `markers.csv` | session events: start/stop, proxy phase changes, BSSID changes, gateway MAC changes, trigger reasons, manual marks |
| `session.json` | effective configuration, stop reason, row counts, file sizes, capture status |

`phase` is `pN-proxy-on` / `pN-proxy-off`, derived from the live system proxy
state, so every row can be split by proxy state without guessing.

## 7. Honest limitations

- One host's view. The AP's own queue depth, the ISP's shaper and other clients
  are invisible.
- Windows has **no per-process network byte counters**. `proc.csv` is connection
  counts plus total I/O (which includes disk), useful only to spot "this process
  is running hot".
- RSSI is what the driver reports; it is smoothed and does not capture
  interference that the driver does not observe.
- A session covers one time window. If the glitch happens outside it, the report
  will say so plainly rather than invent a conclusion.
- The hypothesis table distinguishes **supported / refuted / unknown**. It is
  deliberately not a verdict generator.
