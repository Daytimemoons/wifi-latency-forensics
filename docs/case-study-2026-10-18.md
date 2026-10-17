# Case study: 20 minutes that explained three days of intermittent lag

This is the incident the tool was built from. All addresses, MACs and SSIDs below
are placeholders (`aa:bb:cc:…`, `192.168.1.x`, `CampusWiFi`); the measurements,
timings and conclusions are unmodified.

## The complaint

A Windows laptop on an open-authentication campus SSID (`CampusWiFi`) had become
"slow" three times in three days — once late at night, once in the afternoon, once
in the evening. Each episode lasted a few minutes: every site took seconds to
open, domestic and overseas alike. By the time any network tool was opened, things
looked normal again.

Two facts ruled out the obvious explanation early:

- a **roommate on the same SSID was unaffected** → not a campus-wide outage;
- **both domestic and overseas sites** were slow → not just a degraded proxy node.

So the problem had to be somewhere between this one machine's NIC and the AP.

## What the collector captured

The session ran for 20 minutes. One thing changed during it, and only one:

| | 00:26:19 – 00:30:18 | 00:30:19 – 00:46:08 |
|---|---|---|
| Associated AP | `aa:bb:cc:00:00:01` | `aa:bb:cc:00:00:02` |
| Band / channel / PHY | 2.4 GHz / ch 11 / 802.11n | 5 GHz / ch 157 / 802.11ac |
| Negotiated rx rate | **6.5 Mbps** (36 of 43 samples) | 300–400 Mbps |
| RSSI | −60 … −56 dBm (83 %) | −57 … −55 dBm (85 %) |
| **Local gateway 192.168.1.1** | | |
| samples | 109 | 661 |
| packet loss | **15 (13.8 %)** | **0 (0 %)** |
| p50 | **297 ms** | **4 ms** |
| max | 2126 ms | 88 ms |
| samples > 500 ms | **41.5 %** | **0 %** |

At 00:30:18 the client roamed to the 5 GHz BSSID and the problem **stopped
completely** — zero loss, 4 ms median, for the remaining 16 minutes.

## The decisive evidence

Seven targets, three layers, sampled once per second. At one instant:

```
00:27:22   gateway      2126 ms
           local-dns    2128 ms
           cloudflare   2128 ms
           alidns       2128 ms
           google-dns   2175 ms
           quad9        2128 ms
           cloudflare-v6 2128 ms
```

All seven returned within **2 ms of each other**, including the gateway that sits
two metres away. Queues on different paths cannot produce that. The only
consistent explanation is that the ICMP echoes never left the machine on time —
they sat in the NIC/airtime queue for ≈ 2.1 s and were released together when the
medium became available.

Supporting evidence from the same window:

- TCP retransmissions peaked at **16.9/s** (0.4–1.4/s afterwards);
- delivered throughput during the bad period was **13–200 kB/s** (typically
  15–35 kB/s), versus 85–400 kB/s with peaks of 2.5 MB/s afterwards;
- at 00:27:32 twenty samples across all targets completed **within the same
  second** — the queue draining at once.

## A better AP was next to it the whole time

The snapshot taken during the worst stall listed exactly two BSSIDs:

```
aa:bb:cc:00:00:01   2.4 GHz  ch 11    83 %    ← associated, 6.5 Mbps
aa:bb:cc:00:00:02   5 GHz    ch 157   85 %    ← right there, 360 Mbps
```

A third 2.4 GHz BSSID of the same SSID (`aa:bb:cc:00:00:03`, 83–87 %) was also
visible and stronger than the one in use. The adapter simply stayed put for four
minutes.

The driver event log agreed: `Netwtw14` events 7003/7021 fired as link-quality
evaluations throughout, and a `WLAN-AutoConfig` 11004/11005/11010 cluster landed
at 00:30:13 — five seconds before the BSSID actually changed.

## What was ruled out

| Hypothesis | Verdict | Why |
|---|---|---|
| Campus uplink / AP-wide fault | refuted | the local gateway degraded too; a second machine on the same SSID was fine |
| Local proxy | refuted | the proxy process was not even listening (0/116 probes); the system proxy was disabled |
| Local bandwidth saturation | refuted | inbound never exceeded ~2.5 MB/s while the 5 GHz link could do 360 Mbps |
| CPU / disk | refuted | CPU peak 43 %, disk queue peak 4 |
| ARP spoofing | refuted | the "gateway MAC change" was `00-00-00-00-00-00`, i.e. an unresolved ARP entry during loss |

## Why it came back three times

The last sample of the session — 00:46:09, twenty seconds after recording stopped
— shows the client **back on the 2.4 GHz BSSID**. The machine alternates between
the two APs on every reassociation, and only some of those landings are on the bad
one. That is exactly why the symptom looked random.

## The fix

The adapter had no band preference and medium roaming aggressiveness:

| Intel advanced property | Before | After |
|---|---|---|
| `RoamingPreferredBandType` | `1. No preference` | **`3. Prefer 5 GHz`** |
| `RoamAggressiveness` | `3. Medium` | **`4. Medium-High`** |

After the change, a disconnect/reconnect landed on the 5 GHz BSSID at 400 Mbps,
gateway 3 ms with 0 % loss.

`scripts/Set-WifiBand.ps1` applies and reverts exactly these two values. If you
would rather not change driver settings, the zero-cost workaround is to toggle
Wi-Fi off/on when it gets slow: every observed roam to 5 GHz fixed it instantly.

## Takeaway

The generalisable lesson is not "2.4 GHz is slow". It is that **the shape of the
latency data identifies the layer**: when every target — gateway included —
returns the *same* inflated round-trip at the *same* instant, the queue is local,
and the search space collapses to radio selection, driver behaviour and power
management. When only far targets degrade and the gateway stays flat, stop
looking at your laptop.
