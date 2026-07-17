# wtfi2

**What The F\*ck Internet** — a live, visual network-path diagnostic that
pinpoints *exactly* where your connection dies, and tells you how to fix it.

> The Wi-Fi icon shows full bars. The browser says "Offline".
> Stop guessing which hop is broken. Watch the whole path light up.

This is a ground-up rewrite of the archived
[`wtfi`](https://github.com/kanywst/wtfi). The old version printed a flat
checklist and left you to correlate it. `wtfi2` draws the connection as a
**topology diagram**, streams every hop live, and reasons about the **root
cause** so the answer is one line, not ten.

## What makes it different

- **Topology, not a checklist.** Your connection is rendered as a chain —
  `You → Wi-Fi → Gateway → Internet → DNS → Portal` — with the break marked
  where it actually happens.
- **Root-cause reasoning.** It correlates the hops ("IPs reachable but names
  aren't → DNS-only outage") into a single verdict plus a concrete fix, and it
  hedges honestly with a confidence level.
- **Live dashboard.** `wtfi -w` re-probes continuously with real-time latency
  sparklines and a signal gauge, so you can walk around and find the dead zone.
- **No sudo required.** Signal, noise, gateway RTT, dual-stack reachability,
  DNS benchmarking and captive-portal detection all work unprivileged.

## See it

The live dashboard (`wtfi -w`):

```text
 wtfi  what the f*ck internet  ✓ live
┌ ✓ You ───────┐     ┌ ✓ Wi-Fi ─────┐     ┌ ✓ Gateway ───┐     ┌ ✓ Internet ─┐     ┌ ✗ DNS ───────┐     ┌ – Portal ────┐
│   this Mac   │     │  -45 dBm     │     │  192.168.0.1 │     │   1.1.1.1   │     │system resolve│     │ captive check│
│      ok      │───▶ │   43 dB SNR  │───▶ │     2 ms     │───▶ │    12 ms    │─╳─▶ │     down     │───▶ │   skipped    │
└──────────────┘     └──────────────┘     └──────────────┘     └─────────────┘     └──────────────┘     └──────────────┘
┌ verdict ───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  BROKEN  DNS resolution is failing                                                                                   │
│ Raw internet works (IPs are reachable) but name resolution fails — a classic DNS-only outage.                        │
│ → Switch resolvers to 1.1.1.1 / 8.8.8.8, or flush the DNS cache.                                                     │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

The one-shot report (`wtfi`):

```text
 wtfi · what the f*ck internet

  ✓ You ─── ✓ Wi-Fi ─── ✓ Gateway ─── ✓ Internet ─── ✓ DNS ─── ✓ Portal

  ALL GOOD ✓ You're fully online
            Every hop from your Wi-Fi to the internet is healthy.
```

## Install

From source (requires Rust 1.88+):

```bash
git clone https://github.com/kanywst/wtfi2
cd wtfi2
cargo install --path .
```

## Usage

```bash
wtfi              # one-shot report: diagram + verdict
wtfi -w           # live dashboard (q to quit, r to re-probe now)
wtfi -v           # verbose: every metric for every hop
wtfi --json       # machine-readable output for scripts/CI
wtfi --no-color   # plain text, no ANSI
```

The exit code reflects health, so scripts can branch on it:

| Code | Meaning              |
| ---- | -------------------- |
| 0    | All good             |
| 1    | Degraded (warnings)  |
| 2    | Broken               |

## How it works

Probes fan out concurrently and stream their results into the path as they
complete:

1. **L2 Link** — Wi-Fi RSSI, noise, SNR, channel, PHY mode, security and tx
   rate, graded into a signal quality.
2. **L3 Gateway** — resolves the default route and pings the router for RTT,
   flagging VPN/tunnel interfaces and sub-1500 MTU.
3. **WAN** — real TCP handshakes to anycast resolvers over IPv4 and IPv6 to
   expose asymmetric blackholing without needing raw ICMP.
4. **DNS** — benchmarks the system resolver against Cloudflare and Google to
   separate "DNS is down" from "your resolver is just slow".
5. **Captive portal** — a plain-HTTP hotspot check that catches login-page
   interception before you think you're online.

The diagnosis engine then walks the completed chain, finds the *first* break
(everything downstream is collateral), and turns it into the verdict.

## Tech stack

Built for 2026, single self-contained binary:

| Layer        | Choice                                             |
| ------------ | -------------------------------------------------- |
| Language     | Rust (edition 2021, MSRV 1.88)                     |
| TUI          | `ratatui` 0.30 immediate-mode + `crossterm` 0.29   |
| Async        | `tokio` with a `select!`-driven render loop        |
| DNS          | `hickory-resolver` 0.26                            |
| HTTP         | `reqwest` 0.12 (rustls)                            |
| CLI          | `clap` 4                                           |

The OS-specific data acquisition sits behind a `Platform` trait, so the whole
diagnostic stack is portable — only a thin macOS module touches `system_profiler`,
`route` and `scutil`.

## Platform support

macOS-first (validated on macOS 26). Since macOS 14 the OS redacts the SSID and
BSSID unless the calling app holds Location permission — so those show as
*hidden* in an unsigned build, while RSSI, noise, channel and everything that
actually matters for diagnosis remain available without sudo.

## Roadmap

- CoreWLAN via `objc2-core-wlan` for instant link telemetry and real SSID/BSSID
  in a signed `.app` bundle.
- Linux platform module (`nl80211` / `netlink`).
- Historical trends and export.

## License

[MIT](LICENSE)
