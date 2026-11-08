# Network — Simulated Telemetry

Standalone network telemetry for Lab 08 (Network Forensics on Windows). Unlike the per-host folders, this directory contains organization-level network data that would normally come from sensors, SIEM, proxy servers, and DNS servers — sources that do not live on a single endpoint.

The data is keyed to the WKSTN-221 scenario (`Data/WKSTN-221/`) for cross-correlation: the same `91.214.47.22:443` outbound connection appears here in flow form, in proxy form, and as the result of a DNS query. Students can use this folder alone for Lab 08, or combine it with `Data/WKSTN-221/network-flow.csv` for richer per-host context.

It also carries the network-side trace of the **HR-WS17** insider case from Chapter 11 and Lab 11 — the 2024-11-12 OneDrive Personal upload window from `10.0.4.27`, the consumer sign-in that preceded it, and the personal-webmail navigation that follows. Those rows are not used by Lab 08, whose window is 2024-11-14, but they let Lab 11's host-side OneDrive findings be corroborated from a second, independent source. Filter by date before you count anything.

## Files

| File | Source | What it represents |
|---|---|---|
| `flow-data.csv` | NetFlow / IPFIX export from a perimeter device | Aggregated flow records covering the WKSTN-221 incident window plus background traffic |
| `proxy-logs.csv` | Squid / corporate proxy access log | HTTP and HTTPS sessions through the corporate proxy, with username, URL, response size |
| `dns-queries.csv` | Internal DNS server query log | DNS queries from internal hosts in the relevant window |
| `firewall-blocks.csv` | Perimeter firewall denied-connection log | Sample firewall blocks for context |

## Anchor IPs and domains

| IP / Domain | Role | Notes |
|---|---|---|
| `91.214.47.22` | Adversary infrastructure (fictional) | The C2 endpoint that WKSTN-221's `update.exe` connected to |
| `185.193.126.47` | Adversary scanning host (fictional) | The source of the failed-logon attempts in `WKSTN-221/security-evtx.csv`. `firewall-blocks.csv` denies it at three other hosts and the DNS server but has no deny row for WKSTN-221, which it reached. Lab 08 Step 5 treats that gap as a finding |
| `52.96.128.45`, `40.126.32.74`, `13.107.42.14` | Microsoft 365 / Office 365 endpoints | Legitimate background; should match real M365 IP ranges |
| `8.8.8.8`, `10.0.0.10` | Public and internal DNS servers | Background |
| `40.108.232.91`, `40.84.180.42`, `40.84.180.18` | `onedrive.live.com`, `login.live.com`, `outlook.live.com` | **Consumer** Microsoft endpoints — the HR-WS17 personal-account channel, distinct from the corporate M365 IPs above. That distinction is the finding in Lab 11 |
| `10.0.4.0/24` | Internal corporate subnet | WKSTN-221 lives at `10.0.4.32`; FILESVR-03 at `10.0.4.18`; HR-WS17 at `10.0.4.27` |

## Caveats

- The flow data is intentionally compact (33 rows). Real sensors would produce orders of magnitude more.
- Proxy logs and firewall blocks are sampled; not exhaustive.
- A missing deny row means something only when another source shows the traffic arrived. For the 04:00 UTC scan of WKSTN-221, `flow-data.csv` and the host's Security log both do.
- DNS queries shown represent the queries directly relevant to the incident, plus a small noise floor.
- `Block-Outbound-DNS-Direct` denies outbound UDP/53 except to the internal resolver `10.0.0.10` and the fallback public resolver `8.8.8.8`. That is why the 14:19:38 PTR lookup to `8.8.8.8` was answered and the 14:21:48 UDP/53 probe straight to `91.214.47.22` was denied.
- All addresses outside the `10.0.0.0/8` range are fictional; do not infer real attribution.

---

*Simulated network telemetry — Windows Forensics for Beginners*
