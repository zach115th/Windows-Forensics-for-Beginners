# Lab 08 — Hands-On Walkthrough Sample Answers

*Sample answers for the Hands-On Walkthrough section of `Labs/Lab08/ReadMe.md`. These are reference answers — your filter, your environment, and your tool version may legitimately produce slightly different values. The interpretation matters more than the exact number.*

---

## Step 1 — Load and filter the flow data

**Expected output:** 33 rows total in `flow-data.csv`. Filtering to flows where `SourceIP` or `DestIP` equals `10.0.4.32` and `FlowStart` is between 2024-11-14 14:00:00 and 14:35:00 UTC returns **16 rows**: the six flows to `91.214.47.22` plus routine M365, DNS, and SMB rows the walkthrough text already names.

The 16 rows break down as:

| Destination | Flows | What it is |
|---|---|---|
| `91.214.47.22` | **6** | The suspicious destination |
| `52.96.128.45` | 3 | Exchange Online |
| `10.0.4.18` | 2 | SMB to FILESVR-03 |
| `40.126.32.74` | 1 | Microsoft Graph |
| `10.0.4.32` | 1 | Inbound SMB from the 10.0.4.17 pivot |
| `10.0.0.10` | 1 | Internal DNS |
| `8.8.8.8` | 1 | External DNS |
| `224.0.0.1` | 1 | LLMNR multicast |

That makes 4 flows to M365 endpoints, 5 internal or multicast, 1 external DNS, and 6 to the unfamiliar IP. The suspicious destination is the single most frequent in the window, which is itself worth noticing.

**Verified via:** `python3 -c "import csv; from datetime import datetime; rows=list(csv.DictReader(open('Data/network/flow-data.csv'))); s=datetime(2024,11,14,14,0); e=datetime(2024,11,14,14,35); print(len([r for r in rows if (r['SourceIP']=='10.0.4.32' or r['DestIP']=='10.0.4.32') and s<=datetime.strptime(r['FlowStart'],'%Y-%m-%d %H:%M:%S')<=e]))"`

**Interpretation:** Most of the host's traffic in this 35-minute window is benign Office365 / DNS / SMB. The 6 flows to `91.214.47.22` stand out. They are anomalous because the destination is unfamiliar, the IP is an IP literal with no hostname, and the volumes do not match background browsing patterns.

---

## Step 2 — Identify the suspicious destination

**Expected output:** **6 rows** to `91.214.47.22`, matching the readme's "6 rows":

| FlowStart | DestPort | BytesSent | BytesReceived |
|---|---|---|---|
| 14:19:42 | 443 | 1847 | 184221 |
| 14:21:48 | 53 | 0 | 0 |
| 14:21:48 | 443 | 4218 | 18421 |
| 14:21:55 | 443 | **184221** | **2415891** |
| 14:22:14 | 443 | 18421 | 42184 |
| 14:35:00 | 443 | 8421 | 11421 |

The flow at 14:21:55 is the standout: ~184 KB out / **~2.4 MB in** — the largest by an order of magnitude.

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/network/flow-data.csv'))); [print(r['FlowStart'], r['DestPort'], r['BytesSent'], r['BytesReceived']) for r in rows if r['DestIP']=='91.214.47.22']"`

**Interpretation:** The 14:21:55 byte profile, a large pull and a small push, is a payload-pull signature, not an exfiltration one. It is consistent with the attacker downloading tooling rather than uploading data. The brief UDP/53 probe at 14:21:48 from the same host is also a small signal that may indicate custom DNS-tunnel probing or tooling DNS misuse. The 14:35:00 flow is a final small beacon before quiet.

---

## Step 3 — Cross-check with the proxy logs

**Expected output:** **5 rows** of `CONNECT 91.214.47.22:443` from `FINANCE\payroll-admin` at `10.0.4.32`. The first row at 14:19:42 has `UserAgent=Microsoft .NET CLR 4.8 (Invoke-WebRequest)`. The other 4 rows, at 14:21:48, 14:21:55, 14:22:14, and 14:35:00, carry a literal `-` in `UserAgent`. That is the proxy's placeholder for a request that sent no user-agent header. It is the string `-`, not an empty field, so filter on the value rather than testing for emptiness.

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/network/proxy-logs.csv'))); [print(r['Timestamp'], r['Username'], r['Method'], r['URL'], r['UserAgent']) for r in rows if '91.214.47.22' in r['URL']]"`

**Interpretation:** The first connection's UA fingerprint is itself the evidence. The string `.NET CLR 4.8 (Invoke-WebRequest)` is the literal user agent for `Invoke-WebRequest` from PowerShell. Empty UAs on the subsequent CONNECTs are consistent with raw `System.Net.Sockets` / WinHTTP traffic from a non-PowerShell binary, here the `update.exe` payload. Five proxy hits to a single IP-literal CONNECT URL by an authenticated user is enough to escalate independently of the flow data.

---

## Step 4 — Was the destination ever resolved through DNS?

**Expected output:** **3 rows** of PTR lookups for `91.214.47.22`, all with `ResponseCode=NXDOMAIN`:

| Timestamp | DNSServer |
|---|---|
| 2024-11-14 14:19:38 | 10.0.0.10 (internal) |
| 2024-11-14 14:19:38 | 8.8.8.8 (Google public) |
| 2024-11-14 14:35:00 | 10.0.0.10 (internal) |

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/network/dns-queries.csv'))); [print(r['Timestamp'], r['DNSServer'], r['ResponseCode']) for r in rows if '91.214.47.22' in r['QueryName']]"`

**Interpretation:** No A-record or domain ever produced this IP. The only queries are PTR lookups from the host itself, all returning NXDOMAIN. That's consistent with attacker infrastructure that uses raw IP literals and leaves no DNS footprint to cross-reference. The timing is a pattern worth noting. Two lookups went out at 14:19:38, one to the internal resolver and one to 8.8.8.8, four seconds before the first connection. A third went out at 14:35:00, at the final beacon. The DNS log does not record which process issued them.

---

## Step 5 — Spot the password-spray attempt in firewall logs

**Expected output:** **4 rows** with `SourceIP=185.193.126.47`. Three are inbound SMB scans (TCP/445) against internal hosts at ~04:00 UTC, and one is an inbound DNS-over-TCP probe:

| Timestamp | DestIP | DestPort | RuleName |
|---|---|---|---|
| 04:00:11 | 10.0.4.45 | 445 | Block-Inbound-SMB-WAN |
| 04:00:24 | 10.0.4.51 | 445 | Block-Inbound-SMB-WAN |
| 04:00:42 | 10.0.4.18 | 445 | Block-Inbound-SMB-WAN |
| 04:01:18 | 10.0.0.10 | 53 | Block-Inbound-DNS-TCP-WAN |

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/network/firewall-blocks.csv'))); [print(r['Timestamp'], r['DestIP'], r['DestPort'], r['RuleName']) for r in rows if r['SourceIP']=='185.193.126.47']"`

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/network/flow-data.csv'))); [print(r['FlowStart'], r['FlowEnd'], r['DestIP'], r['BytesSent'], r['BytesReceived'], r['PacketsSent'], r['PacketsReceived']) for r in rows if r['SourceIP']=='185.193.126.47']"`

**Interpretation:** The firewall log and the Security log disagree, and the disagreement is the finding. The perimeter denied `185.193.126.47` at three hosts and the DNS server. WKSTN-221 (`10.0.4.32`) has no deny row. Yet `Data/WKSTN-221/security-evtx.csv` holds four EID 4625 failures from the same IP at 04:00:00, 04:00:11, 04:00:24, and 04:00:42 UTC, so the attempts reached the workstation.

The flow data agrees. The 04:00:00–04:00:42 flow to `10.0.4.32:445` carries 4,218 bytes sent and 2,841 received over 28 and 22 packets: a two-way session. The flows to `10.0.4.45` and `10.0.4.51` are SYN-only, with 156 bytes in 3 packets out and nothing back. Some path let the scanner reach WKSTN-221's SMB port, and the data does not say which. Record the missing deny row as a scoping finding. The brute force itself did not succeed. All four logons failed, and the Security log has no EID 4624 from that IP.

---

## Step 6 — Build the network attribution chain

**Expected output:** **4 rows** in `Data/WKSTN-221/network-flow.csv` for `DestIP=91.214.47.22`:

| FlowStart | OwningProcess | BytesSent | BytesReceived | Notes |
|---|---|---|---|---|
| 14:19:42 | powershell.exe | 1847 | 184221 | First observation of this IP |
| 14:21:48 | update.exe | 4218 | 18421 | Beacon — small bidirectional traffic |
| 14:21:55 | update.exe | 184221 | 2415891 | Large outbound transfer — possible exfil *(the Notes field is wrong: the large number is BytesReceived, so this is inbound; Chapter 13 §13.2.4 uses this mislabel as its example)* |
| 14:22:14 | update.exe | 18421 | 42184 | Continued beacon |

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/WKSTN-221/network-flow.csv'))); [print(r['FlowStart'], r['OwningProcess'], r['BytesSent'], r['BytesReceived']) for r in rows if r['DestIP']=='91.214.47.22']"`

**Interpretation:** Per-host flow assigns an `OwningProcess` to each connection. The first one is `powershell.exe`, the encoded-command stager from Step 4 of Lab 04 (EID 4688). The rest are `update.exe`, the dropped payload. The perimeter flow data (Step 2) shows 6 flows to the same destination. The per-host telemetry attributes only 4 to a process before the agent's session rotates. The 14:21:48 UDP/53 flow and the 14:35:00 final beacon are not in the per-host file. The two views complement each other: the perimeter sees more, but only EDR / per-host telemetry can name the binary.

---

## Step 7 — Build a network timeline snippet

**Expected output:** A 6-row timeline snippet with the same data as Step 2, classified by transfer size:

| Time | Source | Description | Significance |
|---|---|---|---|
| 14:19:42 | Network/flow | TCP/443 to 91.214.47.22; 1847B out / 184221B in | Large inbound - likely download (>100KB in) |
| 14:21:48 | Network/flow | UDP/53 to 91.214.47.22; 0/0 | Beacon (probe) |
| 14:21:48 | Network/flow | TCP/443 to 91.214.47.22; 4218/18421 | Beacon |
| 14:21:55 | Network/flow | TCP/443 to 91.214.47.22; 184221/2415891 | Large inbound - likely download |
| 14:22:14 | Network/flow | TCP/443 to 91.214.47.22; 18421/42184 | Beacon |
| 14:35:00 | Network/flow | TCP/443 to 91.214.47.22; 8421/11421 | Beacon |

The PowerShell snippet in the readme classifies by `BytesReceived > 100000`. Under that rule, the 14:19:42 and 14:21:55 rows are tagged "Large inbound - likely download" and the rest "Beacon". `BytesReceived` counts bytes coming in to the host, so a large value is a download. Exfiltration would show as a large `BytesSent`.

**Verified via:** Same query as Step 2 with classification logic applied.

**Interpretation:** This snippet is the merge-ready timeline fragment from §8.4. Each row is a single network event with an artifact source and a one-line significance. It feeds directly into Lab 10's full multi-source timeline. The most defensible reading of the pattern: stager pull at 14:19:42 (small request, large response), C2 establishment at 14:21:48, large response (tooling pull or data return) at 14:21:55, ongoing beacon at 14:22:14, final beacon at 14:35:00.

---

## Summary

Five independent network sources, one picture:

| Step | Source | Finding |
|---|---|---|
| 1 | Aggregate flow | 16 host-relevant flows in 35-minute window; 6 anomalous to 91.214.47.22 |
| 2 | Aggregate flow | Large 2.4 MB inbound at 14:21:55 — the shape of a tooling pull, not exfiltration |
| 3 | Proxy | 5 CONNECT 91.214.47.22:443 from `FINANCE\payroll-admin`; first UA = Invoke-WebRequest |
| 4 | DNS | 3 PTR lookups, all NXDOMAIN — destination never had a hostname |
| 5 | Firewall | 4 inbound deny events from 185.193.126.47 (same IP as the EID 4625 spray); none for WKSTN-221, which the spray reached |
| 6 | Per-host flow | 4 flows attributed to `powershell.exe` (1) and `update.exe` (3) |

Two separate anomalies appear on the same day. The first is a finance workstation running a process it should never run, under an authenticated user, and talking to an unfamiliar external IP literal. The second is an inbound scan from a different external IP earlier that morning, which the perimeter denied elsewhere but not at WKSTN-221. The scan does not corroborate the C2 activity, and nothing here links the two to one actor. It does mean the workstation's activity sits in a hostile context, which is reason to keep scoping.
