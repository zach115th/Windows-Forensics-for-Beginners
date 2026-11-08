# Lab 08 — Task Answer Key

*Sample answers for the workbook-style Tasks in `Labs/Lab08/ReadMe.md`. These are reference answers, not the only correct answers — your wording may legitimately differ. The reasoning matters more than the prose. For the Hands-On Walkthrough at the end of the lab, see `walkthrough-answers.md` in the same folder.*

---

## Task 1 — Identify the Sources of Network Evidence

**Sample table:**

| Evidence Source | What It Is | What It Helps Answer | Limitation |
|---|---|---|---|
| Packet captures | Full session content — every byte that crossed the sensor | Exact protocol behavior, file content, session reconstruction | High storage cost; encrypted payloads usually opaque; capture requires planning |
| Flow logs (NetFlow / IPFIX / Zeek conn.log / per-host flow) | Metadata-level connection records: src/dst, ports, timing, byte counts | Who talked to whom, when, for how long, how much | No payload; sampling can drop short flows |
| Windows ETL traces | Host-side network tracing produced by Windows event tracing | Per-process socket events, name resolution, low-level networking diagnostics | Not enabled by default; volume can be high; requires dedicated tooling to parse |
| Application logs (proxy, web server, VPN, DNS, firewall) | Service-level records of requests, responses, blocks | User identity, URL, HTTP method, user-agent, block reason — context that flow alone lacks | Each application logs differently; gaps where the service did not handle the traffic |

**Q1:** Why are packet captures usually richer than flow logs?

A packet capture records every byte of every session. From it you can reconstruct files, follow TCP streams, inspect TLS handshakes, and replay protocol behavior. Flow logs record only metadata — addresses, ports, byte counts, timestamps. Only the capture answers deep "what was actually transferred" questions. The trade-off is size: captures are far larger than flows. Captures are rarely retained for more than hours or days, while flows can be retained for months.

**Q2:** Why are flow logs still useful even when you do not have full packet data?

Most IR questions are about *who talked to whom, when, and how much* — exactly what flow records answer. Flow scales: a perimeter device that cannot retain weeks of PCAP can retain weeks of flow. Flow also lets you ask population-scale questions that PCAP search tooling rarely scales to, such as "every host that talked to `91.214.47.22` in the last 30 days." Flow is the right tool for scoping. PCAP is the right tool for forensic detail on a specific session.

**Q3:** Why are application logs often necessary to understand user or service context?

Different evidence sources answer different parts of the question. Flow shows that `10.0.4.32` connected to `91.214.47.22:443`. The proxy log shows that user `FINANCE\payroll-admin` initiated the connection as a `CONNECT 91.214.47.22:443` with a `Microsoft .NET CLR 4.8 (Invoke-WebRequest)` user-agent. Flow gave you the connection. The proxy log gave you the user, the tool, and a strong inference about the originating PowerShell cradle.

---

## Task 2 — Map Network Evidence to Key IR Questions

**Sample table:**

| Investigative Question | Best Evidence Source(s) to Check First | Why |
|---|---|---|
| Was data likely transferred off the host? | Flow logs (byte counts), per-host flow with process attribution | Flow shows direction and volume cheaply; per-host flow ties bytes to a process |
| Which remote IP did the host communicate with? | Flow logs, firewall / proxy logs | Flow is the cheapest "destination inventory" source |
| Did the host maintain a long-lived outbound connection? | Flow logs (FlowEnd - FlowStart durations) | Flow records flow duration directly |
| Did the host communicate with unusual internal systems? | Flow logs, firewall logs (internal sensors) | Internal east-west visibility is usually flow- or sensor-based |
| What content was transferred over a session, if recoverable? | Packet captures (PCAP) | Only PCAP carries payload content |
| Which domain or service should we consider blocking? | DNS logs, proxy logs, threat intel | DNS + proxy show the names; intel decides the blocks |

**Six added questions (sample):**

| Investigative Question | Best Evidence Source(s) to Check First | Why |
|---|---|---|
| Did this host beacon? | Flow logs (regular small flows to the same destination) | Beaconing shows as a cadence in flow; not visible in single-session PCAP |
| Did the user reach a phishing URL? | Proxy logs, browser history, DNS | Proxy is authoritative for outbound HTTP/S; browser history corroborates |
| Was DNS used to resolve a suspicious hostname? | DNS query logs | The resolution event is in DNS logs, including NXDOMAIN |
| Was a password spray attempted against the perimeter? | Firewall logs, authentication logs | Firewall captures inbound 445/3389/etc.; auth logs show the matching failed logins |
| Did an SMB connection happen between two internal hosts? | Flow logs (internal sensor), Windows ETL | Internal east-west needs internal visibility |
| Did the host connect to known C2 infrastructure? | Threat-intel join against flow, proxy, DNS | Intel is the join key; the network sources answer "did we see it" |

**Q1:** Why is "best source" sometimes different for visibility versus proof?

Visibility favors broad, cheap sources such as flow, DNS, and proxy summaries. They can answer "did the host talk to this destination at all." Proof favors authoritative narrow sources — full PCAP for exact bytes, EDR for process attribution, proxy logs for user identity. A flow record may give you a lead, but you usually need a different source to support the strong claim. Distinguish the two roles when reading and citing evidence.

**Q2:** Why do some network questions require multiple sources rather than one?

The strongest claims layer independent evidence. "The host connected to `91.214.47.22`" is one source (flow). "The connection was attributable to `update.exe` running as `payroll-admin`" is a second source (per-host flow + EDR or proxy auth). "The destination was never resolved through DNS — only reached as a raw IP literal" is a third (DNS log). Each one alone is weak. Layered, they describe an attacker who connects to a hard-coded IP with a specific binary under a specific account. That pattern is hard to mistake for normal activity.

**Q3:** Why is a host-focused question often incomplete without network timing?

Host artifacts can show that `update.exe` ran but cannot show whether it talked to anything outside the host. Even if SRUM captures byte counts, it does not give you the remote destination cleanly. Network timing from flow records, with `FlowStart` and `FlowEnd`, closes that loop. It ties the host execution to a specific outbound conversation at a specific moment.

---

## Task 3 — Generate Controlled Traffic in the Lab

**Sample table (illustrative for a lab acquisition):**

| Activity | Source Host | Destination | Approximate Time (UTC) | Why You Included It |
|---|---|---|---|---|
| Web browsing | `LAB-WS01` | `example.com`, `news.example.org` | 2024-11-21 14:00–14:05 | Baseline normal HTTPS activity |
| Connection to test server | `LAB-WS01` | `10.0.99.50:8443` (lab C2 stand-in) | 2024-11-21 14:07 | Suspicious-looking outbound to a non-standard port |
| HTTP file download | `LAB-WS01` | `http://10.0.99.50/tools/loader.zip` | 2024-11-21 14:09 | Simulated payload download |
| PowerShell `Invoke-WebRequest` to lab server | `LAB-WS01` | `https://10.0.99.50/payload.txt` | 2024-11-21 14:11 | Reproduces an in-memory loader cradle for analysis |
| Sustained long-lived connection | `LAB-WS01` | `10.0.99.50:443` (10-minute hold) | 2024-11-21 14:13–14:23 | Models a beacon or interactive-shell session |
| Connection on unusual port | `LAB-WS01` | `10.0.99.50:55555` | 2024-11-21 14:14 | Catches unusual-port filter behavior |

**Q1:** Why is it useful to generate both normal and suspicious traffic in a lab?

Without normal baseline traffic, every alert is suspicious by definition. You cannot tell whether your filter is finding the right things or just finding the only things. Routine browsing traffic gives you a realistic noise floor that the suspicious activity has to stand out against. It also lets you practice the analyst skill that matters most in production: noticing what is anomalous in a sea of legitimate noise.

**Q2:** Why should you record the approximate times of your actions?

Wall-clock times in your notes anchor the capture-side findings. When the analysis shows a connection at 14:07:33 UTC, your notes saying "I initiated the test-server connect at ~14:07" turn that finding into ground truth. Without recorded times you cannot tell whether a capture artifact is your action or noise.

**Q3:** Why does a known-good ground truth help when learning packet analysis?

You can check your work. If you generated five distinct activities and your analysis identified four of them, you know your filter or technique is missing the fifth — and you can iterate. Real incidents do not come with ground truth. Learning to ask the right questions of network data is much easier when you can grade yourself against what you actually did.

---

## Task 4 — Capture the Traffic

**Sample table (illustrative):**

| Field | Value |
|---|---|
| Capture tool | Wireshark 4.2 |
| Capture location (host / monitoring VM / sensor) | Monitoring VM with mirrored SPAN port |
| Source host under review | `LAB-WS01` (10.0.4.32) |
| Capture file name | `lab08-2024-11-21.pcapng` |
| Capture start time (UTC) | 2024-11-21 14:00:00 |
| Capture end time (UTC) | 2024-11-21 14:25:00 |
| Notes / warnings | TLS sessions opaque (no key material); capture passed through one switch hop |

**Q1:** Why does capture location matter?

Each capture location has different blind spots, so location determines what the data can and cannot answer. A capture taken on the host itself sees every byte the host's network stack produces, including traffic that fails to leave the NIC, retransmissions, and locally bound sessions. A capture on a SPAN port sees what the switch forwarded — exactly the bytes that traversed the network. A perimeter capture sees only what crossed the boundary. Host capture misses what other hosts did, and perimeter capture misses internal east-west traffic. Recording the capture location tells the reader which of these limits apply.

**Q2:** Why should you record capture start and end times carefully?

The capture window defines the universe of events. A finding outside the window is not absent — it is unobserved. If the capture started after the C2 connection began, you may see the session in progress but miss the initial handshake. Documenting the window prevents misreading absence-of-evidence as evidence-of-absence.

**Q3:** Why can a host capture and a SPAN/sensor capture produce different visibility?

Host captures include host-local traffic that never leaves the box, see TLS in plaintext if a local key-log is configured, and pick up every retransmission. SPAN captures can suffer switch buffer drops under load, miss host-local traffic entirely, and may catch traffic the host's network stack discarded. Comparing the two helps confirm that a finding is real network activity rather than a local stack artifact.

---

## Task 5 — Filter by Host and Time Window

**Sample table:**

| Filter Goal | Filter or Method Used | Why It Matters |
|---|---|---|
| Narrow to source host | `ip.addr == 10.0.4.32` (Wireshark); `SourceIP == '10.0.4.32' OR DestIP == '10.0.4.32'` (CSV filter) | Removes the noise from every other host on the segment |
| Narrow to time window | `frame.time >= "2024-11-14 14:00" && frame.time <= "2024-11-14 14:35"` | Focuses on the 35-minute incident window |
| Narrow to suspicious destination(s) | `ip.dst == 91.214.47.22` | Isolates the specific C2 candidate |
| Narrow to unusual port(s) | `tcp.port == 8443 \|\| tcp.port == 55555` | Hunts for non-standard service ports |

**Q1:** Why is narrowing by host and time window one of the most important first steps?

Unfiltered captures contain thousands or millions of packets that have nothing to do with the incident. Even modest filtering — one host and a 35-minute window — typically reduces the working set by orders of magnitude and makes pattern-spotting possible. Doing it first also forces you to state which host and which window your evidence covers. That keeps later findings honest.

**Q2:** Why can an unfiltered packet capture hide the important activity in noise?

A few packets to a C2 destination can be lost among thousands of routine packets to legitimate cloud endpoints, Windows Update servers, and corporate services. The most common failure on raw captures is missing the relevant activity entirely, not misinterpreting it.

**Q3:** Why should your notes record the exact filtering logic you used?

Reproducibility. Another analyst running your filter against the same data should produce the same findings. A filter can be wrong: too narrow, off by one timezone, or missing an IP variant. The findings are then unreliable, and you cannot diagnose the problem without the exact filter. Recording the filter is part of the chain-of-evidence for any network finding.

---

## Task 6 — Identify Interesting Streams

**Sample table (six findings, WKSTN-221 / Data/network scenario):**

| Stream / Connection | Why It Stands Out | What It Might Suggest | What It Does Not Prove |
|---|---|---|---|
| `10.0.4.32 → 91.214.47.22:443` at 2024-11-14 14:21:55, BytesSent 184,221 / BytesReceived 2,415,891 | Asymmetric pull pattern — small request, ~2.4 MB inbound | Tooling pull or staged-payload retrieval | What was actually pulled |
| 5 proxy log rows `CONNECT 91.214.47.22:443` by `FINANCE\payroll-admin` | One row has User-Agent `Microsoft .NET CLR 4.8 (Invoke-WebRequest)`; four have empty UA | PowerShell cradle followed by binary calls | Whether the cradle delivered the binary |
| 3 DNS PTR-record lookups for `91.214.47.22` returning NXDOMAIN | Host's resolver asked for a hostname after the fact; nothing registered | C2 reached as a raw IP literal — typical of attacker infrastructure | That the IP itself is malicious; only that no hostname is associated |
| 4 firewall denies from `185.193.126.47` at ~04:00 UTC, three SMB and one DNS-over-TCP, with none for WKSTN-221 | Different external IP scanning inbound at a different time of day. WKSTN-221's Security log shows four 4625s from it, so the scan reached a host the same rule denied elsewhere | Possible password-spray reconnaissance and a gap in perimeter filtering | Which path let the scanner reach WKSTN-221, or a link to the 14:00 outbound activity beyond shared day |
| Repeated short flows from `10.0.4.32 → 91.214.47.22:443` (6 total in flow data) | Small repeating connections to same destination | Beaconing cadence | Beacon contents |
| Per-host flow attribution: `powershell.exe` for early stager flows, `update.exe` for the data-pull flow | Process attribution available only in per-host telemetry | Same destination is touched by two distinct binaries | What the binaries are doing — needs host artifacts |

**Q1:** Why do long-lived connections often deserve attention in C2 cases?

Most legitimate HTTPS sessions are short — a page load, an API call, a brief handshake. C2 channels often hold connections open for control: a reverse shell, an interactive operator session, or a beacon that pings every minute. A multi-minute or multi-hour outbound TCP session is anomalous against typical browsing traffic. Combined with an unfamiliar destination, it is one of the higher-signal patterns flow data produces.

**Q2:** Why can large transfers matter in exfiltration review?

Data movement leaves footprints in flow byte counts. A `BytesSent=184221` / `BytesReceived=2415891` flow is asymmetric toward the host: 2.4 MB received against 184 KB sent. That is the shape of a payload pull, which is what the WKSTN-221 case shows. A large `BytesSent` to an external destination is the classic exfiltration shape. Either way, the byte counts move the question from "did they connect" to "did data move" — and how much.

**Q3:** Why is an unusual port only a lead, not a conclusion?

Plenty of legitimate services run on non-standard ports: corporate VPNs, some SaaS APIs, internal applications. A `tcp/55555` flow is a lead that warrants a look at the destination, the byte counts, and the owning process. By itself, it is not evidence of malice. The conclusion comes from layering the port with destination context, timing, process attribution, and protocol detail.

---

## Task 7 — Reconstruct Content or Session Context

**Sample table:**

| Stream | Reconstruction Method | What You Recovered or Observed | Why It Matters | Limitation |
|---|---|---|---|---|
| `10.0.4.32 → 91.214.47.22:443` | TCP stream follow + TLS metadata inspection | TLS handshake; SNI (if present); JA3 fingerprint of the client | Identifies the client-side TLS implementation; SNI may reveal a hostname not in DNS logs | Payload is encrypted; cannot recover content without key material |
| `CONNECT 91.214.47.22:443` proxy session | Proxy log entry inspection | User-Agent strings: `Microsoft .NET CLR 4.8 (Invoke-WebRequest)` and blank UA | Identifies the user, the tool (PowerShell cradle), and a subsequent binary that did not set a UA | Proxy logs preserve metadata, not payload |
| HTTP download to `10.0.99.50` (lab) | TCP stream follow + Export Objects (Wireshark) | The downloaded file extracted from the session | Direct content recovery proves what was transferred | Only works with cleartext protocols |

**Q1:** Why is stream following useful in IR-focused packet review?

Following a stream takes you from packet-level fragments to the session-level conversation a human can read. For cleartext protocols such as HTTP, plain FTP, and plaintext SMB, it recovers the literal payload. For TLS, it surfaces the handshake, SNI, and certificate exchange — metadata that often answers the case-relevant question even when the payload is opaque. It also makes the protocol behavior easier to interpret than scrolling packet lists.

**Q2:** Why is reconstructing content not always possible or appropriate?

TLS sessions are encrypted. Without server-side keys or pre-master-secret key logging, the payload is opaque. Even cleartext protocols may carry only metadata if the actual transfer happened over a separate channel. In many investigations, content reconstruction also crosses into privacy territory, such as HR cases, attorney-client communications, and healthcare data. It then requires legal sign-off before you proceed. Always confirm that recovery is both technically feasible and authorized before doing it.

**Q3:** Why should responders document both what they recovered and what they could not recover?

A finding that says "files recovered from the session" is incomplete without "but the TLS session to the C2 was opaque." Documenting the absence of evidence and its cause prevents the reader from misreading silence as "nothing happened." It also tells the next analyst which gaps to try to close, such as key material, additional capture, or server-side logs. That spares them re-attempting what is already known to be unrecoverable.

---

## Task 8 — Map the Network Activity to Likely Host Context

**Sample table:**

| Network Finding | Best Host Artifact(s) to Correlate Next | Why |
|---|---|---|
| Suspicious outbound connection | SRUM (network data), EDR network events, Sysmon EID 3, per-host flow with `OwningProcess` | Per-process attribution to map the connection to a binary |
| Large transfer to test server | SRUM bytes, EDR network bytes, host firewall log, Prefetch for the binary | Confirms which process moved the data |
| Browser traffic to a suspicious site | Browser history, browser cache, Office document downloads | Identifies the user-side context of the browse |
| Connection on an unusual port | Sysmon EID 3 + EID 1 chain, EDR ProcessCreate | Ties the port to the process that opened it |
| Repeated internal host-to-host session | Security log EID 4624 (incoming logon), shares accessed, Sysmon EID 3 on both endpoints | Lateral movement requires logon evidence on the destination |

**Q1:** Why is packet data often stronger when paired with process or memory evidence?

PCAP can tell you the host had a session. EDR or SRUM can tell you which process owned it. Memory (`netscan`) can tell you the same with per-PID attribution. Each layer answers a different question: destination (PCAP/flow), process (EDR/SRUM/memory), and user (host event log). The strongest cases stack at least two of these on the same flow. A network finding without a process attribution is hard to act on, but both together are hard to dispute.

**Q2:** Why is browser history useful when packet data suggests web access?

PCAP gives you `https://example.com/path`, or its TLS SNI. Browser history adds the user identity, meaning which profile loaded the page. It also adds the visit time on the host clock, the Transition value (typed, link, search-result, redirect), and previous/next URL context. Together they show *which* user visited the page, *how* they got there, and what they did next.

**Q3:** Why is process-to-connection mapping often critical before briefing leadership?

Leadership wants a process-level story, not a packet-level one. Its questions usually sound like "what is this binary on this host doing?" A finding of "a connection to `91.214.47.22:443`" is meaningless to a director. By contrast, "the `update.exe` process under the `payroll-admin` account pulled ~2.4 MB from `91.214.47.22:443` at 14:21 UTC" is actionable. The process-to-connection mapping makes the network finding briefable.

---

## Task 9 — Build a Timeline Snippet

**Sample 8-row snippet (using the WKSTN-221 / Data/network dataset):**

| Time (UTC) | Source | Destination | Activity | Why It Matters |
|---|---|---|---|---|
| 2024-11-14 04:00–04:01 | `185.193.126.47` | Multiple internal hosts, TCP/445 and TCP/53 | Firewall denies: three inbound SMB attempts and one DNS-over-TCP probe from an external IP. No deny for WKSTN-221, whose Security log shows four failed logons from the same IP | Reconnaissance / password-spray context. The missing WKSTN-221 deny is a perimeter gap to scope |
| 2024-11-14 14:00 (approx) | Internal `10.0.4.32` | `52.96.128.45`, `40.126.32.74`, `13.107.42.14` | Routine M365 traffic | Baseline of normal activity in the window |
| 2024-11-14 14:19:38 | Host resolver | PTR query for `91.214.47.22`, to `10.0.0.10` and to `8.8.8.8` | NXDOMAIN ×2 | The host looked up the IP four seconds before connecting; no name exists |
| 2024-11-14 14:19:42 | Proxy: `FINANCE\payroll-admin` | `CONNECT 91.214.47.22:443` | UA `Microsoft .NET CLR 4.8 (Invoke-WebRequest)` | First contact. PowerShell cradle; user identity captured |
| 2024-11-14 14:19:42 | `10.0.4.32` | `91.214.47.22:443` | Per-host flow attribution: `powershell.exe`, 1,847 bytes out / 184,221 in | Confirms the cradle is the originator |
| 2024-11-14 14:21:48–14:35:00 | Proxy: same user | `CONNECT 91.214.47.22:443` | Four more rows with UA `-` | Binary calls without UA — consistent with `update.exe` |
| 2024-11-14 14:21:55 | `10.0.4.32` | `91.214.47.22:443` | BytesSent 184,221 / BytesReceived 2,415,891; `OwningProcess=update.exe` | Asymmetric pull — ~2.4 MB inbound; the shape of a download, not exfiltration |
| 2024-11-14 14:35:00 | Host resolver | PTR query for `91.214.47.22` | NXDOMAIN | Third lookup, at the final beacon; still no name |

**Q1:** Why is a timeline snippet more useful than a loose list of packet observations?

A snippet sequences the facts: the scan in the early morning, a failed name lookup, the cradle, the attributed flows, the large pull, and a last lookup at the final beacon. Each row gains meaning from its neighbors. A loose list invites cherry-picking and leaves the reader to figure out the order, which is usually where misinterpretation enters. The snippet is also the format you will merge into a full multi-source incident timeline later.

**Q2:** Which entries appear most central to the attacker-activity theory?

Three entries are central: the 14:21:55 flow with the asymmetric byte pattern and `update.exe` attribution, the 14:19:42 proxy entry tying `powershell.exe` to the cradle, and the connection from a finance workstation to an IP with no DNS record. Together they describe a binary that should not be making outbound connections. The host is reaching a destination no DNS source can name, under an account that should not be running PowerShell-cradle-style tooling.

**Q3:** What additional host or log artifacts would make the timeline stronger?

Host-side process-tree confirmation for `powershell.exe` parent and child (Sysmon EID 1 / EDR). MFT and Amcache evidence for `update.exe`. Prefetch evidence of one-time execution. Security log 4624 entries for `payroll-admin`'s logon. Browser history if the cradle came from a click. EDR file-write events for whatever the 2.4 MB pull dropped on disk, if it dropped anything.

---

## Task 10 — Separate Strong Support from Overclaims

| Statement | Classification | Why |
|---|---|---|
| The host connected to a suspicious test server during the 15-minute window | Strongly supported | Flow + proxy + DNS all show the connection |
| A long-lived outbound session occurred during the capture window | Strongly supported (if flow shows duration) | Duration is a directly measurable field |
| The attacker definitely exfiltrated sensitive data | Suggested but needs corroboration | The byte counts in WKSTN-221 actually show a pull, not a push; "exfiltration" needs different evidence |
| A large transfer to an unusual destination deserves deeper review | Strongly supported (as a recommendation) | Recommendations are easy to support; conclusions are harder |
| The observed IP is part of attacker-controlled infrastructure | Suggested but needs corroboration | Needs threat intel, WHOIS, or multi-host correlation |
| The connection pattern is consistent with possible beaconing | Suggested but needs corroboration | "Consistent with" is appropriately hedged; needs cadence analysis to confirm |
| This IP or domain may be a candidate for temporary blocking | Strongly supported (as a recommendation) | Blocking recommendations are scoped to risk; even imperfect evidence can warrant one |
| The observed session was initiated intentionally by the user | Not supported by this evidence alone | Intent is never in network data; needs interview, host artifacts, policy context |

**Six added statements (sample):**

| Statement | Classification | Why |
|---|---|---|
| `update.exe` made an outbound connection to `91.214.47.22:443` | Strongly supported | Per-host flow with `OwningProcess` shows this directly |
| The 14:21:55 flow pulled approximately 2.4 MB from the destination | Strongly supported | `BytesReceived=2,415,891` is a direct measurement |
| The PowerShell `Invoke-WebRequest` cradle delivered the `update.exe` binary | Suggested but needs corroboration | Timing and UA are suggestive; need host MFT/Amcache for the binary's file-create time |
| `91.214.47.22` is the same C2 IP used against WEB-APP-03 | Strongly supported | The IP appears in both datasets |
| The host was the only one in the environment to reach `91.214.47.22` | Suggested but needs corroboration | Needs a flow query across all internal hosts in the same window |
| The inbound SMB scan and the outbound C2 are the same attacker | Not supported by this evidence alone | Same day and same target environment is not the same attacker; needs additional attribution |

---

## Task 11 — Write a Network Findings Summary

**Sample summary:**

Network review of the 14:00–14:35 UTC window on 2024-11-14 for source host `10.0.4.32` (WKSTN-221) shows a coherent suspicious-outbound pattern alongside routine M365 traffic. Six flows in the perimeter dataset terminate at `91.214.47.22:443`, an external IP with no associated DNS record. Three PTR-record reverse lookups during the window returned NXDOMAIN. The standout flow at 14:21:55 carries `BytesSent=184,221` and `BytesReceived=2,415,891`. That is an asymmetric pull pattern, ~2.4 MB inbound and ~184 KB outbound, which the per-host telemetry attributes to `update.exe`.

Proxy logs show 5 `CONNECT 91.214.47.22:443` rows under `FINANCE\payroll-admin`. The first row has a `Microsoft .NET CLR 4.8 (Invoke-WebRequest)` user-agent — strongly suggestive of a PowerShell cradle initiating the contact. The remaining 4 rows have empty User-Agent fields and align in time with `update.exe`'s flows in the per-host telemetry. That fits a binary that does not set a UA, following on after the cradle. Firewall logs from earlier the same day (~04:00 UTC) show four inbound denies from a separate external IP, `185.193.126.47`: three SMB scan attempts and one DNS-over-TCP probe. None is for WKSTN-221. Yet the host's Security log in `Data/WKSTN-221/security-evtx.csv` records four failed logons from that IP, and the flow data shows a two-way SMB session to `10.0.4.32`. The scan reached WKSTN-221 by a path the data does not identify. The same `91.214.47.22` IP appears in the WEB-APP-03 memory dataset, suggesting the same attacker across hosts.

Four points are strongly supported. The host connected to `91.214.47.22:443` repeatedly during the window. A ~2.4 MB pull occurred at 14:21:55, attributable to `update.exe`. An earlier flow at 14:19:42 was attributable to `powershell.exe`. The destination has no DNS record.

Three points are suggested but need corroboration. Whether the PowerShell cradle delivered `update.exe` needs host MFT/Amcache and Prefetch for `update.exe`'s creation and execution times. Whether `91.214.47.22` is attacker-controlled needs threat intel or sweep results. A link between the inbound scan and the outbound C2 also needs corroboration.

Recommended next: MFT/$LogFile for `update.exe`, and Sysmon EID 1 / EDR ProcessCreate to confirm the PowerShell → `update.exe` chain. Also run an EDR sweep across the environment for `91.214.47.22`, and review the host's browser history during the window for cradle-delivery context. Find the path that let `185.193.126.47` reach WKSTN-221's SMB port.

---

## Task 12 — Write an Analyst Handoff Note

**Sample handoff note:**

```
Case Reference:    IR-2024-1114-WKSTN221-NET
Author:            (your name)
Date/Time (UTC):   2024-11-14 15:30

Most Important Network Findings:
- 6 flows from 10.0.4.32 to 91.214.47.22 between 14:19:42 and 14:36:00: five on TCP/443 and one UDP/53 probe the perimeter denied
- 14:21:55 flow: BytesSent 184,221 / BytesReceived 2,415,891
  (asymmetric pull) attributed to update.exe
- Proxy: 5 CONNECT 91.214.47.22:443 rows by FINANCE\payroll-admin;
  first has UA "Microsoft .NET CLR 4.8 (Invoke-WebRequest)"
- DNS: 3 PTR reverse lookups for 91.214.47.22, all NXDOMAIN
- Firewall: 4 inbound denies from 185.193.126.47 at ~04:00 UTC (3 SMB, 1 DNS-over-TCP);
  no deny for WKSTN-221, whose Security log shows 4 failed logons from that IP

Most Important Streams / Destinations:
- Destination IP 91.214.47.22:443 (also appears in WEB-APP-03 memory dataset)
- Source process update.exe and earlier powershell.exe
- User context FINANCE\payroll-admin

What Is Strongly Supported:
- Host connected to 91.214.47.22:443 repeatedly during the window
- A ~2.4 MB inbound pull at 14:21:55 was attributable to update.exe
- An earlier flow was attributable to powershell.exe
- Destination has no DNS hostname record

What Is Suggested but Not Confirmed:
- PowerShell cradle delivered update.exe (need host artifacts)
- 91.214.47.22 is attacker-controlled (need intel)
- Inbound scan and outbound C2 share an actor

Recommended Next Artifacts:
1. MFT + Amcache + Prefetch for update.exe on WKSTN-221
2. Sysmon EID 1 / EDR ProcessCreate for the 14:00–14:25 UTC window
3. EDR / SIEM sweep for any host contact with 91.214.47.22

Open Questions:
- How did update.exe arrive on disk?
- Did the cradle come from a click (browser history) or another source?
- Is payroll-admin the user's real account or a compromised credential?
- What path let 185.193.126.47 reach WKSTN-221 on TCP/445?

Notes for Incoming Analyst:
The network view is solid: destination, byte pattern, process attribution,
user identity, DNS-less infrastructure, multi-host IP overlap. The gap to
close is the host side — once MFT/Amcache and ProcessCreate are aligned to
this window, the case is briefable. Treat 91.214.47.22 as a candidate
block while host work continues.
```

---

## Task 13 — Reflection

**1. Why network evidence matters**

Network evidence answers scoping questions faster than almost anything else. Within minutes of an alert you can ask "did this destination touch any other host," "what binary made the outbound," and "how much data moved." Flow, proxy, DNS, and per-host telemetry answer those questions without forensic imaging. Network evidence is also durable in ways that host evidence is not: flow can be retained for months, while the attacker can delete disk artifacts in seconds. For "how big is this incident" and "what should we block right now," network is usually the fastest path to a useful answer.

**2. Content versus pattern**

You will frequently see encrypted sessions you cannot decrypt, but they do not make the network evidence useless. The *pattern* of the session still carries information. Cadence (regular small flows at fixed intervals = beacon). Duration (10-minute outbound TLS to an unfamiliar destination = persistence). Byte asymmetry (small `BytesSent`, large `BytesReceived` = pull; the opposite = exfil). Repeated connections to the same destination from a non-browser process. Each of these patterns is recognizable without content, and together they often answer the IR question better than partial content would.

**3. Correlation is essential**

Network evidence is strongest when paired with host, memory, and application-log evidence. A flow record showing `update.exe` reaching `91.214.47.22:443` is meaningful. Now pair the same flow with Prefetch evidence that `update.exe` ran once 30 seconds before the flow opened. Add a Sysmon EID 1 showing `powershell.exe` as the parent, and a SHA-1 in Amcache that matches a known IOC. That combination is briefable. Stand-alone network findings invite "is that really yours? could that be normal?" pushback. Layered findings do not.

**4. Blocking decisions and caution**

Blocks affect availability. A wrongly placed block can break a legitimate service, cost money, and burn responder credibility. Before recommending a block based on one suspicious connection, weigh four questions. How confident are you in the destination? How widely does the indicator appear in the environment? Is the block surgical (one IP, one port) or broad (a whole CIDR)? Is it temporary or permanent? The right pattern is usually "temporary, narrow, monitor, escalate." Permanent broad blocks come after thorough corroboration.

---

## Ready-to-move-on self-check

Before starting Lab 09, confirm you can answer these three questions cold. If any feel wobbly, revisit the relevant task.

1. **Why does a `BytesSent=184221 / BytesReceived=2415891` flow look more like a pull than exfiltration?**  *Answer:* Exfiltration shows large `BytesSent` (data leaving) and small `BytesReceived` (mostly ACKs). The WKSTN-221 14:21:55 flow shows the opposite: a small request and a large response. That fits a tooling or payload pull, not data leaving. Direction of byte asymmetry is the cheapest discriminator between the two.
2. **What does it mean that DNS PTR queries for `91.214.47.22` returned NXDOMAIN?**  *Answer:* The host's resolver asked for a hostname for the IP and none was registered. That does not prove the IP is malicious. It is consistent with attacker infrastructure that uses raw IP literals instead of DNS. It also rules out a connection to a well-known service that the host already knew by name.
3. **Which network source uniquely gives you per-process attribution that perimeter logs cannot?**  *Answer:* Per-host (EDR / Sysmon EID 3 / Windows ETL) network telemetry. The perimeter sees the bytes leaving the host. Only the host-side source can tie those bytes to the specific binary that opened the socket.

---

## Walkthrough ↔ workbook bridges

> After Walkthrough Step 1, revisit Task 5.Q1 (narrowing by host and time window). The PowerShell `Where-Object` filter on `SourceIP/DestIP == "10.0.4.32"` plus the 35-minute time window is the concrete filtering logic the workbook was asking you to formalize. Of 33 flows in the dataset, 16 fall in the relevant window, and the rest are noise.

> After Walkthrough Step 2, revisit Task 6.Q2 (large transfers in exfiltration review). The 14:21:55 flow with `BytesSent=184,221` / `BytesReceived=2,415,891` to `91.214.47.22` attributed to `update.exe` is the concrete byte pattern your workbook answer was describing abstractly. The direction (small out / large in) tells you it is a *pull*, not exfiltration, which the workbook self-check picks up.

> After Walkthrough Step 3, revisit Task 7.Q1 (stream-follow value). The proxy log rows are the metadata-level equivalent of stream-follow output. The User-Agent `Microsoft .NET CLR 4.8 (Invoke-WebRequest)` is the kind of "client identity from session metadata" that the workbook question was probing for.

> After Walkthrough Step 5, revisit Task 9.Q3 (additional artifacts to strengthen the timeline). The firewall blocks from `185.193.126.47` at ~04:00 UTC are the kind of "earlier reconnaissance" entry that turns a 15-minute outbound-only window into a fuller day-scale picture. The missing deny row for WKSTN-221 belongs in the timeline too, because the scan reached that host.

> After Walkthrough Step 6, revisit Task 8.Q3 (process-to-connection mapping for briefing). The per-host flow with `OwningProcess=update.exe` / `powershell.exe` is the concrete per-process attribution the workbook was talking about. Perimeter flow shows the connection, but only per-host telemetry names the binary that owned it.
