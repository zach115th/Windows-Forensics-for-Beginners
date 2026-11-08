# Chapter 8 — Review Question and Exercise Answers

*Sample answers for the Review Questions and Practical Exercises at the end of [`Chapter08.md`](../Chapter08.md). These are reference answers, not the only correct answers — your wording will differ and that is fine. What matters is whether your reasoning covers the same ground. For the corresponding lab, see [`Labs/Lab08/task-answers.md`](../../Labs/Lab08/task-answers.md).*

---

## Review Questions

**1. What are the main differences in fidelity, cost, and retention between full PCAP and flow data?**

PCAP records every byte of every observed packet with timing, so you can reconstruct file transfers, recover complete HTTP requests and responses, and inspect TLS handshakes in detail. Flow data records only a summary per conversation: source and destination IP and port, protocol, start and end time, and byte and packet counts in each direction. That difference in fidelity drives cost and retention. Full PCAP of a busy network runs to terabytes per day, so most organizations capture only at strategic choke points and retain days rather than months. Flow records are orders of magnitude smaller, so organizations typically retain them for months and can query them in seconds. For IR, the consequence is that by the time an incident is recognized, the PCAP window you want has usually rolled off, while flow data for the same window is still there. For most IR questions — *did this host talk to this IP, how much moved, for how long* — flow is sufficient.

**2. Why is pure network evidence often insufficient to identify the process responsible for a connection?**

The socket-to-process mapping exists only inside the operating system that owns the socket, and the operating system never transmits it. Network sensors observe traffic at a point on the wire, where the only identity available is an IP address and a port. A flow record showing `10.0.4.32:52916 → 91.214.47.22:443` establishes that something on WKSTN-221 made the connection. It cannot distinguish a browser tab from an injected PowerShell process. Closing that gap requires a host-side source. EDR network telemetry records the initiating process for each connection. A memory image's `netscan` output attributes live sockets to PIDs. Correlation with host artifacts can place a specific binary running in the same window. Without process attribution, a network connection is half a finding.

**3. When would `netsh trace` or `pktmon` be the right tool to use during incident response?**

Use them in two situations. The first is when no network sensor covers the host and nothing was capturing the relevant traffic. You cannot recover history you did not collect, but you can start collecting now by telling the host itself to capture. The second is when you need to answer a narrow live question about a specific host — *what is this process talking to right now?* — without waiting on infrastructure changes, SPAN port configuration, or a change window. Both are live-response tools, and both share the same limitation: they see only what that host sees, and only from the moment you start them. They rarely cover the historical window that matters to the incident, so they supplement rather than replace sensor-derived evidence.

**4. What kinds of application logs typically provide the richest context for HTTP-based investigations?**

Proxy logs provide the richest context. They record the full URL, the HTTP method, the user agent, the response code and size, the content category, and, most important, the authenticated username. That last field is attribution a packet capture cannot provide: `FINANCE\payroll-admin` next to a request is a user, not just an IP. Web server access logs cover the inbound side with source IP, request path, response code, and bytes returned, which is where web-shell activity shows. DNS server logs supply the name-to-address mapping that turns an unfamiliar IP in a flow record into a domain with reputation and registration history. Email gateway logs add sender, recipient, subject, attachment hash, and disposition. Application logs also usually have longer retention than PCAP and are already in the SIEM, which makes them the fastest source to query under time pressure.

**5. Why is encrypted traffic still useful evidence even when its content cannot be recovered?**

Because the metadata answers most of what IR asks. An encrypted session still reveals the endpoints, the timing, the duration, the byte counts in each direction, and the traffic shape. A 49-second TLS session that sent 184 KB and received 2.4 MB looks nothing like a normal short HTTPS request, and that asymmetry is legible without a single decrypted byte. Regular connections of near-identical size at a fixed interval are a beacon regardless of what they carry. TLS also exposes three identifiers before encryption starts: the SNI field naming the requested server, the JA3 fingerprint of the client's TLS hello, and the certificate subject and hash. JA3 can identify the client software even when the destination is unfamiliar. You can then infer content from host-side sources such as browser history, a sync client log, or an EDR file-write record, while the network provides the timing and volume the host cannot.

**6. How does EDR network telemetry complement traditional network capture?**

It supplies the one thing network sources structurally cannot: per-process attribution. EDR records the initiating process name, its full command line, often its parent process tree, and the destination IP, port, and byte counts. It records them from inside the host, where the socket-to-process mapping exists. That turns "this host talked to that IP" into "this specific `powershell.exe`, launched from `outlook.exe`, with this command line, talked to that IP." EDR also travels with the endpoint, so it covers hosts that never pass a monitored choke point, such as remote workers, cloud instances, and laptops on home networks. It does not replace capture. Coverage depends on what the agent collects and how long the platform retains it, and EDR carries no packet content. Together, network for the conversation and EDR for the owner make an attribution chain defensible.

**7. What evidence sources combine to support a defensible exfiltration finding?**

A clean exfiltration finding names the data, the channel, the timing, and the destination, and it takes several sources to get all four. Flow or proxy data establishes that a large outbound transfer happened, to where, when, and how much. EDR network telemetry identifies which process owned the connection. Host artifacts such as Prefetch, Amcache, the MFT, and the USN Journal confirm the process ran, identify the binary by hash, and show the files it staged. Where the destination is a known service, such as cloud storage or webmail, its application-level logs confirm the receiving end. Disk artifacts such as sync-client databases, browser upload traces, and archived staging directories corroborate the file content itself. Any one of these alone is a lead. The combination is a finding. In modern environments the channel is increasingly cloud-based, which makes the browser and cloud artifacts from Chapters 5 and 6 as important as the network layer.

**8. Why is documenting retention windows an important part of network forensic findings?**

Because a finding that depends on data the source will delete next month may become impossible to reproduce. If your conclusion rests on flow records the SIEM retains for 30 days, anyone reviewing the case after day 30 cannot verify it. If the case goes to litigation or regulatory review, someone may request that verification a year later. Documenting retention does three things: it tells you to preserve an export while the data still exists, it tells the reader how much weight the finding can bear, and it turns silence into a defensible statement. "The proxy retains 90 days and we queried within it, so the absence of a matching entry is meaningful" is a much stronger claim than an unqualified "no proxy record was found." The unqualified version is ambiguous between *it did not happen* and *we looked too late*.

**9. How does Wireshark's Conversations view accelerate triage?**

It collapses potentially millions of packets into one row per conversation, with packets and bytes in each direction, start time, and duration. Those are the fields IR triage sorts on. Sorting by total bytes surfaces the large transfers. Sorting by duration surfaces the long-lived sessions that beacons and interactive shells produce. Scanning the destination column surfaces unfamiliar endpoints. The same view shows the asymmetry between directions, which distinguishes a tool download (large inbound) from exfiltration (large outbound) and from a beacon-with-data-pull (both, sustained). It is a flow summary built from the capture you already have. The same output is available headlessly with `tshark -q -z conv,tcp`, which is how you script it or pipe it into filtering.

**10. What information should a network timeline snippet contain to merge cleanly with host-based timelines?**

At minimum: a UTC timestamp, the source host, the source IP and port, the destination IP and port, the protocol, bytes in and out, the owning process where known, the evidence source that produced the entry, a significance annotation, and a confidence rating. The UTC timestamp and the common column shape make the merge mechanical rather than manual, because they match the schema Chapter 10 uses for host-derived entries. The evidence source field carries the provenance, so a reader can trace any row back to the query that produced it. Significance and confidence turn sorted data into something readable: a row saying "likely C2 channel; large outbound transfer suggests exfiltration / High" does analytical work that a raw flow record does not.

---

## Practical Exercises

**1. Capture a brief PCAP of your lab VM browsing a few benign sites. Filter the PCAP in Wireshark by IP and time and identify the three most data-intensive conversations.**

**What you should end up with:** A `.pcapng` file and a three-row table naming each conversation's endpoints, byte counts in each direction, duration, and what it was.

**How to get there:** Capture with Wireshark or `dumpcap` while browsing three or four sites, then stop. Open *Statistics → Conversations*, switch to the TCP tab, and sort descending by total bytes. Filter to your VM with `ip.addr == <your VM IP>` and add a time bound if the capture is long.

**What good looks like:** You can account for all three, such as a page load with images, a video or update stream, and a telemetry endpoint. Note the direction asymmetry: normal browsing is heavily inbound. Once you recognize that shape, the inverted pattern of large outbound and small inbound stands out later as a possible exfiltration signature. If you want the contrast without capturing, [`Data/network/flow-data.csv`](../../Data/network/flow-data.csv) has both shapes in it.

**2. Use `netsh trace` to capture network activity for a defined ten-minute window on your lab VM. Convert the resulting `.etl` file to PCAP-format and load it in Wireshark.**

**What you should end up with:** An `.etl` file, a converted `.pcapng`, and notes on the conversion command and any content differences you observed.

**How to get there:** `netsh trace start capture=yes tracefile=C:\Triage\labvm_net.etl`, generate some traffic, then `netsh trace stop`. Convert with [etl2pcapng](https://github.com/microsoft/etl2pcapng): `etl2pcapng.exe labvm_net.etl labvm_net.pcapng`. Microsoft retired Message Analyzer in 2019, so the `etl2pcapng` route is the practical one. Do not spend time hunting for the old tool.

**What good looks like:** The converted file opens in Wireshark with a sane packet count and timestamps matching your capture window. Note in your write-up that `netsh trace` sees traffic only from the moment you started it, that it captures at the host, and that it takes a noticeable moment to stop and flush. Those characteristics make it a live-response tool, not a substitute for sensor data.

**3. Use `pktmon` to capture a short window of network traffic. Compare the output to `netsh trace` output for the same window.**

**What you should end up with:** A second capture from `pktmon` covering comparable activity, converted to PCAP, plus a short comparison of the two tools.

**How to get there:** `pktmon start --etw -p 0`, generate traffic, `pktmon stop`, then `pktmon etl2pcap PktMon.etl`. Run it over similar activity to your `netsh trace` capture so the comparison is meaningful.

**What good looks like:** A comparison written in operational terms: startup and teardown speed, per-component visibility, filter syntax, and native conversion. `pktmon` can show packets at multiple points in the network stack, which `netsh trace` does not expose as clearly. `pktmon` ships on Windows 10 and Server 2019 and later. `netsh trace` is present further back. Knowing which is available on the host in front of you matters more than which is technically superior.

**4. From a Wireshark capture of your lab VM, extract a downloaded file using *File → Export Objects*. Verify the extracted file's hash matches the original.**

**What you should end up with:** An extracted file, its SHA-256, the original's SHA-256, and a note on whether they matched.

**How to get there:** Download a small file over plain HTTP, not HTTPS, because the export does not work through TLS. Then use *File → Export Objects → HTTP*, select the object, and save it. Hash both copies with `Get-FileHash -Algorithm SHA256`. The scripted equivalent is `tshark -r capture.pcapng --export-objects http,extracted/`.

**What good looks like:** The hashes match, and you understand why the exercise required plain HTTP. The lesson is the boundary: content reconstruction works only for unencrypted protocols, and in a real environment nearly everything of interest is TLS. That is why the chapter emphasizes inferring content from host-side sources such as browser history, EDR file-write records, and sync client logs, while the network supplies timing and volume.

**5. Generate flow-style summary data from a PCAP using a tool like `tshark` (`tshark -r capture.pcap -q -z conv,ip`). Compare with the *Conversations* view in the GUI.**

**What you should end up with:** Text output from `tshark` and a note confirming it matches the GUI view, plus one filtering pipeline you built on top of it.

**How to get there:** Run `tshark -r capture.pcapng -q -z conv,tcp` and compare row-for-row against *Statistics → Conversations*. Then build the triage pipeline from the chapter: exclude known-good destinations and sort by bytes, for example `tshark -r capture.pcapng -q -z conv,tcp | grep -vE '52\.96\.|40\.126\.|13\.107\.' | sort -k7 -n -r | head -20`.

**What good looks like:** You have a repeatable one-liner rather than a set of GUI clicks. The scripted form scales across 10 captures, and you can paste it into a runbook. [`Data/network/flow-data.csv`](../../Data/network/flow-data.csv) is the same shape, already summarized. Filtering it for `91.214.47.22` yields the C2 sessions, including the `14:21:55` record with 184,221 bytes out and 2,415,891 bytes received over 49 seconds. That is the beacon-with-data-pull pattern the chapter describes.

**6. Configure a local browser with `SSLKEYLOGFILE` set, then capture and decrypt a short TLS conversation in Wireshark.**

**What you should end up with:** A key log file, a capture, and Wireshark showing decrypted HTTP inside the TLS sessions.

**How to get there:** Set the environment variable before launching the browser with `setx SSLKEYLOGFILE C:\Triage\sslkeys.log`, then start the browser from a fresh shell. Capture while browsing. In Wireshark, point *Preferences → Protocols → TLS → (Pre)-Master-Secret log filename* at the key file. The decrypted streams appear under the TLS layer.

**What good looks like:** You see plaintext HTTP inside what was previously opaque, and you understand why this almost never helps in a real case. A cooperating client has to have written the key log *during* the capture, which means someone deliberately configured it in advance. Retroactive decryption of captured TLS is not possible. The forensic takeaway is the constraint itself: plan for metadata-based analysis using SNI, JA3, certificate hashes, byte counts, and timing, not decryption.

**7. For a chosen process on your lab VM, build an attribution chain from a captured connection through EDR or memory evidence to the owning process and binary.**

**What you should end up with:** A numbered chain of four or five steps, each naming its evidence source, running from a network observation to a specific binary with a hash.

**How to get there:** Start from a connection in your flow or capture data. Attribute it to a process using EDR telemetry if you have it, or a memory capture and `windows.netscan` if you do not. Confirm the process ran using Prefetch. Identify the binary by hash using Amcache. Confirm the parentage using EDR or Security EID 4688. If you have no EDR in the lab, work the chain against the shipped data: [`Data/WKSTN-221/network-flow.csv`](../../Data/WKSTN-221/network-flow.csv) → `security-evtx.csv` EID 4688 → `prefetch.csv` → `amcache.csv` gives the same shape for `update.exe`. The chapter's own §8.3.5 walks the FIN-WS23 version.

**What good looks like:** Each step is one sentence and names its source, and the chain reads as a progression from vague to specific: *something on this host moved 6 MB* → *this process owned it* → *the process ran at this time* → *the binary has this hash and matches known tooling* → *it was launched by this parent, consistent with the delivery hypothesis*. You should be able to point at exactly which step makes the finding defensible rather than merely plausible.

**8. Build a five-row network timeline snippet for a fabricated lab scenario, with timestamps, source/destination, owning process, and confidence ratings.**

**What you should end up with:** A five-row CSV or table using the schema in §8.4.1: UTC timestamp, source, source IP/port, destination IP/port, protocol, bytes in/out, owning process, evidence source, significance, confidence.

**How to get there:** Either fabricate from your own lab capture or build it from the shipped WKSTN-221 network data, which has a natural five-row arc: `14:19:42` first observation of `91.214.47.22:443`, `14:21:48` beacon, `14:21:55` the large transfer (184 KB out / 2.4 MB in over 49 seconds), `14:22:14` beacon continuation, and `14:35:00` final beacon before quiet. All five are in [`Data/network/flow-data.csv`](../../Data/network/flow-data.csv), with corresponding CONNECT entries in `proxy-logs.csv` carrying the `FINANCE\payroll-admin` username.

**What good looks like:** Every row has a populated significance and confidence field, and the confidence ratings vary with the evidence rather than all being "High." The snippet should merge cleanly into a Chapter 10 host timeline without reformatting, with the same timestamp format and column semantics. Include one useful detail: `dns-queries.csv` shows only reverse PTR lookups for `91.214.47.22` returning NXDOMAIN, never a forward resolution. That absence is a finding — the connection was made to an IP literal, which is common in C2 tooling.

**9. Pick one network artifact file from your lab and document its hash, source description, retention conditions, and chain of custody entry.**

**What you should end up with:** A short provenance block: file name, SHA-256, the source that produced it (sensor, SIEM query, host trace command), the exact query or command, the time window covered, the source's retention window, and who has handled the file.

**How to get there:** Follow the naming convention from §8.4.2. `WKSTN221_flow_20241114_1400-1530.csv` encodes host, source type, and window in the file name itself. Hash the file on creation. Record the query verbatim, not paraphrased, so someone can re-run it.

**What good looks like:** Someone else could re-run your query, get the same data, and verify your hash. If the retention window has passed, the block tells them they cannot, which is itself useful information. The retention field is the one most often omitted and the one that most often matters later.

**10. Identify three internal sources in your environment that record network evidence (sensor, SIEM, EDR, proxy, etc.). Document each source's retention window and the kinds of IR questions it can answer.**

**What you should end up with:** A three-row table: source, what it records, retention window, query interface, owner or team to request it from, and the IR questions it can answer.

**How to get there:** This is a discovery exercise, and the discovery is the point. Ask the network team what sensors exist and where they sit. Ask the SIEM owner what indexes carry network data and what the retention tier is. Check whether the EDR console exposes network events and how far back. Check whether the proxy logs to the SIEM or only locally.

**What good looks like:** The table records what each source *cannot* answer alongside what it can. Flow data cannot tell you what was in the transfer. Proxy logs cover only proxied egress and miss direct-to-internet paths. EDR covers only instrumented hosts. The single highest-value output is discovering a gap before an incident rather than during one. Doing this exercise in advance turns the first hour of the next incident from *what do we even have?* into *pull these three things*.

---

## Common mistakes on this chapter

- **Treating an IP address as a verdict.** A connection to `91.214.47.22` is data, not a conclusion. Whether it matters depends on what that address is, who else in the environment talks to it, and what the host was doing at the time. Cloud and hosting providers put legitimate and malicious tenants on adjacent addresses, so "unfamiliar IP" is a lead. Build the finding from the destination, the owning process, the traffic pattern, and ideally threat-intel context, not from the address alone.

- **Reading absence of network evidence as absence of activity.** Sensors have coverage gaps, flow exporters sample, proxies only see proxied traffic, and firewalls in default configuration frequently do not log allowed connections at all. *We did not see it* and *it did not happen* are different statements, and conflating them produces confidently wrong reports. The honest form names the coverage: "the proxy covers browser egress and shows no upload; direct-to-internet paths bypass the proxy and are not covered by any source we have."

- **Stopping at the connection and skipping process attribution.** A flow record with no owning process is half a finding, and it is the half that does not survive scrutiny. "WKSTN-221 received 2.4 MB from an external address" invites the immediate question *which program?* If you cannot answer it, the finding cannot distinguish an attacker's tooling pull from a large legitimate download. EDR telemetry, memory `netscan`, or host-artifact correlation closes the gap, and one of those three is almost always available.

- **Chasing decryption instead of using metadata.** New responders lose hours trying to decrypt TLS that was never going to be decryptable. Retroactive decryption of captured TLS requires session keys that a cooperating client logged during capture. Meanwhile the metadata that was available the whole time answers the question: SNI, JA3, certificate hash, byte counts by direction, session duration, and inter-session timing. A 49-second session with 184 KB out and 2.4 MB in is legible without a single decrypted byte.

- **Failing to record retention, then losing the evidence.** Network sources age out on schedules nobody thinks about until the data is gone. A finding sourced from 30-day flow retention needs an exported, hashed subset saved into the case folder on day one, not a note saying "see SIEM." The chapter's guidance to save the filtered subset to a separate file is not just about analysis speed. It is the preservation step, and skipping it is how reproducible findings quietly become unverifiable ones.

- **Building the network timeline in a different schema from the host timeline.** Network output that uses local time, a different timestamp format, or column names that do not map to the host-side template creates a manual reconciliation step at exactly the moment the case is moving fastest. Normalize to UTC and to the Chapter 10 column shape when you produce the snippet, not when you try to merge it.
