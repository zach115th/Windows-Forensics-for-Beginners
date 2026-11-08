# Lab 08 — Network Forensics on Windows

**Supporting [Chapter 8: Network Forensics on Windows](../../Book/Chapter08.md)**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

The question "What did the attacker do on the network?" usually breaks down into five practical questions:

- Did data leave the environment?
- Which hosts talked to which systems?
- Was there beaconing or command-and-control activity?
- Did the attacker move laterally?
- What should we block right now?

Network evidence is one of the fastest ways to move from suspicion to scope. It shows communication patterns, timing, transfer size, protocols, destinations, and infrastructure relationships that are difficult to reconstruct from host artifacts alone. On Windows, that often means combining packet captures, flow logs, Windows tracing, and application-layer logs.

This lab introduces network forensics from an incident response perspective. You will generate traffic in a lab, capture it, and narrow the view to the relevant host and time window. Then you will identify suspicious or noteworthy streams, reconstruct what you reasonably can, and write a short timeline snippet for later inclusion in a larger incident timeline.

The goal is a repeatable workflow for answering the network questions that matter most during an incident, not to become a full-time packet analyst in one lab.

---

## What This Lab Covers

This lab supports the following sections from Chapter 8:

| Section | Topic |
|---|---|
| 8.1 | Sources of Network Evidence |
| 8.2 | Key IR Use Cases |
| 8.3 | Capture and IR-Focused Analysis Workflow |
| 8.4 | Building a Network Timeline Snippet |

---

## Learning Objectives

By completing this lab, you will be able to:

- Identify the main sources of Windows-relevant network evidence used in incident response
- Explain the difference between packet capture, flow data, ETL traces, and application logs
- Generate and capture network traffic in a controlled lab scenario
- Filter network evidence by host and time window
- Identify suspicious or noteworthy network patterns such as long-lived connections, large transfers, and unusual ports
- Reconstruct useful stream content where appropriate
- Build a concise network timeline snippet for later correlation with host artifacts

---

## Estimated Time and Difficulty

**Difficulty:** Intermediate

**First time through the material:** 2.5–4 h

**Refresh (already familiar with the chapter):** 60–90 min

> **Key terms used in this lab:** PCAP, flow data, Zeek, proxy logs, DNS logs, ETL traces, NetFlow. See the consolidated [Glossary](../../Book/Glossary.md) for definitions. The chapter cross-references in each entry take you back to the deeper coverage in `Book/`.

---

## Prerequisites

- Completion of Labs 01–07, or equivalent familiarity with Windows IR workflow, execution evidence, memory analysis, and timeline thinking
- A text editor or markdown editor
- Your `lab08-notes.md` file
- A Windows VM and either:
  - A monitoring VM with Wireshark or tcpdump, or
  - Wireshark on the Windows host itself
- A safe lab network
- A locally hosted test service or "suspicious" lab server you control

> **Working without a capture:** Pre-formatted network telemetry is in [`Data/network/`](../../Data/network/) (`flow-data.csv`, `proxy-logs.csv`, `dns-queries.csv`, `firewall-blocks.csv`). The same scenario's per-host network records are in [`Data/WKSTN-221/network-flow.csv`](../../Data/WKSTN-221/network-flow.csv). Use these for the analysis tasks if you are not generating your own captures.

> **Prerequisite outputs from earlier labs (optional but helpful):** This lab works the network side of the same WKSTN-221 attack you've seen disk-side in [Lab 04](../Lab04/ReadMe.md) and event-log-side in [Lab 09](../Lab09/ReadMe.md). The C2 IP `91.214.47.22` is the destination `update.exe` contacted. Prefetch, Amcache, and EID 4688 already placed that binary on the host and showed it ran. If you've worked those labs, you already have the host-side process attribution, and this lab adds the wire view. If you haven't, the network data still stands alone, but the strongest answers come from combining at least two of the three vantage points.

---

## Scenario

You are investigating a suspicious 15-minute window on a Windows host. The team believes the attacker may have:

- Browsed outward to normal-looking sites as cover
- Connected to an unusual internal or lab-controlled server
- Transferred data or staged communications during a short period of activity

You need to determine what happened on the network during that window and preserve a small, focused record that you can later correlate with host artifacts such as browser history, logs, memory, Prefetch, or process creation telemetry.

---

## Background: Sources of Network Evidence

Windows network forensics is rarely based on one artifact alone. Different network evidence sources answer different questions.

| Evidence Source | What It Helps Answer |
|---|---|
| **Packet captures** | Exact traffic contents, session behavior, protocol details |
| **Flow logs** | Who talked to whom, when, for how long, and how much |
| **Windows ETL traces** | Host-side tracing and low-level Windows networking context |
| **Application logs** | Proxy, web server, VPN, and service-specific activity |

Responders use these sources for four recurring goals:

- Confirming exfiltration or large outbound transfer activity
- Identifying C2 endpoints and infrastructure
- Understanding lateral movement paths
- Supporting blocking decisions for IPs, domains, or ports

| IR Use Case | Why Network Evidence Matters |
|---|---|
| **Exfiltration review** | Shows transfer size, direction, timing, and destination |
| **C2 identification** | Reveals repeated connections, beaconing, and suspicious endpoints |
| **Lateral movement analysis** | Shows internal host-to-host communication paths |
| **Blocking support** | Helps identify IPs, domains, ports, or services to contain |

> **IR Reality Check:** Network evidence is often strongest when paired with host evidence. A suspicious socket, browser visit, or PowerShell process becomes much more meaningful when the timing matches a packet stream.

---

## Lab Tasks

---

### Task 1 — Identify the Sources of Network Evidence

**Objective:** Build a practical understanding of the major network evidence sources introduced in the chapter.

Fill in the table below.

| Evidence Source | What It Is | What It Helps Answer | Limitation |
|---|---|---|---|
| Packet captures | | | |
| Flow logs | | | |
| Windows ETL traces | | | |
| Application logs | | | |

Then answer:

1. Why are packet captures usually richer than flow logs?
2. Why are flow logs still useful even when you do not have full packet data?
3. Why are application logs often necessary to understand user or service context?

---

### Task 2 — Map Network Evidence to Key IR Questions

**Objective:** Connect the right network evidence source to the right incident-response question.

For each question below, identify the best evidence source or sources to check first.

| Investigative Question | Best Evidence Source(s) to Check First | Why |
|---|---|---|
| Was data likely transferred off the host? | | |
| Which remote IP did the host communicate with? | | |
| Did the host maintain a long-lived outbound connection? | | |
| Did the host communicate with unusual internal systems? | | |
| What content was transferred over a session, if recoverable? | | |
| Which domain or service should we consider blocking? | | |

Then write six additional network-forensics questions of your own and map them the same way.

Afterward, answer:

1. Why is "best source" sometimes different for visibility versus proof?
2. Why do some network questions require multiple sources rather than one?
3. Why is a host-focused question often incomplete without network timing?

---

### Task 3 — Generate Controlled Traffic in the Lab

**Objective:** Create known traffic so you can practice capture and analysis.

In your lab, generate traffic from the Windows VM during a short activity window.

At minimum, generate two kinds of traffic:

- Normal-looking activity, such as web browsing
- Suspicious test activity, such as connecting to a locally hosted lab service

Document what you generated.

| Activity | Source Host | Destination | Approximate Time (UTC) | Why You Included It |
|---|---|---|---|---|
| Web browsing | | | | |
| Connection to test server | | | | |

Add at least three more traffic activities of your own.

Examples include:

- Downloading a test file
- Copying a file over HTTP to a local lab server
- Using PowerShell `Invoke-WebRequest`
- Connecting to an unusual port on a lab host
- Sustaining a long-lived test connection

Then answer:

1. Why is it useful to generate both normal and suspicious traffic in a lab?
2. Why should you record the approximate times of your actions?
3. Why does a known-good ground truth help when learning packet analysis?

---

### Task 4 — Capture the Traffic

**Objective:** Acquire the network evidence you will analyze.

Capture the traffic on:

- A monitoring VM, or
- The Windows host itself

Use Wireshark or an equivalent tool.

Record the details below.

| Field | Value |
|---|---|
| Capture tool | |
| Capture location (host / monitoring VM / sensor) | |
| Source host under review | |
| Capture file name | |
| Capture start time (UTC) | |
| Capture end time (UTC) | |
| Notes / warnings | |

Then answer:

1. Why does capture location matter?
2. Why should you record capture start and end times carefully?
3. Why can a host capture and a SPAN/sensor capture produce different visibility?

---

### Task 5 — Filter by Host and Time Window

**Objective:** Narrow the capture to the system and 15-minute window that matter.

Using Wireshark or an equivalent tool, filter the packet capture to the relevant:

- Source or destination host
- Time window
- Session set of interest

Document your filtering approach.

| Filter Goal | Filter or Method Used | Why It Matters |
|---|---|---|
| Narrow to source host | | |
| Narrow to time window | | |
| Narrow to suspicious destination(s) | | |
| Narrow to unusual port(s) | | |

Then answer:

1. Why is narrowing by host and time window one of the most important first steps?
2. Why can an unfiltered packet capture hide the important activity in noise?
3. Why should your notes record the exact filtering logic you used?

---

### Task 6 — Identify Interesting Streams

**Objective:** Find sessions that deserve incident-response attention.

Review the filtered capture and identify at least six streams or connection patterns worth noting.

Look for:

- Long-lived connections
- Large transfers
- Unusual ports
- Repeated connections to the same host
- Suspicious internal-to-internal traffic
- Unexpected external endpoints

Record your findings below.

| Stream / Connection | Why It Stands Out | What It Might Suggest | What It Does Not Prove |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |

Then answer:

1. Why do long-lived connections often deserve attention in C2 cases?
2. Why can large transfers matter in exfiltration review?
3. Why is an unusual port only a lead, not a conclusion?

---

### Task 7 — Reconstruct Content or Session Context

**Objective:** Recover useful content or protocol context where appropriate.

For one or more interesting streams, use:

- Follow TCP / UDP stream
- Export objects or file carving tools where appropriate
- Protocol dissection details
- Supporting session context

Record your work below.

| Stream | Reconstruction Method | What You Recovered or Observed | Why It Matters | Limitation |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

Then answer:

1. Why is stream following useful in IR-focused packet review?
2. Why is reconstructing content not always possible or appropriate?
3. Why should responders document both what they recovered and what they could not recover?

---

### Task 8 — Map the Network Activity to Likely Host Context

**Objective:** Prepare the network findings for later host correlation.

Based on the capture, identify what host-side artifacts you would want next to map traffic to a process, user, or action.

Fill in the table below.

| Network Finding | Best Host Artifact(s) to Correlate Next | Why |
|---|---|---|
| Suspicious outbound connection | | |
| Large transfer to test server | | |
| Browser traffic to a suspicious site | | |
| Connection on an unusual port | | |
| Repeated internal host-to-host session | | |

Then answer:

1. Why is packet data often stronger when paired with process or memory evidence?
2. Why is browser history useful when packet data suggests web access?
3. Why is process-to-connection mapping often critical before briefing leadership?

---

### Task 9 — Build a Timeline Snippet

**Objective:** Create the network-focused timeline fragment described in the chapter.

Write a short network timeline snippet using the relevant events from the 15-minute window.

Include at least eight entries if possible.

| Time (UTC) | Source | Destination | Activity | Why It Matters |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

Then answer:

1. Why is a timeline snippet more useful than a loose list of packet observations?
2. Which entries appear most central to the attacker-activity theory?
3. What additional host or log artifacts would make the timeline stronger?

---

### Task 10 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined language around network evidence.

Classify each statement below as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by this evidence alone

| Statement | Classification | Why |
|---|---|---|
| The host connected to a suspicious test server during the 15-minute window | | |
| A long-lived outbound session occurred during the capture window | | |
| The attacker definitely exfiltrated sensitive data | | |
| A large transfer to an unusual destination deserves deeper review | | |
| The observed IP is part of attacker-controlled infrastructure | | |
| The connection pattern is consistent with possible beaconing | | |
| This IP or domain may be a candidate for temporary blocking | | |
| The observed session was initiated intentionally by the user | | |

Then write six additional statements of your own and classify them the same way.

> **Guidance:** Network evidence can be compelling, but it often needs host-side correlation before you can make stronger claims about cause, process ownership, or attacker intent.

---

### Task 11 — Write a Network Findings Summary

**Objective:** Produce a concise working-note summary suitable for the case file.

Write a 3–5 paragraph analyst summary describing what the network evidence suggests about activity during the 15-minute window.

Your summary should include:

- The most important connections or streams you identified
- Whether the evidence suggests normal browsing, suspicious external contact, possible large transfer, or unusual internal movement
- What content or session context you were able to reconstruct
- What is strongly supported by the evidence
- What still requires correlation with host, memory, flow, or application-log artifacts

Write it as a working-note summary rather than a final incident conclusion.

---

### Task 12 — Write an Analyst Handoff Note

**Objective:** Make your network findings easy for another responder to continue.

Use the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Most Important Network Findings:
- 

Most Important Streams / Destinations:
- 

What Is Strongly Supported:
- 

What Is Suggested but Not Confirmed:
- 

Recommended Next Artifacts:
1.
2.
3.

Open Questions:
- 

Notes for Incoming Analyst:
```

---

### Task 13 — Reflection

Answer the following in 3–5 sentences each.

**1. Why network evidence matters**
Why is network evidence often one of the fastest ways to understand attacker scope and behavior?

**2. Content versus pattern**
Why can session patterns, duration, and transfer size matter even when you cannot reconstruct full content?

**3. Correlation is essential**
Why should packet findings usually be paired with host, memory, or application-log evidence before drawing stronger conclusions?

**4. Blocking decisions and caution**
Why should responders be careful before recommending blocks based only on a single suspicious connection?

---

## Hands-On Walkthrough (Using Simulated Data)

This walkthrough exercises Tasks 5–9 against the network telemetry in [`Data/network/`](../../Data/network/) and the per-host network records in [`Data/WKSTN-221/network-flow.csv`](../../Data/WKSTN-221/network-flow.csv). Commands are PowerShell.

### Step 1 — Load and filter the flow data

```powershell
$flow = Import-Csv 'Data\network\flow-data.csv'
$flow.Count
```

```python
import csv
with open('Data/network/flow-data.csv') as f:
    flow = list(csv.DictReader(f))
print(len(flow))
```

Expected: **33** rows. Filter to the WKSTN-221 incident window:

```powershell
$flow | Where-Object {
    $_.SourceIP -eq "10.0.4.32" -or $_.DestIP -eq "10.0.4.32"
  } | Where-Object {
    [DateTime]$_.FlowStart -ge [DateTime]"2024-11-14 14:00:00" -and
    [DateTime]$_.FlowStart -le [DateTime]"2024-11-14 14:35:00"
  } | Sort-Object FlowStart |
  Select-Object FlowStart, DestIP, DestPort, BytesSent, BytesReceived, Notes
```

```python
window = [r for r in flow
          if (r['SourceIP'] == "10.0.4.32" or r['DestIP'] == "10.0.4.32")
          and "2024-11-14 14:00:00" <= r['FlowStart'] <= "2024-11-14 14:35:00"]
window.sort(key=lambda r: r['FlowStart'])
for r in window:
    print(r['FlowStart'], r['DestIP'], r['DestPort'], r['BytesSent'], r['BytesReceived'], r['Notes'])
```

Expected: **16 flows** in the window — 4 to known M365 endpoints (`52.96.128.45`, `40.126.32.74`), 5 internal or multicast, 1 external DNS lookup, and **6 to the unfamiliar IP `91.214.47.22`**. Note that the unfamiliar destination accounts for more flows than any legitimate one.

### Step 2 — Identify the suspicious destination

```powershell
$flow | Where-Object { $_.DestIP -eq "91.214.47.22" } |
        Select-Object FlowStart, SourceIP, DestPort, BytesSent, BytesReceived
```

```python
for r in flow:
    if r['DestIP'] == "91.214.47.22":
        print(r['FlowStart'], r['SourceIP'], r['DestPort'], r['BytesSent'], r['BytesReceived'])
```

Expected: **6 rows** of flows from `10.0.4.32` to `91.214.47.22`. Five are TCP/443. The sixth, at 14:21:48, is a failed UDP/53 probe with zero bytes in either direction. The standout is at **14:21:55** — `BytesSent=184221`, `BytesReceived=2415891`.

Note the direction before you draw a conclusion from it. Roughly **2.4 MB came in and 184 KB went out**: that is the shape of a *download*, not a bulk upload. It is consistent with a second-stage payload or tasking arriving. The 184 KB outbound is consistent with beacon traffic, command output, or a small amount of stolen data, and the flow record alone does not separate those.

This dataset has no owning-process field. Network flow records collected at a network sensor never do. Attributing a flow to a process needs a host-side source, which is what Step 6 does with the per-host `Data/WKSTN-221/network-flow.csv`.

### Step 3 — Cross-check with the proxy logs

```powershell
$proxy = Import-Csv 'Data\network\proxy-logs.csv'
$proxy | Where-Object { $_.URL -like "*91.214.47.22*" } |
         Select-Object Timestamp, ClientIP, Username, Method, URL, UserAgent
```

```python
with open('Data/network/proxy-logs.csv') as f:
    proxy = list(csv.DictReader(f))
for r in proxy:
    if '91.214.47.22' in r['URL']:
        print(r['Timestamp'], r['ClientIP'], r['Username'], r['Method'], r['URL'], r['UserAgent'])
```

Expected: **5 rows** of `CONNECT 91.214.47.22:443` from `FINANCE\payroll-admin`. The first row's `UserAgent` is `Microsoft .NET CLR 4.8 (Invoke-WebRequest)`, which is the PowerShell cradle. The remaining four rows carry a literal `-` in `UserAgent`, the proxy's placeholder for a request that sent no user-agent header. That is the binary `update.exe` calling out without setting one. Filter on the `-` value, not on an empty field. Either signal is enough on its own: a `.NET CLR` UA on a CONNECT to a raw IP literal is unmistakable, and so are missing UAs on the same destination minutes later.

### Step 4 — Was the destination ever resolved through DNS?

```powershell
$dns = Import-Csv 'Data\network\dns-queries.csv'
$dns | Where-Object { $_.QueryName -like "*91.214.47.22*" } |
       Select-Object Timestamp, ClientIP, QueryName, ResponseCode
```

```python
with open('Data/network/dns-queries.csv') as f:
    dns = list(csv.DictReader(f))
for r in dns:
    if '91.214.47.22' in r['QueryName']:
        print(r['Timestamp'], r['ClientIP'], r['QueryName'], r['ResponseCode'])
```

Expected: **3 rows** of PTR-record reverse lookups for `91.214.47.22`, all with `NXDOMAIN`. Two lookups went out at 14:19:38, one to the internal resolver `10.0.0.10` and one to `8.8.8.8`, four seconds before the first connection at 14:19:42. A third went to the internal resolver at 14:35:00, at the final beacon. No hostname was registered for the IP, and the DNS log does not record which process asked. That's consistent with attacker infrastructure that uses raw IP literals.

### Step 5 — Spot the password-spray attempt in firewall logs

```powershell
$fw = Import-Csv 'Data\network\firewall-blocks.csv'
$fw | Where-Object { $_.SourceIP -eq "185.193.126.47" } |
      Select-Object Timestamp, SourceIP, DestIP, DestPort, RuleName
```

```python
with open('Data/network/firewall-blocks.csv') as f:
    fw = list(csv.DictReader(f))
for r in fw:
    if r['SourceIP'] == "185.193.126.47":
        print(r['Timestamp'], r['SourceIP'], r['DestIP'], r['DestPort'], r['RuleName'])
```

Expected: **4 rows** from `185.193.126.47`. Three are inbound SMB (TCP/445) denies at ~04:00 UTC, against `10.0.4.45`, `10.0.4.51`, and `10.0.4.18`. The fourth is an inbound DNS-over-TCP probe at 04:01:18 against the internal resolver `10.0.0.10`. Read the `DestPort` column rather than assuming all four are SMB. The fourth is the same scanner widening the sweep.

Now notice which host is missing. WKSTN-221 (`10.0.4.32`) has no deny row. Yet its Security log in `Data/WKSTN-221/security-evtx.csv` holds four EID 4625 failures from this IP, at 04:00:00, 04:00:11, 04:00:24, and 04:00:42 UTC. The attempts reached the workstation. The flow data agrees. Filter `flow` for `SourceIP == "185.193.126.47"`: the flow to `10.0.4.32:445` is a two-way session, while the flows to `10.0.4.45` and `10.0.4.51` are SYN-only with no reply. The missing deny row is a scoping finding. Some path let the scanner reach WKSTN-221's SMB port, and this data does not say which. A gap in a deny log means something only when another source shows the traffic arrived, as the flow data and the Security log do here.

### Step 6 — Build the network attribution chain

For the `91.214.47.22` flows in Step 2, attribute each connection to a process by joining with the per-host `network-flow.csv`:

```powershell
$wkflow = Import-Csv 'Data\WKSTN-221\network-flow.csv'
$wkflow | Where-Object { $_.DestIP -eq "91.214.47.22" } |
          Select-Object FlowStart, OwningProcess, BytesSent, BytesReceived, Notes
```

```python
with open('Data/WKSTN-221/network-flow.csv') as f:
    wkflow = list(csv.DictReader(f))
for r in wkflow:
    if r['DestIP'] == "91.214.47.22":
        print(r['FlowStart'], r['OwningProcess'], r['BytesSent'], r['BytesReceived'], r['Notes'])
```

Expected: **4 flows**, each annotated with `OwningProcess`: `powershell.exe` for the 14:19:42 stager flow and `update.exe` for the three flows that follow, including the 14:21:55 data pull. The per-host telemetry carries fewer entries than the perimeter flow data from Step 2. The perimeter sees six flows to the same destination, and only four are attributed to a host process before the agent's session rotates. The 14:21:48 UDP/53 probe and the 14:35:00 final beacon are missing from the per-host file. That is why the two views complement each other rather than overlap exactly. EDR or per-host network telemetry ties bytes-on-wire to the responsible binary. Without it, a perimeter view shows traffic but not the process that owns it.

### Step 7 — Build a network timeline snippet

```powershell
$flow | Where-Object { $_.DestIP -eq "91.214.47.22" } |
        Sort-Object FlowStart |
        ForEach-Object {
          [PSCustomObject]@{
            Time         = $_.FlowStart
            Source       = "Network/flow"
            Description  = "Outbound $($_.Protocol)/$($_.DestPort) to $($_.DestIP); $($_.BytesSent)B out / $($_.BytesReceived)B in"
            Significance = if ([int]$_.BytesReceived -gt 100000) { "Large inbound - likely download" } else { "Beacon" }
          }
        } | Format-Table -AutoSize
```

```python
rows = [r for r in flow if r['DestIP'] == "91.214.47.22"]
rows.sort(key=lambda r: r['FlowStart'])
for r in rows:
    desc = f"Outbound {r['Protocol']}/{r['DestPort']} to {r['DestIP']}; {r['BytesSent']}B out / {r['BytesReceived']}B in"
    sig = "Large inbound - likely download" if int(r['BytesReceived']) > 100000 else "Beacon"
    print(r['FlowStart'], "Network/flow", desc, sig)
```

That's the merge-ready timeline snippet from §8.4. Each row is a single network event with an artifact source and a one-line significance, the format you'll feed into Lab10's full multi-source timeline.

### What you've just done

Five independent network sources point to the same picture: flow, proxy, DNS, firewall, and per-host flow with process attribution. A finance workstation contacted an unfamiliar external IP that no DNS source can name, through a process that should not be making outbound connections. The byte counts are consistent with a tooling pull rather than a normal HTTPS request. A separate inbound scan from a different external IP came earlier the same day. The perimeter denied it at three hosts and the DNS server, but not at WKSTN-221, which it reached. The scan does not corroborate the C2 activity, and nothing here links the two to one actor. It does place the workstation in a hostile context, which is reason to keep scoping. Walk back through Tasks 5–9 of the lab, and you have concrete data for every cell of the analyst-notes scaffold.

---

## Deliverables Checklist

Your `lab08-notes.md` should contain:

- [ ] **Task 1** — Network-evidence source table with written responses
- [ ] **Task 2** — Question-to-evidence mapping with six added questions
- [ ] **Task 3** — Traffic-generation table with added activities
- [ ] **Task 4** — Capture record
- [ ] **Task 5** — Host/time-window filtering table
- [ ] **Task 6** — Interesting-streams table with at least six findings
- [ ] **Task 7** — Reconstruction / stream-follow table
- [ ] **Task 8** — Network-to-host correlation table
- [ ] **Task 9** — Network timeline snippet with at least eight entries where possible
- [ ] **Task 10** — Strong support vs overclaim exercise
- [ ] **Task 11** — Network findings summary
- [ ] **Task 12** — Analyst handoff note
- [ ] **Task 13** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab08/
├── ReadMe.md                     ← This file
├── lab08-notes.md                ← Your working notes file (fill this in)
├── walkthrough-answers.md        ← Sample answers for the Hands-On Walkthrough
├── task-answers.md               ← Sample answers for the workbook Tasks
├── Lab08_01/ReadMe.md            ← Ch8 §8.1 — Sources of Network Evidence
├── Lab08_02/ReadMe.md            ← Ch8 §8.2 — Key IR Use Cases
├── Lab08_03/ReadMe.md            ← Ch8 §8.3 — Capture and IR-Focused Analysis
└── Lab08_04/ReadMe.md            ← Ch8 §8.4 — Building a Network Timeline Snippet
```

---

## Key Takeaways

- **Network evidence answers scope and behavior questions quickly.** It helps show who talked to whom, when, and how much.
- **Different sources answer different questions.** Packet captures, flows, ETL traces, and application logs each contribute differently.
- **Filtering matters.** Narrowing by host and time window is often the difference between useful analysis and noise.
- **Interesting streams are leads, not verdicts.** Long-lived connections, large transfers, and unusual ports deserve review but still need context.
- **Correlation makes network findings stronger.** The best network conclusions are reinforced by host, memory, browser, and application evidence.

---

**Next:** Lab 09 — Windows Event Logs

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
