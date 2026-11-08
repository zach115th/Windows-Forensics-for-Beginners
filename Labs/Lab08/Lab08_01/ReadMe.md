# Lab 8.1 — Sources of Network Evidence

**Supporting Section 8.1: Sources of Network Evidence**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

"Looking at the network" usually means looking at several very different evidence sources at once.

A packet capture is not the same as a firewall flow log. A Windows ETL trace is not the same as a proxy log. A VPN log is not the same as a host-based capture. All of these can be useful, but they answer different questions, preserve different levels of detail, and come with different limitations.

This lab focuses on the main sources of network evidence introduced in Chapter 8:

- Packet captures
- Flow logs
- Windows ETL traces
- Application logs

The goal is to understand what each source is, what it is good and not good for, and how to choose the right source for the question in front of you. Effective network forensics starts with knowing how these evidence types differ and why no single source tells the whole story.

---

## What This Lab Covers

This lab supports the following concepts from Section 8.1:

| Section | Topic |
|---|---|
| 8.1.1 | Packet captures |
| 8.1.2 | Flow logs |
| 8.1.3 | Windows ETL traces |
| 8.1.4 | Application-layer logs |
| 8.1.5 | EDR network telemetry |
| 8.1.6 | Zeek and network sensor logs |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain the major sources of Windows-relevant network evidence used in incident response
- Distinguish between packet-level, flow-level, host-trace, and application-log visibility
- Identify what each evidence source is strongest at revealing
- Recognize the major limitations of each evidence source
- Map common IR questions to the most useful network evidence source
- Write concise notes describing what source was used and why it mattered

---

## Estimated Time

35–50 minutes

---

## Prerequisites

- Completion of Labs 01–07, or equivalent familiarity with Windows IR workflow and basic evidence handling
- A text editor or markdown editor
- Your `lab08-notes.md` file
- Optional: access to sample packet captures, firewall logs, Windows ETL traces, or proxy/VPN logs

---

## Scenario

Your IR team is investigating suspicious outbound activity from a Windows workstation named **FIN-WS23**. The team knows the system communicated with at least one unusual remote destination during a short incident window, but it is unsure where to look first.

Available evidence sources may include:

- A packet capture from a monitoring point
- Flow logs from a firewall
- A Windows host trace collected with `netsh trace`
- Proxy and VPN logs from enterprise infrastructure

A junior responder asks:

> *"Which one of these actually tells us what happened?"*

Each one tells part of the story.

Your task in this lab is to identify what each source can reveal, where it is strongest and weakest, and how to choose the right one for the investigative question.

---

## Background: Network Evidence Comes in Layers

Not all network evidence has the same depth.

Some evidence sources preserve full packet detail. Others reduce communication to summaries. Some come from the host itself. Others come from infrastructure. Some show content, while others show only timing, endpoints, and counts.

| Evidence Source | Typical Detail Level | Common Strength |
|---|---|---|
| **Packet capture** | High | Exact session and protocol detail |
| **Flow logs** | Moderate | Communication summary and scope |
| **Windows ETL traces** | Host-focused | Windows networking context and troubleshooting detail |
| **Application logs** | App/service-specific | User, proxy, VPN, or service-layer context |

Each source is useful because it answers different questions:

- Packet captures help you inspect sessions directly.
- Flow logs help you see who talked to whom, when, for how long, and how much.
- Windows ETL traces help you investigate host-side networking behavior on Windows.
- Application logs help explain what the traffic meant in business or user terms.

> **IR Reality Check:** Good network forensics is often about combining incomplete sources, not waiting for one perfect source that explains everything.

---

## Lab Tasks

---

### Task 1 — Define the Four Main Sources of Network Evidence

**Objective:** Build a practical understanding of the main evidence sources in Chapter 8.

Fill in the table below.

| Evidence Source | What It Is | What It Commonly Contains | Why It Matters in IR |
|---|---|---|---|
| Packet captures | | | |
| Flow logs | | | |
| Windows ETL traces | | | |
| Application logs | | | |

Then answer:

1. Why is a packet capture different from a flow log?
2. Why are host traces different from infrastructure logs?
3. Why is application context often important in addition to raw network data?

---

### Task 2 — Compare Strengths and Limitations

**Objective:** Learn what each source is best at and where it falls short.

Complete the table below.

| Evidence Source | Strongest Use | Biggest Limitation | Example IR Question It Helps Answer |
|---|---|---|---|
| Packet captures | | | |
| Flow logs | | | |
| Windows ETL traces | | | |
| Application logs | | | |

Then answer:

1. Why are packet captures often considered the richest source?
2. Why are flow logs still useful even without payload data?
3. Why might application logs be the most useful source for understanding user or service behavior?

---

### Task 3 — Map IR Questions to the Right Evidence Source

**Objective:** Practice choosing the right source for the right question.

For each investigative question below, identify the best evidence source or sources to check first.

| Investigative Question | Best Evidence Source(s) to Check First | Why |
|---|---|---|
| Which remote IP did the host talk to? | | |
| Was there a large outbound transfer? | | |
| What exact HTTP request or session content was sent, if available? | | |
| Which VPN session was associated with a user? | | |
| Did the host make repeated short connections to the same destination? | | |
| Which site or service did the user access through the proxy? | | |
| What local Windows networking activity was observed on the host? | | |
| What infrastructure should be considered for blocking? | | |

Then write six additional questions of your own and map them the same way.

Afterward, answer:

1. Why do some questions have more than one good answer source?
2. Why is the best source for "content" often different from the best source for "scope"?
3. Why should responders frame the question before choosing the data source?

---

### Task 4 — Packet Captures: What They Can and Cannot Tell You

**Objective:** Build disciplined expectations around packet data.

Assume you have a packet capture covering the incident window.

Fill in the table below.

| Packet-Capture Question | What PCAP Can Help Show | Why It Matters | Limitation |
|---|---|---|---|
| Which endpoints communicated? | | | |
| Which ports and protocols were used? | | | |
| Whether a session was long-lived | | | |
| Whether content can be reconstructed | | | |
| Whether data transfer volume appears significant | | | |

Then answer:

1. Why is packet content sometimes available and sometimes not useful?
2. Why can encrypted traffic still be valuable even without decrypted payloads?
3. Why should responders document the capture point when using a PCAP?

---

### Task 5 — Flow Logs: What They Can and Cannot Tell You

**Objective:** Understand why flow data is often a fast scoping source.

Assume you have firewall or NetFlow/IPFIX-style records.

Fill in the table below.

| Flow-Log Question | What Flow Data Can Help Show | Why It Matters | Limitation |
|---|---|---|---|
| Which systems communicated? | | | |
| How long the communication lasted | | | |
| Approximate amount of data transferred | | | |
| Whether traffic was repeated or beacon-like | | | |
| What exact content was sent | | | |

Then answer:

1. Why are flow logs often useful for exfiltration scoping?
2. Why are they often weaker than PCAP for reconstructing session detail?
3. Why can flow logs still be the best available evidence in many real incidents?

---

### Task 6 — Windows ETL Traces and Application Logs

**Objective:** Separate host-side tracing from service-specific logs.

For this task, compare Windows ETL traces and application logs such as proxy, VPN, or web server logs.

Fill in the table below.

| Evidence Source | What It Helps Answer | Why It Matters | Limitation |
|---|---|---|---|
| Windows ETL traces | | | |
| Proxy logs | | | |
| VPN logs | | | |
| Web server logs | | | |
| Other application logs | | | |

Then answer:

1. Why can ETL traces be useful when infrastructure visibility is incomplete?
2. Why are proxy and VPN logs often critical in enterprise investigations?
3. Why should application logs be correlated with host or packet evidence when possible?

---

### Task 7 — Choose the Best Source for the Scenario

**Objective:** Apply the chapter's evidence-source concepts to a live IR-style problem.

For the FIN-WS23 scenario, assume the team wants answers to these questions:

- Did the host talk to an unusual remote destination?
- Was there a large outbound transfer?
- What should we consider blocking?
- Did a user's VPN or proxy activity line up with the suspicious window?

Build a simple source-selection plan.

| Question to Answer | First Source to Check | Second Source to Check | Why This Order Makes Sense |
|---|---|---|---|
| Unusual remote destination | | | |
| Large outbound transfer | | | |
| Blocking decision support | | | |
| User-linked activity | | | |

Then answer:

1. Why did you choose those sources first?
2. Which source would be best for quick scoping?
3. Which source would be best for detailed follow-up?

---

### Task 8 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined language around network evidence sources.

Classify each statement below as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by that source alone

| Statement | Classification | Why |
|---|---|---|
| A packet capture can show the endpoints involved in a session | | |
| A flow log can prove the exact content transferred | | |
| A Windows ETL trace may show host-side networking context | | |
| A proxy log can help tie web access to a specific service or user context | | |
| A VPN log automatically proves malicious intent | | |
| A packet capture may help reconstruct part of a transferred stream | | |
| Flow data may support a theory of large outbound transfer | | |
| Application logs alone always tell the full story | | |

Then write five additional statements of your own and classify them the same way.

> **Guidance:** This lab is about understanding source value and source limits. Stay disciplined about what each source supports.

---

### Task 9 — Write a Short "Sources of Network Evidence" Analyst Note

**Objective:** Produce a concise working note explaining which network evidence sources matter in this case.

Write a 2–4 paragraph analyst summary describing which network evidence sources would be most useful for the FIN-WS23 scenario.

Your summary should include:

- Which sources are available or most relevant
- What each source could help answer
- Which source you would prioritize first and why
- What limitations you would expect from each source

Write it as an internal case note, not a final incident conclusion.

---

### Task 10 — Reflection

Answer the following in 3–5 sentences each.

**1. Why multiple sources matter**
Why is network forensics often stronger when multiple evidence sources are combined instead of relying on only one?

**2. Detail versus scale**
Why are packet captures often stronger for detail, while flow logs are often stronger for scoping?

**3. Host versus infrastructure visibility**
Why can ETL traces and application logs answer questions that raw packet data may not answer well?

**4. Choosing the right source first**
Why does good incident response depend on matching the investigative question to the right network evidence source?

---

## Deliverables Checklist

Your `lab08-notes.md` should contain:

- [ ] **Task 1** — Definitions table for the four main sources plus written responses
- [ ] **Task 2** — Strengths-and-limitations comparison table
- [ ] **Task 3** — IR-question-to-evidence mapping with six added questions
- [ ] **Task 4** — Packet-capture review table with written responses
- [ ] **Task 5** — Flow-log review table with written responses
- [ ] **Task 6** — ETL and application-log comparison table
- [ ] **Task 7** — Scenario-based source-selection plan
- [ ] **Task 8** — Strong support vs overclaim exercise
- [ ] **Task 9** — "Sources of Network Evidence" analyst note
- [ ] **Task 10** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab08/
├── lab08-notes.md  ← Your working notes file (whole lab)
└── Lab08_01/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **Network evidence comes in layers.** Packet captures, flows, ETL traces, and application logs each preserve different kinds of truth.
- **No single source answers every question.** The best source depends on whether you need detail, scope, host context, or service context.
- **Packet captures are rich, but not always available.** Flow and application logs often become the practical backbone of real investigations.
- **Windows host traces matter too.** ETL traces can provide host-side context that infrastructure logs may miss.
- **Question-driven source selection is the real skill.** Good responders choose the evidence source based on what they need to prove or disprove.

---

**Next:** Lab 8.2 — Key IR Use Cases

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
