# Lab 8.4 — Building a Network Timeline Snippet

**Supporting Section 8.4: Building a Network Timeline Snippet**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Network evidence becomes far more useful once you turn it into a timeline.

A responder can identify a suspicious stream, an unusual destination, a large outbound transfer, or a sequence of internal connections. Those observations become operational only once you place them in order. A timeline snippet helps you answer the questions incident response depends on:

- What happened first?
- Which connections clustered together?
- Did suspicious traffic happen before or after a file access or process launch?
- Which events are central enough to carry into the broader case timeline?

This lab focuses on building a concise network timeline snippet from packet captures, flow logs, ETL traces, or application logs. You will not build a full incident timeline yet. Instead, you will extract the network events that matter most from a short activity window. You will preserve them in a format you can later correlate with host, memory, execution, and user-activity evidence.

The lab teaches you to convert packet-level or session-level observations into a structured, defensible record that supports later reporting and scope decisions.

---

## What This Lab Covers

This lab supports the following concepts from Section 8.4:

| Section | Topic |
|---|---|
| 8.4.1 | Why timeline snippets matter in network IR |
| 8.4.2 | Selecting which network events belong in a timeline |
| 8.4.3 | Writing concise, useful event entries |
| 8.4 | Preparing network findings for later case-wide correlation |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain why network events are more useful when placed into a time-ordered sequence
- Select which packet, flow, or log events are worth carrying into a network timeline snippet
- Distinguish central timeline events from background noise
- Write clear, concise timeline entries that are usable later in case analysis
- Preserve enough detail to support later host correlation without overloading the timeline
- Separate strong observations from unsupported inferences
- Write a short analyst note that explains what the timeline snippet shows and what it does not

---

## Estimated Time

45–60 minutes

---

## Prerequisites

- Completion of Labs 8.1 through 8.3, or equivalent familiarity with network evidence sources, IR use cases, and packet-capture analysis
- A text editor or markdown editor
- Your `lab08-notes.md` file
- Packet captures, flow logs, ETL traces, or application logs from your lab scenario
- Optional: host-artifact notes from earlier labs for later correlation planning

---

## Scenario

You are continuing analysis of **FIN-WS23** during a suspicious 15-minute window.

Earlier work has already identified several network observations:

- Normal-looking browser traffic
- One or more connections to a suspicious test server
- At least one stream that may represent a large transfer or unusual session
- Timing that may later need to be matched against browser history, process execution, or memory findings

The case team needs a network timeline snippet to carry into the broader incident timeline. It does not want a full packet-analysis report yet.

Your task is to identify which network events matter most, order them clearly, write concise event entries, and document what the snippet does and does not support.

---

## Background: A Timeline Snippet Is a Forensic Reduction Tool

A good timeline snippet is a curated, evidence-based reduction of the events most relevant to the case. It is not a raw export of everything that happened on the network.

For network evidence, useful timeline entries often include:

- First connection to a suspicious destination
- Large or unusual outbound transfer
- Repeated connections to the same endpoint
- Internal host-to-host movement during the incident window
- Session start and end times for notable streams
- Requests or protocol actions that help explain what likely happened
- Points where network activity should later be correlated to host evidence

| Good Timeline Entry | Why It Helps |
|---|---|
| First outbound connection to unusual IP | Anchors suspicious contact in time |
| Large outbound transfer | Flags possible exfiltration review point |
| Repeated beacon-like session | Supports C2 theory or follow-up review |
| Internal SMB or RDP connection | Supports lateral-movement review |
| Access to cloud or file-sharing site | Supports delivery or exfiltration theory |

A poor timeline snippet usually has one of two problems:

- It is too broad and includes everything
- It is too interpretive and turns observations into conclusions too early

> **IR Reality Check:** A timeline snippet preserves the network events most worth correlating later. It does not need to be exhaustive.

---

## Lab Tasks

---

### Task 1 — Define What Belongs in a Network Timeline Snippet

**Objective:** Build a practical understanding of which network events are worth preserving.

Write a short explanation in 4–6 sentences covering:

- What a network timeline snippet is
- Why it is useful in incident response
- Why not every packet or session belongs in the timeline
- Why timeline entries should stay concise and evidence-based

Then complete the table below.

| Candidate Event Type | Belongs in Timeline Snippet? | Why |
|---|---|---|
| First connection to suspicious destination | | |
| Every DNS query in the capture | | |
| Large outbound transfer | | |
| Repeated short sessions to one host | | |
| Background broadcast noise | | |
| Internal RDP or SMB connection during suspicious window | | |
| Browser access to known benign site unrelated to case | | |
| Access to cloud-storage portal near suspicious activity | | |

Use the ratings:

- Yes
- Maybe / depends
- No

Then answer:

1. Why should timeline snippets focus on significance rather than volume?
2. Why can repeated small events still matter enough to include?
3. Why should timeline entries stay close to observed fact rather than interpretation?

---

### Task 2 — Identify the Best Candidate Events from the Capture

**Objective:** Select the network events that are most likely to matter later.

From your packet capture, flow logs, or lab notes, identify at least 10 candidate events that might belong in the timeline.

Use the table below.

| Candidate Event # | Observed Event | Time (UTC) | Why It Might Matter | Include in Final Snippet? |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |
| 6 | | | | |
| 7 | | | | |
| 8 | | | | |
| 9 | | | | |
| 10 | | | | |

Then answer:

1. Which candidates appear most central to the suspicious activity theory?
2. Which candidates may be contextual but not central?
3. Which candidates did you exclude, and why?

---

### Task 3 — Write Concise Timeline Entries

**Objective:** Practice turning raw observations into usable timeline language.

Choose eight of your best candidate events and write them as proper timeline entries.

Use the table below.

| Time (UTC) | Source | Destination | Event Description | Why It Matters |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

Your event descriptions should be concise and factual.

Good examples:

- "FIN-WS23 initiated HTTPS session to 10.10.10.50."
- "Outbound transfer to 10.10.10.50 exceeded normal browsing volume."
- "Internal SMB session opened to FILESRV-02 during suspicious window."

Weak examples:

- "Attacker exfiltrated data."
- "Malware beaconed to its controller."
- "User intentionally transferred sensitive files."

Then answer:

1. Why should timeline wording stay close to what was observed?
2. Why is "why it matters" a separate field from the event description?
3. Why does a concise format make later case integration easier?

---

### Task 4 — Distinguish Central Events from Supporting Events

**Objective:** Learn to prioritize the timeline entries that carry the most analytic value.

Classify each of the eight entries from Task 3 as:

- Central
- Supporting
- Probably background

Use the table below.

| Timeline Entry | Classification | Why |
|---|---|---|
| | | |
| | | |
| | | |
| | | |
| | | |
| | | |
| | | |
| | | |

Then answer:

1. Why are central events usually the ones that anchor later host correlation?
2. Why are supporting events still worth keeping?
3. Why should background events usually stay out of the final snippet?

---

### Task 5 — Prepare for Host Correlation

**Objective:** Make the timeline snippet useful for later cross-artifact analysis.

For each of the network events below, identify which host artifacts you would want to correlate later.

| Network Event Type | Best Host Artifact(s) to Correlate Next | Why |
|---|---|---|
| First suspicious outbound session | | |
| Large outbound transfer | | |
| Access to suspicious web or cloud service | | |
| Internal SMB or RDP traffic | | |
| Repeated short outbound sessions | | |
| Download-like traffic | | |

Then answer:

1. Why is a network timeline snippet most useful when it points to the next host question?
2. Why are process creation, browser history, and memory findings especially valuable here?
3. Why should the timeline snippet preserve enough detail for future correlation without becoming cluttered?

---

### Task 6 — Evaluate Competing Interpretations

**Objective:** Avoid overconfidence by testing alternate explanations for timeline events.

Choose two important network timeline entries and write:

- One suspicious interpretation
- One benign or less certain interpretation

Use the table below.

| Timeline Event | Suspicious Interpretation | Benign / Alternate Interpretation | Which Is Better Supported? | Why |
|---|---|---|---|---|
| | | | | |
| | | | | |

Then answer:

1. Why can normal application behavior sometimes produce timeline entries that look suspicious?
2. Why is this especially important for browser, SaaS, or internal-admin traffic?
3. Why should alternate interpretations be considered before escalating the timeline to leadership?

---

### Task 7 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined reporting from a network timeline.

Classify each statement below as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by the timeline alone

| Statement | Classification | Why |
|---|---|---|
| FIN-WS23 connected to the suspicious test server during the 15-minute window | | |
| An unusual outbound transfer occurred during the suspicious window | | |
| The transfer contained stolen sensitive data | | |
| Internal movement-related traffic deserves deeper review | | |
| The repeated session pattern is consistent with possible beaconing | | |
| The attacker definitely controlled the remote IP | | |
| The timeline supports prioritizing host-correlation work | | |
| The user intentionally caused the network activity | | |

Then write six additional statements of your own and classify them the same way.

> **Guidance:** A timeline snippet preserves what happened, in order. It is not a license to overstate what the traffic means.

---

### Task 8 — Write the Final Network Timeline Snippet

**Objective:** Produce the clean version you would store for later incident-timeline work.

Write your final timeline snippet as a clean block of entries.

Use this structure:

```
[UTC Timestamp] FIN-WS23 -> [Destination]: [Observed event]. [Why it matters briefly.]
```

Write at least six final entries.

Example format only:

```
2026-03-29 17:02:14 UTC  FIN-WS23 -> 10.10.10.50: Initiated HTTPS session. First connection to unusual destination in incident window.
2026-03-29 17:04:33 UTC  FIN-WS23 -> 10.10.10.50: Outbound transfer volume increased significantly. Candidate event for exfiltration review.
```

Then answer:

1. Why is this cleaner format useful for later case integration?
2. Why is this final snippet better than raw packet notes?
3. Why should the snippet be preserved even if later analysis revises your interpretation?

---

### Task 9 — Write a Timeline-Snippet Analyst Summary

**Objective:** Produce a short note explaining what the snippet shows and what it is for.

Write a 2–4 paragraph analyst summary describing:

- What the network timeline snippet captures
- Which events appear most important
- What the snippet strongly supports
- What still needs host or log correlation
- How the snippet should be used in the broader case timeline later

Write it as an internal working note.

---

### Task 10 — Reflection

Answer the following in 3–5 sentences each.

**1. Why timeline snippets matter**
Why is it useful to reduce network findings into a short, ordered sequence instead of leaving them as scattered observations?

**2. Signal versus noise**
Why is selecting the right events one of the most important parts of building a network timeline snippet?

**3. Correlation is the next step**
Why should a network timeline snippet usually lead directly into host, memory, or application-log correlation?

**4. Reporting discipline**
Why is it important that a timeline snippet preserve observed events without drifting into unsupported conclusions?

---

## Deliverables Checklist

Your `lab08-notes.md` should contain:

- [ ] **Task 1** — Timeline-snippet explanation and event-selection table
- [ ] **Task 2** — Candidate-event table with at least 10 entries
- [ ] **Task 3** — Eight concise timeline entries
- [ ] **Task 4** — Central vs supporting vs background classification table
- [ ] **Task 5** — Host-correlation planning table
- [ ] **Task 6** — Competing-interpretation analysis for two events
- [ ] **Task 7** — Strong support vs overclaim exercise
- [ ] **Task 8** — Final network timeline snippet with at least six entries
- [ ] **Task 9** — Timeline-snippet analyst summary
- [ ] **Task 10** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab08/
├── lab08-notes.md  ← Your working notes file (whole lab)
└── Lab08_04/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **A timeline snippet is a reduction tool.** It preserves the most important network events in order rather than reproducing the full capture.
- **Event selection matters.** The quality of the snippet depends on whether you kept the events that matter and excluded the noise.
- **Concise wording improves usefulness.** Clear, factual event entries are easier to carry into later case analysis.
- **Central events drive correlation.** The best network timeline entries point directly to the host artifacts that should be reviewed next.
- **Discipline matters.** A timeline snippet should record what happened and why it matters, without overstating what the traffic proves.

---

**Next:** Lab 09 — Windows Event Logs

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
