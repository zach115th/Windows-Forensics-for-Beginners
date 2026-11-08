# Lab 8.3 — Capture and IR-Focused Analysis

**Supporting Section 8.3: Capture and IR-Focused Analysis**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

In incident response, packet analysis means getting from raw traffic to defensible answers as quickly as possible. It rarely means reviewing every packet in a capture.

A responder usually starts with a narrow operational question:

- What did this host do during the suspicious window?
- Which connections matter?
- Was there a large transfer?
- Did the host talk to an unusual endpoint?
- Which sessions deserve follow-up with host artifacts?

The real skill goes beyond capturing traffic. You need to capture the right traffic, reduce the noise, and isolate the relevant host and timeframe. Then you identify interesting streams and preserve the key observations in a form you can later correlate with memory, logs, browser history, or process telemetry.

This lab walks through that workflow. You will generate and capture lab traffic, filter it by host and time, and identify suspicious or noteworthy streams. You will then reconstruct session context where appropriate and write a short network timeline snippet for later use in a full incident timeline.

The goal is to build a practical IR workflow for short-window Windows network analysis, not to become a full-time packet analyst.

---

## What This Lab Covers

This lab supports the following concepts from Section 8.3:

| Section | Topic |
|---|---|
| 8.3.1 | Generating and capturing test traffic |
| 8.3.2 | Narrowing analysis by host and timeframe |
| 8.3.3 | Identifying interesting streams |
| 8.3.4 | Reconstructing useful session context for IR |
| 8.3.5 | Mapping network connections back to processes |

---

## Learning Objectives

By completing this lab, you will be able to:

- Generate controlled lab traffic that simulates both normal and suspicious activity
- Capture traffic from a Windows host or monitoring point
- Filter a packet capture down to the relevant host and incident window
- Identify long-lived sessions, unusual ports, and transfer patterns that deserve attention
- Follow streams or reconstruct content where appropriate
- Distinguish useful leads from unsupported conclusions
- Write a short network timeline snippet suitable for later case correlation

---

## Estimated Time

60–90 minutes

---

## Prerequisites

- Completion of Labs 8.1 and 8.2, or equivalent familiarity with network evidence sources and key IR use cases
- A text editor or markdown editor
- Your `lab08-notes.md` file
- A Windows VM and either:
  - Wireshark on the host, or
  - A monitoring VM connected to the same lab network
- A safe test environment
- A locally hosted service or "suspicious" lab endpoint you control

---

## Scenario

You are investigating activity from **FIN-WS23** during a suspicious 15-minute window. The team believes the host may have:

- Performed normal-looking browsing activity
- Connected to a suspicious test server
- Transferred data or maintained one or more interesting streams during a short interval

Your review should stay IR-focused rather than become a general packet-analysis exercise.

Your job is to:

- Generate known traffic
- Capture it
- Narrow the capture to the relevant host and timeframe
- Identify interesting streams
- Reconstruct what you can from the sessions
- Write a short timeline snippet for later use in the broader incident investigation

---

## Background: Good Packet Review Starts with Scope Reduction

The most common mistake in packet-based incident response is treating a capture as something to "look through" rather than something to reduce deliberately.

A useful IR workflow usually looks like this:

| Step | Why It Matters |
|---|---|
| Generate or identify known activity | Gives you a reference point and expected behavior |
| Capture traffic | Preserves the raw evidence |
| Narrow by host and time | Removes noise and makes analysis tractable |
| Identify interesting streams | Focuses attention on sessions that matter |
| Follow / reconstruct content | Reveals what was likely transferred or requested |
| Write timeline notes | Preserves the key findings for later correlation |

Scope reduction matters even in short-window investigations. A 15-minute incident window can still contain thousands of packets, and most of them may be irrelevant.

> **IR Reality Check:** A clean, focused packet review is usually more valuable than a broad, messy review of everything in the capture.

---

## Lab Tasks

---

### Task 1 — Plan the 15-Minute Traffic Window

**Objective:** Define the activity window before you generate and capture traffic.

Write the traffic plan for your 15-minute window.

At minimum, include:

- Normal browsing activity
- Connection to a suspicious test server
- At least one action that could create a more obvious stream or transfer pattern

Fill in the table below.

| Planned Activity | Why You Included It | Expected Network Pattern |
|---|---|---|
| Browse a normal website | | |
| Connect to a suspicious test server | | |
| Download or transfer a test file | | |

Add at least three more planned activities of your own.

Then answer:

1. Why is it useful to plan the traffic before capturing it?
2. Why should the lab include both normal-looking and suspicious-looking traffic?
3. Why does expected behavior help when interpreting packet evidence later?

---

### Task 2 — Generate the Traffic

**Objective:** Create controlled activity that you can later identify in packet review.

During your chosen 15-minute window, generate the planned traffic from the Windows VM.

Document what you actually did.

| Activity Performed | Source Host | Destination | Approximate Time (UTC) | Notes |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |

Record at least six traffic-generating actions.

Examples may include:

- Opening a normal website
- Accessing a suspicious local HTTP service
- Downloading a test file
- Using PowerShell to reach a local endpoint
- Connecting to an unusual port
- Keeping a session open longer than normal browsing would

Then answer:

1. Why is recording your actual actions important for later validation?
2. Why do approximate timestamps matter even in a lab?
3. Why can a long-lived test connection be useful for learning IR-focused packet review?

---

### Task 3 — Capture the Traffic

**Objective:** Preserve the packet evidence for analysis.

Use Wireshark or an equivalent tool to capture the traffic during the activity window.

Record your capture details below.

| Field | Value |
|---|---|
| Capture tool | |
| Capture location | |
| Source host under review | |
| Capture file name | |
| Capture start time (UTC) | |
| Capture end time (UTC) | |
| Notes / warnings | |

Then answer:

1. Why should capture start and end times be documented carefully?
2. Why does it matter whether you captured from the host versus a monitoring point?
3. Why should the original capture be preserved before heavy filtering or export?

---

### Task 4 — Narrow the Capture by Host and Time

**Objective:** Reduce the capture to the traffic that matters.

Using Wireshark, narrow the dataset to:

- The relevant host
- The suspicious 15-minute window
- Any obviously relevant endpoints or protocols

Document the filtering logic you used.

| Filter Goal | Filter / Method Used | Why It Matters |
|---|---|---|
| Source / destination host filtering | | |
| Time-window narrowing | | |
| Protocol narrowing | | |
| Suspicious endpoint narrowing | | |

Then answer:

1. Why is host-and-time filtering one of the most important steps in this workflow?
2. Why can protocol filtering help, but also hide context if used too early?
3. Why should your notes preserve the exact filter logic you used?

---

### Task 5 — Identify Interesting Streams

**Objective:** Find sessions that deserve IR attention.

Review the filtered capture and identify at least six streams or connection patterns worth documenting.

Look for:

- Long-lived connections
- Large data transfers
- Unusual ports
- Suspicious internal or external destinations
- Repeated sessions to the same endpoint
- Activity that lines up with your known test actions

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

1. Why do long-lived sessions often matter in network IR?
2. Why can a large transfer be significant even if you do not know the exact content?
3. Why should "unusual" never be treated as the same thing as "malicious" automatically?

---

### Task 6 — Follow Streams and Reconstruct Useful Context

**Objective:** Recover content or protocol context where appropriate.

Choose at least three interesting streams and use:

- Follow TCP stream
- Follow UDP stream, where appropriate
- Export objects or file carving, if applicable
- Protocol-level review

Record your work below.

| Stream | Reconstruction Method | What You Observed or Recovered | Why It Matters | Limitation |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

Then answer:

1. Why is stream-following often one of the most useful features in Wireshark for IR?
2. Why is reconstructed content sometimes unavailable or incomplete?
3. Why should responders document both successful reconstruction and failed attempts?

---

### Task 7 — Assess Transfer Size, Duration, and Direction

**Objective:** Evaluate stream behavior the way a responder would in an exfiltration or C2 review.

For at least four interesting sessions, record:

- Direction
- Approximate duration
- Relative size
- Why it matters

Use the table below.

| Stream | Direction | Approx. Duration | Approx. Size / Relative Volume | Why It Matters |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |

Then answer:

1. Why are direction and size important in exfiltration review?
2. Why can short repeated sessions matter more than one large session in some C2 cases?
3. Why does duration help distinguish normal browsing from some suspicious traffic patterns?

---

### Task 8 — Map the Network Evidence to Likely Host Context

**Objective:** Prepare the packet findings for later correlation with host artifacts.

For each type of network finding below, identify which host-side artifacts you would want next.

| Network Finding | Best Host Artifact(s) to Correlate | Why |
|---|---|---|
| Suspicious browser-like connection | | |
| Large outbound transfer | | |
| Connection to unusual local lab server | | |
| Repeated short sessions to same destination | | |
| Unusual port usage | | |
| Download-like traffic | | |

Then answer:

1. Why is packet evidence usually stronger when tied to a process or user action?
2. Why are browser history and execution artifacts especially useful after packet review?
3. Why should responders avoid treating network traffic as fully self-explanatory?

---

### Task 9 — Build the Timeline Snippet

**Objective:** Create the exact kind of network timeline fragment described in the chapter.

Write a short timeline snippet covering the important events from the 15-minute window.

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

1. Why is a timeline snippet more useful than a loose list of packets or sessions?
2. Which entries are most central to the suspicious activity theory?
3. Which entries are supportive but not central?

---

### Task 10 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined language based on packet evidence.

Classify each statement below as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by this evidence alone

| Statement | Classification | Why |
|---|---|---|
| The host connected to the suspicious test server during the 15-minute window | | |
| A long-lived connection occurred during the capture window | | |
| A file or object was likely transferred in one of the sessions | | |
| The attacker definitely exfiltrated sensitive data | | |
| The unusual port traffic deserves deeper review | | |
| The traffic pattern is consistent with suspicious behavior | | |
| The traffic was initiated intentionally by the user | | |
| The connection should immediately be blocked in production | | |

Then write six additional statements of your own and classify them the same way.

> **Guidance:** This lab practices drawing disciplined conclusions from a short, focused capture. It is not about overstating what packets prove.

---

### Task 11 — Write an IR-Focused Packet Analysis Summary

**Objective:** Produce a concise working-note summary suitable for a case file.

Write a 3–5 paragraph analyst summary describing what your capture and packet review suggest about activity during the 15-minute window.

Your summary should include:

- The most important streams or connection patterns you identified
- Whether the traffic looks normal, suspicious, mixed, or staged for learning purposes
- What you were able to reconstruct from streams or session context
- What is strongly supported by the packet evidence
- What still needs host, memory, or log correlation

Write it as a working-note summary rather than a final incident conclusion.

---

### Task 12 — Write an Analyst Handoff Note

**Objective:** Make your packet-review findings easy for another responder to continue.

Use the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Most Important Capture Findings:
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

**1. Why capture-and-filter workflow matters**
Why is packet analysis far more effective when you reduce the capture by host and time before hunting for suspicious traffic?

**2. Stream context versus packet noise**
Why are streams usually more useful to responders than isolated packets?

**3. Correlation remains essential**
Why should packet review usually be paired with host evidence before making stronger claims?

**4. Timelines improve reporting**
Why is a network timeline snippet valuable even if it covers only one short incident window?

---

## Deliverables Checklist

Your `lab08-notes.md` should contain:

- [ ] **Task 1** — Traffic-planning table with added activities and written responses
- [ ] **Task 2** — Traffic-generation record with at least six actions
- [ ] **Task 3** — Capture record
- [ ] **Task 4** — Host/time filtering table
- [ ] **Task 5** — Interesting-streams table with at least six findings
- [ ] **Task 6** — Stream-follow / reconstruction table
- [ ] **Task 7** — Transfer-size / duration / direction table
- [ ] **Task 8** — Network-to-host correlation table
- [ ] **Task 9** — Timeline snippet with at least eight entries where possible
- [ ] **Task 10** — Strong support vs overclaim exercise
- [ ] **Task 11** — IR-focused packet analysis summary
- [ ] **Task 12** — Analyst handoff note
- [ ] **Task 13** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab08/
├── lab08-notes.md  ← Your working notes file (whole lab)
└── Lab08_03/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **Capture alone is not the skill.** The real value comes from narrowing, identifying, and interpreting the right sessions.
- **Host and time filtering are essential.** They turn a noisy packet capture into an incident-relevant dataset.
- **Interesting streams create leads.** Long-lived sessions, large transfers, and unusual ports deserve follow-up, not automatic conclusions.
- **Reconstruction adds context.** Following streams and recovering session details can make a connection far more meaningful.
- **Timeline notes preserve value.** A short, clear packet-based timeline snippet makes later host correlation much easier.

---

**Next:** Lab 8.4 — Building a Network Timeline Snippet

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
