# Lab 7.3 — Typical Workflow

**Supporting Section 7.3: Typical Workflow**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Memory forensics is much more useful when you approach it as a workflow instead of a collection of disconnected commands.

In real incident response, responders are rarely trying to "analyze memory" in the abstract. They are trying to answer specific questions under time pressure:

- What operating system and image context am I looking at?
- Which processes stand out?
- Which command lines look suspicious?
- Which network connections matter?
- Are there signs of injected code or memory-resident malware?
- Which processes or memory regions should be dumped for deeper review?

A good workflow keeps you from getting lost in plugin output and helps you perform key steps in a defensible order. This lab follows the practical memory-hunting sequence described in Chapter 7. You identify OS information, enumerate processes, inspect command lines and DLLs, and review network connections. You then run malware-oriented plugins, dump suspicious material, and summarize the result.

The goal is not to memorize commands for their own sake. The goal is to build a repeatable process that another responder could follow and trust.

---

## What This Lab Covers

This lab supports the following concepts from Section 7.3:

| Section | Topic |
|---|---|
| 7.3.1 | Confirm the Image |
| 7.3.2 | Enumerate Processes |
| 7.3.3 | Inspect Command Lines |
| 7.3.4 | Inspect Network Connections |
| 7.3.5 | Look for Injection and Anomalies |
| 7.3.6 | Dump and Inspect Suspicious Processes |
| 7.3.7 | Search Strings as a Last Resort |
| 7.3.8 | Memory Findings — Quick Reference |

---

## Learning Objectives

By completing this lab, you will be able to:

- Follow a practical memory-analysis workflow from image identification to suspicious-region review
- Explain why workflow order matters in memory forensics
- Use process, command-line, DLL, and network review together rather than in isolation
- Recognize when a suspicious lead should be escalated to dumping or deeper analysis
- Build a repeatable memory-hunt sequence for a Windows host
- Write concise notes that distinguish raw findings from analyst interpretation

---

## Estimated Time

75–105 minutes

---

## Prerequisites

- Completion of Labs 7.1 and 7.2, or equivalent familiarity with why memory matters and the Chapter 7 toolset
- A text editor or markdown editor
- Your `lab07-notes.md` file
- A Windows memory image from a lab VM or host
- A memory-analysis framework such as Volatility 3, Volatility 2.x, Rekall, MemProcFS, or Redline

---

## Scenario

You are investigating a suspected memory-resident implant on **FIN-WS23**.

The team has already captured a memory image and wants a disciplined first-pass review. The host may have experienced:

- Short-lived PowerShell activity
- Suspicious outbound connections
- A process that may have existed briefly
- Possible injected code or memory-resident malware
- Incomplete disk and log evidence

Leadership wants a same-day update. Another analyst may need to pick up your work later. Your task is to follow a basic memory-hunt workflow that surfaces the most important leads without jumping straight to unsupported conclusions.

---

## Background: Workflow Prevents Blind Plugin Hunting

A memory image can be overwhelming if you treat every parser or plugin as equally important. A workflow helps by narrowing the questions in sequence.

A typical Windows memory-hunt workflow looks like this:

| Workflow Stage | Why It Comes Early |
|---|---|
| Identify OS / image info | Needed to interpret later analysis correctly |
| Enumerate processes | Establishes what was present |
| Review process trees | Adds context and parent-child relationships |
| Review command lines and DLLs | Adds behavioral context to suspicious processes |
| Review network connections | Links suspicious activity to processes |
| Run malware-oriented plugins | Focuses on suspicious code regions |
| Dump suspicious processes or regions | Preserves material for follow-up analysis |
| Write summary and next steps | Makes findings usable to others |

> **IR Reality Check:** Running `malfind` before you understand the process landscape often creates noise. Good workflow makes later findings stronger.

---

## Lab Tasks

---

### Task 1 — Explain the Typical Workflow in Your Own Words

**Objective:** Build a practical understanding of why the workflow is ordered the way it is.

Write a short explanation in 4–6 sentences covering:

- Why memory analysis benefits from a structured workflow
- Why OS / image identification comes first
- Why process review comes before malware-oriented plugin hunting
- Why summaries and next steps are part of the workflow, not an afterthought

Then answer the following in one or two sentences each:

1. Why is jumping straight to suspicious-region plugins often a mistake?
2. Why is process context central to memory analysis?
3. Why should workflow order be documented in your notes?

---

### Task 2 — Identify OS / Image Context First

**Objective:** Confirm the image context before analyzing processes and plugins.

Use your chosen framework to identify the OS / image information.

Examples from the chapter include:

- `windows.info`
- `imageinfo`
- Equivalent image / system identification commands

Record your work below.

| Question | What You Found | Why It Matters |
|---|---|---|
| OS version | | |
| Architecture | | |
| Kernel or build context | | |
| Other useful image characteristics | | |

Then answer:

1. Why is OS identification one of the first steps in the workflow?
2. Why can incorrect assumptions at this stage affect later findings?
3. Why should this information appear near the top of the analyst note?

---

### Task 3 — Enumerate Processes with Multiple Views

**Objective:** Establish what processes were present and identify suspicious leads.

Using your framework, run the equivalents of:

- `pslist`
- `psscan`
- `pstree`

Review the results and record at least six processes or leads worth attention.

Focus on:

- Weird names
- Odd parent-child relationships
- Uncommon paths
- Processes appearing in one view but not another
- Security tools, script hosts, or user-writable paths in suspicious context

| Process | Why It Stands Out | View / Command | What It Might Suggest | What It Does Not Prove |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

Then answer:

1. Why is it useful to compare multiple process views?
2. Why do parent-child relationships matter so much in incident response?
3. Why should a strange-looking process name never be your only reason for escalation?

---

### Task 4 — Review Command Lines for Suspicious Context

**Objective:** Add process-behavior context beyond names and PIDs.

Choose at least three suspicious or noteworthy processes from Task 3 and inspect command lines or equivalent data.

Use the table below.

| Process | Command-Line Finding | Why It Matters | What It Might Suggest | What Still Needs Corroboration |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

Then answer:

1. Why are command lines often more valuable than process names alone?
2. Why are scripting hosts and LOLBins especially important to review this way?
3. Why should responders still be careful not to over-interpret a suspicious-looking command line?

---

### Task 5 — Review Loaded DLLs / Modules

**Objective:** Identify unusual modules or library-loading context tied to suspicious processes.

For the same processes, or for three other suspicious ones, review loaded DLLs or modules using `dlllist` or the equivalent.

Use the table below.

| Process | DLL / Module Finding | Why It Matters | What It Might Suggest | What It Does Not Prove |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

Then answer:

1. Why can unusual DLLs or modules raise suspicion about a process?
2. Why is DLL review especially useful after process and command-line review?
3. Why should responders be cautious about labeling a module "malicious" too quickly?

---

### Task 6 — Review Network Connections and Tie Them to Processes

**Objective:** Connect suspicious connectivity to process context.

Run `netscan` or the equivalent and identify at least five findings or candidate leads.

Focus on:

- Unfamiliar remote IPs
- Suspicious ports
- Processes with external connections
- Connections that line up with suspicious processes from earlier tasks

| Process / PID | Local Address | Remote Address | Why It Stands Out | What It Might Suggest |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

Then answer:

1. Why is process-linked network evidence especially valuable in memory analysis?
2. Why is an unusual IP or port only a lead and not a full conclusion?
3. Why should network review come after you already understand the process landscape?

---

### Task 7 — Run Malware-Oriented Plugins

**Objective:** Use plugins such as `malfind` after you understand the process context.

Run `malfind` or an equivalent suspicious-memory-region plugin.

For each meaningful hit, record:

- Which process it is tied to
- Why it matters
- Whether it aligns with prior suspicious process, command-line, DLL, or network findings

| Process | Suspicious Region / Plugin Hit | Why It Matters | Prior Context That Supports Concern | Follow-Up Action |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

Then answer:

1. Why is `malfind` stronger when interpreted alongside earlier workflow steps?
2. Why is a suspicious region not automatically proof of malware?
3. Why should responders log both the hit and the context that made it meaningful?

---

### Task 8 — Dump Suspicious Processes or Memory Regions

**Objective:** Preserve suspicious material for deeper review.

Choose at least two suspicious processes or memory regions and document what you would dump and why.

Use the table below.

| Process / Region | Why It Was Chosen | Dump Method / Command | What You Hope to Learn | Risks / Limitations |
|---|---|---|---|---|
| | | | | |
| | | | | |

Then answer:

1. Why should dumping happen after initial triage rather than before any review?
2. Why is it important to document why a process or region was dumped?
3. What follow-up analysis might you perform on dumped content?

---

### Task 9 — Correlate the Workflow Findings

**Objective:** Turn isolated workflow outputs into defensible leads.

Choose three suspicious leads and correlate them across the workflow.

Use the table below.

| Lead | OS / Process Context | Command-Line or DLL Context | Network or Malfind Context | Combined Interpretation | Confidence |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |
| | | | | | |

Then answer:

1. Why is correlation across workflow stages stronger than any single plugin hit?
2. Why should confidence levels still be documented even when multiple findings align?
3. Which combinations of findings would most strongly justify escalation to deeper malware analysis?

---

### Task 10 — Build a Workflow Timeline

**Objective:** Turn the memory hunt into an ordered analytic sequence.

Create a mini-timeline with at least 10 entries if possible.

| Time (UTC) | Workflow Stage / Artifact Source | Event or Observation | Process / Region / Connection | Why It Matters |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

Your timeline may include:

- OS / image confirmation
- Suspicious process discovery
- Parent-child anomalies
- Command-line findings
- DLL anomalies
- Network connections
- `malfind` hits
- Dump decisions

Then answer:

1. Which entries appear most central to the implant theory?
2. Which entries are supportive but not decisive?
3. What major gaps remain after following the workflow?

---

### Task 11 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined reporting after completing the workflow.

Classify each statement below as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by this workflow alone

| Statement | Classification | Why |
|---|---|---|
| A suspicious process was present in memory | | |
| The process had an unusual parent-child relationship | | |
| The process likely deserves escalation for deeper review | | |
| The process was definitely a threat-actor implant | | |
| A suspicious connection was tied to a process of interest | | |
| Memory contains suspicious regions consistent with injected code | | |
| The attacker used the process for credential theft | | |
| The workflow supports concern about a possible memory-resident implant | | |

Then write six additional statements of your own and classify them the same way.

> **Guidance:** The workflow is designed to produce defensible leads, not instant certainty.

---

### Task 12 — Write the Workflow-Based Analyst Note

**Objective:** Produce the short analyst note described in the chapter.

Write a 3–5 paragraph analyst note describing:

- Whether you found anything suspicious during the workflow
- Which processes, command lines, modules, connections, or suspicious regions mattered most
- What the workflow strongly supports
- What still requires corroboration from disk, logs, EDR, or deeper reverse engineering
- What further steps you would take next

Write it as a working-note summary, not a final malware-analysis report.

---

### Task 13 — Write an Analyst Handoff Note

**Objective:** Make your workflow results easy for another responder to continue.

Use the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Most Important Workflow Findings:
- 

Most Important Process / Region / Network Leads:
- 

What Is Strongly Supported:
- 

What Is Suggested but Not Confirmed:
- 

Recommended Next Steps:
1.
2.
3.

Open Questions:
- 

Notes for Incoming Analyst:
```

---

### Task 14 — Reflection

Answer the following in 3–5 sentences each.

**1. Why workflow matters**
Why is a structured memory-analysis workflow better than jumping randomly between plugins?

**2. Context before malware hunting**
Why should process, command-line, and network review usually happen before dumping suspicious regions?

**3. Strong leads versus final conclusions**
Why does a good workflow often produce strong investigative leads without fully solving the case by itself?

**4. Memory in the larger case**
Why should workflow findings still be correlated with disk artifacts, logs, EDR telemetry, and user-activity evidence?

---

## Deliverables Checklist

Your `lab07-notes.md` should contain:

- [ ] **Task 1** — Workflow explanation plus short written responses
- [ ] **Task 2** — OS / image context table
- [ ] **Task 3** — Process-enumeration findings table with at least six leads
- [ ] **Task 4** — Command-line review table for three processes
- [ ] **Task 5** — DLL / module review table for three processes
- [ ] **Task 6** — Network-connection review table with at least five findings
- [ ] **Task 7** — Malware-oriented plugin review table
- [ ] **Task 8** — Dumping decision table for suspicious processes or regions
- [ ] **Task 9** — Correlation table for three suspicious leads
- [ ] **Task 10** — Workflow timeline with at least 10 entries where possible
- [ ] **Task 11** — Strong support vs overclaim exercise
- [ ] **Task 12** — Workflow-based analyst note
- [ ] **Task 13** — Analyst handoff note
- [ ] **Task 14** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab07/
├── lab07-notes.md  ← Your working notes file (whole lab)
└── Lab07_03/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **Workflow creates clarity.** Memory analysis is far more useful when it follows a structured sequence.
- **Context comes first.** OS info, processes, command lines, DLLs, and network connections make later suspicious-region findings more meaningful.
- **Malware-oriented plugins provide leads, not instant verdicts.** Their strength depends on surrounding process and network context.
- **Dumping is a follow-up decision.** Let suspicious leads drive it rather than treating it as the first step.
- **Correlation remains the goal.** The strongest memory conclusions come from multiple workflow stages aligning with evidence from other artifact classes.

---

**Next:** Lab 08 — Network Forensics on Windows

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
