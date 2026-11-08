# Lab 2.3 — Documentation and Repeatability

**Supporting Section 2.3: Documentation and Repeatability**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Good analysis that isn't documented is just memory. Memory fades, gets misremembered, and can't be cross-examined.

In incident response, documentation is part of the work, not a formality you complete after the real work is done. An analyst who can reconstruct every collection decision, tool version, command run, and conclusion reached produces findings that hold up. Those findings survive review and a handoff, and they can support a legal proceeding six months later. Keeping notes "in your head" creates risk for you, your team, and the organization.

This lab builds the specific documentation habits that make forensic work repeatable and defensible. You'll construct a case log, a command record, a structured timeline, and an analyst handoff note. The scenario is set mid-incident, where the pressure to skip documentation is highest.

---

## Learning Objectives

By completing this lab, you will be able to:

- Create a structured case log that captures investigative actions in real time
- Record tool names, versions, commands, and output locations consistently
- Separate observed facts from analytical conclusions and assumptions in written notes
- Build a simple forensic timeline from artifact findings across multiple sources
- Write a handoff note that allows another analyst to continue the investigation without losing context
- Evaluate your own documentation for gaps, ambiguity, and defensibility

---

## Estimated Time

45–60 minutes

---

## Prerequisites

- Completion of Lab 2.1 and Lab 2.2 (or equivalent)
- Your `question-evidence-worksheet.md` from Lab 2.1
- Your `lab02.2-notes.md` case materials from Lab 2.2
- A text editor or markdown editor
- Your `lab02.3-notes.md` file (template included in this folder)

---

## Scenario

You are four hours into a Windows incident investigation involving WKSTN-221, the payroll workstation from Lab 2.2. Initial triage identified active C2 beaconing, a suspicious PowerShell execution chain, and a lateral movement event to FILESVR-03. You captured its memory at 17:35 and isolated it at 18:20, a few minutes ago.

A second analyst is taking over your shift in 30 minutes. You have collected artifacts from WKSTN-221 but have not yet analyzed all of them. Your timeline is partially built. Several questions remain open. The case is active and leadership has asked for a status update by 17:00.

You need to document where things stand clearly enough that the incoming analyst can continue without calling you. The record also has to be thorough enough that your collection and early findings hold up under scrutiny.

---

## Background: What Good Documentation Does

Documentation in IR serves five distinct purposes. Each one has failed someone in a real case:

| Purpose | What It Prevents |
|---|---|
| **Repeatability** | Another analyst re-running your collection differently and getting different results |
| **Handoff continuity** | The incoming analyst duplicating work, missing open threads, or misunderstanding findings |
| **Legal defensibility** | An attorney or regulator questioning whether evidence was altered or conclusions were fabricated |
| **Accountability** | Uncertainty about who authorized what, who touched what, and when |
| **Self-protection** | Being blamed for findings or decisions you can't reconstruct |

The common failure mode is pressure, not malice. When an incident is moving fast, documentation feels like it slows you down. Analysts who skip it usually believe they'll catch up later. They rarely do.

---

## Lab Tasks

---

### Task 1 — Audit Your Existing Notes

**Objective:** Identify gaps in documentation before they become problems.

Before building new documentation, audit what you already have. Pull your notes from Lab 2.2 and evaluate them against the criteria below.

**Part A — Documentation audit**

Review your `lab02.2-notes.md` and complete the following audit table. Be honest. The point of this exercise is to find the gaps.

| Documentation Item | Present? | Complete? | Gap or Issue |
|---|---|---|---|
| Case reference number | | | |
| Authorization record | | | |
| Scope statement | | | |
| Containment decision and reasoning | | | |
| Collection start time (UTC) | | | |
| Tools used with version numbers | | | |
| Exact commands run | | | |
| Output file paths for each artifact | | | |
| Hash values for collected evidence | | | |
| Chain of custody entries | | | |
| Facts clearly separated from conclusions | | | |
| Open questions documented | | | |
| Next actions recorded | | | |

**Part B — Gap impact assessment**

Pick the three most significant gaps from your audit. For each one, write a sentence describing what could go wrong in a real investigation because of that gap.

```
Gap 1:
  What's missing:     
  What could go wrong:

Gap 2:
  What's missing:     
  What could go wrong:

Gap 3:
  What's missing:     
  What could go wrong:
```

---

### Task 2 — Build a Structured Case Log

**Objective:** Create a real-time case log that captures investigative actions as they happen.

A case log is the running record of everything that occurs during an investigation: actions taken, decisions made, artifacts collected, and findings noted. You write it in chronological order, in real time, and never edit it retroactively. If you make a mistake, add a correction entry. Don't delete the original.

**Part A — Case log format**

Each entry in your case log should answer: *what did I do, when, why, and what happened?*

Use this format for every entry:

```
[DateTime UTC] | [Analyst] | [Action Type] | [Description]

Action Types:
  TRIAGE      - Initial assessment activity
  COLLECTION  - Evidence acquisition
  ANALYSIS    - Artifact examination
  DECISION    - Documented decision and reasoning
  FINDING     - Observed fact from artifact examination
  ESCALATION  - Communication to leadership or other teams
  HANDOFF     - Shift change or case transfer
  NOTE        - General observation or context
  ERROR       - Mistake made and correction taken
```

**Part B — Reconstruct the WKSTN-221 case log**

Using your notes from Lab 2.2 and the scenario timeline, reconstruct a case log for the WKSTN-221 investigation covering the first four hours. Write at least 15 entries. Include decisions, collections, findings, and at least one ERROR entry that documents a realistic mistake and its correction.

```
[2024-11-14 14:23 UTC] | [Your initials] | TRIAGE    | SOC escalated EDR alert for WKSTN-221. OUTLOOK.EXE → POWERSHELL.EXE → CMD.EXE process chain observed. Repeated outbound connections to 91.214.47.22:443 since 14:19:42 UTC, consistent with C2 beaconing. Beginning initial triage.

[2024-11-14 14:25 UTC] | [Your initials] | DECISION  | Decided to monitor and collect before isolating. Rationale: continued C2 beaconing may reveal additional infrastructure if observed briefly; volatile evidence must be captured before isolation.

[2024-11-14 14:27 UTC] | [Your initials] | COLLECTION| [Add your entry here]

[Continue for at least 15 total entries]
```

---

### Task 3 — Build a Command Record

**Objective:** Document every tool, version, command, and output from the investigation in a format another analyst can reproduce.

A command record is separate from your case log. The case log records *what happened*. The command record records *exactly how*: tool, version, syntax, flags, output location, and any errors encountered.

**Part A — Command record format**

Use this structure for every tool execution:

```
## [Tool Name] — [Purpose]

Tool:           
Version:        
Platform:       [VM hostname / analyst workstation]
Run by:         
Date/Time (UTC):
Working directory:

Command:
  [exact command including all flags and paths]

Output:
  File:     
  Location: 
  Size:     
  Hash:     

Errors / Notes:
  [Any errors, warnings, unexpected behavior, or deviations from expected output]
```

**Part B — Write command records for WKSTN-221**

Write complete command records for at least six collection or analysis actions from the WKSTN-221 investigation. Include at least one that produced an error or unexpected output.

```
## PowerShell — Volatile Process Capture

Tool:           PowerShell
Version:        
Platform:       WKSTN-221
Run by:         
Date/Time (UTC):
Working directory: E:\IR\WKSTN-221\volatile\

Command:
  Get-Process | Select-Object Name, Id, Path, StartTime, Company |
  Export-Csv ".\processes_20241114_142700.csv" -NoTypeInformation

Output:
  File:     processes_20241114_142700.csv
  Location: E:\IR\WKSTN-221\volatile\
  Size:     
  Hash:     

Errors / Notes:
  [Your entry here]

---

## [Next tool — add your own]

[Continue for at least 6 total entries]
```

---

### Task 4 — Facts, Conclusions, and Assumptions Register

**Objective:** Maintain a clean separation between what you observed, what you concluded, and what you assumed, throughout the investigation, not just at reporting time.

This is the discipline most analysts skip under pressure. Mixing facts and conclusions in your notes creates analysis that is hard to review, hard to challenge, and easy to misrepresent.

**Part A — The three-column register**

Maintain a register with three columns throughout the investigation. Every significant statement in your notes should be categorizable as one of these three:

| Type | Definition | Example |
|---|---|---|
| **Fact** | Directly observed from a named artifact with a timestamp | `Security.evtx EID 4688 at 14:19:38 UTC shows OUTLOOK.EXE spawned POWERSHELL.EXE` |
| **Conclusion** | An inference drawn from one or more facts | `The attacker likely used a malicious macro to execute PowerShell` |
| **Assumption** | A belief held without direct artifact support | `The external IP is attacker-controlled infrastructure` |

**Part B — Populate the register for WKSTN-221**

Complete the register below with at least 12 entries from the WKSTN-221 investigation. Use your Lab 2.2 scenario materials. Include at least four facts, four conclusions, and four assumptions. For each conclusion, name the fact(s) that support it. For each assumption, note what evidence would be needed to promote it to a fact.

| # | Type | Statement | Supporting Fact(s) | Evidence Needed to Promote |
|---|---|---|---|---|
| 1 | Fact | Security.evtx EID 4688 at 14:19:38 UTC records OUTLOOK.EXE spawning POWERSHELL.EXE | Direct observation from named artifact | N/A — already a fact |
| 2 | Conclusion | | | N/A |
| 3 | Assumption | | N/A | |
| 4 | | | | |
| 5 | | | | |
| 6 | | | | |
| 7 | | | | |
| 8 | | | | |
| 9 | | | | |
| 10 | | | | |
| 11 | | | | |
| 12 | | | | |

**Part C — Reflection**

Write 2–3 sentences answering: what happens to your investigation if a conclusion recorded as a fact turns out to be wrong? Give a specific example using the WKSTN-221 scenario.

```
[Your response here]
```

---

### Task 5 — Build a Forensic Timeline

**Objective:** Construct a properly structured timeline for WKSTN-221 that another analyst could use to orient themselves quickly.

A good forensic timeline is a curated, annotated record of the events that matter, not a data dump. It lists them in the order they occurred, with artifact provenance and a confidence rating for each entry.

**Part A — Timeline structure**

Use the following structure for your WKSTN-221 timeline. Every entry must include a source artifact. Entries without a named source do not belong in the timeline.

```
# WKSTN-221 — Forensic Timeline
Case Reference: IR-2024-WKSTN221
Analyst:        
Last Updated:   [UTC]

Legend:
  Confidence — HIGH:   Two or more independent artifact sources agree
  Confidence — MEDIUM: Single reliable artifact source
  Confidence — LOW:    Indirect, ambiguous, or single low-confidence source

| DateTime (UTC)      | Artifact Source         | Event                                          | ATT&CK Tactic     | Confidence | Notes                        |
|---------------------|-------------------------|------------------------------------------------|-------------------|------------|------------------------------|
| 2024-11-14 08:43:17 | Security.evtx EID 4624  | payroll-admin interactive logon (type 2)       | None (baseline)   | MEDIUM     | Normal start-of-day logon    |
| 2024-11-14 14:18:55 | LNK file                | Q4_Payroll_Review.xlsm accessed                | Execution         | MEDIUM     | Likely delivery document     |
| [Continue]          |                         |                                                |                   |            |                              |
```

**Part B — Complete the timeline**

Using the 10 events from Lab 2.2 Task 5 and any additional context from your notes, build a complete timeline for the WKSTN-221 investigation with at least 12 entries. Include ATT&CK tactic annotations for each event.

> **ATT&CK tactic reference for this scenario:** Initial Access, Execution, Defense Evasion, Credential Access, Lateral Movement, Collection, Command and Control, Exfiltration

**Part C — Timeline summary**

Write a three-sentence narrative summary of the timeline: what the attacker did, in what order, and how far they got. You should be able to derive the summary entirely from HIGH and MEDIUM confidence entries.

```
[Your timeline narrative here]
```

---

### Task 6 — Write an Analyst Handoff Package

**Objective:** Produce a complete handoff package that allows an incoming analyst to continue the investigation without calling you.

A handoff is not a summary email. It is a structured document that tells the incoming analyst what the case is, what has been done, what has been found, what remains open, and exactly what to do next.

**Part A — Handoff note**

Complete the following handoff note for the WKSTN-221 case:

```
# Analyst Handoff — WKSTN-221
Case Reference:   IR-2024-WKSTN221
Outgoing Analyst: 
Incoming Analyst: 
Handoff Time:     [UTC]
Case Status:      [Active / Contained / Remediation / Closed]

---

## Case Summary (2–3 sentences)


---

## What Has Been Completed This Shift

| Action | Time (UTC) | Output / Location | Notes |
|---|---|---|---|
| | | | |
| | | | |
| | | | |

---

## Current State of Evidence

| Artifact | Collected? | Location | Analyzed? | Notes |
|---|---|---|---|---|
| Memory dump | | | | |
| Security.evtx | | | | |
| PowerShell logs | | | | |
| Prefetch | | | | |
| MFT | | | | |
| Registry hives | | | | |
| SRUM | | | | |
| LNK / Jump Lists | | | | |
| Amcache | | | | |

---

## Confirmed Findings (Facts Only)

1. 
2. 
3. 

---

## Active Hypotheses

| Hypothesis | Status | Next Step to Confirm or Eliminate |
|---|---|---|
| | Unconfirmed | |
| | Unconfirmed | |
| | Unconfirmed | |

---

## Open Questions

1. 
2. 
3. 

---

## Evidence Gaps

1. 
2. 

---

## Recommended Next Actions (Priority Order)

1. 
2. 
3. 
4. 
5. 

---

## Notes for Incoming Analyst


---

## Contacts and Escalation

| Role | Name | Contact |
|---|---|---|
| SOC Lead | | |
| IR Manager | | |
| Legal / Compliance | | |
| System Owner (WKSTN-221) | | |
| System Owner (FILESVR-03) | | |
```

**Part B — Handoff quality check**

Exchange handoff notes with a colleague if possible, or review your own against this checklist:

- [ ] Can the incoming analyst find every collected artifact without asking?
- [ ] Are all confirmed findings supported by a named artifact?
- [ ] Are open questions specific enough to act on?
- [ ] Are next actions concrete enough that a responder knows exactly what to do?
- [ ] Is anything in the findings section actually a conclusion or assumption labeled as a fact?
- [ ] Are tool versions and output locations documented?
- [ ] Is the case reference consistent throughout?

Document any items you had to fix after the quality check:

```
Items fixed:
1. 
2. 
3. 
```

---

### Task 7 — Build a Personal Documentation Standard

**Objective:** Define the documentation standard you will apply to every future investigation.

Good documentation is easier to maintain when you've decided in advance what it looks like. Hour six of a live incident is the wrong time to remember what you were supposed to write down.

Write a short personal documentation standard of one to two pages that you commit to following. It should cover:

1. **Case log**: when you write entries, what format you use, what action types you track
2. **Command record**: what you document for every tool execution
3. **Facts vs. conclusions**: how you label the difference in your notes
4. **Timeline**: what goes in, what source citation looks like, how you rate confidence
5. **Handoff**: the minimum content required before you hand a case to another analyst
6. **What you will never skip**: two or three non-negotiable documentation requirements regardless of time pressure

```
# My Documentation Standard
Version: 1.0
Created: 

## Case Log


## Command Record


## Facts vs. Conclusions


## Timeline


## Handoff


## Non-Negotiables

1. 
2. 
3. 
```

---

### Task 8 — Reflection

Answer the following in 3–5 sentences each:

**1. Documentation under pressure**
In the scenario, you have 30 minutes before handoff and the case is still active. What do you document first? What do you defer? What are the consequences of deferring it?

**2. The retroactive documentation trap**
After a fast-moving incident, an analyst goes back and writes up their notes from memory. What are the risks of retroactive documentation compared to real-time documentation? What details are most likely to be lost or distorted?

**3. Facts vs. conclusions in practice**
You're writing a finding that says "the attacker used Mimikatz to harvest credentials." Walk through how you would break that statement into its component facts and the conclusion that connects them.

**4. Documentation as communication**
People who weren't there will read your case log and handoff note: legal counsel, a CISO, a regulator, or a future analyst returning to a cold case. How does knowing that audience change how you write?

---

## Deliverables Checklist

Your `lab02.3-notes.md` should contain:

- [ ] **Task 1**: Documentation audit table and gap impact assessment
- [ ] **Task 2**: Reconstructed case log with at least 15 entries including one ERROR entry
- [ ] **Task 3**: Command records for at least 6 tool executions
- [ ] **Task 4**: Facts/conclusions/assumptions register with at least 12 entries and Part C reflection
- [ ] **Task 5**: Complete timeline with at least 12 entries, ATT&CK annotations, and narrative summary
- [ ] **Task 6**: Complete handoff package with quality check completed
- [ ] **Task 7**: Personal documentation standard (1–2 pages)
- [ ] **Task 8**: Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab02/
├── lab02-notes.md    ← Your working notes file (whole lab)
└── Lab02_03/
    ├── ReadMe.md         ← This file
    └── lab02.3-notes.md  ← Your working notes file
```

---

## Key Takeaways

- **Documentation is the investigation.** If it isn't written down with a timestamp, a tool version, and an output location, it cannot be verified, repeated, or defended.
- **Real-time beats retroactive, always.** Notes written hours after an action are reconstructions, not records. The details that matter most are the ones most likely to blur.
- **Facts and conclusions are not interchangeable.** Mixing them creates findings that collapse under scrutiny. Keep the register, label everything, and know which category every statement belongs to.
- **A handoff is a professional obligation.** The incoming analyst's ability to continue your work depends entirely on the quality of what you leave them. A poor handoff wastes time, loses context, and can cost the investigation critical momentum.
- **Your documentation standard should survive a bad day.** Define the non-negotiables in advance, when you're calm, not in the middle of a live incident when every shortcut feels justified.

---

**Next:** Lab 2.4 — From Alert to Investigation Plan

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
