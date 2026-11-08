# Lab 02 — The Forensic Investigation Process for IR

**Supporting [Chapter 2: The Forensic Investigation Process for IR](../../Book/Chapter02.md)**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

This lab builds the investigative habits that make forensic work effective under pressure. Getting a call that something is wrong is easy. The hard part is knowing what to do in the first 15 minutes and being able to defend every decision you made.

The technical skills you develop in later chapters are only useful if you can deploy them in the right order, against the right evidence, in response to the right questions. That discipline starts here.

Lab 02 walks you through the full arc of early-stage incident response. It starts with a vague escalation and moves through structured question definition, evidence prioritization, collection planning, and documentation. It ends with a case handoff that another responder could pick up and continue.

---

## What This Lab Covers

This lab supports the following sections from Chapter 2:

| Section | Topic |
|---|---|
| 2.1 | IR Questions Forensics Should Answer |
| 2.2 | High-Level Process in an Incident |
| 2.3 | Documentation and Repeatability |
| 2.4 | From Alert to Investigation Plan |

---

## Learning Objectives

By completing this lab, you will be able to:

- Translate a vague incident alert into concrete, answerable forensic questions
- Identify which Windows artifacts are most useful for answering common IR questions
- Distinguish volatile evidence from persistent evidence and prioritize accordingly
- Build a defensible, step-by-step evidence collection workflow
- Separate observed facts from analytical conclusions in your documentation
- Document investigative actions, tools, and outputs in a way another responder could follow
- Produce a structured case folder, initial timeline, and analyst handoff note

---

## Estimated Time and Difficulty

**Difficulty:** Beginner

**First time through the material:** 2–3 h

**Refresh (already familiar with the chapter):** 45–75 min

> **Key terms used in this lab:** IR phases, scoping, investigation plan, repeatability, volatile evidence. See the consolidated [Glossary](../../Book/Glossary.md) for definitions. The chapter cross-references in each entry will take you back to the deeper coverage in `Book/`.

---

## Prerequisites

- Completion of Lab 01 (or equivalent Windows VM setup)
- Your `lab1.4-notes.md` baseline documentation
- A text editor or markdown editor
- Your `lab02-notes.md` file (template included in this folder)
- Optional: your Windows lab VM running for reference
- Optional: **[Cyber Triage](https://www.cybertriage.com/download-eval/)** (free evaluation tier) provides a guided workflow that pairs with this lab's investigation-process tasks. It is useful as a structural reference for less-experienced responders or as a sanity check alongside manual analysis. See Appendix D for the broader tooling reference.

---

## Scenario

At 09:14 on a Tuesday morning, your SOC escalates a ticket to the IR team. The alert reads:

> *"EDR flagged unusual PowerShell activity on WKSTN-047, a finance department workstation assigned to a senior accounts payable clerk. The process tree shows PowerShell spawning from an Office application. The host has been online continuously for six days. No containment action has been taken. Leadership is asking for a preliminary scope assessment by end of business."*

That is everything you have. No memory dump. No disk image. No additional context. The clock is running.

Your job is not to solve the case — it's to build the plan that makes solving it possible.

> **Scenario note:** The top-level lab uses **WKSTN-047** as its anchor host. The four sub-exercises in `Lab02_01/` through `Lab02_04/` each introduce their own additional scenarios (WKSTN-112, WKSTN-221, WKSTN-309) so you can practice the same patterns across different alert shapes. The top-level rollup notes file (`lab02-notes.md`) is keyed to WKSTN-047. Each sub-exercise has its own per-section notes file. The variety is intentional, because it helps the patterns stick.

---

## Background: The IR Investigative Process

Chapter 2 describes a six-phase investigative workflow for Windows incident response. These phases rarely happen in strict sequence. In a live incident you'll run several at once, but understanding the structure helps you stay oriented when things move fast.

| Phase | What You're Doing |
|---|---|
| **1. Initial Triage** | Quick checks to establish scope and urgency. Is the attacker still present? Is this one host or many? |
| **2. Scoping and Prioritization** | Identify related hosts, accounts, and data. Decide what to collect and in what order. |
| **3. Evidence Collection** | Acquire the artifacts that answer your questions. Document every action. |
| **4. Analysis and Hypothesis Testing** | Form specific hypotheses. Test them against the evidence. |
| **5. Timeline Construction** | Build a time-ordered view of key events across artifact sources. |
| **6. Reporting and Remediation Support** | Translate findings into recommendations. Communicate to technical and non-technical audiences. |

> **IR Reality Check:** In practice, you'll often be collecting from one host while analyzing another and briefing leadership at the same time. Documentation is the constant that holds the work together, whichever phase you're in.

---

## Lab Tasks

---

### Task 1 — Translate the Alert into Forensic Questions

**Objective:** Convert a vague escalation into specific, answerable investigative questions.

Vague questions produce vague investigations. Before touching any evidence, define exactly what you are trying to find out.

Read the scenario above carefully. Then write at least **10 specific forensic questions** you would want to answer about WKSTN-047. Start with the most urgent questions — the ones that determine whether this is a contained workstation incident or something much larger.

Use this format:

```
Priority  Question
-------   --------
1.        Is a malicious process currently running on WKSTN-047?
2.        Which Office application spawned PowerShell, and what was the command line?
3.        ...
```

> **Guidance:** Good forensic questions are specific and falsifiable. You should be able to look at evidence and say "yes" or "no." A question such as "was there attacker activity?" is not a forensic question. "Did PowerShell execute encoded commands in the last 72 hours?" is.

After writing your questions, group them into the following categories:

| Category | Your Questions (list by number) |
|---|---|
| Attacker presence (still active?) | |
| Initial access and execution | |
| Persistence | |
| Lateral movement | |
| Data access or exfiltration | |
| Scope (other hosts or accounts affected?) | |

---

### Task 2 — Map Questions to Windows Artifacts

**Objective:** Connect each investigative question to the evidence sources that can answer it.

For each question from Task 1, identify the Windows artifacts most likely to provide an answer. Be specific. "Event logs" is not specific enough. "Security.evtx Event ID 4688 (process creation)" is.

| # | Investigative Question | Primary Artifact(s) | Secondary / Corroborating Artifact(s) |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |
| 6 | | | |
| 7 | | | |
| 8 | | | |
| 9 | | | |
| 10 | | | |

> **Tip:** Multiple independent artifact types can answer some questions. That redundancy is intentional. If an attacker clears one source, another may still hold the answer. Noting your corroborating sources now makes your analysis more defensible later.

---

### Task 3 — Volatile vs. Persistent Evidence Prioritization

**Objective:** Make deliberate, documented collection decisions based on evidence volatility.

Not all evidence survives a reboot or a brief delay. Capture volatile evidence first. If WKSTN-047 crashes or is rebooted before you collect it, it's gone.

**Part A:** Sort the artifacts below into the correct column. Add at least three artifacts of your own in each column.

| Volatile (lost on reboot/shutdown) | Persistent (survives reboot) |
|---|---|
| Running processes | MFT |
| Active network connections | Registry hives |
| Logged-on users | Prefetch |
| Clipboard contents | Event logs |
| RAM contents | Amcache |
| *(Add your own)* | *(Add your own)* |

**Part B:** In this scenario, WKSTN-047 has been online continuously for six days, the attacker may still be present, and no containment has happened yet. Write a prioritized collection order for your first 10 collection actions. Explain the reasoning for your top three choices.

| Priority | Collection Action | Volatile? | Reasoning |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |
| 6 | | | |
| 7 | | | |
| 8 | | | |
| 9 | | | |
| 10 | | | |

---

### Task 4 — Build a Collection Workflow

**Objective:** Write a step-by-step collection procedure another responder could follow.

Write a collection workflow for WKSTN-047 that covers the following stages. Your workflow should be specific enough that a responder who wasn't part of the initial escalation could execute it correctly.

**Stage 1 — Pre-Collection Checks**
What do you confirm before touching the system? Authorization, scope, network status, EDR posture, active users?

**Stage 2 — Volatile Evidence Capture**
What do you collect first and how? List specific tools and commands.

```powershell
# Example: Capture running processes
Get-Process | Select-Object Name, Id, Path, StartTime |
  Export-Csv "E:\IR\WKSTN-047\processes_[datetime].csv" -NoTypeInformation
```

**Stage 3 — Memory Acquisition**
What tool do you use? Where does the output go? How do you hash it?

**Stage 4 — Targeted Artifact Collection**
List the specific artifacts you collect, the tool used for each, and the output location.

| Artifact | Collection Tool | Command or Method | Output Location |
|---|---|---|---|
| Running processes | PowerShell | `Get-Process` | `E:\IR\WKSTN-047\` |
| Network connections | PowerShell | `Get-NetTCPConnection` | |
| Security.evtx | PowerShell / xcopy | | |
| PowerShell logs | | | |
| Prefetch | | | |
| MFT | MFTECmd | | |
| Registry hives | reg export / FTK | | |
| SRUM database | xcopy | | |
| LNK files | xcopy | | |
| Amcache | reg export / FTK | | |

**Stage 5 — Packaging and Hashing**
How do you archive and hash the collection? Where does it go?

```powershell
# Example: Hash the output archive
Get-FileHash -Algorithm SHA256 "E:\IR\WKSTN-047.zip" |
  Export-Csv "E:\IR\WKSTN-047_hash.csv" -NoTypeInformation
```

**Stage 6 — Post-Collection Documentation**
What do you record after collection completes? Tool versions, errors encountered, anything unexpected?

---

### Task 5 — Facts vs. Conclusions

**Objective:** Practice separating what you observed from what you inferred, a core discipline in forensic reporting.

Forensic reporting fails when analysts mix observed evidence with analytical conclusions without clearly labeling each. Reviewers such as legal counsel, executives, and regulators need to know what you found versus what you believe it means.

**Part A:** Read the statements below. Label each as **F** (observed fact) or **C** (analytical conclusion). For each conclusion, write the underlying fact that would support it.

| Statement | F or C? | If C: What observed fact supports it? |
|---|---|---|
| PowerShell.exe was observed as a child process of WINWORD.EXE at 08:47 UTC | | |
| The attacker used a macro-enabled document to establish initial access | | |
| Event ID 4624 logon type 3 recorded for account `svc-backup` at 03:12 UTC | | |
| The service account was used for lateral movement | | |
| Prefetch shows `MIMIKATZ.EXE` executed twice on 2024-11-14 | | |
| Credentials were likely harvested from this host | | |
| A 47 MB outbound transfer was observed to 185.220.x.x on port 443 | | |
| Sensitive data was exfiltrated to a threat actor-controlled server | | |

**Part B:** Write a three-sentence finding using only observed facts for the following scenario:

> *You find that `cmd.exe` spawned from `svchost.exe`, executed `net user /domain`, and then connected outbound to an IP address that has no prior connection history on this host.*

Write the finding in a way that a lawyer could cite it without needing to understand Windows internals.

---

### Task 6 — Build a Case Structure

**Objective:** Set up a repeatable folder structure for the WKSTN-047 investigation.

Create the following folder structure on your host machine or lab VM. It mirrors a real IR case folder and keeps your work organized as you add evidence, tool output, notes, and reports.

```
IR-Cases\
└── WKSTN-047\
    ├── 00_Admin\
    │   ├── case-open-note.md
    │   ├── authorization.md
    │   └── chain-of-custody.md
    ├── 01_Collection\
    │   ├── volatile\
    │   ├── memory\
    │   ├── artifacts\
    │   └── hashes\
    ├── 02_Analysis\
    │   ├── mft\
    │   ├── registry\
    │   ├── event-logs\
    │   ├── prefetch\
    │   ├── shell-items\
    │   └── timeline\
    ├── 03_Findings\
    │   ├── facts.md
    │   ├── conclusions.md
    │   └── iocs.md
    └── 04_Reports\
        ├── technical-report.md
        └── executive-summary.md
```

Document the path where you created this structure:

```
Case Root Path:     
Created By:         
Date Created (UTC): 
Notes:              
```

---

### Task 7 — Write a Case Opening Note and Analyst Handoff

**Objective:** Produce the two documents that open every investigation and make it continuable by another responder.

**Part A — Case Opening Note**

Write a case opening note for WKSTN-047. This is the first entry in your `00_Admin\case-open-note.md`. It should be concise, factual, and complete enough that someone reading it two weeks later understands the starting conditions of the investigation.

```
Case Reference:       IR-2024-WKSTN047
Opened By:            
Date/Time Opened:     [UTC]
Escalated From:       SOC
Escalation Summary:   

Systems in Scope:     
Accounts in Scope:    
Initial Questions:    
  1.
  2.
  3.

Evidence Status:      [Not yet collected / In progress / Complete]
Containment Status:   [Not contained / Isolated / Remediated]
Authorization:        
Current Priority:     [Critical / High / Medium / Low]
Next Action:          
```

**Part B — Analyst Handoff Note**

Write a short handoff note as if you are handing this case to a colleague at the end of your shift. The handoff note lives in `00_Admin\` alongside the opening note. It should tell the incoming analyst exactly where things stand and what to do next.

```
Case Reference:       IR-2024-WKSTN047
Handoff From:         
Handoff To:           
Date/Time (UTC):      

Work Completed This Shift:
  -
  -
  -

Current State of Evidence:
  -

What Is Known So Far:
  -

What Remains Unknown:
  -

Recommended Next Actions (in priority order):
  1.
  2.
  3.

Open Questions Needing Follow-Up:
  -

Notes for Incoming Analyst:
```

---

### Task 8 — Reflection

Answer the following in 3–5 sentences each:

**1. Triage under pressure**
In the scenario, leadership wants a preliminary scope assessment by end of business. How does time pressure change your evidence prioritization decisions? What do you deprioritize, and what risk does that create?

**2. The cost of skipping question definition**
What happens if a responder skips Task 1 and goes straight to collecting artifacts? Give a specific example of how that could lead to a flawed conclusion or a missed finding.

**3. Documentation as protection**
How does the documentation discipline in this lab protect *you* as an analyst — not just the investigation?

**4. When the plan changes**
Midway through collection you discover that WKSTN-047 has an active RDP session from an internal IP you don't recognize. How does that change your plan? Walk through the decisions you would make.

---

## Deliverables Checklist

Your `lab02-notes.md` should contain:

- [ ] **Task 1** — At least 10 specific forensic questions, grouped by category
- [ ] **Task 2** — Question-to-artifact mapping with primary and corroborating sources
- [ ] **Task 3** — Volatile/persistent sort and prioritized collection order with reasoning
- [ ] **Task 4** — Step-by-step collection workflow across all six stages
- [ ] **Task 5** — Facts vs. conclusions exercise (Part A table + Part B written finding)
- [ ] **Task 6** — Case folder structure created and path documented
- [ ] **Task 7** — Case opening note and analyst handoff note
- [ ] **Task 8** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab02/
├── ReadMe.md                                   ← This file
├── lab02-notes.md                              ← Rollup working notes for the whole lab
├── task-answers.md                             ← Sample answers for the workbook Tasks
├── Lab02_01/                                   ← Ch2 §2.1 — IR Questions Forensics Should Answer
│   ├── ReadMe.md
│   ├── lab02.1-notes.md
│   └── question-evidence-worksheet.md             Reusable question → evidence mapping sheet
├── Lab02_02/                                   ← Ch2 §2.2 — High-Level Process in an Incident
│   ├── ReadMe.md
│   └── lab02.2-notes.md
├── Lab02_03/                                   ← Ch2 §2.3 — Documentation and Repeatability
│   ├── ReadMe.md
│   └── lab02.3-notes.md
└── Lab02_04/                                   ← Ch2 §2.4 — From Alert to Investigation Plan
    ├── ReadMe.md
    └── lab02.4-notes.md
```

---

## Key Takeaways

- **Questions before evidence.** Knowing what you're trying to prove or disprove before you collect keeps the investigation focused and makes your findings defensible.
- **Volatility determines sequence.** Evidence that disappears on reboot gets collected first — always.
- **Facts and conclusions are not the same thing.** Mixing them in your documentation undermines trust in your findings. Label everything.
- **Documentation is the investigation.** If it isn't written down, it didn't happen as far as anyone reviewing your work is concerned. That includes the tool used, command run, output location, and timestamp.
- **A handoff note is a professional obligation.** Investigations don't end at shift change. A clear handoff keeps the case moving and protects the work you've already done.

---

**Next:** Lab 03 — Digital Forensics and Advanced Data Triage

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
