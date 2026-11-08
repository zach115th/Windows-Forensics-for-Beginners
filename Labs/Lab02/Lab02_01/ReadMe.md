# Lab 2.1 — IR Questions Forensics Should Answer

**Supporting Section 2.1: IR Questions Forensics Should Answer**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

The most common mistake in incident response is starting with the wrong question, not bad tooling or missing artifacts.

When an alert lands, the instinct is to start collecting. Pull the MFT, run the event log parser, dump memory. That instinct isn't wrong. Without a clear set of investigative questions driving the work, though, collection becomes unfocused, analysis drifts, and findings are harder to defend. You may collect terabytes of evidence and still be unable to answer the question leadership is asking.

This lab builds the habit of asking before acting. You'll learn to translate a vague incident report into a structured set of specific, answerable forensic questions. Then you'll map those questions to the Windows artifacts most likely to answer them. This workflow applies to every investigation in this book and every real case you'll work.

---

## Learning Objectives

By completing this lab, you will be able to:

- Identify the most important forensic questions in a Windows incident before touching any evidence
- Distinguish confirmed facts from assumptions, hypotheses, and speculation
- Map common IR questions to specific Windows artifact sources
- Prioritize investigative questions based on urgency and investigative impact
- Recognize evidence gaps and articulate what conclusions those gaps prevent
- Build a reusable question-to-evidence worksheet for future cases

---

## Estimated Time

30–45 minutes

---

## Prerequisites

- Completion of Lab 01 (or equivalent Windows VM setup)
- Completion of Lab 02 introduction (recommended)
- A text editor or markdown editor
- Your `lab02.1-notes.md` file (template included in this folder)

No tooling or artifact parsing is required for this lab.

---

## Scenario

At 10:32 on a Wednesday morning your SOC escalates the following:

> *"A user on WKSTN-112 opened an email attachment approximately 40 minutes ago. The EDR flagged a PowerShell process spawning shortly afterward. There was outbound traffic to an unfamiliar external IP within five minutes of the PowerShell execution. The user is a member of the finance team with access to accounts payable systems. The host has not been contained. No other hosts have been flagged."*

That is the complete picture. Everything else is unknown: what the attachment was, what PowerShell ran, whether data left the network, and whether other hosts are involved.

Your job before touching a single artifact is to turn that paragraph into a structured set of investigative questions.

---

## Background: Why Questions Come First

### Tool-driven vs. question-driven investigation

A tool-driven investigation starts with collection: pull everything, parse everything, look for something bad. This approach has a place, particularly in broad triage. But it produces unfocused findings, wastes time on irrelevant artifacts, and makes it hard to explain *why* you looked where you looked.

A question-driven investigation starts differently: *what are we trying to prove or disprove?* That question determines which artifacts you collect, in what order, and how you interpret what you find. It also produces a more defensible record, because every collection decision traces back to a specific investigative need.

### What good forensic questions look like

Good forensic questions share three characteristics:

**Specific**: answerable by examining a defined artifact or set of artifacts.
> **Weak:** "Was there attacker activity?"
> **Strong:** "Did PowerShell execute with encoded arguments on WKSTN-112 between 09:32 and 10:32 UTC?"

**Falsifiable**: you can look at evidence and reach a yes or no conclusion.
> **Weak:** "Was the user compromised?"
> **Strong:** "Was there an interactive or remote logon to WKSTN-112 using credentials other than the assigned user account?"

**Prioritized**: ordered by urgency. Questions about active attacker presence come before questions about historical activity.

### The six IR question categories

Most incident response questions fall into one of these categories. Your question list should address all of them, though the depth of each will vary by incident type.

| Category | Core Question |
|---|---|
| **Active threat** | Is the attacker still present on this host or the network? |
| **Initial access** | How did the attacker get in? |
| **Execution** | What did they run? |
| **Persistence** | Did they establish a foothold that survives reboot or remediation? |
| **Impact** | What data was accessed, moved, or destroyed? |
| **Scope** | Which other hosts, accounts, or systems are affected? |

---

## Lab Tasks

---

### Task 1 — Separate Facts from Assumptions

**Objective:** Establish what you actually know before building your question list.

Every real incident comes loaded with assumptions, rumors, and inferences dressed up as facts. Read the scenario carefully. Before writing a single investigative question, be clear about what is confirmed and what isn't.

**Part A:** Sort each statement below into the correct column.

| Statement | Confirmed Fact | Assumption / Unknown |
|---|---|---|
| A user on WKSTN-112 opened an email attachment | | |
| The attachment was malicious | | |
| PowerShell executed after the attachment was opened | | |
| PowerShell was launched by the Office application | | |
| Outbound traffic occurred within five minutes of PowerShell execution | | |
| Data was exfiltrated | | |
| The external IP is attacker-controlled | | |
| No other hosts are compromised | | |
| The user's credentials are still valid | | |
| The attacker has persistence on WKSTN-112 | | |

**Part B:** Write 2–3 sentences explaining why the distinction between facts and assumptions matters *before* you start collecting evidence. What could go wrong if you treat an assumption as a confirmed fact during early triage?

```
[Your response here]
```

---

### Task 2 — Build Your Investigative Question List

**Objective:** Translate the scenario into at least 12 specific, prioritized forensic questions.

Using the six IR question categories from the background section, write at least **12 forensic questions** for the WKSTN-112 scenario. Order them by urgency. The questions that determine whether the attacker is still active and whether containment is needed come first.

Apply the specificity test to each question before writing it down: can you point to a specific artifact or log source that would answer it? If not, make the question more specific.

```
Priority  Category              Question
--------  --------              --------
1.        Active threat         
2.        Active threat         
3.        Initial access        
4.        Initial access        
5.        Execution             
6.        Execution             
7.        Persistence           
8.        Persistence           
9.        Impact                
10.       Impact                
11.       Scope                 
12.       Scope                 
```

---

### Task 3 — Map Questions to Windows Artifacts

**Objective:** Connect each investigative question to the specific artifact sources that can answer it.

For each question from Task 2, identify:
- The **primary artifact**: the most direct evidence source
- A **corroborating artifact**: a second independent source that can confirm or contradict the primary
- The **specific data point**: the exact field, event ID, key, or record you're looking for

| # | Question | Primary Artifact | Corroborating Artifact | Specific Data Point |
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
| 11 | | | | |
| 12 | | | | |

> **Why corroborating sources matter:** Two independent artifact sources answering the same question are far more defensible than one. Attackers clear logs, delete Prefetch entries, and tamper with timestamps. If your entire answer to a question rests on a single artifact, a sophisticated attacker can remove it.

---

### Task 4 — Identify Evidence Gaps

**Objective:** Recognize what you can't answer, and why that matters for your conclusions.

Not every question will have a clean artifact answer. Log retention policies, disabled auditing, EDR coverage gaps, and attacker anti-forensics all create blind spots. Knowing where your gaps are is as important as knowing what you found.

**Part A:** For each scenario below, identify what forensic question it prevents you from answering and what conclusion you *cannot* draw as a result.

| Gap Scenario | Question It Prevents | Conclusion You Cannot Draw |
|---|---|---|
| PowerShell Script Block Logging was not enabled on WKSTN-112 | | |
| The Security event log on WKSTN-112 was cleared 20 minutes after the initial alert | | |
| Prefetch is disabled on WKSTN-112 (a tuning script set `EnablePrefetcher` to 0) | | |
| The outbound traffic destination IP resolves to a CDN with thousands of legitimate customers | | |
| The user's email client stores mail in a cloud-hosted mailbox, not locally | | |
| The EDR agent on WKSTN-112 was not collecting process command-line arguments | | |

**Part B:** Write 2–3 sentences on how you would communicate an evidence gap to a non-technical stakeholder. Specifically, how do you explain that "we can't confirm X" is different from "we confirmed X didn't happen"?

```
[Your response here]
```

---

### Task 5 — Build a Reusable Question-to-Evidence Worksheet

**Objective:** Generalize your work from this scenario into a reusable template for future cases.

The questions you asked in Task 2 and the artifact mappings from Task 3 are not unique to WKSTN-112. Most Windows endpoint incidents require answering the same core questions. Only the specifics change.

Build a reusable worksheet by completing the table below. Make it general enough to apply to any Windows endpoint incident, not just this scenario.

| Category | Core Forensic Question | Primary Windows Artifact | Common Event IDs / Keys / Records | Notes |
|---|---|---|---|---|
| **Active threat** | Is a malicious process currently running? | Memory, running process list | N/A (volatile) | Collect first, lost on reboot |
| **Active threat** | Are there active C2 network connections? | Memory, `Get-NetTCPConnection` | N/A (volatile) | Correlate with firewall/proxy logs |
| **Initial access** | Did a user open a malicious document or attachment? | | | |
| **Initial access** | Was there a malicious logon event? | | | |
| **Execution** | What processes executed and when? | | | |
| **Execution** | Did PowerShell or cmd.exe run suspicious commands? | | | |
| **Persistence** | Are there new or modified autorun entries? | | | |
| **Persistence** | Were new services or scheduled tasks created? | | | |
| **Impact** | Were files accessed, staged, or deleted? | | | |
| **Impact** | Was data transferred off the host? | | | |
| **Scope** | Were other hosts accessed from this one? | | | |
| **Scope** | Were credentials used on other systems? | | | |

Save this worksheet as `question-evidence-worksheet.md` in this folder. You'll reference it in every lab from here forward.

---

### Task 6 — Apply the Framework to a Second Scenario

**Objective:** Practice applying the question-driven framework without being prompted step by step.

**Scenario:** The IT help desk reports that a domain administrator account (`DA-svc-backup`) was used to log on to three workstations overnight, all outside normal business hours. The account is normally used only for scheduled backup tasks that run on a single server. No backup jobs are scheduled for those workstations.

Without being walked through each step, produce the following for this scenario in your notes file:

1. A fact/assumption separation (at least six statements sorted)
2. Eight specific forensic questions (two per category minimum for the most relevant categories)
3. A primary artifact for each question
4. Two evidence gaps that could limit your conclusions
5. A two-sentence scope assessment: based on what you know, is this a single-host problem or something broader?

---

### Task 7 — Reflection

Answer the following in 3–5 sentences each:

**1. Question quality**
Look back at your question list from Task 2. Pick the weakest question, the one that's least specific or hardest to answer with a Windows artifact. Rewrite it to be more specific and explain what you changed.

**2. The assumption trap**
In the scenario, the SOC escalation says "The EDR flagged a PowerShell process spawning shortly afterward." A colleague says "PowerShell definitely ran, the EDR said so." What's wrong with that interpretation, and how does your Task 1 work protect against it?

**3. Gaps and conclusions**
You've identified several evidence gaps in Task 4. How do you handle a situation where a gap prevents you from answering a question that leadership considers critical? What do you tell them?

**4. Reusability**
How would the worksheet you built in Task 5 change if the incident involved a Windows server rather than a workstation? What new questions would you add and what might become less relevant?

---

## Deliverables Checklist

Your `lab02.1-notes.md` should contain:

- [ ] **Task 1**: Fact/assumption sort table and Part B written response
- [ ] **Task 2**: At least 12 specific, prioritized forensic questions
- [ ] **Task 3**: Question-to-artifact mapping with primary, corroborating, and specific data points
- [ ] **Task 4**: Evidence gap table and Part B written response
- [ ] **Task 5**: Completed reusable worksheet saved as `question-evidence-worksheet.md`
- [ ] **Task 6**: Second scenario analysis (all five components)
- [ ] **Task 7**: Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab02/
├── lab02-notes.md                  ← Your working notes file (whole lab)
└── Lab02_01/
    ├── ReadMe.md                       ← This file
    ├── lab02.1-notes.md                ← Your working notes file
    └── question-evidence-worksheet.md  ← Reusable question → evidence worksheet
```

---

## Key Takeaways

- **Questions before evidence, always.** Knowing what you're trying to prove or disprove before collecting keeps the investigation focused and the findings defensible.
- **Facts and assumptions are not the same thing.** Separating them at the start of an investigation prevents the most common source of analytical error in IR.
- **Specific questions produce specific findings.** Vague questions lead to broad, unfocused collection and conclusions that don't hold up under scrutiny.
- **Gaps are findings too.** Documenting what you can't determine, and why, is as important as documenting what you found. "We cannot confirm X" is not the same as "X didn't happen."
- **Build once, reuse often.** The question-to-evidence worksheet you built in Task 5 is a living document. Add to it as you learn new artifacts and encounter new incident types.

---

**Next:** Lab 2.2 — High-Level Process in an Incident

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
