# Forensic Challenge: Multi-Host Triage and Acquisition Under Pressure

**Capstone Challenge for Chapter 3**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

This challenge lab makes you apply the full Chapter 3 skill set in one incident instead of one section at a time.

Here you decide on full imaging, memory capture, and targeted triage under operational pressure. You face incomplete information, competing priorities, business impact, legal risk, and a leadership team demanding fast answers. The question is no longer only whether full imaging is good, whether memory matters, or whether targeted triage is defensible.

This is a judgment lab, not a parser lab.

Your task is to make collection decisions that are:
- Operationally realistic
- Forensically defensible
- Clearly documented
- Adaptable when new facts arrive

You will prioritize hosts, choose between memory, targeted triage, and full imaging, and define collection tiers. You will also design an evidence handling approach, document residual risk, and explain your choices to both technical and non-technical audiences.

---

## What This Challenge Covers

| Area | Applied Skill |
|---|---|
| Triage prioritization | Choosing the right host first under constraints |
| Collection depth | Deciding between memory, targeted triage, and full imaging |
| Volatile evidence | Identifying where delay creates the greatest loss |
| Preservation | Determining which systems justify deeper long-term evidence handling |
| Defensibility | Writing notes that survive later review by management, legal, or another responder |
| Adaptation | Revising the plan when the incident scope expands |

---

## Learning Objectives

By completing this challenge, you will be able to:

- Build a first-phase triage plan for a multi-host Windows intrusion
- Justify different collection depths for different hosts
- Prioritize volatile evidence without losing sight of long-term preservation value
- Define escalation triggers that cause deeper collection
- Package and document collection decisions in a way another responder could execute
- Explain triage tradeoffs to leadership without overstating certainty
- Revise a plan when new facts materially change scope

---

## Estimated Time

90–150 minutes

---

## Prerequisites

- Completion of Labs 3.1, 3.2, 3.3, and 3.4
- A text editor or markdown editor
- Your `lab03.5-notes.md` working file (template included in this folder)
- Optional: a Windows VM for thinking through practical collection order and scripting choices

---

## Scenario

At **08:11 UTC on a Monday morning**, your IR team receives multiple alerts that may be part of the same intrusion.

### Known Hosts

**DC-03**
A domain controller shows:
- Multiple failed privileged logons overnight
- Two successful network logons from a workstation that should not be authenticating to the DC
- A new service installation event
- A short burst of LDAP enumeration activity from an internal host

**FIN-WS42**
A finance workstation assigned to a senior payroll specialist shows:
- `OUTLOOK.EXE` spawning `EXCEL.EXE`
- `EXCEL.EXE` spawning `POWERSHELL.EXE`
- Suspicious outbound HTTPS traffic shortly afterward
- No reboot yet
- User reports "Excel froze and then things started closing on their own"

**ENG-FS02**
An engineering file server shows:
- Large after-hours access to a confidential project folder
- More than 6 GB of file reads in a 90-minute window
- Access performed under a valid domain user account that normally does not touch that share

**VPN-GW02**
A remote access gateway shows:
- Successful VPN authentication using the FIN-WS42 user's account
- Source geography inconsistent with the user's normal location
- Session duration of 11 minutes
- No confirmed malware execution on the gateway itself

**WEB-APP-04**
An internal application server shows:
- Brief PowerShell execution
- Unusual outbound connections
- A suspicious service that appeared and then disappeared
- No reboot yet
- Host is still actively serving users

**PRINT-09**
A print server shows:
- One AV quarantine event
- No known suspicious authentication, scripting, or lateral movement
- Low business criticality

---

## Operational Constraints

- Three responders are available for the first four hours
- One responder is junior and should not be assigned the most legally sensitive host alone
- Evidence storage is limited
- Leadership wants a same-day scope update before 16:00 local time
- Operations wants to avoid taking production systems offline unless clearly justified
- Legal has stated that evidence preservation may become critical if payroll or engineering data exposure is confirmed

---

## Challenge Rule

You are not allowed to respond with:

> "Image everything immediately."

Any strategy that ignores time, staffing, storage, volatility, or operational impact is non-responsive.

Your job is to build the most defensible first-phase plan possible with the facts available now.

---

## Challenge Tasks

---

### Task 1 — Define the First-Phase Questions

**Objective:** Identify the questions that should drive collection decisions in the next several hours.

Write at least **12 specific first-phase investigative questions**. These must be triage-driving questions, not long-term case reconstruction questions.

Examples of the level of specificity expected:
- Did FIN-WS42 execute malicious code from the email attachment?
- Is there active attacker presence or volatile evidence on WEB-APP-04?
- Did the account activity on VPN-GW02 precede or enable the activity on FIN-WS42?
- Did DC-03 record evidence consistent with lateral movement or privilege misuse?

Document your answers in `lab03.5-notes.md`:

```
1.
2.
3.
4.
5.
6.
7.
8.
9.
10.
11.
12.
```

Now group them:

| Category | Question Numbers |
|---|---|
| Active attacker presence | |
| Initial access and execution | |
| Authentication misuse | |
| Lateral movement | |
| Data access / exfiltration risk | |
| Preservation / escalation decisions | |

---

### Task 2 — Rank the Hosts

**Objective:** Decide which systems matter most right now and why.

Complete the table.

| Host | Business Criticality | Investigative Value | Volatile Evidence Risk | Preservation Value | Recommended Priority | Notes |
|---|---|---|---|---|---|---|
| DC-03 | | | | | | |
| FIN-WS42 | | | | | | |
| ENG-FS02 | | | | | | |
| VPN-GW02 | | | | | | |
| WEB-APP-04 | | | | | | |
| PRINT-09 | | | | | | |

Then rank them:

| Priority | Host | Why It Belongs Here |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |

Answer the following in three to five sentences each:

**1. Which host should receive the first responder's immediate attention, and why?**

**2. Which host most strongly justifies memory capture before other actions?**

**3. Which host most strongly justifies full disk imaging during the first phase?**

**4. Which host are you most comfortable deferring, and why?**

**5. What one new fact would force you to completely reorder the list?**

---

### Task 3 — Choose a Collection Strategy Per Host

**Objective:** Match collection depth to host value, volatility, and operational need.

Use one of the following for each host:
- Full disk image + memory
- Targeted triage + memory
- Memory first, then reassess
- Targeted triage only
- Deferred pending scope
- Preserve logs / remote artifacts only

| Host | Selected Strategy | Why This Is Appropriate | What It Should Answer Quickly | What You Accept Risking |
|---|---|---|---|---|
| DC-03 | | | | |
| FIN-WS42 | | | | |
| ENG-FS02 | | | | |
| VPN-GW02 | | | | |
| WEB-APP-04 | | | | |
| PRINT-09 | | | | |

---

### Task 4 — Assign Responders and Sequence the First Four Hours

**Objective:** Turn the strategy into an execution plan.

You have:
- **Responder A** — Senior
- **Responder B** — Senior
- **Responder C** — Junior

Build a four-hour plan.

| Time Window | Responder | Host | Action | Primary Goal |
|---|---|---|---|---|
| Hour 1 | | | | |
| Hour 1 | | | | |
| Hour 1 | | | | |
| Hour 2 | | | | |
| Hour 2 | | | | |
| Hour 2 | | | | |
| Hour 3 | | | | |
| Hour 3 | | | | |
| Hour 4 | | | | |
| Hour 4 | | | | |

Then answer:

**1. Why did you assign the junior responder where you did?**

**2. Which host would you avoid assigning to a single junior responder, and why?**

**3. Where is the greatest risk of losing volatile evidence if your plan slips by 45 minutes?**

---

### Task 5 — Build Collection Tiers

**Objective:** Define a reusable collection model instead of making every host an exception.

| Tier | Purpose | Typical Host Type in This Scenario | Artifacts / Evidence Included |
|---|---|---|---|
| Tier 1 | Fast scope collection | | |
| Tier 2 | Standard triage collection | | |
| Tier 3 | Deep preservation collection | | |

Assign each host:

| Host | Assigned Tier | Why |
|---|---|---|
| DC-03 | | |
| FIN-WS42 | | |
| ENG-FS02 | | |
| VPN-GW02 | | |
| WEB-APP-04 | | |
| PRINT-09 | | |

---

### Task 6 — Define Escalation Triggers

**Objective:** Show how the plan changes when new evidence arrives.

For each host, identify at least **two escalation triggers** that would force deeper collection, increased priority, or broader scope.

| Host | Escalation Trigger 1 | Escalation Trigger 2 |
|---|---|---|
| DC-03 | | |
| FIN-WS42 | | |
| ENG-FS02 | | |
| VPN-GW02 | | |
| WEB-APP-04 | | |
| PRINT-09 | | |

Examples:
- Live C2 connection discovered
- Privileged account misuse confirmed
- Evidence of deleted tooling found
- Sensitive data access confirmed
- PowerShell with encoded commands identified
- Additional hosts show matching authentication pattern

---

### Task 7 — Design the Minimum Viable Collection Package

**Objective:** Define what your team must collect from a compromised Windows host before you consider the first phase "good enough."

Choose one host from this scenario that you believe is best suited for **targeted triage + memory**, and define the minimum viable package.

#### Part A — Investigative questions

Write six artifact-answerable questions.

1.
2.
3.
4.
5.
6.

#### Part B — Map to artifacts

| # | Question | Primary Artifact | Corroborating Artifact |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |
| 6 | | | |

#### Part C — Tier the artifacts

Use this pool:
- Memory
- Security.evtx
- System.evtx
- PowerShell logs
- Prefetch
- Amcache
- SRUM
- Registry hives
- Scheduled tasks
- Services configuration
- Browser history
- LNK files
- Jump Lists
- MFT
- USN Journal
- User profile directories

| Priority Tier | Artifacts | Why |
|---|---|---|
| Must Collect | | |
| Strongly Preferred | | |
| Hypothesis-Driven | | |

---

### Task 8 — Imaging and Memory Decision Challenge

**Objective:** Defend your highest-stakes preservation decisions.

Answer the following in four to six sentences each:

**1. Which host in this scenario has the strongest argument for full imaging, and why is that argument stronger than for the other hosts?**

**2. Which host in this scenario has the strongest argument for immediate memory capture, and why?**

**3. Where would targeted triage be more defensible than full imaging, even if imaging would preserve more data?**

**4. What is the strongest argument against your own plan? How do you counter it?**

---

### Task 9 — Draft the Collection Decision Note

**Objective:** Produce the record another responder could inherit.

Save as `Collection_Decision_Note_Lab03.5.md` in this folder.

Use this structure:

```markdown
# Collection Decision Note
Case Reference:
Author:
Date/Time (UTC):

## Incident Summary
[One paragraph]

## Known Hosts
- DC-03:
- FIN-WS42:
- ENG-FS02:
- VPN-GW02:
- WEB-APP-04:
- PRINT-09:

## Priority Order
1.
2.
3.
4.
5.
6.

## Collection Decisions
| Host | Strategy | Reason |
|---|---|---|
| DC-03 | | |
| FIN-WS42 | | |
| ENG-FS02 | | |
| VPN-GW02 | | |
| WEB-APP-04 | | |
| PRINT-09 | | |

## Operational Constraints Acknowledged
-
-
-

## Residual Risks Accepted
-
-
-

## Immediate Next Actions
-
-
-
```

---

### Task 10 — Management Memo

**Objective:** Explain the strategy without sounding evasive or overly technical.

Save as `Management_Justification_Lab03.5.md` in this folder.

Write a short memo with this structure:

```markdown
# Initial Collection Strategy Justification
**Prepared By:**
**Date:**
**Incident Reference:**
**Audience:** IR Leadership, Operations, Legal

---

## Summary
[One paragraph]

## Why We Are Not Taking Every System Offline for Imaging
[2–3 paragraphs]

## What Our First-Phase Collection Will Tell Us
[1–2 paragraphs]

## What It May Not Tell Us Yet
[1 paragraph]

## Systems Most Likely to Require Deeper Preservation
| Host | Likely Deeper Action | Why |
|---|---|---|
| | | |
| | | |
| | | |

## Next Decision Point
[When the plan will be reviewed and what new facts would change it]
```

---

### Task 11 — Scope Expansion Inject

**Objective:** Revise the plan when the case grows.

Halfway through your first-phase collection, the following new facts arrive:

- **FIN-WS42** has confirmed evidence of a malicious macro-enabled spreadsheet and a recent Jump List entry for a suspicious `.xlsm` file.
- **VPN-GW02** logs show the FIN-WS42 user authenticated from an unusual geography 14 minutes before the suspicious Office activity.
- **DC-03** shows the same account later authenticating to a second server not originally in scope.
- **ENG-FS02** confirms 6.4 GB of confidential engineering data was read and compressed.
- **WEB-APP-04** still has not rebooted, and EDR shows a suspicious process tree that may be consistent with a web shell.
- **PRINT-09** shows no additional suspicious activity, and the quarantined file appears to be commodity adware.

Now redo the priority ranking:

| New Priority | Host | Why It Changed or Stayed |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |

Then answer:

1. Is this still a limited workstation incident? Why or why not?
2. Which two hosts now matter most for scope expansion?
3. Which host matters most for potential data exposure?
4. Which host matters most for volatile evidence preservation?
5. What new host category would you now consider bringing into scope?

---

### Task 12 — Reflection

Answer in four to six sentences each.

1. Why is "collect everything" often a poor IR answer even when it sounds safer?
2. Why can delayed memory capture do more damage to an investigation than delaying some disk artifacts?
3. Why does documenting constraints make a triage strategy stronger rather than weaker?
4. Why is changing the plan when new evidence arrives a sign of discipline rather than inconsistency?
5. Which part of this challenge was the hardest: prioritization, preservation depth, documentation, or explaining tradeoffs? Why?

---

## Deliverables Checklist

Your `lab03.5-notes.md` should contain:

- [ ] **Task 1** — 12 first-phase questions grouped by category
- [ ] **Task 2** — Host ranking table and written responses
- [ ] **Task 3** — Per-host collection strategy table
- [ ] **Task 4** — Four-hour responder plan
- [ ] **Task 5** — Collection tier model and host assignments
- [ ] **Task 6** — Escalation triggers for all hosts
- [ ] **Task 7** — Minimum viable collection package for one host
- [ ] **Task 8** — Imaging and memory decision analysis
- [ ] **Task 9** — Collection decision note (saved as `Collection_Decision_Note_Lab03.5.md`)
- [ ] **Task 10** — Management justification memo (saved as `Management_Justification_Lab03.5.md`)
- [ ] **Task 11** — Updated priorities after scope expansion
- [ ] **Task 12** — Reflection answers

---

## Files in This Folder

```
Lab03/
└── Capstone/
    ├── ReadMe.md                                ← This file
    ├── lab03.5-notes.md                         ← Your working notes file
    ├── Collection_Decision_Note_Lab03.5.md      ← Produced in Task 9
    └── Management_Justification_Lab03.5.md      ← Produced in Task 10
```

---

## Key Takeaways

- **The first challenge in incident response is often not analysis.** It is choosing what to collect, from where, and in what order.
- **The right collection strategy is rarely uniform across all hosts.** A finance workstation, a domain controller, and a print server in the same incident deserve very different first-phase decisions.
- **Fast triage and deep preservation are not opposites.** Good responders know when each is justified, and how to combine them.
- **Memory, targeted triage, and full imaging answer different questions and carry different costs.** The right call depends on what you need to prove and what you can afford to lose.
- **A sound strategy that is not documented is difficult to defend.** Reasoning, constraints, and residual risk all need to be on paper.
- **The best triage plans are built to change when the facts change.** Revision is discipline, not failure.

---

**Next:** Lab 04 — Windows File System Forensics (NTFS)

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
