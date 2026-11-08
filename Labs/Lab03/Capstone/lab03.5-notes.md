# Lab 3.5 — Capstone Analyst Notes
**Forensic Challenge: Multi-Host Triage and Acquisition Under Pressure**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________
**Date Started:** ___________________________
**Date Completed:** ___________________________
**Lab Environment:** ___________________________
**Case Reference:** IR-2024-CAPSTONE03

---

## Task 1 — First-Phase Investigative Questions

> Write at least 12 specific triage-driving questions. Not long-term reconstruction questions —
> questions that should drive collection decisions in the next several hours.

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

**Grouped by category:**

| Category | Question Numbers |
|---|---|
| Active attacker presence | |
| Initial access and execution | |
| Authentication misuse | |
| Lateral movement | |
| Data access / exfiltration risk | |
| Preservation / escalation decisions | |

---

## Task 2 — Host Ranking

**Part A — Host assessment table**

| Host | Business Criticality | Investigative Value | Volatile Evidence Risk | Preservation Value | Recommended Priority | Notes |
|---|---|---|---|---|---|---|
| DC-03 | | | | | | |
| FIN-WS42 | | | | | | |
| ENG-FS02 | | | | | | |
| VPN-GW02 | | | | | | |
| WEB-APP-04 | | | | | | |
| PRINT-09 | | | | | | |

---

**Part B — Ranked priority list**

| Priority | Host | Why It Belongs Here |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |

---

**Part C — Short answers (3–5 sentences each)**

**1. Which host should receive the first responder's immediate attention, and why?**
[Your response here]

---

**2. Which host most strongly justifies memory capture before other actions?**
[Your response here]

---

**3. Which host most strongly justifies full disk imaging during the first phase?**
[Your response here]

---

**4. Which host are you most comfortable deferring, and why?**
[Your response here]

---

**5. What one new fact would force you to completely reorder the list?**
[Your response here]

---

## Task 3 — Per-Host Collection Strategy

> Strategy options: Full disk image + memory / Targeted triage + memory / Memory first, then reassess /
> Targeted triage only / Deferred pending scope / Preserve logs / remote artifacts only

| Host | Selected Strategy | Why This Is Appropriate | What It Should Answer Quickly | What You Accept Risking |
|---|---|---|---|---|
| DC-03 | | | | |
| FIN-WS42 | | | | |
| ENG-FS02 | | | | |
| VPN-GW02 | | | | |
| WEB-APP-04 | | | | |
| PRINT-09 | | | | |

---

## Task 4 — Four-Hour Responder Plan

> Three responders: A (senior), B (senior), C (junior). The junior should not be assigned the most
> legally sensitive host alone.

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

---

**1. Why did you assign the junior responder where you did?**
[Your response here]

---

**2. Which host would you avoid assigning to a single junior responder, and why?**
[Your response here]

---

**3. Where is the greatest risk of losing volatile evidence if your plan slips by 45 minutes?**
[Your response here]

---

## Task 5 — Collection Tier Model

**Part A — Tier definitions**

| Tier | Purpose | Typical Host Type in This Scenario | Artifacts / Evidence Included |
|---|---|---|---|
| Tier 1 | Fast scope collection | | |
| Tier 2 | Standard triage collection | | |
| Tier 3 | Deep preservation collection | | |

---

**Part B — Host tier assignments**

| Host | Assigned Tier | Why |
|---|---|---|
| DC-03 | | |
| FIN-WS42 | | |
| ENG-FS02 | | |
| VPN-GW02 | | |
| WEB-APP-04 | | |
| PRINT-09 | | |

---

## Task 6 — Escalation Triggers

> At least two per host. Each trigger should describe a specific finding that would cause
> deeper collection, increased priority, or broader scope.

| Host | Escalation Trigger 1 | Escalation Trigger 2 |
|---|---|---|
| DC-03 | | |
| FIN-WS42 | | |
| ENG-FS02 | | |
| VPN-GW02 | | |
| WEB-APP-04 | | |
| PRINT-09 | | |

---

## Task 7 — Minimum Viable Collection Package

**Selected host:** _______________
**Why this host is best suited for targeted triage + memory:**
[Your response here]

---

**Part A — Six artifact-answerable investigative questions**

```
1.
2.
3.
4.
5.
6.
```

---

**Part B — Question to artifact mapping**

| # | Question | Primary Artifact | Corroborating Artifact |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |
| 6 | | | |

---

**Part C — Tiered artifact list**

| Priority Tier | Artifacts | Why |
|---|---|---|
| Must Collect | | |
| Strongly Preferred | | |
| Hypothesis-Driven | | |

---

## Task 8 — Imaging and Memory Decision Analysis

> 4–6 sentences each.

**1. Which host has the strongest argument for full imaging, and why is that argument stronger than for the other hosts?**
[Your response here]

---

**2. Which host has the strongest argument for immediate memory capture, and why?**
[Your response here]

---

**3. Where would targeted triage be more defensible than full imaging, even if imaging would preserve more data?**
[Your response here]

---

**4. What is the strongest argument against your own plan? How do you counter it?**
[Your response here]

---

## Task 9 — Collection Decision Note

> Save the completed note as `Collection_Decision_Note_Lab03.5.md` in this folder.
> Record completion below.

```
File saved:        Collection_Decision_Note_Lab03.5.md
Saved to:          Lab03/Capstone/
Date completed:    [UTC]
Notes:
```

---

## Task 10 — Management Justification Memo

> Save the completed memo as `Management_Justification_Lab03.5.md` in this folder.
> Record completion below.

```
File saved:        Management_Justification_Lab03.5.md
Saved to:          Lab03/Capstone/
Date completed:    [UTC]
Notes:
```

---

## Task 11 — Scope Expansion: Updated Plan

**New facts received (recap):**
- FIN-WS42 — Malicious macro-enabled spreadsheet confirmed; Jump List shows recent `.xlsm` access
- VPN-GW02 — FIN-WS42 user authenticated from unusual geography 14 minutes before suspicious Office activity
- DC-03 — Same account later authenticated to a second server not originally in scope
- ENG-FS02 — 6.4 GB of confidential engineering data confirmed read and compressed
- WEB-APP-04 — Still has not rebooted; EDR suggests possible web shell process tree
- PRINT-09 — No additional activity; quarantined file appears to be commodity adware

---

**Part A — Re-ranked priority list**

| New Priority | Host | Why It Changed or Stayed |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |

---

**Part B — Scope expansion answers**

**1. Is this still a limited workstation incident? Why or why not?**
[Your response here]

---

**2. Which two hosts now matter most for scope expansion?**
[Your response here]

---

**3. Which host matters most for potential data exposure?**
[Your response here]

---

**4. Which host matters most for volatile evidence preservation?**
[Your response here]

---

**5. What new host category would you now consider bringing into scope?**
[Your response here]

---

## Task 12 — Reflection

> 4–6 sentences each.

**1. Why is "collect everything" often a poor IR answer even when it sounds safer?**
[Your response here]

---

**2. Why can delayed memory capture do more damage to an investigation than delaying some disk artifacts?**
[Your response here]

---

**3. Why does documenting constraints make a triage strategy stronger rather than weaker?**
[Your response here]

---

**4. Why is changing the plan when new evidence arrives a sign of discipline rather than inconsistency?**
[Your response here]

---

**5. Which part of this challenge was the hardest: prioritization, preservation depth, documentation, or explaining tradeoffs? Why?**
[Your response here]

---

## Additional Notes

> Free text — questions, observations, things to revisit, connections to real incidents you've worked.

[Your notes here]

---

*Lab 3.5 Capstone Notes — Windows Forensics for Beginners*
*Keep this file in your `Labs/Lab03/Capstone/` folder alongside the `ReadMe.md`.*
