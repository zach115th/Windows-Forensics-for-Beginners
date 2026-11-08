# Lab 2.1 — Analyst Notes
**IR Questions Forensics Should Answer**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Lab Environment:** ___________________________  

---

## Task 1 — Facts vs. Assumptions

**Part A — Sort each statement**

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

**Part B — Why the distinction matters**

> Write 2–3 sentences explaining why separating facts from assumptions matters before collecting evidence. What could go wrong if you treat an assumption as a confirmed fact during early triage?
[Your response here]
---

## Task 2 — Investigative Question List

> Write at least 12 specific, prioritized forensic questions. Apply the specificity test: can you point to a specific artifact that answers it? If not, rewrite it.
Priority  Category              Question
Active threat
Active threat
Initial access
Initial access
Execution
Execution
Persistence
Persistence
Impact
Impact
Scope
Scope
---

## Task 3 — Question to Artifact Mapping

> For each question, identify the primary artifact, a corroborating artifact, and the specific data point you are looking for.

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

---

## Task 4 — Evidence Gaps

**Part A — Gap analysis table**

| Gap Scenario | Question It Prevents | Conclusion You Cannot Draw |
|---|---|---|
| PowerShell Script Block Logging was not enabled on WKSTN-112 | | |
| The Security event log was cleared 20 minutes after the initial alert | | |
| Prefetch is disabled on WKSTN-112 (a tuning script set `EnablePrefetcher` to 0) | | |
| The outbound IP resolves to a CDN used by thousands of legitimate services | | |
| The user's email is stored in a cloud-hosted mailbox, not locally | | |
| The EDR agent was not collecting process command-line arguments | | |

**Part B — Communicating gaps to non-technical stakeholders**

> Write 2–3 sentences explaining how you would communicate an evidence gap — specifically the difference between "we can't confirm X" and "we confirmed X didn't happen."
[Your response here]
---

## Task 5 — Reusable Worksheet Note

> Record that you saved the completed worksheet and its location.
Worksheet file:     question-evidence-worksheet.md
Saved to:           `Labs/Lab02/Lab02_01/`
Date completed:
Notes:
---

## Task 6 — Second Scenario: DA Account Misuse

**Scenario recap:** Domain admin account `DA-svc-backup` logged into three workstations overnight outside business hours. Normally used only for scheduled backup jobs on a single server. No backup jobs are scheduled for those workstations.

---

**Part A — Facts vs. Assumptions**

> Sort at least six statements into the correct column.

| Statement | Confirmed Fact | Assumption / Unknown |
|---|---|---|
| | | |
| | | |
| | | |
| | | |
| | | |
| | | |

---

**Part B — Eight Forensic Questions**







---

**Part C — Primary Artifact for Each Question**

| # | Question | Primary Artifact |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |
| 7 | | |
| 8 | | |

---

**Part D — Two Evidence Gaps**

Gap 1:
Description:
Question prevented:
Conclusion blocked:
Gap 2:
Description:
Question prevented:
Conclusion blocked:
---

**Part E — Scope Assessment**

> Write two sentences: based on what you know, is this a single-host problem or something broader?
[Your response here]
---

## Task 7 — Reflection

**1. Question quality**
*Look back at Task 2. Pick the weakest question, rewrite it to be more specific, and explain what you changed.*
Weakest question (original):
Rewritten:
What changed and why:
---

**2. The assumption trap**
*A colleague says "PowerShell definitely ran — the EDR said so." What's wrong with that, and how does your Task 1 work protect against it?*
[Your response here]
---

**3. Gaps and conclusions**
*A gap prevents you from answering a question leadership considers critical. What do you tell them?*
[Your response here]
---

**4. Reusability**
*How would the Task 5 worksheet change for a Windows server incident? What new questions would you add and what might become less relevant?*
[Your response here]
---

## Additional Notes
[Free text — questions, observations, connections to real work, things to follow up on]
---

*Lab 2.1 Notes — Windows Forensics for Beginners*  
*Keep this file in your `Labs/Lab02/Lab02_01/` folder alongside the `ReadMe.md`.*
