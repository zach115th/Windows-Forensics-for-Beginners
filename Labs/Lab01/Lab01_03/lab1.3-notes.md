# Lab 1.3 — Analyst Notes
**Authorization, Legal Considerations, and Chain of Custody**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Lab Environment:** ___________________________  
**Case Reference:** ___________________________  

---

## Task 1 — Authorization Statement

> Document authorization before taking any collection action. In the lab, use yourself or a named hypothetical approver. The habit matters more than the formality here.
Authorized By:
Authorization Type:   [Internal IR Policy / Management Direction / HR / Legal / Retainer]
Date/Time Confirmed:
Conditions or Limits:
Notes:
---

## Task 2 — Collection Scope

> Define what you are collecting and explicitly what you are not. Vague scope creates problems later.
System Name / Identifier:
Asset Owner:
Reason for Collection:
Authorized Collector:
In Scope:


Out of Scope:


Special Handling Considerations:
---

## Task 3 — Evidence Item Record

> Fill in every field. If a field does not apply, write N/A and explain briefly. Do not leave fields blank.
Evidence ID:
Description:
Evidence Type:           [Disk image / Memory dump / Archive / Registry hive / Log export]
Source System:
Source Path:
Acquiring Tool:
Acquiring Tool Version:
Collector Name:
Date/Time Acquired:      [UTC]
Storage Location:
Notes:
---

## Task 4 — Hash Record

> Record the SHA-256 hash computed at acquisition. This is your baseline — any future verification that produces a different value means something changed.
Evidence ID:
File Name:
File Size:
Hash Algorithm:     SHA-256
Hash Value:
Date/Time Hashed:   [UTC]
Hashed By:
Tool Used:
Tool Version:
**Command used:**
[Paste the exact command you ran here]
**Raw output:**
[Paste the tool output here]
---

## Task 5 — Chain of Custody Log

> Record every interaction with the evidence from acquisition through analysis. If you touched it, log it.

| # | Date/Time (UTC) | Evidence ID | Action | Handler | From Location | To Location | Hash Verified? | Notes |
|---|---|---|---|---|---|---|---|---|
| 1 | | | Acquired | | | | | Initial collection |
| 2 | | | Copied (working copy) | | | | | |
| 3 | | | Analyzed | | | | | |
| 4 | | | | | | | | |
| 5 | | | | | | | | |

> Add rows as needed. Every access, transfer, copy, and analysis session should have its own entry.

---

## Task 6 — Storage and Access Controls
Original Evidence Location:
Working Copy Location:
Backup Location:
Access Restrictions:
Original Preserved Separately: [Yes / No]
Working Copy Created:          [Yes / No]
Retention Notes:
Notes:
---

## Task 7 — Reflection

**1. Real incident differences**  
*What would be different about this process in a real incident? Think about approvals, timing, communication, and pressure.*
[Your response here]
---

**2. Stakeholder notification**  
*In a real incident, who would need to be notified or approve before collection began?*
[Your response here]
---

**3. Chain-of-custody failures**  
*What risks arise if the chain of custody is incomplete or missing entries? Give at least two concrete scenarios.*
[Your response here]
---

**4. Hashing in internal investigations**  
*Why does hashing matter even when there is no plan to involve law enforcement? Give at least two reasons.*
[Your response here]
---

**5. Scope decisions under pressure**  
*You're mid-incident. Your scope covers event logs and prefetch, but you find a suspicious directory outside your scope. What do you do?*
[Your response here]
---

## Optional Challenge Notes

> Use this section to document your work on any optional challenges.

**A — Dual hash record**
MD5:
SHA-256:
Notes:
**B — Working copy workflow**
Original hash:
Working copy hash:
Match confirmed:   [Yes / No]
Notes:
**C — Team-ready template**
[Note the filename and location of your completed CoC form, or paste it here]
**D — Scope challenge**
[Your domain controller scope statement here]
---

## Additional Notes

> Use this space for anything that came up during the lab — questions, edge cases, things to follow up on, or connections to real incidents you've worked.
[Free text]
---

*Lab 1.3 Notes — Windows Forensics for Beginners*  
*Keep this file in your `Labs/Lab01/Lab01_03/` folder alongside the `ReadMe.md`.*
