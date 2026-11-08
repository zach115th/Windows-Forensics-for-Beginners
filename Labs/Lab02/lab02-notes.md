# Lab 02 — Analyst Notes
**The Forensic Investigation Process for IR**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Lab Environment:** ___________________________  
**Case Reference:** IR-2024-WKSTN047  

---

## Task 1 — Forensic Questions

> Write at least 10 specific, answerable forensic questions for the WKSTN-047 scenario.
> Format: Priority number, then the question. Be specific — "was there attacker activity?" is not a forensic question.








**Question grouping:**

| Category | Question Numbers |
|---|---|
| Attacker presence (still active?) | |
| Initial access and execution | |
| Persistence | |
| Lateral movement | |
| Data access or exfiltration | |
| Scope (other hosts or accounts affected?) | |

---

## Task 2 — Question to Artifact Mapping

> Map each question to its primary and corroborating artifact sources.
> Be specific — "event logs" is not specific enough. "Security.evtx Event ID 4688" is.

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

---

## Task 3 — Volatile vs. Persistent Evidence

**Part A — Evidence sort**

> Sort artifacts into the correct column. Add at least three of your own in each column.

| Volatile (lost on reboot/shutdown) | Persistent (survives reboot) |
|---|---|
| Running processes | MFT |
| Active network connections | Registry hives |
| Logged-on users | Prefetch |
| Clipboard contents | Event logs |
| RAM contents | Amcache |
| | |
| | |
| | |

**Part B — Prioritized collection order**

> List your first ten collection actions for WKSTN-047. Explain the reasoning for your top three choices.

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

## Task 4 — Collection Workflow

> Write a step-by-step collection procedure specific enough that another responder could execute it.

### Stage 1 — Pre-Collection Checks


Authorization confirmed:    [Yes / No]
Scope defined:              [Yes / No]
EDR status checked:         [Yes / No]
Active users on system:
Network status:
Containment status:
Notes:
---

### Stage 2 — Volatile Evidence Capture

> List specific tools and commands. Paste or reference actual command lines.
Action 1:
Tool:
Command:
Output location:
Action 2:
Tool:
Command:
Output location:
Action 3:
Tool:
Command:
Output location:
---

### Stage 3 — Memory Acquisition
Tool used:
Tool version:
Command / method:
Output file:
Output location:
Hash algorithm:     SHA-256
Hash value:
Date/time (UTC):
Notes:
---

### Stage 4 — Targeted Artifact Collection

| Artifact | Collection Tool | Command or Method | Output Location | Notes |
|---|---|---|---|---|
| Running processes | PowerShell | `Get-Process` | | |
| Network connections | PowerShell | `Get-NetTCPConnection` | | |
| Logged-on users | PowerShell | `Get-LocalUser` / `query user` | | |
| Security.evtx | | | | |
| System.evtx | | | | |
| PowerShell operational log | | | | |
| Prefetch | | | | |
| MFT | MFTECmd | | | |
| USN Journal | MFTECmd | | | |
| SYSTEM hive | | | | |
| SOFTWARE hive | | | | |
| NTUSER.DAT | | | | |
| SRUM database | | | | |
| LNK files | | | | |
| Jump lists | | | | |
| Amcache | | | | |

---

### Stage 5 — Packaging and Hashing
Archive name:
Archive location:
Hash algorithm:         SHA-256
Hash value:
Date/time hashed (UTC):
Hashed by:
Tool used:
Tool version:
Notes:
**Command used:**
[Paste exact command here]
**Raw output:**
[Paste hash output here]
---

### Stage 6 — Post-Collection Documentation
Collection completed (UTC):
Collector:
Tool versions used:
Errors or anomalies:
Unexpected findings:
Total collection size:
Evidence stored at:
Chain of custody updated:     [Yes / No]
Notes:
---

## Task 5 — Facts vs. Conclusions

**Part A — Label each statement**

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

**Part B — Written finding using observed facts only**

> Write a three-sentence finding about `cmd.exe` spawning from `svchost.exe`, running `net user /domain`, then connecting outbound to an unknown IP. Write it so a lawyer could cite it without needing to understand Windows internals.
[Your response here]
---

## Task 6 — Case Folder Structure

> Record the path where you created the WKSTN-047 case folder.
Case Root Path:
Created By:
Date Created (UTC):
Notes:
**Folder structure confirmed:**
[ ] IR-Cases\WKSTN-047
[ ] 00_Admin
[ ] 00_Admin\case-open-note.md
[ ] 00_Admin\authorization.md
[ ] 00_Admin\chain-of-custody.md
[ ] 01_Collection\volatile
[ ] 01_Collection\memory
[ ] 01_Collection\artifacts
[ ] 01_Collection\hashes
[ ] 02_Analysis\mft
[ ] 02_Analysis\registry
[ ] 02_Analysis\event-logs
[ ] 02_Analysis\prefetch
[ ] 02_Analysis\shell-items
[ ] 02_Analysis\timeline
[ ] 03_Findings\facts.md
[ ] 03_Findings\conclusions.md
[ ] 03_Findings\iocs.md
[ ] 04_Reports\technical-report.md
[ ] 04_Reports\executive-summary.md
---

## Task 7 — Case Opening Note and Analyst Handoff

**Part A — Case Opening Note**

> Save a copy of this in `00_Admin\case-open-note.md` as well.
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
---

**Part B — Analyst Handoff Note**

> Save a copy of this in `00_Admin\` alongside the opening note.
Case Reference:       IR-2024-WKSTN047
Handoff From:
Handoff To:
Date/Time (UTC):
Work Completed This Shift:


Current State of Evidence:
What Is Known So Far:
What Remains Unknown:
Recommended Next Actions (in priority order):
1.
2.
3.
Open Questions Needing Follow-Up:
Notes for Incoming Analyst:
---

## Task 8 — Reflection

**1. Triage under pressure**
*How does end-of-business deadline pressure change your evidence prioritization? What do you deprioritize and what risk does that create?*
[Your response here]
---

**2. The cost of skipping question definition**
*What happens if a responder skips Task 1 and goes straight to collecting artifacts? Give a specific example of how that leads to a flawed conclusion or missed finding.*
[Your response here]
---

**3. Documentation as protection**
*How does documentation discipline protect you as an analyst — not just the investigation?*
[Your response here]
---

**4. When the plan changes**
*Midway through collection you discover an active RDP session from an unrecognized internal IP. How does that change your plan? Walk through the decisions you would make.*
[Your response here]
---

## Additional Notes

> Use this space for anything that came up during the lab — questions, observations, connections to real incidents, things to follow up on, or ideas for improving your process.
[Free text]
---

*Lab 02 Notes — Windows Forensics for Beginners*  
*Keep this file in your `Labs/Lab02/` folder alongside the `ReadMe.md`.*
