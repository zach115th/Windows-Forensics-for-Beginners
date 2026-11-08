# Lab 2.3 — Analyst Notes
**Documentation and Repeatability**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________
**Date Started:** ___________________________
**Date Completed:** ___________________________
**Lab Environment:** ___________________________
**Case Reference:** IR-2024-WKSTN221

---

## Task 1 — Documentation Audit

**Part A — Audit table**

> Review your lab02.2-notes.md and evaluate each item honestly.

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

---

**Part B — Gap impact assessment**

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

## Task 2 — Case Log

> Write at least 15 entries in chronological order.
> Format: `[DateTime UTC] | [Analyst] | [Action Type] | [Description]`
> Action types: TRIAGE / COLLECTION / ANALYSIS / DECISION / FINDING / ESCALATION / HANDOFF / NOTE / ERROR

```
[2024-11-14 14:23 UTC] | [] | TRIAGE     | SOC escalated EDR alert for WKSTN-221. OUTLOOK.EXE → POWERSHELL.EXE → CMD.EXE process chain observed. Repeated outbound connections to 91.214.47.22:443 since 14:19:42 UTC, consistent with C2 beaconing. Beginning initial triage.

[2024-11-14 14:25 UTC] | [] | DECISION   | Decided to monitor and collect before isolating. Rationale: continued C2 beaconing may reveal additional infrastructure if observed briefly; volatile evidence must be captured before isolation.

[2024-11-14            ] | [] |            |

[2024-11-14            ] | [] |            |

[2024-11-14            ] | [] |            |

[2024-11-14            ] | [] |            |

[2024-11-14            ] | [] |            |

[2024-11-14            ] | [] |            |

[2024-11-14            ] | [] |            |

[2024-11-14            ] | [] |            |

[2024-11-14            ] | [] |            |

[2024-11-14            ] | [] |            |

[2024-11-14            ] | [] |            |

[2024-11-14            ] | [] | ERROR      |

[2024-11-14            ] | [] |            |
```

---

## Task 3 — Command Record

> Document at least 6 tool executions. Include at least one that produced an error or unexpected output.

```
## PowerShell — Volatile Process Capture

Tool:               PowerShell
Version:
Platform:           WKSTN-221
Run by:
Date/Time (UTC):
Working directory:  E:\IR\WKSTN-221\volatile\

Command:
  Get-Process | Select-Object Name, Id, Path, StartTime, Company |
    Export-Csv ".\processes_20241114_141900.csv" -NoTypeInformation

Output:
  File:     processes_20241114_141900.csv
  Location: E:\IR\WKSTN-221\volatile\
  Size:
  Hash:

Errors / Notes:


---

## [Tool 2 — Add name and purpose]

Tool:
Version:
Platform:
Run by:
Date/Time (UTC):
Working directory:

Command:

Output:
  File:
  Location:
  Size:
  Hash:

Errors / Notes:


---

## [Tool 3 — Add name and purpose]

Tool:
Version:
Platform:
Run by:
Date/Time (UTC):
Working directory:

Command:

Output:
  File:
  Location:
  Size:
  Hash:

Errors / Notes:


---

## [Tool 4 — Add name and purpose]

Tool:
Version:
Platform:
Run by:
Date/Time (UTC):
Working directory:

Command:

Output:
  File:
  Location:
  Size:
  Hash:

Errors / Notes:


---

## [Tool 5 — Add name and purpose]

Tool:
Version:
Platform:
Run by:
Date/Time (UTC):
Working directory:

Command:

Output:
  File:
  Location:
  Size:
  Hash:

Errors / Notes:


---

## [Tool 6 — includes error or unexpected output]

Tool:
Version:
Platform:
Run by:
Date/Time (UTC):
Working directory:

Command:

Output:
  File:
  Location:
  Size:
  Hash:

Errors / Notes:
  [Document the error and what you did in response]
```

---

## Task 4 — Facts, Conclusions, and Assumptions Register

**Part B — Register**

> At least 12 entries. At least 4 facts, 4 conclusions, 4 assumptions.
> For conclusions: name the supporting fact(s).
> For assumptions: note what evidence would promote them to facts.

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

---

**Part C — Reflection**

> What happens if a conclusion recorded as a fact turns out to be wrong? Give a specific example from the WKSTN-221 scenario.

[Your response here]

---

## Task 5 — Forensic Timeline

**Part B — Complete timeline**

> At least 12 entries. Every entry must have a named artifact source and ATT&CK tactic.
> ATT&CK tactics for this scenario: Initial Access / Execution / Defense Evasion / Credential Access / Lateral Movement / Collection / Command and Control / Exfiltration

```
# WKSTN-221 — Forensic Timeline
Case Reference: IR-2024-WKSTN221
Analyst:
Last Updated:   [UTC]

Legend:
  HIGH   — Two or more independent artifact sources agree
  MEDIUM — Single reliable artifact source
  LOW    — Indirect, ambiguous, or single low-confidence source
```

| DateTime (UTC) | Artifact Source | Event | ATT&CK Tactic | Confidence | Notes |
|---|---|---|---|---|---|
| 2024-11-14 08:43:17 | Security.evtx EID 4624 | payroll-admin interactive logon (type 2) | None (baseline) | MEDIUM | Normal start-of-day logon |
| 2024-11-14 14:18:55 | LNK file | Q4_Payroll_Review.xlsm accessed | Execution | MEDIUM | Likely delivery document |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |

---

**Part C — Timeline narrative**

> Three sentences derived only from HIGH and MEDIUM confidence entries.

[Your timeline narrative here]

---

## Task 6 — Analyst Handoff Package

**Part A — Handoff note**

```
# Analyst Handoff — WKSTN-221
Case Reference:   IR-2024-WKSTN221
Outgoing Analyst:
Incoming Analyst:
Handoff Time:     [UTC]
Case Status:      [Active / Contained / Remediation / Closed]
```

### Case Summary (2–3 sentences)

[Your summary here]

---

### What Has Been Completed This Shift

| Action | Time (UTC) | Output / Location | Notes |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |

---

### Current State of Evidence

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

### Confirmed Findings (Facts Only)

1.
2.
3.

---

### Active Hypotheses

| Hypothesis | Status | Next Step to Confirm or Eliminate |
|---|---|---|
| | Unconfirmed | |
| | Unconfirmed | |
| | Unconfirmed | |

---

### Open Questions

1.
2.
3.

---

### Evidence Gaps

1.
2.

---

### Recommended Next Actions (Priority Order)

1.
2.
3.
4.
5.

---

### Notes for Incoming Analyst

[Your notes here]

---

### Contacts and Escalation

| Role | Name | Contact |
|---|---|---|
| SOC Lead | | |
| IR Manager | | |
| Legal / Compliance | | |
| System Owner (WKSTN-221) | | |
| System Owner (FILESVR-03) | | |

---

**Part B — Handoff quality check**

- [ ] Incoming analyst can find every collected artifact without asking
- [ ] All confirmed findings are supported by a named artifact
- [ ] Open questions are specific enough to act on
- [ ] Next actions are concrete enough to execute immediately
- [ ] No conclusions or assumptions are labeled as facts
- [ ] Tool versions and output locations are documented
- [ ] Case reference is consistent throughout

**Items fixed after quality check:**

```
1.
2.
3.
```

---

## Task 7 — Personal Documentation Standard

```
# My Documentation Standard
Version: 1.0
Created:

## Case Log
[When I write entries, what format I use, what action types I track]


## Command Record
[What I document for every tool execution]


## Facts vs. Conclusions
[How I label the difference in my notes]


## Timeline
[What goes in, source citation format, confidence rating criteria]


## Handoff
[Minimum content required before handing a case to another analyst]


## Non-Negotiables
[Two or three documentation requirements I will never skip regardless of time pressure]

1.
2.
3.
```

---

## Task 8 — Reflection

**1. Documentation under pressure**
*30 minutes before handoff, case still active. What do you document first? What do you defer? What are the consequences?*

[Your response here]

---

**2. The retroactive documentation trap**
*What are the risks of writing notes from memory after the fact? What details are most likely to be lost or distorted?*

[Your response here]

---

**3. Facts vs. conclusions in practice**
*Break down "the attacker used Mimikatz to harvest credentials" into its component facts and the conclusion that connects them.*

[Your response here]

---

**4. Documentation as communication**
*Your notes will be read by legal counsel, a CISO, a regulator, a future analyst on a cold case. How does knowing that audience change how you write?*

[Your response here]

---

## Additional Notes

> Free text — questions, observations, connections to real work, things to follow up on.

[Your notes here]

---

*Lab 2.3 Notes — Windows Forensics for Beginners*
*Keep this file in your `Labs/Lab02/Lab02_03/` folder alongside the `ReadMe.md`.*
