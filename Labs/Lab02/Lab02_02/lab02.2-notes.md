# Lab 2.2 — Analyst Notes
**High-Level Process in an Incident**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________
**Date Started:** ___________________________
**Date Completed:** ___________________________
**Lab Environment:** ___________________________
**Case Reference:** IR-2024-WKSTN221

---

## Task 1 — Initial Triage

**Part A — Triage checklist**

| Triage Item | Status / Finding | How You Would Verify |
|---|---|---|
| Is a suspicious process currently running? | | |
| Is there an active outbound C2 connection? | | |
| Is the assigned user currently logged on? | | |
| Has the EDR agent been tampered with or disabled? | | |
| Are there other active sessions on this host? | | |
| Is this host joined to a domain? | | |
| What privileged access does the assigned user have? | | |
| Have any other hosts been flagged by EDR? | | |
| Has any data left the network in the past hour? | | |
| Is there an active IR retainer or escalation path? | | |

---

**Part B — Containment decision**

```
Recommendation:   [Isolate / Monitor and collect / Do not isolate]
Reason 1:
Reason 2:
Reason 3:
Risk if wrong:
```

---

**Part C — Triage note**

```
Date/Time (UTC):
Case Reference:   IR-2024-WKSTN221
Analyst:
Active threat indicators:
Containment status:
Immediate actions taken:
Next step:
```

---

## Task 2 — Scoping and Prioritization

**Part A — Scope map**

```
Primary Host:         WKSTN-221
Assigned User:
User's Access:        HR systems, FILESVR-03
Domain:
Active C2 IP:         91.214.47.22

Related Systems to Check:
  FILESVR-03:
  Domain Controller:
  HR systems:
  Email gateway:

Related Accounts to Check:
  Assigned user account:
  Service accounts with same access:
  Admin accounts that logged into WKSTN-221:

External Indicators:
  91.214.47.22:
```

---

**Part B — Evidence priority list**

| Priority | Artifact | Volatile? | Reasoning |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |
| 6 | | | |
| 7 | | | |
| 8 | | | |

---

## Task 3 — Targeted Evidence Collection

**Part A — Volatile evidence capture commands**

> Write the exact PowerShell commands you would run. Specify output file paths.

```powershell
# 1. Running processes
Get-Process | Select-Object Name, Id, Path, StartTime, Company |
  Export-Csv "E:\IR\WKSTN-221\volatile\processes_$(Get-Date -Format yyyyMMdd_HHmmss).csv" -NoTypeInformation

# 2. Active network connections


# 3. Logged-on users


# 4. Recently modified files (last 24 hours)


# 5. Scheduled tasks


# 6. Services

```

---

**Part B — Memory acquisition**

```
Tool:
Tool version:
Command:
Output file:
Output location:    E:\IR\WKSTN-221\memory\
Hash command:
Hash algorithm:     SHA-256
Hash value:
Date/time (UTC):
Notes:
```

---

**Part C — Artifact collection table**

| Artifact | Source Path | Collection Tool | Command or Method | Output Path | Notes |
|---|---|---|---|---|---|
| Security.evtx | `%SystemRoot%\System32\winevt\Logs\Security.evtx` | | | `E:\IR\WKSTN-221\artifacts\logs\` | |
| System.evtx | | | | | |
| PowerShell operational log | | | | | |
| Prefetch | `%SystemRoot%\Prefetch\` | | | | |
| MFT | Volume root | MFTECmd | | | |
| SYSTEM hive | | | | | |
| SOFTWARE hive | | | | | |
| NTUSER.DAT | | | | | |
| SRUM database | | | | | |
| LNK files | | | | | |
| Amcache | | | | | |

---

**Part D — Collection hash record**

```
Archive name:
Archive location:
Hash algorithm:         SHA-256
Hash value:
Date/time hashed (UTC):
Hashed by:
Tool used:
Tool version:
Notes:
```

---

## Task 4 — Hypothesis Testing

**Part A — Hypothesis set**

```
Hypothesis 1:
  Statement:        The attacker used a malicious macro in an Outlook attachment to execute PowerShell
  Confirms if:      Prefetch shows POWERSHELL.EXE ran seconds after an Office document opened;
                    Security.evtx EID 4688 shows OUTLOOK.EXE → POWERSHELL.EXE process chain
  Eliminates if:    PowerShell spawned by a non-Office process;
                    No Office document in recent LNK/jump list entries at relevant time
  Current status:   Unconfirmed

Hypothesis 2:
  Statement:
  Confirms if:
  Eliminates if:
  Current status:   Unconfirmed

Hypothesis 3:
  Statement:
  Confirms if:
  Eliminates if:
  Current status:   Unconfirmed

Hypothesis 4:
  Statement:
  Confirms if:
  Eliminates if:
  Current status:   Unconfirmed

Hypothesis 5:
  Statement:
  Confirms if:
  Eliminates if:
  Current status:   Unconfirmed
```

---

**Part B — Hypothesis priority ranking**

| Priority | Hypothesis # | Why It's Urgent | What Changes if Confirmed |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |

---

## Task 5 — Timeline Construction

**Part A — Ordered timeline**

> Place the ten events from the README in chronological order. Add source artifact and significance for each.

| # | Time (UTC) | Event | Source Artifact | Significance |
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

**Analysis questions:**

1. Most likely initial access vector:
   [Your response here]

2. Time elapsed between execution and first outbound transfer:
   [Your response here]

3. What event J tells us about scope beyond WKSTN-221:
   [Your response here]

4. Which Task 4 hypothesis this timeline supports most strongly:
   [Your response here]

5. Missing artifact needed before drawing final conclusions:
   [Your response here]

---

**Part B — WKSTN-221 working timeline**

> This is your live case timeline. Add entries as you collect and analyze evidence.

| DateTime (UTC) | Artifact Source | Event Description | Significance | Confidence | Notes |
|---|---|---|---|---|---|
| | | | | High / Med / Low | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |

---

## Task 6 — Reporting and Remediation Support

**Part A — Technical findings summary**

```
## Technical Findings — WKSTN-221
Case Reference: IR-2024-WKSTN221
Prepared By:
Date (UTC):

### Confirmed Findings

Finding 1:
  Observation:
  Source:
  Timestamp:

Finding 2:
  Observation:
  Source:
  Timestamp:

Finding 3:
  Observation:
  Source:
  Timestamp:

### Unconfirmed / Pending

Item 1:
  Description:
  Evidence needed:

### Evidence Gaps

Gap 1:
  Description:
  Impact on conclusions:
```

---

**Part B — Remediation recommendations**

| # | Recommendation | Based On | Priority | Owner |
|---|---|---|---|---|
| 1 | | | Critical / High / Medium | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |

---

**Part C — Executive summary**

> Three paragraphs. No jargon. Audience is a CISO or senior business leader.
> Paragraph 1: What happened and when.
> Paragraph 2: What was affected and what the risk is.
> Paragraph 3: What is being done and what decisions leadership needs to make.

```
[Paragraph 1]


[Paragraph 2]


[Paragraph 3]
```

---

## Task 7 — Reflection

**1. Triage decisions under uncertainty**
*What is the cost of isolating too early? Too late? How do you make the call when you genuinely don't know which is worse?*

[Your response here]

---

**2. Hypothesis discipline**
*Why is the elimination condition as important as the confirmation condition? What goes wrong if analysts only look for confirming evidence?*

[Your response here]

---

**3. Timeline gaps**
*The timeline in Task 5 has a gap of roughly seven minutes between events H (14:23:44) and B (14:31:05). Only event E falls inside it, and a SRUM rollup timestamp is not an event time. How would you investigate that gap? What artifacts might fill it, and what does the gap itself tell you?*

[Your response here]

---

**4. The translation problem**
*What gets lost when translating technical findings into an executive summary? How do you preserve precision while keeping it accessible?*

[Your response here]

---

## Additional Notes

> Free text — questions, observations, connections to real work, things to follow up on.

[Your notes here]

---

*Lab 2.2 Notes — Windows Forensics for Beginners*
*Keep this file in your `Labs/Lab02/Lab02_02/` folder alongside the `ReadMe.md`.*
