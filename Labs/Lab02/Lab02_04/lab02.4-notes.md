# Lab 2.4 — Analyst Notes
**From Alert to Investigation Plan**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________
**Date Started:** ___________________________
**Date Completed:** ___________________________
**Lab Environment:** ___________________________
**Case Reference:** IR-2024-WKSTN309

---

## Task 1 — Alert Dissection

**Part A — Alert dissection table**

> Evaluate each claim from the alert. Use confidence levels: Confirmed / Probable / Possible / Unknown.

| Claim from Alert | Source | Confidence Level | Why |
|---|---|---|---|
| WINWORD.EXE spawned POWERSHELL.EXE at 08:51 UTC | EDR process telemetry | | |
| The activity is suspicious | EDR detection engine | | |
| The PowerShell command line was not captured | EDR configuration gap | | |
| Outbound connection to 185.193.126.47:8443 at 08:54 UTC | EDR network telemetry | | |
| The connection lasted approximately 90 seconds | EDR network telemetry | | |
| No lateral movement occurred | EDR — absence of alert | | |
| No data loss occurred | EDR — absence of alert | | |
| j.mercer initiated the activity | EDR session context | | |
| No prior alerts on this host in 90 days | EDR historical data | | |
| The activity was malicious | *(implied by escalation)* | | |

---

**Part B — What the alert does not tell you**

> List at least eight things you do not know that are relevant to the investigation.

```
1.
2.
3.
4.
5.
6.
7.
8.
```

---

**Part C — One-sentence confirmed summary**

> Summarize only what is confirmed — no inferences, no conclusions.

[Your sentence here]

---

## Task 2 — Facts, Assumptions, and Hypotheses

**Part A — Register**

> At least 12 entries. At least 3 facts, 3 assumptions, 3 hypotheses.
> Assumptions: note what artifact would confirm or refute them.
> Hypotheses: note what evidence would confirm or eliminate them.

| # | Type | Statement | Basis | Verification Needed |
|---|---|---|---|---|
| 1 | Fact | EDR telemetry records WINWORD.EXE spawning POWERSHELL.EXE at 08:51 UTC on WKSTN-309 | EDR process telemetry — named source | None — already confirmed by named source |
| 2 | Assumption | j.mercer was physically at the workstation at 08:51 UTC | EDR session context — inferred | Security.evtx logon events; physical access log if available |
| 3 | Hypothesis | A malicious macro in a Word document triggered the PowerShell execution | Process chain consistent with macro execution | Prefetch, LNK files — recently opened .docm/.xlsm; Security.evtx EID 4688 |
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

**Part B — Risk assessment**

```
Most dangerous assumption:

Why it matters:
```

---

## Task 3 — Initial Investigative Questions

> At least 10 specific, prioritized questions. Top 3 should address the most urgent unknowns.

```
Priority  Category          Question
--------  --------          --------
1.        Active threat
2.        Active threat
3.        Initial access
4.        Initial access
5.        Execution
6.        Execution
7.        Persistence
8.        Impact
9.        Impact
10.       Scope
```

**Urgency justification**

> Why are your top three questions the most urgent? What changes if any of them has a bad answer?

[Your response here]

---

## Task 4 — Containment Decision

**Part A — Decision matrix**

| Option | What You Preserve | What You Lose | Conditions That Make This Right |
|---|---|---|---|
| Isolate immediately | | | |
| Monitor and collect before isolating | | | |
| Do not isolate — observe only | | | |

---

**Part B — Recommendation**

```
Recommendation:     [Isolate immediately / Monitor and collect / Observe only]
Primary reason:
Secondary reason:
Risk accepted:
Trigger condition:
Authorized by:
Date/Time (UTC):
```

---

**Part C — Pre-isolation checklist**

> If monitoring and collecting before isolating, list specific actions to complete first.

| # | Action | Tool | Time Estimate |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |

---

## Task 5 — Evidence Collection Plan

**Part A — Collection priority list**

| Priority | Artifact | Volatile? | Justification |
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

**Part B — Collection method table**

| Artifact | Collection Tool | Command or Method | Output Location | Notes |
|---|---|---|---|---|
| | | | `E:\IR\WKSTN-309\volatile\` | |
| | | | `E:\IR\WKSTN-309\volatile\` | |
| | | | `E:\IR\WKSTN-309\volatile\` | |
| | | | `E:\IR\WKSTN-309\artifacts\` | |
| | | | `E:\IR\WKSTN-309\artifacts\` | |
| | | | `E:\IR\WKSTN-309\artifacts\` | |
| | | | `E:\IR\WKSTN-309\artifacts\` | |
| | | | `E:\IR\WKSTN-309\artifacts\` | |

---

**Part C — Gap acknowledgment**

```
Alternative 1:
  Artifact:
  What it may show:
  Condition:

Alternative 2:
  Artifact:
  What it may show:
  Condition:
```

---

## Task 6 — Investigation Plan

```
# Investigation Plan — WKSTN-309
Case Reference:     IR-2024-WKSTN309
Prepared By:
Date/Time (UTC):
Alert Source:       EDR — Suspicious PowerShell Execution
Alert Time (UTC):   2024-11-XX 08:51 UTC
Case Priority:      [Critical / High / Medium / Low]

---

## Alert Summary (facts only — no inferences)


---

## What Is Known

1.
2.
3.

## What Is Assumed (label as assumption)

1.
2.
3.

## Working Hypotheses

Hypothesis 1:
  Statement:
  Confirms if:
  Eliminates if:

Hypothesis 2:
  Statement:
  Confirms if:
  Eliminates if:

Hypothesis 3:
  Statement:
  Confirms if:
  Eliminates if:

---

## Systems and Accounts in Scope

| System / Account | Role | Why in Scope |
|---|---|---|
| WKSTN-309 | Finance workstation — j.mercer | Primary alert host |
| j.mercer (account) | Senior financial analyst | Assigned user at time of alert |
| FINSVR-01 | Finance shared drive | Accessible by j.mercer |
| | | |
| | | |

---

## Containment Decision

Decision:
Reasoning:
Risk accepted:
Trigger to reassess:
Authorized by:

---

## Initial Investigative Questions (priority order)

1.
2.
3.
4.
5.

---

## Evidence Collection Plan (priority order)

| Priority | Artifact | Volatile? | Tool | Output Location |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |

---

## Known Evidence Gaps

1. PowerShell command line not captured by EDR — mitigation: [your answer from Task 5C]
2.
3.

---

## Immediate Next Actions

1.
2.
3.
4.
5.

---

## Escalation and Notification

| Who | Why | When | Method |
|---|---|---|---|
| IR Manager | Active incident | Immediately | |
| Legal / Compliance | Financial data potentially at risk | Within 1 hour | |
| System Owner | WKSTN-309 may need isolation | Before containment action | |
| | | | |

---

## Notes


```

---

## Task 7 — Cold Alert Exercise

**Alert recap:** SIEM rule fired at 23:44 UTC. Account svc-print. Five failed logon attempts (type 3) against WKSTN-088 between 23:39–23:43 UTC, followed by successful type 3 logon at 23:44 UTC from 10.4.22.31 — not a print server. No EDR alerts. No follow-on activity.

---

**Part 1 — Alert dissection (at least 6 claims)**

| Claim | Source | Confidence Level | Why |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |

---

**Part 2 — Facts, assumptions, hypotheses**

```
Facts:
  1.
  2.
  3.
  4.
  5.

Assumptions:
  1.
  2.
  3.

Hypotheses:
  1.
    Confirms if:
    Eliminates if:
  2.
    Confirms if:
    Eliminates if:
```

---

**Part 3 — Eight investigative questions**

```
1.
2.
3.
4.
5.
6.
7.
8.
```

---

**Part 4 — Containment decision**

```
Recommendation:
Primary reason:
Risk accepted:
```

---

**Part 5 — Collection priority list**

| Priority | Artifact | Justification |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |

---

**Part 6 — One-paragraph investigation plan summary**

[Your paragraph here]

---

## Task 8 — Reflection

**1. The 20-minute constraint**
*What gets cut when forced to work that fast? What is the minimum viable output that still produces a defensible starting point?*

[Your response here]

---

**2. Alert confidence vs. artifact confidence**
*Where did you have to resist treating an EDR finding as a confirmed fact? What is the practical risk of conflating the two?*

[Your response here]

---

**3. The missing command line**
*Beyond the Task 5C alternatives, what could your organization do to prevent this gap in the future?*

[Your response here]

---

**4. Plan vs. reality**
*Thirty minutes into execution you learn j.mercer's access should have been revoked last week. How does that change your plan?*

[Your response here]

---

## Additional Notes

> Free text — questions, observations, connections to real work, things to follow up on.

[Your notes here]

---

*Lab 2.4 Notes — Windows Forensics for Beginners*
*Keep this file in your `Labs/Lab02/Lab02_04/` folder alongside the `ReadMe.md`.*
