# Lab 3.4 — Analyst Notes
**Designing a Defensible Triage Strategy**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Lab Environment:** ___________________________  
**Case Reference:** IR-2024-TRIAGE034  

---

## Task 1 — Triage Objectives

> Write at least 10 specific triage objectives. These are first-phase questions that help
> you decide where the incident is, how serious it is, and what to collect next.

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
```





**Grouped by category:**

| Category | Question Numbers |
|---|---|
| Active attacker presence | |
| Initial access and execution | |
| Authentication and privilege misuse | |
| Data access or exfiltration risk | |
| Lateral movement or spread | |
| Scope expansion decisions | |

---

## Task 2 — Host Priority Ranking

**Part A — Host assessment table**

| Host | Business Criticality | Likelihood of Relevant Evidence | Volatile Evidence Risk | Potential Scope Value | Recommended Priority | Notes |
|---|---|---|---|---|---|---|
| DC-02 | | | | | | |
| HR-WS17 | | | | | | |
| ENG-FS01 | | | | | | |
| VPN-GW01 | | | | | | |
| PRINT-03 | | | | | | |

---

**Part B — Ranked priority list**

| Priority | Host | Reason It Belongs Here |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |

---

**Part C — Short answers**

**1. Which host is most likely to help you understand scope fastest?**


[Your response here]
---

**2. Which host is most likely to contain volatile evidence worth immediate action?**
[Your response here]
---

**3. Which host are you most comfortable deferring, and why?**
[Your response here]
---

**4. What finding on PRINT-03 would immediately move it to the top of your priority list?**
[Your response here]
---

## Task 3 — Collection Tiers

**Part A — Tier definitions**

| Tier | Purpose | Typical Use Case | Artifacts Included |
|---|---|---|---|
| **Tier 1** | Fast scoping — minimum viable volatile and targeted collection | | |
| **Tier 2** | Targeted triage — broader artifact set for hosts with stronger compromise indicators | | |
| **Tier 3** | Deep preservation — full imaging or extended collection for highest-value hosts | | |

---

**Part B — Host tier assignments**

| Host | Assigned Tier | Why This Tier Is Appropriate Right Now |
|---|---|---|
| DC-02 | | |
| HR-WS17 | | |
| ENG-FS01 | | |
| VPN-GW01 | | |
| PRINT-03 | | |

---

## Task 4 — Constraints and Collection Strategy

**Part A — Constraint analysis table**

| Constraint | Why It Matters to This Incident | How It Changes the Plan |
|---|---|---|
| Three responders available | | |
| Limited evidence storage | | |
| Same-day scope update required | | |
| Minimize operational disruption | | |
| Legal preservation interest flagged | | |

---

**Part B — Written analysis**

**1. Which constraints push you toward faster targeted triage over deeper collection?**
[Your response here]
---

**2. Which constraints push you toward deeper preservation even at the cost of speed?**
[Your response here]
---

**3. Why is it important to document constraints explicitly rather than just the technical decisions they produced?**
[Your response here]
---

## Task 5 — Triage Decision Matrix

> Every cell must be filled. If something is unknown or deferred, say so explicitly.

| Host | Assigned Responder | Collection Tier | First Collection Action | Primary Question Being Answered | Escalation Trigger for Deeper Collection |
|---|---|---|---|---|---|
| DC-02 | | | | | |
| HR-WS17 | | | | | |
| ENG-FS01 | | | | | |
| VPN-GW01 | | | | | |
| PRINT-03 | | | | | |

---

## Task 6 — Residual Risk and Limitations

**Part A — Limitations table**

| Limitation or Residual Risk | Why It Exists | How You Would Communicate It in Notes or a Briefing |
|---|---|---|
| Not all hosts can receive deep collection immediately | | |
| Volatile evidence may be lost before collection reaches some hosts | | |
| Same-day scope update will rely on partial data | | |
| Deferred systems may later prove more relevant than current indicators suggest | | |
| Legal preservation needs may expand beyond current scope | | |
| Triage artifacts may not capture evidence predating the collection window | | |

---

**Part B — Written response**

*Why does explicitly acknowledging limitations strengthen rather than weaken your triage strategy's defensibility?*
[Your response here — 4 to 6 sentences]
---

## Task 7 — Updated Plan Based on New Facts

**New facts received:**
- HR-WS17 — Suspicious PowerShell child process from OUTLOOK.EXE confirmed; LNK shows recently accessed .xlsm file
- DC-02 — Privileged account confirmed active across two additional servers not previously in scope
- ENG-FS01 — 4.3 GB downloaded from confidential engineering folder overnight
- VPN-GW01 — Successful VPN logon from unfamiliar location using HR-WS17 user credentials, 18 minutes before attachment activity
- PRINT-03 — No additional activity; quarantined file appears to be commodity adware

---

**Part A — Re-ranked priority list**

| New Priority | Host | Why It Moved (or Stayed) |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |

---

**Part B — Plan change documentation**

| Host | Priority Changed? | Collection Strategy Changed? | Specific Change | Why |
|---|---|---|---|---|
| DC-02 | | | | |
| HR-WS17 | | | | |
| ENG-FS01 | | | | |
| VPN-GW01 | | | | |
| PRINT-03 | | | | |

---

**Part C — New scope assessment**

*Based on the updated facts, is this still a workstation-level incident or has scope expanded? What evidence most strongly drives that assessment?*
[Your response here — 3 to 4 sentences]
---

## Task 8 — Triage Strategy Note

> Concise but complete. Another responder, manager, or legal reviewer should be able to
> understand the first-phase strategy without asking you to reconstruct it from memory.

```
# Triage Strategy Note
Case Reference:
Author:
Date/Time (UTC):
Incident Status:      [Active / Developing / Partially contained]

## Known Hosts and Initial Assessment

- DC-02:
- HR-WS17:
- ENG-FS01:
- VPN-GW01:
- PRINT-03:

## Primary Triage Objectives (first phase)

1.
2.
3.
4.
5.
```


**Host Priorities**

| Priority | Host | Collection Tier | Rationale |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |

```
## Operational Constraints Acknowledged

-
-
-

## Residual Risks and Limitations

-
-
-

## Escalation Conditions

[What findings would cause an immediate plan revision?]
-
-
-

## Next Review Point

[When and under what conditions will you revisit this plan?]

## Notes

```

---

## Task 9 — Reflection

**1. Why documentation makes triage defensible**
*Why is a technically sound decision still weak without documentation? What specifically gets lost?*
[Your response here]
---

**2. Scope versus certainty**
*Why do responders need to act on incomplete information during triage, and how can those decisions still be defensible when later facts change the picture?*
[Your response here]
---

**3. The risk of false confidence**
*How can a same-day scope update be useful to leadership without creating false certainty about what is and isn't compromised?*
[Your response here]
---

**4. Changing plans without losing discipline**
*Why is revising a triage strategy based on new evidence a sign of good IR rather than poor planning? What would concern you about a team that never revised their plan?*
[Your response here]
---

## Additional Notes
[Free text — questions, observations, connections to real work, things to follow up on]
---

*Lab 3.4 Notes — Windows Forensics for Beginners*  
*Keep this file in your `Labs/Lab03/Lab03_04/` folder alongside the `ReadMe.md`.*
