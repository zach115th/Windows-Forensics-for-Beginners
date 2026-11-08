# Lab 3.4 — Designing a Defensible Triage Strategy

**Supporting Section 3.4: Designing a Defensible Triage Strategy**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Triage in a real Windows incident is about making deliberate, explainable decisions under pressure, not just collecting artifacts quickly. You decide what to collect first, what can wait, and what warrants escalation to full imaging. You also document those decisions so they still make sense days or weeks later, when someone who wasn't there asks why you made the calls you did.

A weak triage process creates two distinct failure modes. First, you may miss the evidence that mattered most because you collected too broadly, too narrowly, or in the wrong order. Second, even if your technical instincts were sound, your work becomes difficult to defend if you cannot explain why you chose one host, artifact, or collection method over another.

This lab builds a triage strategy that is both operationally practical and forensically defensible. You will prioritize hosts, define collection tiers, justify deviations from standard practice, and document constraints and limitations. You will also produce the written records that make your decisions understandable to other responders, managers, auditors, and legal reviewers.

The goal is a plan that is structured, proportionate, and documented, and that stands up to scrutiny from people with the benefit of hindsight. The goal is not the "perfect" collection plan.

---

## What This Lab Covers

| Section | Topic |
|---|---|
| 3.4.1 | What makes a triage strategy defensible |
| 3.4.2 | Prioritizing hosts, artifacts, and questions under constraints |
| 3.4.3 | Documenting rationale, risk, and limitations |
| 3.4.4 | Adjusting triage decisions as the incident evolves |

---

## Learning Objectives

By completing this lab, you will be able to:

- Build a Windows triage strategy tied to specific investigative questions rather than habit or assumption
- Prioritize systems and artifacts based on value, volatility, and operational risk
- Define collection tiers that scale across multiple hosts during a live incident
- Document why certain systems receive deeper collection than others
- Explain triage limitations and residual risk in professional, non-technical language
- Update a triage plan appropriately when new facts change the case

---

## Estimated Time

60–90 minutes

---

## Prerequisites

- Completion of Labs 3.1, 3.2, and 3.3, or equivalent familiarity with imaging, memory acquisition, and targeted triage
- A text editor or markdown editor
- Your `lab03.4-notes.md` file (template included in this folder)
- Optional: a Windows lab VM for thinking through practical artifact access and collection ordering

---

## Scenario

At 13:05 on a Friday afternoon, your IR team is responding to a suspected multi-host intrusion in a midsize Windows environment. Information is incomplete and still evolving.

**DC-02** — A domain controller showing unusual Kerberos-related activity overnight: multiple failed privileged logons, two successful type 3 logons from a workstation IP with no legitimate reason to authenticate against the DC, and a new service installation event.

**HR-WS17** — An HR workstation where a user opened a suspicious email attachment and then reported "weird pop-ups" before disconnecting from VPN. The user's account has access to personnel records and payroll data.

**ENG-FS01** — A file server hosting shared engineering data with signs of unusual file access overnight — large numbers of file reads on a confidential project folder by an account that normally accesses a different share.

**VPN-GW01** — A remote access gateway that may contain useful authentication and session history. No confirmed malicious activity yet, but several of the accounts seen in DC-02's logs have recent VPN sessions.

**PRINT-03** — A print server with one AV-flagged malware detection that was quarantined. No known signs of broader attacker behavior. Low business criticality.

**Constraints:**
- Three responders available
- Limited evidence storage on the collection drive
- Leadership wants a same-day scope update
- Operations wants minimal disruption to production systems
- Legal has flagged that evidence preservation may become important if sensitive data exposure is confirmed

Your task: build a defensible triage strategy for the next several hours of the response.

---

## Background: Defensible Triage Must Survive Review

A triage strategy is defensible when someone reviewing it later can answer five questions from your documentation alone:

1. What did you know at the time?
2. What questions were you trying to answer?
3. Why were certain systems or artifacts prioritized?
4. What constraints affected the decisions?
5. What limitations remained after collection?

Defensible does not mean perfect. It means reasonable, documented, and proportionate to the facts available at the time.

| Weak Triage Practice | Defensible Triage Practice |
|---|---|
| "We collected what we usually collect." | "We collected these artifacts because they addressed the most urgent scope and persistence questions." |
| "We imaged this host because it looked important." | "We fully imaged this host because it was high-value, showed signs of attacker execution, and may require deeper re-analysis." |
| "We skipped that server because we ran out of time." | "We deferred that server after documenting current indicators, relative risk, and the higher-priority hosts competing for limited collection resources." |
| "We forgot why we made that call." | "The case notes capture the rationale, timing, and constraints influencing each collection decision." |

> **IR Reality Check:** Reviewers judge a triage strategy by what was reasonable given the facts, tools, and time available *then*, not by what became obvious later. Documentation is what proves reasonableness.

---

## Lab Tasks

---

### Task 1 — Define Triage Objectives

**Objective:** Tie your triage plan to specific investigative goals before deciding what to collect.

Before assigning collection priority to any host, write down the key questions your triage strategy must answer in the next several hours. These are triage questions, not long-term case questions. They help you decide where the incident is, how serious it is, and what to collect next.

Write at least **10 specific triage objectives**, then group them by category.

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

**Group by category:**

| Category | Question Numbers |
|---|---|
| Active attacker presence | |
| Initial access and execution | |
| Authentication and privilege misuse | |
| Data access or exfiltration risk | |
| Lateral movement or spread | |
| Scope expansion decisions | |

> **Guidance:** Questions such as "Is the attacker still active on any host?" and "Did the HR-WS17 attachment result in code execution?" are triage objectives. "How did the attacker establish initial access to the environment six months ago?" is a long-term case question. It is important, but it does not drive the next two hours.

---

### Task 2 — Rank Hosts by Triage Priority

**Objective:** Decide which systems deserve earliest attention and make that reasoning explicit.

**Part A — Host assessment table**

Evaluate each host across the four factors that drive collection priority.

| Host | Business Criticality | Likelihood of Relevant Evidence | Volatile Evidence Risk | Potential Scope Value | Recommended Priority | Notes |
|---|---|---|---|---|---|---|
| DC-02 | | | | | | |
| HR-WS17 | | | | | | |
| ENG-FS01 | | | | | | |
| VPN-GW01 | | | | | | |
| PRINT-03 | | | | | | |

**Part B — Ranked priority list**

| Priority | Host | Reason It Belongs Here |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |

**Part C — Short answers**

Answer each in two or three sentences:

**1. Which host is most likely to help you understand scope fastest?**

```
[Your response here]
```

**2. Which host is most likely to contain volatile evidence worth immediate action?**

```
[Your response here]
```

**3. Which host are you most comfortable deferring, and why?**

```
[Your response here]
```

**4. What finding on PRINT-03 would immediately move it to the top of your priority list?**

```
[Your response here]
```

---

### Task 3 — Build Collection Tiers

**Objective:** Create a scalable triage model that can be applied consistently across multiple hosts.

Not every host needs the same collection depth. Define three tiers and assign each host to one.

**Part A — Tier definitions**

| Tier | Purpose | Typical Use Case | Artifacts Included |
|---|---|---|---|
| **Tier 1** | Fast scoping — minimum viable volatile and targeted collection | Hosts needing immediate answers; lower confirmed threat value | |
| **Tier 2** | Targeted triage — broader artifact set for hosts with stronger compromise indicators | Active compromise likely; scope questions remain open | |
| **Tier 3** | Deep preservation — full imaging or extended collection for highest-value hosts | Legal risk, confirmed attacker activity, re-analysis likely needed | |

**Part B — Host tier assignments**

| Host | Assigned Tier | Why This Tier Is Appropriate Right Now |
|---|---|---|
| DC-02 | | |
| HR-WS17 | | |
| ENG-FS01 | | |
| VPN-GW01 | | |
| PRINT-03 | | |

> **Guidance:** A tier assignment states how much collection is *justified right now*, given current evidence and constraints. It is not a final verdict on a host's importance. Revisit tier assignments as new facts arrive.

---

### Task 4 — Map Collection Strategy to Operational Constraints

**Objective:** Show explicitly how the scenario's constraints shape your triage decisions.

**Part A — Constraint analysis table**

| Constraint | Why It Matters to This Incident | How It Changes the Plan |
|---|---|---|
| Three responders available | | |
| Limited evidence storage | | |
| Same-day scope update required | | |
| Minimize operational disruption | | |
| Legal preservation interest flagged | | |

**Part B — Written analysis**

Answer each in three or four sentences:

**1. Which constraints push you toward faster targeted triage over deeper collection?**

```
[Your response here]
```

**2. Which constraints push you toward deeper preservation even at the cost of speed?**

```
[Your response here]
```

**3. Why is it important to document constraints explicitly rather than just documenting the technical decisions they produced?**

```
[Your response here]
```

---

### Task 5 — Build the Triage Decision Matrix

**Objective:** Create a structured, actionable record of who collects what, in what order, and why.

Complete the decision matrix for the first phase of the response. Fill in every cell. If something is unknown or deferred, say so explicitly.

| Host | Assigned Responder | Collection Tier | First Collection Action | Primary Question Being Answered | Escalation Trigger for Deeper Collection |
|---|---|---|---|---|---|
| DC-02 | | | | | |
| HR-WS17 | | | | | |
| ENG-FS01 | | | | | |
| VPN-GW01 | | | | | |
| PRINT-03 | | | | | |

**Escalation trigger guidance:**

Your escalation triggers should answer: *what finding would cause you to immediately change this host's collection depth?* Examples:

- Evidence of attacker tool execution → escalate to full imaging
- Active C2 connection discovered → add memory capture
- Privileged account usage confirmed → raise priority, add targeted triage to previously deferred host

> **Guidance:** Good triage is dynamic. A host that starts as low priority can move to the top of the list if the right evidence surfaces. The escalation trigger is how you build that adaptability into your plan in advance.

---

### Task 6 — Document Residual Risk and Limitations

**Objective:** Be explicit about what your triage plan does not guarantee. That honesty is part of what makes it defensible.

**Part A — Limitations table**

| Limitation or Residual Risk | Why It Exists | How You Would Communicate It in Notes or a Briefing |
|---|---|---|
| Not all hosts can receive deep collection immediately | | |
| Volatile evidence may be lost before collection reaches some hosts | | |
| Same-day scope update will rely on partial data | | |
| Deferred systems may later prove more relevant than current indicators suggest | | |
| Legal preservation needs may expand beyond current scope | | |
| Triage artifacts may not capture evidence of activity predating the collection window | | |

**Part B — Written response**

Write a short paragraph of four to six sentences answering:

*Why does explicitly acknowledging the limitations of your triage strategy strengthen rather than weaken its defensibility?*

```
[Your response here]
```

---

### Task 7 — Update the Plan When New Facts Arrive

**Objective:** Demonstrate that a defensible triage strategy can absorb new evidence without losing structure.

Midway through collection, the following new facts arrive:

- **HR-WS17** — Evidence confirms a suspicious PowerShell child process spawned from OUTLOOK.EXE. LNK files show a recently accessed `.xlsm` file.
- **DC-02** — The privileged account seen in earlier logon activity has now been confirmed across two additional servers not previously in scope.
- **ENG-FS01** — Unusual access to a confidential engineering folder involved downloading 4.3 GB of files in a two-hour window overnight.
- **VPN-GW01** — Logs reveal a successful VPN logon from an unfamiliar geographic location using the HR-WS17 user's credentials, 18 minutes before the suspicious attachment activity.
- **PRINT-03** — No additional suspicious activity. Quarantined file appears to be commodity adware.

**Part A — Re-rank the hosts**

| New Priority | Host | Why It Moved (or Stayed) |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |

**Part B — Document plan changes**

For each host, record whether collection depth, responder assignment, or escalation status changed, and why.

| Host | Priority Changed? | Collection Strategy Changed? | Specific Change | Why |
|---|---|---|---|---|
| DC-02 | | | | |
| HR-WS17 | | | | |
| ENG-FS01 | | | | |
| VPN-GW01 | | | | |
| PRINT-03 | | | | |

**Part C — New scope assessment**

Write three or four sentences answering: based on the updated facts, is this still a workstation-level incident, or has the scope expanded to something larger? What evidence most strongly drives that assessment?

```
[Your response here]
```

> **IR Reality Check:** Revising your plan when new evidence arrives shows that you built it to absorb new information rather than ignore it. It is not a sign of poor initial planning. Document every revision with a timestamp and the fact that triggered it.

---

### Task 8 — Write a Triage Strategy Note

**Objective:** Produce the summary document that makes your triage decision-making understandable to any reviewer.

Write a triage strategy note for the first phase of this incident. Keep it concise, but complete enough that another responder, manager, or legal reviewer can understand the strategy without asking you to reconstruct it from memory.

```
# Triage Strategy Note
Case Reference:       
Author:               
Date/Time (UTC):      
Incident Status:      [Active / Developing / Partially contained]

---

## Known Hosts and Initial Assessment

- DC-02:     [one-line status]
- HR-WS17:   [one-line status]
- ENG-FS01:  [one-line status]
- VPN-GW01:  [one-line status]
- PRINT-03:  [one-line status]

---

## Primary Triage Objectives (first phase)

1. 
2. 
3. 
4. 
5. 

---

## Host Priorities

| Priority | Host | Collection Tier | Rationale |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |

---

## Operational Constraints Acknowledged

- 
- 
- 

---

## Residual Risks and Limitations

- 
- 
- 

---

## Escalation Conditions

[What findings would cause an immediate plan revision?]
- 
- 
- 

---

## Next Review Point

[When and under what conditions will you revisit this plan?]

---

## Notes

```

---

### Task 9 — Reflection

Answer the following in three to five sentences each:

**1. Why documentation makes triage defensible**
Why is a technically sound triage decision still weak if the reasoning behind it is not documented? What specifically gets lost when documentation is absent?

```
[Your response here]
```

**2. Scope versus certainty**
Why do responders often need to make triage decisions on incomplete information, and how can those decisions still be defensible even when later facts change the picture?

```
[Your response here]
```

**3. The risk of false confidence**
How can a same-day scope update be useful to leadership without creating false certainty about what is and isn't compromised?

```
[Your response here]
```

**4. Changing plans without losing discipline**
Why is revising a triage strategy based on new evidence a sign of good incident response rather than poor initial planning? What would concern you about a team that *never* revised their plan?

```
[Your response here]
```

---

## Deliverables Checklist

Your `lab03.4-notes.md` should contain:

- [ ] **Task 1** — At least 10 triage objectives grouped by category
- [ ] **Task 2** — Host assessment table, ranked priority list, and four short answers
- [ ] **Task 3** — Three collection tier definitions and host-to-tier assignments with reasoning
- [ ] **Task 4** — Constraint analysis table and three written responses
- [ ] **Task 5** — Complete triage decision matrix with escalation triggers for all five hosts
- [ ] **Task 6** — Residual risk table and written paragraph on why limitations strengthen defensibility
- [ ] **Task 7** — Updated priority ranking, plan change documentation, and new scope assessment
- [ ] **Task 8** — Complete triage strategy note
- [ ] **Task 9** — Reflection answers (three to five sentences each)

---

## Files in This Folder

```
Lab03/
├── lab03-notes.md    ← Your working notes file (whole lab)
└── Lab03_04/
    ├── ReadMe.md         ← This file
    └── lab03.4-notes.md  ← Your working notes file
```

---

## Key Takeaways

- **Defensible triage is documented triage.** Good instincts are not enough if nobody can reconstruct why you made a decision. That includes you, six weeks later.
- **Prioritization is the core skill.** Choosing the right host and the right first question matters more than the completeness of any individual collection.
- **Constraints are part of the evidence story.** Time, storage, staffing, and operational pressure shape what is reasonable during a live incident. Document them as part of the rationale.
- **Residual risk must be acknowledged.** A triage plan that pretends to answer everything is less trustworthy than one that clearly states what it cannot guarantee.
- **Good triage adapts.** Revising your plan with timestamps and documented reasoning when new evidence arrives is a sign of discipline, not inconsistency.

---

**Next:** Lab 04 — Windows File System Forensics (NTFS)

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
