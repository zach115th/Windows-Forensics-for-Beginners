# Lab 3.1 — Analyst Notes
**Full Images vs. Targeted Triage**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Lab Environment:** ___________________________  
**Case Reference:** IR-2024-TRIAGE031  

---

## Task 1 — Host Assessment

> Evaluate each system across all five dimensions. "High" or "low" without explanation is not sufficient.

| Host | Business Criticality | Investigative Value | Volatile Evidence Risk | Long-Term Preservation Value | Notes |
|---|---|---|---|---|---|
| DC-01 | | | | | |
| FIN-WS23 | | | | | |
| KIOSK-07 | | | | | |

---

## Task 2 — Collection Strategy

> Select a strategy for each host and justify it against your Task 1 assessment.
> Options: Full disk image + memory / Targeted triage + memory / Memory only / Deferred

| Host | Selected Strategy | Why This Level Is Appropriate | What It Will Help Answer | What You May Miss |
|---|---|---|---|---|
| DC-01 | | | | |
| FIN-WS23 | | | | |
| KIOSK-07 | | | | |

---

## Task 3 — Collection Priority Order

> Assign a collection sequence and defend it against the stated operational constraints.

| Priority | Host | Collection Type | Why This Order |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |

---

**1. Why did you assign your #1 priority where you did?**
[Your response here]
---

**2. Which host are you most comfortable delaying, and why?**
[Your response here]
---

**3. If one system rebooted before you reached it, which loss would concern you most and why?**
[Your response here]
---

**4. What single new piece of information would cause you to reorder your priorities entirely?**
[Your response here]
---

## Task 4 — Full Imaging vs. Targeted Triage Tradeoff Analysis

**Part A — Comparison table**

| Decision Factor | Full Disk Image | Targeted Triage |
|---|---|---|
| Collection speed | | |
| Storage requirements | | |
| Re-analysis value (weeks or months later) | | |
| Scalability across many hosts | | |
| Value for urgent scoping questions | | |
| Risk of missing relevant artifacts | | |
| Best fit for domain controllers | | |
| Best fit for user workstations | | |
| Best fit for kiosk or low-sensitivity hosts | | |
| Defensibility under legal scrutiny | | |

---

**Part B — Written analysis**

**1. In what kinds of incidents is full imaging the clearly better choice?**
[Your response here]
---

**2. In what kinds of incidents is targeted triage the more defensible first move?**
[Your response here]
---

**3. Why is "triage first, full image where justified" often the most practical IR model?**
[Your response here]
---

**4. What is the strongest argument against targeted triage, and how do you counter it?**
[Your response here]
---

## Task 5 — Collection Decision Note

> Write this as if it will be the first thing the next responder reads when picking up this case.

```
# Collection Decision Note
Case Reference:
Author:
Date/Time (UTC):
Incident Summary:

Hosts Evaluated:
  DC-01:
  FIN-WS23:
  KIOSK-07:

Collection Decisions:
  DC-01:
  FIN-WS23:
  KIOSK-07:

Priority Order:
  1. [host] — [collection type] — [one-line reason]
  2. [host] — [collection type] — [one-line reason]
  3. [host] — [collection type] — [one-line reason]

Decision Rationale:

Operational Constraints Acknowledged:
  -

Evidence Risks Accepted:
  -

Immediate Next Action:
```

---

## Task 6 — Management-Facing Justification

> 2–3 paragraphs. Plain language. Audience: director, executive, or legal reviewer.
> Cover: why not imaging everything immediately, why triage answers scope questions faster,
> which systems still justify deeper collection, and why your approach is defensible.

```
[Paragraph 1]


[Paragraph 2]


[Paragraph 3]
```

---

## Task 7 — Reflection

**1. The danger of treating every host the same**
*Why can a uniform collection strategy across all affected hosts be a mistake, even if consistency sounds safer?*
[Your response here]
---

**2. Business value versus investigative value**
*How can a lower-value host still matter more forensically than a high-value host in early IR? Give a specific example using the hosts in this scenario.*
[Your response here]
---

**3. The cost of over-collecting**
*What are the operational risks of choosing full images too aggressively in a live incident? Think beyond storage.*
[Your response here]
---

**4. The cost of under-collecting**
*What are the risks if you choose targeted triage where a full image was warranted? What evidence is most at risk, and how would you know — or not know — that you missed something?*
[Your response here]
---

## Additional Notes
[Free text — questions, observations, connections to real work, things to follow up on]
---

*Lab 3.1 Notes — Windows Forensics for Beginners*  
*Keep this file in your `Labs/Lab03/Lab03_01/` folder alongside the `ReadMe.md`.*
