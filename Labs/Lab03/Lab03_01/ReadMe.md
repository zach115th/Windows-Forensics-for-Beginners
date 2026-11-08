# Lab 3.1 — Full Images vs. Targeted Triage

**Supporting Section 3.1: Full Images vs. Targeted Triage**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

One of the first major decisions in a real Windows incident is *how much* evidence to collect from each system before time, storage, and operational constraints start working against you. Which parser to run or which artifact to check comes later.

Traditional forensic work often treats full disk imaging as the default. In active incident response, that default can do real damage. Enterprise systems are large, incidents involve multiple hosts, and volatile evidence disappears quickly. The clock is running before you've touched a single drive.

This lab builds judgment. You will evaluate three Windows systems with different investigative and business profiles and choose between full imaging and targeted triage for each. You will then prioritize collection order under real constraints and document your reasoning so that another responder, manager, or legal reviewer can understand and defend it.

There is no single correct answer here. There are defensible answers and indefensible ones, and the difference is whether you can explain your reasoning.

---

## What This Lab Covers

| Section | Topic |
|---|---|
| 3.1.1 | Why full imaging is not always realistic in IR |
| 3.1.2 | What full imaging preserves |
| 3.1.3 | What targeted triage provides |
| 3.1.4 | Triage first, full image where justified |
| 3.1.5 | Collection depth is a risk decision |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain the operational tradeoffs between full disk imaging and targeted triage
- Evaluate systems based on business criticality, investigative value, and evidence volatility
- Decide which hosts justify full imaging and which are better suited to targeted collection
- Prioritize collection order across multiple affected systems under real constraints
- Identify what evidence may be lost or preserved under each strategy
- Document collection rationale clearly enough that another responder could defend it

---

## Estimated Time

30–45 minutes

---

## Prerequisites

- Completion of Lab 02, or equivalent familiarity with Windows IR collection planning
- A text editor or markdown editor
- Your `lab03.1-notes.md` file (template included in this folder)
- Optional: a Windows lab VM for thinking through practical collection constraints

---

## Scenario

At 07:42 on a Wednesday morning your IR team receives three escalations tied to the same suspected intrusion. You have two responders, one forensic collection drive, limited storage on your evidence share, and a leadership team expecting a preliminary scope assessment before end of business.

**DC-01** — A domain controller showing unusual overnight authentication activity: repeated failed privileged logons, two successful type 3 logons from a workstation IP with no legitimate reason to authenticate against the DC, and a new service installation event in System.evtx.

**FIN-WS23** — A finance department workstation where WINWORD.EXE spawned POWERSHELL.EXE at 06:58 UTC. Suspicious outbound connections followed. The assigned user is a payroll administrator with access to HR systems and a shared finance file server.

**KIOSK-07** — A public-facing kiosk with an AV detection and quarantine. The kiosk has no domain credentials and no known access to sensitive internal systems. It is still serving customers.

None of the systems have been rebooted. None have been collected. Containment decisions are pending.

Your job: decide which host gets collected first, which collection method is appropriate for each, and how to explain those decisions in writing.

---

## Background: Collection Depth Is a Risk Decision

Not every Windows system in an incident deserves the same level of collection. The right decision depends on what the host is, what it likely contains, how much evidence may disappear, and how quickly you need answers.

| Collection Type | Best Use Case | Strengths | Limitations |
|---|---|---|---|
| **Full disk image** | High-value systems, legal sensitivity, deep reconstruction needs | Broad evidence preservation; supports re-analysis; strong legal posture | Slow; storage-intensive; difficult to scale |
| **Targeted triage** | Active IR, multiple hosts, urgent scoping needs | Fast; focused; scalable; supports rapid decision-making | Less complete; may miss artifacts not in the triage set |
| **Memory capture** | Systems where attacker may still be active or fileless activity is suspected | Preserves volatile state, process tree, network connections, injected code | Lost if delayed; not sufficient by itself |
| **Deferred collection** | Low-value hosts with weak indicators and higher priorities elsewhere | Preserves responder time for more important systems | Risks evidence loss if assumptions are wrong |

> **IR Reality Check:** "Collect everything" sounds safe until you spend six hours imaging a low-value kiosk. Meanwhile the actual pivot point, a live domain controller, loses its volatile evidence state, and the attacker moves laterally undetected.

The principle that drives good triage decisions:

> **Collect deliberately. Match depth to value, volatility, and urgency. Document every tradeoff.**

---

## Lab Tasks

---

### Task 1 — Assess the Three Hosts

**Objective:** Evaluate each system across the dimensions that drive collection decisions.

For each host, assess the four factors that determine collection depth. Be specific: "high" or "low" without explanation is not sufficient.

| Host | Business Criticality | Investigative Value | Volatile Evidence Risk | Long-Term Preservation Value | Notes |
|---|---|---|---|---|---|
| DC-01 | | | | | |
| FIN-WS23 | | | | | |
| KIOSK-07 | | | | | |

**Factor definitions:**

| Factor | What to Consider |
|---|---|
| **Business criticality** | What breaks if this system is taken offline or degraded? Who depends on it? |
| **Investigative value** | How central is this host to understanding the intrusion — initial access, persistence, lateral movement, data access? |
| **Volatile evidence risk** | Is there process, network, or memory evidence likely to disappear on reboot or delay? Is the attacker possibly still active? |
| **Long-term preservation value** | Is this a system where broad preservation might matter for later legal proceedings, regulatory response, or deep re-analysis? |

> **Guidance:** Investigative value is not the same as business criticality. KIOSK-07 may be low-value to the business but still forensically significant if it was the attacker's entry point. DC-01 may be both operationally critical and forensically rich. Evaluate each dimension separately.

---

### Task 2 — Choose a Collection Strategy for Each Host

**Objective:** Assign a specific collection strategy to each host and justify it against your Task 1 assessment.

For each system, select one strategy and complete the justification columns.

| Host | Selected Strategy | Why This Level Is Appropriate | What It Will Help Answer | What You May Miss |
|---|---|---|---|---|
| DC-01 | | | | |
| FIN-WS23 | | | | |
| KIOSK-07 | | | | |

**Strategy options:**
- Full disk image + memory
- Targeted triage + memory
- Memory only (then reassess)
- Deferred — scope and prioritize first

Your justifications should address at least two of the following for each host:

- Does this host likely contain evidence of initial access, persistence, or lateral movement?
- Is broad preservation important for later legal or regulatory review?
- Is rapid triage more valuable than a slow full image given current time pressure?
- Is memory likely to contain evidence that cannot be recovered from disk alone?
- What changes if this host's volatile evidence is lost before collection?

---

### Task 3 — Prioritize the Collection Order

**Objective:** Assign a collection sequence and defend it against realistic operational constraints.

**Constraints:**
- Two responders available
- One portable evidence drive ready
- Leadership wants a preliminary scope answer same day
- No systems have been contained yet

| Priority | Host | Collection Type | Why This Order |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |

Answer the following in 2–4 sentences each:

**1. Why did you assign your #1 priority where you did?**

```
[Your response here]
```

**2. Which host are you most comfortable delaying, and why?**

```
[Your response here]
```

**3. If one system rebooted before you reached it, which loss would concern you most and why?**

```
[Your response here]
```

**4. What single new piece of information would cause you to reorder your priorities entirely?**

```
[Your response here]
```

> **Tip:** The most suspicious host is not always the best first collection target. A less suspicious host, such as a domain controller with lateral movement artifacts, may hold the key to understanding the full intrusion scope. If it does, prioritizing the obvious target first may cost you the bigger picture.

---

### Task 4 — Full Imaging vs. Targeted Triage Tradeoff Analysis

**Objective:** Build a reference comparison that articulates the decision logic behind each approach.

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

**Part B — Written analysis**

Answer each of the following in 3–4 sentences:

**1. In what kinds of incidents is full imaging the clearly better choice?**

```
[Your response here]
```

**2. In what kinds of incidents is targeted triage the more defensible first move?**

```
[Your response here]
```

**3. Why is "triage first, full image where justified" often the most practical IR model?**

```
[Your response here]
```

**4. What is the strongest argument against targeted triage, and how do you counter it?**

```
[Your response here]
```

---

### Task 5 — Write a Collection Decision Note

**Objective:** Document your decisions in a format suitable for a case file — readable by another responder, a manager, or legal counsel.

A collection decision note is not analysis. It is a record of what was decided, why, and what comes next. Write it as if it will be the first thing the next responder reads when they pick up this case.

```
# Collection Decision Note
Case Reference:     
Author:             
Date/Time (UTC):    
Incident Summary:   

---

Hosts Evaluated:
  - DC-01:     [one-line description]
  - FIN-WS23:  [one-line description]
  - KIOSK-07:  [one-line description]

---

Collection Decisions:
  DC-01:     [strategy selected]
  FIN-WS23:  [strategy selected]
  KIOSK-07:  [strategy selected]

---

Priority Order:
  1. [host] — [collection type] — [one-line reason]
  2. [host] — [collection type] — [one-line reason]
  3. [host] — [collection type] — [one-line reason]

---

Decision Rationale:
  [2–3 sentences explaining the overall logic of your decisions]

---

Operational Constraints Acknowledged:
  - [list constraints that influenced the decisions]

---

Evidence Risks Accepted:
  - [what you may be giving up with this approach, and why it is acceptable]

---

Immediate Next Action:
  [What happens in the next 30 minutes]
```

---

### Task 6 — Management-Facing Justification

**Objective:** Explain your collection choices to a non-technical stakeholder in plain language.

Leadership asks: *"Why aren't we imaging all three systems right now?"*

Write a response of two to three paragraphs that a director, executive, or legal reviewer could read and understand. Avoid technical jargon. If you must use a term, define it in plain language the first time.

Your response should cover:

1. Why full imaging every host immediately is not always the best IR first move
2. Why targeted triage may produce faster and more useful answers for scoping and containment
3. Which systems still justify deeper preservation and why
4. How your approach remains defensible if questioned later

```
[Your response here]
```

---

### Task 7 — Reflection

Answer the following in 3–5 sentences each:

**1. The danger of treating every host the same**
Why can a uniform collection strategy across all affected hosts be a mistake, even if consistency sounds safer?

```
[Your response here]
```

**2. Business value versus investigative value**
How can a lower-value host still matter more forensically than a high-value host in early incident response? Give a specific example using the hosts in this scenario.

```
[Your response here]
```

**3. The cost of over-collecting**
What are the operational risks of choosing full images too aggressively in a live incident? Think beyond storage — consider time, responder focus, and volatile evidence on other systems.

```
[Your response here]
```

**4. The cost of under-collecting**
What are the risks if you choose targeted triage where a full image was actually warranted? What types of evidence are most at risk, and how would you know — or not know — that you missed something?

```
[Your response here]
```

---

## Deliverables Checklist

Your `lab03.1-notes.md` should contain:

- [ ] **Task 1** — Host assessment table for all three systems
- [ ] **Task 2** — Collection strategy for each host with full justification
- [ ] **Task 3** — Priority order table and four written explanations
- [ ] **Task 4** — Comparison table and four written analysis responses
- [ ] **Task 5** — Completed collection decision note
- [ ] **Task 6** — Management-facing justification (2–3 paragraphs)
- [ ] **Task 7** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab03/
├── lab03-notes.md    ← Your working notes file (whole lab)
└── Lab03_01/
    ├── ReadMe.md         ← This file
    └── lab03.1-notes.md  ← Your working notes file
```

---

## Key Takeaways

- **Collection depth is a judgment call.** Match effort to value, volatility, and urgency, not to habit or anxiety about completeness.
- **Full imaging is thorough but expensive.** It preserves more evidence, but it costs time, storage, and scalability that may be needed elsewhere.
- **Targeted triage is not corner-cutting.** Done correctly, it is a deliberate and defensible way to answer urgent IR questions faster than any full image can.
- **Priority matters as much as method.** Collecting the right host first is often more important than choosing the most complete acquisition method on the wrong one.
- **Your reasoning must be documented.** A collection decision you cannot explain is a collection decision you cannot defend — to leadership, to legal counsel, or to the next analyst who inherits your case.

---

**Next:** Lab 3.2 — Disk Imaging Basics in an IR Context

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
