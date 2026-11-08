# Lab 10.2 — Types of Timelines

**Supporting Section 10.2: Types of Timelines**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Not every timeline should be built the same way.

In some cases, responders need a large multi-source timeline that pulls in everything they can get and lets them filter later. In other cases, that approach creates more confusion than value. A smaller, focused timeline around one host, one user, or one incident window is then the better move.

The distinction matters because timeline work becomes expensive quickly. More data gives the timeline more coverage, but it also adds noise, review time, and interpretation risk. Choose the timeline type that matches the question you are trying to answer.

This lab focuses on the two core timeline styles introduced in Chapter 10:

- Super timelines
- Targeted timelines

You will learn when each is appropriate, what each does well and poorly, and how to choose between them in a real Windows investigation.

---

## What This Lab Covers

This lab supports the following concepts from Section 10.2:

| Section | Topic |
|---|---|
| 10.2.1 | Super timelines |
| 10.2.2 | Targeted timelines |
| 10.2.3 | Strengths and weaknesses of each |
| 10.2 | Choosing the right timeline for the case |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain the difference between a super timeline and a targeted timeline
- Identify when a broad timeline is worth the extra complexity
- Identify when a focused timeline is the better first move
- Recognize the tradeoffs between coverage, noise, speed, and clarity
- Choose a timeline type based on the investigative question rather than habit
- Write concise notes justifying the timeline approach used in a case

---

## Estimated Time

35–50 minutes

---

## Prerequisites

- Completion of Lab 10.1, or equivalent familiarity with why timelines matter in incident response
- A text editor or markdown editor
- Your `lab10-notes.md` file
- Optional: outputs from earlier labs such as MFT CSVs, event log exports, Prefetch output, SRUM output, or network timeline notes

---

## Scenario

Your team is investigating suspicious activity on **FIN-WS23**. You already have these relevant artifacts:

- MFT output
- Event logs
- Prefetch and SRUM
- Network evidence
- User-activity artifacts

The team agrees that a timeline is needed. The open question is which kind to build first.

One responder wants to ingest everything into one large multi-source timeline. Another wants to build a narrow timeline focused only on a 30-minute suspicious window around a PowerShell event.

Both approaches may be useful. In this lab, you evaluate the difference between them and decide when each one is the better choice.

---

## Background: Broad Coverage Versus Focused Clarity

Timeline choice is usually a tradeoff.

A super timeline is designed to include as much relevant timestamped evidence as possible, often from many artifact sources. The idea is to collect first and filter later.

A targeted timeline is built around a specific question, host, user, time window, or artifact subset. The idea is to reduce noise early and focus on what matters most.

| Timeline Type | Basic Idea |
|---|---|
| Super timeline | Gather broadly, then filter down |
| Targeted timeline | Start narrow around a defined investigative need |

Both have value.

| If You Need To… | Timeline Type That Often Fits Best |
|---|---|
| Explore a case with unclear scope | Super timeline |
| Reconstruct a known suspicious window | Targeted timeline |
| Compare many artifact sources across longer periods | Super timeline |
| Explain what happened around one pivot event | Targeted timeline |
| Hunt for patterns you have not fully identified yet | Super timeline |
| Write a clean incident narrative quickly | Targeted timeline |

> **IR Reality Check:** A super timeline is not automatically better because it contains more data. A targeted timeline is not automatically weaker because it contains less. The right choice depends on the question.

---

## Lab Tasks

---

### Task 1 — Define Super Timelines and Targeted Timelines

**Objective:** Build a practical understanding of the two timeline types.

Fill in the table below.

| Timeline Type | What It Is | Why a Responder Might Use It | Main Risk |
|---|---|---|---|
| Super timeline | | | |
| Targeted timeline | | | |

Then answer:

**1. Why is a super timeline often useful when scope is unclear?**

```
[Your response here]
```

**2. Why is a targeted timeline often useful when a pivot event is already known?**

```
[Your response here]
```

**3. Why should responders avoid treating one type as "always correct"?**

```
[Your response here]
```

---

### Task 2 — Compare Coverage, Noise, and Speed

**Objective:** Understand the practical tradeoffs between the two timeline styles.

Complete the table below.

| Factor | Super Timeline | Targeted Timeline | Why the Difference Matters |
|---|---|---|---|
| Coverage breadth | | | |
| Noise level | | | |
| Speed to build | | | |
| Ease of review | | | |
| Best for unknown scope | | | |
| Best for clear incident window | | | |
| Reporting clarity | | | |

Then answer:

**1. Why can broader coverage create more analyst burden?**

```
[Your response here]
```

**2. Why can a narrower timeline sometimes produce faster, clearer findings?**

```
[Your response here]
```

**3. Why might a responder build both types at different stages of the same case?**

```
[Your response here]
```

---

### Task 3 — Map Investigative Questions to the Right Timeline Type

**Objective:** Practice choosing the timeline type based on the actual question.

For each investigative question below, identify whether a super timeline, targeted timeline, or either is the better first choice.

| Investigative Question | Best Timeline Type to Start With | Why |
|---|---|---|
| What happened during the 15 minutes around a suspicious PowerShell event? | | |
| Which hosts may have been involved over the last three days? | | |
| Did file staging, execution, and network activity align around one pivot? | | |
| Are there broader signs of attacker spread across multiple sources? | | |
| What should we show leadership about the most important suspicious window? | | |
| Which timestamped artifacts exist at all before we know what matters most? | | |

Then write six additional questions of your own and map them the same way.

Afterward, answer:

**1. Why should the case question drive the timeline choice?**

```
[Your response here]
```

**2. Why is "more data" not always the same as "better analysis"?**

```
[Your response here]
```

**3. Why does the audience for the output sometimes affect the best timeline type?**

```
[Your response here]
```

---

### Task 4 — Evaluate When a Super Timeline Is Justified

**Objective:** Identify the situations where a broad timeline is worth the effort.

Fill in the table below.

| Situation | Does a Super Timeline Make Sense? | Why |
|---|---|---|
| You have unclear scope across many artifact sources | | |
| You only need to explain one short suspicious window | | |
| Multiple hosts may be involved | | |
| You suspect activity started long before detection | | |
| You need to discover pivot events, not just explain one | | |
| You are under severe time pressure and need a same-day narrative | | |

Then answer:

**1. Why is a super timeline useful when the incident is still poorly understood?**

```
[Your response here]
```

**2. Why can it become hard to manage quickly?**

```
[Your response here]
```

**3. Why does filtering skill matter so much if you choose this route?**

```
[Your response here]
```

---

### Task 5 — Evaluate When a Targeted Timeline Is Justified

**Objective:** Identify the situations where a focused timeline is the better move.

Fill in the table below.

| Situation | Does a Targeted Timeline Make Sense? | Why |
|---|---|---|
| You already have a suspicious process start time | | |
| You need a clean narrative for one event window | | |
| The artifact set is huge and noisy | | |
| Leadership wants a short explanation fast | | |
| You need to validate whether several artifacts align around one pivot | | |
| You are still unsure which events matter at all | | |

Then answer:

**1. Why is a targeted timeline often the fastest route to a usable narrative?**

```
[Your response here]
```

**2. Why is it especially useful for pivot-based analysis?**

```
[Your response here]
```

**3. Why can it miss broader context if used too narrowly?**

```
[Your response here]
```

---

### Task 6 — Design Both Timeline Types for the Same Case

**Objective:** See how the same case can benefit from both approaches.

Using the FIN-WS23 scenario, design:

- One possible super timeline
- One possible targeted timeline

Use the table below.

| Timeline Plan | Sources Included | Time Window | Main Goal | Why This Approach Makes Sense |
|---|---|---|---|---|
| Super timeline | | | | |
| Targeted timeline | | | | |

Then answer:

**1. Which one would you build first, and why?**

```
[Your response here]
```

**2. Which one would be more useful for scoping?**

```
[Your response here]
```

**3. Which one would be more useful for reporting?**

```
[Your response here]
```

---

### Task 7 — Identify the Risks of Using the Wrong Timeline Type

**Objective:** Understand how a poor timeline choice can distort the investigation.

Fill in the table below.

| Wrong Choice | What Could Go Wrong | Why It Matters |
|---|---|---|
| Building only a super timeline when you need a fast pivot analysis | | |
| Building only a targeted timeline when scope is still unknown | | |
| Making the targeted window too narrow | | |
| Making the super timeline too broad without a filter strategy | | |

Then answer:

**1. Why can the wrong timeline type waste valuable response time?**

```
[Your response here]
```

**2. Why can it also distort what the analyst thinks is important?**

```
[Your response here]
```

**3. Why should timeline choice be documented as part of the investigative method?**

```
[Your response here]
```

---

### Task 8 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined reasoning about timeline type selection.

Classify each statement below as:

- Strongly supported
- Suggested but needs context
- Not supported by timeline-type reasoning alone

| Statement | Classification | Why |
|---|---|---|
| A super timeline can help responders discover patterns across many sources | | |
| A targeted timeline can help explain a suspicious event window clearly | | |
| A super timeline is always better because it contains more data | | |
| A targeted timeline is often faster to review and narrate | | |
| A targeted timeline alone always reveals full case scope | | |
| A super timeline without a filtering strategy can become hard to use | | |
| Both timeline types can be useful in the same case | | |
| Choosing a timeline type is mainly a matter of analyst preference rather than investigative need | | |

Then write five additional statements of your own and classify them the same way.

> **Guidance:** This lab is about choosing the right analytic structure, not defending one timeline style as universally superior.

---

### Task 9 — Write a Timeline-Type Selection Note

**Objective:** Practice documenting why one timeline type was chosen.

Write a short case note using this template:

```
Case Reference:
Author:
Date/Time (UTC):

Current Investigative Need:
Recommended Timeline Type:
Why This Type Fits the Case:
Main Sources to Include:
Main Risk or Limitation:
Would a Second Timeline Type Be Useful Later?:
Notes:
```

Your note should explain the reasoning clearly enough that another responder would understand the choice.

---

### Task 10 — Reflection

Answer the following in 3–5 sentences each.

**1. Why timeline type matters**
Why does choosing the right timeline type improve the quality and speed of incident analysis?

```
[Your response here]
```

**2. Scope versus clarity**
Why are super timelines better for broad discovery while targeted timelines are often better for explanation?

```
[Your response here]
```

**3. No one-size-fits-all approach**
Why is it reasonable for the same case to use both a super timeline and a targeted timeline at different stages?

```
[Your response here]
```

**4. Method as evidence**
Why should responders document why they chose one timeline style over another?

```
[Your response here]
```

---

## Deliverables Checklist

Your `lab10-notes.md` should contain:

- [ ] **Task 1** — Super vs targeted timeline definition table with written responses
- [ ] **Task 2** — Coverage/noise/speed comparison table
- [ ] **Task 3** — Investigative-question-to-timeline-type mapping with six added questions
- [ ] **Task 4** — Super-timeline justification table
- [ ] **Task 5** — Targeted-timeline justification table
- [ ] **Task 6** — Two timeline plans for the same case
- [ ] **Task 7** — Wrong-choice risk table
- [ ] **Task 8** — Strong support vs overclaim exercise
- [ ] **Task 9** — Timeline-type selection note
- [ ] **Task 10** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab10/
├── lab10-notes.md  ← Your working notes file (whole lab)
└── Lab10_02/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **Super timelines and targeted timelines solve different problems.** One is broad and discovery-oriented. The other is narrow and explanation-oriented.
- **More data is not always better.** Broader timelines can create noise and slow analysis if you do not filter them carefully.
- **Targeted timelines are often the best first move once you have a pivot.** They can produce faster and clearer incident narratives.
- **Both types can belong in the same case.** One may help scope, and the other may help explain.
- **Timeline choice should be question-driven.** Choose the timeline type that best matches the investigative need.

---

**Next:** Lab 10.3 — Common Tools

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
