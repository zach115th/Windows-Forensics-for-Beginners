# Lab 10.4 — Building a Mini Incident Timeline

**Supporting Section 10.4: Building a Mini Incident Timeline**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

A timeline becomes most useful when it moves from theory into a concrete investigative product.

By this stage, responders often already have several timestamped artifacts: MFT output, event logs, Prefetch, SRUM, and possibly network or shell-item notes. Each source says something important, but none of them is the incident story by itself. The story emerges when you normalize those sources, merge them, narrow them to a meaningful window, and examine them around a pivot event.

This lab walks through that process. You will gather timeline-capable inputs, normalize timestamps into a common timezone, and merge the data into a single CSV or working table. You will then choose a pivot event, examine the surrounding ±10–15 minute window, and write a short narrative paragraph explaining what happened in plain language.

The goal is a usable mini incident timeline, not the largest one possible. It should help another responder understand what happened and give you material for the next chapter's case study work.

---

## What This Lab Covers

This lab supports the following concepts from Section 10.4:

| Section | Topic |
|---|---|
| 10.4.1 | Gathering timeline-capable artifact inputs |
| 10.4.2 | Normalizing timestamps |
| 10.4.3 | Merging events into a single working timeline |
| 10.4.4 | Using a pivot event to build a focused incident narrative |

---

## Learning Objectives

By completing this lab, you will be able to:

- Gather timestamped inputs from multiple Windows artifact sources
- Normalize timestamps into a common time basis
- Merge multiple artifact outputs into a single timeline view
- Identify a defensible pivot event
- Review a focused ±10–15 minute incident window
- Distinguish central events from supporting or background events
- Write a short narrative paragraph that explains the suspicious window in plain language

---

## Estimated Time

75–105 minutes

---

## Prerequisites

- Completion of Labs 10.1 through 10.3, or equivalent familiarity with why timelines matter, timeline types, and common timeline toolchains
- A text editor or markdown editor
- Your `lab10-notes.md` file
- Access to at least some of the following:
  - MFT CSV
  - Event log exports
  - Prefetch output
  - SRUM output
- Optional: spreadsheet software, Timeline Explorer, or a custom script for CSV merging

---

## Scenario

You are investigating a suspicious Windows workstation with several partial artifacts already collected. The team does not yet need a full super timeline. It needs a mini incident timeline that explains what happened around one suspicious event.

Available inputs include:

- MFT CSV
- Event log exports
- Prefetch output
- SRUM output

Your task is to:

- Gather the inputs
- Normalize all timestamps to a common timezone
- Merge the events into a single CSV or working table
- Choose a pivot event
- Examine the surrounding 10–15 minutes before and after
- Write a short narrative paragraph describing what happened in that window

Keep the output clean enough to save and reuse in the next chapter's case study work.

---

## Background: A Mini Timeline Is a Focused Analytic Product

A mini incident timeline should contain the right things, not everything.

The workflow in this chapter is intentionally focused:

| Step | Why It Matters |
|---|---|
| Gather input | Defines which artifact sources contribute time-based evidence |
| Normalize time | Prevents false sequence caused by timezone or skew issues |
| Merge data | Puts separate artifacts into one reviewable sequence |
| Choose a pivot | Anchors the analysis around the event that matters most |
| Examine ±10–15 minutes | Captures immediate lead-up and follow-on activity |
| Write narrative | Turns technical event rows into a usable incident story |

This kind of timeline is especially useful when you already have a suspicious lead, such as:

- A malicious logon
- A PowerShell execution
- A service creation event
- A suspicious file creation or program launch

> **IR Reality Check:** A mini timeline's value is clarity, not completeness.

---

## Lab Tasks

---

### Task 1 — Gather the Input Sources

**Objective:** Identify and document the artifact sources you will use in the mini timeline.

Gather or identify the following if available:

- MFT CSV
- Event log exports
- Prefetch output
- SRUM output

Record them below.

| Input Source | File Name / Location | What It Contributes | Notes |
|---|---|---|---|
| MFT CSV | | | |
| Event log export | | | |
| Prefetch output | | | |
| SRUM output | | | |

Add at least two additional timestamped sources if available.

Examples may include:

- PowerShell log output
- Task Scheduler export
- LNK / Jump List output
- Network timeline notes
- USB-related event timestamps

Then answer:

**1. Why is it useful to know what each source contributes before merging?**

```
[Your response here]
```

**2. Why should you document source provenance before transforming the data?**

```
[Your response here]
```

**3. Why might some artifact sources carry more analytic weight than others in the same timeline?**

```
[Your response here]
```

---

### Task 2 — Normalize Time

**Objective:** Convert all timestamps into one common basis.

Choose a single time basis for the case, such as:

- UTC
- One common case timezone

Document your normalization work below.

| Artifact Source | Original Time Basis | Normalized Time Basis | Adjustment Needed? | Notes |
|---|---|---|---|---|
| MFT CSV | | | | |
| Event logs | | | | |
| Prefetch output | | | | |
| SRUM output | | | | |

Add any extra sources you included.

Then answer:

**1. Why is normalization required before meaningful merging?**

```
[Your response here]
```

**2. Why can small time differences cause false interpretations in a focused incident window?**

```
[Your response here]
```

**3. Why should known or suspected time skew be documented in the notes field?**

```
[Your response here]
```

---

### Task 3 — Design the Merged Timeline Schema

**Objective:** Create a common structure that allows multiple artifact types to live in one timeline.

Use the six-column schema shared across the rest of Lab 10. You can copy the empty `Labs/Lab10/timeline-template.csv` as your starting file. Document why each column is in the schema:

| Field / Column | Why It Is Included |
|---|---|
| Time (UTC) | |
| Source Artifact | |
| Event Description | |
| Significance | |
| Confidence | |
| Notes | |

At minimum, your merged structure should preserve:

- The normalized UTC timestamp
- The originating artifact type / source
- A short description of what happened
- Enough context (paths, processes, users) to understand the event later
- A relevance signal (significance) and a corroboration signal (confidence)

Then answer:

**1. Why is a common schema useful when combining different parsers and outputs?**

```
[Your response here]
```

**2. Why should event descriptions be concise and factual?**

```
[Your response here]
```

**3. Why is it useful to preserve artifact type rather than flatten everything into one generic event label?**

```
[Your response here]
```

---

### Task 4 — Merge the Inputs into a Single Working Timeline

**Objective:** Create the initial unified event sequence.

Using a spreadsheet, Timeline Explorer, or a custom script, merge your normalized inputs into one working timeline.

Document the merge approach below.

| Merge Step | Method Used | Why It Matters |
|---|---|---|
| Import source 1 | | |
| Import source 2 | | |
| Import source 3 | | |
| Import source 4 | | |
| Sort by normalized timestamp | | |
| Review for duplicates / ambiguity | | |

Then answer:

**1. Why is sorting by normalized timestamp the core step in this lab?**

```
[Your response here]
```

**2. Why should duplicate or near-duplicate events be reviewed carefully instead of deleted blindly?**

```
[Your response here]
```

**3. Why is a merged timeline more useful than keeping each artifact source isolated?**

```
[Your response here]
```

---

### Task 5 — Identify a Pivot Event

**Objective:** Choose the event that will anchor the focused timeline review.

Select a pivot event from the merged timeline.

Good pivot examples include:

- Suspicious logon
- PowerShell execution
- Malicious process start
- Service creation
- Scheduled task creation
- Suspicious file execution
- Unusual outbound network event

Record the pivot below.

| Pivot Field | Value |
|---|---|
| Pivot Time (UTC) | |
| Source Artifact | |
| Event Description | |
| Why This Was Chosen | |

Then answer:

**1. Why should the pivot be both specific and defensible?**

```
[Your response here]
```

**2. Why is the best pivot often the event most likely to anchor other surrounding artifacts?**

```
[Your response here]
```

**3. Why can a poor pivot make the rest of the timeline harder to interpret?**

```
[Your response here]
```

---

### Task 6 — Extract the ±10–15 Minute Window

**Objective:** Narrow the merged timeline to the most relevant window around the pivot.

From the full merged timeline, extract a focused window covering approximately:

- 10–15 minutes before the pivot
- 10–15 minutes after the pivot

Record at least 12 entries if possible.

Use the same six-column schema as `timeline-template.csv`. Confidence ratings: **HIGH** (≥2 independent sources agree) · **MEDIUM** (single reliable source) · **LOW** (indirect or single low-confidence source).

| Time (UTC) | Source Artifact | Event Description | Significance | Confidence | Notes |
|---|---|---|---|---|---|
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
| | | | | | |
| | | | | | |

Then answer:

**1. Which events appear most central to the suspicious sequence?**

```
[Your response here]
```

**2. Which are supporting but not central?**

```
[Your response here]
```

**3. Which may be background noise that only happens to fall in the same window?**

```
[Your response here]
```

---

### Task 7 — Identify Cross-Artifact Alignment

**Objective:** Recognize where different evidence sources reinforce each other.

Choose at least four examples from the focused window where two or more artifact sources align meaningfully.

| Timeline Finding | Artifact Source 1 | Artifact Source 2 | Why the Alignment Matters |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |

Then answer:

**1. Why does cross-artifact alignment increase confidence in the timeline?**

```
[Your response here]
```

**2. Why are these aligned clusters often more valuable than isolated events?**

```
[Your response here]
```

**3. Why should alignment still not be treated as automatic proof of causation?**

```
[Your response here]
```

---

### Task 8 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined interpretation of the focused timeline window.

Classify each statement below as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by this timeline alone

| Statement | Classification | Why |
|---|---|---|
| Multiple artifact sources align around the pivot event | | |
| The focused window shows a coherent suspicious sequence | | |
| The attacker definitely intended to perform the observed actions | | |
| Activity immediately before and after the pivot deserves deeper review | | |
| The timeline helps narrow which events likely belong to the same chain | | |
| Every event in the window is incident-related | | |
| The narrative should stay close to what the merged timeline supports | | |
| The mini timeline alone proves full incident scope | | |

Then write six additional statements of your own and classify them the same way.

> **Guidance:** This lab is about building a focused, useful timeline, not claiming that a short window tells the whole case.

---

### Task 9 — Write the Narrative Paragraph

**Objective:** Turn the focused timeline window into a plain-language incident story.

Write one narrative paragraph describing what happened in the focused ±10–15 minute window around your pivot event.

Your paragraph should:

- Use plain language
- Mention the most important aligned events
- Stay close to observed evidence
- Avoid unsupported conclusions
- Read like something that could be reused later in a case study or report

Then answer:

**1. Why is a narrative paragraph useful after the technical timeline table?**

```
[Your response here]
```

**2. Why should the paragraph stay faithful to the timeline rather than expand beyond it?**

```
[Your response here]
```

**3. Why does plain language make the timeline more reusable later?**

```
[Your response here]
```

---

### Task 10 — Save and Package the Mini Timeline

**Objective:** Preserve the timeline and supporting narrative for later use.

Create or describe a folder structure for saving your mini timeline.

Use or adapt this model:

```
Mini-Incident-Timeline/
├── merged-timeline.csv
├── pivot-window.csv
├── timeline-notes.md
└── narrative-paragraph.md
```

Then define naming conventions for:

| Item | Naming Convention | Example |
|---|---|---|
| Full merged timeline | | |
| Pivot window extract | | |
| Narrative paragraph file | | |
| Timeline notes | | |

Afterward, answer:

**1. Why should the pivot-window extract be saved separately from the larger merged timeline?**

```
[Your response here]
```

**2. Why is packaging important if the timeline will be reused in the next chapter?**

```
[Your response here]
```

**3. Why should the narrative paragraph be stored with the data rather than only described elsewhere?**

```
[Your response here]
```

---

### Task 11 — Write an Analyst Handoff Note

**Objective:** Make the mini timeline easy for another responder to understand and continue.

Use the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Timeline Inputs Used:
- 

Chosen Pivot Event:
- 

Most Important Events in the Pivot Window:
- 

What Is Strongly Supported:
- 

What Is Suggested but Not Confirmed:
- 

Recommended Next Correlations:
1.
2.
3.

Notes for Incoming Analyst:
```

---

### Task 12 — Reflection

Answer the following in 3–5 sentences each.

**1. Why mini timelines matter**
Why is a small focused timeline often one of the fastest ways to make sense of a suspicious incident window?

```
[Your response here]
```

**2. Normalization and trust**
Why does timestamp normalization matter so much before merging artifact sources?

```
[Your response here]
```

**3. Pivot-centered analysis**
Why does choosing the right pivot event often determine whether the timeline is useful or confusing?

```
[Your response here]
```

**4. Narrative as the payoff**
Why is the narrative paragraph such an important final step in timeline analysis?

```
[Your response here]
```

---

## Deliverables Checklist

Your `lab10-notes.md` should contain:

- [ ] **Task 1** — Input-source table with added sources if available
- [ ] **Task 2** — Time-normalization table
- [ ] **Task 3** — Merged-timeline schema explanation
- [ ] **Task 4** — Merge-workflow table
- [ ] **Task 5** — Pivot-event record
- [ ] **Task 6** — Focused ±10–15 minute timeline window with at least 12 entries where possible
- [ ] **Task 7** — Cross-artifact alignment table
- [ ] **Task 8** — Strong support vs overclaim exercise
- [ ] **Task 9** — Narrative paragraph
- [ ] **Task 10** — Packaging structure and naming conventions
- [ ] **Task 11** — Analyst handoff note
- [ ] **Task 12** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab10/
├── lab10-notes.md  ← Your working notes file (whole lab)
└── Lab10_04/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **A mini timeline is a focused analytic tool.** It is designed to explain a suspicious window clearly, not to contain everything.
- **Normalization is non-negotiable.** Timezone handling and skew awareness are required before meaningful merging.
- **The pivot event drives the analysis.** A good pivot makes the surrounding activity much easier to interpret.
- **Cross-artifact alignment increases confidence.** The strongest mini timelines show multiple sources reinforcing the same sequence.
- **Narrative makes the timeline useful.** The final paragraph turns the technical sequence into something reusable for reporting and case studies.

---

**Next:** Lab 11 — Forensic Challenge: Investigating Unauthorized Data Exfiltration

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
