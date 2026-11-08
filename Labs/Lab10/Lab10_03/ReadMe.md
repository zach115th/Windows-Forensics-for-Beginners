# Lab 10.3 — Common Tools

**Supporting Section 10.3: Common Tools**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Timelines are useful only if you can build, review, filter, and explain them.

In practice, that means using tools that take timestamped artifacts from different sources and turn them into something a responder can work with. Some tools are built for large multi-source timeline generation. Some are better for focused CSV review. Some are good for Windows-specific artifact parsing. Others are lightweight scripts or spreadsheets that help you merge and inspect a narrow event window.

This lab focuses on the common timeline-building tool categories introduced in Chapter 10:

- Plaso / log2timeline and Timesketch (super-timeline generation and review)
- Eric Zimmerman ecosystem tools and Timeline Explorer (Windows-focused parser CSVs)
- SIEM platforms (centralized, query-driven timeline views across hosts)
- Spreadsheets and custom scripts (focused, repeatable, single-host work)
- Collaborative case-management platforms — IRIS-NG and Timesketch — where timelines are shared across analysts

No one tool is best for every case. This lab covers what each tool category does well and poorly, and how to choose the right tool for the timeline question in front of you.

By the end of this lab, you should be able to explain which timeline tools fit broad scoping, focused host analysis, and quick narrative-building work.

---

## What This Lab Covers

This lab supports the following concepts from Section 10.3:

| Section | Topic |
|---|---|
| 10.3.1 | Plaso / log2timeline and Timesketch (super-timeline generation and front end) |
| 10.3.2 | Eric Zimmerman tools and Timeline Explorer (Windows artifact CSVs) |
| 10.3.3 | SIEM platforms (centralized, query-driven, multi-host timelines) |
| 10.3.4 | Spreadsheets and custom scripts (focused, single-host, repeatable) |
| 10.3.5 | Collaborative timeline / case-management platforms (IRIS-NG, Timesketch) |

---

## Learning Objectives

By completing this lab, you will be able to:

- Identify the major tool categories commonly used for timeline analysis
- Explain the practical role of Plaso/log2timeline, Timesketch, Timeline Explorer, MFTECmd, EvtxECmd, and custom workflows
- Distinguish tools that generate timelines from tools that review or refine them
- Choose tools based on investigative scope, artifact type, and urgency
- Build a practical workflow for merging and reviewing timestamped artifacts
- Document tool choice in a way another responder can understand and reproduce
- Write concise notes about why a given timeline toolchain fits a case

---

## Estimated Time

45–65 minutes

---

## Prerequisites

- Completion of Labs 10.1 and 10.2, or equivalent familiarity with why timelines matter and the difference between super timelines and targeted timelines
- A text editor or markdown editor
- Your `lab10-notes.md` file
- Optional: CSV outputs from tools such as MFTECmd, EvtxECmd, Prefetch parsers, SRUM output, or other timestamped artifact data
- Optional: access to Timeline Explorer, Plaso/log2timeline, Timesketch, spreadsheets, or scripting tools

---

## Scenario

Your team is preparing to build timelines for a suspicious Windows workstation. You already have several timestamped artifact sources available:

- MFT CSV output
- Event log exports
- Prefetch output
- SRUM output
- Optional network timeline notes

The team agrees that a timeline is needed. The disagreement is about how to build it efficiently.

One responder wants to use a large timeline suite. Another wants to stay inside Zimmerman-style CSV outputs and use Timeline Explorer. A third thinks a quick spreadsheet or Python merge is enough for the current scope.

In this lab, you evaluate the common timeline tool options and decide which toolchain best fits different kinds of IR timeline work.

---

## Background: Timeline Tools Solve Different Problems

Timeline tooling usually falls into five practical categories.

| Tool Category | Common Purpose |
|---|---|
| Timeline suites | Build large multi-source timelines from many artifacts |
| Windows artifact parsers | Produce timestamped CSV or structured output from specific artifacts |
| Timeline review tools | Sort, filter, and inspect merged timestamped data |
| Custom scripts / queries | Merge, normalize, and reshape data for focused analysis |
| Spreadsheets | Quick manual review, sorting, filtering, and narrow-window analysis |

Examples from the chapter include:

| Tool / Approach | Typical Use |
|---|---|
| Plaso / log2timeline | Large timeline generation across many artifact types |
| Timesketch | Timeline review, filtering, and collaborative analysis |
| MFTECmd | MFT / NTFS timeline-relevant output |
| EvtxECmd | Event-log parsing into sortable output |
| Timeline Explorer | Review and filter CSV-style artifact data quickly |
| Custom scripts / queries | Merge and normalize multiple timeline sources |

> **IR Reality Check:** The best timeline tool is the one that fits the case question, the artifact volume, and the responder's need for speed and clarity.

---

## Lab Tasks

---

### Task 1 — Separate Tool Types by Role

**Objective:** Understand that timeline tools do different jobs.

Classify each tool or approach below by its primary role.

Use these categories where appropriate:

- Timeline generation
- Artifact parsing
- Timeline review
- Custom merge / transformation
- General-purpose review

| Tool / Approach | Primary Role | Why |
|---|---|---|
| Plaso / log2timeline | | |
| Timesketch | | |
| Timeline Explorer | | |
| MFTECmd | | |
| EvtxECmd | | |
| Custom Python / PowerShell script | | |
| Spreadsheet workflow | | |

Then answer:

**1. Why is it useful to separate artifact parsing from timeline review?**

```
[Your response here]
```

**2. Why can one case require more than one timeline tool?**

```
[Your response here]
```

**3. Why should responders avoid assuming one tool handles every stage equally well?**

```
[Your response here]
```

---

### Task 2 — Compare Common Timeline Tools

**Objective:** Learn what each tool category is best at and where it is limited.

Fill in the table below.

| Tool / Approach | Primary Strength | Best Use Case | Main Limitation |
|---|---|---|---|
| Plaso / log2timeline | | | |
| Timesketch | | | |
| Timeline Explorer | | | |
| MFTECmd + CSV review | | | |
| EvtxECmd + CSV review | | | |
| Custom script / query workflow | | | |
| Spreadsheet workflow | | | |

Then answer:

**1. Why are Plaso and Timesketch often attractive for broader or more mature timeline workflows?**

```
[Your response here]
```

**2. Why are Zimmerman-style parser outputs often practical for focused Windows cases?**

```
[Your response here]
```

**3. Why can custom scripts still be valuable even when dedicated timeline tools exist?**

```
[Your response here]
```

---

### Task 3 — Map Timeline Questions to the Right Tools

**Objective:** Choose tools based on the investigative question, not just preference.

For each question below, identify the best tool or toolchain to start with.

| Investigative Question | Best Tool(s) to Start With | Why |
|---|---|---|
| I need a broad multi-source timeline across many artifacts | | |
| I want to review MFT and EVTX output for one host | | |
| I need a quick ±15 minute pivot-window timeline in CSV form | | |
| I want to collaborate on filtering and reviewing a large timeline | | |
| I need to normalize timestamps from several parser outputs | | |
| I want a fast human-readable review of one Windows artifact CSV | | |

Then write six additional timeline-building questions of your own and map them the same way.

Afterward, answer:

**1. Why should the timeline question drive the tool choice?**

```
[Your response here]
```

**2. Why might a spreadsheet be appropriate in one case and weak in another?**

```
[Your response here]
```

**3. Why can a toolchain be more important than an individual tool?**

```
[Your response here]
```

---

### Task 4 — Build a Toolchain for a Targeted Timeline

**Objective:** Design a practical workflow for the kind of focused timeline described in Chapter 10.

Assume you have:

- MFT CSV
- EVTX exports
- Prefetch output
- SRUM output

Build a targeted timeline toolchain.

Use the table below.

| Workflow Stage | Selected Tool / Approach | Why You Chose It | Expected Output |
|---|---|---|---|
| Parse MFT-related data | | | |
| Parse event logs | | | |
| Parse Prefetch / SRUM or related CSV output | | | |
| Normalize / merge timestamps | | | |
| Review pivot window | | | |
| Write narrative | | | |

Then answer:

**1. Why is this toolchain appropriate for a focused Windows-host case?**

```
[Your response here]
```

**2. Which step matters most for speed?**

```
[Your response here]
```

**3. Which step matters most for clarity when writing the narrative later?**

```
[Your response here]
```

---

### Task 5 — Build a Toolchain for a Super Timeline

**Objective:** Contrast the targeted workflow with a broader timeline approach.

Now design a super timeline toolchain for a broader investigation.

Use the table below.

| Workflow Stage | Selected Tool / Approach | Why You Chose It | Expected Output |
|---|---|---|---|
| Ingest broad artifact set | | | |
| Generate large unified timeline | | | |
| Review / search / pivot | | | |
| Narrow by time or host | | | |
| Export focused subset | | | |
| Support collaborative review | | | |

Then answer:

**1. Why is this toolchain better suited to broader discovery?**

```
[Your response here]
```

**2. Why is it more expensive in time or complexity than a targeted timeline?**

```
[Your response here]
```

**3. Why might you still export a focused subset even after building a large timeline?**

```
[Your response here]
```

---

### Task 6 — Compare Dedicated Tools to Custom Scripts and Spreadsheets

**Objective:** Recognize when lightweight methods are enough.

Fill in the table below.

| Approach | Where It Works Well | Where It Breaks Down |
|---|---|---|
| Spreadsheet-only workflow | | |
| Custom Python / PowerShell merge | | |
| Dedicated timeline suite | | |
| Parser CSV + Timeline Explorer workflow | | |

Then answer:

**1. Why is a spreadsheet sometimes a reasonable DFIR tool?**

```
[Your response here]
```

**2. Why do custom scripts become effective when the artifact schema is predictable?**

```
[Your response here]
```

**3. Why do large investigations often outgrow manual spreadsheet workflows?**

```
[Your response here]
```

---

### Task 7 — Design a Reproducible Timeline Workspace

**Objective:** Organize inputs, merged timelines, and notes so another analyst can follow the work.

Create a folder structure for your timeline workflow.

Use or adapt this model:

```
Case-Timeline-Workspace/
├── 01_Raw_Artifact_Output/
│   ├── MFT/
│   ├── EVTX/
│   ├── Prefetch/
│   └── SRUM/
├── 02_Normalized_CSVs/
├── 03_Merged_Timeline/
├── 04_Pivot_Windows/
├── 05_Notes/
└── 06_Narratives/
```

Then define naming conventions for:

| Item | Naming Convention | Example |
|---|---|---|
| Normalized CSV | | |
| Merged timeline export | | |
| Pivot window export | | |
| Narrative note | | |
| Tooling note | | |

Afterward, answer:

**1. Why is workspace organization especially important in timeline analysis?**

```
[Your response here]
```

**2. Why should raw outputs be separated from normalized or merged data?**

```
[Your response here]
```

**3. Why should narrative and tool notes live next to the data instead of only in memory or chat?**

```
[Your response here]
```

---

### Task 8 — Separate Tool Output from Analyst Conclusion

**Objective:** Practice distinguishing raw tool output from your interpretation.

Classify each statement below as:

- Tool output
- Analyst interpretation
- Unsupported overclaim

| Statement | Classification | Why |
|---|---|---|
| MFTECmd output shows file creation activity in `C:\Users\j.smith\Downloads` at 02:14 UTC | | |
| EvtxECmd output shows a PowerShell-related event at 02:15 UTC | | |
| Timeline Explorer shows those events clustering within one suspicious window | | |
| The attacker definitely staged malware in Downloads and executed it intentionally | | |
| A merged timeline suggests these events deserve focused narrative review | | |
| Timesketch results prove the full incident scope automatically | | |

Then write five statements of your own and classify them the same way.

> **Guidance:** Timeline tools expose and organize events. You still have to interpret them carefully and avoid treating tooling convenience as proof.

---

### Task 9 — Write a Timeline Tooling Decision Note

**Objective:** Produce a concise note explaining why a particular toolchain was chosen.

Write a short case note using this template:

```
Case Reference:
Author:
Date/Time (UTC):

Timeline Goal:
Recommended Toolchain:
Why This Toolchain Fits the Case:
Key Inputs:
Expected Outputs:
Main Limitation:
Notes:
```

Your note should explain the reasoning clearly enough that another responder could continue the work.

---

### Task 10 — Reflection

Answer the following in 3–5 sentences each.

**1. Why common tools matter**
Why is it important for responders to understand what timeline tools are good at rather than just knowing their names?

```
[Your response here]
```

**2. Toolchain versus single tool**
Why is timeline work often best thought of as a workflow made of several tools instead of one "perfect" tool?

```
[Your response here]
```

**3. Scale changes the answer**
Why can the right timeline tooling choice change dramatically depending on host count, artifact volume, and urgency?

```
[Your response here]
```

**4. Reproducibility as protection**
Why does documenting tool choice and workflow make the timeline analysis more defensible?

```
[Your response here]
```

---

## Deliverables Checklist

Your `lab10-notes.md` should contain:

- [ ] **Task 1** — Tool-role classification table with written responses
- [ ] **Task 2** — Common-tools comparison table
- [ ] **Task 3** — Timeline-question-to-tool mapping with six added questions
- [ ] **Task 4** — Targeted-timeline toolchain table
- [ ] **Task 5** — Super-timeline toolchain table
- [ ] **Task 6** — Dedicated-tools vs scripts/spreadsheets comparison table
- [ ] **Task 7** — Reproducible workspace structure and naming conventions
- [ ] **Task 8** — Tool output vs analyst conclusion exercise
- [ ] **Task 9** — Timeline tooling decision note
- [ ] **Task 10** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab10/
├── lab10-notes.md  ← Your working notes file (whole lab)
└── Lab10_03/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **Timeline tools do different jobs.** Some generate, some parse, some review, and some reshape data.
- **Question-driven tool choice matters.** The best toolchain depends on whether you are scoping broadly or explaining a narrow pivot window.
- **Lightweight workflows still matter.** Spreadsheets, parser CSVs, and small scripts are often practical in focused Windows cases.
- **Large timeline suites earn their cost at scale.** Broad multi-source investigations often benefit from tools such as Plaso and Timesketch.
- **Reproducibility matters.** Clean workspace structure and documented tool choice make timeline analysis easier to trust and continue.

---

**Next:** Lab 10.4 — Building a Mini Incident Timeline

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
