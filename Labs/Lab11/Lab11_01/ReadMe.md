# Lab 11.1 — Scenario

**Supporting Section 11.1: Scenario**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Every forensic investigation starts with a story someone is worried might be true.

In this chapter, an internal investigation suggests an employee may have copied sensitive files off a workstation and exfiltrated them using removable media, a cloud service, or both. That kind of case is high stakes because the technical questions quickly become business, legal, and personnel questions. It is not enough to say that a USB device was present or that a browser visited a cloud site. You need to determine what happened, what the evidence strongly supports, what remains uncertain, and how to explain it without overstating the facts.

This lab focuses on understanding the scenario before the investigation begins. You will identify the main investigative questions, the likely evidence sources, the competing theories of exfiltration, and the risks of getting the story wrong.

The goal is to help you think like a responder receiving a sensitive internal case: disciplined, skeptical, and focused on building a defensible explanation rather than chasing isolated suspicious details.

---

## What This Lab Covers

This lab supports the following concepts from Section 11.1:

| Section | Topic |
|---|---|
| 11.1 | Understanding the suspected exfiltration scenario |
| 11.1 | Defining the major investigative questions |
| 11.1 | Identifying likely exfiltration paths |
| 11.1 | Framing the case before artifact analysis begins |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain the core investigative problem in an unauthorized-data-exfiltration case
- Identify the main questions that must be answered before drawing conclusions
- Distinguish between USB-based and cloud-based exfiltration theories
- Recognize why internal investigations require especially careful wording
- Identify the key artifact classes likely to matter in this scenario
- Build a structured case frame before beginning deeper forensic analysis

---

## Estimated Time

35–50 minutes

---

## Prerequisites

- Completion of Labs 01–10, or equivalent familiarity with Windows forensic artifacts, timeline analysis, and IR workflow
- A text editor or markdown editor
- Your `lab11-notes.md` file
- Optional: access to the disk image, memory image, and exported artifacts described in the chapter

---

## Scenario

An internal investigation suggests that an employee may have copied sensitive files off a Windows workstation and exfiltrated them using either:

- A USB device
- A cloud service
- Or both

You have access to:

- A disk image
- A memory image
- Key logs and artifacts already exported or available for extraction

At this stage, the organization does not want guesses. It wants a defensible answer to a few critical questions:

- Did sensitive files leave the workstation?
- Which user account was involved?
- Was removable media involved?
- Was a browser or cloud service involved?
- What evidence supports the answer?
- What remains uncertain?

Your task in this lab is not to solve the case yet. Your task is to define the case correctly before you investigate it.

---

## Background: Exfiltration Cases Are Easy to Oversimplify

Unauthorized-data-exfiltration cases often look simple from the outside:

> *"A user had access to sensitive files, a USB drive was connected, and cloud activity was observed."*

That does not automatically mean the user stole data. There may be benign explanations, shared systems, routine cloud usage, legitimate removable-media use, incomplete logs, or ambiguous timestamps. There may also be strong evidence of staging, copying, archiving, browser uploads, or deliberate cleanup.

That is why these cases require discipline. The responder needs to separate:

- What is known
- What is strongly supported
- What is only suggested
- What still needs corroboration

| Possible Theory | What It Would Mean |
|---|---|
| USB exfiltration | Files were copied to removable media |
| Cloud exfiltration | Files were uploaded or synchronized to a service |
| Mixed pathway | Files were staged locally, then moved by more than one method |
| Benign explanation | Some suspicious artifacts exist, but they do not prove unauthorized exfiltration |

> **IR Reality Check:** In internal cases, the cost of overclaiming can be as serious as the cost of missing the real problem.

---

## Lab Tasks

---

### Task 1 — Define the Core Case Problem

**Objective:** Put the scenario into your own words before analyzing artifacts.

Write a short explanation in 4–6 sentences covering:

- What the organization is worried happened
- Why this is a high-stakes forensic case
- Why the investigation cannot rely on one artifact alone
- Why discipline matters more than speed in drawing conclusions

Then answer the following in one or two sentences each:

**1. Why is this case more sensitive than a routine malware triage case?**

**2. Why can unauthorized-exfiltration allegations not rest on weak artifact interpretation?**

**3. Why does the scenario require both technical and narrative clarity?**

---

### Task 2 — Identify the Main Investigative Questions

**Objective:** Define the questions the investigation must answer.

Write at least 10 case questions you would want answered.

Examples:

- Which user account was active during the suspicious window?
- Which sensitive files were accessed?
- Were the files staged locally before transfer?
- Was a USB device connected and used?
- Was a cloud service accessed or used for upload?
- Were archive tools or scripting tools involved?
- What timeline best explains the sequence of events?

Record them below.

| Question # | Investigative Question | Why It Matters |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |
| 7 | | |
| 8 | | |
| 9 | | |
| 10 | | |

Then group them into categories.

| Category | Question Numbers |
|---|---|
| User / account activity | |
| File staging and handling | |
| USB / removable media | |
| Cloud / browser activity | |
| Timeline and sequence | |
| Scope / confidence | |

Then answer:

**1. Why should these questions be written before deep artifact review begins?**

**2. Why does a question-driven case frame reduce bias?**

**3. Why should the final summary answer these same questions directly?**

---

### Task 3 — Identify the Likely Exfiltration Paths

**Objective:** Separate the main theories of how data may have left the system.

Fill in the table below.

| Possible Exfiltration Path | What It Would Likely Look Like | Key Artifact Types That Might Support It |
|---|---|---|
| USB / removable media | | |
| Cloud browser upload | | |
| Cloud sync client | | |
| Archive-and-transfer workflow | | |
| Network share / internal staging first | | |

Add at least three more possible paths of your own.

Then answer:

**1. Why is it important not to assume USB just because a device was present?**

**2. Why is it important not to assume cloud upload just because a cloud site was visited?**

**3. Why can more than one exfiltration path be involved in the same case?**

---

### Task 4 — Identify the Most Important Evidence Sources

**Objective:** Build a practical list of the artifact classes that matter most in this scenario.

Fill in the table below.

| Evidence Source | Why It Matters in This Case | What It Might Help Prove or Disprove |
|---|---|---|
| Disk image | | |
| Memory image | | |
| MFT / USN | | |
| Registry hives | | |
| Shell items / recent-item artifacts | | |
| USB artifacts | | |
| Browser artifacts | | |
| Event logs | | |
| Timeline analysis | | |

Then add at least four additional evidence sources of your own.

Then answer:

**1. Why is no single evidence source likely to answer the full case?**

**2. Why are USB, browser, and timeline artifacts especially important here?**

**3. Why can memory still matter even in what looks like a file-handling investigation?**

---

### Task 5 — Identify the Main Competing Explanations

**Objective:** Avoid tunnel vision before the investigation begins.

For each finding type below, write one suspicious interpretation and one benign or less certain interpretation.

| Finding Type | Suspicious Interpretation | Benign / Alternate Interpretation |
|---|---|---|
| USB device present | | |
| Browser access to cloud service | | |
| Sensitive file accessed | | |
| Archive file created | | |
| Temporary staging directory used | | |
| File deleted after access | | |

Then answer:

**1. Why is alternate-explanation analysis especially important in internal investigations?**

**2. Why can ordinary business behavior create artifacts that look suspicious?**

**3. Why should a responder test theories instead of choosing one too early?**

---

### Task 6 — Define What a Strong Case Would Need

**Objective:** Clarify what kinds of evidence would make the case strong versus weak.

Fill in the table below.

| Case Element | What Strong Support Would Look Like | What Weak or Ambiguous Support Would Look Like |
|---|---|---|
| User identification | | |
| File staging | | |
| USB involvement | | |
| Cloud involvement | | |
| Timeline coherence | | |
| Exfiltration conclusion | | |

Then answer:

**1. Why does a strong case usually require multiple artifact classes to align?**

**2. Why is "artifact exists" weaker than "artifact aligns with a coherent sequence"?**

**3. Why should confidence levels be built into the case from the start?**

---

### Task 7 — Build a Scenario Framing Note

**Objective:** Write the short case-framing note that should exist before deeper forensic work begins.

Use this template:

```
Case Reference:
Author:
Date/Time (UTC):

Primary Allegation:
Potential Exfiltration Paths:
Key Questions to Answer:
Most Important Evidence Sources:
Main Risks of Misinterpretation:
Initial Investigative Priorities:
Notes:
```

Your note should be concise, professional, and clear enough that another responder could begin the case from it.

---

### Task 8 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined reasoning before the artifact analysis even starts.

Classify each statement below as:

- Strongly supported
- Suggested but needs investigation
- Not supported by the scenario alone

| Statement | Classification | Why |
|---|---|---|
| The case involves a suspicion of unauthorized data exfiltration | | |
| USB is one possible pathway that must be investigated | | |
| Cloud is one possible pathway that must be investigated | | |
| The employee definitely stole data | | |
| The available evidence sources should allow a structured investigation | | |
| One artifact type will probably answer the whole case | | |
| Competing explanations must be tested | | |
| The scenario justifies a timeline-driven approach | | |

Then write five additional statements of your own and classify them the same way.

> **Guidance:** This lab is about framing the case correctly, not solving it prematurely.

---

### Task 9 — Write a Short "Scenario" Analyst Summary

**Objective:** Produce a concise working note that frames the case before the deep investigation begins.

Write a 2–4 paragraph analyst summary describing:

- What the scenario alleges
- Why the case is sensitive and high stakes
- Which evidence sources are likely to matter most
- Which competing exfiltration theories must be tested
- What the investigation should avoid assuming too early

Write it as an internal case note.

---

### Task 10 — Reflection

Answer the following in 3–5 sentences each.

**1. Why scenario framing matters**
Why is it important to define the case clearly before diving into artifacts?

**2. Competing pathways**
Why should responders keep USB and cloud theories separate until evidence aligns strongly enough to favor one or both?

**3. Sensitivity of internal cases**
Why do internal exfiltration cases require more caution in wording than many routine malware investigations?

**4. Good cases start with good questions**
Why does a strong question set improve the quality of the final forensic conclusion?

---

## Deliverables Checklist

Your `lab11-notes.md` should contain:

- [ ] **Task 1** — Core case-problem explanation plus short written responses
- [ ] **Task 2** — At least 10 investigative questions grouped by category
- [ ] **Task 3** — Likely exfiltration-path table with added paths
- [ ] **Task 4** — Evidence-source table with added sources
- [ ] **Task 5** — Competing-interpretation table
- [ ] **Task 6** — Strong-case versus weak-case table
- [ ] **Task 7** — Scenario framing note
- [ ] **Task 8** — Strong support vs overclaim exercise
- [ ] **Task 9** — "Scenario" analyst summary
- [ ] **Task 10** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab11/
├── lab11-notes.md  ← Your working notes file (whole lab)
└── Lab11_01/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **Exfiltration cases are high-stakes interpretation problems.** The evidence must be framed carefully before conclusions are drawn.
- **USB and cloud are separate theories until the artifacts say otherwise.** Good responders test both rather than assuming one too early.
- **Case framing reduces bias.** A strong question set and evidence plan help keep the investigation disciplined.
- **Competing explanations matter.** Internal cases often contain ordinary user behavior mixed with suspicious-looking artifacts.
- **The scenario is part of the evidence strategy.** How you define the case at the start shapes everything that follows.

---

**Next:** Lab 11.2 — Suggested Workflow

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
