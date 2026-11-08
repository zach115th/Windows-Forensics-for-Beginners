# Lab 11.2 — Suggested Workflow

**Supporting Section 11.2: Suggested Workflow**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

A good exfiltration investigation is not just a list of artifacts. It is a sequence of decisions.

If you start in the wrong place, you can waste hours chasing ambiguous clues while missing the evidence that actually explains what happened. If you jump straight to browser history without checking whether files were staged locally, you may miss the preparation phase. If you focus only on USB artifacts, you may miss cloud transfer evidence. If you start drawing conclusions before validating hashes and working copies, you weaken trust in everything that follows.

That is why this chapter includes a suggested workflow. It is not the only valid workflow, but it is a practical sequence for investigating suspected unauthorized data exfiltration from a Windows workstation. It starts with evidence integrity and moves through file-system and user-activity artifacts. It then evaluates removable media and cloud paths, adds logs and timelines for context, and uses memory to catch live-state or short-lived traces that disk evidence may miss.

In this lab, you turn the exfiltration scenario into a structured investigative method that another responder could follow, review, and defend.

---

## What This Lab Covers

This lab supports the following concepts from Section 11.2:

| Section | Topic |
|---|---|
| 11.2.1 | Confirm Authorization and Custody |
| 11.2.2 | Define the Investigative Questions |
| 11.2.3 | Establish the Window |
| 11.2.4 | Gather and Parse the Artifacts |
| 11.2.5 | Build the Timeline |
| 11.2.6 | Investigate the Channels |
| 11.2.7 | Identify the Channel and Build the Conclusion |
| 11.2.8 | Look for Cleanup |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain why exfiltration investigations need an ordered workflow
- Build a defensible investigation sequence from evidence integrity through final correlation
- Identify which artifact class should answer which question first
- Distinguish between staging, access, transfer, and cleanup evidence
- Recognize when the workflow should branch toward USB, cloud, or mixed-path analysis
- Use timelines and logs to unify findings from multiple artifact classes
- Write a concise workflow plan that another responder could reuse

---

## Estimated Time

45–70 minutes

---

## Prerequisites

- Completion of Lab 11.1, or equivalent familiarity with the case scenario and likely exfiltration paths
- A text editor or markdown editor
- Your `lab11-notes.md` file
- Optional access to:
  - A disk image
  - A memory image
  - Exported event logs
  - Registry hives
  - Browser artifacts
  - MFT / USN output
  - USB and shell-item artifacts

---

## Scenario

You are preparing to investigate the suspected unauthorized data-exfiltration case introduced in Section 11.1.

The organization has already identified the likely concern: an employee may have copied sensitive files off a workstation and exfiltrated them using USB, a cloud service, or both.

You have access to:

- A disk image
- A memory image
- Key logs and artifacts already exported or ready for extraction

Before analyzing any one artifact deeply, you need to decide:

> What is the right order of operations for this case, and why?

Your task in this lab is to take the chapter's suggested workflow and turn it into a practical case methodology.

---

## Background: Workflow Reduces Bias and Missed Evidence

Unauthorized exfiltration cases are easy to mishandle because multiple artifact paths can look suspicious at once.

You may see:

- Sensitive files accessed
- A USB device connected
- Browser visits to a cloud service
- Archive creation
- PowerShell or 7-Zip usage
- Deleted staging files

The wrong response is to pick the first suspicious thing and force the whole case around it. The better response is to follow a structured sequence.

| Workflow Stage | Why It Comes Here |
|---|---|
| Integrity and chain of custody | Protects trust in the evidence |
| Working copy creation | Prevents accidental modification of originals |
| MFT / USN review | Establishes file existence, staging, rename, and deletion patterns |
| Shell / Registry review | Adds user, path, and access context |
| USB and Shellbag review | Tests the removable-media theory |
| Browser / cloud review | Tests the cloud-exfiltration theory |
| Logs and timeline review | Aligns everything in sequence |
| Memory review | Adds live-state or short-lived context that disk may miss |

> **IR Reality Check:** The suggested workflow is not rigid law. Its purpose is to keep the case disciplined and make sure early assumptions do not distort later conclusions.

---

## Lab Tasks

---

### Task 1 — Explain Why a Workflow Is Needed

**Objective:** Build a practical explanation of why structured order matters in this case.

Write a short explanation in 4–6 sentences covering:

- Why exfiltration cases benefit from a defined workflow
- Why evidence integrity should come first
- Why staging evidence should usually be reviewed before declaring a transfer path
- Why workflow helps reduce bias and premature conclusions

Then answer the following in one or two sentences each:

**1. Why can a poor workflow waste time in an exfiltration case?**

**2. Why can a poor workflow also distort conclusions?**

**3. Why should the workflow be documented before or during analysis rather than reconstructed afterward?**

---

### Task 2 — Map the Suggested Workflow Stages

**Objective:** Understand the role of each major stage in the chapter's workflow.

Fill in the table below.

| Workflow Stage | What You Are Trying to Learn | Why It Matters |
|---|---|---|
| Confirm chain of custody and hashes | | |
| Create working copy | | |
| MFT / USN review | | |
| Shell items / Registry review | | |
| USB artifacts / Shellbags review | | |
| Browser / cloud artifact review | | |
| Event logs / timeline review | | |
| Memory review | | |

Then answer:

**1. Why is MFT / USN often one of the earliest analytical stages?**

**2. Why are USB and cloud review parallel theories rather than assumptions?**

**3. Why do logs and timelines often become more valuable after earlier artifact review?**

---

### Task 3 — Identify the Questions Each Stage Should Answer

**Objective:** Tie each step of the workflow to specific case questions.

For each stage below, write the primary questions it should answer.

| Workflow Stage | Primary Questions It Should Answer |
|---|---|
| Chain of custody / hashes | |
| Working copy | |
| MFT / USN | |
| Shell items / Registry | |
| USB / Shellbags | |
| Browser / cloud | |
| Event logs / timeline | |
| Memory | |

Then answer:

**1. Why is it useful to assign questions to stages instead of just artifact types?**

**2. Why can multiple stages contribute to the same final conclusion?**

**3. Why should each stage have a clear purpose before you start parsing data?**

---

### Task 4 — Decide What Comes First and Why

**Objective:** Practice ordering the workflow for a real case.

Take the following investigative tasks and put them in a practical order:

- Review browser upload or cloud-sync evidence
- Verify hashes and record evidence integrity
- Build a case timeline
- Review USB and Shellbag evidence
- Create working copies
- Review MFT / USN for staging
- Review event logs
- Review user hives and shell artifacts
- Review memory image

Use the table below.

| Order | Task | Why It Belongs Here |
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

Then answer:

**1. Why should integrity and working-copy steps always be near the beginning?**

**2. Why is timeline work usually stronger after some artifact review has already been done?**

**3. Why might memory move earlier in the order in some cases?**

---

### Task 5 — Build the USB Path Branch

**Objective:** Define how the workflow should proceed if removable-media evidence becomes important.

Assume early evidence suggests removable media may have been involved.

Fill in the table below.

| USB-Focused Step | What You Would Check | What Strong Support Would Look Like |
|---|---|---|
| Identify device presence | | |
| Identify vendor / model / serial | | |
| Review Shellbags for browsing | | |
| Review recent-item artifacts for device-backed files | | |
| Correlate with staging timeline | | |

Then answer:

**1. Why is USB presence weaker than USB interaction?**

**2. Why are Shellbags and recent-item artifacts so important after USBSTOR-style findings?**

**3. Why does the USB branch still need timeline correlation before strong conclusions are drawn?**

---

### Task 6 — Build the Cloud Path Branch

**Objective:** Define how the workflow should proceed if browser or cloud evidence becomes important.

Assume early evidence suggests cloud or browser-mediated exfiltration may have been involved.

Fill in the table below.

| Cloud-Focused Step | What You Would Check | What Strong Support Would Look Like |
|---|---|---|
| Identify cloud portal or service access | | |
| Identify browser history and downloads/uploads context | | |
| Identify sync-root or local cloud-client evidence | | |
| Identify user interaction with files in cloud-related paths | | |
| Correlate with staging timeline | | |

Then answer:

**1. Why is visiting a cloud site weaker than demonstrating interaction with relevant files?**

**2. Why should local cloud-client evidence and browser evidence both be considered?**

**3. Why is provider-side corroboration often the next step in a real enterprise case?**

---

### Task 7 — Decide When the Workflow Should Branch or Rejoin

**Objective:** Recognize when the case should split into multiple theories and when it should recombine.

Fill in the table below.

| Situation | Should the Workflow Branch? | Why |
|---|---|---|
| USB device connected during suspicious window | | |
| Browser access to cloud file-sharing service | | |
| Archive created but no obvious transfer path yet | | |
| Both USB and cloud artifacts appear relevant | | |
| No strong transfer-path evidence yet, but strong staging evidence exists | | |

Then answer:

**1. Why can both USB and cloud branches remain active at the same time?**

**2. Why should the workflow rejoin at the timeline stage?**

**3. Why does branching help prevent false certainty too early?**

---

### Task 8 — Identify Where Timeline and Logs Fit

**Objective:** Understand why the workflow eventually needs a sequence-based view.

Fill in the table below.

| Timeline / Log Goal | Why It Matters in This Workflow |
|---|---|
| Anchor suspicious activity in time | |
| Correlate staging with user activity | |
| Compare USB and cloud activity against the same window | |
| Identify cleanup or deletion after access | |
| Support final narrative writing | |

Then answer:

**1. Why is timeline building usually not the very first analytical step?**

**2. Why does it become critical before writing conclusions?**

**3. Why do logs and timelines help turn multiple weak clues into a stronger case?**

---

### Task 9 — Identify Where Memory Fits

**Objective:** Decide what memory review can add to an exfiltration workflow.

Fill in the table below.

| Memory Review Goal | Why It Might Matter in This Case |
|---|---|
| Identify short-lived tools | |
| Review suspicious command lines | |
| Review browser or PowerShell live-state clues | |
| Identify active or recent network connections | |
| Recover in-memory evidence of archive or transfer tools | |

Then answer:

**1. Why can memory be less central than disk in some exfiltration cases, but still high value?**

**2. Why is memory especially useful when PowerShell or short-lived utilities were used?**

**3. Why should negative memory findings still be written into the workflow notes?**

---

### Task 10 — Build the Full Suggested Workflow Note

**Objective:** Turn the chapter guidance into a reusable case workflow.

Write a workflow note using this template:

```
Case Reference:
Author:
Date/Time (UTC):

Primary Investigative Goal:
Suggested Workflow Order:
1.
2.
3.
4.
5.
6.
7.
8.

USB Branch Trigger:
Cloud Branch Trigger:
Where Timeline Review Fits:
Where Memory Review Fits:
Main Risks if Workflow Is Not Followed:
Notes:
```

Your note should be concise, professional, and specific enough that another responder could use it.

---

### Task 11 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined reasoning about workflow design.

Classify each statement below as:

- Strongly supported
- Suggested but needs context
- Not supported by workflow reasoning alone

| Statement | Classification | Why |
|---|---|---|
| Verifying hashes should happen before deep analysis | | |
| MFT / USN review is useful for identifying staging and file handling | | |
| USB artifacts should always be reviewed before browser artifacts | | |
| Browser and cloud review are important if web-based exfiltration is possible | | |
| Timeline work helps unify findings from different artifact classes | | |
| Memory review may add value when short-lived tools are suspected | | |
| Following a workflow automatically proves the case conclusions are correct | | |
| A structured workflow reduces the chance of bias and missed evidence | | |

Then write six additional statements of your own and classify them the same way.

> **Guidance:** This lab is about designing the right investigative method, not pretending that workflow alone proves the answer.

---

### Task 12 — Write a Short "Suggested Workflow" Analyst Summary

**Objective:** Produce a concise working note describing how the case should be investigated.

Write a 2–4 paragraph analyst summary describing:

- Why the exfiltration case needs a structured workflow
- Which artifact stages should come first and why
- How USB and cloud paths should be tested
- Where logs, timelines, and memory fit into the overall process
- What risks the workflow is designed to reduce

Write it as an internal case note.

---

### Task 13 — Reflection

Answer the following in 3–5 sentences each.

**1. Why workflow matters in exfiltration cases**
Why is a structured workflow especially important when the case involves multiple possible transfer paths?

**2. Branching without bias**
Why is it useful to let the workflow branch into USB and cloud theories instead of choosing one too early?

**3. Timelines as integration points**
Why do logs and timeline analysis usually become more valuable after earlier artifact review stages are complete?

**4. Method as part of defensibility**
Why does documenting the investigative workflow improve the credibility of the final case summary?

---

## Deliverables Checklist

Your `lab11-notes.md` should contain:

- [ ] **Task 1** — Workflow-importance explanation plus short written responses
- [ ] **Task 2** — Suggested-workflow stage table
- [ ] **Task 3** — Stage-to-question mapping table
- [ ] **Task 4** — Ordered task sequence with reasoning
- [ ] **Task 5** — USB-path branch table
- [ ] **Task 6** — Cloud-path branch table
- [ ] **Task 7** — Branch-or-rejoin decision table
- [ ] **Task 8** — Timeline / log role table with written responses
- [ ] **Task 9** — Memory-role table with written responses
- [ ] **Task 10** — Full suggested workflow note
- [ ] **Task 11** — Strong support vs overclaim exercise
- [ ] **Task 12** — "Suggested Workflow" analyst summary
- [ ] **Task 13** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab11/
├── lab11-notes.md  ← Your working notes file (whole lab)
└── Lab11_02/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **Workflow reduces bias.** It helps responders test exfiltration theories in a disciplined order instead of chasing the first suspicious artifact.
- **Integrity comes first.** Hashes, chain of custody, and working copies protect trust in the investigation.
- **USB and cloud are branches, not assumptions.** Good responders let the evidence decide which path matters most.
- **Timelines unify the case.** They are where staging, access, transfer, and cleanup evidence become a coherent sequence.
- **Memory can still matter.** Even in data-handling cases, short-lived tools and live-state evidence may strengthen the answer.
- **Documented method improves defensibility.** A well-explained workflow makes later conclusions easier to trust and review.

---

**Next:** Lab 11.3 — Recreate and Investigate a Mini Exfil Incident

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
