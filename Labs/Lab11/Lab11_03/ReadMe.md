# Lab 11.3 — Recreate and Investigate a Mini Exfil Incident

**Supporting Chapter 11 §11.3 (Simulating the Incident), §11.4 (Capturing and Preserving Artifacts), and §11.5 (Investigating the Exfiltration Path)**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

This lab moves you from artifact analysis to case reconstruction. You will simulate a small unauthorized data-exfiltration incident on a Windows VM, then investigate it as the responder who receives the case afterward. Earlier labs isolated one artifact family at a time. This one makes you work across the full case: file staging, user activity, removable media, cloud access, event logs, memory, and timeline reconstruction.

The simulation does not need to be a perfect red-team scenario. It needs to be a defensible forensic challenge, where the important question is not "what artifact exists," but:

> What actually happened, who was involved, how did the data leave the system, and what evidence supports that conclusion?

You will simulate the incident, capture the resulting artifacts, and investigate the system as a blind case. Then you will write a structured case summary that you could hand to leadership, HR, legal, or another analyst.

---

## What This Lab Covers

This lab works Sections 11.3 through 11.5 as a single investigation, and previews the summary that Lab 11.4 develops:

| Section | Topic |
|---|---|
| 11.3 | Simulating a mini exfiltration incident |
| 11.4 | Capturing the relevant forensic artifacts |
| 11.5 | Investigating the case from the evidence |
| 11.6 | Writing a defensible exfiltration summary |

---

## Learning Objectives

By completing this lab, you will be able to:

- Simulate a realistic mini exfiltration case in a Windows lab
- Preserve evidence in a way that supports later review
- Investigate file staging, user activity, USB usage, and cloud activity together
- Build a timeline that explains the exfiltration sequence
- Identify which user account and transfer paths were involved
- Distinguish strong support from ambiguous or merely suggestive findings
- Write a case summary that answers what happened and what should happen next

---

## Estimated Time

120–180 minutes

---

## Prerequisites

- Completion of Labs 01–11.2, or equivalent familiarity with Windows forensic artifacts, event logs, timelines, and the exfiltration-case workflow
- A Windows VM you can safely modify
- A text editor or markdown editor
- Your `lab11-notes.md` file
- A removable-media option, such as:
  - A USB device, or
  - A virtual removable disk
- A cloud or cloud-like destination, such as:
  - A personal lab cloud account, or
  - A mock web upload target you control
- Optional tools:
  - MFTECmd / USN-capable parsers
  - Registry Explorer / RECmd / RegRipper
  - LECmd / JLECmd / PECmd / SBECmd
  - Browser-history tools
  - Volatility or other memory tools
  - EvtxECmd or event-log parsers
  - Timeline Explorer, spreadsheets, Python, or PowerShell

---

## Scenario

You are recreating and then investigating a suspected unauthorized data-exfiltration incident on a Windows workstation.

The suspected behavior is:

- A user accessed sensitive files
- The files were staged locally
- The files were copied to removable media, a cloud service, or both
- Some activity may have been cleaned up afterward

You will first simulate the incident in your lab environment. Then you will switch roles and treat the host as a forensic case.

Assume the final questions will be:

- What happened?
- Which user account was involved?
- How did the data leave the system?
- What evidence supports that answer?
- What remediation or controls should be recommended?

---

## Background: This Is a Full-Chain Exercise

A strong result in this lab does not come from one artifact. It comes from how the artifacts align.

| Phase | What You Are Trying to Learn |
|---|---|
| Simulate | Create a realistic exfiltration sequence with recoverable evidence |
| Capture | Preserve disk, memory, logs, browser, Registry, and timeline-capable artifacts |
| Investigate | Determine staging, access, transfer path, and sequence |
| Conclude | Explain what happened in plain language with honest confidence levels |

The most useful evidence in this lab usually comes from a combination of:

- MFT / USN
- Shell items and Registry
- USB and removable-device evidence
- Browser or cloud artifacts
- Event logs
- Memory
- Timeline analysis

> **IR Reality Check:** In a real exfiltration case, the best answer is usually not "we found the one magic artifact." It is "multiple sources support the same story."

---

## Lab Tasks

---

### Task 1 — Simulate the Incident

**Objective:** Create the exfiltration activity you will later investigate.

On your Windows VM, simulate a mini exfiltration incident. At minimum:

1. Create a folder named something like `Confidential`.
2. Create several test files inside it.
3. Copy those files to:
   - A removable device or virtual equivalent
   - A cloud destination or mock upload target
4. Use at least one realistic transfer method, such as:
   - File Explorer
   - PowerShell
   - 7-Zip or another archiver
   - Browser upload

If you want to test yourself later, document the activity in a private facilitator note or a separate planning note. Do not rely on that note during the investigation.

Record the simulated actions below.

| Simulated Action | Approximate Time (UTC) | Why You Included It |
|---|---|---|
| Create Confidential folder | | |
| Create test files | | |
| Copy files to removable media | | |
| Upload or sync files to cloud destination | | |
| Use archive or scripting tool | | |

Add at least five more actions of your own.

Examples:

- Rename files before transfer
- Delete staged archive after use
- Open a file before copying it
- Browse to the removable-media path in Explorer
- Visit the cloud portal in a browser before upload

Then answer:

**1. Why is it useful to include both USB and cloud behaviors in the same scenario?**

**2. Why should the simulation include some normal-looking user behavior as noise?**

**3. Why is realistic time spacing between actions valuable for later timeline work?**

---

### Task 2 — Capture the Artifacts

**Objective:** Preserve the evidence you will later investigate.

Acquire or export the following if available:

- Memory dump
- Relevant event logs
- Browser history or browser artifacts
- MFT / USN exports
- Registry hives
- Any other relevant artifact outputs

Record your collection below.

| Artifact Collected | Source | Method | Output Location | Notes |
|---|---|---|---|---|
| Memory dump | | | | |
| Security log | | | | |
| PowerShell log | | | | |
| Browser artifacts | | | | |
| MFT / USN output | | | | |
| Registry hives | | | | |

Add at least four more collected artifacts of your own.

Then answer:

**1. Why should you collect artifacts before making major changes to the system?**

**2. Why is memory especially important if short-lived tools or scripts were used?**

**3. Why does browser-history collection matter in a cloud-exfiltration theory?**

---

### Task 3 — Preserve Evidence Integrity

**Objective:** Apply evidence-handling discipline before analysis.

For each major evidence item, compute or record hashes and create working copies as appropriate.

Fill in the table below.

| Evidence Item | Original Path / Source | Hash Algorithm | Hash Value | Working Copy Created? | Notes |
|---|---|---|---|---|---|
| Disk image or primary disk evidence | | | | | |
| Memory image | | | | | |
| Exported logs | | | | | |
| Browser artifacts | | | | | |
| Registry hives | | | | | |

Then answer:

**1. Why should analysis happen on working copies whenever possible?**

**2. Why is evidence integrity still important even in a classroom or lab case?**

**3. Why should these details appear in your notes before deeper interpretation begins?**

---

### Task 4 — Treat It as a Blind Case

**Objective:** Switch from simulation mode to investigation mode.

Assume you do not know the answer, and begin the case as a responder.

Write at least 12 investigative questions you want the evidence to answer.

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
| 11 | | |
| 12 | | |

Then group the questions.

| Category | Question Numbers |
|---|---|
| User / account activity | |
| File staging | |
| USB / removable media | |
| Cloud / browser activity | |
| Logs / timeline | |
| Memory / live-state context | |

Then answer:

**1. Why is it important to switch mentally into blind-case mode here?**

**2. Why should your investigation questions be more specific than "was data stolen"?**

**3. Why should your final summary answer these questions directly?**

---

### Task 5 — Investigate File Staging and Handling

**Objective:** Determine how the confidential files were handled on disk.

Using MFT / USN and other file-system evidence, investigate:

- Creation of the Confidential folder
- File access and staging
- Archive creation
- Renames or moves
- Deletes or cleanup

Record your findings below.

| File / Path / Artifact | Why It Matters | What It Suggests | What It Does Not Prove |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |

Add at least eight findings.

Then answer:

**1. Why are staging directories and archive files especially important in exfiltration cases?**

**2. Why can deleted or short-lived files be highly significant here?**

**3. Why should file-system findings be correlated with user and transfer artifacts before conclusions are made?**

---

### Task 6 — Investigate User Access and Folder Interaction

**Objective:** Identify which user account likely handled the files and folders involved.

Use shell artifacts, Registry hives, Explorer history, RecentDocs, UserAssist, Jump Lists, LNK files, and related artifacts.

Record your findings below.

| User-Activity Finding | Source Artifact | Why It Matters | What It Suggests | Limitation |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |

Add at least eight findings.

Then answer:

**1. Why is user-hive provenance essential in a case that may involve employee action?**

**2. Why are folder-navigation artifacts useful even if they do not prove transfer?**

**3. Why does user activity become much stronger when aligned with staging and transfer evidence?**

---

### Task 7 — Investigate Removable-Media Involvement

**Objective:** Determine whether USB or removable media was part of the exfiltration path.

Use:

- USB Registry artifacts
- Shellbags
- LNK files
- Jump Lists
- RecentDocs
- Timeline correlation

Record your findings below.

| USB-Related Finding | Source Artifact | Why It Matters | What It Suggests | What It Does Not Prove |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

Add at least eight findings.

Then answer:

**1. What evidence supports device presence?**

**2. What evidence supports likely browsing or file interaction on the device?**

**3. What evidence would make you more confident that copying to USB actually occurred?**

---

### Task 8 — Investigate Cloud or Browser-Based Exfiltration

**Objective:** Determine whether browser or cloud-service activity supports a second exfiltration path.

Use browser history, downloads, upload context, cloud-client artifacts, OneDrive or other sync traces, and web access evidence.

Record your findings below.

| Cloud / Browser Finding | Source Artifact | Why It Matters | What It Suggests | Limitation |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

Add at least eight findings.

Then answer:

**1. Why is browser evidence critical in a suspected web-upload case?**

**2. Why can local cloud evidence strongly suggest activity while still falling short of proof of remote upload success?**

**3. What provider-side or enterprise evidence would strengthen a real-world cloud-exfiltration case?**

---

### Task 9 — Investigate Logs and Live-State Clues

**Objective:** Use event logs and memory to strengthen or challenge the case theory.

Review event logs and memory for:

- Logons
- PowerShell use
- Scheduled tasks or services
- Defender activity
- Suspicious command lines
- Archive tools
- Browser or PowerShell remnants
- Active or recent connections

Record your findings below.

| Log or Memory Finding | Source | Why It Matters | What It Suggests | Limitation |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

Add at least eight findings across logs and memory.

Then answer:

**1. Why do event logs help anchor the timeline?**

**2. Why can memory reveal short-lived activity disk artifacts may miss?**

**3. Why are negative findings still important to record?**

---

### Task 10 — Build the Mini Incident Timeline

**Objective:** Create the sequence that explains the exfiltration window.

Using the artifacts from the earlier tasks, build a focused timeline.

Include at least 15 entries if possible.

| Time (UTC) | Artifact Type | Event Description | Context | Why It Matters |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

Then answer:

**1. Which events are most central to the exfiltration theory?**

**2. Which events support USB use?**

**3. Which events support cloud use?**

**4. Which events remain ambiguous?**

---

### Task 11 — Determine the Most Likely Exfiltration Path

**Objective:** Synthesize the case into defensible conclusions.

Answer the following in short structured form:

**1. What happened?**

**2. Which user account was involved?**

**3. Was USB involved?**

**4. Was cloud activity involved?**

**5. Which path seems strongest?**

**6. What evidence most strongly supports that assessment?**

**7. What remains uncertain?**

Then complete the table below.

| Conclusion Area | Strongest Supporting Evidence | Supporting but Weaker Evidence | Confidence |
|---|---|---|---|
| User account involved | | | |
| File staging | | | |
| USB involvement | | | |
| Cloud involvement | | | |
| Most likely exfiltration path | | | |

---

### Task 12 — Write the Mini Case Summary

**Objective:** Produce the structured summary the chapter calls for.

Write a 1–3 page case summary that answers:

- What happened
- Which hosts/accounts were involved
- How the data left the system
- Recommended remediations and controls

Your case summary should include:

- Scope of the review
- Main evidence sources used
- Most important artifact findings
- Timeline-based narrative
- Strength of the conclusions
- Remaining uncertainties
- Recommended next steps

Use clear, professional language suitable for internal leadership and technical stakeholders.

---

### Task 13 — Write Remediations and Control Recommendations

**Objective:** Translate the case into operational action.

Write at least 10 remediation or control recommendations.

Use the table below.

| Recommendation | Why It Matters | Priority |
|---|---|---|
| | | |
| | | |
| | | |
| | | |
| | | |

These may include:

- Account action
- Host isolation or rebuild
- USB controls
- DLP / cloud controls
- Logging enhancements
- Browser or proxy monitoring
- User-access review
- Event-log retention improvements
- Timeline / alerting improvements
- Legal / HR coordination steps

Then answer:

**1. Why should recommendations cover both immediate response and longer-term control improvement?**

**2. Why do logging and monitoring recommendations usually belong in exfiltration cases?**

**3. Why should recommendations reflect the actual confidence level of the case?**

---

### Task 14 — Write an Analyst Handoff Note

**Objective:** Make the case easy for another analyst or reviewer to continue.

Use the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Primary Investigative Question:
- 

Most Important Findings:
- 

Most Strongly Supported Conclusions:
- 

What Is Suggested but Not Fully Confirmed:
- 

Likely Exfiltration Path(s):
- 

Recommended Next Actions:
1.
2.
3.

Open Questions:
- 

Notes for Incoming Analyst:
```

---

### Task 15 — Reflection

Answer the following in 3–5 sentences each.

**1. Why full-case correlation matters**
Why is this kind of exfiltration investigation much stronger when handled as one integrated case instead of separate artifact reviews?

**2. USB versus cloud ambiguity**
Why is it possible for both exfiltration paths to appear plausible at the same time?

**3. Case summary discipline**
Why should the final case summary clearly separate strong support from uncertainty?

**4. From analysis to action**
Why is a good exfiltration investigation incomplete until it includes remediation and control recommendations?

---

## Deliverables Checklist

Your `lab11-notes.md` should contain:

- [ ] **Task 1** — Simulated incident table with at least 10 actions
- [ ] **Task 2** — Artifact collection table with added sources
- [ ] **Task 3** — Evidence-integrity table
- [ ] **Task 4** — At least 12 investigative questions grouped by category
- [ ] **Task 5** — File-staging and handling findings
- [ ] **Task 6** — User-access and folder-interaction findings
- [ ] **Task 7** — USB-involvement findings
- [ ] **Task 8** — Cloud / browser findings
- [ ] **Task 9** — Log and memory findings
- [ ] **Task 10** — Mini incident timeline with at least 15 entries where possible
- [ ] **Task 11** — Conclusion table and written answers
- [ ] **Task 12** — 1–3 page mini case summary
- [ ] **Task 13** — At least 10 remediation / control recommendations
- [ ] **Task 14** — Analyst handoff note
- [ ] **Task 15** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab11/
├── lab11-notes.md  ← Your working notes file (whole lab)
└── Lab11_03/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **This is where the chapters converge.** File-system, user, USB, browser, log, memory, and timeline evidence all matter together.
- **Exfiltration cases are about sequence and support.** You need to show staging, access, transfer path, and timing, not just isolated suspicious artifacts.
- **USB and cloud paths both need testing.** The evidence may support one, the other, or both.
- **A good case summary is operational.** It answers what happened and what to do next.
- **Remediation is part of the forensic outcome.** Strong analysis should lead to stronger controls.

---

**Next:** Lab 11.4 — Writing the Case Summary

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
