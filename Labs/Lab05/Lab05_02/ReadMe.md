# Lab 5.2 — Important Keys for IR

**Supporting Section 5.2: Important Keys for IR**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Knowing that the Registry matters is only the beginning. When you work an incident, you also need to know which parts of it to check first.

In real Windows investigations, responders do not browse the Registry at random. They go to the areas most likely to answer urgent questions: Was persistence established? Was a suspicious service installed? Was a USB device connected? Is there evidence of remote access, program usage, or user interaction with suspicious folders? The answers determine whether you isolate a host, widen scope, or brief leadership.

This lab focuses on high-value Registry locations responders return to again and again. You will map key paths to incident-response questions and separate strong findings from overclaims. You will also practice building a targeted Registry review plan that is fast enough for IR but still disciplined enough to defend later.

The goal is not to memorize every useful key in Windows. It is to build a working mental map of the Registry areas most likely to matter during real cases.

---

## What This Lab Covers

This lab supports the following concepts from Section 5.2:

| Section | Topic |
|---|---|
| 5.2.1 | Persistence Keys |
| 5.2.2 | Service Definitions |
| 5.2.3 | Network and Remote Access Configuration |
| 5.2.4 | USB and Removable Device History |
| 5.2.5 | User Activity Artifacts in NTUSER.DAT |

---

## Learning Objectives

By completing this lab, you will be able to:

- Identify Registry locations commonly reviewed during Windows incident response
- Explain why certain keys are high-value for persistence analysis
- Locate Registry areas relevant to services, USB history, RDP, and user activity
- Map specific IR questions to the Registry paths most likely to answer them
- Distinguish configuration evidence from proof of actual use
- Build a focused Registry review plan based on the scenario
- Write concise notes that stay within what the keys actually support

---

## Estimated Time

60–80 minutes

---

## Prerequisites

- Completion of Lab 5.1, or equivalent familiarity with Registry structure and key hives
- A text editor or markdown editor
- Your `lab05-notes.md` file
- Optional: a Windows VM or image containing Registry hives
- Optional: a Registry analysis tool such as Registry Explorer, RECmd, or RegRipper

---

## Scenario

You are continuing analysis of **HR-LT12**. Earlier work established which hives were collected and how they map to system-wide and user-specific evidence. The case now needs to move from structure to substance.

Current concerns include:

- A suspicious executable path may have been configured to start automatically
- A removable USB device may have been connected during the suspected incident window
- The user may have browsed to or launched files from unusual locations
- There are questions about possible RDP or remote-access-related activity
- Leadership wants a quick answer on whether there are signs of persistence or removable-media involvement

You do not have time to review every Registry area. Identify the most important keys for incident response, explain what they can tell you, and build a focused review plan for the case.

---

## Background: High-Value Keys Save Time and Improve Defensibility

The Registry is huge. In incident response, value comes from knowing where to start.

Some Registry areas are high-value because they are repeatedly useful across many cases:

- Run / RunOnce areas for startup persistence
- Services for installed or modified service-based persistence
- USBSTOR and related device areas for removable media history
- UserAssist for GUI-driven execution clues
- TypedPaths, RecentDocs, and similar Explorer-related areas for user navigation and file interaction
- RDP-related keys for remote access context

These keys do not answer every question by themselves, but they often narrow the investigation quickly.

| Key Area | Common IR Use |
|---|---|
| **Run / RunOnce** | Startup persistence |
| **Services** | Service-based persistence or system modification |
| **USBSTOR** | USB device recognition history |
| **UserAssist** | User-driven program interaction |
| **Explorer history keys** | Path browsing, recent access clues |
| **Remote access keys** | RDP and access configuration context |

> **IR Reality Check:** The best Registry review is not "check everything." It is "check the keys most likely to answer the question in front of you."

---

## Lab Tasks

---

### Task 1 — Identify High-Value Registry Areas for IR

**Objective:** Build a practical list of Registry areas responders check first.

Fill in the table below with the key areas you consider most important for Windows incident response.

| Registry Path or Area | Primary IR Use | Hive | Why It Is High-Value |
|---|---|---|---|
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | | | |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | | | |
| `HKLM\SYSTEM\CurrentControlSet\Services` | | | |
| `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` | | | |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` | | | |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` | | | |

Add at least eight more paths or areas of your own.

Then answer:

1. Why do responders revisit these same key areas across very different case types?

2. Why is a high-value key not the same thing as a guaranteed malicious finding?

3. Why is it useful to know both the hive and the full key path before you begin analysis?

---

### Task 2 — Focus on Persistence Keys

**Objective:** Identify Registry locations most relevant to startup and persistence analysis.

Assume the team's first urgent question is:

> Was anything configured to persist across reboot or logon?

List the Registry locations you would check first.

Use the table below.

| Registry Path or Area | Type of Persistence It May Reflect | Why It Matters | Example of a Suspicious Finding |
|---|---|---|---|
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | | | |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | | | |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce` | | | |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` | | | |
| `HKLM\SYSTEM\CurrentControlSet\Services` | | | |

Add at least six more relevant areas of your own.

Then answer:

1. Why can user-level persistence be just as important as machine-level persistence?

2. Why is a suspicious path in a startup key often more important than the value name itself?

3. Why should persistence findings be correlated with file-system and execution artifacts before drawing strong conclusions?

---

### Task 3 — Focus on USB and Removable Media Keys

**Objective:** Build a Registry-first plan for removable-device questions.

Assume the case now includes a concern that files may have been copied to removable media.

Identify the keys and supporting areas you would review first.

| Registry Path or Area | What It May Reveal | Why It Matters | Limitation |
|---|---|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` | | | |
| Mounted devices / volume mapping areas | | | |
| Storage device class or related enumeration keys | | | |
| User shell / folder-history areas | | | |

Add at least six more areas or supporting artifacts of your own.

Then answer:

1. Why is a device serial number useful in an IR case?

2. Why is device recognition not the same as proving file transfer?

3. Which non-Registry artifacts would best strengthen a "files copied to USB" theory?

---

### Task 4 — Focus on Remote Access and User Activity Keys

**Objective:** Identify Registry areas that help answer questions about user interaction and access behavior.

Assume the team wants to know whether the user or attacker interacted with suspicious files, folders, or remote-access features.

Fill in the table below.

| Registry Path or Area | What It Helps Answer | Why It Matters | Limitation |
|---|---|---|---|
| UserAssist | | | |
| TypedPaths | | | |
| RecentDocs | | | |
| Shell-related Explorer history areas | | | |
| RDP-related configuration areas | | | |

Add at least seven more relevant areas of your own.

Then answer:

1. Why is UserAssist useful for some execution questions but not all of them?

2. Why can Explorer history matter in staging or exfiltration cases?

3. Why should RDP-related Registry findings be correlated with logs before being treated as proof of remote access?

---

### Task 5 — Map IR Questions to the Right Keys

**Objective:** Practice going from question to key instead of from key to random browsing.

For each of the questions below, identify the Registry key or area you would check first and the one you would check second.

| Investigative Question | First Key / Area to Check | Second Key / Area to Check | Why |
|---|---|---|---|
| Was a suspicious EXE configured to launch at logon? | | | |
| Was a malicious service installed? | | | |
| Was a removable USB device connected? | | | |
| Did the user likely interact with a suspicious program through the GUI? | | | |
| Did the user browse to a suspicious folder path? | | | |
| Was the system configured for remote desktop access? | | | |
| Was a suspicious batch script likely tied to startup behavior? | | | |
| Which user hive is most relevant to Explorer activity? | | | |

Then write five additional IR questions of your own and map them the same way.

Afterward, answer:

1. Why is this question-to-key approach faster than browsing the Registry manually?

2. Why is it more defensible?

3. Why should a responder avoid checking only one key path for an important question?

---

### Task 6 — Separate Strong Findings from Overclaims

**Objective:** Practice disciplined reporting based on Registry evidence.

Read the statements below and classify each as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by these keys alone

| Statement | Classification | Why |
|---|---|---|
| A value referencing `C:\Users\j.smith\AppData\Roaming\updater.exe` exists in a Run key | | |
| `updater.exe` executed successfully at every logon | | |
| USBSTOR contains a record of a specific USB storage device | | |
| Files were definitely copied to that USB device | | |
| UserAssist contains an entry consistent with GUI interaction with a program | | |
| The user intentionally launched the program for malicious purposes | | |
| A service entry references a suspicious executable path | | |
| The service was used by the attacker for persistence | | |

Then write five additional statements of your own and classify them the same way.

> **Guidance:** Configuration clues are valuable, but they do not by themselves prove use, success, or intent. Keeping that distinction is one of the most important disciplines in Registry analysis.

---

### Task 7 — Build a Focused Registry Review Plan for HR-LT12

**Objective:** Turn key knowledge into a prioritized case workflow.

You have limited time and need to answer the case's main questions first.

Build a step-by-step Registry review plan for HR-LT12.

Use the table below.

| Priority | Question to Answer | Key / Area to Review | Why This Comes First | What You Expect to Learn |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |
| 6 | | | | |

Then answer:

1. Why did you choose this order?

2. Which questions are most urgent for scoping?

3. Which findings would cause you to escalate to deeper collection or broader host review?

---

### Task 8 — Write a Short "Important Keys" Analyst Note

**Objective:** Produce a case note that helps another responder start the right Registry review quickly.

Write a 2–3 paragraph analyst note for HR-LT12 explaining:

- Which Registry areas are highest priority for this case
- Which ones are most relevant to persistence, USB history, remote access, and user activity
- What those keys can help answer
- What they cannot prove by themselves

Write it as an internal working note another responder could rely on.

---

### Task 9 — Reflection

Answer the following in 3–5 sentences each.

**1. Why important keys matter**
Why is knowing the highest-value Registry paths such a force multiplier in incident response?

**2. Configuration versus action**
Why do important keys often tell you what the system was set up to do rather than what definitely happened?

**3. Key choice affects conclusions**
How can checking the wrong Registry area first waste time or distort the investigation?

**4. Correlation is still required**
Why are Registry key findings strongest when paired with NTFS, logs, Prefetch, and user-activity artifacts?

---

## Deliverables Checklist

Your `lab05-notes.md` should contain:

- [ ] **Task 1** — High-value Registry area table with eight added paths or areas
- [ ] **Task 2** — Persistence-key table with six added areas and written responses
- [ ] **Task 3** — USB/removable-media table with six added areas or supporting artifacts
- [ ] **Task 4** — Remote access and user-activity table with seven added areas
- [ ] **Task 5** — IR-question-to-key mapping with five added questions
- [ ] **Task 6** — Strongly supported vs overclaim exercise
- [ ] **Task 7** — Focused Registry review plan for HR-LT12
- [ ] **Task 8** — Important Keys analyst note
- [ ] **Task 9** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab05/
├── lab05-notes.md  ← Your working notes file (whole lab)
└── Lab05_02/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **Important keys save time.** In IR, knowing where to look first is often more valuable than knowing every possible key in Windows.
- **The Registry answers practical questions.** Persistence, services, USB history, user activity, and remote-access context often start here.
- **Configuration is not proof of action.** A Run key, service entry, or USB record is meaningful, but it still needs interpretation.
- **Question-driven analysis is stronger.** Mapping the case question to the right key path makes investigations faster and more defensible.
- **Registry findings grow in value through correlation.** Their strongest role is usually as part of a broader evidence picture.

---

**Next:** Lab 5.3 — Cloud Storage (OneDrive Example)

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
