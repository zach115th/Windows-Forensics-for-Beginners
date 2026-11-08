# Lab 6.5 — Removable Device Profiling

**Supporting Section 6.5: Removable Device Profiling**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Removable media is one of the most common and most misunderstood elements in Windows incident response.

A USB device can be completely benign: a headset dongle, a phone, a keyboard receiver, a legitimate backup drive, or a user's normal workflow. It can also be part of a compromise chain: a staging target, a delivery mechanism, a data-collection device, or an exfiltration path. The challenge for responders is not just finding that a device existed. It is determining what kind of device it was, when it was present, how it was used, and how strongly the endpoint evidence supports that interpretation.

This lab treats removable-device profiling as a disciplined forensic process. You will identify and characterize removable devices and distinguish connection from interaction. You will then correlate Registry, Shellbags, LNK files, Jump Lists, NTFS, and user-activity artifacts, and write careful findings without overstating what the evidence proves.

The goal is to build a defensible profile of device presence, likely user interaction, and possible relevance to the incident. Do not jump from "USBSTOR entry found" to "data was stolen."

---

## What This Lab Covers

This lab supports the following concepts from Section 6.5:

| Section | Topic |
|---|---|
| 6.5.1 | Identifying removable devices on Windows |
| 6.5.2 | Distinguishing device presence from user interaction |
| 6.5.3 | Correlating removable-device artifacts across Windows sources |
| 6.5 | Assessing the strength and limits of USB-related conclusions |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain the difference between removable-device recognition, use, and proven data transfer
- Identify the main Windows artifacts used to profile removable devices
- Extract useful device characteristics such as vendor, model, serial, and mount context
- Correlate Registry, Shellbag, LNK, Jump List, NTFS, and recent-item artifacts into a removable-device profile
- Distinguish benign device presence from incident-relevant removable-device activity
- Evaluate how strongly the evidence supports staging, browsing, or possible file movement
- Write concise, defensible notes about removable-device findings without overclaiming

---

## Estimated Time

75–105 minutes

---

## Prerequisites

- Completion of Labs 01–05 and Labs 06.1–6.4, or equivalent familiarity with Registry, NTFS, shell artifacts, execution evidence, and user-activity analysis
- A text editor or markdown editor
- Your `lab06-notes.md` file
- Optional: a Windows VM where you can connect test USB storage devices
- Optional: access to tools such as Registry Explorer, RECmd, SBECmd, LECmd, JLECmd, NTFS parsers, or other Windows forensic tooling

---

## Scenario

You are continuing analysis of **FIN-WS23**. Previous work suggests:

- A removable USB storage device may have been connected during the suspected incident window
- Sensitive documents may have been accessed shortly before suspicious activity
- There may have been staging activity in user-writable or temporary directories
- Management wants to know whether the endpoint evidence supports a removable-media theory

The specific question from leadership is:

> Do the artifacts suggest a removable device was merely connected, or do they support something more meaningful such as browsing, file access, or potential data movement?

Build the strongest defensible removable-device profile the available artifacts allow. You are not expected to prove exfiltration from endpoint evidence alone.

---

## Background: Device Presence Is Only the Beginning

Many Windows artifacts can contribute to removable-device analysis, but they answer different questions.

| Artifact Type | What It Helps Answer |
|---|---|
| **USBSTOR and related Registry keys** | Was a storage device recognized by the host? What vendor/model/serial appears? |
| **Mounted-device / volume artifacts** | How was the device mapped or mounted locally? |
| **Shellbags** | Was the device or one of its folders likely browsed in Explorer? |
| **LNK files / Jump Lists** | Were files likely opened from the device? |
| **RecentDocs / user activity artifacts** | Was the device-related content likely interacted with by the user? |
| **NTFS / staging artifacts** | Were files prepared, copied, or deleted around the same time? |
| **Timelines** | Did device presence line up with suspicious file activity? |

A disciplined responder separates these layers:

- Device recognized
- Device mounted
- Device browsed
- Files likely accessed from device
- Files possibly moved to or from device
- Intent or exfiltration — usually requires more than endpoint artifacts alone

> **IR Reality Check:** A USB record proves far less than many people think. The strength comes from correlation, timing, and path context.

---

## Lab Tasks

---

### Task 1 — Define What Removable Device Profiling Can and Cannot Tell You

**Objective:** Build a practical understanding of the scope and limits of USB-related analysis.

Write a short explanation in 4–6 sentences covering:

- What removable-device profiling means in Windows forensics
- Why device presence alone is not enough
- What artifacts can strengthen the case for actual interaction
- Why removable-device findings need cautious wording

```
[Your explanation here]
```

Then complete the table below.

| Investigative Question | Removable-Device Profiling Value | Why |
|---|---|---|
| Was a USB storage device recognized by the host? | | |
| Was the device likely mounted on the system? | | |
| Was a folder on that device likely browsed in Explorer? | | |
| Was a file definitely copied to the device? | | |
| Was a document likely opened from the device? | | |
| Was the device used for malicious exfiltration? | | |

Use the ratings:

- Strongly useful
- Partially useful
- Not very useful

Then answer:

**1. Why is device recognition a weaker conclusion than device interaction?**

```
[Your response here]
```

**2. Why is folder browsing a different claim from file copying?**

```
[Your response here]
```

**3. Why should responders be careful when management asks "was data taken on USB"?**

```
[Your response here]
```

---

### Task 2 — Identify the Best Artifact Sources for Removable Device Profiling

**Objective:** Map removable-device questions to the artifacts most likely to answer them.

For each question below, identify the best artifact or artifacts to check first.

| Investigative Question | Best Artifact(s) to Check First | Why |
|---|---|---|
| Was a USB storage device connected? | | |
| What vendor, model, or serial is associated with the device? | | |
| Was the device likely browsed in Explorer? | | |
| Were files likely opened from the device? | | |
| Did device activity align with suspicious staging activity? | | |
| Was the device associated with a drive letter or mount point? | | |
| Did the user likely interact with content on the device? | | |
| Was removable-media use relevant to the incident window? | | |

Then write six additional removable-device questions of your own and map them the same way.

Afterward, answer:

**1. Why do removable-device investigations almost always require more than one artifact type?**

```
[Your response here]
```

**2. Why is Registry evidence necessary but not sufficient?**

```
[Your response here]
```

**3. Why is timing correlation one of the most important parts of device profiling?**

```
[Your response here]
```

---

### Task 3 — Build a Device Identity Profile

**Objective:** Practice characterizing a removable device beyond "a USB was present."

Assume you found evidence of a USB storage device on FIN-WS23.

Build a device profile using the fields below.

| Device Profile Field | What You Would Look For | Why It Matters |
|---|---|---|
| Vendor | | |
| Model / product name | | |
| Serial number | | |
| Device class / type | | |
| First-seen or installation context | | |
| Last-seen or recent-use context | | |
| Volume or mount information | | |
| User context, if available | | |

Then answer:

**1. Why is the serial number often one of the most valuable fields?**

```
[Your response here]
```

**2. Why does device type matter when assessing incident relevance?**

```
[Your response here]
```

**3. Why would a storage device usually matter more than a non-storage USB peripheral in this case?**

```
[Your response here]
```

After that, create a focused review table:

| Device Characteristic | What Would Increase Concern |
|---|---|
| High-capacity storage device | |
| Recognized during the incident window | |
| Mounted with a drive letter | |
| Browsed through Explorer | |

Add at least six more characteristics of your own.

---

### Task 4 — Correlate Removable Device Evidence with Shellbags and Explorer Activity

**Objective:** Strengthen or challenge the theory that the device was actually browsed or used.

Fill in the table below.

| Correlation Pair | What the Device Artifact Shows | What Shell / Explorer Artifact Shows | Why the Combination Matters |
|---|---|---|---|
| USBSTOR + Shellbags | | | |
| Mounted-device evidence + Shellbags | | | |
| USB-related path + TypedPaths | | | |
| Device timing + Explorer history | | | |

Then answer:

**1. Why is a USB device record much stronger when paired with Shellbag evidence?**

```
[Your response here]
```

**2. Why does Explorer-related evidence help move the theory from "connected" toward "interacted with"?**

```
[Your response here]
```

**3. Why is browsing still weaker than proving file transfer?**

```
[Your response here]
```

---

### Task 5 — Correlate Removable Device Evidence with LNK, Jump Lists, and RecentDocs

**Objective:** Connect device presence to likely file access from that device.

Assume the case includes possible access to sensitive documents.

For each row below, explain how removable-device evidence would combine with recent-item artifacts.

| Correlation Pair | What the Device Artifact Contributes | What the Recent-Item Artifact Contributes | Why the Combination Matters |
|---|---|---|---|
| USB artifacts + LNK files | | | |
| USB artifacts + Jump Lists | | | |
| USB artifacts + RecentDocs | | | |
| USB artifacts + file-open timestamps | | | |
| USB artifacts + application association | | | |

Then answer:

**1. Why is "file opened from device path" stronger than "device connected"?**

```
[Your response here]
```

**2. Why can Jump Lists help identify which application was involved?**

```
[Your response here]
```

**3. Why should responders still avoid saying "data was exfiltrated" from this correlation alone?**

```
[Your response here]
```

---

### Task 6 — Correlate Removable Device Evidence with NTFS and Staging Activity

**Objective:** Assess whether device use lines up with suspicious file system activity.

Assume earlier NTFS work identified:

- A suspicious archive in Downloads
- Temporary staging activity in `C:\Temp`
- Sensitive documents accessed near the incident window

Fill in the table below.

| NTFS / Staging Lead | What You Would Correlate with Device Evidence | Why It Matters |
|---|---|---|
| Archive in Downloads | | |
| Temporary staging directory | | |
| Deleted files in staging path | | |
| Sensitive document access | | |
| Clustered file activity before or during device presence | | |

Then answer:

**1. Why is staging activity near the time of device use important?**

```
[Your response here]
```

**2. Why can deleted files become more interesting when a removable device is also present?**

```
[Your response here]
```

**3. Why should responders still distinguish "possible staging" from "confirmed copying"?**

```
[Your response here]
```

---

### Task 7 — Evaluate Competing Interpretations

**Objective:** Avoid overconfidence by testing benign explanations.

Choose two removable-device findings and write:

- One suspicious or incident-related interpretation
- One benign or less certain interpretation

Use the table below.

| Finding | Suspicious Interpretation | Benign / Alternate Interpretation | Which Is Better Supported? | Why |
|---|---|---|---|---|
| | | | | |
| | | | | |

Then answer:

**1. Why can normal business activity produce removable-device artifacts that look suspicious?**

```
[Your response here]
```

**2. Why is a USB storage device not automatically evidence of wrongdoing?**

```
[Your response here]
```

**3. Why is alternate-explanation analysis especially important before involving leadership, HR, or legal?**

```
[Your response here]
```

---

### Task 8 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined reporting about removable-device activity.

Classify each statement below as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by these artifacts alone

| Statement | Classification | Why |
|---|---|---|
| A USB storage device was recognized by the host | | |
| The device was likely browsed through Explorer | | |
| A document was likely opened from the device | | |
| Sensitive files were definitely copied to the device | | |
| The device was relevant to the incident window | | |
| The user intentionally used the device for data theft | | |
| Device timing and staging activity make USB use worthy of deeper review | | |
| Removable media was the only plausible exfiltration path | | |

Then write six additional statements of your own and classify them the same way.

> **Guidance:** USB profiling is often persuasive. It is not a shortcut to certainty.

---

### Task 9 — Build a Removable-Device Timeline

**Objective:** Turn device, shell, and file-related findings into a usable sequence.

Create a mini-timeline with at least twelve entries if possible.

| Time (UTC) | Artifact Source | Event or Observation | Device / Path / File | Why It Matters |
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

Your timeline may include:

- Device recognition
- Mount or drive-letter association
- Explorer browsing of device paths
- Recent-item evidence tied to device files
- Staging activity on local disk
- File-open or document-access evidence
- Deletion or cleanup around device presence
- Correlated cloud or network activity if relevant

Then answer:

**1. Which entries appear most central to the removable-device theory?**

```
[Your response here]
```

**2. Which entries are supportive but not decisive?**

```
[Your response here]
```

**3. What major gaps remain after the timeline is built?**

```
[Your response here]
```

---

### Task 10 — Write a Removable Device Findings Summary

**Objective:** Produce a concise working-note summary suitable for the case file.

Write a 3–5 paragraph analyst summary describing what the removable-device artifacts suggest about activity on FIN-WS23.

Your summary should include:

- The most important device-identification findings
- Whether the evidence supports connection, browsing, likely file access, or something stronger
- Whether the timing aligns with staging or sensitive-file activity
- What is strongly supported by the evidence
- What still requires corroboration from logs, file system analysis, cloud artifacts, or other sources

Write it as a working-note summary, not a final incident conclusion.

---

### Task 11 — Write an Analyst Handoff Note

**Objective:** Make your removable-device findings easy for another responder to continue.

Use the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Most Important Device Findings:
- 

Most Important Correlated Artifact Findings:
- 

What Is Strongly Supported:
- 

What Is Suggested but Not Confirmed:
- 

Recommended Next Artifacts:
1.
2.
3.

Open Questions:
- 

Notes for Incoming Analyst:
```

---

### Task 12 — Reflection

Answer the following in 3–5 sentences each.

**1. Why removable-device profiling matters**
Why is it important to profile the device itself instead of just saying "a USB was connected"?

```
[Your response here]
```

**2. Connection versus copying**
Why is it so important to separate device connection, browsing, file access, and confirmed data transfer?

```
[Your response here]
```

**3. Correlation is the real value**
Why are removable-device conclusions strongest when Registry, Shellbags, LNK files, Jump Lists, NTFS, and timelines agree?

```
[Your response here]
```

**4. Caution in high-stakes conclusions**
Why should responders be especially careful before stating that removable media was used for exfiltration or insider theft?

```
[Your response here]
```

---

## Deliverables Checklist

Your `lab06-notes.md` should contain:

- [ ] **Task 1** — Removable-device profiling explanation and usefulness ratings table
- [ ] **Task 2** — Question-to-artifact mapping with six added questions
- [ ] **Task 3** — Device identity profile table and expanded concern table
- [ ] **Task 4** — Shellbag / Explorer correlation table with written responses
- [ ] **Task 5** — LNK / Jump List / RecentDocs correlation table
- [ ] **Task 6** — NTFS and staging correlation table with written responses
- [ ] **Task 7** — Competing-interpretation analysis for two findings
- [ ] **Task 8** — Strong support vs overclaim exercise
- [ ] **Task 9** — Removable-device timeline with at least 12 entries where possible
- [ ] **Task 10** — Removable-device findings summary
- [ ] **Task 11** — Analyst handoff note
- [ ] **Task 12** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab06/
├── lab06-notes.md  ← Your working notes file (whole lab)
└── Lab06_05/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **A USB record is only the start.** Good removable-device profiling goes beyond presence to identity, browsing, access, and timing.
- **Device presence is not file transfer.** Connection, browsing, file open, and copying are separate conclusions with different evidentiary weight.
- **Correlation is essential.** Registry, Shellbags, LNK files, Jump Lists, NTFS, and timing together create the strongest removable-device story.
- **Alternate explanations matter.** Many removable-device artifacts can come from legitimate business activity.
- **High-stakes conclusions require discipline.** Claim exfiltration or insider theft only when the evidence supports it.

---

**Next:** Lab 07 — Memory Forensics

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
