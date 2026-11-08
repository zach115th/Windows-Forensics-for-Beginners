# Lab 6.2 — Shellbags

**Supporting Section 6.2: Shellbags**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Files tell you what existed. Execution artifacts tell you what likely ran. Shellbags help answer a different question:

> What folders were likely browsed through the Windows shell?

In many incidents, the most important user or attacker activity is not just the execution of a tool. It is the navigation that happened around it: browsing to a USB drive, opening a network share, exploring a staging directory, or drilling into a cloud-sync path containing sensitive files. Even when those folders no longer exist, Windows can preserve evidence that they were viewed through Explorer.

This lab focuses on Shellbags as a source of folder-navigation evidence in Windows incident response. You will work through what Shellbags are, what kinds of questions they help answer, and how they differ from file-execution artifacts. You will also correlate them with removable-device, network-share, and user-activity evidence without overstating what they prove.

The goal is to make you comfortable using Shellbags as part of a broader behavioral reconstruction of how a user or attacker moved through the Windows environment, not to treat them as a niche artifact.

---

## What This Lab Covers

This lab supports the following concepts from Section 6.2:

| Section | Topic |
|---|---|
| 6.2.1 | What Shellbags Record |
| 6.2.2 | Why Shellbags Matter |
| 6.2.3 | Limits and Gotchas |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain what Shellbags are in practical forensic terms
- Identify the kinds of folder-navigation questions Shellbags help answer
- Distinguish folder browsing evidence from file-open or execution evidence
- Use Shellbags to assess likely interaction with USB devices, network shares, and staging paths
- Recognize why deleted or no-longer-mounted paths can still matter
- Correlate Shellbag findings with Registry, LNK, Jump List, USB, and NTFS artifacts
- Write concise, defensible notes about folder-navigation evidence

---

## Estimated Time

60–90 minutes

---

## Prerequisites

- Completion of Labs 01–05 and Lab 06.1, or equivalent familiarity with Windows IR workflow, Registry, NTFS, shell artifacts, and execution analysis
- A text editor or markdown editor
- Your `lab06-notes.md` file
- Optional: a Windows VM where you can generate folder-browsing activity
- Optional: access to tools such as SBECmd, Registry Explorer, RECmd, or other Shellbag parsers

---

## Scenario

You are continuing analysis of **FIN-WS23**. Earlier review identified:

- A suspicious executable may have existed in Downloads
- A removable USB device may have been connected during the incident window
- Sensitive documents may have been opened shortly before suspicious activity
- There are signs that the user or attacker may have interacted with multiple storage locations, including local folders and possibly removable media

The SOC now wants to answer a behavior-focused question:

> Which folders were likely browsed through Explorer, and do those paths support a theory of staging, removable-media use, or sensitive-file access?

You are not expected to prove copying or exfiltration from Shellbags alone. Your task is to use Shellbags to determine what folder-navigation activity is most strongly supported and what it means in context.

---

## Background: Shellbags Show Folder Navigation, Not File Execution

Shellbags are Registry-based artifacts that preserve information about folders viewed through the Windows shell, primarily Explorer. They can retain evidence of local, removable, and network paths even after the underlying folder is gone.

For incident responders, Shellbags help answer questions such as:

- Did the user or attacker likely browse to a removable drive?
- Was a suspicious staging folder viewed in Explorer?
- Was a network share explored?
- Did the user navigate into a cloud-sync path containing sensitive documents?

Shellbags are valuable because folder browsing is often part of attacker workflow:

- Exploring a USB drive before copying files
- Navigating to Downloads after a file arrives
- Opening `C:\Temp` or ProgramData during staging
- Browsing a network share before accessing or collecting data
- Navigating into OneDrive or another sync-root path

| Artifact | What It Helps Answer |
|---|---|
| **Shellbags** | Which folders were likely browsed in Explorer |
| **LNK / Jump Lists** | Which files were likely opened and by what application |
| **Prefetch / logs** | Which programs likely executed |
| **USB / mount artifacts** | Which devices were connected and recognized |

> **IR Reality Check:** Browsing a folder is not the same as opening a file, copying data, or executing a program. Shellbags are strongest when used to show path interaction and navigation context.

---

## Lab Tasks

---

### Task 1 — Define What Shellbags Can and Cannot Tell You

**Objective:** Build a practical understanding of Shellbags as a folder-navigation artifact.

Write a short explanation in 4–6 sentences covering:

- What Shellbags are
- What kinds of activity they commonly reflect
- Why they matter in incident response
- What they do not prove by themselves

```
[Your explanation here]
```

Then complete the table below.

| Investigative Question | Shellbag Value | Why |
|---|---|---|
| Was a folder likely browsed in Explorer? | | |
| Was a USB-backed path likely viewed? | | |
| Was a file definitely copied from that folder? | | |
| Was a network share likely browsed? | | |
| Was a suspicious executable definitely run from that folder? | | |
| Did a cloud-sync path likely appear in Explorer navigation? | | |

Use the ratings:

- Strongly useful
- Partially useful
- Not very useful

Then answer:

**1. Why is folder-navigation evidence valuable even when it does not prove file copying?**

```
[Your response here]
```

**2. Why can Shellbags still matter when a USB drive is no longer connected?**

```
[Your response here]
```

**3. Why should responders avoid turning "folder was browsed" into a stronger claim than the artifact supports?**

```
[Your response here]
```

---

### Task 2 — Identify High-Value Paths for Shellbag Review

**Objective:** Focus Shellbag analysis on the paths most relevant to incident response.

List the folder paths or path types you would prioritize in Shellbag review for FIN-WS23.

Fill in the table below.

| Folder or Path Type | Why It Is High-Value | Example of Why It Might Matter |
|---|---|---|
| `C:\Users\j.smith\Downloads\` | | |
| `C:\Temp\` | | |
| `C:\ProgramData\` | | |
| USB volume paths | | |
| Network share paths | | |
| OneDrive or sync-root path | | |

Add at least eight more path types of your own.

Then answer:

**1. Why do writable directories often matter in Shellbag review?**

```
[Your response here]
```

**2. Why can browsing a network share be just as important as browsing a local disk?**

```
[Your response here]
```

**3. Why should path context matter more than the fact that a folder was opened at all?**

```
[Your response here]
```

---

### Task 3 — Review Shellbag Findings for Suspicious Navigation

**Objective:** Identify which folder-navigation findings deserve follow-up.

Use a real dataset if you have one. If you do not, describe the exact workflow you would use.

Your task is to identify at least six Shellbag findings or candidate paths that would stand out during this case.

| Shellbag Finding | Path | Why It Stands Out | What It Might Suggest | What It Does Not Prove |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

Possible areas of focus include:

- Downloads
- Temp or staging directories
- OneDrive paths
- USB-backed folder structures
- Network-share browsing
- User profile folders containing sensitive files
- Short-lived or unusual folder names

Then answer:

**1. Why might a staging folder in ProgramData be important even if no file remains there?**

```
[Your response here]
```

**2. Why is a removable-device path in Shellbags often more meaningful when paired with USB Registry artifacts?**

```
[Your response here]
```

**3. Why should a responder care if multiple suspicious folders appear in the same general time window?**

```
[Your response here]
```

---

### Task 4 — Correlate Shellbags with Removable-Device Evidence

**Objective:** Use Shellbags to strengthen or challenge a removable-media theory.

Assume a USB storage device may have been involved.

Fill in the table below.

| Question | Best Supporting Artifact(s) | What a Stronger Case Would Look Like |
|---|---|---|
| Was a USB device connected? | | |
| Was that device likely browsed in Explorer? | | |
| Were files likely accessed from that device? | | |
| Was the device used during the same time window as suspicious staging activity? | | |
| Do the folder paths suggest access to likely collection targets? | | |

Then answer:

**1. Why is USB connection only the beginning of the analysis?**

```
[Your response here]
```

**2. Why do Shellbags improve the removable-device story without proving data transfer?**

```
[Your response here]
```

**3. What additional artifacts would you want before concluding files were likely copied to or from the device?**

```
[Your response here]
```

---

### Task 5 — Correlate Shellbags with LNK, Jump Lists, and RecentDocs

**Objective:** Connect folder browsing to likely file interaction.

Assume the case involves sensitive documents and suspicious user activity.

For each row below, explain how Shellbags would work with other artifacts.

| Correlation Pair | What Shellbags Contribute | What the Other Artifact Contributes | Why the Combination Matters |
|---|---|---|---|
| Shellbags + LNK files | | | |
| Shellbags + Jump Lists | | | |
| Shellbags + RecentDocs | | | |
| Shellbags + TypedPaths | | | |
| Shellbags + OneDrive path evidence | | | |

Then answer:

**1. Why is "folder browsed" stronger when paired with "file likely opened"?**

```
[Your response here]
```

**2. Why can Jump Lists help narrow which application was involved after a folder was viewed?**

```
[Your response here]
```

**3. Why should responders still keep access, browsing, and execution separate in their notes?**

```
[Your response here]
```

---

### Task 6 — Evaluate Competing Interpretations

**Objective:** Avoid overconfidence by considering alternate explanations for folder navigation.

Choose two Shellbag findings that appear suspicious and write:

- One suspicious or incident-related interpretation
- One benign or less certain interpretation

Use the table below.

| Shellbag Finding or Path | Suspicious Interpretation | Benign / Alternate Interpretation | Which Is Better Supported? | Why |
|---|---|---|---|---|
| | | | | |
| | | | | |

Then answer:

**1. Why can normal user behavior sometimes create Shellbag patterns that look suspicious?**

```
[Your response here]
```

**2. Why is browsing a folder weaker than opening a file from it?**

```
[Your response here]
```

**3. Why is alternative-explanation analysis especially important before briefing leadership?**

```
[Your response here]
```

---

### Task 7 — Separate Strong Findings from Overclaims

**Objective:** Practice disciplined reporting based on Shellbag evidence.

Classify each statement below as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by Shellbags alone

| Statement | Classification | Why |
|---|---|---|
| A USB-backed folder path was likely browsed in Explorer | | |
| Files were definitely copied from that USB device | | |
| A OneDrive-related path was likely navigated through Explorer | | |
| Sensitive files in that path were uploaded to the cloud | | |
| A suspicious staging folder likely existed and was browsed | | |
| The user intentionally staged data for exfiltration | | |
| A network share path was likely viewed on the host | | |
| The attacker used Explorer to identify target documents | | |

Then write six additional statements of your own and classify them the same way.

> **Guidance:** Shellbags are valuable context artifacts. They are not proof of motive, copying, or attacker intent by themselves.

---

### Task 8 — Build a Folder-Navigation Timeline

**Objective:** Turn Shellbag findings into an ordered sequence useful for IR analysis.

Create a mini-timeline with at least 10 entries if possible.

| Time (UTC) | Artifact Source | Event or Observation | Path | Why It Matters |
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

Your timeline may include:

- Browsing of Downloads
- Navigation into suspicious temp or staging paths
- USB-backed folder navigation
- Network-share browsing
- Cloud-sync path interaction
- Correlated LNK or Jump List activity
- Time clustering with execution artifacts

Then answer:

**1. Which timeline entries appear most central to the incident theory?**

```
[Your response here]
```

**2. Which entries may be supportive but not central?**

```
[Your response here]
```

**3. What major gaps remain after building the timeline?**

```
[Your response here]
```

---

### Task 9 — Write a Shellbag Findings Summary

**Objective:** Produce a concise working-note summary focused on folder-navigation evidence.

Write a 3–5 paragraph analyst summary describing what the Shellbag and correlated folder-navigation evidence suggests about activity on FIN-WS23.

Your summary should include:

- The most important folder paths identified
- Whether removable, network, local staging, or cloud-related paths appear relevant
- What is strongly supported by Shellbags
- What is only suggested when correlated with other artifacts
- What still requires additional evidence before stronger conclusions can be made

Write it as a working-note summary rather than a final incident conclusion.

---

### Task 10 — Write an Analyst Handoff Note

**Objective:** Make your Shellbag findings easy for another responder to continue.

Use the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Most Important Shellbag Findings:
- 

Most Important Folder Paths:
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

### Task 11 — Reflection

Answer the following in 3–5 sentences each.

**1. Why Shellbags matter**
Why is folder-navigation evidence useful even when it does not directly prove file access or copying?

```
[Your response here]
```

**2. Removable and network context**
Why are Shellbags especially valuable in USB, network-share, and cloud-folder investigations?

```
[Your response here]
```

**3. Browsing versus action**
Why should responders clearly separate "folder was viewed" from "files were copied or executed"?

```
[Your response here]
```

**4. Correlation is the real value**
Why are Shellbags strongest when paired with LNK files, Jump Lists, USB artifacts, NTFS, and user-activity evidence?

```
[Your response here]
```

---

## Deliverables Checklist

Your `lab06-notes.md` should contain:

- [ ] **Task 1** — Shellbag explanation and usefulness ratings table
- [ ] **Task 2** — High-value-path table with eight added path types
- [ ] **Task 3** — Shellbag findings table with at least six entries or a clearly described workflow
- [ ] **Task 4** — Removable-device correlation table with written responses
- [ ] **Task 5** — Correlation table for Shellbags with other artifacts
- [ ] **Task 6** — Competing-interpretation analysis for two findings
- [ ] **Task 7** — Strongly supported vs overclaim exercise
- [ ] **Task 8** — Folder-navigation timeline with at least 10 entries where possible
- [ ] **Task 9** — Shellbag findings summary
- [ ] **Task 10** — Analyst handoff note
- [ ] **Task 11** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab06/
├── lab06-notes.md  ← Your working notes file (whole lab)
└── Lab06_02/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **Shellbags show navigation context.** They help answer which folders were likely browsed through Explorer.
- **Folder browsing is not file copying or execution.** Good responders keep those distinctions clear.
- **Deleted or unavailable paths can still matter.** Shellbags may preserve folder history even when the underlying location is gone.
- **USB, network, and cloud investigations benefit from Shellbags.** These artifacts help show whether those paths were actually navigated.
- **Correlation gives Shellbags their real value.** They are strongest when combined with USB artifacts, LNK files, Jump Lists, NTFS, and other user-activity evidence.

---

**Next:** Lab 6.3 — UserAssist and Amcache

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
