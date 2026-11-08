# Lab 06 — Shell Items, Removable Devices, and Application Artifacts

**Supporting [Chapter 6: Shell Items, Removable Devices, and Application Artifacts](../../Book/Chapter06.md)**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Attackers do not just leave behind malware. They leave behind evidence of how they interacted with the system.

Windows often preserves traces showing that a folder was browsed, a file was opened, a program executed, or a removable device was connected. Those traces can remain after a suspicious executable is deleted, a USB drive is gone, or a staged document is moved or renamed. They live in artifacts such as LNK files, Jump Lists, Prefetch, SRUM, Shellbags, UserAssist, Amcache, browser history, and related user-activity evidence.

This lab uses those artifacts together, from an incident response perspective, rather than treating each one as an isolated curiosity. Together they answer practical questions: Which files were likely opened? Which programs ran? Did the user browse a USB device or network share? Was a removable device involved in staging or collection? Is there evidence consistent with phishing, cloud access, or user-driven file movement?

By the end of this lab, you should be comfortable treating shell and application artifacts as part of a larger behavior trail rather than as standalone forensic trivia.

---

## What This Lab Covers

This lab supports the following sections from Chapter 6:

| Section | Topic |
|---|---|
| 6.1 | Evidence of Execution |
| 6.1.1 | LNK (Shortcut) Files |
| 6.1.2 | Jump Lists |
| 6.1.3 | Prefetch |
| 6.1.4 | SRUM |
| 6.2 | Shellbags |
| 6.3 | UserAssist and Amcache |
| 6.4 | Browser, Email, and Search Index |
| 6.5 | Removable Device Profiling |
| 6.6 | WSL2 as a Hiding Place |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain the forensic value of common Windows shell and application artifacts
- Identify which artifacts help answer file-open, execution, browsing, and removable-device questions
- Distinguish between evidence of file presence, evidence of execution, and evidence of user interaction
- Use LNK files, Jump Lists, Prefetch, SRUM, Shellbags, UserAssist, and Amcache in a coordinated way
- Assess whether a removable device was likely involved in staging or data movement
- Correlate shell and application artifacts into a short behavioral timeline
- Write concise, defensible notes that stay within what the artifacts actually support

---

## Estimated Time and Difficulty

**Difficulty:** Intermediate

**First time through the material:** 3–5 h

**Refresh (already familiar with the chapter):** 90–120 min

> **Key terms used in this lab:** LNK files, Jump Lists, Prefetch, Shellbags, UserAssist, Amcache, SRUM. See the consolidated [Glossary](../../Book/Glossary.md) for definitions. The chapter cross-references in each entry take you back to the deeper coverage in `Book/`.

---

## Prerequisites

- Completion of Labs 01–05, or equivalent familiarity with Windows IR workflow, NTFS, Registry, and cloud/client artifacts
- A text editor or markdown editor
- Your `lab06-notes.md` file
- Optional: a Windows VM where you can generate test activity
- Optional: access to tools such as LECmd, JLECmd, PECmd, SrumECmd, SBECmd, Amcache parsers, Registry Explorer, or similar utilities

> **Working without a VM:** Pre-parsed CSV outputs for the FIN-WS23 scenario are in [`Data/FIN-WS23/`](../../Data/FIN-WS23/). Use `lnk-files.csv`, `jump-lists.csv`, `prefetch.csv`, `amcache.csv`, `srum.csv`, `userassist.csv`, `shellbags.csv`, `browser-history.csv`, and `usbstor.csv` for this lab's exercises if you are not generating your own activity.

---

## Scenario

You are investigating a Windows workstation named **FIN-WS23** after an alert involving suspicious PowerShell activity and possible data staging. Earlier review established the following:

- A suspicious executable may have been present in the user's Downloads folder
- There are indications that files may have been copied to removable media
- The user may have opened sensitive documents shortly before the suspected incident window
- A USB storage device may have been connected recently
- Management wants to know whether the system shows signs of tool staging, document access, and removable-media involvement

Logs alone have not given you a complete answer. Your task is to use shell items, removable-device artifacts, and application artifacts to determine what the user or attacker likely interacted with, what appears to have executed, and how those findings fit into the case.

---

## Background: These Artifacts Show Behavior, Not Just Presence

NTFS and Registry artifacts tell you a great deal about files and configuration. Shell and application artifacts help answer a different class of questions:

- Was a file likely opened?
- Which application opened it?
- Did a program execute from a suspicious path?
- Which folders were browsed?
- Was a removable device explored through Explorer?
- Which processes used network resources?
- Did the user interact with a specific document, archive, or USB path?

Incident response often depends on reconstructing behavior, not just identifying artifacts in isolation.

| Artifact | Common IR Use |
|---|---|
| **LNK files** | Recent file access, target paths, removable or network locations |
| **Jump Lists** | File access by specific applications |
| **Prefetch** | Program execution evidence and referenced paths |
| **SRUM** | Application resource and network usage patterns |
| **Shellbags** | Folder browsing history, including removable and network locations |
| **UserAssist** | GUI-driven program interaction |
| **Amcache** | Evidence of executable presence and execution-related metadata |
| **Browser / email / search artifacts** | Phishing, downloads, file access context, cloud access clues |
| **USB profiling artifacts** | Device identification, volume correlation, mount history |

> **IR Reality Check:** No single shell artifact proves the whole case. Their strength comes from correlation: file access, program execution, folder navigation, and removable-device evidence all reinforcing one another.

---

## Lab Tasks

---

### Task 1 — Identify Which Artifacts Answer Which Questions

**Objective:** Map common IR questions to the shell and application artifacts most likely to answer them.

For each investigative question below, identify the best artifact or artifacts to review first.

| Investigative Question | Best Artifact(s) to Check First | Why |
|---|---|---|
| Was a suspicious EXE likely executed? | | |
| Did the user likely open a sensitive document? | | |
| Was a folder on removable media browsed in Explorer? | | |
| Which program opened a particular file? | | |
| Did a process use unusual network resources? | | |
| Was a specific archive or document accessed from Downloads? | | |
| Was a removable device likely involved in file staging? | | |
| Did the user interact with a suspicious program through the GUI? | | |

Then write six additional investigative questions of your own and map them the same way.

Afterward, answer:

**1. Why is this question-to-artifact approach better than parsing everything at once?**

```
[Your response here]
```

**2. Why do some questions require multiple artifacts rather than one?**

```
[Your response here]
```

**3. Why is "evidence of execution" different from "evidence of file presence"?**

```
[Your response here]
```

---

### Task 2 — Review LNK Files and Jump Lists

**Objective:** Use shortcut and recent-item artifacts to identify likely file access and path context.

Assume you are trying to determine whether the user accessed suspicious files or staged documents shortly before the incident.

Fill in the table below.

| Artifact Type | What It Can Reveal | Why It Matters | Limitation |
|---|---|---|---|
| LNK files | | | |
| Automatic Jump Lists | | | |
| Custom Jump Lists | | | |

Then answer:

**1. Why are LNK files useful when the original file has been deleted or moved?**

```
[Your response here]
```

**2. Why do Jump Lists help tie a file to a specific application?**

```
[Your response here]
```

**3. Why should you be careful not to overstate what a shortcut proves by itself?**

```
[Your response here]
```

After that, create a working table for likely findings you would want to extract:

| Item of Interest | Path or File | Artifact Source | Why It Would Matter |
|---|---|---|---|
| Suspicious EXE in Downloads | | | |
| Sensitive document | | | |
| Removable-media path | | | |
| Network share path | | | |

Add at least four more items of your own.

---

### Task 3 — Review Prefetch and Amcache

**Objective:** Identify evidence of execution and executable context.

Assume you need to know whether suspicious tools likely executed on FIN-WS23.

Fill in the table below.

| Artifact | What It Can Reveal | Why It Matters in IR | Limitation |
|---|---|---|---|
| Prefetch | | | |
| Amcache | | | |

Then answer:

**1. Why is Prefetch often one of the first artifacts responders check for execution?**

```
[Your response here]
```

**2. Why is Amcache useful even when Prefetch is unavailable or incomplete?**

```
[Your response here]
```

**3. Why should a responder avoid claiming too much from one execution artifact alone?**

```
[Your response here]
```

Next, build a focused review table:

| Suspected Program or File | Artifact to Check | What Finding Would Increase Concern |
|---|---|---|
| `tool.exe` in Downloads | | |
| `runme.bat` in ProgramData | | |
| PowerShell | | |
| Archive extractor or scripting tool | | |

Add at least five more entries of your own.

---

### Task 4 — Review SRUM and UserAssist

**Objective:** Use system resource usage and user-interaction artifacts to assess behavior.

Assume the team wants to know whether suspicious processes used network resources and whether the user likely launched programs interactively.

Fill in the table below.

| Artifact | What It Helps Answer | Why It Matters | Limitation |
|---|---|---|---|
| SRUM | | | |
| UserAssist | | | |

Then answer:

**1. Why is SRUM especially useful in exfiltration or beaconing investigations?**

```
[Your response here]
```

**2. Why is UserAssist helpful for GUI-driven user behavior but incomplete for execution analysis overall?**

```
[Your response here]
```

**3. Why might SRUM and Prefetch together be stronger than either one alone?**

```
[Your response here]
```

After that, identify at least six behavior patterns you would look for using these artifacts.

| Behavior Pattern | Artifact(s) to Use | Why It Matters |
|---|---|---|
| Suspicious process with network usage | | |
| GUI launch of suspicious program | | |
| Unexpected resource usage by an application | | |
| | | |
| | | |
| | | |

---

### Task 5 — Review Shellbags and Folder Navigation Evidence

**Objective:** Determine whether folders on local disks, removable devices, or network shares were browsed.

Assume you are trying to determine whether the user or attacker browsed to a removable device or staging path.

Fill in the table below.

| Artifact | What It Can Reveal | Why It Matters | Limitation |
|---|---|---|---|
| Shellbags | | | |
| Explorer-related history | | | |
| Typed paths | | | |

Then answer:

**1. Why are Shellbags useful even when the underlying folder no longer exists?**

```
[Your response here]
```

**2. Why can folder-browsing evidence matter in a removable-media case?**

```
[Your response here]
```

**3. Why is browsing a folder different from proving a file was copied?**

```
[Your response here]
```

Next, identify likely folders or path types you would want to check.

| Folder or Path Type | Why It Is Relevant |
|---|---|
| USB volume path | |
| OneDrive or sync-root path | |
| Downloads | |
| Desktop | |

Add at least six more of your own.

---

### Task 6 — Profile Removable Device Involvement

**Objective:** Correlate removable-device evidence with shell and application artifacts.

Assume a USB device may have been involved in staging or data transfer.

For this task, combine what you would expect from:

- Registry-based USB history
- Shellbags
- LNK files
- Jump Lists
- RecentDocs
- NTFS artifacts
- Any supporting timeline evidence

Fill in the table below.

| Question | Best Artifact(s) | What Would Strengthen the Theory |
|---|---|---|
| Was a USB storage device connected? | | |
| Was the device browsed in Explorer? | | |
| Were files likely opened from the device? | | |
| Were suspicious files staged near the same time? | | |
| Is there evidence consistent with file movement involving removable media? | | |

Then answer:

**1. Why is device connection only the starting point in a removable-media investigation?**

```
[Your response here]
```

**2. Why is correlation between device artifacts and file-access artifacts so important?**

```
[Your response here]
```

**3. What additional evidence would you want before briefing leadership that removable media was likely involved?**

```
[Your response here]
```

---

### Task 7 — Correlate Browser, Email, and Search Artifacts

**Objective:** Tie document access and suspicious execution to possible delivery or user behavior.

Assume the broader case theory includes phishing or user-initiated download activity.

Fill in the table below.

| Artifact Source | What It May Reveal | Why It Matters |
|---|---|---|
| Browser history | | |
| Browser downloads | | |
| Email artifacts or mail client clues | | |
| Search index or related search evidence | | |
| RecentDocs / LNK correlation | | |

Add at least five more relevant supporting artifacts or sub-artifacts of your own.

Then answer:

**1. Why can browser and email artifacts be critical in determining initial access?**

```
[Your response here]
```

**2. Why is download evidence helpful when paired with Prefetch or Jump Lists?**

```
[Your response here]
```

**3. Why should responders be cautious about assuming the user knowingly caused the event?**

```
[Your response here]
```

---

### Task 8 — Build a Behavioral Timeline

**Objective:** Turn shell, application, and removable-device findings into a usable incident sequence.

Create a mini-timeline with at least 12 entries if possible.

| Time (UTC) | Artifact Source | Event or Observation | File / Path / Device | Why It Matters |
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

- File download or arrival
- Document open activity
- Program execution
- Folder browsing
- USB connection or browsing
- Network-usage indicators
- Recent item creation
- Sync-root or cloud-related path interaction

Then answer:

**1. Which entries appear most central to the case theory?**

```
[Your response here]
```

**2. Which entries may be supportive but not central?**

```
[Your response here]
```

**3. What gaps remain after this timeline?**

```
[Your response here]
```

---

### Task 9 — Separate Strong Support from Overclaims

**Objective:** Practice reporting only what the artifacts actually support.

Classify each statement below as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by these artifacts alone

| Statement | Classification | Why |
|---|---|---|
| A suspicious executable likely executed on the host | | |
| The user opened a document from a removable device | | |
| The removable device was used to copy sensitive files off the system | | |
| A folder associated with a USB device was browsed in Explorer | | |
| A program showed network-usage patterns worth further review | | |
| The user intentionally exfiltrated data | | |
| A specific application likely opened a particular document | | |
| A suspicious archive in Downloads was part of the incident chain | | |

Then write six additional statements of your own and classify them the same way.

> **Guidance:** This chapter is full of artifacts that strongly suggest behavior. The discipline is in separating likely interaction from proven intent or outcome.

---

### Task 10 — Write a Shell and Application Artifact Summary

**Objective:** Produce a concise working-note summary suitable for the case file.

Write a 3–5 paragraph analyst summary describing what the shell, removable-device, and application artifacts suggest about activity on FIN-WS23.

Your summary should include:

- The most important execution-related findings
- The most important file-open or document-access findings
- Whether a removable device appears to have been involved
- What is strongly supported by the evidence
- What still requires corroboration from logs, NTFS, Registry, cloud artifacts, or provider-side evidence

Write it as a working-note summary, not a final incident conclusion.

---

### Task 11 — Write an Analyst Handoff Note

**Objective:** Make your findings easy for another responder to continue.

Use the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Most Important Shell / Application Findings:
- 

Most Important Removable-Device Findings:
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

**1. Why these artifacts matter**
Why are shell and application artifacts so useful in incident response compared with relying only on logs or file listings?

```
[Your response here]
```

**2. User interaction versus execution**
Why is it important to distinguish between a file being present, a file being opened, and a program being executed?

```
[Your response here]
```

**3. Removable-device caution**
Why should responders avoid claiming USB exfiltration too early, even when a device and suspicious files both appear in the case?

```
[Your response here]
```

**4. Correlation is the real value**
Why are LNK, Jump Lists, Prefetch, SRUM, Shellbags, and Registry artifacts strongest when used together?

```
[Your response here]
```

---

## Hands-On Walkthrough (Using Simulated Data)

This walkthrough exercises Tasks 2–7 against the pre-parsed shell-artifact data in [`Data/FIN-WS23/`](../../Data/FIN-WS23/). Commands are PowerShell. The same operations work in Python or in a spreadsheet.

### Step 1 — Find the suspicious binary in Prefetch

Sorting by `LastRun` ascending returns the oldest entries first, which surfaces routine binaries that simply haven't run recently. The cleaner filter is "single-run binaries that ran in the last few days," the textbook "this is new on this host" pattern:

```powershell
$pf = Import-Csv 'Data\FIN-WS23\prefetch.csv'
$pf | Where-Object {
        [int]$_.RunCount -eq 1 -and
        [DateTime]$_.LastRun -ge [DateTime]"2024-11-12 00:00:00"
      } |
      Sort-Object LastRun |
      Select-Object ExecutableName, RunCount, LastRun
```

```python
import csv
with open('Data/FIN-WS23/prefetch.csv') as f:
    pf = list(csv.DictReader(f))
hits = [r for r in pf if int(r['RunCount']) == 1 and r['LastRun'] >= "2024-11-12 00:00:00"]
hits.sort(key=lambda r: r['LastRun'])
for r in hits:
    print(r['ExecutableName'], r['RunCount'], r['LastRun'])
```

Expected: a single row — `DL.EXE` with `LastRun=2024-11-13 06:59:14` and `RunCount=1`.

### Step 2 — Pull the binary's hash from Amcache

```powershell
$am = Import-Csv 'Data\FIN-WS23\amcache.csv'
$am | Where-Object { $_.FullPath -like "*dl.exe" } |
      Select-Object FullPath, Sha1, Created, LastModified
```

```python
with open('Data/FIN-WS23/amcache.csv') as f:
    am = list(csv.DictReader(f))
for r in am:
    if r['FullPath'].lower().endswith("dl.exe"):
        print(r['FullPath'], r['Sha1'], r['Created'], r['LastModified'])
```

Expected: **one row**, path `C:\Users\j.smith\Downloads\dl.exe`, SHA-1 starting `b8e3f4d12a89c4e56701...`. The SHA-1 is what you'd submit to your threat-intel platform. The user-profile path tells you it was downloaded, not installed.

### Step 3 — Confirm the parent process via Jump Lists

```powershell
$jl = Import-Csv 'Data\FIN-WS23\jump-lists.csv'
$jl | Where-Object { $_.AppDescription -eq "Microsoft Word" } |
      Select-Object EntryNumber, LastModified, LocalPath
```

```python
with open('Data/FIN-WS23/jump-lists.csv') as f:
    jl = list(csv.DictReader(f))
for r in jl:
    if r['AppDescription'] == "Microsoft Word":
        print(r['EntryNumber'], r['LastModified'], r['LocalPath'])
```

Expected: **4 rows**. The most recent is `F:\Vendors\Confidential\Bank_Account_Notes.docx` at 09:16:42, opened from the USB you profile in Step 4. The entry that matters for delivery is `Q4_Vendor_Review.docm` at 06:58:00, the last Word open before `DL.EXE` ran at 06:59:14. That macro-enabled file points to Word → PowerShell → loader as the delivery chain.

### Step 4 — Profile the SanDisk USB

```powershell
$usb = Import-Csv 'Data\FIN-WS23\usbstor.csv'
$usb | Where-Object { $_.FriendlyName -like "*SanDisk*" } |
      Select-Object FriendlyName, SerialNumber, FirstConnected, LastConnected, VolumeGuid
```

```python
with open('Data/FIN-WS23/usbstor.csv') as f:
    usb = list(csv.DictReader(f))
for r in usb:
    if 'SanDisk' in r['FriendlyName']:
        print(r['FriendlyName'], r['SerialNumber'], r['FirstConnected'], r['LastConnected'], r['VolumeGuid'])
```

Expected: **one row**, SanDisk Cruzer Glide, serial `4C530001190405104544`, first connection 2024-11-13 09:14:08, volume GUID `{b4d722a1-1142-11ef-8a4f-0c9d92841421}`. It is a single-day connection from a USB device the host had never seen before. Carry the volume GUID forward to Step 5. In this simulated dataset its first eight hex digits match the LNK volume serial `B4D7-22A1`. Real volume GUIDs and volume serials are unrelated, so do not bind on that match.

### Step 5 — Bind the USB volume serial to LNK files

```powershell
$lnk = Import-Csv 'Data\FIN-WS23\lnk-files.csv'
$lnk | Where-Object { $_.VolumeSerialNumber -eq "B4D7-22A1" } |
       Select-Object SourceFile, LocalPath, TargetModified
```

```python
with open('Data/FIN-WS23/lnk-files.csv') as f:
    lnk = list(csv.DictReader(f))
for r in lnk:
    if r['VolumeSerialNumber'] == "B4D7-22A1":
        print(r['SourceFile'], r['LocalPath'], r['TargetModified'])
```

Expected: **2 rows** of LNK files with volume serial `B4D7-22A1`, volume label `CRUZER`, and drive type `RemovableMedia` — files the user opened from `F:`. The volume serial alone does not name the device. It is a file-system value assigned at format time, and it is unrelated to the USBSTOR device serial and to the volume GUID (Chapter 6 §6.5.1). The chain runs LNK volume serial → `MountedDevices` volume → USBSTOR device. This dataset has no `MountedDevices` export, so the chain is incomplete here. The System log stands in for part of it: EID 98 at 09:14:12 records volume `{b4d722a1-1142-11ef-8a4f-0c9d92841421}` as `F:`, and `usbstor.csv` assigns that GUID to the SanDisk serial. The LNKs place the two files on `F:` at 09:16:18 and 09:16:42, inside the 09:14:08–09:24:47 window when the SanDisk was attached. The device binding rests on that timing and the drive letter. Pull `MountedDevices` from the `SYSTEM` hive to complete it.

### Step 6 — Confirm folder navigation on the USB

```powershell
$sb = Import-Csv 'Data\FIN-WS23\shellbags.csv'
$sb | Where-Object { $_.AbsolutePath -like "F:\*" } |
      Select-Object AbsolutePath, FirstInteracted, LastInteracted
```

```python
with open('Data/FIN-WS23/shellbags.csv') as f:
    sb = list(csv.DictReader(f))
for r in sb:
    if r['AbsolutePath'].startswith("F:\\"):
        print(r['AbsolutePath'], r['FirstInteracted'], r['LastInteracted'])
```

Expected: at least **3 rows** showing `F:\`, `F:\Vendors\`, `F:\Vendors\Confidential\` — the directory tree the user browsed on the USB. Shellbags survive after the USB is removed.

### Step 7 — Look for the delivery vector in browser history

```powershell
$bh = Import-Csv 'Data\FIN-WS23\browser-history.csv'
$bh | Where-Object { $_.URL -like "*finance-news-daily*" } |
      Select-Object VisitTime, URL, Transition
```

```python
with open('Data/FIN-WS23/browser-history.csv') as f:
    bh = list(csv.DictReader(f))
for r in bh:
    if 'finance-news-daily' in r['URL']:
        print(r['VisitTime'], r['URL'], r['Transition'])
```

Expected: **2 rows** showing the user navigated to `finance-news-daily.example.com`, a plausible-looking external newsletter URL that delivered the macro-enabled document. Both rows read `Transition=link`, so the user clicked into both pages rather than typing the URLs. `Transition` does not say where the click started. The `ReferrerURL` on the 06:31:42 visit does: `https://outlook.office365.com/mail/inbox`, which points to email.

### What you've just done

You used seven independent shell, device, and browser sources, each pointing to a different step of the same incident. They show a delivery URL (Step 7), a Word document opened from it (Step 3), and a downloaded loader binary (Steps 1–2). They also show a separate USB attached about two hours later the same morning (Step 4), files accessed from that USB (Step 5), and the directory tree the user browsed on it (Step 6). Walk back through Tasks 2–7 of the lab, and the analyst-notes scaffold has concrete inputs in every cell.

---

## Deliverables Checklist

Your `lab06-notes.md` should contain:

- [ ] **Task 1** — Question-to-artifact mapping with six added questions
- [ ] **Task 2** — LNK and Jump List review tables with added items
- [ ] **Task 3** — Prefetch and Amcache review plus focused execution table
- [ ] **Task 4** — SRUM and UserAssist review plus behavior-pattern table
- [ ] **Task 5** — Shellbags and folder-navigation review plus added paths
- [ ] **Task 6** — Removable-device profiling table with written responses
- [ ] **Task 7** — Browser, email, and search-artifact table with added sources
- [ ] **Task 8** — Behavioral timeline with at least 12 entries where possible
- [ ] **Task 9** — Strong support vs overclaim exercise
- [ ] **Task 10** — Shell and application artifact summary
- [ ] **Task 11** — Analyst handoff note
- [ ] **Task 12** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab06/
├── ReadMe.md                     ← This file
├── lab06-notes.md                ← Your working notes file (fill this in)
├── walkthrough-answers.md        ← Sample answers for the Hands-On Walkthrough
├── task-answers.md               ← Sample answers for the workbook Tasks
├── Lab06_01/ReadMe.md            ← Ch6 §6.1 — Evidence of Execution
├── Lab06_02/ReadMe.md            ← Ch6 §6.2 — Shellbags
├── Lab06_03/ReadMe.md            ← Ch6 §6.3 — UserAssist and Amcache
├── Lab06_04/ReadMe.md            ← Ch6 §6.4 — Browser, Email, and Search Index
└── Lab06_05/ReadMe.md            ← Ch6 §6.5 — Removable Device Profiling
```

---

## Key Takeaways

- **These artifacts show behavior.** They help answer what was opened, executed, browsed, and interacted with.
- **Execution, access, and navigation are different things.** Good responders keep those distinctions clear.
- **Removable-device cases require correlation.** Device presence alone is not enough. File and user-activity artifacts matter.
- **Application artifacts add context logs often miss.** They can reveal how a user or attacker actually moved through the system.
- **The real value is in correlation.** LNK files, Jump Lists, Prefetch, SRUM, Shellbags, Registry data, and NTFS findings are strongest when they reinforce one another.

---

**Next:** Lab 6.1 — Evidence of Execution

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
