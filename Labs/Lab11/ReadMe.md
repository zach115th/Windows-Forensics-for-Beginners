# Lab 11 — Forensic Challenge: Investigating Unauthorized Data Exfiltration

**Supporting [Chapter 11: Forensic Challenge: Investigating Unauthorized Data Exfiltration](../../Book/Chapter11.md)**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

This lab is where the earlier chapters come together.

By now, you have worked through Windows file-system artifacts, Registry analysis, shell items, memory forensics, network evidence, event logs, and timelines. In a real case, however, those artifacts do not arrive as isolated training exercises. They arrive as one messy investigation where the key question is simple and high stakes:

> Did someone take sensitive data, and if so, how?

This lab gives you that kind of case.

You will simulate a small unauthorized data-exfiltration incident on a Windows VM, collect the resulting artifacts, and then investigate the system as if you were the responder receiving it after the fact. The focus is not catching every possible trace. It is building a defensible answer to the important questions:

- What happened?
- Which user account was involved?
- Was a USB device used?
- Was a cloud service used?
- What evidence supports each conclusion?
- What should the organization do next?

The lab makes you work like an incident responder instead of a chapter-by-chapter student. You already know the artifact types. Now you need to combine them into a coherent case.

---

## What This Lab Covers

This lab supports the following sections from Chapter 11:

| Section | Topic |
|---|---|
| 11.1 | Scenario |
| 11.2 | Suggested Workflow |
| 11.3 | Simulating the Incident (For the Lab) |
| 11.4 | Capturing and Preserving Artifacts |
| 11.5 | Investigating the Exfiltration Path |
| 11.6 | Writing a Case Summary |

The sub-exercise folders do not map one-to-one onto those sections. `Lab11_03`
works §11.3 through §11.5 as a single investigation, and `Lab11_04` covers
§11.6. `Lab11_05` and `Lab11_06` go beyond Chapter 11 into remediation and
case handoff. Chapter 13 develops that material properly, and the two folders
cross-reference it.

---

## Learning Objectives

By completing this lab, you will be able to:

- Simulate a realistic mini data-exfiltration incident in a controlled Windows lab
- Preserve evidence with hashes, working copies, and basic chain-of-custody discipline
- Investigate file staging using MFT, USN, and related file-system artifacts
- Correlate user activity through shell items, Registry, browser artifacts, event logs, and timelines
- Assess whether removable media, cloud services, or both were involved
- Use memory and logs to strengthen or challenge host-based conclusions
- Write a concise case summary that answers what happened, who was involved, how data left the system, and what should be done next

---

## Estimated Time and Difficulty

**Difficulty:** Advanced

**First time through the material:** 5–8 h

**Refresh (already familiar with the chapter):** 2–3 h

> **Key terms used in this lab:** exfiltration channel, chain of custody, OneDrive forensics, USB profiling, case summary. See the consolidated [Glossary](../../Book/Glossary.md) for definitions. The chapter cross-references in each entry take you back to the deeper coverage in `Book/`.

---

## Prerequisites

- Completion of Labs 01–10, or equivalent familiarity with Windows forensic artifacts and IR workflow
- A Windows VM you can safely modify
- A text editor or markdown editor
- Your `lab11-notes.md` file
- A way to simulate removable media, such as:
  - A USB drive, or
  - A virtual removable disk
- A way to simulate cloud transfer, such as:
  - A real cloud account in a safe personal lab, or
  - A locally hosted mock upload destination or file-sharing page
- Optional tools:
  - MFTECmd / USN-capable parsers
  - Registry Explorer / RegRipper / RECmd
  - LECmd / JLECmd / PECmd / SBECmd / SRUM parsers
  - Browser-history tools
  - Volatility / memory tools
  - EvtxECmd or equivalent event-log parser
  - Timeline Explorer, spreadsheet software, or custom scripts

> **Working without a VM:** A complete capstone dataset for the HR-WS17 scenario is in [`Data/HR-WS17/`](../../Data/HR-WS17/). It holds 20 files spanning every artifact category in the book: MFT, USN, event logs, shell items, registry, USB history, ShimCache, Recycle Bin, OneDrive sync database and logs, browser history, and Volatility 3 memory output. A separate `pricing-files-known-hashes.txt` holds the SHA-256 references legal provided. Use this as the input if you are not running the simulation in your own environment.

> **Prerequisite skills from earlier labs:** This capstone tests skills from every lab in the book, and you have already seen every artifact class in it. Expect to draw on:
>
> | Skill | Lab |
> |---|---|
> | Chain-of-custody, evidence hashing, working copies | [Lab 01](../Lab01/ReadMe.md), [Lab 03](../Lab03/ReadMe.md) |
> | NTFS and USN-journal reading | [Lab 04](../Lab04/ReadMe.md) |
> | Registry persistence, USB history, OneDrive sync | [Lab 05](../Lab05/ReadMe.md) |
> | LNK / Jump Lists / Prefetch / Shellbags / Amcache | [Lab 06](../Lab06/ReadMe.md) |
> | Memory hunt (if you also captured one) | [Lab 07](../Lab07/ReadMe.md) |
> | Proxy / DNS / flow review | [Lab 08](../Lab08/ReadMe.md) |
> | Event-log hunt pack | [Lab 09](../Lab09/ReadMe.md) |
> | Multi-source timeline | [Lab 10](../Lab10/ReadMe.md) |
>
> The capstone does not re-teach these. It expects you to pick the right tool for each question the case asks. If a step feels unfamiliar, revisit the source lab and come back.

---

## Scenario

An internal investigation suggests that an employee may have copied sensitive files off a workstation and exfiltrated them using either USB, a cloud service, or both.

You have the following available for investigation:

- A disk image
- A memory image
- Key logs and artifacts already exported or obtainable from the system

Your task is to simulate such an incident in your lab, then investigate it as if you were the responder. Assume that management wants clear answers, not artifact trivia.

The final questions you need to answer are:

- What happened?
- Which host and user account were involved?
- How did the data leave the system?
- What evidence supports that conclusion?
- What remediation and controls would you recommend?

---

## Background: This Is a Correlation Case

Unauthorized data exfiltration cases rarely hinge on one artifact.

A USB record alone does not prove copying. A OneDrive folder alone does not prove upload. A recent document entry alone does not prove malicious intent. What matters is whether multiple artifact classes line up into a consistent story.

The workflow suggested in the chapter is a good starting point:

| Workflow Element | Why It Matters |
|---|---|
| Chain of custody and hashes | Preserves trust in the evidence |
| Working copy of images | Protects originals from accidental modification |
| MFT / USN | Shows file existence, staging, creation, rename, delete patterns |
| Shell items / Registry | Shows user and folder interaction |
| USB artifacts / Shellbags | Shows removable-device use and navigation |
| Browser / cloud artifacts | Shows web or cloud-based access and upload context |
| Event logs and timelines | Shows sequence and supporting context |
| Memory forensics | May reveal in-memory tools, processes, or network connections |

> **IR Reality Check:** In an exfiltration case, the strongest answer usually comes from multiple modest artifacts aligning — not from one perfect artifact.

---

## Lab Tasks

---

### Task 1 — Receive the Case and Read the Inputs

**Objective:** Begin the case the way real responders begin it — with whatever the previous shift left behind.

This capstone uses the pre-built **HR-WS17 exfiltration dataset** in [`Data/HR-WS17/`](../../Data/HR-WS17/). It contains 20 files of pre-parsed forensic output, plus a `pricing-files-known-hashes.txt` listing the SHA-256 of three pricing files legal has flagged as the data of concern. The output covers MFT, USN, the Security event log, Prefetch, Amcache, ShimCache, SRUM, LNK, Jump Lists, shellbags, USBSTOR, MountedDevices, OneDrive accounts and sync database, OneDrive logs, browser history, the Recycle Bin, and Volatility 3 output (`pslist`, `netscan`, `cmdline`) from the live memory capture.

Treat the dataset as a triage collection that arrived from another team. The other team's prep notes:

- Host: `HR-WS17`, finance/HR workstation, departing-employee preservation
- User of interest: `hr-user`
- Acquisition date: 2024-11-12 (after offboarding); investigation started three weeks later when legal raised concerns
- The IT team captured memory from the live session with WinPmem at 18:01:12 UTC, then imaged the disk with FTK Imager. Chain of custody was documented from acquisition through current preservation

**Part A — Inventory the inputs.** Open `Data/HR-WS17/README.md` and read the file inventory. Then, in your notes file, record:

| Question | Answer |
|---|---|
| What artifact classes are available? | |
| What is missing that you might want? | |
| Which file lists the pricing-file hashes? | |
| What is the primary scenario time window from the README? | |
| Which channel(s) does the README explicitly call out? | |

**Part B — Read the pricing-file hashes.** Open `Data/HR-WS17/pricing-files-known-hashes.txt` and record the three target SHA-256 hashes. You will use these in later tasks to confirm whether the same files crossed any of the exfiltration channels.

**Part C — If you would rather generate your own simulation:** Skip the pre-built dataset and run the original simulation on your own VM: create a `Confidential\` folder, copy to USB, sync to a personal OneDrive, and so on. This path is longer, but it gives you the full collection-and-analysis loop. The investigation tasks below work either way. Substitute your own hostname and paths for `HR-WS17` and `hr-user`.

---

### Task 2 — Verify Evidence Integrity

**Objective:** Apply evidence-handling discipline before analysis.

If you are using the pre-built dataset, your "evidence" is a folder of CSV and text files. The forensic discipline still applies:

**Part A — Hash the dataset on receipt.** Compute SHA-256 hashes for each file in `Data/HR-WS17/` and record them in your notes file. PowerShell:

```powershell
Get-ChildItem 'Data\HR-WS17\' -File |
  Get-FileHash -Algorithm SHA256 |
  Select-Object Path, Hash | Format-Table -AutoSize
```

**Part B — Create a working copy.** Copy `Data\HR-WS17\` to a separate working directory, such as `Cases\IR-2024-HRWS17\working\`. Re-hash the working copy and confirm every hash matches the original. Treat the original as write-protected for the rest of the lab.

**Part C — Record the evidence inventory.** Use the table below.

| Evidence Item | Source Path | SHA-256 (truncate first 16 chars) | Working Copy Created? | Notes |
|---|---|---|---|---|
| `mft.csv` | `Data/HR-WS17/mft.csv` | | | |
| `usn-journal.csv` | | | | |
| `security-evtx.csv` | | | | |
| `prefetch.csv` | | | | |
| `amcache.csv` | | | | |
| `srum.csv` | | | | |
| `lnk-files.csv` | | | | |
| `jump-lists.csv` | | | | |
| `shellbags.csv` | | | | |
| `usbstor.csv` | | | | |
| `mountpoints.csv` | | | | |
| `onedrive-accounts.csv` | | | | |
| `onedrive-syncdb.csv` | | | | |
| `onedrive-logs-extract.txt` | | | | |
| `browser-history.csv` | | | | |
| `pricing-files-known-hashes.txt` | | | | |

> **If you generated your own simulation in Task 1:** acquire your VM disk and memory images, hash them, create working copies, and adapt the table to the artifact set you produced. The discipline is identical. Only the file names differ.

Then answer:

**1. Why should the original evidence be left untouched once verified?**

**2. Why does hashing matter even in a training case?**

**3. Why is chain-of-custody discipline still useful in internal investigations?**

---

### Task 3 — Build the Initial Case Scope

**Objective:** Define what you are trying to prove before diving into artifacts.

Write at least 10 investigative questions you want the case to answer.

Examples:

- Which user account interacted with the confidential files?
- Were the files staged or archived before transfer?
- Was a removable device involved?
- Was a cloud service involved?
- What was the likely exfiltration path?
- What was the timing of the activity?

Group your questions into categories.

| Category | Question Numbers |
|---|---|
| User activity | |
| File staging | |
| Removable media | |
| Cloud / browser activity | |
| Timeline / sequence | |
| Memory / live-state follow-up | |

Then answer:

**1. Why is question definition especially important in a case with many artifact types?**

**2. Why can this kind of case become unfocused without a clear question set?**

**3. Why should your final report answer the same questions you started with?**

---

### Task 4 — Investigate File Staging with MFT and USN

**Objective:** Determine whether the sensitive files were created, copied, renamed, archived, or deleted in suspicious ways.

Using MFT / USN-capable tools or equivalent workflow, investigate:

- The Confidential folder
- Any archive files created
- Any staging directories such as Downloads, Desktop, Temp, or ProgramData
- Any deleted or short-lived files related to the exfil activity

Record your findings below.

| File / Path | Artifact Source | Why It Matters | What It Suggests | What It Does Not Prove |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |

Add at least six findings.

Then answer:

**1. Why are archive creation and staging paths important in an exfiltration case?**

**2. Why do deleted records often become more interesting in these cases?**

**3. Why should file-system findings be correlated rather than treated as proof of exfiltration by themselves?**

---

### Task 5 — Investigate User Access with Shell Items and Registry

**Objective:** Determine which user likely accessed the relevant folders and files.

Use shell items, user hives, Explorer history, RecentDocs, UserAssist, and related artifacts to answer:

- Which user profile interacted with the confidential files?
- Which folders were browsed?
- Whether the user likely navigated to removable-media paths or cloud-sync paths

Record your findings below.

| Finding | Source Artifact | Why It Matters | What It Suggests | Limitation |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

Add at least six findings.

Then answer:

**1. Why is user-hive provenance especially important here?**

**2. Why are folder-browsing artifacts useful even when they do not prove copying?**

**3. Why do these artifacts become much stronger when timed against the staging activity?**

---

### Task 6 — Confirm or Challenge USB Involvement

**Objective:** Determine whether removable media was involved and how strongly the evidence supports that.

Use:

- USB Registry artifacts
- Shellbags
- LNK files
- Jump Lists
- RecentDocs
- Timeline context

Record your findings below.

| USB-Related Finding | Source Artifact | Why It Matters | What It Suggests | What It Does Not Prove |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

Add at least six findings.

Then answer:

**1. What evidence supports simple device recognition?**

**2. What evidence supports likely browsing or file access on the device?**

**3. What additional evidence would make you more confident about copying to USB?**

---

### Task 7 — Investigate Cloud / Browser Exfiltration

**Objective:** Determine whether a cloud service or browser-mediated transfer likely occurred.

Use browser history, downloads, upload-related context, cloud-client artifacts, and any local logs or sync evidence available.

Look for:

- Access to upload or file-sharing pages
- Cloud portal use
- Local sync-root interaction
- Browser upload timing
- Authentication or account evidence if available

Record your findings below.

| Cloud / Browser Finding | Source Artifact | Why It Matters | What It Suggests | Limitation |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

Add at least six findings.

Then answer:

**1. Why is cloud evidence often more difficult to prove from the endpoint alone?**

**2. Why do browser artifacts matter even if OneDrive or another sync client is present?**

**3. What would you want from provider-side logs if this were a real enterprise case?**

---

### Task 8 — Review Event Logs and Build Context

**Objective:** Use event logs to support the timeline and identify related suspicious actions.

Review relevant logs such as:

- Security
- PowerShell Operational
- Task Scheduler Operational
- System
- Defender Operational

Look for:

- Logon activity
- PowerShell executions
- Scheduled task changes
- Service events
- Defender detections or tampering
- Log-clearing or security-relevant actions

Record your findings below.

| Event-Log Finding | Log Source | Why It Matters | What It Suggests | Limitation |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

Add at least six findings.

Then answer:

**1. Why do logs help anchor the case in time?**

**2. Why should missing log events be interpreted carefully?**

**3. Which event patterns are most valuable in a user-driven exfiltration case?**

---

### Task 9 — Review Memory for In-Memory Tools or Context

**Objective:** Use memory forensics to see whether any useful live-state evidence strengthens the case.

Review the memory image for:

- Suspicious processes
- Relevant command lines
- Browser or PowerShell remnants
- Network connections
- Short-lived utilities
- Archive or transfer tools
- In-memory evidence of suspicious sessions or scripts

Record your findings below.

| Memory Finding | Why It Matters | What It Suggests | What It Does Not Prove |
|---|---|---|---|
| | | | |
| | | | |
| | | | |

Add at least four findings or negative findings.

Then answer:

**1. Why can memory be especially valuable if the exfiltration involved short-lived tools?**

**2. Why are negative memory findings still worth documenting?**

**3. Why should memory findings be correlated with disk and log artifacts rather than treated alone?**

---

### Task 10 — Build the Incident Timeline

**Objective:** Turn the artifact findings into a coherent exfiltration sequence.

Using the artifact findings from the earlier tasks, build a focused incident timeline.

Include at least 12 entries if possible.

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

Then answer:

**1. Which events are most central to the suspected exfiltration?**

**2. Which events support the USB path?**

**3. Which events support the cloud path?**

**4. Which events are ambiguous or only weakly supportive?**

---

### Task 11 — Determine What Most Likely Happened

**Objective:** Synthesize the evidence into defensible conclusions.

Write short answers to the following:

**1. What happened?**

**2. Which host and user account were involved?**

**3. How did the data most likely leave the system?**

**4. What evidence most strongly supports that conclusion?**

**5. What alternate explanations remain possible?**

Then complete the table below.

| Conclusion | Evidence That Strongly Supports It | Evidence That Only Suggests It | Confidence |
|---|---|---|---|
| User account involved | | | |
| USB involvement | | | |
| Cloud involvement | | | |
| Staging activity | | | |
| Likely exfil path | | | |

---

### Task 12 — Write the Case Summary

**Objective:** Produce the 1–3 page case summary described in the chapter.

Write a 1–3 page case summary that answers:

- What happened
- Which hosts and accounts were involved
- How the data left the system
- Recommended remediations and controls

Your summary should include:

- Scope of the investigation
- Main evidence sources used
- Most important findings
- Timeline-based narrative
- Strength of conclusions
- Gaps or uncertainties
- Recommended next steps

Use clear, professional language suitable for technical leadership and internal stakeholders.

---

### Task 13 — Write Remediations and Control Recommendations

**Objective:** Translate the case into operational next steps.

Write at least eight recommendations.

These may include:

- Account actions
- Host isolation or rebuild
- USB-control policy improvements
- Cloud-control or DLP improvements
- Logging or monitoring enhancements
- User-access review
- Timeline / alerting improvements
- Investigation follow-up steps

Use the table below.

| Recommendation | Why It Matters | Priority |
|---|---|---|
| | | |
| | | |
| | | |
| | | |

Add at least eight entries.

Then answer:

**1. Why should recommendations include both immediate remediation and longer-term controls?**

**2. Why do logging and artifact-collection improvements often belong in the recommendations?**

**3. Why should the recommendations reflect the uncertainties of the case instead of pretending the evidence is perfect?**

---

### Task 14 — Write an Analyst Handoff Note

**Objective:** Make the case easy for another responder or reviewer to continue.

Use the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Primary Question:
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

**1. Why correlation matters most in exfiltration cases**
Why is unauthorized-data-exfiltration work usually won or lost through cross-artifact correlation rather than one single artifact?

**2. USB versus cloud ambiguity**
Why can it be difficult to distinguish between removable-media and cloud exfiltration if the endpoint evidence is incomplete?

**3. Case-writing discipline**
Why is it important that the case summary separate strongly supported findings from likely but unconfirmed conclusions?

**4. From artifacts to decisions**
Why should the outcome of a forensic challenge like this be not just findings, but remediation and control recommendations?

---

## Hands-On Walkthrough (Using Simulated Data)

This walkthrough is the integration exercise. It pulls together every artifact category in the book and resolves the capstone case using the dataset in [`Data/HR-WS17/`](../../Data/HR-WS17/). Commands are PowerShell.

### Step 1 — Read the target hashes

```powershell
Get-Content 'Data\HR-WS17\pricing-files-known-hashes.txt'
```

```python
with open('Data/HR-WS17/pricing-files-known-hashes.txt') as f:
    print(f.read())
```

Expected: three SHA-256 hashes provided by legal, for `Q4_Customer_Pricing.xlsx`, `Pricing_Strategy_Confidential.docx`, and `Margins_Q3.xlsx`. Compare them against any candidate file you recover during the investigation.

### Step 2 — Confirm staging activity in MFT and USN

```powershell
$usn = Import-Csv 'Data\HR-WS17\usn-journal.csv'
$usn | Where-Object { $_.UpdateReasons -like "*FileDelete*" } |
       Sort-Object UpdateTimestamp |
       Select-Object UpdateTimestamp, FileName, ParentPath
```

```python
import csv
with open('Data/HR-WS17/usn-journal.csv') as f:
    usn = list(csv.DictReader(f))
hits = [r for r in usn if 'FileDelete' in r['UpdateReasons']]
hits.sort(key=lambda r: r['UpdateTimestamp'])
for r in hits:
    print(r['UpdateTimestamp'], r['FileName'], r['ParentPath'])
```

Expected: **10** `FileDelete` entries in two distinct bursts — 5 between 17:55:11 and 17:55:48, then 5 more at 17:57:42. The gap matters. The first burst is the Temp working copies going away, and the second is the source directory itself being removed. The deleted files include `Q4_Customer_Pricing.xlsx` and `Pricing_Strategy_Confidential.docx` from the user's `Temp\` directory. Those files were staged in Temp for some operation, then cleaned up. The MFT entries for the Temp copies are `InUse=False` for the same reason.

### Step 3 — Profile the Kingston USB

```powershell
$usb = Import-Csv 'Data\HR-WS17\usbstor.csv'
$usb | Where-Object { $_.FriendlyName -like "*Kingston*" } |
       Select-Object FriendlyName, SerialNumber, FirstConnected, LastRemovalTime, VolumeGuid
```

```python
with open('Data/HR-WS17/usbstor.csv') as f:
    usb = list(csv.DictReader(f))
for r in usb:
    if 'Kingston' in r['FriendlyName']:
        print(r['FriendlyName'], r['SerialNumber'], r['FirstConnected'], r['LastRemovalTime'], r['VolumeGuid'])
```

Expected: **2 Kingston entries**. The one in the case window is serial `001A92053B7CBE3196B40A0F`, connected 2024-11-12 17:42:08 and removed at 17:58:30. Those 16 minutes of attached time exactly frame the deletion window from Step 2. The volume GUID is `{f1d2e9a4-77c0-4b91-83be-ab4a0ed1c6e5}`.

### Step 4 — Confirm the user browsed sensitive folders on the USB

```powershell
$sb = Import-Csv 'Data\HR-WS17\shellbags.csv'
$sb | Where-Object { $_.AbsolutePath -like "E:\Confidential\*" } |
      Select-Object AbsolutePath, FirstInteracted
```

```python
with open('Data/HR-WS17/shellbags.csv') as f:
    sb = list(csv.DictReader(f))
for r in sb:
    if r['AbsolutePath'].startswith("E:\\Confidential\\"):
        print(r['AbsolutePath'], r['FirstInteracted'])
```

Expected: **2** shellbag entries, `E:\Confidential\Pricing` and `E:\Confidential\HR`, both with `FirstInteracted` at **17:43:42 UTC**. The parent `E:\Confidential` row (17:43:11) does not match the filter, because its path has no trailing backslash. Shellbags survive after the USB is removed, and they are direct evidence that the user navigated to sensitive folders on the device.

### Step 5 — Bind LNK files to the Kingston volume

```powershell
$lnk = Import-Csv 'Data\HR-WS17\lnk-files.csv'
$lnk | Where-Object { $_.VolumeSerialNumber -eq "F1D2E9A4" } |
       Select-Object SourceFile, LocalPath, TargetModified
```

```python
with open('Data/HR-WS17/lnk-files.csv') as f:
    lnk = list(csv.DictReader(f))
for r in lnk:
    if r['VolumeSerialNumber'] == "F1D2E9A4":
        print(r['SourceFile'], r['LocalPath'], r['TargetModified'])
```

Expected: **3 rows** of LNK files with the Kingston's volume serial. These are files the user opened from the USB. Together with the device serial from Step 3 and the folder navigation from Step 4, they establish the USB exfiltration channel with three independent corroborating sources.

### Step 6 — Identify the personal OneDrive account

```powershell
$od = Import-Csv 'Data\HR-WS17\onedrive-accounts.csv'
$od | Select-Object AccountName, AccountType, UserEmail, FirstAdded, LastSignIn
```

```python
with open('Data/HR-WS17/onedrive-accounts.csv') as f:
    od = list(csv.DictReader(f))
for r in od:
    print(r['AccountName'], r['AccountType'], r['UserEmail'], r['FirstAdded'], r['LastSignIn'])
```

Expected: **2 accounts** — the corporate one and `hr.user.personal@outlook.com` (Personal). A personal account on a corporate-managed laptop is itself notable. The LastSignIn date in the case window confirms it was actively used.

### Step 7 — Confirm pricing files synced to the personal account

```powershell
$ods = Import-Csv 'Data\HR-WS17\onedrive-syncdb.csv'
$ods | Select-Object FileName, FileSize, UploadCompletedUtc, Sha256ContentHash
```

```python
with open('Data/HR-WS17/onedrive-syncdb.csv') as f:
    ods = list(csv.DictReader(f))
for r in ods:
    print(r['FileName'], r['FileSize'], r['UploadCompletedUtc'], r['Sha256ContentHash'])
```

Expected: **2 rows** — `Q4_Customer_Pricing.xlsx` and `Pricing_Strategy_Confidential.docx`. The `Sha256ContentHash` values match the legal-provided hashes from Step 1. This step makes the case actionable. The personal OneDrive synced those files, and the content hashes confirm they are the canonical pricing data legal asked about.

### Step 8 — Cross-check the OneDrive client log

```powershell
Get-Content 'Data\HR-WS17\onedrive-logs-extract.txt' | Select-String -Pattern "Q4_Customer_Pricing|Pricing_Strategy"
```

```python
with open('Data/HR-WS17/onedrive-logs-extract.txt') as f:
    for ln in f:
        if 'Q4_Customer_Pricing' in ln or 'Pricing_Strategy' in ln:
            print(ln, end='')
```

Expected: lines from the OneDrive client log showing chunked uploads for both pricing files between **17:46 and 17:49 UTC**, with the same SHA-256 hashes as in Step 1 and Step 7. Three independent sources carry the same hash: the legal-provided reference, the sync database, and the client log. That agreement is very hard to rebut.

### Step 9 — Look for the webmail upload (probable but unconfirmed channel)

```powershell
$bh = Import-Csv 'Data\HR-WS17\browser-history.csv'
$bh | Where-Object { $_.Url -like "*outlook.live*" } |
      Select-Object VisitTime, Url, Title
```

```python
with open('Data/HR-WS17/browser-history.csv') as f:
    bh = list(csv.DictReader(f))
for r in bh:
    if 'outlook.live' in r['Url']:
        print(r['VisitTime'], r['Url'], r['Title'])
```

Expected: **4 rows**. The user navigated to `outlook.live.com/mail/0/` at 17:51:04, then to `/deeplink/compose` to write a new message, then through to `/sentitems`. The sequence is consistent with a webmail send but does not directly prove an attachment crossed. Document it as a "probable channel" rather than confirmed, because the cloud server holds the authoritative record, not the host.

### Step 10 — Build the channel-analysis table

Combine the findings into the capstone deliverable:

| Channel | Result | Evidence |
|---|---|---|
| **USB (Kingston `001A9205…`)** | Confirmed | USBSTOR + MountedDevices + shellbags `E:\Confidential\Pricing\` + 3 LNK files with matching volume serial |
| **Personal OneDrive (`hr.user.personal@outlook.com`)** | Confirmed | Accounts registry + sync database + OneDrive client log; SHA-256 hashes match legal reference for 2 of 3 target files |
| **Webmail (Outlook.com)** | Probable, unverified from host | Browser history shows compose + sent activity at 17:51 UTC; attachment content not recoverable from host artifacts alone — would require cooperation with the email provider |
| **Local mail client / Bluetooth / print** | Ruled out | No evidence of mail-client send, Bluetooth file transfers, or unusual print activity in the artifact set |

### What you've just done

In 10 steps, you touched every artifact category in the book. You hash-matched **two of the three** pricing files against the legal-provided reference through three independent sources: the Step 1 reference list, the Step 7 sync database, and the Step 8 client log. `Margins_Q3.xlsx` appears in no cloud source and reached the USB only. The result is one confirmed USB exfil channel, one confirmed cloud-sync channel covering two of three files, and one probable-but-unverified webmail channel, each with its evidentiary weight named explicitly. Walk back through Tasks 3–14 of the lab, and the analyst-notes scaffold has concrete, defensible inputs in every cell. The case summary deliverable in Task 12 follows directly from the channel-analysis table in Step 10.

---

## Deliverables Checklist

Your `lab11-notes.md` should contain:

- [ ] **Task 1** — Simulated-incident plan and action table
- [ ] **Task 2** — Evidence-preservation and hashing table
- [ ] **Task 3** — At least 10 investigative questions grouped by category
- [ ] **Task 4** — MFT / USN staging-analysis findings
- [ ] **Task 5** — Shell / Registry user-access findings
- [ ] **Task 6** — USB-involvement findings
- [ ] **Task 7** — Cloud / browser exfiltration findings
- [ ] **Task 8** — Event-log context findings
- [ ] **Task 9** — Memory-review findings
- [ ] **Task 10** — Incident timeline with at least 12 entries where possible
- [ ] **Task 11** — Conclusion table and written answers
- [ ] **Task 12** — 1–3 page case summary
- [ ] **Task 13** — At least 8 remediation / control recommendations
- [ ] **Task 14** — Analyst handoff note
- [ ] **Task 15** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab11/
├── ReadMe.md                     ← This file
├── lab11-notes.md                ← Your working notes file (fill this in)
├── walkthrough-answers.md        ← Sample answers for the Hands-On Walkthrough
├── task-answers.md               ← Sample answers for the workbook Tasks
├── Lab11_01/ReadMe.md            ← Ch11 §11.1 — Scenario
├── Lab11_02/ReadMe.md            ← Ch11 §11.2 — Suggested Workflow
├── Lab11_03/ReadMe.md            ← Ch11 §11.3–§11.5 — simulate, preserve, investigate
├── Lab11_04/ReadMe.md            ← Ch11 §11.6 — Writing a Case Summary
├── Lab11_05/ReadMe.md            ← extends Ch11 — remediation and controls (Ch13 §13.5–§13.6)
└── Lab11_06/ReadMe.md            ← extends Ch11 — case review and handoff (Ch13 §13.3)
```

---

> **Going deeper:** This capstone investigates a host. In a real case, the cloud side of the same exfiltration would be in scope as well. `Book/AppendixB.md` (Cloud Identity and M365 Forensics) covers the Entra ID Sign-in / Audit logs, the Unified Audit Log (`MailItemsAccessed`, `FileDownloaded`, sharing-link operations), and OAuth consent grants. Those sources would close the webmail-channel gap this lab leaves probable-but-unverified. If lateral movement or AD compromise had been part of the scenario, `Book/AppendixA.md` (Lateral Movement, Credential Abuse, AD) covers the source/destination/domain-side artifacts.

---

## Key Takeaways

- **Exfiltration cases are correlation cases.** The strongest answers come from file-system, user-activity, device, browser, log, memory, and timeline evidence reinforcing one another.
- **USB and cloud pathways require different artifacts.** Good responders test both instead of assuming one too early.
- **Staging matters.** Archives, temp paths, deleted files, and recent-item activity often reveal the preparation phase before data leaves the host.
- **Case summaries should drive action.** The investigation is not complete until the findings are translated into remediation and control recommendations.
- **Discipline matters most when the stakes are highest.** In internal exfiltration work, careful wording and honest uncertainty are essential.

---

**Next:** Lab 11.1 — Scenario

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
