# Lab 05 — Windows Registry and Cloud Storage Forensics

**Supporting [Chapter 5: Windows Registry and Cloud Storage Forensics](../../Book/Chapter05.md)**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

The Windows Registry often preserves the system's memory of what was configured, what was connected, what was executed, and what devices or services were involved. That memory outlasts the visible evidence. A suspicious binary may be gone, a remote access tool may no longer be running, and a synced folder may look ordinary. When cloud storage is part of the case, those traces become even more important. Local sync clients, account artifacts, registry keys, logs, and databases can show that data movement occurred even when the files themselves are no longer where you expect them to be.

This lab introduces practical Registry and cloud-storage analysis from an incident response perspective. You will work through persistence, USB history, remote access clues, user-level activity, and cloud sync evidence in a way that mirrors real casework. The focus is answering incident-response questions, not abstract registry archaeology: Was persistence established? Was removable media involved? Was OneDrive or another sync client configured? Could files have been staged for exfiltration?

The lab trains you to treat the Registry and local cloud-client artifacts as a structured source of evidence for scoping, hypothesis testing, and reporting.

---

## What This Lab Covers

This lab supports the following sections from Chapter 5:

| Section | Topic |
|---|---|
| 5.1 | Registry Structure and Key Hives |
| 5.2 | Important Keys for IR |
| 5.3 | Cloud Storage (OneDrive Example) |
| 5.4 | Correlating Registry and Cloud Evidence in IR |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain the basic role of the Windows Registry in forensic analysis
- Identify the major system and user hives relevant to incident response
- Locate Registry areas commonly associated with persistence, services, remote access, and USB history
- Recognize how user hives can reveal execution and usage patterns
- Identify local evidence of cloud sync client installation and configuration
- Correlate Registry findings with cloud storage artifacts to support or challenge exfiltration hypotheses
- Write concise, defensible notes based on Registry and sync-client evidence

---

## Estimated Time and Difficulty

**Difficulty:** Intermediate

**First time through the material:** 3–4 h

**Refresh (already familiar with the chapter):** 75–105 min

> **Key terms used in this lab:** registry hives, persistence keys, USBSTOR, mounted devices, OneDrive sync database. See the consolidated [Glossary](../../Book/Glossary.md) for definitions. The chapter cross-references in each entry take you back to the deeper coverage in `Book/`.

---

## Prerequisites

- Completion of Labs 01–04, or equivalent familiarity with Windows IR collection and NTFS artifact analysis
- A text editor or markdown editor
- Your `lab05-notes.md` file
- Optional: a Windows VM or image containing Registry hives and user profile artifacts
- Optional: tools such as Registry Explorer, RegRipper, RECmd, or another Registry parser
- Optional: access to local OneDrive or other cloud sync client artifacts in a lab environment

> **Working without a VM:** Pre-parsed CSV outputs for the HR-LT12 scenario are in [`Data/HR-LT12/`](../../Data/HR-LT12/). Use `registry-runkeys.csv`, `usbstor.csv`, `mountpoints.csv`, `shellbags.csv`, and the OneDrive files for this lab's exercises if you do not have your own hives to work against.

---

## Scenario

You are investigating a Windows workstation named **HR-LT12** after a user reported suspicious account activity and unexpected document access. The initial triage package suggests several lines of inquiry:

- A suspicious startup entry may have been added
- A removable USB device may have been connected recently
- Remote access or RDP-related activity may have occurred
- The user has OneDrive installed, and there is concern that sensitive files may have been synchronized off the system
- The live file listing is incomplete, and the user denies knowingly moving data to the cloud

Use Registry and local cloud-storage artifacts to determine what the system was configured to do and what devices or accounts may have been involved. Then decide whether the evidence supports a theory of persistence, removable-media activity, or cloud-based data movement.

---

## Background: The Registry Remembers What the File System Does Not

The Windows Registry is a hierarchical database that stores system-wide and user-specific configuration. For incident responders, it is one of the richest sources of durable context available on a Windows system.

Registry analysis can help answer questions such as:

- Was malware or a suspicious script configured to start automatically?
- Were services created or modified?
- Was a USB storage device connected?
- Was RDP or other remote access configured or used?
- Which programs did the user interact with?
- Which cloud sync client accounts and folders were configured locally?

The Registry becomes even more valuable when the case involves data movement or exfiltration theories. Cloud sync clients often leave behind a combination of Registry keys, configuration data, local folder structures, logs, and database artifacts that can support the case even when the user claims nothing happened.

| Artifact Area | What It Helps With |
|---|---|
| **SYSTEM hive** | Services, device history, system configuration |
| **SOFTWARE hive** | Installed applications, system-wide settings |
| **NTUSER.DAT** | User-specific execution, Explorer activity, cloud account context |
| **USRCLASS.DAT** | User shell and Explorer-related data |
| **Cloud sync client artifacts** | Account identifiers, sync roots, configuration, logs, local activity traces |

> **IR Reality Check:** The Registry rarely proves the whole case by itself, but it often tells you what the system was prepared to do, what it remembered, and where to look next.

---

## Lab Tasks

---

### Task 1 — Identify the Core Windows Registry Hives for IR

**Objective:** Build a practical understanding of which Registry hives matter most and why.

Fill in the table below.

| Hive | Scope | Typical Path | Why It Matters in IR |
|---|---|---|---|
| **SYSTEM** | | | |
| **SOFTWARE** | | | |
| **SAM** | | | |
| **SECURITY** | | | |
| **NTUSER.DAT** | | | |
| **USRCLASS.DAT** | | | |

Then answer:

1. Why do responders need both system hives and user hives?

2. Why is NTUSER.DAT often more useful for user activity questions than SOFTWARE?

3. Why should you care about hive provenance and the user profile path from which a hive was taken?

> **Guidance:** Keep the answer practical. Focus on what each hive helps you answer in an incident, not only on formal definitions.

---

### Task 2 — Hunt for Persistence and Suspicious Startup Configuration

**Objective:** Identify Registry locations that may reveal malware persistence or suspicious startup behavior.

List the Registry locations you would check first for persistence on HR-LT12.

At minimum, include:

- Run keys
- RunOnce keys
- Services
- Other common autorun-related areas you consider worth checking

Fill in the table below.

| Registry Path or Area | Why It Matters | What a Suspicious Finding Might Look Like |
|---|---|---|
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | | |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | | |
| `HKLM\SYSTEM\CurrentControlSet\Services` | | |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce` | | |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` | | |

Add at least five more locations or areas of your own.

Then answer:

1. Why is a startup entry in a user hive often important even if nothing appears in system-wide autoruns?

2. Why does path context matter when judging whether a Run key value is suspicious?

3. Why should you avoid assuming every unusual startup entry is malicious?

---

### Task 3 — Investigate USB and Removable Device History

**Objective:** Use Registry evidence to assess whether removable media may have been involved.

Assume there is concern that files may have been copied to a USB device.

Identify the Registry areas you would review first and explain what each can reveal.

Use the table below.

| Registry Path or Area | What It May Reveal | Why It Matters |
|---|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` | | |
| Mounted devices / volume mapping areas | | |
| Device class / storage-related keys | | |
| User shell or folder-history areas | | |

Add at least four more relevant areas or supporting artifacts of your own, even if they are not all Registry-only.

Then answer:

1. Why is USB vendor/model/serial data useful in an investigation?

2. Why is device presence not the same as proof that files were copied?

3. What artifacts would you want to correlate with USB history to strengthen a data-transfer theory?

---

### Task 4 — Review Remote Access and User Activity Clues

**Objective:** Identify Registry areas relevant to remote access, user behavior, and possible lateral activity.

For this task, focus on signs that the user or attacker may have used RDP, Explorer navigation, or user-level application execution.

Fill in the table below.

| Registry Path or Area | What It Helps Answer | Why It Matters in IR |
|---|---|---|
| RDP-related configuration keys | | |
| UserAssist | | |
| Typed paths / Explorer history areas | | |
| Shell-related history or shellbags-related areas | | |
| RecentDocs-related areas | | |

Add at least five more relevant user-activity or remote-access areas of your own.

Then answer:

1. Why is UserAssist useful even though it reflects GUI-driven activity rather than everything that ran on the system?

2. Why can typed paths and Explorer history matter in a staging or exfiltration investigation?

3. Why should remote-access configuration findings be correlated with logs rather than treated as proof of connection by themselves?

---

### Task 5 — Identify Cloud Sync Client Evidence

**Objective:** Build a collection and review plan for OneDrive or another local sync client.

Assume OneDrive is installed on HR-LT12, and there is concern that sensitive files may have been synchronized to a cloud account.

Identify the local evidence sources you would want to examine.

Use the table below.

| Artifact Source | What It May Reveal | Why It Matters |
|---|---|---|
| Registry keys related to OneDrive or sync configuration | | |
| Local sync root folder | | |
| Client logs | | |
| Local databases or configuration files | | |
| User profile directories tied to sync activity | | |

Add at least five more relevant sources or sub-sources of your own.

Then answer:

1. Why is local cloud-client configuration often important even if you do not yet have provider-side logs?

2. Why do account identifiers and sync-root paths matter?

3. Why should a responder distinguish "cloud client installed" from "files actually synchronized"?

> **Tip:** Stay disciplined. The goal is to identify what can support or challenge the theory, not to assume exfiltration because OneDrive exists.

---

### Task 6 — Correlate Registry and Cloud Findings into Investigative Questions

**Objective:** Turn raw Registry and sync-client evidence into focused IR questions.

Write at least 10 specific investigative questions you want the Registry and cloud-storage artifacts to answer for HR-LT12.

Examples:

- Was a suspicious program configured to start automatically?
- Was a USB storage device connected during the suspected incident window?
- Was OneDrive configured for a personal or organizational account?
- Which local folder path was associated with the sync root?
- Is there evidence the user browsed to or interacted with a directory containing sensitive files?

Then group them into the categories below.

| Category | Question Numbers |
|---|---|
| Persistence | |
| Removable media | |
| User activity / execution | |
| Remote access | |
| Cloud sync / data movement | |

After that, choose five of the questions and map them to the best artifact sources.

| Question | Primary Artifact Source | Secondary / Corroborating Artifact |
|---|---|---|
| | | |
| | | |
| | | |
| | | |
| | | |

---

### Task 7 — Separate Strong Registry Findings from Overclaims

**Objective:** Practice distinguishing what Registry and cloud artifacts strongly support from what still needs corroboration.

Read each statement below and classify it as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by these artifacts alone

| Statement | Classification | Why |
|---|---|---|
| A OneDrive-related configuration key exists for the user profile | | |
| Sensitive files were exfiltrated to a threat actor-controlled cloud account | | |
| A USB storage device with a specific vendor and serial was connected to the host | | |
| Files were definitely copied to that USB device | | |
| A suspicious executable path is referenced in a Run key | | |
| The executable ran successfully at every logon | | |
| UserAssist shows the user likely interacted with a program through the GUI | | |
| The user intentionally used OneDrive to steal data | | |

Then write four additional statements of your own and classify them the same way.

> **Guidance:** Registry and cloud-client artifacts are often rich, but they do not by themselves answer motive, success, or intent.

---

### Task 8 — Build a Registry and Cloud Correlation Timeline

**Objective:** Turn your findings into a time-ordered sequence useful for IR analysis.

Create a mini-timeline with at least 10 entries if possible.

| Time (UTC) | Artifact Source | Event or Observation | Key / Path / Artifact | Why It Matters |
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

- Suspected persistence configuration
- USB device appearance
- Cloud-client configuration or account evidence
- UserAssist-related usage clues
- Explorer or typed-path activity
- Supporting log or file observations that help with timing

Then answer:

1. Why is a timeline more useful than isolated key findings?

2. Which events in your timeline appear most central to the case theory?

3. What additional artifact types outside the Registry would you want next?

---

### Task 9 — Write a Registry and Cloud Findings Summary

**Objective:** Produce a concise working-note summary suitable for a case file.

Write a 3–5 paragraph analyst summary describing what your Registry and cloud-storage review indicates about HR-LT12.

Your summary should include:

- The most important Registry findings
- Whether you found evidence suggestive of persistence, removable-device history, remote-access clues, or cloud sync configuration
- What is strongly supported by the evidence
- What still requires corroboration from logs, file-system artifacts, Prefetch, browser history, or provider-side data
- What you recommend reviewing next

Write it as a working-note summary, not a final incident report.

---

### Task 10 — Write an Analyst Handoff Note

**Objective:** Summarize the most important follow-up items for another responder.

Write a short handoff note using the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Most Important Registry Findings:
- 

Most Important Cloud-Related Findings:
- 

What Is Strongly Supported:
- 

What Still Needs Corroboration:
- 

Recommended Next Artifacts:
1.
2.
3.

Open Questions:
- 

Notes for Incoming Analyst:
```

Your note should make it easy for another responder to continue the investigation without reconstructing your logic from scratch.

---

### Task 11 — Reflection

Answer the following in 3–5 sentences each.

**1. Why the Registry matters in IR**
Why is the Registry often one of the most valuable evidence sources even when the suspicious file is gone?

**2. Configuration versus action**
Why should responders distinguish between evidence that something was configured and evidence that it was actually used?

**3. Cloud sync versus exfiltration**
Why is local evidence of OneDrive or another sync client useful, but not by itself proof of malicious data exfiltration?

**4. Correlation over certainty**
Why are Registry findings strongest when paired with NTFS, logs, execution artifacts, and user-activity evidence?

---

## Hands-On Walkthrough (Using Simulated Data)

This walkthrough exercises Tasks 2–6 against the pre-parsed registry, USB, shellbag, and OneDrive data in [`Data/HR-LT12/`](../../Data/HR-LT12/). Commands are PowerShell. The same operations work in Python or in a spreadsheet.

### Step 1 — Find the persistence entry

```powershell
$run = Import-Csv 'Data\HR-LT12\registry-runkeys.csv'
$run | Where-Object { $_.ValueData -like "*AppData*" -and $_.ValueData -notlike "*Microsoft*" } |
       Select-Object Hive, KeyPath, ValueName, ValueData, LastWriteTime
```

```python
import csv
with open('Data/HR-LT12/registry-runkeys.csv') as f:
    run = list(csv.DictReader(f))
hits = [r for r in run if 'AppData' in r['ValueData'] and 'Microsoft' not in r['ValueData']]
for r in hits:
    print(r['Hive'], r['KeyPath'], r['ValueName'], r['ValueData'], r['LastWriteTime'])
```

Expected: **one row**, `HpHotkeyMonitor` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` pointing to `C:\Users\hr-user\AppData\Local\hp-hotkey\hpkey.exe`, last-write time 2024-11-08 19:06:42 UTC. The filter excludes the legitimate Microsoft-vendored `OneDrive` and `Teams` Run keys, which also live under AppData. The suspicious one is the third-party-looking entry that does not reference any Microsoft path. Many legitimate per-user apps also run from AppData, so the path alone does not prove malice. What makes this entry suspicious is the combination of a name that imitates an HP utility and a binary in user-writable AppData rather than `Program Files\HP\`.

### Step 2 — Profile the Kingston USB

```powershell
$usb = Import-Csv 'Data\HR-LT12\usbstor.csv'
$usb | Where-Object { $_.FriendlyName -like "*Kingston*" } |
       Select-Object SerialNumber, FirstConnected, LastConnected, VolumeGuid
```

```python
with open('Data/HR-LT12/usbstor.csv') as f:
    usb = list(csv.DictReader(f))
for r in usb:
    if 'Kingston' in r['FriendlyName']:
        print(r['SerialNumber'], r['FirstConnected'], r['LastConnected'], r['VolumeGuid'])
```

Expected: **three Kingston devices**. The one matching the incident window has serial `001A92053B7CBE3196B40A0F` and `FirstConnected = LastConnected = 2024-11-12 16:42:08`. Identical first and last connection times mark a single-connection device, characteristic of an attacker-supplied or one-off drive. Its volume GUID is `{f1d2e9a4-77c0-4b91-83be-ab4a0ed1c6e5}`. Keep that handy for the next step.

### Step 3 — Bind the volume GUID to a drive letter

```powershell
$mp = Import-Csv 'Data\HR-LT12\mountpoints.csv'
$mp | Where-Object { $_.VolumeGuid -eq "{f1d2e9a4-77c0-4b91-83be-ab4a0ed1c6e5}" }
```

```python
with open('Data/HR-LT12/mountpoints.csv') as f:
    mp = list(csv.DictReader(f))
for r in mp:
    if r['VolumeGuid'] == "{f1d2e9a4-77c0-4b91-83be-ab4a0ed1c6e5}":
        print(r)
```

Expected: **one row** binding the Kingston volume `{f1d2e9a4-...}` to a drive letter, with `LastWriteTime` around 2024-11-12 16:42:14 UTC. Drop the `Where-Object` filter to see the surrounding context: every drive letter the system has bound. The Kingston entry is the one matching the volume GUID from Step 2.

### Step 4 — Confirm folder navigation on the USB

```powershell
$sb = Import-Csv 'Data\HR-LT12\shellbags.csv'
$sb | Where-Object { $_.AbsolutePath -like "E:\HR*" } |
      Select-Object AbsolutePath, FirstInteracted, LastInteracted
```

```python
with open('Data/HR-LT12/shellbags.csv') as f:
    sb = list(csv.DictReader(f))
for r in sb:
    if r['AbsolutePath'].startswith("E:\\HR"):
        print(r['AbsolutePath'], r['FirstInteracted'], r['LastInteracted'])
```

Expected: **4 rows** — the user navigated into `E:\HR\`, `E:\HR\Confidential\`, `E:\HR\Confidential\Salary_Data\`, and `E:\HR\Confidential\Personnel\`. Timestamps fall within the 2024-11-12 16:42–17:31 UTC window between the Kingston's insertion and its removal. Shellbags survive after the USB is removed, which makes them the most reliable single piece of evidence that the user browsed sensitive content on the device.

### Step 5 — Identify the personal OneDrive account

```powershell
$oda = Import-Csv 'Data\HR-LT12\onedrive-accounts.csv'
$oda | Select-Object AccountId, Email, ServiceEndpointUri, UserCid, LastWriteTime
```

```python
with open('Data/HR-LT12/onedrive-accounts.csv') as f:
    oda = list(csv.DictReader(f))
for r in oda:
    print(r['AccountId'], r['Email'], r['ServiceEndpointUri'], r['UserCid'], r['LastWriteTime'])
```

Expected: **two rows** — `Business1` (corporate `hr-user@finance.example.com`) and `Personal` (`hr.user.personal@outlook.com`). The personal account's `LastWriteTime` falls in the same incident window. A personal account alongside a corporate one on a managed laptop is in itself a signal worth following.

### Step 6 — List files synchronized to the personal account

```powershell
$ods = Import-Csv 'Data\HR-LT12\onedrive-syncdb.csv'
$ods | Select-Object FileName, Size, LastSync, SyncState
```

```python
with open('Data/HR-LT12/onedrive-syncdb.csv') as f:
    ods = list(csv.DictReader(f))
for r in ods:
    print(r['FileName'], r['Size'], r['LastSync'], r['SyncState'])
```

Expected: **8 rows** showing HR-related files entering the Personal sync queue between 16:55 and 17:10 UTC on 2024-11-12. The `SyncState` column records the client's local view of each file, and all eight read `Synchronized`. Confirming that the uploads completed takes provider-side logs. Combined with Step 5's account identification, this is the cloud half of a possible two-channel exfiltration finding.

### What you've just done

You worked six independent registry, shell, and cloud sources. Five align to the 2024-11-12 16:42–17:31 UTC window. The sixth, the Run key, was planted four days earlier, on 2024-11-08. Together they show a suspicious Run-key persistence (Step 1), a one-off Kingston USB connection (Step 2), the drive-letter binding (Step 3), the user navigating sensitive folders on the USB (Step 4), a personal OneDrive account configured (Step 5), and HR-related files synchronized to that personal account (Step 6). Walk back through Tasks 2 through 6 and complete the analyst-notes scaffold using the data you just produced. Every cell has a concrete answer.

---

## Deliverables Checklist

Your `lab05-notes.md` should contain:

- [ ] **Task 1** — Core Registry hive table with written responses
- [ ] **Task 2** — Persistence-focused Registry review table with added locations
- [ ] **Task 3** — USB/removable-device analysis table with written responses
- [ ] **Task 4** — Remote access and user-activity table with added areas
- [ ] **Task 5** — Cloud sync client evidence table with added sources
- [ ] **Task 6** — At least 10 investigative questions grouped by category, plus artifact mapping
- [ ] **Task 7** — Strongly supported vs overclaim exercise
- [ ] **Task 8** — Registry and cloud correlation timeline with at least 10 entries where possible
- [ ] **Task 9** — Registry and cloud findings summary
- [ ] **Task 10** — Analyst handoff note
- [ ] **Task 11** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab05/
├── ReadMe.md                     ← This file
├── lab05-notes.md                ← Your working notes file (fill this in)
├── walkthrough-answers.md        ← Sample answers for the Hands-On Walkthrough
├── task-answers.md               ← Sample answers for the workbook Tasks
├── Lab05_01/ReadMe.md            ← Ch5 §5.1 — Registry Structure and Key Hives
├── Lab05_02/ReadMe.md            ← Ch5 §5.2 — Important Keys for IR
├── Lab05_03/ReadMe.md            ← Ch5 §5.3 — Cloud Storage (OneDrive Example)
└── Lab05_04/ReadMe.md            ← Ch5 §5.4 — Correlating Registry and Cloud Evidence
```

---

> **Going deeper:** The OneDrive sync database and registry-`Accounts` artifacts touched here are the host-side half of cloud-identity forensics. The other half lives in the cloud — Microsoft Entra ID Sign-in / Audit logs, the Unified Audit Log, OAuth consent, MailItemsAccessed. `Book/AppendixB.md` (Cloud Identity and Microsoft 365 Forensics) covers the cloud-side half with concrete KQL and `Search-UnifiedAuditLog` examples.

---

## Key Takeaways

- **The Registry preserves system and user context.** It often reveals what the host was configured to do even when obvious traces are gone.
- **System hives and user hives answer different questions.** You usually need both.
- **Configuration is not the same as execution.** A Run key, service entry, or sync client setting is important, but it still needs interpretation and correlation.
- **Cloud-client evidence can be highly valuable.** Account clues, sync-root paths, logs, and local configuration often support data-movement investigations.
- **Registry analysis is strongest when correlated.** Its real value emerges when you connect it with file-system artifacts, logs, execution evidence, and user activity.

---

**Next:** Lab 5.1 — Registry Structure and Key Hives

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
