# Lab 04 — Windows File System Forensics (NTFS)

**Supporting [Chapter 4: Windows File System Forensics (NTFS)](../../Book/Chapter04.md)**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

When a Windows host is compromised, the file system often tells the most durable part of the story.

Attackers drop tools, rename files, stage payloads, delete evidence, and modify content long before anyone starts asking questions. Even when logs are incomplete and memory is gone, NTFS artifacts can still show what existed on disk, where it lived, when it changed, and whether someone tried to cover their tracks afterward.

This lab introduces practical NTFS analysis from an incident response perspective. You will work through the questions responders ask when suspicious binaries appear on a Windows system: which files were created, where they were placed, whether they were renamed or deleted, whether their timestamps make sense, and whether the attacker tried to hide activity.

Lab 04 focuses on the Master File Table, the USN Journal, and the analytical workflow needed to turn raw file system metadata into findings you can use and defend. The goal goes beyond parsing NTFS artifacts. It is to build the habit of correlating them carefully, documenting what they support, and being honest about what they don't prove.

---

## What This Lab Covers

| Section | Topic |
|---|---|
| 4.1 | NTFS Overview |
| 4.2 | The Master File Table (MFT) |
| 4.3 | USN Journal |
| 4.4 | Tools |
| 4.5 | Correlating NTFS Artifacts in IR |
| 4.6 | The Recycle Bin: `$I` and `$R` Files |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain the role of the MFT in Windows forensic analysis
- Identify what kinds of information can be extracted from NTFS file records
- Distinguish between Standard Information and File Name timestamps at a practical level
- Use file system metadata to identify suspicious file creation, staging, renaming, and deletion activity
- Explain what the USN Journal adds beyond the MFT alone
- Correlate MFT and USN Journal findings into a short, defensible analytical summary
- Recognize signs that may suggest timestamp manipulation or post-execution cleanup

---

## Estimated Time and Difficulty

**Difficulty:** Intermediate

**First time through the material:** 2.5–4 h

**Refresh (already familiar with the chapter):** 60–90 min

> **Key terms used in this lab:** MFT, USN journal, MACB, $STANDARD_INFORMATION, $FILE_NAME, alternate data streams. See the consolidated [Glossary](../../Book/Glossary.md) for definitions. The chapter cross-references in each entry take you back to the deeper coverage in `Book/`.

---

## Prerequisites

- Completion of Labs 01–03, or equivalent familiarity with Windows IR collection and triage
- A text editor or markdown editor
- Your `lab04-notes.md` file (template included in this folder)
- Optional: a Windows VM with **[MFTECmd](https://ericzimmerman.github.io/)**, AnalyzeMFT, or another NTFS parser installed
- Optional: a USN Journal parser (MFTECmd supports USN Journal parsing)
- Optional: a sample MFT or NTFS image for hands-on parsing practice
- Optional: **[KAPE](https://www.kroll.com/en/services/cyber/incident-response/kroll-artifact-parser-extractor-kape)** for collecting `$MFT` / `$J` from a live or mounted system (the `!SANS_Triage` target plus the `!EZParser` module produces analysis-ready CSVs in one pass)
- Optional: **[Arsenal Image Mounter](https://arsenalrecon.com/downloads/)** if you need to mount a forensic image (E01, VHDX, raw) as a physical disk on a Windows analysis host so MFTECmd can read `\\.\PhysicalDriveN` directly

> **Working without a VM:** Pre-parsed CSV outputs for the WKSTN-221 scenario are in [`Data/WKSTN-221/`](../../Data/WKSTN-221/). Use `mft.csv` and `usn-journal.csv` as the input for this lab's parsing exercises if you do not have your own collection to work against.

---

## Scenario

A Windows workstation named **WKSTN-221** has been flagged during an active incident response engagement. The initial triage package suggests suspicious tool staging under one user profile, but event logging is incomplete and the system was not isolated before some cleanup may have occurred.

**What you know so far:**

- A suspicious executable may have been downloaded to the assigned user's Downloads folder
- A second binary may have been staged in `C:\Temp`
- A responder suspects at least one file was deleted after execution based on USN Journal fragments
- Prefetch shows execution of a file named `svc_updater.exe` but no corresponding file currently exists on disk
- You do not yet know whether timestamps are trustworthy
- You need to determine what files existed, where they were placed, and whether there is evidence of rename or delete activity

Your task: use NTFS artifacts to reconstruct the file-level story as clearly and defensibly as possible.

---

## Background: Why NTFS Matters in Incident Response

Once you need detailed answers about dropped tools, deleted files, and suspicious paths, NTFS becomes one of your most durable evidence sources. Windows responders often focus first on logs, processes, and user activity artifacts, and that's the right instinct during early triage.

| Artifact | What It Helps You Answer |
|---|---|
| **MFT** | What files and directories existed, their full paths, timestamps, size, and allocation state |
| **USN Journal** | What changed over time — creations, deletions, renames, and other file system activity within the journal retention window |

Together, the MFT's structured records and the USN Journal's change history can often show that a suspicious file existed, and what happened to it, even if the file itself is long gone.

**The two timestamp sources you need to understand:**

| Timestamp Source | Location | Updated By |
|---|---|---|
| **Standard Information (SI)** | `$STANDARD_INFORMATION` attribute | Easily modified by user-mode applications and some attacker tools |
| **File Name (FN)** | `$FILE_NAME` attribute | Updated by the NTFS kernel driver — harder to modify without specialized tooling |

Differences between SI and FN timestamps do not automatically prove tampering, but they can indicate that a file was moved or copied, or that its SI timestamps were manipulated after the fact.

> **IR Reality Check:** A file record marked as unallocated in the MFT is not the same as a file that never existed. Attackers can delete tools and clear obvious traces, but NTFS metadata frequently survives long enough to show what happened anyway.

---

## Lab Tasks

---

### Task 1 — Identify Suspicious File Locations

**Objective:** Define where you would look first when investigating possible attacker tooling on disk — before parsing a single artifact.

Good NTFS analysis starts with knowing where to look. Certain paths are high-value targets in almost every Windows investigation because they are writable by standard users, are rarely monitored, and are commonly used for staging, downloading, or executing attacker tools.

**Part A — High-value path table**

Complete the table below. The first six rows are provided. Add at least four more based on your own experience or research.

| Location or Path | Why It Matters | Example Suspicious Use |
|---|---|---|
| `C:\Users\<user>\Downloads\` | Default browser download location; writable by user; commonly overlooked | Malicious document or dropper downloaded via phishing |
| `C:\Temp\` | Writable without elevation on many systems; used for staging | Attacker extracts toolset here after initial access |
| `C:\ProgramData\` | Writable by standard users; often overlooked in AV scope | Persistence mechanism installed here to avoid user-profile artifacts |
| `C:\Users\<user>\AppData\Local\Temp\` | High-volume temp activity makes malicious files harder to spot | Dropper writes payload here before executing |
| `C:\Users\Public\` | Writable by all users; accessible across accounts | Staging location accessible to multiple compromised accounts |
| `C:\Windows\Temp\` | System temp; elevated access typically required but not always | Attacker with elevated access stages tools here to blend with system activity |
| *(Add your own)* | | |
| *(Add your own)* | | |
| *(Add your own)* | | |
| *(Add your own)* | | |

**Part B — Short answers**

Answer each in 2–3 sentences:

**1. Why do attackers often avoid obviously named malware folders — and what does that mean for your analysis?**

```
[Your response here]
```

**2. Why can a "normal-looking" file path still be suspicious in context? Give a specific example.**

```
[Your response here]
```

**3. How would your path prioritization differ between a user workstation and a domain controller?**

```
[Your response here]
```

---

### Task 2 — Parse and Review the MFT

**Objective:** Extract file system metadata and identify candidate files that warrant closer examination.

**Part A — Collection and parsing**

If you have a live Windows VM or a sample MFT available, use MFTECmd or your preferred parser to export the MFT to CSV.

**MFTECmd example:**

```powershell
# Parse MFT from a live system (requires admin)
MFTECmd.exe -f "\\.\C:" --csv "E:\IR\WKSTN-221\filesystem\" --csvf mft_output.csv

# Parse from an acquired MFT file
MFTECmd.exe -f "E:\Evidence\$MFT" --csv "E:\IR\WKSTN-221\filesystem\" --csvf mft_output.csv
```

**Timeline Explorer filter tips:**
- Filter `Extension` column for: `.exe`, `.dll`, `.ps1`, `.bat`, `.cmd`, `.zip`, `.7z`, `.rar`
- Filter `ParentPath` for suspicious directories from Task 1
- Filter `InUse` for `False` to surface deleted file records
- Sort by `Created0x10` (SI Created) to find recently created files

**Part B — Candidate file table**

Document your findings. If you do not have a dataset, describe the exact filters or queries you would apply and create representative hypothetical entries based on the scenario.

| File Name | Full Path | SI Created (UTC) | FN Created (UTC) | Allocated / Deleted | Why It Stands Out |
|---|---|---|---|---|---|
| svc_updater.exe | `C:\Temp\svc_updater.exe` | | | Deleted | Matches Prefetch entry; no longer present on disk |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |

> **Guidance:** The goal is to identify what deserves follow-up, not to label every unusual file as attacker tooling. A `.exe` in Downloads is a starting point for analysis, not a conclusion.

---

### Task 3 — Compare Standard Information and File Name Timestamps

**Objective:** Examine timestamp sources for signs of manipulation or file movement that may affect your timeline.

Choose three files from Task 2 — or create three representative hypothetical entries if you do not have a real dataset. For each file, record both SI and FN timestamps and note any meaningful differences.

| File | SI Created | SI Modified | SI Changed | SI Accessed | FN Created | FN Modified | FN Changed | FN Accessed | Observations |
|---|---|---|---|---|---|---|---|---|---|
| | | | | | | | | | |
| | | | | | | | | | |
| | | | | | | | | | |

**Timestamp source reference:**

| MFTECmd Column | Meaning | Notes |
|---|---|---|
| `Created0x10` | SI Created | Most easily modified by attacker tools |
| `LastModified0x10` | SI Last Modified | Modified when file content changes |
| `LastRecordChange0x10` | SI MFT Entry Changed | Updated when any MFT attribute changes |
| `LastAccess0x10` | SI Last Accessed | May be disabled or unreliable on many systems |
| `Created0x30` | FN Created | Set by NTFS kernel driver at file creation |
| `LastModified0x30` | FN Last Modified | Updated by NTFS driver, not easily faked |

**Short answers:**

**1. Why can differences between SI and FN timestamps matter in an investigation?**

```
[Your response here]
```

**2. What kinds of SI/FN mismatches would cause you to look more closely at a file?**

```
[Your response here]
```

**3. Why should you be careful about claiming "timestomping" based on timestamp differences alone?**

```
[Your response here]
```

**4. What legitimate activity could explain SI/FN discrepancies that have nothing to do with attacker behavior?**

```
[Your response here]
```

---

### Task 4 — Review the USN Journal for Change Activity

**Objective:** Use NTFS change history to identify file creation, rename, and deletion events tied to suspicious files.

The USN Journal records file system change events — creations, deletions, renames, and other operations — within its retention window. It can show you what happened to a file even if the file itself no longer exists in the MFT.

**MFTECmd USN Journal parsing:**

```powershell
# Parse USN Journal from acquired image or live system
MFTECmd.exe -f "E:\Evidence\$J" --csv "E:\IR\WKSTN-221\filesystem\" --csvf usn_output.csv

# Filter in Timeline Explorer by file name or parent path to find relevant records
```

**USN reason codes to look for:**

| Reason Code | Meaning |
|---|---|
| `FILE_CREATE` | File was created |
| `FILE_DELETE` | File was deleted |
| `RENAME_OLD_NAME` | Pre-rename file name — what the file was called before |
| `RENAME_NEW_NAME` | Post-rename file name — what it was renamed to |
| `DATA_OVERWRITE` | File content was overwritten |
| `CLOSE` | File handle was closed — often follows create or modify |

**Part A — USN findings table**

Document records related to the suspicious files or paths from Task 2.

| File / Path | Change Type (Reason Code) | Timestamp (UTC) | Parent Path | Why It Matters | Notes |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |

**Part B — Short answers**

**1. What does the USN Journal tell you that the MFT alone may not make obvious?**

```
[Your response here]
```

**2. Why is rename activity particularly important in attacker tool staging investigations?**

```
[Your response here]
```

**3. How can deleted or short-lived files still leave useful NTFS evidence? What limits that visibility?**

```
[Your response here]
```

---

### Task 5 — Correlate MFT and USN Findings

**Objective:** Combine file existence and file change evidence into coherent, evidence-based analytical statements.

Choose two suspicious files or paths from your Task 2 and Task 4 findings. For each, document what the MFT shows, what the USN Journal adds, and what the combination most reasonably supports. Stay strictly within what the evidence allows.

| File or Path | What the MFT Shows | What the USN Journal Shows | Most Reasonable Interpretation | Confidence |
|---|---|---|---|---|
| | | | | High / Med / Low |
| | | | | High / Med / Low |

**Confidence rating:**
- **High** — Two or more independent artifact sources agree on the same interpretation
- **Medium** — Single reliable artifact supports the interpretation
- **Low** — Indirect, ambiguous, or single low-confidence source

**Acceptable interpretation examples:**

- "A suspicious executable existed in a user-writable directory and was deleted within the same timeframe as suspected attacker activity"
- "A file appears to have been renamed shortly after creation — consistent with an attacker renaming a tool to avoid signature detection"
- "A staging directory was created and populated during the suspected compromise window"
- "The metadata suggests cleanup activity occurred, but intent cannot be determined from file system evidence alone"

> **Guidance:** Avoid claims like "the attacker executed this tool" unless you have separate execution evidence from Prefetch, Amcache, or event logs. File system evidence establishes *existence and change* — execution requires a separate evidence source.

---

### Task 6 — Build a File System Mini-Timeline

**Objective:** Turn NTFS artifact findings into a usable, time-ordered sequence of events that supports the broader investigation.

Build a timeline using your MFT and USN Journal findings. Include at least eight entries where possible. Every entry must have a named artifact source. Entries without attribution do not belong in the timeline.

| Time (UTC) | Artifact Source | Event Type | File / Path | Significance | Confidence |
|---|---|---|---|---|---|
| | MFT — `Created0x30` | File created | | | |
| | USN Journal — `FILE_CREATE` | File creation recorded | | | |
| | USN Journal — `RENAME_OLD_NAME` | File renamed | | | |
| | USN Journal — `RENAME_NEW_NAME` | File renamed to | | | |
| | MFT — `LastModified0x10` | File content modified | | | |
| | USN Journal — `FILE_DELETE` | File deleted | | | |
| | MFT — unallocated record | Deleted file record recovered | | | |
| | | | | | |

**Short answers:**

**1. Why is a timeline more useful to an investigation than a list of isolated file records?**

```
[Your response here]
```

**2. What would you want to correlate next — outside NTFS — to strengthen your findings?**

```
[Your response here]
```

**3. Which artifact types from earlier chapters pair most naturally with this NTFS timeline?**

```
[Your response here]
```

---

### Task 7 — Write an NTFS Findings Summary

**Objective:** Produce a concise, defensible analyst summary based on file system metadata — suitable for a case note or working report.

Write a summary of 2–4 paragraphs describing what your NTFS review indicates about activity on WKSTN-221. Your summary should cover:

- The suspicious file locations identified and why they are notable
- Whether suspicious files appear to have been created, renamed, deleted, or staged
- Whether timestamp patterns appear normal, suspicious, or inconclusive — and what specifically raises or resolves concern
- What NTFS artifacts support your assessment, named specifically
- What you still cannot conclude from file system metadata alone — and what additional artifact types would close those gaps

Write this as if it were going into a case working notes file. Another analyst reading it should understand exactly what the file system evidence shows and where its limits are.

```
[Your NTFS findings summary here — 2 to 4 paragraphs]
```

> **Guidance:** This is an NTFS-scoped summary, not a full incident conclusion. Stay within what file system evidence supports. If execution evidence from Prefetch or Amcache would strengthen a finding, note that, but don't assert it from file system data alone.

---

### Task 8 — Reflection

Answer the following in 3–5 sentences each:

**1. Why the MFT matters in IR**
Why is the MFT such a useful artifact even when you already have EDR telemetry and event logs covering the same timeframe?

```
[Your response here]
```

**2. Deleted does not mean gone**
Why can deleted files still be forensically significant in a Windows investigation? What determines whether their records are recoverable?

```
[Your response here]
```

**3. Metadata versus execution**
Why should responders be careful not to conflate suspicious file metadata with proof that a file was executed? What separate evidence is needed to establish execution?

```
[Your response here]
```

**4. Correlation over certainty**
Why is NTFS analysis strongest when paired with other artifact types rather than treated as a complete story on its own? Give a specific example using the WKSTN-221 scenario.

```
[Your response here]
```

---

## Hands-On Walkthrough (Using Simulated Data)

If you don't have a Windows VM with `MFTECmd` and a sample `$MFT` available, you can work this lab against the pre-parsed data in [`Data/WKSTN-221/`](../../Data/WKSTN-221/). The walkthrough below uses PowerShell on the CSV outputs that `MFTECmd` would have produced for the WKSTN-221 scenario.

> **Cross-platform note.** You can do every step below equivalently in Python 3 (`csv.DictReader` + list comprehensions), in `pandas`, in `awk`, or in a spreadsheet. The first Python equivalent is shown below the corresponding PowerShell so you can pick whichever environment you already have. The investigative pattern matters, not the syntax.

### Step 1 — Load the MFT and look at it

```powershell
$mft = Import-Csv 'Data\WKSTN-221\mft.csv'
$mft.Count
```

```python
import csv
with open('Data/WKSTN-221/mft.csv') as f:
    mft = list(csv.DictReader(f))
print(len(mft))
```

Expected output: **77** rows. Inspect the columns:

```powershell
$mft[0] | Get-Member -MemberType NoteProperty | Select-Object Name
```

```python
print(list(mft[0].keys()))
```

You should see columns including `EntryNumber`, `ParentEntryNumber`, `InUse`, `ParentPath`, `FileName`, `FileSize`, `Created0x10`, `LastModified0x10`, `Created0x30`, `LastModified0x30`. The `0x10` columns are `$SI` timestamps, and the `0x30` columns are `$FN` timestamps.

### Step 2 — Filter for activity in the user's Temp directory

```powershell
$mft | Where-Object { $_.ParentPath -like "*payroll-admin\AppData\Local\Temp*" } |
       Sort-Object Created0x10 |
       Select-Object FileName, InUse, Created0x10, LastModified0x10, Created0x30
```

```python
temp = [r for r in mft if "payroll-admin\\AppData\\Local\\Temp" in r['ParentPath']]
temp.sort(key=lambda r: r['Created0x10'])
for r in temp:
    print(r['FileName'], r['InUse'], r['Created0x10'], r['Created0x30'])
```

Expected: **10** rows including `update.exe`, `~$Q4_Payroll_Review.xlsm`, `MSForms.exd`, three `~DF*.tmp` files, plus benign legacy entries (`wmsetup.log`, `Office_Setup_log.txt`). The `update.exe` row has `InUse=False`. Its MFT record is unallocated, so the file has been deleted but the metadata persists. No `b.tmp` row appears, although Step 4 shows that the file existed under that name. A rename keeps the MFT record, so record 22417 now carries only the name `update.exe`.

### Step 3 — Look for timestomp signals

For each suspicious file, compare `Created0x10` to `Created0x30`:

```powershell
$mft | Where-Object { $_.FileName -eq "update.exe" } |
       Select-Object FileName, Created0x10, Created0x30, LastModified0x10, LastModified0x30
```

```python
for r in mft:
    if r['FileName'] == "update.exe":
        print(r['FileName'], r['Created0x10'], r['Created0x30'], r['LastModified0x10'], r['LastModified0x30'])
```

In this scenario the `$SI` and `$FN` values match, so there is no divergence signal. Both creation columns read `2024-11-14 14:20:11.0000000`, and both modified columns read `2024-11-14 14:20:11.0500000`. That does not prove the binary was never timestomped. A stomp followed by a rename or same-volume move makes NTFS copy the faked `$SI` values into `$FN`, and Step 4 shows that this file was renamed. Check the USN Journal and the MFT record number before you conclude. Here both agree with the MFT dates. The journal records the file's creation as `b.tmp` on record 22417 at 14:20:11.00 UTC, its last data write at 14:20:11.05 UTC, and the rename to `update.exe` at 14:20:11.5 UTC. Record 22417 sits beside records 22418–22421, which were created between 14:18:56 and 14:19:42.6 UTC. A `Created0x10` predating `Created0x30` is the classic timestomping signature, but its absence does not clear a file.

### Step 4 — Pull the USN Journal entries for the deleted file

```powershell
$usn = Import-Csv 'Data\WKSTN-221\usn-journal.csv'
$usn | Where-Object { $_.FileName -eq "update.exe" -or $_.FileName -eq "b.tmp" } |
       Sort-Object USN |
       Select-Object UpdateTimestamp, FileName, UpdateReasons
```

```python
with open('Data/WKSTN-221/usn-journal.csv') as f:
    usn = list(csv.DictReader(f))
hits = [r for r in usn if r['FileName'] in ("update.exe", "b.tmp")]
hits.sort(key=lambda r: int(r['USN']))
for r in hits:
    print(r['UpdateTimestamp'], r['FileName'], r['UpdateReasons'])
```

Expected output: nine rows showing `b.tmp` created at 14:20:11.00, written, closed at 14:20:11.05, then `RenameOldName`/`RenameNewName` to `update.exe` at 14:20:11.25 and 14:20:11.5, then `BasicInfoChange` at 14:21:03 (the execution), then `FileDelete` at 14:23:44. All nine rows belong to MFT record 22417. The MFT shows the record's current name, and the journal shows its history. Reading the sequence reconstructs the brief life of an attacker tool that no longer exists in the live file system.

### Step 5 — Cross-reference with Prefetch

```powershell
$pf = Import-Csv 'Data\WKSTN-221\prefetch.csv'
$pf | Where-Object { $_.ExecutableName -eq "UPDATE.EXE" } |
      Select-Object ExecutableName, Hash, RunCount, LastRun, PreviousRun0
```

```python
with open('Data/WKSTN-221/prefetch.csv') as f:
    pf = list(csv.DictReader(f))
for r in pf:
    if r['ExecutableName'] == "UPDATE.EXE":
        print(r['ExecutableName'], r['Hash'], r['RunCount'], r['LastRun'], r['PreviousRun0'])
```

Expected: one row, `RunCount=1`, `LastRun=2024-11-14 14:21:03`. This row is the corroborating evidence that ties the MFT record (file existed) and the USN entry (file lifecycle) to actual execution.

### Step 6 — Tie the binary to a hash

```powershell
$am = Import-Csv 'Data\WKSTN-221\amcache.csv'
$am | Where-Object { $_.FullPath -like "*update.exe" } |
      Select-Object FullPath, Sha256, Created, LastModified
```

```python
with open('Data/WKSTN-221/amcache.csv') as f:
    am = list(csv.DictReader(f))
for r in am:
    if r['FullPath'].endswith("update.exe"):
        print(r['FullPath'], r['Sha256'], r['Created'], r['LastModified'])
```

The SHA-256 column gives you the value to look up against threat intelligence. In a real investigation, this is the moment to query VirusTotal or your threat-intel platform for the hash.

### What you've just done

Four sources, each independent: MFT (file existed and is now deleted), USN Journal (creation, rename, deletion timeline with timestamps), Prefetch (single execution), and Amcache (hash for attribution). The MFT path adds the user and parent-directory context, but it comes from the MFT and is not a fifth source. That's a defensible finding. Walk back through Tasks 1–7 above and fill in the analyst-notes scaffold using the data you just produced.

---

## Deliverables Checklist

Your `lab04-notes.md` should contain:

- [ ] **Task 1** — Suspicious path table with at least 10 entries and three written responses
- [ ] **Task 2** — MFT candidate file table with at least five entries or equivalent workflow description
- [ ] **Task 3** — SI vs. FN timestamp comparison for three files with four written responses
- [ ] **Task 4** — USN Journal findings table and three written responses
- [ ] **Task 5** — Correlation table for two files with confidence ratings
- [ ] **Task 6** — File system mini-timeline with at least eight entries and three written responses
- [ ] **Task 7** — NTFS findings summary (2–4 paragraphs)
- [ ] **Task 8** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab04/
├── ReadMe.md                                   ← This file
├── lab04-notes.md                              ← Rollup working notes for the whole lab
├── walkthrough-answers.md                      ← Sample answers for the
│                                                  Hands-On Walkthrough
├── task-answers.md                             ← Sample answers for the
│                                                  reflective workbook Tasks
├── Lab04_01/                                   ← Ch4 §4.1 — NTFS Overview
│   ├── ReadMe.md
│   └── lab04.1-notes.md
├── Lab04_02/                                   ← Ch4 §4.2 — The Master File Table (MFT)
│   ├── ReadMe.md
│   └── lab04.2-notes.md
├── Lab04_03/                                   ← Ch4 §4.3 — USN Journal
│   ├── ReadMe.md
│   └── lab04.3-notes.md
├── Lab04_04/                                   ← Ch4 §4.4 — Tools for NTFS Artifact Analysis
│   ├── ReadMe.md
│   └── lab04.4-notes.md
└── Lab04_05/                                   ← Ch4 §4.5 — Correlating NTFS Artifacts in IR
    ├── ReadMe.md
    ├── lab04.5-notes.md
    └── ntfs-observation-matrix.md                 Reusable cross-case NTFS
                                                   findings worksheet
```

---

## Key Takeaways

- **NTFS is durable evidence.** Even when attackers delete files and logs are incomplete, file system metadata frequently survives long enough to show what existed and what changed.
- **The MFT and USN Journal complement each other.** The MFT tells you about file records, and the USN Journal tells you how those records changed over time. Together they are often stronger than either source alone.
- **Suspicious metadata is not proof of execution.** File presence, rename activity, and deletion patterns are important IR findings, but they require corroboration from Prefetch, Amcache, or event logs before you can claim execution.
- **Timestamps deserve scrutiny, not overconfidence.** SI/FN differences can be meaningful, but legitimate file operations also produce discrepancies. Make the case carefully.
- **NTFS analysis supports the larger IR story.** Its real value is in how well it helps you reconstruct file-level activity and connect it to the timeline built from other artifact types.

---

**Next:** Lab 05 — Windows Registry and Cloud Storage Forensics

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
