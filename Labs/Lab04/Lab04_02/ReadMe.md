# Lab 4.2 — The Master File Table (MFT)

**Supporting Section 4.2: The Master File Table (MFT)**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

If NTFS is the structure that makes Windows forensic analysis possible, the Master File Table is the artifact responders end up relying on most.

The MFT is often described as the "database of files" on an NTFS volume. That description is useful but incomplete. For an incident responder, the MFT is where file existence, location, timestamps, allocation state, and core metadata come together. That combination lets you reconstruct what was on disk, even when the original file is gone, renamed, or partially overwritten.

This lab focuses on the MFT as a practical IR artifact. You will work through the questions responders ask when suspicious tools may have been staged on disk: what files existed, where they were, whether they were deleted, when they appeared, whether the timestamps make sense, and which records deserve follow-up with other artifacts.

The goal is not to memorize every internal detail of an MFT record. It is to make you comfortable using MFT data as evidence: extracting useful facts, spotting suspicious patterns, and staying within what the artifact can actually support.

---

## What This Lab Covers

| Section | Topic |
|---|---|
| 4.2.1 | What the MFT is and what it stores |
| 4.2.2 | MACB timestamps and what they actually mean |
| 4.2.3 | Reading `$SI` vs `$FN` |
| 4.2.4 | Resident data and deleted files |
| 4.2.5 | Common IR questions the MFT helps answer |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain what the MFT is in practical forensic terms
- Identify the kinds of information an MFT record can provide
- Use MFT data to identify suspicious files, suspicious paths, and deleted records
- Distinguish between allocated and deleted MFT entries with confidence
- Understand why MFT analysis is valuable even when file content is unavailable
- Separate what MFT evidence supports from what still requires corroboration
- Write a short, evidence-based summary based on MFT findings alone

---

## Estimated Time

45–75 minutes

---

## Prerequisites

- Completion of Lab 4.1, or equivalent understanding of NTFS basics
- A text editor or markdown editor
- Your `lab04.2-notes.md` file (template included in this folder)
- Optional: a Windows VM or sample NTFS dataset
- Optional: MFTECmd, AnalyzeMFT, or another MFT parser

---

## Scenario

A Windows workstation named **WKSTN-221** is under investigation after the SOC reported suspicious activity. Preliminary triage suggests a user may have downloaded a suspicious executable and later deleted it. A second responder believes a batch script may have been staged in a writable directory and removed shortly afterward.

Event logging from the suspected time window is incomplete. Memory was not captured before the host was rebooted. You need to use the MFT to determine what files and directories existed on disk, which stand out, and whether there is evidence of deleted or short-lived artifacts that warrant deeper investigation.

Your task: treat the MFT as a primary evidence source and use it to begin reconstructing the on-disk portion of the story.

---

## Background: Why Responders Care About the MFT

On NTFS volumes, every file and directory has at least one MFT record. Those records persist even after a file is deleted, at least until the space is reused. That persistence is what makes the MFT valuable in IR.

At a practical level, MFT analysis helps answer:

- Did a suspicious file exist on this volume?
- Where was it located in the directory tree?
- Was it still allocated or already marked deleted?
- When was it created, modified, or changed?
- Was it placed in a user-writable or known staging path?
- Are there clusters of related file activity around the suspected incident window?

| MFT Value in IR | What It Helps With |
|---|---|
| **File existence** | Shows that a file or directory record existed on the volume |
| **Path reconstruction** | Places a file in its directory context |
| **Timestamp review** | Supports timeline building and anomaly detection |
| **Deletion awareness** | Can surface records for files no longer present in the live file system |
| **Staging detection** | Helps identify tools in Downloads, Temp, ProgramData, and similar paths |

The MFT does not prove execution, network activity, or intent. It is a file-existence and metadata artifact: strong within that scope, limited outside it.

> **IR Reality Check:** Attackers often clean up after themselves. The MFT is one of the main reasons that cleanup is frequently incomplete from a forensic standpoint. A deleted file record is not an erased file record.

---

## Lab Tasks

---

### Task 1 — Define What the MFT Can and Cannot Tell You

**Objective:** Establish a clear, practical scope for MFT analysis before touching any data.

**Part A — Written explanation**

Write a 4–6 sentence explanation of the MFT. Cover: what it is, what it stores, why it is useful in IR, what it answers well, and what it cannot answer alone.

```
[Your explanation here]
```

**Part B — Usefulness ratings**

| Investigative Question | MFT Value | Why |
|---|---|---|
| Did a file named `tool.exe` exist on this volume? | | |
| Was `tool.exe` executed? | | |
| Was a file located under `C:\Users\Bob\Downloads\`? | | |
| Was a file later deleted from the file system? | | |
| What exact command line launched a script? | | |
| Did several suspicious files appear in the same time window? | | |
| Was a new directory created in a staging path during the incident? | | |
| Did the attacker establish network connections from this host? | | |

**Ratings to use:** Strongly useful / Partially useful / Not very useful

**Part C — Short answer**

*Where does the MFT consistently fall short, and what artifact types pick up where it stops?*

```
[Your response here — 2 to 3 sentences]
```

---

### Task 2 — Identify What Makes an MFT Entry Worth Analyst Attention

**Objective:** Build an internal checklist for recognizing which records deserve follow-up.

**Part A — Characteristics table**

The first five rows are provided. Add at least five more based on your own experience or reasoning.

| Characteristic | Why It Matters in IR | Example |
|---|---|---|
| Executable in a user-writable directory | Standard users should not install executables; common staging path | `C:\Users\<user>\Downloads\update.exe` |
| Deleted batch script | Scripts deleted after use suggest intentional cleanup | Deleted `.bat` in `C:\ProgramData\` |
| Recently created archive | Compression often precedes exfiltration or tool extraction | `.7z` file created in `C:\Temp\` during incident window |
| File under `C:\ProgramData\` | Writable by standard users; often missed by shallow analysis | Persistence binary placed here to survive reboots |
| Suspicious file name | Names mimicking system files or installers are a common masking technique | `svchost32.exe`, `AdobeUpdate.exe` |
| *(Add your own)* | | |
| *(Add your own)* | | |
| *(Add your own)* | | |
| *(Add your own)* | | |
| *(Add your own)* | | |

**Part B — Short answers**

**1. Why should a responder focus on context, not just file extension?**

```
[Your response here]
```

**2. Why can a benign-looking file name still be suspicious?**

```
[Your response here]
```

**3. Why might a deleted file record be more valuable than an allocated one?**

```
[Your response here]
```

---

### Task 3 — Parse and Review the MFT

**Objective:** Extract candidate records from MFT output that warrant closer examination.

**Part A — Collection and parsing**

If you have a live Windows VM or sample MFT, parse it using MFTECmd or your preferred tool.

**MFTECmd commands:**

```powershell
# Parse from a live system (requires admin)
MFTECmd.exe -f "\\.\C:" --csv "E:\IR\WKSTN-221\filesystem\" --csvf mft_output.csv

# Parse from an acquired MFT file
MFTECmd.exe -f "E:\Evidence\$MFT" --csv "E:\IR\WKSTN-221\filesystem\" --csvf mft_output.csv
```

**Recommended filters in Timeline Explorer:**

| Filter | Column | Value |
|---|---|---|
| Suspicious extensions | `Extension` | `.exe`, `.dll`, `.ps1`, `.bat`, `.cmd`, `.zip`, `.7z`, `.rar`, `.iso` |
| High-value paths | `ParentPath` | Downloads, Temp, ProgramData, Public, AppData |
| Deleted records | `InUse` | `False` |
| Recent activity | `Created0x10` | Sort descending — look for incident window |
| Staging directories | `IsDirectory` | `True` — filter for unusual new directories |

**Part B — Candidate records table**

Document at least five candidate entries. If you do not have a dataset, describe the exact filters you would apply and create representative hypothetical entries based on the WKSTN-221 scenario.

| File or Directory | Full Path | Record Type | Allocated / Deleted | Why It Stands Out | Notes |
|---|---|---|---|---|---|
| `svc_updater.exe` | `C:\Temp\svc_updater.exe` | File | Deleted | Matches Prefetch execution entry; no longer on disk | High priority for USN Journal follow-up |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |

> **Guidance:** Your goal is to identify what deserves deeper analysis, not to declare every unusual file malicious. A `.exe` in Downloads starts a conversation. It doesn't end one.

---

### Task 4 — Interpret MFT Metadata for Candidate Records

**Objective:** Extract meaning from the fields responders use most often when evaluating suspicious MFT entries.

For three entries from Task 3, document the core metadata fields and record your observations.

| File / Directory | Full Path | Created (SI) | Modified (SI) | Changed (SI) | Accessed (SI) | Allocated / Deleted | Observations |
|---|---|---|---|---|---|---|---|
| | | | | | | | |
| | | | | | | | |
| | | | | | | | |

**Short answers:**

**1. Why is the file path important — not just the file name?**

```
[Your response here]
```

**2. Why do responders care about allocation state when reviewing suspicious records?**

```
[Your response here]
```

**3. Why can clustered creation timestamps across multiple suspicious files matter to an investigation?**

```
[Your response here]
```

**4. Why should you avoid drawing conclusions from a single MFT field in isolation?**

```
[Your response here]
```

> **Guidance:** A suspicious creation timestamp does not prove malicious intent. It makes the record worth correlating with Prefetch, event logs, and USN Journal data, not worth adding to your findings as a standalone conclusion.

---

### Task 5 — Hunt for Deleted and Short-Lived Artifacts

**Objective:** Recognize why deleted MFT entries are frequently the highest-value records in an IR investigation.

**Part A — Deleted artifact scenario table**

| Scenario | What the MFT Might Still Show | Why That Helps the Investigation |
|---|---|---|
| Suspicious `.exe` deleted from `C:\Users\<user>\Downloads\` | | |
| Batch script deleted from `C:\ProgramData\` | | |
| Archive removed after extraction | | |
| Temporary staging directory created and removed | | |
| Deleted DLL in a writable system path | | |
| Deleted `.ps1` script in `AppData\Local\Temp\` | | |

**Part B — Short answers**

**1. Why does the act of deletion actually increase the investigative value of the file system record?**

```
[Your response here]
```

**2. Why is a deleted attacker tool often a strong lead even without the file content?**

```
[Your response here]
```

**3. What limitations remain if a deleted MFT record exists but the file content is no longer recoverable?**

```
[Your response here]
```

---

### Task 6 — Build an MFT-Centered Mini-Timeline

**Objective:** Turn MFT findings into an ordered sequence of events that supports broader investigation.

Using your candidate records from Tasks 3–5, create a timeline with at least six entries. Every entry must reference a specific MFT field or finding. Do not include unsourced entries.

| Time (UTC) | MFT Field / Source | Event | File / Path | Significance | Confidence |
|---|---|---|---|---|---|
| | `Created0x10` | File created | | | |
| | `Created0x30` | FN creation timestamp | | | |
| | Allocation state — deleted | Deleted file record identified | | | |
| | `LastModified0x10` | File content modified | | | |
| | Directory record | New directory created | | | |
| | Deleted record cluster | Multiple files deleted near same time | | | |

**Confidence rating:** High (two+ independent sources agree) / Medium (single reliable source) / Low (indirect or ambiguous)

**Short answers:**

**1. Why is an ordered timeline more useful than a list of individual suspicious MFT records?**

```
[Your response here]
```

**2. What would you want to correlate outside the MFT to strengthen the entries in this timeline?**

```
[Your response here]
```

**3. Which artifact types from earlier labs pair most directly with MFT-based timeline entries?**

```
[Your response here]
```

---

### Task 7 — Supported vs. Unsupported Claims

**Objective:** Practice the discipline of staying within what MFT evidence actually supports.

Overclaiming in forensic reporting damages credibility more than acknowledged uncertainty ever does.

**Part A — Rating table**

Rate each statement:
- **Supported by MFT alone**
- **Possibly suggested — needs corroboration**
- **Not supported by MFT alone**

| Statement | Rating | Why |
|---|---|---|
| A file named `runme.bat` existed under `C:\ProgramData\` | | |
| `runme.bat` was executed by the assigned user | | |
| A suspicious executable was present in a user-writable directory and later deleted | | |
| The attacker used the deleted executable for lateral movement | | |
| Multiple suspicious files appeared within a ten-minute window | | |
| The user intentionally deleted the file to conceal attacker activity | | |
| A staging directory was created and removed during the incident window | | |
| The deleted file contained malicious code | | |

**Part B — Add three of your own**

Write three statements about the WKSTN-221 scenario and rate them using the same criteria.

| Statement | Rating | Why |
|---|---|---|
| | | |
| | | |
| | | |

**Part C — Short answer**

*Why is "possibly suggested — needs corroboration" a more professionally useful category than forcing every finding into either "proven" or "unproven"?*

```
[Your response here — 2 to 3 sentences]
```

---

### Task 8 — Write an MFT Findings Summary

**Objective:** Produce a concise, defensible analyst summary based on MFT evidence.

Write a 2–4 paragraph summary describing what your MFT review indicates about WKSTN-221. Write it as a working-note entry, not a final incident conclusion.

Your summary must cover:

- Which suspicious files or directories stood out and why
- Whether any records were allocated or deleted at time of analysis
- Whether timing and path context support escalation or further review
- What the MFT supports with confidence
- What still requires corroboration and from which artifact types

```
[Paragraph 1 — suspicious files and directories identified]


[Paragraph 2 — allocation state, timing, and path context]


[Paragraph 3 — what MFT supports with confidence]


[Paragraph 4 — limitations and what corroboration is needed]
```

---

### Task 9 — Reflection

Answer the following in 3–5 sentences each:

**1. Why the MFT is foundational**
Why is the MFT often one of the first file system artifacts responders review — and why does that make sense given what it contains?

```
[Your response here]
```

**2. Deleted does not mean unknowable**
Why can the MFT still provide significant value even when the suspicious file itself is completely gone?

```
[Your response here]
```

**3. Context over raw fields**
Why is a file's path, surrounding directory structure, and timing often more important than the file name or extension alone?

```
[Your response here]
```

**4. Correlation is still necessary**
Why should MFT findings be paired with artifacts like Prefetch, event logs, registry data, or the USN Journal before drawing firm conclusions?

```
[Your response here]
```

---

## Deliverables Checklist

Your `lab04.2-notes.md` should contain:

- [ ] **Task 1** — MFT explanation, usefulness ratings table, and short answer
- [ ] **Task 2** — Characteristics table with at least 10 entries and three short answers
- [ ] **Task 3** — Parsing notes, candidate records table with at least five entries
- [ ] **Task 4** — Metadata interpretation for three entries and four short answers
- [ ] **Task 5** — Deleted artifact scenario table and three short answers
- [ ] **Task 6** — Mini-timeline with at least six entries and three short answers
- [ ] **Task 7** — Supported/unsupported claims table, three additional statements, and short answer
- [ ] **Task 8** — MFT findings summary (2–4 paragraphs)
- [ ] **Task 9** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab04/
├── lab04-notes.md    ← Your working notes file (whole lab)
└── Lab04_02/
    ├── ReadMe.md         ← This file
    └── lab04.2-notes.md  ← Your working notes file
```

---

## Key Takeaways

- **The MFT is one of the core NTFS artifacts.** It gives responders durable visibility into file and directory metadata that survives deletion and cleanup attempts.
- **Deleted records can be the most valuable.** File-system cleanup is frequently incomplete from a forensic standpoint. A deleted MFT entry is not an erased one.
- **Path, timing, and allocation state matter more than file name alone.** Context is everything in MFT analysis.
- **The MFT answers file-existence questions well — execution questions poorly.** Use it to establish what was on disk, then corroborate execution from Prefetch, Amcache, and event logs.
- **Disciplined MFT analysis stays close to what the artifact supports.** The strongest findings are specific, evidence-grounded, and honest about what still needs corroboration.

---

**Next:** Lab 4.3 — USN Journal

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
