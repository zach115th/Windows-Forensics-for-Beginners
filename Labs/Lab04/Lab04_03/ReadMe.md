# Lab 4.3 — USN Journal

**Supporting Section 4.3: USN Journal**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

The MFT tells you that a file record existed. The USN Journal helps tell you what happened to it over time.

That distinction matters to incident responders because attackers rarely create a file and leave it untouched. They stage tools, rename payloads, extract archives, overwrite scripts, delete droppers, and move files through short-lived working directories. Those actions can leave change records in the NTFS Update Sequence Number Journal even when the final file is gone or the path no longer looks suspicious.

This lab uses the USN Journal as a change-tracking artifact in Windows forensic analysis. You will identify relevant file activity, interpret create, rename, and delete patterns, and correlate those patterns with suspicious paths. Throughout, you will stay disciplined about what the journal can and cannot prove by itself.

The goal is to make you comfortable using the journal the way a responder uses it: as durable evidence of file system activity that might otherwise disappear without a trace. Memorizing every low-level flag in a USN record is not the goal.

---

## What This Lab Covers

| Section | Topic |
|---|---|
| 4.3.1 | What the USN Journal is and why it exists |
| 4.3.2 | What kinds of file activity it records |
| 4.3.3 | How create, rename, and delete activity supports IR analysis |
| 4.3.4 | Why the USN Journal is strongest when correlated with other NTFS artifacts |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain what the USN Journal is in practical forensic terms
- Identify the types of file system changes commonly reflected in USN records
- Use USN Journal data to spot file creation, rename, overwrite, and deletion patterns
- Recognize why short-lived or deleted attacker files may still be visible in change history
- Distinguish between what the USN Journal strongly supports and what requires corroboration
- Correlate USN findings with MFT-based file existence and path context
- Write a concise working summary based on journal activity

---

## Estimated Time

45–75 minutes

---

## Prerequisites

- Completion of Labs 4.1 and 4.2, or equivalent familiarity with NTFS basics and MFT analysis
- A text editor or markdown editor
- Your `lab04.3-notes.md` file (template included in this folder)
- Optional: a Windows VM or sample NTFS dataset
- Optional: MFTECmd, UsnJrnl2Csv, or another NTFS-capable USN parser

---

## Scenario

You are continuing analysis of **WKSTN-221**. MFT review from Lab 4.2 identified deleted file records for `svc_updater.exe` and a batch script under `C:\ProgramData\`. The current file listing is incomplete, and several artifacts may have been cleaned up before collection.

A responder believes the attacker may have:

- Dropped a tool into the user's Downloads folder
- Renamed or moved it after extraction from an archive
- Staged a script in a writable path
- Deleted one or more artifacts shortly after use

Determine whether NTFS change history supports that theory, and whether the pattern of activity is consistent with staging, execution, cleanup, or all three.

Your task: use the USN Journal to reconstruct file changes that matter to the investigation.

---

## Background: Why Responders Care About the USN Journal

The USN Journal is a change log for NTFS volumes. It records file and directory activity — creation, modification, renaming, deletion — as those events occur. The records remain whether or not the file is still present in the live file system.

| USN Journal Strength | Why It Matters in IR |
|---|---|
| **Change visibility** | Shows activity beyond simple file presence — what happened, in what sequence |
| **Short-lived artifact coverage** | Helps reveal files that were deleted or renamed before collection |
| **Rename awareness** | Useful when attackers rename tools to look like legitimate system files |
| **Time clustering** | Helps identify bursts of related file operations in the same path |
| **Correlation value** | Strengthens MFT-based findings with sequential change evidence |

**Common USN reason codes you will encounter:**

| Reason Code | Meaning |
|---|---|
| `FILE_CREATE` | A new file or directory was created |
| `FILE_DELETE` | A file or directory was deleted |
| `RENAME_OLD_NAME` | The file name before a rename operation |
| `RENAME_NEW_NAME` | The file name after a rename operation |
| `DATA_OVERWRITE` | File content was overwritten |
| `DATA_EXTEND` | File content was extended (appended) |
| `CLOSE` | File handle was closed — typically follows create, modify, or delete |
| `SECURITY_CHANGE` | File permissions were changed |

> **IR Reality Check:** The live file system shows you what is there now. The USN Journal helps you see what changed to get there — including activity that was deliberately erased from view.

---

## Lab Tasks

---

### Task 1 — Define What the USN Journal Can and Cannot Tell You

**Objective:** Establish a clear, practical scope for USN Journal analysis before touching any data.

**Part A — Written explanation**

Write a 4–6 sentence explanation of the USN Journal. Cover: what it is, what activity it records, why it matters in IR, how it differs from the MFT, and what it cannot prove alone.

```
[Your explanation here]
```

**Part B — Usefulness ratings**

| Investigative Question | USN Journal Value | Why |
|---|---|---|
| Was a suspicious file created during the incident window? | | |
| Was a suspicious file renamed after creation? | | |
| Was a suspicious file executed? | | |
| Was a file deleted from a staging directory? | | |
| Did several related files change within minutes of each other? | | |
| What exact command line launched a script? | | |
| Was a directory briefly created and then removed? | | |
| Did the attacker establish persistence? | | |

**Ratings:** Strongly useful / Partially useful / Not very useful

**Part C — Short answer**

*How does the USN Journal complement the MFT rather than duplicate it? What does each source provide that the other does not?*

```
[Your response here — 2 to 3 sentences]
```

---

### Task 2 — Identify USN Activity Patterns Worth Analyst Attention

**Objective:** Build an internal checklist for recognizing which journal patterns deserve immediate follow-up.

**Part A — Activity pattern table**

The first five rows are provided. Add at least five more based on your own experience or reasoning.

| USN Activity Pattern | Why It Matters | Example |
|---|---|---|
| File created in `Downloads` | Common attacker delivery path. Unexpected executables here are a priority | `FILE_CREATE` for `update.exe` in user Downloads |
| File renamed shortly after creation | Attackers rename tools to blend in or evade file-name-based detection | `RENAME_OLD_NAME: payload.exe` → `RENAME_NEW_NAME: svchost32.exe` |
| File deleted from `C:\Temp\` during activity window | Short-lived files suggest intentional cleanup after use | `FILE_DELETE` for an executable with no prior execution artifacts |
| Burst of changes in a user-writable directory | Rapid sequential activity suggests extraction, staging, or tool deployment | Multiple `FILE_CREATE` records in `C:\ProgramData\` within seconds |
| Directory created and then deleted | Short-lived staging directory is a common attacker pattern | `FILE_CREATE` then `FILE_DELETE` for same directory within minutes |
| *(Add your own)* | | |
| *(Add your own)* | | |
| *(Add your own)* | | |
| *(Add your own)* | | |
| *(Add your own)* | | |

**Part B — Short answers**

**1. Why is rename activity often more forensically interesting than it first appears?**

```
[Your response here]
```

**2. Why can a quick create-then-delete pattern be one of the most important sequences to find?**

```
[Your response here]
```

**3. Why should a responder care about clustered file changes in the same path even if each individual change looks minor?**

```
[Your response here]
```

---

### Task 3 — Parse and Hunt for Candidate USN Records

**Objective:** Use the USN Journal to surface suspicious file system change activity.

**Part A — Collection and parsing**

If you have a live Windows VM or sample NTFS data, parse the USN Journal with MFTECmd.

**MFTECmd USN Journal commands:**

```powershell
# Parse from acquired $J file
MFTECmd.exe -f "E:\Evidence\$J" --csv "E:\IR\WKSTN-221\filesystem\" --csvf usn_output.csv

# Parse from live system (requires admin — copy $J first)
# The $J file is located at: C:\$Extend\$UsnJrnl:$J
```

**Recommended Timeline Explorer filters:**

| Filter Goal | Column | Value / Approach |
|---|---|---|
| Suspicious file types | `Name` | `.exe`, `.dll`, `.ps1`, `.bat`, `.cmd`, `.zip`, `.7z`, `.rar` |
| High-value paths | `ParentPath` | Downloads, Temp, ProgramData, Public, AppData |
| Deletion events | `Reason` | Contains `FILE_DELETE` |
| Rename events | `Reason` | Contains `RENAME_OLD_NAME` or `RENAME_NEW_NAME` |
| Activity clusters | `TimeStamp` | Sort ascending — look for bursts of activity |
| Creation events | `Reason` | Contains `FILE_CREATE` |

**Part B — Candidate records table**

Document at least five candidate entries. If you do not have a dataset, describe the filters you would apply and create representative hypothetical entries based on the WKSTN-221 scenario.

| File or Directory | Path | Change Type (Reason Code) | Timestamp (UTC) | Why It Stands Out | Notes |
|---|---|---|---|---|---|
| `svc_updater.exe` | `C:\Temp\` | `FILE_CREATE`, `CLOSE`, `FILE_DELETE` | | Matches deleted MFT entry from Lab 4.2. Full lifecycle visible in journal | Correlate with Prefetch for execution evidence |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |

---

### Task 4 — Interpret Common USN Change Patterns

**Objective:** Turn journal activity into cautious, evidence-based interpretation.

For three candidate entries from Task 3, analyze the sequence of activity around each one.

| File or Path | Journal Activity Seen | Most Likely Interpretation | What It Does Not Prove | Follow-Up Artifact |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

**Short answers:**

**1. Why is "created then deleted" useful but still forensically incomplete on its own?**

```
[Your response here]
```

**2. Why does a rename event require path context and timing to be meaningful?**

```
[Your response here]
```

**3. Why should you avoid treating a USN entry as evidence of execution?**

```
[Your response here]
```

**4. What makes a sequence of USN records more defensible than a single record in isolation?**

```
[Your response here]
```

---

### Task 5 — Reconstruct Rename and Delete Sequences

**Objective:** Use the USN Journal to follow suspected attacker staging or cleanup behavior through connected change events.

**Assumed sequence to investigate:**

1. A tool was dropped with an obvious name
2. It was renamed to something more benign
3. It was used and then deleted

**Part A — Reconstruction workflow**

| Step in Suspected Sequence | What You Would Look For in the USN Journal | Why It Helps |
|---|---|---|
| Initial file arrival | `FILE_CREATE` in a staging path during the incident window | Establishes when and where the file first appeared |
| Rename to new name | `RENAME_OLD_NAME` followed immediately by `RENAME_NEW_NAME` — same file, same timestamp | Shows the original name before masking |
| Possible path change | Parent path change between rename events | Indicates the file was moved to a different directory |
| Follow-on modification | `DATA_OVERWRITE` or `DATA_EXTEND` after rename | Suggests the file was written to or updated after arrival |
| Deletion or cleanup | `FILE_DELETE` in the same path, near the same time window | Indicates intentional cleanup |

**Part B — Short answers**

**1. Why is the USN Journal especially valuable when the attacker has changed the file name to something benign?**

```
[Your response here]
```

**2. Why is it important to correlate rename activity with time and path context rather than name similarity alone?**

```
[Your response here]
```

**3. What evidence outside the USN Journal would most strengthen confidence that you are tracking a single artifact chain across its rename history?**

```
[Your response here]
```

---

### Task 6 — Correlate USN Journal Findings with the MFT

**Objective:** Combine file change history with file record context to produce stronger, more defensible findings.

Pick two suspicious files or paths from your earlier tasks. For each, document what the MFT shows, what the USN Journal adds, and what the combination most reasonably supports.

| File or Path | What the MFT Shows | What the USN Journal Shows | Combined Interpretation | Confidence |
|---|---|---|---|---|
| | | | | High / Med / Low |
| | | | | High / Med / Low |

**Acceptable interpretation examples:**
- "A suspicious executable existed in a user-writable path and was deleted within the incident window — consistent with tool staging and cleanup"
- "A file appears to have been renamed shortly after creation, then deleted — the original name is recoverable from USN rename records"
- "A short-lived staging directory was created, populated with files, and removed — consistent with a brief tool deployment"

> **What to avoid:** Claims such as "the attacker executed this tool," "the user intentionally hid evidence," or "this file was used for lateral movement" — unless you have supporting artifacts outside NTFS.

**Short answer:**

*Why does the combination of MFT and USN Journal produce stronger findings than either source alone?*

```
[Your response here — 2 to 3 sentences]
```

---

### Task 7 — Build a USN-Centered Mini-Timeline

**Objective:** Turn change records into a usable, time-ordered investigative sequence.

Build a timeline using your USN Journal and MFT findings. Include at least eight entries. Every entry must reference a specific artifact source and reason code or field.

| Time (UTC) | Source | Reason Code / Field | Event | File / Path | Significance | Confidence |
|---|---|---|---|---|---|---|
| | USN Journal | `FILE_CREATE` | File created | | | |
| | USN Journal | `CLOSE` | File handle closed | | | |
| | USN Journal | `RENAME_OLD_NAME` | File rename — original name | | | |
| | USN Journal | `RENAME_NEW_NAME` | File renamed to | | | |
| | USN Journal | `DATA_OVERWRITE` | File content modified | | | |
| | USN Journal | `FILE_DELETE` | File deleted | | | |
| | MFT | Deleted record | Deleted file record recovered | | | |
| | MFT + USN | Correlated | File lifecycle reconstructed | | | |

**Confidence:** High (two+ independent sources agree) / Medium (single reliable source) / Low (indirect or ambiguous)

**Short answers:**

**1. Why is a sequence of journal activity more useful to an investigation than isolated change records?**

```
[Your response here]
```

**2. What would you want to correlate next outside NTFS to strengthen these timeline entries?**

```
[Your response here]
```

**3. Which artifact types from earlier labs pair most naturally with USN-based timeline entries?**

```
[Your response here]
```

---

### Task 8 — Supported vs. Unsupported Claims

**Objective:** Practice keeping your reporting inside what the USN Journal supports.

**Part A — Rating table**

Rate each statement:
- **Supported by USN Journal alone**
- **Possibly suggested — needs corroboration**
- **Not supported by USN Journal alone**

| Statement | Rating | Why |
|---|---|---|
| A file named `adobe_update.exe` was created in Downloads during the incident window | | |
| `adobe_update.exe` was executed by the assigned user | | |
| A suspicious file was renamed after initial creation | | |
| The rename was performed to evade detection | | |
| A short-lived script existed in a writable path and was deleted during the incident window | | |
| The deleted script established persistence on the host | | |
| Multiple file changes occurred in the same directory within a two-minute window | | |
| The attacker intended to delete the files to conceal their activity | | |

**Part B — Three additional statements**

Write three statements about the WKSTN-221 scenario and rate them.

| Statement | Rating | Why |
|---|---|---|
| | | |
| | | |
| | | |

**Part C — Short answer**

*Why does overclaiming in forensic reporting — asserting more than the evidence supports — damage an investigation more than acknowledged uncertainty does?*

```
[Your response here — 2 to 3 sentences]
```

---

### Task 9 — Write a USN Journal Findings Summary

**Objective:** Produce a concise, defensible working-note summary based on USN Journal analysis.

Write a 2–4 paragraph summary describing what your USN Journal review indicates about WKSTN-221. Write it as a working-note entry, not a final incident conclusion.

Your summary must cover:

- The suspicious change patterns that stood out and why
- Whether files appear to have been created, renamed, modified, or deleted during the incident window
- Whether activity suggests staging, short-lived artifacts, cleanup, or a combination
- What the USN Journal supports with confidence
- What still requires corroboration and from which specific artifact types

```
[Paragraph 1 — suspicious change patterns identified]


[Paragraph 2 — create, rename, delete sequences and what they suggest]


[Paragraph 3 — what the journal supports with confidence]


[Paragraph 4 — limitations and what corroboration is needed]
```

---

### Task 10 — Reflection

Answer the following in 3–5 sentences each:

**1. Why the USN Journal matters**
Why is the USN Journal especially valuable when the live file system no longer reflects the most interesting attacker activity?

```
[Your response here]
```

**2. Change history versus file existence**
How does the USN Journal complement the MFT rather than replace it? What does each source provide that the other cannot?

```
[Your response here]
```

**3. Rename and cleanup awareness**
Why are rename and delete patterns often the most forensically significant activity types in attacker tool staging investigations?

```
[Your response here]
```

**4. Correlation over confidence**
Why should responders be careful not to convert journal activity into stronger claims than the evidence actually supports? What goes wrong when they do?

```
[Your response here]
```

---

## Deliverables Checklist

Your `lab04.3-notes.md` should contain:

- [ ] **Task 1** — USN Journal explanation, usefulness ratings, and short answer
- [ ] **Task 2** — Activity pattern table with at least 10 entries and three short answers
- [ ] **Task 3** — Parsing notes and candidate records with at least five entries
- [ ] **Task 4** — Interpretation table for three candidate items and four short answers
- [ ] **Task 5** — Rename/delete reconstruction table and three short answers
- [ ] **Task 6** — MFT and USN correlation table and short answer
- [ ] **Task 7** — Mini-timeline with at least eight entries and three short answers
- [ ] **Task 8** — Supported/unsupported claims table, three additional statements, and short answer
- [ ] **Task 9** — USN findings summary (2–4 paragraphs)
- [ ] **Task 10** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab04/
├── lab04-notes.md    ← Your working notes file (whole lab)
└── Lab04_03/
    ├── ReadMe.md         ← This file
    └── lab04.3-notes.md  ← Your working notes file
```

---

## Key Takeaways

- **The USN Journal captures change, not just presence.** It is one of the primary ways responders can see what happened on a file system after cleanup has begun.
- **Create, rename, and delete patterns reveal attacker behavior.** Staging, masking, and cleanup all leave characteristic sequences in the journal.
- **USN is strongest with context.** Path, timing, surrounding activity, and MFT correlation all improve the quality of interpretation.
- **Journal activity is not proof of execution or intent.** It is useful change metadata, but stronger claims still need corroboration.
- **Good USN analysis is sequence-based.** Most of the value comes from reconstructing the order of related file changes, not from evaluating records in isolation.

---

**Next:** Lab 4.4 — Tools for NTFS Artifact Analysis

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
