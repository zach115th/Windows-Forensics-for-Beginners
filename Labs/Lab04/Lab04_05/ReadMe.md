# Lab 4.5 — Correlating NTFS Artifacts in IR

**Supporting Section 4.5: Correlating NTFS Artifacts in IR**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Before You Start — What "Correlation" Actually Means

Correlation is the step that turns the MFT records and USN Journal entries you have learned to read into analysis.

**Correlation** means asking whether separate artifacts, taken together, tell a coherent story — and being disciplined about which parts of that story you can prove.

Here is the difference:

| Approach | What It Looks Like | Problem |
|---|---|---|
| Isolated observation | "There is a deleted EXE in Downloads." | Means little alone. Many EXEs get deleted legitimately. |
| Correlated analysis | "An EXE arrived in Downloads, was renamed three minutes later, copied to ProgramData, and the original Downloads record was deleted — all within 19 minutes." | Now you have something worth escalating. |

The goal of this lab is to practice moving from the first row to the second, while staying honest about what you can prove.

> **Key principle:** Correlation is not the same as conclusion. You assemble the pieces that fit, document the logic that connects them, and state explicitly what still needs verification. The best NTFS analysis is persuasive because it is careful, not because it is confident.

---

## Overview

No single NTFS artifact tells the whole story.

The MFT shows that a file record existed. The USN Journal shows that it was created, renamed, modified, or deleted. A parser can surface suspicious paths or short-lived files. Incident response does not succeed by collecting isolated observations. It succeeds when responders connect those observations into a coherent, defensible account of what most likely happened on disk.

This lab focuses on that step. You will work with a realistic set of MFT and USN Journal findings from WKSTN-221 and practice correlating them into something usable: a timeline, an activity cluster analysis, a written finding, and a handoff note another analyst could pick up and continue.

---

## What This Lab Covers

| Section | Topic |
|---|---|
| 4.5.1 | Why NTFS artifacts are strongest when used together |
| 4.5.2 | Correlating MFT, USN Journal, and file path context |
| 4.5.3 | Building timelines and activity clusters from NTFS evidence |
| 4.5.4 | Writing careful, evidence-based interpretations in IR |

---

## Learning Objectives

By completing this lab, you will be able to:

- Correlate MFT and USN Journal findings into a unified activity narrative
- Distinguish isolated suspicious records from meaningful artifact clusters
- Use timestamps, path context, and change history together to assess likely file activity
- Recognize patterns consistent with staging, renaming, and cleanup behavior
- Separate what NTFS artifacts strongly support from what still requires corroboration
- Build a short file-system timeline that supports IR decision-making
- Write a concise, defensible NTFS correlation summary

---

## Estimated Time

60–90 minutes

---

## Prerequisites

- Completion of Labs 4.1 through 4.4, or equivalent familiarity with NTFS, the MFT, the USN Journal, and basic forensic tooling
- A text editor or markdown editor
- Your `lab04.5-notes.md` file (template included in this folder)

> **No tools needed.** Every task in this lab uses the shared sample dataset below. Real parsed output from your own environment is a bonus, but you can complete the lab with the provided data alone.

---

## Scenario

You are continuing analysis of **WKSTN-221**. Earlier work identified the MFT and USN Journal as the right artifacts to examine. You have now parsed both and are looking at the output.

The SOC wants a clear answer to a straightforward question:

> *What is the most defensible file-system story we can tell from the available NTFS evidence — and what do we still not know?*

You are not expected to prove the entire compromise from NTFS alone. Your task is to correlate what you have, document your reasoning, and be honest about what still needs verification.

---

## The WKSTN-221 Dataset

> **Use this data for every task in this lab.** If you have your own parsed output from prior labs, you may substitute it, but work from one consistent set of records throughout.

### MFT Records — Parsed Output (MFTECmd, abbreviated)

```
EntryNum | ParentPath                          | FileName              | FileSize | InUse | Created0x10          | LastMod0x10          | LastMod0x30
---------|-------------------------------------|-----------------------|----------|-------|----------------------|----------------------|---------------------
44190    | C:\Users\j.smith\Downloads\         | invoice_q4.zip        | 8421376  | False | 2024-11-13 21:58:11  | 2024-11-13 21:58:11  | 2024-11-13 21:58:09
44195    | C:\Users\j.smith\Downloads\         | adobe_update.exe      | 204800   | False | 2024-11-13 22:11:04  | 2024-11-13 22:11:04  | 2024-11-10 08:22:11
44196    | C:\Users\j.smith\Downloads\         | runme.bat             | 1024     | False | 2024-11-13 22:11:07  | 2024-11-13 22:11:09  | 2024-11-10 08:22:13
44197    | C:\Users\j.smith\AppData\Local\Temp\| ~extract_tmp_883\     | 0        | False | 2024-11-13 22:11:10  | 2024-11-13 22:11:10  | 2024-11-13 22:11:10
44201    | C:\ProgramData\                     | svchost32.exe         | 204800   | True  | 2024-11-13 22:14:39  | 2024-11-13 22:17:44  | 2024-11-10 08:20:05
44202    | C:\ProgramData\                     | config.ini            | 512      | True  | 2024-11-13 22:14:41  | 2024-11-13 22:14:41  | 2024-11-13 22:14:41
44210    | C:\Windows\System32\                | notepad.exe           | 201216   | True  | 2019-03-18 11:52:00  | 2022-09-14 07:14:02  | 2019-03-18 11:52:00
44215    | C:\Users\j.smith\Downloads\         | invoice_q4.zip        | 0        | False | 2024-11-13 22:29:58  | 2024-11-13 22:29:58  | 2024-11-13 22:29:58
```

> **Column reference:**
> - `InUse: False` — the file has been deleted. The MFT record remains, but the space is freed
> - `Created0x10` — timestamp from the STANDARD_INFORMATION attribute (can be modified by an attacker)
> - `LastMod0x30` — timestamp from the FILENAME attribute (harder to modify, and reflects when the file was placed on disk)
> - `FileSize: 0` on a deleted record — the size metadata may have been cleared at deletion time

---

### USN Journal Records — Parsed Output (MFTECmd, abbreviated)

```
Timestamp             | EntryNum | FileName           | FullPath                                                     | Reason
----------------------|----------|--------------------|--------------------------------------------------------------|--------------------
2024-11-13 21:58:09   | 44190    | invoice_q4.zip     | C:\Users\j.smith\Downloads\invoice_q4.zip                    | FILE_CREATE
2024-11-13 21:58:11   | 44190    | invoice_q4.zip     | C:\Users\j.smith\Downloads\invoice_q4.zip                    | DATA_EXTEND
2024-11-13 22:11:04   | 44195    | adobe_update.exe   | C:\Users\j.smith\Downloads\adobe_update.exe                  | FILE_CREATE
2024-11-13 22:11:07   | 44196    | runme.bat          | C:\Users\j.smith\Downloads\runme.bat                         | FILE_CREATE
2024-11-13 22:11:10   | 44197    | ~extract_tmp_883   | C:\Users\j.smith\AppData\Local\Temp\~extract_tmp_883\        | FILE_CREATE
2024-11-13 22:11:12   | 44197    | ~extract_tmp_883   | C:\Users\j.smith\AppData\Local\Temp\~extract_tmp_883\        | FILE_DELETE
2024-11-13 22:14:32   | 44195    | adobe_update.exe   | C:\Users\j.smith\Downloads\adobe_update.exe                  | RENAME_OLD_NAME
2024-11-13 22:14:32   | 44195    | svchost32.exe      | C:\Users\j.smith\Downloads\svchost32.exe                     | RENAME_NEW_NAME
2024-11-13 22:14:39   | 44201    | svchost32.exe      | C:\ProgramData\svchost32.exe                                 | FILE_CREATE
2024-11-13 22:14:41   | 44202    | config.ini         | C:\ProgramData\config.ini                                    | FILE_CREATE
2024-11-13 22:17:11   | 44196    | runme.bat          | C:\Users\j.smith\Downloads\runme.bat                         | FILE_DELETE
2024-11-13 22:17:44   | 44201    | svchost32.exe      | C:\ProgramData\svchost32.exe                                 | DATA_EXTEND
2024-11-13 22:29:44   | 44195    | svchost32.exe      | C:\Users\j.smith\Downloads\svchost32.exe                     | FILE_DELETE
2024-11-13 22:29:58   | 44190    | invoice_q4.zip     | C:\Users\j.smith\Downloads\invoice_q4.zip                    | FILE_DELETE
```

> **Reason code reference:**
> - `FILE_CREATE` — a new file or directory was created
> - `DATA_EXTEND` — data was written to an existing file (size increased)
> - `RENAME_OLD_NAME` — this was the filename *before* a rename operation
> - `RENAME_NEW_NAME` — this was the filename *after* the same rename operation
> - `FILE_DELETE` — the file was deleted

---

## Background: What Correlation Looks Like in Practice

Before starting the tasks, read this short example of what correlating two artifacts produces.

**MFT alone:**
> Entry 44195 shows a deleted record for `adobe_update.exe` in `C:\Users\j.smith\Downloads\`. It was created at 22:11:04 on 2024-11-13.

**USN Journal alone:**
> Entry 44195 received `RENAME_OLD_NAME` and `RENAME_NEW_NAME` events at 22:14:32. It was also deleted at 22:29:44.

**Correlated:**
> `adobe_update.exe` (entry 44195) arrived in `C:\Users\j.smith\Downloads\` at 22:11:04. Three minutes later, at 22:14:32, it was renamed to `svchost32.exe` while still in Downloads. Seven seconds after the rename, a file with the same name appeared in `C:\ProgramData\` under a new entry number (44201). The original Downloads location was deleted at 22:29:44, approximately fifteen minutes after the rename. The FILENAME attribute timestamp (`LastMod0x30`) shows a date of 2024-11-10, three days before the file appeared on this host. That may indicate the file's compile or packaging date predates the incident, or that its STANDARD_INFORMATION timestamp was modified.

That last paragraph is what correlation produces: a sequence, not just a list.

---

## Lab Tasks

---

### Task 1 — Inventory the Dataset and Identify What Is Suspicious

**Objective:** Read the dataset carefully before drawing any conclusions, and flag what deserves closer attention.

This task is about observation, not interpretation. Notice things now, and explain them in later tasks.

**Part A — Observation inventory**

Review both the MFT and USN tables above. For each row you find suspicious or noteworthy, record it below. Aim for at least eight observations.

A good observation is specific: it names the file, path, timestamp, or value that caught your attention and says *why* it matters — not just that it exists.

| # | Observation | Source (MFT / USN / Both) | Why It Stands Out |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |
| 6 | | | |
| 7 | | | |
| 8 | | | |

> **Hints for what to look for:**
> - Files in writable user paths (Downloads, Temp, AppData)
> - Files in system paths that seem out of place
> - Timestamp anomalies — where `Created0x10` and `LastMod0x30` differ significantly
> - Files that were created and then deleted quickly
> - Rename pairs (`RENAME_OLD_NAME` + `RENAME_NEW_NAME`)
> - Files that share the same EntryNumber across different paths
> - Anything with a size of 0 at the time of deletion

**Part B — Initial grouping**

Before doing deeper correlation, group your observations into likely clusters. Some rows in the dataset appear related to each other. Others may be noise or unrelated activity.

| Cluster Name | Observation Numbers | Why These Likely Belong Together |
|---|---|---|
| | | |
| | | |
| | | |

> You may end up with two to four clusters, or one observation that does not clearly belong with the others. That is fine. Part of good analysis is recognizing what does not fit neatly.

**Part C — Short answers**

**1. One file in the dataset is almost certainly not related to the incident. Which one, and why?**

```
[Your response here]
```

**2. What is suspicious about `invoice_q4.zip` showing up *twice* in the MFT — entries 44190 and 44215?**

> *Hint: Look at the sizes, timestamps, and USN records for both entries.*

```
[Your response here]
```

**3. The `~extract_tmp_883` directory (entry 44197) was created and deleted within two seconds. What does that pattern suggest?**

```
[Your response here]
```

---

### Task 2 — Correlate MFT and USN Journal Evidence for Three Files

**Objective:** Combine file-existence evidence with change-history evidence to build a more complete picture of each file.

For each of the three files below, fill in what the MFT and USN Journal each contribute, then write a combined interpretation.

**File 1: `adobe_update.exe` / `svchost32.exe` (EntryNum 44195)**

| Source | What It Shows |
|---|---|
| MFT | |
| USN Journal | |
| Combined interpretation | |
| Confidence | Low / Medium / High |
| What would raise your confidence? | |

**File 2: `runme.bat` (EntryNum 44196)**

| Source | What It Shows |
|---|---|
| MFT | |
| USN Journal | |
| Combined interpretation | |
| Confidence | Low / Medium / High |
| What would raise your confidence? | |

**File 3: `svchost32.exe` in `C:\ProgramData\` (EntryNum 44201)**

| Source | What It Shows |
|---|---|
| MFT | |
| USN Journal | |
| Combined interpretation | |
| Confidence | Low / Medium / High |
| What would raise your confidence? | |

**Short answers:**

**1. Entries 44195 (in Downloads) and 44201 (in ProgramData) both refer to `svchost32.exe`, but they are different MFT entries. What does that tell you about what happened to the file — and what would you want to verify?**

```
[Your response here]
```

**2. Why is the MFT alone insufficient to understand what happened to `adobe_update.exe`?**

```
[Your response here]
```

**3. Why is the USN Journal alone insufficient to understand the full picture of `svchost32.exe` in ProgramData?**

```
[Your response here]
```

---

### Task 3 — Build a Chronological Activity Sequence

**Objective:** Turn correlated findings into a single ordered timeline that shows how events on WKSTN-221 unfolded.

Construct a timeline using the dataset. Include at least ten entries. Use the rows from both the MFT and USN tables, and add a brief note on the significance of each event.

| Time (UTC) | Source | Event | File / Path | Significance |
|---|---|---|---|---|
| 2024-11-13 21:58:09 | USN | FILE_CREATE | `C:\Users\j.smith\Downloads\invoice_q4.zip` | Zip archive arrives — possible initial delivery mechanism |
| 2024-11-13 21:58:11 | USN | DATA_EXTEND | `C:\Users\j.smith\Downloads\invoice_q4.zip` | Archive continues writing — download or copy completes |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

> **Guidance:** Do not just copy rows mechanically. The `Significance` column is where you show you understand *why* an event matters in the context of the others. A rename event alone is interesting. A rename event three minutes after a suspicious EXE arrives, followed immediately by movement to a system path, is a pattern.

**Short answers:**

**1. What is the approximate total duration of the main suspicious activity window — from the first suspicious event to the last cleanup action?**

```
[Your response here — give a time range and identify the specific events at each end]
```

**2. Which single event in the timeline do you consider most significant, and why?**

```
[Your response here]
```

**3. Is there a gap in the timeline where you have no artifact coverage? What might have happened during that gap that NTFS cannot tell you?**

```
[Your response here]
```

---

### Task 4 — Evaluate Competing Interpretations

**Objective:** Practice checking your own reasoning by considering alternative explanations before settling on a theory.

Good analysts test their theory against alternatives before escalating. When evidence is suggestive, it is easy to lock onto one interpretation and stop looking for reasons it might be wrong.

**Part A — Competing interpretations for Cluster 1 (the executable rename and move)**

| | Interpretation |
|---|---|
| **Attacker-related** | |
| **Benign / alternative** | |
| **Which is better supported by the dataset, and why?** | |

> *For the benign interpretation: think carefully. Is there any legitimate reason a file named `adobe_update.exe` would be renamed to `svchost32.exe` and moved to `C:\ProgramData\`? What would that scenario require to be true?*

**Part B — Competing interpretations for Cluster 2 (the zip archive and cleanup)**

| | Interpretation |
|---|---|
| **Attacker-related** | |
| **Benign / alternative** | |
| **Which is better supported by the dataset, and why?** | |

**Short answers:**

**1. The `LastMod0x30` timestamps on `adobe_update.exe` and `runme.bat` both show 2024-11-10 — three days before the incident. Write two different explanations for this discrepancy and say which you find more likely given the rest of the evidence.**

```
[Your response here]
```

**2. Why does considering the benign interpretation make your final analysis stronger, even if you ultimately reject it?**

```
[Your response here]
```

**3. At what point would you feel confident enough in the attacker-related interpretation to recommend escalation — and what evidence would push you past that threshold?**

```
[Your response here]
```

---

### Task 5 — Separate What NTFS Strongly Supports from What Needs More

**Objective:** Practice labeling your findings accurately so that what you report is defensible.

Forensic findings fall into three levels based on how directly the evidence supports them:

| Level | Meaning | Example |
|---|---|---|
| **Strongly supported by NTFS** | The artifact data directly shows this | "A file named `svchost32.exe` exists in `C:\ProgramData\` with a FILENAME timestamp predating its creation record by three days" |
| **Suggested by NTFS, needs corroboration** | NTFS is consistent with this, but cannot prove it alone | "The file may have been executed after being moved to ProgramData" |
| **Not supported by NTFS alone** | Requires different artifact types entirely | "The attacker accessed this host via RDP using stolen credentials" |

**Part A — Classify each statement**

| Statement | Level | Why |
|---|---|---|
| `invoice_q4.zip` was created in `C:\Users\j.smith\Downloads\` at 21:58:09 UTC on 2024-11-13 | | |
| The zip archive was the initial delivery mechanism for the malicious files | | |
| `adobe_update.exe` was renamed to `svchost32.exe` at 22:14:32 UTC | | |
| The rename was intended to make the file blend in with legitimate Windows processes | | |
| `svchost32.exe` was still present in `C:\ProgramData\` at the time of collection | | |
| `svchost32.exe` was executed and ran successfully on WKSTN-221 | | |
| `runme.bat` was deleted at 22:17:11 UTC, approximately six minutes after it was created | | |
| `runme.bat` was used to run commands that established persistence on the host | | |
| The `~extract_tmp_883` directory existed for approximately two seconds | | |
| The attacker accessed WKSTN-221 using j.smith's credentials | | |

**Part B — Short answer**

*Why does being precise about these three levels improve both your reporting and your credibility as an analyst?*

```
[Your response here — 2 to 3 sentences]
```

---

### Task 6 — Identify the Best Next Artifacts to Check

**Objective:** Connect your NTFS analysis to the broader investigation by identifying what to examine next.

NTFS tells you about file existence and change history. It does not tell you about execution, user context, network activity, or attacker intent. Identifying what to look at next is a core IR skill.

**Part A — Next-artifact table**

| Question NTFS Cannot Answer | Best Next Artifact(s) to Check | Why That Artifact Helps |
|---|---|---|
| Was `svchost32.exe` actually executed on this host? | | |
| Did `runme.bat` run before it was deleted? | | |
| Was `invoice_q4.zip` downloaded from the internet, or copied from another internal host? | | |
| Did j.smith intentionally download these files, or was this activity performed without their knowledge? | | |
| Was `svchost32.exe` configured to run at startup or on a schedule? | | |
| Is there evidence of lateral movement to other hosts during this window? | | |

> **Artifact reference — common next steps after NTFS analysis:**
> - **Prefetch** (`C:\Windows\Prefetch\`) — records of application execution, including deleted executables
> - **Shimcache / AppCompatCache** — registry-based record of files that Windows application compatibility layer encountered
> - **Amcache** — records executed files and their hashes
> - **Windows Event Logs** — process creation (Event ID 4688), logon events (4624/4625), service installs (7045)
> - **PowerShell logs** — script block logging, command history
> - **Browser history** — download origin for files that arrived via browser
> - **LNK files / Jump Lists** — recently opened files, tied to user activity
> - **Registry Run keys** — persistence mechanisms

**Part B — Short answers**

**1. You found `svchost32.exe` still present in `C:\ProgramData\` (InUse: True). Why does that finding alone not prove the file was executed?**

```
[Your response here]
```

**2. Prefetch shows a record for `runme.bat`. How does that change your interpretation of the NTFS finding that it was deleted six minutes after creation?**

```
[Your response here]
```

**3. You check Shimcache and find no record for `svchost32.exe`. Does that prove it was not executed? Explain.**

```
[Your response here — think about Shimcache's limitations]
```

---

### Task 7 — Write an NTFS Correlation Summary

**Objective:** Produce a short, disciplined analytic summary that integrates your findings into a coherent narrative.

This is the most important writing exercise in the lab. It is where you show that you can move from rows and timestamps to structured analysis without overstating what the evidence proves.

**Requirements:**
- 3–5 paragraphs
- Cover the most significant files and paths
- Describe how MFT and USN Journal support each finding
- Identify what the pattern suggests (staging? rename? cleanup?)
- Clearly separate what is strongly supported from what still needs corroboration
- Write it as a working analytic note, not a polished final report

**Structure guidance:** You do not need to use exactly these headings, but cover these areas:

```
Paragraph 1: What arrived and when — the initial delivery picture
Paragraph 2: What happened during the suspicious activity window — rename, move, possible execution setup
Paragraph 3: What cleanup looks like in the artifacts
Paragraph 4: What NTFS strongly supports vs. what still needs verification
Paragraph 5: What the overall pattern suggests, stated carefully
```

```
[Your correlation summary here]
```

> **Common mistakes to avoid:**
> - Saying a file "was executed" when NTFS only shows it existed or was moved — execution requires Prefetch, Shimcache, or Event Log evidence
> - Saying the attacker "intended" something — intent is an inference, and NTFS cannot prove it
> - Treating every rename as suspicious without acknowledging there could be a legitimate explanation
> - Omitting uncertainty — good analysis states what it does not know

---

### Task 8 — Write an Analyst Handoff Note

**Objective:** Summarize the NTFS work so a second analyst can continue or verify it without asking you questions.

A handoff note is different from a correlation summary. It is more direct and operational. It tells the incoming analyst exactly what to focus on, what to check next, and what your confidence level is.

Complete every field below:

```
Case Reference:       WKSTN-221
Author:               [Your name]
Date/Time (UTC):      [When you completed this analysis]

Most Important NTFS Findings:
-
-
-

Key Suspicious Files / Paths to Follow Up:
-
-
-

What NTFS Strongly Supports (can be stated as finding):
-
-

What Still Needs Corroboration (do not state as finding yet):
-
-

Recommended Next Artifacts (in priority order):
1.
2.
3.

Notes for Incoming Analyst:
[Anything a second analyst would need to know that is not captured above — e.g., parser version used,
 any records that seemed unusual or contradictory, follow-up questions you would pursue if you had more time]
```

---

### Task 9 — Correlation Practice: Two Scenarios

**Objective:** Apply your skills to two short hypothetical scenarios outside the WKSTN-221 dataset.

These are written exercises — no tools or data needed.

**Scenario A:**

An MFT parse shows a file: `C:\Users\contractor\AppData\Roaming\update_helper.exe`. It is marked as deleted. The `Created0x10` timestamp is 2024-10-15 at 14:22:00. The `LastMod0x30` timestamp is 2024-09-30 at 09:11:00. The USN Journal shows `FILE_CREATE` at 14:22:00 and `FILE_DELETE` at 14:47:00 — twenty-five minutes later. No other USN records exist for that entry number.

**Questions:**

1. What is suspicious about the timestamp discrepancy, and what might it indicate?

```
[Your response here]
```

2. The file was deleted 25 minutes after creation. Does NTFS tell you whether it ran during that window?

```
[Your response here]
```

3. What would you check next — and what specific question would each artifact answer?

```
[Your response here]
```

---

**Scenario B:**

A USN Journal parse shows the following sequence over four minutes:

```
14:01:02  FILE_CREATE   C:\Windows\Temp\kb_patch_001.exe
14:01:04  DATA_EXTEND   C:\Windows\Temp\kb_patch_001.exe
14:03:18  RENAME_OLD_NAME  C:\Windows\Temp\kb_patch_001.exe
14:03:18  RENAME_NEW_NAME  C:\Windows\Temp\svchost.exe
14:04:59  FILE_DELETE   C:\Windows\Temp\svchost.exe
```

The MFT shows no current record for either filename — both are deleted.

**Questions:**

1. Reconstruct what happened to this file in plain language (two to three sentences).

```
[Your response here]
```

2. The rename target is `svchost.exe` — a real Windows system process name. Why is the location (`C:\Windows\Temp\`) significant?

```
[Your response here]
```

3. Both files are now deleted. Does that mean the investigation is over? What can you still recover?

```
[Your response here — think about what artifacts survive deletion]
```

---

### Task 10 — Reflection

Answer each of the following in 3–5 sentences:

**1. Why correlation matters more than collection**

Why is correlating artifacts into a coherent sequence more valuable than simply identifying a large number of suspicious individual records?

```
[Your response here]
```

**2. The risk of a compelling story**

A chain of NTFS artifacts can look very convincing — rename, move, deletion, timestamps lining up. Why can a compelling story still be weak if you have not checked your interpretation against alternatives or corroborating evidence?

```
[Your response here]
```

**3. The value of stating uncertainty**

Some analysts worry that admitting what they do not know makes them look less confident. Why does explicitly stating uncertainty actually strengthen a forensic finding?

```
[Your response here]
```

**4. NTFS in the larger IR process**

NTFS analysis can answer some questions very well and others not at all. How should NTFS findings be used to direct the next stage of an investigation — rather than treated as the final answer?

```
[Your response here]
```

---

## Deliverables Checklist

Your `lab04.5-notes.md` should contain:

- [ ] **Task 1** — Observation inventory (8+ entries), activity cluster groupings, and three short answers
- [ ] **Task 2** — MFT and USN correlation tables for all three files, plus three short answers
- [ ] **Task 3** — Chronological timeline (10+ entries) and three short answers
- [ ] **Task 4** — Competing interpretations for two clusters and three short answers
- [ ] **Task 5** — Classification table (10 statements) and short answer
- [ ] **Task 6** — Next-artifact table and three short answers
- [ ] **Task 7** — NTFS correlation summary (3–5 paragraphs)
- [ ] **Task 8** — Completed analyst handoff note
- [ ] **Task 9** — Responses to both hypothetical scenarios
- [ ] **Task 10** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab04/
├── lab04-notes.md              ← Your working notes file (whole lab)
└── Lab04_05/
    ├── ReadMe.md                   ← This file
    ├── lab04.5-notes.md            ← Your working notes file
    └── ntfs-observation-matrix.md  ← Reusable cross-case NTFS worksheet
```

> **Reusable worksheet:** The [`ntfs-observation-matrix.md`](ntfs-observation-matrix.md) in this folder is designed to outlive the lab. Copy it into your case folder for any real NTFS investigation. It covers file-of-interest identification, MACB-divergence tracking, USN cross-reference, path anomalies, ADS / Mark-of-the-Web context, cross-source corroboration, and evidence gaps. It follows the same pattern as Lab 02's `question-evidence-worksheet.md`.

---

## Key Takeaways

- **Correlation is what turns artifact review into analysis.** Individual suspicious records are interesting. Clusters of related records that tell a coherent story are actionable.
- **MFT and USN Journal answer different parts of the story.** The MFT shows that a file existed. The USN Journal shows what happened to it over time. Neither is complete without the other.
- **Timestamp anomalies are clues, not conclusions.** A FILENAME timestamp that predates a file's arrival on a host may indicate timestamp manipulation — or it may reflect a legitimate compile date. Context and corroboration determine which.
- **Not every suspicious row belongs in the same theory.** Good analysis groups only what the evidence supports. Forcing unrelated rows into one narrative weakens your case.
- **Stating what NTFS cannot prove is part of good analysis.** File existence is not execution. Presence in a path is not persistence. Knowing the boundary of your evidence makes your conclusions more credible, not less.
- **NTFS is the beginning, not the end.** Its value is in directing the next artifact checks — Prefetch for execution, Event Logs for process context, registry for persistence — not in replacing them.

---

**Next:** Lab 05 — Windows Registry and Cloud Storage Forensics

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
