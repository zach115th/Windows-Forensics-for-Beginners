# Lab 4.4 — Tools for NTFS Artifact Analysis

**Supporting Section 4.4: Tools**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Before You Start — A Note on What "Using a Tool" Actually Means

When investigators say "I checked the MFT," they almost always mean:

1. They ran a parser to extract raw MFT records from disk
2. The parser exported those records into a readable format (usually CSV)
3. They filtered or searched that output
4. They drew a conclusion based on what they found

That chain of steps is normal. Notice, though, that a *person* does step 4, not a tool. A parser reads bytes and formats them. You decide what they mean.

This lab teaches you to use these tools well: choose the right one, run it correctly, document what you did, and check that your results mean what you think they mean.

> **Key principle:** The artifact is the evidence. The tool is how you read it. These are different things, and keeping them separate makes you a stronger analyst.

---

## Overview

NTFS artifacts — the MFT, USN Journal, and related structures — do not interpret themselves. Even when you know these are the right sources to examine, you still need tools to extract, parse, filter, and review their contents accurately and reproducibly.

This lab gives you hands-on practice with the tools commonly used in incident response for NTFS analysis. You will:

- Learn what the major NTFS forensic tools do and how they differ
- Run realistic parsing commands and read their output
- Design a documented, repeatable analysis workflow
- Practice validating findings so you are not relying on a single parser
- Learn to clearly separate what a tool produced from what *you* concluded

---

## What This Lab Covers

| Section | Topic |
|---|---|
| 4.4.1 | Why responders rely on parsing tools for NTFS artifacts |
| 4.4.2 | Common tool categories for MFT and USN analysis |
| 4.4.3 | Tool selection, documentation, and repeatability |
| 4.4.4 | Validation and cross-checking of parsed results |

---

## Learning Objectives

By completing this lab, you will be able to:

- Name and describe the tools most commonly used for NTFS analysis in IR
- Explain what each tool does — and what it does *not* do
- Run MFTECmd to parse an MFT and USN Journal and understand the output
- Select the right tool based on the question you are trying to answer
- Document tool use in a way another analyst can reproduce from your notes alone
- Cross-check an important finding using more than one method
- Distinguish clearly between tool output and your own interpretation

---

## Estimated Time

60–90 minutes (slightly longer than prior labs because of the hands-on tool exercises)

---

## Prerequisites

- Completion of Labs 4.1, 4.2, and 4.3, or equivalent familiarity with the MFT and USN Journal
- A Windows environment (VM recommended) with MFTECmd installed, **or** willingness to work through the exercises using the sample output provided in this lab
- Your `lab04.4-notes.md` file (template included in this folder)

> **Tool access is optional.** Every task in this lab includes either sample output you can work with or a written alternative you can complete without running commands. Real practice is better, but the concepts transfer either way.

---

## Scenario

You are continuing analysis of **WKSTN-221**, a Windows workstation flagged for suspicious behavior during a security incident. Previous labs identified the MFT and USN Journal as the right artifacts to examine. Now your team needs to decide:

- Which tools to use
- How to run them correctly
- How to document the work
- How to check that what you found is real

Leadership wants answers quickly. A second analyst may need to continue your work tomorrow. Your work needs to be fast enough for incident response and clear enough that nobody has to guess how you produced a finding.

---

## Tool Reference — What Each Tool Does and When to Use It

> **Read this section carefully before starting the tasks.** The questions throughout the lab depend on knowing what each tool does.

### MFTECmd (EZ Tools) — Your Primary Parser

**What it is:** A command-line tool written by Eric Zimmerman. It is the most widely used MFT and USN Journal parser in incident response.

**What it does:**
- Reads the raw `$MFT` file and outputs structured records in CSV format
- Reads the raw `$J` (USN Journal) file and outputs change records in CSV format
- Runs quickly even on large volumes — parsing a 500MB MFT typically takes under a minute

**What it does not do:**
- It does not tell you what the findings mean. That is your job.
- It does not automatically flag suspicious files. You filter and interpret the output.

**Common commands:**

```powershell
# Parse the MFT — output to CSV
MFTECmd.exe -f "E:\Evidence\$MFT" --csv "E:\IR\WKSTN-221\Parsed\" --csvf mft_output.csv

# Parse the USN Journal — output to CSV
MFTECmd.exe -f "E:\Evidence\$J" --csv "E:\IR\WKSTN-221\Parsed\" --csvf usn_output.csv

# Check MFTECmd version (always record this)
MFTECmd.exe --version
```

**Key flags explained:**

| Flag | What It Does |
|---|---|
| `-f` | Specifies the input file (the artifact you are parsing) |
| `--csv` | Specifies the output *folder* where the CSV will be saved |
| `--csvf` | Specifies the output *filename* |
| `--version` | Prints the tool version — record this in your notes |

**What the MFT CSV output looks like (sample, abbreviated):**

```
EntryNumber, SequenceNumber, ParentEntryNumber, FullPath, FileSize, InUse, Created0x10, LastModified0x10, ...
12345, 1, 5, C:\Users\j.smith\Downloads\adobe_update.exe, 204800, False, 2024-11-13 22:11:04, 2024-11-13 22:11:04, ...
12346, 1, 5, C:\Users\j.smith\Downloads\runme.bat, 1024, False, 2024-11-13 22:11:07, 2024-11-13 22:11:09, ...
```

> **What to notice in MFT output:**
> - `InUse: False` means the file has been deleted. The record still exists, but NTFS marks its space as available.
> - `FullPath` is reconstructed by the parser — it is not stored as a plain string in the raw MFT
> - There are *eight* timestamps per file: four in each of two attributes (STANDARD_INFORMATION and FILENAME). MFTECmd exports both sets, which matters when you check for timestamp tampering.

**What the USN Journal CSV output looks like (sample, abbreviated):**

```
UpdateSequenceNumber, Timestamp, Name, FullPath, Reason, ...
12209844, 2024-11-13 22:11:04, adobe_update.exe, C:\Users\j.smith\Downloads\adobe_update.exe, FILE_CREATE, ...
12209901, 2024-11-13 22:14:32, adobe_update.exe, C:\Users\j.smith\Downloads\adobe_update.exe, RENAME_OLD_NAME, ...
12209902, 2024-11-13 22:14:32, svchost32.exe, C:\Users\j.smith\Downloads\svchost32.exe, RENAME_NEW_NAME, ...
12209950, 2024-11-13 22:17:11, svchost32.exe, C:\Users\j.smith\Downloads\svchost32.exe, FILE_DELETE, ...
```

> **What to notice in USN output:**
> - The `Reason` column tells you *what happened* to the file, not just that it exists
> - `RENAME_OLD_NAME` and `RENAME_NEW_NAME` always appear together — they show you both the before and after name
> - Entries are in chronological order and can be correlated with MFT records using `EntryNumber`

---

### Timeline Explorer (EZ Tools) — Your Viewer and Filter

**What it is:** A GUI tool, also from Eric Zimmerman, that opens, sorts, and filters the large CSV files that MFTECmd and similar tools produce.

**What it does:**
- Opens large CSVs that would be slow or cumbersome in Excel
- Lets you filter by column values, such as only deleted files or only files in a specific path
- Lets you sort by timestamp to build a chronological view
- Lets you add bookmarks and highlight rows for reporting

**What it does not do:**
- It does not parse artifacts directly — it reads the output that MFTECmd already produced
- It does not draw conclusions — that is your job

**Typical workflow with Timeline Explorer:**

```
1. Run MFTECmd → produces mft_output.csv
2. Open Timeline Explorer → File > Load CSV > select mft_output.csv
3. Filter: InUse = False (show only deleted files)
4. Filter: FullPath contains "Downloads" (narrow to that directory)
5. Sort by Created0x10 (chronological order)
6. Bookmark rows of interest
```

---

### AnalyzeMFT — A Python-Based Alternative

**What it is:** An open-source Python script that parses the MFT independently of the EZ Tools ecosystem.

**When to use it:**
- As a second parser to cross-check MFTECmd findings
- In environments where EZ Tools cannot be installed
- When building scripted or automated workflows

**Key difference from MFTECmd:** The column names and output format differ. A field that MFTECmd calls `FullPath` may appear differently in AnalyzeMFT output. This matters when you compare results. Investigate any discrepancy between parsers before you escalate a finding.

---

### Sleuth Kit (fls, istat) — Cross-Platform Command-Line Analysis

**What it is:** A collection of open-source command-line forensic tools. `fls` lists file entries from a file system image. `istat` shows detailed metadata for a specific inode, which is similar to an MFT entry number.

**When to use it:**
- Validating a specific finding from MFTECmd
- Working in a Linux-based analysis environment
- Scripting and automation tasks

**Example commands:**
```bash
# List deleted files in a specific directory (inode 12345)
fls -r -d image.raw 12345

# Show detailed metadata for a specific MFT entry (entry 12346)
istat image.raw 12346
```

---

### Autopsy — GUI Forensic Suite

**What it is:** A full graphical forensic analysis platform that can ingest disk images, parse NTFS structures, and display results through a visual interface.

**When to use it:**
- Broader case review that goes beyond NTFS artifacts
- When you need to present findings visually to non-technical stakeholders
- When multiple artifact types need to be reviewed in one place

**When *not* to use it as your primary triage tool:**
- Autopsy is slower to start and heavier than command-line parsers
- During initial triage when speed matters most, MFTECmd is faster
- When you only need MFT and USN data — Autopsy is more than you need

---

### Tool Comparison Summary

| Tool | Primary Use | Speed | Output Format | Best For |
|---|---|---|---|---|
| MFTECmd | Parse MFT and USN Journal | Fast | CSV | Initial triage, repeatable IR workflow |
| Timeline Explorer | Filter and review parsed CSV | Fast | GUI view | Narrowing large result sets |
| AnalyzeMFT | MFT parsing (Python) | Moderate | CSV | Second-opinion validation, scripting |
| Sleuth Kit | CLI NTFS analysis | Fast | Text | Validation, Linux environments |
| Autopsy | Full GUI case review | Slow to start | GUI | Broader case work, stakeholder review |

---

## Lab Tasks

---

### Task 1 — Map the Tool Landscape

**Objective:** Build your own reference table of tool categories and understand why each exists.

**Part A — Complete the tool category table**

The first five rows are filled in for you. Add at least three more categories of your own. Consider analyst tasks the table does not yet cover, such as collection, hex-level inspection, or reporting.

| Tool Category | What It Is Used For | Example Tool(s) | Why It Is Useful in IR |
|---|---|---|---|
| **MFT parser** | Extract and structure MFT file records | MFTECmd, AnalyzeMFT | Surfaces file existence, paths, timestamps, and deletion state |
| **USN Journal parser** | Extract file system change records | MFTECmd (`-f $J`), UsnJrnl2Csv | Shows create, rename, and delete events that live file listings hide |
| **Timeline tool** | Merge, sort, and filter parsed output chronologically | Timeline Explorer, log2timeline/Plaso | Reveals artifact relationships across time |
| **GUI forensic suite** | Browse, search, and annotate case artifacts visually | Autopsy, FTK | Useful for broader case review and evidence presentation |
| **Command-line / scriptable parser** | Automate parsing and integrate into collection scripts | MFTECmd, Sleuth Kit | Supports repeatable, auditable workflows |
| *(Add your own)* | | | |
| *(Add your own)* | | | |
| *(Add your own)* | | | |

> **Hint for the three you add:** Think about what happens *before* parsing, when you acquire or collect artifacts from a live system. Then think about what happens *after* parsing, when you turn findings into something you can share with others. What tools help with those steps?

**Part B — Hands-on or written exercise**

If you have MFTECmd available, run the following and paste your output below:
```powershell
MFTECmd.exe --version
```

If you do not have access, write: what information does knowing the tool version give you — and why would it matter if a colleague ran a *different* version of the same tool on the same artifact?

```
[Your response or version output here]
```

**Part C — Short answers**

**1. Why is a command-line tool like MFTECmd usually faster to use during initial triage than a GUI tool like Autopsy?**

```
[Your response here — 2 to 3 sentences]
```

**2. Why might you still want a GUI tool later in the same investigation?**

```
[Your response here — 2 to 3 sentences]
```

**3. Two parsers report different timestamps for the same MFT record. What does that tell you, and what should you do next?**

```
[Your response here — 2 to 3 sentences]
```

---

### Task 2 — Read and Interpret Sample Tool Output

**Objective:** Practice working with real-style parser output before designing your own workflow.

> **You can complete this task without any tools installed.** Use the sample output below.

**Part A — MFT output analysis**

The following is a simplified excerpt from an MFTECmd MFT parse of WKSTN-221. Read it carefully, then answer the questions.

```
EntryNumber | FullPath                                          | FileSize | InUse | Created0x10          | LastModified0x10     | LastModified0x30
------------|---------------------------------------------------|----------|-------|----------------------|----------------------|----------------------
44201       | C:\Users\j.smith\Downloads\adobe_update.exe       | 204800   | False | 2024-11-13 22:11:04  | 2024-11-13 22:11:04  | 2024-11-10 08:22:11
44202       | C:\Users\j.smith\Downloads\runme.bat              | 1024     | False | 2024-11-13 22:11:07  | 2024-11-13 22:11:09  | 2024-11-10 08:22:13
44203       | C:\ProgramData\svchost32.exe                      | 204800   | True  | 2024-11-13 22:14:39  | 2024-11-13 22:14:39  | 2024-11-10 08:20:05
44204       | C:\Windows\System32\notepad.exe                   | 201216   | True  | 2019-03-18 11:52:00  | 2022-09-14 07:14:02  | 2019-03-18 11:52:00
```

> **Column reference:**
> - `InUse: False` = deleted (MFT record remains, file space is freed)
> - `Created0x10` = timestamp from STANDARD_INFORMATION attribute (can be modified by an attacker)
> - `LastModified0x30` = timestamp from FILENAME attribute (harder to modify, and often reflects when the file was written to disk)

**Questions:**

1. How many files in this output have been deleted? List their full paths.

```
[Your response here]
```

2. Entry 44203 (`svchost32.exe` in `C:\ProgramData\`) is still present on disk. What is suspicious about it — even from just this output alone?

```
[Your response here — think about name, location, and timestamps]
```

3. Compare the `Created0x10` and `LastModified0x30` timestamps for entry 44203. They are different by several days. What might that indicate?

```
[Your response here]
```

4. Entry 44204 (`notepad.exe`) looks normal by comparison. Why does it look normal? What makes its timestamps less suspicious than entry 44203's?

```
[Your response here]
```

**Part B — USN Journal output analysis**

The following USN Journal records correspond to entries in the MFT output above.

```
Timestamp             | EntryNumber | Name                | FullPath                                              | Reason
----------------------|-------------|---------------------|-------------------------------------------------------|-------------------
2024-11-13 22:11:04   | 44201       | adobe_update.exe    | C:\Users\j.smith\Downloads\adobe_update.exe           | FILE_CREATE
2024-11-13 22:11:07   | 44202       | runme.bat           | C:\Users\j.smith\Downloads\runme.bat                  | FILE_CREATE
2024-11-13 22:14:32   | 44201       | adobe_update.exe    | C:\Users\j.smith\Downloads\adobe_update.exe           | RENAME_OLD_NAME
2024-11-13 22:14:32   | 44201       | svchost32.exe       | C:\Users\j.smith\Downloads\svchost32.exe              | RENAME_NEW_NAME
2024-11-13 22:14:39   | 44203       | svchost32.exe       | C:\ProgramData\svchost32.exe                          | FILE_CREATE
2024-11-13 22:17:11   | 44203       | svchost32.exe       | C:\ProgramData\svchost32.exe                          | DATA_EXTEND
2024-11-13 22:31:05   | 44202       | runme.bat           | C:\Users\j.smith\Downloads\runme.bat                  | FILE_DELETE
```

**Questions:**

1. What was `svchost32.exe` originally called, and when was it renamed? Cite the specific USN records that show this.

```
[Your response here]
```

2. The MFT shows `svchost32.exe` still present in `C:\ProgramData\` (InUse: True), but the USN Journal shows it was copied *from* Downloads *to* ProgramData. How do these two sources complement each other?

```
[Your response here]
```

3. `runme.bat` appears in both the MFT (deleted, entry 44202) and the USN Journal (FILE_CREATE then FILE_DELETE). What is the investigative value of having both records, rather than just one?

```
[Your response here]
```

4. Based on both outputs together, write two sentences describing the sequence of events in plain language — the kind of summary you might put in a case note.

```
[Your case note summary here]
```

---

### Task 3 — Select Tools for the WKSTN-221 Investigation

**Objective:** Choose a practical, justified toolset for the specific investigative needs of this case.

You need to answer the following questions quickly and defensibly:

- Did suspicious files exist on WKSTN-221?
- Were any renamed or deleted during the incident window?
- Can you export findings in a format another analyst can review?
- Can you reproduce this process on a second host tomorrow?

For each need below, select a tool or tool type and justify your choice. There is no single correct answer — the justification matters more than the choice.

| Need | Selected Tool | Why You Chose It | Output Format |
|---|---|---|---|
| Parse the MFT | | | |
| Parse the USN Journal | | | |
| Filter output for suspicious paths and file types | | | |
| Build a chronological timeline of file activity | | | |
| Review results visually and add annotations | | | |
| Record analyst commands and notes | | | |

**Short answers:**

**1. Which step in your toolset is most important for speed during initial triage — and what would you be willing to sacrifice to get it?**

```
[Your response here]
```

**2. Which step is most important for defensibility — and what specifically makes it defensible?**

> *Hint: Think about what "defensible" means in practice. If someone asked you in court or in a post-incident review "how do you know that file was deleted?" — what would you point to?*

```
[Your response here]
```

**3. Which step matters most when handing off to another analyst — and why?**

```
[Your response here]
```

---

### Task 4 — Build a Repeatable Analysis Workflow

**Objective:** Turn your tool selection into a step-by-step procedure another responder could follow from your notes alone.

**Part A — Complete the workflow table**

Steps 1–3 are filled in. Complete steps 4–7. Each step should be specific enough that someone else could execute it without asking you questions.

| Step | Action | Tool | Output | Why This Step Happens Here |
|---|---|---|---|---|
| 1 | Verify source artifacts are present and generate hash values | `sha256sum` or CertUtil | Hash log file | Confirms integrity before any parsing begins |
| 2 | Parse the MFT to CSV | MFTECmd | `mft_output.csv` | Extracts all file and directory records into a filterable format |
| 3 | Parse the USN Journal to CSV | MFTECmd | `usn_output.csv` | Extracts the file change history for correlation with MFT records |
| 4 | | | | |
| 5 | | | | |
| 6 | | | | |
| 7 | | | | |

**Exact commands for reference (steps 2 and 3):**

```powershell
# Hash the source artifacts before parsing
certutil -hashfile "E:\Evidence\$MFT" SHA256 >> "E:\IR\WKSTN-221\03_Notes\hashes.txt"
certutil -hashfile "E:\Evidence\$J" SHA256 >> "E:\IR\WKSTN-221\03_Notes\hashes.txt"

# Parse the MFT
MFTECmd.exe -f "E:\Evidence\$MFT" --csv "E:\IR\WKSTN-221\02_Parsed_Output\MFT\" --csvf mft_output.csv

# Parse the USN Journal
MFTECmd.exe -f "E:\Evidence\$J" --csv "E:\IR\WKSTN-221\02_Parsed_Output\USN\" --csvf usn_output.csv
```

**Part B — Write your rationale**

Write 2–3 sentences explaining why your sequence is in this order — specifically why each stage follows logically from the one before it.

> *Tip for beginners: Start from the beginning. Why do you hash before you parse? Why do you parse before you filter? Why do you document as you go rather than at the end?*

```
[Your rationale here]
```

**Part C — Hands-on exercise (if tools are available)**

If you have access to a test MFT file or a sample NTFS image:

1. Run the MFTECmd parse command above (adjust paths to match your environment)
2. Open the resulting CSV in Timeline Explorer or Excel
3. Filter the `InUse` column for `False` (deleted files only)
4. Count how many deleted file records appear and record the number below

```
Number of deleted file records found: ___

Paste the first 3 rows of your filtered output here (or describe what you see):
[Your response here]
```

If tools are not available, answer this instead: what would you expect to see in the `FullPath` column for a deleted file that was renamed just before deletion?

```
[Your response here]
```

---

### Task 5 — Document Tool Use Correctly

**Objective:** Practice recording the information that makes your work reproducible and trustworthy.

**Why this matters:** Documentation is how you prove that what you found is real and that your process was sound. You need that proof when someone questions your findings six months later in a legal proceeding, a post-incident review, or a peer audit.

**Part A — Fill in the documentation requirements table**

| Field | What You Should Record | Why It Matters |
|---|---|---|
| Tool name | | |
| Tool version | | |
| Source artifact path | | |
| Source artifact hash | | |
| Exact command used | | |
| Output file path | | |
| Output file hash | | |
| Date/time run (UTC) | | |
| Analyst name | | |
| Errors or warnings | | |
| Notes on unexpected output | | |

**Part B — Short answers**

**1. Why does tool version matter — even when a tool's name is well known?**

> *Hint: Think about what would happen if MFTECmd version 1.0 and version 1.2 parsed the same MFT differently. How would you know which result to trust?*

```
[Your response here]
```

**2. Why is recording the exact command line more important than just writing down which tool you ran?**

```
[Your response here]
```

**3. A tool finishes parsing and shows one warning: "Record 44201: Attribute list truncated — partial data returned." You get output and it looks fine. Should you document this warning? Why?**

```
[Your response here]
```

**Part C — Complete a documentation block**

Fill in every field below for one parsing step you would run on WKSTN-221 (real or hypothetical):

```
Tool:
Tool Version:
Source Artifact:
Source Artifact SHA-256:
Command:
Output File:
Output Location:
Output SHA-256:
Date/Time (UTC):
Analyst:
Errors / Warnings:
Notes:
```

---

### Task 6 — Validate and Cross-Check Findings

**Objective:** Build the habit of checking important findings before treating them as conclusions.

**Why this matters for beginners:** High-stakes decisions in incident response, such as escalation, containment, and legal hold, should not rest on a single parsing run. Trusting a tool is easy. Asking whether its output could be wrong, incomplete, or misread is harder and more important.

**Scenario:** MFTECmd shows a deleted file record for `runme.bat` under `C:\Users\j.smith\Downloads\`. Your team wants to escalate this to leadership as evidence of malicious activity. Before you do, what do you check?

**Part A — Validation plan**

The first three rows are filled in. Add at least two more methods of your own.

| Validation Method | What You Would Check | Why It Helps |
|---|---|---|
| Re-run with the same tool using your documented command | Reproduce the output exactly as recorded | Confirms the finding is not a one-time parsing glitch |
| Run a second parser, such as AnalyzeMFT or Sleuth Kit | Check whether the same record appears with consistent values | Independent parser output strengthens confidence |
| Check the raw CSV manually | Verify the `InUse` flag, parent path, and timestamps directly in the file | Confirms the finding is not a filter or display artifact in a GUI |
| *(Add your own)* | | |
| *(Add your own)* | | |

**Part B — Applying the validation plan to WKSTN-221**

Using the sample USN Journal output from Task 2, answer this:

Does the USN Journal independently support the MFT finding that `runme.bat` was created and then deleted? Cite specific records in your answer.

```
[Your response here — be specific about timestamps and reason codes]
```

**Part C — Short answers**

**1. Why is cross-checking especially important before a finding drives escalation or containment?**

```
[Your response here]
```

**2. "The tool said so" is not a sufficient explanation for a finding. Why not?**

```
[Your response here — think about what a tool cannot tell you on its own]
```

**3. You run MFTECmd and AnalyzeMFT on the same $MFT. MFTECmd shows entry 44203 was created on 2024-11-13. AnalyzeMFT shows the same entry was created on 2024-11-10. What do you do?**

```
[Your response here — do not just pick one answer; describe the process]
```

---

### Task 7 — Design an Output Folder Structure

**Objective:** Create an organized, repeatable storage model for parsed NTFS artifact output.

**Why organization matters:** A clear folder structure lets you find anything quickly and lets another analyst orient themselves without asking you. In a real incident, you may work for days or weeks, hand off to other analysts, or return to evidence you collected weeks ago.

**Part A — Fill in the folder structure**

Add a purpose description for each folder and file listed.

```
IR-Cases\
└── WKSTN-221\
    ├── 01_Source_Artifacts\
    │   ├── MFT\             ← Purpose:
    │   └── USN\             ← Purpose:
    ├── 02_Parsed_Output\
    │   ├── MFT\             ← Purpose:
    │   ├── USN\             ← Purpose:
    │   └── Timelines\       ← Purpose:
    ├── 03_Notes\
    │   ├── commands.md      ← Purpose:
    │   ├── findings.md      ← Purpose:
    │   └── validation.md    ← Purpose:
    └── 04_Reports\          ← Purpose:
```

**Part B — Complete the naming convention table**

| Item | Naming Convention | Your Example |
|---|---|---|
| Parsed MFT output | `[CaseID]_[Hostname]_[YYYYMMDD]_mft.csv` | `IR2024001_WKSTN221_20241114_mft.csv` |
| Parsed USN output | | |
| Timeline export | | |
| Command log | | |
| Validation note | | |
| Tool documentation block | | |

**Part C — Short answers**

**1. Why should parsed output be stored separately from the original source artifacts?**

```
[Your response here]
```

**2. You are handing off this case to a second analyst who has never seen the evidence. What is the single most important thing your folder structure communicates to them before they open a single file?**

```
[Your response here]
```

---

### Task 8 — Tool Output vs. Analyst Conclusion

**Objective:** Practice clearly separating what a tool produced from what you concluded from it.

This distinction matters for reporting, peer review, and defensibility. A parser surfaces data. An analyst interprets it. These are different things, so label them separately in your notes.

**Part A — Classify each statement**

Label each as: **Tool output** | **Analyst interpretation** | **Unsupported overclaim**

Use the sample output from Task 2 to ground your answers.

| Statement | Classification | Why |
|---|---|---|
| MFTECmd reports a deleted file record for `runme.bat` in `C:\Users\j.smith\Downloads\` | | |
| The deleted batch file was definitely used to establish persistence on WKSTN-221 | | |
| USN Journal output contains a `RENAME_OLD_NAME` record for `adobe_update.exe` at 22:14:32 | | |
| The rename was likely part of attacker staging — but this needs corroboration from execution artifacts | | |
| MFTECmd shows that `adobe_update.exe` and `svchost32.exe` share the same EntryNumber (44201) | | |
| The attacker intentionally renamed the file to evade detection | | |
| USN Journal shows `svchost32.exe` received a `DATA_EXTEND` record three minutes after appearing in ProgramData | | |
| The attacker used `svchost32.exe` for lateral movement to other hosts on the network | | |

**Part B — Write three statements of your own**

Write one tool output statement, one analyst interpretation, and one unsupported overclaim based on the Task 2 sample data. Then classify each.

| Statement | Classification | Why |
|---|---|---|
| | | |
| | | |
| | | |

**Part C — Short answer**

*Why is it important to label the difference between tool output and analyst interpretation — even when you are confident both are accurate?*

```
[Your response here — 2 to 3 sentences]
```

---

### Task 9 — Write a Tooling Decision Note

**Objective:** Write a clear, concise case note explaining your NTFS analysis toolchain for WKSTN-221.

Write it for a senior analyst who was not involved in the case. They need to understand your choices and be able to continue or reproduce your work.

Your note should cover:

- Which tools you selected and why (match tools to specific investigative needs)
- How you documented the work (version, commands, output paths)
- How you validated important findings
- What another responder would need to know to reproduce your results

```
[Paragraph 1 — tool selection and rationale]


[Paragraph 2 — documentation, validation, and handoff]
```

---

### Task 10 — Reflection

Answer each of the following in 3–5 sentences:

**1. Tools are interpreters, not evidence**
Why should you understand what a forensic tool does internally — even if you trust it and use it every day?

```
[Your response here]
```

**2. Repeatability as protection**
Imagine a finding you documented is questioned six months later. How does having recorded tool version, exact command, and output hashes protect you in that situation?

```
[Your response here]
```

**3. Speed versus rigor**
Incident response moves fast. How do you decide when to slow down and cross-check a finding versus moving quickly to the next step?

```
[Your response here]
```

**4. Tool choice is part of the investigation**
How can choosing the wrong tool — or using the right tool incorrectly — affect the quality and defensibility of your conclusions?

```
[Your response here]
```

---

## Deliverables Checklist

Your `lab04.4-notes.md` should contain:

- [ ] **Task 1** — Tool category table (8+ entries) and three short answers, plus version output or written response
- [ ] **Task 2** — Answers to all MFT and USN output analysis questions, including case note summary
- [ ] **Task 3** — Completed tool selection table and three short answers
- [ ] **Task 4** — Seven-step workflow table, rationale, and hands-on or written exercise response
- [ ] **Task 5** — Documentation requirements table, three short answers, and completed documentation block
- [ ] **Task 6** — Validation plan (5+ rows), applied validation answer, and three short answers
- [ ] **Task 7** — Folder structure with purposes, naming convention table, and two short answers
- [ ] **Task 8** — Classification table, three original statements, and short answer
- [ ] **Task 9** — Tooling decision note (2 paragraphs)
- [ ] **Task 10** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab04/
├── lab04-notes.md    ← Your working notes file (whole lab)
└── Lab04_04/
    ├── ReadMe.md         ← This file
    └── lab04.4-notes.md  ← Your working notes file
```

---

## Key Takeaways

- **Tools are interpreters, not evidence.** The artifact is the evidence, and the parser is how you read it. Never let tool convenience substitute for analytical judgment.
- **Output format shapes analysis.** CSV enables filtering and scripting. GUI tools enable annotation and visual review. Choose based on your current need.
- **Documentation is not optional.** Record the tool name, version, exact command, source path, and output hash every time. Reproducibility depends on it.
- **Important findings deserve cross-checking.** A finding that will drive escalation or containment should not rest on a single parser run if any alternative exists.
- **Output and interpretation are different things.** A tool reports. You conclude. Label them differently in your notes — every time.
- **A clean workflow makes everything else easier.** Good organization reduces errors, speeds up handoffs, and makes peer review possible without a phone call.

---

**Next:** Lab 4.5 — Correlating NTFS Artifacts in IR

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
