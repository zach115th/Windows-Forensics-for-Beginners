# Lab 4.1 — NTFS Overview

**Supporting Section 4.1: NTFS Overview**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Useful Windows file system forensics starts with understanding what NTFS is actually tracking for you.

NTFS is not just a place where files live. It is a structured file system that records metadata about files, directories, timestamps, attributes, allocation state, and internal relationships. That metadata is what makes forensic analysis possible. When responders talk about "checking the MFT," "looking at deleted file records," or "reviewing NTFS timestamps," they are relying on the design of NTFS itself. The file system was built to track far more than where bytes live on disk.

This lab introduces NTFS at the practical level incident responders need. You are not reverse-engineering the entire file system. You are learning how to think about Windows storage the way a responder needs to: what artifacts exist, what they can tell you, what they cannot, and why ordinary file activity leaves behind useful metadata even when the original file is long gone.

The goal is to build enough NTFS awareness that the deeper artifact work in later labs feels grounded rather than mechanical.

---

## What This Lab Covers

| Section | Topic |
|---|---|
| 4.1.1 | What NTFS is and why Windows responders care about it |
| 4.1.2 | Files, directories, metadata, and attributes |
| 4.1.3 | What NTFS will not tell you, including how deleted records degrade over time |
| 4.1 | Why NTFS structure matters for later forensic analysis |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain what NTFS is in practical, responder-focused terms
- Distinguish file content from file system metadata — and explain why the distinction matters
- Identify core NTFS concepts: file records, attributes, directories, allocation state, and timestamps
- Describe why deleted files can still leave useful forensic traces
- Recognize which forensic questions NTFS can answer well and where it falls short
- Explain why NTFS analysis is foundational to Windows incident response

---

## Estimated Time

30–45 minutes

---

## Prerequisites

- Completion of Labs 01–03, or equivalent familiarity with Windows IR workflow and triage
- A text editor or markdown editor
- Your `lab04.1-notes.md` file (template included in this folder)
- Optional: a Windows VM or host system you can examine for file system examples

---

## Scenario

A responder on your team has collected a triage package from a Windows workstation named **WKSTN-144**. The package includes event logs, registry hives, and basic file listings, but not much context yet.

During the initial case discussion, a colleague says:

> *"Let's just check NTFS and see what was really on disk."*

That sounds useful but vague. Before you can parse the MFT, review deleted records, or build timelines from file system metadata, you need to understand what NTFS actually gives you and what its limits are.

Your task in this lab is to build that foundation.

---

## Background: NTFS Is a Metadata-Rich File System

NTFS (New Technology File System) is the primary file system used by modern Windows. For responders, its value is not that it stores files. Its real value is that it stores *structured metadata* about those files and directories. That metadata persists even after the files themselves are deleted, renamed, or moved.

That metadata can help answer questions such as:

- Did a suspicious file exist on this disk?
- Where was it located in the directory tree?
- When was it created, modified, or deleted?
- Was the file renamed or moved between directories?
- Does a record of the file still exist even though the file is gone?

| NTFS Concept | Why It Matters in IR |
|---|---|
| **File record** | Represents a file or directory in NTFS metadata — the fundamental unit of the MFT |
| **Attributes** | Store information about the file: timestamps, names, data references, security descriptors |
| **Directories** | Provide the parent-child path structure that tells you *where* a file lived |
| **Allocation state** | Tells you whether a file record is active (in use) or deleted (unallocated) |
| **Timestamps** | Help place file activity in time — but must be interpreted carefully |
| **Internal identifiers** | Allow tools to correlate records across artifact sources |

> **IR Reality Check:** An attacker may delete a tool, rename a payload, or move files between directories, but NTFS metadata often keeps parts of that history available long after the obvious trace is gone. Understanding the structure is what lets you find it.

---

## Lab Tasks

---

### Task 1 — Define NTFS in Your Own Words

**Objective:** Build a practical, responder-focused understanding of NTFS before touching any tools.

**Part A — Written definition**

Write a 4–6 sentence explanation of NTFS. Write it as if you were explaining it to a new team member who understands Windows administration but has never done forensic analysis. Your explanation should address:

- What NTFS is
- What it stores beyond file content
- Why it matters in forensic investigations
- Why a responder would care even if the original file is missing

```
[Your explanation here]
```

**Part B — Short answers**

Answer each in 1–2 sentences:

**1. Why is NTFS more useful to a responder than a simple folder listing?**

```
[Your response here]
```

**2. Why is file system metadata often as important as file contents?**

```
[Your response here]
```

**3. Why can NTFS still matter after an attacker has run cleanup?**

```
[Your response here]
```

---

### Task 2 — Separate File Content from File System Metadata

**Objective:** Practice the distinction between what a file *contains* and what NTFS *records about* it.

This distinction matters throughout Chapter 4. Metadata answers many forensic questions even when file content is unavailable, encrypted, deleted, or irrelevant.

**Part A — Classification table**

Classify each item as **File Content**, **File System Metadata**, or **Either / Depends**. Explain your reasoning.

| Item | Classification | Why |
|---|---|---|
| The text inside a `.ps1` script | | |
| A file's created timestamp | | |
| The path `C:\Users\Alice\Downloads\tool.exe` | | |
| The raw bytes of a DLL | | |
| Whether a file record is allocated or deleted | | |
| The parent directory relationship | | |
| An Office document's internal author name embedded in the file | | |
| A file's last-modified time stored in the MFT | | |
| Command-line arguments passed at runtime | | |
| The file extension `.exe` | | |

**Part B — Add five of your own**

Add five more examples and classify them.

| Item | Classification | Why |
|---|---|---|
| | | |
| | | |
| | | |
| | | |
| | | |

---

### Task 3 — Define Core NTFS Concepts

**Objective:** Connect NTFS terminology to practical IR meaning before working with actual artifact data.

For each term, write a plain-language definition and explain why it matters during an investigation.

| NTFS Term | Plain-Language Meaning | Why It Matters in IR |
|---|---|---|
| **File record** | | |
| **Attribute** | | |
| **Directory** | | |
| **Allocation state** | | |
| **Timestamp** | | |
| **Parent-child path relationship** | | |
| **Deleted record** | | |
| **Metadata** | | |

**Short answers:**

**1. Why is a deleted record still forensically important?**

```
[Your response here]
```

**2. Why do investigators care about parent directories, not just file names?**

```
[Your response here]
```

**3. Why is the concept of "attribute" more useful than thinking only in terms of "the file"?**

```
[Your response here]
```

---

### Task 4 — What Can NTFS Answer?

**Objective:** Map NTFS capabilities and limits to real IR investigative questions.

For each investigative question below, rate whether NTFS is **Strongly useful**, **Partially useful**, or **Not very useful**, and explain why.

| Investigative Question | NTFS Value | Why |
|---|---|---|
| Did a suspicious file exist on disk? | | |
| Where was the file located in the directory tree? | | |
| Was the file likely executed? | | |
| Was the file later deleted? | | |
| Was a suspicious directory created during the incident window? | | |
| What exact command line launched the file? | | |
| Was a file renamed or moved between directories? | | |
| Was a tool staged in a user-writable location? | | |
| Did the attacker authenticate via RDP? | | |
| Did malware inject into another process only in memory? | | |

**Add three investigative questions of your own:**

| Your Question | NTFS Value | Why |
|---|---|---|
| | | |
| | | |
| | | |

**Short answer:**

*Where does NTFS consistently fall short, and what other artifact types fill those gaps?*

```
[Your response here — 2 to 3 sentences]
```

---

### Task 5 — Allocated vs. Deleted: Why the Difference Matters

**Objective:** Understand why allocation state is one of the most practically important NTFS concepts in IR.

**Part A — Written explanation**

Write 3–4 sentences explaining the difference between an allocated and a deleted NTFS record. Include what "deleted" actually means at the file system level: why the record often still exists, and what determines how long it survives.

```
[Your explanation here]
```

**Part B — Short answers**

**1. Why can a deleted file record still be valuable to an investigation?**

```
[Your response here]
```

**2. Why is a deleted malicious tool sometimes *more* interesting than one that's still present?**

```
[Your response here]
```

**3. Why should you never assume that "deleted" means "irrelevant"?**

```
[Your response here]
```

**Part C — Allocation state scenarios**

| Situation | Why Allocation State Matters Here |
|---|---|
| Suspicious `.exe` found in Downloads — still present and allocated | |
| Suspicious `.exe` found in `C:\Temp` — marked deleted in MFT | |
| Deleted ZIP archive found in a user profile directory | |
| Deleted batch script in `C:\ProgramData` | |
| Deleted directory used briefly — no longer listed in file system | |
| Allocated file with a benign name in an unusual path | |

---

### Task 6 — Build a Simple NTFS-Centered Case Theory

**Objective:** Practice using NTFS concepts to reason about a file-based incident before any tools are run.

**Known facts from WKSTN-144:**

- A file named `adobe_update.exe` was reportedly seen under `C:\Users\j.smith\Downloads\`
- A file named `runme.bat` may have existed under `C:\ProgramData\`
- Neither file is currently present in the live file listing
- You do not yet have proof of execution
- You want to know what NTFS analysis might still reveal

**Part A — NTFS questions to ask first**

Write at least six specific NTFS-based investigative questions for this scenario.

| Question | What NTFS Might Help Show |
|---|---|
| | |
| | |
| | |
| | |
| | |
| | |

**Part B — Short answers**

**1. What would you hope to learn from file records alone — without any other artifact type?**

```
[Your response here]
```

**2. What could NTFS suggest but not prove in this scenario?**

```
[Your response here]
```

**3. What artifact types outside NTFS would you want next to strengthen the case, and specifically why?**

```
[Your response here]
```

---

### Task 7 — Write a Short Analyst Note

**Objective:** Communicate the value of NTFS analysis clearly in a case note a teammate could act on.

Write a 1–2 paragraph analyst note explaining to another responder why NTFS analysis should be part of the next phase of work on WKSTN-144. Write it as if it were being added to the investigation notes right now.

Your note should cover:

- Why NTFS is relevant to the specific facts of this case
- What kinds of answers it may provide
- What its limitations are given what you know so far
- Why it should be correlated with other artifacts rather than treated as standalone evidence

```
[Your analyst note here]
```

---

### Task 8 — Reflection

Answer the following in 3–5 sentences each:

**1. Why file systems matter in IR**
Why is file system knowledge important even for responders who are not full-time forensic examiners?

```
[Your response here]
```

**2. Metadata as evidence**
Why can file system metadata be useful even when the underlying file content is missing, encrypted, or irrelevant?

```
[Your response here]
```

**3. The limits of NTFS alone**
Why should NTFS findings usually be treated as one part of the story rather than the entire story?

```
[Your response here]
```

**4. Deleted does not mean invisible**
Why is it dangerous for attackers to assume that deleting a file removes all meaningful evidence of it?

```
[Your response here]
```

---

## Deliverables Checklist

Your `lab04.1-notes.md` should contain:

- [ ] **Task 1** — Written NTFS definition and three short answers
- [ ] **Task 2** — Classification table completed with five additional examples
- [ ] **Task 3** — Core concept definitions and three short answers
- [ ] **Task 4** — NTFS usefulness ratings for all ten questions, three additional questions, and short answer
- [ ] **Task 5** — Written explanation, three short answers, and allocation state scenario table
- [ ] **Task 6** — NTFS question table with at least six entries and three short answers
- [ ] **Task 7** — Analyst note (1–2 paragraphs)
- [ ] **Task 8** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab04/
├── lab04-notes.md    ← Your working notes file (whole lab)
└── Lab04_01/
    ├── ReadMe.md         ← This file
    └── lab04.1-notes.md  ← Your working notes file
```

---

## Key Takeaways

- **NTFS is more than file storage.** It is a structured metadata system that preserves information responders can use long after obvious traces are gone.
- **Metadata answers real forensic questions.** File existence, path, timestamps, directory relationships, and deletion state all matter, often more than the file content itself.
- **Deleted is still useful.** A missing file may still have a meaningful record in the MFT and USN Journal.
- **NTFS has clear strengths and clear limits.** It is excellent for file-based questions, but weak for runtime, network, and behavioral questions without corroborating artifacts.
- **Understanding NTFS makes later analysis stronger.** The deeper artifact work in Labs 4.2 through 4.5 makes much more sense once the underlying structure is clear.

---

**Next:** Lab 4.2 — The Master File Table (MFT)

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
