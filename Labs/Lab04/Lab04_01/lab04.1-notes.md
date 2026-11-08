# Lab 4.1 — Analyst Notes
**NTFS Overview**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Lab Environment:** ___________________________  
**Case Reference:** IR-2024-WKSTN144  

---

## Task 1 — NTFS Definition

**Part A — Written definition**

> 4–6 sentences. Written for a Windows admin who has never done forensic analysis.
> Cover: what NTFS is, what it stores beyond content, why it matters forensically,
> and why it matters even when the original file is missing.
[Your explanation here]
---

**Part B — Short answers**

**1. Why is NTFS more useful to a responder than a simple folder listing?**
[Your response here]
---

**2. Why is file system metadata often as important as file contents?**
[Your response here]
---

**3. Why can NTFS still matter after an attacker has run cleanup?**
[Your response here]
---

## Task 2 — File Content vs. File System Metadata

**Part A — Classification table**

> Classify each item as File Content / File System Metadata / Either / Depends.
> Explain your reasoning for each.

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

---

**Part B — Five additional examples**

| Item | Classification | Why |
|---|---|---|
| | | |
| | | |
| | | |
| | | |
| | | |

---

## Task 3 — Core NTFS Concepts

> Write a plain-language meaning and explain why it matters in an investigation.

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

---

**Short answers**

**1. Why is a deleted record still forensically important?**
[Your response here]
---

**2. Why do investigators care about parent directories, not just file names?**
[Your response here]
---

**3. Why is the concept of "attribute" more useful than thinking only in terms of "the file"?**
[Your response here]
---

## Task 4 — What Can NTFS Answer?

> Rate each question: Strongly useful / Partially useful / Not very useful.
> Explain why for each.

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

---

**Three additional questions of your own:**

| Your Question | NTFS Value | Why |
|---|---|---|
| | | |
| | | |
| | | |

---

**Short answer: Where does NTFS consistently fall short, and what other artifacts fill those gaps?**
[Your response here — 2 to 3 sentences]
---

## Task 5 — Allocated vs. Deleted

**Part A — Written explanation**

> 3–4 sentences. Explain the difference between allocated and deleted NTFS records.
> Include what "deleted" actually means at the file system level.
[Your explanation here]
---

**Part B — Short answers**

**1. Why can a deleted file record still be valuable to an investigation?**
[Your response here]
---

**2. Why is a deleted malicious tool sometimes more interesting than one still present?**
[Your response here]
---

**3. Why should you never assume that "deleted" means "irrelevant"?**
[Your response here]
---

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

## Task 6 — NTFS-Centered Case Theory

**Known facts:**
- `adobe_update.exe` reportedly seen under `C:\Users\j.smith\Downloads\` — no longer present
- `runme.bat` may have existed under `C:\ProgramData\` — no longer present
- No proof of execution yet
- You want to know what NTFS analysis might still reveal

---

**Part A — NTFS questions to ask first**

> At least 6 specific questions. Map each to what NTFS might help show.

| Question | What NTFS Might Help Show |
|---|---|
| | |
| | |
| | |
| | |
| | |
| | |

---

**Part B — Short answers**

**1. What would you hope to learn from file records alone — without any other artifact type?**
[Your response here]
---

**2. What could NTFS suggest but not prove in this scenario?**
[Your response here]
---

**3. What artifact types outside NTFS would you want next, and specifically why?**
[Your response here]
---

## Task 7 — Analyst Note

> 1–2 paragraphs. Written as a case note for a teammate.
> Cover: why NTFS is relevant to this case, what answers it may provide,
> what its limitations are, and why it should be correlated with other artifacts.
[Paragraph 1]
[Paragraph 2]
---

## Task 8 — Reflection

**1. Why file systems matter in IR**
*Why is file system knowledge important even for responders who are not full-time forensic examiners?*
[Your response here]
---

**2. Metadata as evidence**
*Why can file system metadata be useful even when the underlying file content is missing, encrypted, or irrelevant?*
[Your response here]
---

**3. The limits of NTFS alone**
*Why should NTFS findings usually be treated as one part of the story rather than the entire story?*
[Your response here]
---

**4. Deleted does not mean invisible**
*Why is it dangerous for attackers to assume that deleting a file removes all meaningful evidence of it?*
[Your response here]
---

## Additional Notes
[Free text — questions, observations, connections to real work,
things to follow up on, concepts that need more review]
---

*Lab 4.1 Notes — Windows Forensics for Beginners*  
*Keep this file in your `Labs/Lab04/Lab04_01/` folder alongside the `ReadMe.md`.*
