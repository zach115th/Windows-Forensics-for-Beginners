# Lab 4.2 — Analyst Notes
**The Master File Table (MFT)**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Lab Environment:** ___________________________  
**Case Reference:** IR-2024-WKSTN221  

---

## Task 1 — MFT Scope and Limits

**Part A — Written explanation**

> 4–6 sentences. Cover: what the MFT is, what it stores, why it is useful in IR,
> what it answers well, and what it cannot answer alone.
[Your explanation here]
---

**Part B — Usefulness ratings**

> Ratings: Strongly useful / Partially useful / Not very useful

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

---

**Part C — Short answer**

*Where does the MFT consistently fall short, and what artifact types pick up where it stops?*
[Your response here — 2 to 3 sentences]
---

## Task 2 — Interesting MFT Entry Characteristics

**Part A — Characteristics table**

> First 5 rows provided. Add at least 5 more of your own.

| Characteristic | Why It Matters in IR | Example |
|---|---|---|
| Executable in a user-writable directory | Standard users should not install executables; common staging path | `C:\Users\<user>\Downloads\update.exe` |
| Deleted batch script | Scripts deleted after use suggest intentional cleanup | Deleted `.bat` in `C:\ProgramData\` |
| Recently created archive | Compression often precedes exfiltration or tool extraction | `.7z` created in `C:\Temp\` during incident window |
| File under `C:\ProgramData\` | Writable by standard users; often missed by shallow analysis | Persistence binary placed here to survive reboots |
| Suspicious file name | Names mimicking system files are a common masking technique | `svchost32.exe`, `AdobeUpdate.exe` |
| | | |
| | | |
| | | |
| | | |
| | | |

---

**Part B — Short answers**

**1. Why should a responder focus on context, not just file extension?**
[Your response here]
---

**2. Why can a benign-looking file name still be suspicious?**
[Your response here]
---

**3. Why might a deleted file record be more valuable than an allocated one?**
[Your response here]
---


## Task 3 — MFT Parsing and Candidate Records

**Part A — Parsing notes**

```
Tool used:
Tool version:
Command run:
Input file / source:
Output location:
Date/time (UTC):
Notes:
```

**Exact command used:**

```powershell
[Paste exact command here]
```

---

**Part B — Candidate records table**

> At least 5 entries. If no dataset is available, describe exact filters and create
> representative hypothetical entries based on the WKSTN-221 scenario.

| File or Directory | Full Path | Record Type | Allocated / Deleted | Why It Stands Out | Notes |
|---|---|---|---|---|---|
| `svc_updater.exe` | `C:\Temp\svc_updater.exe` | File | Deleted | Matches Prefetch entry; no longer on disk | High priority for USN Journal follow-up |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |

---

**Part C — Filters applied**

```
Extension filter:
Path filter:
Allocation filter:
Time range filter:
Other filters:
```

---

## Task 4 — MFT Metadata Interpretation

**Part A — Metadata table**

> Three entries from Task 3. Document core metadata and record observations.

| File / Directory | Full Path | Created ($SI) | Modified ($SI) | Changed ($SI) | Accessed ($SI) | Allocated / Deleted | Observations |
|---|---|---|---|---|---|---|---|
| | | | | | | | |
| | | | | | | | |
| | | | | | | | |

---

**Part B — Short answers**

**1. Why is the file path important — not just the file name?**
[Your response here]
---

**2. Why do responders care about allocation state when reviewing suspicious records?**
[Your response here]
---

**3. Why can clustered creation timestamps across multiple suspicious files matter?**
[Your response here]
---

**4. Why should you avoid drawing conclusions from a single MFT field in isolation?**
[Your response here]
---

## Task 5 — Deleted and Short-Lived Artifacts

**Part A — Deleted artifact scenario table**

| Scenario | What the MFT Might Still Show | Why That Helps the Investigation |
|---|---|---|
| Suspicious `.exe` deleted from `C:\Downloads\` | | |
| Batch script deleted from `C:\ProgramData\` | | |
| Archive removed after extraction | | |
| Temporary staging directory created and removed | | |
| Deleted DLL in a writable system path | | |
| Deleted `.ps1` script in `AppData\Local\Temp\` | | |

---

**Part B — Short answers**

**1. Why does deletion increase the investigative value of the file system record?**
[Your response here]
---

**2. Why is a deleted attacker tool often a strong lead even without the file content?**
[Your response here]
---

**3. What limitations remain if a deleted MFT record exists but file content is gone?**
[Your response here]
---

## Task 6 — MFT-Centered Mini-Timeline

**Part A — Timeline table**

> At least 6 entries. Every entry must reference a specific MFT field or finding.
> Confidence: High (two or more sources agree) / Medium (single reliable source) /
> Low (indirect or ambiguous).

| Time (UTC) | MFT Field / Source | Event | File / Path | Significance | Confidence |
|---|---|---|---|---|---|
| | `Created0x10` | File created | | | |
| | `Created0x30` | `$FN` creation timestamp | | | |
| | Allocation state — deleted | Deleted record identified | | | |
| | `LastModified0x10` | File content modified | | | |
| | Directory record | New directory created | | | |
| | Deleted record cluster | Multiple files deleted near same time | | | |

---

**Part B — Short answers**

**1. Why is an ordered timeline more useful than a list of individual suspicious MFT records?**
[Your response here]
---

**2. What would you want to correlate outside the MFT to strengthen these timeline entries?**
[Your response here]
---

**3. Which artifact types from earlier labs pair most directly with MFT timeline entries?**
[Your response here]
---

## Task 7 — Supported vs. Unsupported Claims

**Part A — Rating table**

> Ratings: Supported by MFT alone / Possibly suggested — needs corroboration /
> Not supported by MFT alone.

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

---

**Part B — Three additional statements**

> Write three statements of your own and rate them on the same scale.

| Statement | Rating | Why |
|---|---|---|
| | | |
| | | |
| | | |

---

**Part C — Short answer**

*Why is "possibly suggested — needs corroboration" more useful than forcing findings into proven or unproven?*
[Your response here — 2 to 3 sentences]
---

## Task 8 — MFT Findings Summary

> 2–4 paragraphs. Working-note entry — not a final incident conclusion.
> Cover: suspicious files identified, allocation state and timing, what the MFT supports
> with confidence, and what still requires corroboration.

[Paragraph 1 — suspicious files and directories identified]

[Paragraph 2 — allocation state, timing, and path context]

[Paragraph 3 — what the MFT supports with confidence]

[Paragraph 4 — limitations and what corroboration is needed]
---

## Task 9 — Reflection

**1. Why the MFT is foundational**
*Why is the MFT often one of the first file system artifacts responders review?*
[Your response here]
---

**2. Deleted does not mean unknowable**
*Why can the MFT still provide value even when the suspicious file is completely gone?*
[Your response here]
---

**3. Context over raw fields**
*Why is a file's path, surrounding directory structure, and timing often more important than file name alone?*
[Your response here]
---

**4. Correlation is still necessary**
*Why should MFT findings be paired with Prefetch, event logs, registry data, or the USN Journal before drawing firm conclusions?*
[Your response here]
---

## Additional Notes
[Free text — questions, observations, connections to real work,
tool behavior, parsing errors, things to follow up on]
---

*Lab 4.2 Notes — Windows Forensics for Beginners*  
*Keep this file in your `Labs/Lab04/Lab04_02/` folder alongside the `ReadMe.md`.*
