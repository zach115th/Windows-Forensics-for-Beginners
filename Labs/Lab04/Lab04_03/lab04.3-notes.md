# Lab 4.3 — Analyst Notes
**USN Journal**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Lab Environment:** ___________________________  
**Case Reference:** IR-2024-WKSTN221  

---

## Task 1 — USN Journal Scope and Limits

**Part A — Written explanation**

> 4–6 sentences. Cover: what the USN Journal is, what activity it records,
> why it matters in IR, how it differs from the MFT, and what it cannot prove alone.
[Your explanation here]
---

**Part B — Usefulness ratings**

> Ratings: Strongly useful / Partially useful / Not very useful

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

---

**Part C — Short answer**

*How does the USN Journal complement the MFT rather than duplicate it?*
[Your response here — 2 to 3 sentences]
---

## Task 2 — USN Activity Patterns Worth Attention

**Part A — Activity pattern table**

> First 5 rows provided. Add at least 5 more of your own.

| USN Activity Pattern | Why It Matters | Example |
|---|---|---|
| File created in `Downloads` | Common attacker delivery path; unexpected executables here are a priority | `FILE_CREATE` for `update.exe` in user Downloads |
| File renamed shortly after creation | Attackers rename tools to blend in or evade file-name-based detection | `RENAME_OLD_NAME: payload.exe` → `RENAME_NEW_NAME: svchost32.exe` |
| File deleted from `C:\Temp\` during activity window | Short-lived files suggest intentional cleanup after use | `FILE_DELETE` for executable with no prior execution artifacts |
| Burst of changes in a user-writable directory | Rapid sequential activity suggests extraction, staging, or deployment | Multiple `FILE_CREATE` records in `C:\ProgramData\` within seconds |
| Directory created and then deleted | Short-lived staging directory is a common attacker pattern | `FILE_CREATE` then `FILE_DELETE` for same directory within minutes |
| | | |
| | | |
| | | |
| | | |
| | | |

---

**Part B — Short answers**

**1. Why is rename activity often more forensically interesting than it first appears?**
[Your response here]
---

**2. Why can a quick create-then-delete pattern be one of the most important sequences to find?**
[Your response here]
---

**3. Why should a responder care about clustered file changes in the same path even if each individual change looks minor?**
[Your response here]
---


## Task 3 — Candidate USN Records

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

| File or Directory | Path | Change Type (Reason Code) | Timestamp (UTC) | Why It Stands Out | Notes |
|---|---|---|---|---|---|
| `svc_updater.exe` | `C:\Temp\` | `FILE_CREATE`, `CLOSE`, `FILE_DELETE` | | Matches deleted MFT entry; full lifecycle visible | Correlate with Prefetch |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |

---

**Part C — Filters applied**

```
File type filter:
Path filter:
Reason code filter:
Time range filter:
Other filters:
```

---

## Task 4 — Interpreting Change Patterns

**Part A — Interpretation table**

> Three candidate items from Task 3. Document the activity sequence and your interpretation.

| File or Path | Journal Activity Seen | Most Likely Interpretation | What It Does Not Prove | Follow-Up Artifact |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

---

**Part B — Short answers**

**1. Why is "created then deleted" useful but still forensically incomplete on its own?**
[Your response here]
---

**2. Why does a rename event require path context and timing to be meaningful?**
[Your response here]
---

**3. Why should you avoid treating a USN entry as evidence of execution?**
[Your response here]
---

**4. What makes a sequence of USN records more defensible than a single record in isolation?**
[Your response here]
---

## Task 5 — Rename and Delete Sequence Reconstruction

**Part A — Reconstruction workflow**

| Step in Suspected Sequence | What You Would Look For in the USN Journal | Why It Helps |
|---|---|---|
| Initial file arrival | `FILE_CREATE` in a staging path during the incident window | Establishes when and where the file first appeared |
| Rename to new name | `RENAME_OLD_NAME` followed by `RENAME_NEW_NAME` — same file reference number | Shows the original name before masking |
| Possible path change | Parent path change between rename events | Indicates the file was moved to a different directory |
| Follow-on modification | `DATA_OVERWRITE` or `DATA_EXTEND` after rename | Suggests the file was written to after arrival |
| Deletion or cleanup | `FILE_DELETE` in the same path, near the same time window | Indicates intentional cleanup |

---

**Part B — Short answers**

**1. Why is the USN Journal especially valuable when the attacker changed the file name to something benign?**
[Your response here]
---

**2. Why is it important to correlate rename activity with time and path rather than name similarity alone?**
[Your response here]
---

**3. What evidence outside the USN Journal would most strengthen confidence you are tracking a single artifact chain?**
[Your response here]
---

## Task 6 — MFT and USN Correlation

**Part A — Correlation table**

> Two files or paths. Confidence: High (two or more sources agree) / Medium (single
> reliable source) / Low (indirect or ambiguous).

| File or Path | What the MFT Shows | What the USN Journal Shows | Combined Interpretation | Confidence |
|---|---|---|---|---|
| | | | | |
| | | | | |

---

**Part B — Short answer**

*Why does the combination of MFT and USN Journal produce stronger findings than either source alone?*
[Your response here — 2 to 3 sentences]
---

## Task 7 — USN-Centered Mini-Timeline

**Part A — Timeline table**

> At least 8 entries. Every entry must reference a specific artifact source and reason
> code or field. Confidence: High / Medium / Low.

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

---

**Part B — Short answers**

**1. Why is a sequence of journal activity more useful than isolated change records?**
[Your response here]
---

**2. What would you want to correlate next outside NTFS to strengthen these entries?**
[Your response here]
---

**3. Which artifact types from earlier labs pair most naturally with USN-based timeline entries?**
[Your response here]
---

## Task 8 — Supported vs. Unsupported Claims

**Part A — Rating table**

> Ratings: Supported by USN alone / Possibly suggested — needs corroboration /
> Not supported by USN alone.

| Statement | Rating | Why |
|---|---|---|
| A file named `adobe_update.exe` was created in `Downloads` during the incident window | | |
| `adobe_update.exe` was executed by the assigned user | | |
| A suspicious file was renamed after initial creation | | |
| The rename was performed to evade detection | | |
| A short-lived script existed in a writable path and was deleted during the incident window | | |
| The deleted script established persistence on the host | | |
| Multiple file changes occurred in the same directory within a two-minute window | | |
| The attacker intended to delete the files to conceal their activity | | |

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

*Why does overclaiming in forensic reporting damage an investigation more than acknowledged uncertainty does?*
[Your response here — 2 to 3 sentences]
---

## Task 9 — USN Journal Findings Summary

> 2–4 paragraphs. Working-note entry — not a final incident conclusion.
> Cover: suspicious change patterns, create/rename/delete sequences, what the journal
> supports with confidence, and what still requires corroboration.

[Paragraph 1 — suspicious change patterns identified]

[Paragraph 2 — create, rename, delete sequences and what they suggest]

[Paragraph 3 — what the journal supports with confidence]

[Paragraph 4 — limitations and what corroboration is needed]
---

## Task 10 — Reflection

**1. Why the USN Journal matters**
*Why is it especially valuable when the live file system no longer reflects the most interesting attacker activity?*
[Your response here]
---

**2. Change history versus file existence**
*How does the USN Journal complement the MFT? What does each provide that the other cannot?*
[Your response here]
---

**3. Rename and cleanup awareness**
*Why are rename and delete patterns often the most forensically significant activity types in staging investigations?*
[Your response here]
---

**4. Correlation over confidence**
*Why should responders avoid converting journal activity into stronger claims than the evidence supports? What goes wrong when they do?*
[Your response here]
---

## Additional Notes
[Free text — questions, observations, tool behavior, parsing errors,
connections to real work, things to follow up on]
---

*Lab 4.3 Notes — Windows Forensics for Beginners*  
*Keep this file in your `Labs/Lab04/Lab04_03/` folder alongside the `ReadMe.md`.*
