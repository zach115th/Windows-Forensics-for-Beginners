# Lab 04 — Analyst Notes
**Windows File System Forensics (NTFS)**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________
**Date Started:** ___________________________
**Date Completed:** ___________________________
**Lab Environment:** ___________________________
**Case Reference:** IR-2024-WKSTN221

---

## Task 1 — Suspicious File Locations

**Part A — High-value path table**

> Complete all provided rows. Add at least 4 more locations of your own.

| Location or Path | Why It Matters | Example Suspicious Use |
|---|---|---|
| `C:\Users\<user>\Downloads\` | Default browser download location; writable by user | Malicious document or dropper downloaded via phishing |
| `C:\Temp\` | Writable without elevation on many systems; used for staging | Attacker extracts toolset here after initial access |
| `C:\ProgramData\` | Writable by standard users; often overlooked in AV scope | Persistence mechanism installed to avoid user-profile artifacts |
| `C:\Users\<user>\AppData\Local\Temp\` | High-volume temp activity makes malicious files harder to spot | Dropper writes payload here before executing |
| `C:\Users\Public\` | Writable by all users; accessible across accounts | Staging location accessible to multiple compromised accounts |
| `C:\Windows\Temp\` | System temp; elevated access typically required but not always | Attacker with elevated access stages tools to blend with system activity |
| | | |
| | | |
| | | |
| | | |

---

**Part B — Short answers**

**1. Why do attackers often avoid obviously named malware folders — and what does that mean for your analysis?**

[Your response here]

---

**2. Why can a "normal-looking" file path still be suspicious in context? Give a specific example.**

[Your response here]

---

**3. How would your path prioritization differ between a user workstation and a domain controller?**

[Your response here]

---

## Task 2 — MFT Review

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

**Part B — Candidate file table**

> At least 5 entries. If no dataset is available, describe filters and create representative
> hypothetical entries based on the scenario.

| File Name | Full Path | $SI Created (UTC) | $FN Created (UTC) | Allocated / Deleted | Why It Stands Out |
|---|---|---|---|---|---|
| svc_updater.exe | `C:\Temp\svc_updater.exe` | | | Deleted | Matches Prefetch entry; no longer present on disk |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |

---

## Task 3 — $SI vs. $FN Timestamp Comparison

> Three files from Task 2 or representative hypothetical entries.
> Record all eight timestamp values and note any meaningful differences.

| File | $SI Created | $SI Modified | $SI Changed | $SI Accessed | $FN Created | $FN Modified | $FN Changed | $FN Accessed | Observations |
|---|---|---|---|---|---|---|---|---|---|
| | | | | | | | | | |
| | | | | | | | | | |
| | | | | | | | | | |

---

**Short answers**

**1. Why can differences between $SI and $FN timestamps matter in an investigation?**

[Your response here]

---

**2. What kinds of $SI/$FN mismatches would cause you to look more closely at a file?**

[Your response here]

---

**3. Why should you be careful about claiming "timestomping" based on timestamp differences alone?**

[Your response here]

---

**4. What legitimate activity could explain $SI/$FN discrepancies unrelated to attacker behavior?**

[Your response here]

---

## Task 4 — USN Journal Review

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

**Part B — USN findings table**

> Focus on records related to suspicious files or paths from Task 2.
> Look for `FILE_CREATE`, `FILE_DELETE`, `RENAME_OLD_NAME`, `RENAME_NEW_NAME`, `DATA_OVERWRITE`.

| File / Path | Change Type (Reason Code) | Timestamp (UTC) | Parent Path | Why It Matters | Notes |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |

---

**Part C — Short answers**

**1. What does the USN Journal tell you that the MFT alone may not make obvious?**

[Your response here]

---

**2. Why is rename activity particularly important in attacker tool staging investigations?**

[Your response here]

---

**3. How can deleted or short-lived files still leave useful NTFS evidence? What limits that visibility?**

[Your response here]

---

## Task 5 — MFT and USN Correlation

> Two files or paths. Stay within what the evidence supports.
> Confidence: High (two+ independent sources agree) / Medium (single reliable source) / Low (indirect or ambiguous)

| File or Path | What the MFT Shows | What the USN Journal Shows | Most Reasonable Interpretation | Confidence |
|---|---|---|---|---|
| | | | | |
| | | | | |

---

## Task 6 — File System Mini-Timeline

> At least 8 entries. Every entry must have a named artifact source.

| Time (UTC) | Artifact Source | Event Type | File / Path | Significance | Confidence |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |

---

**Short answers**

**1. Why is a timeline more useful than a list of isolated file records?**

[Your response here]

---

**2. What would you want to correlate next — outside NTFS — to strengthen your findings?**

[Your response here]

---

**3. Which artifact types from earlier chapters pair most naturally with this NTFS timeline?**

[Your response here]

---

## Task 7 — NTFS Findings Summary

> 2–4 paragraphs. Suitable for a case working notes file.
> Cover: suspicious locations, creation/rename/delete activity, timestamp patterns,
> supporting artifacts named specifically, and what cannot be concluded from file system data alone.

```
[Paragraph 1 — suspicious file locations and why they are notable]


[Paragraph 2 — creation, rename, deletion, and staging activity observed]


[Paragraph 3 — timestamp patterns and what they do or do not support]


[Paragraph 4 — limitations and what additional artifacts would close remaining gaps]
```

---

## Task 8 — Reflection

**1. Why the MFT matters in IR**
*Why is the MFT useful even when you already have EDR telemetry and event logs covering the same timeframe?*

[Your response here]

---

**2. Deleted does not mean gone**
*Why can deleted files still be forensically significant? What determines whether their records are recoverable?*

[Your response here]

---

**3. Metadata versus execution**
*Why should responders be careful not to conflate suspicious file metadata with proof of execution? What separate evidence is needed?*

[Your response here]

---

**4. Correlation over certainty**
*Why is NTFS analysis strongest when paired with other artifact types? Give a specific example using the WKSTN-221 scenario.*

[Your response here]

---

## Additional Notes

> Free text — questions, observations, connections to real work, things to follow up on,
> tool behavior notes, parsing errors encountered.

[Your notes here]

---

*Lab 04 Notes — Windows Forensics for Beginners*
*Keep this file in your `Labs/Lab04/` folder alongside the `ReadMe.md`.*
