# Lab 3.2 — Analyst Notes
**Disk Imaging Basics in an IR Context**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________
**Date Started:** ___________________________
**Date Completed:** ___________________________
**Lab Environment:** ___________________________
**Case Reference:** IR-2024-APP12

---

## Task 1 — Full Imaging Decision for APP-12

**Part A — Decision summary**

| Host | Recommended Strategy | Primary Reason |
|---|---|---|
| APP-12 | | |

---

**Part B — Decision rationale**

**1. What factors increase the case for full imaging APP-12?**

[Your response here]

---

**2. What factors might argue for targeted triage instead?**

[Your response here]

---

**3. If you choose full imaging, would you still perform memory acquisition or targeted triage first? Why?**

[Your response here]

---

**4. How does the legal preservation request change your decision compared to a case with no legal involvement?**

[Your response here]

---

## Task 2 — Acquisition Documentation Requirements

**Part A — Acquisition record fields**

> Complete both columns. Why-it-matters must be answered for every field.

| Field | What Should Be Recorded | Why It Matters |
|---|---|---|
| Case reference | | |
| Hostname | | |
| Acquisition date/time (UTC) | | |
| Acquired by | | |
| Authorized by | | |
| Source device description | | |
| Source drive serial / identifier | | |
| Source interface (SATA, USB, NVMe) | | |
| Write blocker used | | |
| Imaging tool used | | |
| Tool version | | |
| Output format (E01, RAW, AFF4) | | |
| Destination storage path | | |
| Hash algorithm(s) used | | |
| Image file name(s) | | |
| Image file size | | |
| Hash value(s) | | |
| Errors or interruptions | | |
| Notes / observations | | |

---

**Part B — Short answers**

**1. Why does tool version matter for a forensic image?**

[Your response here]

---

**2. Why should source device identifiers be recorded before imaging begins?**

[Your response here]

---

**3. Why should acquisition notes explicitly include errors or interruptions?**

[Your response here]

---

## Task 3 — Step-by-Step Imaging Workflow

**Stage 1 — Pre-Acquisition Preparation**

> Write 6–8 steps covering what must be confirmed before imaging begins.

```
1. Confirm authorization — case reference, approving manager, written or verbal record
2. Confirm scope — which disk(s) on APP-12 are in scope; are secondary volumes included?
3.
4.
5.
6.
7.
8.
```

---

**Stage 2 — Source Disk Identification**

```
Steps:
  1.
  2.
  3.

Identifiers to record:
  -

Risk of imaging wrong drive and how to reduce it:

```

---

**Stage 3 — Imaging Execution**

| Step | Action | Notes |
|---|---|---|
| 1 | Launch imaging tool with administrator privileges | |
| 2 | Select source device — verify serial matches documentation | Do not proceed if serial cannot be confirmed |
| 3 | Set output path and file naming per Task 4 convention | |
| 4 | Configure hash algorithm (SHA-256 minimum) | |
| 5 | Configure output format | |
| 6 | Begin acquisition — record start time (UTC) | |
| 7 | Monitor for errors throughout | Document any interruptions immediately |
| 8 | Record completion time and tool-reported hash | |

**FTK Imager reference** *(if used):*

```
Source selected:
Image type:
Output path:
Evidence item info:     [completed / not completed]
Hash algorithm:         SHA-256
Verification enabled:   [Yes / No]
Notes:
```

---

**Stage 4 — Hash Verification**

```
When hashes should be calculated:

Which files should be hashed:

How results should be recorded:

Why verify independently of tool output:

```

**Hash verification command used:**

```powershell
[Paste exact command here]
```

---

**Stage 5 — Post-Acquisition Handling**

```
Storage location for original image:
Working copy created:                   [Yes / No]
Working copy location:
Original image write-protected:         [Yes / No — method used:]
Chain of custody updated:               [Yes / No]
Evidence handling record updated:       [Yes / No]
Next analysis action:
```

---

## Task 4 — Naming and Storage Standard

**Part A — Naming convention**

| Item | Proposed Naming Convention | Example |
|---|---|---|
| Primary image file | `[CaseID]_[Hostname]_[YYYYMMDD]_disk[N].[ext]` | `IR2024001_APP12_20241114_disk0.E01` |
| Segmented image set | | |
| Hash record | | |
| Acquisition note | | |
| Working copy | | |
| Memory image | | |

---

**Part B — Storage structure**

> Fill in the purpose of each folder. Add subfolders specific to APP-12 as needed.

```
IR-Cases\
└── IR-2024-APP12\
    ├── 00_Admin\
    │   ├── authorization.md
    │   ├── chain-of-custody.md
    │   └── case-open-note.md
    ├── 01_Acquisition\
    │   ├── Original_Image\     ← Purpose:
    │   ├── Hashes\             ← Purpose:
    │   └── Notes\              ← Purpose:
    ├── 02_Working_Copy\        ← Purpose:
    └── 03_Analysis\            ← Purpose:
```

**Additional subfolders needed for APP-12:**

[Your additions here]

---

## Task 5 — Hash a Sample Evidence File

**Part A — Command used**

```
[Paste exact command here]
```

---

**Part B — Hash record**

| Item | Value |
|---|---|
| **File Name** | |
| **File Path** | |
| **File Size** | |
| **SHA-256** | |
| **Date/Time Hashed (UTC)** | |
| **Hashed By** | |
| **Tool Used** | |
| **Tool Version** | |

**Raw tool output:**

```
[Paste exact output here]
```

---

**Part C — Short answers**

**1. Why does hashing matter before analysis begins, not just after?**

[Your response here]

---

**2. Why should the hash record be stored separately from the image file itself?**

[Your response here]

---

**3. What would you do if the working copy hash did not match the original?**

[Your response here]

---

## Task 6 — Acquisition Note

> Every field must be completed. If unknown at time of writing, note what is unknown and when it will be resolved.

```
# Disk Acquisition Note — APP-12
Case Reference:
Author:
Date/Time (UTC):

Host:                 APP-12
Reason for Imaging:
Authorized By:
Maintenance Window:   [Yes / No — start/end time if applicable:]

Source Disk:
  Description:
  Serial / ID:
  Interface:
  Size:

Imaging Tool:
Tool Version:
Output Format:
Output Location:
File Name(s):

Hash Algorithm:       SHA-256
Hash Value:
Verified:             [Yes / No]
Verification Method:

Errors / Notes:

Next Step:
```

---

## Task 7 — Reflection

**1. Imaging versus urgency**
*Why might a responder choose not to fully image a host even knowing it would preserve more evidence? When is that reasonable and when is it a mistake?*

[Your response here]

---

**2. Legal preservation versus operational practicality**
*How does a legal preservation request change the imaging discussion during an active incident? What obligations does it create?*

[Your response here]

---

**3. Trust through documentation**
*Why is a poorly documented image almost as problematic as not having one? What specific failures would most undermine trust?*

[Your response here]

---

**4. The danger of analyzing originals**
*Why should originals be preserved separately and working copies used for analysis? What could go wrong if this rule is skipped under time pressure?*

[Your response here]

---

## Additional Notes

> Free text — questions, observations, connections to real work, things to follow up on.

[Your notes here]

---

*Lab 3.2 Notes — Windows Forensics for Beginners*
*Keep this file in your `Labs/Lab03/Lab03_02/` folder alongside the `ReadMe.md`.*
