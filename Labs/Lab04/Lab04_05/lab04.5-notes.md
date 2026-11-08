# Lab 4.5 — Analyst Notes
**Correlating NTFS Artifacts in IR**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________
**Date Started:** ___________________________
**Date Completed:** ___________________________
**Lab Environment:** ___________________________
**Case Reference:** IR-2024-WKSTN221

---

## Task 1 — Inventory the Dataset and Identify What Is Suspicious

> Pull at least eight rows from the MFT or simulated dataset (`Data/WKSTN-221/mft.csv`).
> Mark each as **Strongly suspicious**, **Worth checking**, **Background**, or **Likely benign**.

| File / Path | InUse | $SI Created | $FN Created | Why It Looks This Way | Bucket |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |

**Short answers:**

**1. What did you weight most heavily when assigning your buckets?**

```
[Your response here]
```

**2. Which background files looked suspicious until you understood them in context?**

```
[Your response here]
```

---

## Task 2 — Correlate MFT and USN Journal Evidence for Three Files

> Pick three files from your Task 1 inventory. For each, use both the MFT row and the USN Journal entries (`Data/WKSTN-221/usn-journal.csv`) to reconstruct the file's full lifecycle.

| File | $SI Created | $FN Created | USN First Reason | USN Last Reason | Time of Last USN Event | What This Tells You |
|---|---|---|---|---|---|---|
| | | | | | | |
| | | | | | | |
| | | | | | | |

**Short answers:**

**1. What does the USN Journal tell you that the MFT row alone does not?**

```
[Your response here]
```

**2. For one of the three files, what would you not know without the journal?**

```
[Your response here]
```

---

## Task 3 — Build a Chronological Activity Sequence

> Merge MFT and USN entries for your three files into a single time-sorted view.
> Annotate each row with a one-line interpretation.

| Time (UTC) | Source | File | Event | What It Means in This Story |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

**Short answer:**

**1. Where in your sequence did the story get tighter — i.e., where did two artifacts independently confirm the same moment?**

```
[Your response here]
```

---

## Task 4 — Evaluate Competing Interpretations

> For one of your three files, list at least two plausible interpretations of the activity and what evidence would distinguish them.

| Interpretation | Supporting Evidence | Distinguishing Evidence Needed |
|---|---|---|
| 1. | | |
| 2. | | |
| 3. *(optional)* | | |

**Short answer:**

**1. Why is the discipline of writing down competing interpretations more useful than picking one and moving on?**

```
[Your response here]
```

---

## Task 5 — Separate What NTFS Strongly Supports from What Needs More

> Group your findings by evidentiary weight.

| Strongly Supported by NTFS Alone | Suggested but Not Confirmed | Cannot Be Determined from NTFS |
|---|---|---|
| | | |
| | | |
| | | |

**Short answer:**

**1. Why is the third column ("Cannot be determined from NTFS") often the most professionally important to surface in a finding?**

```
[Your response here]
```

---

## Task 6 — Identify the Best Next Artifacts to Check

> For each item in your "Suggested but not confirmed" column, name the next artifact source most likely to confirm or refute it.

| Suggested Finding | Next Artifact | What You Expect to See if Correct |
|---|---|---|
| | | |
| | | |
| | | |
| | | |

**Short answer:**

**1. Why is the *next-step* discipline more useful than trying to extract more from the current artifact?**

```
[Your response here]
```

---

## Task 7 — Write an NTFS Correlation Summary

> 3–4 paragraphs suitable for a case working notes file.
> Cover: what NTFS strongly supports, what it suggests, what it cannot determine, and what you would do next.

```
[Paragraph 1 — what NTFS strongly supports about this incident]


[Paragraph 2 — what it suggests but does not confirm]


[Paragraph 3 — what it cannot determine, and why those limits matter]


[Paragraph 4 — recommended next steps and which artifacts they require]
```

---

## Task 8 — Write an Analyst Handoff Note

> Write the handoff note as if a colleague will pick up the case on the next shift.
> Keep it under one page.

```
# Analyst Handoff — WKSTN-221 NTFS Correlation
Outgoing analyst:
Incoming analyst:
Handoff time (UTC):

## What I have done

-
-
-

## Strongest NTFS findings

-
-

## Open questions / what I had not yet resolved

-
-

## Recommended next steps

-
-

## Tools and outputs

| Tool | Version | Output Path | Hash |
|---|---|---|---|
| | | | |
| | | | |
```

---

## Task 9 — Correlation Practice: Two Scenarios

**Scenario A — Timestomp candidate**
*A `update.exe` in the user's `Temp\` directory has a `$SI Created` of 2023-11-14 03:00:00 but a `$FN Created` of 2024-11-14 14:20:11. The USN Journal shows the file's first appearance in the journal at 14:20:11. What is the most defensible reading of these timestamps, and what would you say in a finding?*

```
[Your response here]
```

---

**Scenario B — Burst staging followed by deletion**
*The MFT shows seven new files appearing in `C:\Users\<user>\Downloads\` between 14:18:00 and 14:18:30 UTC, all with similar names suggesting an archive split. The USN Journal shows all seven files deleted between 14:23:00 and 14:23:15 UTC. What is the most defensible reading of these timestamps, and what artifacts would you check next to test it?*

```
[Your response here]
```

---

## Task 10 — Reflection

**1. Correlation as a discipline**
*Why is "I correlated the artifacts" not a finding? What turns correlation into a defensible conclusion?*

```
[Your response here]
```

---

**2. The value of restraint**
*Why is naming what NTFS *cannot* tell you often more professional than confidently stating what it can?*

```
[Your response here]
```

---

**3. The next-source instinct**
*Where do you find yourself reaching for the next artifact source most naturally — Prefetch, registry, logs, memory? Why?*

```
[Your response here]
```

---

**4. Habits that survive a bad day**
*Of the eight tasks above, which one will you keep doing in real cases when you are tired, under pressure, or working alone?*

```
[Your response here]
```

---

## Additional Notes

> Free text — questions, observations, edge cases, things to revisit.

[Your notes here]

---

*Lab 4.5 Notes — Windows Forensics for Beginners*
*Keep this file in your `Labs/Lab04/Lab04_05/` folder alongside the `ReadMe.md`.*
