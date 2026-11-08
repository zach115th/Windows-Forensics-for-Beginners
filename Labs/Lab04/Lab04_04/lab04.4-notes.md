# Lab 4.4 — Analyst Notes
**Tools for NTFS Artifact Analysis**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________
**Date Started:** ___________________________
**Date Completed:** ___________________________
**Lab Environment:** ___________________________
**Case Reference:** IR-2024-WKSTN221

---

## Task 1 — Map the Tool Landscape

> Complete the table for each tool. Add at least one tool of your own that you have used or want to learn.

| Tool | Primary Use | Output Format | When to Reach for It | When Not To |
|---|---|---|---|---|
| `MFTECmd` | | | | |
| `AnalyzeMFT.py` | | | | |
| Autopsy | | | | |
| The Sleuth Kit (`fls`, `mmls`, `icat`) | | | | |
| FTK Imager (verification / preview) | | | | |
| | | | | |

**Short answers:**

**1. Why is no single tool a complete answer for NTFS analysis?**

```
[Your response here]
```

**2. What does `MFTECmd` give you that `AnalyzeMFT.py` does not, and vice versa?**

```
[Your response here]
```

---

## Task 2 — Read and Interpret Sample Tool Output

> Pick three rows from a real or simulated `MFTECmd` CSV (e.g., `Data/WKSTN-221/mft.csv`).
> For each row, identify what it tells you and what it does not.

| File / Path | $SI Created | $FN Created | InUse | What This Row Tells You | What It Does Not Tell You |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |
| | | | | | |

**Short answers:**

**1. Why does the same MFT row often need to be read alongside other tool output?**

```
[Your response here]
```

**2. What "tool output" alone almost never proves on its own?**

```
[Your response here]
```

---

## Task 3 — Select Tools for the WKSTN-221 Investigation

> Justify your tooling choice for the WKSTN-221 scenario using the matrix below.

| Tool | Use For | Why This Tool | Output Goes To | Tradeoffs Accepted |
|---|---|---|---|---|
| MFT parser | | | | |
| USN Journal parser | | | | |
| File-system browser | | | | |
| Hash / verify | | | | |
| Timeline merge | | | | |

---

## Task 4 — Build a Repeatable Analysis Workflow

> Five to seven numbered steps another responder could follow without you in the room.

```
1.
2.
3.
4.
5.
6.
7.
```

**Short answers:**

**1. Which step in this workflow is most often skipped under time pressure, and what is the cost of skipping it?**

```
[Your response here]
```

**2. Why does writing the workflow down — even for a "quick" investigation — pay off?**

```
[Your response here]
```

---

## Task 5 — Document Tool Use Correctly

> For each parse you perform, capture the fields below.

```
Tool name and version:
Source file (`$MFT`, `$J`, etc.) with hash:
Exact command used:
Working directory:
Output location with hash:
Date/time of run (UTC):
Errors / warnings:
Notes (any deviation from default flags):
```

**Short answer:**

**1. Why does recording the exact command matter beyond just naming the tool?**

```
[Your response here]
```

---

## Task 6 — Validate and Cross-Check Findings

> Take one MFT-derived finding from the lab and run it through three independent checks.

| Check | What You Did | Result | Confirms or Challenges |
|---|---|---|---|
| Independent parser | | | |
| Different artifact source | | | |
| Hash / integrity verification | | | |

**Short answer:**

**1. What is the single biggest risk of trusting one tool's output without an independent check?**

```
[Your response here]
```

---

## Task 7 — Design an Output Folder Structure

> Sketch a folder layout for the case work product. Mark each folder's purpose.

```
[Case ID]\
├── 00_Admin\          ← chain of custody, authorization, case notes
├── 01_Acquisition\    ← original artifacts + hashes
├── 02_Working_Copy\   ← verified copies for analysis
├── 03_Analysis\       ←
├── 04_Findings\       ←
└── 05_Reports\        ←
```

**Short answer:**

**1. Why does a consistent folder structure across cases save time at the worst possible moment?**

```
[Your response here]
```

---

## Task 8 — Tool Output vs. Analyst Conclusion

> Write the one-paragraph distinction in your own words.

```
[Your response here]
```

**Short answers:**

**1. Give a specific example of an MFT-derived "fact" that, on closer reading, is actually a tool-derived inference.**

```
[Your response here]
```

**2. How do you make sure your reports do not conflate the two?**

```
[Your response here]
```

---

## Task 9 — Write a Tooling Decision Note

> A short memo (2–4 paragraphs) suitable for a case file. Cover: which tools you used, why, what their limits are, and how the choice will be defensible if reviewed later.

```
# Tooling Decision Note — IR-2024-WKSTN221

[Paragraph 1 — what you used]


[Paragraph 2 — why these tools were the right choice for this case]


[Paragraph 3 — what they cannot prove alone, and how that is mitigated]


[Paragraph 4 — what would change the choice for the next case]
```

---

## Task 10 — Reflection

**1. The tool versus the analyst**
*Why is forensic analysis fundamentally about the analyst, not the tool? Where is the line?*

```
[Your response here]
```

---

**2. The tradeoff between speed and depth**
*When should you reach for a quick triage tool, and when does deeper parsing pay off? Give a concrete example for each.*

```
[Your response here]
```

---

**3. The "I checked the MFT" trap**
*Why is "I checked the MFT" rarely sufficient as a finding statement, and what should replace it?*

```
[Your response here]
```

---

**4. Building your own toolkit over time**
*What is one tool you used in this lab that you want to learn more deeply, and what is one you want to add to your kit but haven't yet?*

```
[Your response here]
```

---

## Additional Notes

> Free text — questions, observations, parsing errors, version-specific behavior worth recording.

[Your notes here]

---

*Lab 4.4 Notes — Windows Forensics for Beginners*
*Keep this file in your `Labs/Lab04/Lab04_04/` folder alongside the `ReadMe.md`.*
