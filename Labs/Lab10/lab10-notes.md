# Lab 10 — Analyst Notes
**Timeline Analysis**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Lab Environment:** ___________________________  
**Case Reference:** ___________________________  

---

## Task 1 — Explain Why Timelines Matter

> Write a short explanation in 4–6 sentences covering why timelines are useful in Windows incident response, why single artifacts are often weaker without temporal context, how timelines help create a coherent investigative story, and why timelines are useful for both analysis and reporting.

```
[Your explanation here]
```

**1. Why can a timeline make weak-looking artifacts more meaningful?**

```
[Your response here]
```

**2. Why is sequence often as important as the artifact itself?**

```
[Your response here]
```

**3. Why are timelines especially useful when multiple artifact types are involved?**

```
[Your response here]
```

---

## Task 2 — Distinguish Super Timelines from Targeted Timelines

| Timeline Type | What It Is | Best Use Case | Main Limitation |
|---|---|---|---|
| Super timeline | | | |
| Targeted timeline | | | |

**1. Why is a super timeline useful in larger or less-understood incidents?**

```
[Your response here]
```

**2. Why is a targeted timeline often the better first move when you already have a suspicious pivot?**

```
[Your response here]
```

**3. Why can a timeline that is too broad become hard to analyze effectively?**

```
[Your response here]
```

---

## Task 3 — Gather the Timeline Inputs

| Input Source | File Name / Location | What It Contributes | Notes |
|---|---|---|---|
| MFT CSV | | | |
| Event log export | | | |
| Prefetch output | | | |
| SRUM output | | | |
| | | | |
| | | | |

**1. Why is it useful to know what each source contributes before merging?**

```
[Your response here]
```

**2. Why should you not assume all artifact sources have equally trustworthy timestamps?**

```
[Your response here]
```

**3. Why is documenting input provenance important before building the timeline?**

```
[Your response here]
```

---

## Task 4 — Normalize Time

| Artifact Source | Original Time Basis | Normalized Time Basis | Adjustment Needed? | Notes |
|---|---|---|---|---|
| MFT CSV | | | | |
| Event logs | | | | |
| Prefetch output | | | | |
| SRUM output | | | | |
| | | | | |
| | | | | |

**1. Why is time normalization mandatory before meaningful timeline analysis?**

```
[Your response here]
```

**2. Why can time skew between hosts or sources create false narratives?**

```
[Your response here]
```

**3. Why should time uncertainty be documented rather than ignored?**

```
[Your response here]
```

---

## Task 5 — Merge the Sources into a Single Timeline CSV

| Field / Column | Why It Is Included |
|---|---|
| Timestamp | |
| Artifact Type | |
| Source Artifact | |
| Event Description | |
| Context Field(s) | |
| Notes | |

**1. Why is a common schema useful when merging different artifact sources?**

```
[Your response here]
```

**2. Why should event descriptions be concise instead of overly interpretive?**

```
[Your response here]
```

**3. Why is it helpful to preserve the originating artifact type in the merged timeline?**

```
[Your response here]
```

---

## Task 6 — Identify a Pivot Event

| Pivot Field | Value |
|---|---|
| Pivot Event Time (UTC) | |
| Artifact Source | |
| Event Description | |
| Why It Was Chosen | |

**1. Why is choosing the right pivot event important?**

```
[Your response here]
```

**2. Why should the pivot be specific and defensible rather than vague?**

```
[Your response here]
```

**3. Why can a strong pivot make the surrounding timeline much easier to interpret?**

```
[Your response here]
```

---

## Task 7 — Examine ±10–15 Minutes Around the Pivot

> Record at least twelve entries if possible. Use the empty CSV at `Labs/Lab10/timeline-template.csv` as your starting file — its headers match the table below.
> Confidence ratings: **HIGH** (≥2 independent sources agree) · **MEDIUM** (single reliable source) · **LOW** (indirect or single low-confidence source).

| Time (UTC) | Source Artifact | Event Description | Significance | Confidence | Notes |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |

**1. Which entries appear most central to the suspicious activity?**

```
[Your response here]
```

**2. Which entries are supportive but not central?**

```
[Your response here]
```

**3. Which entries may be noise or unrelated background activity?**

```
[Your response here]
```

---

## Task 8 — Identify Cross-Artifact Alignment

| Timeline Finding | Artifact Source 1 | Artifact Source 2 | Why the Alignment Matters |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |

**1. Why does cross-artifact alignment increase confidence?**

```
[Your response here]
```

**2. Why are isolated events often weaker than multi-source clusters?**

```
[Your response here]
```

**3. Why should you still be careful not to overstate alignment as proof of causation?**

```
[Your response here]
```

---

## Task 9 — Separate Strong Support from Overclaims

> Classify each statement as Strongly supported / Suggested but needs corroboration / Not supported by this timeline alone.

| Statement | Classification | Why |
|---|---|---|
| A suspicious event occurred at the pivot time | | |
| Multiple artifact sources align around the same suspicious window | | |
| The attacker definitely used PsExec at that exact moment | | |
| Activity clustered around the pivot deserves deeper review | | |
| The timeline supports a coherent sequence of suspicious behavior | | |
| The timeline alone proves attacker intent | | |
| A focused window can reveal more than reviewing artifacts separately | | |
| Every event in the window is incident-related | | |

**Six additional statements of your own:**

| Statement | Classification | Why |
|---|---|---|
| | | |
| | | |
| | | |
| | | |
| | | |
| | | |

---

## Task 10 — Write the Narrative Paragraph

> Write a single narrative paragraph describing what happened in the ±10–15 minute window around your pivot event. Use plain language, stay close to what the timeline supports, mention the most important aligned events, avoid unsupported conclusions, and read like something that could later be used in a case study or incident report.

```
[Your narrative paragraph here]
```

**1. Why is a narrative paragraph useful after building the timeline table?**

```
[Your response here]
```

**2. Why should the narrative stay faithful to the timeline instead of embellishing it?**

```
[Your response here]
```

**3. Why does plain language matter if the audience may later include non-specialists?**

```
[Your response here]
```

---

## Task 11 — Save and Package the Mini Timeline

```
Case-Timeline/
├── merged-timeline.csv
├── pivot-window.csv
├── timeline-notes.md
└── narrative-paragraph.md
```

| Item | Naming Convention | Example |
|---|---|---|
| Merged timeline | | |
| Pivot window export | | |
| Narrative paragraph file | | |
| Timeline notes | | |

**1. Why should the focused pivot-window extract be saved separately from the full merged timeline?**

```
[Your response here]
```

**2. Why is packaging important if the timeline will be reused later?**

```
[Your response here]
```

**3. Why should the narrative paragraph live alongside the timeline data and not only in chat notes or memory?**

```
[Your response here]
```

> **Optional — handing off to a multi-user platform:** If this case will move to a team platform (IRIS-NG, Timesketch, a shared SIEM dashboard), export your `pivot-window.csv` using the IRIS-NG header schema in `Labs/Lab10/timeline-template-iris.csv`, or note the field mapping (Time → `event_date` + `event_tz`, Source Artifact → `event_source`, Event Description → `event_title`, Notes → `event_content`, Significance → `event_tags`, Confidence → `event_color`). See Appendix D §D.14 for context.

---

## Task 12 — Write an Analyst Handoff Note

```
Case Reference:
Author:
Date/Time (UTC):

Timeline Inputs Used:
- 

Chosen Pivot Event:
- 

Most Important Timeline Findings:
- 

What Is Strongly Supported:
- 

What Is Suggested but Not Confirmed:
- 

Recommended Next Correlations:
1.
2.
3.

Notes for Incoming Analyst:
```

---

## Task 13 — Reflection

**1. Why timelines matter**
*Why is timeline analysis often one of the best ways to turn scattered artifacts into a coherent investigative story?*

```
[Your response here]
```

---

**2. Focus versus overload**
*Why can a targeted timeline be more useful than a massive super timeline in many cases?*

```
[Your response here]
```

---

**3. Correlation and caution**
*Why does temporal alignment strengthen findings while still requiring careful interpretation?*

```
[Your response here]
```

---

**4. Narrative value**
*Why is it important to convert a timeline window into plain-language narrative after the technical analysis is done?*

```
[Your response here]
```

---

## Additional Notes

> Use this space for anything that came up during the lab — questions, observations, connections to real incidents, things to follow up on, or ideas for improving your process.

```
[Free text]
```

---

*Lab 10 Notes — Windows Forensics for Beginners*
*Keep this file in your `Labs/Lab10/` folder alongside the `ReadMe.md`.*
