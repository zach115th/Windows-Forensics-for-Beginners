# Lab 10 — Timeline Analysis

**Supporting [Chapter 10: Timeline Analysis](../../Book/Chapter10.md)**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Individual artifacts tell you far more once they stop being isolated facts and become part of a sequence.

A suspicious logon matters more when you can place it next to a process launch. A Prefetch entry matters more when it lines up with a network connection. An MFT record matters more when it fits into the same time window as a PowerShell event, a scheduled task, or a file transfer. That is what timeline analysis gives you: a way to align disparate artifact sources into a coherent story.

This lab introduces practical timeline analysis for Windows incident response. You will gather partial artifacts, normalize timestamps, merge them into a single working timeline, identify a pivot event, and examine the surrounding activity to build a focused narrative of what happened. The goal is not the biggest timeline possible. It is a timeline that helps you reason clearly about attacker behavior.

By the end of this lab, you should be comfortable taking artifacts from different parts of an investigation and turning them into a usable incident sequence.

---

## What This Lab Covers

This lab supports the following sections from Chapter 10:

| Section | Topic |
|---|---|
| 10.1 | Why Timelines? |
| 10.2 | Types of Timelines |
| 10.3 | Common Tools |
| 10.4 | Building a Mini Incident Timeline |
| 10.5 | Timestamp Reliability: Which Sources Lie, and How |
| 10.6 | Timezone Normalization in Practice |
| 10.7 | Confidence Annotation as a Method |
| 10.8 | Timeline Anti-Patterns |
| 10.9 | Scaling Beyond the Toy Case |
| 10.10 | Writing the Narrative |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain why timeline analysis is valuable in Windows incident response
- Distinguish between super timelines and targeted timelines
- Gather and normalize timestamps from multiple artifact sources
- Merge artifact output into a single timeline view
- Identify a pivot event and investigate the surrounding window
- Write a concise narrative describing what happened in plain language
- Preserve a timeline that can be reused in a later case study or formal report

---

## Estimated Time and Difficulty

**Difficulty:** Advanced

**First time through the material:** 3–5 h

**Refresh (already familiar with the chapter):** 75–105 min

> **Key terms used in this lab:** pivot event, super timeline, targeted timeline, MACB, cross-artifact alignment. See the consolidated [Glossary](../../Book/Glossary.md) for definitions. The chapter cross-references in each entry take you back to the deeper coverage in `Book/`.

---

## Prerequisites

- Completion of Labs 01–09, or equivalent familiarity with Windows artifact analysis across NTFS, Registry, shell items, memory, network, and event logs
- A text editor or markdown editor
- Your `lab10-notes.md` file
- Access to some or all of the following artifact outputs:
  - MFT CSV
  - Event log exports
  - Prefetch output
  - SRUM output
- Optional: spreadsheet software or Python / PowerShell for merging CSV data
- Optional: tools such as Timeline Explorer, MFTECmd, EvtxECmd, Plaso/log2timeline, Timesketch, or custom scripts

> **Working without your own artifacts:** A complete multi-source artifact set for the WKSTN-221 scenario is in [`Data/WKSTN-221/`](../../Data/WKSTN-221/). Merging `mft.csv`, `usn-journal.csv`, `security-evtx.csv`, `prefetch.csv`, `srum.csv`, and `network-flow.csv` produces the timeline this lab walks through. Timestamps are aligned across the files so cross-source correlation works.

> **Prerequisite outputs from earlier labs (recommended):** This is the synthesis lab. It pulls together every artifact source you've worked through individually. You may already have:
>
> - **From [Lab 04](../Lab04/ReadMe.md):** the WKSTN-221 MFT and USN parsed and the `update.exe` row identified.
> - **From [Lab 09](../Lab09/ReadMe.md):** the Security / System / PowerShell `.evtx` filtered to the hunt-pack hits around 14:14–14:33 UTC.
> - **From [Lab 06](../Lab06/ReadMe.md) and [Lab 08](../Lab08/ReadMe.md):** Prefetch and network-flow analysis techniques. Those labs use different hosts but the same patterns.
>
> If you've worked those labs, this one becomes the merge step, combining work you already did. If you haven't, the underlying CSVs are still in `Data/WKSTN-221/` and the timeline assembly stands on its own.

---

## Scenario

You are investigating a suspicious Windows workstation with partial artifacts collected from earlier triage and analysis.

Available evidence includes:

- An MFT CSV
- Windows event log exports
- Prefetch output
- SRUM output

The case team does not need a massive all-artifact timeline yet. What they need first is a mini incident timeline, focused on a suspicious window, that helps explain what happened on the host.

Your task is to:

- Gather the available timeline-capable inputs
- Normalize timestamps into a common frame of reference
- Merge them into a single working timeline
- Identify a pivot event
- Review roughly ±10–15 minutes around that pivot
- Write a short narrative paragraph describing what happened in that window

This lab prepares material you can reuse in the next chapter's case study work.

---

## Background: Why Timelines Matter

Timelines are one of the most useful ways to transform forensic artifacts into an incident narrative.

They help responders:

- See how different artifact sources align in time
- Move from isolated facts to event sequences
- Confirm or challenge theories about attacker behavior
- Identify cause-and-effect relationships
- Reduce confusion in noisy investigations

A good timeline answers questions such as:

- What happened first?
- What happened immediately before and after the suspicious event?
- Which artifacts reinforce each other?
- Which events look central versus incidental?

| Timeline Type | Practical Use |
|---|---|
| Super timeline | Broad multi-source aggregation, then filtered down |
| Targeted timeline | Focused review of a subset of artifacts and a smaller time window |

In real incident response, both are useful. Super timelines suit large investigations, but targeted timelines are often faster and more practical when you already have a lead and want to explain a narrow incident window.

| Common Tool Type | Example |
|---|---|
| Logging / timeline suites | Plaso, log2timeline, Timesketch |
| Windows artifact parsers | MFTECmd, EvtxECmd, other Zimmerman-style outputs |
| Review tools | Timeline Explorer, spreadsheets |
| Custom workflows | Python, PowerShell, SQL, CSV merges |

> **IR Reality Check:** A timeline is not just a reporting artifact. It is an analysis tool that helps you think more clearly about what happened.

---

## Lab Tasks

---

### Task 1 — Explain Why Timelines Matter

**Objective:** Build a practical responder-focused understanding of timeline analysis.

Write a short explanation in 4–6 sentences covering:

- Why timelines are useful in Windows incident response
- Why single artifacts are often weaker without temporal context
- How timelines help create a coherent investigative story
- Why timelines are useful for both analysis and reporting

Then answer the following in one or two sentences each:

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

### Task 2 — Distinguish Super Timelines from Targeted Timelines

**Objective:** Learn when each timeline style is useful.

Fill in the table below.

| Timeline Type | What It Is | Best Use Case | Main Limitation |
|---|---|---|---|
| Super timeline | | | |
| Targeted timeline | | | |

Then answer:

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

### Task 3 — Gather the Timeline Inputs

**Objective:** Identify and organize the artifact sources you will use.

For this lab, gather or identify the following inputs if available:

- MFT CSV
- Event log exports
- Prefetch output
- SRUM output

Record your inputs below.

| Input Source | File Name / Location | What It Contributes | Notes |
|---|---|---|---|
| MFT CSV | | | |
| Event log export | | | |
| Prefetch output | | | |
| SRUM output | | | |

Add at least two more timeline-capable sources of your own if available.

Examples may include:

- LNK or Jump List output
- PowerShell log exports
- Network timeline notes
- USB artifact timestamps
- Task Scheduler logs

Then answer:

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

### Task 4 — Normalize Time

**Objective:** Convert all relevant timestamps into one consistent time basis.

Choose a single time basis for the lab, such as:

- UTC
- A single agreed case time zone

For each source, document whether conversion or adjustment is needed.

| Artifact Source | Original Time Basis | Normalized Time Basis | Adjustment Needed? | Notes |
|---|---|---|---|---|
| MFT CSV | | | | |
| Event logs | | | | |
| Prefetch output | | | | |
| SRUM output | | | | |

Add any additional sources you included.

Then answer:

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

### Task 5 — Merge the Sources into a Single Timeline CSV

**Objective:** Create one working timeline view from multiple artifact types.

Using a spreadsheet, script, or timeline tool, merge your normalized data into a single CSV or structured table.

Your merged timeline should use the six-column schema below. It is the same schema as the empty `timeline-template.csv` that ships with this lab:

| Column | Purpose |
|---|---|
| Time (UTC) | Orders the event in time; normalized to UTC |
| Source Artifact | Identifies the file or parser the row came from (`MFT`, `Security`, `Prefetch`, …) |
| Event Description | Concise summary of what happened |
| Significance | One- or two-word relevance tag (`c2-comm`, `lateral-move`, `noise`, …) |
| Confidence | HIGH / MEDIUM / LOW based on how independently corroborated the row is |
| Notes | Long-form context: paths, processes, users, hosts, follow-up |

Document your reasoning for each column below.

| Field / Column | Why It Is Included |
|---|---|
| Time (UTC) | |
| Source Artifact | |
| Event Description | |
| Significance | |
| Confidence | |
| Notes | |

Then answer:

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

### Task 6 — Identify a Pivot Event

**Objective:** Choose the event that will anchor the focused timeline review.

Select a pivot event from your merged timeline.

Examples:

- A suspicious logon
- A PowerShell execution event
- A suspicious process start
- A service creation event
- A file creation in a suspicious path

Record the pivot below.

| Pivot Field | Value |
|---|---|
| Pivot Event Time (UTC) | |
| Artifact Source | |
| Event Description | |
| Why It Was Chosen | |

Then answer:

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

### Task 7 — Examine ±10–15 Minutes Around the Pivot

**Objective:** Build a focused incident window around the pivot event.

Review the timeline entries within roughly 10–15 minutes before and after the pivot.

Record at least 12 entries if possible.

Use the six-column schema (same as `timeline-template.csv`). Confidence ratings: **HIGH** (≥2 independent sources agree) · **MEDIUM** (single reliable source) · **LOW** (indirect or single low-confidence source).

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

Then answer:

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

### Task 8 — Identify Cross-Artifact Alignment

**Objective:** Recognize where different evidence sources reinforce each other.

Choose at least four examples where two or more artifact sources align meaningfully in time.

Use the table below.

| Timeline Finding | Artifact Source 1 | Artifact Source 2 | Why the Alignment Matters |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |

Then answer:

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

### Task 9 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined timeline interpretation.

Classify each statement below as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by this timeline alone

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

Then write six additional statements of your own and classify them the same way.

> **Guidance:** Timeline analysis earns its value by improving coherence, not by proving everything.

---

### Task 10 — Write the Narrative Paragraph

**Objective:** Turn the focused timeline window into plain-language incident description.

Write a single narrative paragraph describing what happened in the ±10–15 minute window around your pivot event.

Your paragraph should:

- Use plain language
- Stay close to what the timeline supports
- Mention the most important aligned events
- Avoid unsupported conclusions
- Read like something that could later be used in a case study or incident report

Then answer:

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

### Task 11 — Save and Package the Mini Timeline

**Objective:** Preserve the timeline so it can be reused in the next chapter or a case study.

Create or describe a folder structure for storing your mini timeline and supporting notes.

Use or adapt this model:

```
Case-Timeline/
├── merged-timeline.csv
├── pivot-window.csv
├── timeline-notes.md
└── narrative-paragraph.md
```

Then define naming conventions for:

| Item | Naming Convention | Example |
|---|---|---|
| Merged timeline | | |
| Pivot window export | | |
| Narrative paragraph file | | |
| Timeline notes | | |

Afterward, answer:

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

---

### Task 12 — Write an Analyst Handoff Note

**Objective:** Make your timeline work easy for another responder to continue.

Use the template below.

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

### Task 13 — Reflection

Answer the following in 3–5 sentences each.

**1. Why timelines matter**
Why is timeline analysis often one of the best ways to turn scattered artifacts into a coherent investigative story?

```
[Your response here]
```

**2. Focus versus overload**
Why can a targeted timeline be more useful than a massive super timeline in many cases?

```
[Your response here]
```

**3. Correlation and caution**
Why does temporal alignment strengthen findings while still requiring careful interpretation?

```
[Your response here]
```

**4. Narrative value**
Why is it important to convert a timeline window into plain-language narrative after the technical analysis is done?

```
[Your response here]
```

---

## Hands-On Walkthrough (Using Simulated Data)

Lab 10's central exercise is a multi-source timeline merge. The pre-parsed data in [`Data/WKSTN-221/`](../../Data/WKSTN-221/) is structured so this works end to end without a Windows VM. The walkthrough below uses PowerShell. The same operations work in `pandas`, in a SQL query against imported CSVs, or in Excel with PivotTable filters.

The empty CSV at [`Labs/Lab10/timeline-template.csv`](timeline-template.csv) ships with the agreed column headers (`Time (UTC)`, `Source Artifact`, `Event Description`, `Significance`, `Confidence`, `Notes`). The PowerShell below produces objects in that same schema so the final `Export-Csv` matches the template byte-for-byte.

### Step 1 — Load the inputs

```powershell
$mft = Import-Csv 'Data\WKSTN-221\mft.csv' | ForEach-Object {
    [PSCustomObject][ordered]@{
        'Time (UTC)'        = $_.Created0x10
        'Source Artifact'   = 'MFT'
        'Event Description' = "File created: $($_.FileName)"
        'Significance'      = ''
        'Confidence'        = ''
        'Notes'             = "$($_.ParentPath)\$($_.FileName)  (InUse=$($_.InUse))"
    }
}
$usn = Import-Csv 'Data\WKSTN-221\usn-journal.csv' | ForEach-Object {
    [PSCustomObject][ordered]@{
        'Time (UTC)'        = $_.UpdateTimestamp
        'Source Artifact'   = 'USN'
        'Event Description' = "$($_.UpdateReasons): $($_.FileName)"
        'Significance'      = ''
        'Confidence'        = ''
        'Notes'             = "$($_.ParentPath)\$($_.FileName)"
    }
}
$sec = Import-Csv 'Data\WKSTN-221\security-evtx.csv' | ForEach-Object {
    [PSCustomObject][ordered]@{
        'Time (UTC)'        = $_.TimeCreated
        'Source Artifact'   = "evtx-Security-EID$($_.EventID)"
        'Event Description' = $_.Description
        'Significance'      = ''
        'Confidence'        = ''
        'Notes'             = ($_.Payload -split ' ')[0..2] -join ' '
    }
}
$pf = Import-Csv 'Data\WKSTN-221\prefetch.csv' | ForEach-Object {
    [PSCustomObject][ordered]@{
        'Time (UTC)'        = $_.LastRun
        'Source Artifact'   = 'Prefetch'
        'Event Description' = "Executed: $($_.ExecutableName)"
        'Significance'      = ''
        'Confidence'        = ''
        'Notes'             = "RunCount=$($_.RunCount)"
    }
}
$net = Import-Csv 'Data\WKSTN-221\network-flow.csv' | ForEach-Object {
    [PSCustomObject][ordered]@{
        'Time (UTC)'        = $_.FlowStart
        'Source Artifact'   = 'Network'
        'Event Description' = "Flow $($_.SourceIP):$($_.SourcePort) -> $($_.DestIP):$($_.DestPort)"
        'Significance'      = ''
        'Confidence'        = ''
        'Notes'             = "out=$($_.BytesSent) in=$($_.BytesReceived) proc=$($_.OwningProcess)"
    }
}
```

```python
import csv
def row(t, src, desc, notes):
    return {'Time (UTC)': t, 'Source Artifact': src, 'Event Description': desc,
            'Significance': '', 'Confidence': '', 'Notes': notes}
with open('Data/WKSTN-221/mft.csv') as f:
    mft = [row(r['Created0x10'], 'MFT', f"File created: {r['FileName']}",
               f"{r['ParentPath']}\\{r['FileName']}  (InUse={r['InUse']})")
           for r in csv.DictReader(f)]
with open('Data/WKSTN-221/usn-journal.csv') as f:
    usn = [row(r['UpdateTimestamp'], 'USN', f"{r['UpdateReasons']}: {r['FileName']}",
               f"{r['ParentPath']}\\{r['FileName']}")
           for r in csv.DictReader(f)]
with open('Data/WKSTN-221/security-evtx.csv') as f:
    sec = [row(r['TimeCreated'], f"evtx-Security-EID{r['EventID']}", r['Description'],
               ' '.join(r['Payload'].split(' ')[:3]))
           for r in csv.DictReader(f)]
with open('Data/WKSTN-221/prefetch.csv') as f:
    pf = [row(r['LastRun'], 'Prefetch', f"Executed: {r['ExecutableName']}",
              f"RunCount={r['RunCount']}")
          for r in csv.DictReader(f)]
with open('Data/WKSTN-221/network-flow.csv') as f:
    net = [row(r['FlowStart'], 'Network',
               f"Flow {r['SourceIP']}:{r['SourcePort']} -> {r['DestIP']}:{r['DestPort']}",
               f"out={r['BytesSent']} in={r['BytesReceived']} proc={r['OwningProcess']}")
           for r in csv.DictReader(f)]
```

### Step 2 — Merge into a single timeline

```powershell
$timeline = $mft + $usn + $sec + $pf + $net |
            Sort-Object { [DateTime]$_.'Time (UTC)' }
$timeline.Count
```

```python
timeline = sorted(mft + usn + sec + pf + net, key=lambda r: r['Time (UTC)'])
print(len(timeline))
```

Expected: **206** entries (77 MFT + 51 USN + 38 Security + 20 Prefetch + 20 network).

### Step 3 — Curate around a pivot event

The Prefetch entry for `update.exe` at 14:21:03 UTC is a natural pivot. Filter to a 15-minute window around it:

```powershell
$pivot  = [DateTime]'2024-11-14 14:21:03'
$window = $timeline | Where-Object {
    $t = [DateTime]$_.'Time (UTC)'
    $t -ge $pivot.AddMinutes(-15) -and $t -le $pivot.AddMinutes(15)
} | Sort-Object { [DateTime]$_.'Time (UTC)' }

$window | Format-Table -AutoSize
```

```python
from datetime import datetime, timedelta
pivot = datetime(2024, 11, 14, 14, 21, 3)
def parse(t):
    return datetime.fromisoformat(t.replace('Z', '').split('.')[0])
window = sorted(
    [r for r in timeline if r['Time (UTC)'] and abs(parse(r['Time (UTC)']) - pivot) <= timedelta(minutes=15)],
    key=lambda r: r['Time (UTC)'])
for r in window:
    print(r['Time (UTC)'], r['Source Artifact'], r['Event Description'])
```

Expected output: a chronological narrative around the pivot. The first lines are the user opening `Q4_Payroll_Review.xlsm` (MFT and USN rows for the `Q4_Payroll_Review.lnk` shortcut); 43 seconds later `OUTLOOK.EXE → POWERSHELL.EXE` (EID 4688); the outbound TCP/443 to 91.214.47.22 (Network); the `update.exe` creation in Temp (MFT, USN); the Prefetch first-run; the large `update.exe` flow to 91.214.47.22 at 14:21:55 (Network); the `update.exe` deletion (USN); and shortly after, the explicit-credential use to FILESVR-03 (EID 4648). The `update.exe` creation appears under two names. The MFT row carries only the final name. The USN rows show the same record (22417) created as `b.tmp` at 14:20:11 and renamed half a second later. A rename keeps the MFT record, so the MFT shows a file's current name and the USN Journal shows its history.

### Step 4 — Annotate with significance and confidence

Fill in the empty `Significance` and `Confidence` columns with simple analyst rules. Edit in place and export:

```powershell
$annotated = $window | ForEach-Object {
    $_.'Significance' = switch -Wildcard ($_.'Event Description') {
        "*update.exe*"           { 'Attacker tooling' }
        "*POWERSHELL.EXE*"       { 'Suspicious child of OUTLOOK.EXE' }
        "*explicit credentials*" { 'Lateral movement signal' }
        "*Flow*91.214.47.22*"    { 'C2 candidate' }
        default                  { '' }
    }
    $_.'Confidence' = switch ($_.'Source Artifact') {
        'Network' { 'High (sensor + EDR)' }
        'MFT'     { 'High' }
        'USN'     { 'High' }
        default   { 'Medium' }
    }
    $_
}
$annotated | Export-Csv 'wkstn221-timeline.csv' -NoTypeInformation
```

```python
def significance(desc):
    d = desc.lower()  # case-insensitive, like PowerShell -Wildcard
    if 'update.exe' in d:           return 'Attacker tooling'
    if 'powershell.exe' in d:       return 'Suspicious child of OUTLOOK.EXE'
    if 'explicit credentials' in d: return 'Lateral movement signal'
    if 'flow' in d and '91.214.47.22' in d: return 'C2 candidate'
    return ''
conf_map = {'Network': 'High (sensor + EDR)', 'MFT': 'High', 'USN': 'High'}
for r in window:
    r['Significance'] = significance(r['Event Description'])
    r['Confidence'] = conf_map.get(r['Source Artifact'], 'Medium')
with open('wkstn221-timeline.csv', 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(window[0].keys()))
    w.writeheader()
    w.writerows(window)
```

The output `wkstn221-timeline.csv` has the same six headers as [`Labs/Lab10/timeline-template.csv`](timeline-template.csv). Open both side by side. The template is the empty starting point you would have filled in by hand, and this one is the same schema populated from the WKSTN-221 dataset.

### Step 5 — Write the narrative paragraph

Open `wkstn221-timeline.csv` in your spreadsheet of choice. Filter to rows where `Significance` is non-empty. Read top to bottom, and the timeline writes itself. Your narrative paragraph (the deliverable in Task 10) should read approximately like this:

> *At 14:18:55 UTC the user opened `Q4_Payroll_Review.xlsm`. Forty-three seconds later, `outlook.exe` spawned `powershell.exe` with an encoded command line, which then established an outbound TCP/443 connection to `91.214.47.22`. A binary named `update.exe` was created in the user's `Temp\` directory at 14:20:11 UTC and executed at 14:21:03 UTC. A later connection to the same IP, at 14:21:55 UTC, received approximately 2.3 MB and sent roughly 184 KB. The binary was deleted at 14:23:44 UTC. About 9.5 minutes later the same account authenticated to FILESVR-03 with explicit credentials.*

Every statement in that paragraph comes from the CSV you just produced.

> **Reference output:** A finished, fully annotated 40-row version of this same window ships at [`../../Data/WKSTN-221/example-curated-timeline.csv`](../../Data/WKSTN-221/example-curated-timeline.csv). Of its 40 rows, 39 fall inside the ±15-minute window. It spans 14:18:55 to 14:38:00 UTC, sourced from the same WKSTN-221 dataset, and every row is tagged with `Significance` and rated `HIGH` / `MEDIUM` / `LOW` confidence. The pivot row is `update.exe` first run at 14:21:03 UTC. The surrounding context covers the lure-document open, the encoded-PowerShell stager, the C2 beaconing, and the lateral-move handoff to FILESVR-03. Open `Data/WKSTN-221/example-curated-timeline.csv` side by side with your own output, but only *after* you build your own. Comparing first spoils the analytical exercise.

### What you've just done

You've turned five disconnected artifact streams into a curated, annotated, narrative chronology, which is the deliverable Lab 10 asks for. The merge, sort, filter, annotate, and narrative steps generalize. In essence, `super timelines` and SIEM-driven incident reconstructions reduce to this same pattern.

---

## Deliverables Checklist

Your `lab10-notes.md` should contain:

- [ ] **Task 1** — Timeline-importance explanation plus short written responses
- [ ] **Task 2** — Super timeline vs targeted timeline table
- [ ] **Task 3** — Timeline-inputs table with added sources if available
- [ ] **Task 4** — Time-normalization table
- [ ] **Task 5** — Merged-timeline schema explanation
- [ ] **Task 6** — Pivot-event selection record
- [ ] **Task 7** — Focused ±10–15 minute timeline window with at least 12 entries where possible
- [ ] **Task 8** — Cross-artifact alignment table
- [ ] **Task 9** — Strong support vs overclaim exercise
- [ ] **Task 10** — Narrative paragraph
- [ ] **Task 11** — Timeline packaging structure and naming conventions
- [ ] **Task 12** — Analyst handoff note
- [ ] **Task 13** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab10/
├── ReadMe.md                     ← This file
├── lab10-notes.md                ← Your working notes file (fill this in)
├── walkthrough-answers.md        ← Sample answers for the Hands-On Walkthrough
├── task-answers.md               ← Sample answers for the workbook Tasks
├── timeline-template.csv         ← Empty CSV with the agreed column headers;
│                                   copy this and fill it in for Tasks 5–8
├── timeline-template-iris.csv    ← Same template using IRIS-NG / DFIR-IRIS
│                                   field names (event_date, event_tz,
│                                   event_title, event_source, event_content,
│                                   event_tags, event_color) for direct import
│                                   into IRIS-NG. Optional. See Appendix D §D.14.
├── Lab10_01/ReadMe.md            ← Ch10 §10.1 — Why Timelines?
├── Lab10_02/ReadMe.md            ← Ch10 §10.2 — Types of Timelines
├── Lab10_03/ReadMe.md            ← Ch10 §10.3 — Common Tools
└── Lab10_04/ReadMe.md            ← Ch10 §10.4 — Building a Mini Incident Timeline
```

---

> **Going deeper:** When you outgrow the spreadsheet, the natural next step is a collaborative timeline platform. Typical triggers are multiple analysts on the same case, a multi-host incident, or a tabletop where shared annotations matter. [IRIS-NG](https://github.com/zach115th/iris-ng), a fork of DFIR-IRIS, and [Timesketch](https://github.com/google/timesketch) are the two open-source options covered in Appendix D §D.14. The spreadsheet schema in this lab maps directly onto IRIS-NG's CSV import fields. An IRIS-ready header version of the template ships at `timeline-template-iris.csv` in this folder.

---

## Key Takeaways

- **Timelines make artifacts more meaningful.** They show how events from different sources align in time.
- **Targeted timelines are often the right first move.** A focused window around a pivot event can reveal the key sequence faster than a giant undifferentiated timeline.
- **Normalization matters.** Timezone handling and skew awareness are essential before merging evidence.
- **Cross-artifact alignment increases confidence.** Events that line up across MFT, logs, Prefetch, SRUM, and other sources are usually more valuable than isolated entries.
- **Narrative is the payoff.** A good timeline should end in a plain-language explanation of what happened in the suspicious window.

---

**Next:** Lab 10.1 — Why Timelines?

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
