# Lab 07 — Memory Forensics

**Supporting [Chapter 7: Memory Forensics](../../Book/Chapter07.md)**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Some of the most important evidence in a Windows incident never touches disk in a durable way.

A process can run briefly and disappear. A beacon can maintain live network connections without leaving useful file artifacts. Injected code can live inside another process. Credentials, tokens, keys, and plaintext content may exist only in RAM. When attackers use fileless, memory-resident, or EDR-aware tradecraft, disk and Registry evidence alone may tell only part of the story.

This lab introduces memory forensics from an incident response perspective. The goal is not to make you a reverse engineer in one sitting but to build a practical workflow. You will collect a memory image, identify the system context, enumerate processes, review command lines and DLLs, and check network connections. You will then use malware-hunting plugins and document what you found in a way another analyst can follow.

By the end of this lab, you should be comfortable treating memory as a core IR evidence source rather than an optional specialty artifact.

---

## What This Lab Covers

This lab supports the following sections from Chapter 7:

| Section | Topic |
|---|---|
| 7.1 | Why Memory Matters in IR |
| 7.2 | Tooling |
| 7.3 | Typical Workflow |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain why memory analysis is valuable in Windows incident response
- Identify the kinds of evidence that may exist only in RAM
- Capture a memory image in a controlled way and record integrity information
- Use common memory-analysis workflows to identify OS context, processes, command lines, DLLs, and network connections
- Recognize suspicious process characteristics such as unusual names, odd parent-child relationships, and non-standard paths
- Use malware-oriented plugins such as malfind to identify suspicious memory regions
- Write a concise analyst note summarizing what memory review did and did not reveal

---

## Estimated Time and Difficulty

**Difficulty:** Advanced

**First time through the material:** 3–5 h

**Refresh (already familiar with the chapter):** 75–105 min

> **Key terms used in this lab:** process tree, code injection, malfind, netscan, EPROCESS, reflective loading. See the consolidated [Glossary](../../Book/Glossary.md) for definitions. The chapter cross-references in each entry take you back to the deeper coverage in `Book/`.

---

## Prerequisites

- Completion of Labs 01–06, or equivalent familiarity with Windows IR workflow, file-system analysis, Registry analysis, execution evidence, and shell/application artifacts
- A text editor or markdown editor
- Your `lab07-notes.md` file
- A Windows VM you can safely acquire memory from
- A memory acquisition tool such as WinPmem or DumpIt
- A memory-analysis framework such as Volatility 3, Volatility 2, Rekall, MemProcFS, or Redline

> **Working without a memory image:** Pre-formatted Volatility 3 plugin output for the WEB-APP-03 scenario is in [`Data/WEB-APP-03/`](../../Data/WEB-APP-03/). Use `volatility-pslist.txt`, `volatility-pstree.txt`, `volatility-cmdline.txt`, `volatility-netscan.txt`, `volatility-malfind.txt`, `volatility-dlllist.txt`, `volatility-svcscan.txt`, and `volatility-handles.txt` to work the analysis tasks if you are not capturing your own image.

---

## Scenario

You are investigating a Windows host where defenders suspect a memory-resident implant.

Disk evidence is limited. Logging is incomplete. The defenders are concerned that the attacker may have used short-lived processes, injected code, or an in-memory beacon that would be difficult to explain from file-system artifacts alone.

Your task is a basic memory hunt:

- Capture memory from the host or lab VM
- Confirm system / OS context
- Enumerate processes and process trees
- Review suspicious command lines and loaded DLLs
- Inspect network connections
- Use malware-oriented memory-analysis techniques
- Write an analyst note describing what you found and what should happen next

You are not expected to fully reverse engineer malware in this lab. Your job is to use memory forensics to identify suspicious leads and turn them into defensible next steps.

---

## Background: Why Memory Matters in IR

Memory analysis helps answer questions that disk artifacts often cannot answer well enough on their own.

It can reveal:

- Fileless malware and injected code
- C2 beacons and active sockets
- In-memory secrets such as tokens, passwords, or keys
- Processes that existed briefly and never left useful durable traces
- Modules and DLLs loaded into suspicious processes
- Command-line evidence that may no longer be available elsewhere

This matters especially when attackers use:

- Living-off-the-land binaries
- Short-lived PowerShell or script activity
- Reflective loading or process injection
- EDR-aware tradecraft designed to minimize disk artifacts

| Memory Question | Why Memory Helps |
|---|---|
| Is something suspicious running right now? | RAM preserves live process state |
| Did a short-lived process exist? | Memory frameworks may recover traces beyond simple live task listings |
| Is a process injected or hollowed? | Memory plugins can flag suspicious regions |
| Which process owns this network activity? | Netscan-style analysis can correlate sockets to processes |
| Did malware avoid writing tools to disk? | Memory may preserve the only useful artifact |

> **IR Reality Check:** Memory is not always available, and it is never complete by itself. In some incidents, though, it is the only place where the most important evidence still exists.

---

## Lab Tasks

---

### Task 1 — Explain Why Memory Matters

**Objective:** Build a practical understanding of why responders prioritize RAM in some cases.

Write a short explanation in 4–6 sentences covering:

- Why memory matters in Windows incident response
- What kinds of evidence may exist only in memory
- Why memory is especially important in fileless or EDR-aware intrusions
- Why disk evidence alone may be insufficient in some cases

Then complete the table below.

| Investigative Question | Memory Forensics Value | Why |
|---|---|---|
| Did a suspicious process likely exist in RAM? | | |
| Did a short-lived process leave useful live-response traces? | | |
| Was code injected into another process? | | |
| Were suspicious network connections active? | | |
| Did a malicious file exist on disk? | | |
| Were credentials or tokens potentially present in memory? | | |

Use the ratings:

- Strongly useful
- Partially useful
- Not very useful

Then answer:

1. Why is memory especially valuable in fileless cases?
2. Why is memory usually time-sensitive evidence?
3. Why should responders still avoid treating memory as a complete answer by itself?

---

### Task 2 — Identify the Tools and Their Roles

**Objective:** Understand the main memory-forensics tools and when they are useful.

Fill in the table below.

| Tool | Primary Role | Why It Matters | Limitation |
|---|---|---|---|
| Volatility 3 | | | |
| Volatility 2.x | | | |
| Rekall | | | |
| MemProcFS | | | |
| Redline | | | |
| WinPmem | | | |
| DumpIt | | | |

Then answer:

1. Why is it useful to separate acquisition tools from analysis tools?
2. Why might one responder prefer MemProcFS or Redline for triage but Volatility for deeper work?
3. Why does tool choice matter for repeatability and defensibility?

---

### Task 3 — Capture Memory and Record Integrity

**Objective:** Acquire a memory image and document it properly.

Use WinPmem or DumpIt on your Windows VM or lab host.

Your goal is to:

- Capture memory
- Save the dump
- Compute a hash
- Document the basic collection details

Record your work in the table below.

| Field | Value |
|---|---|
| Host / VM Name | |
| Acquisition Tool | |
| Tool Version | |
| Output File Name | |
| Output Path | |
| Approximate File Size | |
| Hash Algorithm | |
| Hash Value | |
| Acquisition Date/Time (UTC) | |
| Notes / Warnings | |

Then answer:

1. Why should memory be hashed immediately after acquisition?
2. Why does the acquisition tool and version matter?
3. Why should warnings or collection issues be documented even if a dump file was created?

> **Guidance:** If you cannot perform hands-on acquisition, write the exact workflow and commands you would use in a real lab.

---

### Task 4 — Identify OS / Image Information

**Objective:** Confirm the system context before deeper analysis.

Using Volatility or an equivalent framework, identify the system / OS information for the memory image.

Examples from the chapter include:

- `windows.info`
- `imageinfo` or equivalent

Record your work below.

| Question | What You Found | Why It Matters |
|---|---|---|
| OS family / version | | |
| Kernel or image characteristics | | |
| Architecture | | |
| Other useful context | | |

Then answer:

1. Why is confirming OS context one of the first steps in memory analysis?
2. Why can a wrong profile or wrong assumptions break later analysis?
3. Why should system context be recorded in your analyst notes before deeper findings?

---

### Task 5 — Enumerate Processes and Process Trees

**Objective:** Identify suspicious processes, parent-child relationships, and path context.

Using Volatility or equivalent tooling, run:

- `pslist`
- `psscan`
- `pstree`

Review the results and look for:

- Weird process names
- Odd parent-child relationships
- Uncommon execution paths
- Processes that appear in one view but not another
- Suspicious processes launched under user-writable locations

Record at least six process findings or candidate leads.

| Process | Why It Stands Out | Artifact / Command | What It Might Suggest | What It Does Not Prove |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

Then answer:

1. Why is it useful to compare `pslist`, `psscan`, and `pstree` rather than trusting just one view?
2. Why do odd parent-child relationships matter in incident response?
3. Why is process path context sometimes as important as the process name itself?

---

### Task 6 — Review Command Lines and Loaded DLLs

**Objective:** Use process context to assess suspicious execution behavior.

Choose at least three suspicious processes from Task 5 and review:

- Command lines
- Loaded DLLs / modules
- Any unusual path or module indicators

Use the table below.

| Process | Command-Line Clue | DLL / Module Clue | Why It Matters | What Still Needs Corroboration |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

Then answer:

1. Why are command lines often more revealing than process names alone?
2. Why can unusual DLLs or modules increase concern about a process?
3. Why should DLL review still be interpreted carefully rather than treated as proof of malware by itself?

---

### Task 7 — Review Network Connections

**Objective:** Tie suspicious network activity back to processes in memory.

Using `netscan` or the equivalent in your chosen framework, identify suspicious or noteworthy connections.

Look for:

- Unfamiliar remote IPs
- Unusual ports
- Suspicious processes owning sockets
- Connections that align with suspicious process findings

Record at least five findings or candidate leads.

| Process / PID | Local Address | Remote Address | Why It Stands Out | What It Might Suggest |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

Then answer:

1. Why is memory often one of the best places to connect network activity to a process?
2. Why is a suspicious remote IP not automatically proof of C2 by itself?
3. Why do process, time, and network context matter together?

---

### Task 8 — Run Malware-Oriented Review

**Objective:** Use malware-hunting plugins to identify suspicious memory regions.

Using `malfind` or an equivalent approach, inspect suspicious findings.

For any meaningful hits, review them with:

- Strings
- Dumped regions or dumped processes
- Supporting process context
- DLL / module review

Record your findings in the table below.

| Process | Malfind / Suspicious Region Finding | Why It Matters | Follow-Up Action |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |

Then answer:

1. Why is `malfind` useful in injected-code or memory-resident implant cases?
2. Why is a `malfind` hit only the beginning of the analysis?
3. Why is process dumping or region dumping useful after an initial suspicious hit?

---

### Task 9 — Correlate the Memory Findings

**Objective:** Turn individual plugin output into a defensible analysis.

Choose three suspicious findings and correlate them across multiple memory-analysis steps.

Use the table below.

| Suspicious Lead | Supporting Artifact 1 | Supporting Artifact 2 | Supporting Artifact 3 | Combined Interpretation | Confidence |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |
| | | | | | |

Possible supporting sources include:

- Process enumeration
- Parent-child relationships
- Command lines
- DLL lists
- Network connections
- `malfind`
- Dumped region review
- Strings output

Then answer:

1. Why is correlation more valuable than a single suspicious plugin hit?
2. Why should responders describe confidence instead of certainty in many memory cases?
3. Which combinations of memory findings would most strongly justify escalation?

---

### Task 10 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined reporting around memory evidence.

Classify each statement below as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by these findings alone

| Statement | Classification | Why |
|---|---|---|
| A suspicious process was present in memory | | |
| A suspicious process had an unusual parent-child relationship | | |
| The process was definitely controlled by an external attacker | | |
| A suspicious network connection was associated with a process of interest | | |
| Memory contains indications of code injection or suspicious regions | | |
| The suspicious process stole credentials from the user | | |
| The host shows signs consistent with a memory-resident implant | | |
| The attacker used this process for data exfiltration | | |

Then write six additional statements of your own and classify them the same way.

> **Guidance:** Memory artifacts can be compelling, but they still need careful wording and, in many cases, follow-on validation.

---

### Task 11 — Build a Memory-Hunt Timeline

**Objective:** Turn memory findings into a usable incident sequence or analytic order.

Create a mini-timeline with at least 10 entries if possible.

| Time (UTC) | Artifact Source | Event or Observation | Process / Region / Connection | Why It Matters |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

Your timeline may include:

- Process start relationships
- Command-line review points
- Network-connection observations
- Suspicious module findings
- `malfind` hits
- Dump or string review observations
- Correlation with any known incident window

Then answer:

1. Which timeline entries appear most central to the possible implant theory?
2. Which entries are supportive but not decisive?
3. What major gaps remain after the memory hunt?

---

### Task 12 — Write the Analyst Note

**Objective:** Produce the short analyst note described in the chapter.

Write a 3–5 paragraph analyst note answering:

- Whether you found anything suspicious in memory
- Which processes, regions, or network findings matter most
- What the memory evidence strongly supports
- What still requires corroboration from disk, logs, EDR, or deeper reverse engineering
- What further steps you would take next

Write it as a working-note summary rather than a final malware-analysis report.

---

### Task 13 — Write an Analyst Handoff Note

**Objective:** Make your memory-hunt results easy for another responder to continue.

Use the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Most Important Memory Findings:
- 

Most Important Process / Network Leads:
- 

What Is Strongly Supported:
- 

What Is Suggested but Not Confirmed:
- 

Recommended Next Steps:
1.
2.
3.

Open Questions:
- 

Notes for Incoming Analyst:
```

---

### Task 14 — Reflection

Answer the following in 3–5 sentences each.

**1. Why memory matters**
Why can memory analysis reveal evidence that disk-based analysis may never recover?

**2. Live state versus durable state**
Why is memory so valuable for understanding processes, sockets, and injected code during an active incident?

**3. Caution in interpretation**
Why should responders avoid turning suspicious memory findings into stronger claims than the evidence supports?

**4. Correlation remains essential**
Why are memory findings strongest when paired with disk artifacts, logs, EDR telemetry, and user-activity evidence?

---

## Hands-On Walkthrough (Using Simulated Data)

This walkthrough exercises Tasks 4–9 against the pre-formatted Volatility 3 plugin output in [`Data/WEB-APP-03/`](../../Data/WEB-APP-03/). The host is a Windows Server 2019 IIS application server suspected of running a web shell. Memory was captured at 2024-11-21 10:42 UTC. You can read the files directly, or load them into a text editor that supports column alignment for easier scanning.

> **Volatility 3 vs. MemProcFS:** This walkthrough uses Volatility 3 plugin output for tooling continuity with the rest of the book. If you have a real memory image and would rather explore it as a file system, [MemProcFS](https://github.com/ufrisk/MemProcFS) mounts the image, typically at `M:\`, and exposes the same data as a directory tree: `M:\name\powershell.exe-3704\cmdline\`, `M:\name\<process>\modules\`, `M:\registry\`, and so on. You could answer every analytical question in this walkthrough equally well with `dir` / `findstr` / `Get-Content` against the mounted file system. Many practitioners default to MemProcFS for exploration and reach for Volatility 3 plugins when they want a specific analytical heuristic. Either path produces the same forensic conclusion, so pick the ergonomics you prefer. See Appendix D §D.9 for a longer side-by-side.

### Step 1 — Confirm the image is parsable (`windows.info`)

```powershell
Get-Content 'Data\WEB-APP-03\volatility-info.txt' | Select-Object -First 35
```

```python
with open('Data/WEB-APP-03/volatility-info.txt') as f:
    for line in f.readlines()[:35]:
        print(line, end='')
```

Expected: standard `windows.info` output showing **Windows Server 2019**, build 17763, x64, with kernel base, KdDebuggerDataBlock, and system time at acquisition. If `windows.info` failed in a real investigation, every subsequent step would fail too. It is the sanity check that tells you the image is intact.

### Step 2 — Walk the process tree (`pstree`)

```powershell
Get-Content 'Data\WEB-APP-03\volatility-pstree.txt' |
  Select-String -Pattern "w3wp|cmd|powershell|wininit|services" |
  Select-Object -First 20
```

```python
import re
with open('Data/WEB-APP-03/volatility-pstree.txt') as f:
    hits = [ln for ln in f if re.search(r'w3wp|cmd|powershell|wininit|services', ln)]
for ln in hits[:20]:
    print(ln, end='')
```

Expected: the indented `pstree` output shows the suspicious subtree under `w3wp.exe` (PID 2860), which has spawned **both** `cmd.exe` (PID 3580) and `powershell.exe` (PID 3704) as direct children. Check the PPID column rather than reading the indentation as a single chain. IIS workers should never spawn shells at all, and a worker that spawned two of them is the central anomaly of the case.

### Step 3 — Read the suspicious command line

```powershell
Get-Content 'Data\WEB-APP-03\volatility-cmdline.txt' |
  Select-String -Pattern "powershell.exe|3704|EncodedCommand"
```

```python
with open('Data/WEB-APP-03/volatility-cmdline.txt') as f:
    for ln in f:
        if re.search(r'powershell\.exe|3704|EncodedCommand', ln):
            print(ln, end='')
```

Expected: PID **3704** powershell.exe with `-NoProfile -WindowStyle Hidden -EncodedCommand <base64>`. Decode the base64 in PowerShell with `[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('<paste>'))`, and you will see the in-memory loader cradle that runs `Invoke-WebRequest` against the C2 endpoint and pipes the response into `IEX`.

### Step 4 — Identify active C2 (`netscan`)

```powershell
Get-Content 'Data\WEB-APP-03\volatility-netscan.txt' |
  Select-String -Pattern "ESTABLISHED|powershell"
```

```python
with open('Data/WEB-APP-03/volatility-netscan.txt') as f:
    for ln in f:
        if 'ESTABLISHED' in ln or 'powershell' in ln:
            print(ln, end='')
```

Expected: an established TCPv4 connection from PID 3704 powershell.exe at 10.0.8.34:49918 to **91.214.47.22:443**. That is the same C2 IP that appears in the WKSTN-221 dataset, which points to the same attacker across hosts. The `netscan` plugin attributes the connection directly to the owning process, which is the per-process attribution that pure network sources cannot produce.

### Step 5 — Confirm injected code (`malfind`)

```powershell
Get-Content 'Data\WEB-APP-03\volatility-malfind.txt' |
  Select-String -Pattern "^[0-9]+\s+(powershell|svchost|w3wp)"
```

```python
with open('Data/WEB-APP-03/volatility-malfind.txt') as f:
    for ln in f:
        if re.match(r'^[0-9]+\s+(powershell|svchost|w3wp)', ln):
            print(ln, end='')
```

Expected: **3 hits** — PID 3704 (`powershell.exe`), PID 1142 (`svchost.exe`), PID 2860 (`w3wp.exe`). All three are `PAGE_EXECUTE_READWRITE` private-memory regions with no backing file, and all three begin with the `4d 5a` (`MZ`) PE signature. They are fully formed binaries resident in memory that are not on disk. The signature alone does not tell you they are the *same* binary. Comparing the dumped regions is the next step.

### Step 6 — Inspect loaded DLLs (`dlllist`)

```powershell
Get-Content 'Data\WEB-APP-03\volatility-dlllist.txt' |
  Select-String -Pattern "Temp\\|cmdshell"
```

```python
with open('Data/WEB-APP-03/volatility-dlllist.txt') as f:
    for ln in f:
        if 'Temp\\' in ln or 'cmdshell' in ln:
            print(ln, end='')
```

Expected: **one row**, `cmdshell.dll` loaded into PID 2860 (w3wp.exe) from `C:\Windows\Temp\cmdshell.dll` at 2024-11-21 10:19:14 UTC. A DLL loaded from `C:\Windows\Temp\` is essentially never legitimate. It loaded 32 seconds after `w3wp.exe` spawned both shells at 10:18:42 UTC, so it is follow-on activity, not what launched them.

### Step 7 — Find the disappearing service (`svcscan`)

```powershell
Get-Content 'Data\WEB-APP-03\volatility-svcscan.txt' |
  Select-String -Pattern "WindowsHealthCollector|whcs"
```

```python
with open('Data/WEB-APP-03/volatility-svcscan.txt') as f:
    for ln in f:
        if 'WindowsHealthCollector' in ln or 'whcs' in ln:
            print(ln, end='')
```

Expected: a service named `WindowsHealthCollector` with binary path `C:\Windows\Temp\whcs.exe`, currently `SERVICE_STOPPED`. This is the "service that appeared and disappeared" referenced in the System.evtx scenario. It is present in the service registry but not currently running. The Temp-directory binary path mirrors the DLL pattern from Step 6.

### Step 8 — Pull the suspicious process's handles (`handles`)

```powershell
Get-Content 'Data\WEB-APP-03\volatility-handles.txt' |
  Select-String -Pattern "cmdshell|whcs|1142"
```

```python
with open('Data/WEB-APP-03/volatility-handles.txt') as f:
    for ln in f:
        if re.search(r'cmdshell|whcs|1142', ln):
            print(ln, end='')
```

Expected: **five rows**. Three are file handles: `\Device\HarddiskVolume2\Windows\Temp\cmdshell.dll`, `whcs.exe`, and the named pipe `\Device\NamedPipe\whcs_ctrl` (`\\.\pipe\whcs_ctrl` in Win32 terms). The other two are a Process handle and a Thread handle into PID 1142 (svchost.exe), which confirm the injection target identified by `malfind` in Step 5.

### What you've just done

Eight Volatility plugins produced eight independent observations, and all of them point to the same picture. The IIS worker spawned two shells and then loaded `cmdshell.dll` from `C:\Windows\Temp\`. A child PowerShell runs a clearly malicious encoded command and holds an active C2 connection to `91.214.47.22:443`. That PowerShell injected into `svchost.exe`. A disappearing service rooted in `C:\Windows\Temp\` still has a named-pipe handle alive. Walk back through Tasks 4 through 9, and the analyst-notes scaffold has concrete data in every cell. The findings on this host share the C2 IP with the WKSTN-221 dataset. Note that as a multi-host indicator if the case expands.

---

## Deliverables Checklist

Your `lab07-notes.md` should contain:

- [ ] **Task 1** — Memory-forensics explanation and usefulness ratings table
- [ ] **Task 2** — Tool-role table with written responses
- [ ] **Task 3** — Memory acquisition and hash record
- [ ] **Task 4** — OS / image information review
- [ ] **Task 5** — Process-enumeration findings table
- [ ] **Task 6** — Command-line and DLL review for three suspicious processes
- [ ] **Task 7** — Network-connection review table
- [ ] **Task 8** — Malware-oriented review table
- [ ] **Task 9** — Correlation table for three suspicious leads
- [ ] **Task 10** — Strong support vs overclaim exercise
- [ ] **Task 11** — Memory-hunt timeline with at least 10 entries where possible
- [ ] **Task 12** — Analyst note
- [ ] **Task 13** — Analyst handoff note
- [ ] **Task 14** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab07/
├── ReadMe.md                     ← This file
├── lab07-notes.md                ← Your working notes file (fill this in)
├── walkthrough-answers.md        ← Sample answers for the Hands-On Walkthrough
├── task-answers.md               ← Sample answers for the workbook Tasks
├── Lab07_01/ReadMe.md            ← Ch7 §7.1 — Why Memory Matters in IR
├── Lab07_02/ReadMe.md            ← Ch7 §7.2 — Tooling
└── Lab07_03/ReadMe.md            ← Ch7 §7.3 — Typical Workflow
```

---

> **Going deeper:** EDR platforms such as Microsoft Defender for Endpoint, CrowdStrike Falcon, and SentinelOne produce process, network, module, and handle telemetry in the same shape as the Volatility output you have been reading, and so does Sysmon. `Book/AppendixC.md` (EDR Platforms and Sysmon) covers their query languages (KQL, FQL, Lucene-style Deep Visibility) and the Sysmon EIDs (1, 3, 7, 8, 10, 11, 22) that map to the same patterns. For credential-theft and process-injection patterns specifically, `Book/AppendixA.md` covers the LSASS-access (Pass-the-Hash, Mimikatz) and reflective-loader signatures.

---

## Key Takeaways

- **Memory captures live state.** It can reveal processes, sockets, injected code, and secrets that may never appear clearly on disk.
- **Acquisition and integrity matter.** Capture a memory dump carefully, hash it, and document it like any other evidence source.
- **Process context is critical.** Names, parents, paths, command lines, DLLs, and sockets all help turn a process listing into analysis.
- **Malware-oriented plugins provide leads, not final answers.** A suspicious hit needs context, follow-up, and careful interpretation.
- **Correlation is what makes memory findings defensible.** The strongest conclusions come from multiple memory indicators reinforced by other artifact classes.

---

**Next:** Lab 08 — Network Forensics on Windows

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
