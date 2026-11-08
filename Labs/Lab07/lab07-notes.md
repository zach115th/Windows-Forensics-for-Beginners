# Lab 07 — Analyst Notes
**Memory Forensics**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Lab Environment:** ___________________________  
**Case Reference:** IR-2024-FIN-WS23  

---

## Task 1 — Explain Why Memory Matters

> Write a short explanation in 4–6 sentences covering why memory matters in Windows IR, what kinds of evidence may exist only in memory, why memory is especially important in fileless or EDR-aware intrusions, and why disk evidence alone may be insufficient.

```
[Your explanation here]
```

**Investigative-question usefulness ratings:**

> Use the ratings: Strongly useful / Partially useful / Not very useful.

| Investigative Question | Memory Forensics Value | Why |
|---|---|---|
| Did a suspicious process likely exist in RAM? | | |
| Did a short-lived process leave useful live-response traces? | | |
| Was code injected into another process? | | |
| Were suspicious network connections active? | | |
| Did a malicious file exist on disk? | | |
| Were credentials or tokens potentially present in memory? | | |

**Short answers:**

**1. Why is memory especially valuable in fileless cases?**
```
[Your response here]
```

**2. Why is memory usually time-sensitive evidence?**
```
[Your response here]
```

**3. Why should responders still avoid treating memory as a complete answer by itself?**
```
[Your response here]
```

---

## Task 2 — Identify the Tools and Their Roles

> Fill in the table below with each tool's primary role, why it matters, and its limitations.

| Tool | Primary Role | Why It Matters | Limitation |
|---|---|---|---|
| Volatility 3 | | | |
| Volatility 2.x | | | |
| Rekall | | | |
| MemProcFS | | | |
| Redline | | | |
| WinPmem | | | |
| DumpIt | | | |

**Short answers:**

**1. Why is it useful to separate acquisition tools from analysis tools?**
```
[Your response here]
```

**2. Why might one responder prefer MemProcFS or Redline for triage but Volatility for deeper work?**
```
[Your response here]
```

**3. Why does tool choice matter for repeatability and defensibility?**
```
[Your response here]
```

---

## Task 3 — Capture Memory and Record Integrity

> Capture memory using WinPmem or DumpIt. If hands-on acquisition is not possible, write the exact workflow and commands you would use in a real lab.

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

**Exact command used:**

```powershell
[Paste exact command here]
```

**Raw hash output:**

```
[Paste hash output here]
```

**Short answers:**

**1. Why should memory be hashed immediately after acquisition?**
```
[Your response here]
```

**2. Why does the acquisition tool and version matter?**
```
[Your response here]
```

**3. Why should warnings or collection issues be documented even if a dump file was created?**
```
[Your response here]
```

---

## Task 4 — Identify OS / Image Information

> Using Volatility or an equivalent framework, identify the system / OS information for the memory image.

| Question | What You Found | Why It Matters |
|---|---|---|
| OS family / version | | |
| Kernel or image characteristics | | |
| Architecture | | |
| Other useful context | | |

**Command(s) used:**

```
[Paste exact commands here]
```

**Short answers:**

**1. Why is confirming OS context one of the first steps in memory analysis?**
```
[Your response here]
```

**2. Why can a wrong profile or wrong assumptions break later analysis?**
```
[Your response here]
```

**3. Why should system context be recorded in your analyst notes before deeper findings?**
```
[Your response here]
```

---

## Task 5 — Enumerate Processes and Process Trees

> Run `pslist`, `psscan`, and `pstree` (or equivalents). Record at least six process findings or candidate leads.

| Process | Why It Stands Out | Artifact / Command | What It Might Suggest | What It Does Not Prove |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

**Short answers:**

**1. Why is it useful to compare `pslist`, `psscan`, and `pstree` rather than trusting just one view?**
```
[Your response here]
```

**2. Why do odd parent-child relationships matter in incident response?**
```
[Your response here]
```

**3. Why is process path context sometimes as important as the process name itself?**
```
[Your response here]
```

---

## Task 6 — Review Command Lines and Loaded DLLs

> Choose at least three suspicious processes from Task 5. Review command lines, loaded DLLs / modules, and any unusual path or module indicators.

| Process | Command-Line Clue | DLL / Module Clue | Why It Matters | What Still Needs Corroboration |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

**Short answers:**

**1. Why are command lines often more revealing than process names alone?**
```
[Your response here]
```

**2. Why can unusual DLLs or modules increase concern about a process?**
```
[Your response here]
```

**3. Why should DLL review still be interpreted carefully rather than treated as proof of malware by itself?**
```
[Your response here]
```

---

## Task 7 — Review Network Connections

> Run `netscan` or the equivalent. Record at least five findings or candidate leads.

| Process / PID | Local Address | Remote Address | Why It Stands Out | What It Might Suggest |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

**Short answers:**

**1. Why is memory often one of the best places to connect network activity to a process?**
```
[Your response here]
```

**2. Why is a suspicious remote IP not automatically proof of C2 by itself?**
```
[Your response here]
```

**3. Why do process, time, and network context matter together?**
```
[Your response here]
```

---

## Task 8 — Run Malware-Oriented Review

> Use `malfind` or an equivalent approach. For meaningful hits, review with strings, dumped regions or processes, supporting process context, and DLL / module review.

| Process | Malfind / Suspicious Region Finding | Why It Matters | Follow-Up Action |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |

**Short answers:**

**1. Why is `malfind` useful in injected-code or memory-resident implant cases?**
```
[Your response here]
```

**2. Why is a `malfind` hit only the beginning of the analysis?**
```
[Your response here]
```

**3. Why is process dumping or region dumping useful after an initial suspicious hit?**
```
[Your response here]
```

---

## Task 9 — Correlate the Memory Findings

> Choose three suspicious findings and correlate them across multiple memory-analysis steps.

| Suspicious Lead | Supporting Artifact 1 | Supporting Artifact 2 | Supporting Artifact 3 | Combined Interpretation | Confidence |
|---|---|---|---|---|---|
| | | | | | High / Med / Low |
| | | | | | High / Med / Low |
| | | | | | High / Med / Low |

**Short answers:**

**1. Why is correlation more valuable than a single suspicious plugin hit?**
```
[Your response here]
```

**2. Why should responders describe confidence instead of certainty in many memory cases?**
```
[Your response here]
```

**3. Which combinations of memory findings would most strongly justify escalation?**
```
[Your response here]
```

---

## Task 10 — Separate Strong Support from Overclaims

> Classify each statement as: Strongly supported / Suggested but needs corroboration / Not supported by these findings alone.

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

## Task 11 — Build a Memory-Hunt Timeline

> Create a mini-timeline with at least ten entries if possible.

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

**Short answers:**

**1. Which timeline entries appear most central to the possible implant theory?**
```
[Your response here]
```

**2. Which entries are supportive but not decisive?**
```
[Your response here]
```

**3. What major gaps remain after the memory hunt?**
```
[Your response here]
```

---

## Task 12 — Write the Analyst Note

> Write a 3–5 paragraph analyst note as a working-note summary, not a final malware-analysis report.

```
[Your analyst note here — 3 to 5 paragraphs]
```

---

## Task 13 — Write an Analyst Handoff Note

> Make your memory-hunt results easy for another responder to continue.

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

## Task 14 — Reflection

**1. Why memory matters**
*Why can memory analysis reveal evidence that disk-based analysis may never recover?*
```
[Your response here]
```

---

**2. Live state versus durable state**
*Why is memory so valuable for understanding processes, sockets, and injected code during an active incident?*
```
[Your response here]
```

---

**3. Caution in interpretation**
*Why should responders avoid turning suspicious memory findings into stronger claims than the evidence supports?*
```
[Your response here]
```

---

**4. Correlation remains essential**
*Why are memory findings strongest when paired with disk artifacts, logs, EDR telemetry, and user-activity evidence?*
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

*Lab 07 Notes — Windows Forensics for Beginners*
*Keep this file in your `Labs/Lab07/` folder alongside the `ReadMe.md`.*
