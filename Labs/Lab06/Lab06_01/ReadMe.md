# Lab 6.1 — Evidence of Execution

**Supporting Section 6.1: Evidence of Execution**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

One of the most important questions in Windows incident response is deceptively simple:

> Did this program actually run?

In a real investigation, responders need to distinguish file presence from evidence of execution. Finding a suspicious file on disk is useful, but it is not enough. Attackers stage tools they never use. Users download files they never open. Automated processes drop installers, archives, and scripts into temporary paths all the time.

This lab focuses on that distinction. You will work through the Windows artifacts most often used to assess whether a program executed. For each one, you will judge how strongly it supports that conclusion and where it falls short on its own. The emphasis is on reasoning carefully from multiple artifact types without overclaiming, not on memorizing parser output.

By the end of this lab, you should be able to evaluate suspicious programs using execution-focused artifacts and explain, in disciplined language, what the evidence supports, what it only suggests, and what still needs corroboration.

---

## What This Lab Covers

This lab supports the following concepts from Section 6.1:

| Section | Topic |
|---|---|
| 6.1.1 | LNK (Shortcut) Files |
| 6.1.2 | Jump Lists |
| 6.1.3 | Prefetch |
| 6.1.4 | SRUM (System Resource Usage Monitor) |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain the difference between file presence and likely execution
- Identify the Windows artifacts most useful for execution analysis
- Distinguish stronger execution evidence from weaker contextual evidence
- Map execution questions to artifacts such as Prefetch, Amcache, UserAssist, Jump Lists, event logs, and related sources
- Recognize the limitations of each execution-related artifact
- Correlate multiple artifacts into a more defensible conclusion about program activity
- Write concise notes that clearly separate supported findings from inference

---

## Estimated Time

60–90 minutes

---

## Prerequisites

- Completion of Labs 01–05 and Lab 06, or equivalent familiarity with NTFS, Registry, shell artifacts, and general Windows IR workflow
- A text editor or markdown editor
- Your `lab06-notes.md` file
- Optional: a Windows VM where you can generate test executions
- Optional: access to tools such as PECmd, Amcache parsers, Registry Explorer, EvtxECmd, JLECmd, or similar analysis tools

---

## Scenario

You are continuing analysis of **FIN-WS23**. Earlier review identified several suspicious items:

- A possible executable under `C:\Users\j.smith\Downloads\`
- A batch script or command file under `C:\ProgramData\`
- Signs that PowerShell may have been involved in the incident
- User concerns about a document opened shortly before suspicious activity began

The SOC now wants a clearer answer:

> Which suspicious programs or files were likely executed, and how confident are we?

You are not expected to prove every action with absolute certainty. Your task is to determine what the available artifacts can say about likely execution, what they cannot prove, and which additional evidence you would want before escalating the conclusion.

---

## Background: Evidence of Execution Is Usually a Correlation Problem

Windows does not preserve a single universal "program ran" artifact. Responders usually work from a set of artifacts that each contribute part of the answer.

Examples include:

- **Prefetch** — often strong evidence that an executable ran
- **Amcache** — useful for executable metadata and execution-related context
- **UserAssist** — useful for GUI-driven launches
- **Jump Lists** — useful for application-file interaction
- **LNK files** — useful for accessed files and paths
- **Event logs** — useful where process creation logging or PowerShell logging is available
- **SRUM** — useful when network or resource usage by an application matters
- **Registry and startup artifacts** — useful for showing configuration that may have led to execution

Each artifact has strengths and limits.

| Artifact | What It Helps Answer |
|---|---|
| **Prefetch** | Did an executable likely run on this host? |
| **Amcache** | What executable existed, and is there execution-related context? |
| **UserAssist** | Did the user likely launch a program through the GUI? |
| **Jump Lists / LNK** | What file was likely opened, and by which application? |
| **Event logs** | Was process creation or script execution logged? |
| **SRUM** | Did an application show notable resource or network usage? |

> **IR Reality Check:** The best execution assessment usually comes from multiple artifacts lining up, not from one isolated row in one parser.

---

## Lab Tasks

---

### Task 1 — Define What Counts as Evidence of Execution

**Objective:** Build a practical understanding of what responders mean by "execution evidence."

Write a short explanation in 4–6 sentences covering:

- What "evidence of execution" means in Windows forensics
- Why file presence is weaker than execution evidence
- Why some artifacts support execution more strongly than others
- Why execution findings usually need cautious wording

```
[Your explanation here]
```

Then complete the table below.

| Statement | Strength as Execution Evidence | Why |
|---|---|---|
| A suspicious EXE exists in Downloads | | |
| Prefetch exists for that EXE | | |
| A Run key references that EXE | | |
| UserAssist contains an entry consistent with GUI launch | | |
| A Jump List references a document opened by Word | | |
| PowerShell 4104 logging shows a suspicious script block | | |

Use the ratings:

- Strong
- Moderate
- Weak
- Not execution evidence by itself

Then answer:

**1. Why is "file existed" not the same as "file ran"?**

```
[Your response here]
```

**2. Why is configuration evidence different from execution evidence?**

```
[Your response here]
```

**3. Why do responders need to describe confidence levels instead of speaking in absolutes too early?**

```
[Your response here]
```

---

### Task 2 — Identify the Best Execution Artifacts for Common Questions

**Objective:** Map execution questions to the artifacts most likely to answer them.

For each investigative question below, identify the best artifact or artifacts to review first.

| Investigative Question | Best Artifact(s) to Check First | Why |
|---|---|---|
| Did `tool.exe` likely execute on the host? | | |
| Did PowerShell likely run suspicious commands? | | |
| Did a user likely open a suspicious document in Word? | | |
| Was a batch file likely launched from ProgramData? | | |
| Did a suspicious process show network activity after execution? | | |
| Was a program launched through the GUI? | | |

Then write six additional execution-related questions of your own and map them the same way.

Afterward, answer:

**1. Why do different execution questions require different artifact combinations?**

```
[Your response here]
```

**2. Why is "best artifact" sometimes different for EXEs, scripts, and documents?**

```
[Your response here]
```

**3. Why can a missing artifact weaken, but not always eliminate, an execution theory?**

```
[Your response here]
```

---

### Task 3 — Review Prefetch as Execution Evidence

**Objective:** Use Prefetch as a high-value execution artifact without overstating what it proves.

Fill in the table below.

| Prefetch Question | What You Would Look For | Why It Matters | Limitation |
|---|---|---|---|
| Did the EXE likely run? | | | |
| How many times did it appear to run? | | | |
| When did it last run? | | | |
| What referenced files or paths appear relevant? | | | |

Then answer:

**1. Why is Prefetch often treated as one of the strongest execution artifacts for normal EXEs?**

```
[Your response here]
```

**2. Why does Prefetch still have limitations in forensic reporting?**

```
[Your response here]
```

**3. Why might a suspicious path referenced in Prefetch matter as much as the executable name itself?**

```
[Your response here]
```

Next, build a focused review table:

| Suspected Program | What Prefetch Finding Would Increase Concern | What Would Still Need Corroboration |
|---|---|---|
| `tool.exe` in Downloads | | |
| `powershell.exe` | | |
| `cmd.exe` | | |
| `7z.exe` or other archiver | | |

Add at least five more entries of your own.

---

### Task 4 — Review Amcache and UserAssist

**Objective:** Use execution-related artifacts that provide context beyond Prefetch.

Fill in the table below.

| Artifact | What It Can Reveal | Why It Matters | Limitation |
|---|---|---|---|
| Amcache | | | |
| UserAssist | | | |

Then answer:

**1. Why is Amcache useful in cases involving executables that may no longer be present?**

```
[Your response here]
```

**2. Why is UserAssist useful for user-driven launches but not a complete execution source?**

```
[Your response here]
```

**3. Why do Amcache and UserAssist become more valuable when correlated with Prefetch?**

```
[Your response here]
```

Afterward, create a working table:

| Suspected Program or Activity | Artifact to Check | What Finding Would Matter Most |
|---|---|---|
| GUI launch of suspicious EXE | | |
| Short-lived utility from Downloads | | |
| Installer or dropper execution | | |
| User-launched archive extraction tool | | |

Add at least six more entries of your own.

---

### Task 5 — Review Execution Clues in Event Logs and PowerShell Logging

**Objective:** Use logging-based artifacts to strengthen or challenge execution theories.

Assume some logging is available on FIN-WS23.

Fill in the table below.

| Log Source | What It May Reveal | Why It Matters | Limitation |
|---|---|---|---|
| Security process creation events | | | |
| PowerShell operational logs | | | |
| Script block logging | | | |
| Application logs | | | |
| EDR process telemetry | | | |

Add at least five more relevant log or telemetry sources of your own.

Then answer:

**1. Why can event logs be stronger than shell artifacts for some execution questions?**

```
[Your response here]
```

**2. Why are process creation events especially valuable when available?**

```
[Your response here]
```

**3. Why should a responder not assume missing logs mean no execution occurred?**

```
[Your response here]
```

---

### Task 6 — Correlate Execution Evidence Across Artifacts

**Objective:** Move from isolated findings to a defensible execution assessment.

Pick three suspicious programs, scripts, or files from the scenario and correlate what multiple artifacts suggest.

Use the table below.

| Program / File | Artifact 1 | Artifact 2 | Artifact 3 | Combined Interpretation | Confidence |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |
| | | | | | |

Possible artifacts may include:

- Prefetch
- Amcache
- UserAssist
- PowerShell logs
- Process creation logs
- Jump Lists
- LNK files
- SRUM
- EDR telemetry

Then answer:

**1. Why is three-artifact correlation often stronger than any one artifact alone?**

```
[Your response here]
```

**2. Why should you still document uncertainty even when several artifacts agree?**

```
[Your response here]
```

**3. Which combinations of artifacts would give you the most confidence for EXE execution? For script execution? For document opening?**

```
[Your response here]
```

---

### Task 7 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined wording around likely execution.

Classify each statement below as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by these artifacts alone

| Statement | Classification | Why |
|---|---|---|
| A suspicious executable likely ran on the host | | |
| The user intentionally launched the executable for malicious purposes | | |
| PowerShell executed content worthy of deeper review | | |
| A document was likely opened in Word | | |
| The opened document contained the initial malicious payload | | |
| A batch script was probably involved in startup or follow-on activity | | |
| The attacker used the executed tool for lateral movement | | |
| A suspicious archiver likely ran during the incident window | | |

Then write six additional statements of your own and classify them the same way.

> **Guidance:** This is the core discipline of execution analysis. Evidence that a program ran does not automatically tell you why, by whom, or with what result.

---

### Task 8 — Build an Execution-Focused Timeline

**Objective:** Turn execution artifacts into an ordered incident sequence.

Create a mini-timeline with at least 10 entries if possible.

| Time (UTC) | Artifact Source | Event or Observation | Program / File | Why It Matters |
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

- Document opening
- Prefetch-based execution indicators
- PowerShell activity
- Batch/script execution clues
- Resource or network use following execution
- Follow-on tools or archive utilities
- Supporting Jump List or LNK activity

Then answer:

**1. Which timeline entries appear most central to the likely incident sequence?**

```
[Your response here]
```

**2. Which entries are supportive but not decisive?**

```
[Your response here]
```

**3. What major gaps remain after the timeline is built?**

```
[Your response here]
```

---

### Task 9 — Write an Evidence of Execution Summary

**Objective:** Produce a concise working-note summary about likely execution on the host.

Write a 3–5 paragraph analyst summary describing what the execution-related artifacts suggest about activity on FIN-WS23.

Your summary should include:

- Which suspicious programs or files appear most likely to have executed
- Which artifacts support those conclusions
- Whether PowerShell, scripts, or user-opened documents appear relevant
- What is strongly supported by the evidence
- What still requires corroboration from other artifact classes

Write it as a working-note summary rather than a final incident conclusion.

---

### Task 10 — Write an Analyst Handoff Note

**Objective:** Make your execution findings easy for another responder to continue.

Use the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Most Important Execution Findings:
- 

Artifacts Providing the Strongest Support:
- 

What Is Strongly Supported:
- 

What Is Suggested but Not Confirmed:
- 

Recommended Next Artifacts:
1.
2.
3.

Open Questions:
- 

Notes for Incoming Analyst:
```

---

### Task 11 — Reflection

Answer the following in 3–5 sentences each.

**1. Why execution evidence matters**
Why is proving or disproving execution more valuable than simply finding suspicious files on disk?

```
[Your response here]
```

**2. Artifact strength differences**
Why are some artifacts stronger for execution analysis than others?

```
[Your response here]
```

**3. Confidence versus certainty**
Why should responders talk in terms of likelihood and support instead of absolute proof in many execution cases?

```
[Your response here]
```

**4. Correlation is the real answer**
Why are execution conclusions strongest when Prefetch, logs, user-activity artifacts, and other evidence agree?

```
[Your response here]
```

---

## Deliverables Checklist

Your `lab06-notes.md` should contain:

- [ ] **Task 1** — Execution-evidence explanation and strength ratings table
- [ ] **Task 2** — Question-to-artifact mapping with six added questions
- [ ] **Task 3** — Prefetch review table and focused program table
- [ ] **Task 4** — Amcache and UserAssist review plus expanded activity table
- [ ] **Task 5** — Event log and PowerShell logging table with added sources
- [ ] **Task 6** — Correlation table for three suspicious programs/files
- [ ] **Task 7** — Strong support vs overclaim exercise
- [ ] **Task 8** — Execution-focused timeline with at least 10 entries where possible
- [ ] **Task 9** — Evidence of execution summary
- [ ] **Task 10** — Analyst handoff note
- [ ] **Task 11** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab06/
├── lab06-notes.md  ← Your working notes file (whole lab)
└── Lab06_01/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **Execution matters more than presence.** A suspicious file on disk is only the start of the question.
- **No single artifact answers everything.** Prefetch, Amcache, logs, UserAssist, and other sources each contribute part of the answer.
- **Artifact strength varies by question.** What works best for an EXE may not work best for a script or document.
- **Discipline matters.** Evidence of likely execution does not automatically prove user intent, attacker control, or downstream impact.
- **Correlation is the strongest path.** Execution conclusions are most defensible when multiple artifacts point to the same sequence.

---

**Next:** Lab 6.2 — Shellbags

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
