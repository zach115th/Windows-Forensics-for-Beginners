# Lab 6.3 — UserAssist and Amcache

**Supporting Section 6.3: UserAssist and Amcache**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

UserAssist and Amcache sit in a useful middle ground between artifacts that tell you what existed and artifacts that help tell you what likely happened.

UserAssist helps you assess whether a user launched a program through the Windows graphical interface. Amcache preserves information about executables and other application entries that existed on the system, often including paths, metadata, and execution-relevant context. Neither artifact tells the whole story alone. Together, they help answer a core incident response question:

> Was this program likely interacted with or executed on this host, and what context supports that conclusion?

In this lab, you work through what each artifact can reveal, where each is strong and weak, and how to correlate them with Prefetch, logs, shell artifacts, and NTFS findings without overstating what they prove.

The goal is to use UserAssist and Amcache as part of a disciplined execution and user-activity assessment, not to memorize parser output.

---

## What This Lab Covers

This lab supports the following concepts from Section 6.3:

| Section | Topic |
|---|---|
| 6.3.1 | What UserAssist reveals about GUI-driven interaction |
| 6.3.2 | What Amcache reveals about executables and application context |
| 6.3.3 | The strengths and limits of each artifact |
| 6.3 | Correlating UserAssist and Amcache in IR |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain what UserAssist and Amcache are in practical forensic terms
- Distinguish user interaction evidence from broader execution evidence
- Identify when UserAssist is helpful and when it is not
- Identify when Amcache is helpful and when it is not
- Correlate UserAssist and Amcache with Prefetch, logs, LNK files, and NTFS artifacts
- Separate strongly supported findings from plausible but unproven conclusions
- Write concise, defensible notes about likely program interaction and execution context

---

## Estimated Time

60–90 minutes

---

## Prerequisites

- Completion of Labs 01–05, Lab 06, Lab 6.1, and Lab 6.2, or equivalent familiarity with Windows IR workflow, execution analysis, shell artifacts, and Registry structure
- A text editor or markdown editor
- Your `lab06-notes.md` file
- Optional: a Windows VM where you can generate program-launch activity
- Optional: access to Registry and execution-artifact tools such as Registry Explorer, RECmd, Amcache parsers, or similar utilities

---

## Scenario

You are continuing analysis of **FIN-WS23**. Earlier work identified several suspicious items and possible execution clues:

- A suspicious executable may have been present in `C:\Users\j.smith\Downloads\`
- A script or batch file may have existed in `C:\ProgramData\`
- PowerShell activity remains part of the broader case theory
- Sensitive documents may have been opened shortly before suspicious behavior
- Management wants clearer answers on likely user interaction versus likely program execution

The team now wants to know:

> Which artifacts suggest the user likely launched something through the GUI, and which artifacts suggest executable presence or broader execution context?

Use UserAssist and Amcache to clarify that distinction and integrate the results into the case.

---

## Background: UserAssist and Amcache Answer Different Parts of the Story

UserAssist and Amcache are often discussed together, but they are not interchangeable.

UserAssist is stored in the user hive. It is most useful for assessing whether a user launched applications through the Windows shell or graphical interface, so it is most valuable when the question is about user behavior.

Amcache is a system-level, execution-related artifact. It can preserve information about executables and application entries even after the files are removed from normal view. Use it for executable metadata, path context, and evidence that a program was present and relevant to activity on the host.

| Artifact | Common IR Use |
|---|---|
| **UserAssist** | GUI-driven user interaction with programs |
| **Amcache** | Executable presence and execution-related application context |
| **Prefetch** | Stronger evidence that an executable likely ran |
| **Logs / EDR telemetry** | Process creation, script execution, and timing |
| **LNK / Jump Lists** | File access and application association |

> **IR Reality Check:** UserAssist is often strongest for "the user likely launched this through the GUI." Amcache is often strongest for "this executable existed on the system and is relevant to execution analysis." Do not treat either one as a complete answer alone.

---

## Lab Tasks

---

### Task 1 — Define What UserAssist and Amcache Can and Cannot Tell You

**Objective:** Build a practical understanding of the strengths and limits of each artifact.

Write a short explanation in 4–6 sentences covering:

- What UserAssist is
- What Amcache is
- Why responders use them
- How they differ from each other
- What they do not prove by themselves

```
[Your explanation here]
```

Then complete the table below.

| Investigative Question | UserAssist Value | Amcache Value | Why |
|---|---|---|---|
| Did the user likely launch a program through the GUI? | | | |
| Did an executable likely exist on the host? | | | |
| Did a script definitely run? | | | |
| Was a suspicious EXE relevant to the incident timeline? | | | |
| Did a file definitely execute from a command line or service context? | | | |
| Was a program interacted with by a specific user profile? | | | |

Use the ratings:

- Strongly useful
- Partially useful
- Not very useful

Then answer:

**1. Why is UserAssist more user-behavior oriented than Amcache?**

```
[Your response here]
```

**2. Why is Amcache useful even when a suspicious file is no longer present?**

```
[Your response here]
```

**3. Why should neither artifact be treated as final proof on its own?**

```
[Your response here]
```

---

### Task 2 — Review UserAssist as a User-Interaction Artifact

**Objective:** Use UserAssist to assess likely GUI-driven program launches.

Fill in the table below.

| UserAssist Question | What You Would Look For | Why It Matters | Limitation |
|---|---|---|---|
| Was a suspicious program likely launched by the user? | | | |
| Was the launch associated with the affected user profile? | | | |
| Did a common Windows utility appear in suspicious context? | | | |
| Did activity cluster around the incident window? | | | |

Then answer:

**1. Why is UserAssist especially helpful when investigating user-driven execution?**

```
[Your response here]
```

**2. Why is UserAssist weaker for service-based, scheduled, or background execution?**

```
[Your response here]
```

**3. Why is user-hive provenance especially important when interpreting UserAssist?**

```
[Your response here]
```

Next, build a focused review table:

| Suspected Program or Activity | Why UserAssist Might Matter | What Finding Would Increase Concern |
|---|---|---|
| Suspicious EXE in Downloads | | |
| PowerShell launched from user context | | |
| Archive extractor or file utility | | |
| Script host or command shell | | |

Add at least six more entries of your own.

---

### Task 3 — Review Amcache as Executable Context Evidence

**Objective:** Use Amcache to assess suspicious executables and application-related context.

Fill in the table below.

| Amcache Question | What You Would Look For | Why It Matters | Limitation |
|---|---|---|---|
| Did a suspicious executable exist on the host? | | | |
| What path was associated with the executable? | | | |
| Is there useful metadata for the file or program entry? | | | |
| Does the artifact strengthen the case that the executable is incident-relevant? | | | |

Then answer:

**1. Why is path context often one of the most important Amcache findings?**

```
[Your response here]
```

**2. Why is Amcache useful when investigating deleted or short-lived tools?**

```
[Your response here]
```

**3. Why is Amcache still not the same as direct proof of execution timing?**

```
[Your response here]
```

Afterward, create a working table:

| Suspected Program | Why Amcache Review Matters | What Finding Would Increase Concern |
|---|---|---|
| `tool.exe` in Downloads | | |
| `runme.bat` or related launcher | | |
| `powershell.exe` in suspicious context | | |
| Archiver, dropper, or unpacking utility | | |

Add at least six more entries of your own.

---

### Task 4 — Compare UserAssist and Amcache Directly

**Objective:** Learn when each artifact is the better fit for the question.

Complete the table below.

| Question Type | Better Artifact to Check First | Why |
|---|---|---|
| Did the user likely launch a program through Explorer? | | |
| Did a suspicious executable exist on the host? | | |
| Is this tied to a specific user profile? | | |
| Is the suspicious path incident-relevant? | | |
| Was a background persistence mechanism involved? | | |
| Did a file likely execute during the same window as other suspicious artifacts? | | |

Then answer:

**1. Why is "which artifact is better" a more useful question than asking which artifact is "best overall"?**

```
[Your response here]
```

**2. Why can these artifacts complement each other instead of compete?**

```
[Your response here]
```

**3. Why does the case question need to drive the artifact choice?**

```
[Your response here]
```

---

### Task 5 — Correlate UserAssist and Amcache with Other Execution Artifacts

**Objective:** Build a defensible execution and interaction theory using multiple sources.

Choose three suspicious programs, scripts, or activities and correlate UserAssist or Amcache with other artifacts.

Use the table below.

| Program / Activity | UserAssist Finding | Amcache Finding | Corroborating Artifact | Combined Interpretation | Confidence |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |
| | | | | | |

Possible corroborating artifacts include:

- Prefetch
- Process creation logs
- PowerShell logs
- LNK files
- Jump Lists
- RecentDocs
- SRUM
- NTFS file evidence
- EDR telemetry

Then answer:

**1. Why is UserAssist + Prefetch a strong combination for suspected user-launched execution?**

```
[Your response here]
```

**2. Why is Amcache + NTFS often useful for deleted or staged tools?**

```
[Your response here]
```

**3. Why should even multi-artifact correlation still be reported carefully?**

```
[Your response here]
```

---

### Task 6 — Evaluate Competing Interpretations

**Objective:** Avoid overconfidence by considering alternate explanations.

Choose two findings involving UserAssist or Amcache and write:

- One suspicious interpretation
- One benign or less certain interpretation

Use the table below.

| Finding | Suspicious Interpretation | Benign / Alternate Interpretation | Which Is Better Supported? | Why |
|---|---|---|---|---|
| | | | | |
| | | | | |

Then answer:

**1. Why can normal user behavior produce UserAssist entries that look alarming out of context?**

```
[Your response here]
```

**2. Why can legitimate software create Amcache entries that still deserve review?**

```
[Your response here]
```

**3. Why is alternate-explanation analysis important before escalating a case theory?**

```
[Your response here]
```

---

### Task 7 — Separate Strong Findings from Overclaims

**Objective:** Practice disciplined reporting based on UserAssist and Amcache.

Classify each statement below as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by these artifacts alone

| Statement | Classification | Why |
|---|---|---|
| The affected user likely launched a program through the GUI | | |
| A suspicious executable existed on the host and deserves deeper review | | |
| The suspicious executable definitely executed through a user click | | |
| The user intentionally launched malware | | |
| A suspicious program path is incident-relevant | | |
| The executable was used by the attacker for persistence | | |
| UserAssist supports likely user interaction with a program | | |
| Amcache supports the presence of a suspicious executable on the host | | |

Then write six additional statements of your own and classify them the same way.

> **Guidance:** These artifacts are useful precisely because they help narrow possibilities. Do not convert that value into false certainty.

---

### Task 8 — Build a UserAssist and Amcache Timeline

**Objective:** Turn interaction and executable-context findings into a usable sequence.

Create a mini-timeline with at least ten entries if possible.

| Time (UTC) | Artifact Source | Event or Observation | Program / Path | Why It Matters |
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

- UserAssist-based interaction clues
- Amcache-based executable context
- Prefetch alignment
- PowerShell or process-creation logging
- LNK or Jump List support
- NTFS path or deletion context
- Time clustering around suspicious user activity

Then answer:

**1. Which entries appear most central to the case theory?**

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

### Task 9 — Write a UserAssist and Amcache Findings Summary

**Objective:** Produce a concise working-note summary suitable for the case file.

Write a 3–5 paragraph analyst summary describing what UserAssist and Amcache suggest about activity on FIN-WS23.

Your summary should include:

- Which suspicious programs or paths stand out most
- Whether there is evidence of likely user-driven interaction
- Whether there is evidence of executable presence or broader execution-related context
- What is strongly supported by the artifacts
- What still requires corroboration from Prefetch, logs, NTFS, shell artifacts, or other sources

Write it as a working-note summary, not a final incident conclusion.

---

### Task 10 — Write an Analyst Handoff Note

**Objective:** Make your findings easy for another responder to continue.

Use the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Most Important UserAssist Findings:
- 

Most Important Amcache Findings:
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

**1. Why these artifacts matter**
Why are UserAssist and Amcache valuable even though neither one is a universal execution artifact?

```
[Your response here]
```

**2. User behavior versus executable context**
Why is it useful to separate likely user interaction from broader executable presence?

```
[Your response here]
```

**3. Confidence and caution**
Why should responders avoid claiming too much from UserAssist or Amcache alone?

```
[Your response here]
```

**4. Correlation is the real strength**
Why do these artifacts become more valuable when paired with Prefetch, logs, NTFS, and shell evidence?

```
[Your response here]
```

---

## Deliverables Checklist

Your `lab06-notes.md` should contain:

- [ ] **Task 1** — UserAssist and Amcache explanation with usefulness ratings table
- [ ] **Task 2** — UserAssist review table and expanded suspicious-activity table
- [ ] **Task 3** — Amcache review table and expanded suspicious-program table
- [ ] **Task 4** — Direct comparison table for UserAssist vs Amcache
- [ ] **Task 5** — Correlation table for three suspicious programs or activities
- [ ] **Task 6** — Competing-interpretation analysis for two findings
- [ ] **Task 7** — Strong support vs overclaim exercise
- [ ] **Task 8** — UserAssist and Amcache timeline with at least 10 entries where possible
- [ ] **Task 9** — Findings summary
- [ ] **Task 10** — Analyst handoff note
- [ ] **Task 11** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab06/
├── lab06-notes.md  ← Your working notes file (whole lab)
└── Lab06_03/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **UserAssist and Amcache answer different questions.** One is stronger for likely GUI-driven interaction. The other is stronger for executable presence and context.
- **Neither artifact is enough alone.** Their strength comes from what they add to a broader execution and user-activity picture.
- **Path and user context matter.** A suspicious path or a specific user hive can change the meaning of a finding.
- **Discipline matters.** Likely interaction or executable presence is not the same as proven attacker use, intent, or impact.
- **Correlation creates confidence.** Prefetch, logs, NTFS, shell artifacts, and Registry data make these artifacts more defensible and useful.

---

**Next:** Lab 6.4 — Browser, Email, and Search Index

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
