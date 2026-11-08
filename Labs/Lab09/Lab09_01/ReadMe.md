# Lab 9.1 — Log Types

**Supporting Section 9.1: Log Types**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Windows event logging is not one thing. It is a collection of log families that answer different kinds of incident-response questions.

A responder who looks only at the Security log may miss PowerShell execution, Defender detections, or Task Scheduler activity. One who looks only at application-specific logs may miss authentication events, service activity, or system changes. Good Windows log analysis starts with a basic but critical question:

> Which log type is most likely to answer the question I am asking right now?

This lab focuses on the main Windows log types introduced in Chapter 9:

- Security
- System
- Application
- Microsoft-Windows Operational logs

Before building filters or hunt packs, you need to know what each log contains. This lab covers what each log family is for, what kinds of activity it commonly records, why it matters in incident response, and where its limits begin.

By the end of this lab, you should be able to look at a Windows logging question and identify the most relevant log types to check first.

---

## What This Lab Covers

This lab supports the following concepts from Section 9.1:

| Section | Topic |
|---|---|
| 9.1.1 | Security log |
| 9.1.2 | System log |
| 9.1.3 | Application log |
| 9.1.4 | PowerShell Operational log |
| 9.1.5 | Other high-value Operational logs |
| 9.1.6 | Public EVTX datasets for practice |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain the role of the major Windows log types in incident response
- Distinguish Security, System, Application, and Operational logs in practical terms
- Identify the kinds of events each log type commonly contains
- Map common IR questions to the log family most likely to answer them
- Recognize why some event data lives in Operational logs instead of the main Application log
- Describe the limitations of each log family in an investigation
- Write concise notes about log scope and investigative value

---

## Estimated Time

40–55 minutes

---

## Prerequisites

- Completion of Labs 01–08, or equivalent familiarity with Windows IR workflow and core Windows artifacts
- A text editor or markdown editor
- Your `lab09-notes.md` file
- Optional: a Windows lab VM with Event Viewer access
- Optional: exported `.evtx` files from Security, System, Application, and relevant Operational logs

---

## Scenario

Your team has collected several Windows event logs from a workstation named **FIN-WS23** after suspicious activity was reported. A junior responder asks where to start.

The case may involve:

- Failed and successful logons
- PowerShell activity
- Possible scheduled task creation
- Service-related changes
- Defender detections
- Application errors or warnings tied to suspicious timing

Before building searches or analyzing event IDs, you need to answer a more basic question:

> Which log family is supposed to answer which part of this case?

Your task in this lab is to build that foundation.

---

## Background: Not All Windows Logs Answer the Same Questions

Windows event logs are structured by purpose. Some logs are broad and high-volume. Others are narrower but highly valuable when enabled.

At a practical level:

| Log Type | Common Role in IR |
|---|---|
| Security | Authentication, privilege use, account activity, object access where configured |
| System | Service state, driver issues, startup/shutdown, system-level operational changes |
| Application | Application-generated warnings, errors, and custom app events |
| Microsoft-Windows Operational logs | Feature-specific visibility such as PowerShell, Task Scheduler, Defender, and other focused telemetry |

The wrong log choice can waste time or create false confidence.

A responder asking "did PowerShell run suspicious code?" should not begin in the generic Application log if PowerShell Operational logging is available. A responder asking "was there a service installed?" may get more value from System and service-related logs than from Security alone.

> **IR Reality Check:** "Check the logs" is too vague to be useful. Good responders know which log family to check first and why.

---

## Lab Tasks

---

### Task 1 — Define the Major Log Types in Your Own Words

**Objective:** Build a practical responder-focused understanding of the main Windows log families.

Write a short explanation in 4–6 sentences covering:

- What Windows event log types are
- Why different logs exist for different purposes
- Why incident responders should not treat all logs as interchangeable
- Why Operational logs often matter more than beginners expect

Then answer the following in one or two sentences each:

1. Why is "Windows logs" too vague to be a useful analytic category?

2. Why can the same incident require multiple log families?

3. Why is understanding log scope important before hunting event IDs?

---

### Task 2 — Identify What Each Log Family Commonly Contains

**Objective:** Map the core log families to the kinds of events they usually hold.

Fill in the table below.

| Log Type | What It Commonly Contains | Why It Matters in IR | Common Limitation |
|---|---|---|---|
| Security | | | |
| System | | | |
| Application | | | |
| Microsoft-Windows-PowerShell / Operational | | | |
| Microsoft-Windows-TaskScheduler / Operational | | | |
| Microsoft-Windows-Windows Defender / Operational | | | |

Then answer:

1. Why is the Security log often treated as high-value but still incomplete?

2. Why can System logs matter even when the case seems user-driven?

3. Why are Operational logs often the best place for feature-specific hunting?

---

### Task 3 — Map IR Questions to the Right Log Type

**Objective:** Practice going from the case question to the best log family.

For each investigative question below, identify the best log type or log types to check first.

| Investigative Question | Best Log Type(s) to Check First | Why |
|---|---|---|
| Were there repeated failed logons followed by a success? | | |
| Was a service created or started? | | |
| Did PowerShell run suspicious script content? | | |
| Was a scheduled task created or modified? | | |
| Did Defender record a detection or action? | | |
| Did an application crash or log suspicious warnings? | | |
| Was there remote logon activity? | | |
| Did system drivers or boot behavior change unexpectedly? | | |

Then write six additional questions of your own and map them the same way.

Afterward, answer:

1. Why does choosing the right log first save time during incident response?

2. Why can the wrong log create a misleading sense that "nothing happened"?

3. Why should responders document which logs they checked and why?

---

### Task 4 — Compare Security, System, and Application Logs

**Objective:** Distinguish the three classic log families in practical investigative terms.

Complete the table below.

| Log Family | Best For | Weakness | Example IR Use |
|---|---|---|---|
| Security | | | |
| System | | | |
| Application | | | |

Then answer:

1. Why is Security often central for authentication questions?

2. Why is System often central for services, drivers, and system-state questions?

3. Why is Application often the least predictable of the three from an IR perspective?

---

### Task 5 — Understand Why Operational Logs Matter

**Objective:** Recognize why focused Microsoft-Windows logs are often more useful than generic logs.

For each Operational log area below, explain what it is especially useful for.

| Operational Log | What It Helps Answer | Why It Matters |
|---|---|---|
| PowerShell Operational | | |
| Task Scheduler Operational | | |
| Windows Defender Operational | | |
| Other Microsoft-Windows feature-specific logs | | |

Add at least four more Operational log categories of your own.

Then answer:

1. Why is PowerShell Operational logging often more useful than Application logging for script investigations?

2. Why is Task Scheduler Operational logging important in persistence cases?

3. Why can Operational logs be high-value even when they are narrower than Security or System?

---

### Task 6 — Evaluate Log-Type Limitations

**Objective:** Practice recognizing what each log family might miss.

Fill in the table below.

| Log Type | What It Can Miss | Why That Matters |
|---|---|---|
| Security | | |
| System | | |
| Application | | |
| Operational logs | | |

Then answer:

1. Why is the absence of a useful event not always evidence that the activity never happened?

2. Why do logging configuration and retention change how much trust you can place in each log?

3. Why should responders think about limitations before building strong conclusions?

---

### Task 7 — Build a Log-Selection Plan for the Scenario

**Objective:** Turn log-type knowledge into a practical first-pass IR workflow.

For the FIN-WS23 scenario, create a first-pass log-selection plan.

Use the table below.

| Priority | Question to Answer | Log Type(s) to Check First | Why This Comes First |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |
| 6 | | | |

Then answer:

1. Why did you choose this order?

2. Which log family would you prioritize first for authentication-driven suspicion?

3. Which log family would you prioritize first for script-driven suspicion?

---

### Task 8 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined reporting about log-type value and scope.

Classify each statement below as:

- Strongly supported
- Suggested but needs more context
- Not supported by log type alone

| Statement | Classification | Why |
|---|---|---|
| Security logs are often useful for logon analysis | | |
| System logs may help show service or driver-related changes | | |
| PowerShell Operational logs can be high-value in script investigations | | |
| Application logs always contain the most important evidence in every case | | |
| If Security has no suspicious events, the host was definitely not compromised | | |
| Operational logs can provide feature-specific visibility that broad logs miss | | |
| A log family's value depends on the question you are asking | | |
| One log family alone usually explains the full incident | | |

Then write five additional statements of your own and classify them the same way.

> **Guidance:** This lab is about understanding log-family value, not claiming that one log automatically proves everything.

---

### Task 9 — Write a Short "Log Types" Analyst Note

**Objective:** Produce a concise working note that helps another responder start in the right place.

Write a 2–4 paragraph analyst summary describing:

- Which Windows log families matter most for the FIN-WS23 scenario
- What kinds of questions each one is best suited to answer
- Why Operational logs deserve special attention
- What limitations you would keep in mind before drawing conclusions

Write it as an internal case note.

---

### Task 10 — Reflection

Answer the following in 3–5 sentences each.

**1. Why log types matter**
Why is it important to understand the role of each Windows log family before hunting event IDs or building filters?

**2. Broad logs versus focused logs**
Why can Operational logs sometimes outperform broader logs like Application or even Security for a narrow IR question?

**3. Limits of absence**
Why should responders be careful when interpreting a lack of suspicious entries in one log family?

**4. Question-driven log selection**
Why does good IR depend on matching the investigative question to the right log type first?

---

## Deliverables Checklist

Your `lab09-notes.md` should contain:

- [ ] **Task 1** — Responder-focused explanation of log types plus short written responses
- [ ] **Task 2** — Log-family contents table with written responses
- [ ] **Task 3** — IR-question-to-log mapping with six added questions
- [ ] **Task 4** — Security/System/Application comparison table
- [ ] **Task 5** — Operational-log importance table with four added categories
- [ ] **Task 6** — Log-type limitation table with written responses
- [ ] **Task 7** — Scenario-based log-selection plan
- [ ] **Task 8** — Strong support vs overclaim exercise
- [ ] **Task 9** — "Log Types" analyst note
- [ ] **Task 10** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab09/
├── lab09-notes.md  ← Your working notes file (whole lab)
└── Lab09_01/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **Windows logs are not one thing.** Security, System, Application, and Operational logs answer different kinds of questions.
- **Question-driven log selection saves time.** Good responders start with the log family most likely to answer the actual IR question.
- **Operational logs are often high-value.** They provide feature-specific visibility that broader logs may not expose clearly.
- **Absence is not certainty.** Retention, configuration, and log scope all affect what you do and do not see.
- **Understanding log types improves every later step.** Good filtering, hunting, and reporting all depend on knowing which logs matter first.

---

**Next:** Lab 9.2 — Challenges

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
