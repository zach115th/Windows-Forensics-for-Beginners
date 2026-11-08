# Lab 5.1 — Registry Structure and Key Hives

**Supporting Section 5.1: Registry Structure and Key Hives**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

The Windows Registry is one of the most important evidence sources in Windows forensics because it preserves the system's memory of how it was configured and how users interacted with it.

The Registry often keeps durable context after files, processes, and temporary folders are gone. That context explains what the system was set up to do, which user hive belonged to whom, what software was installed, which devices were recognized, and where investigators should look next. For incident responders, understanding the Registry is foundational.

This lab introduces the Registry at the level responders actually need. You will work through the structure of the Registry, the difference between system-wide and user-specific hives, where those hives live on disk, and what kinds of incident-response questions each one helps answer. The goal is not to memorize every key path in Windows. It is to understand the Registry as a structured evidence source, so later labs on persistence, USB history, remote access, and cloud sync make sense.

By the end of this lab, you should be able to look at a set of Registry hives and understand right away what each one represents, whose activity it may reflect, and why it matters in an investigation.

---

## What This Lab Covers

This lab supports the following concepts from Section 5.1:

| Section | Topic |
|---|---|
| 5.1.1 | Hives and Where They Live |
| 5.1.2 | Keys, Values, and Last-Write Times |
| 5.1.3 | Per-Machine vs. Per-User |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain what the Windows Registry is in practical forensic terms
- Distinguish keys, subkeys, values, and value data
- Identify the major system hives and user hives relevant to incident response
- Recognize where Registry hives are typically stored on disk
- Explain the difference between machine-wide and user-specific Registry evidence
- Map common investigative questions to the most relevant hives
- Write concise notes about hive scope and forensic value

---

## Estimated Time

45–60 minutes

---

## Prerequisites

- Completion of Labs 01–04, or equivalent familiarity with Windows IR workflow and core artifact analysis
- A text editor or markdown editor
- Your `lab05-notes.md` file
- Optional: a Windows VM or image containing Registry hives
- Optional: a Registry viewer such as Registry Explorer or RECmd

---

## Scenario

Your team has collected a triage package from a Windows laptop named **HR-LT12**. The package includes several Registry hives, but a junior responder is unsure how to organize the analysis. They know the case may involve suspicious startup behavior, possible USB usage, and questions about whether OneDrive was configured on the host.

Before anyone starts hunting through keys, you need to answer a more basic question:

> Which hives matter, what do they represent, and what kinds of questions should each one answer?

In this lab, you build that foundation so later Registry analysis is structured, efficient, and defensible.

---

## Background: The Registry Is a Hierarchical Configuration Database

The Windows Registry is a hierarchical database that the operating system and applications use to store configuration and state information. For responders, it matters because it preserves both system-wide and user-specific evidence.

Registry analysis helps answer questions such as:

- What software and services were configured on this system?
- What user-specific activity or settings were present?
- Which devices were recognized by the host?
- Which applications or startup entries were configured to run?
- Which user profile does a given hive belong to?

The Registry is organized into keys and values rather than normal files and folders. The logic is similar enough that responders can think of it as structured data stored in hive files.

| Registry Concept | Practical Meaning |
|---|---|
| **Key** | Like a folder in a hierarchy |
| **Subkey** | A key nested under another key |
| **Value** | A named entry stored inside a key |
| **Value data** | The actual data associated with a value |
| **Hive** | A backing file that stores part of the Registry |
| **System hive** | Machine-wide configuration and state |
| **User hive** | Per-user configuration and activity |

> **IR Reality Check:** The Registry rarely gives you one magic answer. It gives you durable context that often survives after files are deleted and processes are gone.

---

## Lab Tasks

---

### Task 1 — Explain the Registry in Responder Terms

**Objective:** Build a practical, non-academic understanding of what the Registry is and why responders care.

Write a short explanation of the Windows Registry in 4–6 sentences.

Your explanation should address:

- What the Registry is
- What kinds of information it stores
- Why it matters in incident response
- Why it can still be useful even when files or processes are gone

Then answer the following in one or two sentences each:

1. Why is the Registry more useful than a simple list of installed files?

2. Why can Registry evidence still matter after attacker cleanup?

3. Why is Registry analysis often about context rather than one single "smoking gun"?

---

### Task 2 — Separate Keys, Values, and Data

**Objective:** Distinguish the structural pieces of the Registry clearly.

For each item below, identify whether it is a:

- Key
- Subkey
- Value name
- Value data
- Hive file

| Item | Classification | Why |
|---|---|---|
| `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | | |
| `Run` | | |
| `OneDrive` in a Run key entry | | |
| `"C:\Program Files\Microsoft OneDrive\OneDrive.exe /background"` | | |
| `NTUSER.DAT` | | |
| `HKEY_CURRENT_USER\Software\Microsoft` | | |
| `Start Page` in an application settings key | | |
| `https://example.org` stored in that value | | |
| `SYSTEM` | | |
| `USBSTOR` under a system path | | |

Then add five more examples of your own.

After that, answer:

1. Why is it important to distinguish a value name from its data?

2. Why can a suspicious path appear as value data rather than as part of a key path?

3. Why should responders record both the full path and the specific value when documenting findings?

---

### Task 3 — Identify the Major Registry Hives

**Objective:** Learn which hives matter most in Windows forensic investigations.

Fill in the table below.

| Hive | Scope | Typical Location | What It Commonly Helps Answer |
|---|---|---|---|
| **SYSTEM** | | | |
| **SOFTWARE** | | | |
| **SAM** | | | |
| **SECURITY** | | | |
| **NTUSER.DAT** | | | |
| **USRCLASS.DAT** | | | |

Then answer:

1. Which of these are primarily system-wide hives?

2. Which of these are primarily user-specific hives?

3. Why do responders often need both types to understand what happened on a host?

> **Guidance:** Keep your answers practical. Focus on the kinds of IR questions each hive helps with.

---

### Task 4 — Map Common IR Questions to the Right Hives

**Objective:** Build the habit of going to the right hive first.

For each investigative question below, identify the hive or hives you would check first.

| Investigative Question | Best Hive(s) to Check First | Why |
|---|---|---|
| Was a suspicious service configured on the system? | | |
| Was a USB storage device recognized by the host? | | |
| Did a specific user have a startup entry in their profile? | | |
| Was OneDrive configured for a user account? | | |
| What software appears to be installed system-wide? | | |
| Which user profile shows evidence of Explorer activity? | | |
| Is there evidence tied to user-specific application settings? | | |
| Was the host configured with machine-level startup behavior? | | |

Then write four additional questions of your own and map them the same way.

After that, answer:

1. Why does choosing the right hive first save time during an investigation?

2. Why can the wrong hive lead to incomplete or misleading conclusions?

3. Why is "check the Registry" too vague to be a useful analytic instruction?

---

### Task 5 — Understand Hive Provenance and User Context

**Objective:** Recognize why the source path and owning user matter when analyzing user hives.

Assume you collected the following files from a Windows system:

- `C:\Windows\System32\config\SYSTEM`
- `C:\Windows\System32\config\SOFTWARE`
- `C:\Users\j.smith\NTUSER.DAT`
- `C:\Users\j.smith\AppData\Local\Microsoft\Windows\USRCLASS.DAT`
- `C:\Users\a.lee\NTUSER.DAT`

For each one, identify:

- Whether it is system-wide or user-specific
- Which user it belongs to, if applicable
- What mistakes an analyst might make if they ignore provenance

Use the table below.

| Hive Path | System or User Hive? | User Context | Why Provenance Matters |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |

Then answer:

1. Why is `C:\Users\j.smith\NTUSER.DAT` fundamentally different from SOFTWARE in evidentiary meaning?

2. Why can multiple NTUSER.DAT files on one system matter?

3. Why should you document the exact path the hive came from in your notes?

---

### Task 6 — Build a Hive-Centered Investigation Plan

**Objective:** Turn Registry structure knowledge into an actionable analysis plan.

Using the HR-LT12 scenario, assume you need to answer these case themes:

- Possible persistence
- Possible USB usage
- Possible OneDrive configuration
- Possible user activity related to suspicious files

For each theme, identify:

- Which hive or hives you would review first
- What kinds of keys or data you would expect to find there
- What the limitations of that hive would be

Use the table below.

| Investigation Theme | First Hive(s) to Review | What You Hope to Find | What That Hive Cannot Tell You by Itself |
|---|---|---|---|
| Persistence | | | |
| USB usage | | | |
| OneDrive configuration | | | |
| User activity | | | |

Then answer:

1. Why is a hive-centered plan better than just browsing randomly through keys?

2. Why should your plan reflect the investigative question rather than the order the hives were collected?

3. Why is it useful to think about limitations before you even start parsing?

---

### Task 7 — Separate Strongly Supported Registry Scope from Overclaims

**Objective:** Practice staying within what hive structure and scope actually support.

Read the statements below and classify each as:

- Strongly supported
- Suggested but needs more analysis
- Not supported by hive structure alone

| Statement | Classification | Why |
|---|---|---|
| `C:\Users\j.smith\NTUSER.DAT` is a user-specific Registry hive tied to j.smith | | |
| A value under HKCU reflects system-wide behavior for all users | | |
| The SYSTEM hive may contain evidence relevant to services and hardware recognition | | |
| Because a Run key exists in a user hive, malware definitely executed | | |
| USRCLASS.DAT may contain user-shell-related context worth reviewing | | |
| A user hive by itself proves the user intentionally performed every recorded action | | |

Then write four additional statements of your own and classify them the same way.

> **Guidance:** This lab is about structure and scope. Stay disciplined about what hive identity tells you versus what later key-level analysis might show.

---

### Task 8 — Write a Short Registry Orientation Note

**Objective:** Produce a concise note that would help another responder start Registry analysis correctly.

Write a 1–2 paragraph analyst note for HR-LT12 explaining:

- Which hives were collected
- Which are system hives versus user hives
- Which hives are most relevant to the suspected issues in this case
- Why user context matters before interpreting findings

Write it as an internal case note another analyst could use before beginning key-level review.

---

### Task 9 — Reflection

Answer the following in 3–5 sentences each.

**1. Why Registry structure matters**
Why is understanding hive structure and scope important before looking for specific keys?

**2. System-wide versus user-specific evidence**
Why can it be dangerous to confuse system hives with user hives during an investigation?

**3. Provenance as evidence**
Why does the source path of a hive matter just as much as the contents inside it?

**4. Foundation before detail**
Why is it worth learning Registry basics carefully before diving into persistence keys, USB history, and cloud-client artifacts?

---

## Deliverables Checklist

Your `lab05-notes.md` should contain:

- [ ] **Task 1** — Responder-focused explanation of the Registry plus short written responses
- [ ] **Task 2** — Keys/values/data classification table with five added examples
- [ ] **Task 3** — Major hive table with written responses
- [ ] **Task 4** — IR-question-to-hive mapping with four added questions
- [ ] **Task 5** — Hive provenance table with written responses
- [ ] **Task 6** — Hive-centered investigation plan
- [ ] **Task 7** — Strongly supported vs overclaim exercise
- [ ] **Task 8** — Short Registry orientation note
- [ ] **Task 9** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab05/
├── lab05-notes.md  ← Your working notes file (whole lab)
└── Lab05_01/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **The Registry is structured evidence.** Understanding keys, values, data, and hives makes later analysis more accurate.
- **Hive scope matters.** System hives and user hives answer different questions and should not be conflated.
- **Provenance matters.** Where a hive came from and which user it belongs to can change the meaning of a finding.
- **Registry analysis starts with the right hive.** Good investigations map questions to the correct evidence source first.
- **Foundation improves speed and defensibility.** The better you understand Registry structure, the better your later persistence, USB, and cloud-storage analysis will be.

---

**Next:** Lab 5.2 — Important Keys for IR

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
