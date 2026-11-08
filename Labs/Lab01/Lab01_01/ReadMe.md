# Lab 1.1 — What is Digital Forensics?

**Supporting Section 1.1: What is Digital Forensics?**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Digital forensics is the structured process of identifying, collecting, preserving, analyzing, and reporting digital evidence so that others can trust the findings.

In an incident response context, forensics is about answering specific questions with evidence, not just finding bad things:

- *What happened?*
- *When did it happen?*
- *How did it happen?*
- *Which systems or accounts were involved?*
- *What evidence supports that conclusion?*

This lab builds the mindset and workflow discipline that underlie every hands-on lab in this book. Before you parse an MFT record or carve memory, you need to think like a forensic analyst: structured, evidence-driven, and disciplined about documentation.

---

## Learning Objectives

By completing this lab, you will be able to:

- Define digital forensics in practical, IR-relevant terms
- Describe the major phases of a forensic process and how they interact in real incidents
- Distinguish evidence-based analysis from assumption-driven troubleshooting
- Formulate structured investigative questions from a vague incident report
- Map investigative questions to specific evidence sources
- Write a basic analyst note that opens a documented investigation

---

## Estimated Time

20–30 minutes

---

## Prerequisites

No specialized tooling is required for this lab. You will need:

- A text editor or markdown editor
- A file to record your notes (`lab1.1-notes.md` works fine)
- Basic familiarity with Windows systems

---

## Background: The Five Phases of Digital Forensics

Most forensic frameworks describe five core phases. In textbooks these look sequential. In IR they rarely are. You'll often collect and analyze simultaneously, then loop back to collect more once a new question surfaces.

| Phase | What it means in IR |
|---|---|
| **Identification** | Which systems, accounts, logs, and data sources are relevant to the incident? |
| **Collection** | Acquire the relevant evidence in a controlled, documented way |
| **Preservation** | Protect evidence integrity: hash it, control access, avoid unnecessary modification |
| **Analysis** | Examine the evidence to answer specific investigative questions |
| **Reporting** | Explain what happened, what evidence supports it, and what it means for the organization |

> **IR Reality Check:** The phases are a mental model, not a rigid sequence. In a fast-moving incident you may be identifying new systems, collecting from others, and analyzing a third set all at the same time. Documentation stays constant: record what you did, when, and why, regardless of which phase you think you're in.

---

## Lab Tasks

---

### Task 1 — Define Digital Forensics in Your Own Words

**Objective:** Internalize the definition before moving into artifact analysis.

Write a short paragraph (5–8 sentences) that answers:

1. What is digital forensics?
2. Why does it matter specifically in incident response?
3. Why is documentation non-negotiable?

Write this in your own words. Don't copy the chapter or this README. The goal is to make sure the concept has actually landed before you start analyzing artifacts.

Record your response in `lab1.1-notes.md` under the heading `## Task 1 — My Definition`.

---

### Task 2 — Forensics vs. IT Troubleshooting

**Objective:** Understand why forensic analysis requires a different mindset than normal IT work.

Both IT troubleshooting and digital forensics involve investigating a problem on a Windows system. The difference in *intent* changes everything about how you proceed.

Complete the comparison table below with at least **seven rows**. Five are provided as examples. Add at least two more that reflect your own thinking.

| Topic | IT Troubleshooting | Digital Forensics |
|---|---|---|
| Primary goal | Restore service as quickly as possible | Preserve and interpret evidence |
| System changes | Often immediate; whatever fixes the problem | Minimized, controlled, and fully documented |
| Output | A fix, workaround, or patch | Evidence-based findings with supporting documentation |
| Success metric | Is the system working again? | Can I prove what happened with verifiable evidence? |
| Reboots and patches | Common first response | May destroy volatile evidence; requires deliberate decision |
| *(Add your own)* | | |
| *(Add your own)* | | |

> **Discussion prompt:** Think of a time you (or someone you know) troubleshot a Windows problem by rebooting, reinstalling, or wiping a machine. What forensic evidence would have been lost? Would it have mattered?

---

### Task 3 — Formulate Investigative Questions

**Objective:** Shift from vague suspicion to structured investigation.

**Scenario:** A user calls the help desk and says their Windows workstation "has been acting weird for the past few days." IT noticed some unusual outbound traffic in the firewall logs. You've been asked to determine whether the system is compromised.

You don't have any artifacts yet. Your first job is to decide what you're actually trying to find out.

Write at least **eight investigative questions** you would want to answer. Be specific. "Was something bad happening" is not a useful forensic question. "Was there an interactive logon to this system outside of business hours in the past 14 days?" is.

Use this format:

```
1. Was there unauthorized interactive or remote logon activity on this system?
2. Is a malicious process currently running or has one run recently?
3. ...
```

> **Why this matters:** Forensic analysis without prior questions is just browsing. Articulating your questions first keeps the investigation focused, makes your analysis defensible, and tells you when you're done.

---

### Task 4 — Map Questions to Evidence Sources

**Objective:** Connect investigative questions to the Windows artifacts that can answer them.

For each question from Task 3, identify one or more evidence sources that could help answer it. Use the examples below as a starting point.

| Investigative Question | Possible Evidence Sources |
|---|---|
| Was there an unauthorized interactive logon? | Security.evtx (Event ID 4624, 4625), RDP logs, EDR telemetry |
| Did a suspicious executable run? | Prefetch, Amcache, UserAssist, ShimCache |
| Was data accessed, moved, or deleted? | MFT, USN Journal, LNK files, Jump Lists |
| Was data exfiltrated? | SRUM (network usage), browser history, cloud sync logs, firewall logs |
| Was persistence established? | Registry Run keys, services, scheduled tasks, Startup folder |
| Was a tool downloaded? | Browser history, MFT timestamps, Zone.Identifier alternate data streams |
| Was there lateral movement from this host? | Security.evtx (4648, 4776), NTLM logs, Prefetch, network connections |
| *(Your questions from Task 3)* | |

Complete the table for all eight of your questions. If you're unsure of the right artifact, make your best guess and note it. You'll learn the correct answer as you progress through the book.

---

### Task 5 — Write an Analyst Opening Note

**Objective:** Practice opening a documented investigation the way a real analyst would.

An analyst note is a short, factual summary written at the start of an investigation. It records what you've been told, what you know, what you don't know, and what you're going to do first. It's the first entry in your case record.

Write an opening analyst note for the scenario in Task 3. Keep it to 1–2 short paragraphs. Use this structure:

```
Date/Time: [fill in]
Analyst: [your name or initials]
Case Reference: LAB01-001

Reported Issue:
[What was reported and by whom]

Currently Known:
[What facts are established at this point]

Currently Unknown:
[What has not yet been determined]

Initial Collection Priority:
[What evidence you would want first and why]
```

> **Good analyst notes are brief and factual.** Avoid speculation. If you don't know something, say so. If you're making an assumption, label it as an assumption.

---

### Task 6 — Reflection

**Objective:** Consolidate what you've learned before moving on.

Answer the following in 2–3 sentences each:

1. **The cost of skipping documentation:** What could go wrong during a real incident if you started collecting and analyzing evidence without writing anything down?

2. **Forensics under pressure:** In a fast-moving IR situation, what parts of the forensic process are most likely to get skipped, and why is that dangerous?

3. **Your biggest gap:** Based on what you've read in Section 1.1 and completed in this lab, what concept or skill feels least clear to you right now? (There's no wrong answer — identifying gaps is part of learning.)

---

## Deliverables Checklist

When you complete this lab, your `lab1.1-notes.md` file should contain:

- [ ] **Task 1** — Your definition of digital forensics (5–8 sentences)
- [ ] **Task 2** — Completed comparison table with at least 7 rows
- [ ] **Task 3** — At least 8 specific investigative questions
- [ ] **Task 4** — Evidence source mapping for all 8 questions
- [ ] **Task 5** — A completed analyst opening note
- [ ] **Task 6** — Reflection answers (2–3 sentences each)

---

## Files in This Folder

```
Lab01/
└── Lab01_01/
    ├── ReadMe.md        ← This file
    └── lab1.1-notes.md  ← Your working notes file
```

---

## Key Takeaways

- Digital forensics answers *specific questions* with *verifiable evidence*. It's not a fishing expedition.
- The five phases (Identify, Collect, Preserve, Analyze, Report) overlap in real IR. Documentation is the constant that holds them together.
- Asking the right questions *before* touching evidence is one of the most important forensic skills you'll develop.
- Forensic discipline — minimizing unnecessary changes, recording every action, hashing evidence — protects both the investigation and you.

---

**Next:** Lab 1.2 — Why Windows Matters in Incident Response

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
