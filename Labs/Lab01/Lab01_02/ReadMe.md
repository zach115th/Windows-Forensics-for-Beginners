# Lab 1.2 — Why Windows Matters in Incident Response

**Supporting Section 1.2: Why Windows Matters in IR**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Most enterprise incidents involve Windows somewhere in the attack path — a compromised workstation, a domain controller, a file server, an administrative jump box, or a Windows application server hosting something critical.

Even in organizations that have invested heavily in cloud infrastructure, EDR platforms, and centralized logging, Windows hosts still produce artifacts that no other data source replicates. Understanding what those artifacts are, what questions they answer, and how to prioritize them under time pressure is one of the most valuable skills an incident responder can develop.

This lab builds that awareness. You won't be parsing artifacts yet. That starts in Lab 4. The goal here is to connect Windows evidence sources to real IR questions before you're in the middle of an incident trying to figure out both at once.

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain why Windows systems are a consistent focus in enterprise incident response
- Identify at least 10 Windows forensic artifacts and describe their IR value
- Map common IR questions to the artifact sources that can answer them
- Make defensible triage prioritization decisions under time pressure
- Articulate to a non-technical audience why native Windows artifacts matter even when EDR and SIEM are present

---

## Estimated Time

20–35 minutes

---

## Prerequisites

No specialized tooling required. You will need:

- A text editor or markdown editor
- Your `lab1.2-notes.md` file (template included in this folder)
- Basic familiarity with Windows endpoints or servers
- Recommended: complete Lab 1.1 first

A Windows VM is optional but useful for exploring the file paths mentioned in the artifact table below.

---

## Background: What Windows Evidence Looks Like

Windows systems generate evidence of nearly everything that happens on them — user activity, program execution, file changes, authentication events, network usage, and attacker behavior. The challenge in IR is knowing where to look and in what order.

The table below introduces the artifact categories you'll work with throughout this book. Review it before starting the tasks.

| Artifact | Location (approximate) | What It Can Show |
|---|---|---|
| **MFT** | `$MFT` (root of each NTFS volume) | File existence, timestamps, deleted file traces |
| **USN Journal** | `$Extend\$UsnJrnl` | File creations, deletions, renames — even after deletion |
| **Security.evtx** | `%SystemRoot%\System32\winevt\Logs\` | Logons, account activity, privilege use |
| **System.evtx** | Same as above | Service installs, driver loads, reboots |
| **PowerShell logs** | `Microsoft-Windows-PowerShell%4Operational.evtx` | Script block content, command execution |
| **SYSTEM hive** | `%SystemRoot%\System32\config\SYSTEM` | Services, USB history, network config, timezone |
| **SOFTWARE hive** | `%SystemRoot%\System32\config\SOFTWARE` | Installed software, run keys, OS metadata |
| **NTUSER.DAT** | `%USERPROFILE%\NTUSER.DAT` | Per-user run keys, UserAssist, typed paths, MRUs |
| **Prefetch** | `%SystemRoot%\Prefetch\` | Program execution history, referenced file paths |
| **Amcache** | `%SystemRoot%\AppCompat\Programs\Amcache.hve` | Binary metadata: paths, hashes, first execution times |
| **SRUM** | `%SystemRoot%\System32\sru\SRUDB.dat` | Per-process CPU and network usage over time |
| **LNK files** | `%APPDATA%\Microsoft\Windows\Recent\` | Recently accessed files, target paths, timestamps |
| **Jump Lists** | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` | Per-app recent file history |
| **Shellbags** | USRCLASS.DAT | Folder navigation history, including removable media |
| **Browser history** | Varies by browser (SQLite databases) | URLs visited, downloads, search queries |
| **Memory** | Live capture required | Running processes, injected code, in-memory secrets, C2 sockets |

> **Note:** File paths above reflect default Windows configurations. Paths may vary by OS version or system policy.

---

## Lab Tasks

---

### Task 1 — Explain Why Windows Matters

**Objective:** Articulate the IR relevance of Windows forensics in your own words.

Write a paragraph of 5–8 sentences answering all three of the following:

1. Why are Windows systems important in enterprise incident response?
2. Why do responders need to understand Windows-specific artifacts — not just generic log analysis?
3. Why does Windows still matter forensically even when an organization uses cloud services, EDR, and centralized SIEM?

Write this in your own words. The goal is to make sure the reasoning has landed before you move into artifact analysis.

Record your response in `lab1.2-notes.md` under `## Task 1`.

---

### Task 2 — Build Your Artifact Awareness Reference

**Objective:** Build a personal reference that will support every future lab in this book.

Using the background table above and Section 1.2 of the book, create your own artifact list with at least **12 entries**. For each artifact, write:

- What the artifact is
- Where it lives on disk (approximate path is fine)
- One sentence on what it helps you understand during an IR

**Don't just copy the table above.** Rewrite the descriptions in your own words. Paraphrasing helps the information stick.

Use this format:

| Artifact | Location | IR Value |
|---|---|---|
| Security.evtx | `%SystemRoot%\System32\winevt\Logs\` | Records logon events, failed authentications, and privilege use — often the first place to check for unauthorized access |
| *(continue)* | | |

---

### Task 3 — Map IR Questions to Artifacts

**Objective:** Practice connecting investigative questions to evidence sources before you're under pressure.

Below are eight common IR questions. For each one, identify two or more Windows artifacts that could help answer it. Add at least two questions of your own at the bottom.

| IR Question | Windows Artifact(s) |
|---|---|
| Did a suspicious executable run on this host? | |
| Which user accounts had interactive logons? | |
| Was a USB drive or removable device connected? | |
| Did PowerShell execute suspicious commands? | |
| Was data staged, moved, or deleted? | |
| Was there evidence of persistence on this host? | |
| Did a process make significant network connections? | |
| Was a file opened or accessed by a specific user? | |
| *(Your question)* | |
| *(Your question)* | |

> **Tip:** Multiple artifact types can answer some questions, and that redundancy is valuable. If an attacker clears one source, another may still hold the answer.

---

### Task 4 — Triage Prioritization Under Time Pressure

**Objective:** Practice making defensible collection decisions when you can't collect everything.

**Scenario:** You have 20 minutes on a potentially compromised Windows host before it needs to be returned to service. You cannot take a full disk image. You need to collect what matters most.

Choose your **top six artifacts** and for each one explain:

- Why it made your priority list
- What specific IR question it helps answer
- Whether it is volatile (lost on reboot/shutdown) or persistent (survives reboot)

Use this format:

| Priority | Artifact | Why It Made the List | IR Question It Answers | Volatile? |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |
| 6 | | | | |

After completing the table, write 2–3 sentences reflecting on your choices: what did you leave out, and what are you accepting as a risk by not collecting it?

---

### Task 5 — The EDR Gap Explanation

**Objective:** Practice explaining Windows artifact value to a non-forensics audience.

**Scenario:** A colleague who manages your organization's EDR platform asks: *"If we have EDR on every endpoint and everything feeds into the SIEM, why do we need to pull raw Windows artifacts? Isn't that redundant?"*

Write a response of 1–2 short paragraphs that explains:

- What EDR and SIEM can and can't see
- What native Windows artifacts provide that security tooling does not
- Why both are valuable and how they complement each other

Write this as if you're sending a Slack message to a technically literate colleague — clear and direct, no jargon for its own sake.

---

### Task 6 — Reflection

Answer the following in 2–3 sentences each:

**1. Coverage gaps:** If an attacker knew exactly which Windows artifacts you were going to collect, what might they do to complicate your investigation? What artifacts would be hardest to tamper with?

**2. The limits of artifact awareness:** Knowing *what* artifacts exist is different from knowing *how* to analyze them. Where do you feel the gap most right now — awareness, analysis skill, tooling, or something else?

**3. Connecting to real work:** Think about a real incident you've worked (or a realistic hypothetical). Which Windows artifact from this lab would have been most useful, and why?

---

## Deliverables Checklist

Your `lab1.2-notes.md` should contain:

- [ ] **Task 1** — Your explanation of why Windows matters in IR (5–8 sentences)
- [ ] **Task 2** — Artifact awareness reference with at least 12 entries in your own words
- [ ] **Task 3** — IR question-to-artifact mapping (8 provided + 2 of your own)
- [ ] **Task 4** — Prioritized triage table with 6 artifacts and a reflection paragraph
- [ ] **Task 5** — The EDR gap explanation (1–2 paragraphs)
- [ ] **Task 6** — Reflection answers (2–3 sentences each)

---

## Files in This Folder

```
Lab01/
└── Lab01_02/
    ├── ReadMe.md        ← This file
    └── lab1.2-notes.md  ← Your working notes file
```

---

## Key Takeaways

- Windows artifacts are often the most detailed record of what happened on a host. They are more granular than most EDR telemetry, and they remain available even when security tooling was tampered with or never deployed.
- Artifact awareness — knowing what exists and where — is a prerequisite for effective triage. You can't prioritize what you don't know about.
- EDR and SIEM are useful but incomplete. Native Windows artifacts fill gaps that centralized tooling misses: deleted file traces, offline activity, pre-EDR history, and artifacts that attackers haven't thought to clear.
- Triage decisions have consequences. Knowing what you're *not* collecting — and accepting that risk consciously — is part of professional IR discipline.

---

**Next:** Lab 1.3 — Authorization, Legal Considerations, and Chain of Custody

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
