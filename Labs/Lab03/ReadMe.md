# Lab 03 — Digital Forensics and Advanced Data Triage

**Supporting [Chapter 3: Digital Forensics and Advanced Data Triage](../../Book/Chapter03.md)**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

In incident response, the hardest collection decision is rarely *how* to acquire evidence. It is deciding *how much* to collect, from which systems, and in what order. You make that decision while the clock is running, storage is limited, and leadership is asking for answers you don't have yet.

This lab introduces one of the most consequential practical skills in Windows IR: triage decision-making under operational constraints. You will practice choosing between full imaging and targeted collection, building a minimum viable triage package, and designing a repeatable collection script. You will also package artifacts with proper integrity controls and explain your decisions in plain language to people who don't know what a prefetch file is.

Lab 03 is where forensic theory meets operational reality. The question is no longer just *what artifacts exist?* It is *what should you collect right now to answer the most urgent IR questions without wasting time, burning storage, or losing volatile evidence?*

---

## What This Lab Covers

| Section | Topic |
|---|---|
| 3.1 | Full Images vs. Targeted Triage |
| 3.2 | Disk Imaging Basics in an IR Context |
| 3.3 | Memory Acquisition Basics |
| 3.4 | Designing a Defensible Triage Strategy |
| 3.5 | BitLocker and Encrypted Volumes |
| 3.6 | Volume Shadow Copies as an Analysis Target |
| 3.7 | The Acquisition Decision Tree |

---

## Learning Objectives

By completing this lab, you will be able to:

- Distinguish when full disk imaging is justified versus when targeted triage is the better operational choice
- Prioritize systems for collection based on business impact, volatility, and investigative value
- Define a minimum viable Windows triage package for incident response
- Organize artifacts into practical collection tiers based on urgency and investigative need
- Translate a triage plan into a realistic scripted collection workflow
- Package, hash, and document a triage collection in a defensible manner
- Explain triage tradeoffs clearly to management and non-technical stakeholders
- Walk a host through the acquisition decision tree and defend the order you collected in

---

## Estimated Time and Difficulty

**Difficulty:** Intermediate

**First time through the material:** 2.5–4 h

**Refresh (already familiar with the chapter):** 60–90 min

> **Key terms used in this lab:** targeted triage, full image, memory acquisition, defensibility. See the consolidated [Glossary](../../Book/Glossary.md) for definitions. The chapter cross-references in each entry take you back to the deeper coverage in `Book/`.

---

## Prerequisites

- Completion of Lab 02 (or equivalent familiarity with IR collection workflow planning)
- Your `lab02-notes.md` for reference
- A Windows lab VM for the optional hands-on tasks in Task 4
- A text editor or markdown editor
- Your `lab03-notes.md` file (template included in this folder)
- Optional but recommended: [KAPE](https://www.kroll.com/en/services/cyber/incident-response/kroll-artifact-parser-extractor-kape) for hands-on triage collection (Targets + Modules), and [FTK Imager](https://www.exterro.com/digital-forensics-software/ftk-imager) for image preview and verification. See Appendix D for a short tooling reference.

---

## Scenario

At 07:42 on a Wednesday morning your IR team receives three escalations tied to the same suspected intrusion:

> **DC-01** — A domain controller showing unusual authentication activity overnight: multiple failed privileged logons, two successful type 3 logons from a workstation IP that has no legitimate reason to authenticate against the DC, and a new service installation event in System.evtx.

> **FIN-WS23** — A finance department workstation where WINWORD.EXE spawned POWERSHELL.EXE at 06:58 UTC. Suspicious outbound connections were observed to an external IP on port 443 shortly afterward. The assigned user is a payroll administrator.

> **KIOSK-07** — A public-facing kiosk system. The AV engine flagged and quarantined a file. The kiosk has no domain credentials and no access to sensitive internal systems. It is still serving customers.

Leadership wants to know which systems should be collected first, whether full imaging is warranted, and how quickly the team can provide a preliminary scope assessment. You have two responders, one portable drive, and limited time before the business day fully ramps up.

Your job is to design and justify a triage strategy another responder could execute under pressure — not to solve the full intrusion.

---

## Background: Triage Is a Forensic Decision, Not a Shortcut

Chapter 3 introduces the core tradeoff between completeness and speed. Full imaging is the traditional forensic gold standard: it preserves the most data and supports future re-analysis. In active incident response, you must balance that standard against operational reality.

| Collection Type | Strengths | Limitations |
|---|---|---|
| **Full disk image** | Maximum preservation; supports deep re-analysis; strongest legal posture | Slow; storage-intensive; impractical at scale |
| **Targeted triage** | Fast; scalable; focused on urgent IR questions | Less complete; may omit artifacts found relevant later |
| **Memory capture** | Volatile data, process state, network artifacts, injected code | Lost on reboot; can be large; requires specific tooling |
| **Hybrid** | Balances speed and preservation for priority hosts | Requires judgment and documentation |

The key principle is this:

> **Good triage is not "collect less." It is "collect deliberately."**

A defensible triage plan identifies which evidence is most likely to answer the most urgent IR questions and captures volatile data before it disappears. It reserves full imaging for systems where the added value clearly justifies the time and storage cost. Every collection decision should be documentable. The reason is not that someone will audit you. It is that the next responder who picks up your work needs to understand what you collected, why, and what you left behind.

---

## Lab Tasks

---

### Task 1 — Collection Strategy Decisions

**Objective:** Make defensible, documented collection decisions for three hosts under real operational constraints.

**Part A — Per-host strategy**

Evaluate each host in the scenario and recommend a collection strategy. Use the factors below to guide your reasoning. Your answer for each host should reflect both investigative value and the operational reality of two responders and one drive.

| Host | Business Criticality | Suspected Threat Value | Volatile Evidence Risk | Recommended Strategy | Justification |
|---|---|---|---|---|---|
| DC-01 | | | | | |
| FIN-WS23 | | | | | |
| KIOSK-07 | | | | | |

**Collection strategy options:**
- Full disk image + memory
- Targeted triage + memory
- Memory only (then reassess)
- Deferred — scope first, collect later

**Part B — Priority and sequencing**

Answer the following, each in 3–4 sentences:

```
1. Which host do you collect from first, and why?


2. Which host most strongly justifies a full disk image, and why?


3. Which host is the best candidate for targeted triage, and why?


4. What single new piece of information would cause you to change your
   collection order entirely? What would it be and why would it matter?
```

> **Guidance:** "Image everything" is not an acceptable response unless you can justify why time, tooling, staffing, and storage would permit it for all three hosts simultaneously. A response that acknowledges constraints and explains tradeoffs is more defensible than one that ignores them.

---

### Task 2 — Build a Minimum Viable Triage Package

**Objective:** Define the smallest practical artifact set that still supports meaningful incident response analysis for FIN-WS23.

**Part A — Define the investigative questions**

Write at least six specific investigative questions your triage package must be capable of answering for FIN-WS23. Apply the specificity test from Lab 2.1: each question should be answerable by examining a named artifact.

```
1. 
2. 
3. 
4. 
5. 
6. 
```

**Part B — Map questions to artifacts**

For each question, identify the primary artifact and at least one corroborating source.

| # | Investigative Question | Primary Artifact | Corroborating Artifact |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |
| 6 | | | |

**Part C — Build the collection tier structure**

Organize the following artifacts into three priority tiers for FIN-WS23. Your tier assignments should be internally consistent and explicitly tied to investigative need, not just general best practice.

*Artifact pool:* Memory, MFT, USN Journal, Security.evtx, System.evtx, PowerShell logs, Registry hives (SYSTEM/SOFTWARE/NTUSER.DAT), Prefetch, SRUM, LNK files, Jump Lists, Scheduled tasks, Services configuration, Browser history, User profile directories, Amcache

| Tier | Description | Artifacts | Reasoning |
|---|---|---|---|
| **Tier 1** | Collect in every Windows compromise — no justification needed | | |
| **Tier 2** | Collect when time and access permit — strong IR value | | |
| **Tier 3** | Collect when a specific hypothesis justifies it | | |

**Part D — What you are explicitly not collecting**

List at least three artifact types or data sources you are *not* including in this triage package, and explain what you are accepting as a risk by leaving them behind.

| Not Collected | Risk Accepted |
|---|---|
| | |
| | |
| | |

> **Why this matters:** Every collection decision has two sides. A defensible triage plan accounts for what it doesn't collect, not just what it does.

---

### Task 3 — Design a Triage Collection Script

**Objective:** Translate your triage plan into a structured, reproducible scripted collection workflow.

Your team wants a standard PowerShell-based triage script for Windows endpoints. The team has asked you to design the structure before anyone writes production code. The script will be named `Get-WinIRArtifacts.ps1`.

**Part A — Parameters**

Define the parameters the script should accept at runtime. For each parameter, specify the type, whether it is required or optional, and its purpose.

```powershell
# Suggested parameters — expand and adjust as needed

param (
    [Parameter(Mandatory=$true)]
    [string]$CaseID,           # Unique case identifier

    [Parameter(Mandatory=$true)]
    [string]$OutputPath,       # Root path for collection output

    [Parameter(Mandatory=$false)]
    [switch]$IncludeMemory,    # Trigger memory acquisition

    [Parameter(Mandatory=$false)]
    [switch]$IncludeBrowser,   # Include browser artifacts

    # Add your own parameters here
)
```

**Part B — Working directory structure**

Define the folder structure the script should create for each collection. Use or adapt this model:

```
[CaseID]_[Hostname]_[Timestamp]\
├── Memory\
├── Registry\
├── EventLogs\
├── Filesystem\
├── ExecutionArtifacts\
├── Network\
├── Hashes\
└── CollectionLog\
```

Explain why you would or would not add any additional subfolders for FIN-WS23's specific artifact set.

**Part C — Collection functions**

Define the major functions or sections the script should include. For each, write a one-sentence description of what it does and note any critical implementation consideration.

| Function / Section | Purpose | Key Consideration |
|---|---|---|
| `Initialize-Collection` | Create output directories and validate parameters | Fail fast if OutputPath is unavailable or case ID is blank |
| `Get-SystemMetadata` | Capture hostname, IP, username, OS version, timestamp | Run first — metadata anchors the entire collection |
| `Copy-RegistryHives` | Export offline copies of key registry hives | Hives may be locked — handle gracefully |
| `Export-EventLogs` | Copy EVTX files to output directory | Check for locked files; log any skipped |
| `Collect-ExecutionArtifacts` | Prefetch, Amcache, SRUM, LNK, Jump Lists | Some paths require elevation |
| `Compress-Collection` | Create ZIP archive of output folder | Exclude the Hashes folder from the archive |
| `Write-Hashes` | Compute SHA-256 of archive and individual files | Hash after compression is complete |
| `Write-CollectionLog` | Write structured log of all actions taken | Log must be written outside the archive |
| *(Add your own)* | | |

**Part D — Logging requirements**

Define what the script must log during execution. Your log should be recoverable even if the script fails partway through.

Every log entry should include at minimum:

```
[DateTime UTC] | [Function] | [Status] | [Detail]

Status values: INFO / SUCCESS / WARNING / ERROR / SKIPPED
```

List the specific events that must always generate a log entry:

```
1. Script start (parameters, hostname, analyst)
2. Each directory created
3. Each file copy attempted (success or failure)
4. Each locked or inaccessible file
5. [Add your own — at least 5 more]
6. 
7. 
8. 
9. 
10. 
```

**Part E — Safety and scope considerations**

Write 6–8 bullet points covering the safety and scope constraints the script must respect:

```
- 
- 
- 
- 
- 
- 
- 
- 
```

**Part F — Optional prototype**

If you want hands-on practice, write a simple non-destructive prototype that demonstrates the core workflow:

```powershell
# Get-WinIRArtifacts-Prototype.ps1
# Non-destructive prototype — copies test files, compresses, and hashes

param (
    [string]$CaseID = "TEST-001",
    [string]$OutputPath = "E:\IR\Test"
)

# Stage 1: Create working directory
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$hostname = $env:COMPUTERNAME
$workDir = Join-Path $OutputPath "${CaseID}_${hostname}_${timestamp}"

New-Item -ItemType Directory -Path $workDir -Force | Out-Null
Write-Output "Created working directory: $workDir"

# Stage 2: Copy test files
# [Add your file copy commands here]

# Stage 3: Compress
# [Add your compression command here]

# Stage 4: Hash
# [Add your Get-FileHash command here]

# Stage 5: Log
# [Add your log write here]
```

---

### Task 4 — Package and Hash a Triage Collection

**Objective:** Practice triage output handling with the same integrity discipline expected of full forensic acquisitions.

Targeted triage collections require the same packaging, hashing, and documentation discipline as full disk images. The artifact is smaller, but the standard is identical.

**Part A — Build a sample package**

On your lab VM, create the following folder structure and populate it with harmless test files. Text files, exported registry keys, or copied event logs from your baseline VM are ideal:

```
Sample-Triage\
├── Registry\
│   └── [one or more test files]
├── EventLogs\
│   └── [one or more test files]
├── ExecutionArtifacts\
│   └── [one or more test files]
└── Notes\
    └── collection-notes.txt
```

Add a `collection-notes.txt` to the Notes folder with: case ID, hostname, collector name, date/time (UTC), and a brief description of what is in each subfolder.

**Part B — Compress the package**

```powershell
# Compress the sample triage folder
Compress-Archive -Path ".\Sample-Triage\*" `
                 -DestinationPath ".\Sample-Triage_[CaseID]_[Date].zip" `
                 -CompressionLevel Optimal
```

**Part C — Hash the archive**

```powershell
# Compute SHA-256 of the archive
Get-FileHash -Algorithm SHA256 ".\Sample-Triage_[CaseID]_[Date].zip" |
  Select-Object Algorithm, Hash, Path |
  Export-Csv ".\Sample-Triage_[CaseID]_[Date]_hash.csv" -NoTypeInformation
```

Record the result:

| Item | Value |
|---|---|
| **Archive Name** | |
| **Archive Path** | |
| **File Size** | |
| **SHA-256** | |
| **Date/Time Hashed (UTC)** | |
| **Hashing Tool** | |
| **Hashing Tool Version** | |

**Part D — Evidence handling record**

```
Case ID:                    
Host Name:                  
Collector:                  
Collection Date/Time (UTC): 
Collection Method:          Targeted triage — PowerShell
Archive Name:               
SHA-256:                    
Storage Location:           
Working Copy Created:       [Yes / No]
Original Preserved:         [Yes / No]
Transfer Status:            [In place / Transferred to case storage]
Chain of Custody Updated:   [Yes / No]
Notes:                      
```

**Part E — Defensibility statement**

Write two paragraphs covering:

1. Why this targeted triage package is still trustworthy evidence — what controls make it reliable
2. What it cannot provide compared to a full image, and under what conditions a full image would be required

```
[Paragraph 1 — why the package is trustworthy]


[Paragraph 2 — limitations and when a full image is required]
```

---

### Task 5 — Explain Triage Tradeoffs to Management

**Objective:** Communicate collection decisions clearly to a non-technical audience.

Leadership is concerned the team is not imaging every suspicious system immediately. Explain why that isn't always the right move, and why targeted triage is often the *faster* path to the answers they're actually asking for.

Write a short memo saved as `Management_Justification_Targeted_Triage.md`.

Use this structure:

```markdown
# Triage Collection Approach — Justification
**Prepared By:**    
**Date:**           
**Incident:**       IR-2024-[your reference]
**Audience:**       IR Manager, Legal, Executive Leadership

---

## Summary

[One paragraph: what happened, what collection decisions were made, and the bottom line]

---

## Why We Did Not Image Every System Immediately

[2–3 paragraphs explaining the operational constraints and why full imaging of all hosts
was not the right first move. No jargon. If you must use a technical term, define it.]

---

## What Targeted Triage Can Tell Us

[1–2 paragraphs on what the triage approach reliably answers — scope, active threat,
execution evidence, persistence, etc.]

---

## What Targeted Triage May Miss

[1 paragraph, honest about limitations — this protects you if something is found later
that triage didn't capture]

---

## Recommended Next Steps

| Host | Recommended Action | Reason | Priority |
|---|---|---|---|
| DC-01 | | | |
| FIN-WS23 | | | |
| KIOSK-07 | | | |

---

## Questions or Concerns

[Invite follow-up. Provide a contact or escalation path.]
```

> **Guidance:** This is not a technical artifact list. It is a business-facing justification. Write it at the level of a director, legal reviewer, or CISO who is accountable for the outcome but not responsible for executing the collection.

---

### Task 6 — Walk the Acquisition Decision Tree

**Objective:** Take six hosts through the decision tree in Chapter 3 §3.7 and commit to an acquisition order before you know how the case ends.

Tasks 1–5 asked *how much* to collect. This task asks *in what order*, on the machine in front of you, in the first few minutes. That is the decision hardest to undo. The tree branches on power state, whether anyone is logged in, whether you can elevate, whether the volume is encrypted, whether triage answers the question, and finally whether the image is physical or logical.

Two nodes on that tree cost you evidence if you get them wrong: **capture memory before anything else on a live host, and never power on a machine you were handed powered off**. Everything else on the tree is a tradeoff you can revisit. Those two are not.

**Part A — The scenarios**

Read all six before you answer any of them. They are deliberately not variations on one problem.

> **Scenario 1 — WKSTN-118.** A domain-joined workstation, powered on, the assigned user is signed in at the keyboard, and you are holding a break-glass domain admin credential that works. EDR alerted 40 minutes ago on suspected credential access. The volume is BitLocker-protected with a TPM-only protector and is currently unlocked. Nothing is stopping you from doing whatever you decide to do.

> **Scenario 2 — SALES-LT44.** A laptop in a branch office, powered on, the user is signed in as a standard user. Helpdesk cannot get you a local administrator credential inside your response window — the approval chain is the problem, not the technology. The EDR agent is installed, healthy, and reporting, and you have console access to it.

> **Scenario 3 — EXEC-LT09.** Handed to you in a bag by the user's manager, powered off. The device is Intune-managed and Entra-joined, BitLocker is enabled, and the recovery key is present in the Entra device record. Nobody has touched it since it was shut down last night.

> **Scenario 4 — CONTRACT-LT07.** Handed to you powered off. BitLocker is enabled. The device was never enrolled in Intune and is not in AD — it was a contractor's workgroup machine that IT allowed onto the network. The contractor left the company two weeks ago and does not respond. There is no `.BEK` file with the device, no printed key, and no escrow record anywhere you can find. Legal wants to know what was on it.

> **Scenario 5 — APP-SRV-04.** A production application server, powered on, you have administrative access. It processes customer orders continuously and the business will not authorise downtime during the engagement. A service named `AppTelemetrySvc` was installed at 02:14 and nobody in the platform team recognises it. Suspected persistence, no confirmed second stage.

> **Scenario 6 — ENG-DT22.** An engineering desktop found powered off in a locked office. No encryption. You imaged it with a write-blocker, hash-verified the image, and analysed it. There is an `HKLM\...\CurrentVersion\Run` value named `SysHostSvc` pointing at a path you cannot identify, and the referenced binary is not where the value says it should be. Neither the file system nor the registry tells you what it actually does.

**Part B — Walk each scenario through the tree**

For each scenario, record the branch you take, the order you collect in, the tool you would actually reach for, what you lose if you get the order wrong, and what goes in the acquisition note. Keep the acquisition order numbered: the order is the answer.

| # | Host | Path through the tree | Acquisition order | Tool choice | What you lose by getting it wrong | What you document |
|---|---|---|---|---|---|---|
| 1 | WKSTN-118 | | | | | |
| 2 | SALES-LT44 | | | | | |
| 3 | EXEC-LT09 | | | | | |
| 4 | CONTRACT-LT07 | | | | | |
| 5 | APP-SRV-04 | | | | | |
| 6 | ENG-DT22 | | | | | |

**Part C — Physical or logical**

Two of the six scenarios push you toward a logical image rather than a physical one, and for different reasons. Identify them and state, in one or two sentences each, what you are giving up by acquiring logically and why it is still the right call.

```
Scenario ___ — logical because:


  What is given up:


Scenario ___ — logical because:


  What is given up:
```

**Part D — Reflection on the tree**

Answer the following in 3–5 sentences each:

**1. Why memory goes first**
Memory is not always the most valuable artifact on a compromised host — often the event logs or the MFT matter more to the final report. So why does memory still go first on every live host where you can capture it? Frame your answer around what threatens each artifact rather than what each artifact contains.

**2. "Powered off" is not the same as "no memory"**
Scenario 3's laptop was shut down last night by a user who thought they had turned it off. What might still be on that disk that behaves like memory evidence, why does it exist, and what does that change about the files you explicitly list in your collection?

**3. Writing up an unrecoverable position**
Scenario 4 has no technical answer. Write the two or three sentences you would put in the report to describe the position, and then state what the organisation should take away from it. Whose problem is this, and where does the fix belong?

**4. Booting evidence on purpose**
Scenario 6 is the one case in this chapter where powering on an evidence machine is defensible. What conditions have to be satisfied first, what does the resulting capture actually prove, and what does it emphatically not prove?

> **Guidance:** "It depends" is a real answer only if you then say what it depends on and commit to a decision for the facts you were given. On a live engagement you do not get to defer. You get to document. Record the constraint, choose, and move.

---

### Task 7 — Reflection

Answer the following in 3–5 sentences each:

**1. Completeness versus speed**
Why is "collect everything" sometimes a bad incident response strategy, even when it sounds more thorough? Give a specific scenario where imaging every host first would have made the incident worse.

**2. The cost of delayed memory capture**
Why can a delayed memory capture be more damaging to an investigation than delaying collection of some disk artifacts? What specific evidence categories are at risk and why?

**3. Documenting your rationale**
How does writing down your collection reasoning protect you professionally if someone later questions why you didn't fully image every host? What specific documentation would you point to?

**4. When new facts change the plan**
Halfway through your triage of FIN-WS23 you learn that DC-01 logged a successful authentication from FIN-WS23's IP at 07:01 UTC — three minutes after the suspicious PowerShell execution. How does that change your collection priorities and why?

---

## Deliverables Checklist

Your `lab03-notes.md` should contain:

- [ ] **Task 1** — Per-host strategy table, priority and sequencing answers
- [ ] **Task 2** — Investigative questions, artifact mapping, collection tiers, and explicit non-collection decisions
- [ ] **Task 3** — Script parameters, directory structure, function definitions, logging requirements, safety considerations, and optional prototype
- [ ] **Task 4** — Sample triage package built, archive compressed and hashed, handling record completed, defensibility statement written
- [ ] **Task 5** — Management justification memo saved as `Management_Justification_Targeted_Triage.md`
- [ ] **Task 6** — Decision-tree walk for all six scenarios, physical-versus-logical answers, and the four reflection answers
- [ ] **Task 7** — Reflection answers (3–5 sentences each)

You should also have a copy of `acquisition-checklist.md` filled in for at least one of the Task 6 scenarios. Treat it as the artifact you would actually produce on scene.

---

## Files in This Folder

```
Lab03/
├── ReadMe.md                                   ← This file
├── lab03-notes.md                              ← Rollup working notes for the whole lab
├── task-answers.md                             ← Sample answers for the workbook Tasks
├── acquisition-checklist.md                    ← Reusable per-host acquisition worksheet
├── Lab03_01/                                   ← Ch3 §3.1 — Full Images vs. Targeted Triage
│   ├── ReadMe.md
│   └── lab03.1-notes.md
├── Lab03_02/                                   ← Ch3 §3.2 — Disk Imaging Basics in an IR Context
│   ├── ReadMe.md
│   └── lab03.2-notes.md
├── Lab03_03/                                   ← Ch3 §3.3 — Memory Acquisition Basics
│   ├── ReadMe.md
│   └── lab03.3-notes.md
├── Lab03_04/                                   ← Ch3 §3.4 — Designing a Defensible Triage Strategy
│   ├── ReadMe.md
│   └── lab03.4-notes.md
└── Capstone/                                   ← Chapter 3 capstone challenge
    ├── ReadMe.md                                  Multi-host triage under pressure
    └── lab03.5-notes.md                           Capstone analyst-notes scaffold
```

---

> **Going further:** Once you've completed Tasks 1–7 above, the [**Lab 03 Capstone — Multi-Host Triage and Acquisition Under Pressure**](Capstone/ReadMe.md) is a scenario challenge that applies the full Chapter 3 skill set in a single incident: six hosts, competing priorities, business impact, leadership pressure. It is a judgment lab rather than a parser lab, and it is the one chapter-scoped capstone in this book (Lab 11 is the book-wide capstone).

---

## Key Takeaways

- **Triage is a decision process, not a shortcut.** Every collection choice should be documentable, tied to investigative need, and defensible to a reviewer who wasn't there.
- **Not every host deserves the same treatment.** Business value, volatility, and suspected threat activity drive collection depth, not host count or ease of access.
- **Memory is the most volatile and the most time-sensitive.** When in doubt about whether to capture it, capture it. You can't go back.
- **Documenting why you didn't collect something is as important as documenting what you did.** Negative collection decisions are part of the defensible record.
- **A machine handed to you powered off stays powered off.** Booting it fires `RunOnce` keys that delete themselves, pushes new entries into Prefetch and Amcache, rolls event logs, and moves timestamps. ShimCache is not written at boot, but the session you start overwrites its cached entries at clean shutdown. There is one justified exception, and it comes after the image, not instead of it.
- **A small, scripted, reproducible workflow beats a large, ad-hoc one.** The triage that runs the same way on every host produces the timeline you can later defend.

---

**Next:** Lab 04 — Windows File System Forensics (NTFS)

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
