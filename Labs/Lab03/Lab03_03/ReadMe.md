# Lab 3.3 — Memory Acquisition Basics

**Supporting Section 3.3: Memory Acquisition Basics**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Memory is often the most fragile and time-sensitive source of evidence in a Windows incident.

A reboot, crash, shutdown, or even a 30-minute delay can permanently destroy volatile artifacts. These include process state, network connection data, injected code, loaded modules, clipboard contents, and command history, which may never exist on disk in a useful form. Memory acquisition is therefore one of the highest-value activities in live response, and one of the easiest to mishandle if you haven't planned it in advance.

This lab covers the practical side of memory acquisition in incident response. You will decide when memory capture is justified and identify which questions memory can help answer. You will plan a defensible acquisition workflow, document collection details at the level later trust requires, and work out how to preserve integrity while minimizing disruption to a live Windows system.

The goal is to make sure you understand when to capture memory, why it matters, how to do it methodically, and how to explain and defend that decision afterward. Becoming a memory analysis expert comes later.

---

## What This Lab Covers

| Section | Topic |
|---|---|
| 3.3.1 | Why volatile memory matters in incident response |
| 3.3.2 | What kinds of evidence can exist in RAM but not on disk |
| 3.3.3 | Planning and documenting memory acquisition |
| 3.3.4 | Preserving integrity and handling operational risk during live collection |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain why memory acquisition is often the most time-critical collection step in a Windows incident
- Identify what types of evidence may exist in RAM but not on disk — and why that distinction matters
- Recognize scenarios where memory capture should be prioritized over disk collection
- Plan a step-by-step Windows memory acquisition workflow that another responder could execute
- Document the minimum details needed to make a memory capture trustworthy later
- Explain the risks, limitations, and operational tradeoffs of live memory collection on a production system

---

## Estimated Time

45–75 minutes

---

## Prerequisites

- Completion of Lab 3.1 and Lab 3.2, or equivalent familiarity with triage and acquisition planning
- A text editor or markdown editor
- Your `lab03.3-notes.md` file (template included in this folder)
- Optional: a Windows VM for workflow planning practice
- Optional: WinPmem, DumpIt, FTK Imager, or an EDR live response memory capture feature

---

## Scenario

At 10:31 on a Thursday morning, your SOC escalates a suspected compromise involving a Windows application server named **WEB-APP-03**. Analysts report:

- The host is making unusual outbound connections to an IP address with no prior history in the environment
- EDR telemetry shows PowerShell executed briefly, but the full command line was not retained because of a configuration gap
- A suspicious service appeared in System.evtx and then disappeared within minutes — no current service entry exists
- No reboot has occurred since the activity was observed
- The server is still online and actively serving internal users
- A second analyst has flagged that WEB-APP-03 may be running a web shell based on the process chain observed in EDR

Leadership wants a fast scope assessment. The IR team is concerned that the most valuable evidence may exist only in volatile memory. Any delay, reboot, or containment action taken before memory capture could permanently destroy it.

You have been asked to decide whether memory acquisition should happen now, what risks it introduces, and how to document it.

---

## Background: Why RAM Matters

Disk artifacts tell you a great deal about what happened on a Windows system. Memory can show you what was happening *right now* — or what happened too briefly or too carefully to leave durable disk traces.

| Evidence Type | More Likely in Memory | More Likely on Disk |
|---|---|---|
| Running process state | Yes | No |
| Full command-line arguments | Yes | Sometimes (if logging enabled) |
| Injected or shellcode | Yes | Not reliably |
| Network socket state | Yes | Limited |
| In-memory decrypted content | Yes | Rarely |
| Credentials, tokens, logon sessions | Yes | No |
| Fileless malware | Yes | No |
| Registry hives | No | Yes |
| Event logs | No | Yes |
| File system metadata | No | Yes |
| Prefetch and execution artifacts | No | Yes |

Unlike most disk artifacts, RAM is strictly volatile. If the host is rebooted, shut down, or crashes before capture, that evidence is gone with no recovery path.

> **IR Reality Check:** When you suspect fileless malware, short-lived PowerShell activity, in-memory C2 beacons, or attacker presence that will vanish with a reboot, memory capture is often your most perishable collection step. It is often the highest-value one too. If you skip or delay it, make that decision deliberately and document it explicitly.

---

## Lab Tasks

---

### Task 1 — Decide Whether WEB-APP-03 Requires Memory Acquisition

**Objective:** Make and defend a prioritized memory acquisition decision for a live production server.

**Part A — Decision summary**

| Host | Recommended Action | Priority |
|---|---|---|
| WEB-APP-03 | | [Immediate / High / Deferred / Not warranted] |

**Action options:**
- Capture memory immediately before any other collection or containment action
- Capture memory as part of a coordinated volatile evidence sweep (process list, network state, then memory)
- Defer memory capture pending scope confirmation
- Do not capture memory — targeted triage is sufficient

**Part B — Decision rationale**

Answer each in two or three sentences:

**1. Which facts from the scenario most strongly support capturing memory immediately?**

```
[Your response here]
```

**2. What operational concerns could make memory capture harder or riskier on WEB-APP-03?**

```
[Your response here]
```

**3. Should memory be captured before any containment action, shutdown, or remediation step? Why?**

```
[Your response here]
```

**4. What single piece of new information would change your recommendation — and in which direction?**

```
[Your response here]
```

> **Guidance:** The point is to show that the need in this scenario is strong enough to justify live collection on a production system, and to document that reasoning so you can defend it later. Do not assume "capture memory always."

---

### Task 2 — Map Investigative Questions to Memory Evidence

**Objective:** Connect volatile evidence categories to specific IR questions before collection begins.

Write at least eight specific investigative questions that a memory capture from WEB-APP-03 might help answer. Then map each question to the memory-resident evidence that could provide the answer.

| # | Investigative Question | Memory Evidence That May Help Answer It |
|---|---|---|
| 1 | Is a suspicious or unexpected process currently running on WEB-APP-03? | Active process list — name, PID, parent PID, full path |
| 2 | What command line was associated with the brief PowerShell execution? | Process memory — command-line arguments retained in process environment block |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |
| 7 | | |
| 8 | | |

**Memory evidence categories to draw from:**

- Active processes and parent-child relationships
- Full command-line arguments (including encoded or obfuscated content)
- Loaded DLLs and injected modules
- Open network sockets and connection state
- Injected shellcode or in-memory malware
- PowerShell runspace remnants
- Logon sessions, tokens, and credentials
- Clipboard and console history
- Handles to files, registry keys, or named pipes

> **Specificity test:** "Was the attacker here?" is not a forensic question. "Is POWERSHELL.EXE resident in memory with a parent process of W3WP.EXE, which would indicate web shell execution?" is.

---

### Task 3 — Build a Memory Acquisition Workflow

**Objective:** Write a live-response memory collection process another responder could execute safely and consistently.

---

**Stage 1 — Pre-Collection Checks**

Write six to eight steps covering what you must confirm before memory collection begins.

```
1. Confirm authorization — case reference, approving manager, scope of collection
2. Confirm the host is stable enough for live collection — check for crash indicators,
   high CPU/memory load, or pending restarts
3. 
4. 
5. 
6. 
7. 
8. 
```

Items to consider: destination storage path and free space, tool availability and version, whether other volatile data (process list, network connections) should be captured immediately before memory, whether EDR tooling may interfere with acquisition, whether the system owner needs to be notified before the collection begins.

---

**Stage 2 — Tool Selection**

Choose a memory acquisition tool for WEB-APP-03 and document your reasoning.

| Item | Your Choice / Notes |
|---|---|
| **Acquisition tool** | |
| **Why selected** | |
| **Output format** | |
| **Expected output size** | |
| **Destination path** | |
| **Operational concerns** | |

**Tool reference:**

| Tool | Notes |
|---|---|
| **WinPmem** | Open source; command-line; produces raw or AFF4 output; lightweight |
| **DumpIt** | Simple single-binary execution; widely used in IR; raw output |
| **FTK Imager** | GUI-based; can capture memory and export to case folder; familiar to many analysts |
| **EDR live response** | Built-in to some EDR platforms; may be most operationally convenient; output format varies |

> **Guidance:** Focus on what makes the tool practical and defensible in this specific scenario. You do not need to argue that one tool is universally best.

---

**Stage 3 — Acquisition Execution**

Write the steps for the memory collection itself. Be specific enough that a responder who wasn't present for the planning conversation could execute it correctly.

| Step | Action | Notes |
|---|---|---|
| 1 | Record system time (UTC) and local time before starting | Time skew matters for later correlation |
| 2 | Confirm destination path is writable and has sufficient free space | Memory image is typically 1–1.5× installed RAM |
| 3 | Transfer acquisition tool to destination — do not run from the suspect system | Avoids contaminating evidence with tool artifacts |
| 4 | Execute acquisition tool with administrator privileges | |
| 5 | Record tool command line used exactly | |
| 6 | Monitor acquisition progress — note any errors or warnings | |
| 7 | Record completion time (UTC) | |
| 8 | Do not reboot or shut down the host until memory capture is confirmed complete | |

**Example WinPmem command:**

```powershell
# Run from destination drive, not from C:\
.\winpmem_mini_x64.exe E:\IR\WEB-APP-03\memory\WEBAPP03_memory_20241121_1042.raw
```

**Example FTK Imager:**

```
File → Capture Memory
Destination path: E:\IR\WEB-APP-03\memory\
Filename:         WEBAPP03_memory_20241121_1042.mem
Include pagefile: [Yes / No — document decision]
```

---

**Stage 4 — Hashing and Integrity Recording**

Answer each of the following:

```
When should the memory image be hashed?


Which file(s) should be hashed?


Which hash algorithm?


Where should the hash record be stored?


Why does integrity documentation matter for a volatile acquisition specifically?

```

**Hash command:**

```powershell
Get-FileHash -Algorithm SHA256 "E:\IR\WEB-APP-03\memory\WEBAPP03_memory_20241121_1042.raw" |
  Select-Object Algorithm, Hash, Path |
  Export-Csv "E:\IR\WEB-APP-03\memory\WEBAPP03_memory_hash.csv" -NoTypeInformation
```

---

**Stage 5 — Post-Acquisition Handling**

```
Storage location for memory image:      
Working copy created:                   [Yes / No]
Original write-protected:               [Yes / No — method:]
Pagefile collected:                     [Yes / No — reason:]
Hibernation file collected:             [Yes / No — reason:]
Chain of custody updated:               [Yes / No]
Case notes updated:                     [Yes / No]
Next collection step:                   
```

> **Pagefile and hibernation note:** `pagefile.sys` and `hiberfil.sys` can contain memory-resident content that survived prior reboots or was paged out during the incident window. When time permits, collect both alongside the live memory image to strengthen your volatile evidence set.

---

### Task 4 — Risks and Limitations of Live Memory Collection

**Objective:** Recognize that live memory acquisition is valuable but not consequence-free.

**Part A — Risk table**

| Risk or Limitation | Why It Matters | How You Would Mitigate or Document It |
|---|---|---|
| Live collection changes system state | | |
| Memory image can be very large | | |
| Acquisition may affect system performance | | |
| Tool may fail, hang, or crash the host | | |
| Not all memory content is interpretable | | |
| Encrypted or protected regions may limit visibility | | |
| Collection tool leaves artifacts on the system | | |

**Part B — Written analysis**

**1. Why is live memory collection still forensically defensible even though it changes the running system?**

```
[Your response here]
```

**2. Why is "we didn't want to touch the live host" not always a sufficient reason to skip memory capture?**

```
[Your response here]
```

---

### Task 5 — Define Memory Acquisition Documentation Requirements

**Objective:** Establish the minimum documentation that makes a memory image trustworthy for later analysis.

**Part A — Acquisition record**

Complete every field. If a field would be unknown at the time of collection, note what is unknown and when it will be resolved.

| Field | What Should Be Recorded | Why It Matters |
|---|---|---|
| Case reference | | |
| Hostname | | |
| Acquisition date/time (UTC) | | |
| Acquired by | | |
| Authorized by | | |
| Acquisition tool | | |
| Tool version | | |
| Exact command used | | |
| Output file name | | |
| Output path | | |
| Approximate file size | | |
| Hash algorithm | | |
| Hash value | | |
| System state at time of collection | | |
| Pagefile collected | | |
| Hibernation file collected | | |
| Errors or warnings | | |
| Notes / observations | | |

**Part B — Short answers**

**1. Why does recording the exact command used matter beyond just noting the tool name?**

```
[Your response here]
```

**2. Why should system state notes — active users, server load, running services — be recorded at time of collection?**

```
[Your response here]
```

**3. Why do errors and partial failures need to be documented even if the image file was created successfully?**

```
[Your response here]
```

---

### Task 6 — Write a Memory Collection Note

**Objective:** Produce a concise, defensible case note for memory acquisition of WEB-APP-03.

Write a collection note as if memory capture has just finished or is about to begin. Fill in every field. If a field is unknown at the time of writing, note what is unknown and when it will be resolved.

```
# Memory Acquisition Note — WEB-APP-03
Case Reference:           
Author:                   
Date/Time (UTC):          

Host:                     WEB-APP-03
Reason for Memory Capture:
Authorized By:            
System Status at Collection:

Tool Selected:            
Tool Version:             
Command Used:             
Output File Name:         
Output Destination:       
Approximate Output Size:  

Hash Algorithm:           SHA-256
Hash Value:               
Hash Verified:            [Yes / No]

Pagefile Collected:       [Yes / No — reason:]
Hibernation File Collected:[Yes / No — reason:]

Operational Considerations:
Errors / Warnings:        
Notes:                    
Next Step:                
```

---

### Task 7 — Memory vs. Disk Prioritization

**Objective:** Practice deciding when volatile evidence should take precedence over broader disk preservation.

For each scenario, decide whether memory should come first, disk should come first, or either order is acceptable. Then explain your reasoning.

| Scenario | Priority Decision | Reasoning |
|---|---|---|
| Suspected fileless malware with active outbound C2 connection still live | | |
| Low-value kiosk with malware detection, already scheduled for rebuild | | |
| High-value server with signs of short-lived PowerShell execution — no reboot yet | | |
| Workstation where the primary concern is deleted attacker tools on disk | | |
| System actively crashing — may not survive a memory capture attempt | | |
| Server where attacker logged in via RDP 20 minutes ago and session may still be active | | |

> **Guidance:** What matters is whether you can articulate the tradeoffs clearly and consistently. There is not always one correct answer.

---

### Task 8 — Reflection

Answer the following in three to five sentences each:

**1. Why memory is different**
Why does memory acquisition require faster decision-making than most disk artifact collection? What makes the window of opportunity uniquely narrow?

```
[Your response here]
```

**2. The cost of delay**
What specific types of evidence can disappear if memory capture is delayed until after containment, reboot, or remediation? Give at least two concrete examples relevant to the WEB-APP-03 scenario.

```
[Your response here]
```

**3. Documentation as protection**
How does documenting the reason for memory capture — specifically — protect you if someone later questions why you performed a live collection on a production server that was actively serving users?

```
[Your response here]
```

**4. The limits of memory alone**
Why is a memory capture powerful but still not a complete replacement for disk evidence? What categories of evidence require both sources to be fully understood?

```
[Your response here]
```

---

## Deliverables Checklist

Your `lab03.3-notes.md` should contain:

- [ ] **Task 1** — Memory acquisition decision for WEB-APP-03 with four written rationale answers
- [ ] **Task 2** — At least eight investigative questions mapped to memory-resident evidence
- [ ] **Task 3** — Step-by-step memory acquisition workflow across all five stages
- [ ] **Task 4** — Risk table and two written analysis responses
- [ ] **Task 5** — Acquisition documentation table with why-it-matters column and three short answers
- [ ] **Task 6** — Complete memory collection note for WEB-APP-03
- [ ] **Task 7** — Memory vs. disk prioritization table with reasoning for all six scenarios
- [ ] **Task 8** — Reflection answers (three to five sentences each)

---

## Files in This Folder

```
Lab03/
├── lab03-notes.md    ← Your working notes file (whole lab)
└── Lab03_03/
    ├── ReadMe.md         ← This file
    └── lab03.3-notes.md  ← Your working notes file
```

---

## Key Takeaways

- **Memory is perishable.** If memory matters to the case, even a short delay in capture can permanently destroy the best evidence available.
- **Volatile evidence answers different questions.** RAM reveals process state, command lines, network sockets, injected code, and credentials that disk artifacts may never record.
- **Live collection is still forensically defensible.** Memory acquisition changes a running system, but that does not invalidate it. It means you must understand the change, document it, and account for it in analysis.
- **Documentation matters as much as the capture itself.** Tool, version, exact command, output path, hash, system state, and errors all affect how trustworthy the image will be six months later.
- **Memory and disk complement each other.** The strongest investigations correlate volatile evidence with persistent artifacts rather than relying on either source alone.

---

**Next:** Lab 3.4 — Designing a Defensible Triage Strategy

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
