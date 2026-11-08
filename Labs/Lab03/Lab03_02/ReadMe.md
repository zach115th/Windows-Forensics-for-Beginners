# Lab 3.2 — Disk Imaging Basics in an IR Context

**Supporting Section 3.2: Disk Imaging Basics in an IR Context**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

In incident response, full disk imaging is an operational decision with consequences, not just a technical task. It is also one of the most recognizable activities in digital forensics.

Imaging preserves a broad snapshot of system state for later analysis. It gives you access to deleted files, slack space, alternate data streams, unallocated space, and artifacts you may not have realized were important at the time of collection. That breadth is its value. It is also why imaging is slow, storage-intensive, and sometimes hard to justify during a fast-moving incident with three other hosts waiting.

This lab covers the practical side of disk imaging in Windows IR. You will decide when a full image is warranted and plan an imaging workflow. You will document acquisition details with the rigor later trust requires, hash image output correctly, and work out how to preserve integrity under time pressure.

The goal is to make sure that when you decide to take a full image, you do it deliberately and methodically. Another analyst, or a legal reviewer six months later, should be able to trust the result. The goal is not to turn you into a hardware imaging specialist.

---

## What This Lab Covers

| Section | Topic |
|---|---|
| 3.2.1 | Why full imaging is still valuable in modern IR |
| 3.2.2 | When to image a Windows system instead of relying on triage alone |
| 3.2.3 | Documenting acquisition details and preserving integrity |
| 3.2.4 | Hashing, storage, and handling of forensic image files |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain when full disk imaging is justified in a Windows IR context
- Identify the operational and forensic benefits a full image provides over targeted triage
- Plan a defensible disk imaging workflow from acquisition through storage
- Document the minimum acquisition details required for later trust and repeatability
- Compute, record, and verify image hashes correctly
- Distinguish between preserving an original image and using a working copy for analysis

---

## Estimated Time

45–75 minutes

---

## Prerequisites

- Completion of Lab 3.1, or equivalent familiarity with triage vs. full imaging decisions
- A text editor or markdown editor
- Your `lab03.2-notes.md` file (template included in this folder)
- Optional: a Windows VM, VHD/VMDK/VHDX file, or any large non-sensitive file for hands-on hashing practice
- Optional: FTK Imager or a command-line imaging utility for demonstration

---

## Scenario

Your IR team has escalated a suspected compromise involving a Windows application server named **APP-12**. The system hosts an internal business application used across multiple departments. Analysts have already observed:

- Suspicious service creation recorded in System.evtx
- Unusual outbound network connections during off-hours
- Evidence that attacker tooling was executed and then deleted
- A pending request from legal to preserve evidence in case the incident expands into a contractual or regulatory matter

Management wants answers quickly, but legal has specifically asked whether the team can preserve the system in a way that supports later review. The host is still online. A maintenance window has been approved if acquisition requires downtime.

You have been asked to determine whether APP-12 should receive a full disk image — and if so, to plan and document the imaging process before collection begins.

---

## Background: Why Full Images Still Matter

Even in fast-moving IR, full images remain valuable when the system is important enough and the additional preservation is justified. A full image can recover:

- Deleted files and remnants of attacker tooling not captured in a triage set
- Unallocated space and file slack that triage parsers don't touch
- File system metadata beyond what targeted collection covers
- Artifacts you didn't know to look for at the time of collection
- A broader evidence base for peer review, legal proceedings, or re-analysis months later

Full imaging also has real operational costs, and you must weigh them explicitly.

| Factor | Full Disk Image | Targeted Triage |
|---|---|---|
| Evidence completeness | High | Moderate |
| Time to collect | High | Low |
| Storage burden | High | Low |
| Re-analysis value | High | Limited to collected artifacts |
| Scalability across many hosts | Low | High |
| Usefulness for legal preservation | Often strong | Depends on scope |

> **IR Reality Check:** Full imaging is not the default on the grounds that it is always best. It is justified when the added preservation value clearly outweighs the time, storage, and operational impact. Document that justification instead of assuming it.

---

## Lab Tasks

---

### Task 1 — Decide Whether APP-12 Warrants Full Imaging

**Objective:** Make and defend a full-image decision for a Windows server in an active incident.

**Part A — Decision summary**

| Host | Recommended Strategy | Primary Reason |
|---|---|---|
| APP-12 | | |

**Strategy options:**
- Full disk image + memory (before or during maintenance window)
- Targeted triage + memory now; full image deferred if legally required
- Targeted triage + memory only; full image not justified

**Part B — Decision rationale**

Answer each of the following in two or three sentences:

**1. What factors increase the case for full imaging APP-12?**

```
[Your response here]
```

**2. What factors might argue for targeted triage instead?**

```
[Your response here]
```

**3. If you choose full imaging, would you still perform memory acquisition or targeted triage first? Why?**

```
[Your response here]
```

**4. How does the legal preservation request change your decision compared to a case with no legal involvement?**

```
[Your response here]
```

> **Guidance:** Answer from an operational IR perspective, not from a "best-case forensic purity" perspective. A response that acknowledges constraints and explains tradeoffs is more defensible than one that recommends full imaging without justification.

---

### Task 2 — Define Acquisition Documentation Requirements

**Objective:** Identify the minimum information that must be recorded to make an image trustworthy for later use.

An image is evidence only when you can trace it to a specific source device, a named acquirer, a verified hash, and a documented tool and version. Without those, it is a file of unknown provenance.

**Part A — Acquisition record fields**

For each field, complete the table with what to record and why it matters.

| Field | What Should Be Recorded | Why It Matters |
|---|---|---|
| Case reference | | |
| Hostname | | |
| Acquisition date/time (UTC) | | |
| Acquired by | | |
| Authorized by | | |
| Source device description | | |
| Source drive serial / identifier | | |
| Source interface (SATA, USB, NVMe) | | |
| Write blocker used | | |
| Imaging tool used | | |
| Tool version | | |
| Output format (E01, RAW, AFF4) | | |
| Destination storage path | | |
| Hash algorithm(s) used | | |
| Image file name(s) | | |
| Image file size | | |
| Hash value(s) | | |
| Errors or interruptions | | |
| Notes / observations | | |

**Part B — Short answer**

Answer each in two or three sentences:

**1. Why does tool version matter for a forensic image?**

```
[Your response here]
```

**2. Why should source device identifiers be recorded before imaging begins?**

```
[Your response here]
```

**3. Why should acquisition notes explicitly include errors or interruptions — even minor ones?**

```
[Your response here]
```

---

### Task 3 — Build a Step-by-Step Imaging Workflow

**Objective:** Write a repeatable imaging process another responder could execute reliably under pressure.

Document a full imaging workflow for APP-12 across the five stages below. Be specific enough that a responder who was not present during the decision could execute each stage correctly.

---

**Stage 1 — Pre-Acquisition Preparation**

Write six to eight steps covering what you must confirm before imaging begins.

```
1. Confirm authorization — case reference, approving manager, written or verbal record
2. Confirm scope — which disk(s) on APP-12 are in scope; are secondary volumes included?
3. 
4. 
5. 
6. 
7. 
8. 
```

Items to consider: maintenance window approval, destination storage availability and free space, tooling readiness, write blocker availability and feasibility, whether memory should be captured first, whether the system should be shut down or imaged live.

---

**Stage 2 — Source Disk Identification**

Describe how you would identify and verify the correct source disk before imaging begins.

```
Steps:
1. 
2. 
3. 

Identifiers to record:
- 

Risk of imaging wrong drive and how to reduce it:

```

---

**Stage 3 — Imaging Execution**

Write the steps for the acquisition itself. Specify the tool, output format, naming convention, and when the tool generates hashes.

| Step | Action | Notes |
|---|---|---|
| 1 | Launch imaging tool with administrator privileges | |
| 2 | Select source device — verify serial matches documentation | Do not proceed if serial cannot be confirmed |
| 3 | Set output path and file naming per convention | See Task 4 for naming standard |
| 4 | Configure hash algorithm (SHA-256 minimum) | Enable tool-native hashing if available |
| 5 | Configure output format | E01 recommended for segmentation and metadata support |
| 6 | Begin acquisition — record start time (UTC) | |
| 7 | Monitor for errors throughout | Document any interruptions immediately |
| 8 | Record completion time and tool-reported hash | |

**FTK Imager reference** *(if using FTK Imager in your lab):*

```
File → Create Disk Image
Source: Physical Drive → select correct drive
Image Type: E01
Destination: [your output path per Task 4 naming convention]
Evidence Item Information: complete all fields
Hash: SHA-256 (enable verification after acquisition)
```

---

**Stage 4 — Hash Verification**

Answer each of the following:

```
When should hashes be calculated?


Which files should be hashed?


How should hash results be recorded?


Why verify hashes independently even if the imaging tool reports them?

```

**Hash verification command** *(PowerShell — for local verification of image file):*

```powershell
Get-FileHash -Algorithm SHA256 "D:\Evidence\APP-12_IR2024_disk0.E01" |
  Select-Object Algorithm, Hash, Path |
  Export-Csv "D:\Evidence\APP-12_IR2024_disk0_hash.csv" -NoTypeInformation
```

---

**Stage 5 — Post-Acquisition Handling**

Document what happens after imaging completes.

```
Storage location for original image:    
Working copy created:                   [Yes / No]
Working copy location:                  
Original image write-protected:         [Yes / No — how?]
Chain of custody updated:               [Yes / No]
Evidence handling record updated:       [Yes / No]
Next analysis action:                   
```

> **Rule:** Never mount, parse, or analyze the original image directly. Perform all analysis on a verified working copy. Store the original separately and access it only to create new verified copies.

---

### Task 4 — Design an Image Naming and Storage Standard

**Objective:** Create a repeatable naming and storage convention that eliminates ambiguity across cases and analysts.

**Part A — Naming convention**

Define a naming standard for each output type. Your convention should encode enough information to identify a file without opening it.

| Item | Proposed Naming Convention | Example |
|---|---|---|
| Primary image file | `[CaseID]_[Hostname]_[YYYYMMDD]_disk[N].[ext]` | `IR2024001_APP12_20241114_disk0.E01` |
| Segmented image set | | `IR2024001_APP12_20241114_disk0.E01`, `.E02`, `.E03` |
| Hash record | | |
| Acquisition note | | |
| Working copy | | |
| Memory image | | |

**Part B — Storage structure**

Define a folder structure for the APP-12 case. Document it below and explain the purpose of each folder.

```
IR-Cases\
└── IR-2024-APP12\
    ├── 00_Admin\
    │   ├── authorization.md
    │   ├── chain-of-custody.md
    │   └── case-open-note.md
    ├── 01_Acquisition\
    │   ├── Original_Image\     ← [purpose]
    │   ├── Hashes\             ← [purpose]
    │   └── Notes\              ← [purpose]
    ├── 02_Working_Copy\        ← [purpose]
    └── 03_Analysis\            ← [purpose]
```

Fill in the purpose of each folder and add any subfolders you would need for APP-12 specifically.

---

### Task 5 — Hash a Sample Evidence File

**Objective:** Practice recording integrity information correctly using a real file in your lab environment.

Use any large non-sensitive file available in your lab — a VM disk file, ISO, ZIP archive, or exported VHD. This simulates hashing a forensic image without requiring a real acquisition.

**Part A — Compute the hash**

```powershell
# PowerShell
Get-FileHash -Algorithm SHA256 "C:\Path\To\SampleFile.bin" |
  Select-Object Algorithm, Hash, Path
```

```bash
# Bash (Linux/macOS)
sha256sum /path/to/samplefile.bin
```

**Part B — Record the result**

| Item | Value |
|---|---|
| **File Name** | |
| **File Path** | |
| **File Size** | |
| **SHA-256** | |
| **Date/Time Hashed (UTC)** | |
| **Hashed By** | |
| **Tool Used** | |
| **Tool Version** | |

**Raw tool output:**

```
[Paste exact output here]
```

**Part C — Short answer**

Answer each in two or three sentences:

**1. Why does hashing matter before analysis begins, not just after?**

```
[Your response here]
```

**2. Why should the hash record be stored separately from the image file itself?**

```
[Your response here]
```

**3. What would you do if you verified the hash of your working copy and it did not match the original?**

```
[Your response here]
```

---

### Task 6 — Write an Acquisition Note

**Objective:** Produce a concise, defensible imaging note suitable for the APP-12 case file.

Write a short acquisition note as if imaging of APP-12 has just finished or is about to begin. Fill in every field. If a field is genuinely unknown at the time of writing, note what is unknown and when it will be resolved.

```
# Disk Acquisition Note — APP-12
Case Reference:       
Author:               
Date/Time (UTC):      

Host:                 APP-12
Reason for Imaging:   
Authorized By:        
Maintenance Window:   [Yes / No — start/end time if applicable]

Source Disk:
  Description:        
  Serial / ID:        
  Interface:          
  Size:               

Imaging Tool:         
Tool Version:         
Output Format:        
Output Location:      
File Name(s):         

Hash Algorithm:       SHA-256
Hash Value:           
Verified:             [Yes / No]
Verification Method:  

Errors / Notes:       

Next Step:            
```

---

### Task 7 — Reflection

Answer the following in three to five sentences each:

**1. Imaging versus urgency**
Why might a responder choose not to fully image a host even when they know a full image would preserve more evidence? When is that a reasonable professional judgment and when is it a mistake?

```
[Your response here]
```

**2. Legal preservation versus operational practicality**
How does a legal preservation request change the imaging discussion, even during an active incident where time is critical? What obligations does that request create?

```
[Your response here]
```

**3. Trust through documentation**
Why is a poorly documented image almost as problematic as not having one at all? What specific documentation failures would most undermine trust in an image?

```
[Your response here]
```

**4. The danger of analyzing originals**
Why should the original image be preserved separately and a working copy used for analysis? What could go wrong if this rule is skipped under time pressure?

```
[Your response here]
```

---

## Deliverables Checklist

Your `lab03.2-notes.md` should contain:

- [ ] **Task 1** — Full imaging decision for APP-12 with four written rationale answers
- [ ] **Task 2** — Acquisition documentation table completed with why-it-matters column and three short answers
- [ ] **Task 3** — Step-by-step imaging workflow across all five stages
- [ ] **Task 4** — Naming convention table and storage structure with folder purposes documented
- [ ] **Task 5** — Sample file hash record, raw output, and three short answers
- [ ] **Task 6** — Complete acquisition note for APP-12
- [ ] **Task 7** — Reflection answers (three to five sentences each)

---

## Files in This Folder

```
Lab03/
├── lab03-notes.md    ← Your working notes file (whole lab)
└── Lab03_02/
    ├── ReadMe.md         ← This file
    └── lab03.2-notes.md  ← Your working notes file
```

---

## Key Takeaways

- **A full image is a preservation decision.** It is justified when the additional evidence it retains is worth the time, storage, and operational cost. Document that justification.
- **Imaging without documentation is weak evidence handling.** Tool, version, source disk identifiers, hashes, and acquisition notes are what make the image trustworthy. They are not optional extras.
- **Hashes are not optional.** They show that evidence has not changed between acquisition and analysis, however many months apart those are.
- **Originals must be preserved.** Analysis belongs on a verified working copy. Store the original image separately and never mount it directly.
- **Full imaging still has a place in IR.** It is not always the first move. When the case needs legal preservation, deep re-analysis, or reconstruction of a high-value host, image carefully and methodically, with a complete acquisition record.

---

**Next:** Lab 3.3 — Memory Acquisition Basics

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
