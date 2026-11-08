# Lab 1.3 — Authorization, Legal Considerations, and Chain of Custody

**Supporting Section 1.3: Authorization, Legal Considerations, and Chain of Custody**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Forensic evidence is only as credible as the process used to collect it.

You can analyze artifacts perfectly, with correct timestamps, accurate conclusions, and solid tool output, and still have your findings discounted or thrown out. That happens when nobody can answer basic questions: *Who authorized this? What did you collect? Did the evidence change between collection and analysis?*

Authorization, scope, and chain of custody are not bureaucratic overhead. They are the foundation that makes your findings trustworthy to legal counsel, regulators, HR, executive leadership, and, if it comes to it, a court. They also protect *you*. A responder who documents everything is far harder to second-guess than one who acted without a paper trail.

This lab makes those habits concrete before you start collecting real artifacts.

---

## Learning Objectives

By completing this lab, you will be able to:

- Confirm and document authorization before touching a system
- Define a defensible collection scope that limits overreach and legal exposure
- Identify and document an evidence item with all required metadata
- Compute and record a SHA-256 hash as part of evidence documentation
- Maintain a chain-of-custody log through acquisition, transfer, and analysis
- Articulate why documentation discipline matters even in purely internal investigations

---

## Estimated Time

30–45 minutes

---

## Prerequisites

- A Windows lab VM or forensic image (from Lab 01 setup)
- At least one evidence item to document — choose one:
  - A virtual disk file (`.vmdk`, `.vhdx`)
  - A memory dump
  - A ZIP archive of collected artifacts
  - A registry hive export
  - An event log export
- Access to a hashing tool:
  - PowerShell (`Get-FileHash`) — built into Windows, no install required
  - `sha256sum` — Linux/macOS
  - FTK Imager — hash during acquisition
- Your `lab1.3-notes.md` file (template included in this folder)

---

## Background: Why These Three Things Matter

### Authorization

Before you touch any system in a real incident, you need to be able to answer: *do I have permission to do this?*

Depending on your context, authorization can come from internal IR policy, a management directive, HR approval, legal counsel, or a formal retainer agreement. The source matters. "I assumed it was fine" is not authorization. Acting without authorization can expose you and your organization to legal liability, undermine any findings you produce, and complicate external reporting obligations.

### Scope

Scope defines what you are collecting and — just as importantly — what you are *not* collecting. Collecting beyond your authorized scope can create additional legal exposure, sweep up personal data from other jurisdictions, and generate obligations your organization may not be prepared to handle.

Good scope documentation answers: *what system, what data, and why?* If you find yourself collecting something you didn't plan to collect, stop and document the decision before continuing.

### Chain of Custody

Chain of custody is a chronological record of who handled the evidence, when, and what they did to it. It answers the question any reviewer will eventually ask: *how do we know this evidence hasn't been altered?*

The hash you compute at acquisition is your baseline. Every subsequent verification that produces the same hash confirms the evidence is unchanged. A mismatch at any point is a serious problem that requires immediate documentation and escalation.

---

## Lab Tasks

---

### Task 1 — Define Authorization

**Objective:** Practice documenting authorization before taking forensic action.

For this lab you are working in your own environment, so formal authorization isn't required. The point is to practice the *habit* of documenting it before you act.

Write a short authorization statement that answers:

- Who authorized this activity? (In the lab: yourself, or a named hypothetical approver)
- What is the authority basis? (IR policy, management direction, HR request, legal instruction, retainer agreement)
- When was authorization confirmed?
- Are there any conditions or limitations on your authority?

Use this template in `lab1.3-notes.md`:

```
Authorized By:        
Authorization Type:   [Internal IR Policy / Management Direction / HR / Legal / Retainer]
Date/Time Confirmed:  
Conditions or Limits: 
Notes:                
```

> **Real incident note:** In a real incident, complete this entry *before* any collection begins. If you're acting under verbal authorization, document who gave it and follow up with written confirmation as soon as possible.

---

### Task 2 — Define Collection Scope

**Objective:** Practice scoping a collection effort before touching any evidence.

Document what is in scope and explicitly what is out of scope for your collection. Vague scope creates problems later.

Complete the following in your notes file:

```
System Name / Identifier:    
Asset Owner:                 
Reason for Collection:       
Authorized Collector:        

In Scope:
  - [List specific artifacts, directories, hives, logs, or disk images you will collect]

Out of Scope:
  - [List anything you are explicitly NOT collecting and why]

Special Handling Considerations:
  - [Personal data? Regulated data? Data from other jurisdictions? Sensitivity level?]
```

> **Scope creep warning:** If during collection you discover something outside your defined scope that appears relevant, do not simply collect it. Document the discovery, pause, and seek authorization to expand scope before proceeding.

---

### Task 3 — Identify and Document the Evidence Item

**Objective:** Create a complete evidence record for the item you will hash and log.

Choose one item from your lab environment to treat as evidence. Fill in every field, and leave nothing blank. If a field genuinely does not apply, write `N/A` and explain briefly.

```
Evidence ID:             [Assign a unique ID, e.g. LAB01-003-001]
Description:             [What is this item?]
Evidence Type:           [Disk image / Memory dump / Archive / Registry hive / Log export]
Source System:           [Hostname or VM name]
Source Path:             [Full file path on source]
Acquiring Tool:          [e.g. FTK Imager, PowerShell, manual copy]
Acquiring Tool Version:  
Collector Name:          
Date/Time Acquired:      [UTC preferred]
Storage Location:        [Where is the file stored now?]
Notes:                   
```

> **Why UTC?** Always record incident response timestamps in UTC to avoid ambiguity across time zones, especially when correlating artifacts from multiple systems. Record the local time as well if it helps, but always include UTC.

---

### Task 4 — Compute and Record a SHA-256 Hash

**Objective:** Hash your evidence item and record the result as part of the evidence record.

Compute a SHA-256 hash of the evidence file you documented in Task 3.

**PowerShell (Windows):**
```powershell
Get-FileHash -Algorithm SHA256 "C:\Path\To\Your\evidence-file.vhdx"
```

**Bash (Linux/macOS):**
```bash
sha256sum /path/to/evidence-file.vhdx
```

**FTK Imager:**
FTK Imager verifies the hash when it creates an image, if you tick *Verify images after they are created*. To check an existing image, use *File > Verify Drive/Image*. FTK Imager 4.x reports MD5 and SHA-1 on both routes, so take the SHA-256 from one of the commands above.

Record the result in your notes file:

```
Evidence ID:        
File Name:          
File Size:          
Hash Algorithm:     SHA-256
Hash Value:         
Date/Time Hashed:   [UTC]
Hashed By:          
Tool Used:          
Tool Version:       
```

> **Why SHA-256 and not MD5?** MD5 is still widely used and fast, but it is cryptographically broken: collisions are achievable. SHA-256 is the current standard for forensic evidence hashing. Use MD5 only if a specific tool or process requires it, and supplement with SHA-256.

---

### Task 5 — Maintain a Chain-of-Custody Log

**Objective:** Record every interaction with your evidence item from acquisition through analysis.

Fill in the log below as you work through the lab. Add an entry every time you access, move, copy, or analyze the evidence. The log should be able to answer: *who touched this, when, and what did they do?*

| # | Date/Time (UTC) | Evidence ID | Action | Handler | From Location | To Location | Hash Verified? | Notes |
|---|---|---|---|---|---|---|---|---|
| 1 | | | Acquired | | | | Yes / No | Initial collection |
| 2 | | | Copied (working copy) | | | | Yes / No | |
| 3 | | | Analyzed | | | | Yes / No | |
| 4 | | | | | | | | |

> **Working copies:** Analyze a *copy* of your evidence, not the original. Store the original separately, and access it only to create new verified copies. Record the creation of the working copy as a separate log entry with its own hash.

---

### Task 6 — Record Storage and Access Controls

**Objective:** Document where evidence is stored and how access is restricted.

```
Original Evidence Location:   
Working Copy Location:        
Backup Location:              
Access Restrictions:          [Who can access this? Password protected? Encrypted?]
Original Preserved Separately:[Yes / No]
Working Copy Created:         [Yes / No]
Retention Notes:              [How long should this be kept? Any disposal requirements?]
Notes:                        
```

---

### Task 7 — Reflection

Answer the following in 3–5 sentences each in your notes file.

**1. Real incident differences**
What would be different about this process if this were a real incident rather than a lab exercise? Think about approvals, timing, communication, and pressure.

**2. Stakeholder notification**
In a real incident, who would need to be notified or approve before collection began? Consider legal, HR, management, and any external obligations.

**3. Chain-of-custody failures**
What risks arise if the chain of custody is incomplete, inconsistent, or missing entries? Give at least two concrete scenarios where a gap in the log could cause a problem.

**4. Hashing in internal investigations**
Why does hashing matter even when there is no plan to involve law enforcement or external parties? Give at least two reasons.

**5. Scope decisions under pressure**
You're in the middle of a live incident. You've scoped your collection to event logs and prefetch, but you notice a suspicious directory full of files that isn't in your scope. What do you do?

---

## Optional Challenge

Complete one or more of the following to extend this lab:

**A — Dual hash record**
Compute both MD5 and SHA-256 hashes for your evidence item. Document both. Discuss in your notes why you would or wouldn't use MD5 alone.

**B — Working copy workflow**
Create a verified copy of your evidence file. Hash both the original and the copy. Confirm they match. Record each step in your chain-of-custody log as separate entries.

**C — Team-ready template**
Take the chain-of-custody table from Task 5 and convert it into a reusable form for your team — add a signature field for transfers, a case reference block at the top, and a hash-verification footer. Save it as `CoC_Form_v1.md` in this folder.

**D — Scope challenge**
Write a one-paragraph scope statement for a realistic scenario: a domain controller suspected of being used for credential harvesting. Define what you would and would not collect, and explain your reasoning.

---

## Deliverables Checklist

Your `lab1.3-notes.md` should contain:

- [ ] **Task 1** — Authorization statement with all fields completed
- [ ] **Task 2** — Scope documentation with explicit in-scope and out-of-scope items
- [ ] **Task 3** — Complete evidence item record with all fields filled
- [ ] **Task 4** — SHA-256 hash record with tool, version, and timestamp
- [ ] **Task 5** — Chain-of-custody log with at least three entries
- [ ] **Task 6** — Storage and access control documentation
- [ ] **Task 7** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab01/
└── Lab01_03/
    ├── ReadMe.md                       ← This file
    ├── chain_of_custody_template.docx  ← Chain-of-custody form (binary — open in Word)
    └── lab1.3-notes.md                 ← Your working notes file
```

---

## Key Takeaways

- **Authorization comes first.** Document who approved the activity, under what authority, and when — before you touch anything.
- **Scope limits liability.** Explicitly defining what you will and will not collect protects you, your organization, and the people whose data is on the system.
- **The hash is your proof.** A hash computed at acquisition and verified at each later step lets anyone confirm the evidence hasn't changed.
- **Chain of custody is a habit, not a form.** The value comes from consistent, complete entries, not from having the right template.
- **Working copies protect originals.** Always analyze a copy. The original is your ground truth.

---

**Next:** Lab 1.4 — Standing Up a Windows IR Lab

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
