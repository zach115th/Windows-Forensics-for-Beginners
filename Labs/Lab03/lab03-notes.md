# Lab 03 — Analyst Notes
**Digital Forensics and Advanced Data Triage**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Lab Environment:** ___________________________  
**Case Reference:** IR-2024-TRIAGE03  

---

## Task 1 — Collection Strategy Decisions

**Part A — Per-host strategy table**

> Evaluate each host. Assign a collection strategy and justify it.
> Strategy options: Full disk image + memory / Targeted triage + memory / Memory only / Deferred

| Host | Business Criticality | Suspected Threat Value | Volatile Evidence Risk | Recommended Strategy | Justification |
|---|---|---|---|---|---|
| DC-01 | | | | | |
| FIN-WS23 | | | | | |
| KIOSK-07 | | | | | |

---

**Part B — Priority and sequencing**
Which host do you collect from first, and why?
Which host most strongly justifies a full disk image, and why?
Which host is the best candidate for targeted triage, and why?
What single new piece of information would change your collection
order entirely? What would it be and why would it matter?
---

## Task 2 — Minimum Viable Triage Package

**Part A — Investigative questions**

> At least 6 specific, answerable questions your triage package must address for FIN-WS23.





---

**Part B — Question to artifact mapping**

| # | Investigative Question | Primary Artifact | Corroborating Artifact |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |
| 6 | | | |

---

**Part C — Collection tier structure**

> Assign each artifact to a tier. Reasoning must be tied to investigative need, not general best practice.

| Tier | Description | Artifacts | Reasoning |
|---|---|---|---|
| **Tier 1** | Collect in every Windows compromise — no justification needed | | |
| **Tier 2** | Collect when time and access permit — strong IR value | | |
| **Tier 3** | Collect when a specific hypothesis justifies it | | |

---

**Part D — What you are not collecting**

> List at least 3 artifact types you are explicitly excluding and the risk you accept by doing so.

| Not Collected | Risk Accepted |
|---|---|
| | |
| | |
| | |

---

## Task 3 — Triage Collection Script Design

**Part A — Script parameters**

> Define all parameters for Get-WinIRArtifacts.ps1.

```powershell
param (
    [Parameter(Mandatory=$true)]
    [string]$CaseID,

    [Parameter(Mandatory=$true)]
    [string]$OutputPath,

    [Parameter(Mandatory=$false)]
    [switch]$IncludeMemory,

    [Parameter(Mandatory=$false)]
    [switch]$IncludeBrowser,

    # Add your parameters here

)

Part B — Working directory structure
Define the folder layout the script creates. Note any additions or changes for FIN-WS23.
[CaseID]_[Hostname]_[Timestamp]\
├── Memory\
├── Registry\
├── EventLogs\
├── Filesystem\
├── ExecutionArtifacts\
├── Network\
├── Hashes\
└── CollectionLog\
Additions or changes for FIN-WS23:
[Your notes here]
Part C — Collection functions
Function / Section
Purpose
Key Consideration
Initialize-Collection
Create output directories and validate parameters
Fail fast if OutputPath is unavailable or CaseID is blank
Get-SystemMetadata
Capture hostname, IP, username, OS version, timestamp
Run first — metadata anchors the entire collection
Copy-RegistryHives
Export offline copies of key registry hives
Hives may be locked — handle gracefully
Export-EventLogs
Copy EVTX files to output directory
Check for locked files; log any skipped
Collect-ExecutionArtifacts
Prefetch, Amcache, SRUM, LNK, Jump Lists
Some paths require elevation
Compress-Collection
Create ZIP archive of output folder
Exclude Hashes folder from archive
Write-Hashes
Compute SHA-256 of archive and key files
Hash after compression is complete
Write-CollectionLog
Write structured log of all actions
Log must be written outside the archive






Part D — Logging requirements
List at least 10 events that must always generate a log entry.
Log entry format: [DateTime UTC] | [Function] | [Status] | [Detail]
Status values:    INFO / SUCCESS / WARNING / ERROR / SKIPPED

Required log events:
1.  Script start — parameters, hostname, analyst name
2.  Each directory created
3.  Each file copy attempted — success or failure
4.  Each locked or inaccessible file
5.  
6.  
7.  
8.  
9.  
10.
Part E — Safety and scope considerations
- 
- 
- 
- 
- 
- 
- 
-
Part F — Optional prototype
If completing the hands-on prototype, paste your script here.
# Get-WinIRArtifacts-Prototype.ps1
# Non-destructive prototype — creates folder structure, copies test files,
# compresses, and hashes output.

param (
    [string]$CaseID = "TEST-001",
    [string]$OutputPath = "E:\IR\Test"
)

# Stage 1: Create working directory


# Stage 2: Copy test files


# Stage 3: Compress


# Stage 4: Hash


# Stage 5: Log
Task 4 — Package and Hash a Triage Collection
Part A — Sample package confirmation
Folder structure created:   [Yes / No]
Test files added:           [Yes / No]
collection-notes.txt added: [Yes / No]
Notes file contents:        
  Case ID:      
  Hostname:     
  Collector:    
  Date/Time:    
  Contents:
Part B — Compression command used
[Paste exact command here]
Part C — Hash record
Item
Value
Archive Name

Archive Path

File Size

SHA-256

Date/Time Hashed (UTC)

Hashing Tool

Hashing Tool Version

Raw hash output:
[Paste tool output here]
Part D — Evidence handling record
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
Part E — Defensibility statement
[Paragraph 1 — why this targeted triage package is still trustworthy evidence]


[Paragraph 2 — limitations compared to a full image; when a full image is required]
Task 5 — Management Justification Memo
Save the completed memo as Management_Justification_Targeted_Triage.md in this folder.
Record the file location and a brief summary here.
Memo file:      Management_Justification_Targeted_Triage.md
Saved to:       Lab03/
Date completed: 

Summary of key points made:
1. 
2. 
3.
```

---

## Task 6 — Walk the Acquisition Decision Tree

**Part B — Decision-tree walk**

> One row per scenario. Keep the acquisition order numbered — the order is the answer.
> Path notation: powered on/off → logged in? → admin? → encrypted? → triage enough? → physical or logical.

| # | Host | Path through the tree | Acquisition order | Tool choice | What you lose by getting it wrong | What you document |
|---|---|---|---|---|---|---|
| 1 | WKSTN-118 | | | | | |
| 2 | SALES-LT44 | | | | | |
| 3 | EXEC-LT09 | | | | | |
| 4 | CONTRACT-LT07 | | | | | |
| 5 | APP-SRV-04 | | | | | |
| 6 | ENG-DT22 | | | | | |

---

**Part C — Physical or logical**

> Identify the two scenarios that push toward a logical image, and say what you give up.

```
Scenario ___ — logical because:


  What is given up:


Scenario ___ — logical because:


  What is given up:
```

---

**Part D — Reflection on the tree**

**1. Why memory goes first**
Memory is not always the most valuable artifact. Why does it still go first on every live host you can capture from? Answer in terms of what threatens each artifact, not what each contains.

```
[Your response here]
```

**2. "Powered off" is not the same as "no memory"**
What might still be on EXEC-LT09's disk that behaves like memory evidence, why does it exist, and what does that change about the files you list explicitly in your collection?

```
[Your response here]
```

**3. Writing up an unrecoverable position**
Write the two or three sentences you would put in the report for CONTRACT-LT07, then state what the organisation should take away from it and where the fix belongs.

```
[Your response here]
```

**4. Booting evidence on purpose**
For ENG-DT22: what conditions must be satisfied first, what does the capture prove, and what does it not prove?

```
[Your response here]
```

---

**Acquisition checklist**

> Fill in `acquisition-checklist.md` for at least one scenario above. Record which one and anything the checklist forced you to think about that the table did not.

```
Scenario used:      
Checklist copy saved to:      
What the checklist surfaced that the table did not:
```

---

## Task 7 — Reflection

**1. Completeness versus speed**
Why is "collect everything" sometimes a bad IR strategy? Give a specific scenario where imaging every host first would have made the incident worse.

```
[Your response here]
```

**2. The cost of delayed memory capture**
Why can delayed memory capture be more damaging than delayed disk artifact collection? What specific evidence categories are at risk?

```
[Your response here]
```

**3. Documenting your rationale**
How does writing down your collection reasoning protect you professionally if someone later questions your decisions? What documentation would you point to?

```
[Your response here]
```

**4. When new facts change the plan**
You learn DC-01 logged a successful authentication from FIN-WS23's IP at 07:01 UTC — three minutes after the PowerShell execution. How does that change your collection priorities and why?

```
[Your response here]
```

---

## Additional Notes

```
[Free text — questions, observations, connections to real work, things to follow up on]
```

---

*Lab 03 Notes — Windows Forensics for Beginners*
*Keep this file in your `Labs/Lab03/` folder alongside the `ReadMe.md`.*
