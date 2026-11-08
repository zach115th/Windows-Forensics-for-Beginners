# Lab 2.2 — High-Level Process in an Incident

**Supporting Section 2.2: High-Level Process in an Incident**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Knowing which artifacts exist is only half the job. The other half is knowing *when* to collect them, in what order, and how to move from raw evidence to defensible conclusions. That half separates a structured investigation from an expensive fishing expedition.

This lab builds a repeatable incident workflow you can apply under time pressure and with incomplete information. You'll work through each phase of a Windows investigation: initial triage, scoping, targeted collection, hypothesis testing, timeline construction, and reporting. The scenario is realistic and doesn't give you all the answers up front.

Real incidents don't move in a clean sequence. You'll often be triaging one host, collecting from another, and briefing leadership simultaneously. The process in this lab is a mental model for staying organized when everything is moving at once, not a rigid checklist.

---

## Learning Objectives

By completing this lab, you will be able to:

- Perform structured initial triage on a suspected Windows compromise
- Make a defensible containment decision with limited information
- Identify which systems, accounts, and artifacts to prioritize first
- Build a targeted evidence collection workflow for live host response
- Form specific investigative hypotheses and identify the evidence needed to test them
- Construct a basic forensic timeline from multiple artifact sources
- Translate forensic findings into concrete response recommendations

---

## Estimated Time

60–90 minutes

---

## Prerequisites

- Completion of Lab 01 and Lab 2.1 (or equivalent)
- Your Windows lab VM running and accessible
- Your `question-evidence-worksheet.md` from Lab 2.1
- A text editor or markdown editor
- Your `lab02.2-notes.md` file (template included in this folder)
- Optional: FTK Imager, EZ Tools, and PowerShell available in your VM

---

## Scenario

At 14:23 UTC your SOC escalates the following:

> *"EDR on WKSTN-221 triggered on a suspicious process chain: OUTLOOK.EXE → POWERSHELL.EXE → CMD.EXE. The PowerShell command line was partially captured: `-EncodedCommand [base64 string]`. Four seconds after PowerShell started, the host opened an outbound connection to 91.214.47.22 on port 443. Three more connections followed between 14:21 and 14:22 UTC, consistent with an implant beaconing to 91.214.47.22:443. The assigned user is a payroll administrator with access to HR systems and a shared finance file server (FILESVR-03). The EDR agent is active but did not block the activity. No other hosts have been flagged yet. The user is currently at their desk."*

You now have enough to start. You do not have enough to finish.

---

## Background: The Six-Phase IR Workflow

Section 2.2 covers each phase of the workflow below. This lab walks you through all six, applied to the scenario above.

| Phase | Core Activity | Key Output |
|---|---|---|
| **1. Initial Triage** | Establish urgency and scope; decide on containment | Triage note and containment decision |
| **2. Scoping and Prioritization** | Identify related hosts, accounts, and data; rank evidence | Scope statement and collection priority list |
| **3. Targeted Collection** | Acquire the artifacts that answer your questions | Collected evidence with hashes and CoC entries |
| **4. Hypothesis Testing** | Form specific hypotheses; test against evidence | Supported and eliminated hypotheses |
| **5. Timeline Construction** | Build a time-ordered view of key events | Merged artifact timeline |
| **6. Reporting and Remediation** | Translate findings into recommendations | Technical findings and executive summary |

---

## Lab Tasks

---

### Task 1 — Initial Triage

**Objective:** Establish urgency, assess containment need, and document what you know in the first five minutes.

Initial triage is not analysis. It is rapid assessment: is the attacker still active, how bad could this get, and what needs to happen right now?

**Part A — Triage checklist**

Work through the following checklist for WKSTN-221. Answer each item based on the scenario information available. Where you don't have enough information, note what you would check and how.

| Triage Item | Status / Finding | How You Would Verify |
|---|---|---|
| Is a suspicious process currently running? | | |
| Is there an active outbound C2 connection? | | |
| Is the assigned user currently logged on? | | |
| Has the EDR agent been tampered with or disabled? | | |
| Are there other active sessions on this host? | | |
| Is this host joined to a domain? | | |
| What privileged access does the assigned user have? | | |
| Have any other hosts been flagged by EDR? | | |
| Has any data left the network in the past hour? | | |
| Is there an active incident response retainer or escalation path? | | |

**Part B — Containment decision**

Write a containment recommendation for WKSTN-221. Your recommendation should be one of the following: isolate immediately, monitor and collect before isolating, or do not isolate. Support your recommendation with at least three specific reasons drawn from the scenario.

```
Recommendation:   [Isolate / Monitor and collect / Do not isolate]

Reason 1:         
Reason 2:         
Reason 3:         

Risk if wrong:    [What happens if your recommendation turns out to be the wrong call?]
```

**Part C — Triage note**

Write a triage note as if it were the first entry in your case record. Keep it under 10 lines. It should capture what is known, what is active, and what decision you made.

```
Date/Time (UTC):  
Case Reference:   IR-2024-WKSTN221
Analyst:          

Active threat indicators:     
Containment status:           
Immediate actions taken:      
Next step:                    
```

---

### Task 2 — Scoping and Prioritization

**Objective:** Identify what else may be affected and decide what to collect first.

Scoping happens in parallel with triage. While one analyst is on the host, another should be pulling account activity, checking related systems, and mapping the potential blast radius.

**Part A — Scope map**

Based on the scenario, complete the scope map below. Fill in what you know and flag what you need to find out.

```
Primary Host:         WKSTN-221
Assigned User:        [payroll administrator — name unknown]
User's Access:        HR systems, FILESVR-03 (finance file server)
Domain:               [unknown — flag for verification]
Active C2 IP:         91.214.47.22

Related Systems to Check:
  - FILESVR-03:       [Why? What would you look for?]
  - Domain Controller:[Why? What would you look for?]
  - HR systems:       [Why? What would you look for?]
  - Email gateway:    [Why? What would you look for?]

Related Accounts to Check:
  - Assigned user account:    
  - Any service accounts with same access:  
  - Admin accounts that logged into WKSTN-221: 

External Indicators:
  - 91.214.47.22:     [What would you look up? What sources would you check?]
```

**Part B — Evidence priority list**

Rank the following artifact types in the order you would collect them from WKSTN-221. The C2 beaconing has not been contained. Explain your top three choices.

| Priority | Artifact | Volatile? | Reasoning |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |
| 6 | | | |
| 7 | | | |
| 8 | | | |

*Artifact pool to rank: memory dump, running processes, active network connections, Security.evtx, PowerShell operational logs, Prefetch, MFT, registry hives (SYSTEM/SOFTWARE/NTUSER.DAT), SRUM database, LNK files and jump lists, Amcache*

---

### Task 3 — Targeted Evidence Collection

**Objective:** Build a specific, documented collection workflow for WKSTN-221.

This task produces the collection procedure you would follow on the live host. Write it specifically enough that another responder could execute it correctly with the tools available in your lab VM.

**Part A — Volatile evidence capture**

Write the exact PowerShell commands you would run to capture volatile state from WKSTN-221. For each command, specify the output file path and what you expect it to contain.

```powershell
# 1. Running processes
Get-Process | Select-Object Name, Id, Path, StartTime, Company |
  Export-Csv "E:\IR\WKSTN-221\volatile\processes_$(Get-Date -Format yyyyMMdd_HHmmss).csv" -NoTypeInformation

# 2. Active network connections
[Add your command here]

# 3. Logged-on users
[Add your command here]

# 4. Recently modified files (last 24 hours)
[Add your command here]

# 5. Scheduled tasks
[Add your command here]

# 6. Services
[Add your command here]
```

**Part B — Memory acquisition**

Describe how you would acquire memory from WKSTN-221 using a tool available in your lab. Specify the tool, the command, the output location, and how you would hash the output.

```
Tool:               
Tool version:       
Command:            
Output file:        
Output location:    E:\IR\WKSTN-221\memory\
Hash command:       
Hash algorithm:     SHA-256
Notes:              
```

**Part C — Artifact collection table**

Complete the collection table for the non-volatile artifacts on your priority list.

| Artifact | Source Path | Collection Tool | Command or Method | Output Path | Notes |
|---|---|---|---|---|---|
| Security.evtx | `%SystemRoot%\System32\winevt\Logs\Security.evtx` | xcopy / PowerShell | | `E:\IR\WKSTN-221\artifacts\logs\` | |
| System.evtx | | | | | |
| PowerShell operational log | | | | | |
| Prefetch | `%SystemRoot%\Prefetch\` | | | | |
| MFT | Volume root | MFTECmd | | | Requires admin or live acquisition tool |
| SYSTEM hive | | | | | |
| SOFTWARE hive | | | | | |
| NTUSER.DAT | | | | | |
| SRUM database | | | | | |
| LNK files | | | | | |
| Amcache | | | | | |

**Part D — Collection hash record**

After collecting and archiving your artifacts, record the package hash.

```
Archive name:           WKSTN-221_artifacts_[date].zip
Archive location:       
Hash algorithm:         SHA-256
Hash value:             
Date/time hashed (UTC): 
Hashed by:              
Tool used:              
```

---

### Task 4 — Hypothesis Testing

**Objective:** Form specific hypotheses about what happened on WKSTN-221 and identify the evidence needed to confirm or eliminate each one.

Hypothesis testing separates analysis from browsing. A hypothesis is a specific, testable statement about attacker behavior. For each hypothesis you form, you should be able to name the artifact and specific data point that would confirm it, and the artifact and data point that would eliminate it.

**Part A — Build your hypothesis set**

Write at least five hypotheses for the WKSTN-221 scenario. Use this format:

```
Hypothesis 1:
  Statement:        The attacker used a malicious macro in an Outlook attachment to execute PowerShell
  Confirms if:      Prefetch shows POWERSHELL.EXE ran seconds after an Office document opened;
                    Security.evtx EID 4688 shows OUTLOOK.EXE → POWERSHELL.EXE process chain
  Eliminates if:    PowerShell was spawned by a non-Office process;
                    No Office document in recent LNK/jump list entries at the relevant time
  Current status:   Unconfirmed

Hypothesis 2:
  Statement:        
  Confirms if:      
  Eliminates if:    
  Current status:   Unconfirmed

Hypothesis 3:
  Statement:        
  Confirms if:      
  Eliminates if:    
  Current status:   Unconfirmed

Hypothesis 4:
  Statement:        
  Confirms if:      
  Eliminates if:    
  Current status:   Unconfirmed

Hypothesis 5:
  Statement:        
  Confirms if:      
  Eliminates if:    
  Current status:   Unconfirmed
```

**Part B — Hypothesis triage**

Not all hypotheses are equally urgent. Rank your five hypotheses by investigation priority and explain your ordering. Which hypothesis, if confirmed, would most change your containment or remediation response?

| Priority | Hypothesis # | Why It's Urgent | What Changes if Confirmed |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |

---

### Task 5 — Timeline Construction

**Objective:** Build a time-ordered view of key events from multiple artifact sources.

A forensic timeline merges timestamps from different artifact types into a single chronological record. Its value is correlation. An event that appears in Prefetch, Security.evtx, and the MFT at the same time is far more reliable than one that appears in only one source.

**Part A — Simulated timeline exercise**

The following events come from artifacts on a hypothetical system. Place them in chronological order and identify the artifact source for each. Then answer the analysis questions below.

*Events (unordered):*

```
A.  POWERSHELL.EXE prefetch entry — last run time 14:19:38 UTC, run count 3
B.  Security.evtx EID 4624 — logon type 3, account: payroll-admin, source IP: 10.0.4.17, time: 14:31:05 UTC
C.  MFT record — update.exe created in C:\Users\payroll-admin\AppData\Local\Temp\, timestamp: 14:20:11 UTC
D.  Security.evtx EID 4688 — OUTLOOK.EXE spawned POWERSHELL.EXE, time: 14:19:38 UTC
E.  SRUM record — update.exe sent 184,221 bytes and received 2,415,891 bytes (2.3 MB), hourly bucket timestamp: 14:30:00 UTC
F.  LNK file — target: Q4_Payroll_Review.xlsm, last accessed: 14:18:55 UTC
G.  Security.evtx EID 4624 — logon type 2, account: payroll-admin, time: 08:43:17 UTC (normal start of day)
H.  MFT record — update.exe deleted from Temp directory, timestamp: 14:23:44 UTC
I.  Prefetch — update.exe entry, last run time: 14:21:03 UTC, run count: 1
J.  Security.evtx EID 4648 — explicit credential use, account: payroll-admin, target: FILESVR-03, time: 14:33:18 UTC
```

**Ordered timeline:**

| # | Time (UTC) | Event | Source Artifact | Significance |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |
| 6 | | | | |
| 7 | | | | |
| 8 | | | | |
| 9 | | | | |
| 10 | | | | |

**Analysis questions:**

1. What is the most likely initial access vector based on this timeline?
2. How long elapsed between initial execution and the first outbound data transfer?
3. What does event J tell you about scope beyond WKSTN-221?
4. Which hypothesis from Task 4 does this timeline support most strongly?
5. What artifact is missing from this timeline that you would want before drawing final conclusions?

```
1. 
2. 
3. 
4. 
5. 
```

**Part B — Timeline template**

Set up a blank timeline file for WKSTN-221 in your case folder. Use this structure as your working timeline as you collect and analyze evidence.

```
# WKSTN-221 — Forensic Timeline
Case Reference: IR-2024-WKSTN221
Last Updated:   
Updated By:     

| DateTime (UTC) | Artifact Source | Event Description | Significance | Confidence | Notes |
|---|---|---|---|---|---|
| | | | | High / Med / Low | |
```

> **Confidence rating:** Use High when two or more independent artifact sources agree. Use Medium when a single reliable artifact supports the event. Use Low when the evidence is indirect, ambiguous, or from a single low-confidence source.

---

### Task 6 — Reporting and Remediation Support

**Objective:** Translate your investigation findings into outputs that support both technical remediation and executive decision-making.

Forensic work that stays in a spreadsheet doesn't drive response. The last phase of the workflow is translation: turning artifact analysis into clear findings, actionable recommendations, and communication that non-technical stakeholders can act on.

**Part A — Technical findings summary**

Write a technical findings summary for WKSTN-221 based on the timeline from Task 5. Use only observed facts. Include no conclusion that a named artifact doesn't directly support. Use this structure:

```
## Technical Findings — WKSTN-221
Case Reference: IR-2024-WKSTN221
Prepared By:    
Date (UTC):     

### Confirmed Findings

Finding 1:
  Observation:   
  Source:        
  Timestamp:     

Finding 2:
  Observation:   
  Source:        
  Timestamp:     

Finding 3:
  Observation:   
  Source:        
  Timestamp:     

### Unconfirmed / Pending

Item 1:
  Description:   
  Evidence needed:

### Evidence Gaps

Gap 1:
  Description:   
  Impact on conclusions:
```

**Part B — Remediation recommendations**

Write at least five specific, actionable remediation recommendations for WKSTN-221. Each recommendation should reference a specific finding from your timeline or hypothesis set.

| # | Recommendation | Based On | Priority | Owner |
|---|---|---|---|---|
| 1 | | | Critical / High / Medium | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |

**Part C — Executive summary**

Write a three-paragraph executive summary for WKSTN-221. Assume the audience is a CISO or senior business leader with no forensic background. Cover:

- Paragraph 1: What happened and when (no jargon)
- Paragraph 2: What was affected and what the risk is
- Paragraph 3: What is being done and what decisions leadership needs to make

```
[Your executive summary here]
```

---

### Task 7 — Reflection

Answer the following in 3–5 sentences each:

**1. Triage decisions under uncertainty**
Your containment recommendation in Task 1 was made with incomplete information. What is the cost of isolating too early? What is the cost of waiting too long? How do you make that call when you genuinely don't know which is worse?

**2. Hypothesis discipline**
In Task 4, you were asked to identify what would *eliminate* each hypothesis, not just what would confirm it. Why is the elimination condition as important as the confirmation condition? What goes wrong if analysts only look for confirming evidence?

**3. Timeline gaps**
The timeline in Task 5 has a gap of roughly seven minutes between events H (14:23:44) and B (14:31:05). Only event E falls inside it, and a SRUM rollup timestamp is not an event time. How would you investigate that gap? What artifacts might fill it, and what does the gap itself tell you?

**4. The translation problem**
Writing the executive summary in Task 6 requires you to describe technical findings without technical language. What gets lost in that translation? How do you preserve precision and accuracy while keeping the summary accessible?

---

## Deliverables Checklist

Your `lab02.2-notes.md` should contain:

- [ ] **Task 1**: Triage checklist, containment decision with reasoning, and triage note
- [ ] **Task 2**: Scope map and evidence priority list with reasoning for top three
- [ ] **Task 3**: Volatile capture commands, memory acquisition plan, collection table, and hash record
- [ ] **Task 4**: Five hypotheses with confirm/eliminate conditions and priority ranking
- [ ] **Task 5**: Ordered timeline with analysis questions answered and blank WKSTN-221 timeline file created
- [ ] **Task 6**: Technical findings summary, remediation recommendations, and executive summary
- [ ] **Task 7**: Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab02/
├── lab02-notes.md    ← Your working notes file (whole lab)
└── Lab02_02/
    ├── ReadMe.md         ← This file
    └── lab02.2-notes.md  ← Your working notes file
```

---

## Key Takeaways

- **Triage determines everything downstream.** A wrong containment decision in the first five minutes can destroy evidence or give an attacker time to spread. Make it deliberately, document it, and own the risk you accepted.
- **Scoping prevents tunnel vision.** An active C2 connection on one host is almost never the whole story. Always look at related accounts, systems, and data before concluding the scope is limited.
- **Hypotheses keep analysis honest.** Naming what would *eliminate* a hypothesis is as important as naming what would confirm it. Confirmation bias is among the most damaging errors in forensic analysis.
- **Timelines reveal what single artifacts hide.** An event that appears in three independent artifact sources at the same time is a fact. An event supported by one ambiguous source is a hypothesis. Build the timeline before drawing conclusions.
- **Findings that don't drive action don't matter.** The technical report and executive summary exist to produce decisions about containment, remediation, notification, and recovery, not to demonstrate analytical depth. Write for the action you want the reader to take.

---

**Next:** Lab 2.3 — Documentation and Repeatability

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

--- 
