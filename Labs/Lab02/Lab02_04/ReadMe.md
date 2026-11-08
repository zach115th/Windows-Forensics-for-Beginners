# Lab 2.4 — From Alert to Investigation Plan

**Supporting Section 2.4: From Alert to Investigation Plan**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

An alert is not an investigation. It is a signal, often ambiguous, frequently incomplete, and almost never sufficient on its own to tell you what actually happened.

The gap between "we got an alert" and "we have a structured investigation" is where most IR failures begin. Responders jump to collection without defining questions. They treat EDR detections as confirmed facts. They isolate hosts before capturing volatile evidence. They start analyzing artifacts before deciding which artifacts actually matter.

This lab closes that gap. You'll take a realistic alert intake, the kind that lands in your queue at 09:00 on a Tuesday. Then you'll build it into a defensible investigation plan before touching a single artifact. By the end you'll have a structured document that tells any responder exactly what is known, what is suspected, what needs to happen first, and why.

---

## Learning Objectives

By completing this lab, you will be able to:

- Read a raw alert and extract only what is actually confirmed
- Separate facts, assumptions, and working hypotheses with precision
- Define the first investigative questions the evidence needs to answer
- Build a prioritized, documented evidence collection plan
- Make and justify an early containment or preservation decision
- Produce an investigation plan another analyst could execute from scratch
- Communicate a clear starting direction under time pressure and incomplete information

---

## Estimated Time

45–60 minutes

---

## Prerequisites

- Completion of Lab 2.1, 2.2, and 2.3 (or equivalent)
- Your `question-evidence-worksheet.md` from Lab 2.1
- A text editor or markdown editor
- Your `lab02.4-notes.md` file (template included in this folder)

---

## Scenario

At 09:07 UTC your SOC escalates the following alert to the IR queue:

> *"EDR alert on WKSTN-309 — medium severity. User account: j.mercer. Detection name: Suspicious PowerShell Execution. WINWORD.EXE spawned POWERSHELL.EXE at approximately 08:51 UTC. PowerShell command line was not captured due to an EDR configuration gap. An outbound connection to an external IP (185.193.126.47) on port 8443 was observed at 08:54 UTC and lasted approximately 90 seconds before terminating. No lateral movement detected. No data loss alerts triggered. Host is online. User j.mercer is a senior financial analyst with access to the finance shared drive (FINSVR-01), the accounts payable application, and a Citrix remote access environment. No prior alerts on this host in the last 90 days."*

That is everything your SOC has. The EDR did not block the activity. The PowerShell command line was not captured. The connection has terminated. The user is likely at their desk.

You have been asked to produce an investigation plan within the next 20 minutes.

---

## Background: The Alert-to-Plan Transition

Every investigation starts with the same problem: you have incomplete information and need to make consequential decisions anyway. The alert-to-plan transition is the structured process that converts raw intake into an organized response, before you've touched the host or parsed a single artifact.

A well-executed transition produces five things:

| Output | What It Does |
|---|---|
| **Fact/assumption separation** | Establishes what you actually know vs. what you're inferring |
| **Initial question list** | Defines what the investigation needs to answer |
| **Containment decision** | Documents whether to isolate, monitor, or preserve — and why |
| **Collection priority list** | Orders evidence acquisition by urgency and volatility |
| **Investigation plan** | Gives any responder a clear starting direction |

The entire transition should take 15–20 minutes on a real case. The goal is structured clarity before action, not perfection.

---

## Lab Tasks

---

### Task 1 — Dissect the Alert

**Objective:** Extract what the alert tells you: nothing more, nothing less.

Alerts contain a mix of confirmed observations, inferences made by detection tools, and metadata that may or may not be accurate. Before building an investigation plan, you need to know the confidence level each piece of information carries.

**Part A — Alert dissection table**

Break the alert into individual claims and evaluate each one.

| Claim from Alert | Source | Confidence Level | Why |
|---|---|---|---|
| WINWORD.EXE spawned POWERSHELL.EXE at 08:51 UTC | EDR process telemetry | | |
| The activity is suspicious | EDR detection engine | | |
| The PowerShell command line was not captured | EDR configuration gap | | |
| Outbound connection to 185.193.126.47:8443 at 08:54 UTC | EDR network telemetry | | |
| The connection lasted approximately 90 seconds | EDR network telemetry | | |
| No lateral movement occurred | EDR — absence of alert | | |
| No data loss occurred | EDR — absence of alert | | |
| j.mercer initiated the activity | EDR session context | | |
| The host has had no prior alerts in 90 days | EDR historical data | | |
| The activity was malicious | *(implied by escalation)* | | |

> **Confidence levels to use:** Confirmed (artifact-verified) / Probable (strong indicator, not verified) / Possible (plausible but unverified) / Unknown (no basis to evaluate)

**Part B — What the alert does not tell you**

List at least eight things you do not know from the alert alone that are relevant to the investigation.

```
1. 
2. 
3. 
4. 
5. 
6. 
7. 
8. 
```

**Part C — One-sentence alert summary**

Write a single sentence that summarizes only what the alert confirms, with no inferences and no conclusions.

```
[Your sentence here]
```

---

### Task 2 — Separate Facts, Assumptions, and Hypotheses

**Objective:** Build a clean three-way separation before you make any investigative decisions.

These three categories are distinct and must stay distinct throughout the investigation:

| Category | Definition |
|---|---|
| **Fact** | Directly supported by a named artifact or confirmed data source |
| **Assumption** | Believed to be true without direct artifact support — often reasonable, always a liability |
| **Hypothesis** | A testable statement about what may have happened — explicitly held until evidence confirms or eliminates it |

**Part A — Populate the register**

Complete the register with at least 12 entries. Include at least three of each type. For assumptions, note what artifact would confirm or refute them. For hypotheses, note what evidence would confirm or eliminate them.

| # | Type | Statement | Basis | Verification Needed |
|---|---|---|---|---|
| 1 | Fact | EDR telemetry records WINWORD.EXE spawning POWERSHELL.EXE at 08:51 UTC on WKSTN-309 | EDR process telemetry — named source | None — already confirmed by named source |
| 2 | Assumption | j.mercer was physically at the workstation at 08:51 UTC | EDR session context — inferred | Security.evtx logon events; physical access log if available |
| 3 | Hypothesis | A malicious macro in a Word document triggered the PowerShell execution | Process chain is consistent with macro execution | Prefetch, LNK files, jump lists — presence of recently opened .docm/.xlsm; Security.evtx EID 4688 |
| 4 | | | | |
| 5 | | | | |
| 6 | | | | |
| 7 | | | | |
| 8 | | | | |
| 9 | | | | |
| 10 | | | | |
| 11 | | | | |
| 12 | | | | |

**Part B — Risk assessment**

Identify the single most dangerous assumption in your register: the one that would most change your investigation approach if it were wrong. Explain why in 2–3 sentences.

```
Most dangerous assumption:    

Why it matters:               
```

---

### Task 3 — Define Initial Investigative Questions

**Objective:** Translate the alert into a prioritized list of specific, answerable questions before any collection begins.

Using the six IR question categories from Lab 2.1, write at least 10 specific investigative questions for the WKSTN-309 scenario. Your first three questions should address the most urgent unknowns, the ones that change your immediate response if the answer is bad.

```
Priority  Category          Question
--------  --------          --------
1.        Active threat      
2.        Active threat      
3.        Initial access     
4.        Initial access     
5.        Execution          
6.        Execution          
7.        Persistence        
8.        Impact             
9.        Impact             
10.       Scope              
```

**Urgency justification**

Explain in 2–3 sentences why your top three questions are the most urgent. If any of them has a bad answer, what changes in your collection plan, containment decision, or stakeholder communication?

```
[Your response here]
```

---

### Task 4 — Make the Containment Decision

**Objective:** Document a containment recommendation with explicit reasoning and acknowledged risk.

This is one of the most consequential decisions you'll make in the first 20 minutes. There is no universally correct answer. The right call depends on what you know, what you suspect, and what you can afford to lose.

**Part A — Evaluate the options**

Complete the decision matrix for WKSTN-309.

| Option | What You Preserve | What You Lose | Conditions That Make This Right |
|---|---|---|---|
| **Isolate immediately** | Prevents further spread; protects other systems | Active volatile evidence; possible C2 visibility; ability to observe attacker behavior | |
| **Monitor and collect before isolating** | Volatile evidence; potential C2 infrastructure visibility | Time; risk of spread if attacker is still active | |
| **Do not isolate, observe only** | Full attacker visibility; behavioral intelligence | High risk if attacker is active and moves laterally | |

**Part B — Your recommendation**

```
Recommendation:     [Isolate immediately / Monitor and collect / Observe only]

Primary reason:     
Secondary reason:   
Risk accepted:      [What could go wrong with this choice?]
Trigger condition:  [What finding would cause you to change this decision immediately?]
Authorized by:      
Date/Time (UTC):    
```

**Part C — Pre-isolation checklist**

If your recommendation is to monitor and collect before isolating, list the specific actions you would complete before pulling the network cable. Be precise. "Collect volatile evidence" is not specific enough.

| # | Action | Tool | Time Estimate |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |

---

### Task 5 — Build the Evidence Collection Plan

**Objective:** Produce a prioritized, documented collection plan that any responder could execute from a cold start.

**Part A — Collection priority list**

Order the following artifacts by collection priority for WKSTN-309. The C2 connection has terminated but the host is still online. Justify your top four choices.

*Artifact pool:* memory dump, running process list, active network connections, Security.evtx, System.evtx, PowerShell operational logs, Prefetch, MFT, SYSTEM hive, SOFTWARE hive, NTUSER.DAT, SRUM database, LNK files, Jump Lists, Amcache, browser history

| Priority | Artifact | Volatile? | Justification |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |
| 6 | | | |
| 7 | | | |
| 8 | | | |
| 9 | | | |
| 10 | | | |

**Part B — Collection method table**

For your top eight artifacts, specify the collection tool, method, and output location.

| Artifact | Collection Tool | Command or Method | Output Location | Notes |
|---|---|---|---|---|
| | | | `E:\IR\WKSTN-309\volatile\` | |
| | | | `E:\IR\WKSTN-309\volatile\` | |
| | | | `E:\IR\WKSTN-309\volatile\` | |
| | | | `E:\IR\WKSTN-309\artifacts\` | |
| | | | `E:\IR\WKSTN-309\artifacts\` | |
| | | | `E:\IR\WKSTN-309\artifacts\` | |
| | | | `E:\IR\WKSTN-309\artifacts\` | |
| | | | `E:\IR\WKSTN-309\artifacts\` | |

**Part C — Gap acknowledgment**

The EDR did not capture the PowerShell command line. Identify two additional artifact sources that might recover what PowerShell executed, and note the conditions under which each would be useful.

```
Alternative 1:
  Artifact:         
  What it may show: 
  Condition:        [What needs to be true for this to work?]

Alternative 2:
  Artifact:         
  What it may show: 
  Condition:        
```

---

### Task 6 — Write the Investigation Plan

**Objective:** Produce a single document that any responder could use to start and structure the investigation.

An investigation plan is an actionable, prioritized guide that converts your alert analysis into a structured response, not a wish list. You should be able to complete it in the first 20 minutes of a case and refer to it throughout.

Complete the following investigation plan for WKSTN-309:

```
# Investigation Plan — WKSTN-309
Case Reference:     IR-2024-WKSTN309
Prepared By:        
Date/Time (UTC):    
Alert Source:       EDR — Suspicious PowerShell Execution
Alert Time (UTC):   2024-11-XX 08:51 UTC
Case Priority:      [Critical / High / Medium / Low]

---

## Alert Summary (facts only — no inferences)


---

## What Is Known

1. 
2. 
3. 

## What Is Assumed (label as assumption)

1. 
2. 
3. 

## Working Hypotheses

Hypothesis 1:
  Statement:      
  Confirms if:    
  Eliminates if:  

Hypothesis 2:
  Statement:      
  Confirms if:    
  Eliminates if:  

Hypothesis 3:
  Statement:      
  Confirms if:    
  Eliminates if:  

---

## Systems and Accounts in Scope

| System / Account | Role | Why in Scope |
|---|---|---|
| WKSTN-309 | Finance workstation — j.mercer | Primary alert host |
| j.mercer (account) | Senior financial analyst | Assigned user at time of alert |
| FINSVR-01 | Finance shared drive | Accessible by j.mercer |
| | | |
| | | |

---

## Containment Decision

Decision:           
Reasoning:          
Risk accepted:      
Trigger to reassess:
Authorized by:      

---

## Initial Investigative Questions (priority order)

1. 
2. 
3. 
4. 
5. 

---

## Evidence Collection Plan (priority order)

| Priority | Artifact | Volatile? | Tool | Output Location |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |

---

## Known Evidence Gaps

1. PowerShell command line not captured by EDR — mitigation: [your answer from Task 5C]
2. 
3. 

---

## Immediate Next Actions

1. 
2. 
3. 
4. 
5. 

---

## Escalation and Notification

| Who | Why | When | Method |
|---|---|---|---|
| IR Manager | Active incident | Immediately | |
| Legal / Compliance | Financial data potentially at risk | Within 1 hour | |
| System Owner | WKSTN-309 may need isolation | Before containment action | |
| | | | |

---

## Notes


```

---

### Task 7 — Apply the Framework to a Cold Alert

**Objective:** Practice the full alert-to-plan transition without step-by-step prompting.

**Alert:**

> *"SIEM correlation rule fired at 23:44 UTC last night. Rule name: 'Multiple Failed Logons Followed by Success — Off Hours.' Account: svc-print. Five failed logon attempts (type 3) against WKSTN-088 between 23:39 and 23:43 UTC, followed by a successful type 3 logon at 23:44 UTC from source IP 10.4.22.31. svc-print is a service account used for print spooler management. 10.4.22.31 is not a print server. No EDR alerts. No follow-on activity detected."*

Without being guided through each step, produce the following in your notes file:

1. Alert dissection table (at least six claims evaluated)
2. Five facts, three assumptions, two hypotheses
3. Eight investigative questions in priority order
4. A containment decision with reasoning
5. A six-item collection priority list with justification for the top three
6. A one-paragraph investigation plan summary

---

### Task 8 — Reflection

Answer the following in 3–5 sentences each:

**1. The 20-minute constraint**
The background section says the alert-to-plan transition should take 15–20 minutes on a real case. What gets cut when you're forced to work that fast? What is the minimum viable output that still produces a defensible starting point?

**2. Alert confidence vs. artifact confidence**
EDR detections and SIEM alerts are valuable but not the same as artifact-verified facts. Where in today's lab did you have to resist treating an EDR finding as a confirmed fact? What's the practical risk of conflating the two?

**3. The missing command line**
The EDR configuration gap that prevented PowerShell command-line capture is a realistic forensic problem. Beyond the alternatives you identified in Task 5C, what could your organization do to prevent that gap in the future? What would you recommend?

**4. Plan vs. reality**
You've built a careful investigation plan. Thirty minutes into execution the incoming analyst calls and says j.mercer's manager just told HR that j.mercer resigned last week and their access should have been revoked. How does that change your plan? Walk through the decisions you would make.

---

## Deliverables Checklist

Your `lab02.4-notes.md` should contain:

- [ ] **Task 1** — Alert dissection table, eight unknowns, and one-sentence confirmed summary
- [ ] **Task 2** — Twelve-entry register with facts/assumptions/hypotheses and risk assessment
- [ ] **Task 3** — Ten prioritized investigative questions and urgency justification
- [ ] **Task 4** — Containment decision matrix, recommendation with reasoning, and pre-isolation checklist
- [ ] **Task 5** — Collection priority list, collection method table, and gap acknowledgment
- [ ] **Task 6** — Complete investigation plan document
- [ ] **Task 7** — Cold alert exercise (all six components)
- [ ] **Task 8** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab02/
├── lab02-notes.md    ← Your working notes file (whole lab)
└── Lab02_04/
    ├── ReadMe.md         ← This file
    └── lab02.4-notes.md  ← Your working notes file
```

---

## Key Takeaways

- **An alert is a starting point, not a finding.** Bridge the gap between what the EDR flagged and what happened with artifact analysis, not assumption.
- **The first 20 minutes set the trajectory of the investigation.** A structured alert-to-plan transition prevents the most common early failures: wrong containment timing, wrong collection order, and conclusions drawn before evidence is examined.
- **Containment decisions have costs on both sides.** Isolating too early destroys volatile evidence and closes intelligence collection windows. Waiting too long risks spread. Document your reasoning regardless of which way you go.
- **Configuration gaps are findings too.** The missing PowerShell command line is more than an inconvenience. It is a detection gap to document, mitigate, and remediate.
- **A plan another analyst can execute is a plan worth writing.** If your investigation plan only makes sense to you, it is personal notes, not an investigation plan.

---

**Next:** Lab 03 — Digital Forensics and Advanced Data Triage

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
