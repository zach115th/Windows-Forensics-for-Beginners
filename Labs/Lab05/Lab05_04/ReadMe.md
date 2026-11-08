# Lab 5.4 — Correlating Registry and Cloud Evidence in IR

**Supporting Section 5.4: Correlating Registry and Cloud Evidence in IR**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Registry evidence and cloud-storage artifacts are useful on their own, but their real value appears when you use them together.

No single finding tells the full story. A OneDrive client may be installed. A sync-root path may exist. A suspicious startup value may reference a script under a user profile, and a USB device may also have been present. Each finding matters, but none of them settles the case by itself. In incident response, the question is usually not "Did I find a key?" It is "What is the most defensible explanation for how these findings fit together?"

This lab practices that correlation step. You will combine Registry findings, local cloud-client evidence, and supporting user-context clues into a disciplined account. That account covers what the evidence shows the host was configured to do, what the user likely interacted with, and what still requires corroboration. The emphasis is on structured reasoning, not speculation.

The goal is to turn isolated Registry and OneDrive artifacts into an incident-response narrative that supports scoping, hypothesis testing, and handoff to another analyst.

---

## What This Lab Covers

This lab supports the following concepts from Section 5.4:

| Section | Topic |
|---|---|
| 5.4.1 | Did This User Mount a USB Device and Copy Files? |
| 5.4.2 | Did This User Move Data Off the Host Through OneDrive? |
| 5.4.3 | Did the Attacker Establish Persistence on This Host? |
| 5.4.4 | Registry and Cloud Findings — Quick Reference |

---

## Learning Objectives

By completing this lab, you will be able to:

- Correlate Registry findings with local cloud-storage artifacts into a coherent case theory
- Distinguish installation, configuration, likely use, and unproven exfiltration claims
- Use user-hive, system-hive, and local sync evidence together to assess cloud-related risk
- Identify which findings strongly support persistence, user interaction, or sync-client configuration
- Recognize where alternative explanations remain possible
- Build a timeline from combined Registry and cloud evidence
- Write concise, defensible summaries and handoff notes based on correlated findings

---

## Estimated Time

75–105 minutes

---

## Prerequisites

- Completion of Labs 5.1, 5.2, and 5.3, or equivalent familiarity with Registry hives, important keys, and local OneDrive artifacts
- A text editor or markdown editor
- Your `lab05-notes.md` file
- Optional: a Windows VM or image with Registry hives and OneDrive artifacts
- Optional: Registry and file-system analysis tools

---

## Scenario

You are continuing analysis of **HR-LT12**. Earlier review produced these leads:

- OneDrive appears to be installed on the host
- Local evidence suggests a OneDrive sync-root path may exist under the user profile
- Some artifacts suggest user interaction with folders that may contain sensitive HR files
- A suspicious startup-related value may reference an executable or script in a user-writable path
- A removable USB device may also have been recognized by the system during the broader incident window

Leadership is now asking a more useful question than "Was OneDrive present?" They want to know:

> What is the most defensible evidence-based explanation for how Registry and cloud-related artifacts fit together on this host?

You are not expected to prove cloud exfiltration from endpoint artifacts alone. Your task is to correlate the evidence you do have into the strongest disciplined interpretation possible.

---

## Background: Correlation Turns Clues into Analysis

Each artifact answers a narrow question, and correlation is what makes the answers useful. A single Registry key can tell you something was configured. A local sync-root path can tell you where synchronized content may have lived. A RecentDocs entry or LNK file can suggest user interaction. A client log can show timestamps consistent with sync activity.

| Artifact Type | What It Contributes |
|---|---|
| **System hives** | Machine-wide services, devices, startup context |
| **User hives** | User-specific activity, startup context, Explorer behavior |
| **Cloud-client Registry data** | Local installation and account-related configuration |
| **Sync-root folders and logs** | Local evidence of OneDrive structure and activity |
| **User activity artifacts** | Interaction with synced files or folders |
| **Timeline correlation** | Whether related events cluster in a meaningful sequence |

A defensible interpretation does not mean certainty. It means you can explain:

- What was found
- Why the findings likely relate to one another
- What they strongly support
- What they only suggest
- What remains unknown without further evidence

> **IR Reality Check:** Even strong endpoint analysis often does not "solve" the cloud question completely. It narrows the possibilities, identifies the most likely interpretation, and shows exactly what evidence is still needed.

---

## Lab Tasks

---

### Task 1 — Identify Which Findings Belong Together

**Objective:** Separate isolated facts from likely related activity.

Review your findings from Labs 5.1 through 5.3, or use the scenario details if you do not have prior notes.

List at least ten noteworthy Registry or cloud-related observations.

Examples may include:

- OneDrive installation evidence
- Account-related Registry data
- Sync-root path evidence
- UserAssist or RecentDocs references to OneDrive content
- Typed paths referencing sensitive folders
- Startup values pointing to suspicious paths
- USB device recognition
- Client log timestamps
- LNK or Jump List references to files in synchronized folders

Record them in the table below.

| Observation # | Finding | Source Artifact | Why It Matters |
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

Then group the observations into likely correlation clusters.

| Cluster Name | Related Observation Numbers | Why These Likely Belong Together |
|---|---|---|
| OneDrive installation / configuration cluster | | |
| User interaction with synchronized content cluster | | |
| Suspicious startup or persistence cluster | | |
| Removable media / alternate data-movement cluster | | |

Add more clusters if needed.

> **Guidance:** Not every interesting observation belongs to the same theory. Good correlation includes ruling out unrelated noise.

---

### Task 2 — Correlate Registry and OneDrive Configuration Evidence

**Objective:** Combine Registry configuration evidence with local sync-client evidence.

Pick three important findings related to OneDrive or cloud-client setup and correlate them in the table below.

| Finding Area | What the Registry Shows | What Local Cloud Artifacts Show | What the Combined Evidence Suggests | Confidence |
|---|---|---|---|---|
| OneDrive presence | | | | |
| Account or profile context | | | | |
| Sync-root path | | | | |
| Client activity timing | | | | |

You may use three or four rows.

Then answer:

1. Why is Registry evidence alone sometimes insufficient for cloud-related questions?

2. Why are logs or sync-root artifacts alone sometimes insufficient?

3. Why does combining them create a stronger interpretation?

---

### Task 3 — Correlate Cloud Evidence with User Activity

**Objective:** Tie local cloud configuration to actual user-side interaction.

Your goal is to determine whether the user likely interacted with files or folders inside the OneDrive path.

Choose three relevant user-activity findings and correlate them with OneDrive evidence.

| User-Activity Artifact | What It Shows | Related OneDrive Evidence | Combined Interpretation | Confidence |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

Possible user-activity sources include:

- UserAssist
- RecentDocs
- Typed paths
- LNK files
- Jump Lists
- Shell-related folder history
- NTFS traces within the sync-root path

Then answer:

1. Why is user interaction with a sync-root path important?

2. Why is "folder existed" weaker than "user likely opened files from that folder"?

3. Why should these combined findings still stop short of claiming confirmed cloud upload?

---

### Task 4 — Evaluate Competing Explanations

**Objective:** Avoid overconfidence by testing alternate interpretations.

For two of your main correlation clusters, write the following in the table below:

- One suspicious or incident-related interpretation
- One benign or less certain interpretation

| Cluster | Suspicious Interpretation | Benign / Alternate Interpretation | Which Is Better Supported? | Why |
|---|---|---|---|---|
| | | | | |
| | | | | |

Then answer:

1. Why is it important to test alternate explanations in cloud-related cases?

2. Why can normal enterprise OneDrive use sometimes look suspicious at first glance?

3. Why should responders avoid collapsing "possible sync activity" into "malicious exfiltration" too early?

---

### Task 5 — Separate Strong Support from Unproven Theory

**Objective:** Practice keeping your reporting inside what the combined evidence actually supports.

Sort your findings into the categories below.

| Statement or Finding | Category | Why |
|---|---|---|
| | Strongly supported by correlated endpoint evidence / Suggested but needs corroboration / Not supported by endpoint evidence alone | |
| | | |
| | | |
| | | |
| | | |
| | | |

Include at least:

- Two findings that are strongly supported
- Two findings that are suggested but need corroboration
- Two findings that are not supported by endpoint evidence alone

Examples may include:

- OneDrive was installed
- OneDrive was configured for a user profile
- A sync-root path likely existed locally
- The user likely interacted with files in that path
- Sensitive files were uploaded to cloud storage
- The user intentionally used OneDrive for exfiltration
- A suspicious startup entry may indicate persistence
- USB and cloud pathways were both possible in the same case

Then answer:

Why does this separation improve the quality of forensic reporting?

---

### Task 6 — Build a Combined Registry and Cloud Timeline

**Objective:** Turn correlated findings into a usable investigative sequence.

Create a mini-timeline with at least ten entries if possible.

| Time (UTC) | Artifact Source | Event or Observation | Key / Path / Artifact | Why It Matters |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

Your timeline may include:

- OneDrive installation or configuration evidence
- User-hive findings tied to the sync-root path
- RecentDocs or LNK evidence for files in OneDrive folders
- Typed paths or Explorer history involving sensitive directories
- Startup or persistence-related values
- USB recognition events
- Client log timestamps consistent with sync activity

Then answer:

1. Which events are most central to your case theory?

2. Which events may be contextual but not central?

3. What time window appears most important for follow-up?

---

### Task 7 — Identify the Best Next Corroborating Artifacts

**Objective:** Connect your endpoint findings to the next investigative steps.

For each question below, identify the best next artifact(s) you would seek.

| Investigative Question | Best Next Artifact(s) | Why |
|---|---|---|
| Were sensitive files actually uploaded to OneDrive? | | |
| Was the OneDrive account business-managed or personal? | | |
| Did the suspicious startup item execute? | | |
| Were files also copied to USB media? | | |
| Which user most likely interacted with the synced files? | | |
| Did cloud-related activity occur during the main incident window? | | |

Possible answers include:

- Tenant audit logs
- Provider-side logs
- Browser history
- Prefetch
- LNK files
- Jump Lists
- NTFS timeline
- USB-related file traces
- PowerShell logs
- EDR telemetry

Then answer:

1. Why should endpoint artifacts usually lead to more collection, not premature certainty?

2. Which questions are best answered locally, and which usually need enterprise or provider-side evidence?

3. Why is this step essential before briefing leadership about likely exfiltration?

---

### Task 8 — Write a Correlated Findings Summary

**Objective:** Produce a concise working-note summary from combined Registry and cloud evidence.

Write a 3–5 paragraph analyst summary describing what the correlated endpoint artifacts suggest about HR-LT12.

Your summary should include:

- The most important Registry findings
- The most important OneDrive or cloud-client findings
- Whether the combined evidence supports installation, configuration, likely use, or something stronger
- Whether the evidence suggests multiple possible data-movement paths
- What is strongly supported, what is only suggested, and what still requires external corroboration

Write it as a working analytic note, not a final incident conclusion.

---

### Task 9 — Write an Analyst Handoff Note

**Objective:** Summarize the most important conclusions and next steps for another responder.

Use the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Most Important Correlated Findings:
- 

What Endpoint Evidence Strongly Supports:
- 

What Endpoint Evidence Suggests but Does Not Confirm:
- 

Possible Data-Movement Paths Identified:
- 

Most Important Follow-Up Artifacts:
1.
2.
3.

Open Questions:
- 

Notes for Incoming Analyst:
```

Your note should make it easy for another analyst to continue the case without redoing your reasoning from scratch.

---

### Task 10 — Reflection

Answer the following in 3–5 sentences each.

**1. Why correlation matters**
Why are Registry findings and cloud-client artifacts more useful together than on their own?

**2. Strong findings versus strong stories**
Why can a persuasive narrative still be weak if the supporting endpoint artifacts are not clearly linked?

**3. The role of uncertainty**
Why does explicitly stating what remains unconfirmed strengthen your analysis?

**4. Endpoint evidence in the larger case**
How does good Registry-and-cloud correlation support scoping, follow-on collection, and later reporting?

---

## Deliverables Checklist

Your `lab05-notes.md` should contain:

- [ ] **Task 1** — At least 10 observations grouped into likely correlation clusters
- [ ] **Task 2** — Registry and OneDrive configuration correlation table
- [ ] **Task 3** — Cloud evidence and user-activity correlation table
- [ ] **Task 4** — Competing-interpretation analysis for two clusters
- [ ] **Task 5** — Strong support vs unproven theory table
- [ ] **Task 6** — Combined Registry and cloud timeline with at least 10 entries where possible
- [ ] **Task 7** — Best next corroborating artifacts table with written responses
- [ ] **Task 8** — Correlated findings summary
- [ ] **Task 9** — Analyst handoff note
- [ ] **Task 10** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab05/
├── lab05-notes.md  ← Your working notes file (whole lab)
└── Lab05_04/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **Correlation turns clues into analysis.** Registry keys, sync-root paths, logs, and user-activity artifacts are strongest when they reinforce one another.
- **Installation, configuration, and likely use are different findings.** Keeping them separate improves accuracy and defensibility.
- **Endpoint evidence has real value and real limits.** It can strongly support local configuration and user interaction, but not always remote-side success or intent.
- **Alternative explanations matter.** Good responders test benign explanations before escalating to stronger claims.
- **Correlated endpoint findings guide the next step.** Their job is often to narrow possibilities, identify risk, and show exactly what evidence you need to collect next.

---

**Next:** Lab 06 — Shell Items, Removable Devices, and Application Artifacts

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
