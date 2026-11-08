# Lab 5.3 — Cloud Storage (OneDrive Example)

**Supporting Section 5.3: Cloud Storage (OneDrive Example)**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Cloud storage changes the shape of Windows investigations. In a traditional workstation case, responders often think in terms of local files, removable media, and network shares. Once a sync client such as OneDrive enters the picture, those assumptions are no longer enough. A document can be opened locally, moved into a sync root, renamed, uploaded, deleted, restored, or synchronized across devices without leaving one simple "exfiltration artifact." Instead, responders have to work from a combination of local configuration, Registry evidence, folder structure, logs, databases, and user activity clues.

This lab focuses on the local forensic side of cloud storage, using OneDrive as the primary example. The point is not to reverse-engineer Microsoft's cloud platform. It is to teach you how to investigate the Windows endpoint evidence that shows whether a sync client was installed, which account it may have been tied to, and what local sync roots existed. That evidence also shows whether the system has signs consistent with file synchronization or cloud-based data movement.

This lab should make you comfortable treating OneDrive and similar sync clients as a normal part of Windows IR. In modern environments, cloud storage is part of the operating environment, and sometimes part of the incident.

---

## What This Lab Covers

This lab supports the following concepts from Section 5.3:

| Section | Topic |
|---|---|
| 5.3.1 | What a Sync Client Leaves Behind |
| 5.3.2 | OneDrive Registry Artifacts |
| 5.3.3 | The OneDrive Settings Files |
| 5.3.4 | OneDrive Logs |
| 5.3.6 | Cloud Clients and Browser Uploads |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain why local cloud-storage artifacts matter in incident response
- Identify endpoint evidence that a OneDrive client was installed and configured
- Locate likely sources of account, sync-root, and configuration evidence
- Distinguish between "client present," "client configured," and "files likely synchronized"
- Map cloud-storage questions to local artifacts such as Registry keys, folders, logs, and databases
- Recognize the limitations of endpoint-only evidence in cloud exfiltration cases
- Write concise, defensible notes about OneDrive-related findings

---

## Estimated Time

60–90 minutes

---

## Prerequisites

- Completion of Labs 5.1 and 5.2, or equivalent familiarity with Registry structure and high-value Registry keys
- A text editor or markdown editor
- Your `lab05-notes.md` file
- Optional: a Windows VM with OneDrive configured
- Optional: access to Registry analysis tools, file-system parsers, and local user profile artifacts

---

## Scenario

You are investigating **HR-LT12**, a Windows laptop used by an HR staff member with access to sensitive personnel documents. The case has expanded beyond persistence and USB questions. Management is now concerned that files may have been moved or synchronized through OneDrive.

Current known facts:

- OneDrive appears to be installed on the host
- The user denies intentionally moving files to the cloud
- The laptop contains sensitive HR files under user-accessible directories
- Leadership wants to know whether the endpoint shows evidence of cloud sync configuration or possible file movement
- You do not yet have provider-side logs or tenant audit data

Examine the local Windows evidence that could support or challenge a theory of cloud synchronization or cloud-assisted data movement.

---

## Background: Local Cloud Evidence Is Configuration Plus Context

OneDrive and similar sync clients leave multiple kinds of local traces on Windows systems. These may include:

- Registry keys showing installation or account-related context
- Local sync-root directories under the user profile
- Configuration files and local databases
- Client logs showing activity, errors, or sync behavior
- User activity artifacts that suggest files were accessed from or moved into synchronized folders

No single artifact proves malicious exfiltration, but together these artifacts can answer important questions such as:

- Was the sync client installed?
- Was it configured for a user or organizational account?
- Which local folders were associated with synchronization?
- Did the user interact with a sync-root path?
- Are there local signs consistent with upload or synchronization behavior?

| Cloud Artifact Type | What It Can Help Answer |
|---|---|
| **Registry configuration** | Was OneDrive present and configured locally? |
| **Sync-root folder structure** | Which local path was tied to sync activity? |
| **Client logs** | Was there client activity, error handling, or sync behavior? |
| **Local databases / config** | What account or sync metadata existed locally? |
| **User activity artifacts** | Did the user browse to, open, or interact with sync-root content? |

> **IR Reality Check:** Endpoint evidence can strongly support that OneDrive was present, configured, and used locally. It usually cannot prove the full cloud-side story without tenant logs, provider records, or corroborating enterprise telemetry.

---

## Lab Tasks

---

### Task 1 — Define What Local OneDrive Evidence Can and Cannot Tell You

**Objective:** Build a practical understanding of the limits and value of endpoint-side cloud artifacts.

Write a short explanation of local OneDrive evidence in 4–6 sentences.

Your explanation should address:

- Why cloud sync clients matter in Windows investigations
- What kinds of local evidence they can leave behind
- Why endpoint evidence is useful even without provider-side logs
- What local evidence usually cannot prove by itself

Then complete the table below.

| Investigative Question | Local OneDrive Evidence Value | Why |
|---|---|---|
| Was OneDrive installed on the host? | | |
| Was OneDrive configured for a user account? | | |
| Which local folder acted as a sync root? | | |
| Were files definitely uploaded to Microsoft's cloud? | | |
| Did the user likely interact with synchronized content locally? | | |
| Was OneDrive merely present but unused? | | |

Use the ratings:

- Strongly useful
- Partially useful
- Not very useful

---

### Task 2 — Identify Local OneDrive Evidence Sources

**Objective:** Build a practical list of endpoint artifacts to review.

List the local evidence sources you would check first on HR-LT12 when investigating possible OneDrive usage.

Fill in the table below.

| Artifact Source | What It May Reveal | Why It Matters |
|---|---|---|
| OneDrive-related Registry keys | | |
| Local OneDrive sync-root folder | | |
| User profile directories associated with OneDrive | | |
| OneDrive client logs | | |
| OneDrive configuration files or local databases | | |

Add at least seven more relevant sources or sub-sources of your own.

Possible additions may include:

- Shell-related history tied to the OneDrive path
- RecentDocs references to files under the sync root
- LNK files referencing OneDrive locations
- Jump Lists tied to synced files
- Browser artifacts for web-based cloud access
- NTFS activity in sync-root folders
- Recycle Bin or deleted-file context tied to OneDrive paths

Then answer:

1. Why is the sync-root path one of the most important local clues?

2. Why are logs and configuration files different kinds of evidence?

3. Why should you check both Registry and file-system artifacts instead of relying on one alone?

---

### Task 3 — Build a OneDrive-Focused Collection Plan

**Objective:** Translate the case theory into a structured artifact review plan.

Assume you are performing targeted analysis on HR-LT12 and need to answer the cloud-storage question quickly.

Create a step-by-step collection and review plan for local OneDrive artifacts.

Use the table below.

| Priority | Question to Answer | Artifact Source | Why This Comes First | What You Expect to Learn |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |
| 6 | | | | |

Then answer:

1. Why did you choose this order?

2. Which steps are most important for determining whether OneDrive was merely installed versus actively configured?

3. Which findings would make you escalate for provider-side logs or tenant audit review?

---

### Task 4 — Distinguish Installation, Configuration, and Likely Use

**Objective:** Practice separating different levels of confidence in cloud-client findings.

For each example below, classify it as evidence of:

- Installation
- Configuration
- Likely use
- Needs corroboration

| Finding | Classification | Why |
|---|---|---|
| OneDrive executable present under Program Files | | |
| Registry keys indicating a known OneDrive account context | | |
| A local folder path under the user profile appears tied to a sync root | | |
| Client log entries reflect sync-related activity timestamps | | |
| LNK files point to documents inside the OneDrive directory | | |
| A sensitive file exists under a synchronized folder path | | |
| Browser history shows login to a Microsoft account portal | | |
| The file was exfiltrated to an attacker-controlled cloud account | | |

Then add five more findings of your own and classify them the same way.

Afterward, answer:

1. Why is "client installed" a much weaker finding than "client configured"?

2. Why is "likely use" still not the same as proof of upload?

3. Why should responders explicitly label these levels of confidence in their notes?

---

### Task 5 — Map Cloud Questions to the Best Local Artifacts

**Objective:** Practice going from investigative question to artifact source.

For each question below, identify the best local artifacts to review first and second.

| Investigative Question | First Artifact to Check | Second Artifact to Check | Why |
|---|---|---|---|
| Was OneDrive configured for this user? | | | |
| Which local folder path was used for synchronization? | | | |
| Did the user likely access documents inside the OneDrive path? | | | |
| Is there evidence of client-side sync activity? | | | |
| Were sensitive files present inside or moved into the sync root? | | | |
| Does the endpoint suggest business or personal account usage? | | | |

Then write five additional cloud-related questions of your own and map them the same way.

Afterward, answer:

1. Why is this question-to-artifact approach more efficient than browsing the user profile randomly?

2. Why do some questions require both Registry and non-Registry artifacts?

3. Which questions can local endpoint evidence answer best, and which ones usually need provider-side support?

---

### Task 6 — Correlate OneDrive Evidence with User Activity

**Objective:** Connect sync-client evidence to actual user interaction on the host.

Assume you found signs that OneDrive was configured on HR-LT12. Now you want to know whether the user likely interacted with files in the OneDrive path.

Fill in the table below.

| User-Activity Artifact | What It Could Show | Why It Matters |
|---|---|---|
| UserAssist | | |
| RecentDocs | | |
| Typed paths / Explorer history | | |
| LNK files | | |
| Jump Lists | | |
| Shell-related history / folder navigation clues | | |

Add at least five more relevant artifacts of your own.

Then answer:

1. Why is user interaction with the OneDrive path important in this case?

2. Why would opening a file in a sync-root path matter more than just the folder existing?

3. Why should these artifacts still be interpreted cautiously?

---

### Task 7 — Separate Strong Findings from Overclaims

**Objective:** Practice disciplined cloud-storage reporting.

Read the statements below and classify each as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by local endpoint artifacts alone

| Statement | Classification | Why |
|---|---|---|
| OneDrive was installed on HR-LT12 | | |
| OneDrive was configured for a user account on HR-LT12 | | |
| The local endpoint contains a folder that appears to be a OneDrive sync root | | |
| The user likely interacted with files in that OneDrive path | | |
| Sensitive HR files were definitely uploaded to Microsoft cloud storage | | |
| The user intentionally exfiltrated files through OneDrive | | |
| Local evidence suggests cloud sync activity occurred during the incident window | | |
| The cloud account was controlled by an attacker | | |

Then write five additional statements of your own and classify them the same way.

> **Guidance:** Stay strict. Local cloud evidence is often persuasive, but it does not by itself answer intent, success, or remote-side activity.

---

### Task 8 — Build a OneDrive Correlation Timeline

**Objective:** Turn local cloud-storage findings into a usable investigative sequence.

Create a mini-timeline with at least 10 entries if possible.

| Time (UTC) | Artifact Source | Event or Observation | Path / Key / Artifact | Why It Matters |
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

- Installation evidence
- Account or configuration evidence
- Sync-root path observations
- User interaction with OneDrive folders or files
- Client log timestamps
- NTFS changes within the sync-root path
- Recent document or shell history tied to synchronized content

Then answer:

1. Why is a timeline more useful than a list of isolated cloud artifacts?

2. Which events appear most central to the question of likely cloud use?

3. What evidence would you want next from outside the endpoint?

---

### Task 9 — Write a OneDrive Findings Summary

**Objective:** Produce a concise working-note summary based on local cloud-storage evidence.

Write a 3–5 paragraph analyst summary describing what your local OneDrive review indicates about HR-LT12.

Your summary should include:

- Whether OneDrive appears to have been installed and configured
- What local path appears to have served as the sync root, if known
- Whether local artifacts suggest user interaction or likely sync-related activity
- What is strongly supported by endpoint evidence
- What still requires corroboration from tenant logs, provider-side evidence, or other artifacts

Write it as a working-note summary rather than a final incident conclusion.

---

### Task 10 — Write an Analyst Handoff Note

**Objective:** Make your cloud-storage findings easy for another responder to continue.

Write a short handoff note using the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Most Important OneDrive Findings:
- 

What Is Strongly Supported:
- 

What Is Suggested but Unconfirmed:
- 

Most Important Paths / Keys / Artifacts:
- 

Recommended Next Steps:
1.
2.
3.

External Evidence Needed:
- 

Notes for Incoming Analyst:
```

---

### Task 11 — Reflection

Answer the following in 3–5 sentences each.

**1. Why local cloud artifacts matter**
Why can endpoint evidence be extremely valuable in a cloud-related case even before you get provider-side logs?

**2. Installation versus use**
Why is it important to separate "OneDrive exists on the system" from "OneDrive was actively used in a way relevant to the incident"?

**3. Endpoint limits**
Why can strong local evidence still fall short of proving cloud upload or malicious exfiltration?

**4. Correlation over assumptions**
Why are OneDrive findings strongest when paired with Registry, NTFS, user-activity, and enterprise audit artifacts?

---

## Deliverables Checklist

Your `lab05-notes.md` should contain:

- [ ] **Task 1** — Local OneDrive evidence explanation and usefulness ratings table
- [ ] **Task 2** — OneDrive evidence-source table with seven added sources
- [ ] **Task 3** — OneDrive-focused collection and review plan
- [ ] **Task 4** — Installation/configuration/likely-use classification with five added findings
- [ ] **Task 5** — Cloud-question-to-artifact mapping with five added questions
- [ ] **Task 6** — OneDrive and user-activity correlation table with five added artifacts
- [ ] **Task 7** — Strongly supported vs overclaim exercise
- [ ] **Task 8** — OneDrive correlation timeline with at least 10 entries where possible
- [ ] **Task 9** — OneDrive findings summary
- [ ] **Task 10** — Analyst handoff note
- [ ] **Task 11** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab05/
├── lab05-notes.md  ← Your working notes file (whole lab)
└── Lab05_03/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **Cloud sync clients are endpoint artifacts too.** OneDrive leaves local evidence that can be highly valuable in Windows investigations.
- **Installation, configuration, and likely use are different findings.** Keeping them separate improves analytic discipline.
- **Local evidence can strongly support cloud-related activity.** It can often show configuration, sync roots, and user interaction even without tenant logs.
- **Endpoint evidence has limits.** Upload success, remote-side access, and malicious intent usually require more than local artifacts alone.
- **Correlation is essential.** OneDrive findings become much stronger when paired with Registry, NTFS, logs, user-activity evidence, and provider-side records.

---

**Next:** Lab 5.4 — Correlating Registry and Cloud Evidence in IR

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
