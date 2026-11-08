# Lab 6.4 — Browser, Email, and Search Index

**Supporting Section 6.4: Browser, Email, and Search Index**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Some of the most important evidence in a Windows incident starts as user activity, not malware. It can be a click, a downloaded archive, a webmail session, or a phishing attachment. It can also be a search for a filename, a browser visit to a cloud-storage portal, or a document opened from an email client.

By the time responders are called, the malicious binary may be gone and the obvious process activity may be incomplete. What often remains are the surrounding artifacts that explain how the user or attacker got there.

This lab focuses on three evidence areas that often provide that surrounding context:

- Browser artifacts
- Email artifacts
- Windows Search–related evidence

Together, these sources can help answer practical IR questions such as:

- Did the user visit a suspicious site?
- Was a file downloaded through the browser?
- Was a phishing email or attachment likely opened?
- Was webmail or a cloud-storage service accessed?
- Did the user search for, preview, or interact with files that later became incident-relevant?

The goal is to use browser, email, and search artifacts as part of a disciplined reconstruction of delivery, access, and user behavior, not to turn browser history into a standalone incident report.

---

## What This Lab Covers

This lab supports the following concepts from Section 6.4:

| Section | Topic |
|---|---|
| 6.4.1 | Browser history and download artifacts |
| 6.4.2 | Email-client and message-store evidence |
| 6.4.3 | Webmail, cloud access, and user search behavior |
| 6.4 | Correlating browser, email, and search artifacts in IR |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain the forensic value of browser, email, and search artifacts in Windows incident response
- Identify local evidence relevant to phishing, downloads, web access, and cloud usage
- Distinguish between site access, download activity, attachment access, and execution
- Recognize the value and limits of email-client evidence such as PST/OST data and mail metadata
- Use search-related artifacts to support file-access and user-interest questions
- Correlate browser, email, search, and execution artifacts into a more defensible incident theory
- Write concise, evidence-based notes about delivery and user-behavior context

---

## Estimated Time

75–105 minutes

---

## Prerequisites

- Completion of Labs 01–05 and Labs 06.1–6.3, or equivalent familiarity with Windows IR workflow, execution artifacts, shell artifacts, Registry analysis, and general endpoint triage
- A text editor or markdown editor
- Your `lab06-notes.md` file
- Optional: a Windows VM with browser and email activity
- Optional: access to browser parsers, email parsers, OST/PST review tools, or search-index-related artifacts

---

## Scenario

You are continuing analysis of **FIN-WS23**. Earlier work established that suspicious activity on the host may involve:

- A suspicious executable or archive in Downloads
- Possible PowerShell activity
- Sensitive documents accessed shortly before the incident window
- A possible removable-device angle

The case team now wants to understand the likely delivery and access path.

Current questions include:

- Did the user visit a suspicious site or webmail portal?
- Was a file downloaded through the browser?
- Did the user open an email attachment related to the incident?
- Was the user searching for or interacting with specific sensitive documents?
- Did cloud-storage or web-based access play a role?

Use browser, email, and search-related artifacts to reconstruct the most defensible user-behavior context possible.

---

## Background: These Artifacts Explain How the Incident Reached the Host

Browser, email, and search artifacts answer different questions from execution, NTFS, and Registry artifacts. Execution artifacts tell you what likely ran. NTFS and Registry artifacts tell you what existed and what was configured. Browser, email, and search artifacts help answer questions such as:

- How did the suspicious file arrive?
- What did the user likely click, open, or search for?
- Was the file delivered by email, browser download, or web-based access?
- Did the user interact with cloud services, webmail, or document portals?

These artifacts often become critical when investigating:

- Phishing
- Malicious downloads
- Webmail-based delivery
- Cloud-file access
- Search-driven discovery of sensitive files
- User claims about whether they knowingly opened or downloaded something

| Artifact Area | Common IR Use |
|---|---|
| **Browser history** | Visited sites, referrers, webmail, cloud portals, phishing pages |
| **Browser downloads** | File arrival, download source, local save path |
| **Email artifacts** | Message metadata, attachments, sender/recipient context |
| **Search-related evidence** | File discovery, preview, and user interest in specific content |
| **Recent documents and shell correlation** | Whether delivered content was likely opened later |

> **IR Reality Check:** A malicious file rarely appears out of nowhere. Browser and email artifacts often reveal the path that brought it onto the host.

---

## Lab Tasks

---

### Task 1 — Identify Which Questions These Artifacts Help Answer

**Objective:** Map common IR questions to browser, email, and search artifacts.

For each investigative question below, identify the best artifact or artifacts to check first.

| Investigative Question | Best Artifact(s) to Check First | Why |
|---|---|---|
| Did the user visit a suspicious website? | | |
| Was a suspicious file downloaded through the browser? | | |
| Did the user access webmail related to the incident? | | |
| Did the user likely open an email attachment? | | |
| Was a sensitive file searched for or discovered locally? | | |
| Did the user access a cloud-storage or file-sharing site? | | |
| Was the suspicious document likely delivered by email or web download? | | |
| Did the user revisit the same suspicious domain multiple times? | | |

Then write six additional questions of your own and map them the same way.

Afterward, answer:

**1. Why is this question-to-artifact approach better than dumping browser history without a plan?**

```
[Your response here]
```

**2. Why do some questions require both browser and email evidence?**

```
[Your response here]
```

**3. Why is "downloaded" different from "opened" or "executed"?**

```
[Your response here]
```

---

### Task 2 — Review Browser History and Download Evidence

**Objective:** Use browser artifacts to assess suspicious site visits and file delivery.

Fill in the table below.

| Browser Artifact | What It Can Reveal | Why It Matters | Limitation |
|---|---|---|---|
| History records | | | |
| Download records | | | |
| Cached content / cache metadata | | | |
| Cookies / session evidence | | | |
| Saved logins or form history | | | |

Add at least five more browser-related artifacts or sub-artifacts of your own.

Then answer:

**1. Why are download records often more important than general browsing history in malware-delivery cases?**

```
[Your response here]
```

**2. Why can repeated visits to the same suspicious domain matter?**

```
[Your response here]
```

**3. Why should responders be careful not to equate "visited site" with "malicious intent"?**

```
[Your response here]
```

After that, build a focused review table:

| Browser Lead | What You Would Look For | Why It Would Matter |
|---|---|---|
| Suspicious domain visit | | |
| Download of suspicious archive | | |
| Webmail access during incident window | | |
| Visit to cloud-storage portal | | |

Add at least six more entries of your own.

---

### Task 3 — Review Email Evidence and Attachment Context

**Objective:** Use email artifacts to assess phishing, attachment access, and message-driven delivery.

Assume local email evidence is available through an email client, message store, or related metadata.

Fill in the table below.

| Email Artifact | What It Can Reveal | Why It Matters | Limitation |
|---|---|---|---|
| PST / OST message content | | | |
| Message metadata (from, to, subject, time) | | | |
| Attachment metadata | | | |
| Mail client recent-item clues | | | |
| Webmail-related browser evidence | | | |

Add at least five more relevant email-related artifacts or supporting sources of your own.

Then answer:

**1. Why is email metadata often as important as email body content in phishing cases?**

```
[Your response here]
```

**2. Why is attachment presence not the same as attachment execution?**

```
[Your response here]
```

**3. Why can browser evidence still matter even when a thick email client is in use?**

```
[Your response here]
```

Next, create a working table:

| Email Lead | What You Would Want to Confirm | Why It Would Matter |
|---|---|---|
| Suspicious sender | | |
| Malicious-looking attachment | | |
| Message sent near incident start | | |
| Link in phishing email | | |

Add at least six more entries of your own.

---

### Task 4 — Review Search Index and Search-Related Evidence

**Objective:** Use search-related artifacts to assess file discovery and user interest.

Assume the team is concerned that the user or attacker may have looked for sensitive files shortly before the incident escalated.

Fill in the table below.

| Search-Related Artifact | What It Can Reveal | Why It Matters | Limitation |
|---|---|---|---|
| Windows Search index / related metadata | | | |
| Search terms or recent search history | | | |
| RecentDocs correlation | | | |
| Explorer navigation history | | | |
| Search-related application behavior | | | |

Add at least five more relevant search or file-discovery artifacts of your own.

Then answer:

**1. Why can search-related evidence matter in insider-risk or data-staging cases?**

```
[Your response here]
```

**2. Why is searching for a filename different from opening that file?**

```
[Your response here]
```

**3. Why should search evidence be correlated with document access artifacts before drawing stronger conclusions?**

```
[Your response here]
```

---

### Task 5 — Correlate Browser, Email, and Search with Execution Artifacts

**Objective:** Connect delivery context to file access and likely execution.

Choose three suspicious files, documents, links, or delivery paths and correlate the evidence.

Use the table below.

| Item / Delivery Path | Browser Evidence | Email or Search Evidence | Execution / Access Artifact | Combined Interpretation | Confidence |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |
| | | | | | |

Possible execution or access artifacts include:

- Prefetch
- UserAssist
- Jump Lists
- LNK files
- RecentDocs
- PowerShell logs
- Process creation logs
- NTFS timeline
- EDR telemetry

Then answer:

**1. Why is browser history stronger when paired with download and execution artifacts?**

```
[Your response here]
```

**2. Why is email evidence stronger when paired with attachment-access or document-open artifacts?**

```
[Your response here]
```

**3. Why should you still avoid overclaiming even when multiple artifacts align?**

```
[Your response here]
```

---

### Task 6 — Evaluate Competing Interpretations

**Objective:** Avoid tunnel vision by considering alternate explanations.

Choose two key findings from browser, email, or search review and write:

- One suspicious interpretation
- One benign or less certain interpretation

Use the table below.

| Finding | Suspicious Interpretation | Benign / Alternate Interpretation | Which Is Better Supported? | Why |
|---|---|---|---|---|
| | | | | |
| | | | | |

Then answer:

**1. Why can normal browsing or email behavior look suspicious without context?**

```
[Your response here]
```

**2. Why is a cloud-storage site visit not automatically an exfiltration event?**

```
[Your response here]
```

**3. Why is alternate-explanation analysis important before briefing leadership or HR?**

```
[Your response here]
```

---

### Task 7 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined reporting around delivery and access evidence.

Classify each statement below as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by these artifacts alone

| Statement | Classification | Why |
|---|---|---|
| The user visited a suspicious domain during the incident window | | |
| A suspicious file was downloaded through the browser | | |
| The downloaded file was definitely executed | | |
| A phishing email with a relevant attachment existed in the user's mailbox | | |
| The user intentionally opened the phishing attachment knowing it was malicious | | |
| Search-related artifacts suggest interest in sensitive files | | |
| Sensitive files were exfiltrated through a webmail or cloud service | | |
| A web-based portal likely played a role in the incident chain | | |

Then write six additional statements of your own and classify them the same way.

> **Guidance:** These artifacts are excellent for context and delivery paths. They are not universal proof of execution, exfiltration, or intent.

---

### Task 8 — Build a Delivery-and-Access Timeline

**Objective:** Turn browser, email, and search findings into a usable incident sequence.

Create a mini-timeline with at least twelve entries if possible.

| Time (UTC) | Artifact Source | Event or Observation | Site / Message / File | Why It Matters |
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
| | | | | |
| | | | | |

Your timeline may include:

- Suspicious site visits
- File downloads
- Email receipt or access
- Attachment-related clues
- Search behavior
- Opening of a downloaded document
- PowerShell or process activity after access
- Cloud-portal or webmail interaction

Then answer:

**1. Which entries appear most central to the likely delivery path?**

```
[Your response here]
```

**2. Which entries are supportive but not decisive?**

```
[Your response here]
```

**3. What major gaps remain after the timeline is built?**

```
[Your response here]
```

---

### Task 9 — Write a Browser, Email, and Search Findings Summary

**Objective:** Produce a concise working-note summary suitable for the case file.

Write a 3–5 paragraph analyst summary describing what browser, email, and search artifacts suggest about activity on FIN-WS23.

Your summary should include:

- The most important browsing and download findings
- The most important email or attachment-related findings
- Whether search-related artifacts appear relevant to sensitive-file access or discovery
- What is strongly supported by the evidence
- What still requires corroboration from execution artifacts, logs, NTFS, Registry, or provider-side data

Write it as a working-note summary rather than a final incident conclusion.

---

### Task 10 — Write an Analyst Handoff Note

**Objective:** Make your findings easy for another responder to continue.

Use the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Most Important Browser Findings:
- 

Most Important Email / Search Findings:
- 

What Is Strongly Supported:
- 

What Is Suggested but Not Confirmed:
- 

Recommended Next Artifacts:
1.
2.
3.

Open Questions:
- 

Notes for Incoming Analyst:
```

---

### Task 11 — Reflection

Answer the following in 3–5 sentences each.

**1. Why these artifacts matter**
Why are browser, email, and search artifacts often critical for understanding initial access or delivery?

```
[Your response here]
```

**2. Delivery versus execution**
Why is it important to distinguish between a file being downloaded or attached and that file actually being opened or executed?

```
[Your response here]
```

**3. User behavior versus user intent**
Why should responders avoid turning browsing or email activity into assumptions about malicious intent?

```
[Your response here]
```

**4. Correlation is the real strength**
Why are these artifacts strongest when paired with LNK files, Jump Lists, execution artifacts, NTFS, and logs?

```
[Your response here]
```

---

## Deliverables Checklist

Your `lab06-notes.md` should contain:

- [ ] **Task 1** — Question-to-artifact mapping with six added questions
- [ ] **Task 2** — Browser-artifact table with added sources and focused review table
- [ ] **Task 3** — Email-artifact table with added sources and focused review table
- [ ] **Task 4** — Search-related-artifact table with added sources
- [ ] **Task 5** — Correlation table for three suspicious items or delivery paths
- [ ] **Task 6** — Competing-interpretation analysis for two findings
- [ ] **Task 7** — Strong support vs overclaim exercise
- [ ] **Task 8** — Delivery-and-access timeline with at least 12 entries where possible
- [ ] **Task 9** — Browser, email, and search findings summary
- [ ] **Task 10** — Analyst handoff note
- [ ] **Task 11** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab06/
├── lab06-notes.md  ← Your working notes file (whole lab)
└── Lab06_04/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **These artifacts explain delivery and context.** They help answer how the suspicious content reached the host and what the user likely interacted with.
- **Download, open, and execute are different things.** Keep those distinctions clear in your notes.
- **Email and browser evidence often frame the incident chain.** They are especially valuable in phishing, malicious download, and cloud-access cases.
- **Search artifacts can matter too.** They may reveal user interest in or discovery of sensitive files before broader suspicious activity.
- **Correlation is what turns context into analysis.** Browser, email, search, execution, and file-access artifacts are strongest when they align.

---

**Next:** Lab 6.5 — Removable Device Profiling

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
