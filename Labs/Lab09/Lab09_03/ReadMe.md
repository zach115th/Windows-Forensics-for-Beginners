# Lab 9.3 — Approach

**Supporting Section 9.3: Approach**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Windows event logs become useful in incident response when you stop treating them as a giant pile of records and start treating them as a question-driven hunting source.

The right approach is not "open Event Viewer and scroll." It is:

- Start with known-good filters
- Hunt for patterns that matter operationally
- Parse logs at scale when needed
- Document what you looked for, what you found, and what the limits were

This lab focuses on the practical event-log workflow described in Chapter 9. You will start from a small set of high-value suspicious patterns and turn them into reusable filters. You will then think about scale and tooling, and package the result into a repeatable approach another responder could use.

The goal is a disciplined approach that moves you quickly from raw Windows logs to defensible investigative leads, not memorizing event IDs for their own sake.

---

## What This Lab Covers

This lab supports the following concepts from Section 9.3:

| Section | Topic |
|---|---|
| 9.3.1 | Start with known-good filters |
| 9.3.2 | Use tooling to parse at scale |
| 9.3.3 | Build a hunt pack |
| 9.3.4 | Combine logs with other artifacts |
| 9.3.5 | Log findings — quick reference |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain why event-log hunting should begin with high-value filters rather than broad manual review
- Identify the suspicious patterns most useful for early IR event-log hunting
- Map those patterns to the relevant Windows log families
- Choose a reasonable tool-assisted approach for parsing logs at scale
- Design reusable searches or filters that another responder could apply later
- Document your event-log hunting process in a repeatable way
- Write concise notes that distinguish detections, gaps, and next steps

---

## Estimated Time

60–80 minutes

---

## Prerequisites

- Completion of Labs 9.1 and 9.2, or equivalent familiarity with Windows log types and common event-log challenges
- A text editor or markdown editor
- Your `lab09-notes.md` file
- A Windows lab VM
- Optional: tools such as EvtxECmd, Windows Event Forwarding, a SIEM, or PowerShell log-export/search methods

---

## Scenario

You are helping your team build a practical Windows event-log hunting workflow for systems like **FIN-WS23**.

The team wants a repeatable approach, not another one-off investigation process. It should start with the highest-value suspicious patterns and work whether the logs are reviewed:

- Locally from exported `.evtx` files
- Through a parsing tool
- Through Windows Event Forwarding
- In a SIEM

The team's questions are practical:

- Which filters should we always start with?
- Which suspicious patterns matter most in early triage?
- How do we hunt consistently across multiple hosts?
- How do we document the approach so another responder can reuse it?

Your task is to design and document that approach.

---

## Background: Good Event-Log Hunting Starts Narrow

Responders who get lost in event logs usually started too broad.

A better approach is to begin with a small set of known-good patterns that repeatedly matter in IR, such as:

- Failed logons followed by success
- Privilege escalation or special logon activity
- Service creation or installation
- Scheduled task creation or change
- PowerShell execution and script block activity
- Security control changes or Defender activity

These patterns are useful because they align to real IR questions:

| Suspicious Pattern Type | IR Question It Helps Answer |
|---|---|
| Authentication anomalies | Did someone gain access or attempt access? |
| Privilege use | Did someone gain elevated capability? |
| Service creation | Was persistence or tool deployment established? |
| Scheduled task activity | Was persistence or automation configured? |
| PowerShell activity | Was script-based activity involved? |
| Defender or security-tool events | Did the endpoint detect or respond to suspicious behavior? |

At scale, this approach usually depends on tooling rather than manual Event Viewer review alone.

| Tooling Approach | Why It Matters |
|---|---|
| EvtxECmd / parsing tools | Fast local parsing and export |
| Windows Event Forwarding | Centralized collection across hosts |
| SIEM | Search, correlation, saved hunts, and dashboards |

> **IR Reality Check:** The best event-log approach is not the one with the most filters. It is the one that consistently finds the events that matter most.

---

## Lab Tasks

---

### Task 1 — Explain the Event-Log Hunting Approach

**Objective:** Build a practical responder-focused explanation of the Chapter 9 approach.

Write a short explanation in 4–6 sentences covering:

- Why responders start from known-good filters
- Why event-log hunting should be tied to real IR questions
- Why tool-assisted parsing matters once the environment or log volume grows
- Why documentation is part of the approach, not an afterthought

Then answer the following in one or two sentences each:

1. Why is broad manual review usually a poor first move in an incident?

2. Why do known-good filters improve both speed and consistency?

3. Why does a reusable approach matter more than one-off clever searches?

---

### Task 2 — Identify the Highest-Value Suspicious Patterns

**Objective:** Define the event patterns your approach should prioritize first.

Fill in the table below.

| Suspicious Pattern | Why It Matters | Primary Log(s) | Primary IR Question |
|---|---|---|---|
| Multiple failed logons followed by a success | | | |
| Privilege escalation / special logon activity | | | |
| Service creation / installation | | | |
| Scheduled task creation or modification | | | |
| PowerShell script execution or unusual PowerShell activity | | | |
| Defender detection or protection event | | | |

Add at least six more suspicious patterns of your own.

Examples may include:

- New local account creation
- Log clearing
- Security-tool disablement
- Remote logon activity
- Service start after installation
- Encoded or suspicious PowerShell behavior
- Task execution from unusual paths

Then answer:

1. Why are these patterns better starting points than arbitrary event-ID hunting?

2. Why do patterns matter more than single isolated events in many cases?

3. Why should each pattern map to a clear IR question?

---

### Task 3 — Map Patterns to Known-Good Filters

**Objective:** Convert high-value patterns into reusable searches.

For each suspicious pattern below, define a known-good filter or search concept.

You may express this as:

- Event ID logic
- SIEM search logic
- XML filter logic
- PowerShell filter logic
- Parser-based pseudocode

Use the table below.

| Suspicious Pattern | Filter / Search Definition | Tool / Platform | Why This Filter Is Worth Saving |
|---|---|---|---|
| Multiple failed logons followed by a success | | | |
| Service creation / installation | | | |
| Scheduled task creation or modification | | | |
| PowerShell unusual execution | | | |
| Privilege escalation / special logon | | | |
| Defender detection / action | | | |

Add at least four more filters of your own.

Then answer:

1. Why should filter definitions be reusable rather than case-specific when possible?

2. Why should filters be written in a way that another analyst can understand without guessing?

3. Why is it helpful to record which platform the filter was built for?

---

### Task 4 — Choose the Right Tooling Approach for Scale

**Objective:** Match the hunting workflow to the size of the problem.

For each environment below, choose the most reasonable log-hunting approach.

| Environment / Situation | Best Approach | Why |
|---|---|---|
| One lab VM with exported `.evtx` files | | |
| A handful of Windows hosts during a contained case | | |
| Many endpoints across a medium-sized environment | | |
| Enterprise-scale centralized hunting | | |

Use these possible choices where appropriate:

- Manual local review
- EvtxECmd or similar parser
- Windows Event Forwarding
- SIEM
- Combination approach

Then answer:

1. Why is manual review less viable as host count and log volume grow?

2. Why does centralization matter in multi-host incidents?

3. Why might a parser still be useful even when a SIEM exists?

---

### Task 5 — Build a First-Pass Event Hunt Workflow

**Objective:** Turn the chapter's approach into a repeatable hunting sequence.

Create a step-by-step event-log hunting workflow for FIN-WS23 or a similar Windows host.

Use the table below.

| Step | Action | Why It Happens Here | Expected Output |
|---|---|---|---|
| 1 | Identify available logs and logging gaps | | |
| 2 | Start with high-value filters | | |
| 3 | Review authentication patterns | | |
| 4 | Review service, task, and persistence indicators | | |
| 5 | Review PowerShell or operational logs | | |
| 6 | Expand to supporting logs if needed | | |
| 7 | Document hits, misses, and limitations | | |

You may modify the steps, but include at least seven.

Then answer:

1. Why should the first-pass workflow start with high-value hunts instead of broad review?

2. Why should logging gaps be identified early?

3. Why is documentation part of the workflow rather than something saved for the end?

---

### Task 6 — Design a Reusable Filter Pack Structure

**Objective:** Organize the approach into a reusable set of filters and notes.

Create a reusable folder or documentation structure for your event-log hunting approach.

Use or adapt this model:

```
Windows-Event-Hunt-Approach/
├── README.md
├── hunt-overview.md
├── filters/
│   ├── authentication/
│   ├── privileges/
│   ├── services/
│   ├── tasks/
│   ├── powershell/
│   └── defender/
├── test-cases/
└── notes/
```

Then define naming conventions for:

| Item | Naming Convention | Example |
|---|---|---|
| Filter file | | |
| Hunt documentation section | | |
| Test case note | | |
| False-positive note | | |

Afterward, answer:

1. Why is structure important if the approach will be reused by a team?

2. Why should false-positive guidance live alongside the filter definitions?

3. Why is packaging part of making the approach operationally useful?

---

### Task 7 — Test the Approach with Lab Events

**Objective:** Validate that the approach actually works against real activity.

Generate or identify at least six test actions in your lab VM that should trigger part of your hunting approach.

Examples may include:

- Failed logons
- Successful logon after failures
- Service creation or start
- Scheduled task creation
- PowerShell script execution
- Defender-triggering test behavior where safe and appropriate

Record your work below.

| Test Action | Expected Pattern / Hunt | Approximate Time (UTC) | Did the Approach Catch It? |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |

Then answer:

1. Why is a reusable approach incomplete if it has never been tested?

2. Why should you document misses as well as hits?

3. Why does validation help improve team trust in the approach?

---

### Task 8 — Refine the Approach Based on Results

**Objective:** Treat tuning as part of the process, not a failure.

Review your filter results and identify which parts of the approach need refinement.

Use the table below.

| Hunt / Filter | What Worked | What Did Not Work | Adjustment Needed |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |

Then answer:

1. Why is refinement normal in event-log hunting?

2. Why can a technically correct filter still be operationally weak?

3. Why should the approach capture both filter logic and tuning history?

---

### Task 9 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined language about what a log-hunting approach can actually do.

Classify each statement below as:

- Strongly supported
- Suggested but needs more context
- Not supported by this approach alone

| Statement | Classification | Why |
|---|---|---|
| Known-good filters improve early triage speed | | |
| A hunt pack can help identify suspicious patterns worth investigation | | |
| A saved filter automatically proves malicious activity | | |
| Parsing tools can help review logs at scale more effectively than Event Viewer alone | | |
| A SIEM query by itself proves full incident scope | | |
| Testing filters against lab-generated activity improves confidence in the approach | | |
| A reusable event-log approach should include limitations and false positives | | |
| This approach removes the need for correlation with other artifact types | | |

Then write six additional statements of your own and classify them the same way.

> **Guidance:** This lab is about building a better approach, not pretending event-log hunting can replace every other DFIR method.

---

### Task 10 — Write an "Approach" Analyst Note

**Objective:** Produce a concise working note that explains the hunting approach.

Write a 2–4 paragraph analyst summary describing:

- How your event-log hunting approach works
- Which suspicious patterns it prioritizes first
- Which tooling it relies on
- How it scales from one host to many
- What its limits are and how those limits should be handled

Write it as an internal workflow note for your team.

---

### Task 11 — Reflection

Answer the following in 3–5 sentences each.

**1. Why approach matters**
Why is a disciplined event-log approach more valuable than ad hoc hunting during an incident?

**2. Filters as force multipliers**
Why do known-good filters improve both speed and consistency across analysts?

**3. Scale changes everything**
Why does the right event-log approach change when you move from one host to many?

**4. Correlation remains essential**
Why do even the best Windows event-log hunts still need to be paired with host, execution, Registry, or network evidence?

---

## Deliverables Checklist

Your `lab09-notes.md` should contain:

- [ ] **Task 1** — Event-log-approach explanation plus short written responses
- [ ] **Task 2** — Suspicious-pattern table with at least 12 total patterns
- [ ] **Task 3** — Known-good filter mapping table
- [ ] **Task 4** — Tooling-at-scale table with written responses
- [ ] **Task 5** — First-pass event-hunt workflow
- [ ] **Task 6** — Reusable filter-pack structure and naming conventions
- [ ] **Task 7** — Test-action table with at least six actions
- [ ] **Task 8** — Refinement / tuning table
- [ ] **Task 9** — Strong support vs overclaim exercise
- [ ] **Task 10** — "Approach" analyst note
- [ ] **Task 11** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab09/
├── lab09-notes.md         ← Your working notes file (whole lab)
└── Lab09_03/
    ├── ReadMe.md              ← This file
    └── hunt-pack-scaffold.md  ← Reusable hunt-pack template
```

> **Reusable worksheet:** The [`hunt-pack-scaffold.md`](hunt-pack-scaffold.md) in this folder is the structured template for the hunt pack you build in Lab 09. It includes a pack inventory, a per-pattern block, a field-mapping cheatsheet for high-value EIDs and logon types, and a maintenance log. Each per-pattern block runs MITRE ATT&CK technique → channels → EIDs → field conditions → time-window → known false-positives → tool implementations → test evidence. Copy it into your team's shared `hunt-packs/` location once filled out.

---

## Key Takeaways

- **A good approach starts narrow.** Known-good filters tied to real IR questions beat broad manual review.
- **Patterns matter more than isolated events.** Authentication anomalies, services, scheduled tasks, PowerShell, and similar areas are high-value starting points.
- **Tooling determines scale.** Local parsers, WEF, and SIEMs each fit different investigation sizes.
- **Validation improves trust.** Tested and refined filters are far more valuable than unproven hunt ideas.
- **Approach beats improvisation.** A documented, reusable event-log workflow makes teams faster, more consistent, and more defensible.

---

**Next:** Lab 10 — Timeline Analysis

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
