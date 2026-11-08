# Lab 13.6 — Recovery, Lessons Learned, and the Detection Feedback Loop

**Supporting Section 13.6: Recovery, Lessons Learned, and the Detection Feedback Loop**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

This sub-exercise covers the part of the incident response loop that most organizations perform as theatre. It is the last sub-exercise in the last lab of the book.

Recovery is the business's decision, informed by yours. The IR team owes the business a clear statement, in the confidence language from §13.2.2, of what has and has not been established. The business then accepts a risk it can see rather than one it has been told does not exist. The hinge is a single number: the earliest confirmed compromise timestamp. Only the investigation can produce that number, and it is what makes a restore point safe rather than hopeful.

The post-incident review comes next. It has a bad reputation because teams usually run it as a blameless retrospective that produces a list of aspirations nobody owns. A useful one produces a few changes with names and dates attached.

The detection feedback loop pays for the whole engagement. Every case should leave the detection posture measurably better than it found it, and "measurably" means specific artifacts. Those are behavioral detections written as portable rules, generalized hunt-pack entries, and logging gaps. The logging gaps are the most valuable, written up as specific funded changes tied to the specific findings they would have resolved. The Undetermined rows in your report are next year's detection roadmap. The window in which the organization will act on logging recommendations closes fast, and the incident report is the moment.

---

## What This Lab Covers

This lab supports the following concepts from Section 13.6:

| Section | Topic |
|---|---|
| 13.6.1 | Restoring service with confidence |
| 13.6.2 | Validating that backups are clean |
| 13.6.3 | The lessons learned that isn't theatre |
| 13.6.4 | Turning findings into detection content |
| 13.6.5 | Logging gaps are deliverables |
| 13.6.6 | Closing the case |

---

## Learning Objectives

By completing this lab, you will be able to:

- State the prerequisites that must be met before service returns, and stage a recovery so a mistake is observable
- Use a defensible earliest-confirmed-compromise timestamp to select and defend a restore point
- Validate that a backup is clean before restoring it, including validating the backup infrastructure itself
- Run a post-incident review that produces owned, dated changes rather than aspirations
- Measure the intervals an insurer and a regulator will both ask about
- Convert a behavioral finding into a Sigma rule that outlives the campaign
- Sort a case's detection harvest into the five §13.6.4 categories and assign shelf lives
- Write a logging gap tied to a specific finding, with a change, an owner, and a cost — the form that gets funded
- Close a case as an action rather than a fade-out

---

## Estimated Time

70–95 minutes

---

## Prerequisites

- Chapter 13 §13.6 read, with the §13.6.4 Sigma example and the §13.6.5 gap form to hand
- Labs 13.1 through 13.5 completed. Task 3 of this lab needs your findings and confidence levels from Lab 13.2, and Task 5 needs your Undetermined findings by number
- `report-templates.md` from the parent `Lab13/` folder — §4 is the lessons-learned skeleton
- A text editor or markdown editor
- Your `lab13-notes.md` file, in the parent `Lab13/` folder
- Helpful: your `hunt-pack.md` from Lab 09. Task 4 of this lab feeds a new entry back into it

---

## Scenario

**2024-11-17.** Containment has held for three days. Eradication is planned and partly executed. The business wants the `Finance$` share back, and it wants to know when.

What the last three days established:

- **FILESVR-03** showed the `net use` at 14:33 and directory enumeration of `Finance$`, but no file reads beyond directory listings and no attacker binary.
- **`10.0.4.17`** was located. It is an unmanaged Windows host under a desk in a decommissioned lab space, domain-joined 18 months ago and never inventoried. Its disk was imaged.
- An estate-wide EDR hunt for the `update.exe` hash found it on no other host. The C2 address appears in flow records only for WKSTN-221 and `10.0.4.17`.
- Three days of elevated monitoring have produced nothing new.

### The recovery constraints

| | |
|---|---|
| Backups | FILESVR-03 is backed up nightly at **01:00 UTC** to a backup appliance **on the same domain** |
| Earliest observed attacker activity on WKSTN-221 | LNK created **14:18:55 on 2024-11-14**. EID 4688 `OUTLOOK.EXE` → `POWERSHELL.EXE` at **14:19:38** |
| An earlier event of interest | Four failed network logons (EID 4625, type 3) from `185.193.126.47` at **04:00:00–04:00:42 on 2024-11-14** for `admin`, `administrator`, `root`, `svc-admin` |
| Log coverage | Security log on workstations is **20 MB, wraps in roughly 36 hours**. **No Windows Event Forwarding.** No host DNS query logging. Perimeter flow records retained **14 days**. No packet capture. |
| `10.0.4.17` dwell | Unknown. Domain-joined 18 months, unmanaged, no telemetry, no logs retained |

### The response clock

| Time (UTC) | Event |
|---|---|
| 14:18:55, 14 Nov | First observed attacker action on WKSTN-221 |
| 14:21, 14 Nov | EDR alerts on the `OUTLOOK.EXE` → `POWERSHELL.EXE` chain |
| 14:23, 14 Nov | Alert triaged and escalated to IR |
| 14:25, 14 Nov | Decision recorded: monitor and collect before isolating |
| 14:33:18, 14 Nov | Explicit-credential logon from WKSTN-221 to FILESVR-03, 10 minutes after escalation |
| 15:10, 14 Nov | Triage collection begins — disk and logs only, no memory |
| 17:20, 14 Nov | FILESVR-03 and `10.0.4.17` identified as in scope |
| 17:35–18:04, 14 Nov | Memory captured on WKSTN-221 |
| 18:05, 14 Nov | FILESVR-03 suspended and snapshotted |
| 18:20, 14 Nov | WKSTN-221 isolated by EDR |

### What is still missing

No memory image from the intrusion window. The WKSTN-221 capture began at 17:35, about three hours after on-host activity ended. No malware sample — `update.exe` was deleted at 14:23:44 and nothing was carved from unallocated space. No host DNS query logging. No Windows Event Forwarding, so a log clearing on any host would have been total.

---

## Background: The Harvest Is the Payment

Chapter §13.6.4 lists five output categories from a single case. They differ in value and in shelf life.

| Category | Example from this case | Shelf life | Effort to produce |
|---|---|---|---|
| Atomic indicators | The `update.exe` SHA-256; `91.214.47.22` | Days to weeks — the attacker changes them | Minutes. Do it anyway |
| Behavioral detections | `OUTLOOK.EXE` as parent of `powershell.exe` | Years | An hour, and this is where the value is |
| Hunt-pack entries | The *shape* of "outbound from a user-context process to a newly-observed external IP" | Years | An hour |
| Detection gaps (had the log, no rule) | A detection engineering ticket per gap | Until the rule ships | Minutes to write, weeks to fund |
| Logging gaps (did not have the log) | No memory capture capability; 20 MB Security log | Years of benefit | The highest-value output of the whole exercise |

> **IR Reality Check:** A gap tied to a finding gets funded. A gap presented as a general best practice does not. This is the single most effective piece of advocacy an incident responder gets to do, and the incident report is the moment to do it.

---

## Lab Tasks

---

### Task 1 — Restoring Service with Confidence

**Objective:** State the prerequisites and stage the recovery (§13.6.1).

**Part A.** Chapter §13.6.1 lists five practical prerequisites before service returns. For each, state whether IR-2024-11-014 has met it as of 17 November, and what specifically is outstanding.

| Prerequisite | Met? | What is outstanding | Owner |
|---|---|---|---|
| Eradication verification complete, with results documented | | | |
| Rebuilt or cleaned hosts brought up on rotated credentials | | | |
| Restored systems patched and hardened against the original entry vector *before* reconnection | | | |
| Elevated monitoring in place with owners assigned | | | |
| A documented rollback plan if restoration shows signs of compromise | | | |

**Part B.** Stage the recovery. Bring services back most-critical and best-understood first, with an observable interval between each.

| Stage | What comes back | When | What you watch during the interval | Rollback trigger |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |

Then answer:

**1. The chapter says staged recovery turns "the whole environment is back and something is wrong" into "the third system we brought back is wrong." What is the minimum interval between your stages, and what determines it?**

**2. Recovery is the business's decision, informed by yours. Write the two-sentence statement of residual risk you would give the business before it decides — using the confidence language from §13.2.2.**

**3. One of the five prerequisites in Part A is the one your case is furthest from meeting. Which, and what would it take to close?**

---

### Task 2 — Validate the Backup

**Objective:** Establish a restore point against a defensible earliest-confirmed-compromise timestamp (§13.6.2).

**Part A — Establish the timestamp.**

| Candidate | Timestamp | Confidence | Argument for it as the earliest confirmed compromise | Argument against |
|---|---|---|---|---|
| LNK creation for `Q4_Payroll_Review.xlsm` | 14:18:55, 14 Nov | | | |
| EID 4688, `OUTLOOK.EXE` → `POWERSHELL.EXE` | 14:19:38, 14 Nov | | | |
| Failed logons from `185.193.126.47` | 04:00:00, 14 Nov | | | |
| Something earlier, unestablished | — | | | |

Commit to one, with a confidence level. Then state the sentence you would put in the report.

**Part B — Select and defend a restore point for FILESVR-03.** Backups run nightly at 01:00 UTC.

| Question | Your answer |
|---|---|
| Which backup do you restore from? | |
| Why that one and not the one immediately before the compromise? | |
| What confidence does your earliest-compromise timestamp carry, and how does that change the margin you leave? | |
| If dwell time on `10.0.4.17` is Undetermined, does that affect the FILESVR-03 restore point? | |

**Part C — Validate the backup before restoring it.** Chapter §13.6.2 gives five checks. Write each as an executable step here.

| Check | Concrete action for this case | Done when |
|---|---|---|
| Identify the earliest confirmed compromise and state its confidence | | |
| Select a restore point comfortably before it | | |
| Scan the backup content offline for the case IOC set, especially persistence artifacts | | |
| Verify the backup infrastructure itself was not compromised | | |
| Restore into an isolated segment, verify, then reconnect | | |

Then answer:

**1. The backup appliance is on the same domain. Chapter §13.6.2 says backup servers are a primary target "because compromising them defeats recovery." What specifically would you check, and what would "not compromised" look like as a positive finding rather than an absence?**

**2. If your earliest-compromise timestamp were Undetermined rather than Confirmed, what is the honest statement to the business about restore points?**

**3. The IOC scan of backup content targets persistence artifacts especially. Which two artifacts from this case would you scan a FILESVR-03 backup for, and why those two?**

---

### Task 3 — Write the Sigma Rules

**Objective:** Convert behavioral findings into portable detection content (§13.6.4).

Write **two** rules. One must target the persistence mechanism the case found. The other must target something earlier in the chain. Both must be behavioral — a relationship or pattern, not an atomic indicator.

```yaml
title:
id:
status: experimental
description:
references:
  - Internal case IR-2024-11-014
logsource:
  category:
  product: windows
detection:
  selection:
  condition: selection
falsepositives:
  -
level:
```

Each rule must have a real title, a description referencing the case, a `logsource`, a `detection` block that would actually fire on the WKSTN-221 evidence, a realistic `falsepositives` entry, and a `level`.

For each rule, state:

| | Rule 1 | Rule 2 |
|---|---|---|
| Which artifact in the case would have made it fire | | |
| At what exact timestamp | | |
| Which log source or telemetry it depends on | | |
| Whether that source exists in this environment today | | |

Then answer:

**1. One of your two rules depends on a telemetry source this environment does not have on servers. Which, and what does that do to the rule's coverage?**

**2. Chapter §13.6.4 says to tag every artifact with the case reference so rules whose originating threat is long dead can be retired deliberately. Write the retirement criterion for one of your two rules — the specific condition under which a future engineer should turn it off.**

**3. Your `falsepositives` entry should be evidence-based, not a guess. What would you actually measure to populate it, and over what window?**

---

### Task 4 — Sort the Harvest

**Objective:** Populate all five §13.6.4 output categories from this case.

| Category | Items from IR-2024-11-014 | Where it goes | Shelf life |
|---|---|---|---|
| Atomic indicators | | | |
| Behavioral detections | | | |
| Hunt-pack entries (generalized) | | | |
| Detection gaps (had the log, no rule) | | | |
| Logging gaps (did not have the log) | | | |

For the hunt-pack row, write the new entry in the format of the hunt pack you built in Lab 09, generalized. Save the *shape* of the query, not the instance. If you wrote a query to find `91.214.47.22` across the estate, the durable version is "outbound connections from user-context processes to newly-observed external IPs."

Then answer:

**1. The atomic indicator row is the lowest-value row on the table and the chapter still says to do it. Why?**

**2. Which row on this table did you find hardest to populate, and is that because the case did not produce the material or because the category is harder to think in?**

**3. Give one example of a detection gap in this case that is genuinely a gap — the log existed and no rule watched it — and distinguish it from the logging gaps in the row below.**

---

### Task 5 — Cost the Logging Gaps

**Objective:** Write gaps in the form that gets funded (§13.6.5).

Write **three** gap entries in the §13.6.5 form. At least one must be tied by number to a specific Undetermined finding from Lab 13.2.

```markdown
**Gap L-N:** [The specific condition, with the number that makes it concrete.]
[Which findings are Undetermined or degraded as a direct result — by finding number.]
**Change:** [The specific configuration change, with the specific target value.]
**Owner:** [Named team.]
**Cost:** [Licence, storage, engineering time, collector capacity.]
```

Candidate gaps this incident exposed, at least three of which are real:

- No memory capture capability on physical endpoints
- Security log capped at 20 MB, wrapping in roughly 36 hours on WKSTN-221
- No Windows Event Forwarding, so log clearing on a host would be total
- No host-level DNS query logging
- No EDR on servers
- No packet capture anywhere
- An unmanaged domain-joined host absent from the CMDB for 18 months
- Flow retention of 14 days against an unknown dwell time

Then answer:

**1. Chapter §13.6.5 says "a gap tied to a finding gets funded. A gap presented as a general best practice does not." Take one of your three gaps and write the unfundable version of it, then explain in one sentence what the fundable version does differently.**

**2. One of the candidate gaps above is not a logging gap at all — it is an asset management gap. Which, and does it still belong in this section of the report? Argue it.**

**3. The chapter says the window in which the organization will act on logging recommendations "closes fast." How fast, in your judgement, and what does that imply about when you write this section relative to the rest of the report?**

---

### Task 6 — The Lessons-Learned Entry

**Objective:** Produce owned, dated changes rather than aspirations (§13.6.3).

**Part A — Measure the intervals.** Use the response clock in the Scenario.

| Interval | Value | How measured |
|---|---|---|
| First attacker action → first alert | | |
| First alert → responder engaged | | |
| Responder engaged → containment | | |
| Containment → eradication verified | | |
| Eradication verified → service restored | | |

**Part B — The four questions.** Every output gets an owner and a date. Outputs without owners are not outputs.

| Question | Answer for IR-2024-11-014 | Resulting action | Owner | Due |
|---|---|---|---|---|
| What let this happen? | | | | |
| What delayed detection? | | | | |
| What slowed the response? | | | | |
| What worked, and is it repeatable? | | | | |

Use the §4 skeleton in `report-templates.md` for the full entry.

Then answer:

**1. Question 2 has a measurable answer in this case. State the interval between first attacker action and first alert using the timestamps above, and name the one control that would have shortened it most.**

**2. Chapter §13.6.3 says the fourth question gets skipped and that skipping it is how good practice fails to become standard practice. Name one thing that genuinely worked on this incident and write the action that would make it a default rather than a lucky choice by one analyst.**

**3. The review should be held within two weeks, with the responders, the system owners, the detection engineers, and someone with budget authority in the room. Which of those four is hardest to get, and what specifically fails to happen if they are absent?**

---

### Task 7 — Close the Case

**Objective:** Treat closure as an action rather than a fade-out (§13.6.6).

Work the closure checklist for IR-2024-11-014. For each item, state what it means concretely here, who owns it, and whether it is done.

| Item | Concrete meaning for this case | Owner | Done? |
|---|---|---|---|
| Final report version issued and distributed per its classification | | | |
| Evidence retention period set, with a disposal date and a named owner | | | |
| Chain of custody closed out for every item | | | |
| Detection content deployed, FP rate checked after two weeks | | | |
| Lessons-learned actions logged with owners | | | |
| Case folder archived per the naming standard, findable by search | | | |

Then answer:

**1. The chapter says the last item "matters more than it sounds," because the case you close today is the reference material for the case you open next quarter. What naming and tagging would make this case findable in 18 months by someone who does not know its reference number?**

**2. Evidence retention needs a disposal date and an owner. What retention period would you set here, what would drive it, and who decides?**

**3. Detection content gets its false-positive rate checked after two weeks. What happens to a rule that fires 40 times a day, and what happens to the team's trust in the whole rule set if nobody checks?**

---

### Task 8 — Reflection

Answer each in 3–5 sentences.

**1. The number that makes recovery possible**
The earliest confirmed compromise timestamp is the one output of the investigation that nothing else can produce. What does that tell you about where to spend investigative effort when time is short?

**2. Theatre versus change**
You have almost certainly sat in a post-incident review that produced nothing. What specifically was missing, and which of §13.6.3's four questions would have caught it?

**3. Advocacy is part of the job**
Chapter 13 calls the logging-gaps section "the single most effective piece of advocacy an incident responder gets to do." Are you comfortable with that framing of the role? What does it require of you that pure analysis does not?

**4. The end of the loop is the start of the next one**
This is the last sub-exercise of the last lab. Looking back across Labs 01 to 13, name the habit — not the tool, not the artifact — you would most want to carry into a real engagement, and say why.

---

## Deliverables Checklist

Your `lab13-notes.md` should contain:

- [ ] **Task 1** — Recovery prerequisites table, staged recovery plan, plus three written responses
- [ ] **Task 2** — Earliest-compromise timestamp with confidence, restore point selection, the five validation checks, plus three written responses
- [ ] **Task 3** — Two Sigma rules with firing artifacts and timestamps, plus three written responses
- [ ] **Task 4** — Five-category harvest table and the generalized hunt-pack entry, plus three written responses
- [ ] **Task 5** — Three costed logging gaps in the §13.6.5 form, at least one tied to a numbered finding, plus three written responses
- [ ] **Task 6** — Measured intervals, the four-question lessons-learned table with owners and dates, plus three written responses
- [ ] **Task 7** — Case closure checklist, plus three written responses
- [ ] **Task 8** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab13/
├── lab13-notes.md  ← Your working notes file (whole lab)
└── Lab13_06/
    └── ReadMe.md       ← This file
```

---

> **Going deeper:** `Book/AppendixC.md` (EDR Platforms and Sysmon) covers translating the Sigma rules you write in Task 3 into the EDR and SIEM query languages your organization actually runs. It also gives the Sysmon event IDs your rules should target where Security-log auditing does not reach: 1 for process creation, 3 for network connections, and 19/20/21 for WMI filters, consumers, and bindings. `Book/AppendixB.md` (Cloud Identity and M365 Forensics) covers the token and refresh-credential side of recovery, which Task 1's "brought up on rotated credentials" prerequisite quietly assumes. For a one-page condensation of every artifact path, event ID, and logon type referenced across this lab, see `Book/AppendixE.md`.

---

## Key Takeaways

- **Recovery is the business's decision, informed by yours.** Your job is to state what has and has not been established clearly enough that the business is accepting a risk it can see.
- **The earliest confirmed compromise timestamp is what makes a restore point safe rather than hopeful.** If dwell time is Undetermined, the honest statement is that any restore point carries unquantified risk.
- **Validate the backup infrastructure, not just the backup.** A backup catalogue an attacker had administrative access to cannot be trusted without verification.
- **Stage the recovery.** An observable interval between restorations turns "something is wrong" into "the third system we brought back is wrong."
- **A lessons-learned entry without owners and dates is a list of aspirations.** Of the four questions, the fourth — what worked — is the one that gets skipped.
- **Behavioral detections outlive the campaign, and atomic indicators do not.** Write the behaviour as a portable rule, save the *shape* of the hunt query rather than the instance, and tag everything with the case reference so it can be retired deliberately.
- **Logging gaps are the highest-value output of the whole exercise.** Tied to a numbered finding, with a change, an owner, and a cost, they get funded. Presented as best practice, they do not.
- **Closing is an action, not a fade-out.** Report issued, retention set with a disposal date and an owner, custody closed, detections deployed and checked, actions logged, case folder archived and findable.

---

**Next:** [Chapter 14 — Conclusion and Next Steps](../../../Book/Chapter14.md). This is the final sub-exercise in the lab series; Chapter 14 closes the book with a self-assessment, the territory deliberately left out of scope, and a plan for keeping the skills sharp.

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
