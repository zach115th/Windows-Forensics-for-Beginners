# Lab 13.3 — Report Structures That Work

**Supporting Section 13.3: Report Structures That Work**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Three documents cover almost every incident: a one-page executive brief, a full incident report, and a technical appendix. They are not drafts of each other. They have different readers, different lifespans, and different failure modes, and it is normal for all three to exist at once.

You write the brief in the first two hours and reissue it on a cadence. You write the incident report once the investigation stabilizes, and an insurer or an auditor is still reading it 18 months later. The appendix is for the analyst who comes after you: an incoming responder, a peer reviewer, a retained expert, or you in a year.

This sub-exercise is about the skeletons and about the two sections inexperienced report writers drop by accident. Section 3.4, what you examined and *cleared*, is how a reader distinguishes "the attacker did not touch the domain controllers" from "we did not look at the domain controllers." Section 5, evidence gaps, is where the confidence scale from §13.2 earns its keep. Both are boring to write, and both are the first thing a hostile reviewer turns to.

You are not writing prose from scratch here. You are building the containers for the findings from Lab 13.2. The cells you cannot fill show you where your case is thin.

---

## What This Lab Covers

This lab supports the following concepts from Section 13.3:

| Section | Topic |
|---|---|
| 13.3.1 | The one-page executive brief |
| 13.3.2 | The incident report — including the two sections most often omitted |
| 13.3.3 | The technical appendix as the reproducibility layer |
| 13.3.4 | What not to write in any of the three |

---

## Learning Objectives

By completing this lab, you will be able to:

- Choose the right document for a given reader, deadline, and lifespan
- Produce a one-page executive brief that survives its page limit
- Populate an incident report skeleton, including sections 3.4 and 5
- Merge attacker and responder actions into a single labelled chronology
- Assemble a technical appendix that passes the reproducibility test
- Identify content that must not appear in any incident document, and say what to write instead

---

## Estimated Time

60–80 minutes

---

## Prerequisites

- Chapter 13 §13.3 read, with the three skeletons to hand
- Lab 13.2 completed — you will be placing those findings into the structures built here
- `report-templates.md` from the parent `Lab13/` folder. §1, §2, §2a, and §2b are all used in this lab
- A text editor or markdown editor
- Your `lab13-notes.md` file, in the parent `Lab13/` folder
- Helpful: the Chapter 11 §11.6 case summary template, which is the worked instance of the middle document

---

## Scenario

**IR-2024-11-014**, WKSTN-221. Two clocks apply in this sub-exercise.

**17:30 UTC on 2024-11-14.** The CFO wants a brief at 18:00. Someone in her leadership meeting told her "there was a hack in finance." Nothing has been contained. FILESVR-03 has not been collected. `10.0.4.17` read 4.2 MB off WKSTN-221 over SMB. It is a host inside your network, it is not in the CMDB, and nobody knows what it is.

**2024-11-17, three days later.** Containment held. WKSTN-221 memory was captured at 17:35–18:04 on 14 November and the host was isolated at 18:20. FILESVR-03 was snapshotted at 18:05. The FILESVR-03 review showed the `net use` at 14:33 and directory enumeration of `Finance$`, but no file reads beyond directory listings and no attacker binary. The team located `10.0.4.17`: an unmanaged Windows host under a desk in a decommissioned lab space, domain-joined 18 months ago and never inventoried. Its disk was imaged. An estate-wide EDR hunt found the `update.exe` hash nowhere else. The C2 address appears in flow records only for WKSTN-221 and `10.0.4.17`. Three days of elevated monitoring have produced nothing new.

Still true on both dates: no memory image from the intrusion window, no malware sample, no host DNS query logging, no Windows Event Forwarding, and a 20 MB Security log on workstations that wraps in roughly 36 hours.

### The response clock

The lab supplies these timestamps. They do not appear in `Data/WKSTN-221/`, which contains host artifacts only. You cannot build Section 2 or measure time-to-contain without them.

| Time (UTC) | Action | By |
|---|---|---|
| 14:21, 14 Nov | EDR alerts on the `OUTLOOK.EXE` → `POWERSHELL.EXE` chain | EDR platform |
| 14:23, 14 Nov | Alert triaged and escalated to IR | SOC |
| 14:25, 14 Nov | Decision recorded: monitor and collect before isolating | IR |
| 15:10, 14 Nov | Triage collection begins on WKSTN-221 — disk and logs only, no memory | IR |
| 17:20, 14 Nov | FILESVR-03 and `10.0.4.17` identified as in scope | IR |
| 17:30, 14 Nov | Nothing contained, nothing collected from either additional host | — |

---

## Background: Three Documents, Three Lifespans

| Document | Reader | Written when | Lives for | The way it fails |
|---|---|---|---|---|
| **Executive brief** | Non-technical decision-maker with five minutes | First two hours; reissued on cadence | Hours | Runs to two pages; contains no decision, so it is an FYI and is not read |
| **Incident report** | Insurer, auditor, counsel, the organization in 18 months | Once the investigation stabilizes | Years | Sections 3.4 and 5 are missing, so "we cleared it" is indistinguishable from "we did not look" |
| **Technical appendix** | The analyst who comes after you | Alongside the report | As long as the evidence is retained | A dumping ground rather than a reproducibility layer; C, D, or G incomplete |

> **IR Reality Check:** The test for the appendix is whether a competent analyst holding it and the evidence could re-derive your findings without speaking to you. If they could not, something in Tooling and Commands, Full Timeline, or Artifact Excerpts is missing.

---

## Lab Tasks

---

### Task 1 — Pick the Document

**Objective:** Match reader, deadline, and lifespan to a document before writing anything.

| Request | Which document | Why that one | What you would refuse to include |
|---|---|---|---|
| CFO wants to know at 18:00 whether payroll data was stolen | | | |
| Cyber insurer's adjuster asks for the response chronology | | | |
| Incoming night-shift responder takes the case at 20:00 | | | |
| Counsel asks what is established and what must be preserved | | | |
| Finance team lead asks when their share comes back | | | |
| Detection engineer, in six months, asks why a Sigma rule exists | | | |
| An auditor, in 18 months, asks whether the DCs were checked | | | |

Then answer:

**1. Two of the seven requests are answered by the same document but different sections of it. Which two, and which sections?**

**2. One request is answered by something that is not one of the three documents at all. Which, and what is it?**

**3. The chapter says the three documents "are not drafts of each other." What goes wrong when an analyst treats the executive brief as a shortened incident report?**

---

### Task 2 — Write the One-Page Executive Brief

**Objective:** Produce the document the CFO will actually read, at the length she will actually read (§13.3.1).

Go back to **17:30 UTC on 14 November**. Use the §13.3.1 skeleton, reproduced in `report-templates.md` §1. Fill every section.

Non-negotiables:

- **Bottom line** is two or three sentences. A reader who stops there must not be misinformed. Readable by someone who does not know what an event ID is.
- **What we do not know yet** must contain the FILESVR-03 question and the `10.0.4.17` question, each with an expected time.
- **Business impact** must write "under assessment" where it is under assessment, and must not name a data category the evidence does not support.
- **Decisions needed from leadership** must contain at least one real decision with a deadline and a stated consequence of delay. An FYI is not a brief.
- No event IDs, no IP addresses, no hashes, no tool names, no filenames.
- Zero words from the §13.2.2 banned list.
- One page. If it runs to two pages, it is a different document and you have failed the task.

Then write a **second version dated 17 November** for the same reader, same skeleton. The status line moves from Active to Contained.

Then answer:

**1. What did the page limit force you to cut from the 14 November brief? Name the item and state whether cutting it changed what the CFO would decide.**

**2. Your brief says something about payroll data. Compare that sentence against your Lab 13.2 Confirmed and Undetermined findings. Is the plain-language version still true at the same confidence level, or did translation quietly upgrade it?**

**3. The 17 November version carries good news. Chapter §13.1.3 warns about a failure mode around good news and cadence. What is it, and how does your second brief avoid it?**

---

### Task 3 — Build the Incident Report Scope Section

**Objective:** Populate Section 3, including the subsection everyone drops.

Work at the **17 November** clock. Use `report-templates.md` §2.

**Part A — 3.1 Systems in scope, and how scope was determined.** Name the *method*, not just the result. "Hunted hash X and C2 Y across N endpoints via EDR" is a scoping method. "We looked" is not.

| Host | Role | Basis for inclusion | Confidence |
|---|---|---|---|
| WKSTN-221 | | | |
| FILESVR-03 | | | |
| 10.0.4.17 | | | |

**Part B — 3.2 Accounts in scope.**

| Account | Type | Basis for inclusion | Rotated? |
|---|---|---|---|
| `payroll-admin` | | | |
| | | | |

**Part C — 3.3 Data in scope.** Name only categories the evidence supports, each with a confidence level.

| Category | Volume | Basis | Confidence |
|---|---|---|---|
| | | | |

**Part D — 3.4 Systems and accounts examined and ruled out.** This is the section most often omitted. Include what you checked, how, and what coverage the check had.

| Host / account | What was checked | Coverage / limitation | Outcome |
|---|---|---|---|
| Estate endpoints (EDR) | | | |
| DC01 / DC02 | | | |
| Run keys and Services on WKSTN-221 | | | |
| | | | |

Then answer:

**1. Section 3.4 is how a reader distinguishes "the attacker did not touch the domain controllers" from "we did not look at the domain controllers." Which of your 3.4 rows has the weakest coverage, and how did you say so in the Limitation column?**

**2. In 3.3, did you name a data category at all? If you did, defend it against your Lab 13.2 confidence assignments. If you did not, what do you write instead of a blank?**

**3. Scope grew twice during this incident — at 17:20 on 14 November and again when `10.0.4.17` was identified. Where in the report does scope *growth* get recorded, and why does an insurer care?**

---

### Task 4 — The Merged Chronology

**Objective:** Build Section 2 with attacker and responder actions in one timeline (§13.3.2).

Insurers and regulators both want the interval between discovery and containment. A merged chronology answers that at a glance.

Build the Section 2 table. Use the WKSTN-221 host artifacts for attacker rows and the response clock in the Scenario for responder rows. Curate — this is not the raw timeline.

| Time (UTC) | Actor | Event | Source artifact | Confidence |
|---|---|---|---|---|
| | Attacker / Responder | | | |

Aim for 12–18 rows. Then compute:

| Interval | Value | How you measured it |
|---|---|---|
| First attacker action → first alert | | |
| First alert → responder engaged | | |
| Responder engaged → containment decision | | |

Then answer:

**1. What is your "first attacker action," and how confident are you that it was the first? Name the source that would settle it.**

**2. Chapter §13.3.2 says attacker and responder actions must be "visually distinguished." What convention did you use, and would it survive being pasted into a Word document by someone else?**

**3. Which rows did you cut from the raw timeline to get to 12–18? State the rule you applied, in a form another analyst could reuse.**

---

### Task 5 — The Evidence Gaps Section

**Objective:** Write Section 5, where the confidence scale earns its keep.

Every Undetermined finding in Section 4 appears here. Use your Lab 13.2 Task 6 output as the starting set and add any this sub-exercise surfaced.

| # | What could not be determined | Which source would have answered it | Why it was unavailable | What it prevents concluding |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |

At least five rows. At least one must trace to a logging configuration rather than to an analyst decision.

Then answer:

**1. Chapter §13.3.2 calls Section 5 one of the two sections inexperienced writers omit. What is the *incentive* to omit it, and what does yielding to that incentive cost?**

**2. Sort your five gaps into two buckets: those that were our choice and those that were our configuration. Which bucket is easier to write and which is more useful to the organization?**

**3. Look ahead to §13.6.5. Which of your five rows is going to become a funded change, and what makes it fundable when the others are not?**

---

### Task 6 — Assemble the Technical Appendix

**Objective:** Build the reproducibility layer (§13.3.3).

Use the §2a inventory from `report-templates.md`. For each section, state what this case actually has, what it is missing, and whether the gap is fatal to reproducibility.

| Appendix section | What this case has | What is missing | Fatal to reproducibility? |
|---|---|---|---|
| A. Chain of custody records | | | |
| B. Evidence inventory | | | |
| C. Tooling and commands | | | |
| D. Full timeline | | | |
| E. Indicators of compromise | | | |
| F. Detection content produced | | | |
| G. Artifact excerpts | | | |
| H. Analyst notes | | | |

Then populate **section E** properly. The IOC set for this case includes hashes, an IP, filenames, paths, a task name and path, WMI filter and consumer names, and account names. List them all, exactly as they appear in the evidence.

| IOC type | Value | Source | Shelf life |
|---|---|---|---|
| | | | |

Then answer:

**1. Apply the chapter's test: could a competent analyst with your appendix and the evidence re-derive your findings without speaking to you? Where does it break?**

**2. Section E has a shelf-life column. Which of your IOCs are worth minutes and which are worth years? What does that tell you about where to spend effort in §13.6.4?**

**3. The chapter says "the appendix is not a dumping ground. It is the reproducibility layer." Name one thing you were tempted to put in it that belongs in the report body instead.**

---

### Task 7 — What Not to Write

**Objective:** Identify content that must not appear in any of the three documents (§13.3.4).

For each statement, decide whether it belongs in any document. If not, write what you would say instead.

| # | Statement | Belongs anywhere? | What to write instead |
|---|---|---|---|
| 1 | "This intrusion is consistent with tooling publicly associated with a known ransomware affiliate." | | |
| 2 | "This was a nation-state actor." | | |
| 3 | "The user opened a malicious attachment." | | |
| 4 | "The user should have known better than to open it." | | |
| 5 | "We estimate the breach will cost the business between £400k and £900k." | | |
| 6 | "The attacker was after payroll data." | | |
| 7 | "No evidence of lateral movement beyond FILESVR-03 was identified." | | |
| 8 | "The `10.0.4.17` host was left unmanaged by the platform team for eighteen months." | | |

Then answer:

**1. Statements 3 and 4 look similar and are not. State the distinction in one sentence, and say what happens to statement 4 if the report reaches an employment tribunal.**

**2. Statement 8 is factually true and traceable. Is it blame, or is it a finding? Where would you put it so it is useful rather than corrosive?**

**3. Statement 1 is defensible and statement 2 is not, according to the chapter. What is the specific difference, and what does statement 2 change about the legal and insurance posture of the incident?**

---

### Task 8 — Reflection

Answer each in 3–5 sentences.

**1. One page means one page**
The page limit is the most-broken rule in incident reporting. What does breaking it actually cost, in terms of the reader's decision?

**2. The sections nobody writes**
Why do 3.4 and 5 get dropped, given that both are easy to fill in and both make the report stronger?

**3. Writing for the analyst who comes after you**
The appendix is written for someone you may never meet. Does that make it easier or harder to write well, and what standard do you hold it to?

**4. Durable versus disposable**
The brief lives for hours and the report lives for years. How should that difference change the way you write each one?

---

## Deliverables Checklist

Your `lab13-notes.md` should contain:

- [ ] **Task 1** — Document-selection table for seven requests, plus three written responses
- [ ] **Task 2** — Executive briefs for 14 and 17 November, both within one page, plus three written responses
- [ ] **Task 3** — Incident report sections 3.1 through 3.4, plus three written responses
- [ ] **Task 4** — Merged chronology of 12–18 rows and the three measured intervals, plus three written responses
- [ ] **Task 5** — Evidence gaps table with at least five rows, plus three written responses
- [ ] **Task 6** — Appendix inventory and the populated IOC section, plus three written responses
- [ ] **Task 7** — What-not-to-write classification for eight statements, plus three written responses
- [ ] **Task 8** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab13/
├── lab13-notes.md  ← Your working notes file (whole lab)
└── Lab13_03/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **Three documents, three lifespans, three readers.** They are not drafts of each other, and all three normally exist at once.
- **One page means one page.** If the brief runs to two, it is a different document and the reader with five minutes will not finish it.
- **A brief without a decision is an FYI.** Nobody reads FYIs during a crisis.
- **Section 3.4 is how the reader tells "we cleared it" from "we did not look."** It takes 10 minutes to write, and it is the first thing an auditor turns to.
- **Section 5 is where the confidence scale earns its keep.** Every Undetermined finding gets a row with a named missing source.
- **The appendix is the reproducibility layer, not a dumping ground.** The test is whether someone could re-derive your findings without speaking to you.
- **Some things belong in no document at all.** Attribution without an intelligence basis, blame directed at individuals, cost estimates that are not your role, and unqualified negatives.

---

**Next:** Lab 13.4 — Containment Without Destroying Evidence

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
