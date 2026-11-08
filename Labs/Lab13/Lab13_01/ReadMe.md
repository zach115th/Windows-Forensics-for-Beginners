# Lab 13.1 — Writing for the Audience That Has to Act

**Supporting Section 13.1: Writing for the Audience That Has to Act**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

A report is not a record of your work. It is an instrument for someone else's decision.

That sentence is easy to nod at and hard to act on. Your notes are already a record of your work: chronological, complete, and organized around what you did. Converting notes into a report by cleaning up the formatting is the most common reporting failure in incident response. It is why technically excellent investigations routinely produce documents nobody reads.

This sub-exercise is about the conversion. You will take one afternoon's evidence from WKSTN-221 and write it out for readers whose decisions have nothing in common. A night-shift responder has to pick up an open thread. An IR manager has to allocate a second analyst. A CFO has to decide whether to tell anyone. Counsel needs to know what a hostile party could establish from the same evidence.

The forensic content does not change across those documents. What changes is what is foregrounded, what is compressed, and what is omitted. An analyst who writes one document and sends it to everyone has not saved time — they have produced something too technical for half the readers and too thin for the rest.

There is no parsing here and no dataset to open. Everything you need is quoted below.

---

## What This Lab Covers

This lab supports the following concepts from Section 13.1:

| Section | Topic |
|---|---|
| 13.1.1 | One investigation, many artifacts — the seven-audience mapping |
| 13.1.2 | The same finding, written three ways |
| 13.1.3 | Cadence beats completeness during an active incident |

---

## Learning Objectives

By completing this lab, you will be able to:

- Name the decision each incident audience is about to make, rather than their job title
- Decide what to foreground, compress, and omit for a given reader without changing the underlying facts
- Write the same finding for a technical peer, a manager, and an executive, keeping the uncertainty intact in each
- Explain why legal counsel and regulators require different handling from every other audience
- Set a written update cadence in the first hour of an incident and hold to it
- Recognize when silence from the IR team is being interpreted, and pre-empt it

---

## Estimated Time

45–60 minutes

---

## Prerequisites

- Chapter 13 §13.1 read, particularly the seven-audience table in §13.1.1
- A text editor or markdown editor. Nothing else — no VM, no parsers
- Your `lab13-notes.md` file, in the parent `Lab13/` folder
- Helpful but not required: your `lab10-notes.md` timeline narrative from Lab 10, and the case summary you wrote in Lab 11 Task 12

---

## Scenario

It is **17:30 UTC on 2024-11-14**. You are the analyst on IR-2024-11-014.

About three hours ago, at 14:23, the SOC escalated an EDR alert on **WKSTN-221**, a finance workstation assigned to `payroll-admin`. You have worked the triage collection all afternoon. You know the host in detail between 14:18 and 14:35 UTC. You know very little about anything else.

Four people want something from you before the end of the day, and one of them wants it in 30 minutes.

### The evidence you are writing from

Verified against `Data/WKSTN-221/`. Do not round these figures and do not soften them.

| Time (UTC) | Event | Source |
|---|---|---|
| 14:18:55 | LNK file created for `Q4_Payroll_Review.xlsm` | `lnk-files.csv` |
| 14:19:38 | `OUTLOOK.EXE` spawns `POWERSHELL.EXE` with `-EncodedCommand` (EID 4688) | `security-evtx.csv` |
| 14:21:03 | `update.exe` executes. Prefetch `UPDATE.EXE-89A4B22C.pf`, **RunCount 1** | `prefetch.csv` |
| 14:21:55 | TCP/443 flow to `91.214.47.22`, owning process `update.exe` — **184,221 bytes sent, 2,415,891 bytes received** | `network-flow.csv` |
| 14:23:02 | WMI event subscription created in `root\subscription`, binding present | `wmi-persistence.csv` |
| 14:23:44 | `update.exe` deleted from `Temp\` | `usn-journal.csv` |
| 14:31:05–14:33:14 | Inbound SMB from `10.0.4.17` — **4,218,421 bytes read off WKSTN-221** | `network-flow.csv` |
| 14:33:18 | Explicit-credential logon (EID 4648), `TargetServerName=FILESVR-03` (10.0.4.18) | `security-evtx.csv` |

Plus the standing facts: no memory capture exists, no malware sample was recovered, FILESVR-03 has not been collected, and `10.0.4.17` is not in the CMDB and nobody knows what it is.

### Your readers

| Reader | Why they are asking |
|---|---|
| Night-shift responder | Takes the case at 20:00 and needs to keep working it, not re-derive it |
| IR manager (J. Okafor) | Deciding whether to pull a second analyst off another case tonight |
| CFO | Heard "there was a hack in finance" from a third party. Wants a brief at 18:00 |
| Legal counsel | Preparing a preservation memo, and wants facts separated from inference |

A second, unrelated case is also open: **IR-2024-11-009**, the HR-WS17 departing-employee exfiltration from Lab 11. Legal and HR read that one. It appears here only as a contrast.

---

## Background: The Same Evidence, Different Instruments

Chapter §13.1.1 lists seven audiences. They are not reading different reports because they have different clearance. They are reading different reports because they have **different decisions**.

| Audience | The decision |
|---|---|
| Technical peer / incoming responder | What do I work on next, and what has already been ruled out? |
| IR manager | Where do I put people, and do I need to escalate? |
| Executive leadership | Do we tell anyone, and what do I say if asked? |
| Legal counsel | What can and cannot be established, and what must be preserved? |
| Cyber insurer | Was the response timely and were controls in place? |
| Regulator | Which data, which individuals, which dates, which jurisdictions? |
| Affected business unit | What do my people do right now, and when do we get service back? |

> **IR Reality Check:** Two of these deserve special care. Counsel is *actively harmed* by unlabelled inference, because they need to know what a hostile party could establish from the same evidence. Regulators run on statutory clocks that start at discovery, not at conclusion. You often have to extract the notification-relevant subset of your findings, with precision, long before the investigation is finished.

---

## Lab Tasks

---

### Task 1 — Name the Decision, Not the Job Title

**Objective:** Establish who is reading what before you write a word.

For each reader below, state the decision they will make in the next 24 hours. Write a decision, not a responsibility. "Decide whether to notify the audit committee tonight" is a decision. "Oversee the incident" is not.

| Reader | The decision they make in the next 24 h | The deadline on it |
|---|---|---|
| Night-shift responder | | |
| IR manager | | |
| CFO | | |
| Legal counsel | | |
| Finance team lead (business unit) | | |
| Legal + HR on IR-2024-11-009 (HR-WS17) | | |

Then answer:

**1. Which two of the six readers does Chapter §13.1.1 say deserve special care, and what specifically goes wrong when an analyst writes for them the way they would write for a technical peer?**

**2. Two readers on this list have deadlines set by someone other than you. Which two, and what does that do to the order you write in?**

**3. One reader on this list is not on IR-2024-11-014 at all. Why is it useful to hold both cases in view while you plan the day's writing?**

---

### Task 2 — Foreground, Compress, Omit

**Objective:** Practise the three operations that convert one investigation into many documents.

For each reader, pick one item from the evidence table in the Scenario to foreground, one to compress into a phrase, and one to leave out entirely. Then state the failure mode if you get the choice wrong.

| Reader | Foreground | Compress to a phrase | Omit entirely, and why | Failure mode if wrong |
|---|---|---|---|---|
| Night-shift responder | | | | |
| IR manager | | | | |
| CFO | | | | |
| Legal counsel | | | | |

Then answer:

**1. The 14:21:55 flow carries 184,221 bytes out and 2,415,891 bytes in. Which readers need the direction, which need only the magnitude, and which need neither?**

**2. Which single item in the evidence table would you refuse to put in *any* of the four documents at this stage? What would have to change for it to become releasable?**

**3. "Omit" and "compress" are different operations with different risks. Describe the risk of each in one sentence.**

---

### Task 3 — The Same Finding, Three Ways

**Objective:** Compress and translate without losing the uncertainty (§13.1.2).

The subject is the same in all three versions: **what `update.exe` did on WKSTN-221 and what left the host**.

| Reader | Constraint | Your version |
|---|---|---|
| Night-shift responder | Artifact-level. At least one named artifact, at least one exact figure, and an explicit "not yet checked" naming the top open thread. | |
| IR manager | No artifact names, no event IDs. State current scope, what would grow it, and one concrete resource ask. **Under 120 words.** | |
| CFO | No event IDs, no IP addresses, no tool names, no hashes, no filenames. Must state what is not yet known and when you expect to know it. **Under 80 words.** | |

Use the §13.1.2 worked example in the chapter as your model. Read it once, then write yours without looking at it.

Then answer:

**1. The chapter says the uncertainty does not disappear across the three versions — it changes form. Quote the exact phrase carrying the uncertainty in each of your three versions.**

**2. Your CFO version is under 80 words. Name the single most important thing you cut and state the risk you accepted by cutting it.**

**3. Read your CFO version as though you were the CFO. Is there any sentence from which she could reasonably conclude something the evidence does not support? Fix it.**

---

### Task 4 — Write the Counsel Version

**Objective:** Handle the audience that is harmed by unlabelled inference.

Counsel is preparing a preservation memo on IR-2024-11-014. Their question is narrow: **what is established, what is inferred, and what data categories are in question?**

Write a note for counsel of no more than 200 words, covering:

- What the artifacts directly record
- What you have concluded by reasoning, labelled as such
- What data categories are in question and at what confidence, naming none the evidence does not support
- What must be preserved right now and for how long
- What is *not* established

Then, as a second version, write the equivalent 200-word note for **legal and HR on IR-2024-11-009** — the HR-WS17 case from Lab 11. Counsel's question there is different: *which of the named pricing files can we establish left the host, by what route, and at what confidence?*

Then answer:

**1. The HR-WS17 note is the one where you should be naming what is *not* established almost as prominently as what is. Why does the legal audience invert the emphasis?**

**2. Chapter §13.3.4 lists things that should not appear in any incident document. Which of them were you tempted to write into the counsel note, and why is the temptation strongest for this reader?**

**3. In one sentence: what does counsel do with your report that no other reader does, and how should that change your sentence construction?**

---

### Task 5 — Set the Cadence

**Objective:** Establish an update rhythm in the first hour and hold to it (§13.1.3).

Chapter §13.1.3 gives four standing headings for every update during an active incident: **what changed, what is confirmed now, what is still open, what decision is needed from the reader.**

**Part A.** Write the 18:00 UTC update to the IR manager using those four headings. Keep it under 150 words.

**Part B.** Write the 22:00 UTC update. Assume nothing has changed since 18:00: FILESVR-03 is still uncollected, `10.0.4.17` is still unidentified, and containment held. Send it anyway.

**Part C.** Fill in the cadence plan you would have set at 15:10 UTC, when the triage collection began.

| Reader | Update frequency | Format | Owner | First update due |
|---|---|---|---|---|
| Night-shift responder | | | | |
| IR manager | | | | |
| CFO | | | | |
| Legal counsel | | | | |
| Finance team lead | | | | |

Then answer:

**1. The chapter says readers "interpret silence from the IR team, and they never interpret it charitably." What specifically will the CFO conclude if the 22:00 update does not arrive?**

**2. Your Part B update says nothing changed. What is the value of sending it, stated in terms of the reader's decision rather than your diligence?**

**3. Cadence costs analyst time during the hours when analyst time is scarcest. Make the argument for it anyway, in the terms an IR manager would accept.**

---

### Task 6 — Reflection

Answer each in 3–5 sentences.

**1. The deliverable is a decision**
Chapter 13 argues that a perfect timeline sitting in a case folder while leadership makes an uninformed disclosure decision is a failed engagement. Do you accept that framing? What does accepting it change about how you would spend the last hour of an investigation?

**2. Notes are not a report**
Why is "clean up the formatting on my notes" such a persistent failure mode, and what would you do differently on your next case to avoid it?

**3. Uncertainty survives translation**
Executives are the audience analysts are most tempted to smooth over for. Why is that exactly backwards?

**4. Seven documents, one investigation**
Writing for seven audiences sounds like seven times the work. Explain, from what you produced in Tasks 3 and 4, why it is not.

---

## Deliverables Checklist

Your `lab13-notes.md` should contain:

- [ ] **Task 1** — Decision table for all six readers, plus three written responses
- [ ] **Task 2** — Foreground / compress / omit table for four readers, plus three written responses
- [ ] **Task 3** — The same finding written three ways, plus three written responses
- [ ] **Task 4** — The counsel note for IR-2024-11-014 and the counsel/HR note for IR-2024-11-009, plus three written responses
- [ ] **Task 5** — The 18:00 and 22:00 updates, the cadence plan table, plus three written responses
- [ ] **Task 6** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab13/
├── lab13-notes.md  ← Your working notes file (whole lab)
└── Lab13_01/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **A report is an instrument for someone else's decision.** Organize it around what the reader has to decide, not around what you did.
- **Name the decision, not the job title.** "The CFO" is not an audience. "The person deciding tonight whether to brief the audit committee" is.
- **The forensic content does not change across audiences — the framing does.** Foreground, compress, omit. Nothing gets invented and nothing gets softened.
- **Uncertainty changes form across versions, but it never disappears.** "Not yet checked" becomes "unconfirmed and I need it parsed today" becomes "we expect to know by end of day."
- **Counsel and regulators are special cases.** Counsel is harmed by unlabelled inference. Regulators run on a statutory clock that started at discovery.
- **Cadence beats completeness.** The update that arrives on time and says "nothing changed" is worth more than the complete one that arrives Thursday.

---

**Next:** Lab 13.2 — The Anatomy of a Defensible Finding

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
