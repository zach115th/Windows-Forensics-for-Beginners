# Lab 12.1 — What Makes Ransomware Different

**Supporting Section 12.1: What Makes Ransomware Different**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

A ransomware case runs on four clocks, and none of them is yours. Every other case in this book reconstructs something that already finished: you arrive, the evidence sits still, and the only clock is your own.

Here, the ransom note is a negotiation deadline. The finance director wants a return-to-service estimate. Counsel wants a yes-or-no answer on data theft within a window set by regulation rather than by evidence. The infrastructure lead has already booked the reimage that will destroy the disk you have not yet copied.

This sub-exercise covers the judgment that has to happen before you open a single CSV. You will name the four clocks and the decision each one pressures, and write the preservation request that has to go out inside the first hour. You will work out what the encryption event tells you about the intrusion, which is very little. Then you will reason about why "just restore from backup" is an answer to one problem out of four.

There is almost no artifact analysis here, by design. The most expensive mistakes on a ransomware case happen in the first 90 minutes, when analysis starts before preservation.

---

## What This Lab Covers

This lab supports the following concepts from Section 12.1:

| Section | Topic |
|---|---|
| 12.1.1 | The four clocks — recovery, negotiation, notification, insurance |
| 12.1.2 | The encryption is the end of the intrusion, not the start |
| 12.1.3 | Double, triple, and fourth-layer extortion models |
| 12.1.4 | Why "just restore from backup" answers only the availability problem |
| 12.1.5 | The ACCT-FS01 scenario and its parameters |

---

## Learning Objectives

By completing this lab, you will be able to:

- Name the four clocks in a ransomware incident, identify who sets each, and state the investigative cost if each one wins
- Write a preservation request that survives contact with an infrastructure lead who has a reimage scheduled
- Explain why an investigation scoped to the encryption event produces a fast, confident, and wrong answer
- Distinguish single, double, triple and fourth-layer extortion, and name the forensic question each layer creates
- Identify the four problems that restoring from backup does *not* solve
- Read a ransom note for investigative value rather than for its threats
- Separate the actor's claims from the evidence, in writing

---

## Estimated Time

45–70 minutes

---

## Prerequisites

- Completion of Labs 01–11, or equivalent familiarity with preservation, chain of custody, and IR workflow
- A text editor or markdown editor
- Your `lab12-notes.md` file
- [`Data/ACCT-FS01/ransom-note.txt`](../../../Data/ACCT-FS01/ransom-note.txt) and [`Data/ACCT-FS01/README.md`](../../../Data/ACCT-FS01/README.md) — no other data files are needed for this sub-exercise

---

## Scenario

**Case reference:** IR-2024-ACCTFS01

At 04:38 UTC on 2024-11-12 the overnight service desk took three calls about a finance share that would not open. At 05:02 the on-call administrator logged on to `ACCT-FS01`. Every document in `C:\Shares\` carried a `.vaulted` extension, and every folder held a file named `RECOVER-YOUR-FILES.txt`.

You are engaged at 07:15. When you arrive:

- The host is still powered on. Nobody has captured memory. Nobody has imaged the disk.
- A reimage is scheduled for 14:00 and a replacement server has already been provisioned.
- Shadow copies are gone and the backup team says "the last few backups look odd."
- The finance director wants a return-to-service estimate by 09:00.
- Counsel wants to know, in their words, "yes or no, did they take anything?"
- The cyber insurer has asked which forensics vendor is engaged.

Nothing in that list is a forensic question. All of it constrains the forensics.

---

## Background: Four Clocks, One Set of Hands

| Clock | Set by | Runs at | Pressures you to |
|---|---|---|---|
| Recovery | The business | Hours | Release the host so it can be reimaged and restored |
| Negotiation | The actor | Days, per the note's deadline structure | Deliver partial findings before the price changes |
| Notification | Regulation and contract | 72 h under GDPR; varies elsewhere | Answer the exfiltration question before you are certain |
| Insurance | The policy | Hours to days | Confirm the engaged vendor and notify within the policy window |

These clocks conflict with each other, not just with you. Recovery wants speed. Notification wants certainty. Forensics can only trade one for the other. The highest-value act in the first hour is to name that conflict out loud on the first bridge call, and to get an explicit decision on preservation before recovery begins.

The reframing underneath all of it:

> **The encryption event is the end of the intrusion, not the beginning.**

In this case the encryption ran for 84 minutes. The intrusion ran for six days. The 84 minutes tell you what was encrypted. The six days tell you how they got in, whose credentials are burned, what left the building, and whether restoring will simply hand the environment back.

> **IR Reality Check:** An investigation scoped to the encryption produces an answer fast enough to satisfy the recovery clock and wrong enough to get the organisation encrypted a second time.

---

## Lab Tasks

---

### Task 1 — Build the Four-Clock Table

**Objective:** Turn an abstract pressure into something you can point at on a call.

Complete the table, and be specific. "It costs evidence" is not an answer. "The memory image is gone permanently, so any key material resident in `vault.exe`'s address space is unrecoverable" is.

| Clock | Who sets it | What it pressures you to do | Investigative cost if it wins | Who you negotiate with |
|---|---|---|---|---|
| Recovery | | | | |
| Negotiation | | | | |
| Notification | | | | |
| Insurance | | | | |

Then answer:

**1. Which two clocks conflict most directly, and what is the trade being made between them?**

**2. Which clock is the only one you can meaningfully slow down, and how?**

**3. Which clock has the shortest legal fuse, and what does that mean for the order in which you work the case?**

---

### Task 2 — Write the Preservation Request

**Objective:** Do the work that has to happen at 07:20, before you open any artifact.

The reimage is scheduled for 14:00. Write the message you send to the infrastructure lead and the incident commander, in **no more than 150 words**. It must state:

- What must not happen, and by when
- What must happen first
- How long that will take
- What is lost permanently if it is skipped
- Who is on the hook for the decision if it is overruled

Write it as a message you would actually send, not as an essay. Assume the reader is under pressure and will read the first sentence carefully and the rest quickly.

Then answer:

**1. Why does the memory capture carry more urgency than the disk image, even though the disk image is the larger evidentiary prize?**

**2. Your request will be read as an obstacle to recovery. What one sentence makes it read as risk management instead?**

**3. If the decision goes against you and the host is reimaged at 14:00, what do you write down, and where?**

---

### Task 3 — Rank the Acquisition Order

**Objective:** You have two analysts and a six-hour window. Sequence it.

| Item | Order (1–7) | Why here | What decays if you wait |
|---|---|---|---|
| Memory image of `ACCT-FS01` | | | |
| Disk image of `ACCT-FS01` | | | |
| Domain controller Security logs | | | |
| Jump host (`JUMP-01`) disk and logs | | | |
| Perimeter firewall / VPN logs | | | |
| Backup platform logs and catalog state | | | |
| EDR telemetry export | | | |

Justify positions 1 and 2 in a sentence each, and name the one item on the list whose decay depends on **retention policy** rather than on host state.

Then answer:

**1. Two of these live off-host and are therefore out of the actor's reach. Which, and why does that matter for how late you can afford to collect them?**

**2. Which item would you collect first if you knew the actor was still active in the environment right now?**

---

### Task 4 — The Encryption Is the End

**Objective:** Internalise the reframing that drives everything else in this lab.

The scenario parameters, from [`Data/ACCT-FS01/README.md`](../../../Data/ACCT-FS01/README.md):

| Element | Value |
|---|---|
| Encryption window | 2024-11-12 02:14:06 – 03:38:41 UTC (84 minutes) |
| First failed logon against `svc-backup` | 2024-11-06 21:03:12 UTC |
| Brute force succeeds | 2024-11-06 21:47:22 UTC |
| Dwell time | 6 days |

For each business question below, record whether an investigation scoped to the **84-minute encryption window** could answer it, and if not, where in the six days the answer lives.

| Business question | Answerable from the 84 minutes? | Where the answer actually lives |
|---|---|---|
| What is encrypted and how much of it? | | |
| How did they get in? | | |
| Is that path still open? | | |
| Which credentials must be rotated? | | |
| Where else did they go? | | |
| Did they take data? | | |
| Will restoring reinfect us? | | |

Then answer:

**1. Exactly one row in that table is fully answerable from the encryption window. Which, and why is it also the least valuable to the business?**

**2. A colleague proposes reporting "the incident occurred at 02:14 on 2024-11-12." Rewrite that sentence so it is defensible.**

**3. Ratio check: 84 minutes of encryption on top of six days of dwell. Express that as a percentage of the intrusion, and say what the percentage argues about where analyst hours should go.**

---

### Task 5 — Map the Extortion Layers

**Objective:** Work out which extortion model you are facing, and what each layer obliges you to investigate.

| Layer | Mechanism | Forensic question it creates | Evidence in this case that the layer is in play |
|---|---|---|---|
| Single extortion | | | |
| Double extortion | | | |
| Triple extortion | | | |
| Fourth-layer pressure | | | |

Use `ransom-note.txt` for the last column. The note's TIMELINE section is explicit about what happens at each stage.

Then answer:

**1. Which layer makes exfiltration analysis non-optional, and which regulatory clock does it start?**

**2. A responder confirms the encryption scope and does not investigate exfiltration. Which half of the case have they answered, and which half will be quoted back at the organisation in a regulatory filing?**

**3. Triple extortion targets the victim's customers and partners. What does that change about who needs to be in the room when your findings are briefed?**

---

### Task 6 — Read the Ransom Note for Evidence, Not for Threats

**Objective:** Extract everything of investigative or downstream value from an artifact designed to manipulate you.

Open [`Data/ACCT-FS01/ransom-note.txt`](../../../Data/ACCT-FS01/ransom-note.txt) and complete the table.

| Item from the note | Value | Who needs it | Why they need it |
|---|---|---|---|
| Family / strain indicator | | | |
| Encrypted-file extension | | | |
| Note filename | | | |
| Victim identifier | | | |
| Contact channel | | | |
| Claimed exfiltration volume | | | |
| Claimed data categories | | | |
| Deadline structure | | | |
| Claims about shadow copies and backups | | | |

The note is 62 lines. Three of the items above are what you send to threat intelligence and to [No More Ransom](https://www.nomoreransom.org/) inside the first hour to find out whether a free decryptor exists. Mark which three.

Then answer:

**1. The note claims 34 GB of data was copied. What evidentiary weight does that number carry today, and what would have to be true for you to cite it in a report?**

**2. The note claims shadow copies were removed and the backup catalog deleted. How is that claim different in kind from the exfiltration claim, and how would you test each?**

**3. Why is one copy of the note preserved as evidence rather than deleted with the rest of the encrypted set?**

**4. The note instructs the victim not to involve recovery companies. What does that instruction tell you about the actor's model, and does it change anything you do?**

---

### Task 7 — "Just Restore From Backup"

**Objective:** Take apart the sentence that gets said on every ransomware bridge call.

Restoring from backup solves the availability problem. For each of the four problems it does *not* solve, record the consequence and the evidence you would need to address it.

| Problem restoring does not solve | Consequence if ignored | What forensics must supply |
|---|---|---|
| The actor's access is not removed | | |
| The backup may contain the actor's persistence | | |
| The exfiltrated data is still exfiltrated | | |
| Restoring destroys the evidence on the encrypted host | | |

Add a fifth row of your own for the assumption the sentence makes but does not state: that the backups are intact.

Then answer:

**1. Backup viability is described in the chapter as a forensic question as much as an ops question. What is the single forensic input that makes it answerable?**

**2. The backup team says "the last few backups look odd." Turn that into a question you can put to the backup platform owner, phrased so the answer is useful.**

**3. Why can an organisation restore perfectly and still have a notification obligation?**

---

### Task 8 — Establish Your Client and Your Lane

**Objective:** Know who you work for before you write anything down.

| Question | Your answer | How you would confirm it |
|---|---|---|
| Who is the client — the company, counsel, or the carrier? | | |
| Who receives the report first? | | |
| Is the work privileged, and who decides? | | |
| Who is authorised to approve the preservation request? | | |
| Who decides whether to pay? | | |

Then answer:

**1. Name one thing that changes about your reporting depending on whether counsel or the company is the client.**

**2. Someone asks on the 09:00 call whether you think they should pay. Write your answer in no more than two sentences.**

**3. Why is that answer a professional position rather than an evasion?**

---

### Task 9 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined language before the artifact work begins.

Classify each statement as *Strongly supported*, *Suggested but needs investigation*, or *Not supported by the scenario alone*.

| Statement | Classification | Why |
|---|---|---|
| Files on `ACCT-FS01` were encrypted on 2024-11-12 | | |
| The intrusion began on 2024-11-12 | | |
| The actor exfiltrated 34 GB of data | | |
| The actor claims to have exfiltrated 34 GB of data | | |
| Shadow copies are unavailable on this host | | |
| The organisation can safely restore from its most recent backup | | |
| Memory should have been captured before the responder arrived | | |
| The encryption is the last stage of a longer intrusion | | |
| The account used by the encryptor is compromised | | |

Then write four statements of your own about this scenario and classify them the same way.

> **Guidance:** This sub-exercise is about framing the case correctly and preserving the ability to answer it. Resist the urge to conclude anything about the intrusion yet. The evidence arrives in 12.2 through 12.5.

---

### Task 10 — Write the First-Hour Note

**Objective:** Produce the working note that should exist before deeper forensic work begins.

Use this template:

```
Case Reference:
Author:
Date/Time (UTC):

What Is Known:
What Is Claimed by the Actor:
Preservation Actions Requested:
Preservation Actions Completed:
Acquisition Order and Rationale:
Client and Reporting Chain:
Clocks in Play and Their Deadlines:
Questions the Business Has Asked:
What I Will Not Answer Yet, and Why:
```

Keep it to a single page. Another responder should be able to take over the case from it.

---

### Task 11 — Reflection

Answer the following in 3–5 sentences each.

**1. Why the first hour is disproportionate**
Why do decisions made before any analysis begins have more effect on the outcome of a ransomware case than the analysis itself?

**2. Scoping to the wrong window**
Why is an investigation scoped to the encryption event worse than no investigation at all in some circumstances?

**3. Claims versus evidence**
Ransomware crews routinely claim to have stolen data they did not take. Why is repeating the actor's number in a report a professional failure rather than a shortcut?

**4. Neutrality under pressure**
Why does declining to recommend for or against payment protect the credibility of everything else you write?

---

## Deliverables Checklist

Your `lab12-notes.md` should contain:

- [ ] **Task 1** — Four-clock table with costs and counterparties
- [ ] **Task 2** — Preservation request, 150 words or fewer
- [ ] **Task 3** — Acquisition ranking with decay reasoning
- [ ] **Task 4** — Business-question table plus the rewritten "incident occurred at" sentence
- [ ] **Task 5** — Extortion-layer table with in-case evidence
- [ ] **Task 6** — Ransom-note extraction table with the three threat-intelligence items marked
- [ ] **Task 7** — "Just restore" table with a fifth row of your own
- [ ] **Task 8** — Client determination and the two-sentence payment answer
- [ ] **Task 9** — Strong-support vs overclaim classification, plus four statements of your own
- [ ] **Task 10** — First-hour note
- [ ] **Task 11** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab12/
├── lab12-notes.md  ← Your working notes file (whole lab)
└── Lab12_01/
    └── ReadMe.md       ← This file
```

Backing data for this sub-exercise: [`Data/ACCT-FS01/ransom-note.txt`](../../../Data/ACCT-FS01/ransom-note.txt) and [`Data/ACCT-FS01/README.md`](../../../Data/ACCT-FS01/README.md).

---

## Key Takeaways

- **Four clocks, and none of them are yours.** Recovery, negotiation, notification and insurance all run at different speeds and pull in different directions. Naming the conflict out loud is the responder's job.
- **The preservation request is the first substantive act.** Everything downstream in this lab depends on a disk image that only exists because someone asked for it before 14:00.
- **The encryption is the end of the intrusion.** Eighty-four minutes of encryption sat on six days of dwell. Six of the seven questions the business is asking live in the six days.
- **Double extortion makes exfiltration analysis mandatory.** It is the finding with the shortest legal fuse and the one most likely to survive a perfect restore.
- **Restoring solves availability and nothing else.** It does not remove access, does not un-exfiltrate data, may reinstate persistence, and destroys the evidence if you did not image first.
- **The actor's claim is not evidence.** The 34 GB figure is a number in a threat letter until your own artifacts support it.

---

**Next:** Lab 12.2 — The Ransomware Kill Chain in Windows Artifacts

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
