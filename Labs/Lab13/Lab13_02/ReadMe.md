# Lab 13.2 — The Anatomy of a Defensible Finding

**Supporting Section 13.2: The Anatomy of a Defensible Finding**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

The rest of Lab 13 rests on this sub-exercise. Everything else in the chapter is built out of findings: the report structures, the containment records, the eradication plan, and the logging gaps. If the findings are weak, nothing downstream can compensate.

A finding is defensible when a hostile, competent reviewer who has your evidence but not your goodwill reaches the same conclusion. Failing that, the reviewer can see exactly where they would have to disagree with you, and why.

Most weak findings are weak in one of three ways. They state an inference as an observation. They use confidence words with no defined meaning. Or they omit what the evidence does *not* establish, leaving the reader to assume it establishes everything.

You will work all three failure modes here, against real evidence with real numbers. You will also hit the trap the WKSTN-221 case is built around: a byte count that points the opposite way from what the draft report assumes. That trap is not a gimmick. Reading a total instead of a direction is the most common form of confidence inflation in network findings. It is also the error most likely to survive an internal review and reach counsel.

Give this sub-exercise more time than the others. It is the one that transfers.

---

## What This Lab Covers

This lab supports the following concepts from Section 13.2:

| Section | Topic |
|---|---|
| 13.2.1 | Fact, inference, assumption — and why they fail differently |
| 13.2.2 | A confidence scale that means something: Confirmed / Probable / Possible / Undetermined |
| 13.2.3 | The shape of a finding: claim, basis, confidence, what it does not establish |
| 13.2.4 | Good and bad, side by side — the three standard failure patterns |
| 13.2.5 | The adversarial reviewer test |

---

## Learning Objectives

By completing this lab, you will be able to:

- Classify a written statement as fact, inference, or assumption, and name what breaks downstream if an assumption fails
- Apply the four-level confidence scale using its stated test rather than your intuition
- Recognize that "independent sources" means sources that could not have inherited the same error
- Record Undetermined as a finding with a named missing source, rather than omitting it
- Write a finding in the four-part form and populate the fourth part honestly
- Strip banned confidence language and impression adjectives from forensic prose
- Read byte counts for direction, not magnitude, and refuse to cite an analyst annotation as evidence
- Run the adversarial reviewer test on a report and produce a specific defect list

---

## Estimated Time

75–105 minutes

---

## Prerequisites

- Chapter 13 §13.2 read in full. This lab assumes the §13.2.2 confidence table is in front of you
- Lab 13.1 completed, or equivalent familiarity with the WKSTN-221 case file
- A text editor or markdown editor
- Your `lab13-notes.md` file, in the parent `Lab13/` folder
- `report-templates.md` from the parent folder — §2b is the finding skeleton you will use in Task 5

---

## Scenario

You are the analyst on **IR-2024-11-014**. The draft report is due to the IR manager tonight and to counsel tomorrow.

A colleague, tired and two and a half hours into the case, wrote the paragraph below at 16:50 and dropped it into the draft. Your job in this sub-exercise is to take the same evidence they had and produce findings that survive a reviewer who wants them to be wrong.

### The evidence

All values verified against `Data/WKSTN-221/`. Byte counts, run counts, and timestamps are exact.

| Time (UTC) | Event | Source file |
|---|---|---|
| 04:00:00–04:00:42 | Four failed network logons (EID 4625, type 3) from `185.193.126.47` for `admin`, `administrator`, `root`, `svc-admin` | `security-evtx.csv` |
| 13:55:00 | System time changed: previous `13:54:58`, new `13:55:00` (Kernel-General EID 1, +2 s) | `system-evtx.csv` |
| 14:18:55 | LNK file created for `Q4_Payroll_Review.xlsm` | `lnk-files.csv` |
| 14:19:38 | EID 4688: `powershell.exe` created, parent `OUTLOOK.EXE`, `-EncodedCommand` | `security-evtx.csv` |
| 14:19:42 | TCP/443 to `91.214.47.22`, process `powershell.exe` — **1,847 sent / 184,221 received** | `network-flow.csv` |
| 14:20:11 | `update.exe` present in `…\AppData\Local\Temp\`, **174,080 bytes** | `mft.csv`, `amcache.csv` |
| 14:21:03 | `update.exe` executes. Prefetch `UPDATE.EXE-89A4B22C.pf`, **RunCount 1** | `prefetch.csv` |
| 14:21:55 | TCP/443 to `91.214.47.22`, process `update.exe` — **184,221 sent / 2,415,891 received** | `network-flow.csv` |
| 14:22:58 | Scheduled task `\Microsoft\Windows\WindowsUpdate\WindowsUpdateSync`, author `FINANCE\payroll-admin`, `LastTaskResult 0x41303` — **never executed** | `scheduled-tasks.csv` |
| 14:23:02 | WMI subscription in `root\subscription`: filter `WindowsUpdateFilter`, consumer `WindowsUpdateConsumer`, **binding present** | `wmi-persistence.csv` |
| 14:23:44 | `update.exe` deleted from `Temp\` | `usn-journal.csv` |
| 14:30:00 | SRUM records `update.exe`: **184,221 sent / 2,415,891 received** | `srum.csv` |
| 14:31:05–14:33:14 | Inbound SMB from `10.0.4.17` — **11,421 sent to the host / 4,218,421 received from it** | `network-flow.csv` |
| 14:33:18 | EID 4648, `TargetServerName=FILESVR-03`, `ProcessName=…\cmd.exe` | `security-evtx.csv` |
| 14:33:42–14:35:00 | Outbound SMB to `10.0.4.18` — 184,221 sent, 8,421 received | `network-flow.csv` |

These standing facts also apply. No memory capture exists. The binary was deleted, and no sample was recovered. FILESVR-03 has not been collected, and `10.0.4.17` is not in the CMDB. Enumeration of Run keys and Services found nothing attacker-authored. The Security log on this host wraps in roughly 36 hours.

### The draft paragraph

> **Draft Finding 4.** *The attacker appears to have been a sophisticated actor. After gaining access to WKSTN-221 via a phishing email, they quickly established persistence and moved laterally through the finance environment using advanced techniques. They likely exfiltrated a significant amount of sensitive payroll data to their command-and-control server at 91.214.47.22 before we were able to respond. No evidence of further lateral movement was identified. The host has been cleaned and returned to the user.*

---

## Background: Three Ways Findings Go Wrong

| Failure | What it looks like | What it costs |
|---|---|---|
| **Inference dressed as observation** | "The user opened the attachment at 14:18" | You observed an LNK file and an MFT timestamp, not a human at a keyboard. A reviewer who checks will find the gap |
| **Undefined confidence language** | "Likely exfiltrated" | "Likely" means 51% to one reader and 95% to another. The writer usually meant "I believe this but do not want to be pinned down" |
| **Missing boundary** | "Data was transferred to 91.214.47.22" | The reader draws the boundary somewhere more generous than the evidence supports — and their version is the one that reaches the press release |

> **IR Reality Check:** Findings that survive the adversarial reviewer test are usually shorter and more heavily caveated than the first draft. That is the correct direction.

---

## Lab Tasks

---

### Task 1 — Sort Fact, Inference, and Assumption

**Objective:** Separate the three categories structurally, because they fail differently when wrong (§13.2.1).

Label each statement **F** (fact — directly supported by a named artifact, reproducible by another analyst), **I** (inference — a conclusion drawn by reasoning), or **A** (assumption — treated as true without direct evidence because the investigation must proceed).

For each **I**, name the fact underneath it. For each **A**, name what moves downstream if it fails.

| # | Statement | F / I / A | Underlying fact, or what breaks if it fails |
|---|---|---|---|
| 1 | Prefetch `UPDATE.EXE-89A4B22C.pf` records a run count of 1 and a last-run time of 14:21:03 UTC. | | |
| 2 | `update.exe` executed once on WKSTN-221 at 14:21:03 UTC. | | |
| 3 | An LNK file referencing `Q4_Payroll_Review.xlsm` was created at 14:18:55 UTC. | | |
| 4 | The `payroll-admin` user opened `Q4_Payroll_Review.xlsm` at 14:18:55 UTC. | | |
| 5 | The WKSTN-221 system clock was accurate to within a few seconds of true UTC across the incident window. | | |
| 6 | A WMI consumer named `WindowsUpdateConsumer` exists in `root\subscription` with a filter and a binding, created 14:23:02 UTC. | | |
| 7 | The attacker created the WMI event subscription. | | |
| 8 | 4,218,421 bytes were read off WKSTN-221 by `10.0.4.17` over SMB between 14:31:05 and 14:33:14. | | |
| 9 | `10.0.4.17` is controlled by the attacker. | | |
| 10 | The data read by `10.0.4.17` consisted of finance documents. | | |

Then answer:

**1. Statement 5 is the assumption the entire timeline rests on. One event in the evidence table bears on it directly. Find it, and state whether it strengthens or weakens the assumption — and by how much.**

**2. Take statement 9 and describe concretely what has to be re-argued in the report if it turns out to be wrong. Name the other findings that move.**

**3. Which of statements 1–10 would you not put in a report at all, in any form? Why?**

---

### Task 2 — Make the Confidence Scale Do Work

**Objective:** Use the §13.2.2 tests rather than your intuition.

For each claim below, assign one of **Confirmed / Probable / Possible / Undetermined**, and then apply the scale's own test in writing. The test is the point of the exercise. An assignment without the test is a guess with a label on it.

| # | Claim | Level | The test, applied |
|---|---|---|---|
| 1 | `update.exe` executed on WKSTN-221 at 14:21:03 UTC | | Could I defend this in a deposition with only the appendix? |
| 2 | Live persistence existed on WKSTN-221 as of 14:23:02 UTC | | |
| 3 | 2,415,891 bytes were received by WKSTN-221 from `91.214.47.22` in the 14:21:55 session | | |
| 4 | The 184,221 bytes sent to `91.214.47.22` in that session included data taken from the host | | |
| 5 | `payroll-admin` credentials were harvested from memory on WKSTN-221 | | |
| 6 | Files were read from the `Finance$` share on FILESVR-03 | | |
| 7 | The intrusion began with the 14:18:55 attachment and not earlier | | |
| 8 | The `update.exe` hash exists on no other host in the estate | | |

Then answer:

**1. Rule 1 of §13.2.2 says "independent" means the sources could not have inherited the same error. Claim 3 has two sources — the flow record and SRUM. Are they independent? Argue it properly rather than asserting it.**

**2. Two of the eight claims are Undetermined for different reasons: one source was never generated, one was never collected. Which are they, and does the distinction change what you write in the report?**

**3. Claim 7 is about a negative — that nothing happened before 14:18:55. What is the largest single obstacle to raising its confidence, and is that obstacle a forensic problem or a logging problem?**

---

### Task 3 — Direction, Not Totals

**Objective:** Read the byte counts the way a reviewer will.

This is the trap the case is built around. Work it slowly.

**Part A.** Complete the table for every network flow in the evidence table. State, for each, which way the *large* number points.

| Time (UTC) | Peer | Process | Bytes out of WKSTN-221 | Bytes into WKSTN-221 | The large number points… | What that shape is consistent with |
|---|---|---|---|---|---|---|
| 14:19:42 | `91.214.47.22` | `powershell.exe` | | | | |
| 14:21:55 | `91.214.47.22` | `update.exe` | | | | |
| 14:31:05 | `10.0.4.17` | `System` (SMB) | | | | |
| 14:33:42 | `10.0.4.18` | `System` (SMB) | | | | |

**Part B.** The `Notes` column in `network-flow.csv` reads **"Large outbound transfer — possible exfil"** against the 14:21:55 flow. Whoever first triaged the alert wrote it.

- Compare that annotation against the byte counts you just tabulated.
- Write one sentence for your case notes on how to treat parser output containing a human's opinion column in a finding's Basis.

**Part C.** Write a single sentence, suitable for a report, stating what the 14:21:55 session establishes about data movement. It must survive a reviewer opening the flow record.

Then answer:

**1. Which flow in the case carries the largest volume of data *away from* WKSTN-221, and where does it go?**

**2. The draft paragraph asserts exfiltration to `91.214.47.22`. Is that claim unsupported, or is it contradicted? State the difference and say which applies.**

**3. An analyst who reads only totals would rank the 14:21:55 flow as the most significant event in the case. Which flow actually deserves that ranking, and what does the misranking do to the containment decision downstream?**

---

### Task 4 — Strip the Banned Language

**Objective:** Remove undefined hedges and impression adjectives, and notice what is left.

§13.2.2 strikes these words from findings entirely: *likely, probably, seems, appears, may have, could have, believed to be, presumably, obviously, clearly, sophisticated, advanced, highly targeted.*

**Part A.** Find every instance in the draft paragraph. For each, state whether removing it leaves a checkable statement, or whether removing it reveals that there was no statement underneath.

| # | Banned word | The clause it appears in | What is left when it is removed |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |

**Part B.** Rewrite these three sentences with the hedges replaced by a defined confidence level — or state that you cannot, because the underlying evidence supports no level.

1. *"The attacker probably escalated to SYSTEM on WKSTN-221."*
2. *"It appears the scheduled task was intended to re-establish access."*
3. *"Sensitive payroll data may have been accessed."*

Then answer:

**1. The chapter says the last three banned terms are different in kind from the first ten. What is the difference, and where do those three words tend to end up?**

**2. Sentence 3 in Part B names a data category. Chapter §13.3.4 and §13.1.1 both warn about this. What does that phrase trigger if the document reaches counsel?**

**3. One of your Part B rewrites should have been "I cannot write this at any confidence level." Which one, and what would you write in the report instead of nothing?**

---

### Task 5 — Write Findings in the Four-Part Form

**Objective:** Produce report-ready findings in the §13.2.3 structure.

Use the skeleton from `report-templates.md` §2b. Do not skip the fourth part. It is the one analysts drop, and the one that protects you.

```markdown
**Finding N — [Title: host, account, action, object].**
**Basis:** [Artifacts, with enough identifying detail — file name, event ID, exact
timestamp, exact byte count, run count, hash — that another analyst can retrieve
them. Name the source file. If relying on two sources, say why they are independent.]
**Confidence:** [Confirmed / Probable / Possible / Undetermined] — [one clause of
reason if the level is not self-evident]
**What this does not establish:** [The boundary of the claim.]
```

Write four findings:

| # | Subject |
|---|---|
| **Finding 1** | Initial access and the execution chain |
| **Finding 2** | Persistence established on WKSTN-221 |
| **Finding 3** | Data movement between WKSTN-221 and `91.214.47.22` |
| **Finding 4** | Access to FILESVR-03 |

Constraints, all enforceable by a reviewer:

- Every artifact you cite must actually exist in the evidence table. If you want to cite something that is not there, that is a gap, and it belongs in "what this does not establish."
- No banned word may appear.
- Finding 2 covers two persistence mechanisms with materially different status — one live with a binding present, one that never executed. Decide whether that is one finding or two, and defend the choice under Rule 2 of §13.2.2.
- Finding 4 is the hardest. Read carefully what evidence *on WKSTN-221* can and cannot say about what happened *on FILESVR-03*.

Then answer:

**1. For Finding 2, did you split or combine? What was the deciding argument?**

**2. In Finding 4, name the single artifact from a host you have not collected that would move your confidence up one level. Name the host, the artifact, and the specific field.**

**3. Read your four "what this does not establish" clauses back to back. Which one was hardest to write, and why is that the one a reviewer will read first?**

---

### Task 6 — Undetermined Is a Finding

**Objective:** Write the rows most analysts leave blank (§13.2.2, rule 3).

An Undetermined finding names the missing source. It does not say "no evidence was found."

**Part A.** Write three Undetermined findings for this case in the four-part form. Each must name the specific source that would have answered the question and the reason it was unavailable.

Candidate subjects — pick three:

- Whether credential material was harvested from memory on WKSTN-221
- Whether files were read from `Finance$` on FILESVR-03
- What the 184,221 bytes sent to `91.214.47.22` at 14:21:55 contained
- Whether the intrusion extended to hosts beyond WKSTN-221, FILESVR-03, and `10.0.4.17`
- What `update.exe` actually did, functionally

**Part B.** For each, classify the reason the source is missing:

| Finding | Cleared | Never retained | Never generated | Not yet collected |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

Then answer:

**1. Of the four reasons in Part B, which is the most uncomfortable to write down about your own engagement? Why is it still the one you must write down?**

**2. Rewrite this unqualified negative so a hostile reviewer cannot read it as "the attacker installed no other persistence": "Run keys and Services were enumerated and no attacker-authored entries were found."**

**3. Chapter §13.2.4 says Example 3, the unqualified negative, marks "the difference between a report that closes an incident and one that an auditor reopens four months later." Reconstruct that scenario for this case in three sentences.**

---

### Task 7 — Run the Adversarial Reviewer Test

**Objective:** Read the draft in the character of someone who wants it to be wrong (§13.2.5).

**Part A.** Work the draft paragraph sentence by sentence.

| # | Sentence | The word or omission that fails | What the evidence actually supports | Verdict |
|---|---|---|---|---|
| 1 | "The attacker appears to have been a sophisticated actor." | | | |
| 2 | "After gaining access to WKSTN-221 via a phishing email…" | | | |
| 3 | "…they quickly established persistence and moved laterally through the finance environment using advanced techniques." | | | |
| 4 | "They likely exfiltrated a significant amount of sensitive payroll data to their command-and-control server at 91.214.47.22…" | | | |
| 5 | "…before we were able to respond." | | | |
| 6 | "No evidence of further lateral movement was identified." | | | |
| 7 | "The host has been cleaned and returned to the user." | | | |

**Part B.** Apply the five §13.2.5 questions to the paragraph as a whole:

- Which word in this sentence is doing work the evidence does not support?
- If this artifact could be produced by benign activity, did I say so and rule it out?
- Does any conclusion rest on a single source that I described as if it were several?
- Is any assumption stated only implicitly?
- Would removing one finding collapse three others? Are those dependencies visible?

**Part C.** Rewrite the paragraph as a properly formed finding set. Expect it to split into three or four numbered findings. Findings that survive this pass are usually shorter and more heavily caveated than the first draft (§13.2.5).

Then answer:

**1. Sentence 7 is a claim about response actions, not about the intrusion. Why is it more dangerous in this report than any of the six forensic sentences above it?**

**2. Of the five questions in Part B, which does the draft fail most severely? Quote the specific hidden dependency or single source.**

**3. You are the reviewer, not the author. The author is a peer who worked the case with you and is exhausted. Write the two-sentence message you would actually send them.**

---

### Task 8 — Reflection

Answer each in 3–5 sentences.

**1. The hostile reader**
Chapter §13.2 defines defensibility in terms of a reviewer who has your evidence but not your goodwill. What changes in your writing when you picture that person rather than your manager?

**2. Why the fourth part gets dropped**
"What this does not establish" is the part of a finding that gets cut. Why is it cut, and what does its absence cost you six months later?

**3. Direction over magnitude**
The 14:21:55 flow is the case's trap. What habit would you adopt to stop yourself falling into the same one on a real engagement?

**4. Confidence as a discipline, not a hedge**
An analyst can use the four-level scale as a way of being precise or as a way of avoiding commitment. What separates the two in practice?

---

## Deliverables Checklist

Your `lab13-notes.md` should contain:

- [ ] **Task 1** — F/I/A classification for all 10 statements, plus three written responses
- [ ] **Task 2** — Confidence level and applied test for all eight claims, plus three written responses
- [ ] **Task 3** — Flow direction table, the annotation judgement, the one-sentence finding, plus three written responses
- [ ] **Task 4** — Banned-word inventory, three rewrites, plus three written responses
- [ ] **Task 5** — Four complete four-part findings, plus three written responses
- [ ] **Task 6** — Three Undetermined findings with missing-source classification, plus three written responses
- [ ] **Task 7** — Sentence-by-sentence review table, the five-question pass, the rewritten finding set, plus three written responses
- [ ] **Task 8** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab13/
├── lab13-notes.md  ← Your working notes file (whole lab)
└── Lab13_02/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **Defensible means survivable by a hostile competent reader.** Not "convincing to a colleague who already agrees with you."
- **Facts, inferences, and assumptions degrade differently.** A wrong fact means you misread an artifact. A wrong assumption moves every conclusion downstream of it.
- **The confidence scale only works if you apply its test.** Assigning a level without applying the test is a guess wearing a label.
- **Independent means the sources could not have inherited the same error.** Two exports of the same event log are one source.
- **Undetermined is a finding, not a blank.** Name the missing source and why it was unavailable. Omitting the row implies you did not look.
- **Read direction, not totals.** The single most consequential error available in this case is reading a byte count without reading which way it went.
- **Annotation columns are not evidence.** Citing a `Notes` field is citing someone's earlier hypothesis as though it were data.
- **The fourth part protects you.** Every finding has a boundary. If you do not draw it, the reader will draw it somewhere more generous than the evidence supports.

---

**Next:** Lab 13.3 — Report Structures That Work

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
