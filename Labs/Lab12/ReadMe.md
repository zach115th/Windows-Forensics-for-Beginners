# Lab 12 — Ransomware Incident Response

**Supporting [Chapter 12: Ransomware Incident Response](../../Book/Chapter12.md)**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

This lab drops you into a ransomware case on the morning it is discovered. At 04:40 your phone rings. The overnight team has found `RECOVER-YOUR-FILES.txt` on the accounting file server, and nobody can open a spreadsheet. By 06:00 there is a bridge call. By 07:00 someone from finance is asking when the server comes back, and counsel is asking whether data left the building. The infrastructure lead has already scheduled a reimage for this afternoon.

Lab 11 was a correlation case worked at your own pace. This one is a correlation case worked against four clocks that disagree with each other: recovery, negotiation, notification, and insurance. The recovery team's fastest path destroys your evidence, and the notification clock will not wait for certainty. The forensics is not harder than Chapters 4 through 10. The assembly order is different, the pressure is real, and the actor has worked to remove the things you would normally look at first.

The host is `ACCT-FS01`. The encryption ran for 84 minutes on 2024-11-12. The intrusion started six days earlier, and almost everything that matters happened in those six days. Your job across 13 tasks is to:

- Scope the blast radius — which files, how many, how much data, which directories, and when
- Establish the encryption window from the USN Journal rather than from the ransom note's timestamp
- Prove whether the encryption ran locally or over SMB from somewhere else
- Reconstruct the defense-evasion sequence *despite* the Security log having been cleared five minutes before encryption
- Chain backwards through the jump host to patient zero and defend a dwell window
- Answer the exfiltration question in the tiered confidence language the chapter defines — without overclaiming and without being useless
- Deliver the four assessments the recovery decision actually needs

You will not be asked whether to pay. That is not your decision, and a responder who treats it as one has stepped outside their role.

---

## What This Lab Covers

This lab supports the following sections from Chapter 12:

| Section | Topic | Lab tasks |
|---|---|---|
| 12.1 | What Makes Ransomware Different | 1, 2 |
| 12.2 | The Ransomware Kill Chain in Windows Artifacts | 3, 8 |
| 12.3 | Scoping the Encryption | 4, 5, 6 |
| 12.4 | Finding Patient Zero and the Dwell Window | 7, 9 |
| 12.5 | Did They Steal Data Before Encrypting? | 10, 11 |
| 12.6 | Supporting the Recovery Decision | 12, 13 |

---

## Learning Objectives

By completing this lab, you will be able to:

- Name the four clocks in a ransomware incident and state the preservation decision each one pressures
- Scope an encryption event by file count, by data volume, and by directory, and explain why the three rank differently
- Bin USN Journal records into one-minute buckets and read the encryption window off the resulting curve
- Use ransom-note placement and `$SI` Born timestamps to reconstruct an encryptor's directory traversal order
- Distinguish encryption performed locally from encryption performed remotely over SMB, using evidence rather than assumption
- Assemble a defense-evasion timeline from operational channels, Prefetch, and NTFS when the Security log has been cleared
- Chain backwards from an encryptor, through an account, across host boundaries, to an entry point confirmed by independent evidence
- Report a dwell window with its log-retention boundary stated explicitly
- Apply the five-tier exfiltration confidence language, and distinguish "no evidence found" from "cannot be determined"
- Produce the scope-confidence, actor-presence, backup-trustworthiness and reinfection-risk assessments that a recovery decision requires

---

## Estimated Time and Difficulty

**Difficulty:** Advanced

**First time through the material:** 6–9 h

**Refresh (already familiar with the chapter):** 2–3 h

> **Key terms used in this lab:** blast radius, dwell time, encryption window, patient zero, pre-encryption exfiltration, double extortion, USN mass-modification pattern, shadow copy deletion, staging directory, reinfection risk. See the consolidated [Glossary](../../Book/Glossary.md) for definitions. The chapter cross-references in each entry take you back to the deeper coverage in `Book/`.

---

## Prerequisites

- Completion of Labs 01–11, or equivalent familiarity with NTFS, Registry, execution, event-log, network and timeline artifacts
- Your `lab12-notes.md` file
- A spreadsheet, `python3`, or PowerShell for binning and aggregating a few thousand rows
- Optional tools, if you want to work from raw artifacts rather than parsed output:
  - MFTECmd (for `$MFT` and `$UsnJrnl:$J`)
  - EvtxECmd or an equivalent event-log parser
  - PECmd / AmcacheParser / AppCompatCacheParser
  - RECmd or Registry Explorer
  - `srum-dump`
  - Timeline Explorer, or any tool that will sort and pivot a CSV

> **Working without a VM:** The complete ACCT-FS01 ransomware dataset is in [`Data/ACCT-FS01/`](../../Data/ACCT-FS01/). Its 19 data files cover NTFS (`mft.csv`, `usn-journal.csv`), the extension-sweep worksheet (`encrypted-files-inventory.csv`), five event-log channels on this host plus the domain controller's and the jump host's Security logs, and execution evidence (Prefetch, Amcache, ShimCache). They also cover persistence (`registry-runkeys.csv`), egress (`network-flow.csv`, `srum.csv`), and three plaintext artifacts: the ransom note, the recovered `rclone.conf`, and live-triage `vssadmin` output. Read [`Data/ACCT-FS01/README.md`](../../Data/ACCT-FS01/README.md) first. It documents what is deliberately missing as well as what is present. You do not need a VM, a sample of real ransomware, or an isolated network to complete this lab, and you should not go looking for any of those.

> **Prerequisite skills from earlier labs:** Ransomware does not require new forensics — only a different assembly order. Expect to draw on:
>
> | Skill | Lab |
> |---|---|
> | Preservation decisions, evidence hashing, chain of custody | [Lab 01](../Lab01/ReadMe.md), [Lab 03](../Lab03/ReadMe.md) |
> | MFT reading, USN Journal reasons, deleted-file recovery | [Lab 04](../Lab04/ReadMe.md) |
> | Registry persistence: services, Run keys, policy values | [Lab 05](../Lab05/ReadMe.md) |
> | Prefetch, Amcache, ShimCache — execution vs. presence | [Lab 06](../Lab06/ReadMe.md) |
> | Memory capture reasoning (why it should have been taken here) | [Lab 07](../Lab07/ReadMe.md) |
> | Flow analysis, egress volume, destination reputation | [Lab 08](../Lab08/ReadMe.md) |
> | Event-log hunt pack: 4624/4625/4648/4688/1102/7045 | [Lab 09](../Lab09/ReadMe.md) |
> | Multi-source timeline construction and pivot events | [Lab 10](../Lab10/ReadMe.md) |
> | Tiered confidence language and defensible case summaries | [Lab 11](../Lab11/ReadMe.md) |
>
> If a step feels unfamiliar, revisit the source lab and come back. This lab does not re-teach the artifacts. It asks you to pick the right one for each question the case forces on you.

---

## Scenario

**Case reference:** IR-2024-ACCTFS01

At 04:38 UTC on 2024-11-12, the overnight service desk at a mid-sized professional-services firm took three calls about a finance share that would not open. At 05:02 the on-call systems administrator logged on to `ACCT-FS01`. Every document in `C:\Shares\` had been renamed with a `.vaulted` extension, and every folder held a file called `RECOVER-YOUR-FILES.txt`. The note demands contact within 72 hours, claims that data was copied before encryption, and gives an identifier of `VLT-8837-ACCT`.

`ACCT-FS01` is a Windows Server 2019 accounting file server at `10.0.6.15` in the `FINANCE` domain. It hosts the accounting, finance, HR and legal shares, plus a directory of nightly SQL backups.

You are engaged at 07:15. The following is true when you arrive:

- The host is still powered on. Nobody has captured memory. Nobody has imaged the disk.
- The infrastructure lead has a reimage scheduled for 14:00 and has already provisioned a replacement.
- The backup team reports that shadow copies are gone and that "the last few backups look odd."
- The finance director wants a return-to-service estimate by 09:00.
- Counsel has been engaged and wants to know, in their words, "yes or no, did they take anything?"
- The cyber insurer has been notified and has asked which forensics vendor is engaged.

Your first substantive act on this case is a preservation request, and Task 1 is where you write it.

The artifact collection in [`Data/ACCT-FS01/`](../../Data/ACCT-FS01/) is what the triage collection produced once the preservation argument was won. A disk image was taken at 08:40 and parsed. The outputs were handed to you together with the domain controller's and the jump host's Security logs. Memory was never captured. That is a real gap, and part of your job is to say so.

The questions the business is asking:

- What is encrypted, how much of it, and which parts matter most?
- When did the encryption run, and how long did it take?
- How did they get in, when, and is that path still open?
- Which accounts are compromised, and how widely do we have to rotate?
- Did they take data before encrypting, and can you prove it?
- Is there a backup we can trust, and will restoring get us encrypted again?

---

## Background: Why the Ordinary Approach Fails Here

Three things make a ransomware case behave differently from every other case in this book.

**The encryption is the end of the intrusion, not the beginning.** By the time `.vaulted` files appear, the actor has been inside for days. Scoping the investigation to the encryption produces a fast, confident, and wrong answer. The dwell window is where the useful findings live.

**The actor has already attacked your evidence.** The actor disabled Defender, deleted the shadow copies, and cleared the Security log five minutes before the encryption began. Each of those is a *finding* rather than a dead end, but only if you know where the same fact still lives.

| The actor destroyed | The same fact still lives in |
|---|---|
| Local authentication history | Domain controller Security log, TerminalServices operational channel |
| The 4688 for `vssadmin` | `volsnap` EID 25, `VSSADMIN.EXE` Prefetch, PowerShell 4104 |
| The 4688 for the Defender disable | Defender 5001/5007, the Defender policy registry values, PowerShell 4104 |
| The staging directory contents | USN Journal records for creation *and* deletion; MFT entries marked `InUse=False` |
| The transfer tool and its config | Prefetch, Amcache SHA-1, ShimCache, and a `rclone.conf` recoverable from unallocated space |
| Nothing at all about file activity | MFT and USN Journal — log clearing does not touch NTFS |

**The deliverable is a decision input, not a report.** The recovery decision needs four assessments: scope confidence, actor presence, backup trustworthiness, and reinfection risk. Each carries an explicit confidence level and an explicit list of what would raise it. An organisation that restores without those gets encrypted a second time, often within days, using access the actor never lost.

> **IR Reality Check:** The most expensive mistake on a ransomware case is not a wrong artifact interpretation. It is reporting a dwell window bounded by the oldest surviving log without saying so, and letting the client restore from a backup that sits inside it.

---

## Lab Tasks

---

### Task 1 — Manage the Clocks and Write the Preservation Request

**Objective:** Do the first-hour work that has to happen before you open any artifact.

**Part A — Name the clocks.** Chapter 12 §12.1.1 identifies four. For each, record who sets it, what it is pressuring you to do, and what it costs the investigation if it wins.

| Clock | Who sets it | What it pressures you to do | Investigative cost if it wins |
|---|---|---|---|
| Recovery | | | |
| Negotiation | | | |
| Notification | | | |
| Insurance | | | |

**Part B — Write the preservation request.** The reimage is scheduled for 14:00. Write the message you send at 07:20, in no more than 150 words, to the infrastructure lead and the incident commander. It must state what must not happen, what must happen first, how long it will take, and what is lost if it is skipped.

**Part C — Rank the acquisition order.** You have limited hands. Put these in the order you would collect them and justify positions 1 and 2 in a sentence each.

| Item | Order (1–7) | Why here |
|---|---|---|
| Memory image of `ACCT-FS01` | | |
| Disk image of `ACCT-FS01` | | |
| Domain controller Security logs | | |
| Jump host (`JUMP-01`) disk and logs | | |
| Perimeter firewall / VPN logs | | |
| Backup platform logs and catalog state | | |
| EDR telemetry export | | |

**Part D — Establish your client.** Record whether you believe your client is the company, counsel, or the carrier, and how you would confirm it. Then record one thing that changes about your reporting depending on the answer.

Then answer:

**1. Why is the memory capture urgent in a way that the disk image is not?**

**2. The four clocks conflict. Which conflict is the responder's job to name out loud, and to whom?**

**3. What is lost, specifically and permanently, if `ACCT-FS01` is reimaged at 14:00?**

---

### Task 2 — Receive the Case and Inventory the Inputs

**Objective:** Start where real responders start — with whatever the previous shift left behind.

Open [`Data/ACCT-FS01/README.md`](../../Data/ACCT-FS01/README.md) and read the file inventory and the "What you will and won't find" section.

**Part A — Inventory the collection.**

| Question | Answer |
|---|---|
| Which artifact classes are available? | |
| Which files were collected from a host other than `ACCT-FS01`, and why are they here? | |
| What is missing that you would want, and what would each missing item have told you? | |
| How many rows are in `security-evtx.csv`, and what is the timestamp of the first one? | |
| What does that first row tell you about everything you will *not* find in that file? | |

**Part B — Verify integrity.** Hash every file in the folder on receipt and record the results. The evidence here is a directory of parsed output rather than an image, but the discipline is identical.

```powershell
Get-ChildItem 'Data\ACCT-FS01\' -File |
  Get-FileHash -Algorithm SHA256 |
  Select-Object Path, Hash | Format-Table -AutoSize
```

Create a working copy, re-hash it, and confirm every hash matches. The original is write-protected for the rest of the lab.

**Part C — Record what the ransom note gives you.** Open `ransom-note.txt` and extract every item of investigative or downstream value.

| Item from the note | Value | Who needs it |
|---|---|---|
| Family / strain indicator | | |
| Encrypted-file extension | | |
| Victim identifier | | |
| Contact channel | | |
| Claimed exfiltration volume | | |
| Stated deadline structure | | |

Then answer:

**1. The note claims data was copied before encryption. What evidentiary weight does that claim carry, and why?**

**2. Why should one copy of the note be preserved as evidence rather than deleted with the rest of the encrypted set?**

**3. Which two items in your Part C table would you send to threat intelligence within the first hour, and what would you hope to get back?**

---

### Task 3 — Map the Kill Chain to Artifacts

**Objective:** Build the lookup table you will use for the rest of the lab.

For each stage of the intrusion, record which artifact in `Data/ACCT-FS01/` evidences it on this host. Most important, record whether that artifact survived the log clear at 02:09:41.

| Stage | Artifact(s) in this dataset | Survived the log clear? | What it proves |
|---|---|---|---|
| Initial access | | | |
| Persistence | | | |
| Credential access | | | |
| Discovery | | | |
| Lateral movement | | | |
| Collection and staging | | | |
| Exfiltration | | | |
| Defense evasion | | | |
| Encryption | | | |

Add at least eight rows in total.

Then answer:

**1. Which stages have evidence *only* from sources outside `ACCT-FS01`? What does that tell you about collection priorities on the next case?**

**2. Which single artifact class in your table would you least want to lose, and why?**

**3. Chapter 12 §12.2.8 warns that a ransomware binary run once on a server may execute before Prefetch flushes to disk. How does that caveat change how you write the "encryption performed locally" finding?**

---

### Task 4 — Sweep the Encrypted Extension

**Objective:** Produce the blast-radius numbers the recovery team cannot plan without.

Using `encrypted-files-inventory.csv`, or an equivalent filter on `mft.csv`, produce:

| Measure | Value |
|---|---|
| Total encrypted file count | |
| Total encrypted data volume (bytes and GiB) | |
| Number of affected directories | |
| Directory with the highest **file count** | |
| Directory with the highest **data volume** | |
| Earliest `$SI` Modified across the encrypted set | |
| Latest `$SI` Modified across the encrypted set | |

Then produce a per-directory table for at least the top eight directories by count, and separately the top three by volume.

| Directory | File count | Bytes | Share of total count | Share of total volume |
|---|---|---|---|---|
| | | | | |

Then answer:

**1. The count ranking and the volume ranking put different directories at the top. Which ranking does the recovery team need, and which does counsel need?**

**2. `C:\Shares\Finance\Reports\Archive` sits inside an otherwise-encrypted share and has no `.vaulted` files. Give two competing explanations and say what evidence would separate them.**

**3. Why is every number in this task explicitly preliminary until the whole environment is swept, and what does that mean for how you phrase it in a 09:00 executive update?**

---

### Task 5 — Establish the Encryption Window from the USN Journal

**Objective:** Derive the window from the file-system record rather than trusting the ransom note or the file timestamps.

**Part A — Bin the records.** Bucket `usn-journal.csv` into one-minute bins across 2024-11-12 and record:

| Measure | Value |
|---|---|
| First minute bin with encryption-consistent activity | |
| Last minute bin with encryption-consistent activity | |
| Duration | |
| Total USN records inside the window | |
| Peak records in a single minute | |
| Lowest records in a single minute *inside* the window | |
| Typical records per minute in the two hours *before* the window | |

**Part B — Characterise the shape.** Chapter 12 §12.3.2 lists five properties of the encryption signature. For each, record whether this dataset exhibits it and cite the evidence.

| Property | Present? | Evidence |
|---|---|---|
| Sustained high rate | | |
| Uniform reason-code sequence per file | | |
| Rename pairs, new name = old name + extension | | |
| Records grouped by directory in a deterministic walk order | | |
| Interleaved note creation at directory boundaries | | |

**Part C — Explain the trough.** Inside the window, the per-minute count collapses to a small fraction of the plateau and then recovers. Identify the minutes, identify the cause, and explain why an analyst who had not looked at file sizes might misread it as the end of the attack.

Then answer:

**1. Why is the USN Journal a better source for the encryption window than the `$SI` Modified timestamps on the encrypted files themselves?**

**2. What would the per-minute curve look like if the encryption had been performed over SMB from three hosts simultaneously?**

**3. The dataset's per-minute rates are two to three orders of magnitude lower than a real file server's. Which of your conclusions in this task depend on the *rate*, and which depend only on the *shape*?**

---

### Task 6 — Map the Blast Radius from Ransom-Note Placement

**Objective:** Use the note as a directory map and reconstruct the encryptor's traversal.

Filter `mft.csv` for `RECOVER-YOUR-FILES.txt` and build the traversal table.

| Order | Directory | Note `$SI` Born (UTC) | Gap from previous | Files in directory |
|---|---|---|---|---|
| 1 | | | — | |
| 2 | | | | |
| … | | | | |

Include all directories.

Then answer:

**1. What does note placement give you that a per-file extension sweep does not?**

**2. Two consecutive notes are separated by a much larger gap than any other pair. Which pair, and what explains it?**

**3. If a second host in the environment carried the same note filename but a different victim identifier, what would that suggest, and what would you do about it?**

**4. The encryptor visited `C:\Users\svc-backup\Documents` last. What does the presence of that directory in the encrypted set tell you about the account the encryptor ran as?**

---

### Task 7 — Prove Where the Encryption Ran

**Objective:** Answer the question responders most often get wrong on a file server.

Chapter 12 §12.3.4 describes two possibilities: the encryptor ran locally, or it ran on another host and encrypted this server's files over SMB. Each produces a distinct evidence pattern.

| Evidence | Local execution predicts | Remote SMB execution predicts | What this dataset shows |
|---|---|---|---|
| 4688 for the encryptor | | | |
| Prefetch entry for the encryptor | | | |
| Amcache / ShimCache entry | | | |
| Encryptor binary on disk (MFT) | | | |
| Security 5140 / 5145 volume | | | |
| Network flow to port 445 during the window | | | |

Record your conclusion and the confidence level you would attach to it.

Then answer:

**1. Which single piece of evidence in your table is the strongest for your conclusion, and what is its weakness?**

**2. Suppose Prefetch had been disabled on this host, as it is by default on Windows Server. Which evidence would you still have, and would the conclusion survive?**

**3. Responders regularly spend hours hunting for an encryptor binary on a file server that never ran one. What single query would you run first on the next case to avoid that?**

---

### Task 8 — Reconstruct the Defense-Evasion Sequence

**Objective:** Rebuild a chain of events whose primary evidence source was deliberately destroyed.

Build the ordered evasion timeline. For each step, name the artifact that evidences it *and* state whether the Security log 4688 for it survived.

| # | Time (UTC) | Action | Evidencing artifact(s) | 4688 survived? |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |
| 6 | | | | |

Include at least six steps, ending with the first encrypted file.

Then record:

| Measure | Value |
|---|---|
| Interval from the first evasion action to the first encrypted file | |
| Interval from the log clear to the first encrypted file | |
| Account named in the 1102 record | |
| Earliest surviving record in `security-evtx.csv` | |

Then answer:

**1. The 1102 event names an account and a time. What two separate findings does that single record establish?**

**2. Defender quarantined actor tooling on 2024-11-09, days before it was disabled. Chapter 12 calls this "a gift." Why?**

**3. The Defender exclusion for the staging directory was added at 21:52 on 2024-11-11, and real-time protection was not fully disabled until 02:02 the next morning. What does that ordering tell you about the actor's operational discipline?**

**4. Name three evidence sources in this dataset that a log-clearing actor commonly forgets exist, and say what each contributed here.**

---

### Task 9 — Chain Backwards to Patient Zero

**Objective:** Establish a defensible dwell window by backwards chaining, one confirmed link at a time.

**Part A — Anchor on the encryptor.** Record the process, the account, and the binary's arrival time on disk.

| Question | Answer | Source |
|---|---|---|
| What process performed the encryption? | | |
| What account did it run as? | | |
| When did the binary arrive on disk? | | |
| How long between arrival and execution? | | |

**Part B — Follow the account backwards.** Build an account-centric timeline for `FINANCE\svc-backup` from `dc-security-evtx.csv` and `terminalservices-evtx.csv`, spanning 2024-11-01 to 2024-11-12. Include at least 12 rows.

| Time (UTC) | Event ID | Host | Logon type / detail | Normal or anomalous | Why |
|---|---|---|---|---|---|
| | | | | | |

Annotate the exact point at which the account's behaviour diverges from its established pattern, and say what its established pattern was.

**Part C — Cross the host boundary.** Document each hop from `ACCT-FS01` to the entry point. For each, name the source-side and destination-side artifact.

| Hop | From | To | Source-side artifact | Destination-side artifact |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |

**Part D — Confirm the entry point.** Record the brute-force evidence and its independent corroboration.

| Measure | Value | Source |
|---|---|---|
| Failed-logon count | | |
| Burst start / end | | |
| Successful logon time | | |
| Logon type | | |
| Source IP | | |
| Independent corroboration #1 | | |
| Independent corroboration #2 | | |

**Part E — State the dwell window.** Write it as a single sentence that a report can carry verbatim, including the log-retention boundary.

Then answer:

**1. A domain admin account appears in the DC log partway through the dwell window. When, and what does its appearance tell you happened on a host you have not looked at?**

**2. Chapter 12 §12.4.5's field composite describes a team that reported a dwell window bounded by their oldest surviving log. What is the one sentence that would have saved them?**

**3. Why is the domain controller Security log the single highest-priority collection on day one of a ransomware case?**

---

### Task 10 — Investigate Staging and the Transfer Tool

**Objective:** Reconstruct what was collected and how it was moved, from artifacts the actor deleted.

**Part A — The staging directory.** `C:\Windows\Temp\wu\` no longer exists. Reconstruct it.

| Measure | Value | Source |
|---|---|---|
| When was the directory created? | | |
| How many archive volumes? | | |
| Total staged bytes | | |
| Staging start / end | | |
| When was the directory deleted? | | |
| What else was in it besides the archives? | | |

**Part B — What was actually collected.** The archive volumes tell you the *size* of the staged set but not its contents. Find the artifact that names the source directories, and record what it says.

| Source directory in the archive command | Encrypted file count in that tree | Notes |
|---|---|---|
| | | |

**Part C — The transfer tool.** Build the artifact set for `rclone.exe`.

| Artifact | What it shows | Value |
|---|---|---|
| Prefetch | | |
| Amcache | | |
| ShimCache | | |
| MFT | | |
| Recovered configuration | | |
| Command line | | |
| Persistence reference | | |

Then answer:

**1. The staged file names are archive volumes, not document names. What does that cost you when counsel asks which records were affected, and what partially compensates?**

**2. The rclone invocation omits `--log-file`. Chapter 12 §12.5.3 calls the log "listing every transferred file by name." What would its presence have changed about your final confidence tier?**

**3. Why is `rclone.conf` described in the chapter as "the highest-value single artifact in an exfiltration case"?**

---

### Task 11 — Bound the Egress and Write the Exfiltration Finding

**Objective:** Answer the question with the shortest legal fuse, honestly.

**Part A — Volume evidence.**

| Source | Measure | Value |
|---|---|---|
| `network-flow.csv` | Session count to `185.220.101.44` | |
| `network-flow.csv` | Total bytes sent to that destination | |
| `network-flow.csv` | First / last session time | |
| `network-flow.csv` | Prior contact with that destination? | |
| `srum.csv` | `rclone.exe` bytes sent, by bucket | |
| `srum.csv` | `rclone.exe` total bytes sent | |
| Staged set | Total archive bytes | |

**Part B — The sanity check.** Compare the staged volume against the observed egress and state what the comparison supports.

| Comparison | Value | Interpretation |
|---|---|---|
| Egress ÷ staged | | |
| SRUM ÷ staged | | |
| Conclusion about transfer completion | | |

**Part C — Rule out the confounder.** `network-flow.csv` contains a legitimate nightly transfer that is substantially *larger* than the exfiltration. Identify it and explain, in one sentence, why volume alone is not the signal here.

**Part D — Write the finding.** Using the five-tier language from Chapter 12 §12.5.5, write a one-paragraph exfiltration finding. State the tier explicitly, name every supporting evidence source, and name at least two evidence gaps that constrain the conclusion.

| Tier | Applies here? | Why / why not |
|---|---|---|
| Confirmed | | |
| Highly likely | | |
| Possible / cannot be excluded | | |
| No evidence found | | |
| Cannot be determined | | |

Then answer:

**1. What single additional artifact would move this finding from your chosen tier to "Confirmed"?**

**2. Explain to a non-technical executive, in two sentences, the difference between "we found no evidence of exfiltration" and "we could not determine whether exfiltration occurred."**

**3. The leak site publishes a directory listing next week that matches your share structure. How does that change your finding, and how does it not?**

---

### Task 12 — Deliver the Four Recovery Assessments

**Objective:** Produce the inputs the recovery decision needs.

Complete the assessment table. Every row needs a confidence level and an explicit statement of what would raise it.

| Assessment | Your answer | Primary evidence | Confidence | What would raise it |
|---|---|---|---|---|
| Scope confidence | | | | |
| Actor presence | | | | |
| Backup trustworthiness | | | | |
| Reinfection risk | | | | |

**Part A — Persistence inventory.** List every persistence mechanism you can evidence from this dataset, with the artifact and the date it was established.

| Mechanism | Artifact | Established (UTC) | Would survive a restore? |
|---|---|---|---|
| | | | |

Add at least four entries.

**Part B — Backup viability.** The dwell window starts on 2024-11-06. Answer the three separate questions Chapter 12 §12.6.3 distinguishes.

| Question | Answer | Basis |
|---|---|---|
| Do the backups exist? | | |
| Are they clean? | | |
| Are they complete? | | |

**Part C — Remediation prerequisites.** Write the list of conditions that must be true before restoration begins. Include at least six items, each phrased as a verifiable statement.

Then answer:

**1. Which of the four assessments can you give with the highest confidence from this dataset, and which with the lowest?**

**2. A backup taken on 2024-11-10 is offered as the restore point because it loses the least data. What is your response, and what evidence supports it?**

**3. Why is "we checked the backup image for the persistence artifacts we found in production" worth substantially more than "we believe the backup is clean"?**

---

### Task 13 — Write the Incident Summary and Handoff

**Objective:** Turn 13 tasks of findings into two documents someone else can act on.

**Part A — The scoping deliverable.** Complete the table from Chapter 12 §12.3.5. This is what goes out in the first few hours.

| Field | ACCT-FS01 |
|---|---|
| Encryption start (UTC) | |
| Encryption stop (UTC) | |
| Duration | |
| Encrypted file count | |
| Encrypted data volume | |
| Affected directories | |
| Directories excluded | |
| Encryption performed locally? | |
| Shadow copies available? | |

**Part B — The incident summary.** Write 1–3 pages covering: scope of investigation, evidence sources used, the dwell window with its retention boundary, the kill chain in narrative form, the exfiltration finding with its tier, the four recovery assessments, gaps and uncertainties, and recommended next steps. Write for an audience of technical leadership, counsel, and an insurer — each of whom will read it differently.

**Part C — The handoff note.** Use the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Primary Questions:
-

Confirmed Findings:
-

Findings With Stated Confidence Below "Confirmed":
-

Dwell Window (with retention boundary):
-

Exfiltration Finding (tier + basis + gaps):
-

Persistence Not Yet Remediated:
-

Remediation Prerequisites Before Restore:
1.
2.
3.

Open Questions:
-

Preservation Issues to Escalate:
-

Notes for Incoming Analyst:
```

**Part D — The question you will be asked.** Someone on the bridge call asks whether you think they should pay. Write your answer, verbatim, in no more than four sentences.

Then answer:

**1. Which sentence in your incident summary is most likely to be quoted out of context, and how did you phrase it defensively?**

**2. Why does advocating a position on payment cost you the ability to be a neutral source of fact on everything else in the same report?**

**3. What did this case reveal about the organisation's logging and preservation posture that belongs in the recommendations rather than the findings?**

---

## Hands-On Walkthrough (Using Simulated Data)

This walkthrough resolves the case against [`Data/ACCT-FS01/`](../../Data/ACCT-FS01/). Every count below was produced by running the query shown. Run them from the repository root. Each step gives a PowerShell block and an equivalent Python block. Use whichever matches your environment.

The Python blocks assume this preamble once per session:

```python
import csv, collections
def R(name):
    with open(f'Data/ACCT-FS01/{name}', newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))
```

### Step 1 — Read the note and establish the strain

```powershell
Get-Content 'Data\ACCT-FS01\ransom-note.txt' |
  Select-String -Pattern 'VLT-|\.vaulted|GB|portal'
```

```python
with open('Data/ACCT-FS01/ransom-note.txt') as f:
    for ln in f:
        if any(k in ln for k in ('VLT-', '.vaulted', 'GB', 'portal')):
            print(ln.rstrip())
```

Expected: the note identifies the family as Vault, the extension as `.vaulted`, and the victim identifier as `VLT-8837-ACCT`. It also gives a defanged contact portal and a **claimed** exfiltration of 34 GB of accounting, finance, HR and legal data. Three of these — the family, the extension, and the note filename — are what you send to threat intelligence and to [No More Ransom](https://www.nomoreransom.org/) to check whether a free decryptor exists. The 34 GB figure is the actor's claim, not evidence. Step 8 tests it against your own data.

### Step 2 — Sweep the encrypted extension

```powershell
$inv = Import-Csv 'Data\ACCT-FS01\encrypted-files-inventory.csv'
"Files : {0}" -f $inv.Count
"Bytes : {0}" -f ($inv | Measure-Object SizeBytes -Sum).Sum
"Dirs  : {0}" -f ($inv.Directory | Sort-Object -Unique).Count
$inv | Group-Object Directory |
  Sort-Object Count -Descending |
  Select-Object -First 5 Count, Name
```

```python
inv = R('encrypted-files-inventory.csv')
print('Files:', len(inv))
print('Bytes:', sum(int(r['SizeBytes']) for r in inv))
by_dir = collections.Counter(r['Directory'] for r in inv)
print('Dirs :', len(by_dir))
for name, n in by_dir.most_common(5):
    print(f'{n:>4}  {name}')
```

Expected: **418 files**, 78,662,133,156 bytes (73.26 GiB), across 24 directories. The top five by count are `AP\Invoices\2024` (38), `AP\Invoices\2023` (31), `Vendors` (29), `AR\Statements` (27), and `Archive\2022` (26).

Now rank the same set by volume instead:

```powershell
$inv | Group-Object Directory | ForEach-Object {
    [pscustomobject]@{
      Dir   = $_.Name
      Files = $_.Count
      GiB   = [math]::Round((($_.Group | Measure-Object SizeBytes -Sum).Sum / 1GB), 2)
    }
} | Sort-Object GiB -Descending | Select-Object -First 3
```

```python
sizes = collections.Counter()
for r in inv:
    sizes[r['Directory']] += int(r['SizeBytes'])
for name, b in sizes.most_common(3):
    print(f'{b / 1024**3:>8.2f} GiB  ({by_dir[name]:>3} files)  {name}')
```

Expected: `C:\Shares\IT\Backups\SQL` at 67.28 GiB from just 5 files, then `Accounting\Archive\2022` at 2.01 GiB, then `Accounting\Archive\2021` at 1.51 GiB. Five files, **1.2 % of the count, are 91.8 % of the data volume.** The recovery team plans against the volume ranking. Counsel scopes notification against the count and the content. Chapter 12 §12.3.1's warning that "file count is not data volume" is not a nuance here. It inverts the whole priority list.

### Step 3 — Map the blast radius from ransom-note placement

```powershell
Import-Csv 'Data\ACCT-FS01\mft.csv' |
  Where-Object { $_.FileName -eq 'RECOVER-YOUR-FILES.txt' } |
  Sort-Object Created0x10 |
  Select-Object Created0x10, ParentPath
```

```python
notes = [r for r in R('mft.csv') if r['FileName'] == 'RECOVER-YOUR-FILES.txt']
notes.sort(key=lambda r: r['Created0x10'])
for r in notes:
    print(r['Created0x10'][11:19], r['ParentPath'])
```

Expected: **24 notes**, one per encrypted directory, with `$SI` Born timestamps running from 02:21:07 (`Shares\Accounting\AP\Invoices\2024`) to 03:38:41 (`Users\svc-backup\Documents`). Sorted by Born time, they *are* the encryptor's traversal order: the Accounting tree first, then Finance, then HR, then Legal, then the SQL backups, then the service account's profile.

Two features stand out. First, the largest gap between consecutive notes is **03:30:12 → 03:37:20**, seven minutes for a single directory. That directory is `C:\Shares\IT\Backups\SQL`, with its five multi-gigabyte files. Second, the last directory encrypted is the profile of `svc-backup`, the account the encryptor ran as. Families that walk profile directories routinely encrypt their own operator's home path.

### Step 4 — Bin the USN Journal and read the window off the curve

```powershell
$usn = Import-Csv 'Data\ACCT-FS01\usn-journal.csv'
$usn | Where-Object { $_.UpdateTimestamp -like '2024-11-12 0[23]:*' } |
  Group-Object { $_.UpdateTimestamp.Substring(0,16) } |
  Sort-Object Name |
  Select-Object Name, Count
```

```python
usn = R('usn-journal.csv')
bins = collections.Counter(
    r['UpdateTimestamp'][:16] for r in usn
    if r['UpdateTimestamp'].startswith('2024-11-12'))
for minute in sorted(bins):
    print(minute, '#' * bins[minute], bins[minute])

window = [r for r in usn
          if '2024-11-12 02:14' <= r['UpdateTimestamp'][:16] <= '2024-11-12 03:38']
print('records in window:', len(window))
print('peak minute      :', max(bins.items(), key=lambda kv: kv[1]))
```

Expected: **2,162 USN records** between 02:14 and 03:38, in 85 consecutive non-empty minute bins. The plateau runs 20–30 records per minute, with a peak of 30 tied at 02:52, 03:20 and 03:23. The two hours before the window (00:14–02:14) carry 16 records in total, roughly 0.13 per minute. Against that baseline, the curve rises by more than two orders of magnitude in a single minute and drops just as sharply at the end.

The trough inside the window is the SQL-backup directory, not the end of the attack. Bins 03:30 through 03:36 collapse to **2–9 records per minute** and then recover to 21–22 for the final two minutes. The directory's five files of 8–24 GB each take seven minutes to encrypt and generate five USN records apiece. An analyst who read the trough as "the attack stopped at 03:30" would truncate the window by eight minutes and miss the last two directories entirely.

Now confirm the reason-code signature:

```powershell
$window = $usn | Where-Object {
    $_.UpdateTimestamp -ge '2024-11-12 02:14' -and $_.UpdateTimestamp -le '2024-11-12 03:39' }
$window | Group-Object UpdateReasons | Sort-Object Count -Descending |
  Select-Object Count, Name
```

```python
for reasons, n in collections.Counter(r['UpdateReasons'] for r in window).most_common():
    print(f'{n:>5}  {reasons}')
```

Expected: exactly **five reason codes at 418 each**, plus three note-creation codes at 24 each. The five are `DataOverwrite`, `DataOverwrite|DataTruncation`, `DataOverwrite|DataTruncation|RenameOldName`, `DataOverwrite|DataTruncation|RenameNewName`, and `DataOverwrite|DataTruncation|RenameNewName|Close`. Perfect uniformity across 418 files is the mass-modification pattern. Note the rename pairing: 418 `RenameOldName` records and 836 records carrying `RenameNewName`, because the new name persists into the closing record.

### Step 5 — Prove the encryption ran locally

```powershell
Import-Csv 'Data\ACCT-FS01\security-evtx.csv' |
  Where-Object { $_.EventID -eq '4688' -and $_.Payload -like '*vault.exe -enc*' } |
  Select-Object TimeCreated, UserName, Payload

Import-Csv 'Data\ACCT-FS01\prefetch.csv' |
  Where-Object { $_.ExecutableName -eq 'VAULT.EXE' } |
  Select-Object ExecutableName, RunCount, LastRun, PreviousRun0

Import-Csv 'Data\ACCT-FS01\security-evtx.csv' |
  Where-Object { $_.EventID -in '5140','5145' } | Measure-Object
```

```python
sec = R('security-evtx.csv')
for r in sec:
    if r['EventID'] == '4688' and 'vault.exe -enc' in r['Payload']:
        print(r['TimeCreated'], r['UserName'], r['Payload'])
for r in R('prefetch.csv'):
    if r['ExecutableName'] == 'VAULT.EXE':
        print(r['ExecutableName'], 'RunCount=' + r['RunCount'], r['LastRun'],
              'PreviousRun0=' + repr(r['PreviousRun0']))
print('5140/5145 count:',
      sum(1 for r in sec if r['EventID'] in ('5140', '5145')))
```

Expected: one 4688 at 02:13:52 for `C:\Windows\Temp\vault.exe -enc -threads 16 -note RECOVER-YOUR-FILES.txt -ext .vaulted -id VLT-8837-ACCT`, running as `svc-backup`. A `VAULT.EXE` Prefetch entry shows RunCount 1 and no previous-run values. The whole Security log holds exactly one 5140 and **no 5145 records at all**.

Mass modification *plus* local execution evidence *plus* the near-total absence of share-access records is the local-execution pattern: this server encrypted itself. Suppose the pattern had been reversed, with thousands of 5145 records from a single source IP and no Prefetch or 4688. Then you would be looking at the wrong host, and Chapter 12 §12.3.4's advice to pivot immediately to the 5145 source IP would apply.

The ordering is what makes this evidence available at all. The actor cleared the log at 02:09:41 and ran the encryptor at 02:13:52. The 4688 exists **because** it was written into the log the actor had just emptied.

### Step 6 — Rebuild the defense-evasion sequence around the cleared log

```powershell
$sec = Import-Csv 'Data\ACCT-FS01\security-evtx.csv'
"Security rows        : {0}" -f $sec.Count
"Earliest record      : {0} (EID {1})" -f $sec[0].TimeCreated, $sec[0].EventID

Import-Csv 'Data\ACCT-FS01\defender-evtx.csv' |
  Where-Object { $_.EventID -in '5001','5007','5010' } |
  Select-Object TimeCreated, EventID, Description

Import-Csv 'Data\ACCT-FS01\system-evtx.csv' |
  Where-Object { $_.EventID -eq '25' } | Select-Object TimeCreated, Description

Import-Csv 'Data\ACCT-FS01\powershell-evtx.csv' |
  Where-Object { $_.Payload -match 'vssadmin|Set-MpPreference|wevtutil' } |
  Select-Object TimeCreated, EventID, Payload
```

```python
print('Security rows :', len(sec))
print('Earliest      :', sec[0]['TimeCreated'], 'EID', sec[0]['EventID'])
for r in R('defender-evtx.csv'):
    if r['EventID'] in ('5001', '5007', '5010'):
        print(r['TimeCreated'], r['EventID'], r['Description'])
print('volsnap 25 records:',
      sum(1 for r in R('system-evtx.csv') if r['EventID'] == '25'))
for r in R('powershell-evtx.csv'):
    if any(k in r['Payload'] for k in ('vssadmin', 'Set-MpPreference', 'wevtutil')):
        print(r['TimeCreated'], r['Payload'][:110])
```

Expected: `security-evtx.csv` contains 24 rows, and its **earliest record is the EID 1102 at 2024-11-12 02:09:41**, naming `svc-backup`. That single fact establishes two findings at once: the account was compromised, and the clearing was deliberate rather than administrative.

Everything before 02:09:41 comes from channels the actor did not clear:

| Time (UTC) | Action | Surviving evidence | 4688? |
|---|---|---|---|
| 2024-11-11 21:52:41 | Defender path exclusion for `C:\Windows\Temp\wu` | Defender **5007**, `registry-runkeys.csv` | destroyed |
| 2024-11-12 02:02:12 | `Set-MpPreference -DisableRealtimeMonitoring $true` | PowerShell **4104** | destroyed |
| 2024-11-12 02:02:18 | Real-time protection disabled | Defender **5001**, **5007** ×2, **5010** | destroyed |
| 2024-11-12 02:06:29 | `cmd /c 'vssadmin delete shadows /all /quiet'` | PowerShell **4104** | destroyed |
| 2024-11-12 02:06:33 | `vssadmin.exe` executes | `VSSADMIN.EXE` Prefetch, RunCount 2 | destroyed |
| 2024-11-12 02:06:34–02:06:41 | Four shadow copies deleted | System **volsnap EID 25** ×4 | n/a |
| 2024-11-12 02:09:36 | `wevtutil cl Security` | PowerShell **4104** | destroyed |
| 2024-11-12 02:09:41 | Security log cleared | Security **1102** | is the 1102 |
| 2024-11-12 02:10:58 / 02:11:19 | `wbadmin delete catalog`, `bcdedit ... recoveryenabled No` | Security **4688** | **survived** |
| 2024-11-12 02:13:52 | Encryptor executes | Security **4688**, Prefetch | **survived** |
| 2024-11-12 02:14:06 | First encrypted file | USN Journal | n/a |

**Elapsed from the real-time protection disable (02:02:18) to the first encrypted file: 11 minutes 48 seconds. From the log clear to the first encrypted file: 4 minutes 25 seconds.** The disable is not the first evasion action. The `Set-MpPreference` 4104 that caused it is six seconds earlier, at 02:02:12. The path exclusion opened the sequence at 2024-11-11 21:52:41 UTC, 4 hours 21 minutes 25 seconds before the first encrypted file. Cross-check the shadow-copy conclusion with `vssadmin-list-shadows.txt`, which returns "No items found that satisfy the query."

The Defender detections earlier in the week are the bonus finding:

```powershell
Import-Csv 'Data\ACCT-FS01\defender-evtx.csv' |
  Where-Object { $_.EventID -in '1116','1117' } |
  Select-Object TimeCreated, EventID, Payload
```

```python
for r in R('defender-evtx.csv'):
    if r['EventID'] in ('1116', '1117'):
        print(r['TimeCreated'], r['EventID'], r['Payload'][:80])
```

Expected: **4 records**, for `HackTool:Win64/Mimikatz.E` quarantined on 2024-11-09 02:14:07 and `HackTool:Win32/NetworkScanner` on 2024-11-09 02:44:31. Both fall inside the actor's first interactive session on ACCT-FS01 (01:26:41–03:11:20). Defender named the actor's tooling about three days before it was switched off. The Mimikatz detection is the `comsvcs.dll` LSASS-dump technique from JUMP-01, repeated on this host the day after. Those detections independently corroborate the credential-access and discovery stages whose 4688 records are gone.

### Step 7 — Chain backwards to patient zero

```powershell
$jump = Import-Csv 'Data\ACCT-FS01\jumphost-security-evtx.csv'
$fails = $jump | Where-Object { $_.EventID -eq '4625' }
"4625 count : {0}" -f $fails.Count
"First      : {0}" -f $fails[0].TimeCreated
"Last       : {0}" -f $fails[-1].TimeCreated
$jump | Where-Object { $_.EventID -eq '4624' -and $_.UserName -eq 'svc-backup' } |
  Select-Object TimeCreated, Payload

$dc = Import-Csv 'Data\ACCT-FS01\dc-security-evtx.csv'
($dc | Where-Object { $_.EventID -eq '4776' -and $_.Payload -like '*0xC000006A*' }).Count
```

```python
jump = R('jumphost-security-evtx.csv')
fails = [r for r in jump if r['EventID'] == '4625']
print('4625 count:', len(fails))
print('first     :', fails[0]['TimeCreated'])
print('last      :', fails[-1]['TimeCreated'])
for r in jump:
    if r['EventID'] == '4624' and r['UserName'] == 'svc-backup':
        print('SUCCESS   :', r['TimeCreated'], r['Payload'][:120])
dc = R('dc-security-evtx.csv')
print('DC 4776 failures:',
      sum(1 for r in dc if r['EventID'] == '4776' and '0xC000006A' in r['Payload']))
```

Expected: **212 failed logons** (EID 4625, LogonType 10) against `svc-backup` from `45.147.230.19`. They run from 2024-11-06 21:03:12 to 21:46:58, a span of 43 minutes 46 seconds, and end with a single 4624 LogonType 10 at 21:47:22. The domain controller independently records the same burst as 212 × EID 4776 with error `0xC000006A`, plus one success. Two hosts, two event IDs, one story: that is what "confirm the entry point with independent evidence" means in practice.

Now watch the account:

```powershell
$dc | Where-Object { $_.UserName -eq 'a-mbrennan' } |
  Sort-Object TimeCreated | Select-Object TimeCreated, EventID, Payload
$dc | Where-Object { $_.UserName -eq 'svc-backup' -and $_.EventID -eq '4769' } |
  Sort-Object TimeCreated | Select-Object -First 4 TimeCreated, Payload
```

```python
for r in sorted((r for r in dc if r['UserName'] == 'a-mbrennan'),
                key=lambda r: r['TimeCreated']):
    print(r['TimeCreated'], r['EventID'], r['Payload'][:95])
```

Expected: **4 records for the domain admin `a-mbrennan`**, the earliest at 2024-11-08 02:04:18. The three Kerberos records (one 4768, two 4769) carry the jump host's IP, `10.0.2.28`. The 4672 at 02:04:41 records no source address. In the same log, `svc-backup`'s genuine pattern is three Kerberos service tickets every night from 2024-11-01, against `BKP-SRV01`, `BKP-SRV02` and `BKP-SRV03` at 01:05:11, 01:14:12 and 02:23:13. That is 36 records of unremarkable backup activity. On 2024-11-06 the account starts doing something it has never done: a RemoteInteractive logon on a jump host. Two days later a domain admin account appears from the same source. That divergence is the whole intrusion in two sentences.

The host-boundary crossing is in the operational channel, which was never cleared:

```powershell
Import-Csv 'Data\ACCT-FS01\terminalservices-evtx.csv' |
  Where-Object { $_.EventID -eq '1149' } |
  Select-Object TimeCreated, UserName, Payload
```

```python
for r in R('terminalservices-evtx.csv'):
    if r['EventID'] == '1149':
        print(r['TimeCreated'], r['UserName'], r['Payload'][:95])
```

Expected: **8 records**. Four are the actor's sessions as `svc-backup` from `10.0.2.28` (the jump host) on 2024-11-09, 11-10, 11-11 and 11-12. Three are routine administrative connections by named users on 11-01, 11-04 and 11-05 from the `10.0.4.0/24` desktop range. The last is the incident-response session at 08:05 on 11-12. The actor's 11-12 session begins at 02:01:41, 37 seconds before the Defender disable, and ends at 04:12:44.

**Dwell window, stated defensibly:** *Earliest observed attacker activity is 2024-11-06 21:03:12 UTC (first failed logon against `svc-backup` on JUMP-01 from 45.147.230.19); encryption completed 2024-11-12 03:38:41 UTC — a six-day dwell. JUMP-01 Security log retention begins 2024-11-04; activity before that date cannot be excluded.*

### Step 8 — Reconstruct staging and bound the egress

```powershell
$usn | Where-Object { $_.ParentPath -eq 'Windows\Temp\wu' } | Measure-Object
$usn | Where-Object { $_.ParentPath -eq 'Windows\Temp\wu' -and
                      $_.UpdateReasons -like '*FileDelete*' } |
  Select-Object UpdateTimestamp, FileName

$mft = Import-Csv 'Data\ACCT-FS01\mft.csv'
$arch = $mft | Where-Object { $_.FileName -like 'acct-fs01-data.7z.*' }
"Volumes : {0}" -f $arch.Count
"Staged  : {0}" -f ($arch | Measure-Object FileSize -Sum).Sum
```

```python
wu = [r for r in usn if r['ParentPath'] == 'Windows\\Temp\\wu']
print('USN records in staging dir:', len(wu))
print('deletions:', sum(1 for r in wu if 'FileDelete' in r['UpdateReasons']))
arch = [r for r in R('mft.csv') if r['FileName'].startswith('acct-fs01-data.7z.')]
staged = sum(int(r['FileSize']) for r in arch)
print('archive volumes:', len(arch), 'staged bytes:', staged)
```

Expected: **868 USN records** in `Windows\Temp\wu`, of which 16 are deletions at 03:41:22: 12 archive volumes plus `rclone.exe`, `rclone.conf`, `7z.exe` and `7z.dll`. The MFT still carries all 16 entries with `InUse=False`. The 12 archive volumes total 36,829,344,563 bytes (34.30 GiB).

Bin the staging burst the same way you binned the encryption:

```python
staging = [r for r in usn
           if '2024-11-11 21:14' <= r['UpdateTimestamp'][:16] <= '2024-11-11 22:38']
sb = collections.Counter(r['UpdateTimestamp'][:16] for r in staging)
print('records:', len(staging), 'bins:', len(sb),
      'min/max per minute:', min(sb.values()), max(sb.values()))
```

Expected: **847 records across 84 minute bins, 7–12 per minute**. The technique that found the encryption window, applied at roughly a third of the amplitude, finds data movement four hours earlier that nobody was looking for. Chapter 12 §12.3.2 promises exactly this.

Now the egress:

```powershell
$flow = Import-Csv 'Data\ACCT-FS01\network-flow.csv'
$ex = $flow | Where-Object { $_.DestIP -eq '185.220.101.44' }
"Sessions : {0}" -f $ex.Count
"BytesOut : {0}" -f ($ex | Measure-Object BytesSent -Sum).Sum
"First    : {0}" -f $ex[0].FlowStart
"Last     : {0}" -f ($ex | Sort-Object FlowEnd)[-1].FlowEnd

Import-Csv 'Data\ACCT-FS01\srum.csv' |
  Where-Object { $_.ApplicationName -eq 'rclone.exe' } |
  Select-Object Timestamp, BytesSent
```

```python
flow = R('network-flow.csv')
ex = [r for r in flow if r['DestIP'] == '185.220.101.44']
egress = sum(int(r['BytesSent']) for r in ex)
print('sessions:', len(ex), 'bytes out:', egress)
print('first:', ex[0]['FlowStart'], 'last:', max(r['FlowEnd'] for r in ex))
srum = [r for r in R('srum.csv') if r['ApplicationName'] == 'rclone.exe']
print('SRUM rows:', len(srum), 'bytes:', sum(int(r['BytesSent']) for r in srum))
print('egress / staged = %.4f' % (egress / staged))
```

Expected: **14 sessions** to `185.220.101.44:443` between 2024-11-11 22:41:06 and 2024-11-12 00:52:10, totalling 37,312,004,096 bytes out (34.75 GiB). SRUM independently records `rclone.exe` sending 36,884,201,472 bytes (34.35 GiB) across 3 hourly buckets. Egress is 1.31 % above the staged archive total, which is the overhead you would expect from TLS and TCP framing on a completed transfer. The three independent measurements fall within 1.5 % of each other.

Check two things before you write this up. First, `185.220.101.44` appears in no flow record before 22:41 on 2024-11-11. That absence of prior contact is what separates actor infrastructure from a legitimate cloud service. Second, and more important:

```python
big = sorted(flow, key=lambda r: -int(r['BytesSent']))[:3]
for r in big:
    print(r['FlowStart'], r['DestIP'], r['BytesSent'], r['OwningProcess'], '|', r['Notes'])
```

Expected: the three largest flows in the entire capture are **nightly backup jobs to `10.0.6.41`, each moving 214,748,364,800 bytes — roughly 5.8× the exfiltration.** Volume alone is not the signal. Destination, process, and prior-contact history are.

### Step 9 — Inventory the persistence and assess the restore

```powershell
Import-Csv 'Data\ACCT-FS01\system-evtx.csv' |
  Where-Object { $_.EventID -eq '7045' } |
  Select-Object TimeCreated, Payload

Import-Csv 'Data\ACCT-FS01\registry-runkeys.csv' |
  Where-Object { $_.Notes -like 'MALICIOUS*' } |
  Select-Object KeyPath, ValueName, ValueData, LastWriteTime
```

```python
for r in R('system-evtx.csv'):
    if r['EventID'] == '7045':
        print(r['TimeCreated'], r['Payload'][:100])
for r in R('registry-runkeys.csv'):
    if r['Notes'].startswith('MALICIOUS'):
        print(r['LastWriteTime'], r['KeyPath'] + '\\' + r['ValueName'], '=', r['ValueData'][:60])
```

Expected: **2 service installs**: `PSEXESVC` at 2024-11-09 01:19:44 for remote execution, and `VaultUpd` at 2024-11-10 23:41:08. `VaultUpd` has the display name "Windows Update Assistant", starts automatically, and points at `C:\Windows\Temp\wu\rclone.exe`. There are also 4 malicious registry values: the `WindowsUpdateSvc` Run value, the two Defender policy values, and the staging-path exclusion. `fDenyTSConnections` is `0`, with a LastWrite of 2024-11-09 01:21:07, inside the dwell window.

This is the assessment that decides the restore:

| Assessment | Finding | Confidence | What would raise it |
|---|---|---|---|
| **Scope confidence** | ACCT-FS01 fully scoped: 418 files, 24 directories, 84-minute window. Environment **not** scoped — the actor reached BKP-SRV01 on 2024-11-09 and holds a domain admin credential | LOW for the environment, HIGH for this host | An EDR sweep for `.vaulted` and `RECOVER-YOUR-FILES.txt` across all reachable hosts |
| **Actor presence** | No authentication by compromised accounts after 04:12:44 on 11-12, and no flow to `185.220.101.44` after 00:52. But the `VaultUpd` service and the Run value were never remediated | MEDIUM | Live EDR telemetry; DC authentication review for both accounts since 11-12 |
| **Backup trustworthiness** | Shadow copies destroyed; catalog deleted. Any backup after 2024-11-06 21:03 is inside the dwell window. The 11-11 nightly backup demonstrably contains `VaultUpd`, the Run value and the RDP re-enablement; the 11-10 backup already carries the RDP re-enablement | Persistence-in-backup finding is HIGH; overall viability **cannot be determined** from this host | Backup-platform logs and a mounted pre-11-06 image hunted for the six persistence entries |
| **Reinfection risk** | HIGH. The RDP path on JUMP-01 is still exposed, `svc-backup` and `a-mbrennan` are not rotated, and the persistence survives a restore | HIGH | Confirmation that 3389 is closed, both accounts rotated, `krbtgt` assessed, and the five persistence entries still on the host removed |

The exfiltration finding, in the chapter's tiered language:

> **Highly likely.** Data was staged and exfiltrated before encryption. Basis: 12 archive volumes totalling 36,829,344,563 bytes created in `C:\Windows\Temp\wu\` between 21:14 and 22:38 on 2024-11-11 (USN Journal, 847 records; MFT entries surviving deletion); `rclone.exe` execution confirmed by Prefetch (RunCount 3), Amcache and ShimCache; a recovered `rclone.conf` naming a WebDAV endpoint at `185.220.101.44`; 37,312,004,096 bytes egressed to that address across 14 sessions with no prior contact; and SRUM independently attributing 36,884,201,472 bytes sent to `rclone.exe` in the same window. The three volume measurements agree within 1.5 %, which is consistent with a completed transfer. **Not "Confirmed"**: the rclone invocation omitted `--log-file`, so there is no per-file transfer record. The staged set is known at archive-volume granularity and, from the 7-Zip command line in PowerShell 4104, at source-directory granularity — `C:\Shares\Accounting`, `\Finance`, `\HR`, `\Legal` and `\IT\Backups\SQL` — but not at file granularity. No proxy logs were retained for the window. Provider-side or proxy evidence identifying transferred filenames would move this to Confirmed.

### What you've just done

Nine steps, and the case is resolved. You established the blast radius by two measures that rank the directories in nearly opposite orders. You derived the encryption window from the file system rather than trusting the actor's own timestamps, and you read a seven-minute trough correctly instead of truncating the window. You proved local execution rather than assuming it. You rebuilt a defense-evasion sequence whose primary evidence source had been deliberately destroyed, using four channels the actor forgot about. You chained backwards across two host boundaries to a 212-attempt brute force that the domain controller corroborated independently. You stated the dwell window with its retention boundary attached. You bounded the exfiltration with three measurements agreeing within 1.5 %, and then declined to call it "Confirmed" because one artifact was missing.

That last decision is the one that matters. Everything else in this walkthrough is technique. The willingness to stop one tier short of what the evidence almost supports is the discipline.

Tasks 4 through 13 of the workbook now have concrete inputs in every cell. The scoping deliverable in Task 13 Part A is Steps 2, 4 and 5. The recovery assessments in Task 12 are Step 9.

---

## Deliverables Checklist

Your `lab12-notes.md` should contain:

- [ ] **Task 1** — Four-clock table, preservation request, acquisition ranking, client determination
- [ ] **Task 2** — Collection inventory, hash table, ransom-note extraction
- [ ] **Task 3** — Kill-chain-to-artifact map with at least 8 rows, each marked for log-clear survival
- [ ] **Task 4** — Extension sweep: count, volume, directory count, per-directory rankings by both measures
- [ ] **Task 5** — Per-minute USN binning, the five-property signature table, and the trough explanation
- [ ] **Task 6** — Complete 24-row ransom-note traversal map
- [ ] **Task 7** — Local-vs-remote execution table and stated conclusion with confidence
- [ ] **Task 8** — Defense-evasion timeline (≥6 steps) with survival marked, plus the interval measurements
- [ ] **Task 9** — Backwards chain: encryptor anchor, ≥12-row account timeline, host hops, entry-point confirmation, dwell-window sentence
- [ ] **Task 10** — Staging reconstruction, source-directory identification, transfer-tool artifact set
- [ ] **Task 11** — Egress table, sanity check, confounder identification, tiered exfiltration finding
- [ ] **Task 12** — Four recovery assessments, persistence inventory (≥4), backup viability, remediation prerequisites (≥6)
- [ ] **Task 13** — Scoping deliverable, 1–3 page incident summary, handoff note, and the pay/don't-pay answer

---

## Files in This Folder

```
Lab12/
├── ReadMe.md                ← This file — the end-to-end engagement
├── lab12-notes.md           ← Your working notes file (fill this in)
├── task-answers.md          ← Model answers for the workbook Tasks
├── walkthrough-answers.md   ← Expected output for the Hands-On Walkthrough,
│                              with the verification command for every count
├── Lab12_01/                ← §12.1 What Makes Ransomware Different
├── Lab12_02/                ← §12.2 The Kill Chain in Windows Artifacts
├── Lab12_03/                ← §12.3 Scoping the Encryption
├── Lab12_04/                ← §12.4 Patient Zero and the Dwell Window
├── Lab12_05/                ← §12.5 Did They Steal Data Before Encrypting?
└── Lab12_06/                ← §12.6 Supporting the Recovery Decision
```

The six sub-exercises drill one chapter section each. This top-level lab is the
end-to-end run. Work the sub-exercises if you want to build the skills
separately first, or come here directly if you want the whole engagement.

Backing data: [`Data/ACCT-FS01/`](../../Data/ACCT-FS01/) — 19 data files plus
`generate.py` and `README.md`, the largest
dataset in the book and the only one carrying event logs from three hosts. Start
with its `README.md`.

---

> **Going deeper:** This lab works a single host end to end. Three appendices cover the parts of a real ransomware case that sit outside it. `Book/AppendixA.md` (Lateral Movement, Credential Abuse, Active Directory) covers the credential-access and lateral-movement stages this lab observes only from the destination side. It also covers what to do about `krbtgt` once you conclude the domain is compromised, a step Task 12's reinfection assessment stops short of. `Book/AppendixC.md` (EDR Platforms and Sysmon) covers the off-host telemetry that would have made the cleared Security log a non-event, and the live-query sweeps that would answer Task 12's scope-confidence question. `Book/AppendixB.md` (Cloud Identity and M365 Forensics) covers the tenant-side audit that increasingly matters when the exfiltration destination is a cloud service rather than a bare IP.

---

## Key Takeaways

- **The encryption is the end of the intrusion.** Eighty-four minutes of encryption sat on top of six days of dwell. Everything the business needs to know is in the six days: how they got in, what they took, whether the backups are safe, and whether it will happen again.
- **Count and volume rank differently, and both matter.** Five SQL backup files were 1.2 % of the encrypted count and 91.8 % of the encrypted volume. Reporting one number without the other misleads whoever is planning the restore.
- **A cleared log relocates the investigation, it does not end it.** The 1102 at 02:09:41 destroyed the local authentication history and nothing else. The domain controller, the jump host, four operational channels, NTFS, Prefetch, Amcache, ShimCache and SRUM all survived. The encryptor's own 4688 survived too, because it ran *after* the clear.
- **Independent corroboration is what turns a log entry into a finding.** The 212 failures on the jump host and the 212 validation failures on the domain controller are the same event seen twice. Either alone is a hypothesis.
- **State the retention boundary with the dwell window.** "Earliest observed activity: 2024-11-06; retention begins 2024-11-04; earlier activity cannot be excluded" is a longer sentence and a defensible one. Read the boundary off the file rather than assuming it. The DC log reaches back to 11-01 and the jump-host log does not, so quoting the wrong one overstates how much history you have.
- **Stop one tier short when the evidence stops.** Three volume measurements agreeing within 1.5 % is *highly likely*, not *confirmed*, because no per-file transfer record exists. Naming the gap is what makes the rest of the report credible.
- **Restoring is not remediating.** A backup taken inside the dwell window carries the actor's persistence. The four assessments exist so that nobody restores into the same access path.

---

**Next:** Lab 13 — Reporting, Containment, and Recovery

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
