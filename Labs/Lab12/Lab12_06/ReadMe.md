# Lab 12.6 — Supporting the Recovery Decision

**Supporting Section 12.6: Supporting the Recovery Decision**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

This sub-exercise turns the findings from the rest of Lab 12 into decision inputs, which is a different job with a different failure mode.

Recovery is a business decision, and the responder does not make it. The responder owes the people who do make it four assessments: scope confidence, actor presence, backup trustworthiness, and reinfection risk. Deliver each one as early as you can responsibly give it, with an explicit confidence level and an explicit list of what would raise that confidence. Deliver them late and the organisation restores without them. Deliver them without confidence levels and they get read as certainties.

The failure mode is specific and common. An organisation restores from a backup taken inside the dwell window and reinstates the actor's persistence. Within days it is encrypted a second time, through access the actor never lost. Every task here exists to prevent that.

The last part of this sub-exercise is the pay/don't-pay question, which you will be asked. The answer is that it is not your decision. This lab is where you practise saying that as a professional position rather than an evasion.

---

## What This Lab Covers

This lab supports the following concepts from Section 12.6:

| Section | Topic |
|---|---|
| 12.6.1 | What forensics owes the business — the four assessments |
| 12.6.2 | Is the actor still in? Persistence, credential exposure, active C2, recent authentication |
| 12.6.3 | Are the backups trustworthy? Existence, cleanliness, completeness |
| 12.6.4 | Decryptors and key material — public decryptors and memory-resident keys |
| 12.6.5 | The pay / don't pay question and the responder's lane |

---

## Learning Objectives

By completing this lab, you will be able to:

- Produce the four recovery assessments with explicit confidence levels and explicit escalation criteria
- Build a persistence inventory that distinguishes mechanisms surviving a restore from those that do not
- Separate the three distinct questions conflated under "are the backups good?"
- Identify the earliest candidate restore point from the dwell window and state why it is a candidate rather than an answer
- Write a remediation prerequisite list as verifiable statements rather than intentions
- Check for free decryptors and memory-resident key material, and present both without raising expectations
- State the responder's position on payment without advocating, editorialising, or implying a recommendation

---

## Estimated Time

60–90 minutes

---

## Prerequisites

- Completion of Labs 12.1 through 12.5 — this sub-exercise consumes their outputs
- Your `lab12-notes.md` file, containing the dwell window, the persistence findings, and the exfiltration tier
- `python3`, PowerShell, or a spreadsheet
- From [`Data/ACCT-FS01/`](../../../Data/ACCT-FS01/): `registry-runkeys.csv`, `system-evtx.csv`, `network-flow.csv`, `security-evtx.csv`, `dc-security-evtx.csv`, `terminalservices-evtx.csv`, `vssadmin-list-shadows.txt`, `ransom-note.txt`

Preamble for the Python blocks, run from the repository root:

```python
import csv, collections
def R(name):
    with open(f'Data/ACCT-FS01/{name}', newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))
```

---

## Scenario

It is 16:20 on 2024-11-12. The reimage was deferred. The disk image was taken at 08:40, and you have worked the case from the parsed output all afternoon.

The bridge call at 17:00 has the CIO, the infrastructure lead, the finance director, outside counsel, and the insurer's claims contact on it. The agenda is one item: what do we do tonight.

The infrastructure lead has a proposal ready. Restore `ACCT-FS01` from the 2024-11-10 backup — the most recent one that exists — and be back in service by morning. It loses two days of accounting data, which is painful but survivable.

You know the dwell window starts on 2024-11-06.

Your job on that call is not to say no. It is to give four assessments accurately enough that the people who *do* decide can see what the proposal costs.

---

## Background: Four Assessments, One Question Each

| Assessment | The question it answers | Primary evidence |
|---|---|---|
| **Scope confidence** | Do we know every affected host, or only every host we have looked at? | Enterprise sweep coverage; hosts with no telemetry |
| **Actor presence** | Is the actor still in the environment right now? | Persistence findings, active C2, recent authentications |
| **Backup trustworthiness** | Is there a restore point that predates the intrusion and is free of persistence? | Dwell window start vs. backup dates; persistence artifacts in backup images |
| **Reinfection risk** | If we restore today, what is the chance of being encrypted again? | Initial access status, credential rotation status, persistence remediation status |

Each carries a confidence level and a list of what would raise it. A confidence level without escalation criteria is a shrug with a label on it.

> **IR Reality Check:** Restoring is not remediating. A backup taken inside the dwell window carries the actor's persistence forward into the "clean" environment. The second encryption event usually arrives faster than the first.

---

## Lab Tasks

---

### Task 1 — Build the Persistence Inventory

**Objective:** Enumerate every mechanism that would still be there after a restore.

```powershell
Import-Csv 'Data\ACCT-FS01\system-evtx.csv' |
  Where-Object { $_.EventID -eq '7045' } | Select-Object TimeCreated, Payload
Import-Csv 'Data\ACCT-FS01\registry-runkeys.csv' |
  Select-Object LastWriteTime, KeyPath, ValueName, ValueData, Notes
```

```python
for r in R('system-evtx.csv'):
    if r['EventID'] == '7045':
        print(r['TimeCreated'], r['Payload'][:110])
for r in R('registry-runkeys.csv'):
    print(r['LastWriteTime'][:19], r['KeyPath'], '|', r['ValueName'], '=', r['ValueData'][:55])
```

| Mechanism | Artifact and file | Established (UTC) | Inside the dwell window? | Would survive a restore from 11-10? |
|---|---|---|---|---|
| | | | | |

Include at least six rows. Classify every value in `registry-runkeys.csv`. Several are benign, and getting that classification right is part of the exercise.

Then answer:

**1. One persistence mechanism points at a file that no longer exists. Why is it still a remediation item, and what happens to it on a restore from a backup taken before the deletion?**

**2. One registry value is not itself malicious but is a finding because of its LastWrite timestamp. Which, what does it control, and why does its timestamp matter?**

**3. Two services were installed during the intrusion. Only one is persistence. Identify each, and say what the other one tells you about how the actor arrived.**

**4. Chapter 12 §12.6.2 says persistence found on one host should be hunted for on all hosts. Write the four indicators you would push to an enterprise sweep, in the form a live-query tool would take them.**

---

### Task 2 — Is the Actor Still In?

**Objective:** Assemble the evidence for the assessment that decides whether tonight's restore happens at all.

**Part A — Recent authentication.** Check for any activity by the compromised accounts after the encryption event.

```python
sec = R('security-evtx.csv')
for r in sec:
    if r['TimeCreated'] > '2024-11-12 03:38':
        print(r['TimeCreated'][:19], r['EventID'], r['UserName'], r['Payload'][:80])
```

| Measure | Value |
|---|---|
| Last action by the primary compromised account | |
| Last action by the domain admin account | |
| Any authentication by either after that point? | |
| Who else authenticated to the host after the encryption, and are they benign? | |

**Part B — Active C2.**

```python
flow = R('network-flow.csv')
for r in flow:
    if r['DestIP'] == '185.220.101.44':
        print(r['FlowStart'], r['FlowEnd'], r['BytesSent'])
print('capture ends:', max(r['FlowEnd'] for r in flow))
```

| Measure | Value |
|---|---|
| Last session to the exfiltration destination | |
| Flow capture end time | |
| Gap between them | |
| Does the absence of later flow prove the actor is gone? | |

**Part C — Credential exposure.**

| Question | Answer | Basis |
|---|---|---|
| Which accounts were compromised? | | |
| Which hosts did each touch during the dwell window? | | |
| Was a domain controller touched? | | |
| Was `NTDS.dit` accessed? | | |
| What is the correct assumption about cached credentials on the touched hosts? | | |
| Does `krbtgt` need assessment? | | |

Then answer:

**1. "No authentication since 04:12:44" is evidence of absence only if you had visibility. What visibility do you actually have across the environment, and what does that do to your confidence level?**

**2. The domain admin account's last observed action targeted backup infrastructure. Why does that single row change the actor-presence assessment for hosts you have never examined?**

**3. Name the one collection you would request tonight that would most improve this assessment, and say what it would tell you.**

---

### Task 3 — Are the Backups Trustworthy?

**Objective:** Separate three questions that get conflated into one on every bridge call.

```
Get-Content 'Data\ACCT-FS01\vssadmin-list-shadows.txt'
```

| Question | Answer | Basis | Confidence |
|---|---|---|---|
| **Do the backups exist?** | | | |
| **Are they clean?** | | | |
| **Are they complete?** | | | |

Now assess the specific proposal on the table:

| Measure | Value |
|---|---|
| Dwell window start | |
| Proposed restore point | |
| Is the proposed restore point inside the dwell window? | |
| Persistence mechanisms established before the proposed restore point | |
| Which of those the restore would reinstate | |
| Earliest date a restore point would have to predate to be a candidate | |
| Data loss implied by that earlier restore point | |

Then answer:

**1. Write your response to the infrastructure lead's proposal in no more than four sentences. Name the evidence.**

**2. Chapter 12 §12.6.3 says a pre-dwell backup is "only a candidate until you have checked it." What specifically would you check it for, and how?**

**3. Why is "we checked the backup image for the persistence artifacts we found in production" worth substantially more than "we believe the backup is clean"?**

**4. Shadow copies and the backup catalog are both gone. Which of the three questions can this host answer, and which must be answered from the backup platform instead?**

---

### Task 4 — Deliver the Four Assessments

**Objective:** Produce the table that goes on the 17:00 call.

Every row needs an answer, primary evidence, an explicit confidence level, and an explicit statement of what would raise it.

| Assessment | Your answer | Primary evidence | Confidence | What would raise it |
|---|---|---|---|---|
| Scope confidence | | | | |
| Actor presence | | | | |
| Backup trustworthiness | | | | |
| Reinfection risk | | | | |

Two of these should carry *different* confidence levels for different parts of the same answer — this host versus the environment, for example. Where that is true, say so in the cell rather than averaging it away.

Then answer:

**1. Which assessment can you give with the highest confidence from this dataset, and which with the lowest? What is the difference between them made of?**

**2. Scope confidence is the only assessment that can be raised by a single action. Which action, and why is it the highest-value thing the organisation could do in the next two hours?**

**3. Reinfection risk depends on three status conditions, none of which are forensic findings. Name them, and say who owns each.**

---

### Task 5 — Write the Remediation Prerequisites

**Objective:** State what must be true before restoration begins, as things someone can verify.

Write at least eight prerequisites. Each must be phrased as a **verifiable statement** — something that is either demonstrably true or demonstrably not. "Improve RDP security" fails. "TCP/3389 is not reachable from the internet on JUMP-01, confirmed by external scan" passes.

| # | Prerequisite | Owner | How it is verified | Evidence that made it necessary |
|---|---|---|---|---|
| 1 | | | | |
| … | | | | |

Your list should cover, at minimum: the initial access path, credential rotation, the persistence items from Task 1, endpoint visibility on restored hosts, monitoring for the identified indicators, and the backup restore point.

Then answer:

**1. Which prerequisite would be the most unpopular on the call, and how do you make the case for it using evidence rather than principle?**

**2. Two of your prerequisites cannot be verified from anything in this dataset. Which, and who do you have to ask?**

**3. Why does phrasing these as verifiable statements rather than recommendations change what happens to them after the call ends?**

---

### Task 6 — Check for a Decryptor and for Key Material

**Objective:** Two long shots, both cheap, both worth checking before anyone concludes payment is the only path.

**Part A — Family identification.** Assemble what a family-identification service or threat-intelligence provider would need.

| Input | Value from this case | Source |
|---|---|---|
| Ransom note filename | | |
| Ransom note text sample | | |
| Encrypted-file extension | | |
| Victim identifier format | | |
| Sample encrypted file | | |
| Encryptor SHA-1 / SHA-256 | | |
| Contact channel format | | |

Where would you send this set, and what are you hoping to get back? [No More Ransom](https://www.nomoreransom.org/) is the starting point named in Chapter 12 §12.6.4.

**Part B — Key material in memory.**

| Question | Answer |
|---|---|
| Was the host rebooted after encryption? | |
| Was memory captured? | |
| When did the encryptor process exit? | |
| Is memory-resident key recovery still possible on this host? | |
| What was the last moment at which it was possible? | |

Then answer:

**1. Memory was never captured on this host. Write the sentence about that fact for the report, and say whether it belongs in findings or in recommendations.**

**2. Both of these lines of inquiry are long shots. How do you present them to a client without raising expectations, and why is presenting them at all still correct?**

**3. "Capture memory before rebooting an encrypted host" costs one procedure. Name three separate things a memory image could contribute to this case beyond key material.**

---

### Task 7 — The Question You Will Be Asked

**Objective:** Practise the answer before you need it.

Someone on the 17:00 call asks what you think they should do about the ransom.

**Part A — Write the answer.** Verbatim, in no more than four sentences.

**Part B — Map your contributions.** For each input the decision-makers will weigh, record whether it is yours to supply and what you would say.

| Decision input | Yours to supply? | What you contribute |
|---|---|---|
| Whether recovery without a decryptor is feasible | | |
| Whether data was actually exfiltrated | | |
| Whether a free decryptor exists | | |
| Precise family identification | | |
| Whether the actor still has access | | |
| Sanctions exposure of a payment | | |
| Insurance policy terms | | |
| Business tolerance for data publication | | |
| The ethics of paying | | |

**Part C — Identify the failure mode.** Rewrite each of the following so it stays inside the responder's lane.

| Statement as written | Why it steps outside the lane | Rewritten |
|---|---|---|
| "Given the backup situation, paying is probably your only realistic option." | | |
| "I wouldn't pay these people — they rarely hand over a working decryptor." | | |
| "The exfiltration is bad enough that you should assume you'll have to pay to suppress it." | | |
| "We found no evidence of exfiltration, so there's nothing to pay for." | | |

Then answer:

**1. Why does advocating a position on payment cost you the ability to be a neutral source of fact on everything else in the same report?**

**2. Chapter 12 says a responder who treats the ransom decision as theirs "has stepped outside their role." What is the role, stated positively?**

**3. Your findings can imply a recommendation through selective framing even when no sentence advocates anything. Give one example from your own Task 4 table and say how you would neutralise it.**

---

### Task 8 — Write the Recovery Decision Brief

**Objective:** Package everything above into the document the call needs.

Use this structure. Keep it to one page.

```
Case Reference:
Author:
Date/Time (UTC):

Scope of Investigation (what was examined, what was not):

The Four Assessments:
  Scope confidence      —  finding / confidence / what would raise it
  Actor presence        —  finding / confidence / what would raise it
  Backup trustworthiness—  finding / confidence / what would raise it
  Reinfection risk      —  finding / confidence / what would raise it

Dwell Window (with retention boundary):

Exfiltration Finding (tier + basis + gaps):

Persistence Not Yet Remediated:

Remediation Prerequisites Before Restore:
  1.
  2.
  3.

Decryptor / Key Material Status:

Preservation Issues to Escalate:

What This Brief Does Not Decide:
```

Then answer:

**1. Which sentence in your brief is most likely to be quoted out of context, and how did you phrase it defensively?**

**2. Three audiences will read this — technical leadership, counsel, and the insurer. Name one thing each will take from it that the other two will not.**

**3. What did this case reveal about the organisation's logging and preservation posture that belongs in recommendations rather than findings?**

---

### Task 9 — Reflection

Answer the following in 3–5 sentences each.

**1. Findings versus decision inputs**
What changes about how you write when the deliverable is an input to someone else's decision rather than a record of what you found?

**2. Confidence with escalation criteria**
Why is "MEDIUM confidence" almost useless on its own, and what does attaching "what would raise it" actually give the reader?

**3. Restoring is not remediating**
Explain, to someone who has never worked an incident, why the fastest path back to service is often the path back to the same incident.

**4. The lane**
Neutrality on the payment question can feel like avoiding responsibility. Explain why it is the opposite.

---

## Deliverables Checklist

Your `lab12-notes.md` should contain:

- [ ] **Task 1** — Persistence inventory, at least six rows, with benign values correctly classified
- [ ] **Task 2** — Actor-presence evidence across recent authentication, active C2, and credential exposure
- [ ] **Task 3** — The three backup questions answered separately, plus the assessment of the proposed restore point
- [ ] **Task 4** — Four-assessment table with confidence levels and escalation criteria
- [ ] **Task 5** — At least eight remediation prerequisites, each verifiable, with owners
- [ ] **Task 6** — Family-identification input set and the memory / key-material assessment
- [ ] **Task 7** — The four-sentence payment answer, the decision-input map, and the four rewritten statements
- [ ] **Task 8** — One-page recovery decision brief
- [ ] **Task 9** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab12/
├── lab12-notes.md  ← Your working notes file (whole lab)
└── Lab12_06/
    └── ReadMe.md       ← This file
```

Backing data: [`Data/ACCT-FS01/`](../../../Data/ACCT-FS01/) — principally `registry-runkeys.csv`, `system-evtx.csv`, `network-flow.csv` and `vssadmin-list-shadows.txt`.

---

## Key Takeaways

- **Four assessments, each with a confidence level and escalation criteria.** Scope confidence, actor presence, backup trustworthiness, reinfection risk. A confidence level without "what would raise it" is not an assessment.
- **Persistence established inside the dwell window survives the restore.** A service, a Run value and an RDP-enable setting written days before encryption are all reinstated by a backup taken after they were written.
- **"Are the backups good?" is three questions.** Do they exist, are they clean, are they complete. The host can only answer part of the first. The backup platform owns the rest.
- **Check the backup image for the indicators you found in production.** It converts "we believe it is clean" into "we checked". It is also the most frequently skipped high-value step in ransomware recovery.
- **Decryptors and memory keys are cheap to check and wrong to promise.** Identify the family precisely, check the public sources, and capture memory before reboot. Present both as long shots.
- **The payment decision is not yours.** Supply the five inputs you have visibility into, decline the rest, and keep the neutrality that makes every other finding in your report credible.

---

**Next:** Lab 13 — Reporting, Containment, and Recovery

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
