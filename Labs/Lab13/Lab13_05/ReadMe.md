# Lab 13.5 — Eradication and the Reinfection Question

**Supporting Section 13.5: Eradication and the Reinfection Question**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Eradication is where forensics stops being an investigative activity and becomes a completeness check. The question is no longer *what happened* but *have I found all of it*.

That shift is uncomfortable, because evidence cannot prove completeness. You can show that a persistence mechanism exists. You cannot show that no others do. You can only show which locations you checked, with what coverage. Eradication planning is therefore an exercise in stating your own uncertainty precisely enough that someone else can decide how much of it the business should carry.

The classic failure is the four-day reinfection, and it has five causes: missed persistence, unrotated credentials, an unclosed entry point, an out-of-scope compromised host, and a restore from a compromised backup. Only the first is a forensics failure in the narrow sense. The other four are failures of scope, sequencing, or coordination. That is why the analyst who did the investigation needs to be in the eradication planning conversation, rather than handing over a report and leaving.

This sub-exercise puts you in that conversation, with three hosts, two persistence mechanisms with different status, a service account with an awkward timestamp, and a memory image taken three hours after on-host activity ended.

---

## What This Lab Covers

This lab supports the following concepts from Section 13.5:

| Section | Topic |
|---|---|
| 13.5.1 | The three questions an eradication plan must answer |
| 13.5.2 | Why cleaned hosts come back |
| 13.5.3 | Rebuild or clean |
| 13.5.4 | Credential rotation, in dependency order |
| 13.5.5 | Eradication is verified, not declared |

---

## Learning Objectives

By completing this lab, you will be able to:

- Answer the three eradication questions with confidence levels attached, and name the reinfection risk each unresolved answer creates
- Build a persistence verification checklist covering the mechanisms that survive cleanup, not just the two everyone checks
- Apply the rebuild-versus-clean criteria to hosts of different roles and reach a defensible call
- Name the three host categories where rebuild is mandatory rather than preferred
- Sequence credential rotation in dependency order and explain what goes wrong out of order
- Reason about credential exposure when no memory image covers the intrusion window
- Turn the §13.5.5 verification pass into executable steps with owners and completion criteria

---

## Estimated Time

60–85 minutes

---

## Prerequisites

- Chapter 13 §13.5 read, with the §13.5.3 rebuild-or-clean table and the §13.5.4 rotation order to hand
- Lab 13.4 completed — containment has to have happened before eradication is a real conversation
- A text editor or markdown editor
- Your `lab13-notes.md` file, in the parent `Lab13/` folder
- Optional: `Book/AppendixA.md` for the artifact side of `krbtgt` rotation and Golden Ticket indicators, and `Book/AppendixB.md` for the Entra ID token side of rotation category 7

---

## Scenario

**The clock has moved. It is 2024-11-17, three days after the intrusion.**

Containment held. WKSTN-221 memory was captured at 17:35–18:04 on 14 November, about three hours after on-host activity ended, and the host was isolated at 18:20. FILESVR-03 was snapshotted at 18:05. What the last three days established:

- FILESVR-03 was reviewed. It showed the `net use` session at 14:33 and directory enumeration of `Finance$`, but **no file reads beyond directory listings** and no attacker binary.
- `10.0.4.17` was located. It is an unmanaged Windows host under a desk in a decommissioned lab space, **joined to the domain 18 months ago and never inventoried**. Its disk was imaged.
- An estate-wide EDR hunt for the `update.exe` hash found it on **no other host**. The C2 address `91.214.47.22` appears in flow records only for WKSTN-221 and `10.0.4.17`.
- Three days of elevated monitoring have produced nothing new.

**Unchanged:** still no memory image from the intrusion window, still no malware sample, still no host DNS query logging, still no Windows Event Forwarding, and the Security log on WKSTN-221 still wraps in roughly 36 hours.

### What the case found on WKSTN-221

| Item | Detail |
|---|---|
| Entry | `Q4_Payroll_Review.xlsm`, LNK created 14:18:55. EID 4688 at 14:19:38 — `powershell.exe` with parent `OUTLOOK.EXE` and `-EncodedCommand` |
| Payload | `update.exe`, 174,080 bytes, SHA-256 `4f8b2c1a8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345`. Amcache records Publisher `Microsoft Corporation` and `ProductName=Update`. Both come from the file's own version-info resource, not a code signature, and both are **forged metadata**. Executed 14:21:03, Prefetch `UPDATE.EXE-89A4B22C.pf`, **RunCount 1**. Deleted 14:23:44. **No sample recovered.** |
| Persistence 1 | Scheduled task `\Microsoft\Windows\WindowsUpdate\WindowsUpdateSync`, author `FINANCE\payroll-admin`, logon trigger, action `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand <payload>`. `LastTaskResult 0x41303` — **never executed**. |
| Persistence 2 | WMI event subscription in `root\subscription`: filter `WindowsUpdateFilter` (uptime 200–320 s), consumer `WindowsUpdateConsumer` (`CommandLineEventConsumer`), **binding present**, same encoded payload. **Live.** |
| Checked and clear | Run / RunOnce and Services were enumerated and contained nothing attacker-authored |
| Access level | All observed activity ran in the `payroll-admin` user context. No EID 4672, no service install, no driver load observed |
| Lateral | EID 4648 at 14:33:18 to FILESVR-03. Inbound SMB from `10.0.4.17` read 4,218,421 bytes off the host |
| Dwell | First observed attacker action 14:18:55. Last on-host activity 14:38:00, the EID 4634 logoff of the `10.0.4.17` session. Roughly 19 minutes on this host. EDR alert at 14:21 and escalation to IR at 14:23, while the attacker was still active. On-host activity continued for 15 minutes after escalation |

### One awkward fact

`svc-backup` authenticated to WKSTN-221 at **2024-11-14 02:14 UTC**, roughly 12 hours before the intrusion, via a scheduled task `BackupServiceSync` running `C:\Program Files\BackupAgent\bkupagent.exe`.

---

## Background: Completeness Is Not Provable

| Eradication question | What "yes" would require | What you actually have |
|---|---|---|
| All persistence identified? | Every mechanism in §13.5.1 checked on every in-scope host, with coverage stated | Two found on one host. Fifteen-odd locations named by the chapter. How many did the triage collection actually reach? |
| All reachable credentials rotated? | Every credential that existed in memory, in a file, in a browser store, in a script, or in a service config on any compromised host | No memory image from the intrusion window. What sat in LSASS while the attacker was active cannot be shown from evidence |
| Entry point closed? | A positive test — the version verified, MFA confirmed, the rule checked in the running config | An email attachment reached a user's inbox and executed. What is the closable condition? |

> **IR Reality Check:** Any of the three answered as "Possible" or "Undetermined" is a reinfection risk you should name explicitly in the report. Naming it is not an admission of failure. It is how the business gets to decide what risk it is carrying, instead of being told there is none.

---

## Lab Tasks

---

### Task 1 — Answer the Three Questions

**Objective:** Apply §13.5.1 with confidence levels attached.

| # | Question | Your answer | Confidence | If Possible or Undetermined: the reinfection risk this creates, in one sentence |
|---|---|---|---|---|
| 1 | Have all persistence mechanisms been identified? | | | |
| 2 | Have all attacker-accessible credentials been rotated? | | | |
| 3 | Is the entry point closed? | | | |

Use the four-level scale from §13.2.2 and apply its test, not your intuition.

Then answer:

**1. Question 1 asks whether you have found all persistence, not whether you have found persistence. What would have to be true for you to answer it Confirmed, and is that achievable on this engagement?**

**2. Question 3 is the one this incident answers worst. State what the entry point actually was, what "closed" would mean for it, and what positive test would demonstrate it.**

**3. Which of the three questions is most likely to be answered optimistically by a team under pressure to restore service? What is the mechanism by which that optimism enters the answer?**

---

### Task 2 — Build the Persistence Verification Checklist

**Objective:** Cover the mechanisms that survive cleanup, not just the two everyone checks (§13.5.1).

Chapter §13.5.1 names roughly 15 persistence locations. Build the checklist with the artifact or command you would use for each on a Windows host. The two the case actually found are pre-filled as the pattern.

| # | Mechanism | How to check | Found in this case? | Verified clear on (host / date) |
|---|---|---|---|---|
| 1 | Run / RunOnce | `RECmd` over SOFTWARE + NTUSER.DAT; `Software\Microsoft\Windows\CurrentVersion\Run{,Once}` | No — enumerated, nothing attacker-authored | |
| 2 | Services | | No | |
| 3 | Scheduled Tasks | `C:\Windows\System32\Tasks\`, EID 4698; check the Author field and non-Microsoft entries inside Microsoft task folders | **Yes** — `\Microsoft\Windows\WindowsUpdate\WindowsUpdateSync`, author `FINANCE\payroll-admin`, created 14:22:58 | |
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

Then answer:

**1. Row 4 carries a warning about `root\default`. What would an analyst who enumerated only `root\subscription` have missed on a host like this one, and why is that exactly the mistake an attacker would want you to make?**

**2. Row 14 describes "a licensed RMM agent installed by the attacker" as persistence. Why is that category harder to detect than any of rows 5–13, and what would you compare against to find it?**

**3. The case found persistence in rows 3 and 4 and nothing in rows 1 and 2 — the two everyone checks. Is that a coincidence, or does it tell you something about the attacker?**

---

### Task 3 — Does a Mechanism That Never Fired Still Count?

**Objective:** Reason about the scheduled task, which was created but returned `0x41303`.

The scheduled task at 14:22:58 has a logon trigger and never executed. The WMI subscription created four seconds later has a binding present and is live.

**Part A.** Decide, with reasons, whether the scheduled task belongs in each of the following:

| Destination | Include? | Reason |
|---|---|---|
| The eradication checklist (must be removed) | | |
| The IOC list distributed for estate-wide hunting | | |
| The Findings section of the incident report | | |
| The Sigma rule set produced by the case | | |

**Part B.** The two mechanisms were created four seconds apart with the same payload. Write the two-sentence note for the report explaining what that timing implies and what it does not.

Then answer:

**1. If you exclude the never-fired task from the IOC list, what specifically becomes undetectable on other hosts? Is that acceptable?**

**2. Chapter §13.2.2 rule 2 says a finding with mixed confidence is more than one finding. Are these two mechanisms one finding or two? Argue it and commit.**

**3. `LastTaskResult 0x41303` means the task has never run. Name one benign reason a legitimate scheduled task could show the same value, and say how you ruled it out here.**

---

### Task 4 — Rebuild or Clean

**Objective:** Apply the §13.5.3 criteria to hosts of different roles and reach a defensible call.

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

Now add a fourth column for **HR-WS17** from the Lab 11 capstone. That case has no intrusion at all. It is an insider exfiltration on a host preserved at offboarding. Work the same eight factors and state what the rebuild-or-clean question even means for a host that is already an image in an evidence locker.

Then answer:

**1. Chapter §13.5.3 says rebuild is the default and cleaning is the exception requiring justification. Did any of your three live hosts genuinely justify cleaning? If you said "clean" anywhere, write the justification as though a reviewer is reading it in six months.**

**2. `10.0.4.17` was domain-joined and unmanaged for 18 months. Which of the eight factors does that single fact move, and by how much?**

**3. The chapter names three host categories where rebuild is mandatory rather than merely preferred. Name them. Then suppose the 14:33 explicit-credential logon had gone to DC02 rather than FILESVR-03 — what changes, and how far does the conversation escalate?**

---

### Task 5 — Credential Rotation, In Order

**Objective:** Sequence rotation so you are not rotating credentials the attacker re-harvests from a host they still control (§13.5.4).

**Part A — Build the rotation list.** For each of the seven categories, state whether it applies here, what specifically is in scope, and when it happens relative to containment and to service restoration.

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

- **`svc-backup`.** It authenticated to WKSTN-221 at 2024-11-14 02:14 UTC, 12 hours before the intrusion, via the `BackupServiceSync` scheduled task. Was that credential exposed? State your reasoning and the confidence level, then say what you would do about it and what it costs the business if you are wrong in either direction.
- **No memory image covers the intrusion window**, so you cannot demonstrate credential material in LSASS. Does the absence of a memory capture from that window make the credential-exposure question *easier* or *harder* to answer conservatively? What does a conservative answer look like in the report?
- **`10.0.4.17` was domain-joined and unmanaged for 18 months.** What does that do to categories 2 and 4?

Then answer:

**1. What specifically goes wrong if you rotate on 14 November at 17:35, before WKSTN-221 is isolated?**

**2. Category 7 is "the category most often forgotten." Name three items in it that plausibly exist in a finance department and would not appear on anyone's rotation list.**

**3. Is `krbtgt` rotation justified in this incident as scoped on 17 November? Argue both sides, then commit to an answer and state what evidence would change it.**

---

### Task 6 — Why Cleaned Hosts Come Back

**Objective:** Pre-mortem the four-day reinfection (§13.5.2).

Chapter §13.5.2 names five causes. For each, assess this incident's exposure and name the specific control in your plan that addresses it.

| Cause | Exposure in IR-2024-11-014 | Which task in your plan addresses it | Residual risk |
|---|---|---|---|
| Missed persistence | | | |
| Unrotated credentials | | | |
| Entry point never closed | | | |
| A second compromised host outside the scope | | | |
| Backup restored from a compromised point | | | |

Then answer:

**1. The chapter says only the first of the five is a forensics failure in the narrow sense, and that the other four are failures of scope, sequencing, or coordination. What follows from that about who needs to be in the eradication planning meeting?**

**2. Chapter §13.5.2 links the fourth cause directly to §13.2.4's Example 3 — the unqualified negative. Reconstruct that chain for this incident: what would an unqualified "no lateral movement identified" have cost here?**

**3. Rank the five causes by your actual exposure on this incident and justify your top one.**

---

### Task 7 — The Verification Pass

**Objective:** Turn §13.5.5's five bullets into executable steps with owners and completion criteria.

Eradication is verified, not declared. Write each of the chapter's five verification steps as a concrete action for **this** incident.

| Step | Concrete action for IR-2024-11-014 | Owner | Done when |
|---|---|---|---|
| Re-hunt the full IOC set across the estate | | | |
| Re-check every persistence location on formerly-compromised hosts | | | |
| Positively test that the entry point is closed | | | |
| Confirm credential rotation actually completed for every item | | | |
| Elevated monitoring for a defined period | | | |

Then write the short paragraph that goes into the incident report as section 6.1, Eradication Verification, recording what you did and what the outcomes were. Dates, not claims.

Then answer:

**1. "Positively test" rather than "assert." For the entry point in this case, what is the difference in practice, and which one is your organization more likely to accept as sufficient?**

**2. The chapter says "partial rotation is common, and it usually surfaces during the next incident." How would you actually confirm completion for category 3 rather than taking someone's word for it?**

**3. The chapter suggests two to four weeks of elevated monitoring with the case's detection content deployed and someone assigned to triage its hits. Which half of that sentence gets skipped in practice, and what happens when it does?**

---

### Task 8 — Reflection

Answer each in 3–5 sentences.

**1. Completeness is not provable**
Eradication asks whether you found all of it, and evidence cannot answer that. How do you write a defensible eradication plan under that constraint?

**2. Rebuild as an assessment against nothing**
The chapter argues that rebuilding from a trusted image does not depend on the completeness of your investigation, and that this is exactly what makes it safer than your own confidence. Do you find that persuasive? Where does it break down?

**3. The analyst in the room**
Four of the five reinfection causes are not forensics failures. What does that mean for how you hand off a case?

**4. Rotation as sequencing**
Credential rotation is conceptually simple and routinely botched. What is the single sequencing error you would most expect to make under pressure, and what would prevent it?

---

## Deliverables Checklist

Your `lab13-notes.md` should contain:

- [ ] **Task 1** — The three eradication questions with confidence levels and reinfection risks, plus three written responses
- [ ] **Task 2** — Full persistence verification checklist, all 15-plus rows, plus three written responses
- [ ] **Task 3** — The never-fired-task decision across four destinations, the timing note, plus three written responses
- [ ] **Task 4** — Rebuild-or-clean scoring for three live hosts plus HR-WS17, with justifications, plus three written responses
- [ ] **Task 5** — Rotation sequence (Part A), the three specific decisions (Part B), plus three written responses
- [ ] **Task 6** — Reinfection pre-mortem across the five causes, plus three written responses
- [ ] **Task 7** — The five verification steps with owners and criteria, the section 6.1 paragraph, plus three written responses
- [ ] **Task 8** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab13/
├── lab13-notes.md  ← Your working notes file (whole lab)
└── Lab13_05/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **Eradication is a completeness check on the investigation.** The question stops being *what happened* and becomes *have I found all of it*.
- **All three eradication questions carry confidence levels.** Any answered Possible or Undetermined is a reinfection risk that belongs in the report by name.
- **Run keys and Services are the two everyone checks.** Scheduled tasks with innocuous names and WMI event subscriptions are the perennial winners, and `root\default` is the namespace people forget.
- **Rebuild is the default, and cleaning is the exception that requires justification.** Rebuild is mandatory for domain controllers, certificate authorities, and backup infrastructure.
- **Rotate in dependency order.** Start with confirmed attacker-used accounts and finish with tokens and certificates, the category most often forgotten. Rotate after containment and before service restoration.
- **No memory image from the intrusion window makes credential exposure harder, not easier.** The conservative answer is to treat everything reachable on the host as known to the attacker, and to say so.
- **Eradication is verified, not declared.** A verification pass with dates and outcomes is a section in the report, not an assertion in a meeting.

---

**Next:** Lab 13.6 — Recovery, Lessons Learned, and the Detection Feedback Loop

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
