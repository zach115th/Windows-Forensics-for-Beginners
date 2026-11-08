# Lab 12.4 — Finding Patient Zero and the Dwell Window

**Supporting Section 12.4: Finding Patient Zero and the Dwell Window**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Finding the entry point is the core forensic work of a ransomware case. It decides whether the organisation's recovery succeeds or hands the environment straight back.

The technique is backwards chaining. Start at the event you are certain about — the encryption — and walk the evidence toward the entry point, one confirmed link at a time. Each answer becomes the next anchor. The process gives you an account, the account gives you an authentication trail, that trail gives you a source IP, and the source IP gives you another host. You repeat the process on each host until you reach one whose earliest actor activity has an external source.

The obstacle is what makes this sub-exercise instructive. The actor cleared the Security log on `ACCT-FS01` at **02:09:41 UTC**, four and a half minutes before encryption began. Only 24 rows survive, and the first of them is the record of its own clearing. There is no local authentication history for the entire six-day dwell window.

The clear relocates the investigation rather than ending it. You will rebuild the whole chain from sources the actor did not touch: the domain controller, the jump host, four operational channels, NTFS, and execution artifacts. Then you will write the dwell-window sentence in the only defensible form, with its log-retention boundary attached.

---

## What This Lab Covers

This lab supports the following concepts from Section 12.4:

| Section | Topic |
|---|---|
| 12.4.1 | Anchoring on the encryptor — process, account, delivery time |
| 12.4.2 | Following the account backwards across the environment |
| 12.4.3 | Crossing the host boundary and repeating at each hop |
| 12.4.4 | Reaching the edge and confirming the entry point independently |
| 12.4.5 | Working around the cleared log |

---

## Learning Objectives

By completing this lab, you will be able to:

- Anchor an investigation on a certain event and derive the next pivot from each answer
- Build an account-centric timeline that spans hosts rather than sitting on one
- Recognise the point at which a service account's behaviour diverges from its established baseline
- Cross a host boundary using paired source-side and destination-side artifacts
- Confirm an entry point with independent evidence rather than a single log entry
- Enumerate the evidence sources that survive a Security log clear and state what each contributes
- Write a dwell-window statement that carries its own retention boundary

---

## Estimated Time

75–110 minutes

---

## Prerequisites

- Completion of Labs 12.1, 12.2 and 12.3
- Completion of Labs 09 and 10, or equivalent familiarity with the event-log hunt pack and multi-source timeline construction
- Your `lab12-notes.md` file
- `python3`, PowerShell, or a spreadsheet
- From [`Data/ACCT-FS01/`](../../../Data/ACCT-FS01/): `security-evtx.csv`, `dc-security-evtx.csv`, `jumphost-security-evtx.csv`, `terminalservices-evtx.csv`, `system-evtx.csv`, `prefetch.csv`, `mft.csv`, `usn-journal.csv`

Preamble for the Python blocks, run from the repository root:

```python
import csv, collections
def R(name):
    with open(f'Data/ACCT-FS01/{name}', newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))
```

---

## Scenario

Scoping is delivered. The 09:00 update went out with the blast-radius numbers and the encryption window. The next question is the one the business needs answered before it restores anything:

> *How did they get in, when, and is that path still open?*

You know the encryption started at 2024-11-12 02:14:06 UTC. You know almost nothing about how the actor got far enough to run it. The actor emptied the log that would have told you four and a half minutes earlier.

You have the domain controller's Security log, the jump host's Security log, and every operational channel on `ACCT-FS01`. Start at the encryptor and work backwards.

---

## Background: Backwards Chaining, and the Hole in the Middle

Backwards chaining works because each confirmed fact generates the next question:

```
Encryptor  →  which process?   →  which account?   →  where did the binary come from?
Account    →  which logons?    →  from which host? →  what ran there?
Host       →  which logons?    →  from where?      →  external source → entry point
```

In this case the chain runs `ACCT-FS01` → jump host → internet and ends at a brute force from an external address.

What the log clear removed, and where the same fact still lives:

| Removed from `ACCT-FS01` | Still available in |
|---|---|
| 4624 / 4625 authentication history | `dc-security-evtx.csv` (Kerberos and NTLM validation), `terminalservices-evtx.csv` (1149 / 21 / 22 / 23 / 25) |
| 4648 explicit-credential use | `jumphost-security-evtx.csv` — the *source* side of the same events |
| 4688 process creation before 02:09:41 | `powershell-evtx.csv` 4104, `prefetch.csv`, `amcache.csv`, `shimcache.csv` |
| Any record of file activity | `mft.csv`, `usn-journal.csv` — log clearing does not touch NTFS |
| Per-application network usage | `srum.csv` |

The 1102 record itself is evidence. It names the account that cleared the log and the second it happened.

> **IR Reality Check:** Never report a dwell window bounded by the oldest surviving log without saying so. "Earliest observed activity: X; log retention begins Y; earlier activity cannot be excluded" is a longer sentence and a defensible one.

---

## Lab Tasks

---

### Task 1 — Anchor on the Encryptor

**Objective:** Convert the one thing you are certain about into three new pivots.

```python
sec = R('security-evtx.csv')
for r in sec:
    if r['EventID'] == '4688' and 'vault.exe' in r['Payload']:
        print(r['TimeCreated'], r['UserName'], r['Payload'])
usn = R('usn-journal.csv')
for r in usn:
    if r['FileName'] == 'vault.exe':
        print(r['UpdateTimestamp'], r['ParentPath'], r['UpdateReasons'])
```

| Question | Answer | Source |
|---|---|---|
| What process performed the encryption? | | |
| What was its full command line? | | |
| What account did it run as? | | |
| Did it hold elevated privilege? | | |
| When did the binary arrive on disk? | | |
| How did it arrive? | | |
| Elapsed between arrival and execution | | |
| When was it deleted? | | |

Then answer:

**1. Apart from the bare `-enc` switch, the command line passes four parameters that take values. Name each and say what it independently confirms about findings you made in Lab 12.3.**

**2. The binary's arrival time is a new pivot. What question does it open, and which artifact would you go to next to answer it?**

**3. A 4672 appears in the same second as the 4688. What privileges does it list, and why does `SeBackupPrivilege` matter specifically on a file server?**

---

### Task 2 — Establish the Account's Baseline

**Objective:** Before you can say behaviour diverged, you have to say what it diverged *from*.

`svc-backup` is a service account with a legitimate job. Establish what that job looks like in the domain controller's log.

```python
dc = R('dc-security-evtx.csv')
base = [r for r in dc if r['EventID'] == '4769'
        and r['UserName'] == 'svc-backup' and 'BKP-SRV' in r['Payload']]
print('baseline records:', len(base))
print('earliest:', base[0]['TimeCreated'], 'latest:', base[-1]['TimeCreated'])
print(collections.Counter(r['TimeCreated'][11:19] for r in base).most_common())
```

| Measure | Value |
|---|---|
| Baseline event ID and what it represents | |
| Number of baseline records | |
| Target services | |
| Times of day they occur | |
| Date range covered | |
| Ticket encryption type on the baseline records | |

Write the account's normal pattern in one sentence, of the form: *"`svc-backup` normally does X, against Y, at Z, every day."*

Then answer:

**1. Why is establishing the baseline from the domain controller rather than from `ACCT-FS01` the only option available here?**

**2. What would you have done if the DC log did not go back far enough to establish a baseline?**

**3. Baseline records are noise on most cases. Why are they load-bearing evidence on this one?**

---

### Task 3 — Follow the Account Backwards

**Objective:** Build the account-centric timeline and find the divergence point.

Pull every record for `svc-backup` across `dc-security-evtx.csv`, `jumphost-security-evtx.csv` and `terminalservices-evtx.csv`, sort by time, and build the timeline. **Include at least 12 rows** and cover 2024-11-01 to 2024-11-12.

| Time (UTC) | Event ID | Host | Logon type / detail | Normal or anomalous | Why |
|---|---|---|---|---|---|
| | | | | | |

Then isolate the non-baseline activity:

```python
other = [r for r in dc if r['EventID'] == '4769'
         and r['UserName'] == 'svc-backup' and 'BKP-SRV' not in r['Payload']]
for r in other:
    print(r['TimeCreated'], r['Payload'][:120])
```

| Time (UTC) | Service requested | Source IP | What it indicates |
|---|---|---|---|
| | | | |

Then record the divergence:

| Question | Answer |
|---|---|
| Exact timestamp at which behaviour diverges from baseline | |
| What the account did that it had never done before | |
| From which host | |
| How long after the divergence did the first non-baseline service ticket appear | |

Then answer:

**1. A service account whose normal pattern is a nightly ticket request against three backup servers suddenly performs a RemoteInteractive logon on a jump host. Why is that single fact close to conclusive on its own?**

**2. The non-baseline service tickets name the file server and the domain controller. Reading them in order, describe what the actor was doing on each date.**

**3. Which of these records would you have missed if you had only pulled 4624 and 4625 and ignored Kerberos?**

---

### Task 4 — The Second Account

**Objective:** Find the evidence of a compromise on a host you have not looked at.

```python
for r in sorted((r for r in dc if r['UserName'] == 'a-mbrennan'),
                key=lambda r: r['TimeCreated']):
    print(r['TimeCreated'], r['EventID'], r['Payload'][:110])
```

| Time (UTC) | Event ID | Detail | Source IP |
|---|---|---|---|
| | | | |

| Question | Answer |
|---|---|
| How many records exist for this account in the DC log? | |
| What kind of account is it? | |
| When does it first appear? | |
| From which IP? | |
| Which host is that IP? | |
| Which privileges does the 4672 list? | |
| What is the last thing it does, and against which host? | |

Then answer:

**1. This account appears from the jump host's IP. What does that tell you happened on the jump host, and roughly when?**

**2. How many hours separate the credential-access activity you found in Lab 12.2 from this account's first appearance? What does that interval suggest about the actor's workflow?**

**3. The account's final record targets a backup server. Why is that the single most alarming row in this table, and which of the four recovery assessments in 12.6 does it feed?**

---

### Task 5 — Cross the Host Boundary

**Objective:** Document each hop with paired evidence.

The chain runs `ACCT-FS01` → jump host → internet. For each hop, name the source-side and destination-side artifact.

| Hop | From | To | Source-side artifact | Destination-side artifact | Time (UTC) |
|---|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |

Supporting detail for hop 1:

```python
jump = R('jumphost-security-evtx.csv')
for r in jump:
    if r['EventID'] == '4648':
        print(r['TimeCreated'], r['Payload'][:150])
for r in R('terminalservices-evtx.csv'):
    if r['EventID'] == '1149':
        print(r['TimeCreated'], r['UserName'], r['Payload'][:100])
```

| Measure | Value |
|---|---|
| 4648 events naming `ACCT-FS01` as the target server | |
| Their timestamps | |
| Process that initiated the first one | |
| Corresponding destination-side service install | |
| RDP session-start records (1149) on `ACCT-FS01` | |
| How many are actor sessions, and their dates | |
| Session reconnect (EID 25), and what was happening at that moment | |
| Final actor session logoff | |

Then answer:

**1. Chapter 12 §12.4.3 suggests checking the `Terminal Server Client\Servers` registry key and the RDP bitmap cache on the source host. Neither is in this dataset. What would each have added, and how would you request them?**

**2. The 1149 records include routine administrative sessions. What distinguishes the actor's, and would that distinction hold if the actor had pivoted through a desktop first?**

**3. One of the actor's RDP sessions shows a reconnect rather than a fresh logon. What was in flight at that moment, and why is a reconnect a plausible artifact of it?**

---

### Task 6 — Confirm the Entry Point

**Objective:** Turn a hypothesis into a finding using independent evidence.

```python
fails = [r for r in jump if r['EventID'] == '4625']
print('4625:', len(fails), fails[0]['TimeCreated'], '→', fails[-1]['TimeCreated'])
print('DC 4776 failures:',
      sum(1 for r in dc if r['EventID'] == '4776' and '0xC000006A' in r['Payload']))
print('DC 4776 successes:',
      sum(1 for r in dc if r['EventID'] == '4776' and '0xC000006A' not in r['Payload']))
```

| Measure | Value | Source |
|---|---|---|
| Failed-logon count on the jump host | | |
| Logon type on the failures | | |
| Burst start / end | | |
| Burst duration | | |
| Source IP | | |
| Target account | | |
| Successful logon time and type | | |
| Independent corroboration #1 — count and event ID | | |
| Independent corroboration #2 | | |
| First command run after the successful logon | | |

Then apply the chapter's four confirmation criteria:

| Criterion | Satisfied? | Evidence or gap |
|---|---|---|
| Perimeter firewall / VPN logs showing inbound 3389 | | |
| TerminalServices RCM 1149 recording the source IP | | |
| Netflow showing the connection and its duration | | |
| Absence of a competing explanation | | |

Then answer:

**1. Two of the four criteria cannot be satisfied from this dataset. Which, and how does that change how you phrase the entry-point finding?**

**2. Two hosts record the same 212 failures under two different event IDs. Why is that pair worth more than 424 records from one source?**

**3. The actor ran two commands within two and a half minutes of the successful logon. What were they, and what do they tell you about whether this was automated or hands-on-keyboard?**

---

### Task 7 — Work Around the Cleared Log

**Objective:** Enumerate what survived and what each source contributed.

```python
print('security-evtx.csv rows:', len(sec))
print('earliest:', sec[0]['TimeCreated'], 'EID', sec[0]['EventID'], sec[0]['UserName'])
```

| Surviving source | File in this dataset | What it contributed to this sub-exercise |
|---|---|---|
| Domain controller logs | | |
| Jump host logs | | |
| TerminalServices operational channel | | |
| PowerShell operational channel | | |
| Defender operational channel | | |
| System channel | | |
| MFT and USN Journal | | |
| Prefetch / Amcache / ShimCache | | |
| SRUM | | |
| Volume shadow copies | | |
| EDR telemetry | | |

Two rows in that table should be marked unavailable. Identify them and say what you lost.

Then record the 1102 itself:

| Measure | Value |
|---|---|
| Time of the clear | |
| Account named | |
| Rows surviving in the log | |
| Interval from clear to encryptor execution | |
| Which of the actor's own actions were therefore recorded | |

Then answer:

**1. What two separate findings does the single 1102 record establish?**

**2. The actor cleared the log and then produced fresh evidence into it. List the surviving 4688s and say what each one would have cost you if the clear had happened five minutes later.**

**3. Chapter 12 §12.4.5 lists operational channels as "cleared far less often because attackers forget they exist." Which channel in this dataset was most valuable, and what specifically would you have been unable to state without it?**

---

### Task 8 — State the Dwell Window

**Objective:** Write the sentence a report can carry verbatim.

First establish the retention boundaries — the earliest record in each log you are relying on. Do not take these from any summary. Read them from the files.

```python
for name in ('dc-security-evtx.csv', 'jumphost-security-evtx.csv',
             'terminalservices-evtx.csv', 'security-evtx.csv'):
    rows = R(name)
    print(f'{name:<32} {min(r["TimeCreated"] for r in rows)}')
```

| Log | Earliest surviving record | What that bounds |
|---|---|---|
| `dc-security-evtx.csv` | | |
| `jumphost-security-evtx.csv` | | |
| `terminalservices-evtx.csv` | | |
| `security-evtx.csv` | | |

Now write the dwell-window statement. It must contain:

- Earliest **observed** actor activity, with its source
- The end of the intrusion, with its source
- The elapsed dwell time
- The retention boundary of the log that carries the earliest observation
- An explicit statement that earlier activity cannot be excluded

Write it as one or two sentences, in a form you would paste directly into a report.

Then answer:

**1. Chapter 12 §12.4.5's field composite describes a team whose "clean" backup contained the actor's scheduled task, because they reported a dwell window bounded by their oldest surviving log. What is the one sentence that would have saved them?**

**2. Two of the logs you checked start on different dates. Which one bounds your dwell-window claim, and why is it not simply the earliest of the four?**

**3. Someone asks you to "just give a number" for dwell time. Give it, and then give the sentence that has to accompany it.**

---

### Task 9 — Reflection

Answer the following in 3–5 sentences each.

**1. One confirmed link at a time**
Why does backwards chaining produce a more defensible result than searching forward from the earliest suspicious event you can find?

**2. The domain controller as backbone**
Why is the DC Security log the single highest-priority collection on day one of a ransomware case, and what does that imply about your first phone call?

**3. Baselines make anomalies**
The divergence in `svc-backup`'s behaviour is only visible because 36 unremarkable records established what normal looked like. What does that argue about how much log retention is enough?

**4. Honest boundaries**
Attaching a retention boundary to a dwell window makes the finding sound weaker. Explain why it makes the report stronger.

---

## Deliverables Checklist

Your `lab12-notes.md` should contain:

- [ ] **Task 1** — Encryptor anchor table with command line, account, and binary arrival
- [ ] **Task 2** — Account baseline table and the one-sentence normal pattern
- [ ] **Task 3** — Account-centric timeline, at least 12 rows, with the divergence point identified
- [ ] **Task 4** — Second-account table and its implications
- [ ] **Task 5** — Host-hop table with paired source-side and destination-side artifacts
- [ ] **Task 6** — Entry-point confirmation table plus the four-criterion assessment
- [ ] **Task 7** — Surviving-source table with two rows marked unavailable, and the 1102 detail
- [ ] **Task 8** — Retention-boundary table and the verbatim dwell-window statement
- [ ] **Task 9** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab12/
├── lab12-notes.md  ← Your working notes file (whole lab)
└── Lab12_04/
    └── ReadMe.md       ← This file
```

Backing data: [`Data/ACCT-FS01/`](../../../Data/ACCT-FS01/) — principally `dc-security-evtx.csv`, `jumphost-security-evtx.csv` and `terminalservices-evtx.csv`.

---

## Key Takeaways

- **Anchor on certainty and walk backwards.** The encryption is the one event you cannot be wrong about. Every answer it yields is the next question.
- **A baseline is what makes an anomaly visible.** The 36 boring nightly records are the reason one RemoteInteractive logon reads as an intrusion rather than as noise.
- **Cross host boundaries with paired evidence.** Source-side and destination-side artifacts for the same hop turn a hypothesis into a finding.
- **Two hosts recording the same burst is worth more than one host recording it twice.** Independent corroboration is the difference between a log entry and a conclusion.
- **A cleared log relocates the investigation.** The domain controller, the jump host, four operational channels, NTFS, execution artifacts and SRUM all survived. The encryptor's own 4688 survived too, because it ran after the clear.
- **Report the retention boundary with the dwell window.** The longer sentence is the defensible one, and the shorter one is how organisations restore into their own compromise.

---

**Next:** Lab 12.5 — Did They Steal Data Before Encrypting?

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
