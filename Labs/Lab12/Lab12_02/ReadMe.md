# Lab 12.2 — The Ransomware Kill Chain in Windows Artifacts

**Supporting Section 12.2: The Ransomware Kill Chain in Windows Artifacts**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Ransomware does not require new forensics. It requires a different assembly order.

Every stage of a human-operated ransomware intrusion leaves artifacts you already know how to read. The stages are initial access, persistence, credential access, discovery, lateral movement, staging, exfiltration, defense evasion, and encryption. The 4625 burst is the same 4625 burst from Chapter 9. The Prefetch entry is the same Prefetch entry from Chapter 6. What changes is that you now have to know, without hesitation, which artifact evidences which stage. You also have to know which of those artifacts survives an actor who deliberately attacked your evidence before encrypting.

This sub-exercise builds that lookup table against the ACCT-FS01 dataset. For each of the nine stages you will find the artifact in `Data/ACCT-FS01/` that evidences it, record whether it survived the Security log clear at 02:09:41, and note which host it came from. The result is the reference you will use for the rest of Lab 12. More usefully, it is the reference you will rebuild from memory on your first real case.

The single most important column in that table is the survival column.

---

## What This Lab Covers

This lab supports the following concepts from Section 12.2:

| Section | Topic |
|---|---|
| 12.2.1 | Initial access — RDP brute force and its artifact signature |
| 12.2.2 | Persistence — accounts, services, Run keys, scheduled tasks, remote-access tooling |
| 12.2.3 | Credential access — LSASS dumping, hive extraction, Kerberoasting |
| 12.2.4 | Discovery and lateral movement — paired source-side and destination-side artifacts |
| 12.2.5 | Collection and staging — MFT and USN evidence of data gathering |
| 12.2.6 | Exfiltration — pointer forward to 12.5 |
| 12.2.7 | Defense evasion — Defender, shadow copies, backups, log clearing |
| 12.2.8 | Encryption — the USN rename storm and note placement |

---

## Learning Objectives

By completing this lab, you will be able to:

- Map each stage of a ransomware kill chain to the specific Windows artifact that evidences it
- Identify which artifacts survive a Security log clear and which do not
- Distinguish source-side from destination-side lateral-movement artifacts and explain why you want both
- Recognise the persistence set that a ransomware crew installs early and the reason they install it early
- Read a quarantine record as an inventory of the actor's tooling
- Build a stage-to-artifact lookup table you can reuse on a live case
- Explain why collection priority on the next case follows directly from this table

---

## Estimated Time

60–90 minutes

---

## Prerequisites

- Completion of Lab 12.1
- Completion of Labs 04, 05, 06 and 09, or equivalent familiarity with NTFS, registry persistence, execution artifacts, and the event-log hunt pack
- Your `lab12-notes.md` file
- `python3`, PowerShell, or a spreadsheet
- The full [`Data/ACCT-FS01/`](../../../Data/ACCT-FS01/) dataset — this sub-exercise touches nearly every file in it

---

## Scenario

You have won the preservation argument. The disk was imaged at 08:40 and parsed. The outputs were handed to you together with the domain controller's and the jump host's Security logs.

Before you scope anything, you need to know what you are holding: 19 data files, 16 of them CSV, drawn from three hosts. Some contain the whole story of a stage. Some contain a single decisive row. Some contain nothing but benign noise until you know what to filter for.

The actor cleared the Security log on `ACCT-FS01` at **2024-11-12 02:09:41 UTC**. That file now contains 24 rows, and the first of them is the EID 1102 that records its own clearing. Everything before 02:09:41 has to come from somewhere else.

---

## Background: The Chain, and What Survived It

```
Initial Access  →  Persistence  →  Credential Access  →  Discovery
      →  Lateral Movement  →  Collection & Staging  →  Exfiltration
      →  Defense Evasion  →  Encryption
```

The actor worked that chain over six days and then spent 11 minutes attacking the evidence for it. The table shows what they destroyed and where the same fact still lives:

| The actor destroyed | The same fact still lives in |
|---|---|
| Local authentication history on `ACCT-FS01` | `dc-security-evtx.csv`, `terminalservices-evtx.csv` |
| The 4688 for `vssadmin` | `system-evtx.csv` (volsnap 25), `prefetch.csv`, `powershell-evtx.csv` |
| The 4688 for the Defender disable | `defender-evtx.csv`, `registry-runkeys.csv`, `powershell-evtx.csv` |
| The 4688s for staging and exfiltration | `powershell-evtx.csv` (4104), `prefetch.csv`, `amcache.csv`, `shimcache.csv` |
| The staging directory contents | `usn-journal.csv`, `mft.csv` (entries with `InUse=False`) |
| Nothing at all about file activity | `mft.csv`, `usn-journal.csv` — NTFS is untouched by log clearing |

The 4688 for the encryptor itself **does** survive, because the encryptor ran at 02:13:52, four minutes *after* the clear. The actor emptied the log and then wrote fresh evidence into it.

> **IR Reality Check:** A cleared log relocates the investigation. It does not end it. Treat the 1102 as a finding with a time and an account attached, not as a wall.

---

## Lab Tasks

---

### Task 1 — Inventory What You Are Holding

**Objective:** Know the collection before you query it.

Read [`Data/ACCT-FS01/README.md`](../../../Data/ACCT-FS01/README.md), then complete the table. Row counts are one command away, so get them rather than estimating.

```powershell
Get-ChildItem 'Data\ACCT-FS01\*.csv' | ForEach-Object {
    [pscustomobject]@{ File = $_.Name; Rows = (Import-Csv $_.FullName).Count }
} | Sort-Object Rows -Descending
```

```python
import csv, glob, os
for p in sorted(glob.glob('Data/ACCT-FS01/*.csv')):
    with open(p, newline='', encoding='utf-8') as f:
        print(f'{len(list(csv.DictReader(f))):>5}  {os.path.basename(p)}')
```

| File | Rows | Source host | Which stage(s) it evidences |
|---|---|---|---|
| `mft.csv` | | | |
| `usn-journal.csv` | | | |
| `encrypted-files-inventory.csv` | | | |
| `security-evtx.csv` | | | |
| `dc-security-evtx.csv` | | | |
| `jumphost-security-evtx.csv` | | | |
| `system-evtx.csv` | | | |
| `defender-evtx.csv` | | | |
| `terminalservices-evtx.csv` | | | |
| `powershell-evtx.csv` | | | |
| `prefetch.csv` | | | |
| `amcache.csv` | | | |
| `shimcache.csv` | | | |
| `registry-runkeys.csv` | | | |
| `network-flow.csv` | | | |
| `srum.csv` | | | |

Then answer:

**1. Three of these files were collected from a host other than `ACCT-FS01`. Which, and why are they in this folder rather than in their own?**

**2. `security-evtx.csv` is one of the smallest files in the collection. What does its size tell you before you read a single row?**

**3. Which file would you expect to be the largest on a real file server, and roughly by how much? (The dataset README's modelling notes answer this.)**

---

### Task 2 — Initial Access

**Objective:** Establish the artifact signature of an RDP brute force, from two independent hosts.

```python
import csv, collections
def R(n):
    with open(f'Data/ACCT-FS01/{n}', newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))

jump = R('jumphost-security-evtx.csv')
fails = [r for r in jump if r['EventID'] == '4625']
print('4625:', len(fails), fails[0]['TimeCreated'], '→', fails[-1]['TimeCreated'])
for r in jump:
    if r['EventID'] == '4624' and r['UserName'] == 'svc-backup':
        print('SUCCESS', r['TimeCreated'], r['Payload'][:120])
```

| Measure | Value | Source file |
|---|---|---|
| Failed-logon count | | |
| Logon type on the failures | | |
| Source IP | | |
| Target account | | |
| Burst start / end | | |
| Burst duration | | |
| Successful logon time and type | | |
| Independent corroboration on the domain controller | | |

Then answer:

**1. The domain controller records the same burst under a different event ID. Which, what status code, and why does the DC see it at all?**

**2. Chapter 12 §12.2.1 lists five artifact types for RDP initial access. Which of the five are present in this dataset and which are not?**

**3. Service accounts are the classic brute-force target. Give three reasons why, and say which of the three is a password-policy finding rather than an attack finding.**

---

### Task 3 — Persistence

**Objective:** Inventory everything the actor installed to guarantee they could come back.

```python
for r in R('system-evtx.csv'):
    if r['EventID'] == '7045':
        print(r['TimeCreated'], r['Payload'][:110])
for r in R('registry-runkeys.csv'):
    print(r['LastWriteTime'][:19], r['KeyPath'], '|', r['ValueName'], '=', r['ValueData'][:60])
```

| Mechanism | Artifact and file | Established (UTC) | Malicious or benign | Would survive a restore? |
|---|---|---|---|---|
| | | | | |

Include at least six rows. `registry-runkeys.csv` holds nine values, and they are not all malicious. Classifying the benign ones correctly is part of the exercise.

Then answer:

**1. Two services were installed. One is a persistence mechanism and one is a by-product of remote execution. Which is which, and how do you tell?**

**2. The `VaultUpd` service has a display name chosen to survive a glance at `services.msc`. What is it, and what would you do to check whether it is legitimate on a host you did not know?**

**3. One registry value in this set is not itself malicious but is a *finding* because of when it was written. Identify it and explain.**

**4. The Run value points at a file that no longer exists. Why is the value still a remediation item?**

---

### Task 4 — Credential Access

**Objective:** Find the pivot that turned a foothold into a domain problem.

Search `jumphost-security-evtx.csv` for the 4688 records on 2024-11-08, and cross-reference `defender-evtx.csv`.

| Time (UTC) | Technique | Command line or artifact | Source file |
|---|---|---|---|
| | | | |

Then record the consequence:

| Question | Answer | Evidence |
|---|---|---|
| Which account did the actor start with? | | |
| Which account appears later that they did not start with? | | |
| When does the second account first appear? | | |
| Where did it appear *from*? | | |

Then answer:

**1. Defender caught and quarantined something on 2024-11-09. What, when, and why is a quarantine record on the *attacker's* side of the case a gift to the responder?**

**2. Chapter 12 §12.2.3 says the output of the credential-access stage is usually visible as "a change in which account is doing things." Where in this dataset does that change become visible, and how many hours after the dumping did it happen?**

**3. `reg save HKLM\SAM` and `reg save HKLM\SYSTEM` were both run. What does the pair give the actor that either alone does not?**

---

### Task 5 — Discovery and Lateral Movement

**Objective:** Build the paired-artifact table that makes a host-to-host link defensible.

Discovery first. Pull the discovery commands from `jumphost-security-evtx.csv` 4688 records and the PowerShell 4104 records on `ACCT-FS01`, then corroborate with Prefetch.

| Command / tool | Time (UTC) | Host | Corroborating execution artifact |
|---|---|---|---|
| | | | |

Now lateral movement. For each method in the chapter's table, record what this dataset shows.

| Movement method | Source-side artifact (expected) | Destination-side artifact (expected) | Present in this dataset? |
|---|---|---|---|
| RDP | | | |
| SMB / `net use` | | | |
| PsExec-style | | | |
| WMI / WinRM | | | |
| Scheduled task push | | | |

Then complete the specific link:

| Measure | Value | Source file |
|---|---|---|
| 4648 explicit-credential events naming `ACCT-FS01` | | |
| First 4648, and the process that initiated it | | |
| Destination-side service install | | |
| First interactive RDP session on `ACCT-FS01` | | |
| Total RDP session-start records (1149) on `ACCT-FS01` | | |
| How many of those are attacker sessions | | |

Then answer:

**1. Chapter 12 §12.2.4 calls 4648 "one of the highest-value single events in a ransomware case." What three things does a single 4648 record carry?**

**2. The 1149 records include routine administrative connections as well as attacker sessions. What distinguishes them in this dataset, and what would you do if the actor had come from a desktop-range IP instead?**

**3. Two movement methods in your table are present and three are not. Does the absence of the other three mean they were not used? What would you check before saying so in a report?**

---

### Task 6 — Collection, Staging, and Exfiltration

**Objective:** Locate the stages that produce almost no event-log evidence at all.

Staging is an NTFS story. Query the USN Journal for the staging directory and the MFT for the archives.

```python
usn = R('usn-journal.csv')
wu = [r for r in usn if r['ParentPath'] == 'Windows\\Temp\\wu']
print('USN records in staging dir:', len(wu))
arch = [r for r in R('mft.csv') if r['FileName'].startswith('acct-fs01-data.7z.')]
print('archive volumes:', len(arch), 'bytes:', sum(int(r['FileSize']) for r in arch))
```

| Measure | Value | Source file |
|---|---|---|
| Staging directory path | | |
| USN records in that directory | | |
| Archive volumes | | |
| Total staged bytes | | |
| Archiver used, and its execution evidence | | |
| Transfer tool used, and its execution evidence | | |
| Command line for the archive step | | |
| Command line for the transfer step | | |

Then answer:

**1. The staging directory path was chosen to look like something legitimate. What, and what is the one-line check that separates it from the real thing?**

**2. Both command lines survive in a channel the actor did not clear. Which channel, which event ID, and why do actors so consistently forget it exists?**

**3. Exfiltration is developed fully in 12.5. Name the two artifacts already visible here that will carry that analysis, and the one artifact whose absence will cap your confidence.**

---

### Task 7 — Defense Evasion

**Objective:** Recognise the signature set, in order.

Build the ordered sequence. Every step must be evidenced by something other than a surviving 4688 unless you can show otherwise.

| # | Time (UTC) | Action | Evidencing artifact(s) | 4688 survived? |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |
| 6 | | | | |
| 7 | | | | |
| 8 | | | | |

Then measure it:

| Measure | Value |
|---|---|
| First evasion action | |
| First encrypted file | |
| Elapsed between them | |
| Log clear → first encrypted file | |
| Account named in the 1102 | |
| Number of `volsnap` EID 25 records | |
| Result of `vssadmin list shadows` at triage | |

Then answer:

**1. The Defender exclusion for the staging directory was added at 21:52 on 2024-11-11, and real-time protection was not disabled until 02:02 the next morning. What does that ordering tell you about the actor's operational discipline?**

**2. Chapter 12 §12.2.7 says log clearing "cannot be hidden." Why not, and what two findings does the single 1102 record establish simultaneously?**

**3. Read the `Description` field of the four `volsnap` EID 25 records. It attributes the deletion to shadow copy storage failing to grow — not to a command. Given that, what does the EID 25 cluster actually establish on its own, what has to be paired with it before you can say a deletion command ran, and what does the count of four tell you about the host's recovery posture before the attack?**

---

### Task 8 — Encryption

**Objective:** Close the chain with the stage that generates the most evidence and the least insight.

| Measure | Value | Source file |
|---|---|---|
| Encryptor binary path | | |
| 4688 time and full command line | | |
| Account it ran as | | |
| Prefetch entry and RunCount | | |
| Previous-run values in Prefetch | | |
| Amcache SHA-1 and publisher field | | |
| ShimCache `Executed` value | | |
| When the binary arrived on disk | | |
| When the binary was deleted | | |

Then answer:

**1. The encryptor's Prefetch entry has a RunCount but no previous-run values. What does that mean, and why is Chapter 12 §12.2.8's warning about Prefetch flushing relevant to how you phrase the local-execution finding?**

**2. The Amcache publisher field for the encryptor differs from every other binary in that file. How, and what is the value of that observation?**

**3. `shimcache.csv` has `Executed = NA` on every row. Why, and what does a ShimCache row therefore prove?**

---

### Task 9 — Build the Kill-Chain Lookup Table

**Objective:** Consolidate everything above into the reference you will use for the rest of Lab 12.

| Stage | Artifact(s) in this dataset | Source host | Survived the log clear? | What it proves |
|---|---|---|---|---|
| Initial access | | | | |
| Persistence | | | | |
| Credential access | | | | |
| Discovery | | | | |
| Lateral movement | | | | |
| Collection and staging | | | | |
| Exfiltration | | | | |
| Defense evasion | | | | |
| Encryption | | | | |

Then answer:

**1. Which stages have evidence *only* from sources outside `ACCT-FS01`? What does that tell you about collection priorities on the next case?**

**2. Which single artifact class in your table would you least want to lose, and what would you no longer be able to say without it?**

**3. Rank the nine stages by how much evidence each left behind. Then rank them by investigative value. Explain why the two rankings are close to inverted.**

---

### Task 10 — Reflection

Answer the following in 3–5 sentences each.

**1. Same artifacts, different order**
Chapter 12 says ransomware "does not require new forensics, only a different assembly order." Having built the table, do you agree? What, if anything, is genuinely new?

**2. The survival column**
Why is "did this survive the log clear?" a more useful column than "what event ID is this?" on a ransomware case?

**3. Off-host telemetry**
Three of the most load-bearing sources in this case were outside the actor's reach. What does that argue about EDR, log forwarding, and where an organisation should spend its next detection dollar?

**4. Evidence the actor left for you**
Defender's quarantine records named the actor's tooling days before Defender was switched off. What does that pattern suggest about how you should read *any* security product's history on a compromised host?

---

## Deliverables Checklist

Your `lab12-notes.md` should contain:

- [ ] **Task 1** — Collection inventory with row counts, source hosts, and stages
- [ ] **Task 2** — Initial-access signature table with independent corroboration
- [ ] **Task 3** — Persistence inventory, at least six rows, benign values classified correctly
- [ ] **Task 4** — Credential-access table plus the account-pivot record
- [ ] **Task 5** — Discovery commands, lateral-movement method table, and the specific host-to-host link
- [ ] **Task 6** — Staging and transfer-tool artifact set
- [ ] **Task 7** — Ordered defense-evasion sequence, at least six steps, with interval measurements
- [ ] **Task 8** — Encryption artifact table
- [ ] **Task 9** — Consolidated nine-stage kill-chain lookup table
- [ ] **Task 10** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab12/
├── lab12-notes.md  ← Your working notes file (whole lab)
└── Lab12_02/
    └── ReadMe.md       ← This file
```

Backing data: [`Data/ACCT-FS01/`](../../../Data/ACCT-FS01/) — all 19 data files.

---

## Key Takeaways

- **Every stage leaves something.** The chain is only invisible if you do not know which artifact family evidences which stage.
- **The survival column is the one that matters.** On a case where the actor attacked your evidence, knowing where a destroyed fact still lives is worth more than knowing the event ID it used to have.
- **Paired artifacts make a link defensible.** A 4648 on the source host and a service install on the destination are the same event seen twice. Either alone is a hypothesis.
- **PowerShell 4104 is the actor's blind spot.** Every command line the Security log lost survived in the script-block log, because actors clear `Security` and forget the operational channels.
- **Quarantine records are an inventory of the actor's toolkit.** Defender named Mimikatz and a network scanner days before it was disabled, corroborating two stages whose 4688s are gone.
- **The encryptor's own 4688 survived the clear.** The actor emptied the log at 02:09:41 and ran the encryptor at 02:13:52. Sequence matters more than intent.

---

**Next:** Lab 12.3 — Scoping the Encryption

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
