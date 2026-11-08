# Lab 12.5 — Did They Steal Data Before Encrypting?

**Supporting Section 12.5: Did They Steal Data Before Encrypting?**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Exfiltration is the question with the shortest legal fuse and the hardest evidence.

Encryption is loud. It rewrites hundreds of files, drops a note in every directory, and leaves a USN signature you can read off a histogram. Exfiltration is quiet. At the packet level, a few tens of gigabytes leaving over HTTPS looks like a backup job. On this host, a real backup job moves nearly six times as much data every night.

The actor's cleanup targets exactly the artifacts that would prove the transfer. The staging directory, the transfer tool, and its configuration are all deleted. The tool's log was never written.

You will be asked a binary question. *Was data exfiltrated, yes or no?* The honest answer is a confidence statement. This sub-exercise builds one that is neither an overclaim nor useless.

You will reconstruct a staging directory that no longer exists from NTFS records alone. You will assemble the transfer-tool artifact set from four independent execution sources and bound the egress from two independent volume measurements. You will rule out the legitimate transfer that dwarfs the malicious one. Then you will write the finding at the tier the evidence supports, stopping one tier short of where it almost reaches.

---

## What This Lab Covers

This lab supports the following concepts from Section 12.5:

| Section | Topic |
|---|---|
| 12.5.1 | Why the exfiltration question is hard to answer cleanly |
| 12.5.2 | Staging evidence — USN, MFT, Recycle Bin, archiver execution |
| 12.5.3 | Transfer-tool artifacts — rclone, WinSCP, cloud-sync clients |
| 12.5.4 | Egress volume analysis — SRUM, flow records, proxy logs, sanity checks |
| 12.5.5 | Answering honestly when the evidence is partial — the five tiers |

---

## Learning Objectives

By completing this lab, you will be able to:

- Reconstruct a deleted staging directory from USN Journal and MFT records
- Identify the artifact that names *what* was collected when the archives themselves are gone
- Assemble a transfer-tool artifact set spanning Prefetch, Amcache, ShimCache, MFT, and a recovered configuration file
- Bound egress volume from two independent host- and network-side sources and sanity-check them against the staged set
- Distinguish actor infrastructure from legitimate high-volume destinations without relying on volume
- Apply the five-tier confidence language consistently and justify the tier you chose
- Explain the difference between "no evidence found" and "cannot be determined" to a non-technical audience

---

## Estimated Time

75–110 minutes

---

## Prerequisites

- Completion of Labs 12.1 through 12.4
- Completion of Labs 04, 06, 08 and 11, or equivalent familiarity with NTFS, execution artifacts, flow analysis, and tiered confidence language
- Your `lab12-notes.md` file
- `python3`, PowerShell, or a spreadsheet
- From [`Data/ACCT-FS01/`](../../../Data/ACCT-FS01/): `usn-journal.csv`, `mft.csv`, `powershell-evtx.csv`, `prefetch.csv`, `amcache.csv`, `shimcache.csv`, `network-flow.csv`, `srum.csv`, `rclone-conf-recovered.txt`, `registry-runkeys.csv`

Preamble for the Python blocks, run from the repository root:

```python
import csv, collections
def R(name):
    with open(f'Data/ACCT-FS01/{name}', newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))
```

---

## Scenario

Counsel has asked the question twice now, both times in the same words: *"Yes or no, did they take anything?"*

The ransom note claims 34 GB of accounting, finance, HR and legal data. That is the actor's number, printed in a document designed to make the victim pay. It is worth nothing as evidence until your own artifacts support it.

The actor deleted the staging directory `C:\Windows\Temp\wu\` and everything in it at 2024-11-12 03:41:22 UTC. The transfer tool went with it. There are no proxy logs for the window. There is no memory image, because nobody captured one before you arrived.

What you do have is NTFS, four execution-artifact sources, the PowerShell script-block log the actor forgot about, a configuration file recovered from unallocated space, and two independent measurements of bytes leaving the host.

---

## Background: Quiet Evidence, Loud Confounders

The exfiltration half of a ransomware case fails in two directions:

- **Overclaiming.** Reporting "34 GB of payroll data was exfiltrated" because the note said so, or because a staging directory existed. Counsel scopes notification from your sentence. A sentence that outruns the evidence has consequences that outlast the engagement.
- **Uselessness.** Reporting "we cannot rule out exfiltration" when you have staging evidence, tool execution, and matching egress volume. That is a real finding phrased as a shrug.

The five tiers exist to make the middle ground sayable:

| Statement | Evidentiary basis |
|---|---|
| **Confirmed** | Direct evidence of transfer with named data and volume, such as a transfer log listing files, corroborated by egress volume |
| **Highly likely** | Staging plus tool execution plus egress volume consistent with the staged set, without a per-file record |
| **Possible / cannot be excluded** | Staging or tool presence, no corroborating egress data |
| **No evidence found** | The relevant sources were available and reviewed, and showed nothing |
| **Cannot be determined** | The relevant sources were unavailable — cleared, rolled over, or never collected |

The last two are different statements. Conflating them is one of the most consequential errors in ransomware reporting.

> **IR Reality Check:** The actor's claim is not evidence. If the leak site publishes a file tree next week, treat it as a lead to verify against your own artifacts — not as a finding.

---

## Lab Tasks

---

### Task 1 — Reconstruct the Deleted Staging Directory

**Objective:** Rebuild a directory that no longer exists, from the file-system record.

```powershell
$usn = Import-Csv 'Data\ACCT-FS01\usn-journal.csv'
$wu  = $usn | Where-Object { $_.ParentPath -eq 'Windows\Temp\wu' }
"USN records : {0}" -f $wu.Count
$wu | Where-Object { $_.UpdateReasons -like '*FileDelete*' } |
  Select-Object UpdateTimestamp, FileName
```

```python
usn = R('usn-journal.csv')
wu = [r for r in usn if r['ParentPath'] == 'Windows\\Temp\\wu']
print('USN records in staging dir:', len(wu))
for r in wu:
    if 'FileDelete' in r['UpdateReasons']:
        print(' ', r['UpdateTimestamp'], r['FileName'])
```

| Measure | Value | Source |
|---|---|---|
| Staging directory path | | |
| When was the directory created? | | |
| Total USN records in the directory | | |
| Number of deletion records | | |
| When was the directory deleted? | | |
| Archive volumes present | | |
| Total staged bytes | | |
| Same, in GiB | | |
| What else was in the directory besides the archives? | | |
| Do the MFT entries still exist? What is their `InUse` value? | | |

Now bin the staging burst the way you binned the encryption in Lab 12.3:

```python
staging = [r for r in usn
           if '2024-11-11 21:14' <= r['UpdateTimestamp'][:16] <= '2024-11-11 22:38']
sb = collections.Counter(r['UpdateTimestamp'][:16] for r in staging)
print('records:', len(staging), 'bins:', len(sb),
      'min/max per minute:', min(sb.values()), max(sb.values()))
```

| Measure | Value |
|---|---|
| Staging start / end | |
| Duration | |
| Records in the burst | |
| Minute bins | |
| Records per minute, min / max | |
| Ratio of this amplitude to the encryption plateau | |

Then answer:

**1. The same binning technique that found the encryption window found this burst four hours before anyone was looking for it. What does that argue about running the technique as a default rather than as a targeted query?**

**2. The staging directory path was chosen to resemble a legitimate Windows path. Which, and what is the check that separates it from the real thing?**

**3. Every file in this directory was deleted. Which two artifacts still carry the file names and sizes, and why is log clearing irrelevant to both?**

---

### Task 2 — Find Out What Was Actually Collected

**Objective:** The archive volumes tell you the size of the staged set. They do not tell you its contents.

```python
for r in R('powershell-evtx.csv'):
    if '7z.exe' in r['Payload']:
        print(r['TimeCreated'], r['Payload'])
```

| Measure | Value |
|---|---|
| Event ID and channel carrying the command | |
| Timestamp | |
| Archiver invoked, and from where | |
| Volume-size switch and what it means | |
| Compression and header-encryption switches | |
| Output archive base name | |
| Source directories named | |

Now map each source directory back to the encryption scope:

| Source directory in the archive command | Encrypted file count in that tree | Data categories it holds | Notification relevance |
|---|---|---|---|
| | | | |

Use `encrypted-files-inventory.csv` for the middle column — the encrypted directories sit under these trees.

Then answer:

**1. The staged file names are archive volumes, not document names. What does that cost you when counsel asks which records were affected, and what partially compensates?**

**2. Compare the source directories in the archive command against the ransom note's claim about which data was taken. Do they agree? What does agreement prove, and what does it not?**

**3. The archiver's execution is independently confirmed by an execution artifact. Which, with what run count, and what do the run count and previous-run time together suggest about how many attempts were made?**

---

### Task 3 — Build the Transfer-Tool Artifact Set

**Objective:** Assemble everything that evidences the tool, from five independent sources.

```python
for r in R('prefetch.csv'):
    if r['ExecutableName'] == 'RCLONE.EXE':
        print('PF ', r['RunCount'], r['LastRun'], r['PreviousRun0'])
for r in R('amcache.csv'):
    if 'rclone' in r['FullPath'].lower():
        print('AM ', r['FullPath'], r['Sha1'], r['Publisher'], r['Created'])
for r in R('shimcache.csv'):
    if 'rclone' in r['Path'].lower():
        print('SC ', r['Path'], r['LastModifiedTimeUTC'], 'Executed=' + r['Executed'])
```

| Artifact | What it shows | Value |
|---|---|---|
| Prefetch | | |
| Amcache | | |
| ShimCache | | |
| MFT | | |
| USN Journal | | |
| Recovered configuration | | |
| Command line | | |
| Persistence reference | | |
| SRUM attribution | | |

Now read [`Data/ACCT-FS01/rclone-conf-recovered.txt`](../../../Data/ACCT-FS01/rclone-conf-recovered.txt) and extract:

| Field from the config | Value |
|---|---|
| Remote name | |
| Transfer protocol | |
| Endpoint URL and port | |
| Remote username | |
| How the file was recovered | |
| What the config says is *absent* from the invocation | |

Then answer:

**1. Why does Chapter 12 §12.5.3 call the configuration file "the highest-value single artifact in an exfiltration case"?**

**2. The remote name in the config appears in a second artifact elsewhere in this dataset. Where, and why does that cross-reference matter more than either artifact alone?**

**3. The transfer tool is a legitimate open-source utility with a real publisher string in Amcache. How do you distinguish malicious use from an administrator who happens to use the same tool? Name three checks.**

**4. Chapter 12 §12.5.3 notes these tools are frequently renamed to blend in. If this binary had been called `svchost.exe`, which two artifacts in your table would still have identified it?**

---

### Task 4 — Bound the Egress

**Objective:** Measure how much left, from two independent sources.

```powershell
$flow = Import-Csv 'Data\ACCT-FS01\network-flow.csv'
$ex = $flow | Where-Object { $_.DestIP -eq '185.220.101.44' }
"Sessions : {0}" -f $ex.Count
"BytesOut : {0}" -f ($ex | Measure-Object BytesSent -Sum).Sum
```

```python
flow = R('network-flow.csv')
ex = [r for r in flow if r['DestIP'] == '185.220.101.44']
print('sessions:', len(ex), 'bytes:', sum(int(r['BytesSent']) for r in ex))
print('first:', min(r['FlowStart'] for r in ex), 'last:', max(r['FlowEnd'] for r in ex))
srum = [r for r in R('srum.csv') if r['ApplicationName'] == 'rclone.exe']
for r in srum:
    print('SRUM', r['Timestamp'][:19], r['BytesSent'])
print('SRUM total:', sum(int(r['BytesSent']) for r in srum))
```

| Source | Measure | Value |
|---|---|---|
| `network-flow.csv` | Session count to the destination | |
| `network-flow.csv` | Destination port and protocol | |
| `network-flow.csv` | Owning process | |
| `network-flow.csv` | Total bytes sent | |
| `network-flow.csv` | First / last session time | |
| `network-flow.csv` | Any contact with that destination before the incident? | |
| `srum.csv` | Number of hourly buckets for the transfer tool | |
| `srum.csv` | Bytes sent per bucket | |
| `srum.csv` | Total bytes sent | |
| Staged set | Total archive bytes | |

**The sanity check:**

| Comparison | Value | Interpretation |
|---|---|---|
| Egress ÷ staged | | |
| SRUM ÷ staged | | |
| Spread across the three measurements | | |
| Conclusion about transfer completion | | |

Then answer:

**1. Chapter 12 §12.5.4 gives the interrupted-transfer case: 40 GB staged, 2 GB observed. What would that have changed about the finding, and why does the difference matter to counsel rather than only to you?**

**2. Egress slightly exceeds the staged total. Give the benign technical explanation, and say why a number slightly *above* the staged set is more reassuring than one exactly equal to it.**

**3. Why is SRUM described as "particularly valuable on a host where the actor performed cleanup"? Name two properties that make it hard for an actor to reach.**

**4. The three measurements come from two hosts' worth of visibility. Which is host-side, which is network-side, and what would you say if only one of the two existed?**

---

### Task 5 — Rule Out the Confounder

**Objective:** Prove to yourself that volume is not the signal.

```python
for r in sorted(flow, key=lambda r: -int(r['BytesSent']))[:5]:
    print(r['FlowStart'], r['DestIP'], f"{int(r['BytesSent']):>15,}",
          r['OwningProcess'], '|', r['Notes'][:60])
```

| Rank | Destination | Bytes sent | Owning process | Legitimate? | How you know |
|---|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |
| 4 | | | | | |
| 5 | | | | | |

| Measure | Value |
|---|---|
| Largest single flow in the capture | |
| How many flows of that size exist | |
| Ratio of that flow to the entire exfiltration | |
| Total bytes to the legitimate backup destination | |

Then answer:

**1. Write the one sentence explaining why volume alone is not the signal here.**

**2. Name the three properties that *do* separate the exfiltration from the backup job, and rank them by how quickly you could check each on a live case.**

**3. A detection rule alerts on "any host sending more than 30 GB outbound in a rolling hour." How many alerts would this dataset generate in the dwell window, and how many would be true positives?**

**4. The exfiltration destination had no prior contact in the flow record. Why is prior-contact history one of the highest-value fields in a flow dataset, and what is its main limitation?**

---

### Task 6 — Assess the Evidence Gaps

**Objective:** Name what you do not have, before you decide what you can say.

| Missing evidence | Would have told you | Why it is missing | Could it still be obtained? |
|---|---|---|---|
| Transfer-tool log file | | | |
| Proxy logs for the window | | | |
| Memory image | | | |
| Provider-side records at the destination | | | |
| Pre-clear Security log | | | |

Read the "What you will and won't find" section of [`Data/ACCT-FS01/README.md`](../../../Data/ACCT-FS01/README.md) to check your list.

Then answer:

**1. One of these gaps is the direct result of a choice the actor made at the command line. Which, and what would its presence have changed about your confidence tier?**

**2. One of these gaps is the result of a preservation failure by the responding organisation rather than by the actor. Which, and where does it belong in the report — findings or recommendations?**

**3. For each gap, is it a "no evidence found" gap or a "cannot be determined" gap? The distinction is the whole of Task 7.**

---

### Task 7 — Choose the Tier and Write the Finding

**Objective:** Say exactly what the evidence supports, and no more.

Work through the tiers explicitly before you choose.

| Tier | Applies here? | Why / why not |
|---|---|---|
| Confirmed | | |
| Highly likely | | |
| Possible / cannot be excluded | | |
| No evidence found | | |
| Cannot be determined | | |

Now write the finding. **One paragraph.** It must:

- State the tier explicitly, in bold, as the first thing the reader sees
- Name every supporting evidence source with its measured value
- State the granularity at which the staged set is known
- Name at least two evidence gaps that constrain the conclusion
- Say what single additional artifact would move it up one tier

Then answer:

**1. What single additional artifact would move this finding to "Confirmed", and who would you have to ask for it?**

**2. Explain to a non-technical executive, in two sentences, the difference between "we found no evidence of exfiltration" and "we could not determine whether exfiltration occurred."**

**3. The leak site publishes a directory listing next week that matches your share structure. How does that change your finding, and how does it not?**

**4. Your finding stops one tier short of where three independent measurements agreeing within 1.5 % seem to point. Defend that decision in two sentences to a client who thinks you are hedging.**

---

### Task 8 — Reflection

Answer the following in 3–5 sentences each.

**1. Quiet evidence**
Encryption is loud and exfiltration is quiet. What does that asymmetry imply about where an organisation should invest in visibility?

**2. Granularity is the finding**
The staged set is known at archive-volume granularity and at source-directory granularity, but not at file granularity. Why does that specific gap map so directly onto what counsel can and cannot do?

**3. Two sentences, two decisions**
"No evidence found" and "cannot be determined" produce different legal decisions. Why is choosing between them a technical judgment rather than a wording preference?

**4. Stopping short**
Chapter 12 calls the willingness to stop one tier short of what the evidence almost supports "the discipline." What does a responder gain by doing it, and what do they risk by not?

---

## Deliverables Checklist

Your `lab12-notes.md` should contain:

- [ ] **Task 1** — Staging-directory reconstruction plus the binned staging burst
- [ ] **Task 2** — Archive command breakdown and the source-directory-to-encryption-scope mapping
- [ ] **Task 3** — Transfer-tool artifact set across five sources, plus the recovered-config extraction
- [ ] **Task 4** — Egress table from two independent sources and the three-way sanity check
- [ ] **Task 5** — Top-five flow table and the confounder analysis
- [ ] **Task 6** — Evidence-gap table with each gap classified
- [ ] **Task 7** — Five-tier assessment table and the one-paragraph exfiltration finding
- [ ] **Task 8** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab12/
├── lab12-notes.md  ← Your working notes file (whole lab)
└── Lab12_05/
    └── ReadMe.md       ← This file
```

Backing data: [`Data/ACCT-FS01/`](../../../Data/ACCT-FS01/) — principally `usn-journal.csv`, `mft.csv`, `powershell-evtx.csv`, `network-flow.csv`, `srum.csv` and `rclone-conf-recovered.txt`.

---

## Key Takeaways

- **A deleted staging directory is still a directory.** USN records and MFT entries marked `InUse=False` carry the file names, the sizes, and the deletion time long after the files are gone.
- **The archive command is worth more than the archives.** When the staged files are named only by volume number, the command line that created them is the only artifact that says *which trees* were taken.
- **The configuration file is the highest-value single artifact.** It names the protocol, the endpoint and the remote. It is recoverable from unallocated space because it is small and resident.
- **Two independent volume measurements beat one precise one.** Host-side SRUM and network-side flow agreeing within 1.5 % is a much stronger statement than either alone.
- **Volume is not the signal.** The largest flows in this capture are legitimate backup jobs, each nearly six times the size of the whole exfiltration. Destination, owning process and prior-contact history are what separate them.
- **Tier the finding and name the gap.** Staging plus tool execution plus consistent egress is *highly likely*. Without a per-file record it is not *confirmed*. Saying so is what makes the rest of the report credible.

---

**Next:** Lab 12.6 — Supporting the Recovery Decision

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
