# Lab 12.3 — Scoping the Encryption

**Supporting Section 12.3: Scoping the Encryption**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Scoping is the half of a ransomware case that has to be delivered first. It answers four questions: **which hosts, which data, how many files, and when**. The recovery team cannot plan without it, and the 09:00 executive update will quote it. It is also the fastest half, which is why it gets rushed and misreported.

This sub-exercise is the most data-driven in Lab 12. You will sweep the encrypted extension and produce blast-radius numbers by two measures that rank the affected directories in nearly opposite orders. You will bin the USN Journal into one-minute buckets and read the encryption window off the curve rather than trusting the file timestamps or the ransom note. You will use ransom-note placement as a directory map and reconstruct the encryptor's traversal. And you will prove — rather than assume — whether the encryption ran on this server or arrived over SMB from somewhere else.

That last one is where responders most often burn hours on a file server. Mass file modification with no local execution evidence means you are looking at the wrong host.

---

## What This Lab Covers

This lab supports the following concepts from Section 12.3:

| Section | Topic |
|---|---|
| 12.3.1 | The encrypted-extension sweep — count, volume, per-directory aggregation |
| 12.3.2 | USN Journal mass-modification patterns and per-minute binning |
| 12.3.3 | Ransom notes as a directory map and traversal record |
| 12.3.4 | Which hosts and which shares — local versus SMB-sourced encryption |
| 12.3.5 | Producing the scoping deliverable |

---

## Learning Objectives

By completing this lab, you will be able to:

- Sweep a parsed MFT or extension inventory and produce file count, data volume, and per-directory aggregation
- Explain why file count and data volume rank directories differently and who needs which ranking
- Bin USN Journal records into one-minute buckets and derive an encryption window from the resulting shape
- Identify the five properties of the USN mass-modification signature in real parsed output
- Read a trough inside an encryption window correctly instead of truncating the window at it
- Use ransom-note `$SI` Born timestamps to reconstruct an encryptor's directory traversal order
- Distinguish locally executed encryption from SMB-sourced encryption using evidence rather than assumption
- Produce the first-hours scoping deliverable with every number marked preliminary

---

## Estimated Time

75–110 minutes

---

## Prerequisites

- Completion of Labs 12.1 and 12.2
- Completion of Lab 04, or equivalent familiarity with `$MFT`, `$UsnJrnl:$J`, and USN reason codes
- Your `lab12-notes.md` file
- `python3`, PowerShell, or a spreadsheet capable of grouping a few thousand rows
- From [`Data/ACCT-FS01/`](../../../Data/ACCT-FS01/): `encrypted-files-inventory.csv`, `mft.csv`, `usn-journal.csv`, `security-evtx.csv`, `prefetch.csv`, `network-flow.csv`

The Python blocks below assume this preamble once per session, run from the repository root:

```python
import csv, collections
def R(name):
    with open(f'Data/ACCT-FS01/{name}', newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))
```

---

## Scenario

It is 08:50. The 09:00 executive update is in 10 minutes, and the finance director wants a return-to-service estimate. The infrastructure lead wants to know how much disk the restore will need. Counsel wants to know which shares are affected, because the share names map to data categories and the data categories map to notification obligations.

Three different people, three different numbers, one dataset.

You have `encrypted-files-inventory.csv`, an extension sweep an analyst exported earlier, plus the parsed MFT and USN Journal. Nothing you produce in the next 10 minutes is final. All of it will be quoted.

---

## Background: Three Numbers, Three Audiences

| Number | Who needs it | Why |
|---|---|---|
| File count | Counsel, and the notification scope | Files map to records; records map to data subjects |
| Data volume | The recovery team | Restore time and storage are a function of bytes, not files |
| Affected directories | Both, plus the business owners | Directory names are how the business identifies its own data |

Chapter 12 §12.3.1 warns that "file count is not data volume." On this host that is not a nuance. It inverts the priority list, as you will demonstrate in Task 2.

The other scoping trap is temporal. The `$SI` Modified timestamps on the encrypted files give you *a* window, but the actor can write them, and they tell you nothing about sequence. The USN Journal gives you the sequence, and for encryption the sequence *is* the evidence.

> **IR Reality Check:** A scoping number you have to revise upward later costs credibility you will need when you deliver the recovery assessments. Mark everything preliminary, and say why.

---

## Lab Tasks

---

### Task 1 — Sweep the Encrypted Extension

**Objective:** Produce the headline blast-radius numbers.

```powershell
$inv = Import-Csv 'Data\ACCT-FS01\encrypted-files-inventory.csv'
"Files : {0}" -f $inv.Count
"Bytes : {0}" -f ($inv | Measure-Object SizeBytes -Sum).Sum
"Dirs  : {0}" -f ($inv.Directory | Sort-Object -Unique).Count
```

```python
inv = R('encrypted-files-inventory.csv')
print('Files:', len(inv))
print('Bytes:', sum(int(r['SizeBytes']) for r in inv))
print('Dirs :', len(set(r['Directory'] for r in inv)))
```

| Measure | Value |
|---|---|
| Total encrypted file count | |
| Total encrypted data volume (bytes) | |
| Same, in GiB | |
| Number of affected directories | |
| Earliest `EncryptedModifiedUtc` | |
| Latest `EncryptedModifiedUtc` | |
| Directories with a ransom note but no encrypted files | |

Cross-check the count against `mft.csv` by filtering for the `.vaulted` extension. The two sources should agree. If you get a different number, work out which query is wrong before you go any further.

Then answer:

**1. Why is the extension sweep the right *first* query rather than, say, a search for the encryptor binary?**

**2. The inventory has a `NoteInDirectory` column. What is its value across the whole set, and what does that consistency let you assume in Task 4?**

**3. The earliest and latest encrypted-file timestamps bound a window. Name two reasons that window is weaker evidence than the one you will derive in Task 3.**

---

### Task 2 — Rank by Count, Then by Volume

**Objective:** Demonstrate to yourself that the two rankings are different investigations.

```python
by_dir = collections.Counter(r['Directory'] for r in inv)
for name, n in by_dir.most_common(8):
    print(f'{n:>4}  {name}')

sizes = collections.Counter()
for r in inv:
    sizes[r['Directory']] += int(r['SizeBytes'])
for name, b in sizes.most_common(3):
    print(f'{b/1024**3:>8.2f} GiB  ({by_dir[name]:>3} files)  {name}')
```

Top eight by **count**:

| Rank | Directory | File count | Share of total count |
|---|---|---|---|
| 1 | | | |
| … | | | |
| 8 | | | |

Top three by **volume**:

| Rank | Directory | Bytes | GiB | File count | Share of total volume |
|---|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |

Now compute the headline comparison:

| Measure | Value |
|---|---|
| Files in the highest-volume directory | |
| Those files as a percentage of the total count | |
| Those files as a percentage of the total volume | |

Then break the set down by original file type:

```python
for ext, n in collections.Counter(r['OriginalExtension'] for r in inv).most_common():
    print(f'{n:>4}  .{ext}')
```

| Original extension | Count | What it suggests about the data |
|---|---|---|
| | | |

Then answer:

**1. Which ranking does the recovery team need, and which does counsel need? Give the one-sentence justification for each.**

**2. A single directory holds a small handful of files and the overwhelming majority of the bytes. What kind of directory is it, and why does that make the restore both easier and harder than the file count suggests?**

**3. Four file extensions in your type breakdown are themselves archive or Outlook mail formats. Which, and why do they complicate a count-based notification scope?**

**4. Write the one sentence you would say at 09:00 that gives both numbers without letting either be quoted alone.**

---

### Task 3 — Bin the USN Journal and Read the Window

**Objective:** Derive the encryption window from the file-system record.

```powershell
$usn = Import-Csv 'Data\ACCT-FS01\usn-journal.csv'
$usn | Where-Object { $_.UpdateTimestamp -like '2024-11-12 0[23]:*' } |
  Group-Object { $_.UpdateTimestamp.Substring(0,16) } |
  Sort-Object Name | Select-Object Name, Count
```

```python
usn = R('usn-journal.csv')
bins = collections.Counter(r['UpdateTimestamp'][:16] for r in usn
                           if r['UpdateTimestamp'].startswith('2024-11-12'))
for minute in sorted(bins):
    print(minute, '#' * bins[minute], bins[minute])
```

| Measure | Value |
|---|---|
| First minute bin with encryption-consistent activity | |
| Last minute bin with encryption-consistent activity | |
| Number of consecutive non-empty bins | |
| Duration | |
| Total USN records inside the window | |
| Peak records in a single minute (and which minutes tie) | |
| Lowest records in a single minute *inside* the window | |
| Total records in the two hours *before* the window | |
| Orders of magnitude between the pre-window rate and the plateau | |

**Part B — Characterise the shape.** Chapter 12 §12.3.2 lists five properties of the encryption signature. Record whether this dataset exhibits each, and cite the evidence.

| Property | Present? | Evidence |
|---|---|---|
| Sustained high rate | | |
| Uniform reason-code sequence per file | | |
| Rename pairs, new name = old name + extension | | |
| Records grouped by directory in a deterministic walk order | | |
| Interleaved note creation at directory boundaries | | |

**Part C — Confirm the reason-code signature.**

```python
window = [r for r in usn
          if '2024-11-12 02:14' <= r['UpdateTimestamp'][:16] <= '2024-11-12 03:38']
for reasons, n in collections.Counter(r['UpdateReasons'] for r in window).most_common():
    print(f'{n:>5}  {reasons}')
```

| Reason-code sequence | Count | What it corresponds to |
|---|---|---|
| | | |

You should end up with two distinct groups of codes at two distinct counts. Explain what each group is and why the counts are what they are. Include why the number of records carrying `RenameNewName` does not equal the number carrying `RenameOldName`.

**Part D — Explain the trough.** Inside the window, the per-minute count collapses to a small fraction of the plateau and then recovers.

| Measure | Value |
|---|---|
| Trough start / end minute | |
| Records per minute inside the trough | |
| Records per minute immediately after it recovers | |
| Directory responsible | |
| Files in that directory | |
| USN records generated per file there | |

Then answer:

**1. Why is the USN Journal a better source for the encryption window than the `$SI` Modified timestamps on the encrypted files?**

**2. An analyst reads the trough as "the attack stopped." By how many minutes would they truncate the window, and how many directories would they miss?**

**3. What would the per-minute curve look like if the encryption had been performed over SMB from three hosts simultaneously?**

**4. This dataset's per-minute rates are two to three orders of magnitude below a real file server's. Which of your conclusions in this task depend on the *rate*, and which depend only on the *shape*?**

---

### Task 4 — Map the Blast Radius from Ransom-Note Placement

**Objective:** Use the note as a directory map and reconstruct the traversal.

```powershell
Import-Csv 'Data\ACCT-FS01\mft.csv' |
  Where-Object { $_.FileName -eq 'RECOVER-YOUR-FILES.txt' } |
  Sort-Object Created0x10 | Select-Object Created0x10, ParentPath
```

```python
notes = [r for r in R('mft.csv') if r['FileName'] == 'RECOVER-YOUR-FILES.txt']
notes.sort(key=lambda r: r['Created0x10'])
prev = None
for r in notes:
    t = r['Created0x10'][11:19]
    print(t, r['ParentPath'])
```

Build the complete traversal table. Include every directory.

| Order | Directory | Note `$SI` Born (UTC) | Gap from previous | Encrypted files in directory |
|---|---|---|---|---|
| 1 | | | — | |
| 2 | | | | |
| … | | | | |

Then record:

| Measure | Value |
|---|---|
| Total notes | |
| First note time and directory | |
| Last note time and directory | |
| Largest gap between consecutive notes | |
| Directory responsible for that gap | |
| Share-level traversal order (which share tree first, second, …) | |

Then answer:

**1. What does note placement give you that a per-file extension sweep does not?**

**2. The largest gap between consecutive notes matches the trough you identified in Task 3. Confirm that they refer to the same directory, and explain why two independent artifacts agreeing here matters more than either finding alone.**

**3. The last directory encrypted is a user profile rather than a share. Whose, and what does its presence in the encrypted set tell you about the account the encryptor ran as?**

**4. If a second host in the environment carried the same note filename but a *different* victim identifier, what would that suggest, and what would you do about it?**

---

### Task 5 — Find What Was *Not* Encrypted

**Objective:** Treat the gaps as evidence.

Chapter 12 §12.3.1 notes that directories with no encrypted files are as informative as directories with many.

```python
mft = R('mft.csv')
enc_dirs = set(r['Directory'] for r in inv)
# List every directory in the share tree, then subtract the encrypted set.
```

| Measure | Value |
|---|---|
| Directories excluded from encryption (system paths) | |
| Share-tree directory with files but no `.vaulted` entries | |
| Files in that directory | |
| Does it contain a ransom note? | |
| The actor's own working directories, and whether they were encrypted | |

Then answer:

**1. `C:\Shares\Finance\Reports\Archive` sits inside an otherwise-encrypted share and has no encrypted files. Give two competing explanations and say what evidence would separate them.**

**2. Most families skip `C:\Windows\`, `C:\Program Files\` and their own staging directory. What is the operational reason for each of the three exclusions?**

**3. Why is an unencrypted directory in the middle of an encrypted volume worth a second look rather than a shrug?**

---

### Task 6 — Prove Where the Encryption Ran

**Objective:** Answer the question responders most often get wrong on a file server.

Chapter 12 §12.3.4 gives two possibilities, each with a distinct evidence pattern.

```python
sec = R('security-evtx.csv')
for r in sec:
    if r['EventID'] == '4688' and 'vault.exe' in r['Payload']:
        print(r['TimeCreated'], r['UserName'], r['Payload'][:150])
for r in R('prefetch.csv'):
    if r['ExecutableName'] == 'VAULT.EXE':
        print(r['ExecutableName'], 'RunCount=' + r['RunCount'], r['LastRun'])
print('5140:', sum(1 for r in sec if r['EventID'] == '5140'))
print('5145:', sum(1 for r in sec if r['EventID'] == '5145'))
```

| Evidence | Local execution predicts | Remote SMB execution predicts | What this dataset shows |
|---|---|---|---|
| 4688 for the encryptor | | | |
| Prefetch entry for the encryptor | | | |
| Amcache / ShimCache entry | | | |
| Encryptor binary in the MFT | | | |
| Security 5140 volume | | | |
| Security 5145 volume | | | |
| Network flow to port 445 during the window | | | |

Record your conclusion and the confidence level you attach to it, then answer:

**1. Which single piece of evidence is strongest for your conclusion, and what is its weakness?**

**2. Note the ordering that makes the 4688 available at all. What is it, and what does that say about the actor's sequencing?**

**3. Prefetch is disabled by default on Windows Server. If it had been disabled here, which evidence would remain, and would the conclusion survive?**

**4. What single query would you run first on the next case to avoid hunting for an encryptor binary on a server that never ran one?**

---

### Task 7 — Produce the Scoping Deliverable

**Objective:** Write the short document that goes out in the first few hours.

Complete the table from Chapter 12 §12.3.5.

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

Add three rows of your own for things this table omits but the recovery team will ask about.

Then write the **covering paragraph** that goes above the table, in no more than 120 words. It must state what the numbers cover, what they do not cover, and that they are preliminary. Do not use the word "confirmed" anywhere in it.

Then answer:

**1. Which single field in this table is most likely to be revised upward later, and what would cause the revision?**

**2. Why does enterprise-wide scoping use the same two selectors you used here, and what tool executes them at scale?**

**3. What does "affected directories: 24" mean, and what does it *not* mean, when the environment has not yet been swept?**

---

### Task 8 — Reflection

Answer the following in 3–5 sentences each.

**1. Count versus volume**
Why does reporting one of the two rankings without the other actively mislead the person planning the restore?

**2. Shape over amplitude**
The USN rates in this dataset are downsampled by orders of magnitude, and the analysis still works. What does that say about which properties of an artifact signature are load-bearing?

**3. Two artifacts, one fact**
The trough in the USN curve and the largest gap in the ransom-note traversal are the same event seen through two artifacts. Why is that kind of agreement worth seeking out deliberately?

**4. Preliminary numbers under pressure**
Scoping numbers get quoted in board updates within the hour. How do you phrase a number so that it is useful now and revisable later without losing credibility either way?

---

## Deliverables Checklist

Your `lab12-notes.md` should contain:

- [ ] **Task 1** — Extension-sweep headline numbers, cross-checked against `mft.csv`
- [ ] **Task 2** — Top-eight-by-count and top-three-by-volume tables, the count/volume comparison, and the file-type breakdown
- [ ] **Task 3** — Per-minute binning table, the five-property signature table, the reason-code counts, and the trough explanation
- [ ] **Task 4** — Complete ransom-note traversal map, all directories
- [ ] **Task 5** — What was not encrypted, with competing explanations
- [ ] **Task 6** — Local-versus-remote evidence table and stated conclusion with confidence
- [ ] **Task 7** — Scoping deliverable table plus the 120-word covering paragraph
- [ ] **Task 8** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab12/
├── lab12-notes.md  ← Your working notes file (whole lab)
└── Lab12_03/
    └── ReadMe.md       ← This file
```

Backing data: [`Data/ACCT-FS01/`](../../../Data/ACCT-FS01/) — principally `encrypted-files-inventory.csv`, `mft.csv` and `usn-journal.csv`.

---

## Key Takeaways

- **Scope by count, by volume, and by directory — all three.** They rank the affected data in different orders and serve different audiences.
- **The USN Journal gives you sequence, and the MFT gives you state.** For encryption, the sequence is the evidence.
- **Read the whole curve, including the trough.** A collapse in the per-minute rate can mean large files rather than the end of the attack. Cross-check against file sizes before you close the window.
- **Ransom-note placement is a directory map.** One MFT filter returns the complete blast radius, and the `$SI` Born timestamps return the traversal order for free.
- **Prove local execution rather than assuming it.** Mass modification with no local execution evidence means the encryptor ran somewhere else and you are scoping the wrong host.
- **Mark every number preliminary until the environment is swept.** One host fully scoped is not an environment scoped, and the difference belongs in the sentence, not in a footnote.

---

**Next:** Lab 12.4 — Finding Patient Zero and the Dwell Window

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
