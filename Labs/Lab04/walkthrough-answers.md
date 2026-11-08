# Lab 04 — Hands-On Walkthrough Sample Answers

*Sample answers for the Hands-On Walkthrough section of `Labs/Lab04/ReadMe.md`. These are reference answers. Your filter, your environment, and your tool version may legitimately produce slightly different values. The interpretation matters more than the exact number.*

---

## Step 1 — Load the MFT and look at it

**Expected output:** **77** rows. Columns include `EntryNumber`, `ParentEntryNumber`, `InUse`, `ParentPath`, `FileName`, `Extension`, `FileSize`, `IsDirectory`, `Created0x10`, `LastModified0x10`, `LastRecordChange0x10`, `LastAccess0x10`, `Created0x30`, `LastModified0x30` (14 total).

**Verified via:** `python3 -c "import csv; print(len(list(csv.DictReader(open('Data/WKSTN-221/mft.csv')))))"`

**Interpretation:** A scoped MFT export (77 records) is a deliberately curated triage subset, not a full `$MFT` dump. The CSV exposes both the `$STANDARD_INFORMATION` (`0x10`) and `$FILE_NAME` (`0x30`) timestamp pairs. That pairing is the foundation for every timestomping check later in the lab.

---

## Step 2 — Filter for activity in the user's Temp directory

**Expected output:** **10** rows under `C:\Users\payroll-admin\AppData\Local\Temp`. Sorted by `Created0x10`:

| FileName | InUse | Created0x10 |
|---|---|---|
| wmsetup.log | True | 2024-09-19 14:11:14 |
| Office_Setup_log.txt | True | 2024-10-12 11:32:00 |
| ~DF89C2AB.tmp | False | 2024-11-13 09:14:00 |
| ~DF12A4B8.tmp | False | 2024-11-14 11:14:22 |
| ~DF45B89A.tmp | False | 2024-11-14 11:14:23 |
| ~$Q4_Payroll_Review.xlsm | False | 2024-11-14 14:18:56 |
| VBE | True | 2024-11-14 14:18:57 |
| MSForms.exd | False | 2024-11-14 14:18:58 |
| a.tmp | False | 2024-11-14 14:19:42.6 |
| update.exe | False | 2024-11-14 14:20:11 |

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/WKSTN-221/mft.csv'))); print(len([r for r in rows if 'payroll-admin' in r['ParentPath'] and 'AppData\\Local\\Temp' in r['ParentPath']]))"`

**Interpretation:** Two benign legacy Office logs predate the incident. Three deleted `~DF*.tmp` files carry MFT creation times of 2024-11-13 09:14 and 2024-11-14 11:14, hours before the incident. The remaining five cluster tightly in the 14:18–14:20 UTC window of 14 Nov 2024. `update.exe` is `InUse=False`. Its MFT record is unallocated, so the file has been deleted but the metadata persists. `a.tmp` is the staging file that preceded `update.exe` in the dropper sequence. The Excel lock file is unallocated too, and the USN Journal records its deletion at 14:24:18. No `b.tmp` row appears, although Step 4 shows the file existed. The rename kept MFT record 22417 and changed only its name, so the MFT shows `update.exe` and only the USN Journal remembers `b.tmp`.

---

## Step 3 — Look for timestomp signals (update.exe)

**Expected output:** SI and FN timestamps for `update.exe` match exactly:
- `Created0x10` = `Created0x30` = `2024-11-14 14:20:11.0000000`
- `LastModified0x10` = `LastModified0x30` = `2024-11-14 14:20:11.0500000`

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/WKSTN-221/mft.csv'))); [print(r['FileName'], r['Created0x10'], r['Created0x30']) for r in rows if r['FileName']=='update.exe']"`

**Interpretation:** The SI and FN timestamps are byte-for-byte identical, so this record shows no timestomp signature. That does not prove the binary was never timestomped: a stomp followed by the 14:20:11 rename would copy the faked `$SI` values into `$FN` (see the ReadMe, Step 3). The modified value matches the last data write that the USN Journal records for record 22417, at 14:20:11.05. The test still matters: a `Created0x10` predating `Created0x30` is the classic timestomping signature, and absence of evidence is itself documentable.

---

## Step 4 — Pull the USN Journal entries for the deleted file

**Expected output:** **9 rows** for `b.tmp` and `update.exe` combined, in this order:

| Timestamp | FileName | UpdateReasons |
|---|---|---|
| 2024-11-14 14:20:11.00 | b.tmp | FileCreate |
| 2024-11-14 14:20:11.00 | b.tmp | DataExtend |
| 2024-11-14 14:20:11.05 | b.tmp | DataExtend\|FileClose |
| 2024-11-14 14:20:11.25 | b.tmp | RenameOldName |
| 2024-11-14 14:20:11.5 | update.exe | RenameNewName |
| 2024-11-14 14:20:11.5 | update.exe | RenameNewName\|FileClose |
| 2024-11-14 14:21:03 | update.exe | BasicInfoChange |
| 2024-11-14 14:23:44 | update.exe | FileDelete |
| 2024-11-14 14:23:44.5 | update.exe | FileClose |

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/WKSTN-221/usn-journal.csv'))); [print(r['UpdateTimestamp'], r['FileName'], r['UpdateReasons']) for r in sorted([r for r in rows if r['FileName'] in ('update.exe','b.tmp')], key=lambda x: int(x['USN']))]"`

**Interpretation:** These rows cover the entire short life of the attacker tool. It was created as `b.tmp` at 14:20:11.00, written and closed by 14:20:11.05, and renamed to `update.exe` 200 ms later. It executed at 14:21:03, where the `BasicInfoChange` corresponds to the access-time bump, and was deleted 161 seconds after that. All nine rows belong to MFT record 22417, because a rename keeps the record number. The USN sequence reconstructs a lifecycle that the MFT alone could not, because the MFT sees only current state plus the unallocated record.

---

## Step 5 — Cross-reference with Prefetch

**Expected output:** **1 row** — `UPDATE.EXE-89A4B22C.pf`, `RunCount=1`, `LastRun=2024-11-14 14:21:03`, `FilesCount=28`, `VolumeSerialNumber=9C8BFF21`.

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/WKSTN-221/prefetch.csv'))); [print(r) for r in rows if r['ExecutableName']=='UPDATE.EXE']"`

**Interpretation:** Prefetch is the corroborating execution evidence the MFT and USN cannot provide on their own. One run, exactly aligned with the USN `BasicInfoChange` at 14:21:03, ties the file lifecycle to actual code execution. A single-run Prefetch entry for a binary that no longer exists on disk is a textbook attacker-tool signature.

---

## Step 6 — Tie the binary to a hash

**Expected output:** **1 row** — `C:\Users\payroll-admin\AppData\Local\Temp\update.exe`, SHA-256 `4f8b2c1a8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345`, SHA-1 `a1b2c3d4e5f6789012345678901234567890abcd`, FileSize 174080 bytes, Compiled 2024-11-12 03:14:00, IsPeFile True (pe64bit).

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/WKSTN-221/amcache.csv'))); [print(r) for r in rows if 'update.exe' in r['FullPath'].lower()]"`

**Interpretation:** Amcache supplies the durable fingerprint — a SHA-256 hash that survives deletion of the binary. In a real investigation, you submit this value to VirusTotal or your threat-intel platform for attribution. The `Compiled` timestamp (2024-11-12, two days before deployment) is also a useful pivot when you hunt other hosts in the environment.

---

## Summary

Four independent sources, all aligned on the same picture:

- **MFT** — file existed in `payroll-admin\AppData\Local\Temp`, now unallocated. The path attributes it to user `payroll-admin`
- **USN Journal** — full create → rename → execute → delete lifecycle in 213 seconds
- **Prefetch** — one execution at 14:21:03 UTC
- **Amcache** — SHA-256 hash for threat-intel lookup, plus compile timestamp

Walk back through Tasks 1–7 and use the values above to populate the analyst-notes scaffold.
