# Lab 12 — Hands-On Walkthrough Sample Answers

*Sample answers for the Hands-On Walkthrough section of `Labs/Lab12/ReadMe.md`. These are reference answers. Your filter, your environment, and your tool version may legitimately produce slightly different values, and the interpretation matters more than the exact number. Every count below comes from running the command shown in "Verified via" against the committed `Data/ACCT-FS01/` files. Run the commands from the repository root.*

---

## Step 1 — Read the note and establish the strain

**Expected output:** the note yields six items of downstream value:

| Item | Value |
|---|---|
| Family / strain | **Vault** |
| Encrypted-file extension | `.vaulted` |
| Ransom note filename | `RECOVER-YOUR-FILES.txt` |
| Victim identifier | `VLT-8837-ACCT` |
| Contact channel | `hxxp://vault-recovery-portal[.]onion/VLT-8837-ACCT` (defanged, fictional) |
| Claimed exfiltration | **34 GB** of accounting, finance, HR and legal data |

**Verified via:** `grep -E 'VLT-|\.vaulted|GB|portal' Data/ACCT-FS01/ransom-note.txt`

**Interpretation:** The first three items are the family-identification triplet. Sent to threat intelligence, [No More Ransom](https://www.nomoreransom.org/) or ID Ransomware within the first hour, they answer the question of whether a free decryptor exists. That is cheap to check and occasionally worth the entire ransom. The victim ID and contact channel go to counsel and the negotiation vendor.

The 34 GB claim is **not evidence**. Ransomware crews routinely claim data they did not take. Treat it as a lead to verify against your own artifacts, which Step 8 does. When you get there, your independently measured staged set of 34.30 GiB happens to agree with the claim. That agreement corroborates *your* finding. It does not validate *their* claim, and the direction of inference matters.

---

## Step 2 — Sweep the encrypted extension

**Expected output:** **418 files**, **78,662,133,156 bytes** (73.26 GiB), across **24 directories**.

Top five by file count:

| Files | Directory | Bytes | % of count | % of volume |
|---|---|---|---|---|
| 38 | `C:\Shares\Accounting\AP\Invoices\2024` | 174,202,530 | 9.1 % | 0.22 % |
| 31 | `C:\Shares\Accounting\AP\Invoices\2023` | 118,640,451 | 7.4 % | 0.15 % |
| 29 | `C:\Shares\Accounting\Vendors` | 153,351,929 | 6.9 % | 0.19 % |
| 27 | `C:\Shares\Accounting\AR\Statements` | 126,923,623 | 6.5 % | 0.16 % |
| 26 | `C:\Shares\Accounting\Archive\2022` | 2,159,650,355 | 6.2 % | 2.75 % |

Top three by data volume:

| Files | Directory | Bytes | % of count | % of volume |
|---|---|---|---|---|
| **5** | `C:\Shares\IT\Backups\SQL` | **72,245,603,301** | **1.2 %** | **91.84 %** |
| 26 | `C:\Shares\Accounting\Archive\2022` | 2,159,650,355 | 6.2 % | 2.75 % |
| 21 | `C:\Shares\Accounting\Archive\2021` | 1,625,266,025 | 5.0 % | 2.07 % |

**Verified via:**
```
python3 -c "import csv,collections; rows=list(csv.DictReader(open('Data/ACCT-FS01/encrypted-files-inventory.csv'))); print(len(rows), sum(int(r['SizeBytes']) for r in rows), len(set(r['Directory'] for r in rows)))"
python3 -c "import csv,collections; rows=list(csv.DictReader(open('Data/ACCT-FS01/encrypted-files-inventory.csv'))); c=collections.Counter(r['Directory'] for r in rows); s=collections.Counter();
[s.update({r['Directory']:int(r['SizeBytes'])}) for r in rows]; [print(n,c[d],d) for d,n in s.most_common(3)]"
```

**Interpretation:** Two rankings, almost opposite orders. `C:\Shares\IT\Backups\SQL` holds five files, which are 1.2 % of the encrypted count and 91.8 % of the encrypted volume. Report only the count, and the recovery team under-provisions restore capacity by an order of magnitude. Report only the volume, and counsel concludes the incident is a database problem and misses the 413 accounting, payroll, HR and legal documents that actually drive notification analysis.

Both numbers go in the scoping deliverable, side by side, and neither is described as "the" scope. Chapter 12 §12.3.1's caution that "file count is not data volume" is not a nuance in this case. It inverts the priority list.

---

## Step 3 — Map the blast radius from ransom-note placement

**Expected output:** **24 notes**, one per encrypted directory. Sorted by `$SI` Born, they reproduce the encryptor's traversal:

| # | Directory | Note Born (UTC) | Gap | Files |
|---|---|---|---|---|
| 1 | `C:\Shares\Accounting\AP\Invoices\2024` | 02:21:07 | — | 38 |
| 2 | `C:\Shares\Accounting\AP\Invoices\2023` | 02:26:51 | 5:44 | 31 |
| 3 | `C:\Shares\Accounting\AR\Statements` | 02:31:51 | 5:00 | 27 |
| 4 | `C:\Shares\Accounting\Payroll\2024` | 02:36:19 | 4:28 | 24 |
| 5 | `C:\Shares\Accounting\Payroll\2023` | 02:39:40 | 3:21 | 18 |
| 6 | `C:\Shares\Accounting\Tax\2024` | 02:42:29 | 2:49 | 15 |
| 7 | `C:\Shares\Accounting\Tax\2023` | 02:44:44 | 2:15 | 12 |
| 8 | `C:\Shares\Accounting\Reconciliation` | 02:48:50 | 4:06 | 22 |
| 9 | `C:\Shares\Accounting\Budgets\FY25` | 02:52:01 | 3:11 | 17 |
| 10 | `C:\Shares\Accounting\Vendors` | 02:57:23 | 5:22 | 29 |
| 11 | `C:\Shares\Accounting\Audit\2024` | 02:59:28 | 2:05 | 11 |
| 12 | `C:\Shares\Accounting\Archive\2022` | 03:04:27 | 4:59 | 26 |
| 13 | `C:\Shares\Accounting\Archive\2021` | 03:08:30 | 4:03 | 21 |
| 14 | `C:\Shares\Accounting\Shared\Templates` | 03:12:13 | 3:43 | 20 |
| 15 | `C:\Shares\Finance\Reports\Monthly` | 03:15:46 | 3:33 | 19 |
| 16 | `C:\Shares\Finance\Reports\Quarterly` | 03:17:33 | 1:47 | 9 |
| 17 | `C:\Shares\Finance\Forecast` | 03:20:00 | 2:27 | 13 |
| 18 | `C:\Shares\Finance\BankRecs` | 03:23:00 | 3:00 | 16 |
| 19 | `C:\Shares\HR\Compensation` | 03:24:53 | 1:53 | 10 |
| 20 | `C:\Shares\HR\Benefits` | 03:26:25 | 1:32 | 8 |
| 21 | `C:\Shares\Legal\Contracts` | 03:29:03 | 2:38 | 14 |
| 22 | `C:\Shares\Legal\NDA` | 03:30:12 | 1:09 | 6 |
| 23 | `C:\Shares\IT\Backups\SQL` | **03:37:20** | **7:08** | **5** |
| 24 | `C:\Users\svc-backup\Documents` | 03:38:41 | 1:21 | 7 |

**Verified via:** `python3 -c "import csv; rows=[r for r in csv.DictReader(open('Data/ACCT-FS01/mft.csv')) if r['FileName']=='RECOVER-YOUR-FILES.txt']; rows.sort(key=lambda r: r['Created0x10']); print(len(rows)); [print(r['Created0x10'][11:19], r['ParentPath']) for r in rows]"`

**Interpretation:** The note map gives you three things a per-file sweep does not. It gives you the *directory list* directly, without deduplicating 418 paths. It gives you the *order*, which is the encryptor's tree walk. And it gives you the *pace*, from which anomalies fall out.

This map shows two anomalies. The first is the 7-minute 8-second gap before note 23, `C:\Shares\IT\Backups\SQL`. That directory holds five multi-gigabyte database backups, and the gap is also the trough in the Step 4 histogram. Cross-reading the note map against the histogram explains the trough without speculation.

The second is note 24: the last directory encrypted is `C:\Users\svc-backup\Documents`, the profile of the account the encryptor ran as. Families that walk profile directories routinely encrypt their own operator's home path. The detail is a small corroboration of the account attribution from Step 5. It is also the kind of detail that makes a report read as evidence-led rather than assumption-led.

---

## Step 4 — Bin the USN Journal and read the window off the curve

**Expected output:** **2,162 USN records** between **02:14** and **03:38** on 2024-11-12, spread across **85 consecutive non-empty minute bins**.

| Measure | Value |
|---|---|
| First bin | 02:14 (24 records) |
| Last bin | 03:38 (21 records) |
| Duration | 84 min 35 s (02:14:06.549 → 03:38:41.095) |
| Records in window | **2,162** |
| Peak minute | **30** — tied at 02:52, 03:20 and 03:23 |
| Lowest minute inside window | **2** — at 03:32 |
| Baseline, 00:14–02:14 | **16 records total** (~0.13/min) |

Reason-code distribution inside the window — perfectly uniform:

| Count | Reason |
|---|---|
| 418 | `DataOverwrite` |
| 418 | `DataOverwrite\|DataTruncation` |
| 418 | `DataOverwrite\|DataTruncation\|RenameOldName` |
| 418 | `DataOverwrite\|DataTruncation\|RenameNewName` |
| 418 | `DataOverwrite\|DataTruncation\|RenameNewName\|Close` |
| 24 | `FileCreate` |
| 24 | `FileCreate\|DataExtend` |
| 24 | `FileCreate\|DataExtend\|Close` |

The trough: bins **03:30 through 03:36** fall to **9, 4, 2, 4, 4, 3, 4** records per minute, then recover to 22 and 21 for the final two minutes.

**Verified via:**
```
python3 -c "import csv,collections; rows=list(csv.DictReader(open('Data/ACCT-FS01/usn-journal.csv'))); w=[r for r in rows if '2024-11-12 02:14'<=r['UpdateTimestamp'][:16]<='2024-11-12 03:38']; b=collections.Counter(r['UpdateTimestamp'][:16] for r in w); print(len(w), len(b), max(b.values()), min(b.values())); [print(k,v) for k,v in sorted(b.items())]"
python3 -c "import csv,collections; rows=list(csv.DictReader(open('Data/ACCT-FS01/usn-journal.csv'))); w=[r for r in rows if '2024-11-12 02:14'<=r['UpdateTimestamp'][:16]<='2024-11-12 03:38']; [print(n,x) for x,n in collections.Counter(r['UpdateReasons'] for r in w).most_common()]"
```

**Interpretation:** All five properties from Chapter 12 §12.3.2 are present. The *rate* jumps from 0.13 records per minute to 24 in a single minute, more than two orders of magnitude, and the drop at the end is equally sharp. The *uniformity* is absolute: 418 files, five reason codes, 418 records each. The *rename pairing* shows as 418 `RenameOldName` records and 836 records carrying `RenameNewName`, because the new name persists into the closing record. The *directory walk order* is visible when you sort on `ParentPath` within time. The *interleaved note creation* is the three `FileCreate*` codes at 24 each, one triplet per directory boundary.

The trough is the trap. An analyst who binned the journal, saw the count collapse at 03:30, and reported the encryption as ending there would truncate the window by eight minutes. That analyst would also miss the last two directories, including the SQL backups, which are 91.8 % of the data volume. The cause is file size: five backups of 12.4–18.4 GB each generate five USN records apiece regardless of how long they take to encrypt. Record *count* per minute is not encryption *throughput*. Cross-check any apparent end-of-window against the ransom-note map from Step 3, which shows a note still being written at 03:38:41.

Carry one caveat into any writeup: these per-minute rates are two to three orders of magnitude below a real file server's. The dataset is downsampled so you can do the binning by hand. Every conclusion above depends on the *shape*: the sharp rise, the uniformity, the rename pairing, the trough. None of them depend on the absolute rate.

---

## Step 5 — Prove the encryption ran locally

**Expected output:**

| Evidence | Value |
|---|---|
| Security 4688 for the encryptor | **1 record, 02:13:52**, `C:\Windows\Temp\vault.exe -enc -threads 16 -note RECOVER-YOUR-FILES.txt -ext .vaulted -id VLT-8837-ACCT`, `SubjectUserName=svc-backup` |
| Prefetch | `VAULT.EXE`, **RunCount 1**, LastRun 02:13:52, no previous-run values |
| Amcache | `C:\Windows\Temp\vault.exe`, unsigned, 412,672 bytes |
| ShimCache | `C:\Windows\Temp\vault.exe`, `Executed=NA` |
| MFT | `Windows\Temp\vault.exe`, `InUse=False` (deleted 03:39:12) |
| Security 5140 | **1 record**, 02:44:02, `Accounting$`, AccessMask `0x1` |
| Security 5145 | **0 records** |

**Verified via:**
```
python3 -c "import csv; [print(r['TimeCreated'], r['UserName'], r['Payload']) for r in csv.DictReader(open('Data/ACCT-FS01/security-evtx.csv')) if r['EventID']=='4688' and 'vault.exe -enc' in r['Payload']]"
python3 -c "import csv; [print(r) for r in csv.DictReader(open('Data/ACCT-FS01/prefetch.csv')) if r['ExecutableName']=='VAULT.EXE']"
python3 -c "import csv; rows=list(csv.DictReader(open('Data/ACCT-FS01/security-evtx.csv'))); print('5140:',sum(1 for r in rows if r['EventID']=='5140'),'5145:',sum(1 for r in rows if r['EventID']=='5145'))"
```

**Interpretation:** This is the local-execution pattern, and it is unambiguous: mass file modification *plus* four independent local execution artifacts *plus* the near-total absence of share-access records. The encryption ran on ACCT-FS01, as `FINANCE\svc-backup`, from `C:\Windows\Temp\vault.exe`.

State the alternative pattern from Chapter 12 §12.3.4 explicitly in the report, so a reviewer can see you considered and excluded it. Had the encryption run over SMB from another host, you would expect thousands of 5145 records from a single source IP, sustained port-445 flow during the window, and *no* Prefetch entry, *no* 4688, and no binary in the MFT. You have the exact opposite on every count.

Two caveats belong with the finding. First, `VAULT.EXE` has RunCount 1 and no previous-run values, which is what a single-run encryptor looks like. Chapter 12 §12.2.8 warns that on many real servers it would not have flushed to Prefetch at all. Second, application prefetching is not enabled by default on Windows Server. This host's build image happens to set `EnablePrefetcher=3`. If Prefetch had been absent, you would still have the 4688, Amcache and ShimCache, and the conclusion would survive with three sources instead of four.

The ordering is what makes the 4688 available at all. The actor cleared the log at 02:09:41 and ran the encryptor at 02:13:52. **The evidence of the encryption exists because it was written into the log the actor had just emptied.**

---

## Step 6 — Rebuild the defense-evasion sequence around the cleared log

**Expected output:** `security-evtx.csv` contains **24 rows**. Its earliest record is **EID 1102 at 2024-11-12 02:09:41**, `SubjectUserName=svc-backup`.

The full evasion sequence, reconstructed from channels the actor did not clear:

| Time (UTC) | Action | Surviving evidence | 4688 survived? |
|---|---|---|---|
| 2024-11-11 21:52:41 | Defender path exclusion for `C:\Windows\Temp\wu` | Defender **5007**, `registry-runkeys.csv` | destroyed |
| 2024-11-11 21:53:01/21:53:04 | Defender process exclusion for `rclone.exe` | Defender **5007**, PowerShell **4104** | destroyed |
| 2024-11-12 02:02:12 | `Set-MpPreference -DisableRealtimeMonitoring $true …` | PowerShell **4104** | destroyed |
| 2024-11-12 02:02:18 | Real-time protection disabled | Defender **5001** | destroyed |
| 2024-11-12 02:02:21 / 02:02:24 | `DisableRealtimeMonitoring` and `DisableAntiSpyware` set to 1 | Defender **5007** ×2, `registry-runkeys.csv` | destroyed |
| 2024-11-12 02:02:52 | Scanning disabled | Defender **5010** | destroyed |
| 2024-11-12 02:04:41 | Backup and SQL services stopped | PowerShell **4104** | destroyed |
| 2024-11-12 02:06:29 | `cmd /c 'vssadmin delete shadows /all /quiet'` | PowerShell **4104** | destroyed |
| 2024-11-12 02:06:33 | `vssadmin.exe` executes | Prefetch `VSSADMIN.EXE`, RunCount 2 | destroyed |
| 2024-11-12 02:06:34 – 02:06:41 | Four shadow copies deleted | System **volsnap EID 25 ×4** | n/a |
| 2024-11-12 02:09:36 | `wevtutil cl Security` | PowerShell **4104** | destroyed |
| **2024-11-12 02:09:41** | **Security log cleared** | Security **1102** | *is* the 1102 |
| 2024-11-12 02:10:58 | `wbadmin delete catalog -quiet` | Security **4688** | **survived** |
| 2024-11-12 02:11:19 | `bcdedit /set {default} recoveryenabled No` | Security **4688** | **survived** |
| 2024-11-12 02:13:52 | Encryptor executes | Security **4688**, Prefetch | **survived** |
| 2024-11-12 02:14:06 | First encrypted file | USN Journal | n/a |

| Measure | Value |
|---|---|
| Real-time protection disabled (Defender 5001) → first encrypted file | **11 min 48 s** (02:02:18 → 02:14:06) |
| First evasion action, the staging-path exclusion (Defender 5007) → first encrypted file | **4 h 21 min 25 s** (2024-11-11 21:52:41 → 2024-11-12 02:14:06) |
| Log clear → first encrypted file | **4 min 25 s** (02:09:41 → 02:14:06) |
| Account named in the 1102 | `svc-backup` |
| Earliest surviving Security record | 2024-11-12 02:09:41 |

Defender's earlier detections — **4 records** (1116/1117 pairs):

| Time (UTC) | Threat | Path | Action |
|---|---|---|---|
| 2024-11-09 02:14:07 / :09 | `HackTool:Win64/Mimikatz.E` | `C:\Windows\Temp\l.dmp` (via `rundll32.exe`) | Quarantine |
| 2024-11-09 02:44:31 / :33 | `HackTool:Win32/NetworkScanner` | `C:\Windows\Temp\netscan.exe` | Quarantine |

**Verified via:**
```
python3 -c "import csv; rows=list(csv.DictReader(open('Data/ACCT-FS01/security-evtx.csv'))); print(len(rows), rows[0]['TimeCreated'], rows[0]['EventID'], rows[0]['UserName'])"
python3 -c "import csv; [print(r['TimeCreated'], r['EventID'], r['Description']) for r in csv.DictReader(open('Data/ACCT-FS01/defender-evtx.csv')) if r['EventID'] in ('1116','1117','5001','5007','5010')]"
python3 -c "import csv; print(sum(1 for r in csv.DictReader(open('Data/ACCT-FS01/system-evtx.csv')) if r['EventID']=='25'))"
python3 -c "import csv; [print(r['TimeCreated'], r['Payload'][:120]) for r in csv.DictReader(open('Data/ACCT-FS01/powershell-evtx.csv')) if any(k in r['Payload'] for k in ('vssadmin','Set-MpPreference','wevtutil'))]"
```

**Interpretation:** Thirteen of the 16 steps above have no surviving 4688, and the sequence is still fully reconstructable. The log clear destroyed 10 of them, two would never have generated one, and one is the 1102 record itself. That is the whole lesson of Chapter 12 §12.4.5: **log clearing relocates the investigation, it does not end it.** Four channels the actor forgot about carried the story: Defender Operational, System (`volsnap`), PowerShell Operational (4104), and Prefetch. The registry values add the on-disk residue of the same actions.

The 1102 establishes two findings simultaneously, and both belong in the report. First, `svc-backup` was compromised, because a service account does not clear a Security log as part of its job. Second, the clearing was deliberate and adversarial rather than administrative, because it sits 4 minutes 25 seconds before the first encrypted file.

The Defender detections on 2024-11-09, both inside the actor's first interactive session on ACCT-FS01, are what Chapter 12 §12.2.7 calls "a gift." They name the actor's tooling, credential dumping and network scanning, about three days before the encryption. They also independently corroborate the credential-access and discovery stages, whose 4688 records on the jump host you would otherwise have to take on trust. The `l.dmp` detection shows the same `comsvcs.dll` dump technique used on JUMP-01 on 2024-11-08 being repeated on this host, where the log clear destroyed its 4688. Always look *before* the disable, not only at the disable.

The exclusion-then-disable ordering also deserves a sentence in the report. The actor excluded the staging directory at 21:52 on 2024-11-11. The exclusion was narrow and quiet, and enough to let `7z.exe` and `rclone.exe` run. The actor did not disable real-time protection wholesale until 02:02 the following morning, minutes before encryption. That is an operator managing detection risk, not a script running end to end. It is a small indicator of a human-operated intrusion, which is what the dwell window then confirms.

---

## Step 7 — Chain backwards to patient zero

**Expected output:**

| Measure | Value |
|---|---|
| 4625 count on `JUMP-01` | **212** |
| Burst start | 2024-11-06 21:03:12 |
| Burst end | 2024-11-06 21:46:58 |
| Burst duration | 43 min 46 s (~4.8 attempts/minute) |
| Target account | `FINANCE\svc-backup`, LogonType 10 |
| Source IP | `45.147.230.19` |
| Success | **1 × 4624 LogonType 10 at 2024-11-06 21:47:22** |
| DC corroboration | **212 × EID 4776 with `ErrorCode=0xC000006A`**, plus one success |
| Domain admin `a-mbrennan` records on the DC | **4**, earliest 2024-11-08 02:04:18 |
| TerminalServices 1149 records on ACCT-FS01 | **8** (4 attacker, 3 routine, 1 IR) |

`svc-backup`'s genuine baseline in the DC log: three Kerberos service tickets against `BKP-SRV01`, `BKP-SRV02` and `BKP-SRV03` at **01:05:11, 01:14:12 and 02:23:13 every night** from 2024-11-01 — 36 records of ordinary backup activity.

The four attacker RDP sessions on ACCT-FS01, from `10.0.2.28`:

| Session start | Session end | What happened in it |
|---|---|---|
| 2024-11-09 01:26:41 | 03:11:20 | First interactive session; share enumeration |
| 2024-11-10 23:38:14 | 2024-11-11 00:24:02 | Persistence installed (`VaultUpd`, Run key) |
| 2024-11-11 20:52:08 | 2024-11-12 01:04:51 | Staging and exfiltration |
| 2024-11-12 02:01:41 | 04:12:44 | Evasion chain, log clear, encryption |

**Verified via:**
```
python3 -c "import csv; rows=list(csv.DictReader(open('Data/ACCT-FS01/jumphost-security-evtx.csv'))); f=[r for r in rows if r['EventID']=='4625']; print(len(f), f[0]['TimeCreated'], f[-1]['TimeCreated']); [print(r['TimeCreated'], r['Payload']) for r in rows if r['EventID']=='4624' and r['UserName']=='svc-backup']"
python3 -c "import csv; rows=list(csv.DictReader(open('Data/ACCT-FS01/dc-security-evtx.csv'))); print(sum(1 for r in rows if r['EventID']=='4776' and '0xC000006A' in r['Payload'])); [print(r['TimeCreated'], r['EventID'], r['Payload'][:90]) for r in rows if r['UserName']=='a-mbrennan']"
python3 -c "import csv; rows=[r for r in csv.DictReader(open('Data/ACCT-FS01/terminalservices-evtx.csv')) if r['EventID']=='1149']; print(len(rows)); [print(r['TimeCreated'], r['UserName'], r['Payload'][:70]) for r in rows]"
```

**Interpretation:** The chain runs **ACCT-FS01 → JUMP-01 → internet**, and two independent sources carry each link.

The link from ACCT-FS01 to the jump host rests on two records. On the destination side, the TerminalServices 1149 records capture the source address `10.0.2.28` *before* authentication, which is why RCM 1149 is so useful. On the source side, 4648 explicit-credential events on the jump host's Security log name ACCT-FS01 as the target server. That pairing covers source side and destination side, as the Chapter 12 §12.2.4 table requires.

The entry point is confirmed twice over. On the jump host, 212 failures and one success are a hypothesis. On the domain controller, 212 NTLM validation failures with error `0xC000006A` for the same account in the same window are confirmation. A single log entry is never an entry-point finding.

The account behaviour is the clearest single narrative in the case. For six days before the intrusion, `svc-backup` did exactly three things per night, on the same three backup servers, at the same three times. On 2024-11-06 at 21:47 it did something it had never done: a RemoteInteractive logon on a jump host from an external address. At 02:04:18 on 2024-11-08, 12 minutes after the LSASS dump on the jump host, a **domain admin account appeared from the jump host's address, `10.0.2.28`**. That tells you that credential theft succeeded on a host you have not yet examined, and that the blast radius of the credential compromise extends past this file server.

**The dwell window, written for the report:**

> Earliest observed attacker activity is 2024-11-06 21:03:12 UTC — the first failed logon against `FINANCE\svc-backup` on JUMP-01 from 45.147.230.19. Encryption of ACCT-FS01 completed 2024-11-12 03:38:41 UTC. Dwell time is therefore six days. JUMP-01 Security log retention begins 2024-11-04; activity before that date cannot be excluded.

The field composite in Chapter 12 §12.4.5 is about that final sentence. It costs 13 words, and it is the difference between a defensible dwell window and one that gets a client restored into a live intrusion.

---

## Step 8 — Reconstruct staging and bound the egress

**Expected output — staging:**

| Measure | Value |
|---|---|
| USN records in `Windows\Temp\wu` | **868** |
| Deletions in that directory | **16**, between 03:41:22 and 03:41:24 on 2024-11-12 |
| Archive volumes | **12** (`acct-fs01-data.7z.001` … `.012`) |
| Total staged bytes | **36,829,344,563** (34.30 GiB) |
| Staging window | 2024-11-11 21:14:22 → 22:37:45 |
| Records in the staging window | **847** across **84 minute bins**, 7–12 per minute |
| Other contents | `rclone.exe`, `rclone.conf`, `7z.exe`, `7z.dll` |
| MFT status | all 16 entries present with `InUse=False` |

**Expected output — egress:**

| Source | Measure | Value |
|---|---|---|
| `network-flow.csv` | Sessions to `185.220.101.44:443` | **14** |
| `network-flow.csv` | Bytes sent | **37,312,004,096** (34.75 GiB) |
| `network-flow.csv` | Window | 2024-11-11 22:41:06 → 2024-11-12 00:52:10 |
| `network-flow.csv` | Prior contact with that address | **none** |
| `srum.csv` | `rclone.exe` rows | **3** hourly buckets |
| `srum.csv` | `rclone.exe` bytes sent | **36,884,201,472** (34.35 GiB) |
| — | Egress ÷ staged | **1.0131** |

SRUM bucket detail:

| Bucket | Bytes sent |
|---|---|
| 2024-11-11 22:00 | 15,122,522,603 |
| 2024-11-11 23:00 | 16,229,048,647 |
| 2024-11-12 00:00 | 5,532,630,222 |

The confounder: the six largest flows in the entire capture are **nightly Veeam backup jobs to `10.0.6.41` at 214,748,364,800 bytes each** — roughly **5.8×** the exfiltration.

**Verified via:**
```
python3 -c "import csv,collections; rows=list(csv.DictReader(open('Data/ACCT-FS01/usn-journal.csv'))); wu=[r for r in rows if r['ParentPath']=='Windows\\\\Temp\\\\wu']; print(len(wu), sum(1 for r in wu if 'FileDelete' in r['UpdateReasons'])); s=[r for r in rows if '2024-11-11 21:14'<=r['UpdateTimestamp'][:16]<='2024-11-11 22:38']; b=collections.Counter(r['UpdateTimestamp'][:16] for r in s); print(len(s), len(b), min(b.values()), max(b.values()))"
python3 -c "import csv; a=[r for r in csv.DictReader(open('Data/ACCT-FS01/mft.csv')) if r['FileName'].startswith('acct-fs01-data.7z.')]; print(len(a), sum(int(r['FileSize']) for r in a))"
python3 -c "import csv; e=[r for r in csv.DictReader(open('Data/ACCT-FS01/network-flow.csv')) if r['DestIP']=='185.220.101.44']; print(len(e), sum(int(r['BytesSent']) for r in e), e[0]['FlowStart'], max(r['FlowEnd'] for r in e))"
python3 -c "import csv; s=[r for r in csv.DictReader(open('Data/ACCT-FS01/srum.csv')) if r['ApplicationName']=='rclone.exe']; print(len(s), sum(int(r['BytesSent']) for r in s)); [print(r['Timestamp'], r['BytesSent']) for r in s]"
python3 -c "import csv; rows=sorted(csv.DictReader(open('Data/ACCT-FS01/network-flow.csv')), key=lambda r: -int(r['BytesSent']))[:3]; [print(r['FlowStart'], r['DestIP'], r['BytesSent'], r['OwningProcess']) for r in rows]"
```

**Interpretation:** Three independent measurements of the same transfer agree within 1.5 %: 34.30 GiB staged on disk, 34.35 GiB attributed to `rclone.exe` by SRUM, and 34.75 GiB observed leaving toward `185.220.101.44` in flow. Flow sits 1.31 % above the staged total, which is what TLS and TCP framing overhead look like on a transfer that completed. The transfer passes Chapter 12 §12.5.4's volume sanity check: this was not an interrupted transfer.

Two details do the real work in this step.

First, the staging burst. Applying the Step 4 binning technique to 2024-11-11 finds **847 records across 84 minutes at 7–12 per minute**. That is roughly a third of the encryption amplitude, four hours before anyone knew there was an incident. Chapter 12 §12.3.2 promises that the same technique detects data movement you were not looking for, and here it does.

Second, the confounder. The single biggest outbound flows in this capture are legitimate nightly backups, each 5.8× larger than the exfiltration. Anyone hunting exfiltration by sorting on `BytesSent` finds Veeam six times before finding rclone. **Volume alone is not the signal.** What identifies `185.220.101.44` is the combination of an unfamiliar destination with no prior contact, an owning process that has no business making outbound connections, a time window outside any scheduled job, and a byte count that matches a staged set on disk.

SRUM deserves specific credit here. It is the one host-side source that survived both the log clear and the actor's deletion of the staging directory, and it attributes bytes to a named process. On a case where the actor cleaned up thoroughly, it is often the only thing standing between "we think they took something" and a defensible volume.

---

## Step 9 — Inventory the persistence and assess the restore

**Expected output — persistence:**

| Mechanism | Artifact | Established (UTC) | Still on the host? | Comes back with a restore from the 2024-11-11 nightly backup? |
|---|---|---|---|---|
| `PSEXESVC` service | System **7045** | 2024-11-09 01:19:44 | No — removed at 01:22:18 | No |
| `VaultUpd` service ("Windows Update Assistant", auto-start, → `C:\Windows\Temp\wu\rclone.exe`) | System **7045**, **7040** | 2024-11-10 23:41:08 | **Yes** | **Yes** |
| `HKLM\…\Run\WindowsUpdateSvc` → same path | `registry-runkeys.csv`, PowerShell **4104** | 2024-11-10 23:39:52 | **Yes** | **Yes** |
| `DisableRealtimeMonitoring = 1`, `DisableAntiSpyware = 1` | `registry-runkeys.csv`, Defender **5007** | 2024-11-12 02:02:21 / 02:02:24 | **Yes** | No — set after that job |
| Defender exclusions for `C:\Windows\Temp\wu` and `rclone.exe` | `registry-runkeys.csv` (path only), Defender **5007** ×2 | 2024-11-11 21:52:41 / 21:53:04 | **Yes** | No — set after that job |
| `fDenyTSConnections = 0` | `registry-runkeys.csv` | 2024-11-09 01:21:07 | **Yes** | **Yes** (also in the 2024-11-10 job) |

Five items remain on the host. Three of them come back with a restore from the newest nightly backup in `network-flow.csv`, the 2024-11-11 job at 01:12–02:00 UTC. The two Defender entries postdate every backup job in the flow record.

**Verified via:**
```
python3 -c "import csv; [print(r['TimeCreated'], r['Payload'][:110]) for r in csv.DictReader(open('Data/ACCT-FS01/system-evtx.csv')) if r['EventID']=='7045']"
python3 -c "import csv; [print(r['LastWriteTime'], r['KeyPath']+'\\\\'+r['ValueName'], '=', r['ValueData'][:60]) for r in csv.DictReader(open('Data/ACCT-FS01/registry-runkeys.csv')) if r['Notes'].startswith('MALICIOUS')]"
```

Expected: **2 service installs** and **4 malicious registry values**.

**The four recovery assessments:**

| Assessment | Finding | Confidence | What would raise it |
|---|---|---|---|
| **Scope confidence** | ACCT-FS01 fully scoped — 418 files, 24 directories, 84-minute window, local execution proven. The *environment* is not scoped: the actor reached BKP-SRV01 on 2024-11-09 and holds `a-mbrennan` | HIGH for the host, **LOW for the environment** | EDR live query for `.vaulted` and `RECOVER-YOUR-FILES.txt` across every reachable host; DC authentication review for both accounts |
| **Actor presence** | No authentication by either compromised account after 04:12:44 on 2024-11-12; no flow to `185.220.101.44` after 00:52. But the `VaultUpd` service, the Run value and the RDP re-enablement were never remediated, so re-entry does not require re-exploitation | MEDIUM | Live EDR telemetry; DC logs since 11-12; confirmation that 3389 on JUMP-01 is closed |
| **Backup trustworthiness** | Shadow copies destroyed (volsnap 25 ×4, `vssadmin list shadows` empty); catalog deletion attempted at 02:10:58. Any backup after 2024-11-06 21:03 sits inside the dwell window, and the 2024-11-11 nightly backup (01:12–02:00 in `network-flow.csv`) demonstrably contains `VaultUpd` and the Run value | Persistence-in-backup: **HIGH**. Overall viability: **cannot be determined from this host** | Backup-platform logs; a pre-2024-11-06 image mounted and hunted for the six indicators above |
| **Reinfection risk** | **HIGH.** The initial access path is open, neither compromised account is rotated, and five persistence items remain on the host, three of which come back with a restore from the newest nightly backup | HIGH | Verified closure of 3389, rotation of `svc-backup` and `a-mbrennan`, `krbtgt` assessment, removal of all five remaining persistence items, EDR on every restored host |

**The exfiltration finding, in the chapter's tiered language:**

> **Highly likely.** Data was staged and exfiltrated before encryption.
>
> **Basis.** Twelve 7-Zip archive volumes totalling 36,829,344,563 bytes were created in `C:\Windows\Temp\wu\` between 21:14:22 and 22:37:45 UTC on 2024-11-11. The USN Journal holds 847 records for that window, and all 12 MFT entries survive deletion with `InUse=False`. Prefetch (RunCount 3, LastRun 22:41:06), Amcache and ShimCache confirm `rclone.exe` execution. A recovered `rclone.conf` names a WebDAV endpoint at `185.220.101.44`. Flow records show 37,312,004,096 bytes sent to that address across 14 sessions between 22:41:06 and 00:52:10, with no prior contact with that address in the retained window. SRUM independently attributes 36,884,201,472 bytes sent to `rclone.exe` in the same period. The three volume measurements agree within 1.5 %, consistent with a completed transfer.
>
> **Why not "Confirmed".** The rclone invocation recorded in PowerShell 4104 omits `--log-file`, so **no per-file transfer record exists**. The staged set is known at archive-volume granularity and, from the 7-Zip command line, at source-directory granularity (`C:\Shares\Accounting`, `\Finance`, `\HR`, `\Legal`, `\IT\Backups\SQL`), but not at file granularity. No proxy logs were retained for the window, so the `rclone/v1.65.0` user-agent evidence that would name the transfer at the request level is unavailable. A per-file rclone log, a proxy log, or destination-side evidence would move this finding to Confirmed.
>
> **What this does not say.** It does not say which specific records left. It does not adopt the actor's claim of "34 GB" as a finding, even though the independently measured staged set happens to agree with it.

**Verified via:** composition of Steps 2–8 above.

**Interpretation:** The finding above is the deliverable the whole lab builds toward. The most important part of it is the paragraph that begins "Why not Confirmed." Three volume measurements inside 1.5 % of each other are very strong evidence. They are strong enough that the temptation to write "confirmed" is real, and strong enough that nobody would immediately challenge it. Stopping one tier short, and saying precisely which artifact would close the gap, is what makes every other finding in the report credible.

Counsel will act on the distinction between *highly likely* and *cannot be determined*, so state plainly in the covering note that the relevant sources here were available and reviewed. That is a different sentence from "flow records for the window were not retained," and it produces different notification decisions.

---

## Summary

| Step | Source | Finding |
|---|---|---|
| 1 | Ransom note | Vault / `.vaulted` / `VLT-8837-ACCT`; 34 GB claimed |
| 2 | Extension sweep | 418 files, 78,662,133,156 bytes, 24 directories; 5 files = 91.8 % of volume |
| 3 | Ransom-note placement | 24 notes, 02:21:07 → 03:38:41; traversal order recovered; 7:08 gap at the SQL directory |
| 4 | USN binning | 2,162 records, 85 bins, peak 30/min, baseline 0.13/min; trough at 03:30–03:36 |
| 5 | 4688 + Prefetch vs 5145 | Local execution proven; 1 × 5140, 0 × 5145 |
| 6 | Defender / volsnap / 4104 / Prefetch | Full evasion chain rebuilt; 1102 at 02:09:41 names `svc-backup`; 4 min 25 s to first encrypted file |
| 7 | Jump host + DC + TerminalServices | 212 failures + 1 success at 21:47:22 on 2024-11-06; corroborated 212 × 4776 on the DC; six-day dwell |
| 8 | USN + MFT + flow + SRUM | 34.30 GiB staged, 34.75 GiB egressed, 34.35 GiB per SRUM — agreement within 1.5 % |
| 9 | 7045 + Run keys + assessments | 5 persistence items still on the host, 3 of them in the newest backup; reinfection risk HIGH; exfiltration **highly likely**, not confirmed |
