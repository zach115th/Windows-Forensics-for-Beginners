# ACCT-FS01 — Simulated Ransomware Triage Dataset

Anchor scenario for **[Chapter 12 — Ransomware Incident Response](../../Book/Chapter12.md)** and **[Lab 12](../../Labs/Lab12/ReadMe.md)**. `ACCT-FS01` is an accounting file server encrypted by the fictional **Vault** ransomware family. The dataset is built so that the whole case can be worked end to end: scope the blast radius, bin the USN Journal to find the encryption window, chain backwards through the jump host to patient zero, answer the exfiltration question, and brief the recovery decision.

Everything here is synthetic. The family name, the file extension, the ransom note, the victim identifier, the contact URL, the accounts, the hostnames and the IP addresses are invented for teaching. No real ransomware family, leak site, cryptocurrency address, onion service or victim is referenced anywhere in this folder.

## Scenario

| Element | Value |
|---|---|
| Host | `ACCT-FS01`, accounting file server, Windows Server 2019 Standard |
| IP | `10.0.6.15` |
| Domain | `FINANCE` (`finance.local`) |
| Ransomware family | **Vault** (fictional) |
| Encrypted-file extension | `.vaulted` |
| Ransom note | `RECOVER-YOUR-FILES.txt`, one per encrypted directory |
| Victim identifier | `VLT-8837-ACCT` |
| Initial access | Internet-exposed RDP on the jump host `JUMP-01` (`10.0.2.28`); credential brute force against `svc-backup` from `45.147.230.19` |
| Initial access date | 2024-11-06 21:03 UTC (first failed logon), 21:47:22 UTC (success) |
| Encryption window | 2024-11-12 02:14:06 – 03:38:41 UTC (84 minutes) |
| Dwell time | 6 days |
| Staging directory | `C:\Windows\Temp\wu\` |
| Exfiltration tool | `rclone.exe` (WebDAV) to `185.220.101.44:443` |
| Defense evasion | Defender real-time protection disabled; `vssadmin delete shadows /all /quiet`; Security log cleared (EID 1102) |
| Compromised accounts | `FINANCE\svc-backup` (primary), `FINANCE\a-mbrennan` (domain admin, first seen 2024-11-08) |

## The point of this dataset: the log was cleared

`security-evtx.csv` for ACCT-FS01 contains **24 rows**, and the first of them is the EID 1102 that records its own clearing at **2024-11-12 02:09:41 UTC**. There is no pre-clear authentication history on this host at all. That is deliberate and it is the central exercise: everything before 02:09:41 has to be rebuilt from sources the actor did not touch.

| What the actor destroyed | Where the same fact still lives |
|---|---|
| 4625 burst / 4624 Type 10 for the initial access | `jumphost-security-evtx.csv` (212 failures + 1 success), `dc-security-evtx.csv` (212 × 4776 failure + 1 success) |
| 4624 / 4648 for lateral movement onto this host | `dc-security-evtx.csv` (Kerberos 4768/4769), `terminalservices-evtx.csv` (RCM 1149, LSM 21/22/23/25) |
| 4688 for `vssadmin delete shadows /all /quiet` | `system-evtx.csv` (volsnap EID 25 × 4), `prefetch.csv` (`VSSADMIN.EXE`), `powershell-evtx.csv` (4104 with the exact command line) |
| 4688 for the Defender disable | `defender-evtx.csv` (5001 / 5007), `registry-runkeys.csv`, `powershell-evtx.csv` (4104 `Set-MpPreference`) |
| 4688 for the staging and exfiltration commands | `powershell-evtx.csv` (4104 with the 7-Zip and rclone command lines), `prefetch.csv`, `amcache.csv`, `shimcache.csv` |
| Everything about the file activity | `mft.csv`, `usn-journal.csv` — NTFS is untouched by log clearing |
| Everything about the egress volume | `srum.csv`, `network-flow.csv` |

The 4688 for the encryptor itself **does** survive, because it ran at 02:13:52 — four minutes *after* the clear. That asymmetry is worth noticing: the actor cleared the log and then produced fresh evidence into the empty log.

## Files

| File | Description | Rows |
|---|---|---|
| `generate.py` | Deterministic generator for everything below. `--dry-run`, `--out-dir`, `--seed`. | — |
| `mft.csv` | MFTECmd-style parse of `$MFT`: 418 `.vaulted` entries, 24 ransom notes, the deleted staging directory and its 12 archive volumes, the deleted encryptor, the share directory tree, and one unencrypted control directory | 523 |
| `usn-journal.csv` | MFTECmd parse of `$UsnJrnl:$J` — the encryption storm (2,162 records), the staging burst (847 records), tool delivery, cleanup, and normal file-server churn | 3,301 |
| `encrypted-files-inventory.csv` | One row per encrypted file: original name, original extension, encrypted name, size, original `$SI` Created, encryption time, and whether the directory has a note. The extension-sweep worksheet | 418 |
| `security-evtx.csv` | ACCT-FS01 Security log — **post-clear only**, starting with the 1102 | 24 |
| `dc-security-evtx.csv` | `FINANCE-DC01` Security log — the 4776 validation burst, the success, the Kerberos trail across the dwell window, `svc-backup`'s genuine nightly baseline, and the pivot to `a-mbrennan` | 263 |
| `jumphost-security-evtx.csv` | `JUMP-01` Security log — 212 × 4625 from `45.147.230.19`, the terminating 4624 Type 10, the discovery and credential-access 4688s, and 4648 explicit-credential events naming ACCT-FS01 | 238 |
| `system-evtx.csv` | System channel — 7045 service installs (`PSEXESVC`, `VaultUpd`), four `volsnap` EID 25 records, service-state churn | 41 |
| `defender-evtx.csv` | Defender Operational — 1116/1117 detections naming the actor's tooling, 5007 exclusions, 5001 real-time-protection disable at 02:02:18 | 17 |
| `terminalservices-evtx.csv` | RemoteConnectionManager 1149 and LocalSessionManager 21/22/23/25 — four attacker RDP sessions from `10.0.2.28` | 21 |
| `powershell-evtx.csv` | PowerShell Operational 4103/4104 — the surviving command lines for the Defender disable, the shadow-copy deletion, the 7-Zip staging command and the rclone invocation | 22 |
| `prefetch.csv` | PECmd output. `VAULT.EXE` RunCount 1, `RCLONE.EXE` RunCount 3, `VSSADMIN.EXE` LastRun 02:06:33 | 24 |
| `amcache.csv` | AmcacheParser output with SHA-1 / SHA-256 for every binary that executed, including `rclone.exe` and the unsigned encryptor | 13 |
| `shimcache.csv` | AppCompatCacheParser output. `Executed` is `NA` on every row — Server 2019 does not populate that bit | 22 |
| `registry-runkeys.csv` | Run / RunOnce values plus the Defender policy and Terminal Server keys — the persistence-inventory input | 9 |
| `network-flow.csv` | Flow records: 14 sessions to `185.220.101.44`, inbound RDP and SMB from the jump host, routine traffic, and the nightly backup job | 68 |
| `srum.csv` | SRUM per-application network usage. `rclone.exe` in three hourly buckets | 45 |
| `ransom-note.txt` | The `RECOVER-YOUR-FILES.txt` content, as dropped in all 24 directories | 62 lines |
| `rclone-conf-recovered.txt` | The deleted `rclone.conf`, recovered from unallocated space — names the WebDAV endpoint and the remote | 34 lines |
| `vssadmin-list-shadows.txt` | Live-triage output confirming no shadow copies survive, with the corroborating artifact list | 26 lines |

## Key timestamps (UTC)

| Time | Event | Source artifact |
|---|---|---|
| 2024-11-06 21:03:12 | First failed logon against `svc-backup` from `45.147.230.19` | `jumphost-security-evtx.csv` 4625 |
| 2024-11-06 21:46:58 | Last failed logon (212 attempts over 43 min 46 s) | `jumphost-security-evtx.csv` 4625 |
| 2024-11-06 21:47:22 | **Brute force succeeds** — 4624 LogonType 10 | `jumphost-security-evtx.csv`, `dc-security-evtx.csv` 4776 |
| 2024-11-07 02:11:40 | Discovery: `systeminfo`, `net view`, `nltest /dclist:`, `netscan.exe` | `jumphost-security-evtx.csv` 4688 |
| 2024-11-08 01:52:14 | LSASS dumped via `comsvcs.dll MiniDump`; `reg save` of SAM and SYSTEM | `jumphost-security-evtx.csv` 4688 |
| 2024-11-08 02:04:18 | **Account pivot** — domain admin `a-mbrennan` appears for the first time | `dc-security-evtx.csv` 4768 |
| 2024-11-09 01:19:44 | Lateral movement to ACCT-FS01; `PSEXESVC` installed | `system-evtx.csv` 7045, `jumphost-security-evtx.csv` 4648 |
| 2024-11-09 01:26:41 | First interactive RDP session on ACCT-FS01 | `terminalservices-evtx.csv` 1149 / 21 |
| 2024-11-09 02:14:07 | Defender on ACCT-FS01 quarantines `HackTool:Win64/Mimikatz.E` (`l.dmp`): the jump host's LSASS-dump technique, repeated here | `defender-evtx.csv` 1116/1117 |
| 2024-11-10 23:41:08 | Persistence — `VaultUpd` service and a `Run` value | `system-evtx.csv` 7045, `registry-runkeys.csv` |
| 2024-11-11 20:58:40 | Staging directory `C:\Windows\Temp\wu\` created | `usn-journal.csv`, `mft.csv` |
| 2024-11-11 20:58:41 | `rclone.exe` written to `C:\Windows\Temp\wu\` | `usn-journal.csv`, `mft.csv` |
| 2024-11-11 21:52:41 | Defender path exclusion added for the staging directory | `defender-evtx.csv` 5007 |
| 2024-11-11 21:14:22 – 22:37:45 | **Staging** — 12 split 7-Zip volumes, 36,829,344,563 bytes | `usn-journal.csv` (847 records) |
| 2024-11-11 22:41:06 – 2024-11-12 00:52:10 | **Exfiltration** — 14 sessions to `185.220.101.44`, 37,312,004,096 bytes out | `network-flow.csv`, `srum.csv` |
| 2024-11-12 02:02:18 | **Defender real-time protection disabled** | `defender-evtx.csv` 5001 |
| 2024-11-12 02:06:33 | **`vssadmin delete shadows /all /quiet`** | `prefetch.csv`, `system-evtx.csv` volsnap 25, `powershell-evtx.csv` 4104 |
| 2024-11-12 02:09:41 | **Security log cleared** — earliest surviving record on this host | `security-evtx.csv` 1102 |
| 2024-11-12 02:11:04 | `vault.exe` written to `C:\Windows\Temp\` | `usn-journal.csv` |
| 2024-11-12 02:13:52 | **Encryptor executes** (post-clear, so the 4688 survives) | `security-evtx.csv` 4688, `prefetch.csv` |
| 2024-11-12 02:14:06 | First encrypted file | `usn-journal.csv`, `encrypted-files-inventory.csv` |
| 2024-11-12 03:38:41 | Last ransom note written — encryption ends | `mft.csv`, `usn-journal.csv` |
| 2024-11-12 03:39:12 | Encryptor deleted | `usn-journal.csv` |
| 2024-11-12 03:41:22 | Staging directory deleted (12 archives + 4 tool files + the folder) | `usn-journal.csv` |
| 2024-11-12 04:12:44 | Actor logs off | `security-evtx.csv` 4634, `terminalservices-evtx.csv` 23 |
| 2024-11-12 08:05:11 | Incident response session begins | `terminalservices-evtx.csv` 1149 |

## Scoping numbers

Every value below is produced by a query against the files in this folder; the Lab 12 walkthrough shows the query for each.

| Field | Value |
|---|---|
| Encryption start / stop | 2024-11-12 02:14:06 / 03:38:41 UTC |
| Duration | 84 minutes 35 seconds |
| Encrypted file count | **418** |
| Encrypted data volume | **78,662,133,156 bytes** (73.26 GiB) |
| Affected directories | **24** (one `RECOVER-YOUR-FILES.txt` in each) |
| Directories excluded | `C:\Windows\`, `C:\Program Files\`, `C:\ProgramData\`, the staging directory, and `C:\Shares\Finance\Reports\Archive` |
| USN records in the encryption window | **2,162** |
| Peak USN records in one minute | **30** (02:52, 03:20, 03:23) |
| Encryption performed locally? | **Yes** — 4688 at 02:13:52 plus a `VAULT.EXE` Prefetch entry, and no mass 5145 share access |
| Shadow copies available? | **No** — `vssadmin list shadows` returns nothing; volsnap 25 × 4 at 02:06 |
| Staged volume | 36,829,344,563 bytes (34.30 GiB) across 12 archive volumes |
| Egress volume | 37,312,004,096 bytes (34.75 GiB) — 1.3 % above the staged set, consistent with a completed transfer |
| SRUM `rclone.exe` bytes sent | 36,884,201,472 bytes (34.35 GiB) |

The single most instructive line in the scoping table is the pair of volume numbers. `C:\Shares\IT\Backups\SQL` holds **5 files** — 1.2 % of the encrypted count — and **67.28 GiB**, which is 91.8 % of the encrypted volume. Count and volume are different recovery problems and they rank the directories in almost opposite orders.

## What you will and won't find

The dataset contains:

- A complete, self-consistent encryption event with the USN rename-pair signature, per-directory note placement, and a per-minute histogram whose shape can be read
- Three independent surviving sources for the initial access (jump host 4625 burst, DC 4776 burst, TerminalServices 1149)
- The full defense-evasion sequence with each step evidenced by something other than the Security log
- Staging evidence at archive-volume granularity, transfer-tool execution evidence, a recovered `rclone.conf`, and two independent egress-volume sources
- Persistence that would survive a restore (`VaultUpd` service, `Run` value, `fDenyTSConnections=0`)
- Deliberate benign noise in every file — routine service churn, legitimate administrative RDP, six nightly backup jobs each larger than the exfiltration

It does not contain:

- **An rclone `--log-file`.** The invocation in `powershell-evtx.csv` omits it, so there is **no per-file transfer record**. This is what holds the exfiltration finding at *highly likely* rather than *confirmed* under the tiered language in Chapter 12 §12.5.5. The staged set is known at archive-volume granularity and, from the 7-Zip command line, at source-directory granularity — not at file granularity.
- **A memory image.** ACCT-FS01 was still running when the responder arrived, so one *should* have been taken; the lab treats its absence as a preservation failure to write up, not as a neutral fact.
- **Proxy logs.** The `rclone/v1.65.0` user-agent finding Chapter 12 §12.5.4 describes is not available here. Flow and SRUM are the egress sources.
- **The pre-clear ACCT-FS01 Security log.** No shadow copy survived, so there is no recoverable earlier `Security.evtx`.
- **Backup-platform logs.** Whether the backup catalog deletion succeeded, and whether any restore point predates 2024-11-06, has to be answered from the backup platform, not from this host.

## Modelling notes and caveats

- **The USN volumes are downsampled.** A real file server produces tens of thousands of USN records per minute during bulk encryption. This dataset produces a 2–30 per minute plateau so the binning exercise can be done by hand, in a spreadsheet, or in a five-line script. The *shape* is faithful; the amplitude is not. Do not quote the per-minute rates here as representative.
- **Prefetch on a server.** Application prefetching is not enabled by default on Windows Server. This host's build image sets `EnablePrefetcher=3`, which is why `prefetch.csv` exists. On many real file servers it would not, and the `VAULT.EXE` RunCount 1 entry — the thing that proves local execution — would be missing. Note that `VAULT.EXE` has no `PreviousRun` values: a single-run encryptor barely makes it to disk.
- **`Executed` is `NA` throughout `shimcache.csv`.** Windows 8 and later stopped populating the InsertFlags bit. A ShimCache row is evidence of *presence*, never of execution. A dataset that quietly filled that column in would teach the opposite.
- **The encryption was performed locally.** Chapter 12 §12.3.4 describes the alternative — mass modification on a file server with *no* local execution evidence, meaning the encryption ran over SMB from another host. That is not this case, and the walkthrough asks you to prove it rather than assume it. `security-evtx.csv` contains exactly one 5140 and no 5145 storm.
- **The DC and jump-host logs live in this folder** even though they were collected from other hosts. Real collections are organised by host; these are here because Lab 12's backwards-chaining exercise is unanswerable without them, and splitting them into `Data/JUMP-01/` and `Data/FINANCE-DC01/` would suggest those hosts have complete datasets, which they do not.
- **Byte-for-byte reproducible.** `python3 generate.py --out-dir <dir>` twice into two directories produces identical files. Seeds are derived with `zlib.crc32`, not Python's per-process-salted `hash()`.

## Tooling assumptions

The files are formatted to match what an analyst would have after running:

- [`MFTECmd`](https://ericzimmerman.github.io/) over `$MFT` and `$UsnJrnl:$J`
- [`EvtxECmd`](https://ericzimmerman.github.io/) over `Security.evtx`, `System.evtx`, and the Defender, TerminalServices and PowerShell operational channels
- [`PECmd`](https://ericzimmerman.github.io/) over `%SystemRoot%\Prefetch\*.pf`
- [`AmcacheParser`](https://ericzimmerman.github.io/) over `Amcache.hve`
- [`AppCompatCacheParser`](https://ericzimmerman.github.io/) over the `SYSTEM` hive with `-c 1`
- [`RECmd`](https://ericzimmerman.github.io/) over `SYSTEM`, `SOFTWARE` and `NTUSER.DAT`
- `srum-dump` over `C:\Windows\System32\sru\SRUDB.dat`
- A netflow collector or firewall flow export for `network-flow.csv`
- The `encrypted-files-inventory.csv` is the kind of output an analyst produces themselves — an extension sweep exported to CSV — rather than a tool's native format

## Notes for the responder

- **The encryption is the end of the intrusion.** Six days of it happened before 02:14 on 2024-11-12. An investigation scoped to the 84-minute window answers a question nobody is asking.
- **The 1102 is a finding, not a wall.** It names the account (`svc-backup`) and the time (02:09:41), which simultaneously establishes that the account was compromised and that the clearing was deliberate.
- **Say what the log retention actually bounds.** The jump-host log covers 2024-11-04 onwards; the DC log reaches back to 2024-11-01. "Earliest observed activity: 2024-11-06 21:03; JUMP-01 log retention begins 2024-11-04; earlier activity cannot be excluded" is the defensible sentence. Note how little headroom that leaves — the first observed attacker activity is barely two days inside the retention boundary, which is exactly when the caveat matters most.
- **Do not upgrade the exfiltration finding.** Staging plus tool execution plus consistent egress volume is *highly likely*, not *confirmed*. There is no per-file record. Write the tier explicitly and name the gap.
- **The persistence survives a restore.** The `VaultUpd` service, the `Run` value and `fDenyTSConnections=0` were all set on or before 2024-11-10. Any backup taken after 2024-11-06 is inside the dwell window and must be checked, not assumed clean.

## Note on registry `LastWriteTime`

`registry-runkeys.csv` reports **one `LastWriteTime` per key**, repeated on every
value row under that key. That is not a flattening artifact of the export — it is
how the registry works. `LastWriteTime` is a property of the **key**; individual
values carry no timestamp of their own.

The practical consequence, and the reason the column looks redundant: a recent
`LastWriteTime` tells you that *something* under the key changed, not *which*
value changed, and not what it changed from. You cannot date an individual Run
value from this column alone. To attribute a specific value to a specific time
you need a second source — registry transaction logs (`.LOG1` / `.LOG2`), a prior
copy of the hive from a Volume Shadow Copy, or a corroborating artifact such as
the MFT record of the binary the value points at.

Chapter 5 §5.1.2 covers the mechanism; Chapter 10 §10.5 covers the trap it sets
when you drop these rows into a timeline.

---

*Simulated ACCT-FS01 dataset — Windows Forensics for Beginners*
