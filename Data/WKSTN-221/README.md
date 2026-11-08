# WKSTN-221 — Simulated Triage Dataset

Anchor scenario for Labs 02, 03, 04, 09, and 10. Used as the cross-reference for hypothesis testing, timeline construction, and multi-source correlation throughout the IR-process chapters.

## Scenario

`WKSTN-221` is a finance department workstation assigned to user `payroll-admin`. At **14:23:00 UTC on 2024-11-14**, the SOC escalated an EDR alert showing the process chain `OUTLOOK.EXE → POWERSHELL.EXE → CMD.EXE`, with a partial PowerShell command line containing `-EncodedCommand`. Within minutes:

- An outbound TCP/443 connection was established to `91.214.47.22`
- A binary named `update.exe` was created in the user's `Temp\` directory and executed
- The binary was deleted approximately three minutes later
- The user account authenticated to `FILESVR-03` with explicit credentials

The data in this folder represents what an analyst would have after running standard parsers against a triage collection of WKSTN-221.

## Key timestamps (UTC)

| Time | Event | Source artifact |
|---|---|---|
| 08:43:17 | `payroll-admin` interactive logon (normal start of day) | `security-evtx.csv` EID 4624 |
| 13:55:00 | System clock moved forward 2 s, from 13:54:58, by `svchost.exe` | `system-evtx.csv` Kernel-General EID 1 |
| 14:18:55 | LNK file created for `Q4_Payroll_Review.xlsm` | `lnk-files.csv` |
| 14:19:38 | `OUTLOOK.EXE` spawned `POWERSHELL.EXE` | `security-evtx.csv` EID 4688 |
| 14:19:42 | Outbound TCP/443 connection to `91.214.47.22` (ends 14:19:48, 184,221 bytes received) | `network-flow.csv` |
| 14:19:42.6–14:19:48 | Encrypted payload `a.tmp` (174,080 bytes) written to `Temp\` while that flow runs | `usn-journal.csv`, `mft.csv` |
| 14:20:07.6 | XOR decode script block reads `a.tmp`, writes `b.tmp`, removes `a.tmp` | `powershell-evtx.csv` EID 4104 |
| 14:20:11 | `b.tmp` written on MFT record 22417 and `a.tmp` deleted. `b.tmp` is then renamed to `update.exe` and keeps the record | `usn-journal.csv` (history), `mft.csv` (current name only) |
| 14:21:03 | `update.exe` executed (run count 1) | `prefetch.csv`, `security-evtx.csv` EID 4688 |
| 14:21:55 | Large outbound transfer to `91.214.47.22` (≈180 KB out / 2.3 MB received) | `network-flow.csv`, `srum.csv` (`update.exe`) |
| 14:22:58 | Scheduled task `WindowsUpdateSync` registered | `scheduled-tasks.csv` |
| 14:23:02 | WMI subscription `WindowsUpdateFilter` / `WindowsUpdateConsumer` created | `wmi-persistence.csv` |
| 14:23:44 | `update.exe` deleted from `Temp\` | `usn-journal.csv` |
| 14:31:05 | Network logon (type 3) from `10.0.4.17` | `security-evtx.csv` EID 4624 |
| 14:33:18 | Explicit credential use to `FILESVR-03` | `security-evtx.csv` EID 4648 |

## Files

| File | Description | Rows |
|---|---|---|
| `mft.csv` | MFTECmd-style parse of NTFS `$MFT`, focused on `Temp\` and recent activity | 77 |
| `usn-journal.csv` | USN Journal entries showing creation/deletion/rename activity | 51 |
| `security-evtx.csv` | Parsed Security event log — logons, process creation, credential use | 38 |
| `system-evtx.csv` | Parsed System event log — services, reboots, and one clock change | 18 |
| `powershell-evtx.csv` | PowerShell operational log — EID 4104 script blocks | 9 |
| `prefetch.csv` | Prefetch entries showing executable runs | 20 |
| `amcache.csv` | Amcache binary metadata with SHA-1 hashes | 15 |
| `srum.csv` | SRUM per-process network and CPU usage | 20 |
| `lnk-files.csv` | LNK file metadata from `Recent\` | 10 |
| `jump-lists.csv` | Jump List entries per application | 11 |
| `registry-runkeys.csv` | `Run`, `RunOnce` registry values | 13 |
| `registry-services.csv` | Service definitions, including any new services | 20 |
| `network-flow.csv` | NetFlow-style records for the relevant time window | 20 |
| `shimcache.csv` | AppCompatCacheParser output from the `SYSTEM` hive — `update.exe` at cache position 0 | 49 |
| `scheduled-tasks.csv` | `\Windows\System32\Tasks` inventory, including one attacker-registered task | 16 |
| `wmi-persistence.csv` | `root\subscription` filters, consumers and bindings, including one malicious pair | 6 |

## What you will and won't find

The dataset is curated, not exhaustive. It contains:

- The full execution chain leading to the `update.exe` activity
- Enough background entries that filtering and correlation are non-trivial
- Realistic timestamps, file paths, and event IDs

It does not contain:

- The full live-OS background noise of a real workstation (which would be tens of thousands of additional rows per source)
- Memory image content (this scenario does not include a memory capture; see `WEB-APP-03/` for memory data)
- Decrypted PowerShell payload bodies beyond what would appear in EID 4104

## Note on the ShimCache `Executed` column

Every row in `shimcache.csv` has `Executed` set to `NA`. That is not missing
data. On Windows 8 and later the "executed" insert flag that older
AppCompatCache formats carried is no longer populated, so
`AppCompatCacheParser` reports `NA` and there is nothing better to report.

A ShimCache entry means the file was **present and enumerated by the
application-compatibility subsystem** — not that it ran. `update.exe` is at
cache position 0 with `LastModifiedTimeUTC` 14:20:11, matching the MFT `$SI`
modified time for entry 22417. Execution is proved by `prefetch.csv` (run
count 1) and Security EID 4688, not by this file. The two artifacts together
are strong; either alone is not.

Two further properties to preserve if you edit the file:

- **Order is insertion order**, most-recent first, and is the artifact's only
  ordering signal. Several older OS binaries further down the list carry
  *newer* file timestamps than rows above them. Sorting by
  `LastModifiedTimeUTC` destroys the evidence.
- The export was taken with `-c 1` (ControlSet001 only), which is why
  `Duplicate` is `False` throughout.

## Note on the persistence mechanisms

`scheduled-tasks.csv` and `wmi-persistence.csv` describe the same adversary
action performed twice, forty-six seconds before `update.exe` was deleted:

- Scheduled task `WindowsUpdateSync` (`\Microsoft\Windows\WindowsUpdate\`),
  created 14:22:58, authored by `FINANCE\payroll-admin` rather than by
  Microsoft, with `LastRunTime` = `1999-11-30 00:00:00` and
  `LastTaskResult` = `267011` (`0x41303`, "task has never run").
- WMI event subscription `WindowsUpdateFilter` / `WindowsUpdateConsumer` in
  `root\subscription`, created 14:23:02, using the classic
  `SystemUpTime >= 200 AND < 320` boot-window trigger.

Both carry the **same** `-EncodedCommand` payload that appears in the 14:19:38
EID 4688 for `powershell.exe`. Decoding all three and observing they are
identical is the intended correlation exercise. `wmi-persistence.csv` also
contains one consumer with no binding and one filter with no consumer —
neither is live persistence, and telling the difference is the point.

## Note on the encoded PowerShell command

The PowerShell command line in the EID 4688 entry (and the EID 4104 entry in `powershell-evtx.csv`) contains a base64 string. Decoding it will reveal the simulated attacker payload — a download cradle that fetched `update.exe`. Decoding is left to the reader as part of Lab09 and Lab10 work.

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

*Simulated WKSTN-221 dataset — Windows Forensics for Beginners*
