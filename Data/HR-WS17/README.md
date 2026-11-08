# HR-WS17 — Simulated Triage Dataset (Capstone)

Anchor scenario for **Lab 11 — Forensic Challenge: Investigating Unauthorized Data Exfiltration**. This is the capstone dataset for the book: every artifact class touched in earlier chapters appears here, and the case can only be resolved by correlating across them. Treat it as the input to a real exfiltration investigation, not as a single-artifact exercise.

## Scenario

`HR-WS17` is an HR/finance workstation belonging to user `hr-user` (domain `FINANCE`). The host was assigned to a now-departed employee whose role granted them access to confidential pricing data — including bid materials and customer-specific pricing strategy.

The workstation was preserved at offboarding by the IT team: WinPmem was run against the live host at **18:01:12 UTC** — 62 seconds before the user's final logoff — and the disk was then imaged with FTK Imager. Three weeks later, legal asked whether the departing employee took confidential pricing data on or near their last day. Specifically:

- A folder `C:\HR\Pricing\` contained three known-sensitive files: `Q4_Customer_Pricing.xlsx`, `Pricing_Strategy_Confidential.docx`, and `Margins_Q3.xlsx`. The SHA-256 hashes of those files (as held by legal at the time of the request) are recorded in `pricing-files-known-hashes.txt`.
- Forensics has been asked to determine whether any of those files left the host through a removable device, a personal cloud account, webmail, or another channel — and to give a defensible answer with each conclusion's confidence level made explicit.

The case date is **2024-11-12**. The exfiltration window of interest is **2024-11-12 17:35–18:00 UTC** (roughly the last 25 minutes of the user's session before they signed off for the day).

## Channel summary

| Channel | Status | Strongest evidence |
|---|---|---|
| Removable media (Kingston DataTraveler 3.0, serial `001A92053B7CBE3196B40A0F`) | **Confirmed** | USBSTOR install record, `MountedDevices` binding to `E:`, shellbags into `E:\Confidential\Pricing\`, three LNK files with the device's volume serial number, MFT entries for transient copies in `Temp\` |
| Personal OneDrive (`hr.user.personal@outlook.com`) | **Confirmed** | Personal account in `HKCU\...\OneDrive\Accounts\Personal`, sync-engine database rows for `Q4_Customer_Pricing.xlsx` and `Pricing_Strategy_Confidential.docx` between 17:46 and 17:49 UTC, OneDrive client log entries showing successful uploads, SRUM bytes-out for `OneDrive.exe` in the same window |
| Browser webmail upload (Outlook on the web) | **Probable, not confirmed from host alone** | Browser history shows navigation to `outlook.live.com` at 17:51 UTC; SRUM shows outbound bytes for `msedge.exe` consistent with a small upload; no specific upload trace recoverable from cache or form data on the host |
| Personal email client (PST/OST), printer/MTP/Bluetooth, network share | Not observed | No artifacts in scope |

The first two channels are independently supported by multiple artifact classes lining up in time. The third is consistent with the rest of the picture but requires provider-side mail logs (Microsoft 365 audit) to elevate from probable to confirmed — see the chapter's "What you would want from provider-side logs" discussion.

## Key timestamps (UTC)

| Time | Event | Source artifact |
|---|---|---|
| 08:42:11 | `hr-user` interactive logon (normal start of day) | `security-evtx.csv` EID 4624 |
| 17:38:42 | `Q4_Customer_Pricing.xlsx` opened locally from `C:\HR\Pricing\` | `lnk-files.csv`, `jump-lists.csv` |
| 17:39:05 | First pricing file copied into `Temp\` | `mft.csv`, `usn-journal.csv` |
| 17:39:18 | Second pricing file copied into `Temp\` | `mft.csv`, `usn-journal.csv` |
| 17:42:08 | Kingston DataTraveler 3.0 first installation | `usbstor.csv` |
| 17:42:14 | Volume `{f1d2e9a4-...}` bound to drive `E:` | `mountpoints.csv` |
| 17:43:11 | `E:\Confidential\` first interacted (shellbag) | `shellbags.csv` |
| 17:43:42 | `E:\Confidential\Pricing\` first interacted | `shellbags.csv` |
| 17:44:18 | LNK file created for `E:\Confidential\Pricing\Q4_Customer_Pricing.xlsx` | `lnk-files.csv` |
| 17:44:55 | LNK file created for `E:\Confidential\Pricing\Pricing_Strategy_Confidential.docx` | `lnk-files.csv` |
| 17:45:32 | LNK file created for `E:\Confidential\Pricing\Margins_Q3.xlsx` | `lnk-files.csv` |
| 17:46:02 | Personal OneDrive account first signed in; second `OneDrive.exe` starts | `onedrive-accounts.csv`, `onedrive-logs-extract.txt`, `volatility-pslist.txt` |
| 17:46:42 | First file enters Personal OneDrive sync queue (`Q4_Customer_Pricing.xlsx`) | `onedrive-syncdb.csv`, `onedrive-logs-extract.txt` |
| 17:48:41 | Second file synchronized (`Pricing_Strategy_Confidential.docx`) | `onedrive-syncdb.csv`, `onedrive-logs-extract.txt` |
| 17:49:18 | OneDrive sync window closes | `onedrive-logs-extract.txt`, `srum.csv` |
| 17:51:04 | `msedge.exe` navigates to `https://outlook.live.com/mail/0/` | `browser-history.csv`, `srum.csv` |
| 17:55:11 | Both transient copies in `Temp\` deleted | `usn-journal.csv` |
| 17:57:42 | `C:\HR\Pricing\` directory itself deleted | `usn-journal.csv`, `mft.csv` |
| 17:57:42 | Three pricing files sent to the Recycle Bin | `recyclebin.csv`, `usn-journal.csv` |
| 17:58:02 | Recycle Bin emptied (`$R` payloads unlinked, `$I` records recoverable) | `recyclebin.csv` |
| 17:58:30 | Kingston DataTraveler 3.0 removed | `usbstor.csv` |
| 18:01:12 | WinPmem memory capture taken while the session was still live | `volatility-*.txt` |
| 18:02:14 | `hr-user` logoff (last day at the company) | `security-evtx.csv` EID 4634 |

The earlier part of 2024-11-12 contains normal HR / pricing-team activity — Outlook, Edge, several Excel files opened from local and corporate-OneDrive paths — that should not be confused with the incident.

## Files

| File | Description | Rows |
|---|---|---|
| `pricing-files-known-hashes.txt` | SHA-256 hashes of the three pricing files, as provided by legal | 3 entries |
| `mft.csv` | MFTECmd-style parse of NTFS `$MFT`. Includes the local pricing folder, the transient `Temp\` copies (now deleted), the LNK files, the OneDrive client install, and normal background entries | ~40 |
| `usn-journal.csv` | USN Journal entries showing the Temp create/delete cycle, the LNK creates, the local pricing folder deletion, and other activity | ~40 |
| `security-evtx.csv` | Parsed Security event log — interactive logons for `hr-user`, `cmd.exe` and `explorer.exe` process creation around the exfil window, and the offboarding-day session | ~25 |
| `prefetch.csv` | Prefetch entries including `7zG.EXE` (7-Zip GUI), `EXCEL.EXE`, `WINWORD.EXE`, `MSEDGE.EXE`, `ONEDRIVE.EXE`, and standard system executables | ~15 |
| `amcache.csv` | Amcache binary metadata with SHA-1 hashes for any binaries that ran on the host, including `7zG.exe` and `OneDrive.exe` | ~12 |
| `srum.csv` | SRUM per-process network usage. `OneDrive.exe` shows outbound bytes during the 17:46–17:49 sync window; `msedge.exe` shows outbound bytes around 17:51 | ~12 |
| `lnk-files.csv` | LNK metadata from `Recent\`. Each pricing file has two LNKs — one for the local path under `C:\HR\Pricing\` and one for the USB path under `E:\Confidential\Pricing\`. The USB LNKs carry the Kingston device's volume serial number | ~12 |
| `jump-lists.csv` | Jump-list entries for Excel and Word showing recent-file MRUs with both local and USB paths | ~10 |
| `shellbags.csv` | Shellbag entries showing the user navigated `E:\`, `E:\Confidential\`, and `E:\Confidential\Pricing\` at 17:43 UTC, plus normal local folder navigation | ~15 |
| `usbstor.csv` | `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` device history, with the suspect Kingston DataTraveler and several earlier benign devices | 5 |
| `mountpoints.csv` | `HKLM\SYSTEM\MountedDevices` mappings, binding the Kingston volume GUID to `E:` | ~8 |
| `onedrive-accounts.csv` | `HKCU\Software\Microsoft\OneDrive\Accounts` entries for both Business1 (`hr-user@finance.example.com`) and Personal (`hr.user.personal@outlook.com`) | 2 |
| `onedrive-syncdb.csv` | Sync-engine database rows from the personal account showing the two pricing files entering the sync queue between 17:46 and 17:49 UTC | 2 |
| `onedrive-logs-extract.txt` | Plaintext extract from `%LOCALAPPDATA%\Microsoft\OneDrive\logs\` showing personal-account upload activity in the sync window | ~35 lines |
| `browser-history.csv` | Edge `History` SQLite extract — normal background browsing plus the navigation to `outlook.live.com` at 17:51 UTC | ~20 |
| `shimcache.csv` | AppCompatCacheParser output from the `SYSTEM` hive. Covers `7zG.exe` **and** `7z.exe` — the latter has an Amcache row but no Prefetch entry | 40 |
| `recyclebin.csv` | RBCmd parse of `C:\$Recycle.Bin\<SID>\`. The three pricing files are orphaned `$I` records (the bin was emptied) | 8 |
| `volatility-pslist.txt` | `windows.pslist` — the live session at acquisition, including **two** `OneDrive.exe` processes | 40 processes |
| `volatility-netscan.txt` | `windows.netscan` — sockets per PID; the personal OneDrive instance talks to a different endpoint than the corporate one | ~21 |
| `volatility-cmdline.txt` | `windows.cmdline` — Office command lines still carrying `C:\HR\Pricing\` paths that no longer exist on disk | 40 |

> **Schema note:** This folder's `onedrive-accounts.csv` and `onedrive-syncdb.csv` use a richer column set than `Data/HR-LT12/` (e.g. `Sha256ContentHash`, `UploadCompletedUtc`). Both layouts are reasonable; the labs are independent exercises and each lab uses only its own dataset.

## What you will and won't find

The dataset is curated, not exhaustive. It contains:

- Three artifact classes confirming the USB channel (USBSTOR + MountedDevices + shellbags + LNK)
- Three artifact classes confirming the personal-OneDrive channel (Accounts registry + sync database + client logs + SRUM)
- Two artifact classes that are *suggestive* of a webmail upload (browser history + SRUM bytes-out)
- File-system evidence that staging through `Temp\` happened and was then cleaned up
- Some cleanup activity (the `C:\HR\Pricing\` folder itself was deleted near the end of the session) — that deletion is itself evidence

It does not contain:

- A full memory image. The three Volatility 3 text files are plugin *output* from the WinPmem capture, not the image itself. If a lab step needs a plugin that is not in this folder, treat that as a collection question ("what else would you have run at acquisition time?") rather than assuming the answer is absent
- Any evidence of malware, injected code, or command-and-control. This is an insider case: nothing in memory is malicious, and `malfind`-style findings would be a fabrication. See `WEB-APP-03/` for the malware-in-memory dataset
- Provider-side OneDrive audit logs or Microsoft 365 mail-flow logs. The OneDrive evidence here represents what is recoverable from the local SQLite database and client logs, not what the cloud tenant would show
- The contents of any uploaded webmail message — that would live on the mail server, not the host
- A `network-flow.csv` for the host. Use SRUM as the bytes-out indicator and treat the lack of flow telemetry as a real-world gap (not every endpoint is in scope for NetFlow)

## Tooling assumptions

The CSVs are formatted to match what an analyst would have after running:

- [`MFTECmd`](https://ericzimmerman.github.io/) over `$MFT` and `$UsnJrnl:$J`
- [`EvtxECmd`](https://ericzimmerman.github.io/) over `Security.evtx`
- [`PECmd`](https://ericzimmerman.github.io/) over `%SystemRoot%\Prefetch\*.pf`
- [`AmcacheParser`](https://ericzimmerman.github.io/) over `Amcache.hve`
- `srum-dump` over `SRUDB.dat`
- [`LECmd`](https://ericzimmerman.github.io/) and [`JLECmd`](https://ericzimmerman.github.io/) over `Recent\` and `Recent\AutomaticDestinations\`
- [`SBECmd`](https://ericzimmerman.github.io/) over `UsrClass.dat`
- [`RECmd`](https://ericzimmerman.github.io/) (or `Registry Explorer`) over `SYSTEM`, `NTUSER.DAT`, and `UsrClass.dat`
- DB Browser for SQLite over the personal-account `<UserCid>SyncEngineDatabase.db`
- DB Browser for SQLite over Edge `History`
- Direct text extraction from `%LOCALAPPDATA%\Microsoft\OneDrive\logs\Personal\SyncDiagnostics-*.log`
- [`AppCompatCacheParser`](https://ericzimmerman.github.io/) over the `SYSTEM` hive
- [`RBCmd`](https://ericzimmerman.github.io/) over `C:\$Recycle.Bin\<SID>\` plus the `$I` records carved from unallocated space
- `vol.py -f HR-WS17-memory.raw windows.pslist` / `windows.netscan` / `windows.cmdline` (Volatility 3 Framework 2.5.2)

## Notes for the responder

- **The file hashes matter.** `pricing-files-known-hashes.txt` is the comparison target. If you can demonstrate that the synchronized OneDrive blob, the LNK target, and the local file all share an identifier consistent with the legal-provided hash, that materially strengthens the case.
- **Two LNKs per file is intentional.** Windows creates a separate LNK per access location, so each pricing file appears once for the local open and once for the USB open. The USB LNKs are distinguishable by volume serial number — that's the binding the chapter relies on.
- **The `C:\HR\Pricing\` deletion is evidence.** Cleanup activity is not an evidentiary gap; it is its own observation.
- **Webmail is "probable, not confirmed".** Be precise in the case summary about which channel is which confidence level. Overclaiming on webmail would weaken every other defensible finding in the report.

## Note on the ShimCache `Executed` column

Every row in `shimcache.csv` reads `Executed = NA`. HR-WS17 is Windows 10, and
on Windows 8 and later the "executed" insert flag older cache formats carried
is simply not populated — `AppCompatCacheParser` has nothing to report. A
ShimCache row proves the binary was **present and enumerated**, not that it
ran.

`LastModifiedTimeUTC` is the *binary's* file modification time, never a run
time. `OneDrive.exe` and `msedge.exe` both carry `2024-11-12 03:14:00` (the
morning's update), which says nothing about when the user launched them.
Reading those as execution times is the classic ShimCache error.

Ordering is insertion order, most recent first. Do not sort the file by
timestamp — position is the only ordering signal it carries.

The one genuinely new fact here is `7z.exe`: it has an `amcache.csv` row but
**no Prefetch entry**, so ShimCache is the second artifact that puts it on the
host at all.

## Note on the Recycle Bin

The three pricing rows in `recyclebin.csv` are **orphaned `$I` records**. The
user deleted the contents of `C:\HR\Pricing\` to the Recycle Bin at
17:57:42 and emptied the bin twenty seconds later, which unlinks both the
`$I` metadata and the `$R` payload. These three `$I` records were recovered
from unallocated space and parsed individually; the matching `$R` files could
not be recovered.

That distinction is load-bearing for the report. The `$I` proves *which* files
were deleted and *when* — the 17:57:42 values agree to the second with the
`FileDelete` rows in `usn-journal.csv` and with the `InUse=False` MFT entries
20420–20422, three sources on one event. It does **not** give you the file
contents back, so hash comparison against `pricing-files-known-hashes.txt` is
not available through this channel. Say so explicitly rather than implying the
deleted copies were recovered.

Note also what is absent:

- The two transient copies staged in `%TEMP%` were removed at 17:55:11 by
  `cmd.exe /c del`. `del` bypasses the Recycle Bin entirely, so they have no
  `$I` record at all.
- Nothing from the `E:` volume appears. Removable media does not use the
  system volume's Recycle Bin.

## Note on the memory output

The three `volatility-*.txt` files use the same plain-text format as
`Data/WEB-APP-03/` — Volatility 3's tab-delimited renderer with tabs expanded
at tabstop 8 — so both hosts' memory output reads with identical tooling.

This is an insider-data-theft case, so there is deliberately no injected code,
no unbacked executable memory, and no C2 socket. The forensic value is
elsewhere:

- **Two `OneDrive.exe` processes.** PID 3184 started at 08:42:54, shortly
  after the 08:42:11 logon (the corporate Business1 account); PID 6428
  started at **17:46:02**, mid-session, matching the Personal account's
  `FirstAdded` value in `onedrive-accounts.csv` to the second. A second sync
  client appearing in the middle of the afternoon is the clearest
  memory-side indicator of the personal-account channel.
  `volatility-netscan.txt` separates them further: PID 6428 holds established
  TCP/443 sockets to the consumer OneDrive endpoint that PID 3184 never
  touches.
- **`C:\HR\Pricing\` paths in live command lines.** `EXCEL.EXE` (PID 4218)
  and `WINWORD.EXE` (PID 4258) still carry the local pricing-file arguments in
  `volatility-cmdline.txt`, character-for-character identical to the 17:38:42
  and 17:39:18 EID 4688 records — for a folder that was deleted at 17:57:42
  and is `InUse=False` in the MFT by the time the disk was imaged.

Two limits worth stating in the case notes:

- `7zG.exe` (17:40:11) and `cmd.exe` (17:55:11) are **not** in the process
  list. Both had exited before acquisition. Memory is a snapshot, not a
  history; Prefetch and the Security log still have them, and the gap is not a
  contradiction.
- The command lines do **not** show the `E:\Confidential\Pricing\` copies
  opened at 17:44–17:45. Office is single-instance, so those opens were handed
  to the already-running processes over DDE and never reached a command line.
  The LNK files answer that question; memory does not. Knowing which artifact
  answers which question is the exercise.

Finally, `winpmem_mini_x6` (PID 7284) is the acquisition tool itself, writing
to a network share rather than to the subject disk. Every memory image
contains the footprint of whatever captured it, and documenting that is part
of a defensible acquisition record.

---

*Simulated HR-WS17 dataset — Windows Forensics for Beginners*
