# FIN-WS23 — Simulated Triage Dataset

Anchor scenario for Lab 06 (Shell Items, Removable Devices, and Application Artifacts). Used as the cross-reference for shell-artifact analysis, removable-device profiling, and execution-evidence correlation throughout Chapter 6.

## Scenario

`FIN-WS23` is a finance department workstation joined to the `FINANCE` domain, assigned to user `j.smith`. At **06:58:30 UTC on 2024-11-13**, an EDR alert flagged the process chain `WINWORD.EXE → POWERSHELL.EXE` after the user opened a macro-enabled document, `Q4_Vendor_Review.docm`, downloaded through a link in an email. Within minutes:

- A binary named `dl.exe` was created in the user's `Downloads\` directory and executed
- An outbound TCP/443 connection was established to a low-reputation host
- The user account remained interactively logged on through the morning
- A SanDisk Cruzer USB device (`VID_0781&PID_5567`) was attached briefly at 09:14 UTC and mounted as `F:`
- Several documents were opened from the USB volume before it was removed

The data in this folder represents what an analyst would have after running standard parsers (`LECmd`, `JLECmd`, `PECmd`, `AmcacheParser`, `SrumECmd`, `RECmd`, `SBECmd`) against a triage collection of FIN-WS23.

## Key timestamps (UTC)

| Time | Event | Source artifact |
|---|---|---|
| 06:28:11 | `j.smith` interactive logon (normal start of day) | `security-evtx.csv` EID 4624 |
| 06:31:42–06:32:18 | Lure article, then its `Q4_Vendor_Review.docm` download URL, opened from an email link | `browser-history.csv` |
| 06:57:48 | LNK file created for `Q4_Vendor_Review.docm` | `lnk-files.csv` |
| 06:58:00 | `WINWORD.EXE` opened `Q4_Vendor_Review.docm` | `prefetch.csv`, `jump-lists.csv` |
| 06:58:30 | `WINWORD.EXE` spawned `POWERSHELL.EXE` | `security-evtx.csv` EID 4688 (parent), `prefetch.csv` (run time) |
| 06:59:14 | `dl.exe` first run from `Downloads\` (run count 1) | `prefetch.csv`, `amcache.csv` |
| 07:00 | SRUM row for 06:30–07:00 attributes outbound bytes to `dl.exe` | `srum.csv` |
| 07:14:22 | `cmd.exe` executed (recon-style commands) | `prefetch.csv` |
| 07:16:04 | `Q4_Vendor_Review.docm` sent to the Recycle Bin | `recyclebin.csv` |
| 09:14:08 | SanDisk Cruzer USB attached; its volume reported as `F:` at 09:14:12 | `usbstor.csv`, `system-evtx.csv` EID 98 |
| 09:15:32 | Shellbag entries written for `F:\Vendors\Confidential\` | `shellbags.csv` |
| 09:16:18 | LNK files created for documents opened from `F:\` | `lnk-files.csv` |
| 09:24:47 | SanDisk Cruzer USB removed | `usbstor.csv` |
| 09:30:42 | Last Edge browsing activity in window | `browser-history.csv` |

## Files

| File | Description | Rows |
|---|---|---|
| `lnk-files.csv` | LECmd-style parse of `%APPDATA%\Microsoft\Windows\Recent\*.lnk` | ~14 |
| `jump-lists.csv` | JLECmd parse of automatic Jump Lists per application | ~15 |
| `prefetch.csv` | PECmd-style Prefetch entries showing executable runs | ~21 |
| `amcache.csv` | Amcache binary metadata with SHA-1 hashes | ~18 |
| `srum.csv` | SRUM per-process network usage in the activity window (30-minute intervals; see the note below) | ~18 |
| `userassist.csv` | UserAssist GUI-launch history decoded from `NTUSER.DAT` | ~20 |
| `shellbags.csv` | SBECmd shellbag entries (local + USB browsing) | ~16 |
| `browser-history.csv` | Edge/Chromium browser history for the activity window | ~25 |
| `usbstor.csv` | RECmd parse of `HKLM\System\CurrentControlSet\Enum\USBSTOR` | ~6 |
| `shimcache.csv` | AppCompatCacheParser output from the `SYSTEM` hive — `dl.exe` at cache position 0 | 42 |
| `recyclebin.csv` | RBCmd parse of `C:\$Recycle.Bin\<SID>\` `$I` records, including the deleted lure document | 8 |
| `security-evtx.csv` | Parsed Security event log — the `WINWORD.EXE` → `POWERSHELL.EXE` → `dl.exe` chain with parent process names, plus the USB session | 29 |
| `system-evtx.csv` | Parsed System event log — PnP driver install for the Cruzer, volume-healthy for `F:`, service state changes | 20 |

## What you will and won't find

The dataset is curated, not exhaustive. It contains:

- The execution chain leading from the document open through `dl.exe`
- Removable-device evidence consistent with browsing `F:\Vendors\Confidential\`
- Enough background entries that filtering and correlation are non-trivial
- Realistic timestamps, file paths, and identifiers

It does not contain:

- A complete Security/System event log. `security-evtx.csv` and `system-evtx.csv` cover the incident window and enough background to make filtering non-trivial, but they are a curated slice, not the full logs — Lab06 still leads with shell and application artifacts
- A memory image (this scenario does not include a memory capture)
- The Q4_Vendor_Review.docm macro source or PowerShell payload body — decoding what `dl.exe` did from the artifacts present is part of the lab work

## Note on the ShimCache `Executed` column

Every row in `shimcache.csv` reads `Executed = NA`. That is accurate, not
missing. On Windows 8 and later the "executed" insert flag older cache formats
carried is no longer populated, so `AppCompatCacheParser` has nothing to
report. A ShimCache row means the binary was **present and enumerated**, not
that it ran — execution for `dl.exe` is proved by `prefetch.csv` (run count 1)
and by the EID 4688 in `security-evtx.csv`.

Two more things to preserve:

- `dl.exe` sits at cache position 0 with `LastModifiedTimeUTC` `06:59:08`.
  ShimCache spells it lower-case (the on-disk name); `prefetch.csv` spells it
  `DL.EXE` because Prefetch upper-cases. Same binary, two spellings.
- Ordering is **insertion order, most recent first** — not timestamp order.
  Several OS binaries lower in the file carry newer file timestamps than rows
  above them. Sorting by `LastModifiedTimeUTC` throws the signal away.

## Note on SRUM intervals

Each `Timestamp` in `srum.csv` closes the 30-minute interval it summarizes,
because SRUM writes a record at the end of the period it covers. The 07:00
rows cover 06:30–07:00: the lure download, the PowerShell drop and `dl.exe`'s
first run. SRUM cannot place traffic more precisely than its interval. It
supports "`dl.exe` sent 1,428,421 bytes between 06:30 and 07:00," not a time to
the second. The 06:30 interval holds only SYSTEM traffic, because no user
application had started yet.

## Note on the Recycle Bin

Each row of `recyclebin.csv` is one `$I` metadata file: `SourceName` is the
`$I` file's own path, `FileName` is the original path recorded inside it.

The row that matters is `Q4_Vendor_Review.docm`, deleted at **07:16:04** —
seventeen minutes after `dl.exe` ran. Its `SourceCreated` and `SourceModified`
values still match the `TargetCreated` / `TargetModified` pair in the
`Q4_Vendor_Review.lnk` row of `lnk-files.csv`. The LNK survives the deletion,
so the two artifacts corroborate each other: the LNK shows the lure was
*opened*, the `$I` shows it was then *thrown away*.

Nothing from the `F:` volume appears here. Deletions on removable media do not
use the fixed disk's Recycle Bin, so that absence is a real finding rather
than a hole in the dataset.

## Note on the SanDisk USB

The USB device shown in `usbstor.csv` (vendor `0781`, product `5567`, serial `4C530001190405104544`) corresponds to the volume-serial value `B4D7-22A1` referenced in the `lnk-files.csv` entries for documents opened from `F:\Vendors\Confidential\`. Tying the device to those LNK records is one of the Lab06 correlation exercises.

---

*Simulated FIN-WS23 dataset — Windows Forensics for Beginners*
