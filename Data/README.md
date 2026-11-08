# Simulated Lab Data

Pre-parsed artifact data for the labs in this book. Each subdirectory contains the kind of CSV and text output a responder would have after running standard tooling (`MFTECmd`, `EvtxECmd`, `PECmd`, `RECmd`, `Volatility`, etc.) against a triage collection.

Use this data when you want to work through the labs without setting up a Windows VM, or when you want a known-good reference your output can be compared against.

## Important caveats

- **This is simulated data.** It mirrors the format of real parser output but the entries are fabricated to match each lab's scenario. Do not use it for tool comparison, regression testing, or training detection logic.
- **Timestamps align across files within a host.** A Prefetch run at `14:21:03 UTC` will correspond to a Security event log entry at the same time, an MFT record created at `14:20:11 UTC`, a USN Journal entry, and a network flow record. Cross-correlation is the point.
- **Volume varies.** Each file contains enough entries to make the lab exercises non-trivial — typically 30 to 300 rows — but is far smaller than a real triage collection. You should not assume the absence of a row in this data means the artifact would be absent on a live host.
- **Hostnames, IPs, accounts, file names** are fictional. The IP `91.214.47.22` and similar are placeholders chosen to be visibly out-of-band; they do not refer to real infrastructure.

## Hosts

| Host | Anchor Scenario | Labs |
|---|---|---|
| `WKSTN-221/` | Payroll workstation, Office macro → PowerShell → CMD chain, outbound C2, lateral move to FILESVR-03 | Lab02, Lab03, Lab04, Lab09, Lab10 |
| `HR-LT12/` | HR laptop with persistence, USB activity, and OneDrive sync configuration | Lab05 |
| `FIN-WS23/` | Finance workstation, Word → PowerShell, mixed shell-artifact evidence | Lab06 |
| `WEB-APP-03/` | Internal web application server, transient PowerShell, suspected web shell | Lab07 |
| `HR-WS17/` | Departing-employee workstation, multi-channel exfiltration (USB + personal OneDrive) | Lab11 (capstone) |
| `ACCT-FS01/` | Accounting file server, "Vault" ransomware — six-day dwell, RDP entry, rclone exfiltration before encryption, shadow copies destroyed and Security log cleared | Lab12 |
| `network/` | Standalone network telemetry: flow data, proxy logs, DNS queries, firewall blocks | Lab08 |

`ACCT-FS01/` is the largest dataset in the book and the only one that
carries event logs from **three** hosts. That is not padding: the file
server's own Security log was cleared at 02:09:41 with EID 1102, so the
brute-force evidence survives only on the jump host and the domain
controller. Reconstructing the intrusion from the surviving sources is the
point of Lab 12, not an inconvenience to work around.

## Per-host file inventory

Each host folder contains a `README.md` with the scenario summary and a per-file inventory. Common files (not every host has all of them):

| File | Source | Tool that would have produced it |
|---|---|---|
| `mft.csv` | NTFS `$MFT` | `MFTECmd` |
| `usn-journal.csv` | NTFS `$Extend\$UsnJrnl:$J` | `MFTECmd` |
| `security-evtx.csv` | `Security.evtx` | `EvtxECmd` |
| `system-evtx.csv` | `System.evtx` | `EvtxECmd` |
| `powershell-evtx.csv` | `Microsoft-Windows-PowerShell/Operational.evtx` | `EvtxECmd` |
| `prefetch.csv` | `%SystemRoot%\Prefetch\*.pf` | `PECmd` |
| `amcache.csv` | `%SystemRoot%\AppCompat\Programs\Amcache.hve` | `AmcacheParser` |
| `srum.csv` | `%SystemRoot%\System32\sru\SRUDB.dat` | `srum-dump` / `SRUMDump` |
| `lnk-files.csv` | `%APPDATA%\Microsoft\Windows\Recent\*.lnk` | `LECmd` |
| `jump-lists.csv` | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` | `JLECmd` |
| `shellbags.csv` | `UsrClass.dat` shellbag keys | `SBECmd` |
| `userassist.csv` | `NTUSER.DAT` UserAssist | `RECmd` |
| `registry-runkeys.csv` | `Run`, `RunOnce` keys | `RECmd` |
| `registry-services.csv` | `HKLM\System\CurrentControlSet\Services` | `RECmd` |
| `usbstor.csv` | `HKLM\System\CurrentControlSet\Enum\USBSTOR` | `RECmd` |
| `mountpoints.csv` | `HKLM\System\MountedDevices` | `RECmd` |
| `onedrive-accounts.csv` | `HKCU\Software\Microsoft\OneDrive\Accounts` | `RECmd` |
| `onedrive-syncdb.csv` | OneDrive `<UserCid>SyncEngineDatabase.db` | DB Browser for SQLite |
| `browser-history.csv` | Chromium `History` SQLite db | DB Browser for SQLite |
| `network-flow.csv` | Flow telemetry (NetFlow / IPFIX) | SIEM export |
| `shimcache.csv` | AppCompatCache in the `SYSTEM` hive | `AppCompatCacheParser` |
| `recyclebin.csv` | `$Recycle.Bin\<SID>\$I*` records | `RBCmd` |
| `scheduled-tasks.csv` | `%SystemRoot%\System32\Tasks` | `Get-ScheduledTask` / `schtasks /query /xml` |
| `wmi-persistence.csv` | `root\subscription` WMI filters, consumers, bindings | `Get-WmiObject` / `PyWMIPersistenceFinder` |
| `volatility-*.txt` | Volatility plugin output | `vol.py windows.<plugin>` |
| `encrypted-files-inventory.csv` | Post-encryption file sweep | `Get-ChildItem -Recurse` export |
| `dc-security-evtx.csv` | `Security.evtx` from the domain controller | `EvtxECmd` |
| `jumphost-security-evtx.csv` | `Security.evtx` from the RDP jump host | `EvtxECmd` |
| `defender-evtx.csv` | `Microsoft-Windows-Windows Defender/Operational.evtx` | `EvtxECmd` |
| `terminalservices-evtx.csv` | `TerminalServices-*/Operational.evtx` | `EvtxECmd` |

## How to use

1. Read the relevant lab's `ReadMe.md` to understand the scenario.
2. Open the corresponding host folder in `Data/`.
3. Read that folder's `README.md` for the file inventory.
4. Filter, query, and correlate the CSV files using a spreadsheet, [Timeline Explorer](https://ericzimmerman.github.io/), PowerShell, Python, or your tool of choice.
5. Compare your findings against the analyst-notes scaffold in the lab's `labNN-notes.md`.

For Lab10 (timeline analysis) in particular, the WKSTN-221 dataset is the intended input: merging `mft.csv`, `usn-journal.csv`, `security-evtx.csv`, `prefetch.csv`, `srum.csv`, and `network-flow.csv` should produce the timeline the lab walks through.

For Lab11 (capstone), the HR-WS17 dataset is the intended input. It is the only
host that carries file-system, registry, event-log, cloud-sync, browser,
Recycle Bin **and** memory evidence for the same 25-minute window.

### A note on ShimCache

`shimcache.csv` appears for WKSTN-221, FIN-WS23 and HR-WS17. In all three the
`Executed` column reads `NA` on every row, because on Windows 8 and later that
flag is no longer populated — a ShimCache entry is evidence that a file was
**present and enumerated**, not that it ran. Row order is insertion order
(most recent first), which is the artifact's only ordering signal; sorting
these files by `LastModifiedTimeUTC` destroys it. Each host README says the
same thing at more length, because it is the single easiest thing to get
wrong about the artifact.

## Regenerating the WKSTN-221 dataset

The WKSTN-221 folder ships with a deterministic generator script that reproduces every CSV in place:

```
cd Data/WKSTN-221
python3 generate.py --dry-run            # print plan, write nothing
python3 generate.py --out-dir /tmp/x     # write to a scratch dir to diff first
python3 generate.py                       # overwrite in place
```

The script's top docstring spells out the attack narrative — read it first if you want to understand what the dataset is telling you. The seed is fixed; two runs into separate directories produce md5-identical files for all 14 outputs.

Every other host folder now ships the same generator, with the same three flags:

```
cd Data/<HOST>
python3 generate.py --dry-run
python3 generate.py --out-dir /tmp/x
python3 generate.py
```

Each script's top docstring spells out that host's narrative. Seeds are fixed
and every generator's row content is independent of the random stream, so two
runs into separate directories produce byte-identical output. If you add a new
output, add a generator function *and* a dispatch-table entry, then update the
host's `README.md` file inventory and the table above.

---

*Simulated lab data — Windows Forensics for Beginners*
