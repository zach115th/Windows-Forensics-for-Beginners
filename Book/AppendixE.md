# Appendix E — Windows Forensics Quick Reference

This appendix condenses the artifact paths, event IDs, tool commands, and investigative questions that recur most often in Windows incident response. Use it at case open, when you don't have time to leaf through 14 chapters. Print it, keep it on a second monitor, or pin it in your case folder.

Cross-references back to the body chapters use `Ch4 §4.2`-style notation. The full treatment of any item lives in the corresponding chapter. This appendix is the at-a-glance reference, not the explanation.

---

## E.1 IR Workflow at a Glance

| Phase | Goal | Key Output |
|---|---|---|
| 1. Identification | Which systems / accounts / data sources are in scope | Initial scope memo |
| 2. Collection | Acquire evidence with method and chain of custody | Hashed images / triage packages |
| 3. Preservation | Protect originals; analyze working copies | Verified working copies |
| 4. Analysis | Test hypotheses against evidence | Findings + timeline |
| 5. Reporting | Translate findings into action | Technical report + executive summary |

**Alert-to-plan transition (Ch2 §2.4):** facts vs. assumptions vs. hypotheses → containment decision → collection priority list → investigation plan another responder could execute. Target: 15–20 minutes.

**Five durable habits (Ch14 §14.5):** real-time documentation; hash on acquisition; separate facts from conclusions; name the gap; corroborate before concluding.

---

## E.2 NTFS — File System Forensics (Ch4)

### Key files

| Source | Path |
|---|---|
| MFT | Volume root: `$MFT` (use `'$MFT'` quoting in PowerShell) |
| USN Journal | `$Extend\$UsnJrnl:$J` |
| Boot record | `$Boot` |

### MACB timestamps

| Attribute | Modified | Accessed | Changed | Born |
|---|---|---|---|---|
| `$STANDARD_INFORMATION` ($SI) | Last data change | Last read/open | MFT entry change | Created on this volume |
| `$FILE_NAME` ($FN) | Updated on rename | Same | Same | Same |

User-mode code can modify `$SI`, which makes it the timestomping target. Only the file system itself writes `$FN`, and it cannot be set directly. **`$SI Modified` predating `$FN Modified` is a classic timestomping signal.**

Caveat: a stomp followed by a rename or same-volume move makes NTFS copy the faked `$SI` into the new `$FN`, so the two agree and both are wrong. When they agree, fall back to the USN Journal and the MFT record number, which the double-stomp does not fix (Appendix G §G.2.2).

### Suspicious file paths

`C:\Users\<user>\Downloads\` · `C:\Users\<user>\AppData\Local\Temp\` · `C:\Temp\` · `C:\Windows\Temp\` · `C:\ProgramData\` · `C:\Users\Public\` · `C:\PerfLogs\`

### Common USN reason codes

`FileCreate` · `DataExtend` · `DataOverwrite` · `FileDelete` · `RenameOldName` / `RenameNewName` · `BasicInfoChange` · `FileClose`

### Tool quick commands

```powershell
# Parse MFT
MFTECmd.exe -f 'C:\Triage\<host>\$MFT' --csv 'C:\Cases\<host>\mft\'

# Parse USN Journal
MFTECmd.exe -f 'C:\Triage\<host>\$J' --csv 'C:\Cases\<host>\usn\'

# Get the MFT live (requires admin)
MFTECmd.exe -f 'C:\$Extend\$J' --csv .   # live USN journal
# A live $MFT cannot be read directly — extract it with KAPE or FTK Imager first
```

---

## E.3 Registry (Ch5, Appendix A)

### Hive locations

| Hive | On-disk path | Loaded as |
|---|---|---|
| SYSTEM | `%SystemRoot%\System32\config\SYSTEM` | `HKLM\SYSTEM` |
| SOFTWARE | `%SystemRoot%\System32\config\SOFTWARE` | `HKLM\SOFTWARE` |
| SAM | `%SystemRoot%\System32\config\SAM` | `HKLM\SAM` |
| SECURITY | `%SystemRoot%\System32\config\SECURITY` | `HKLM\SECURITY` |
| NTUSER.DAT | `%USERPROFILE%\NTUSER.DAT` | `HKCU` |
| UsrClass.dat | `%USERPROFILE%\AppData\Local\Microsoft\Windows\UsrClass.dat` | `HKCU\Software\Classes` |

Always collect the `.LOG1` / `.LOG2` transaction logs alongside the hive — modern Windows defers writes to these.

### Persistence locations (Ch5 §5.2.1)

```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon  (Userinit, Shell)
HKLM\System\CurrentControlSet\Services                       (each service's ImagePath)
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options  (debugger hijack)
```

### USB / removable device history (Ch5 §5.2.4)

```
HKLM\System\CurrentControlSet\Enum\USBSTOR             vendor / product / serial / first+last connected
HKLM\System\CurrentControlSet\Enum\USB                 broader USB device tree
HKLM\Software\Microsoft\Windows Portable Devices\Devices   friendly-name + drive letter
HKLM\System\MountedDevices                             volume GUID -> drive letter at last mount
%SystemRoot%\INF\setupapi.dev.log                      first-installation timestamp (plaintext)
```

### User-activity artifacts (NTUSER.DAT)

| Artifact | Path | What it shows |
|---|---|---|
| UserAssist | `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` | GUI program launches (ROT-13 names) + run count + last execution |
| TypedPaths | `Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` | Paths user typed in Explorer address bar |
| RecentDocs | `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | Recently opened documents by extension |
| ComDlg32 | `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU` | Files chosen via Open/Save dialogs |
| RDP MRU | `Software\Microsoft\Terminal Server Client\Default` (`MRU0`, `MRU1`, …) | Recently typed RDP destinations |

### Tool quick commands

```powershell
# Eric Zimmerman batch parse
RECmd.exe --bn BatchExamples\Kroll_Batch.reb -d 'C:\Triage\<host>\Registry' --csv 'C:\Cases\<host>\registry\'

# Single key
RECmd.exe -f 'C:\Triage\<host>\Registry\NTUSER.DAT' --kn 'Software\Microsoft\Windows\CurrentVersion\Run'

# Decoded UserAssist (in Registry Explorer GUI: built-in plugin auto-decodes ROT-13)
```

---

## E.4 Shell / Execution / Device Artifacts (Ch6)

### Locations

| Artifact | Path |
|---|---|
| LNK files | `%APPDATA%\Microsoft\Windows\Recent\*.lnk` |
| Jump Lists (auto) | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms` |
| Jump Lists (custom) | `%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\` |
| Prefetch | `%SystemRoot%\Prefetch\*.pf` (disabled by default on server SKUs — verify) |
| SRUM | `%SystemRoot%\System32\sru\SRUDB.dat` (~30–60 day window of per-process resource use) |
| Amcache | `%SystemRoot%\AppCompat\Programs\Amcache.hve` |
| ShimCache | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache` |
| Shellbags | `UsrClass.dat` under `Local Settings\Software\Microsoft\Windows\Shell\BagMRU` and `Bags` |
| Recycle Bin | `C:\$Recycle.Bin\<SID>\$I******` (metadata) + `$R******` (content) |
| WSL2 distro file system | `%LOCALAPPDATA%\Packages\CanonicalGroupLimited*\LocalState\ext4.vhdx`; registry at `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss` |
| Browser history (Chromium) | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\History` (SQLite) |
| Browser history (Edge) | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History` |
| Browser history (Firefox) | `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\places.sqlite` |
| Outlook OST/PST | `%LOCALAPPDATA%\Microsoft\Outlook\*.ost` / `*.pst` |
| Windows Search index | `%ProgramData%\Microsoft\Search\Data\Applications\Windows\Windows.edb` |

### What each execution artifact does and does not prove

| Artifact | Proves | Does NOT prove |
|---|---|---|
| Prefetch | Execution, run count, last 8 run times | Anything if disabled (common on server SKUs) |
| UserAssist | GUI-launched execution, run count, focus time | Anything launched from a command line or by a service |
| Amcache | Presence and identity (SHA-1), survives deletion | **Execution** — the compat subsystem inventories files it never ran |
| ShimCache | Presence and enumeration, path, binary `$SI` mtime | **Execution** — no execute flag or exec timestamp on Win8+ |

Amcache and ShimCache are the most commonly misread artifacts in Windows forensics. Pair either with Prefetch, a 4688, or a UserAssist entry before writing "executed".

### Recycle Bin `$I` quick facts

- `$I` and `$R` share a suffix: `$IA1B2C3.xlsx` pairs with `$RA1B2C3.xlsx`
- `$I` holds the original full path, deletion timestamp, and original size
- Per-SID directory gives you *which user* deleted it — map the SID via `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
- Bypassed by Shift+Delete, `Remove-Item`, network and removable paths, and quota-exceeding files — absence is not evidence the file was not deleted
- `$I` records are small enough to stay MFT-resident, so they often survive an emptied bin
- Parse with `RBCmd`

### Prefetch quick facts

- One `.pf` file per executable, named `<EXENAME>-<HASH>.pf`
- Last-run + previous 7 run timestamps (Win8+); run count; volume name + serial; referenced-files list
- **Disabled by default on Windows server SKUs.** Confirm via `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher`.

### Tool quick commands

```powershell
LECmd.exe -d '%APPDATA%\Microsoft\Windows\Recent' --csv 'C:\Cases\<host>\lnk\'
JLECmd.exe -d '%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations' --csv 'C:\Cases\<host>\jumplists\'
PECmd.exe -d '%SystemRoot%\Prefetch' --csv 'C:\Cases\<host>\prefetch\'
SBECmd.exe -d <UsrClass.dat or NTUSER.DAT> --csv 'C:\Cases\<host>\shellbags\'
AmcacheParser.exe -f '%SystemRoot%\AppCompat\Programs\Amcache.hve' --csv 'C:\Cases\<host>\amcache\'
# SRUM
srum_dump.exe -i 'C:\Triage\<host>\SRUDB.dat' -o 'C:\Cases\<host>\srum\' -t SRUM_TEMPLATE.xlsx
```

---

## E.5 Memory Forensics (Ch7)

### Acquisition

```
WinPmem:  winpmem_mini_x64.exe E:\IR\<host>\memory\<host>_memory_<UTC>.raw
DumpIt:   DumpIt.exe /OUTPUT E:\IR\<host>\memory\<host>_memory_<UTC>.raw /QUIET /NOLOGO
FTK Imager:  File → Capture Memory
```

Switch names differ between DumpIt builds and between the Comae and Magnet releases. Run `DumpIt.exe /?` once on your own kit and record the exact invocation in your runbook rather than trusting a cheatsheet — including this one.

### Volatility 3 plugin quick reference

```
windows.info               OS / build / kernel base — sanity check first
windows.pslist             active process list
windows.psscan             scan-based process list (catches hidden / unlinked)
windows.pstree             hierarchical view
windows.cmdline            full command lines (highest-value triage output)
windows.netscan            network sockets with owning PID
windows.malfind            suspicious memory regions (PAGE_EXECUTE_READWRITE + no file)
windows.dlllist [--pid N]  loaded modules per process
windows.svcscan            services
windows.handles [--pid N]  open handles
windows.lsadump / cachedump / hashdump  credential material — handle accordingly
```

### MemProcFS quick reference (Appendix D §D.9)

```
# Mount memory image as a virtual file system
MemProcFS.exe -device <memory.raw> -mount M:

# Process directories
M:\name\<process>-<PID>\
  cmdline\        modules\        handles\        vad\        memorymap.txt

# Other top-level views
M:\sys\           system info
M:\registry\      registry browsable as text
M:\misc\          YARA scans, timeline, analysis output
```

---

## E.6 Network Forensics (Ch8)

### Source quick comparison

| Source | Fidelity | Retention | Per-process attribution |
|---|---|---|---|
| PCAP | Highest | Hours–days | No (need EDR/host correlation) |
| Flow data (NetFlow/IPFIX) | Summary | Weeks–months | No |
| Zeek `conn.log` | Connection-level | Weeks | No |
| Proxy / firewall / DNS logs | Application-level | Variable | Sometimes (proxy with auth) |
| EDR network telemetry | Per-connection + process | Vendor-specific | **Yes** |

### Wireshark / tshark display filters

```
ip.addr == 10.0.4.32 and frame.time >= "Nov 14, 2024 14:00:00"
http.request                 # all HTTP requests
tls.handshake.type == 1      # TLS Client Hellos (JA3 source)
dns.qry.name contains ".onion"
tcp.flags.syn == 1 and tcp.flags.ack == 0   # outbound SYNs
```

### Zeek `conn.log` fields

```
ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state
```

`zeek-cut` filters fast: `zeek-cut <fields> < conn.log | awk '<filter>'`

### Host capture

```
netsh trace start capture=yes tracefile=C:\Triage\<host>\trace.etl
netsh trace stop
etl2pcapng.exe trace.etl trace.pcapng

pktmon start --etw -p 0 ; <wait> ; pktmon stop ; pktmon etl2pcap PktMon.etl
```

---

## E.7 Event Logs (Ch9, Appendix A)

### Channels worth knowing

```
Security                                       authentication, process creation, object access
System                                         services, drivers, reboots
Microsoft-Windows-PowerShell/Operational       EID 4103/4104/4105/4106
Windows PowerShell                             classic PS log (EID 400/403/600/800)
Microsoft-Windows-Sysmon/Operational           if Sysmon is installed
Microsoft-Windows-WMI-Activity/Operational     WMI queries and event consumers
Microsoft-Windows-TaskScheduler/Operational    scheduled tasks
Microsoft-Windows-TerminalServices-LocalSessionManager/Operational         RDP
Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational     RDP inbound
Microsoft-Windows-Windows Defender/Operational Defender detections / RTP changes
Microsoft-Windows-Bits-Client/Operational      BITS transfers
```

### High-value Security event IDs

| EID | Meaning |
|---|---|
| 4624 | Successful logon (see logon types below) |
| 4625 | Failed logon |
| 4634 / 4647 | Logoff |
| 4648 | Logon attempted with explicit credentials (lateral-move signal) |
| 4672 | Special privileges assigned (admin-equivalent) |
| 4688 | Process creation (full command line if auditing enabled) |
| 4697 | Service installed via SCM |
| 4698 | Scheduled task created |
| 4720 | User account created |
| 4738 | User account changed |
| 4768 / 4769 / 4771 | Kerberos TGT / TGS / preauth fail (DC) |
| 4776 | NTLM credential validation (DC for domain accounts; local host for local accounts) |
| 4798 | User local-group membership enumerated |
| 1102 | **Audit log was cleared** — investigate immediately |

### Logon types

```
2  Interactive (console)
3  Network (SMB, RPC)              <- common lateral-move type
4  Batch (scheduled task)
5  Service
7  Unlock
9  NewCredentials (runas /netonly) <- Pass-the-Hash signal
10 RemoteInteractive (RDP)
11 CachedInteractive
```

### System EID 7045 (service installed) high-value fields

```
ServiceName · ServiceFileName · ServiceType · StartType · AccountName
```

Cross-reference with `HKLM\System\CurrentControlSet\Services\<ServiceName>` for the registry side.

### PowerShell EID 4104 (script block compilation)

EID 4104 records the **content** of executed script blocks. It requires the Script Block Logging policy. Where that policy is off, 4104 events do not exist at all, which is a gap, not a clean host. AMSI bypasses do not suppress 4104, because the engine writes it at compilation, not AMSI. In-memory tampering with the cached logging settings or with the ETW provider does suppress it. Absence is never evidence of absence.

### Tool quick commands

```powershell
EvtxECmd.exe -d 'C:\Triage\<host>\Logs' --csv 'C:\Cases\<host>\evtx\'
Get-WinEvent -FilterHashtable @{Path='Security.evtx';Id=4625} | Select-Object TimeCreated, Properties
hayabusa.exe csv-timeline -d 'C:\Triage\<host>\Logs' -o 'C:\Cases\<host>\hayabusa.csv' -p super-verbose
wevtutil epl Security 'D:\Cases\<host>\Security.evtx'   # EXPORT FIRST — this reads only
wevtutil sl Security /ms:1073741824   # then raise retention to 1 GB (writes to the evidence host — log it)
auditpol /get /category:*             # what's actually being audited?
```

---

## E.8 Timeline Analysis (Ch10)

### Inputs to merge for a typical Windows incident

```
mft.csv (Created0x10, Created0x30)
usn-journal.csv
security-evtx.csv
system-evtx.csv
powershell-evtx.csv
prefetch.csv (LastRun)
amcache.csv
srum.csv (Timestamp)
lnk-files.csv (TargetCreated, TargetModified)
jump-lists.csv
network-flow.csv (FlowStart)
```

### Timeline row schema

```
Time (UTC) | Source Artifact | Event Description | Significance | Confidence | Notes
```

An empty CSV with these headers ships at `Labs/Lab10/timeline-template.csv`. Start your fill-in from that file rather than building headers from scratch. Confidence ratings: **HIGH** (≥2 independent sources agree) · **MEDIUM** (single reliable source) · **LOW** (indirect or single low-confidence source).

### Tools

```
Plaso / log2timeline:    log2timeline.py --storage-file <case>.plaso <image>
                         psort.py -o l2tcsv -w timeline.csv <case>.plaso
Timeline Explorer:       GUI for the EZ Tools CSVs (sortable, filterable)
Hayabusa csv-timeline:   Sigma-rule-driven detection timeline mapped to MITRE ATT&CK
IRIS-NG / Timesketch:    Collaborative timeline + case-management (Appendix D §D.14)
```

### IRIS-NG / DFIR-IRIS field mapping

| Spreadsheet column | IRIS field      | Notes |
|---|---|---|
| Time (UTC)         | `event_date`    | Pair with `event_tz=UTC` |
| Source Artifact    | `event_source`  | `MFT`, `Security`, `Prefetch`, ... |
| Event Description  | `event_title`   | Concise headline |
| Notes              | `event_content` | Long-form description |
| Significance       | `event_tags`    | Comma-separated |
| Confidence         | `event_color`   | HIGH=green · MEDIUM=yellow · LOW=gray |

IRIS-ready CSV: `Labs/Lab10/timeline-template-iris.csv`.

---

## E.9 Lateral Movement / Credential Abuse (Appendix A)

| Technique | Source-side signal | Destination-side signal | Domain-side signal |
|---|---|---|---|
| PsExec | `PsExec*.pf`, EID 4648 | EID 7045 service install (`PSEXESVC`) | EID 4624 LogonType 3 |
| WMI exec | `WMIC.EXE` Prefetch | child of `WmiPrvSE.exe` | EID 4624 LogonType 3 |
| Scheduled task | `SCHTASKS.EXE` Prefetch, 4648 | TaskScheduler/Operational, 4698 | EID 4624 LogonType 3/4 |
| RDP | `MSTSC.EXE` Prefetch, RDP MRU registry, bitmap cache | TerminalServices logs, 4624 LogonType 10 | EID 4624 LogonType 10 |
| PSRemoting | encoded PowerShell, 4104 | WinRM/Operational + 4104 | EID 4624 LogonType 3 |
| Pass-the-Hash | EID 4624 LogonType 9 (`runas /netonly`) | 4624 LogonType 3, NTLM auth | EID 4776 |
| Kerberoasting | many 4769 requests, RC4 tickets | — | **EID 4769 with RC4 enctype on SPN account** |
| DCSync | — | — | **EID 4662 with DS-Replication-Get-Changes from non-DC source** |

### Credential-theft red flags

```
Defender EID 5007 / 5010 — RTP disabled or service stopped
Sysmon EID 10 — ProcessAccess targeting lsass.exe
Mass 4624 LogonType 3 from one source to many destinations in a short window
EID 4768 with PreAuthType=0  (AS-REP roasting target)
```

---

## E.10 Cloud / M365 / Entra ID (Appendix B)

### Three logs that carry the IR value

```
Entra ID Sign-in Logs              every authentication event (SigninLogs in Sentinel)
Entra ID Audit Logs                directory changes (AuditLogs)
Unified Audit Log (UAL)            M365 service activity (OfficeActivity in Sentinel; Search-UnifiedAuditLog in PS)
```

### High-value UAL operations

```
Exchange Online:    MailItemsAccessed, New-InboxRule, Set-InboxRule, Add-MailboxPermission
                    Set-Mailbox (with ForwardingSmtpAddress)
SharePoint/OneDrive: FileDownloaded, FileSyncDownloadedFull, AnonymousLinkCreated, SharingSet
Audit Logs:         "Consent to application", "Add member to role", "Add owner to service principal",
                    "Update application — Certificates and secrets management"
```

### Tenant-takeover pattern (alert immediately)

`Add application` → `Add service principal credentials` → `Consent to application` (broad permissions) → role assignment.

### Recovery essentials

```powershell
# AzureAD module retired March 2025 — use Microsoft Graph:
Revoke-MgUserSignInSession -UserId user@domain
Get-InboxRule -Mailbox user@domain     # check + remove malicious rules
Get-MgUserOauth2PermissionGrant -UserId <userObjId>
```

---

## E.11 Tool Cheat List (Appendix D)

| Need | Tool |
|---|---|
| Parse MFT, USN, evtx, registry, shell, prefetch | Eric Zimmerman tool suite |
| Triage collection + chained parsing | KAPE (`!SANS_Triage` + `!EZParser`) |
| Disk image / memory image / preview | FTK Imager |
| Mount E01 / VHDX / raw as physical disk | Arsenal Image Mounter |
| Sigma-rule EVTX threat hunting + ATT&CK | Hayabusa |
| Repeatable Hayabusa pipeline | HayabusaAutorun |
| Memory analysis — plugin-driven | Volatility 3 |
| Memory analysis — file-system-style navigation | MemProcFS |
| Guided IR triage | Cyber Triage |
| Linux analysis VM | SANS SIFT Workstation |
| Endpoint EDR-grade telemetry without an EDR | Sysmon |
| Packet capture analysis | Wireshark / tshark |

---

## E.12 Acquisition Decision Tree (Ch3 §3.7)

**The two mistakes that cost you evidence: not taking memory first on a live host, and powering on a host you were handed powered off.**

```
POWERED ON?
├─ YES ─ user logged in?
│        ├─ NO  ─ have creds? ── no ─→ EDR live response, or plan a lawful shutdown
│        │                    └─ yes ─→ log in, continue below
│        └─ YES ─ local admin (or can elevate)?
│                 ├─ NO  ─→ user-context triage + EDR. Document the constraint.
│                 └─ YES ─→ 1. MEMORY          (WinPmem / DumpIt / FTK Imager / EDR)
│                           2. TRIAGE          (KAPE targets)
│                           3. Full disk only if triage fell short
│                              ├─ normal        ─→ PHYSICAL image
│                              └─ BitLocker,
│                                 no key        ─→ LOGICAL image of the unlocked
│                                                  volume — your ONLY option
│
└─ NO ── DO NOT POWER IT ON
         ├─ encrypted + no key? ─→ find key (AD / Entra / MBAM / .BEK / printout) first
         ├─ image with forensic boot media (Paladin, CAINE, write-blocker)
         ├─ PHYSICAL image by default
         ├─ collect hiberfil.sys + pagefile.sys + swapfile.sys
         └─ boot it ONLY as a justified exception (see below)
```

### Why memory first on a live host

Memory is the only artifact for which *your own collection activity* is the main threat. Every other artifact is patient. If BitLocker is unlocked right now, the volume master key may also be in RAM. Lose the running state, and you may lose the disk.

### What booting a powered-off host costs you

```
RunOnce keys       fire and delete themselves — gap you cannot recover
Prefetch/Amcache/  take new writes, pushing older entries out
ShimCache
Event logs         record the boot; small MaxSize rolls older records off
Timestamps         last-access, registry LastWriteTime, $SI modified all move
Boot-trigger tasks attacker tooling may re-execute and change the disk
```

### "Powered off" may still hold memory

- **Fast Startup / hybrid shutdown** (default since Win8) hibernates the *kernel* session to `hiberfil.sys`. A machine the user "turned off" may carry a recoverable kernel-memory image. Check for `hiberfil.sys`, its size, and its timestamp.
- `pagefile.sys`, `swapfile.sys`, `hiberfil.sys` all persist paged-out process memory across shutdown. Collect all three with the image. Hibernation files are compressed and are **not** a raw memory image. Recent Volatility 3 releases include a hibernation layer that reads them directly, but older ones do not, and support elsewhere is uneven. Confirm your tool version handles them, or convert first with `Hibr2Bin` and then analyze the converted image.

### Booting evidence — the justified exception

Booting evidence is legitimate only to make persistence fire when the image left the question unanswered. All four conditions must hold:

```
1. Physical image taken and hash-verified FIRST
2. Network isolated or sinkholed
3. Boot a COPY in a VM where possible, not the original
4. Record the boot time — every later timestamp is yours, not the attacker's
```

Gets you: proof the mechanism executes, and what it does when it runs.
Does **not** get you: the attacker's prior session. That is gone.

### Physical vs logical

| | Physical | Logical |
|---|---|---|
| Deleted data, slack, unallocated | Yes | No |
| Size | Full capacity | Used space |
| Locked BitLocker | Valid ciphertext capture | Not possible |
| **Default** | **Yes** | Only when physical is impossible or pointless |

---

## E.13 Encrypted Volumes and Shadow Copies (Ch3)

### BitLocker triage

```
manage-bde -status                       # is the volume encrypted, and is it locked?
manage-bde -protectors -get C:           # enumerate protectors; note the Numerical Password ID
manage-bde -unlock D: -RecoveryPassword <48-digit>
```

Boot-record signature: `-FVE-FS-` where an unencrypted NTFS volume reads `NTFS␣␣␣␣`.

| State you found it in | What you can still get | What you lose by waiting |
|---|---|---|
| Running, volume unlocked | Everything — live image, memory with FVEK in RAM | All of it, the moment it powers off |
| Running, volume locked | Memory only | The volume unless you find a key |
| Powered off | Nothing without a recovery key | — |

**Capture memory first on a live unlocked host.** The FVEK may be recoverable from RAM. Once the machine is off, you may never get back in.

Recovery key escrow: AD `msFVE-RecoveryInformation` · Entra ID / Intune · MBAM / ConfigMgr · printed or `.BEK` file.

### Volume Shadow Copies

```
vssadmin list shadows                                  # enumerate
Get-CimInstance Win32_ShadowCopy | Select DeviceObject, InstallDate
mklink /d C:\vsc1 \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\   # trailing backslash is mandatory
```

Snapshots hold **prior registry hives**, prior file versions, and pre-cleanup state. If an attacker deleted a Run key on Tuesday, Monday's snapshot may still have it.

`vssadmin delete shadows /all /quiet` is a near-universal ransomware precursor — see E.14. The *absence* of expected snapshots is itself a finding.

---

## E.14 Ransomware Engagement (Ch12)

### Scoping the encryption

```
Extension sweep       -> how many files, which volumes, total bytes
Ransom-note placement -> a directory map of what the actor reached
USN minute-binning    -> start, stop, and rate of the encryption run
```

### The order the artifacts answer things

| Question | Look at |
|---|---|
| When did encryption run? | USN mass-modification burst; ransom-note `$SI` Born times |
| Did the binary run *here*? | 4688 + Prefetch + Amcache locally. If those are present and 5140/5145 are absent, local execution is the better explanation — but check `auditpol` first: **file-share auditing is off by default**, so zero 5145 usually means the subcategory was never enabled, not that no SMB access happened |
| Who cleared the log? | EID 1102 carries the account and logon ID — chain it to 4624/4672 |
| How did they get in? | Work backwards; the entry point is usually days earlier than the encryption |
| Did data leave first? | Staging dirs, `rclone`/`WinSCP`/`MEGAsync` artifacts, SRUM byte totals, egress flows |

### Defense-evasion sequence to expect

```
Defender disabled (5001 / 5007)  ->  vssadmin delete shadows /all /quiet  ->  wevtutil cl / EID 1102  ->  encryption
```

**The encryption event is the end of the intrusion, not the start.** Dwell time is typically days to weeks. Report the dwell window with an explicit statement of what bounds it — usually the oldest surviving log.

---

## E.15 Confidence Language (Ch13)

| Level | Means |
|---|---|
| **Confirmed** | Two or more independent sources agree, and neither inherits the other's error |
| **Probable** | One reliable source, consistent with everything else known |
| **Possible** | Consistent with the evidence but alternatives are not excluded |
| **Undetermined** | The source that would answer this is missing — **name it** |

"Undetermined" is a finding, not a failure. Every finding gets exactly one level.

Banned without qualification: *likely*, *clearly*, *obviously*, *sophisticated*, *advanced*, *the attacker covered their tracks*.

Facts, inferences, and assumptions carry different weights — label which one you are writing.

### Containment ranked by evidence cost

Condensed from Chapter 13 §13.4.1 — same ordering, least to most destructive.

```
lowest cost   Hypervisor suspend + snapshot (VM)   memory AND disk, atomically
              Monitor only, no containment         costs nothing but time at risk
              Perimeter / DNS block of C2          host untouched
              EDR host isolation                   drops in-flight sessions
              VLAN quarantine / switchport ACL     same loss, slower
              Physical network disconnect          also loses remote collection
              Account disable / lockout            may kill the processes you need
              Graceful shutdown                    all memory + shutdown handlers fire
highest cost  Hard power-off                       all memory + FS inconsistency
```

Two things responders get backwards:

- **VM snapshot is the cheapest option, not a specialist one.** If the host is virtual and you have hypervisor access, suspend and snapshot *first*. Teams routinely skip it because the EDR console is the reflex.
- **Account disable is not "low impact."** It does not touch the host, so it feels free. But killing the attacker's sessions can terminate the exact processes whose memory you wanted. Sequence it after capture.

**Memory capture is not on this list** because it is a collection step, not a containment step, and it has no evidence cost. The default sequence is: document the decision → capture memory (or snapshot) → capture volatile network/process state → contain with the least destructive option that stops the actual harm → disable accounts and rotate → collect disk. Disk is patient.

The one override: **if data is actively being destroyed, contain first.** If encryption is running, a wiper is executing, or logs are being deleted in real time, the memory you lose by cutting the network now is less than the data you lose in the 90 seconds a capture takes.

---

## E.16 The Five Questions, Always

When triage feels unstructured, fall back to these five questions:

1. **Active threat?** Is the attacker still operating? — Memory + live network + EDR
2. **Initial access?** How did they get in? — Email, browser, exposed service, stolen credential
3. **Execution?** What did they run? — Prefetch, Amcache, EID 4688, EID 4104
4. **Persistence?** What survives reboot? — Run keys, services, scheduled tasks, WMI
5. **Impact?** What was accessed, staged, exfiltrated? — MFT/USN, shellbags, SRUM, network, OneDrive logs

Then: **scope.** Which other hosts / accounts / data stores are involved?

These six categories cover the structure of nearly every Windows incident, and the artifact tables above map each question to its evidence sources.

---

*End of Appendix E. Print double-sided if you want to keep this on the desk.*

---
