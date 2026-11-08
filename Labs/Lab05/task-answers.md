# Lab 05 — Task Answer Key

*Sample answers for the workbook-style Tasks in `Labs/Lab05/ReadMe.md`. These are reference answers, not the only correct answers — your wording may legitimately differ. The reasoning matters more than the prose. For the Hands-On Walkthrough at the end of the lab, see `walkthrough-answers.md` in the same folder.*

---

## Task 1 — Identify the Core Windows Registry Hives for IR

**Sample table:**

| Hive | Scope | Typical Path | Why It Matters in IR |
|---|---|---|---|
| **SYSTEM** | Host-wide hardware, services, drivers, device history | `%SystemRoot%\System32\config\SYSTEM` | Services, USBSTOR, MountedDevices, ControlSet selection, last-shutdown time — the host's "what was wired in and what was configured to run" hive |
| **SOFTWARE** | Host-wide installed software and system policy | `%SystemRoot%\System32\config\SOFTWARE` | Installed apps, system-wide autoruns, Windows version, network profiles, AV configuration |
| **SAM** | Local accounts and group membership | `%SystemRoot%\System32\config\SAM` | Local account names, RIDs, last-logon, password history hints — needed when domain logs cannot explain a local logon |
| **SECURITY** | Local security policy and LSA secrets | `%SystemRoot%\System32\config\SECURITY` | Audit policy, cached LSA secrets, service account material — relevant to credential theft scoping |
| **NTUSER.DAT** | Per-user roaming hive | `C:\Users\<user>\NTUSER.DAT` | UserAssist, per-user Run keys, RecentDocs, typed paths, RDP MRU, application-specific user settings — the bulk of user-behavior evidence |
| **USRCLASS.DAT** | Per-user Explorer/shell hive | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | Shellbags (Explorer folder navigation including USB and network paths), file-association overrides |

**Q1:** Why do responders need both system hives and user hives?

System hives answer "what was the host configured to do" — services, drivers, mounted devices, host-wide autoruns. User hives answer "what did this specific account do or interact with" — GUI-driven program use, Explorer navigation, recent documents, per-user persistence. Most real cases need both. A service installed system-wide means little until you can tie it to the user whose session ran it. UserAssist alone never explains a SYSTEM-context service or driver-level persistence.

**Q2:** Why is NTUSER.DAT often more useful for user activity questions than SOFTWARE?

NTUSER.DAT records what the specific user actually touched — programs they launched through the GUI (UserAssist), files they recently opened (RecentDocs), paths they typed (TypedPaths), RDP destinations they connected to. SOFTWARE records what was installed and configured at the machine level. It says nothing about whether any particular user ever used those programs. For "did this user do X" questions, NTUSER.DAT and USRCLASS.DAT are the right hives, and SOFTWARE is supporting context.

**Q3:** Why should you care about hive provenance and the user profile path from which a hive was taken?

A loose NTUSER.DAT on disk is meaningless unless you can say which account profile it came from. If no one recorded the file's origin path, you can confuse UserAssist for `hr-user` with UserAssist for `helpdesk-admin`. Provenance also matters for chain of custody. If you parsed a hive but cannot point to the exact source path and acquisition timestamp, the finding loses defensibility. Always record the full profile path, the collection time, and the hash before parsing.

---

## Task 2 — Hunt for Persistence and Suspicious Startup Configuration

**Sample table (first five rows + five added):**

| Registry Path or Area | Why It Matters | What a Suspicious Finding Might Look Like |
|---|---|---|
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | System-wide autoruns visible to every interactive logon | Value pointing to `C:\ProgramData\<vendor-y>\update.exe` where no such vendor is installed |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Per-user autoruns — runs only when the affected user logs on | Value pointing to `%AppData%\<random-name>\loader.exe` |
| `HKLM\SYSTEM\CurrentControlSet\Services` | Services run as SYSTEM and survive reboots | New `auto-start` service with binary in `C:\Windows\Temp\` |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce` | Runs once at next logon then deletes — common for installers and droppers | Value that points to a script in a temp directory |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` | Same as above but per-user | Single-use loader staged in user profile |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders` (Startup) and the on-disk Startup folder | Files in the user's Startup folder run at logon | LNK or script in `%AppData%\...\Startup` |
| `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` | "Debugger" sub-key hijacks legitimate binaries (Sticky Keys, Magnifier, etc.) | A `Debugger` value under `sethc.exe` pointing to `cmd.exe` |
| `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` | `Userinit`, `Shell`, and `Notify` values are loaded at session start | `Userinit` value with an extra binary appended |
| Scheduled Tasks (`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree` and `%SystemRoot%\System32\Tasks\`) | Persistence via scheduled tasks survives reboots, runs as SYSTEM, and often hides under legitimate-sounding names | Task named `MicrosoftEdgeUpdateTaskMachineUA` pointing at a non-Edge binary |
| WMI event consumers (`HKLM\Software\Microsoft\WBEM\CIMOM` plus `root\subscription`) | Fileless persistence via permanent event consumers | `__EventConsumer` triggering a PowerShell snippet on every logon |

**Q1:** Why is a startup entry in a user hive often important even if nothing appears in system-wide autoruns?

Writing a user-hive Run key does not require admin privilege. That makes these keys a default landing spot for malware that arrives as a non-elevated user-land payload, such as most phishing-delivered loaders. They also run only when that specific user logs on, so a forensic snapshot taken under a different account will silently miss them. If you triage while logged on as Administrator, the suspicious `HKCU\...\Run` value for `hr-user` is not in your hive. You have to mount `hr-user`'s NTUSER.DAT explicitly. In the HR-LT12 dataset, the `HpHotkeyMonitor` Run-key value pointing to `C:\Users\hr-user\AppData\Local\hp-hotkey\hpkey.exe` is the canonical example.

**Q2:** Why does path context matter when judging whether a Run key value is suspicious?

A vendor-branded value pointing into `C:\Program Files\<vendor>\` is almost always legitimate. The same value name pointing into `C:\Users\<user>\AppData\Local\<vendor>\` is a different story. User-writable AppData is where malware lives, precisely because writing there does not need elevation. Path context also catches name-spoofing: a value called `Adobe Updater` pointing to `C:\Users\Public\` is not Adobe. Always compare the value name against the actual file path before deciding the entry is benign.

**Q3:** Why should you avoid assuming every unusual startup entry is malicious?

Legitimate software installs autoruns constantly. OEM utilities (HP, Lenovo, Dell), updater services, conferencing clients, and sync clients all live in Run keys, sometimes from AppData paths. Teams and OneDrive are the classic Microsoft-vendored examples. An unfamiliar name is a lead, not a conclusion. Pivot through the file: digital signature, on-disk path, hash against threat intel, and Prefetch evidence of whether it has actually executed. Reporting every unrecognized Run key as malware quickly burns trust with the rest of the IR team.

---

## Task 3 — Investigate USB and Removable Device History

**Sample table (first four rows + four added):**

| Registry Path or Area | What It May Reveal | Why It Matters |
|---|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` | Per-device vendor/product/serial, first/last seen | The authoritative "what USB storage devices has this host known" record |
| `HKLM\SYSTEM\MountedDevices` | Binds volume GUIDs to drive letters | Lets you say a specific USBSTOR device was mounted as `E:\` (or another letter) and tie subsequent shellbag/LNK evidence to it |
| `HKLM\SYSTEM\CurrentControlSet\Enum\USB` | Device descriptor / VID-PID — covers non-storage USB too | Useful when the question is about HID injection devices, network adapters, or other non-storage USB |
| User shell / folder-history areas (Shellbags, RecentDocs, OpenSavePidlMRU) | Drive-letter paths the user navigated to | Survives device removal — strongest single piece of evidence for "the user actually browsed the USB content" |
| `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices` | Friendly volume label + last drive letter | Useful sanity-check against MountedDevices when serial numbers are obscured |
| `HKLM\SYSTEM\CurrentControlSet\Enum\SCSI` | Disk class enumeration including USB-to-SATA bridges and external HDDs | Catches large external drives that may not appear under USBSTOR with a friendly Kingston/SanDisk name |
| Setupapi log (`C:\Windows\inf\setupapi.dev.log`) | First-insertion timestamp for each device-instance ID | First-time install timestamp is more precise than the registry LastWriteTime alone |
| Event log `Microsoft-Windows-Partition/Diagnostic` (EID 1006) and `Microsoft-Windows-DriverFrameworks-UserMode/Operational` (EID 2003, 2004, 2100, 2102) | Connect/disconnect events per device-instance | Gives you wall-clock connect/disconnect pairs, not just first/last |

**Q1:** Why is USB vendor/model/serial data useful in an investigation?

The serial number is the only field that uniquely identifies a specific physical device. Vendor and model alone could match thousands of legitimate user-owned drives. With the serial, you can correlate the device across hosts: the same serial seen on another workstation tells you the device moved. You can also tie it to volume-shadow or backup metadata and ask whether the legal team should request the physical drive. Without the serial, removable-media findings stay vague.

**Q2:** Why is device presence not the same as proof that files were copied?

USBSTOR confirms the device was plugged in and a driver was loaded. It does not confirm that the user or any process opened Explorer to the device, browsed folders, or copied files. A USB inserted in a docking station while a different user is on the keyboard leaves the same USBSTOR row as one that was actively used. The shellbag, LNK, RecentDocs, USN Journal, and Prefetch artifacts are what move you from "connected" to "browsed" to "files moved."

**Q3:** What artifacts would you want to correlate with USB history to strengthen a data-transfer theory?

Shellbags showing folder navigation on the drive letter the USB was mounted as. LNK files whose target volume serial matches the USB's volume serial, because Windows created those LNKs when files on that exact device were opened. RecentDocs entries pointing at the drive letter. USN Journal entries showing files copied with the USB mounted. Prefetch entries for `xcopy.exe`, `robocopy.exe`, or 7-Zip whose referenced-file lists include paths on the drive letter. Prefetch does not record command lines. The HR-LT12 dataset carries the shellbag side of this, aligned to the 16:42–17:31 UTC window on 2024-11-12. It does not ship LNK, RecentDocs, USN Journal, or Prefetch data, so in this lab the claim that the device was used rests on shellbags alone. Name that gap in the finding. That alignment, not any single artifact, is what makes the case defensible.

---

## Task 4 — Review Remote Access and User Activity Clues

**Sample table (first five rows + five added):**

| Registry Path or Area | What It Helps Answer | Why It Matters in IR |
|---|---|---|
| RDP-related configuration keys (`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`, `HKCU\Software\Microsoft\Terminal Server Client\Default`, `...\Servers`) | Is RDP enabled? Which hosts has this user connected out to? | TS Client `Default` / `Servers` is the "RDP MRU" — outgoing destinations from this account |
| UserAssist (`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<GUID>\Count`) | Which programs has the user launched through the Explorer GUI | ROT13-encoded; gives launch count and last-run timestamp |
| Typed paths / Explorer history (`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`) | What did the user type into the Explorer address bar | Catches `\\fileserver\share` traversal or direct paths to staging directories |
| Shellbags (in USRCLASS.DAT under `BagMRU` / `Bags`) | Which folders has the user navigated through Explorer | Survives after the underlying folder, USB, or share is gone |
| RecentDocs (`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`) | What documents has the user recently opened | Per-extension MRU plus a combined MRU |
| OpenSavePidlMRU / LastVisitedPidlMRU (`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32`) | What paths appeared in common Open/Save dialogs | Catches save-as targets for downloaded or staged files |
| RunMRU (`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`) | Commands the user typed into the Run dialog | Often shows direct invocations of `cmd`, `powershell`, `regedit`, or UNC paths |
| WordWheelQuery (`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`) | Strings the user typed into Explorer search | Useful when the question is "did the user search for the sensitive file by name" |
| WinSCP, PuTTY, FileZilla MRU keys (`HKCU\Software\Martin Prikryl\WinSCP 2\Sessions`, `HKCU\Software\SimonTatham\PuTTY\Sessions`) | Outbound SSH/SFTP destinations | Common exfil-channel artifact missed by RDP-only reviews |
| `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber` and `fDenyTSConnections` | Is RDP listening, on what port, and was it enabled recently | Tells you whether the host could accept incoming RDP — combine with EID 4624/4625 logon type 10 |

**Q1:** Why is UserAssist useful even though it reflects GUI-driven activity rather than everything that ran on the system?

UserAssist is uniquely valuable when the question is "did the user interact with this program." It captures the moment a human, or something masquerading as one, double-clicked a binary, picked it from the Start menu, or launched it through Explorer. It ties that execution to a specific account and gives launch count and last-run time. Headless and command-line execution does not show up there. Prefetch and Amcache fill that gap. It is corroborating evidence for "the user knew about this program," which matters in insider cases.

**Q2:** Why can typed paths and Explorer history matter in a staging or exfiltration investigation?

`TypedPaths` records what the user typed directly into the Explorer address bar — UNC paths to file shares, drive letters of removable media, sync-root paths. That is much stronger than "the user clicked through a tree" because it implies that the user, or someone using their session, already knew where to go. In an exfil case, a `TypedPaths` entry such as `\\fileserver\HR\Confidential\` is the difference between "the user happened to wander into a sensitive folder" and "the user navigated directly to it."

**Q3:** Why should remote-access configuration findings be correlated with logs rather than treated as proof of connection by themselves?

Configuration says the system was prepared to allow RDP. It does not say anyone actually connected. The TS Client MRU shows destinations this user attempted to connect *to*, not whether the remote host accepted them. To go from configuration to connection, you need Security log EID 4624 type 10 (incoming RDP logon) and 4625 (failed), plus NetworkConnection EIDs and TerminalServices Operational logs.

---

## Task 5 — Identify Cloud Sync Client Evidence

**Sample table (first five rows + five added):**

| Artifact Source | What It May Reveal | Why It Matters |
|---|---|---|
| Registry keys related to OneDrive (`HKCU\Software\Microsoft\OneDrive\Accounts\Business1` and `\Personal`) | Configured accounts, sync endpoint, user CID, account email | Distinguishes a corporate-tenant sync from a personal-outlook.com sync on the same host |
| Local sync root folder (`%UserProfile%\OneDrive - <tenant>`, `%UserProfile%\OneDrive`) | What folder structure was actually being synchronized locally | The on-disk presence of HR documents under a personal sync root is much stronger than the registry alone |
| Client logs (`%LocalAppData%\Microsoft\OneDrive\logs\Personal\` and `\Business1\`) | Per-file sync transactions, errors, sign-in events | Often the only host-side record of which files actually uploaded |
| Local databases (`SyncEngineDatabase.db`, `SafeDelete.db`, `ClientPolicy.ini`) | File-level sync queue, deletion ledger, configured restrictions | The sync database is the on-host equivalent of the cloud activity log |
| User profile directories tied to sync activity (`%LocalAppData%\Microsoft\OneDrive\settings\<accountId>\`) | Per-account configuration, dat files, scope IDs | Useful for binding the Personal account's GUID to a specific email and tenant |
| Browser-history entries for `onedrive.live.com`, `<tenant>.sharepoint.com` | Web-side access to the same content the client was syncing | Distinguishes "client syncing in the background" from "user actively visited the cloud UI" |
| Process artifacts for `OneDrive.exe` (Prefetch, UserAssist) | Whether the client has actually been launched and how recently | Confirms the client is not just installed but in use |
| Network telemetry (Windows ETL traces, EDR network events, perimeter flow) for `*.onedrive.com`, `*.live.com`, `*.sharepoint.com` | Real-time evidence of upload bytes | The only authoritative "data actually left the host via this channel" source |
| Office MRU and `Place` keys (`HKCU\Software\Microsoft\Office\<ver>\Common\Identity` and `\Internet\Server Cache`) | Office documents opened from or saved to OneDrive locations | Cross-references Office app usage with sync destinations |
| Provider-side evidence (Microsoft Graph activity, Unified Audit Log `FileUploaded`/`FileSyncDownloadedFull`) | Authoritative cloud-side record of which files moved | Host evidence becomes much stronger when paired with the provider's view; see AppendixB |

**Q1:** Why is local cloud-client configuration often important even if you do not yet have provider-side logs?

Local evidence is available immediately under your existing host access, while provider-side telemetry takes time to acquire. You may need account credentials, tenant cooperation, or a legal preservation request. Local evidence also tells you *which* tenant and which account to ask about. In HR-LT12, the host had a `Personal` OneDrive configured for `hr.user.personal@outlook.com`. That tells you to ask Microsoft Consumer rather than the corporate tenant, and to subpoena the personal account rather than chase the wrong one for a week.

**Q2:** Why do account identifiers and sync-root paths matter?

The account identifier is the conclusive bind between host evidence and any cloud-side evidence you eventually acquire. For personal accounts it is the CID, and for business accounts it is the tenant plus user GUID. It lets you say "this host's `Personal` account is the same account that the cloud logs show uploading files." The sync-root path tells you which on-disk folder was the loading bay: any file dropped into that folder was a candidate for upload. Without the account identifier and root path, the cloud finding stays generic.

**Q3:** Why should a responder distinguish "cloud client installed" from "files actually synchronized"?

OneDrive is preinstalled on modern Windows, so finding it installed is not a finding. Finding it *configured for a personal account on a corporate laptop* is much closer to a finding. Finding it *configured for a personal account, with the sync database showing 8 HR files entering the upload queue during the suspected exfiltration window* is the actual finding. Each step is a separate evidentiary claim, so report each one separately. Overclaiming on the basis of installation alone burns your credibility on the steps that actually matter.

---

## Task 6 — Correlate Registry and Cloud Findings into Investigative Questions

**Sample ten questions (yours can differ):**

1. Was a suspicious user-hive Run-key value added during the suspected incident window?
2. Did a service install during the same window with a binary path in a user-writable location?
3. Was a previously unseen USB storage device connected during the window?
4. Was that USB device's volume GUID bound to a drive letter, and which letter?
5. Are there shellbag entries showing the user browsed sensitive folders on that drive letter?
6. Did the user have a personal OneDrive account configured on a corporate-managed laptop?
7. Does the OneDrive sync database show HR-related files entering the upload queue during the window?
8. Did UserAssist record interactive launch of any binary referenced in a suspicious Run key?
9. Are there typed-path or RecentDocs entries that match the sensitive folders shown in shellbags?
10. Did the same user's session show RDP MRU entries to hosts inside or outside the corporate boundary?

**Category mapping:**

| Category | Question Numbers |
|---|---|
| Persistence | 1, 2 |
| Removable media | 3, 4, 5 |
| User activity / execution | 8, 9 |
| Remote access | 10 |
| Cloud sync / data movement | 6, 7 |

**Five questions mapped to artifacts:**

| Question | Primary Artifact Source | Secondary / Corroborating Artifact |
|---|---|---|
| Was a suspicious user-hive Run-key value added during the window? | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` in NTUSER.DAT | Prefetch / Amcache for the binary it points at |
| Was a previously unseen USB connected? | USBSTOR | Setupapi.dev.log, DriverFrameworks-UserMode EIDs 2003/2102 |
| Did the user browse sensitive folders on the USB? | Shellbags in USRCLASS.DAT | LNK files whose volume serial matches the USB volume serial |
| Is there a personal OneDrive account configured? | `HKCU\Software\Microsoft\OneDrive\Accounts\Personal` | OneDrive client logs in `%LocalAppData%\Microsoft\OneDrive\logs\Personal\` |
| Did HR files enter the personal-account upload queue? | OneDrive `SyncEngineDatabase.db` | Microsoft's records for the consumer account, obtained through legal process. The corporate Unified Audit Log does not cover consumer accounts |

---

## Task 7 — Separate Strong Registry Findings from Overclaims

| Statement | Classification | Why |
|---|---|---|
| A OneDrive-related configuration key exists for the user profile | Strongly supported | The registry value either exists or it does not. No interpretation needed |
| Sensitive files were exfiltrated to a threat actor-controlled cloud account | Not supported by these artifacts alone | Host registry cannot prove the destination is attacker-controlled or that the user did not authorize it. Needs provider-side telemetry, threat intel, interview |
| A USB storage device with a specific vendor and serial was connected to the host | Strongly supported | USBSTOR plus MountedDevices give vendor, product, serial, and drive-letter binding directly |
| Files were definitely copied to that USB device | Suggested but needs corroboration | Connection and folder browsing are not copy operations. Confirm with USN Journal, $LogFile, or process telemetry |
| A suspicious executable path is referenced in a Run key | Strongly supported | The Run-key value either references that path or it does not |
| The executable ran successfully at every logon | Suggested but needs corroboration | Run keys configure intent, not outcome. Verify with Prefetch run count, Amcache, EDR process telemetry |
| UserAssist shows the user likely interacted with a program through the GUI | Strongly supported | UserAssist records precisely GUI-driven launches, and its count and timestamp are reliable |
| The user intentionally used OneDrive to steal data | Not supported by these artifacts alone | No artifact proves intent. Even a personal-OneDrive sync of HR files needs interview and policy context |

**Four additional statements (sample):**

| Statement | Classification | Why |
|---|---|---|
| The Kingston USB serial `001A92053B7CBE3196B40A0F` was mounted as drive `E:` on 2024-11-12 | Strongly supported | USBSTOR + MountedDevices give serial-to-drive-letter binding with timestamps |
| Files on `E:\HR\Confidential\` were viewed in Explorer | Strongly supported | Shellbag entries record folder navigation explicitly |
| The user opened salary spreadsheets from the USB | Suggested but needs corroboration | Browsing a folder is not opening a file. Confirm with LNK files with matching volume serial or Office MRU |
| The personal OneDrive account was the exfiltration channel | Suggested but needs corroboration | Strongly suggested by the sync database queue entries but needs provider-side records from Microsoft, or the local OneDrive client logs, to confirm the uploads completed |

---

## Task 8 — Build a Registry and Cloud Correlation Timeline

**Sample 10-row timeline (using the HR-LT12 dataset):**

| Time (UTC) | Artifact Source | Event or Observation | Key / Path / Artifact | Why It Matters |
|---|---|---|---|---|
| 2024-11-08 19:06:42 | NTUSER.DAT Run key | `HpHotkeyMonitor` value created | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\HpHotkeyMonitor` → `C:\Users\hr-user\AppData\Local\hp-hotkey\hpkey.exe` | Persistence staged four days before the suspected exfil window |
| 2024-11-12 16:42:08 | USBSTOR | New Kingston DataTraveler 3.0 first/last-connected (single-connection device) | Serial `001A92053B7CBE3196B40A0F` | One-off USB consistent with attacker-supplied or staged-for-this-purpose device |
| 2024-11-12 16:42:14 | MountedDevices | Kingston volume GUID bound to drive letter `E:` | `{f1d2e9a4-77c0-4b91-83be-ab4a0ed1c6e5}` → `E:` | Drive letter that subsequent shellbags reference |
| 2024-11-12 16:43–17:30 | Shellbags (USRCLASS.DAT) | User navigated `E:\HR\`, `E:\HR\Confidential\`, `E:\HR\Confidential\Salary_Data\`, `E:\HR\Confidential\Personnel\` | BagMRU entries with these AbsolutePaths | Folder navigation on the USB during the suspected window |
| 2024-11-12 16:51:33 | OneDrive registry | Personal account record last-updated | `HKCU\Software\Microsoft\OneDrive\Accounts\Personal` (`hr.user.personal@outlook.com`) | Personal account live on a corporate laptop |
| 2024-11-12 16:55–17:10 | OneDrive SyncEngineDatabase | 8 HR-related files entered the Personal sync queue | `Data/HR-LT12/onedrive-syncdb.csv` | Cloud upload channel correlates with USB navigation |
| 2024-11-12 17:31:02 | System log, Kernel-PnP | USB device removal request | EID 225 for the Kingston device; matches `LastRemovalTime` in USBSTOR | Closes the device-engagement window |

Every row above comes from `Data/HR-LT12/`. Three more artifacts would extend this timeline on a real host, but the dataset does not include them: UserAssist, to show whether `hpkey.exe` actually launched; `ComDlg32\OpenSavePidlMRU`, for save dialogs pointed at `E:\HR\Confidential\`; and `RecentDocs`, for files opened from the USB rather than only browsed. List them as next steps, not as findings.

**Q1:** Why is a timeline more useful than isolated key findings?

A timeline shows the reader how findings connect, while isolated findings invite the reader to draw connections you may not have established. The suspicious Run-key was installed four days before the exfil window. The USB appeared at 16:42:08 and was bound to `E:` six seconds later. The user browsed sensitive folders for the next ~45 minutes, and the personal OneDrive sync queue lit up during the same window. None of those facts makes the case in isolation, but in sequence they are hard to read any other way.

**Q2:** Which events in your timeline appear most central to the case theory?

Three events define the case: the USB connection plus the drive-letter binding (16:42:08–16:42:14), the shellbag navigation into HR/Confidential subfolders, and the OneDrive personal-account sync-queue entries during the same window. The Run-key persistence is supporting context. It shows the host was compromised before the exfil window, but the USB and OneDrive evidence establishes the data-movement theory.

**Q3:** What additional artifact types outside the Registry would you want next?

USN Journal entries during the window to see file copies. MFT $STANDARD_INFORMATION timestamps for files in the OneDrive sync root. Prefetch and Amcache for `hpkey.exe` to confirm the Run-key entry actually executed. OneDrive client logs from `%LocalAppData%\Microsoft\OneDrive\logs\Personal\`. Provider-side records for the personal Outlook.com account, requested from Microsoft through counsel. The corporate tenant's Unified Audit Log will not contain them. Network flow showing upload bytes to `*.onedrive.com` from the host during the window.

---

## Task 9 — Write a Registry and Cloud Findings Summary

**Sample three-paragraph summary:**

Registry and cloud-client review of HR-LT12 indicates a coordinated configuration-and-data-movement sequence between 2024-11-08 and 2024-11-12. A user-hive Run-key value, `HpHotkeyMonitor` under `HKCU\...\Run`, was added on 2024-11-08 19:06:42 UTC. It points to `C:\Users\hr-user\AppData\Local\hp-hotkey\hpkey.exe`, a non-Microsoft binary staged in user-writable AppData. Four days later, at 2024-11-12 16:42:08 UTC, a previously unseen Kingston DataTraveler 3.0 (serial `001A92053B7CBE3196B40A0F`) was connected for the first and only time and mounted as drive `E:`. Shellbag entries during the same window record navigation into `E:\HR\`, `E:\HR\Confidential\`, `E:\HR\Confidential\Salary_Data\`, and `E:\HR\Confidential\Personnel\`.

Concurrently, OneDrive registry artifacts show two accounts configured for the user profile: the expected `Business1` corporate tenant and a `Personal` consumer account (`hr.user.personal@outlook.com`). The OneDrive `SyncEngineDatabase` shows eight HR-related files entering the `Personal` account's upload queue between 16:55 and 17:10 UTC on 2024-11-12, overlapping the USB-browsing window.

Five findings are strongly supported. The Run-key persistence was added on 2024-11-08 19:06:42 UTC. The Kingston USB with the specified serial was connected on 2024-11-12 starting at 16:42:08 UTC. The user browsed the HR/Confidential folder tree on that USB. A personal-Outlook OneDrive account was configured on the host, and HR files entered that account's local sync queue during the same window. Three points still require corroboration. Whether `hpkey.exe` actually executed needs Prefetch, Amcache, or EDR evidence. Whether files were copied *to* the USB, rather than only browsed, needs the USN Journal and `xcopy`/`robocopy` Prefetch. Whether the OneDrive sync queue entries completed upload needs provider-side records from Microsoft for the consumer account. Recommended next steps: pull Prefetch and Amcache for `hpkey.exe`, pull the USN Journal for the 16:42–17:31 UTC window, ask counsel to request Microsoft's records for the personal Outlook.com account for the same window, and review network flow for `*.onedrive.com` upload bytes.

---

## Task 10 — Write an Analyst Handoff Note

**Sample handoff note:**

```
Case Reference:    IR-2024-1112-HRLT12
Author:            (your name)
Date/Time (UTC):   2024-11-13 09:00

Most Important Registry Findings:
- HKCU\...\Run value HpHotkeyMonitor added 2024-11-08 19:06:42, pointing to
  C:\Users\hr-user\AppData\Local\hp-hotkey\hpkey.exe (non-Microsoft, user-writable path)
- USBSTOR shows new Kingston DataTraveler 3.0 serial 001A92053B7CBE3196B40A0F
  connected once on 2024-11-12 16:42:08, mounted as E:
- Shellbags show navigation through E:\HR\Confidential\Salary_Data\ and \Personnel\

Most Important Cloud-Related Findings:
- HKCU\Software\Microsoft\OneDrive\Accounts\Personal configured for
  hr.user.personal@outlook.com on a corporate-managed device
- OneDrive SyncEngineDatabase shows 8 HR-related files entering the Personal
  account's upload queue between 16:55 and 17:10 UTC on 2024-11-12

What Is Strongly Supported:
- Persistence Run-key installed 4 days before suspected exfil window
- Specific USB serial was mounted as E: during the window
- User browsed sensitive HR folders on that USB
- Personal OneDrive account was configured and showed sync activity in the same window

What Still Needs Corroboration:
- Did hpkey.exe actually execute? (need Prefetch / Amcache / EDR)
- Did files copy to the USB vs only being browsed? (need USN Journal)
- Did the Personal OneDrive queue entries complete upload? (need provider-side UAL)

Recommended Next Artifacts:
1. Prefetch and Amcache for hpkey.exe and any unfamiliar binaries from AppData
2. USN Journal / $LogFile for 2024-11-12 16:42–17:31 UTC
3. Microsoft's consumer-account records for hr.user.personal@outlook.com, same window (via legal process; the corporate Unified Audit Log does not cover it)

Open Questions:
- Is hr.user.personal@outlook.com a known account for this user, or unknown?
- Is the Kingston device physically recoverable?
- Does network flow show *.onedrive.com upload bytes from this host?

Notes for Incoming Analyst:
The HpHotkeyMonitor Run-key entry is the persistence half of the story; the USB +
OneDrive pair is the data-movement half. Treat them as one chain unless you find
evidence they were unrelated. Provider-side OneDrive logs are the load-bearing
follow-up — without them the cloud-upload claim stays at "suggested."
```

---

## Task 11 — Reflection

**1. Why the Registry matters in IR**

The Registry remembers what the file system actively forgets. A binary can be deleted in seconds. The Run-key value that pointed at it, the serial of the USB drive used, the configured OneDrive account, and the folders the user navigated to all persist in registry hives until someone explicitly clears the keys. In a fast-moving incident where the on-disk evidence is gone, the registry is often the only place the relevant facts still live. Treat it as a primary IR evidence source, not a last resort.

**2. Configuration versus action**

A Run-key value, a service binary path, an RDP MRU entry, and a OneDrive account record all describe what the system or user account was *prepared* to do — not what actually happened. Malware can add a Run-key value that never fires because the binary fails to launch. RDP can be enabled and never connected to. OneDrive can be configured for an account that is then never used to sync anything. Always separate the configuration finding from the execution, connection, or upload finding. Keep the execution evidence in a different bucket: Prefetch, Amcache, Security log 4624, OneDrive sync database, network flow.

**3. Cloud sync versus exfiltration**

Local OneDrive evidence tells you a sync client was configured, what account it was configured for, and what files entered the local sync queue. It does not by itself tell you that files left the host, that they reached the cloud, or that they reached a destination outside the user's legitimate control. To make the exfiltration claim, you need either the provider-side audit log showing completed uploads or perimeter network evidence showing the upload bytes. Ideally, you also need policy context that says the personal-account sync was unauthorized. Report what the host evidence supports and flag the provider-side data as required next.

**4. Correlation over certainty**

Registry findings carry real evidentiary weight, but they are also frequently misread. A Run-key value pointing into AppData might be malware or might be Teams. A USB serial might be the attacker's drive or the user's regular backup. A personal OneDrive account on a corporate laptop might be exfil or might be policy non-compliance with no malicious intent. You reach a defensible interpretation by stacking registry findings against NTFS metadata, Prefetch and Amcache, Security and Operational event logs, browser history, network telemetry, and provider-side data when available. The case draws its strength from the alignment of those independent sources to the same window and the same user, not from any one of them on its own.

---

## Ready-to-move-on self-check

Before starting Lab 06, confirm you can answer these three questions cold. If any feel wobbly, revisit the relevant task.

1. **Which Registry hive answers "what folders did this user navigate through Explorer"?**  *Answer:* USRCLASS.DAT — Shellbags live under `BagMRU` / `Bags` in the user's UsrClass hive, not in NTUSER.DAT.
2. **What does USBSTOR not tell you that you still need to answer "did files leave the host on this USB"?**  *Answer:* USBSTOR confirms connection and gives device identity. It does not show files being read or copied. You need Shellbags, LNK files with matching volume serial, RecentDocs, USN Journal, and Prefetch for copy utilities to move from "device connected" to "files moved."
3. **Why is a `HKCU\...\Run` value in AppData not automatically malware?**  *Answer:* Microsoft-vendored apps (Teams, OneDrive, Edge updates) legitimately install Run-key values that point into AppData. The trigger is non-Microsoft path context, unsigned binary, no recognized vendor, and no Prefetch / installer evidence of how it got there.

---

## Walkthrough ↔ workbook bridges

> After Walkthrough Step 1, revisit Task 2.Q1 (user-hive persistence). Your prose-only answer should now read more concretely. The registry value `HpHotkeyMonitor` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with `LastWriteTime` `2024-11-08 19:06:42`, pointing to `C:\Users\hr-user\AppData\Local\hp-hotkey\hpkey.exe`, is the specific evidence the workbook question was probing for.

> After Walkthrough Step 2, revisit Task 3 (USB profiling). The Kingston DataTraveler with serial `001A92053B7CBE3196B40A0F` and a single-connection profile (`FirstConnected = LastConnected = 2024-11-12 16:42:08`) is the textbook one-off USB you were describing abstractly in the table.

> After Walkthrough Step 3, revisit Task 3.Q3 (what to correlate with USB history). The volume GUID `{f1d2e9a4-77c0-4b91-83be-ab4a0ed1c6e5}` from Step 2 binds to drive letter `E:` in MountedDevices. That drive letter makes the next step, shellbags on `E:\HR\...`, attributable to this specific physical device.

> After Walkthrough Step 4, revisit Task 4.Q2 (typed paths / Explorer history in staging cases). The shellbag entries for `E:\HR\`, `E:\HR\Confidential\`, and `E:\HR\Confidential\Salary_Data\` are exactly the kind of "user knew where to go" navigation evidence the task was asking you to think about.

> After Walkthrough Step 5–6, revisit Task 5.Q3 (cloud client installed vs files actually synced). The two OneDrive accounts (`Business1` corporate and `Personal` for `hr.user.personal@outlook.com`) plus the eight HR-related files entering the Personal sync queue between 16:55 and 17:10 UTC is the layered evidence chain. "Installed," "configured for a personal account on a corporate laptop," and "showed sync activity during the incident window" are three separate findings, each stronger than the last.
