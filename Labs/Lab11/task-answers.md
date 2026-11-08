# Lab 11 — Task Answer Key (Capstone)

*Sample answers for the workbook-style Tasks in `Labs/Lab11/ReadMe.md`. These are reference answers, not the only correct ones. A defensible capstone answer names the evidence, the channel, and the confidence level. It does not flatten a multi-channel case into a single all-or-nothing conclusion. For the Hands-On Walkthrough that resolves the case against `Data/HR-WS17/`, see `walkthrough-answers.md`.*

> **The capstone's central nuance:** three pricing files were in scope, and the evidence differs by file. `Q4_Customer_Pricing.xlsx` and `Pricing_Strategy_Confidential.docx` have SHA-256 hashes that match both the legal-provided reference and the personal OneDrive sync database, which confirms the cloud channel for those two. The third, `Margins_Q3.xlsx`, appears in the USB LNK evidence but not in the OneDrive sync database. That file reached the Kingston device but is not provably on the personal cloud. A good capstone answer keeps these distinctions visible at every step. Flattening them to "all three were exfiltrated through both channels" is the most common and most damaging overclaim in this case.

---

## Task 1 — Receive the Case and Read the Inputs

**Part A — Inventory the inputs (sample answers):**

| Question | Answer |
|---|---|
| What artifact classes are available? | NTFS (mft, usn-journal), event log (security-evtx), execution and presence (prefetch, amcache, shimcache), resource usage (srum), shell items (lnk-files, jump-lists, shellbags), USB and mount history (usbstor, mountpoints), cloud (onedrive-accounts, onedrive-syncdb, onedrive-logs-extract), browser history, Recycle Bin (recyclebin), memory (volatility-pslist, volatility-netscan, volatility-cmdline). Total: 20 CSV/text files plus the legal reference. |
| What is missing that you might want? | The memory image itself (only three Volatility 3 plugin outputs from the 18:01:12 WinPmem capture ship, so no other plugin can be run); provider-side OneDrive audit logs and Microsoft 365 mail-flow logs; per-host network flow (only SRUM bytes-out is available); the contents of any webmail attachment (lives on the mail server, not the host) |
| Which file lists the pricing-file hashes? | `Data/HR-WS17/pricing-files-known-hashes.txt` — three SHA-256 reference hashes provided by legal |
| What is the primary scenario time window from the README? | 2024-11-12 17:35–18:00 UTC — the last ~25 minutes of the departing employee's last session |
| Which channel(s) does the README explicitly call out? | USB (Kingston, confirmed), Personal OneDrive (`hr.user.personal@outlook.com`, confirmed), Webmail (Outlook on the web, probable but not confirmed from host alone) |

**Part B — Pricing-file hashes:**

| File | SHA-256 (legal reference) |
|---|---|
| `Q4_Customer_Pricing.xlsx` | `7a4b8c12d3e5f6789012345678901234567890abcdef1234567890abcdef1234` |
| `Pricing_Strategy_Confidential.docx` | `9b9cdc69c1c24e2b3142a4b5d6e7f8901234567890abcdef1234567890abcdef` |
| `Margins_Q3.xlsx` | `12dc1ea8e34b6a0b8b2c1a4f8b3d4e5f67890abcdef1234567890abcdef12345` |

The third hash is the case-critical one. `Margins_Q3.xlsx` reaches the USB but is not provably present in the personal OneDrive sync database. Keep that distinction in mind, because it shapes every later task.

**Part C — Self-generated simulation:** if you run the simulation on your own VM, substitute your hostname, USB serial, and personal OneDrive account, and adapt the file inventory. The investigation tasks below work either way. The specific evidence values change, but the analytical structure does not.

---

## Task 2 — Verify Evidence Integrity

**Sample evidence-inventory table (truncated hashes are illustrative — your actual hashes will differ):**

| Evidence Item | Source Path | SHA-256 (first 16) | Working Copy Created? | Notes |
|---|---|---|---|---|
| `mft.csv` | `Data/HR-WS17/mft.csv` | `4e2c8f9b71a0d3c5` | Yes | ~40 rows; includes Temp staging copies, the surviving `pricing-staging.zip`, and the deleted Pricing folder |
| `usn-journal.csv` | `Data/HR-WS17/usn-journal.csv` | `e8b1f2a3c7d4905a` | Yes | ~40 rows; 10 FileDelete entries, five at 17:55 and five at 17:57:42 |
| `security-evtx.csv` | `Data/HR-WS17/security-evtx.csv` | `1a9f3b2d8e7c5b04` | Yes | ~25 rows; includes 08:42 logon and 18:02 logoff |
| `prefetch.csv` | `Data/HR-WS17/prefetch.csv` | `c4d3e2f1a098b765` | Yes | ~15 rows; `7zG.EXE` ran once, at 17:40:11 |
| `amcache.csv` | `Data/HR-WS17/amcache.csv` | `9b8c7d6e5f4a3b21` | Yes | ~12 rows; SHA-1 hashes for binaries present on the host |
| `srum.csv` | `Data/HR-WS17/srum.csv` | `7a8b9c0d1e2f3a4b` | Yes | ~12 rows; `OneDrive.exe` sent 3184221 bytes and `msedge.exe` 684221 bytes in the 18:00 bucket |
| `lnk-files.csv` | `Data/HR-WS17/lnk-files.csv` | `5c6d7e8f9a0b1c2d` | Yes | ~12 rows; two LNKs per pricing file (local + USB) |
| `jump-lists.csv` | `Data/HR-WS17/jump-lists.csv` | `3e4f5a6b7c8d9e0f` | Yes | ~10 rows; Excel and Word MRUs |
| `shellbags.csv` | `Data/HR-WS17/shellbags.csv` | `0a1b2c3d4e5f6a7b` | Yes | ~15 rows; E:\Confidential\ paths present |
| `usbstor.csv` | `Data/HR-WS17/usbstor.csv` | `8c9d0e1f2a3b4c5d` | Yes | 5 rows; Kingston DataTraveler in case window |
| `mountpoints.csv` | `Data/HR-WS17/mountpoints.csv` | `6e7f8a9b0c1d2e3f` | Yes | ~8 rows; volume GUID binds to E: |
| `onedrive-accounts.csv` | `Data/HR-WS17/onedrive-accounts.csv` | `2c3d4e5f6a7b8c9d` | Yes | 2 rows; Business + Personal |
| `onedrive-syncdb.csv` | `Data/HR-WS17/onedrive-syncdb.csv` | `4a5b6c7d8e9f0a1b` | Yes | 2 rows; `Q4_Customer_Pricing.xlsx` and `Pricing_Strategy_Confidential.docx` only |
| `onedrive-logs-extract.txt` | `Data/HR-WS17/onedrive-logs-extract.txt` | `7b8c9d0e1f2a3b4c` | Yes | ~35 lines; client-log chunked-upload trace |
| `browser-history.csv` | `Data/HR-WS17/browser-history.csv` | `5e6f7a8b9c0d1e2f` | Yes | ~20 rows; outlook.live.com navigation at 17:51 |
| `shimcache.csv` | `Data/HR-WS17/shimcache.csv` | `2b7fa04bcbec35f0` | Yes | 40 rows; `7z.exe` present with no Prefetch entry; `Executed = NA` throughout |
| `recyclebin.csv` | `Data/HR-WS17/recyclebin.csv` | `1e4ee887762e3af3` | Yes | 8 rows; orphaned `$I` records for the three pricing files, deleted 17:57:42 |
| `volatility-pslist.txt` | `Data/HR-WS17/volatility-pslist.txt` | `e4305368118614df` | Yes | 40 processes; two `OneDrive.exe` (PIDs 3184 and 6428) |
| `volatility-netscan.txt` | `Data/HR-WS17/volatility-netscan.txt` | `0efc65bbbb55edb7` | Yes | 21 sockets; PID 6428 on its own OneDrive endpoint |
| `volatility-cmdline.txt` | `Data/HR-WS17/volatility-cmdline.txt` | `e99f4eea45de1d75` | Yes | 40 command lines; Office still carries `C:\HR\Pricing\` paths |
| `pricing-files-known-hashes.txt` | `Data/HR-WS17/pricing-files-known-hashes.txt` | `9d0e1f2a3b4c5d6e` | Yes | Three SHA-256 reference hashes |

**Q1: Why should the original evidence be left untouched once verified?**

The original is the only thing you can re-hash to prove the working copy was never modified. Run every analytical operation against the working copy. If you analyze the original directly, any inadvertent change destroys your ability to attest that the evidence today matches the evidence at collection. The discipline also matters for testimony. "I never touched the original after acquisition" is a much stronger position than "I tried to be careful with the original."

**Q2: Why does hashing matter even in a training case?**

Training is where the muscle memory forms. If you skip hashing in lab work, the first time you hash under real pressure is also the moment when getting it wrong matters most. Hashes catch real problems even in training. If a working copy's hash differs from the original's, something happened to one of them, and finding that out in a lab is much cheaper than finding it out in a deposition.

**Q3: Why is chain-of-custody discipline still useful in internal investigations?**

Internal cases turn into HR matters, employment disputes, and occasionally external legal proceedings. A case investigated with sloppy custody cannot be escalated. A case investigated with disciplined custody keeps every option open. The discipline also protects you personally. Clear, contemporaneous custody records are your best defense if someone later challenges how you conducted the investigation.

---

## Task 3 — Build the Initial Case Scope

**Sample question set (10 investigative questions, grouped):**

1. Which user account interacted with the three pricing files on 2024-11-12?
2. Were the files copied or staged before any transfer?
3. Was a removable device connected during the case window? Which device, when, and to which drive letter?
4. Did the user navigate to folders on the removable device that match the pricing-folder structure?
5. Was a personal cloud account active on this host? Which provider, which account, when was it last signed in?
6. Were any of the three pricing files synchronized to a personal cloud account, and do the hashes match the legal reference?
7. Is there evidence of webmail or browser-based upload activity in the case window?
8. What is the order of events between local file access, USB connection, and cloud sync?
9. Was there post-activity cleanup — deletions, log clearing, or other anti-forensic steps?
10. Is there evidence excluding alternative channels (mail client, Bluetooth, network share, print)?

| Category | Question Numbers |
|---|---|
| User activity | 1, 4 |
| File staging | 2, 9 |
| Removable media | 3, 4 |
| Cloud / browser activity | 5, 6, 7 |
| Timeline / sequence | 8, 9 |
| Memory / live-state follow-up | (none above — add one: which processes and sockets were live at the 18:01:12 WinPmem capture?) |

**Q1: Why is question definition especially important in a case with many artifact types?**

Questions are how you prioritize. Twenty CSV and text files plus a hash file are enough material to lose two days in if you start by reading every file front-to-back. The questions tell you which artifact to read first, which finding to weight most, and when to stop reading. Without them, the investigation becomes a tour of the dataset rather than a resolution of the case. The questions also give the eventual case summary its structure, so writing them first saves work at the end.

**Q2: Why can this kind of case become unfocused without a clear question set?**

Exfiltration cases involve every artifact class in the book: file system, registry, shell, browser, cloud, event log, and sometimes memory. Without questions to narrow the scope, the analyst drifts into interesting-but-irrelevant findings, such as a six-month-old USB connection or a normal browser history entry. The result is a report that is long, technically correct, and useless for the decision-maker. Questions force the analyst to keep asking "does this finding answer one of my ten?"

**Q3: Why should your final report answer the same questions you started with?**

Anything else is scope drift. If the report answers questions you never asked, the decision-maker has to work out whether their own questions were answered. If it skips questions you did ask, they cannot trust that the silence is meaningful. Returning to the original question set at the end is the discipline that produces useful capstone reports.

---

## Task 4 — Investigate File Staging with MFT and USN

**Sample findings (six entries):**

| File / Path | Artifact Source | Why It Matters | What It Suggests | What It Does Not Prove |
|---|---|---|---|---|
| `C:\Users\hr-user\AppData\Local\Temp\Q4_Customer_Pricing.xlsx` | MFT (`InUse=False`) + USN `FileCreate` 17:39:05 → `FileDelete` 17:55:11 | Transient copy in user-writable Temp directory — classic staging pattern | The file was placed in Temp briefly before some operation, then cleaned up | Why it was placed there — staging for USB, for archiving, for sync, or for upload |
| `C:\Users\hr-user\AppData\Local\Temp\Pricing_Strategy_Confidential.docx` | MFT (`InUse=False`) + USN create-then-delete pair | Same pattern as above for the second pricing file | Two of the three pricing files passed through Temp; consistent with batched staging | Whether the third file (`Margins_Q3.xlsx`) was also staged through Temp — no MFT/USN evidence here |
| `C:\HR\Pricing\` (the source directory itself) | USN `FileDelete` 17:57:42 + MFT InUse=False | The source folder was deleted near the end of the session | Deliberate cleanup of the source materials | Whether the deletion was the user's or automated; either way, the cleanup itself is evidence |
| Ten `FileDelete` entries in two bursts on 2024-11-12: five at 17:55 in `Temp\` and five at 17:57:42 in `C:\HR\Pricing\` | USN journal | Cleanup happens in two tight bursts, not scattered through the day | The deletions are intentional and coordinated, not incidental Windows churn | Which tool performed them. The journal does not say, but EID 4688 shows `cmd.exe /c del /f /q` against the two Temp copies at 17:55:11 |
| `C:\Users\hr-user\AppData\Local\Temp\pricing-staging.zip` (1721184 bytes) | MFT entry 22421 (`InUse=True`) + USN `FileCreate` 17:40:11 | The Temp copy of `Q4_Customer_Pricing.xlsx` was archived 66 seconds after it was staged | Archiving was part of the staging. The archive survived the cleanup, so you can extract it from the image and hash its contents against the legal reference | That the archive left the host. No LNK, sync-database row, or browser artifact references it, and the confirmed channels carried individual files |
| `7ZG.EXE` Prefetch entry with `RunCount=1` and `LastRun` 17:40:11 | Prefetch + EID 4688 + Amcache (SHA-1) | 7-Zip GUI ran once, inside the case window. The 4688 command line (`a -tzip`) names `pricing-staging.zip` as the output and the Temp copy of `Q4_Customer_Pricing.xlsx` as the input | `hr-user` launched the archive step from Explorer | What the archive was for. Amcache proves only that the binary was present. Prefetch and the 4688 prove the run |

**Q1: Why are archive creation and staging paths important in an exfiltration case?**

Attackers and departing employees use archives to batch and compress data before transfer. An archive reduces the upload footprint and hides the source-file structure at the destination. Staging paths such as `Temp\`, `Downloads\`, `Public\`, and `ProgramData\` are where the source files pass through on their way out. Both leave artifacts, such as MFT entries, USN reasons, and Prefetch hits for the archive tool, that together paint the staging picture. In HR-WS17, `7zG.exe` created `pricing-staging.zip` in `Temp\` at 17:40:11 from the staged copy of `Q4_Customer_Pricing.xlsx`. The archive is still on disk, and no USB, OneDrive, or browser artifact references it. The confirmed channels carried individual files, so the archive is a staging finding to extract and hash, not a transfer.

**Q2: Why do deleted records often become more interesting in these cases?**

Cleanup is itself evidence of intent. A user who copies files to USB without thinking about evidence does not delete the source folder. A user who knows what they are doing does. The `FileDelete` entries for the Temp copies at 17:55 UTC and the source-folder deletion at 17:57:42 turn the case from "files happened to leave the host" into "files were placed off-host and then the local copies were removed." Deletions are also where USN and MFT are most useful: the file may be gone, but the journal entry remains, often with the original filename intact.

**Q3: Why should file-system findings be correlated rather than treated as proof of exfiltration by themselves?**

File-system findings alone establish that a file existed. Correlation with USB, cloud, and browser artifacts establishes where it went. A file in `Temp\` is consistent with many narratives, such as a save-as operation, a Word autorecovery copy, or an antivirus scan staging. The same file in `Temp\` *with* a USB connection at the same minute, *with* a personal OneDrive sync log entry referencing the same filename, and *with* a SHA-256 hash matching the legal reference is exfiltration.

---

## Task 5 — Investigate User Access with Shell Items and Registry

**Sample findings (six entries):**

| Finding | Source Artifact | Why It Matters | What It Suggests | Limitation |
|---|---|---|---|---|
| LNK files for all three pricing files exist under `\Recent\` for `hr-user` | LNK metadata | Direct evidence the user opened each file via Explorer | The user interacted with all three pricing files locally on the case day | Does not establish intent; opening a file at work is not malicious by itself |
| Each pricing file has *two* LNKs — one for `C:\HR\Pricing\` (local) and one for `E:\Confidential\Pricing\` (USB) | LNK target paths + volume serial | The user accessed each pricing file from both the local path and the USB path | Direct evidence of USB access to all three pricing files | Does not establish *that* the files were copied to USB — could be opened from USB after being copied via another tool |
| Jump list entries for Excel and Word include both `C:\HR\Pricing\*` and `E:\Confidential\Pricing\*` MRUs | Jump lists | Corroborates the LNK evidence with a second shell-item source | Two independent shell-item classes agree on USB access | Same as LNK — proves access, not copy |
| Shellbag entries for `E:\Confidential\` and `E:\Confidential\Pricing\` with `FirstInteracted` around 17:43 UTC | Shellbags | Records Explorer navigation to those USB folders | The user opened Explorer on the USB and browsed into the sensitive folder hierarchy | Shellbags are not perfectly precise on timing; "around 17:43" is the right resolution |
| OneDrive Accounts registry shows both Business1 (`hr-user@finance.example.com`) and Personal (`hr.user.personal@outlook.com`) | `HKCU\Software\Microsoft\OneDrive\Accounts` | Two accounts on a corporate-managed device — the personal one is the case-relevant one | The user had a personal OneDrive account configured and signed in | Does not prove what was synced through it; account configuration is necessary but not sufficient |
| Not in this dataset — check next: a UserAssist entry for `7zG.exe` | `NTUSER.DAT` UserAssist (not exported to `Data/HR-WS17/`) | Would record the GUI launch in `hr-user`'s own hive | EID 4688 already shows `hr-user` launching `7zG.exe` from Explorer at 17:40:11, so UserAssist would corroborate the run rather than discover it | UserAssist coverage depends on Windows version, and an unparsed source supports no finding either way |

**Q1: Why is user-hive provenance especially important here?**

The case has to attribute the activity to `hr-user` specifically, because multiple users could in theory have touched this workstation. LNK files, jump lists, and shellbags are all user-specific. They live in the user's profile or `UsrClass.dat`, and finding them there is direct evidence that the corresponding profile interacted with the artifacts. Without user-hive provenance, the most you could say is "someone on this host accessed those files." With it, you can name the account.

**Q2: Why are folder-browsing artifacts useful even when they do not prove copying?**

Browsing artifacts establish opportunity and intent. A user with shellbags for `E:\Confidential\Pricing\` did not stumble onto that folder. They navigated there deliberately. Combined with USB device-attached evidence and the timing alignment to the staging and deletion events, browsing artifacts close one alternative explanation: "maybe the user did not know what was on the USB." Direct proof of file copy is rare on Windows hosts. Circumstantial but converging evidence is how these cases actually get made.

**Q3: Why do these artifacts become much stronger when timed against the staging activity?**

The temporal alignment converts "the user touched the USB" into "the user touched the USB during the specific minutes the pricing files were being staged." A shellbag for `E:\Confidential\Pricing\` is informative on its own. A shellbag for `E:\Confidential\Pricing\` with `FirstInteracted` at 17:43:42 forms a tight chain. It falls 94 seconds after the USB was first connected at 17:42:08 and immediately before the three USB LNKs were created at 17:44–17:45. Sequence matters here as much as substance.

---

## Task 6 — Confirm or Challenge USB Involvement

**Sample findings (six entries):**

| USB-Related Finding | Source Artifact | Why It Matters | What It Suggests | What It Does Not Prove |
|---|---|---|---|---|
| Kingston DataTraveler 3.0, serial `001A92053B7CBE3196B40A0F`, first connected 17:42:08 UTC, removed 17:58:30 UTC | USBSTOR | Device installed and active in the case window for 16 minutes 22 seconds | A specific, identifiable device was attached during the activity | That data crossed to the device — installation alone is not exfiltration |
| MountedDevices binds volume GUID `{f1d2e9a4-...}` to drive letter `E:` | MountedDevices | The Kingston device showed up as `E:` to the OS and the user | Drive letter for the USB is established; later artifacts referencing `E:` are this device | Same — binding alone is not transfer |
| Shellbags for `E:\Confidential\` (17:43:11 UTC) and `E:\Confidential\Pricing\` (17:43:42 UTC) | Shellbags | The user navigated to sensitive folders on the device | Folder existed and was browsed on the USB | What was *in* those folders or what happened in them |
| Three LNK files under `\Recent\` with volume serial `F1D2E9A4` — one for each pricing file | LNK volume-serial binding | All three pricing files were opened from the USB path `E:\Confidential\Pricing\` | All three pricing files reached the USB | Whether they were copied *to* the USB from this host vs. opened from a USB that already held them |
| Transient `Temp\` copies of `Q4_Customer_Pricing.xlsx` and `Pricing_Strategy_Confidential.docx` created at 17:39, deleted at 17:55 | MFT + USN | The two files appear in Temp before the USB attachment, consistent with intermediate staging | The two files were prepared for transfer; the USB attached shortly after | Why `Margins_Q3.xlsx` does *not* appear in Temp staging — possibly copied directly from `C:\HR\Pricing\` to USB |
| `pricing-staging.zip` created in `Temp\` at 17:40:11 by `7zG.exe` (Prefetch `RunCount=1`, EID 4688 `a -tzip`) and still `InUse=True` | MFT + USN + Prefetch + Security | An archive of the staged `Q4_Customer_Pricing.xlsx` existed before the USB was attached | The USB LNKs name the individual files, not the archive, so the device received the files themselves | Whether the archive was also copied to the device. Host artifacts record opens, not copies, and no LNK or jump list references the archive |

**Q1: What evidence supports simple device recognition?**

Three artifacts together prove that a specific device was attached at a specific time. USBSTOR holds the device-history install record with vendor, model, and serial. MountedDevices binds the volume GUID to a drive letter. The corresponding `SetupAPI.dev.log` entry is not in this dataset but is present on a live host. This evidence is uniformly strong, because device recognition is one of the better-supported areas of Windows forensics. The Kingston DataTraveler with serial `001A92053B7CBE3196B40A0F` at 17:42:08 UTC is established beyond reasonable doubt.

**Q2: What evidence supports likely browsing or file access on the device?**

Three artifact classes corroborate user interaction with the USB beyond mere attachment. Shellbags record Explorer navigation into folders on the device. LNK files carrying the device's volume serial record files opened from it. Jump-list entries with USB paths record the recent-file MRU from the device. The HR-WS17 dataset has all three: shellbags into `E:\Confidential\Pricing\` at 17:43, three LNKs with volume serial `F1D2E9A4`, and Excel/Word jump-list MRUs pointing at `E:\Confidential\Pricing\*.xlsx` and `.docx`.

**Q3: What additional evidence would make you more confident about copying to USB?**

Four sources would help, in order of decreasing realism:

1. A copy of the USB itself, so you can hash the files and compare them directly to the legal reference. In a real case where the device is recovered, this is the best evidence available.
2. `MFT`/`USN`-equivalent artifacts from the USB volume showing the file-create events on E: with timestamps matching the host's `Temp\` deletion pattern.
3. An EDR with file-write telemetry recording the copy operation directly.
4. Provider-side OneDrive or DLP logs that observed the file movement.

None of these are in scope for this lab. That is why "the USB channel is confirmed at the host-evidence level" is the carefully bounded conclusion the case supports.

---

## Task 7 — Investigate Cloud / Browser Exfiltration

**Sample findings (six entries):**

| Cloud / Browser Finding | Source Artifact | Why It Matters | What It Suggests | Limitation |
|---|---|---|---|---|
| Personal OneDrive account `hr.user.personal@outlook.com` is configured on a corporate-managed host | `onedrive-accounts.csv` | Personal cloud on a corporate device is a policy issue in its own right, and a viable exfil channel | The user had a non-corporate sync target available | Account presence is not transfer; LastSignIn matters |
| Sync database (`onedrive-syncdb.csv`) contains **two** rows: `Q4_Customer_Pricing.xlsx` (enqueued 17:46:42, upload completed 17:47:18) and `Pricing_Strategy_Confidential.docx` (enqueued 17:48:41, upload completed 17:49:18) | OneDrive sync engine database | The cloud channel is independently logged on the host — the sync engine writes its own database row per file with the upload time and content hash | Two pricing files were synced to the personal cloud account during the case window | The third file (`Margins_Q3.xlsx`) is **not** in the sync database — that distinction is critical |
| `Sha256ContentHash` values in `onedrive-syncdb.csv` match the legal-provided hashes for `Q4_Customer_Pricing.xlsx` and `Pricing_Strategy_Confidential.docx` | Cross-source hash comparison | The synced files are demonstrably the same content as the legal-reference files | The cloud channel carried the canonical pricing documents legal asked about | This is the strongest single piece of evidence in the case |
| OneDrive client log (`onedrive-logs-extract.txt`) shows chunked-upload entries between 17:46 and 17:49 UTC referencing both filenames | OneDrive client log | A third independent source confirms the upload | Three sources (legal reference, sync database, client log) all carry the same hashes | Same scope as the sync database — covers two files, not three |
| Browser history shows navigation to `outlook.live.com/mail/0/`, `/deeplink/compose`, and `/sentitems` between 17:51:04 and 17:54:42 UTC | Edge `History` SQLite | Consistent with a webmail compose-and-send sequence | The user composed and sent a webmail message in the case window | Does not prove an attachment crossed; the mail server, not the host, holds that record |
| SRUM records 684221 bytes sent by `msedge.exe` in the 18:00 bucket | SRUM per-process network | Volume consistent with a small attachment upload | Outbound browser traffic in the same bucket as the compose-and-send navigation | SRUM is bucketed, so it cannot place the bytes at 17:51 or name the file |

**Q1: Why is cloud evidence often more difficult to prove from the endpoint alone?**

The authoritative record of cloud activity lives on the provider's side: the OneDrive blob storage, the M365 audit log, the mail server. The endpoint has artifacts of cloud activity, such as sync databases, client logs, and browser history, but those are derived, not authoritative. They can be tampered with on the host, they can be incomplete, and they cannot answer questions such as "is the file still in the cloud?" or "who else accessed it?" The endpoint case is strongest when it shows that the cloud transfer *initiated*. You need the cloud-side audit to show that the transfer *completed* and what happened next.

**Q2: Why do browser artifacts matter even if OneDrive or another sync client is present?**

Different transfer mechanisms leave different traces. A file synced through the OneDrive client appears in the sync database. A file uploaded as a webmail attachment sometimes appears in browser cache and form data. A file uploaded to a sharing service through a browser appears in browser history and `Downloads\`. The OneDrive sync database covers only transfers made through the OneDrive client. Browser history is the catch-net for everything else, including the webmail session at 17:51 UTC that the OneDrive evidence does not address.

**Q3: What would you want from provider-side logs if this were a real enterprise case?**

In this case, provider-side artifacts would elevate the webmail finding from "probable" to "confirmed" and would add an independent cloud-side confirmation of the OneDrive uploads. For OneDrive, you would want the Microsoft 365 Unified Audit Log entries for `FileUploaded` against the personal account, the OneDrive activity feed for the upload time, and ideally the file blob itself for hash confirmation against the legal reference. For webmail, you would want the M365 mail-flow logs or the Outlook.com equivalent for sends in the 17:51 UTC window, the message metadata including attachment names and sizes, and ideally the message body. The chapter and Appendix B cover the specific log sources.

---

## Task 8 — Review Event Logs and Build Context

**Sample findings (six entries):**

| Event-Log Finding | Log Source | Why It Matters | What It Suggests | Limitation |
|---|---|---|---|---|
| `hr-user` interactive logon (EID 4624 LogonType 2) at 08:42:11 UTC on 2024-11-12 | Security | Establishes the user was on the host through the case window | The case-day session is unambiguously attributable to `hr-user` | LogonType 2 is local interactive — does not address remote scenarios that are not in scope here |
| `hr-user` logoff (EID 4634) at 18:02:14 UTC | Security | End of session matches the post-cleanup timing | Session ended naturally after the activity; not abrupt | Logoff is a normal event, not in itself evidence of anything |
| 4688 entries with command lines for `7zG.exe` (`a -tzip`, 17:40:11), `msedge.exe` (`--new-window https://outlook.live.com/mail/0/`, 17:51:04), and `cmd.exe` (`/c del /f /q` against the two Temp copies, 17:55:11) | Security | Records the staging, webmail, and cleanup steps as the commands the user ran | Each step was launched by `hr-user` from Explorer | No suspicious parent/child pairs in this dataset — unlike WKSTN-221, no Outlook-spawned PowerShell |
| Not in this dataset — check next: EID 7045 (service install) in the case window | System (not exported to `Data/HR-WS17/`) | Would show whether a service was installed during the activity | An empty result would rule out persistence-via-service | The dataset holds only the Security log, so no System-log finding can be quoted |
| No EID 1102 (security-log clear) | Security | The Security log was not wiped | Cleanup activity did not include log tampering | The case window is short; if log clearing had happened, it would be visible |
| Not in this dataset — check next: PowerShell EID 4104 in the case window | PowerShell Operational (not exported to `Data/HR-WS17/`) | Would show whether scripting played a part | No 4688 for `powershell.exe` appears in the Security log, which points the same way | Without the Operational log you cannot quote a 4104 negative finding |

**Q1: Why do logs help anchor the case in time?**

Event logs carry the most reliable timestamps on the host. They also cover the activity types that frame the other artifacts: logons, process creation, service install, and scheduled-task creation. The 4624 logon at 08:42:11 and the 4634 logoff at 18:02:14 bound the entire session. Everything between them has to be attributable to the active session, and anything outside it cannot be this user's activity.

**Q2: Why should missing log events be interpreted carefully?**

An absence in the log is meaningful only if the corresponding audit category was enabled. Process-creation auditing (EID 4688) is off by default on Windows, and capturing command lines needs a second policy setting. On a host where it is off, the absence of 4688 means nothing. Confirm what was being audited before you conclude that the silence is informative. In HR-WS17, 4688 records with full command lines are present, so process-creation and command-line auditing were enabled, and you can quote absences within the Security log.

**Q3: Which event patterns are most valuable in a user-driven exfiltration case?**

Four patterns carry the most value. The session-bracket logons (4624 / 4634) confirm who was on the host and when. The process-creation events show the tools used: Explorer, 7-Zip, Edge, the OneDrive client, and `cmd.exe` for the Temp deletions. The negative findings, such as no log clearing, no service install, and no suspicious PowerShell, exclude alternative narratives. Finally, 4624 LogonType 3 (network logon) and 4648 (explicit credential) events show access to or from other hosts. HR-WS17 has one LogonType 3: `svc-backup` from the backup server `10.0.4.42` at 02:14:14 (Kerberos), the routine overnight job. It has no 4648. Nothing shows the activity reaching off this host, so this is a single-host exfiltration case, not a lateral-movement one.

---

## Task 9 — Review Memory for In-Memory Tools or Context

**The capstone-specific reality:** IT ran WinPmem against the live host at 18:01:12 UTC, 62 seconds before the 18:02:14 logoff, and then imaged the disk with FTK Imager. The dataset ships three Volatility 3 plugin outputs from that capture (`volatility-pslist.txt`, `volatility-netscan.txt`, `volatility-cmdline.txt`), not the image itself. Work from those three files and document what they cannot answer.

**Sample findings table (with negative findings explicitly):**

| Memory Finding | Why It Matters | What It Suggests | What It Does Not Prove |
|---|---|---|---|
| Two `OneDrive.exe` processes in `volatility-pslist.txt`: PID 3184 created 08:42:54 and PID 6428 created 17:46:02 | The second client started mid-session, to the second of the Personal account's `FirstAdded` value | Memory independently corroborates the personal-OneDrive channel | What the second client uploaded. The sync database and client log answer that |
| PID 6428 holds ESTABLISHED TCP/443 sockets to 13.107.42.12, an endpoint PID 3184 never touches (`volatility-netscan.txt`) | Separates the personal and corporate sync clients by endpoint | The personal client was connected at acquisition | How many bytes moved. Socket records carry no volume or content |
| `EXCEL.EXE` (PID 4218) and `WINWORD.EXE` (PID 4258) command lines still carry `C:\HR\Pricing\` paths (`volatility-cmdline.txt`) | The folder was deleted at 17:57:42, yet live processes still name it | Matches the 17:38:42 and 17:39:18 EID 4688 records character for character | The 17:44–17:45 opens from `E:\Confidential\Pricing\`. Office passed those to the running processes, so only the LNK files record them |
| `msedge.exe` PID 6604 created 17:51:04 with `--new-window https://outlook.live.com/mail/0/`, with sockets to 52.96.128.51:443 created 17:51:04 and 17:52:11 | Places the browser on the personal webmail at the browser-history times | A third source for the webmail session | That an attachment was sent |
| `7zG.exe` (17:40:11) and `cmd.exe` (17:55:11) are absent from the process list | Both had exited before acquisition | Memory is a snapshot. Prefetch and EID 4688 still record both runs | That they did not run. Absence from `pslist` is not a contradiction |
| `winpmem_mini_x6` (PID 7284) writing to `\\10.0.4.12\ir$\HR-WS17\HR-WS17-memory.raw` | The acquisition tool's own footprint | Belongs in the acquisition record, not the findings | Anything about the user's activity. No `malfind` or other plugin output ships, so record that as a collection gap |

**Q1: Why can memory be especially valuable if the exfiltration involved short-lived tools?**

Memory captures the running process table, command lines, loaded modules, and network connection table at acquisition time, and disk-only forensics sees none of them. Some tools execute, transfer, and exit without leaving Prefetch entries. That happens especially on hosts where Prefetch is disabled or where the binary ran from a path Prefetch does not record. Such tools can also be missing from Amcache, because the hive is subject to periodic cleanup and rebuild (Chapter 6 §6.3.2), and even an Amcache entry proves presence, not execution. Memory has its own limit: in HR-WS17, `7zG.exe` and `cmd.exe` had exited before the 18:01:12 capture, so memory holds neither. For a live-state exfil case, memory often holds evidence that does not exist anywhere else.

**Q2: Why are negative memory findings still worth documenting?**

Documenting what the memory review did not cover is much more honest than implying full coverage. The case summary's confidence claims have to reflect what you actually examined. In HR-WS17 you have three plugin outputs, not the image. Saying "no in-memory evidence of additional tools" without disclosing that only `pslist`, `netscan`, and `cmdline` were reviewed would be misleading. Negative findings, properly captioned, define the scope of the analysis and preserve credibility.

**Q3: Why should memory findings be correlated with disk and log artifacts rather than treated alone?**

Memory captures a moment, while disk and logs capture a history. Correlation is what assigns weight to memory findings. A process visible in memory with no disk or log trace is suspicious and worth investigating. A process visible in memory with a clean Amcache entry and a normal Prefetch hit is benign. Treated alone, memory produces many "this process existed at acquisition time" findings, and you cannot assess their significance without the rest of the evidence base.

---

## Task 10 — Build the Incident Timeline

**Sample timeline (15 entries from the HR-WS17 dataset):**

| Time (UTC) | Artifact Type | Event Description | Context | Why It Matters |
|---|---|---|---|---|
| 08:42:11 | Security 4624 | `hr-user` interactive logon (LogonType 2) | Start of the case-day session | Bounds the activity to a single attributable session |
| 17:38:42 | LNK / Jump List | `Q4_Customer_Pricing.xlsx` opened locally from `C:\HR\Pricing\` | User accesses first pricing file | Earliest case-window activity; establishes user contact with the data |
| 17:39:05 | MFT + USN `FileCreate` | `Q4_Customer_Pricing.xlsx` copied into `%TEMP%` | Staging begins | First evidence of preparation-for-transfer |
| 17:39:18 | MFT + USN `FileCreate` | `Pricing_Strategy_Confidential.docx` copied into `%TEMP%` | Second file staged 13 seconds after the first | Batched staging — consistent with deliberate prep |
| 17:40:11 | Prefetch + Security 4688 + MFT + USN | `7zG.exe` archives the Temp copy of `Q4_Customer_Pricing.xlsx` into `Temp\pricing-staging.zip` | Staging includes an archive step | The archive is still on disk (`InUse=True`). No later artifact shows it leaving the host |
| 17:42:08 | USBSTOR | Kingston DataTraveler 3.0 (serial `001A92053B7CBE3196B40A0F`) first connected | USB attached after staging | USB channel opens; the temporal gap between staging and USB is small |
| 17:43:11 / 17:43:42 | Shellbags | `E:\Confidential\` then `E:\Confidential\Pricing\` first-interacted | User navigates into sensitive USB folders | The user does not stumble into these folders — they navigate there |
| 17:44:18 / 17:44:55 / 17:45:32 | LNK with volume serial `F1D2E9A4` | LNK files created for all three pricing files at `E:\Confidential\Pricing\*` | All three files reach the USB | This is where `Margins_Q3.xlsx` enters the evidence — only via USB |
| 17:46:42 | OneDrive sync DB + client log | `Q4_Customer_Pricing.xlsx` enters personal-OneDrive sync queue (`EnqueuedUtc`). Upload completes at 17:47:18 | Cloud channel opens for first pricing file | SHA-256 in sync DB matches legal reference — strongest single piece of evidence |
| 17:48:41 | OneDrive sync DB + client log | `Pricing_Strategy_Confidential.docx` enters the sync queue. Upload completes at 17:49:18 | Cloud channel handles second pricing file | Second hash match against legal reference |
| 17:51:04–17:54:42 | Browser history + SRUM | `msedge.exe` navigates to `outlook.live.com/mail/0/`, then `/deeplink/compose` (17:52:11), then `/sentitems` (17:54:42). SRUM records 684221 bytes sent by `msedge.exe` in the 18:00 bucket | Webmail compose-and-send sequence | Probable third channel; attachment content not recoverable from host |
| 17:55:11 | USN `FileDelete` (x2) | Both Temp staging copies deleted | Cleanup of staging area | Intentional cleanup; consistent with awareness of forensic traces |
| 17:57:42 | USN + MFT | `C:\HR\Pricing\` source directory deleted | Cleanup of source materials | Compounds the cleanup evidence; the directory deletion is itself a finding |
| 17:58:30 | USBSTOR | Kingston DataTraveler 3.0 removed | USB channel closes | 16 minutes 22 seconds attached; bookended by purposeful activity |
| 18:02:14 | Security 4634 | `hr-user` logoff | End of session, end of activity | Session ends after the activity completes; not abrupt |

**Q1: Which events are most central to the suspected exfiltration?**

The most central events are the OneDrive sync database rows enqueued at 17:46:42 and 17:48:41. Their SHA-256 hashes match the legal-provided reference, which is the finding with the most evidentiary weight in the case. The three USB LNK creations at 17:44–17:45 come second, because they establish that all three pricing files reached the device. The MFT/USN staging-and-deletion pattern is third. It ties the disk-side preparation to both the USB and cloud channels.

**Q2: Which events support the USB path?**

Five independent artifact classes corroborate the USB channel:

- USBSTOR install at 17:42:08
- MountedDevices binding to `E:`
- shellbags into `E:\Confidential\Pricing\` at 17:43
- three LNKs with the Kingston volume serial `F1D2E9A4` for all three pricing files at 17:44–17:45
- USB removal at 17:58:30

The USB is the *only* channel for which `Margins_Q3.xlsx` has direct evidence.

**Q3: Which events support the cloud path?**

Four artifact classes confirm the cloud channel for `Q4_Customer_Pricing.xlsx` and `Pricing_Strategy_Confidential.docx`. The personal OneDrive account is configured in `HKCU\...\OneDrive\Accounts`. The sync database has rows for two of the three pricing files, with matching SHA-256 hashes. OneDrive client log entries show chunked uploads for both files between 17:46 and 17:49. SRUM shows bytes-out for `OneDrive.exe` in the same window. The cloud channel for `Margins_Q3.xlsx` is **not** evidenced.

**Q4: Which events are ambiguous or only weakly supportive?**

The browser navigation to `outlook.live.com` at 17:51:04 is consistent with a webmail send but does not prove an attachment crossed. The SRUM bytes-out for `msedge.exe` are bucketed and only show that *some* outbound traffic happened. The `pricing-staging.zip` archive created at 17:40:11 is ambiguous too. It is staging evidence, but no artifact shows where, if anywhere, it went. The memory output covers one moment and three plugins. That is a limitation rather than an ambiguous finding, but flag it anyway.

---

## Task 11 — Determine What Most Likely Happened

**Q1: What happened?**

On 2024-11-12 between approximately 17:38 and 18:00 UTC, user `hr-user` on host `HR-WS17` accessed three confidential pricing files: `Q4_Customer_Pricing.xlsx`, `Pricing_Strategy_Confidential.docx`, and `Margins_Q3.xlsx`. The user staged at least two of them through `%TEMP%`, archived the staged copy of `Q4_Customer_Pricing.xlsx` into `pricing-staging.zip`, and copied all three to a Kingston DataTraveler 3.0 USB device (serial `001A92053B7CBE3196B40A0F`). The user also synchronized two of the three, `Q4_Customer_Pricing.xlsx` and `Pricing_Strategy_Confidential.docx`, to a personal OneDrive account (`hr.user.personal@outlook.com`). In the same window, the user navigated to Outlook.com webmail in a sequence consistent with composing and sending an email. Host artifacts alone cannot confirm the attachment content. The local source folder and Temp staging copies were deleted before logoff. The archive was left in place.

**Q2: Which host and user account were involved?**

Host: `HR-WS17`, a FINANCE/HR workstation running Windows 10, which IT preserved at offboarding on 2024-11-12 using FTK Imager. User account: `hr-user`, with an interactive logon at 08:42:11 UTC and a logoff at 18:02:14 UTC. The case-day session is unambiguously attributable to this account. The personal cloud account involved was `hr.user.personal@outlook.com`, a non-corporate Microsoft account configured in `HKCU\Software\Microsoft\OneDrive\Accounts\Personal`.

**Q3: How did the data most likely leave the system?**

Via **two confirmed channels and one probable channel**:

- **Confirmed — USB:** all three pricing files reached the Kingston device. The evidence is three LNKs with the device volume serial, shellbags into `E:\Confidential\Pricing\`, and the USBSTOR + MountedDevices binding.
- **Confirmed — Personal OneDrive:** two of the three files (`Q4_Customer_Pricing.xlsx`, `Pricing_Strategy_Confidential.docx`) were synced to the personal OneDrive account. The SHA-256 hashes in the OneDrive sync database match the legal-provided reference hashes. That match is the strongest single piece of evidence in the case.
- **Probable but unconfirmed from host alone — Webmail:** browser navigation to `outlook.live.com/compose` and `/sentitems` at 17:51 UTC, plus 684221 bytes sent by `msedge.exe` in the SRUM 18:00 bucket, are consistent with a webmail send. The host cannot confirm whether an attachment crossed. Provider-side mail logs would close this gap.

The third pricing file, `Margins_Q3.xlsx`, has direct evidence for the USB channel only. It is **not** in the OneDrive sync database, and no host-side artifact attributes it to the webmail channel. Stating that "all three files were exfiltrated through all three channels" is the canonical overclaim this case trains against.

**Q4: What evidence most strongly supports that conclusion?**

The SHA-256 hash matches between the legal-provided reference, the OneDrive sync database, and the OneDrive client log for `Q4_Customer_Pricing.xlsx` and `Pricing_Strategy_Confidential.docx`. Three independent sources carrying the same hashes is unrebuttable evidence that those two files reached the personal cloud account. For the USB channel, the combination of USBSTOR + MountedDevices + shellbags + volume-serial-matched LNKs across three pricing files is similarly strong, even though the device contents themselves are not in scope for this lab.

**Q5: What alternate explanations remain possible?**

- *The user was using personal OneDrive routinely and the timing is coincidence.* Refuted by the temporal alignment between the staging, the USB attachment, and the OneDrive sync window, and by the targeting of confidential pricing files specifically.
- *The pricing files were already on the USB before this session — the user merely opened them.* Partly refuted by the Temp staging pattern for two of the three files immediately before the USB attachment. Staging before attachment is inconsistent with files that were already on the USB.
- *The webmail navigation is unrelated to file transfer.* This is genuinely possible. The webmail finding is documented as probable-but-unconfirmed precisely for this reason; provider-side mail logs would resolve it.
- *Someone else used the account.* Refuted by the unbroken 4624-to-4634 session for `hr-user` and the lack of any 4648 or remote-logon evidence during the case window.

**Sample conclusion table:**

| Conclusion | Evidence That Strongly Supports It | Evidence That Only Suggests It | Confidence |
|---|---|---|---|
| User account involved | `hr-user` 4624 at 08:42, 4634 at 18:02 bracket the entire activity window; LNKs and shellbags under that profile | — | HIGH |
| USB involvement | USBSTOR + MountedDevices + shellbags into `E:\Confidential\Pricing\` + three LNKs with volume serial `F1D2E9A4` for all three pricing files | — | HIGH |
| Cloud involvement (2 of 3 files) | OneDrive accounts registry + sync database with matching SHA-256 hashes + OneDrive client log + SRUM bytes-out | — | HIGH (for the two files in the sync DB) |
| Cloud involvement for `Margins_Q3.xlsx` | — | None of the cloud sources reference this file | NOT SUPPORTED |
| Staging activity | MFT + USN agree on Temp create/delete pattern for two pricing files. Prefetch, EID 4688, MFT, and USN agree on the 17:40:11 `pricing-staging.zip` archive | The staging picture for `Margins_Q3.xlsx` is gap-filled — no Temp staging visible | HIGH for two files; MEDIUM for the staging picture overall |
| Likely exfil path | USB (all three files) + personal OneDrive (two files) — both confirmed | Webmail (third channel) — probable but cloud-side evidence needed | HIGH for the named channels; MEDIUM overall because the webmail thread is open |

---

## Task 12 — Write the Case Summary

**Sample case summary (one-to-three page length, suitable for technical leadership and internal stakeholders):**

> **Case reference:** IR-2024-HRWS17 — Pricing-file exfiltration, departing employee
> **Author:** J. Responder, IR team
> **Date/Time (UTC):** 2024-12-03 (legal request received) — 2024-12-04 (analysis completed)
>
> **Scope of investigation.** On 2024-12-03, Legal asked IR to determine whether a recently departed employee took confidential pricing data on or near their last day. IR analyzed the preservation image of host `HR-WS17`, an HR/finance workstation that IT acquired with FTK Imager at offboarding on 2024-11-12. Chain of custody has been documented continuously since acquisition. The investigative window of interest was the user's last session, 2024-11-12 08:42 to 18:02 UTC. Legal provided three SHA-256 reference hashes for the pricing files in scope: `Q4_Customer_Pricing.xlsx`, `Pricing_Strategy_Confidential.docx`, and `Margins_Q3.xlsx`.
>
> **Main evidence sources used.** NTFS evidence (MFT, USN Journal), shell items (LNK, Jump Lists, Shellbags), Registry (USBSTOR, MountedDevices, OneDrive Accounts), OneDrive sync database and client log, browser history (Edge), the Security event log, SRUM, Prefetch, and Volatility 3 output (pslist, netscan, cmdline) from the WinPmem memory capture IT took at 18:01:12 UTC while the session was still live.
>
> **Most important findings.** Between 17:38 and 18:00 UTC on 2024-11-12, user `hr-user` interacted with all three pricing files locally and staged at least two of them through `%TEMP%`. The user copied all three to a Kingston DataTraveler 3.0 USB device (serial `001A92053B7CBE3196B40A0F`), which was attached for 16 minutes 22 seconds. The user also synchronized two of the three (`Q4_Customer_Pricing.xlsx` and `Pricing_Strategy_Confidential.docx`) to a personal Microsoft account, `hr.user.personal@outlook.com`. The SHA-256 hashes for the two synced files in the OneDrive sync database match the legal-provided reference hashes. The legal reference, the sync database, and the client log together give independent triple-source confirmation that those specific files reached the personal cloud account. The local source folder `C:\HR\Pricing\` and the Temp staging copies were deleted before logoff. The user also navigated to Outlook.com webmail at 17:51 UTC in a sequence consistent with composing and sending an email. This third channel is probable but cannot be confirmed from host evidence alone.
>
> **Timeline-based narrative.** The user logged on at 08:42 UTC for what is otherwise a normal HR/finance workday. At 17:38, near the end of the session, the user opened `Q4_Customer_Pricing.xlsx`. Within 36 seconds, two of the three pricing files had been copied into `%TEMP%`, and at 17:40:11 7-Zip archived the first copy into `pricing-staging.zip`. At 17:42:08, the Kingston USB device was first connected, mounted as `E:`. The user navigated into `E:\Confidential\Pricing\` (shellbags at 17:43), and by 17:45:32 LNK files for all three pricing files had been created against the USB volume serial. The OneDrive sync engine queued and uploaded the first two pricing files between 17:46 and 17:49. At 17:51, the user navigated through Outlook.com's compose-and-send flow, and SRUM records 684221 bytes sent by the browser in its 18:00 bucket. Cleanup followed: both Temp copies were deleted at 17:55:11, the source `C:\HR\Pricing\` directory at 17:57:42, and the USB device was removed at 17:58:30. The user logged off normally at 18:02:14.
>
> **Strength of conclusions.** The USB channel is confirmed for all three pricing files at the host-evidence level (USBSTOR install + MountedDevices binding + shellbags + three volume-serial-matched LNK files). The personal-OneDrive channel is confirmed for two of the three pricing files at the highest evidentiary level available. Two host-side sources, the sync database and the client log, carry the same SHA-256 content hashes, and those hashes match the legal-provided reference. That is as strong as endpoint forensics gets for a cloud transfer. The webmail channel is consistent with the timeline but cannot be elevated from probable to confirmed without provider-side mail logs.
>
> **Gaps or uncertainties.** Three principal gaps remain. (1) `Margins_Q3.xlsx` reaches the USB but is not in the personal-OneDrive sync database. Its only documented exfil channel is USB. (2) The webmail attachment content is not recoverable from the host, and provider-side audit logs are required. (3) Memory covers one snapshot. Tools that had exited before the 18:01:12 capture, such as `7zG.exe` and `cmd.exe`, do not appear in it, and only three plugin outputs were kept. None of these gaps materially weakens the principal findings, because the two confirmed channels for the two highest-priority files are independently established. Any onward communication should still acknowledge them.
>
> **Recommended next steps.** Pull the Microsoft 365 Unified Audit Log for the personal-account upload time window to obtain provider-side `FileUploaded` confirmation. Pull Outlook.com mail-flow logs for sends from `hr.user.personal@outlook.com` between 17:50 and 17:55 UTC to resolve the webmail channel. Attempt recovery of the Kingston USB device for direct hashing of `Margins_Q3.xlsx` against the legal reference. Review whether the personal-OneDrive account on a corporate-managed device represents a policy violation independent of the exfiltration finding.

---

## Task 13 — Write Remediations and Control Recommendations

**Sample recommendation table (eight entries):**

| Recommendation | Why It Matters | Priority |
|---|---|---|
| Initiate legal hold on `hr-user`'s former mailbox, the personal Microsoft account if available via subpoena, and the Kingston USB device if recoverable | Preserves the remaining evidence channels before they are lost; the personal account and the device are the routes to the unresolved webmail and `Margins_Q3.xlsx` questions | HIGH |
| Pull Microsoft 365 Unified Audit Log entries for the personal-account upload window and Outlook.com mail-flow logs for the 17:51 UTC send | Resolves the webmail-channel uncertainty and adds independent cloud-side confirmation of the OneDrive uploads | HIGH |
| Block personal Microsoft / OneDrive accounts from being added to corporate-managed devices via Conditional Access or Intune device-restriction policy | Closes the cloud-channel route used in this case; durable preventive control | HIGH |
| Implement USB write-blocking or USB-control DLP on all finance/HR workstations | Closes the removable-media channel used in this case; covers the file that left only via USB (`Margins_Q3.xlsx`) | HIGH |
| Enable Microsoft Purview DLP or equivalent for the pricing-file repository, with auto-classification of HR/Pricing as confidential and policy-based blocking of upload to non-corporate cloud, USB, and external email | Prevents the next instance of this exact case; addresses all three channels at once | HIGH |
| Keep live memory capture in the offboarding workflow, and standardize the Volatility plugin set run against it (for example `windows.filescan` and `windows.handles` alongside `pslist`, `netscan`, and `cmdline`) | The 18:01:12 capture produced the second-OneDrive-client finding, but only three plugin outputs were kept, which limits what a later reviewer can check | MEDIUM |
| Review and tighten audit-policy coverage on finance/HR endpoints: confirm process-creation auditing, command-line auditing, and PowerShell ScriptBlockLogging are all enabled and centrally forwarded | Ensures the next investigation has the event-log coverage this one benefited from | MEDIUM |
| Implement a pre-offboarding usage-anomaly review for departing employees in roles with access to pricing or other regulated data: review USB activity, personal-cloud sign-ins, and unusual export volumes in the 30 days before departure | Detects exfiltration prep activity before the employee leaves, when intervention is still meaningful | MEDIUM |

**Q1: Why should recommendations include both immediate remediation and longer-term controls?**

Immediate remediation closes the current case, and longer-term controls prevent the next one. Recommending only immediate actions, such as "revoke the account" or "issue legal hold," leaves the door open for the same scenario to recur. Recurrence is the part of the case that matters to the business. Recommending only longer-term controls leaves the current case unaddressed. You need both, and you have to priority-rank them separately because they compete for the same security-team capacity.

**Q2: Why do logging and artifact-collection improvements often belong in the recommendations?**

Every case reveals what would have made the next case easier: a log that was not enabled, an artifact that was not collected, a control that would have caught the activity earlier. The HR-WS17 case kept only three memory plugin outputs and had no centralized DLP signal for personal-OneDrive use. Both are reasonable additions to recommend. Logging improvements also tend to cost less and pay off more than they appear to, because they help in every future case rather than preventing one specific scenario.

**Q3: Why should the recommendations reflect the uncertainties of the case instead of pretending the evidence is perfect?**

The people who read recommendations rely on them to make resource decisions, so they need an accurate picture of the case's strength. If the webmail channel is probable but not confirmed, the recommendation to pursue provider-side mail logs belongs explicitly in the HIGH-priority list, because that work closes the uncertainty. Pretending the case is fully resolved produces recommendations that miss the work that matters. Honest uncertainty in the recommendations also calibrates stakeholder expectations about what the report does and does not prove.

---

## Task 14 — Write an Analyst Handoff Note

**Sample handoff note:**

```
Case Reference:    IR-2024-HRWS17
Author:            J. Responder
Date/Time (UTC):   2024-12-04 16:00

Primary Question:
- Did the departing employee take confidential pricing data on or near their
  last day, and if so, through which channel(s)?

Most Important Findings:
- USB exfiltration confirmed for all three pricing files (Kingston DataTraveler 3.0,
  serial 001A92053B7CBE3196B40A0F, attached 17:42:08-17:58:30 UTC on 2024-11-12)
- Personal-OneDrive exfiltration confirmed for Q4_Customer_Pricing.xlsx and
  Pricing_Strategy_Confidential.docx — SHA-256 hashes match legal-provided
  reference (sync DB and client log both carry the hashes)
- Webmail exfiltration probable but not confirmed from host alone — browser
  navigation to outlook.live.com compose+send at 17:51 UTC plus SRUM bytes-out

Most Strongly Supported Conclusions:
- Two of three pricing files reached personal-OneDrive (`hr.user.personal@outlook.com`)
- All three pricing files reached the Kingston USB device
- The user attempted to clean up — Temp staging copies and the C:\HR\Pricing\
  source directory deleted before logoff

What Is Suggested but Not Fully Confirmed:
- Whether the webmail send carried a pricing-file attachment
- Whether `Margins_Q3.xlsx` reached anywhere other than the Kingston USB device
- Whether the Kingston device contents are still recoverable

Likely Exfiltration Path(s):
- Confirmed: USB (Kingston, all three files), Personal OneDrive (two of three files)
- Probable: Outlook.com webmail (channel only; attachment content unverified)
- Ruled out: mail client (PST/OST), Bluetooth file transfer, printer/MTP, network share

Recommended Next Actions:
1. Pull M365 Unified Audit Log for the personal-account upload window — provider-
   side confirmation of FileUploaded events
2. Pull Outlook.com mail-flow logs for sends from hr.user.personal@outlook.com
   between 17:50 and 17:55 UTC on 2024-11-12 — resolves webmail channel
3. Recover and image the Kingston USB device if possible — direct hash of
   Margins_Q3.xlsx against legal reference would close the remaining file gap

Open Questions:
- Did Margins_Q3.xlsx leave the host via any channel other than USB?
- Was the webmail send a personal communication or an attachment-bearing message?
- Are there other pricing files outside the three named by legal that were also
  touched in the case window?

Notes for Incoming Analyst:
The case has two firm conclusions and one open thread. Do not collapse the
three pricing files to "all three were exfiltrated through all three channels" —
the evidence supports a more precise statement than that, and overclaiming is
the most damaging mistake you can make on this case. Margins_Q3.xlsx is the
file that distinguishes the channels; treat it as the test case for any new
finding. The cloud-side evidence is the strongest part of the file; the host-
side webmail evidence is the weakest. Provider-side audit work would be the
highest-value next step.
```

---

## Task 15 — Reflection

**Q1: Why correlation matters most in exfiltration cases**

Exfiltration cases rarely have a single artifact that proves transfer. A USB connection is consistent with both routine work and exfiltration. A OneDrive sync entry is consistent with both legitimate cloud backup and unauthorized upload. A webmail send is consistent with both personal communication and attachment-bearing exfil. The surrounding cluster is what converts each of these into evidence of exfiltration: staging in Temp, source-folder deletion, and hash-matched cloud uploads in the same window as the USB connection and the webmail navigation. No single artifact in this case proves anything on its own. The combination of all of them is what produces a defensible answer. Single-artifact answers in exfil cases are almost always overclaims.

**Q2: USB versus cloud ambiguity**

Both channels can produce host-side artifacts that look similar at a glance, such as file access, shell items, and recent-item entries. That makes it easy to attribute activity to the wrong channel. USB artifacts (USBSTOR, MountedDevices, volume-serial LNKs) and cloud artifacts (OneDrive accounts, sync database, client logs) live in different parts of the host and require different parsing workflows, so an incomplete investigation can miss one entirely. The HR-WS17 case illustrates the trap directly. The USB channel covers all three pricing files, and the cloud channel covers two. The difference matters legally and operationally, but it is invisible unless the analyst checks each channel against each file. Never assume the channels overlap perfectly.

**Q3: Case-writing discipline**

The audience reads the case summary differently than the analyst writes it. The analyst knows which sentences are HIGH confidence and which are MEDIUM. The audience treats every sentence as equally weighted unless told otherwise. Writing that explicitly separates "confirmed" from "probable" in both the table and the prose is the only way to keep the eventual decision aligned with the actual evidence. Sloppy case-writing leads to decisions based on findings the evidence does not support. An overclaim harms the affected employee, and an underclaim harms the organization. Be exactly as confident as the evidence allows, and no more.

**Q4: From artifacts to decisions**

Investigations exist to inform decisions: account actions, legal proceedings, control improvements, and policy changes. A report that ends with findings but no recommendations leaves the decision-maker to translate the technical content, which they often cannot do well. Translating findings into remediations is also where the analyst surfaces what would have prevented or detected the case. That is often more valuable to the organization than the case itself. The investigation is complete not when the artifacts are catalogued, but when the organization knows what to do differently as a result.

---

## Ready-to-move-on self-check

**1. What is the strongest single piece of evidence in the HR-WS17 case, and why?**

The SHA-256 hash matches between the legal-provided reference, the OneDrive sync database, and the OneDrive client log for `Q4_Customer_Pricing.xlsx` and `Pricing_Strategy_Confidential.docx`. Two host-side sources, the sync database and the client log, carry the same content hashes, and those hashes line up with hashes legal generated separately from canonical copies. That is as strong as endpoint forensics gets. The hash match is the moment the case becomes legally defensible.

**2. Why is it incorrect to say "all three pricing files were exfiltrated through both confirmed channels"?**

Because the evidence does not support it for `Margins_Q3.xlsx` on the OneDrive channel. The OneDrive sync database has two rows, not three. `Margins_Q3.xlsx` is present in the USB evidence (LNK with volume serial) but absent from every cloud-side artifact. Flattening the three files to a single uniform conclusion overclaims the cloud channel and is exactly the mistake the case is designed to train against.

**3. Why is the webmail channel described as "probable but not confirmed from host alone"?**

The host shows the navigation to compose-and-send at 17:51 UTC, and SRUM records 684221 bytes sent by the browser in the 18:00 bucket. Both are consistent with a webmail send carrying an attachment, but neither artifact identifies *what* was sent or *whether* an attachment crossed. The Outlook.com mail server holds the authoritative record. Without it, the host evidence is suggestive rather than conclusive. The chapter's discipline is to label suggestive evidence as suggestive, not to upgrade it.

---

## Walkthrough ↔ workbook bridges

These bridges connect the workbook tasks in this file to specific values that the Hands-On Walkthrough produces when it resolves the case against `Data/HR-WS17/`.

- **Task 4 (file staging) ↔ Walkthrough Step 2.** The walkthrough produces 10 `FileDelete` USN entries on 2024-11-12: five at 17:55 in `%TEMP%` and five at 17:57:42 in the `C:\HR\Pricing\` source folder. That is the pattern Task 4 asks for: deliberate cleanup of staging and source paths in two bursts, consistent with awareness of forensic traces. The `Q4_Customer_Pricing.xlsx` and `Pricing_Strategy_Confidential.docx` copies deleted from Temp are the same pair that reaches OneDrive in Steps 7–8, and the temporal alignment connects them.

- **Task 6 (USB confirmation) ↔ Walkthrough Steps 3–5.** The walkthrough establishes the USB channel with three converging sources: USBSTOR (Kingston DataTraveler 3.0, serial `001A92053B7CBE3196B40A0F`, attached 17:42:08 UTC, removed 17:58:30 UTC), shellbags into `E:\Confidential\Pricing\` at ~17:43, and three LNK files with volume serial `F1D2E9A4` covering all three pricing files. That convergence is the textbook USB-confirmation pattern.

- **Task 7 (cloud confirmation) ↔ Walkthrough Steps 6–8.** The OneDrive accounts CSV shows the personal account `hr.user.personal@outlook.com` is configured. The sync database has *two* rows: `Q4_Customer_Pricing.xlsx` (upload completed 17:47:18 UTC) and `Pricing_Strategy_Confidential.docx` (upload completed 17:49:18 UTC). Their `Sha256ContentHash` values match the legal-provided reference hashes from `pricing-files-known-hashes.txt`. The OneDrive client log corroborates with chunked-upload entries in the same window. That gives three independent sources for two files, which is the case's strongest evidence. The third file, `Margins_Q3.xlsx`, is **not in any cloud source**. This bridges to Task 11's careful distinction between the two channels and the three files.

- **Task 7 (webmail probability) ↔ Walkthrough Step 9.** Browser history shows four rows: navigation to `outlook.live.com/mail/0/` at 17:51:04, then `/deeplink/compose`, then `/sentitems`, then back to `/mail/0/` at 17:55:48. SRUM records 684221 bytes sent by `msedge.exe` in the 18:00 bucket. Both are consistent with a webmail send, but neither proves an attachment crossed. Task 7 documents this as "probable, unconfirmed from host alone" — the exact label the chapter requires.

- **Task 10 (timeline) ↔ Walkthrough Step 10.** The channel-analysis table in the walkthrough is the synthesis the timeline supports: USB confirmed for all three files, Personal OneDrive confirmed for two of three (with hash matches), Webmail probable, all other channels ruled out. The timeline rows from 17:38 to 18:02 produce exactly that table. No row is invented or omitted, and the asymmetry between the three files and the three channels is preserved.

- **Task 11 (defensible conclusions) ↔ Walkthrough Step 10.** The walkthrough flags each channel by status (Confirmed / Confirmed / Probable / Ruled out) and each finding by the evidence that supports it. Task 11 inherits that structure verbatim. The "Conclusion table" maps cleanly onto the channel-analysis table, and the answer to "what most likely happened" reads as a prose rendering of the same content. That discipline at the case-conclusion step is what survives review. Overclaiming at this step is the failure mode the entire capstone is designed to defend against.
