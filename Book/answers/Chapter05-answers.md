# Chapter 5 — Review Question and Exercise Answers

*Sample answers for the Review Questions and Practical Exercises at the end of [`Chapter05.md`](../Chapter05.md). These are reference answers, not the only correct answers. Your wording will differ, and that is fine. What matters is whether your reasoning covers the same ground. For the corresponding lab, see [`Labs/Lab05/task-answers.md`](../../Labs/Lab05/task-answers.md) and [`Labs/Lab05/walkthrough-answers.md`](../../Labs/Lab05/walkthrough-answers.md).*

---

## Review Questions

**1. What is the difference between a per-machine and a per-user registry hive, and why does it matter forensically?**

Per-machine hives (`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, in `%SystemRoot%\System32\config\`) load as `HKLM` and hold configuration that applies to the whole host: services, drivers, installed software, network configuration, USB device history, system policies. Every user sees the same content, and modifying it normally requires administrator rights. Per-user hives (`NTUSER.DAT` and `UsrClass.dat` under each profile) load as `HKCU` for whoever is logged on. They hold that individual's typed paths, recently accessed files, application preferences, shellbags, and per-user run-on-logon entries, and changing them does not require elevation. The forensic consequence is attribution. A malicious `Run` value in `HKLM\Software` tells you something ran on this machine and that whoever wrote it had administrator rights. The same value in a specific user's `NTUSER.DAT` tells you *which account* it belongs to and that no elevation was needed. On a multi-user host, collect every profile's hives, or you have collected only part of the evidence.

**2. Why is a key's last-write time a less precise artifact than people sometimes assume?**

Because it is a property of the key, not of any individual value. A last-write time tells you that something under that key changed at that moment. It does not tell you *which* value changed, what it changed from, or whether the change was the one you care about. A `Run` key with a last-write time inside the incident window might have had a malicious value added. Or a software update that happened to run at the same time might have updated an unrelated legitimate entry. Values themselves carry no timestamps at all. Reconstructing value-level history requires registry transaction logs, prior versions from Volume Shadow Copies, or independent corroboration from another artifact. In a finding, say that the key was modified at a given time and the observed value is consistent with that modification. Do not say the value was written then.

**3. What kinds of attacks are commonly investigated using the `Run`, `RunOnce`, and `Services` keys?**

Persistence, primarily — the mechanism by which an attacker arranges to regain code execution after reboot, logoff, or partial remediation. `Run` and `RunOnce` in both `HKLM\Software` and `HKCU` launch programs at logon and are the cheapest persistence an attacker can establish, which is exactly why they remain common. `HKLM\System\CurrentControlSet\Services` is the higher-privilege equivalent and carries more: `ImagePath` names the executable, `Start` controls whether it launches at boot, and `Type` distinguishes a kernel driver from a user-mode service. A malicious driver is a much more serious finding than a malicious user-mode service. Attackers also use the same key set for privilege abuse and lateral movement, since remotely installing a service is a classic execution technique. Winlogon hooks (`Userinit`, `Shell`) and Image File Execution Options debugger hijacks belong in the same investigative sweep. The questions to ask of any new entry are constant: who owns the executable, when did the key change, does the file still exist on disk, and does it behave like a legitimate program.

**4. How does USBSTOR combined with `Windows Portable Devices\Devices` support a "files copied to USB" hypothesis?**

`HKLM\System\CurrentControlSet\Enum\USBSTOR` identifies the device itself: vendor, product, revision, and serial number. It also records first and last connection times, which establishes *that a specific physical device was attached and when*. `HKLM\Software\Microsoft\Windows Portable Devices\Devices` adds the device's `FriendlyName`, normally the volume label it was formatted with. It does not record drive letters. For that you need `HKLM\SYSTEM\MountedDevices`, which maps `\DosDevices\E:` to a volume GUID that ties back to the USBSTOR entry. The drive-letter binding is what lets you connect the device to path-based evidence elsewhere. Without it, a shellbag entry for `E:\Confidential\` or a LNK file pointing at `E:\...` is unattributable, because Windows reassigns `E:` to other removable devices over time. Together these keys turn "some device was attached" and "the user browsed E:" into "the user browsed this Kingston DataTraveler with this serial." That is still not proof of copying. For that you need shellbags for the folders browsed, LNK files and Jump Lists for the files opened, and MFT or USN evidence for files created on the host. It is, however, the identification layer everything else hangs from. In the shipped `Data/HR-LT12/` set, `usbstor.csv` (USBSTOR) and `mountpoints.csv` (MountedDevices) show the device record and the drive-letter binding side by side. The set has no `Windows Portable Devices` export.

**5. Why does UserAssist remain useful even when Prefetch is disabled?**

Because it is an independent record. It is stored per-user in `NTUSER.DAT` rather than as files in `%SystemRoot%\Prefetch\`, and it survives every condition that removes Prefetch. Prefetch is disabled by default on Windows server SKUs, is sometimes turned off on SSD-backed systems, and its `.pf` files can be deleted. None of that affects UserAssist. UserAssist also answers a question Prefetch cannot. It records programs the user launched *through the Explorer GUI*, with a run counter and a last-execution timestamp. That makes it the artifact of choice when the distinction between user-initiated and automated execution matters, especially in insider cases. The same property is its limit. Programs launched from a command line, a script, or a scheduled task generally do not appear at all, so an empty UserAssist result is not evidence that a binary did not run.

**6. What additional information do registry transaction logs provide beyond the live hive?**

They contain changes that have been written but not yet merged into the main hive file. Windows uses `.LOG1` and `.LOG2` files alongside each hive for crash-consistency, and at any given moment the most recent modifications may exist only there. A parser that understands transaction logs replays them and shows current values. A parser that does not shows stale ones. Two analysts examining the same collected hive with different tools can therefore legitimately get different answers. This matters most for hives collected from a live system, where the gap is largest and where the changes most likely to be pending are the recent ones you care about. In practice, always collect `.LOG1` and `.LOG2` with the hive, always keep them together, and use tooling that handles them. Registry Explorer and RECmd both do this transparently when the files are present.

**7. What forensic artifacts are produced by a typical cloud sync client, and which carries the most detailed per-file history?**

Five categories. The local sync folder under the user profile shows what is currently synchronized. Registry configuration (`HKCU\Software\Microsoft\OneDrive` for OneDrive) names the accounts, sync roots, and whether each is personal or business. The sync state database under `%LOCALAPPDATA%\Microsoft\OneDrive\settings\` records per-file sync history. The application logs under `%LOCALAPPDATA%\Microsoft\OneDrive\logs\` record operational detail of uploads, deletions, and errors. And NTFS metadata records creation, modification, and deletion of the synchronized files themselves. The richest single source is the sync database — a SQLite file whose tables carry file paths, item identifiers, content hashes, last-modified times, and sync states. `Data/HR-LT12/onedrive-syncdb.csv` shows that shape with `ItemPath`, `FileName`, `Size`, `ContentHash`, `LastChange`, `LastSync`, and `SyncState` columns. The logs are the corroboration layer. Their retention is short, so prompt collection matters here as it does for the USN Journal.

**8. How would you confirm or refute a "data was exfiltrated through OneDrive" hypothesis using multiple artifact sources?**

Start with the account: `HKCU\Software\Microsoft\OneDrive\Accounts` tells you which accounts were signed in and, critically, whether any of them is a personal Microsoft account rather than the corporate tenant. Then the sync database gives you the file list, timestamps, and content hashes for what was synchronized to that account. Then the OneDrive logs give operational confirmation that upload actually occurred rather than merely being queued. Then NTFS shows file creation in the sync folder, which corroborates timing and often shows the files being copied in from elsewhere on the host. Finally, browser history covers the alternate path. A clean sync database does not refute cloud exfiltration if the user uploaded through the web interface instead. The strongest version of the finding names the account, the files, the timestamps, and the upload activity. A weaker version — sync-folder file creations plus a personal account in the configuration — is still worth reporting to leadership as a hypothesis, provided it is labeled as one.

**9. Why is browser-based upload activity a separate evidence path from sync client activity?**

Because it bypasses the sync client entirely and therefore leaves none of the sync client's artifacts. Dragging a file into a webmail attachment field or uploading through a personal Dropbox or Google Drive web interface produces no entry in the OneDrive database, no sync log line, and no file in the sync folder. The evidence lives in a different place: browser history for the destination URL and the timing, plus browser cache and session data. A LNK or Jump List entry may show the file was opened from a file-picker dialog, and network telemetry may show the outbound volume. The operational consequence to internalize is that a clean sync database does not rule out cloud exfiltration. The right investigative question is not "was OneDrive used" but "did data leave, and by which of the available paths," and the two paths need different collections.

**10. What documentation should accompany a registry finding to make it defensible later?**

Per 5.4.4: the hive file and its transaction logs with hashes, the exact key path and value name, the key's last-write time, the value data as observed, the tool with version and the exact command, any decoded form of the data (ROT-13 for UserAssist, hex or Unicode decoding where relevant), and the corroborating artifacts. For a cloud finding, add the account email, the tenant identifier, and the specific database query or log search that produced the file list. "The OneDrive database showed these files" is not reproducible, and "this query against this table returned these rows" is. Record both the decoded *and* the raw forms. A reviewer needs to be able to check your decoding, and a decoded-only record hides the step where mistakes happen.

---

## Practical Exercises

**1. Export `SYSTEM`, `SOFTWARE`, `NTUSER.DAT`, and `UsrClass.dat` from your lab VM. Compute SHA-256 hashes and record them as evidence items.**

**What you should end up with:** Four hive files (plus their transaction logs), each with a recorded SHA-256, in an evidence record.

**How to get there:** These are locked files on a running system, so use FTK Imager, a triage collector, or an offline copy from a mounted image. `Copy-Item` will fail. Take `.LOG1` and `.LOG2` alongside each hive. Collecting the hive alone is the most common collection error in this chapter. Then `Get-FileHash -Algorithm SHA256` each file and record the digest, size, source path, and UTC collection time.

**What good looks like:** Expect 8 to 12 files rather than 4, because of the transaction logs. Your evidence record should list `NTUSER.DAT` per profile rather than one generic entry. On a multi-user host, "we collected NTUSER.DAT" is ambiguous about whose. Note the source path exactly, because `C:\Users\jdoe\NTUSER.DAT` and `C:\Users\Default\NTUSER.DAT` are very different artifacts.

**2. Use Registry Explorer to inspect `Run` and `RunOnce` keys in both `SOFTWARE` and `NTUSER.DAT`. Document each entry, its target executable, and the key's last-write time.**

**What you should end up with:** A table of every autorun value across all four key locations, with target path and key last-write time.

**How to get there:** Load the hive in Registry Explorer with its transaction logs present so pending changes are replayed. Navigate to `Microsoft\Windows\CurrentVersion\Run` and `RunOnce` in `SOFTWARE`, and the parallel paths in `NTUSER.DAT`. Record hive, key path, value name, value data, and the key's last-write time. `Data/HR-LT12/registry-runkeys.csv` has this exact shape (`Hive`, `KeyPath`, `ValueName`, `ValueData`, `ValueType`, `LastWriteTime`, `Notes`) if you want a populated example to compare against.

**What good looks like:** You triage each entry rather than just listing it. For every value, ask whether the target executable exists on disk, whether its path is a normal install location, whether the publisher matches the name, and whether the key's last-write time is consistent with when that software was installed. A `Run` value pointing into `AppData\Local\Temp` or `C:\ProgramData\` deserves follow-up regardless of how legitimate its name sounds. Note explicitly that the last-write time belongs to the key, not the value. The point of review question 2 becomes obvious the moment you have a key with six values and one timestamp.

**3. Plug a USB drive into your lab VM, copy a file to it, and eject it. Then examine `USBSTOR` and confirm you can identify the device by vendor, product, and serial.**

**What you should end up with:** A device identification you could put in a report: vendor, product, revision, serial number, and connection timestamps.

**How to get there:** After ejecting, re-export the `SYSTEM` hive and inspect `CurrentControlSet\Enum\USBSTOR`. The subkey names encode class, vendor, product, and revision. The child key is the device serial. Connection timestamps live under the device's `Properties\{83da6326-97a6-4088-9453-a1923f573b29}\` subkey, in values `0064`, `0066`, and `0067` (Windows 8 and later). Then cross-reference `HKLM\System\MountedDevices` for the drive letter and `HKLM\Software\Microsoft\Windows Portable Devices\Devices` for the volume label. `Data/HR-LT12/usbstor.csv` and `mountpoints.csv` show the finished form.

**What good looks like:** You end with a serial number, not just a friendly name. "SanDisk Cruzer" identifies a product line, while `4C530001120523104381` identifies a device. Watch for serials whose second character is `&`. That character indicates the device does not report a real serial number and Windows generated one. The identifier is then not portable between hosts, and any cross-host correlation on it is invalid. That caveat belongs in the finding.

**4. Decode at least five UserAssist entries in your lab `NTUSER.DAT` and confirm the program executions match your expectations from the lab activity.**

**What you should end up with:** Five decoded entries with program path, run count, and last-execution time, checked against what you actually did.

**How to get there:** Registry Explorer and RegRipper decode the ROT-13 value names automatically. To see the mechanism, decode one by hand and confirm the tool agrees. The values sit under `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`, with different GUIDs covering executables versus shortcuts.

**What good looks like:** Some of your expectations are wrong, and you can explain why. Programs you launched from a PowerShell prompt will be missing, because UserAssist only records GUI-launched executions. Noticing that absence is the real learning outcome. Run counts also often lag what you remember, because the counter updates on a schedule rather than instantly.

**5. Sign in to a OneDrive account on your lab VM (personal account is fine for testing). Examine `HKCU\Software\Microsoft\OneDrive\Accounts` and identify the account email, tenant, and sync folder path.**

**What you should end up with:** A record naming the account email, the tenant identifier (for business accounts), the user CID, and the local sync root path.

**How to get there:** Inspect `HKCU\Software\Microsoft\OneDrive\Accounts` and look at each subkey — `Personal`, `Business1`, and so on. Record the email, `UserFolder`, `UserCid`, and, for business accounts, the tenant values under `Tenants`. `Data/HR-LT12/onedrive-accounts.csv` shows the field set (`AccountId`, `Email`, `ServiceEndpointUri`, `UserFolder`, `UserCid`, `ConfiguredTenantsClient`, `LastWriteTime`).

**What good looks like:** You can answer the high-value triage question from 5.3.2 directly: which cloud accounts has this user signed into on this machine? A `Personal` subkey on a corporate device, or a business account whose tenant identifier does not match the organization's, is the finding worth flagging. Note the account key's last-write time as a rough indicator of when the account was configured or last modified.

**6. Open the OneDrive settings database in DB Browser for SQLite. Identify the table that records per-file sync state and run a query that lists the last twenty synchronized items.**

**What you should end up with:** A 20-row result set of recently synchronized files with paths and sync timestamps.

**How to get there:** The database lives at `%LOCALAPPDATA%\Microsoft\OneDrive\settings\<account>\<UserCid>SyncEngineDatabase.db`. Copy it before opening. Do not query the live file while the client is running. Browse the schema first, since table and column names vary by client version, and look for the table carrying item identifiers, paths, hashes, and sync state. Then sort descending on the last-sync column and take 20. If you would rather work with a fixed schema, `Data/HR-LT12/onedrive-syncdb.csv` is the flattened equivalent and can be queried with `python -c` and `csv.DictReader` or loaded into a spreadsheet.

**What good looks like:** You record the schema you found and the exact query you ran. The next client version may differ, and your finding needs to be reproducible against the version you had. Two columns are worth calling out. The content hash lets you tie a synchronized file to a known copy on the host. The sync state distinguishes a file that uploaded successfully from one that was merely queued or errored.

**7. Use RECmd with a published batch file to extract a standard set of IR-relevant values from a hive, and review the CSV output.**

**What you should end up with:** CSV output from a batch-driven RECmd run, reviewed rather than merely produced.

**How to get there:** RECmd ships with batch files in its `BatchExamples` folder. `Kroll_Batch.reb` is the broad one, and targeted ones cover specific artifact classes. A typical run: `RECmd.exe -d C:\Triage\HR-LT12\registry --bn BatchExamples\Kroll_Batch.reb --csv C:\Cases\HR-LT12\registry\`. Point it at a directory of collected hives rather than a single file so it processes the whole set.

**What good looks like:** You can explain what the batch file actually asked for. A batch run is only as good as its definition. Treating it as "the tool found everything" is precisely the failure the chapter warns about. Open the `.reb`, read the key list, and note which keys relevant to your case are *not* in it. Extending a batch file with one extra key you needed is the follow-on worth doing.

**8. For a chosen file you copied to OneDrive, build a one-page reconstruction that combines the OneDrive database, OneDrive logs, NTFS metadata for the sync folder, and account configuration.**

**What you should end up with:** A one-page, four-source reconstruction of a single file's journey off the host.

**How to get there:** Follow the chain in 5.4.2. Account configuration names *which account*. NTFS gives you the creation time of the file in the sync folder and, if it was copied in from elsewhere, the source location. The sync database gives you the item identifier, content hash, and sync state. The logs give you the upload event and its outcome. Lay the four out chronologically and state the conclusion once, at the top.

**What good looks like:** Each of the four sources appears explicitly, and the reconstruction states its own limits. NTFS proves the file was in the sync folder, the database proves the client tracked it, and the logs prove upload occurred. Only the cloud-side audit log proves it landed and who accessed it afterward. Appendix B covers the cloud-side half: the M365 unified audit log and OneDrive/SharePoint activity records. A host-only reconstruction should point at it rather than pretend the host tells the whole story.

**9. Document the exact tool, version, command, and source hive hash for each parse you perform.**

**What you should end up with:** A parse log with one row per parse.

**How to get there:** Same discipline as Chapter 4: tool name, version captured at run time, platform, operator, working directory, verbatim command, output path, and the SHA-256 of each source hive *and* its transaction logs as collected.

**What good looks like:** The transaction logs are hashed too. They are part of the evidence. A parser that replays them produces different values than one that does not, so the logs shape the result and belong in the integrity record. Also record whether your parser is transaction-log-aware, since that explains any discrepancy between your output and someone else's.

---

## Common mistakes on this chapter

- **Reading a key's last-write time as the timestamp of a specific value.** The key carries one timestamp and may hold a dozen values, none of which are individually timestamped. "This malicious `Run` value was written at 14:07" overstates what the registry recorded. What you can actually say is "the key was last modified at 14:07 and contains this value." Getting this wrong puts a precise-sounding and unsupportable claim into a report.
- **Collecting hives without their `.LOG1` and `.LOG2` transaction logs.** The most recent changes may exist only in the logs, so an analyst who collects the hive alone can be looking at stale values and never know it. Collect them together, keep them together, and use tooling that replays them.
- **Collecting only the logged-on user's `NTUSER.DAT`.** Per-user artifacts are per user. UserAssist, TypedPaths, RecentDocs, ComDlg32, and shellbags for every other profile on the host are separate evidence. On a shared workstation or a terminal server, the account you did not collect is often the one that matters.
- **Treating an empty UserAssist result as evidence that a program did not run.** UserAssist records GUI-launched executions only. Anything started from a command line, a script, a service, or a scheduled task is invisible to it, and that covers most attacker execution. Absence in UserAssist is close to meaningless for that population. Use Prefetch, Amcache, 4688, or Sysmon for the negative claim.
- **Concluding that a clean OneDrive database rules out cloud exfiltration.** It rules out *sync client* exfiltration. Direct browser upload to webmail or a personal cloud account leaves nothing in the sync database and everything in browser history and network telemetry. The hypothesis is "data left the host," and the sync client is only one of the paths.
- **Accepting a USB serial number at face value without checking whether it is real.** Devices that do not report a serial get a Windows-generated identifier, recognizable by an `&` in the second character position. Those identifiers are host-specific, and correlating them across machines produces a confident, wrong conclusion. That sort of error surfaces late and expensively.
- **Reporting a persistence key with no corroboration.** "There is a suspicious `Run` key" is a starting point, not a finding. The defensible version adds whether the referenced binary exists on disk, when it was created per NTFS, whether it has execution evidence in Prefetch or Amcache, and what its hash resolves to. The chapter states the standard plainly in 5.4.3, and it is the difference between a lead and a conclusion.

---

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) book series.*
