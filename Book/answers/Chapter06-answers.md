# Chapter 6 — Review Question and Exercise Answers

*Sample answers for the Review Questions and Practical Exercises at the end of [`Chapter06.md`](../Chapter06.md). These are reference answers, not the only correct answers — your wording will differ and that is fine. What matters is whether your reasoning covers the same ground. For the corresponding lab, see [`Labs/Lab06/task-answers.md`](../../Labs/Lab06/task-answers.md).*

---

## Review Questions

**1. Why does an LNK file remain useful after its target file has been deleted?**

The LNK is an independent file that captured a snapshot of the target's metadata at the moment the shortcut was created. It lives in `%APPDATA%\Microsoft\Windows\Recent\`, a completely different place from the file it points at. Inside it are the target's full path, its MAC timestamps *as they were at the time of the interaction*, its size, the volume serial number and label of the volume it sat on, the creating machine's hostname, and in some configurations the MAC address. Deleting the target changes none of that. So a LNK pointing at a path that no longer exists still establishes that the file was there, how big it was, when it was created and modified, and which volume it lived on. That last point makes LNK files decisive in removable-media cases: it is often the only surviving record that a file existed on a drive you no longer have.

**2. What does a Jump List add to the evidence already provided by LNK files?**

Per-application attribution. A LNK file in `Recent\` says a file was opened. A Jump List entry says it was opened *with a specific application*, because the Jump List file itself is named with the `AppID` of the owning program. Jump Lists also carry an access count and last-access ordering in the `DestList` stream. A standalone LNK does not, so the Jump List gives you frequency and sequence rather than a single most-recent interaction. Structurally, Jump Lists are compound files holding many embedded LNK structures, so all the target metadata is still there. In practice, the attribution turns a probable conclusion into a confirmed one. Knowing a sensitive spreadsheet was opened is useful. Knowing it was opened by Excel rather than by a script or an archiving utility is a different claim. In `Data/FIN-WS23/jump-lists.csv`, the `AppId` and `AppDescription` columns carry exactly this, alongside `LocalPath` and `VolumeSerialNumber`.

**3. Why is it important to confirm Prefetch's enablement state when investigating activity on a Windows server?**

Prefetch is disabled by default on server SKUs. An empty `%SystemRoot%\Prefetch\` directory on a server almost never means nothing executed. It means nothing was being recorded. Reporting "no execution evidence found in Prefetch" without that check produces a negative finding that nothing supports. It is the kind of error that survives into a report because it looks like diligence. The check itself is cheap: read `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher` from the collected `SYSTEM` hive. The values are 0 for disabled, 1 for application prefetching, 2 for boot, and 3 for both. The same discipline applies to workstations where an administrator or an SSD-tuning script turned it off. When Prefetch is unavailable, pivot to Amcache, UserAssist, ShimCache, 4688, or Sysmon rather than concluding anything from the silence.

**4. What kinds of investigative questions does SRUM uniquely answer?**

SRUM answers two questions that nothing else on the host answers as directly. The first is which processes used the network in a given window and how many bytes each sent and received. The second is which processes were active on a given day even when event logs do not record them. SRUM records per-process resource usage — CPU time, bytes sent and received, energy — in an ESE database at `%SystemRoot%\System32\sru\SRUDB.dat`. It updates roughly hourly and retains about 30 to 60 days. That retention window is longer than most Windows artifacts and often longer than log retention, which makes SRUM valuable when you arrive late. Its signature use case is exfiltration volume: a custom binary that never triggered an alert still leaves a SRUM row naming its executable path, its interface, and the byte counts. `Data/FIN-WS23/srum.csv` has that shape — `Timestamp`, `ApplicationName`, `UserSID`, `InterfaceLuid`, `BytesSent`, `BytesReceived`. The limitation to keep in mind is granularity: the hourly aggregation means SRUM tells you a process moved 4 GB in an hour, not the minute it started.

**5. How do shellbags continue to provide evidence when the folders themselves no longer exist?**

Shellbags are a record of the *navigation*, stored in the user's registry hives. They are not a property of the folder. When a user browses a directory in Explorer, Windows writes the folder's identity and view preferences into `BagMRU` and `Bags` under `UsrClass.dat`. That entry persists whether or not the folder still exists. Delete the folder, format the drive, unplug the device, disconnect from the share — the shellbag entry stays. That persistence makes shellbags useful for the three cases in 6.2.2. A user who browsed a sensitive directory, copied its contents, and deleted the directory still has the entry. A user who browsed a USB drive that is now gone still has entries naming each folder they visited on it. Shellbags also survive the cleanup people actually think to do. Someone who deletes files and clears browser history is very unlikely to consider clearing `UsrClass.dat`.

**6. What is the difference between UserAssist and Amcache as sources of execution evidence?**

They cover different populations and answer different questions. UserAssist is per-user and lives in `NTUSER.DAT`. It records programs launched *through the Explorer GUI*, such as from Start menu shortcuts, double-clicks, and taskbar items, with a run counter and last-execution timestamp. It is the artifact for "did this user deliberately launch this program," which matters most in insider cases. Amcache is per-machine and lives in `%SystemRoot%\AppCompat\Programs\Amcache.hve`. It catalogues binaries the system has *seen*, recording full path, SHA-1 hash, size, version metadata, and often a first-execution time. Its unique contribution is the hash, which lets you identify a binary against threat intelligence even after the file has been deleted from disk. The critical asymmetry runs both ways. UserAssist misses everything launched from a command line, a script, or a scheduled task. Amcache includes some binaries that Windows compatibility infrastructure scanned but that did not necessarily execute. Neither is a clean execution oracle on its own.

**7. When is browser history evidence most decisive in an investigation?**

When the question is about something that happened over the network through the browser and there is no other host-side record of it. Browser history can confirm or refute that a user visited a phishing page, and at what time. It can establish that a particular file was downloaded from a particular URL, which is often the initial-access link that nothing else on the host preserves. It can also demonstrate a direct upload to a personal cloud storage or webmail account. As Chapter 5 covered, that exfiltration path leaves no sync-client artifact at all. Browser history is also where user intent occasionally surfaces through search queries. A search for how to delete browser history or how to encrypt and archive files shortly before suspect activity proves nothing by itself, but it is a useful supporting observation. In `Data/FIN-WS23/browser-history.csv`, the `URL`, `VisitTime`, `TypedCount`, and `ReferrerURL` columns carry this. `TypedCount` in particular separates deliberate navigation from a redirect.

**8. A LNK file records a volume serial number and USBSTOR records a device serial number. Why can the two not be compared directly, and what chain of artifacts actually binds a shortcut to a specific physical device?**

They are different values from different layers, and neither appears in the other's artifact. The **volume serial number** is a 32-bit value the file system carries, assigned when the volume was formatted. It is what the LNK records, alongside the volume label and drive type. The **device serial number** is a string in the USB device descriptor, burned in by the manufacturer. It is what `USBSTOR` records. Neither is derived from the other, so putting `F1D2E9A4` next to `001A92053B7CBE3196B40A0F` and calling it a match is not an argument — a reviewer sees two unrelated numbers.

The binding runs through the registry in two hops. `HKLM\SYSTEM\MountedDevices` maps `\??\Volume{GUID}` and `\DosDevices\E:` entries onto the underlying device instance, which resolves to the `USBSTOR` subkey for a specific vendor, product, and serial. `HKCU\...\MountPoints2` adds the third fact you usually want: *which user account* mounted that volume. So the chain is LNK → volume serial → the volume in `MountedDevices` → the `USBSTOR` device. Separately, the volume GUID → `MountPoints2` → the user.

Done that way, the binding is strong. State each hop in the finding rather than asserting the conclusion. Two caveats belong in the write-up. First, the volume serial identifies the volume, so reformatting the device changes it and breaks the chain, which is occasionally itself a finding. Second, drive letters are recycled constantly, so `E:` on its own identifies nothing.

**9. What artifact sources together support a defensible reconstruction of files copied to a USB drive?**

The chain in 6.5.1. `USBSTOR` for vendor, product, and serial plus first and last connection times. `Enum\USB` for broader device history. `Windows Portable Devices\Devices` for the friendly-name mapping. `MountedDevices` for the volume-GUID-to-drive-letter binding. `setupapi.dev.log` for the first-installation timestamp, which is often the earliest evidence the device ever touched the host. Shellbags for which folders on the device were browsed and when. LNK files and Jump Lists for which files were opened from it, with the volume serial tying them back to the device. And the host's MFT and USN Journal for files copied *off* the device onto the host, or for the source files that were copied to it. Each element is independently useful, and none is sufficient. The reconstruction is defensible when they align in time and when the volume serial links the shell artifacts to the identified device. The host-side chain still cannot prove that a copy operation occurred rather than a file merely being opened. That inference needs the timing and the file-creation evidence to line up.

**10. Why is documentation of tool, version, and command particularly important for shell artifact analysis?**

These artifacts are undocumented binary structures whose interpretation depends entirely on the parser, and parsers disagree. Shellbag timestamp semantics vary by Windows version and entry type. Jump List `DestList` parsing has changed across tool releases. Amcache's layout differs between Windows builds, with recent versions splitting content across multiple files. LNK structures carry optional fields that some tools surface and others drop. Two analysts running different tools — or different versions of the same tool — against the same `UsrClass.dat` can legitimately produce different row counts and different timestamps. Without the tool, version, and exact command in the record, a discrepancy is unresolvable and looks like an error by one of the analysts. Add the source artifact hash and you can at least prove you were both parsing the same bytes. This is also the chapter where the temptation to skip documentation is highest, because the tools are fast and the output looks self-explanatory.

---

## Practical Exercises

**1. From your lab VM, copy the contents of `%APPDATA%\Microsoft\Windows\Recent\` and parse the LNK files with LECmd. Identify at least three target files and their volume serial numbers.**

**What you should end up with:** Parsed LNK output with at least three resolved target paths and their volume serials.

**How to get there:** Copy the `Recent\` directory out, then `LECmd.exe -d C:\Triage\LAB-VM\Recent --csv C:\Cases\LAB-VM\lnk\`. Review the resolved `LocalPath`, `TargetCreated`/`TargetModified`/`TargetAccessed`, `VolumeSerialNumber`, `VolumeLabel`, and `DriveType`. `Data/FIN-WS23/lnk-files.csv` carries the same column set if you want a populated reference.

**What good looks like:** You notice that the target timestamps in the LNK differ from the current timestamps of the files on disk, because the LNK preserved the state at the moment of interaction. Also check `DriveType`. A value indicating removable media on a LNK whose volume serial you do not recognize is the thread worth pulling. If every target resolves to `C:` with the same serial, create a shortcut to a file on a USB drive and re-parse so you have seen the contrast.

**2. Parse the Jump Lists in `Recent\AutomaticDestinations\` with JLECmd. For one application, list the files it has recently opened and the timestamps.**

**What you should end up with:** A per-application list of recently opened files with access timestamps and ordering.

**How to get there:** `JLECmd.exe -d C:\Triage\LAB-VM\Recent\AutomaticDestinations --csv C:\Cases\LAB-VM\jumplists\`. Each source file is named with an `AppID`. JLECmd resolves many known AppIDs to application names automatically, and you can look up unresolved ones against published AppID lists. Pick one application and read its `DestList` entries in order.

**What good looks like:** You can state which application opened which file, in what order, and how recently — and you understand that the ordering comes from the `DestList` stream rather than from file timestamps. An unresolved AppID is worth chasing rather than ignoring. An unknown application with a Jump List full of sensitive documents is a finding, and the AppID is how you identify it.

**3. Run a simple PowerShell script on your lab VM, then parse the corresponding Prefetch file with PECmd. Identify the referenced files and the run count.**

**What you should end up with:** Parsed Prefetch output for `powershell.exe` showing run count, last-run times, and the referenced-file list.

**How to get there:** Run the script, wait a couple of minutes for Prefetch to flush, then `PECmd.exe -d C:\Windows\Prefetch --csv C:\Cases\LAB-VM\prefetch\`. Use `-d` with the `--csv` and the `_Timeline` output. PECmd also has a mode that lists referenced files per executable, which is the half of the exercise that matters. `Data/FIN-WS23/prefetch.csv` shows the summary columns (`RunCount`, `LastRun`, `PreviousRun0-2`, `FilesCount`, `VolumeSerialNumber`).

**What good looks like:** Your script's path appears in `powershell.exe`'s referenced-file list. That is the point of the exercise. Prefetch records what the executable touched at startup, so it frequently names attacker input files, working directories, and modules that have since been deleted. Note also that Windows 8 and later retain up to eight execution timestamps, not just the most recent, so a single `.pf` can establish a pattern of use rather than a single event.

**4. Confirm whether Prefetch is enabled on your lab VM by checking the relevant registry value, and document the result.**

**What you should end up with:** The value of `EnablePrefetcher` and a written statement of what it implies for your analysis.

**How to get there:** Read `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher` — from the collected `SYSTEM` hive for a real case, or with `Get-ItemProperty` on the live lab VM. Values: 0 disabled, 1 application prefetching, 2 boot prefetching, 3 both.

**What good looks like:** You write down what the value means for the negative case, not just the positive one. "EnablePrefetcher = 3, so application prefetching was active and an absent `.pf` for a given executable is meaningful" is the useful form. If you have access to a Windows Server instance, check it there too and see the default difference for yourself. Reading about it and observing it land differently.

**5. Open `SRUDB.dat` from your lab system with srum-dump and identify a process with non-trivial network usage in the last hour.**

**What you should end up with:** A named process with byte counts for a specific hour and interface.

**How to get there:** Copy `%SystemRoot%\System32\sru\SRUDB.dat` along with the transaction logs in the same directory. The database is in use on a running system, and the logs carry recent state. Run it through srum-dump or `srum_dump.py`, which produce spreadsheet or CSV output. The network usage table is the one to sort by `BytesSent`. `Data/FIN-WS23/srum.csv` is the flattened equivalent and can be sorted directly.

**What good looks like:** You can name the executable, the user SID it ran under, the hour, and the byte counts in each direction. Expect the top talkers on a lab VM to be the browser and Windows Update. That is the correct baseline lesson. SRUM's value in a real case comes from spotting a process that has no business moving that volume, and you need to know what normal looks like first. Note the hourly granularity explicitly in whatever you write.

**6. Browse into a folder on a USB drive in your lab VM, then unplug the drive. Parse the shellbags from your `UsrClass.dat` and confirm the folder is recorded.**

**What you should end up with:** A shellbag entry naming a folder on a device that is no longer attached.

**How to get there:** Browse a few levels deep on the drive so you generate several entries, then eject it. Log off or otherwise flush the hive, export `UsrClass.dat` with its transaction logs, and run `SBECmd.exe -d C:\Triage\LAB-VM\registry --csv C:\Cases\LAB-VM\shellbags\`. Look for the drive letter path in the `AbsolutePath` column. `Data/FIN-WS23/shellbags.csv` and `Data/HR-LT12/shellbags.csv` show the output shape (`BagPath`, `AbsolutePath`, `ShellType`, `FirstInteracted`, `LastInteracted`, `MRUPosition`, `NodeSlot`).

**What good looks like:** The entry is there with the device gone, which is the whole demonstration. Pay attention to the two timestamp columns and to what they actually mean. `FirstInteracted` and `LastInteracted` are not always what intuition suggests, and 6.2.3 is explicit that shellbag timestamp semantics vary by Windows version and entry type. Writing down that ambiguity is part of doing this correctly. A finding that asserts a precise navigation time from a shellbag alone is overstating the artifact.

**7. Decode at least five UserAssist entries from your lab `NTUSER.DAT` and confirm the program executions match your expectations.**

**What you should end up with:** Five decoded entries with program identifier, run count, and last-execution time.

**How to get there:** Registry Explorer, RegRipper, or RECmd decodes the ROT-13 names automatically from `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`. Decode one by hand as a sanity check on the tool. `Data/FIN-WS23/userassist.csv` shows the parsed shape (`ProgramName`, `RunCounter`, `FocusCount`, `FocusTime`, `LastExecuted`).

**What good looks like:** Some expected programs are missing and you can say why. Anything you launched from a PowerShell prompt, a script, or a scheduled task will not be there, because UserAssist records GUI launches only. That absence is the most important thing this exercise teaches, and it is the reason UserAssist can never carry a negative execution finding on its own.

**8. Parse Amcache with AmcacheParser and identify the SHA-1 hash for a chosen binary. Look the hash up in a public sample database (e.g., VirusTotal) to confirm identification.**

**What you should end up with:** A SHA-1 from Amcache and a lookup result for it.

**How to get there:** `AmcacheParser.exe -f C:\Triage\LAB-VM\Amcache.hve --csv C:\Cases\LAB-VM\amcache\ -i` (the `-i` includes file entries). Pick a binary and take its SHA-1. Look it up. `Data/FIN-WS23/amcache.csv` carries both `Sha1` and `Sha256` alongside `FullPath`, `Publisher`, and `Compiled` if you want to practice the workflow without a live host.

**What good looks like:** You treat the lookup as identification, not adjudication. A clean result on a public database means the sample is unknown to that database, not that the binary is benign — plenty of bespoke tooling has never been submitted. Real casework also carries an operational-security consideration. Submitting a *file* to a public service can tip off an attacker who is monitoring for it, whereas submitting a *hash* is much lower risk. Hash lookups are the safe default, and file submissions should be a deliberate, authorized decision.

**9. Build a one-page profile of a removable device used in your lab — vendor, product, serial, drive letter at last connection, browsed folders, opened files — using at least four artifact sources.**

**What you should end up with:** A device profile in the shape of 6.5.2 and 6.5.3.

**How to get there:** Pull vendor, product, serial, and connection timestamps from `USBSTOR`. Pull the drive letter from `MountedDevices` and the portable-devices key. Pull first-installation time from `setupapi.dev.log`. Pull browsed folders from shellbags. Pull opened files and volume serials from LNK files and Jump Lists. Pull any files copied to the host from the MFT and USN Journal. `Data/HR-LT12/` supports this end to end with `usbstor.csv`, `mountpoints.csv`, `setupapi-dev-log.txt`, and `shellbags.csv`, and `Data/FIN-WS23/` adds the LNK and Jump List side.

**What good looks like:** The volume serial in the LNK entries resolves, through `MountedDevices`, to the device you identified in `USBSTOR`. You write out both hops rather than asserting a serial-to-serial match, because that chain is the load-bearing link in the whole profile. The page should also be honest about what it does not establish: host-side artifacts show a device was attached, folders were browsed, and files were opened, and only rarely prove that a copy operation occurred. State the inference and label it as one.

**10. Document the exact tool, version, command, and source artifact hash for each parse you perform during these exercises.**

**What you should end up with:** A parse log covering every LECmd, JLECmd, PECmd, SBECmd, AmcacheParser, and srum-dump run.

**How to get there:** One row per parse: tool, version captured at run time, operator, UTC time, working directory, verbatim command, output path, and SHA-256 of the source artifact — the `Recent\` collection, the `UsrClass.dat` and its logs, `Amcache.hve`, `SRUDB.dat` and its logs, the Prefetch directory.

**What good looks like:** The log lets someone reproduce every CSV in your case folder. For this chapter especially, the version field is the one that earns its keep. The Eric Zimmerman tools iterate frequently and shell artifact parsing changes with them, so "SBECmd 2.0" and "SBECmd 1.5" can legitimately produce different results against identical bytes.

---

## Common mistakes on this chapter

- **Reading Amcache as proof of execution.** Amcache records binaries the system has *seen*, which includes files enumerated by Windows compatibility infrastructure that never ran. Its unique value is the SHA-1 that identifies a binary after deletion, not an execution assertion. The same caution applies to ShimCache, the artifact adjacent to it in Figure 6.1: presence means the binary was known to the system, and only Prefetch, 4688, Sysmon EID 1, or a UserAssist counter turns that into "it ran."
- **Concluding "nothing executed" from an empty Prefetch directory on a server.** Prefetch is off by default on server SKUs. It is one of the most consistently surprising facts in Windows IR, and it produces confidently wrong negative findings. Check `EnablePrefetcher` before drawing any conclusion from Prefetch's silence, on servers and on tuned workstations alike.
- **Treating shellbag timestamps as precise navigation times.** The recorded time may reflect first navigation, last navigation, or a related view event depending on Windows version and entry type. Shellbags are excellent at establishing *that* a folder was browsed and weak at establishing exactly when. Report the ambiguity rather than picking the interpretation that suits the theory.
- **Matching a drive letter instead of a volume serial.** `E:` identifies nothing — every removable device the host has ever seen has probably been `E:` at some point. The volume serial in the LNK file is the identifier that binds a shortcut to a specific physical volume. A device profile built on drive letters alone falls apart the moment a second device enters the picture.
- **Collecting only the current user's shell artifacts.** LNK files, Jump Lists, UserAssist, and shellbags are all per-user and live under individual profiles. On a shared workstation, a jump host, or a terminal server, the profile you skipped is frequently the one holding the evidence.
- **Treating a clean VirusTotal result as exoneration.** An unknown hash means the sample has not been submitted, which is common for bespoke tooling and says nothing about intent. In a live engagement, uploading the file rather than the hash can alert an attacker who is watching for their sample to appear. Look up hashes first, and submit the file only as a deliberate and authorized step.
- **Presenting a single artifact as the finding.** The unifying theme of the chapter is redundancy: these artifacts tell overlapping versions of the same story, and the strength comes from the overlap. A LNK file alone is a lead. A LNK file whose volume serial matches an identified USBSTOR device, plus shellbags for the folder, plus a matching MFT creation on the host, is a conclusion.

---

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) book series.*
