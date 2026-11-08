# Chapter 9 — Review Question and Exercise Answers

*Sample answers for the Review Questions and Practical Exercises at the end of [`Chapter09.md`](../Chapter09.md). These are reference answers, not the only correct answers — your wording will differ and that is fine. What matters is whether your reasoning covers the same ground. For the corresponding lab, see [`Labs/Lab09/task-answers.md`](../../Labs/Lab09/task-answers.md).*

---

## Review Questions

**1. Why is `Security.evtx` so often the first log clearing target during an attack?**

Because it holds the attacker's own tracks. `Security.evtx` records authentication (4624, 4625, 4648), privilege assignment (4672), process creation with parent and command line (4688), service installation (4697), scheduled task creation (4698), and account manipulation (4720, 4738). Nearly every step of a typical intrusion — the initial logon, the credential reuse, the tool execution, the persistence — leaves a record there, and nowhere else records it with the same fidelity. Clearing it is also easy: a single `wevtutil cl Security` or the equivalent API call from an administrator context does it. Clearing generates EID 1102 in the newly empty log, though, so the act of hiding is itself recorded. A `Security.evtx` whose oldest entry is timestamped in the middle of the incident day, with 1102 near the start, tells you a great deal even though its prior contents are gone.

**2. What is the difference between EID 4624 LogonType 3 and LogonType 10, and what does each suggest?**

LogonType 3 is a network logon. The account authenticated to this host from another machine over the network, typically for SMB file share access, remote WMI, or a service connection. Windows creates no interactive session and loads no desktop. LogonType 10 is RemoteInteractive, meaning RDP: a full interactive session with a desktop, initiated remotely. The investigative implications differ sharply. Type 3 events are very common and mostly benign background, so what matters is the combination of source address and account. An unexpected pairing suggests lateral movement over SMB. Type 10 is far less common on a typical workstation, and an inbound RDP session to a user endpoint from a non-administrative source is a much stronger signal on its own. Type 10 also means the attacker had a graphical session, which changes the shell and browser artifacts you should expect to find.

**3. Why is EID 4688's command-line field often missing in default Windows configurations?**

Two settings control it, and both are off by default. Process creation auditing itself must be enabled. Even when it is, the `CommandLine` field requires a separate policy setting: `Include command line in process creation events` under Administrative Templates → System → Audit Process Creation. Microsoft made command-line inclusion opt-in partly because command lines routinely contain sensitive data, such as passwords passed as arguments, connection strings, and tokens. That data then sits in a log many accounts can read. On unprepared hosts, you get 4688 events naming the executable and parent but not the arguments. The arguments are exactly what distinguishes a legitimate `powershell.exe` from a malicious one. Confirming the setting with `auditpol /get /category:*` before drawing conclusions is what separates "the process ran with no arguments" from "we do not record arguments."

**4. What does PowerShell EID 4104 record, and why is its presence or absence so consequential?**

EID 4104 is Script Block Logging. It records the text of every PowerShell script block that runs, including the deobfuscated, post-decode content. An `-EncodedCommand` base64 blob appears in 4104 as the decoded script it expands to. An obfuscated string concatenation appears as the resolved command, and an in-memory download cradle appears in full. It is the closest thing Windows offers to a recording of what the attacker typed. Its absence matters just as much. The policy is off by default, so on an unprepared host these events do not exist, and the gap says nothing about whether PowerShell ran. That makes it one of the most common and most misread log gaps in IR. Confirming the policy state is how you tell "no malicious PowerShell ran" from "we would not have recorded it if it had."

**5. What are the practical implications of default 20 MB log sizes on busy systems?**

Windows event logs are circular buffers, so once the file reaches its maximum size, Windows overwrites the oldest entries. At the default 20 MB, a busy enterprise-audited host may hold only hours of `Security` events, and a domain controller can roll over in minutes. Incidents are usually detected days or weeks after initial access, so the entries covering the intrusion are often gone before triage begins. Three consequences follow. First, on every in-scope host, export the logs before anything else, then raise retention with `wevtutil sl Security /ms:1073741824` so nothing further rolls off. The order matters because `wevtutil sl` writes to the evidence host (§9.2.2). Second, look elsewhere for the rolled-off window: SIEM-forwarded copies, domain controller logs, quieter channels, and Volume Shadow Copies containing older `.evtx` files. Low-volume channels such as Defender Operational retain much longer. Third, state the retention conditions in the finding, because a live log covering only four days cannot support a claim about a 19-day dwell period.

**6. How can a responder distinguish a log gap caused by configuration from a gap caused by clearing?**

Look at the shape of the gap and at the corroborating signals. A clearing gap is abrupt in time. The log's oldest record starts suddenly at a specific moment, usually with EID 1102 (Security cleared) or EID 104 (other log cleared) near the beginning. The record count is small relative to the host's activity level. A configuration gap is selective in kind, not time. The log spans a normal period and volume, but one *category* of event is entirely absent: no 4688s at all, or 4688s with no command lines, or no 4104s despite other evidence that PowerShell ran. Confirm with `auditpol /get /category:*` for the audit policy and the relevant Group Policy or registry keys for PowerShell logging. Also check System EID 6005/6006 for Event Log service stop and start, which can indicate someone deliberately halted the service. Where both exist, compare against SIEM-forwarded copies. The forwarded copy often still has what the local log lost.

**7. Why are saved filters and a hunt pack a higher-leverage investment than ad-hoc browsing?**

Because event log volume defeats browsing. Even a quiet enterprise host produces tens of thousands of Security events a day, and a busy server produces millions. Scrolling Event Viewer in the hope that something looks wrong is not a method. A hunt pack encodes the small set of filters that catch a high proportion of incidents, so the analysis starts from a reviewable result set instead of a haystack. The set covers repeated 4625 from a single source, 4624 Type 10 from unexpected addresses, 4624 followed by 4672 for non-admin accounts, 4648 outbound from workstations, 7045 with non-standard image paths, 4698 with unusual task paths, 4104 containing `IEX`/`DownloadString`/`FromBase64String`, and 1102/104. The value compounds across the team. The pack records the expected baseline noise level and known false positives for each filter, so the third analyst to use it does not rediscover what the first two learned. It also makes coverage gaps visible, since a filter that never returns anything on a host usually means the host is not generating those events at all.

**8. How do EvtxECmd and `Get-WinEvent` differ in typical use?**

The practical split is `Get-WinEvent` for a quick question on a live host, EvtxECmd for parsing a collection into an analysis-ready form. `Get-WinEvent` is the native PowerShell interface, available on any Windows host with no installation. It is the right tool for ad-hoc queries against a live system or a single `.evtx` file. `-FilterHashtable` pushes the filter into the log service, which makes it reasonably fast. Pulling specific fields, though, means indexing into the `Properties` array by position, which is fiddly and brittle across event types. EvtxECmd is a purpose-built offline parser. Point it at a directory of `.evtx` files and it produces normalized CSV across every channel, with named fields resolved through per-event maps, ready to filter, join, and merge into a timeline. It is the better choice for a collected triage bundle, for cross-channel correlation, and for anything that feeds a timeline.

**9. What artifact sources best corroborate a Security log EID 4688 event?**

Prefetch is the natural pair. It confirms the executable ran, gives a run count, and records referenced files, which corroborates the 4688 timestamp from an independent subsystem. Amcache adds the binary's SHA-1, which turns "a file named `update.exe` ran" into an identity you can submit to threat intel and match across hosts. MFT and USN Journal establish when the binary appeared on disk and whether it was later deleted. The create-execute-delete cycle is a strong pattern when all three timestamps line up. SRUM adds per-process resource and network usage, tying execution to data movement. Registry `Run` keys or `Services` entries show whether the process was configured to persist. Memory, if captured, shows the process's live state, sockets, and injected regions. The 4688 event is the anchor. Each additional source makes the finding harder to dispute and covers the case where the log was cleared.

**10. What documentation should accompany a log-based finding to make it defensible?**

Six things, per §9.3.5. The source — which log file or SIEM index, from which host, collected when and how. The retention conditions of that source, so the reader knows whether the window you queried was fully covered. The audit policy state at the time of the event, where the event type depends on non-default configuration. The exact query or filter used, verbatim, so anyone can re-run it. The corroborating artifacts that support the conclusion. And the known gaps, such as cleared logs, disabled auditing, or absent forwarding, together with what those gaps prevent you from concluding. That last item most distinguishes a strong finding from a weak one. A finding that names its own limits is more credible than one that claims to have none, and it protects you when opposing review looks for the thing you did not mention.

---

## Practical Exercises

**1. Export `Security.evtx`, `System.evtx`, and the PowerShell operational log from your lab VM. Compute SHA-256 hashes and record them as evidence items.**

**What you should end up with:** Three exported `.evtx` files with recorded SHA-256 digests, export method, source paths, and export time in UTC.

**How to get there:** Either copy from `%SystemRoot%\System32\winevt\Logs\` or export with `wevtutil epl Security C:\Triage\Security.evtx`. The PowerShell operational log is `Microsoft-Windows-PowerShell%4Operational.evtx`. Hash with `Get-FileHash -Algorithm SHA256`. The live log is in use, so a plain copy may fail. `wevtutil epl` or a VSS-based copy handles that.

**What good looks like:** The evidence record names the method used, because `wevtutil epl` and a raw file copy are not identical operations, and a reviewer may care which you did. Before exporting, note the current log size and the oldest record's timestamp. That pair tells you how much history the file contains, which is the retention statement your later findings will need.

**2. Use EvtxECmd to convert one log to CSV. Filter by event ID and extract the most recent ten EID 4624 events.**

**What you should end up with:** A CSV of parsed events plus a ten-row extract of the most recent successful logons with time, account, logon type, and source address.

**How to get there:** `EvtxECmd.exe -f C:\Triage\Security.evtx --csv C:\Cases\LABVM\evtx\`, then filter. In PowerShell: `Import-Csv .\*_Security.csv | Where-Object {$_.EventId -eq 4624} | Sort-Object TimeCreated -Descending | Select-Object -First 10`. You can work the same shape against [`Data/WKSTN-221/security-evtx.csv`](../../Data/WKSTN-221/security-evtx.csv), which is already in EvtxECmd-style form. It contains the `08:43:17` normal-day logon, the `14:31:05` Type 3 network logon from `10.0.4.17`, and the `14:33:18` EID 4648 explicit credential use to FILESVR-03.

**What good looks like:** Your extract includes the logon type column, not just account and time, because type is what makes a 4624 interpretable. On the WKSTN-221 data, you should be able to distinguish the routine morning interactive logon from the type 3 network logon that arrives during the incident window. You should also be able to explain why the second is more interesting than the first.

**3. Use `Get-WinEvent` to query for any EID 1102 events in your lab VM's `Security.evtx`. Document any results and what they imply.**

**What you should end up with:** Either a set of 1102 records with times and the account that performed the clearing, or a documented negative result.

**How to get there:** `Get-WinEvent -Path C:\Triage\Security.evtx -FilterHashtable @{Id=1102} -ErrorAction SilentlyContinue`. The cmdlet throws when nothing matches, which is why the error action matters. Also check the oldest record in the log and compare it to the host's uptime and install date.

**What good looks like:** You document a negative result as a negative result, with the supporting reasoning: no 1102 present, and the log's oldest record is consistent with normal rollover at the configured size rather than with a sudden truncation. To see a 1102, deliberately clear the log on a scratch VM. When you find one, note that the event records the subject account and time, but the prior content is not recoverable from the live log. Volume Shadow Copies or SIEM-forwarded copies are the next places to look.

**4. Confirm whether process command-line auditing is enabled on your lab VM (`auditpol /get /category:* | findstr "Process Creation"`). Enable it if not and verify with a test process launch.**

**What you should end up with:** The before and after audit policy state, the policy path you changed, and a 4688 event containing a populated `CommandLine` field.

**How to get there:** Run the `auditpol` check. Enable process creation auditing with `auditpol /set /subcategory:"Process Creation" /success:enable`. Separately, enable command-line inclusion via `Computer Configuration → Administrative Templates → System → Audit Process Creation → Include command line in process creation events`, or the registry value `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`. Launch something with distinctive arguments and find the resulting 4688.

**What good looks like:** You observe both states, a 4688 without a command line and then a 4688 with one, because seeing the difference makes the gap recognizable in a real case. Note in your write-up that these are two separate settings. That is the detail most often missed when someone enables process auditing and then wonders why arguments are still absent.

**5. Confirm whether PowerShell Script Block Logging is enabled. Enable it via Group Policy or registry and run a test PowerShell command. Verify the resulting EID 4104 event.**

**What you should end up with:** The policy state before and after, and at least one 4104 event whose message body contains the text of the script block you ran.

**How to get there:** Check `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging`. Enable via `Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging`. Then run something distinctive and query `Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -FilterHashtable @{Id=4104}`.

**What good looks like:** The real payoff is testing the deobfuscation property. Run a command through `-EncodedCommand` with a base64 blob and confirm that the 4104 event contains the *decoded* script, not the base64. That property is what makes 4104 so valuable, and it is worth seeing with your own eyes. [`Data/WKSTN-221/powershell-evtx.csv`](../../Data/WKSTN-221/powershell-evtx.csv) contains the scenario's 4104 entries for comparison.

**6. Build a saved filter or PowerShell function that identifies repeated EID 4625 events from a single source IP within a sliding window.**

**What you should end up with:** A reusable function taking a log path, a threshold, and a window length, returning source IPs and accounts that exceed the threshold.

**How to get there:** Parse with EvtxECmd or `Get-WinEvent`, extract the source network address and target account, then group and count within a rolling window. A workable approach is to bucket by source IP, sort each bucket by time, and slide a window comparing the first and last timestamp against your threshold count. Keep the threshold and window as parameters rather than hard-coding them.

**What good looks like:** The function documents its expected false positives. A user with a stale cached credential on a phone or a mapped drive generates repeated 4625s from one address all day, and a service account with an expired password does the same from a server. A filter that fires on those without comment will be ignored within a week. The output becomes materially more useful when it distinguishes *many failures against one account from one source* (password guessing) from *one failure against many accounts from one source* (spraying).

**7. Build a saved filter for EID 7045 events with image paths outside `%SystemRoot%\System32` and `%ProgramFiles%`.**

**What you should end up with:** A filter over `System.evtx` returning service installations whose `ImagePath` falls outside the standard directories, with service name, image path, service type, start type, and account.

**How to get there:** Parse `System.evtx` with EvtxECmd, filter to EID 7045, then exclude image paths matching the standard prefixes. Test against [`Data/WKSTN-221/system-evtx.csv`](../../Data/WKSTN-221/system-evtx.csv). Its only 7045 is the `npcap` kernel driver at 2024-11-14 02:14:18 UTC, with `ServiceFileName=\??\C:\Windows\System32\drivers\npcap.sys`, so a correct filter returns nothing. The `\??\` prefix is worth noticing, because a plain prefix match on `C:\Windows\System32` misses it and flags the driver. The chapter's HR-LT12 example, `HpHotkeyMonitor`, is an HKCU `Run` value, not a service, so it never produces a 7045. Its image path, `C:\Users\hr-user\AppData\Local\hp-hotkey\hpkey.exe`, is still the kind of user-writable location this filter exists to catch.

**What good looks like:** The filter surfaces user-profile paths, `C:\Windows\Temp\`, `C:\ProgramData\`, and `C:\Users\Public\`, the staging directories that account for most malicious service installs. It also outputs the start type, since `Start=2` (Automatic) means the service survives a reboot, which materially raises the priority. Your notes should record the legitimate third-party services in your environment that the filter also catches. That baseline is what makes the filter usable rather than noisy.

**8. Build a saved filter for EID 4104 events containing strings like `IEX`, `DownloadString`, or `FromBase64String`.**

**What you should end up with:** A filter over the PowerShell operational log matching a maintained list of tradecraft indicators, returning time, the matched indicator, and the script block text.

**How to get there:** Filter to EID 4104 and regex the message body. A reasonable starting list: `IEX`, `Invoke-Expression`, `DownloadString`, `DownloadFile`, `FromBase64String`, `-EncodedCommand`, `-nop`, `-w hidden`, `-ep bypass`, `New-Object Net.WebClient`, `Invoke-WebRequest`, `Reflection.Assembly::Load`, `VirtualAlloc`. Test against [`Data/WKSTN-221/powershell-evtx.csv`](../../Data/WKSTN-221/powershell-evtx.csv).

**What good looks like:** The filter is a list you can extend rather than a single hard-coded pattern. Each indicator has a note on its false positive profile, because legitimate installers and configuration management tooling use `DownloadString` and `FromBase64String` routinely. For extra credit, add a second-pass scoring rule. A script block matching three or more indicators is far more interesting than one matching a single term, and expressing that in the filter cuts review time substantially.

**9. For a chosen log entry, build a corroboration table listing the entry, the EID, the supporting NTFS, Prefetch, registry, and memory evidence, and the timestamp alignment across sources.**

**What you should end up with:** A table with one row per corroborating source: source, artifact, timestamp, what it establishes, and how it aligns with the anchor event.

**How to get there:** Use the WKSTN-221 `update.exe` chain, which corroborates cleanly across the shipped data. `security-evtx.csv` has EID 4688 at `14:21:03`, and `prefetch.csv` shows first execution with run count 1 at the same time. `mft.csv` and `usn-journal.csv` show creation in `Temp\` at `14:20:11` and deletion at `14:23:44`. `amcache.csv` gives the SHA-1, `srum.csv` the process's outbound bytes, and `network-flow.csv` the `14:21:55` transfer to `91.214.47.22`.

**What good looks like:** The timestamp alignment column does real work. It should show a coherent sequence rather than repeating the same time in every row: created, then executed 52 seconds later, then transferring data, then deleted. Note any source that disagrees and explain why. Small differences between file-system timestamps and log timestamps are normal, and knowing which differences are normal is part of the skill.

**10. Document one full finding using the structure recommended in 9.3.5: source, retention, audit policy state, query used, corroboration, and limits.**

**What you should end up with:** A one-page finding with all six elements filled in, not just the conclusion.

**How to get there:** Take the finding from Exercise 9 and write it up properly. Source: which log file, from which host, collected when and how, with hash. Retention: the log's configured size, its oldest record, and whether the window of interest is fully covered. Audit policy: whether command-line auditing and script block logging were enabled at the time. Query: the exact filter, verbatim. Corroboration: the table from Exercise 9. Limits: what the evidence does not establish.

**What good looks like:** The limits section is specific rather than boilerplate. For the WKSTN-221 chain, the evidence establishes that a binary named `update.exe` was created, executed, transferred data to an external address, and was deleted, all attributed to the `payroll-admin` session. It does not establish who was at the keyboard, what the transferred data contained, or whether the same tooling reached other hosts. Naming those three gaps makes the rest of the finding more credible, not less.

---

## Common mistakes on this chapter

- **Reading an absent event as proof the activity did not happen.** This is the single most common event-log error. No 4104 events does not mean no malicious PowerShell, because Script Block Logging is off by default. No command line on a 4688 does not mean the process ran without arguments, because command-line inclusion is a separate, non-default setting. Before any conclusion that rests on absence, confirm the audit policy with `auditpol /get /category:*` and the relevant Group Policy state. "The event type was not being generated on this host" and "the activity did not occur" are entirely different findings.

- **Skipping the retention check, then anchoring a finding to a log that cannot cover the window.** A live `Security.evtx` at the 20 MB default may hold only hours on a busy host. Claiming an intrusion started on a given date because that is the oldest entry in the log is a circular argument. The oldest entry is where rollover happened, not where the incident began. Check the oldest record against the log size on first contact. Export the logs, then raise retention with `wevtutil sl`. Then look for the rolled-off window in the SIEM, the domain controller logs, quieter channels, and shadow copies.

- **Quoting an event ID without its qualifying fields.** "There was a 4624" is nearly meaningless. A 4624 needs at minimum the logon type, the target account, and the source network address before it means anything. Type 3 from a file server is background. Type 10 from an unexpected external address at 03:00 is an incident. The same applies to 4688 without a parent process, and 7045 without the image path and start type. The event ID identifies the record class, and the fields carry the finding.

- **Browsing Event Viewer instead of parsing to CSV.** Scrolling a busy Security log in the GUI feels like analysis and produces almost nothing. It also cannot join across channels, which is where most of the value is. A 4688 next to a 7045 next to a 4104 in one time-sorted view tells a story that three separate GUI sessions do not. Parse the whole collection with EvtxECmd once, then filter, join, and timeline from the CSV.

- **Treating EID 1102 as the only tampering signal.** Skilled attackers may stop the Event Log service instead of clearing it, which shows up as System 6005/6006. They may also filter selectively, or operate on a host where nobody enabled the useful auditing. Corroborate the log record against sources that do not depend on it: Prefetch, MFT and USN Journal, Amcache, registry last-write times, and SIEM-forwarded copies. An investigation that collapses when the logs are cleared was over-dependent on them to begin with.

- **Building filters without documenting their baseline noise.** A hunt-pack filter with no notes on expected false positives is a filter the next analyst will disable. Repeated 4625s from one address are usually a stale cached credential. Services outside `System32` are usually legitimate third-party software. Record what the filter normally catches in your environment, and why that is fine. That record is what lets the filter survive contact with production.
