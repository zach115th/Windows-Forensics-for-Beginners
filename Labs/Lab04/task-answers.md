# Lab 04 — Task Answer Key

*Sample answers for the workbook-style Tasks 1–8 in `Labs/Lab04/ReadMe.md`. These are reference answers, not the only correct answers. Your wording may legitimately differ. The reasoning matters more than the prose. For the Hands-On Walkthrough at the end of the lab, see `walkthrough-answers.md` in the same folder.*

---

## Task 1 — Identify Suspicious File Locations

**Part A — sample populated table (additions beyond the six provided rows):**

| Location or Path | Why It Matters | Example Suspicious Use |
|---|---|---|
| `C:\Users\<user>\Downloads\` | (provided) | (provided) |
| `C:\Temp\` | (provided) | (provided) |
| `C:\ProgramData\` | (provided) | (provided) |
| `C:\Users\<user>\AppData\Local\Temp\` | (provided) | (provided) |
| `C:\Users\Public\` | (provided) | (provided) |
| `C:\Windows\Temp\` | (provided) | (provided) |
| `C:\Users\<user>\AppData\Roaming\` | Writable by user. Commonly used by legitimate apps, so attacker payloads blend in | Persistence binary dropped in a fake vendor subfolder (`\AppData\Roaming\Microsoft\Office\` style) |
| `C:\PerfLogs\` | Default-existing directory most users have never opened. Rarely scanned | Staging directory for exfil archives; tool drop point |
| `C:\Windows\Tasks\` (and `C:\Windows\System32\Tasks\`) | Scheduled task XML definitions live here. Attacker persistence often touches them | Malicious scheduled task XML with payload path, renamed to mimic a legitimate Microsoft task |
| `C:\Users\<user>\AppData\Local\Microsoft\Windows\INetCache\` | Browser-cached content the user never sees. High churn means low scrutiny | Downloader writes second-stage binary masquerading as `.tmp` |
| `C:\$Recycle.Bin\` per-SID subfolders | Files moved here retain content until permanent deletion. Some attackers use it as a hiding spot | Attacker tool moved to Recycle Bin to remove from "live" file listings while still executable |
| Alternate Data Streams (`file.ext:hidden`) | NTFS ADS aren't visible to most tools or shell listings | Payload hidden in an ADS on an otherwise benign file (`readme.txt:payload.exe`) |

**Part B — short answers:**

**1. Why do attackers avoid obviously named malware folders, and what does that mean for your analysis?**

Attackers know that defenders search for known-bad strings such as `malware`, `hack`, `tool`, or the name of the framework they're using, so they avoid those names. Instead they pick paths that look like normal Windows activity: `\Temp\update.exe`, `\AppData\Local\Microsoft\Windows\Caches\`, and names that mimic real Windows services. For analysis, string-matching on bad names is the lowest-yield search you can run. The higher-yield analysis looks for an *unusual file in a usual-looking path*: a `.exe` in a folder that should only contain `.tmp` files, a file that doesn't match the publisher of its enclosing directory, or a creation time outside the normal activity pattern for that path. The WKSTN-221 scenario is the canonical example. `update.exe` in `\Temp\` is a benign-looking name in a benign-looking path that turns out to be the dropper rename.

**2. Why can a "normal-looking" file path still be suspicious in context? Give a specific example.**

Context is the difference between routine and suspect. `C:\Users\jdoe\AppData\Local\Temp\update.exe` is unremarkable in isolation, because Temp folders contain `.exe` files all the time during legitimate installations. The same file is highly suspicious if (a) it was created at 14:20 UTC on a host whose user wasn't actively installing anything, (b) it appeared two minutes after a Word document fired a macro on the same host, and (c) Prefetch shows it executed once and the file has since been deleted. The path is normal. The *story* the file tells in context is what flags it, which is why timeline-aware analysis beats path-pattern analysis.

**3. How would your path prioritization differ between a user workstation and a domain controller?**

On a workstation, you start at user-writable paths — `\Downloads\`, `\AppData\Local\Temp\`, `\Users\Public\` — because the most common compromise pattern (phishing -> macro -> dropper) writes there. On a domain controller, those paths are barely relevant because DCs typically have no interactive users. You instead prioritize `C:\Windows\System32\Tasks\`, `C:\Windows\NTDS\` and access to it, `C:\Windows\Sysvol\`, and registry locations for new services. DCs see attacker activity through credential abuse and persistence via a service or task. Workstations see it through user-context dropper execution. The investigative question is the same — "where did the attacker write something?" — but the highest-probability answer differs.

---

## Task 2 — Parse and Review the MFT

**Part B — sample candidate file table** (entries reflect what the WKSTN-221 dataset shows after Task 2 of the walkthrough):

| File Name | Full Path | SI Created (UTC) | FN Created (UTC) | Allocated / Deleted | Why It Stands Out |
|---|---|---|---|---|---|
| svc_updater.exe | `C:\Temp\svc_updater.exe` | (scenario detail — file no longer on disk) | (same) | Deleted | Matches Prefetch entry; no longer present on disk |
| update.exe | `C:\Users\payroll-admin\AppData\Local\Temp\update.exe` | 2024-11-14 14:20:11 | 2024-11-14 14:20:11 | Deleted | InUse=False but record persists; SI==FN (no timestomping); name doesn't match any installed software |
| a.tmp | `C:\Users\payroll-admin\AppData\Local\Temp\a.tmp` | 2024-11-14 14:19:42.6 | 2024-11-14 14:19:42.6 | Deleted | Staging file in the same dir; same size as update.exe (174,080 bytes); deleted at 14:20:11.1, just before the rename |
| ~$Q4_Payroll_Review.xlsm | `C:\Users\payroll-admin\AppData\Local\Temp\~$Q4_Payroll_Review.xlsm` | 2024-11-14 14:18:56 | 2024-11-14 14:18:56 | Deleted | Excel lock file; indicates the user had a macro-enabled workbook open immediately before the dropper sequence. Deleted at 14:24:18, per the USN Journal |
| MSForms.exd | `C:\Users\payroll-admin\AppData\Local\Temp\VBE\MSForms.exd` | 2024-11-14 14:18:58 | 2024-11-14 14:18:58 | Deleted | Office VBA extender cache; presence + deletion is a classic macro-execution residue pattern |

The list is curated, not exhaustive. The goal is to identify what deserves follow-up, not to dump every `.exe` you find. The list's investigative value comes from the cluster of files created in a 75-second window in a single Temp directory. Note the missing row as well. The Temp folder holds no `b.tmp` record, because the rename to `update.exe` kept record 22417. The MFT shows a record's current name, and the USN Journal (Task 4) shows its history.

---

## Task 3 — Compare Standard Information and File Name Timestamps

**Sample populated table** (using update.exe, a.tmp, and a hypothetical timestomped contrast):

| File | SI Created | SI Modified | SI Changed | SI Accessed | FN Created | FN Modified | FN Changed | FN Accessed | Observations |
|---|---|---|---|---|---|---|---|---|---|
| update.exe | 2024-11-14 14:20:11 | 2024-11-14 14:20:11.05 | 2024-11-14 14:23:44 | 2024-11-14 14:21:03 | 2024-11-14 14:20:11 | 2024-11-14 14:20:11.05 | (not in export) | (not in export) | SI == FN for create/modify; access bumped 52 sec later (execution time per Prefetch). SI Changed matches the 14:23:44 deletion. Not timestomped. |
| a.tmp | 2024-11-14 14:19:42.6 | 2024-11-14 14:19:48 | 2024-11-14 14:20:11.1 | 2024-11-14 14:19:48 | 2024-11-14 14:19:42.6 | 2024-11-14 14:19:48 | (not in export) | (not in export) | SI == FN for create/modify. SI Changed matches the 14:20:11.1 deletion. Consistent with normal file lifecycle (create, write, close, delete). |
| (hypothetical) old_driver.sys | 2018-04-12 09:30:00 | 2018-04-12 09:30:00 | 2024-11-14 14:25:00 | 2024-11-14 14:25:00 | 2024-11-14 14:25:00 | 2024-11-14 14:25:00 | 2024-11-14 14:25:00 | 2024-11-14 14:25:00 | Classic timestomping signature: SI Created predates FN Created by years; FN times all cluster in the incident window. |

The WKSTN-221 `mft.csv` exports only two `$FN` timestamps, `Created0x30` and `LastModified0x30`. FN Changed and FN Accessed are not available for the real rows.

**Short answers:**

**1. Why can differences between SI and FN timestamps matter in an investigation?**

User-mode code can easily modify the SI ($STANDARD_INFORMATION) timestamps. Windows APIs such as `SetFileTime` rewrite them, and many attacker tools include timestomping as a built-in feature. The NTFS kernel driver writes the FN ($FILE_NAME) timestamps when the file name attribute is created or updated, and the normal API surface cannot modify them. When SI and FN diverge, the FN values are the more trustworthy record of when the file landed on disk. That lets you reconstruct a true creation time even when an attacker has tried to make a file look old.

**2. What kinds of SI/FN mismatches would cause you to look more closely at a file?**

The classic signature is SI Created earlier than FN Created. That is the literal signature of someone setting the SI timestamps to an older date after the file already existed. SI Modified earlier than FN Created is similar. Another flag is round-number SI timestamps, with everything ending in `:00:00.0000000`, when the FN timestamps have realistic sub-second values. Any file in a high-traffic temp directory whose SI Created predates the directory's own creation also deserves attention.

**3. Why should you be careful about claiming "timestomping" based on timestamp differences alone?**

Legitimate operations can produce SI/FN mismatches too. Copying a file from another volume with `xcopy /K` preserves source SI timestamps but creates new FN timestamps. Restoring from backup, extracting from a ZIP that preserves modified times, or pulling files from a shadow copy can all create similar patterns. A finding of "timestomping" needs at least one corroborating signal. The file may be in an attacker-suspect path, have no matching install record, or have SI values that aren't merely older but specifically suspicious, such as exact noon timestamps or a date that matches the Windows install date. One mismatch alone is a flag for further analysis, not a finding.

**4. What legitimate activity could explain SI/FN discrepancies that have nothing to do with attacker behavior?**

Legitimate explanations include file copy from another volume with metadata preservation (xcopy/robocopy), archive extraction that restores original modified times, and restore from backup. File synchronization tools such as OneDrive and Dropbox preserve source timestamps. Software installation can lay down files with embedded version timestamps, and Windows servicing operations write files with timestamps inherited from the update package. A mismatch alone is not a finding. The *combination* of a mismatch with other suspicious context is.

---

## Task 4 — Review the USN Journal for Change Activity

**Part A — sample populated table** (reflects WKSTN-221 USN data for `b.tmp` and `update.exe`):

| File / Path | Change Type (Reason Code) | Timestamp (UTC) | Parent Path | Why It Matters | Notes |
|---|---|---|---|---|---|
| b.tmp | FILE_CREATE | 2024-11-14 14:20:11.00 | `\Users\payroll-admin\AppData\Local\Temp` | First evidence of dropper file landing on disk, on MFT record 22417 | NTFS does not record the creating process. Sysmon EID 11 would, but WKSTN-221 has no Sysmon log. PowerShell EID 4104 at 14:20:07.6 shows a script block that writes `b.tmp` |
| b.tmp | DATA_EXTEND | 2024-11-14 14:20:11.00 | same | File content written | |
| b.tmp | DATA_EXTEND\|FILE_CLOSE | 2024-11-14 14:20:11.05 | same | Write finished | |
| b.tmp | RENAME_OLD_NAME | 2024-11-14 14:20:11.25 | same | File about to be renamed | Pre-rename record |
| update.exe | RENAME_NEW_NAME | 2024-11-14 14:20:11.5 | same | New name post-rename — classic dropper pattern | b.tmp -> update.exe in 250ms, same record 22417 |
| update.exe | RENAME_NEW_NAME\|FILE_CLOSE | 2024-11-14 14:20:11.5 | same | Close on the renamed file | A rename writes no data |
| update.exe | BASIC_INFO_CHANGE | 2024-11-14 14:21:03 | same | Likely access-time bump from execution | Lines up with Prefetch LastRun |
| update.exe | FILE_DELETE | 2024-11-14 14:23:44 | same | File deleted 213 seconds after creation | Short-lived attacker tool; cleanup |
| update.exe | FILE_CLOSE | 2024-11-14 14:23:44.5 | same | Final close after delete | |

**Part B — short answers:**

**1. What does the USN Journal tell you that the MFT alone may not make obvious?**

The USN Journal tells you the *sequence* of changes that produced the MFT's current state — creates, deletes, renames, writes, in order. The MFT only tells you what files exist, or existed in the case of unallocated records, at the moment you parsed it. For `update.exe` on WKSTN-221, the MFT shows a single unallocated record (entry 22417) at `\Users\payroll-admin\AppData\Local\Temp\update.exe` created at 14:20:11. The USN Journal shows where that name came from. `b.tmp` was created on the same entry, 22417, at 14:20:11.00 and written by 14:20:11.05. Its `RenameOldName` record at 14:20:11.25 pairs with a `RenameNewName` record for `update.exe` at 14:20:11.5, still on entry 22417. `update.exe` then shows a `BasicInfoChange` at the 14:21:03 execution and a `FileDelete` at 14:23:44, under four minutes after `b.tmp` appeared. A rename within one volume keeps the record number (Chapter 4 §4.6.1). That is why the MFT holds no `b.tmp` row: it shows the record's current name, and only the journal remembers the staging name.

**2. Why is rename activity particularly important in attacker tool staging investigations?**

Renaming is one of the cheapest evasion techniques an attacker has. The attacker writes a generic-looking file (`b.tmp`, `temp.dat`), then renames it to its real name (`update.exe`, `svchost.exe`) just before execution. An AV signature that fires only on the final name misses the file while it exists under its staging name. Forensically, the rename pair (RENAME_OLD_NAME -> RENAME_NEW_NAME) is also one of the strongest *behavioral* indicators of staging. The only legitimate processes that rename their own files in this pattern are installers, and those produce predictable signatures: publisher, installer path, and presence of an `.msi`.

**3. How can deleted or short-lived files still leave useful NTFS evidence? What limits that visibility?**

Three things keep deleted files visible in NTFS metadata. First, the MFT record stays present, marked unallocated, until that record number is reused. Second, the USN Journal retains the file's change history until its retention window rolls off. The typical default is several megabytes of entries, which covers hours to a few days of activity on a busy host. Third, any artifact that referenced the file by path (Prefetch, Amcache, LNK, jump lists, Shimcache) was written when the file existed and may still be intact. Record reuse, USN Journal rollover, and time itself limit that visibility. High disk churn pushes old MFT records back into rotation faster, and a file deleted thirty days ago on a busy host may have nothing left to find.

---

## Task 5 — Correlate MFT and USN Findings

**Sample populated correlation table** (using update.exe and the Excel lock-file context):

| File or Path | What the MFT Shows | What the USN Journal Shows | Most Reasonable Interpretation | Confidence |
|---|---|---|---|---|
| `\Users\payroll-admin\AppData\Local\Temp\update.exe` | Unallocated record; SI Created = FN Created = 2024-11-14 14:20:11; SI==FN throughout (no timestomping); no longer present on disk | b.tmp -> update.exe rename at 14:20:11.5; BASIC_INFO_CHANGE at 14:21:03 (execution); FILE_DELETE at 14:23:44 — total lifecycle of 213 seconds | A short-lived staged executable was renamed from a generic tmp name to update.exe in a user-writable Temp directory, executed once, and deleted within four minutes. The pattern is consistent with dropper staging followed by cleanup. Execution is corroborated by Prefetch (RunCount=1, LastRun=14:21:03). | High |
| `\Users\payroll-admin\AppData\Local\Temp\~$Q4_Payroll_Review.xlsm` + MSForms.exd cluster | Excel lock file created at 14:18:56 and now unallocated; MSForms.exd present at 14:18:58 and now unallocated | Lock file and MSForms.exd creations cluster immediately before the b.tmp/update.exe staging sequence. The lock file was deleted at 14:24:18, after update.exe | The user had a macro-enabled Excel workbook open in the seconds immediately before the dropper staging began. The temporal proximity strongly suggests the macro produced the dropper, but the macro itself isn't in the MFT/USN excerpt — Office logs or the open workbook are needed for direct attribution. | Medium |

The discipline being trained here: "consistent with" is honest analysis, and "the attacker did X" is a claim. File system evidence supports the first. The second requires either execution evidence (Prefetch, Amcache, EDR) or a corroborating artifact source.

---

## Task 6 — Build a File System Mini-Timeline

**Sample populated mini-timeline** (anchored to WKSTN-221 14 Nov 2024):

| Time (UTC) | Artifact Source | Event Type | File / Path | Significance | Confidence |
|---|---|---|---|---|---|
| 2024-11-14 14:18:56 | MFT — `Created0x10` | File created | `\Temp\~$Q4_Payroll_Review.xlsm` | Excel lock file appears — workbook opened | High |
| 2024-11-14 14:18:58 | MFT — `Created0x10` | File created | `\Temp\VBE\MSForms.exd` | Office VBA extender cache written | High |
| 2024-11-14 14:19:42.6 | MFT — `Created0x30` | File created | `\Temp\a.tmp` | First staging file in dropper sequence | High |
| 2024-11-14 14:20:11.00 | USN Journal — `FILE_CREATE` | File creation | `\Temp\b.tmp` | Second staging file, on MFT record 22417 | High |
| 2024-11-14 14:20:11.25 | USN Journal — `RENAME_OLD_NAME` | File renamed | `\Temp\b.tmp` | About to be renamed | High |
| 2024-11-14 14:20:11.5 | USN Journal — `RENAME_NEW_NAME` | File renamed to | `\Temp\update.exe` | Dropper produces final-name binary | High |
| 2024-11-14 14:21:03 | USN Journal — `BASIC_INFO_CHANGE` | Access-time bump | `\Temp\update.exe` | Execution-time signal (corroborates Prefetch) | High |
| 2024-11-14 14:23:44 | USN Journal — `FILE_DELETE` | File deleted | `\Temp\update.exe` | Attacker cleanup of dropper binary | High |
| 2024-11-14 (post) | MFT — unallocated record | Deleted file record recovered | `\Temp\update.exe` | File no longer present but MFT record persists for analysis | High |

**Short answers:**

**1. Why is a timeline more useful to an investigation than a list of isolated file records?**

A timeline tells a story, and a list of records doesn't. That `update.exe` was created at 14:20:11 is interesting in isolation. That it was created 75 seconds after an Excel lock file appeared and 213 seconds before being deleted is the story. The timeline format makes causal relationships visible: what came before, what came after, and what was simultaneous. Those relationships are where conclusions live. A reviewer reading the table above can reconstruct the dropper sequence without forensic expertise. The same evidence presented as bullet points loses that clarity.

**2. What would you want to correlate next — outside NTFS — to strengthen your findings?**

Prefetch, already in the walkthrough, confirms that `update.exe` executed once and gives a precise execution time. Amcache provides the SHA-256 hash for threat-intel lookup. Sysmon Event ID 1 (process creation) would link `update.exe` to its parent process, which the surrounding Excel lock file points to as the macro path. Sysmon Event ID 3 or firewall flow data would show whether the process made outbound network connections. PowerShell Operational 4104 would show whether PowerShell was invoked from the macro. Each adds a different dimension — execution, attribution, network, scripting — to a story that file system metadata alone can only sketch.

**3. Which artifact types from earlier chapters pair most naturally with this NTFS timeline?**

These artifact types come in later chapters, not earlier ones. Prefetch and Amcache (Chapter 6) pair most naturally because they answer the execution question NTFS cannot. Security.evtx 4688 and Sysmon EID 1 (Chapter 9) pair next because they provide command-line content NTFS cannot. PowerShell Operational logs (Chapter 9) and registry Run keys (Chapter 5) close the loop on what the executable *did* once it ran. NTFS is the skeleton, and the other artifact types are the muscle and skin.

---

## Task 7 — Write an NTFS Findings Summary

**Sample summary (3 paragraphs, ~280 words):**

> Between 14:18:56 and 14:23:44 UTC on 2024-11-14, file system metadata on WKSTN-221 records a brief but coherent sequence of activity centered on `C:\Users\payroll-admin\AppData\Local\Temp`. An Excel workbook lock file (`~$Q4_Payroll_Review.xlsm`) and the Office VBA extender cache (`MSForms.exd`) appear at 14:18:56 and 14:18:58. Immediately afterward, a staging file (`a.tmp`) appears at 14:19:42.6. A second file, `b.tmp`, is created at 14:20:11.00 on MFT record 22417, and its final write-close follows at 14:20:11.05. `a.tmp` is deleted at 14:20:11.1. The USN Journal shows that `b.tmp` was renamed to `update.exe` on the same record 200 ms after its final write-close. A `BASIC_INFO_CHANGE` consistent with an access-time bump from execution was recorded at 14:21:03, and `update.exe` was deleted at 14:23:44 — a complete lifecycle of 213 seconds.

> The MFT records for `update.exe` and `a.tmp` are both marked unallocated (`InUse=False`). The files have been deleted, but their metadata persists. No MFT record carries the name `b.tmp`, because the rename kept record 22417 and changed only its name. For both, the `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps are byte-for-byte identical, so this evidence shows no timestomping signature. Three features are jointly consistent with attacker dropper behavior and inconsistent with normal Office activity: the path (`AppData\Local\Temp` under a payroll administrator account), the rename from a generic tmp name to the final name, and the rapid create-execute-delete lifecycle.

> The file system evidence supports the existence and lifecycle of these files. On its own, it cannot prove what `update.exe` was, what it did, or whether it was malicious. Confirming execution requires Prefetch, where a corresponding `UPDATE.EXE-*.pf` would establish it. Attribution requires the binary's SHA-256 from Amcache for threat-intel lookup. Behavioral evidence requires process and network telemetry from Sysmon, Security.evtx, or EDR. The next step is to examine those corroborating sources. This summary is scoped to file system metadata and stops there.

---

## Task 8 — Reflection

**Reflective question 1 (paraphrased):** Why is the MFT useful even when EDR and event logs already cover the same window?

EDR and event logs are configurable and clearable, but the NTFS driver itself creates and maintains the MFT for every file on every volume. EDR can be disabled, paused, or misconfigured to ignore a path. Event logs can be filtered or cleared. The MFT is structural, because disabling it would mean disabling NTFS. It also carries information no other source has: the full set of file records, their allocation state, their precise creation order, and the FN timestamps that resist user-mode modification. When EDR coverage is incomplete or event logs have gaps, the MFT is often the most reliable record of "what was actually on this disk." Even when the other sources are complete, the MFT corroborates them in a way that's hard to fake.

**Reflective question 2 (paraphrased):** Why can deleted files still be forensically significant in Windows? What determines whether their records are recoverable?

A deleted file in NTFS isn't immediately gone. Its MFT record is flagged unallocated, but the record itself stays in place until the record number is reused for a new file. The path, size, timestamps, and often the resident attribute content can all remain readable long after the user-visible file is gone. Disk churn determines recoverability. On a busy file server, an MFT record can be recycled within hours. On a workstation with mostly idle disk activity, the same record may survive for weeks. The USN Journal follows a similar pattern: entries persist until the journal's circular buffer rolls them out, usually within hours to a few days. There's no fixed answer to "is the deleted file still there." You check, and if it is, you treat it as a genuine evidence source rather than a curiosity.

**Reflective question 3 (paraphrased):** Why should responders be careful not to conflate suspicious metadata with proof of execution? What separate evidence establishes execution?

File system metadata can only prove that a file existed, not that anyone ran it. An attacker can drop a binary, delete it, and never execute it. An attacker can also drop a binary, execute it many times, and never delete it. The metadata for both cases looks similar in places and different in others, but neither pattern *proves* execution by itself. Separate evidence sources establish execution. Prefetch keeps one entry per executable on most Windows builds, with run count and last-run time. Amcache lists programs the system has observed, often with hashes and first-seen times. Shimcache offers similar coverage through a slightly different population mechanism. Sysmon Event ID 1 or Security.evtx 4688 records process creation with the command line. Without at least one of those, "the file was on the system" is the strongest defensible claim from NTFS alone.

**Reflective question 4 (paraphrased):** Why is NTFS analysis strongest when paired with other artifact types? Give a specific WKSTN-221 example.

NTFS tells the durable but narrow story of file *existence and change*. It doesn't tell the execution story, the network story, or the user-intent story. Pairing it with other sources turns a sketch into a defensible finding. On WKSTN-221, NTFS alone shows that `update.exe` was created at 14:20:11 in a payroll admin's Temp directory and deleted three minutes later. That is suspicious but not conclusive. Pairing it with Prefetch (`UPDATE.EXE-89A4B22C.pf`, RunCount=1, LastRun=14:21:03) confirms execution. Pairing it with Amcache (SHA-256 of the binary) provides the value to query threat intelligence. Pairing it with Sysmon or Security.evtx 4688 ties `update.exe` to its parent process, which the surrounding lock file implies is the Excel macro path. Each addition narrows the space of "what could have happened." What remains is a defensible reconstruction: an Office macro produced a dropper, the dropper renamed and executed a payload, the payload exited, and the dropper cleaned up. NTFS provided the spine, and the corroborating sources gave it muscle.

---

## Ready-to-move-on self-check

Before starting Lab 05, confirm you can answer these three questions cold. If any of them feel wobbly, revisit the relevant task in this lab.

1. **What's the difference between SI and FN timestamps, and why does the FN attribute resist timestomping that the SI attribute does not?**
   *Answer:* User-mode APIs (`SetFileTime`) routinely update SI ($STANDARD_INFORMATION) timestamps, so an attacker tool can rewrite them. The NTFS kernel driver writes FN ($FILE_NAME) timestamps when the file-name attribute is created or updated. The normal API surface doesn't expose them, so modifying them requires specialized tooling. When SI and FN diverge, FN is the more trustworthy record of when the file landed on disk.

2. **A file's MFT record is `InUse=False`. What does that mean, and what can you still learn from it?**
   *Answer:* It means the file has been deleted. The MFT record is flagged unallocated and is eligible for reuse by the next created file. Until reuse happens, you can still read the file's path, size, and timestamps from the record, and for small resident files, its content too. That's why "deleted" is not the same as "gone" in NTFS.

3. **The USN Journal shows a `RENAME_OLD_NAME` -> `RENAME_NEW_NAME` pair from `b.tmp` to `update.exe`. Why is that pattern important?**
   *Answer:* It's a classic dropper signature: write a generic-looking staging file, then rename it to the final name immediately before execution. AV signatures keyed to the final name miss the staging window. The rename pair is also one of the cleanest behavioral indicators that an attacker is staging a payload rather than installing legitimate software.

---

## Walkthrough ↔ workbook bridges

The Hands-On Walkthrough in `Labs/Lab04/ReadMe.md` produces concrete numbers from the WKSTN-221 dataset. Use these bridges to revisit the workbook tasks with that data in hand.

> **After Walkthrough Step 2** (the Temp directory filter that returns 10 rows), revisit Task 1.A and Task 2. The `update.exe` and `a.tmp` rows in `C:\Users\payroll-admin\AppData\Local\Temp`, and the absent `b.tmp` row, are the specific evidence your "high-value paths" answer pointed to. Updating the Task 2 candidate file table with these exact rows turns a hypothetical into a documented finding.

> **After Walkthrough Step 3** (the SI/FN comparison showing `Created0x10 = Created0x30 = 2024-11-14 14:20:11` for `update.exe`), revisit Task 3. Your timestamp-comparison table can now be populated with real values rather than placeholders. The absence of timestomping in this scenario is *itself* a documentable finding. Record it explicitly rather than leaving the cell blank, because "checked and not present" is a different statement from "did not check."

> **After Walkthrough Step 4** (the 9-row USN sequence from `b.tmp` create at 14:20:11.00 through `update.exe` delete at 14:23:44), revisit Task 4 and Task 6. The Task 4 USN findings table populates directly from this sequence. The Task 6 mini-timeline gets its anchor entries for `RENAME_OLD_NAME`, `RENAME_NEW_NAME`, `BASIC_INFO_CHANGE`, and `FILE_DELETE`. If your prose-only Task 6 timeline was vague about "when the rename happened," it should now read `2024-11-14 14:20:11.5`.

> **After Walkthrough Step 5** (the Prefetch hit for `UPDATE.EXE-89A4B22C.pf`, RunCount=1, LastRun=2024-11-14 14:21:03), revisit Task 5 and Task 7. The Task 5 correlation entry for `update.exe` moves from "Medium" confidence to "High" once execution is independently confirmed. The Task 7 summary can now state execution as a documented fact rather than an inference. This is the moment in the walkthrough where NTFS becomes a *corroborated* story rather than a *suggestive* one.

> **After Walkthrough Step 6** (the Amcache SHA-256 lookup for `update.exe`), revisit Task 8 question 4. The specific WKSTN-221 example your reflective answer points to is now end-to-end: NTFS established existence and lifecycle, USN established sequence, Prefetch established execution, Amcache established hash for attribution. That four-source chain is the concrete shape of "correlation over certainty."

---

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
