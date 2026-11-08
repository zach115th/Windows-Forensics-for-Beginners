# Chapter 4 — Review Question and Exercise Answers

*Sample answers for the Review Questions and Practical Exercises at the end of [`Chapter04.md`](../Chapter04.md). These are reference answers, not the only correct answers — your wording will differ and that is fine. What matters is whether your reasoning covers the same ground. For the corresponding lab, see [`Labs/Lab04/task-answers.md`](../../Labs/Lab04/task-answers.md) and [`Labs/Lab04/walkthrough-answers.md`](../../Labs/Lab04/walkthrough-answers.md).*

---

## Review Questions

**1. Why are NTFS artifacts often considered more durable than logs or EDR telemetry?**

Because the file system driver produces NTFS metadata as a structural consequence of storing files, not as a configurable security feature. Event logs can be cleared, rotated, or never enabled. EDR can be uninstalled, paused, misconfigured, or deployed after the intrusion started. Retention policies can drop the window you care about. The MFT keeps working because NTFS cannot store files without it. The USN Journal is harder to remove than a log, but not impossible. An administrator can delete it with `fsutil usn deletejournal` without disabling NTFS, and the replacement journal's new ID and low USN base give that away (Appendix G §G.5.2). They also carry information no other source has — the full set of file records, allocation state, creation order, and a second timestamp set in `$FILE_NAME` that ordinary user-mode code cannot rewrite. The durability is not absolute, and Chapter 4 is careful about that. Records get reused, journals wrap, and SSD TRIM reduces recoverability. But relative to logs and telemetry, NTFS is the source least dependent on someone having configured something correctly before the incident.

**2. What information does an MFT record contain, and which fields are most useful in incident response?**

Each record holds the file's logical name and parent directory reference, `$STANDARD_INFORMATION` MACB timestamps, `$FILE_NAME` MACB timestamps, allocation flags indicating live or deleted or directory, logical and physical size, pointers to data runs when the content is non-resident, and the content itself when it is small enough to be resident. In IR, three groups of fields carry the weight. The two timestamp sets matter because their disagreement is itself evidence. The allocation flag distinguishes "still here" from "deleted but recoverable." The parent path plus file name give you the full path for filtering. In the shipped `Data/WKSTN-221/mft.csv`, these appear as `Created0x10`/`LastModified0x10` for `$SI`, `Created0x30`/`LastModified0x30` for `$FN`, `InUse` for allocation, and `ParentPath` plus `FileName` for location. The `0x10` and `0x30` suffixes are the NTFS attribute type codes.

**3. How do $SI and $FN timestamps differ, and why does that difference matter when investigating timestomping?**

`$STANDARD_INFORMATION` holds the timestamps that Windows Explorer and most tools display, and they update continuously as a file is written, read, and modified. They are also writable through the ordinary user-mode API surface. `SetFileTime` rewrites them, and timestomping is a built-in feature of many attacker tools. `$FILE_NAME` holds a parallel MACB set that the file system itself maintains. It is generally set when the file is created or renamed, and ordinary writes do not touch it. Because different mechanisms maintain the two sets, an attacker who rewrites `$SI` typically leaves `$FN` intact, and the disagreement becomes the tamper signal. The classic pattern is `$SI` Created predating `$FN` Created — a file that appears to have been modified before it was created. The field composite in section 4.5 is the operational lesson. A tool that defaulted to `$SI` nearly carried a false conclusion, and pulling both attributes corrected it.

**4. What conditions make resident data forensically valuable in deleted file recovery?**

When a file's content fits inside the 1024-byte MFT record rather than in separate data runs on disk, that content lives in the MFT itself. Deleting the file marks the record unallocated but does not immediately erase it. Until a new file reuses the record number, the name, path, timestamps, *and the full content* remain readable. That matters because the small files are often the interesting ones: short scripts, configuration files, encoded payloads, batch files, one-line droppers. Recovery depends entirely on record reuse, which is a function of disk activity. A busy file server may recycle records within hours, and a lightly used workstation may hold them for months. Prompt collection therefore materially changes what you can recover, and "deleted" should never be treated as a synonym for "gone."

**5. What does the USN Journal preserve that the live MFT cannot reconstruct after the fact?**

Sequence and intermediate state. The MFT is a snapshot of the file system as it currently is. It tells you a record exists and is unallocated, but not the path the file took to get there. The USN Journal records each change as it happens — created, data extended, renamed, security changed, closed, deleted. Each entry carries a timestamp, the MFT record number, the file name *at the time of the change*, and the parent directory. A file that was created as `b.tmp`, written, renamed to `update.exe`, executed, and deleted leaves one unallocated record in the live MFT, under its final name. The `b.tmp` name appears nowhere in the MFT, because a rename keeps the record number and changes only the name. The journal shows all of those steps in order, with both names. The rename case is the sharpest example. The renamed file looks unremarkable in the live file system, and the journal entry pair preserves what it used to be called and exactly when it changed.

**6. Why is the USN Journal most valuable when collected promptly?**

It is a circular buffer with a finite default size, typically around 32 MB on modern Windows. When it fills, new activity overwrites the oldest entries, and the journal itself offers no way to recover them. How much history that 32 MB represents depends entirely on file system churn: hours to a few days on a busy host, potentially months on a quiet one. A host imaged a week after the incident may retain nothing from the relevant window, even though the journal is technically intact and full of entries. This is one of the strongest arguments for triage collection over waiting for a full imaging window. `$J` is small, fast to copy, and irreplaceable once it wraps.

**7. What kinds of patterns in the MFT and USN Journal suggest staging or cleanup behavior?**

Staging shows up as a burst of file creations clustered tightly in time. The files are of unusual type or size for their location, such as executables in a user profile temp directory or large archives in Downloads. A later burst of accesses or copies follows as the staged set is moved, and sometimes a final burst of deletions. Cleanup shows up as multiple `FileDelete` USN entries clustered around one time and as MFT records marked unallocated for files with suspicious names or in suspicious locations. The tell that is easiest to miss is a discrepancy between event logs that still reference a binary and a live file system that no longer contains it. The building blocks in both cases are just timestamps, allocation flags, and parent directories. Clustering turns them into a pattern. Attacker tools rarely arrive alone, so sorting by `$FN` Born and reading the neighbours is often more productive than examining the one file you already suspect.

**8. How can NTFS evidence be used to corroborate findings drawn from event logs or Prefetch?**

By providing an independent record that the referenced file actually existed at the referenced time. If Security.evtx 4688 says a process started from a given path, the MFT can confirm the binary was present and when it was created, and the USN Journal can show whether it was deleted afterward. If Prefetch shows an execution, NTFS can confirm the executable's creation predates it and place other files created in the same window. If a suspicious service is found in the registry, the MFT can date the placement of its `ImagePath` binary. The relationship runs the other way too. NTFS establishes existence and lifecycle but never attributes an action to a user or a process, so log and execution artifacts supply what NTFS structurally cannot. Keep Chapter 4's framing: treat NTFS as the corroborating source that turns a probable conclusion into a confirmed one.

**9. What are the main tradeoffs between offline image analysis, triage collection, and live acquisition for NTFS artifacts?**

Offline parsing of a forensic image is the most defensible. The source is preserved, the `$MFT` comes from a known frozen state, and analysis cannot alter it. It is also the slowest to obtain and the most operationally disruptive. Triage collection, such as a KAPE target that copies `$MFT` and `$J` to portable storage, trades some completeness for a great deal of speed. It is usually adequate for incident response questions. What it gives up is unallocated space, slack, and anything outside the target list. Live acquisition with a tool such as FTK Imager can pull `$MFT` and `$J` from a running system. The file system keeps changing while the copy runs, so the result is a smear rather than a snapshot. That is acceptable for IR purposes if you document the limitation rather than gloss over it.

**10. What documentation should accompany an MFT or USN Journal parse to make the analysis defensible later?**

Per the quick reference in 4.5.4: the file name and full path of the item in question, the MFT record number, both `$SI` and `$FN` timestamp sets, allocation status, the parsing tool with its version and the exact command executed, the hash of the source `$MFT` and `$J` as collected, and the corroborating artifacts that support the finding. The two most often skipped are the tool version and the source hash. Version matters because parser output changes between releases. Field names, timestamp precision, and even record recovery behavior differ, and reproducibility requires knowing what produced the numbers. The source hash matters because it links what you parsed to what was collected. Record the acquisition method too — image, triage collection, or live copy — because it bounds what conclusions the data can support.

---

## Practical Exercises

**1. Parse the `$MFT` from your lab VM using MFTECmd and produce a CSV. Examine the columns and identify which represent $SI versus $FN timestamps.**

**What you should end up with:** A CSV from your own volume, and a clear understanding of which columns come from which attribute.

**How to get there:** Extract `$MFT` from the lab VM with FTK Imager or a triage collector. It is a locked system file, so `Copy-Item` will not work. Then run it through the parser, minding the quoting: `MFTECmd.exe -f 'C:\Triage\LAB-VM\$MFT' --csv C:\Cases\LAB-VM\mft\`. The single quotes matter because PowerShell treats `$MFT` as a variable expansion otherwise. If you cannot extract from your own VM, the shipped `Data/WKSTN-221/mft.csv` is already in MFTECmd's output shape and works for the column-identification half of the exercise.

**What good looks like:** You can state without looking it up that the `0x10` suffix means `$STANDARD_INFORMATION` and `0x30` means `$FILE_NAME`. So `Created0x10` and `LastModified0x10` are the tamperable set, and `Created0x30` and `LastModified0x30` are the harder-to-tamper set. You should also notice `InUse` (allocation), `ParentPath` and `FileName` (which you concatenate for full path), `EntryNumber` (the MFT record number you will cite in findings), and `IsDirectory`. Filter to one directory before browsing. The CSV is wide and long, and reading it unfiltered teaches nothing.

**2. Write a small file to disk with a known timestamp, then use a timestomping technique to alter its $SI timestamps. Compare the result against the file's $FN timestamps in the MFT.**

**What you should end up with:** One file whose `$SI` and `$FN` timestamps visibly disagree, and a parsed record proving it.

**How to get there:** Create the file and note the real time. Then rewrite `$SI` from PowerShell — `$f = Get-Item .\test.txt; $f.CreationTimeUtc = '2016-03-01 12:00:00'; $f.LastWriteTimeUtc = '2016-03-01 12:00:00'; $f.LastAccessTimeUtc = '2016-03-01 12:00:00'` does it with no special tooling, which is itself the lesson. Re-extract and re-parse `$MFT`, then locate the record.

**What good looks like:** `Created0x10` reads 2016 and `Created0x30` reads today. That single row is the whole point of section 4.2.3. The attribute Explorer shows you is the one an attacker can rewrite from a three-line script, and the one the file system maintains is the one that told the truth. You also did not need administrator rights or a specialist tool, which is why `$SI` alone is never sufficient for a creation-time claim.

**3. Create, modify, rename, and delete a file in a single short window. Parse the USN Journal and reconstruct the sequence of events.**

**What you should end up with:** An ordered list of journal entries covering the file's whole life, with change reasons and timestamps.

**How to get there:** Do the four actions deliberately and note the wall-clock times. Extract `$Extend\$UsnJrnl:$J` and parse it (`MFTECmd.exe -f 'C:\Triage\LAB-VM\$J' --csv C:\Cases\LAB-VM\usn\`). Then filter to your file name. Filter on *both* names, because the rename splits the entries across them. `Data/WKSTN-221/usn-journal.csv` already has the equivalent sequence if you want a reference to compare against. Its `UpdateReasons` column carries the change-reason strings, and `FullPath` gives you the path at the time of the change.

**What good looks like:** More entries than actions. Four user-visible operations produce something like eight to ten journal records, because a single "save" is `FileCreate` then `DataExtend` then `FileClose`, and a rename is a `RenameOldName`/`RenameNewName` pair. The skill here is recognizing that the journal records file system operations rather than user intentions. The rename pair is the specific pattern worth memorizing, because it is the signature of dropper staging in real cases.

**4. Identify three deleted files in your lab MFT and recover the file names, paths, and creation timestamps. Note which records are unallocated and which still contain resident data.**

**What you should end up with:** Three recovered deleted-file records with full detail.

**How to get there:** Filter the parsed CSV to `InUse` false. On a lab VM, most hits will be installer temp files and browser cache. That is fine, because the point is the mechanics. Record `EntryNumber`, `ParentPath` plus `FileName`, both creation timestamps, and `FileSize`. MFTECmd's `--csv` output does not carry the resident content directly. Infer resident candidates from small `FileSize` values, under about 600 bytes per the working rule in §4.2.4, and confirm with a tool that dumps record contents if you want to go further.

**What good looks like:** You can articulate what "unallocated" actually means: the record is flagged as free and eligible for reuse, not erased. You can also predict which of your three are likely to be recoverable in full versus name-and-metadata only. A worthwhile follow-on is to delete several files and re-parse after a period of heavy disk activity. Watching a record disappear makes the reuse window concrete in a way that reading about it does not.

**5. Choose a known executable on your lab VM and use the MFT plus the USN Journal to construct a one-page life history of the file from creation to current state.**

**What you should end up with:** A one-page chronological narrative for a single file, sourced entry by entry.

**How to get there:** Pick something with real history — an installer you ran, or a script you created and edited several times. Pull the MFT record for both timestamp sets, allocation state, size, and record number. Pull every USN entry for that record number and for the file name. Sort into one chronology and annotate each entry with what it means. If you would rather work against a scenario with a clear answer, `update.exe` in `Data/WKSTN-221/` has a complete lifecycle across `mft.csv`, `usn-journal.csv`, `prefetch.csv`, and `amcache.csv`.

**What good looks like:** The page separates what the file system recorded from what you inferred. "`DataExtend` at 14:20:11.00" is an observation. "The dropper was writing its payload" is an interpretation, and the page should label it as one. The page should also state what NTFS could not tell you: which process performed each operation, and what the file did when it ran.

**6. Build a small CSV that combines MFT timestamps for a chosen directory with corresponding Prefetch entries. Sort by time and identify any sequences that suggest staging or execution chains.**

**What you should end up with:** A merged, time-sorted table spanning two artifact sources.

**How to get there:** Filter the MFT to one directory — a user's `AppData\Local\Temp` is the highest-yield choice — and pull `Created0x30`, path, and size. Parse Prefetch with PECmd and pull `ExecutableName`, `RunCount`, and `LastRun`. Normalize both to UTC, tag each row with its source, concatenate, and sort by time. The shipped data supports this directly: `Data/WKSTN-221/mft.csv` and `prefetch.csv` cover the same window, and the `SourceFilename`/`RunCount`/`LastRun` columns in the Prefetch file line up with the MFT rows for the Temp directory.

**What good looks like:** The merged view shows a creation preceding an execution by a plausible interval, with other files created in the same burst. That ordering — file lands, file runs, file disappears — is the execution chain the exercise is trying to make visible. If your merged table shows an execution *before* the creation timestamp, that is not an error to hide. It is either a timestomp or a clock issue, and it is worth chasing.

**7. Document the exact tool, version, command, and source `$MFT` hash for each parse you perform during the chapter exercises.**

**What you should end up with:** A parse log with one row per parse operation.

**How to get there:** Capture the version at the time you run it. `MFTECmd.exe` prints it in the banner, so record it rather than assuming. Record the operator, the UTC time, the working directory, the verbatim command including quoting, the output path, and `Get-FileHash -Algorithm SHA256` of the source `$MFT` and `$J` as collected — not of the CSV output, though hashing that too costs nothing.

**What good looks like:** Someone else could re-run every parse from your log and get byte-identical CSVs. The quoting detail belongs in the record verbatim, because `-f C:\Triage\$MFT` and `-f 'C:\Triage\$MFT'` behave differently in PowerShell. The failure mode is a confusing error rather than an obvious one.

**8. Write a one-paragraph finding that combines NTFS evidence with at least two other artifact sources to support a single conclusion about a file of interest.**

**What you should end up with:** One tight paragraph, in report voice, resting on three or more sources.

**How to get there:** Follow the multi-source pattern in 4.5.1: MFT for existence and creation, USN Journal for lifecycle and rename, Prefetch for execution, Security.evtx 4688 for user context and parent process, Amcache for the hash. Name each source explicitly as you use it. State the conclusion once, then the evidence, then the limits.

**What good looks like:** Every claim is attributable to a named artifact, and the paragraph ends by saying what it does *not* establish. A finding that says a binary "was malicious" without a hash match or behavioral evidence has overreached. A finding that says the binary was created at a stated time, executed once, and deleted three minutes later, with each fact tied to a source, is defensible as written. `Labs/Lab04/task-answers.md` Task 7 shows a three-paragraph version of this in the WKSTN-221 scenario if you want a longer model.

---

## Common mistakes on this chapter

- **Treating `$SI` as authoritative.** This is the defining error of the chapter, and it survives well into people's careers. `$SI` is what Explorer shows, what `Get-ChildItem` returns, and what most tools default to. It is also rewritable from a three-line PowerShell script by an unprivileged user. Any creation-time claim in a finding should be backed by `$FN`, and if the two disagree, that disagreement *is* the finding.
- **Declaring "timestomping" from a single mismatch.** `$SI`/`$FN` divergence has plenty of innocent causes — copying across volumes with metadata preservation, archive extraction that restores original modified times, restore from backup, sync clients that preserve source timestamps, installers writing files with package-embedded dates. A mismatch is a flag for follow-up, not a conclusion. Corroborate with path, absence of an install record, or clustering with other suspicious files before putting the word in a report.
- **Reading MFT presence as proof of execution.** The MFT proves a file existed at a path with a set of timestamps. It says nothing about whether anyone ran it, who ran it, or what it did. Execution comes from Prefetch, Amcache, UserAssist, 4688, or Sysmon EID 1. Until one of those is in hand, "the file was on the system" is the strongest defensible statement.
- **Expecting one USN entry per user action.** A single save produces a `FileCreate`/`DataExtend`/`FileClose` sequence, and a rename produces an old-name/new-name pair. Analysts new to the journal read the extra entries as duplicated activity or as evidence of repeated operations. They are the file system's own vocabulary, and learning the common reason-code combinations is what makes journal output readable.
- **Collecting `$J` late and being surprised it is empty of relevant entries.** The journal is a circular buffer of finite size and wraps in hours on a busy host. It is also tiny and copies in seconds. There is no good reason for `$J` to be missing from a triage collection, and no way to recover it once the window has rolled.
- **Skipping the source hash and the parser version in the parse record.** Both feel like bureaucracy in the moment, and both are exactly what a reviewer or a future analyst needs. Parser output genuinely differs across versions, and without the source hash there is no chain between the CSV in the case file and the artifact that was collected off the host.

---

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) book series.*
