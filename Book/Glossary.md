# Glossary

Consolidated key terms from across the book. Each entry includes a short definition and the chapter(s) where the concept is developed at length. For deeper coverage of any term, follow the chapter link.

_Compiled from each chapter's **Key Terms** section. **170 terms** at last build._

## Index

[A](#a) · [B](#b) · [C](#c) · [D](#d) · [E](#e) · [F](#f) · [H](#h) · [I](#i) · [J](#j) · [K](#k) · [L](#l) · [M](#m) · [N](#n) · [P](#p) · [Q](#q) · [R](#r) · [S](#s) · [T](#t) · [U](#u) · [V](#v) · [W](#w)

---

## A

**ActiveTimeBias** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
The value under `HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation` recording the total UTC offset in minutes in force when the hive was last written; a snapshot at collection time, not necessarily the offset that applied during the incident.

**Adversarial Reviewer Test** &nbsp;·&nbsp; *[Ch 13](Chapter13.md)*  
A pre-release review of a report conducted in the character of a hostile competent reader, checking each finding for unsupported words, unstated assumptions, and hidden single-source dependencies.

**Allocation Flag** &nbsp;·&nbsp; *[Ch 4](Chapter04.md)*  
A bit in an MFT record indicating whether the corresponding file is currently in use (allocated) or has been deleted (unallocated).

**Ambiguous Local Hour** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
The repeated local hour produced by a daylight-saving fall-back transition, in which every local timestamp matches two distinct UTC instants and ordering must be recovered from monotonic sequence numbers instead.

**Amcache** &nbsp;·&nbsp; *[Ch 1](Chapter01.md), [Ch 6](Chapter06.md)*  
A registry hive at `%SystemRoot%\AppCompat\Programs\Amcache.hve` that records metadata, including SHA-1 hashes, for binaries the system has seen.

**AppID** &nbsp;·&nbsp; *[Ch 6](Chapter06.md)*  
A unique identifier for an application that owns a Jump List file in `AutomaticDestinations\`.

**Attribute** &nbsp;·&nbsp; *[Ch 4](Chapter04.md)*  
A typed structure within an MFT record that holds a specific piece of metadata or data, such as Standard Information, File Name, or Data.

**Audit Policy** &nbsp;·&nbsp; *[Ch 9](Chapter09.md)*  
The Windows configuration that determines which categories of security events are recorded in `Security.evtx`.

---

## B

**BitLocker** &nbsp;·&nbsp; *[Ch 3](Chapter03.md)*  
The Microsoft full-volume encryption feature built into Windows, which renders a volume unreadable without a key protector even when the volume is imaged successfully.

**BitLocker Recovery Key** &nbsp;·&nbsp; *[Ch 3](Chapter03.md)*  
A 48-digit numerical password that unlocks a BitLocker volume independently of the TPM, commonly escrowed to Active Directory, Entra ID, MBAM, or Configuration Manager.

**Blast Radius** &nbsp;·&nbsp; *[Ch 12](Chapter12.md)*  
The full extent of an encryption event — every host, volume, share, and directory affected — established through extension sweeps and ransom-note placement.

---

## C

**Case Log** &nbsp;·&nbsp; *[Ch 2](Chapter02.md)*  
A chronological real-time record of investigative actions, decisions, findings, and context.

**Case Summary** &nbsp;·&nbsp; *[Ch 11](Chapter11.md)*  
A written document, suitable for legal, HR, and executive audiences, that translates the technical investigation into actionable conclusions.

**Chain of Custody** &nbsp;·&nbsp; *[Ch 1](Chapter01.md)*  
The documented history of who handled an evidence item, when, where, and for what purpose.

**Channel Analysis** &nbsp;·&nbsp; *[Ch 11](Chapter11.md)*  
The systematic examination of each plausible exfiltration path (USB, cloud sync, browser upload, email, etc.), confirming or ruling out each.

**Cleanup Evidence** &nbsp;·&nbsp; *[Ch 11](Chapter11.md)*  
Indicators that a user attempted to remove traces of activity (file deletion, history clearing, log clearing, secure delete tools), which is itself evidence.

**Clear Key** &nbsp;·&nbsp; *[Ch 3](Chapter03.md)*  
A key protector written into the volume metadata when BitLocker protection is suspended, allowing the volume to unlock itself without the TPM until protection is resumed.

**Clock Skew** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
The difference between a host's clock and true time, measured against an event that a second clock also recorded; documented always and corrected only when a conclusion depends on it.

**Cloud Sync Client** &nbsp;·&nbsp; *[Ch 5](Chapter05.md)*  
A background application that synchronizes files between a local folder and a cloud account, such as OneDrive, Dropbox, Google Drive, or Box.

**Collection** &nbsp;·&nbsp; *[Ch 1](Chapter01.md)*  
The acquisition of relevant evidence in a controlled and documented manner.

**Collection Tier** &nbsp;·&nbsp; *[Ch 3](Chapter03.md)*  
A defined level of collection depth used to scale triage across multiple hosts.

**Confidence Scale** &nbsp;·&nbsp; *[Ch 13](Chapter13.md)*  
A defined, published set of levels — here Confirmed, Probable, Possible, Undetermined — used consistently across a report so that confidence language carries the same meaning for every reader.

**Confirmed (confidence level)** &nbsp;·&nbsp; *[Ch 13](Chapter13.md)*  
Supported by two or more independent artifact sources in agreement, or by one authoritative source with no plausible alternative explanation.

**Confirmed Finding** &nbsp;·&nbsp; *[Ch 11](Chapter11.md)*  
A finding directly supported by named artifacts with evidence sufficient to withstand scrutiny.

**Containment** &nbsp;·&nbsp; *[Ch 13](Chapter13.md)*  
Action taken to stop an intrusion from continuing or spreading, ranging from perimeter blocking to power-off, each with a distinct cost to available evidence.

**Containment Decision** &nbsp;·&nbsp; *[Ch 2](Chapter02.md)*  
The documented choice to isolate, monitor, or otherwise control a system during incident response.

**Conversion Log** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
A record of each timeline input's source file, parsing tool and version, the tool's output timezone, the basis for that claim, and the offset applied — the artifact that makes a normalization reproducible by a reviewer.

**Corroborating Artifact** &nbsp;·&nbsp; *[Ch 2](Chapter02.md)*  
A secondary evidence source used to confirm or challenge a conclusion drawn from a primary artifact.

**Curation** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
The deliberate process of selecting timeline entries that matter, with annotations that explain why, while setting aside background activity that does not.

---

## D

**Data Run** &nbsp;·&nbsp; *[Ch 4](Chapter04.md)*  
A pointer in an MFT record to a sequence of clusters on disk where a file's content is stored when the data is non-resident.

**Defensible Triage** &nbsp;·&nbsp; *[Ch 3](Chapter03.md)*  
A documented, proportionate, and reviewable triage strategy tied to available facts and constraints.

**DestList Stream** &nbsp;·&nbsp; *[Ch 6](Chapter06.md)*  
A stream within a Jump List file that records the order, last-access time, and access count of recent items.

**Detection Feedback Loop** &nbsp;·&nbsp; *[Ch 13](Chapter13.md)*  
The practice of converting case findings into durable detection content — behavioral rules, hunt-pack entries, and logging changes — so that each incident improves the organization's ability to detect the next one.

**Digital Forensics** &nbsp;·&nbsp; *[Ch 1](Chapter01.md)*  
The systematic process of identifying, acquiring, preserving, analyzing, and reporting digital evidence.

**Directory Index ($I30)** &nbsp;·&nbsp; *[Ch 4](Chapter04.md)*  
The `$INDEX_ROOT` and `$INDEX_ALLOCATION` attributes of a directory, which store an entry per child file containing a copy of that child's `$FILE_NAME` metadata.

**Distribution Restriction** &nbsp;·&nbsp; *[Ch 11](Chapter11.md)*  
A note on a case document indicating who is authorized to receive it; standard for sensitive investigations.

**Double Extortion** &nbsp;·&nbsp; *[Ch 12](Chapter12.md)*  
A ransomware model in which data is exfiltrated before encryption so the actor can threaten publication in addition to withholding the decryption key.

**Dwell Time** &nbsp;·&nbsp; *[Ch 12](Chapter12.md)*  
The interval between an attacker's initial access to an environment and the point at which their presence is detected or their objective is executed.

---

## E

**Earliest Confirmed Compromise** &nbsp;·&nbsp; *[Ch 13](Chapter13.md)*  
The defensible timestamp of the first attacker activity established by the investigation; the reference point that determines which backups are safe to restore.

**EDR** &nbsp;·&nbsp; *[Ch 1](Chapter01.md)*  
Endpoint Detection and Response tooling used for endpoint visibility, alerting, and response actions.

**Encryption Window** &nbsp;·&nbsp; *[Ch 12](Chapter12.md)*  
The bounded period during which a ransomware encryptor ran, established from USN Journal modification rates and ransom-note creation timestamps.

**EPROCESS** &nbsp;·&nbsp; *[Ch 7](Chapter07.md)*  
The Windows kernel structure representing an active process; central to memory forensics process enumeration.

**Eradication** &nbsp;·&nbsp; *[Ch 13](Chapter13.md)*  
Removal of attacker access, tooling, and persistence from the environment, verified rather than declared, and dependent on the completeness of the investigation's scope.

**Eric Zimmerman Tool Suite** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
A widely used set of Windows forensic tools (MFTECmd, EvtxECmd, RECmd, AmcacheParser, etc.) whose CSV output is naturally suited to timeline construction.

**ETL (Event Trace Log)** &nbsp;·&nbsp; *[Ch 8](Chapter08.md)*  
The Windows-native trace file format produced by ETW-based capture tools including `netsh trace` and `pktmon`.

**Event ID (EID)** &nbsp;·&nbsp; *[Ch 9](Chapter09.md)*  
A numeric identifier for a specific kind of event within a log channel.

**Event Timestamp** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
A time value written by a subsystem at the moment it observed the event, such as a Security EID 4688 or a USN Journal entry; the only class of timestamp that belongs on a timeline axis without qualification.

**Evidence Cost** &nbsp;·&nbsp; *[Ch 13](Chapter13.md)*  
The specific categories of evidence lost by a given containment action, accepted deliberately and recorded in the case log.

**Evidence Gap** &nbsp;·&nbsp; *[Ch 2](Chapter02.md), [Ch 11](Chapter11.md)*  
A specific question the available evidence cannot answer, named explicitly in findings to maintain honesty about the analysis's limits.

**EvtxECmd** &nbsp;·&nbsp; *[Ch 9](Chapter09.md)*  
A command-line `.evtx` parser, part of the Eric Zimmerman tool suite, that produces CSV output for further analysis.

**Executive Brief** &nbsp;·&nbsp; *[Ch 13](Chapter13.md)*  
A one-page incident document written for non-technical decision-makers, stating the bottom line, what is known, what is not yet known, business impact, actions taken, and the decisions required from leadership.

---

## F

**Fact** &nbsp;·&nbsp; *[Ch 2](Chapter02.md)*  
A statement directly supported by a named artifact or confirmed telemetry source.

**Fast Startup (Hybrid Shutdown)** &nbsp;·&nbsp; *[Ch 3](Chapter03.md)*  
The default Windows shutdown behaviour since Windows 8, which closes user sessions but hibernates the kernel session to `hiberfil.sys` rather than discarding it — meaning a machine that appears powered off may still hold a recoverable image of kernel memory.

**File Name Attribute ($FN)** &nbsp;·&nbsp; *[Ch 4](Chapter04.md)*  
An MFT attribute containing a separate set of MACB timestamps, generally updated by the file system itself and harder to tamper with than $SI.

**Fileless Malware** &nbsp;·&nbsp; *[Ch 7](Chapter07.md)*  
Malicious code that operates primarily or entirely in memory, leaving little or no useful disk footprint.

**Flow Data** &nbsp;·&nbsp; *[Ch 8](Chapter08.md)*  
Summary records of network conversations (source, destination, port, protocol, byte and packet counts, time range), produced by NetFlow, IPFIX, sFlow, and equivalent technologies.

**Forensic Boot Media** &nbsp;·&nbsp; *[Ch 3](Chapter03.md)*  
A bootable environment such as Paladin or CAINE that starts a machine without mounting its internal storage read-write, allowing a powered-off host to be imaged without altering it.

**Full Disk Image** &nbsp;·&nbsp; *[Ch 3](Chapter03.md)*  
A broad preservation copy of a storage device intended to retain as much evidence as possible for later analysis.

**FVEK (Full Volume Encryption Key)** &nbsp;·&nbsp; *[Ch 3](Chapter03.md)*  
The symmetric key that actually encrypts and decrypts BitLocker volume data. It is resident in memory while the volume is unlocked and may be recoverable from a memory image.

---

## H

**Hive** &nbsp;·&nbsp; *[Ch 5](Chapter05.md)*  
A single file containing one branch of the registry tree, such as `SOFTWARE`, `SYSTEM`, or `NTUSER.DAT`.

**HKCU (HKEY_CURRENT_USER)** &nbsp;·&nbsp; *[Ch 5](Chapter05.md)*  
The per-user registry branch, drawn from the active user's `NTUSER.DAT` hive.

**HKLM (HKEY_LOCAL_MACHINE)** &nbsp;·&nbsp; *[Ch 5](Chapter05.md)*  
The per-machine registry branch, applying to all users on the system.

**Human-Operated Ransomware** &nbsp;·&nbsp; *[Ch 12](Chapter12.md)*  
Ransomware deployed by an interactive operator who performs reconnaissance, credential theft, and lateral movement before encrypting, as distinct from automatically propagating worms.

**Hunt Pack** &nbsp;·&nbsp; *[Ch 9](Chapter09.md)*  
A reusable set of saved searches, scripts, and documentation that codifies an organization's standard log-based detection logic.

**Hybrid Collection** &nbsp;·&nbsp; *[Ch 3](Chapter03.md)*  
A mixed approach that combines memory, targeted triage, and full imaging based on host value and investigative need.

**Hypothesis** &nbsp;·&nbsp; *[Ch 2](Chapter02.md)*  
A testable statement about what may have happened, held until evidence confirms or eliminates it.

---

## I

**Identification** &nbsp;·&nbsp; *[Ch 1](Chapter01.md)*  
The phase in which relevant systems, accounts, logs, and data sources are identified.

**INDX Slack** &nbsp;·&nbsp; *[Ch 4](Chapter04.md)*  
Unused space at the tail of an INDX record where the entries of deleted files often remain intact, allowing recovery of a file's name, size, and `$FN` timestamps after its MFT record has been reused.

**Inherited Timestamp** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
A time value copied into an artifact from elsewhere, such as a LNK file's target MACB set, ShimCache's `LastModifiedTimeUTC`, or Amcache's PE-header `Compiled` field; describes the source object, not an event on the host.

**Insider Exfiltration** &nbsp;·&nbsp; *[Ch 11](Chapter11.md)*  
Data movement performed by an authorized user (often without authorization for the specific data) using legitimate access.

**Investigation Plan** &nbsp;·&nbsp; *[Ch 2](Chapter02.md)*  
A structured document that converts alert information into prioritized questions, collection steps, and decisions.

---

## J

**JA3 Fingerprint** &nbsp;·&nbsp; *[Ch 8](Chapter08.md)*  
A hash-based fingerprint of the TLS Client Hello, used to identify TLS clients even on encrypted connections.

**Jump List** &nbsp;·&nbsp; *[Ch 6](Chapter06.md)*  
A per-application list of recently accessed items, stored under `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\`.

---

## K

**Kernel Pool** &nbsp;·&nbsp; *[Ch 7](Chapter07.md)*  
A region of kernel memory used for kernel-mode allocations; sometimes scanned during memory analysis to recover unlinked structures.

**Key Protector** &nbsp;·&nbsp; *[Ch 3](Chapter03.md)*  
A mechanism that releases the BitLocker volume master key — TPM, TPM with PIN, password, external key (`.BEK`) file, or numerical recovery password.

---

## L

**Last-Write Time** &nbsp;·&nbsp; *[Ch 5](Chapter05.md)*  
The timestamp recorded against each registry key, indicating when the key or any of its values was last modified.

**LNK File** &nbsp;·&nbsp; *[Ch 6](Chapter06.md)*  
A Windows shortcut file recording target path, target timestamps, volume serial number, and other metadata about a file the user has accessed.

**Log Channel** &nbsp;·&nbsp; *[Ch 9](Chapter09.md)*  
A named log stream in the Windows event log architecture (e.g., `Security`, `System`, `Microsoft-Windows-PowerShell/Operational`).

**log2timeline** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
The extractor component of the Plaso super timeline framework.

**Logical Image** &nbsp;·&nbsp; *[Ch 3](Chapter03.md)*  
A file-level acquisition capturing only the files the file system currently references, excluding unallocated space, slack, and deleted content.

**LogonType** &nbsp;·&nbsp; *[Ch 9](Chapter09.md)*  
A field on logon events that distinguishes interactive, network, batch, service, RDP, and several other logon categories.

---

## M

**MACB Timestamps** &nbsp;·&nbsp; *[Ch 4](Chapter04.md)*  
The Modified, Accessed, Changed (metadata), and Born (created) timestamps recorded for each file. Each appears in both $SI and $FN attributes.

**`malfind`** &nbsp;·&nbsp; *[Ch 7](Chapter07.md)*  
A Volatility plugin that identifies memory regions exhibiting characteristics common to injected code.

**Master File Table (MFT)** &nbsp;·&nbsp; *[Ch 4](Chapter04.md)*  
The central database in NTFS containing one record per file or directory on the volume.

**Memory Acquisition** &nbsp;·&nbsp; *[Ch 3](Chapter03.md)*  
The live capture of volatile RAM content from a running system.

**MemProcFS** &nbsp;·&nbsp; *[Ch 7](Chapter07.md)*  
A tool that mounts a memory image as a virtual file system, allowing process and module data to be browsed with standard file-system tools.

**Metadata Timestamp** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
A time value that is a property of an object updated as a side effect of some operation — MFT `$SI` and `$FN`, a registry key's `LastWriteTime` — recording when the object last changed but not what changed it.

**MFT** &nbsp;·&nbsp; *[Ch 1](Chapter01.md)*  
The Master File Table, a core NTFS artifact used to understand file-system activity.

**MFT Record** &nbsp;·&nbsp; *[Ch 4](Chapter04.md)*  
A fixed-size entry in the MFT representing a single file or directory and containing its attributes.

**Mirror Port (SPAN Port)** &nbsp;·&nbsp; *[Ch 8](Chapter08.md)*  
A switch configuration that copies traffic from one port or VLAN to a monitoring port for capture.

**MountedDevices** &nbsp;·&nbsp; *[Ch 6](Chapter06.md)*  
The registry path under `HKLM\System\MountedDevices` that records the mapping between volume GUIDs and drive letters.

---

## N

**`netsh trace`** &nbsp;·&nbsp; *[Ch 8](Chapter08.md)*  
A Windows-native command-line interface for starting and stopping network captures, producing ETL output.

**NTUSER.DAT** &nbsp;·&nbsp; *[Ch 5](Chapter05.md)*  
The per-user registry hive containing user-specific configuration and activity artifacts.

---

## P

**Patient Zero** &nbsp;·&nbsp; *[Ch 12](Chapter12.md)*  
The first host compromised in an intrusion, identified by chaining backwards from later activity to an entry point with an external source.

**PCAP / PCAPNG** &nbsp;·&nbsp; *[Ch 8](Chapter08.md)*  
Packet capture file formats containing full packet content with timing.

**Personal Cloud Account** &nbsp;·&nbsp; *[Ch 11](Chapter11.md)*  
A cloud storage or email account associated with a user's personal identity rather than the organization, often used as an exfiltration channel.

**Physical Image** &nbsp;·&nbsp; *[Ch 3](Chapter03.md)*  
A bit-for-bit acquisition of an entire storage device, including unallocated space, file slack, and partition gaps, from which deleted data may be recoverable.

**PIDL** &nbsp;·&nbsp; *[Ch 6](Chapter06.md)*  
A pointer-to-identifier-list structure that Windows uses to represent items in the shell namespace, including in shellbags.

**Pivot Event** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
An entry in a timeline that is confirmed to be part of the incident and that drives expansion of the analysis to nearby events.

**`pktmon`** &nbsp;·&nbsp; *[Ch 8](Chapter08.md)*  
A Windows-native packet capture utility introduced in Windows 10 / Server 2019.

**Plaso** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
An open-source framework for super timeline extraction and formatting from disk images and many artifact sources.

**PowerShell Script Block Logging** &nbsp;·&nbsp; *[Ch 9](Chapter09.md)*  
A PowerShell logging feature that records the content of executed script blocks as EID 4104 in `Microsoft-Windows-PowerShell/Operational`.

**Pre-Encryption Exfiltration** &nbsp;·&nbsp; *[Ch 12](Chapter12.md)*  
Data theft performed during the dwell window and before encryption, typically staged locally and transferred with a legitimate file-sync or transfer utility.

**Prefetch** &nbsp;·&nbsp; *[Ch 6](Chapter06.md)*  
A Windows performance feature that produces `.pf` files in `%SystemRoot%\Prefetch\` recording executable launch metadata; disabled by default on server SKUs.

**Preservation** &nbsp;·&nbsp; *[Ch 1](Chapter01.md)*  
The protection of evidence integrity through hashing, access control, and careful handling.

**Probable Finding** &nbsp;·&nbsp; *[Ch 11](Chapter11.md)*  
A finding supported by evidence that requires some inference, with the basis for the inference documented.

**Process Hollowing** &nbsp;·&nbsp; *[Ch 7](Chapter07.md)*  
A technique in which an attacker creates a legitimate process in suspended state, replaces its memory contents with malicious code, and resumes it.

**Process Injection** &nbsp;·&nbsp; *[Ch 7](Chapter07.md)*  
Any of several techniques for inserting code into the address space of another process; visible in memory but often not on disk.

**Provenance** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
The record of where a timeline entry came from, including the source artifact, the parsing tool, and the time of collection.

**Proxy Logs** &nbsp;·&nbsp; *[Ch 8](Chapter08.md)*  
Application logs from web proxy servers recording URLs accessed, user agents, response sizes, and content categories.

**`pslist`** &nbsp;·&nbsp; *[Ch 7](Chapter07.md)*  
A Volatility plugin that walks the kernel's active process list to enumerate running processes.

**`psscan`** &nbsp;·&nbsp; *[Ch 7](Chapter07.md)*  
A Volatility plugin that scans memory for `EPROCESS` structures directly, including unlinked or hidden processes.

**`pstree`** &nbsp;·&nbsp; *[Ch 7](Chapter07.md)*  
A Volatility plugin that displays the process hierarchy in indented form, making anomalous parent-child relationships visible.

---

## Q

**Question-to-Evidence Mapping** &nbsp;·&nbsp; *[Ch 2](Chapter02.md)*  
The process of tying investigative questions to specific artifacts or data sources.

---

## R

**Ransom Note** &nbsp;·&nbsp; *[Ch 12](Chapter12.md)*  
A file dropped by the encryptor containing the victim identifier, contact channel, and demands; its placement across directories serves as a map of the affected file set.

**RECmd** &nbsp;·&nbsp; *[Ch 5](Chapter05.md)*  
A command-line registry parser, part of the Eric Zimmerman tool suite, used for batch extraction and CSV output.

**Recycle Bin Content File ($R)** &nbsp;·&nbsp; *[Ch 4](Chapter04.md)*  
The renamed copy of a deleted file's content held under `C:\$Recycle.Bin\<SID>\`, paired with a matching `$I` metadata file.

**Recycle Bin Metadata File ($I)** &nbsp;·&nbsp; *[Ch 4](Chapter04.md)*  
A small record under `C:\$Recycle.Bin\<SID>\` holding a deleted file's original full path, deletion timestamp, and original size. Version 1 (Vista/7) uses a fixed 260-character path field; version 2 (Windows 8 and later) uses a variable-length path.

**Reflective DLL Loading** &nbsp;·&nbsp; *[Ch 7](Chapter07.md)*  
A technique for loading a DLL into a process from memory rather than from disk, bypassing the standard loader.

**Registry Explorer** &nbsp;·&nbsp; *[Ch 5](Chapter05.md)*  
A GUI registry parser, part of the Eric Zimmerman tool suite, that understands transaction logs and decodes common binary structures.

**RegRipper** &nbsp;·&nbsp; *[Ch 5](Chapter05.md)*  
A Perl-based registry parser with an extensive plugin library covering many specialized keys.

**Reinfection** &nbsp;·&nbsp; *[Ch 13](Chapter13.md)*  
Return of attacker access after eradication, typically caused by missed persistence, unrotated credentials, an unclosed entry point, an out-of-scope compromised host, or a restore from a compromised backup.

**Reinfection Risk** &nbsp;·&nbsp; *[Ch 12](Chapter12.md)*  
The likelihood that a restored environment will be encrypted again, driven by unremediated persistence, unrotated credentials, and an unclosed initial access path.

**Repeatability** &nbsp;·&nbsp; *[Ch 2](Chapter02.md)*  
The ability for another analyst to reproduce a collection or analysis method and understand the same reasoning path.

**Resident Data** &nbsp;·&nbsp; *[Ch 4](Chapter04.md)*  
File content small enough to be stored entirely inside its MFT record rather than in separate data runs on disk.

**Residual Risk** &nbsp;·&nbsp; *[Ch 3](Chapter03.md)*  
The investigative uncertainty or exposure that remains after a chosen collection strategy is executed.

**Rollup Timestamp** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
The time a periodic writer flushed accumulated totals, as with SRUM's hourly buckets; a bucket boundary rather than the moment the underlying activity occurred.

---

## S

**Scope** &nbsp;·&nbsp; *[Ch 1](Chapter01.md)*  
The defined boundaries of what is authorized for collection and analysis.

**SHA-256** &nbsp;·&nbsp; *[Ch 1](Chapter01.md)*  
A cryptographic hashing algorithm commonly used to verify evidence integrity.

**Shadow Copy Deletion** &nbsp;·&nbsp; *[Ch 12](Chapter12.md)*  
Destruction of Volume Shadow Copy Service snapshots, typically via `vssadmin delete shadows /all /quiet`, performed immediately before encryption to prevent local recovery.

**Shellbag** &nbsp;·&nbsp; *[Ch 6](Chapter06.md)*  
A registry artifact recording folder navigation history in Explorer, persistent across deletion of the folder.

**Shellbags** &nbsp;·&nbsp; *[Ch 5](Chapter05.md)*  
Registry artifacts under `UsrClass.dat` that record folder navigation history, including for folders on removable media or network shares.

**ShimCache (AppCompatCache)** &nbsp;·&nbsp; *[Ch 6](Chapter06.md)*  
A binary value at `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache` recording the path and `$SI` last-modified timestamp of executables the operating system has evaluated. On Windows 10 and 11 it carries no execution flag or execution timestamp, is capped at 1024 most-recent-first entries, and is written to the registry only at shutdown.

**Sigma Rule** &nbsp;·&nbsp; *[Ch 13](Chapter13.md)*  
A portable, vendor-neutral YAML detection rule format, used to express a behavioral detection derived from case findings in a form deployable across SIEM and EDR platforms.

**Source Independence** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
The test for whether two artifacts corroborate each other — they must not be able to inherit the same error, which requires both different writing subsystems and different underlying events.

**SRUM** &nbsp;·&nbsp; *[Ch 1](Chapter01.md)*  
The System Resource Usage Monitor database, which can preserve per-process resource and network usage information.

**SRUM (System Resource Usage Monitor)** &nbsp;·&nbsp; *[Ch 6](Chapter06.md)*  
A Windows feature that records per-process resource and network usage in `%SystemRoot%\System32\sru\SRUDB.dat`.

**SSLKEYLOGFILE** &nbsp;·&nbsp; *[Ch 8](Chapter08.md)*  
An environment variable that, when set, causes a TLS-aware client to write session keys to a file, allowing later decryption of captured TLS traffic.

**Staging Directory** &nbsp;·&nbsp; *[Ch 12](Chapter12.md)*  
A location where an actor collects and archives data prior to exfiltration, often chosen to resemble legitimate system paths.

**Standard Information Attribute ($SI)** &nbsp;·&nbsp; *[Ch 4](Chapter04.md)*  
An MFT attribute containing the timestamps shown in Windows Explorer; modifiable by user-mode code and a common target of timestomping.

**Super Timeline** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
A timeline that captures every timestamped event from every recognized artifact source on a system, typically containing millions of rows.

**Sysmon** &nbsp;·&nbsp; *[Ch 9](Chapter09.md)*  
A free Microsoft Sysinternals tool that produces high-fidelity process, network, and file event records to a dedicated operational log.

**SYSTEM Hive** &nbsp;·&nbsp; *[Ch 5](Chapter05.md)*  
A per-machine registry hive containing service definitions, network configuration, USB device history, and other system-wide settings.

---

## T

**TAP (Terminal Access Point)** &nbsp;·&nbsp; *[Ch 8](Chapter08.md)*  
A passive hardware device that mirrors network traffic without affecting the link.

**Targeted Timeline** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
A focused, curated timeline drawn from a specific subset of artifacts in a specific time window around a specific question.

**Targeted Triage** &nbsp;·&nbsp; *[Ch 3](Chapter03.md)*  
Focused collection of selected artifacts intended to answer specific incident response questions quickly.

**Time-Window Bracketing** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
Establishing an incident's outer bounds from cheap, high-signal sources first, then parsing high-volume sources only within that bracket plus a margin.

**Timeline Explorer** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
The GUI front end for Eric Zimmerman tools' CSV output, supporting filtering, sorting, and conditional highlighting.

**Timesketch** &nbsp;·&nbsp; *[Ch 10](Chapter10.md)*  
A web-based front end for Plaso output, useful for collaborative timeline review.

**Timestomping** &nbsp;·&nbsp; *[Ch 4](Chapter04.md)*  
The deliberate manipulation of file timestamps, usually $SI, to make attacker tools appear older, newer, or otherwise unremarkable.

**Transaction Log** &nbsp;·&nbsp; *[Ch 5](Chapter05.md)*  
A file (`.LOG1`, `.LOG2`) maintained alongside each hive that records pending changes for crash recovery and forensic completeness.

**Triage** &nbsp;·&nbsp; *[Ch 2](Chapter02.md)*  
The rapid early assessment of an incident to determine urgency, risk, and next actions.

---

## U

**Undetermined (confidence level)** &nbsp;·&nbsp; *[Ch 13](Chapter13.md)*  
A statement that available evidence neither supports nor refutes, recorded as a finding together with the named source that would have resolved it and the reason it was unavailable.

**USBSTOR** &nbsp;·&nbsp; *[Ch 5](Chapter05.md), [Ch 6](Chapter06.md)*  
The registry path under `HKLM\System\CurrentControlSet\Enum\USBSTOR` that records the history of USB mass storage devices connected to the system.

**UserAssist** &nbsp;·&nbsp; *[Ch 5](Chapter05.md), [Ch 6](Chapter06.md)*  
An NTUSER.DAT artifact recording GUI program executions launched through Explorer, with names ROT-13 encoded.

**USN Journal** &nbsp;·&nbsp; *[Ch 1](Chapter01.md), [Ch 4](Chapter04.md)*  
The Update Sequence Number Journal, a circular log of file system changes that retains evidence of file creations, modifications, renames, and deletions.

**USN Mass-Modification Pattern** &nbsp;·&nbsp; *[Ch 12](Chapter12.md)*  
The distinctive high-rate, uniform, rename-paired sequence of USN Journal records produced by bulk encryption, used to establish the encryption window.

---

## V

**Volatile Evidence** &nbsp;·&nbsp; *[Ch 2](Chapter02.md), [Ch 3](Chapter03.md)*  
Evidence that may be lost if the system is rebooted, shut down, or allowed to continue running without collection.

**Volatility** &nbsp;·&nbsp; *[Ch 7](Chapter07.md)*  
The de facto standard open-source memory forensics framework, currently maintained as Volatility 3.

**Volume** &nbsp;·&nbsp; *[Ch 4](Chapter04.md)*  
A single NTFS-formatted partition with its own MFT and journal structures.

**Volume Serial Number** &nbsp;·&nbsp; *[Ch 6](Chapter06.md)*  
A unique identifier assigned to a formatted volume, recorded in LNK files and elsewhere, that ties shell artifacts to specific physical media.

**Volume Shadow Copy (VSC)** &nbsp;·&nbsp; *[Ch 5](Chapter05.md)*  
A periodic snapshot of system volumes that may preserve prior versions of registry hives and other files.

**VSS Snapshot (Volume Shadow Copy)** &nbsp;·&nbsp; *[Ch 3](Chapter03.md)*  
A point-in-time, copy-on-write view of a volume created by the Volume Shadow Copy Service, preserving prior versions of files, registry hives, and logs as they existed when the snapshot was taken.

---

## W

**Wevtutil** &nbsp;·&nbsp; *[Ch 9](Chapter09.md)*  
A command-line utility for managing event logs, including configuring retention sizes and exporting log content.

**Windows Event Forwarding (WEF)** &nbsp;·&nbsp; *[Ch 9](Chapter09.md)*  
A native Windows mechanism for forwarding event log entries from many endpoints to one or more central collectors.

**Windows Search Index** &nbsp;·&nbsp; *[Ch 6](Chapter06.md)*  
A database of indexed file content and metadata at `%ProgramData%\Microsoft\Search\Data\Applications\Windows\Windows.edb`.

**Wireshark** &nbsp;·&nbsp; *[Ch 8](Chapter08.md)*  
The de facto standard open-source packet analysis tool.

**Working Copy** &nbsp;·&nbsp; *[Ch 3](Chapter03.md), [Ch 11](Chapter11.md)*  
A verified copy of preserved evidence used for analysis instead of the original acquisition artifact.

**Write Blocker** &nbsp;·&nbsp; *[Ch 3](Chapter03.md)*  
A hardware or software control used to reduce the risk of modifying source media during acquisition.

**WSL2 (Windows Subsystem for Linux 2)** &nbsp;·&nbsp; *[Ch 6](Chapter06.md)*  
A Linux kernel running in a lightweight VM on a Windows host. Its distributions are stored as `ext4.vhdx` virtual disks and registered per-user under `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss`; processes inside them are not Win32 processes and produce little host execution telemetry.

---

*See also:* [Appendix E — Windows Forensics Quick Reference](AppendixE.md) for the one-page cheatsheet form, and [Appendix G — Anti-Forensics and Evidence Tampering](AppendixG.md) for the tampering techniques these artifacts are used to detect.
