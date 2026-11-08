# Lab 03 — Task Answer Key

*Sample answers for the workbook-style Tasks 1–7 in `Labs/Lab03/ReadMe.md`. These are reference answers, not the only correct ones, and your wording may legitimately differ. The reasoning matters more than the prose. Lab 03 has no Hands-On Walkthrough at the top level, so this key is the only calibration for the per-section workbook. The Capstone is a separate exercise. This key does not cover it, and the Capstone has no answer key of its own.*

---

## Task 1 — Collection Strategy Decisions

**Part A — sample populated per-host strategy table:**

| Host | Business Criticality | Suspected Threat Value | Volatile Evidence Risk | Recommended Strategy | Justification |
|---|---|---|---|---|---|
| DC-01 | Critical — domain authentication for the entire org | High — type 3 logons from an unexpected workstation IP, new service install, failed privileged logon attempts overnight | High — DCs hold the credentials and active sessions an attacker most wants; reboot or session close loses LSASS evidence and live network state | Targeted triage + memory (full image on standby if scope expands) | Full imaging a DC mid-business-day is operationally fraught (drive size, performance impact on auth) and rarely the fastest path to the questions leadership is asking. A targeted triage of Security/System EVTX, registry (services/scheduled tasks), and memory captures the highest-value evidence without taking the DC offline. Keep full imaging on standby if memory analysis surfaces credential dumping or a confirmed second-stage payload. |
| FIN-WS23 | High — payroll administrator role; access to financial systems | High — confirmed WINWORD->POWERSHELL spawn with outbound to external IP; canonical macro-and-beacon pattern | Medium-high — process state, in-memory PowerShell content, and decoded C2 strings live in memory; on-disk artifacts (MFT, EVTX, Prefetch) survive | Full disk image + memory | This is the host most likely to anchor the rest of the investigation. The user role makes business impact a real concern, because financial records could be exfiltrated. The EDR signal is concrete. The host is a workstation, so imaging it offline is operationally feasible. A full image lets you re-analyze slack and unallocated space if needed, and memory captures live C2 state. |
| KIOSK-07 | Low — public-facing, no domain credentials, no sensitive data access | Low — AV quarantined the file before execution; no domain credentials or lateral path | Low — kiosk environments are typically constrained, and the AV action means the malicious file is already in quarantine | Deferred — scope first, collect later | The AV catch and the lack of domain integration make this the lowest-priority host. If the quarantined sample is related to the FIN-WS23 dropper, the kiosk becomes a useful comparison data point. At first triage, though, it does not justify pulling a responder or the only spare drive. Document the deferral and the rationale, and collect later if the sample turns out to be related. |

**Part B — priority and sequencing:**

1. **Which host do you collect from first, and why?**
   *FIN-WS23.* It has the most concrete EDR signal: a confirmed parent/child process chain and a confirmed outbound connection. The host is a workstation, so collection is operationally simple. The user is a payroll admin, so the business and regulatory stakes are real. Memory has to come first because the encoded PowerShell command and any decoded C2 strings live there. On-disk artifacts can wait the 30 minutes that takes.

2. **Which host most strongly justifies a full disk image, and why?**
   *FIN-WS23.* It's the host where you most need the option to re-analyze the disk later. You may need it for data-exfiltration scope questions, deleted-file recovery, or cross-checking which staged tools may have existed before deletion. DC-01 would be the next candidate, but its size and operational role make full imaging a heavier call. Targeted triage there gives you 90% of the answer for 20% of the cost.

3. **Which host is the best candidate for targeted triage, and why?**
   *DC-01.* Event logs, registry hives, scheduled tasks, and memory answer the questions leadership is asking: "did the attacker move laterally via the DC, did they install persistence, did they create accounts?" None of those require a full image, and full imaging a domain controller during business hours has a genuinely high operational cost. A scoped triage produces the evidence faster and keeps the DC serving authentication.

4. **What single new piece of information would cause you to change your collection order entirely?**
   *Confirmed credential dumping on DC-01 (e.g., 4673 + EDR LSASS access alerts, or a service install pointing to mimikatz-like binary).* That moves DC-01 to the top. Stolen domain credentials threaten every host in the environment, and minutes matter for memory capture and containment decisions. Dumping evidence also changes the legal posture. Many regulatory frameworks treat confirmed credential theft as a notification trigger, which changes who needs to be informed and when.

---

## Task 2 — Build a Minimum Viable Triage Package for FIN-WS23

**Part A — investigative questions (sample):**

```
1. What was the exact PowerShell command line that spawned at 06:58 UTC, including any encoded or obfuscated content?
2. What outbound connections did PowerShell or its children make, to which IPs/ports, and what bytes transferred?
3. Was any second-stage payload written to disk after the macro fired, and where?
4. Was persistence installed (Run keys, scheduled tasks, services, WMI subscriptions) since 06:00 UTC?
5. Was any sensitive file (payroll data, shared drive mapping) accessed or copied since the alert window?
6. Did the user account on FIN-WS23 authenticate to any other internal host since 06:58 UTC?
```

**Part B — question-to-artifact mapping:**

| # | Investigative Question | Primary Artifact | Corroborating Artifact |
|---|---|---|---|
| 1 | Exact PowerShell command line at 06:58 UTC | PowerShell Operational EID 4104 (script block) | Sysmon EID 1, Security.evtx 4688 with command line, in-memory process strings |
| 2 | Outbound connections from PowerShell and children | Sysmon EID 3 | Firewall/proxy logs, `Get-NetTCPConnection` snapshot if still live, memory `netscan` |
| 3 | Second-stage payload written to disk | MFT (`Created0x10` clustered around the alert window in user-writable paths) | USN Journal `FILE_CREATE`/`RENAME_NEW_NAME`, Prefetch, Amcache |
| 4 | New persistence since 06:00 UTC | Registry Run keys, `\Windows\System32\Tasks\`, Services subkey of SYSTEM hive | Autoruns export, Sysmon EID 12/13 (registry), 4697 (service install) |
| 5 | Sensitive file access | Security.evtx 4663 / 5145, jump lists, LNK files in `Recent\` | Office MRU registry keys, SRUM application network usage |
| 6 | Outbound authentication from FIN-WS23 | Security.evtx 4624/4648 from this host, DC Security.evtx 4624 type 3/10 with FIN-WS23 source | Sysmon EID 3 to SMB/WinRM/RDP, NetFlow |

**Part C — collection tier structure:**

| Tier | Description | Artifacts | Reasoning |
|---|---|---|---|
| **Tier 1** | Collect in every Windows compromise — no justification needed | Memory; Security.evtx, System.evtx, Application.evtx; PowerShell logs; Registry hives (SYSTEM, SOFTWARE, NTUSER.DAT, USRCLASS); Prefetch; Amcache | These answer the foundational questions (what ran, who logged on, what persisted, what changed) on essentially every Windows IR case. The marginal collection cost is low and the marginal investigative value is high. |
| **Tier 2** | Collect when time and access permit — strong IR value | MFT; USN Journal; LNK files; Jump Lists; Scheduled tasks folder; Services configuration; SRUM | These add file-level, user-activity, and resource-usage detail that strengthens the timeline. They take slightly more time and storage to collect, but taking them is rarely a bad call. |
| **Tier 3** | Collect when a specific hypothesis justifies it | Browser history; full user profile directories | Browser history is high-value when the hypothesis involves web-based phishing or credential theft via browser. Whole profile directories are large and justified only when document or staged-tool recovery is in scope. Not every case needs them, but when they're indicated they're decisive. |

**Part D — what you are explicitly not collecting:**

| Not Collected | Risk Accepted |
|---|---|
| Full disk image | If a deleted second-stage payload was never written to a tracked artifact source (no MFT record retained, no Amcache entry, no Prefetch), it may be unrecoverable. The tradeoff is accepted because of time and storage limits, and because targeted artifacts cover the most likely loss modes. |
| Mailbox content (PST/OST) | If the initial-access vector was an email attachment the user has since deleted, the mailbox would hold direct evidence. Mail is usually best collected through the mail platform's audit API rather than from the endpoint, though, and including PST/OST per host inflates collection size significantly. |
| Browser cache and full history | Browser history is collected per the Tier 3 decision above. The full cache is large and rarely decisive. If the hypothesis later requires browser cache, we can collect it on a follow-up pass. |

---

## Task 3 — Design a Triage Collection Script

**Part A — parameters (sample populated):**

```powershell
param (
    [Parameter(Mandatory=$true)]
    [string]$CaseID,            # e.g., IR-2024-WKSTN047

    [Parameter(Mandatory=$true)]
    [string]$OutputPath,        # Root path for collection output, e.g., E:\IR

    [Parameter(Mandatory=$true)]
    [string]$Analyst,           # Name or initials of collector — recorded in log

    [Parameter(Mandatory=$false)]
    [switch]$IncludeMemory,     # Trigger memory acquisition

    [Parameter(Mandatory=$false)]
    [switch]$IncludeBrowser,    # Include browser artifacts (Tier 3)

    [Parameter(Mandatory=$false)]
    [switch]$DryRun,            # Validate paths, hashes, dependencies without copying

    [Parameter(Mandatory=$false)]
    [string]$LogLevel = "INFO"  # INFO, DEBUG, WARN — defaults to INFO
)
```

`-Analyst` is added because chain-of-custody requires it. `-DryRun` is added because a script's first run on a critical host should not be how you find out about a typo in a path. `-LogLevel` is added because verbose logs are useful in failures but noisy in success.

**Part B — working directory structure:**

The provided structure is sufficient. Additions worth justifying for FIN-WS23:

- `Office/` subdirectory under `ExecutionArtifacts/` if the case involves Office document analysis (MRU keys, recent docs, Trust Records).
- `User/` subdirectory under `Filesystem/` for `NTUSER.DAT`, `USRCLASS.DAT`, `Recent\` LNK files, and Jump Lists — grouped together because they're all user-context artifacts.

Avoid creating subfolders that have no content. Empty folders in a collection archive leave a reader unsure whether collection failed silently.

**Part C — collection functions (sample populated):**

| Function / Section | Purpose | Key Consideration |
|---|---|---|
| `Initialize-Collection` | Create output directories and validate parameters | Fail fast if OutputPath is unavailable or case ID is blank |
| `Get-SystemMetadata` | Capture hostname, IP, username, OS version, timestamp | Run first — metadata anchors the entire collection |
| `Copy-RegistryHives` | Export offline copies of key registry hives | Hives may be locked — use `reg save` over file copy; handle gracefully |
| `Export-EventLogs` | Copy EVTX files to output directory | Use `wevtutil epl` to handle in-use logs; check for locked files; log skipped |
| `Collect-ExecutionArtifacts` | Prefetch, Amcache, SRUM, LNK, Jump Lists | Some paths require elevation; SRUM database is in use — copy from VSS shadow if possible |
| `Capture-VolatileState` | Process list, network connections, logged-on users, ARP/DNS cache | Run *before* memory acquisition; output to its own subfolder so it's not lost if memory step fails |
| `Acquire-Memory` | Invoke WinPMEM or similar | Long-running; emit progress; hash immediately on completion |
| `Compress-Collection` | Create ZIP archive of output folder | Exclude the Hashes folder from the archive |
| `Write-Hashes` | Compute SHA-256 of archive and individual files | Hash after compression is complete |
| `Write-CollectionLog` | Write structured log of all actions taken | Log must be written outside the archive |
| `Verify-Collection` | Re-hash the archive; compare to the written hash; log mismatch | Final sanity check — if the hash drifts between write and verify, something is wrong |

**Part D — logging requirements (sample populated):**

```
1.  Script start (parameters, hostname, analyst)
2.  Each directory created
3.  Each file copy attempted (success or failure)
4.  Each locked or inaccessible file
5.  Tool version invoked (MFTECmd 1.2.x, WinPMEM 4.0.1, PowerShell 5.1)
6.  Start and end timestamp for each major function
7.  Any function that returns non-zero exit code or throws an exception
8.  Memory acquisition start, end, image size, and hash
9.  Each registry hive successfully saved (and any that failed)
10. Archive creation, archive size, archive SHA-256
11. Final verification step (re-hash of archive, pass/fail)
12. Any user-prompt interaction (should be zero — flag if any occur)
```

**Part E — safety and scope considerations (sample populated):**

```
- Do not write to the source disk being collected from. All output goes to the OutputPath, which must be a separate volume.
- Do not run if OutputPath is on a network share unless an explicit -AllowNetwork switch is set; network paths can fail mid-write and leave partial archives.
- Refuse to overwrite an existing collection archive for the same CaseID and hostname — never destroy prior evidence by accident.
- Do not collect user mailbox files (PST/OST) without an explicit -IncludeMailbox switch; mail content is high-privacy and usually best collected via the mail platform.
- Do not invoke any anti-forensic or system-modifying command (no `sdelete`, no `wevtutil cl`, no shadow copy creation that the analyst didn't request).
- Limit memory acquisition runtime; if it exceeds a configured ceiling (e.g., 60 minutes), log a warning so the analyst can decide whether to abort.
- Do not run script logic that requires internet egress unless explicitly enabled; the script should be runnable on an air-gapped collection drive.
- Treat all output files as evidence; the script must not modify the timestamps of files it copies (use `robocopy /COPY:DAT` or equivalent to preserve metadata).
```

**Part F — optional prototype:**

The prototype is procedural and intentionally non-destructive. A minimal completion:

```powershell
# Stage 2: Copy test files
$testSource = "C:\Windows\Temp\test-source"
if (Test-Path $testSource) {
    Copy-Item -Path "$testSource\*" -Destination $workDir -Recurse -Force
    Write-Output "Copied test files from $testSource"
}

# Stage 3: Compress
$zipPath = "$workDir.zip"
Compress-Archive -Path "$workDir\*" -DestinationPath $zipPath -CompressionLevel Optimal

# Stage 4: Hash
$hash = Get-FileHash -Algorithm SHA256 $zipPath
$hash | Export-Csv "$workDir\archive_hash.csv" -NoTypeInformation

# Stage 5: Log
"$(Get-Date -Format o) | Prototype | SUCCESS | CaseID=$CaseID Host=$hostname Archive=$zipPath SHA256=$($hash.Hash)" |
    Out-File "$workDir\collection.log" -Append
```

---

## Task 4 — Package and Hash a Triage Collection

**Part A through Part C — sample populated record:**

| Item | Value |
|---|---|
| **Archive Name** | `Sample-Triage_IR-2024-TEST01_20241114.zip` |
| **Archive Path** | `E:\IR\Sample-Triage_IR-2024-TEST01_20241114.zip` |
| **File Size** | 42,318,114 bytes (40.4 MB) |
| **SHA-256** | `c4e9...` (full 64-character hash) |
| **Date/Time Hashed (UTC)** | `2024-11-14T19:42:00Z` |
| **Hashing Tool** | `Get-FileHash` (PowerShell built-in) |
| **Hashing Tool Version** | PowerShell 5.1.22621.2506 |

**Part D — sample evidence handling record:**

```
Case ID:                    IR-2024-TEST01
Host Name:                  LAB-WIN11-01
Collector:                  A. Analyst (AAN)
Collection Date/Time (UTC): 2024-11-14T19:30:00Z
Collection Method:          Targeted triage — PowerShell
Archive Name:               Sample-Triage_IR-2024-TEST01_20241114.zip
SHA-256:                    c4e9... (full hash)
Storage Location:           E:\IR\ on encrypted external drive (WD-Passport, S/N WX12...)
Working Copy Created:       Yes — copy at E:\IR\Working\
Original Preserved:         Yes — original archive untouched at E:\IR\
Transfer Status:            In place — to be transferred to case storage at shift end
Chain of Custody Updated:   Yes — entry LAB03-001 in CoC log
Notes:                      Prototype data only; treated with the same handling
                            discipline as live evidence to reinforce the pattern.
```

**Part E — sample defensibility statement:**

> *Paragraph 1.* This targeted triage package is trustworthy as evidence for four reasons. (a) The collection was scripted and reproducible: another responder running the same script against the same source state would produce the same artifact set. (b) Every artifact was copied with its metadata preserved, not transformed in flight. (c) The archive was hashed immediately after creation, and the hash was recorded outside the archive. (d) The chain-of-custody record traces the artifact from acquisition through storage, with named timestamps and a named collector. These structural controls make targeted triage defensible at the same standard as a full image.

> *Paragraph 2.* This package cannot provide anything that lives outside the collected artifact set. That includes unallocated disk space, file slack, browser cache the script did not include, deleted file content not represented in the MFT or USN Journal, and the binary content of files we copied only metadata for. Questions that need those would require a full disk image, because the targeted package cannot answer them. Examples are "recover the original document the user deleted from the Downloads folder" and "examine browser cache for the URL the macro called out to." The acceptable conditions for switching to a full image are a confirmed data-exfiltration scope question that requires deleted-file recovery, a regulatory requirement for full disk preservation, or any litigation hold notice received during the engagement.

---

## Task 5 — Explain Triage Tradeoffs to Management

This task is procedural: produce `Management_Justification_Targeted_Triage.md`. A skeleton with sample content for each section follows. Adapt the voice to your audience.

```markdown
# Triage Collection Approach — Justification
**Prepared By:** A. Analyst (AAN), IR Team
**Date:**        2024-11-14
**Incident:**    IR-2024-MULTI-HOST (DC-01, FIN-WS23, KIOSK-07)
**Audience:**    IR Manager, Legal, Executive Leadership

---

## Summary

Three hosts were escalated this morning under what appears to be a coordinated intrusion
attempt. The IR team has begun collection on the host most likely to anchor the
investigation (FIN-WS23) with a full disk image and memory capture, is conducting a
targeted triage on the domain controller (DC-01) to avoid taking it offline during
business hours, and has deferred KIOSK-07 collection because the antivirus engine
already quarantined the suspicious file and the kiosk has no domain credentials. We
expect a preliminary scope assessment by end of business today.

---

## Why We Did Not Image Every System Immediately

Full disk imaging is the most preservation-rich way to collect evidence, but it is also
the slowest and most disruptive. A 500 GB workstation drive takes 4–6 hours to image to
encrypted external media; a domain controller drive can take significantly longer and
imposes performance impact on the authentication service for the entire organization
while it runs. With two responders available and one collection drive, imaging all three
hosts in parallel is not operationally possible — and serial imaging would delay the
answers leadership is actually asking for (is the attacker still active, how far did
this spread, what data was touched) by half a day.

Targeted triage collects the specific artifacts that answer those questions — event
logs, registry, file system metadata, prefetch, scheduled tasks — in 15 to 30 minutes
per host. For DC-01, the questions on the table are answerable from those sources; full
imaging would not produce a faster or more accurate answer for the questions actually
being asked. We have preserved the option to escalate DC-01 to a full image if memory
analysis or initial triage surfaces findings that require it.

---

## What Targeted Triage Can Tell Us

Targeted triage reliably establishes: whether attacker code is currently executing,
which user accounts were used and from where, what new persistence has been installed
in the relevant window, what tools or executables ran on the host, and whether the
suspect activity moved beyond the initially-identified host. These are the scope and
containment questions that drive the next 24 hours of the response.

---

## What Targeted Triage May Miss

What triage does not give us — and where full imaging would be required — is access to
deleted-file content that no longer has a tracked artifact, to slack space and
unallocated space that may hold remnants of earlier activity, and to evidence that
would only emerge through full forensic examination of disk content. If subsequent
analysis indicates that any of these are likely to hold material evidence, we will
recommend escalating the affected host to a full image at that point.

---

## Recommended Next Steps

| Host | Recommended Action | Reason | Priority |
|---|---|---|---|
| DC-01 | Targeted triage + memory; hold on full image | Type 3 logons from unfamiliar source; need credential-theft evaluation without taking the DC offline | High |
| FIN-WS23 | Full disk image + memory | Confirmed Office-to-PowerShell + outbound C2; anchor host for the investigation | Highest |
| KIOSK-07 | Defer; preserve AV quarantine sample | AV blocked execution; no domain credentials; no lateral path | Low |

---

## Questions or Concerns

Direct any questions to the IR Manager (J. Doe). For legal review of scope or
authorization, contact the General Counsel's office; the IR Team will provide whatever
documentation is needed.
```

The discipline being trained: write it at the level of a director who is accountable for the outcome but is not technical. If you have to use a term such as "MFT," define it. If you can avoid it, do.

---

## Task 6 — Walk the Acquisition Decision Tree

*Chapter 3 §3.7 is the authority for this task. A student's answer may differ from the table below and still respect the two hard rules: memory before anything else on a live host, and do not power on a machine handed to you powered off. Treat such an answer as correct, and mark the reasoning, not the wording.*

**Part B — sample populated decision-tree walk:**

| # | Host | Path through the tree | Acquisition order | Tool choice | What you lose by getting it wrong | What you document |
|---|---|---|---|---|---|---|
| 1 | WKSTN-118 | Powered on → user logged in → admin available → unlocked BitLocker volume → triage first, escalate if needed | 1. `manage-bde -status` and `-protectors -get`, saved. 2. Memory. 3. KAPE targeted triage through the running (decrypted) file system. 4. Full physical image only if triage leaves the question open | WinPmem, DumpIt, or the EDR live-response capture for memory; KAPE Targets for triage; FTK Imager or Guymager for the image if it is escalated | Everything volatile: the decoded command line, injected code with no on-disk copy, live network state, cached credentials — and, because the volume is BitLocker-protected, potentially the FVEK that keeps the disk readable at all. Power this host off without a key protector in hand and the disk image becomes ciphertext you cannot open | Protection status, lock status, protector types, Numerical Password ID, the exact UTC time of the memory capture, tool and version, hash of the memory image, and the fact that triage was collected through the live decrypted volume rather than from an image |
| 2 | SALES-LT44 | Powered on → user logged in → **no admin and cannot elevate** → limited collection, document the constraint | 1. EDR live-response session (runs as SYSTEM regardless of who is at the keyboard) — process list, network state, memory or targeted file pulls if the platform supports them. 2. User-context triage of what is readable without elevation. 3. Escalate the credential request through the proper channel and re-collect when it lands | The EDR console first; user-context KAPE or manual copies for `NTUSER.DAT`, `Recent\`, Jump Lists, and browser data | Time, mostly — but if you wait for the credential rather than collecting what the EDR can reach now, you lose the same volatile state you would lose on any live host. The other loss is silent: collecting only the user context and not saying so leaves a reader assuming you had SYSTEM | That you could not elevate, why (an approval gap, not a technical one), what that excluded — raw memory, SYSTEM/SECURITY hives, other user profiles, `$MFT` at volume level — and who the credential request went to and when. Do not attempt privilege escalation on a production host to route around an authorization gap |
| 3 | EXEC-LT09 | Powered off → **do not power it on** → encrypted → key available in Entra → forensic boot media or write-blocker → physical image | 1. Confirm the recovery key in the Entra device record and match the Numerical Password ID before you touch the hardware. 2. Write-blocker or forensic boot media (Paladin, CAINE). 3. Physical image, hash-verified. 4. Explicitly collect `hiberfil.sys`, `pagefile.sys`, and `swapfile.sys`. 5. Unlock a working copy with the recovery password and analyse | Tableau or equivalent write-blocker; FTK Imager or `dc3dd`/Guymager for acquisition; Arsenal Image Mounter, `manage-bde -unlock`, or `dislocker` against the working copy | Boot it and `RunOnce` values fire and delete themselves, Prefetch and Amcache take new writes, the new session overwrites ShimCache at clean shutdown, the boot event may roll older records off a small log, and `$SI` and registry `LastWriteTime` values move. You also lose the hibernation image the moment a resume completes | Where the key came from, who authorised its release, the Numerical Password ID used, hashes of the encrypted source and the decrypted output, the unlock tool and version, and confirmation that unlocking was performed on a working copy, not the original |
| 4 | CONTRACT-LT07 | Powered off → do not power it on → encrypted → **no recoverable key** → park it | 1. Physical image of the ciphertext anyway, if storage allows, and hash it. 2. Exhaust the escrow search on the record: AD, Entra, MBAM/ConfigMgr, ticketing, the user's password manager, any removable media seized with the device. 3. Stop, and report the constraint | Write-blocker plus any imaging tool — the image is a preservation act, not an analysis one. Commercial key-recovery products (Passware, Elcomsoft) exist but assume a weak protector or a memory source you do not have | Nothing further — the loss already happened, before you arrived, at the moment an unmanaged device was allowed onto the network without escrow. What you can still lose is credibility, by implying a recovery path that does not exist | The exhaustive list of escrow locations checked and the negative result for each, the hash of the preserved ciphertext image and where it is stored, an explicit statement that the contents are not recoverable with the key material available, and a lessons-learned finding on BitLocker escrow policy |
| 5 | APP-SRV-04 | Powered on → logged in with admin → live collection only; a full image would require downtime the business will not authorise | 1. Memory. 2. Live capture of the persistence question specifically — service configuration from the SYSTEM hive, `\Windows\System32\Tasks\`, autorun keys, WMI subscriptions, and the binary the service points at. 3. Targeted triage: System.evtx around 02:14 for the 7045, Security.evtx, Prefetch, Amcache, MFT, USN. 4. If disk-level depth is genuinely needed, a logical image taken from a volume shadow copy, with the limitation stated | WinPmem or the EDR capture; KAPE for triage; `vssadmin list shadows` and a snapshot mount if a file-level image is escalated | Reboot or "just restart the service to see what happens" and you lose the running process, its handles, its network connections, and any in-memory configuration — which on a suspected-persistence question is the evidence that identifies what the thing actually is | The business constraint and who set it, that no full physical image was taken and why, the exact capture times, and the residual risk accepted — principally that deleted data and unallocated space were never preserved on this host |
| 6 | ENG-DT22 | Powered off → imaged with a write-blocker → analysed → persistence question still unanswered → **§3.7.5 justified exception** | 1. Confirm the physical image exists and re-verify its hash. 2. Isolate the network or point it at a sinkhole. 3. Boot a copy of the image in a VM in preference to the original hardware. 4. Capture memory at the moment the `Run` value fires. 5. Observe and record what it launches, injects, decrypts, or connects to | Arsenal Image Mounter or a VM built from the image; a host-only or sinkholed network; WinPmem or the hypervisor's own memory snapshot | Boot the original before the image is taken and hash-verified and you have contaminated the only pristine copy — the finding becomes indefensible even if it is correct. Boot it on a live network and you have told the operator you are looking | The justification for booting, the decision-maker, the exact UTC boot time so every subsequent timestamp is attributable to you rather than to the attacker, the network isolation method, and whether a copy or the original was booted |

**Part C — physical or logical:**

*Scenario 4 — CONTRACT-LT07.* Logical is the only route that would ever produce readable data, and it is not available here. A logical image requires the volume to be unlocked, and this volume never will be. A physical image is still worth taking as ciphertext preservation, but it is a large pile of noise unless a key appears later. What is given up is everything. This is the genuinely unrecoverable position §3.7.6 warns about.

*Scenario 5 — APP-SRV-04.* The host cannot be taken offline, so a bit-for-bit physical image is not on the table. Anything beyond triage is a file-level acquisition through the running system or a shadow copy. What is given up is deleted data, unallocated space, and file slack, which are precisely what a full image exists to preserve. Say so in the report, because the first question a reviewer asks about a live logical acquisition is what could not be recovered from it.

*Students who nominate Scenario 1 instead of Scenario 5 are not wrong in principle.* A BitLocker host with no escrowed key does push toward a decrypted logical image from the live system. The facts given, however, describe a domain-joined workstation with a TPM-only protector, unlocked right now. Nothing says the key is missing, and Active Directory is the first escrow location to check (§3.5.3). Physical remains the default there unless that search comes back empty.

**Part D — reflection on the tree:**

**Reflective question 1 (paraphrased):** Why does memory go first even when it is not the most valuable artifact?

Memory goes first because it is the only artifact where *your own actions* are the main threat to it. Running a triage collection changes memory. Plugging in a USB drive changes memory. Every minute the host stays up, pages turn over and processes exit. The MFT, the registry hives, and the event logs are patient. The same records will be there in 20 minutes, and mostly in 20 hours. The ordering rule is therefore about volatility and self-contamination, not about which artifact carries the most weight in the final report. On an unlocked encrypted host the argument is even sharper: the FVEK in RAM may be the only thing that keeps the disk readable at all.

**Reflective question 2 (paraphrased):** What might a "powered off" machine still be holding?

`hiberfil.sys`, principally. Since Windows 8, the default shutdown is a *hybrid shutdown*. User sessions close, but Windows hibernates the kernel session to disk rather than discarding it. A machine the user believes they turned off may therefore carry a compressed image of kernel memory, loaded drivers and all. Separately, and regardless of Fast Startup, `pagefile.sys` and `swapfile.sys` routinely hold paged-out fragments of process memory: strings, command lines, decrypted configuration, and sometimes credentials. None of these substitutes for a live RAM capture, because they lack the structure a real memory image has. They are still a genuine second source that survives shutdown. The practical change is that you list all three files explicitly in the collection. Never write "the host was off, so there was no memory evidence" without first checking whether hibernation was enabled. Recent Volatility 3 releases read a hibernation file directly, but older releases do not, and support in other tools is uneven. Confirm your tool version handles it, or convert the file first with `Hibr2Bin`.

**Reflective question 3 (paraphrased):** How do you write up an unrecoverable position?

Something close to: *"CONTRACT-LT07 was received powered off with BitLocker protection enabled. Recovery key escrow was checked in Active Directory, Entra ID, Configuration Manager, and the service desk ticket system, and no recovery information exists for this device; no `.BEK` file or printed key was received with the hardware, and the assigned user is no longer contactable. A physical image of the encrypted volume has been preserved (SHA-256 recorded in the acquisition log) but its contents are not recoverable with the key material available. No findings can be produced from this host."* Then the takeaway. This is not an analysis failure. It is the visible consequence of an asset-management and encryption-policy gap: IT allowed an unmanaged device onto the network with no key escrow. The fix belongs with IT and policy, not with the IR team. It belongs in the lessons-learned (Chapter 13 §13.6), where it can fund a mandatory-escrow control. Resist the urge to imply a recovery path. There is no clever technique here, and offering one costs you credibility on every other finding in the report.

**Reflective question 4 (paraphrased):** What does booting an evidence machine actually prove?

Four conditions come first, in order. First, take the pristine physical image and hash-verify it before anything is powered on. Second, isolate the network or sinkhole it, so the implant cannot reach live infrastructure. Third, boot a copy in a VM in preference to the original hardware. Reserve the original for cases where hardware dependencies or full-disk encryption make the VM route impractical. Fourth, document the decision, its justification, and the exact boot time, so that every artifact timestamp after that moment is attributable to you. The resulting capture proves that the persistence mechanism executes, and shows what it does when it runs: the process it launches, the code it injects, the configuration it decrypts, the destination it reaches for. That upgrades *"a suspicious `Run` value exists"* into *"`SysHostSvc` executes the following and beacons to X,"* which is a far stronger finding. It does not give you the attacker's prior interactive session or any volatile state from before the shutdown. Those are gone, and no boot recovers them. Booting is an analysis step performed on evidence you have already preserved. It is never an acquisition step, and never a reason a disk image was skipped.

---

## Task 7 — Reflection

**Reflective question 1 (paraphrased):** Why is "collect everything" sometimes a bad IR strategy, even when it sounds thorough? Give a specific scenario where imaging every host first would have made the incident worse.

"Collect everything" sounds thorough, but in practice it trades response speed for completeness when speed often matters more. Specific scenario: an attacker establishes initial access at 09:00 on Host A, moves laterally to Host B at 09:30, and begins data exfiltration from Host C at 10:00. Suppose the IR team's policy is "full image every involved host before doing anything else," and each image takes four hours. The team is still collecting on Host A while exfiltration completes on Host C, and the attacker wins the clock. A targeted triage on Host A at 09:30 would have identified the lateral movement path within 20 minutes, allowing containment of Host B and Host C before exfiltration began. The right model is "collect deliberately": volatile evidence first on the most consequential host, parallel targeted triage on the rest, and full imaging reserved for hosts where the marginal value justifies the time.

**Reflective question 2 (paraphrased):** Why can delayed memory capture be more damaging than delayed disk collection? What's at risk?

Memory holds the most volatile evidence, and the only copy of certain evidence categories. Once it's gone, it's gone. Specifically at risk:

- running process command lines that were never logged to disk
- decoded PowerShell command content that only ever existed in memory between AMSI evaluation and execution
- injected code in legitimate processes (hollowing, reflective DLL load) that leaves no on-disk trace
- active network sessions, including the destination IP, port, and bytes transferred for a C2 channel that closed when you rebooted
- cached credentials in LSASS that would tell you exactly which accounts an attacker had access to

Disk artifacts such as the MFT, registry, EVTX, and Prefetch are persistent. The same record will be there in an hour, a day, or often a week. Memory will not. That asymmetric loss is why memory acquisition ranks high in every IR priority list.

**Reflective question 3 (paraphrased):** How does documenting your collection rationale protect you if your decision is later questioned?

It moves the conversation from "why did you make this decision" to "given what you knew at the time, was the decision reasonable." Competent professionals win the second conversation. The specific documentation that matters starts with the case-open note, which records starting conditions and initial questions. Next is the collection-strategy entry with named tradeoffs ("two responders, one drive, three hosts; FIN-WS23 imaged first because of confirmed C2, DC-01 triaged because of operational cost, KIOSK-07 deferred because AV quarantined"). Then come the contemporaneous collection log, showing exactly what was collected and when, and the hash-and-handoff records showing chain of custody. If a regulator or counsel asks six months later "why didn't you image DC-01?", "I made the call at 07:55 UTC, here's the document, here's the reasoning, here's what I collected instead" is a complete answer. "I don't remember" is not.

**Reflective question 4 (paraphrased):** Mid-triage on FIN-WS23 you learn that DC-01 logged a successful auth from FIN-WS23 at 07:01 UTC — three minutes after the suspicious PowerShell. How does that change your priorities?

That 07:01 authentication moves DC-01 from "targeted triage when we have time" to immediate concern. It means the FIN-WS23 compromise has touched the domain controller, and the attacker may be holding credentials that work elsewhere in the environment. Concretely, three changes happen. (a) Memory capture on DC-01 becomes urgent. LSASS state, active sessions, and live SMB/WinRM connections are now the highest-value volatile evidence in the environment. (b) The scope question expands from "what did the attacker do on FIN-WS23" to "what did the attacker do with the FIN-WS23 user's credentials anywhere." That means pulling DC-01 4624/4769 events for the user across the wider window and hunting in EDR for the same credential use elsewhere. (c) Containment timing tightens. If there's credential theft, every minute you wait to invalidate sessions is a minute the attacker can act. The triage on FIN-WS23 continues in parallel.

---

## Ready-to-move-on self-check

Before starting Lab 04, confirm you can answer these three questions cold. If any of them feel wobbly, revisit the relevant task in this lab.

1. **A peer says "we should image every workstation in this incident, the company can afford it." What's wrong with that as an IR strategy, even if it's technically affordable?**
   *Answer:* The constraint is usually time and people, not money. Imaging takes hours per host, and during those hours an active attacker can do real damage if no one is hunting. The right model is targeted triage on most hosts and full imaging reserved for the hosts where the marginal evidence value justifies the time.

2. **Why is memory the highest-priority volatile capture, ahead of disk artifacts?**
   *Answer:* Memory holds evidence that exists nowhere else, such as decoded command content, injected code, live network state, and cached credentials. It disappears on reboot or shutdown. Disk artifacts are persistent and will still be there in an hour. Memory will not.

3. **What two pieces of documentation make a triage collection defensible later, when someone asks why you didn't fully image a host?**
   *Answer:* (a) The contemporaneous collection-strategy note recording the tradeoff with named constraints (responder count, drives, business impact, what was collected instead). (b) The chain-of-custody record and hash log showing exactly what *was* collected, when, and that it has not been altered since.

---

*Lab 03 has no Hands-On Walkthrough at the top level, so this answer key has no walkthrough↔workbook bridges. The Lab 03 Capstone is a separate exercise with its own deliverables. Lab 04 is the first lab whose top-level Tasks have a corresponding walkthrough.*

---

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
