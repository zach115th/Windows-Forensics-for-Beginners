# Lab 02 — Task Answer Key

*Sample answers for the workbook-style Tasks 1–8 in `Labs/Lab02/ReadMe.md`. These are reference answers, not the only correct answers — your wording may legitimately differ. The reasoning matters more than the prose. Lab 02 has no Hands-On Walkthrough, so this answer key is the only calibration for the lab's top-level tasks.*

---

## Task 1 — Translate the Alert into Forensic Questions

This task asks for at least 10 specific, falsifiable questions and a categorization. Below is a sample populated set keyed to the WKSTN-047 alert.

**Sample question list:**

```
Priority  Question
-------   --------
1.        Is a malicious process currently running on WKSTN-047, and if so, what is its full command line, parent, and network state?
2.        Which Office application (WINWORD, EXCEL, OUTLOOK) spawned PowerShell, and what was the exact PowerShell command line — encoded or otherwise?
3.        Is there an active outbound connection from WKSTN-047 to an external IP, and to what destination(s)?
4.        Is the document or attachment that triggered the macro still present on the host, and what is its hash?
5.        What user account was logged on at the time of the Office-to-PowerShell spawn, and was it interactive or remote?
6.        Has PowerShell on this host executed encoded commands, downloaded content, or invoked WMI/CIM in the last 72 hours?
7.        Has any persistence been installed in the last 7 days — Run keys, scheduled tasks, services, WMI subscriptions, or startup folder entries?
8.        Have any new user accounts been created or existing accounts had their group membership changed?
9.        Has WKSTN-047 authenticated to any other host (4624/4648 outbound, RDP, SMB) since the alert window?
10.       Are there other hosts in the environment that received the same phishing message or executed the same parent document?
11.       What credentials (cached, browser, RDP) might be accessible from WKSTN-047, and have any signs of credential dumping (LSASS access, sekurlsa, comsvcs) appeared in EDR or event logs?
12.       Has any sensitive data — HR/finance share access, sensitive document opens — been touched from this host since the alert window?
```

**Sample category grouping:**

| Category | Question Numbers |
|---|---|
| Attacker presence (still active?) | 1, 3 |
| Initial access and execution | 2, 4, 5, 6 |
| Persistence | 7 |
| Lateral movement | 8, 9 |
| Data access or exfiltration | 11, 12 |
| Scope (other hosts or accounts affected?) | 10 |

**The discipline being trained:** every question is *specific*, because it names the artifact-shaped answer it expects. Every question is also *falsifiable*: it has a yes/no answer backed by named artifact evidence. "Was there attacker activity?" is not a forensic question. "Did PowerShell execute encoded commands in the last 72 hours?" is.

---

## Task 2 — Map Questions to Windows Artifacts

| # | Investigative Question | Primary Artifact(s) | Secondary / Corroborating Artifact(s) |
|---|---|---|---|
| 1 | Is a malicious process currently running? | Live process list (`Get-Process`, EDR telemetry), `netstat`/`Get-NetTCPConnection` | Memory image (Volatility `pslist`, `netscan`), Sysmon Event ID 1 |
| 2 | Which Office app spawned PowerShell, command line? | Security.evtx 4688 with command line, Sysmon EID 1, EDR process tree | PowerShell Operational EID 4104 (script block), prefetch for both processes |
| 3 | Active outbound connection / destination? | `Get-NetTCPConnection`, EDR network telemetry | Sysmon EID 3, firewall logs, proxy/DNS logs |
| 4 | Is the document still present, what is its hash? | NTFS MFT, recent files for the user (Recent\ + LNK), Outlook attachments folder | Amcache (if the doc was opened by a tracked application), USN Journal for the rename/delete trail |
| 5 | Logged-on user, session type? | Security.evtx 4624/4634 with logon type, `query user` | Sysmon EID 1 user context, RDP TerminalServices logs |
| 6 | PowerShell encoded commands / downloads in 72h? | PowerShell Operational EID 4104, 4103, 4100 | Sysmon EID 1 command line, AMSI events, ScriptBlockLogging output |
| 7 | New persistence in last 7 days? | Registry Run/RunOnce keys (Software\Microsoft\Windows\CurrentVersion\Run), Schtasks (`\Windows\System32\Tasks\`), Services hive | Autoruns export, Sysmon EID 12/13 (registry), EID 4697 (service install), Amcache |
| 8 | New accounts / group changes? | Security.evtx 4720 (account created), 4732/4728 (group membership) | NTDS extract (on DC), AD audit logs |
| 9 | Outbound authentication from WKSTN-047? | WKSTN-047 Security.evtx 4648 (explicit credential use), DC Security.evtx 4768/4769 (Kerberos) and 4776 (NTLM) naming WKSTN-047 as the client | 4624 type 3/10 on each destination host, Sysmon EID 3 to SMB/RDP/WinRM ports, NetFlow / proxy logs |
| 10 | Other hosts affected? | EDR cross-host search for the same parent hash / command line | Mail gateway logs for the original phish recipient list, DNS logs for the same C2 domain |
| 11 | Credential dumping signals? | EDR LSASS access alerts, Sysmon EID 10 with `lsass.exe` target | PowerShell 4104 for sekurlsa/comsvcs, prefetch for known dumpers |
| 12 | Sensitive data access since alert? | File share audit logs (5145, 4663), Office MRU registry keys, jump lists | LNK files in Recent\, browser history, DLP/CASB telemetry |

Note: this mapping is redundant by design, which keeps a finding defensible when one source is incomplete. If an attacker clears one source, such as Security.evtx, the corroborating sources (Sysmon, EDR, Prefetch, Amcache) still let you reach the same answer with a slightly different defensibility profile.

---

## Task 3 — Volatile vs. Persistent Evidence Prioritization

**Part A — sample populated table:**

| Volatile (lost on reboot/shutdown) | Persistent (survives reboot) |
|---|---|
| Running processes | MFT |
| Active network connections | Registry hives |
| Logged-on users | Prefetch |
| Clipboard contents | Event logs |
| RAM contents | Amcache |
| ARP and routing tables | SRUM database |
| DNS resolver cache | LNK files / Jump Lists |
| Open file handles (and the user/process holding them) | USN Journal |

**Part B — prioritized collection order (first 10 actions):**

| Priority | Collection Action | Volatile? | Reasoning |
|---|---|---|---|
| 1 | Capture running processes + parent/child + command lines (PowerShell or EDR live response) | Yes | Highest-information volatile artifact; tells you immediately whether the attacker is still live on the host. |
| 2 | Snapshot active network connections (`Get-NetTCPConnection`, `netstat -ano`) | Yes | C2 channels, lateral movement targets, and exfil destinations are visible *only* if captured before connections close. |
| 3 | Acquire full memory image (WinPMEM, MAGNET RAM, FTK Imager) | Yes | Process memory, injected code, encrypted strings, and connection state all live here. After 1 and 2, this is the single most consequential volatile capture. |
| 4 | Capture logged-on users, RDP sessions, open SMB sessions | Yes | Identifies which credentials are in play right now. |
| 5 | Capture ARP and DNS resolver caches | Yes | Useful for reconstructing recent network conversation and C2 lookup. |
| 6 | Collect Windows event logs (Security, System, Application, PowerShell Operational, Sysmon) | No | Most actionable persistent evidence; bounded size, easy to copy. |
| 7 | Export registry hives (SYSTEM, SOFTWARE, NTUSER.DAT, USRCLASS) | No | Persistence, software inventory, user activity. |
| 8 | Copy Prefetch and Amcache | No | Execution evidence — answers "what ran on this host." |
| 9 | Copy MFT and USN Journal | No | File-level activity and change history. |
| 10 | Copy SRUM, LNK files, Jump Lists, scheduled tasks folder | No | Resource usage, recent file access, lateral persistence. |

**Reasoning for the top three:**

1. *Running processes first* because if the attacker is currently on the box, you need to know now — before containment changes the state. A 30-second process snapshot is the cheapest, fastest piece of evidence you can take.
2. *Network connections second* because they tell you who the attacker is talking to and what other hosts may already be compromised. Connections close when sessions end. Memory acquisition can take 20–40 minutes, and if you wait until after it, you'll miss short-lived C2 beacons.
3. *Memory image third* because it captures everything the first two snapshots missed, plus the full process address space. It also takes the longest, so you do it after the quick snapshots. Doing memory first means you'd lose live process and network state during the 20+ minute capture.

---

## Task 4 — Build a Collection Workflow

Below is a sample populated workflow for WKSTN-047. The shape matters more than the specific commands: six stages, named tools, and output paths.

**Stage 1 — Pre-Collection Checks**

```
- Confirm authorization in writing (case ID, scope, host, time window, authorized actions). Save to 00_Admin\authorization.md.
- Verify host identity (hostname, asset tag, assigned user) matches the alert.
- Confirm EDR is connected and not in a degraded state — if it is, that itself is a finding.
- Confirm network status: is the host isolated, in segmented mode, or still on the production VLAN? Document.
- Identify active interactive sessions: are any users (analyst included) about to alter state?
- Stage destination drive (encrypted external or network share with restricted ACL) and create case folder structure.
- Note system date/time vs. wall clock; record any drift for timeline normalization later.
```

**Stage 2 — Volatile Evidence Capture (PowerShell, run as admin)**

```powershell
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$out = "E:\IR\WKSTN-047\01_Collection\volatile"

Get-Process | Select-Object Name, Id, Path, StartTime, Company, FileVersion |
  Export-Csv "$out\processes_$ts.csv" -NoTypeInformation

Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
  Export-Csv "$out\netconn_$ts.csv" -NoTypeInformation

query user > "$out\logged_on_users_$ts.txt" 2>&1
arp -a > "$out\arp_$ts.txt"
ipconfig /displaydns > "$out\dnscache_$ts.txt"
```

**Stage 3 — Memory Acquisition**

```
Tool:           WinPMEM 4.0.1 (open-source) or MAGNET RAM Capture
Command:        winpmem_v4.0.1.exe E:\IR\WKSTN-047\01_Collection\memory\WKSTN-047_mem.raw
Output:         E:\IR\WKSTN-047\01_Collection\memory\WKSTN-047_mem.raw
Hash:           Get-FileHash -Algorithm SHA256 WKSTN-047_mem.raw |
                Export-Csv ..\..\hashes\memory_hash.csv -NoTypeInformation
Notes:          Record start and end time; capture from elevated PowerShell; do not pause for analysis until hash is recorded.
```

**Stage 4 — Targeted Artifact Collection**

| Artifact | Collection Tool | Command or Method | Output Location |
|---|---|---|---|
| Running processes | PowerShell | `Get-Process \| Export-Csv` | `01_Collection\volatile\processes_<ts>.csv` |
| Network connections | PowerShell | `Get-NetTCPConnection \| Export-Csv` | `01_Collection\volatile\netconn_<ts>.csv` |
| Security.evtx | `wevtutil` | `wevtutil epl Security 01_Collection\artifacts\security.evtx` | `01_Collection\artifacts\security.evtx` |
| PowerShell logs | `wevtutil` | `wevtutil epl "Microsoft-Windows-PowerShell/Operational" 01_Collection\artifacts\powershell.evtx` | same |
| Prefetch | xcopy / robocopy | `robocopy C:\Windows\Prefetch 01_Collection\artifacts\prefetch *.pf /S` | `01_Collection\artifacts\prefetch\` |
| MFT | KAPE `$MFT` target, then MFTECmd | Raw-copy `C:\$MFT` to `01_Collection\artifacts\filesystem\$MFT`, then `MFTECmd.exe -f 01_Collection\artifacts\filesystem\$MFT --csv 01_Collection\artifacts\filesystem --csvf mft.csv` | `01_Collection\artifacts\filesystem\mft.csv` |
| Registry hives | KAPE `RegistryHives` target | `kape.exe --tsource C: --tdest 01_Collection\artifacts\registry --target RegistryHives` copies `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, each user's `NTUSER.DAT` and `UsrClass.dat`, and their `.LOG1`/`.LOG2` files. `reg save` would rebuild each hive without its deleted records or logs, and it cannot reach a logged-off user's hives | `01_Collection\artifacts\registry\` |
| SRUM database | KAPE `SRUM` target | Raw-copy `C:\Windows\System32\sru\SRUDB.dat`, which is locked on a live host. Parse it with the `SOFTWARE` hive collected in the row above | `01_Collection\artifacts\srum\` |
| LNK files | xcopy | Copy `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\*` | `01_Collection\artifacts\lnk\` |
| Amcache | KAPE `Amcache` target | Raw-copy `C:\Windows\AppCompat\Programs\Amcache.hve` and its `.LOG1`/`.LOG2` files. It is a standalone hive file, not a loaded HKLM key, so `reg save` cannot reach it | same |

**Stage 5 — Packaging and Hashing**

```powershell
# Zip the collection
Compress-Archive -Path "E:\IR\WKSTN-047\01_Collection\*" `
                 -DestinationPath "E:\IR\WKSTN-047\WKSTN-047_$ts.zip" `
                 -CompressionLevel Optimal

# Hash the archive (and each major file inside)
Get-FileHash -Algorithm SHA256 "E:\IR\WKSTN-047\WKSTN-047_$ts.zip" |
  Export-Csv "E:\IR\WKSTN-047\01_Collection\hashes\archive_hash.csv" -NoTypeInformation
```

**Stage 6 — Post-Collection Documentation**

```
- Tool versions used (MFTECmd 1.2.x, WinPMEM 4.0.1, PowerShell 5.1) — record in collection-log.md
- Any files that failed to copy (locked hives, permission denied) — log each with reason
- Anything anomalous noticed during collection (process crashes, EDR alerts during run, network drops)
- Start and end timestamps for each major stage
- Analyst name, role, and the case ID of authorization referenced
```

---

## Task 5 — Facts vs. Conclusions

**Part A — sample populated table:**

| Statement | F or C? | If C: What observed fact supports it? |
|---|---|---|
| PowerShell.exe was observed as a child process of WINWORD.EXE at 08:47 UTC | F | (observed in Security.evtx 4688 / Sysmon EID 1) |
| The attacker used a macro-enabled document to establish initial access | C | A macro-enabled document was observed open in WINWORD.EXE at 08:46 UTC, and PowerShell.exe spawned as a child of WINWORD at 08:47 — the macro path is *consistent with* this observation but other paths (DDE injection, manual paste) could produce the same parent/child pair. |
| Event ID 4624 logon type 3 recorded for account `svc-backup` at 03:12 UTC | F | (observed in Security.evtx 4624) |
| The service account was used for lateral movement | C | A type 3 logon from an internal IP not previously associated with that account, outside the account's documented usage window, supports the inference — but lateral movement specifically requires evidence of the *next* hop (file access, command execution) on the destination host. |
| Prefetch shows `MIMIKATZ.EXE` executed twice on 2024-11-14 | F | (observed in `C:\Windows\Prefetch\MIMIKATZ.EXE-<hash>.pf` with RunCount=2) |
| Credentials were likely harvested from this host | C | Mimikatz prefetch evidence + LSASS access logged by EDR support this, but Mimikatz can be aborted, blocked, or run in test mode; harvesting requires either successful credential output evidence or downstream use of those credentials. |
| A 47 MB outbound transfer was observed to 185.220.x.x on port 443 | F | (observed in firewall flow log or Sysmon EID 3 byte counters) |
| Sensitive data was exfiltrated to a threat actor-controlled server | C | A large outbound transfer to an unfamiliar IP supports a hypothesis of exfiltration. "Sensitive data" requires evidence that the transferred bytes corresponded to sensitive files, and "threat actor-controlled" requires attribution evidence (TI, infrastructure reuse) we don't yet have. |

**Part B — sample three-sentence finding:**

> At 03:12 UTC on 2024-11-14, `cmd.exe` was observed as a child process of `svchost.exe` on WKSTN-047 (Security.evtx Event ID 4688, PID 5824). Within the same minute, that `cmd.exe` invoked `net user /domain`, an Active Directory query that enumerates domain accounts. Immediately afterward, an outbound TCP connection from PID 5824 was recorded to an IP address with no prior connection history on this host (Sysmon Event ID 3, no matching destination in 30 days of preceding flow data).

The finding sticks to observable facts: process, parent, command, timestamp, destination, and baseline absence. It leaves out the interpretation, "this is consistent with command-and-control beaconing after reconnaissance," so that a separate conclusions section can address it.

---

## Task 6 — Build a Case Structure

The folder structure is procedural. Its value depends on whether the structure gets populated. A sample completed metadata block:

```
Case Root Path:     E:\IR-Cases\WKSTN-047
Created By:         A. Analyst (initials AAN)
Date Created (UTC): 2024-11-12T13:30:00Z
Notes:              Created at start of shift. Drive E: is the IR collection drive (encrypted,
                    BitLocker recovery key on file with IR manager). All evidence stays under
                    01_Collection\; analyst output goes in 02_Analysis\. No raw evidence
                    files are edited — copies are made into 02_Analysis\ before any
                    transformation. Working notes (this lab's `lab02-notes.md`) live alongside.
```

The discipline being trained: a case folder is empty unless someone fills it. Whatever your organization's convention is, use *one* convention consistently. The shape above mirrors a common IR consultancy structure: admin, collection, analysis, findings, and reports. Adapt it if your organization expects something else, but don't invent a new structure per case.

---

## Task 7 — Write a Case Opening Note and Analyst Handoff

**Part A — sample Case Opening Note:**

```
Case Reference:       IR-2024-WKSTN047
Opened By:            A. Analyst (AAN)
Date/Time Opened:     2024-11-12T13:30:00Z
Escalated From:       SOC (ticket SOC-2024-3892)
Escalation Summary:   EDR flagged unusual PowerShell activity on WKSTN-047, a finance
                      workstation. Process tree shows PowerShell spawning from an Office
                      application. Host has been online continuously for six days; no
                      containment action taken. Leadership requested preliminary scope
                      assessment by end of business.

Systems in Scope:     WKSTN-047 (finance, assigned to senior AP clerk).
                      Pending scope decision: file shares accessed by the assigned user,
                      and any host the user authenticated to in the alert window.
Accounts in Scope:    User account assigned to WKSTN-047 (pending HR confirmation of
                      identity). Any service accounts observed in 4624/4648 from this host.

Initial Questions:
  1. Is malicious code currently executing on WKSTN-047?
  2. Which Office application spawned PowerShell, and what did PowerShell do next?
  3. Has the activity moved beyond this host?

Evidence Status:      Not yet collected — collection plan drafted (lab02-notes Task 4).
Containment Status:   Not contained — pending decision pending volatile evidence capture.
Authorization:        Verbal from IR Manager (J. Doe) at 13:15; written confirmation
                      requested and pending. Reference: email IR-AUTH-WKSTN047.
Current Priority:     High — active EDR alert, unconfirmed scope, leadership engagement.
Next Action:          Stage 1 pre-collection checks; volatile evidence capture per Task 4
                      workflow.
```

**Part B — sample Analyst Handoff Note:**

```
Case Reference:       IR-2024-WKSTN047
Handoff From:         A. Analyst (AAN)
Handoff To:           B. Analyst (BAN)
Date/Time (UTC):      2024-11-12T22:00:00Z

Work Completed This Shift:
  - Authorization confirmed in writing (email IR-AUTH-WKSTN047 saved to 00_Admin\).
  - Volatile evidence captured (processes, netconn, query user, ARP, DNS cache); files
    in 01_Collection\volatile\ and hashed.
  - Memory image acquired (WKSTN-047_mem.raw, 16 GB, SHA-256 in
    01_Collection\hashes\memory_hash.csv).
  - Targeted artifact collection complete: Security/PowerShell/Sysmon EVTX, Prefetch,
    MFT, registry hives, Amcache, SRUM, LNK files. All hashed; archive built.
  - Initial review of Security.evtx confirms WINWORD.EXE spawned PowerShell.exe at
    08:47 UTC with an encoded command line (decoded copy in 02_Analysis\powershell\).

Current State of Evidence:
  - Full collection archive: E:\IR-Cases\WKSTN-047\WKSTN-047_20241112_140312.zip
  - SHA-256 recorded; chain-of-custody updated.

What Is Known So Far:
  - WINWORD.EXE -> PowerShell.exe -> outbound HTTPS to 185.x.x.x at 08:47 UTC.
  - No new persistence observed in Run keys, Schtasks, or Services in last 7 days.
  - No 4624 type 3 from WKSTN-047 to other internal hosts in the alert window.

What Remains Unknown:
  - Document that triggered the macro (search of Recent\ and Outlook attachments
    pending).
  - Decoded PowerShell command's downstream activity — Volatility analysis in
    progress on the memory image.
  - Whether 185.x.x.x is reachable from any other host in the environment.

Recommended Next Actions (in priority order):
  1. Complete Volatility pslist/netscan/malfind on the memory image; document any
     injected code findings.
  2. EDR hunt across the environment for the parent doc hash and the C2 IP.
  3. Pull mail gateway logs for the same document delivered to other recipients.

Open Questions Needing Follow-Up:
  - Has the assigned user been contacted yet? HR has not responded as of 21:30.
  - Containment decision still pending — recommend isolation at next handoff if
    EDR hunt finds additional hosts.

Notes for Incoming Analyst:
  Memory image is large; pre-stage Volatility profile work overnight if possible. All
  hashes verified post-archive. Authorization email is the master scope document — do
  not collect outside WKSTN-047 without updated authorization.
```

The discipline: a stranger should be able to act on the handoff note without asking you a single question. If they have to ping you, the handoff was incomplete.

---

## Task 8 — Reflection

**Reflective question 1 (paraphrased):** How does end-of-day time pressure change your evidence prioritization, what do you deprioritize, and what risk does that create?

Time pressure pushes you toward the fastest path to a *preliminary* answer that can support a containment decision. That path is typically volatile evidence and targeted execution artifacts: memory, PowerShell logs, Prefetch, and the recent process tree. What you deprioritize is full disk imaging on hosts where the EDR data plus a targeted triage already gives you 80% of the answer for 20% of the time. The risk is that you may miss artifacts that only show up in a full image, such as slack space, browser cache, and file content for staged-but-deleted tools. You may also overlook hosts that weren't in the initial scope but should have been. The mitigation is to document the deprioritization decision in real time. If a follow-up question requires the deeper evidence, you can go back and collect it knowing exactly what wasn't collected the first time.

**Reflective question 2 (paraphrased):** What happens if a responder skips Task 1 (question definition) and jumps straight to collecting artifacts?

You end up with a large pile of evidence and no clear way to evaluate whether anything in it is dispositive. For example, a responder dumps memory, exports all event logs, and runs MFTECmd, then sits down to "analyze." Without defined questions, they search the EVTX for "PowerShell" and find 4,000 events. They grep the MFT for `.exe` and find 30,000 records. They miss that a single 4104 query filtered to a 60-minute window answers the actual question: "did encoded PowerShell run between 08:30 and 09:30?" Question-first analysis prevents that drift. It also forces the analyst to admit what they don't know, which keeps the investigation honest.

**Reflective question 3 (paraphrased):** How does documentation discipline protect *you* personally, not just the investigation?

It protects you from the question "why did you do X (or not do X)?" asked six months later by someone who wasn't there and isn't sympathetic. If you decided not to image a host, the contemporaneous note saying "decided targeted triage at 14:20 UTC because two responders, one drive, and active C2 on a higher-value host" is your defense. Without that note, the same decision is indistinguishable from negligence. The same protection extends to insurers, regulators, and, in the worst cases, your own legal team. They will accept "I made the right call given the information I had" *only* if the information you had is documented.

**Reflective question 4 (paraphrased):** Mid-collection you discover an active RDP session to WKSTN-047 from an unfamiliar internal IP. How do you change the plan?

The active session is now the highest-priority finding. It means there's a live attacker right now, or at least live remote access from an unexpected source. The first decision is containment vs. observation. Cutting the session preserves the host but may tip off the attacker. Leaving it open buys intelligence at the cost of continued attacker presence. That decision is not yours alone. It goes to the IR manager and ideally the security director. While that's being decided, take three actions. First, immediately snapshot the active session state (`query user`, `query session`, `Get-SmbSession`, `Get-NetTCPConnection` filtered to the RDP port). Second, start a parallel collection on the source IP, because that host is now in scope. Third, pull DC Security.evtx 4768/4769 (Kerberos) and 4776 (NTLM) records for the source IP and the accounts it used. The 4769 service names show which hosts it requested access to. Confirm each one with 4624 type 10 or type 3 on that destination host. The plan changes from "complete WKSTN-047 triage" to "scope the lateral movement." The original triage continues but is no longer the gating activity.

---

## Ready-to-move-on self-check

Before starting Lab 03, confirm you can answer these three questions cold. If any of them feel wobbly, revisit the relevant task in this lab.

1. **You receive an alert that "PowerShell ran from Word on a finance host." Write the first two forensic questions you'd want answered, in the falsifiable form the lab teaches.**
   *Answer:* (a) "Which exact Office document was open at the time of the spawn, and is it still present on disk?" (b) "What was the PowerShell command line — encoded or otherwise — and what did it spawn or connect to next?"

2. **What determines the order of collection, and why does volatility weigh so heavily?**
   *Answer:* Volatility, business impact, and investigative value all shape the order (Chapter 2 §2.2.2). Volatility usually sets the first cut. Volatile evidence such as memory, network connections, and process state disappears on reboot or session close. If you don't capture it first, you can't go back for it later. Persistent evidence such as the MFT, registry, and event logs can usually wait an hour without loss. Investigative value then orders items within each group. The memory image comes before the ARP cache because it answers more of the case's questions.

3. **What's the difference between an observed fact and an analytical conclusion in a report, and why does mixing them matter?**
   *Answer:* A fact is what an artifact directly shows: "PowerShell.exe was a child of WINWORD.EXE at 08:47 UTC per 4688." A conclusion is the inference you draw from the facts: "the attacker used a malicious macro to establish initial access." Mixing them in a single sentence makes the conclusion look like evidence, which makes the report harder to defend. Reviewers can't tell what was observed from what was inferred.

---

*Lab 02 has no Hands-On Walkthrough — there are no walkthrough↔workbook bridges for this answer key. Lab 04 is the first lab where that section becomes relevant.*

---

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
