Question-to-Evidence Worksheet
**Windows Endpoint Incident Response — Reusable Reference**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Version:** 1.0  
**Created:** ___________________________  
**Last Updated:** ___________________________  
**Author:** ___________________________  

---

## How to Use This Worksheet

This worksheet is a living reference. For each new investigation:

1. Copy it into your case folder under `00_Admin\`
2. Work through the categories relevant to your incident type
3. Check off questions as you answer them
4. Add case-specific questions at the bottom of each section
5. Note evidence gaps where artifacts are unavailable or inconclusive

Update the master copy whenever you discover a new artifact mapping or refine an existing one.

---

## Category 1 — Active Threat (Collect First — Volatile)

> These questions determine whether the attacker is still present. Answer them before anything else. Evidence in this category is lost on reboot or shutdown.

| # | Forensic Question | Primary Artifact | Collection Tool | Specific Data Point | Notes |
|---|---|---|---|---|---|
| 1.1 | Is a malicious or unexpected process currently running? | Live process list | `Get-Process`, Task Manager, EDR | Name, PID, parent PID, path, command line | Volatile — collect immediately |
| 1.2 | Are there active outbound connections to unknown external IPs? | Live network state | `Get-NetTCPConnection`, `netstat -ano` | Remote IP, port, owning PID | Correlate PID with process list |
| 1.3 | Are there active inbound connections suggesting remote access? | Live network state | `Get-NetTCPConnection` | Local port, remote IP, state | Look for RDP (3389), WinRM (5985/5986) |
| 1.4 | Are there users currently logged on who should not be? | Live session data | `query user`, `Get-LocalUser`, EDR | Username, session type, logon time | Volatile — document before any action |
| 1.5 | Are there scheduled tasks or services that were recently modified? | Task scheduler, services | `schtasks /query`, `sc query`, registry | Task name, executable path, last modified | Cross-reference with registry Run keys |
| 1.6 | *(Add case-specific question)* | | | | |

---

## Category 2 — Initial Access

> These questions establish how the attacker got in. Initial access artifacts are usually persistent but may be modified or deleted by the attacker.

| # | Forensic Question | Primary Artifact | Collection Tool | Specific Data Point | Notes |
|---|---|---|---|---|---|
| 2.1 | Did a user open a malicious email attachment? | Email client data, LNK files, Zone.Identifier ADS | LECmd, mail client forensics | Target path, download timestamp, zone origin | Zone.Identifier marks files downloaded from internet |
| 2.2 | Was a malicious document or script executed via Office? | Security.evtx, Prefetch, Sysmon | EvtxECmd, PECmd | EID 4688 parent/child process, prefetch entry | Look for Office spawning PowerShell, cmd, wscript |
| 2.3 | Was there a successful external logon before the incident? | Security.evtx | EvtxECmd | EID 4624 (logon type 3/10), source IP | Correlate with VPN/firewall logs |
| 2.4 | Was a vulnerability or exposed service exploited? | IIS/app logs, Security.evtx, Sysmon | EvtxECmd, log review | Unusual process spawned by web/app service | Check for web shells, unusual child processes |
| 2.5 | Was a malicious file downloaded via browser? | Browser history SQLite, MFT, Zone.Identifier | DB Browser, MFTECmd | Download URL, timestamp, file path | Cross-reference with MFT created timestamp |
| 2.6 | *(Add case-specific question)* | | | | |

---

## Category 3 — Execution

> These questions establish what the attacker ran. Execution artifacts are among the richest in Windows forensics — multiple independent sources often record the same event.

| # | Forensic Question | Primary Artifact | Collection Tool | Specific Data Point | Notes |
|---|---|---|---|---|---|
| 3.1 | What executables ran on this host and when? | Prefetch, Amcache | PECmd, Registry Explorer | Executable name, run count, last run time, referenced paths | Prefetch disabled by default on server SKUs |
| 3.2 | Did PowerShell execute suspicious or encoded commands? | PowerShell operational log, Security.evtx | EvtxECmd | EID 4104 (script block), EID 4688 (process creation with cmdline) | Requires Script Block Logging enabled |
| 3.3 | Did cmd.exe or scripting engines run unexpected commands? | Security.evtx, Sysmon, Prefetch | EvtxECmd, PECmd | EID 4688 parent/child, command line arguments | Requires process command-line auditing enabled |
| 3.4 | Were any LOLBins (living-off-the-land binaries) used? | Prefetch, Security.evtx, Amcache | PECmd, EvtxECmd | mshta, rundll32, regsvr32, certutil, wscript, cscript | Cross-reference with known LOLBin list |
| 3.5 | Were any tools or malware dropped to disk and executed? | MFT, Prefetch, Amcache, USN Journal | MFTECmd, PECmd | File creation timestamp, execution timestamp, path | Look for Temp, AppData, ProgramData, root of C:\ |
| 3.6 | *(Add case-specific question)* | | | | |

---

## Category 4 — Persistence

> These questions establish whether the attacker established a foothold that survives reboot, remediation, or credential reset.

| # | Forensic Question | Primary Artifact | Collection Tool | Specific Data Point | Notes |
|---|---|---|---|---|---|
| 4.1 | Were new autorun registry keys added or modified? | NTUSER.DAT, SOFTWARE hive | Registry Explorer, RECmd | Run, RunOnce keys — value name, data, timestamp | Check both HKLM and HKCU |
| 4.2 | Were new services installed? | SYSTEM hive, Security.evtx | Registry Explorer, EvtxECmd | EID 7045 (new service), service binary path | Malicious services often use random names or mimic legitimate ones |
| 4.3 | Were new or modified scheduled tasks created? | Task scheduler XML files, Security.evtx | EvtxECmd, manual review | EID 4698 (task created), task action and trigger | Check `C:\Windows\System32\Tasks\` |
| 4.4 | Were startup folders modified? | MFT, LNK files, shellbags | MFTECmd, LECmd | Files added to `\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` | Also check `C:\ProgramData\Microsoft\Windows\Start Menu\` |
| 4.5 | Were WMI subscriptions created? | WMI repository | Manual review, Autoruns | Event consumer, filter, binding objects | Stealthy persistence — often missed without specific checks |
| 4.6 | *(Add case-specific question)* | | | | |

---

## Category 5 — Impact

> These questions establish what the attacker did once inside — what data was accessed, moved, or destroyed.

| # | Forensic Question | Primary Artifact | Collection Tool | Specific Data Point | Notes |
|---|---|---|---|---|---|
| 5.1 | Were sensitive files accessed or opened? | LNK files, Jump Lists, MFT | LECmd, JLECmd, MFTECmd | Target file path, access timestamp | LNK files survive even after target deletion |
| 5.2 | Were files staged, compressed, or renamed before exfil? | MFT, USN Journal, Prefetch | MFTECmd, PECmd | File creation/rename events, compression tool execution | Look for 7zip, WinRAR, zip in staging dirs |
| 5.3 | Were files deleted and is recovery possible? | MFT (allocated flag), USN Journal | MFTECmd | Deallocated MFT records, USN delete entries | Recovery depends on disk activity since deletion |
| 5.4 | Was data transferred off the host? | SRUM, firewall/proxy logs, browser history | SRUM parser, log review | Per-process network bytes sent, destination IPs/domains | SRUM retains up to 30–60 days of usage data |
| 5.5 | Was cloud sync or webmail used for exfiltration? | Browser history, SRUM, OneDrive/Dropbox logs | DB Browser, SRUM parser | Upload activity, sync client logs, cloud storage URLs | Check both browser and native sync client logs |
| 5.6 | *(Add case-specific question)* | | | | |

---

## Category 6 — Scope

> These questions establish the blast radius — which other hosts, accounts, and systems may be affected.

| # | Forensic Question | Primary Artifact | Collection Tool | Specific Data Point | Notes |
|---|---|---|---|---|---|
| 6.1 | Were other hosts accessed from this one? | Security.evtx, Prefetch, SRUM | EvtxECmd, PECmd | EID 4648 (explicit credential use), net commands in Prefetch | Lateral movement often visible in Prefetch on source host |
| 6.2 | Were domain credentials used or harvested? | Security.evtx, memory | EvtxECmd, Volatility | EID 4776 (NTLM auth), EID 4768/4769 (Kerberos), LSASS memory | Memory analysis required for in-memory credential theft |
| 6.3 | Were remote access tools or RDP used? | Security.evtx, registry, Prefetch | EvtxECmd, Registry Explorer | EID 4624 logon type 10, RDP client history, mstsc in Prefetch | Check both source and destination hosts |
| 6.4 | Were any accounts created or modified? | Security.evtx, SAM hive | EvtxECmd, Registry Explorer | EID 4720 (account created), EID 4738 (account changed) | New local accounts are a common persistence mechanism |
| 6.5 | Is there evidence of reconnaissance against other systems? | Security.evtx, Prefetch, network logs | EvtxECmd, PECmd | net.exe, nltest.exe, arp, ping in Prefetch; failed logon spikes on other hosts | Host-based recon often visible in Prefetch and process logs |
| 6.6 | *(Add case-specific question)* | | | | |

---

## Evidence Gap Tracker

> Use this section to document artifact sources that are unavailable, incomplete, or inconclusive for this case.

| Gap | Artifact Affected | Question(s) Impacted | Conclusion Blocked | Mitigation Attempted |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |

---

## Case-Specific Questions

> Add questions unique to this investigation that don't fit the standard categories above.

| # | Question | Artifact | Notes |
|---|---|---|---|
| C1 | | | |
| C2 | | | |
| C3 | | | |

---

## Answered / Outstanding Tracker

> Check off questions as you answer them. Use this to track investigation progress.

| # | Question | Status | Answered By (artifact) | Date Answered |
|---|---|---|---|---|
| 1.1 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 1.2 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 1.3 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 1.4 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 1.5 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 2.1 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 2.2 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 2.3 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 2.4 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 2.5 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 3.1 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 3.2 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 3.3 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 3.4 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 3.5 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 4.1 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 4.2 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 4.3 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 4.4 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 4.5 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 5.1 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 5.2 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 5.3 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 5.4 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 5.5 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 6.1 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 6.2 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 6.3 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 6.4 | | ☐ Open / ☐ Answered / ☐ Gap | | |
| 6.5 | | ☐ Open / ☐ Answered / ☐ Gap | | |

---

*Question-to-Evidence Worksheet — Windows Forensics for Beginners*  
*Version 1.0 — Update this document as you learn new artifacts and encounter new incident types.*
