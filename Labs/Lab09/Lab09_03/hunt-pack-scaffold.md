# Event-Log Hunt Pack Scaffold
**Windows Event-Log Hunting — Reusable Reference**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Version:** 1.0
**Pack Name:** ___________________________
**Created:** ___________________________
**Last Updated:** ___________________________
**Author:** ___________________________

---

## How to Use This Worksheet

This scaffold is a living artifact: the hunt-pack you build in Lab 09 and refine across real cases. For each new pattern you want to detect:

1. Copy this file into your team's shared `hunt-packs/` location.
2. Fill out the cells for each pattern you care about.
3. Test each entry against a known-positive `.evtx` (the [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) dataset is the easiest source) before declaring the entry done.
4. When a real case turns up a new pattern, add it here. The hunt pack is most valuable when it grows with the team's experience.

---

## Pack Inventory

| # | Pattern Name | Status | Last Tested | Tested Against | Detection Confidence |
|---|---|---|---|---|---|
| 1 | Multiple failed logons → success | | | | |
| 2 | Service installation (4697 / 7045) | | | | |
| 3 | Scheduled task created (4698 / TaskScheduler 106) | | | | |
| 4 | PowerShell from suspicious parent (4688 + 4104) | | | | |
| 5 | Explicit-credential logon (4648) | | | | |
| 6 | Log clearing (1102) | | | | |
| 7 | Defender service disabled (5007 / 5010) | | | | |
| 8 | RDP success (4624 LogonType 10) | | | | |
| 9 | LSASS access (Sysmon 10) | | | | |
| 10 | DCSync indicator (4662 with replication right) | | | | |
| 11 | *(add)* | | | | |

Status values: **Draft / Tested / Production / Deprecated**.
Detection confidence: **HIGH / MEDIUM / LOW** based on false-positive history.

---

## Per-Pattern Worksheet

For each pattern, fill in one block:

```
### Pattern: <name>

**MITRE ATT&CK technique(s):**       <T1078, T1059.001, …>
**Channels:**                         <Security, System, PowerShell/Operational, …>
**Event IDs:**                        <4624, 4688, 4104, …>
**Field-level conditions:**           <e.g., LogonType=10 AND IpAddress NOT IN trusted_range>
**Time window (sliding):**            <e.g., 5 failed 4625 followed by a 4624 within 60s>
**Known false-positive sources:**     <e.g., service accounts X, Y, Z; backup jobs at 02:00>
**Suppression / allowlist:**          <accounts, IPs, processes you DO NOT want to alert on>

**Tool implementations:**
- PowerShell:    `Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} | …`
- EvtxECmd:      `EvtxECmd.exe -f Security.evtx --csv … | findstr 4625`
- Hayabusa:      `hayabusa.exe csv-timeline -d <Logs>/ -p super-verbose`
- Sigma rule:    `<repo path or inline YAML>`
- SIEM query:    `<KQL / SPL / EQL>`

**Test evidence (must pass):**
- True positive case: <file or sample>
- True negative case: <file or sample>

**Notes / history:**
<who added this, when, why; any case where it produced the finding>
```

Repeat the block for every pattern in the pack inventory above.

---

## Field-Mapping Cheatsheet

For quick reference when authoring patterns:

### Security log — high-value EIDs

| EID | Meaning | Key fields |
|---|---|---|
| 4624 | Successful logon | `TargetUserName`, `LogonType`, `IpAddress`, `LogonProcessName` |
| 4625 | Failed logon | `TargetUserName`, `FailureReason`, `Status`, `IpAddress` |
| 4648 | Explicit-credential logon | `SubjectUserName`, `TargetUserName`, `TargetServerName`, `ProcessName` |
| 4672 | Special privileges assigned | `SubjectUserName`, `PrivilegeList` |
| 4688 | Process created | `NewProcessName`, `ParentProcessName`, `CommandLine`, `SubjectUserName` |
| 4697 | Service installed | `ServiceName`, `ServiceFileName`, `ServiceStartType`, `ServiceAccount` |
| 4698 | Scheduled task created | `TaskName`, `TaskContent` |
| 4720 | User account created | `TargetUserName`, `SubjectUserName` |
| 4768 / 4769 | Kerberos TGT / TGS | `TargetUserName`, `ServiceName`, `TicketEncryptionType` (`0x17` = RC4 = Kerberoasting flag) |
| 1102 | Audit log cleared | `SubjectUserSid`, `SubjectUserName` |

### Logon types (with 4624 / 4625 / 4648)

| Type | Meaning | When suspicious |
|---|---|---|
| 2 | Interactive (console) | Off-hours; service accounts |
| 3 | Network (SMB, RPC) | Common lateral-move type |
| 4 | Batch (scheduled task) | Unexpected task scheduler activity |
| 5 | Service | New / unusual service accounts |
| 7 | Unlock | Off-hours unlocks |
| 9 | NewCredentials (`runas /netonly`) | **Pass-the-Hash signal** |
| 10 | RemoteInteractive (RDP) | RDP from non-jump-host source |
| 11 | CachedInteractive | Offline cached creds — laptop |

### Operational channels worth knowing

```
Microsoft-Windows-PowerShell/Operational           — 4103 (pipeline), 4104 (scriptblock)
Microsoft-Windows-TaskScheduler/Operational        — 106, 140, 141, 200, 201, 4698, 4699, 4700, 4701, 4702
Microsoft-Windows-WinRM/Operational                — 91, 142, 161, 169
Microsoft-Windows-Windows Defender/Operational     — 1116, 1117, 5001, 5004, 5007, 5010
Microsoft-Windows-Sysmon/Operational               — 1 (process), 3 (network), 7 (image load), 10 (process access), 11 (file create), 13 (registry)
```

---

## Maintenance Log

Record when entries change, are added, or are deprecated.

| Date | Change | Reason | Tested? |
|---|---|---|---|
| | | | |
| | | | |
| | | | |

---

## Sharing and Distribution

- **Internal location:** ___________________________
- **Owner / maintainer:** ___________________________
- **Review cadence:** ___________________________ (quarterly recommended)
- **Last full-pack regression test:** ___________________________

---

*Event-Log Hunt Pack Scaffold — Windows Forensics for Beginners. The pack is most valuable when it grows with your team's experience. New attacker pattern → new pack entry.*
