# Appendix C — EDR Platforms and Sysmon

This appendix covers EDR and Sysmon, which the main chapters mention repeatedly but never develop. It makes the most common queries and configurations concrete enough that a working responder can use them on day one.

EDR coverage focuses on Microsoft Defender for Endpoint (MDE), CrowdStrike Falcon, and SentinelOne, the three platforms most common in enterprise Windows environments. Each section is brief because the underlying data model is similar across vendors, and most analysis patterns translate.

## C.1 Why EDR Matters Forensically

EDR platforms continuously record process, file, network, registry, and authentication telemetry from every endpoint they cover and store it centrally. For incident response, that gives you three things:

- **Historical visibility.** EDR usually retains 30 days or more of telemetry centrally. The host's own logs may have rolled over within hours.
- **Per-process attribution at the network layer.** EDR records which process owned each connection. Pure network sources cannot.
- **Cross-host queries.** When you find a suspicious binary hash, file path, or domain on one host, a single query across the EDR can show every other host that has seen it.

The tradeoff: EDR's view depends on the agent's collection logic, the platform's retention, and the attacker's interaction with the agent itself. EDR complements Windows-native artifacts rather than replacing them. The strongest investigations correlate both.

## C.2 Microsoft Defender for Endpoint (MDE)

MDE telemetry lives in Microsoft Defender XDR, formerly Microsoft 365 Defender. You query it through Advanced Hunting in Kusto Query Language (KQL).

### C.2.1 Core tables

| Table | What it records |
|---|---|
| `DeviceEvents` | Generic security events from the agent (defender detections, ASR, AMSI, etc.) |
| `DeviceFileEvents` | File creation, modification, deletion events |
| `DeviceImageLoadEvents` | DLL loads |
| `DeviceLogonEvents` | Logons observed at the endpoint (parallels Security.evtx but cross-host) |
| `DeviceNetworkEvents` | Network connection attempts and outcomes, with owning process |
| `DeviceProcessEvents` | Process creation events, with full command line and parent chain |
| `DeviceRegistryEvents` | Registry value creation, modification, deletion |
| `DeviceFromIP` / `DeviceInfo` | Static device metadata |

The schema is the same across all tables: `Timestamp`, `DeviceId`, `DeviceName`, an `InitiatingProcess*` group describing the actor, and event-specific fields.

### C.2.2 Queries that come up repeatedly

**Process tree of a suspicious binary, by SHA-256:**

```kql
DeviceProcessEvents
| where SHA256 == "4f8b2c1a8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

**All hosts that have ever seen a particular file path:**

```kql
DeviceFileEvents
| where FolderPath == "C:\\Users\\hr-user\\AppData\\Local\\hp-hotkey\\hpkey.exe"
| summarize first_seen = min(Timestamp), last_seen = max(Timestamp),
            actions = make_set(ActionType)
            by DeviceName
```

**Outbound connections to an indicator IP:**

```kql
DeviceNetworkEvents
| where RemoteIP == "91.214.47.22"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          RemoteIP, RemotePort, ActionType
| sort by Timestamp asc
```

**PowerShell executions with encoded commands:**

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("EncodedCommand", "-enc ", " -e ", "-encod")
| where TimeGenerated > ago(7d)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

**Service installations (parallel to System log EID 7045) across the fleet:**

```kql
DeviceRegistryEvents
| where TimeGenerated > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey startswith "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services"
| where RegistryValueName == "ImagePath"
| where RegistryValueData !startswith "C:\\Windows\\System32\\" 
        and RegistryValueData !startswith "\\??\\C:\\Windows\\system32\\"
| project Timestamp, DeviceName, RegistryKey, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
```

**Reading the process tree for a specific event** — a common follow-up after you find something suspicious:

```kql
DeviceProcessEvents
| where DeviceName == "WKSTN-221" and Timestamp between (datetime(2024-11-14 14:19:00) .. datetime(2024-11-14 14:25:00))
| project Timestamp, ProcessId, FileName, ProcessCommandLine,
          InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

The output is the process tree in chronological order. Follow the parent ID column to reconstruct the chain.

### C.2.3 Live response

MDE includes a Live Response feature that gives the responder a constrained shell on the endpoint. Useful commands:

```
getfile "C:\Users\hr-user\AppData\Local\Temp\suspect.exe"
processes
network
findfile <SHA256>
run <library script>
library
```

The `library` is a folder of approved PowerShell scripts available to live response sessions. A small library of triage scripts, such as ones that collect Prefetch or collect the MFT via FTK Imager CLI, makes investigation much faster.

## C.3 CrowdStrike Falcon

Falcon's Investigate UI uses Falcon Query Language (FQL). The underlying telemetry is in the Event Search.

Key event types:

| Event | Meaning |
|---|---|
| `ProcessRollup2` | Aggregated process-creation event; contains command line, parent, hashes |
| `NetworkConnectIP4` / `NetworkConnectIP6` | Network connection with owning process |
| `DnsRequest` | DNS lookup, with owning process |
| `FsBaseFileWritten` / `FsBaseFileDeleted` | File events |
| `ScriptControlScanTelemetry` | AMSI / Script Control telemetry — capture of script content blocked or scanned |

Falcon's UI is more click-and-drill than KQL-style, but the API supports the same kinds of queries:

```fql
event_simpleName=ProcessRollup2 AND CommandLine=*EncodedCommand*
| table @timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, ParentCommandLine
```

For network attribution:

```fql
event_simpleName=NetworkConnectIP4 AND RemoteAddressIP4="91.214.47.22"
| table @timestamp, ComputerName, FileName, CommandLine, RemoteAddressIP4, RemotePort
```

CrowdStrike's **Real-Time Response (RTR)** is the equivalent of MDE Live Response — a constrained shell on the endpoint.

## C.4 SentinelOne

SentinelOne's Deep Visibility query surface is Lucene-style:

```
EventType = "Process Creation" AND TgtProcCmdLine ContainsCIS "EncodedCommand"
```

Common fields: `TgtProcImageName`, `TgtProcCmdLine`, `TgtProcParentName`, `SrcProcCmdLine`, `RemoteIP`, `RemotePort`. Storyline, the platform's most distinctive feature, aggregates related events into a single attack-graph view.

For live response, SentinelOne also supports a remote PowerShell-like session through the management console.

## C.5 Common Cross-Vendor Patterns

Whatever the vendor, six queries appear in every IR investigation:

1. **Process trees rooted at suspicious parents.** Office applications spawning script interpreters, `wmiprvse.exe` spawning `cmd.exe`, `services.exe` spawning unusual children.

2. **Encoded PowerShell.** Almost every modern intrusion uses `-EncodedCommand` somewhere.

3. **Binaries running from user-writable paths.** `AppData\Local\Temp\`, `Public\`, `ProgramData\` (when world-writable subfolders exist).

4. **LOLBins called with unusual arguments.** `mshta http://...`, `regsvr32 /s /u /i:http://...`, `rundll32 javascript:`, `certutil -urlcache -f`. Living-off-the-land binaries are the most common modern delivery mechanism.

5. **Fleet-wide hash searches.** Once you confirm a malicious hash on one host, a single query finds every other host that has seen it.

6. **Logon-event correlation across hosts.** The `DeviceLogonEvents` table, or its vendor equivalent, is easier to query than per-host Security.evtx exports, especially for finding lateral-movement patterns.

## C.6 Sysmon: When You Want EDR-Class Telemetry Without an EDR

[Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) is a free Microsoft Sysinternals driver that writes high-fidelity event telemetry to a dedicated event log channel (`Microsoft-Windows-Sysmon/Operational`). With a good configuration, Sysmon produces process, network, file, registry, image-load, and DNS telemetry comparable to a commercial EDR, minus the central console and cross-host querying.

For shops that don't have EDR, or that want a redundant evidence source, Sysmon is the standard answer.

### C.6.1 Event IDs that matter

| EID | Meaning |
|---|---|
| 1 | Process Creation (with full command line, parent, image hash) |
| 2 | A process changed a file creation time (potential timestomping) |
| 3 | Network connection (with owning process, source/destination IP and port) |
| 5 | Process terminated |
| 7 | Image (DLL) loaded |
| 8 | CreateRemoteThread (process injection signal) |
| 10 | ProcessAccess (LSASS access, Mimikatz signal) |
| 11 | FileCreate |
| 12 / 13 / 14 | RegistryEvent (object created / value set / key/value renamed) |
| 15 | FileCreateStreamHash (alternate data stream creation) |
| 17 / 18 | NamedPipeEvent (creation / connect) |
| 22 | DNS query |
| 23 | FileDelete (with archive of the deleted file's content if configured) |
| 25 | ProcessTampering (image change detection — common in process hollowing) |

EIDs 1, 3, 10, 11, 22, and 23 cover most typical IR analysis. EID 10 (ProcessAccess targeting `lsass.exe`) is the single highest-value Sysmon event for credential-theft detection.

### C.6.2 Configuration

Sysmon's value depends entirely on its configuration. A blank install logs almost nothing useful. A thoughtful configuration logs the right events and excludes the noise.

The standard public configuration is **[SwiftOnSecurity's Sysmon config](https://github.com/SwiftOnSecurity/sysmon-config)**, which is well-commented and forms the basis of most enterprise Sysmon deployments. Other widely used configs include [Olaf Hartong's sysmon-modular](https://github.com/olafhartong/sysmon-modular), which is more granular and lets you assemble per-technique modules.

Install with:

```
Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

Update the configuration without reinstalling:

```
Sysmon64.exe -c sysmonconfig-export.xml
```

Verify what's running:

```
Sysmon64.exe -c
```

### C.6.3 Querying Sysmon with EvtxECmd or Get-WinEvent

Sysmon writes to `Microsoft-Windows-Sysmon%4Operational.evtx` in the standard Windows event log location, so all the tools from Chapter 9 work directly:

```powershell
# Process creation events for a specific binary
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterHashtable @{Id=1} |
    Where-Object { $_.Properties[4].Value -eq "powershell.exe" } |
    Select-Object TimeCreated,
        @{Name="CommandLine"; Expression={$_.Properties[10].Value}},
        @{Name="ParentImage"; Expression={$_.Properties[20].Value}}
```

```
# Convert all Sysmon events to CSV
EvtxECmd.exe -f "C:\Triage\WKSTN-221\Microsoft-Windows-Sysmon%4Operational.evtx" --csv "C:\Cases\WKSTN-221\sysmon\"
```

### C.6.4 Shipping Sysmon to a SIEM

Sysmon by itself is per-host. For cross-host queries, ship the events through Windows Event Forwarding (WEF) to a collector. Alternatively, use a dedicated log shipper, such as Winlogbeat, NXLog, or the Sentinel agent, to push the channel into a SIEM.

In Sentinel, Sysmon events arrive in the `Event` table by default. The standard Sentinel Sysmon parser, the `Sysmon` function, normalizes them:

```kql
Sysmon
| where TimeGenerated > ago(1d)
| where EventID == 1
| where CommandLine has "EncodedCommand"
| project TimeGenerated, Computer, Image, CommandLine, ParentImage, ParentCommandLine
```

## C.7 AMSI, ASR, and Defender's Operational Logs

Windows Defender produces several operational logs that pair well with Sysmon and EDR:

### C.7.1 Defender Operational

`Microsoft-Windows-Windows Defender/Operational` records detections, scans, and exclusions:

| EID | Meaning |
|---|---|
| 1006 / 1007 | Malware detection / action taken |
| 1116 / 1117 | Antimalware platform detection |
| 5001 / 5004 / 5007 | Real-time protection state changes (5007 = configuration changed; if RTP was disabled, this fires) |
| 5010 | Defender service stopped — common attacker action |
| 1131 | Tamper protection event |

EID 5007 with the value "Real-time protection disabled" and EID 5010 service-stop events are red flags, because attackers commonly disable Defender before deploying tooling.

### C.7.2 AMSI

The Antimalware Scan Interface (AMSI) lets script engines submit content to Defender for scanning before execution. AMSI events appear in the Defender operational log when scans detect content. AMSI bypass is one of the most common attacker techniques against PowerShell-based payloads, so:

- **AMSI scan failures or "AmsiScanBuffer failed" events** in PowerShell error logs are sometimes a bypass attempt
- **PowerShell EID 4104 records the script-block content even after AMSI bypass**, because Script Block Logging happens at a lower level than AMSI

Script Block Logging is therefore the practical answer to AMSI bypass: it captures the content that AMSI did not get to scan.

### C.7.3 Attack Surface Reduction (ASR)

ASR rules in Defender block specific attacker techniques, such as Office spawning child processes, `wscript`/`mshta` launched from Office, and JavaScript downloading payloads. ASR events appear in the Defender operational log:

| EID | Meaning |
|---|---|
| 1121 | ASR rule blocked an action |
| 1122 | ASR rule audited an action (block mode disabled) |

For incident response, ASR audit-mode events are particularly valuable, because they show the technique was attempted even when it was not blocked.

## C.8 Putting It Together: EDR Plus Sysmon Plus Logs

This worked example uses all three:

1. **EDR alert.** MDE flags `powershell.exe` PID 5128 on `WKSTN-221` for an encoded command line.
2. **EDR cross-host check.** Query `DeviceProcessEvents` across the fleet for the same SHA-256 of the encoded payload. The results confirm that 3 other hosts had related activity in the last hour.
3. **Sysmon corroboration.** On WKSTN-221, Sysmon EID 1 records the process with its full command line, parent (`outlook.exe`), and image hash. EID 3 records the network connection to the C2 IP. EID 22 records the DNS query, or shows its absence if the connection used an IP literal.
4. **Defender event log.** EID 1006 may show that Defender detected the dropped binary later. Check for a matching action record, EID 1007. A detection with no action means Defender saw the binary but did not block it.
5. **Security event log.** EID 4688 corroborates the process creation. EID 4104 (PowerShell) carries the decoded script-block content.

Assembled, these steps place the event in five independent telemetry sources, so removing any one of them does not destroy the finding.

## C.9 Pointers for Going Deeper

For Microsoft Defender for Endpoint specifically, the **Microsoft Defender XDR Hunting documentation** (`learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview`) is the authoritative reference for the Advanced Hunting schema and example queries.

The **CrowdStrike Falcon Query Language Reference** in the Falcon Help Center documents FQL.

For Sysmon, the [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config), [sysmon-modular](https://github.com/olafhartong/sysmon-modular), and the **Microsoft Sysmon documentation** are the starting points. In many cases, the `Sysmon.exe -? config` output is more useful than the website docs.

For AMSI bypass and PowerShell-related detections, the Black Hills Information Security blog and the SpecterOps blog publish ongoing technique research.

For comparing detection coverage across EDR vendors, the annual **MITRE ATT&CK Evaluations** publish detailed per-vendor results that are useful for understanding strengths and gaps.

---

*End of Appendix C.*

---
