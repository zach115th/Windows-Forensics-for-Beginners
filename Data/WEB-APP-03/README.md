# WEB-APP-03 — Simulated Memory Forensics Dataset

Anchor scenario for **Lab 07 — Memory Forensics**. This folder contains simulated Volatility 3 plugin output for a single memory image acquired from `WEB-APP-03`. Use it to work through the Lab07 tasks (process enumeration, command-line review, DLL review, network review, and `malfind`) without having to acquire and parse a real memory image.

## Scenario

`WEB-APP-03` is a Windows Server 2019 internal application server that hosts a line-of-business web application behind IIS. The host is part of the same incident as `WKSTN-221`: SOC analysts triaging the `update.exe` activity on the workstation found that `91.214.47.22` had also been contacted from the server side of the network later the same week, and pivoted onto `WEB-APP-03` to look for follow-on activity.

By the time memory was captured:

- EDR had observed a brief `powershell.exe` execution as a child of `w3wp.exe` (the IIS worker process)
- A short-lived service had appeared and disappeared in `System.evtx`
- The SOC suspected an in-memory web shell or post-exploitation tool
- The host had **not** been rebooted

Memory was acquired with **WinPmem 4.0.rc1** at **10:42 UTC on 2024-11-21** to a USB-attached evidence drive, hashed (SHA-256), and copied to the analysis workstation. The output files in this folder represent what an analyst would have after running standard Volatility 3 plugins against the resulting `WEB-APP-03_memory.raw` image.

## Key timestamps (UTC, 2024-11-21)

| Time | Event | Observable in |
|---|---|---|
| 09:00:14 | `w3wp.exe` (AppPool1) started by `WAS` (normal IIS startup) | `volatility-pslist.txt`, `volatility-pstree.txt` |
| 10:18:42 | `cmd.exe` (PID 3580) and `powershell.exe` (PID 3704) spawned as direct children of `w3wp.exe`, in the same second | `volatility-pslist.txt`, `volatility-pstree.txt` |
| 10:18:42 | The `powershell.exe` created at that second carries `-EncodedCommand` (`cmdline` records no time; the time is the `pslist` CreateTime) | `volatility-cmdline.txt` |
| 10:19:01 | Outbound TCP/443 connection established to `91.214.47.22` from the suspicious `powershell.exe` | `volatility-netscan.txt` |
| 10:19:14 | `cmdshell.dll` loaded into the `w3wp.exe` worker from `C:\Windows\Temp\` | `volatility-dlllist.txt` |
| 10:21:30 – 10:23:11 | `whcs.exe` (PID 3756), the `WindowsHealthCollector` service binary, runs under `services.exe` and exits; the service is left `SERVICE_STOPPED` | `volatility-pslist.txt` (CreateTime / ExitTime), `volatility-svcscan.txt` (state) |
| 10:42:08 | `winpmem.exe` started | `volatility-pslist.txt` |
| 10:42:11 | Memory image acquired with WinPmem | `volatility-info.txt` (`SystemTime`) |

## Files

| File | Volatility 3 Plugin | What an analyst would notice |
|---|---|---|
| `volatility-info.txt` | `windows.info` | Confirms image is Windows Server 2019 (build 17763), x64, single layer; system time at acquisition aligns with the WinPmem run |
| `volatility-pslist.txt` | `windows.pslist` | All expected system processes plus `w3wp.exe`, the IIS worker for `AppPool1` (its `-ap` argument in `cmdline`); `cmd.exe` and `powershell.exe` are children of `w3wp.exe` — an unusual parent-child relationship that should not occur on a healthy IIS host |
| `volatility-pstree.txt` | `windows.pstree` | Same data as `pslist` but indented; the `w3wp.exe` branch with `cmd.exe` and `powershell.exe` as sibling children (PPID 2860 for both, not a `cmd.exe → powershell.exe` chain) is visually obvious |
| `volatility-cmdline.txt` | `windows.cmdline` | Most processes have benign command lines; the suspicious `powershell.exe` has `-NoProfile -WindowStyle Hidden -EncodedCommand …` (a base64 blob). The `cmd.exe` beside it has no arguments: an interactive shell driven over redirected input, so its commands are not in `cmdline` |
| `volatility-netscan.txt` | `windows.netscan` | Listening ports 80, 443, 445, 3389, 5985 are expected; the established connection to `91.214.47.22:443` owned by the suspicious `powershell.exe` is **not** expected and matches the C2 IP from the `WKSTN-221` scenario |
| `volatility-malfind.txt` | `windows.malfind` | Three suspicious memory regions; the most important is in the suspicious `powershell.exe` and shows the classic `4D 5A 90 00` (`MZ`) PE header — consistent with a reflectively loaded module or shellcode-stage PE; a second hit in `svchost.exe` (PID 1142) is consistent with code injection from the powershell process; the third is in `w3wp.exe` (PID 2860) |
| `volatility-dlllist.txt` | `windows.dlllist --pid <w3wp PID>` | Expected IIS / .NET / Windows DLLs plus a non-standard `cmdshell.dll` loaded from `C:\Windows\Temp\` — outside the normal load paths and not signed |
| `volatility-svcscan.txt` | `windows.svcscan` | A `WindowsHealthCollector` service whose binary path is `C:\Windows\Temp\whcs.exe` and whose state is `SERVICE_STOPPED` — a service name that does not match any legitimate Microsoft service and a binary path that is not used for legitimate services |
| `volatility-handles.txt` | `windows.handles --pid <powershell PID>` | File and named-pipe handles for the suspicious `powershell.exe`, including handles to `\Device\NamedPipe\…` entries and `C:\Windows\Temp\` files that align with the `cmdshell.dll` and `whcs.exe` evidence |

## What you will and won't find

The dataset is curated for the Lab 07 tasks. It contains:

- A complete enough process listing (58 rows) to make `pslist` / `pstree` review non-trivial
- Enough listening sockets and established connections to make `netscan` review realistic
- A small but coherent set of `malfind` hits, suspicious DLLs, and suspicious handles that line up with the same suspicious `powershell.exe`
- Cross-host correlation with `WKSTN-221` via the shared `91.214.47.22` C2 IP

It does not contain:

- The full DLL list for every process on the host (only the suspicious `w3wp.exe`)
- A full dump of every handle for every process (only the suspicious `powershell.exe`)
- The decoded base64 PowerShell payload (decoding it is left to the reader as a Lab 07 exercise)
- A real PE binary in the `malfind` region; the visible bytes are illustrative

Two things in the process list are expected rather than suspicious:

- `csrss.exe` (436, 532) and `wininit.exe` (524) list parent PIDs 428 and 516, which are not in the list. Those parents are the per-session `smss.exe` instances, which exit once their session starts. An absent parent here is normal.
- `w3wp.exe`'s parent is `WAS.exe` (PID 2712, `C:\Windows\System32\inetsrv\WAS.exe`). That is a simplification: on a real IIS host, WAS and W3SVC share one `svchost.exe -k iissvcs`, so the worker's parent is that `svchost.exe`. Here W3SVC runs in its own `svchost.exe -k iissvcs` (PID 2780).

## Note on the encoded PowerShell command

`volatility-cmdline.txt` contains the suspicious `powershell.exe` command line with an `-EncodedCommand` argument. The base64 decodes to a short download cradle similar in structure to the `WKSTN-221` payload, calling back to the same C2 IP. Decoding is part of Lab 07 Task 6 (command-line review) and Lab 09 (correlation across hosts).

## Cross-host correlation

`91.214.47.22` is the same C2 IP used in the `WKSTN-221/` dataset. This is intentional — the labs use a shared IP across two different hosts so that responders can practice pivoting from one case onto another and recognize that two outwardly different incidents share infrastructure.

---

*Simulated WEB-APP-03 dataset — Windows Forensics for Beginners*
