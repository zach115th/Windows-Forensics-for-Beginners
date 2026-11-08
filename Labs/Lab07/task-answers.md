# Lab 07 — Task Answer Key

*Sample answers for the workbook-style Tasks in `Labs/Lab07/ReadMe.md`. These are reference answers, not the only correct answers — your wording may legitimately differ. The reasoning matters more than the prose. For the Hands-On Walkthrough at the end of the lab, see `walkthrough-answers.md` in the same folder.*

---

## Task 1 — Explain Why Memory Matters

**Sample explanation:**

Memory analysis is valuable in Windows incident response because the most volatile and often most decisive evidence lives only in RAM. Live process state, established sockets, injected code regions, and loaded modules can all disappear the moment the host reboots. So can in-memory secrets such as plaintext passwords or session tokens, and the command-line arguments of short-lived processes. Fileless and EDR-aware tradecraft is designed to minimize disk artifacts. A reflective loader, a PowerShell cradle running an encoded command in memory, or a process-hollowed implant may leave little or nothing useful on disk while remaining plainly visible in a memory image. In those cases disk evidence alone gives an incomplete and sometimes actively misleading picture, because the relevant facts are running in RAM right now and will be gone on the next reboot.

**Sample table:**

| Investigative Question | Memory Forensics Value | Why |
|---|---|---|
| Did a suspicious process likely exist in RAM? | Strongly useful | `pslist` / `psscan` / `pstree` are direct evidence; can recover unlinked processes |
| Did a short-lived process leave useful live-response traces? | Partially useful | Memory may carry residual structures even after termination; depends on time since exit |
| Was code injected into another process? | Strongly useful | `malfind` and DLL/module review are the canonical signals for injected code |
| Were suspicious network connections active? | Strongly useful | `netscan` ties sockets to owning processes — per-process attribution disk lacks |
| Did a malicious file exist on disk? | Not very useful | Memory rarely answers disk-presence questions well; MFT / Amcache are better |
| Were credentials or tokens potentially present in memory? | Strongly useful | LSASS memory may contain Kerberos tickets, NTLM hashes, plaintext when WDigest is on |

**Q1:** Why is memory especially valuable in fileless cases?

Fileless intrusions deliberately avoid writing executable code to disk. Reflective loaders unpack into memory, PowerShell `-EncodedCommand` cradles execute in-process, .NET Assembly.Load runs DLLs that never touched the file system, and process-injection techniques hide payload code inside legitimate processes. Disk artifacts may show only legitimate Windows binaries running. The malicious code itself exists only in RAM, so capturing memory before the host reboots is often the only way to recover it. The WEB-APP-03 case is exactly this pattern: `malfind` flags `PAGE_EXECUTE_READWRITE` private regions inside `powershell.exe`, `svchost.exe`, and `w3wp.exe` with no backing file on disk.

**Q2:** Why is memory usually time-sensitive evidence?

Normal system operation overwrites memory continuously, and a reboot clears it almost entirely. Even without a reboot, paged-out regions can be lost to the page file, and short-lived processes may have their EPROCESS structures unlinked and overwritten in minutes. If you suspect a memory-resident implant, the right answer is usually "capture now, analyze later," because every minute of delay costs evidence. A memory image is also a single-point-in-time snapshot. You cannot go back and re-acquire what was running an hour ago.

**Q3:** Why should responders still avoid treating memory as a complete answer by itself?

Memory captures live state at one instant. It does not answer how the implant got there, when it was first installed, whether the same attacker is on other hosts, or what data has already been exfiltrated. It can also mislead. A `malfind` hit may flag legitimate JIT-compiled code from browsers or the .NET runtime as readily as it flags malware. Memory is one input among several, and the strong cases pair memory findings with disk, logs, EDR telemetry, and network evidence.

---

## Task 2 — Identify the Tools and Their Roles

**Sample table:**

| Tool | Primary Role | Why It Matters | Limitation |
|---|---|---|---|
| Volatility 3 | Plugin-based memory analysis framework, current generation | Active development, modern Windows symbol support, extensive plugin set | Plugin output is line-based and can be unwieldy at scale |
| Volatility 2.x | Legacy memory analysis framework | Some plugins and community workflows still target it; profile-based | Profile selection is fragile; superseded by Vol 3 for current Windows |
| Rekall | Forked memory framework | Some unique plugins and live-system support | Archived and no longer maintained |
| MemProcFS | Mounts a memory image as a virtual file system | Browse processes / modules / handles / registry as files; trivial `findstr` / `dir` workflows | Different mental model from plugin-based analysis |
| Redline | FireEye/Mandiant GUI memory and host analysis | GUI triage and IOC scanning; useful for non-specialist responders | Closed-source; limited compared to Volatility for deep analysis |
| WinPmem | Live memory acquisition (driver-based) | Open-source, widely accepted acquisition tool | Requires driver loading; modern Windows kernel protections complicate use |
| DumpIt | Lightweight live memory acquisition | Simple capture; common in field collection kits | Older tool; supplanted in some workflows by `winpmem` or vendor tooling |

**Q1:** Why is it useful to separate acquisition tools from analysis tools?

Acquisition has a different risk profile than analysis. The acquisition tool runs on the live host, loads a kernel driver, touches memory pages, and produces an artifact whose integrity must be defensible. The analysis tool runs offline against the artifact and is essentially read-only. Keeping the two roles separate lets you choose the lowest-impact acquisition path for the live host while still having a rich analysis stack offline. It also prevents the worst case, in which a problem in your analysis tool corrupts the original image.

**Q2:** Why might one responder prefer MemProcFS or Redline for triage but Volatility for deeper work?

MemProcFS exposes the image as a file tree, such as `M:\name\powershell.exe-3704\cmdline\`, `M:\name\<process>\modules\`, and `M:\registry\`. That tree is fast to navigate with familiar tools such as `dir`, `findstr`, and `Get-Content`, which suits triage when you want to look around. Redline gives a guided GUI experience. Volatility plugins encode specific analytical heuristics (`malfind`, `cmdline`, `netscan`, `svcscan`) that are repeatable and scriptable for deeper or comparative work. Many practitioners default to MemProcFS for exploration and reach for Volatility for hypothesis-driven plugins.

**Q3:** Why does tool choice matter for repeatability and defensibility?

A finding reported as "Volatility 3 v2.5.2 `windows.malfind` plugin against `WEB-APP-03_memory.raw` produced three hits" is reproducible by anyone with the same image and tool version. A finding reported as "I looked at the memory image and saw injected code" is not. For court use, peer review, and even a basic re-run of the analysis a year later, record the tool name and version, and make sure the same tool is available to anyone re-running the work.

---

## Task 3 — Capture Memory and Record Integrity

**Sample table (illustrative; values from a lab acquisition):**

| Field | Value |
|---|---|
| Host / VM Name | WEB-APP-03 |
| Acquisition Tool | WinPmem |
| Tool Version | 4.0.rc1 |
| Output File Name | `WEB-APP-03_memory.raw` |
| Output Path | `E:\Evidence\` (USB-attached evidence drive) |
| Approximate File Size | 16 GB |
| Hash Algorithm | SHA-256 |
| Hash Value | `7f3a... (full 64-hex digest)` |
| Acquisition Date/Time (UTC) | 2024-11-21 10:42:08 (`winpmem.exe` start; image `SystemTime` 10:42:11) |
| Notes / Warnings | One non-fatal smear warning during driver load; image parsed cleanly with `windows.info` |

**Q1:** Why should memory be hashed immediately after acquisition?

The hash is the chain-of-custody anchor for the image. If the file is modified later, accidentally or intentionally, the hash will no longer match the value recorded at acquisition. Hash before any other action: before parsing, before copying off the host, before writing notes. Record the hash, the algorithm, and the wall-clock time of the hash. Later analysis runs should never modify the image. They should operate on copies whose hashes also match the original.

**Q2:** Why does the acquisition tool and version matter?

Different tools, and even different versions of the same tool, can produce subtly different memory images. Page coverage varies, smear behavior varies, and some tools include hibernation or page-file content while others do not. A Volatility plugin that works on one tool's output may behave differently on another. Recording the exact tool and version lets later analysts reproduce your acquisition or know when their results may diverge legitimately.

**Q3:** Why should warnings or collection issues be documented even if a dump file was created?

An image captured with warnings may still be analyzable, but the warnings can foreshadow specific reliability gaps, such as smear during VAD parsing, partial coverage of high physical addresses, or kernel-page anomalies. Documenting them up front lets the next analyst weigh suspicious findings against known acquisition issues rather than chase false positives that were really acquisition artifacts. For forensic purposes, silent acquisitions are worse than noisy ones.

---

## Task 4 — Identify OS / Image Information

**Sample table (WEB-APP-03):**

| Question | What You Found | Why It Matters |
|---|---|---|
| OS family / version | Windows Server 2019, build 17763 | Confirms server SKU; affects which Volatility symbols and plugin behavior apply |
| Kernel or image characteristics | Kernel base, KdDebuggerDataBlock present, system time matches acquisition wall-clock | Image is parsable; clock alignment matters for timeline correlation |
| Architecture | x64 | Required for matching Volatility 3 Windows symbols |
| Other useful context | Acquisition time 2024-11-21 10:42 UTC; non-fatal smear at acquisition | Establishes the "as-of" time the rest of the analysis describes |

**Q1:** Why is confirming OS context one of the first steps in memory analysis?

Every subsequent plugin needs to know which Windows-version structures to use. Without OS context, plugins either fail outright, because Volatility 3 cannot resolve symbols, or silently produce wrong output. Running `windows.info` first is the sanity check. If it succeeds, the image is parsable. If it fails, no other plugin will work, and you should triage acquisition issues first.

**Q2:** Why can a wrong profile or wrong assumptions break later analysis?

In Volatility 2, the profile for a specific OS build drove all structure offsets. The wrong profile produced subtly incorrect results: slightly wrong process names, addresses off by a small offset, and plugins that crashed mid-run. Volatility 3 uses symbol packages that mostly auto-detect, but the same family of failures applies if the wrong symbol set is matched. Assumptions about pointer width, scheduler structures, or AppCompat layouts that are wrong for the actual build will produce confidently wrong output.

**Q3:** Why should system context be recorded in your analyst notes before deeper findings?

Every finding implicitly references "what host, what time, what OS." If the analyst notes record `WEB-APP-03 / Windows Server 2019 build 17763 / acquisition 2024-11-21 10:42 UTC` at the top, every downstream finding inherits that context. A reader who has only the deeper findings has to reconstruct it later. Recording provenance up front prevents misattribution when notes are excerpted into reports or shared between analysts.

---

## Task 5 — Enumerate Processes and Process Trees

**Sample table (four WEB-APP-03 findings plus two illustrative patterns that are not in this dataset):**

| Process | Why It Stands Out | Artifact / Command | What It Might Suggest | What It Does Not Prove |
|---|---|---|---|---|
| `powershell.exe` (PID 3704) | Direct child of `w3wp.exe` (PID 2860), created at 10:18:42 in the same second as `cmd.exe` | `windows.pstree` | IIS spawned a shell — never legitimate | That this specific PowerShell is malicious by itself |
| `cmd.exe` (PID 3580) | Parent is `w3wp.exe`; still running at capture (no exit time) | `windows.pstree` | Web shell mechanism | The commands run through it. Its `cmdline` is just `"cmd.exe"` with no `/c` argument, so they came in over redirected input |
| `w3wp.exe` (PID 2860) | Parent of both shells; loaded a DLL from `C:\Windows\Temp\` 32 seconds later | `windows.pstree`, `windows.dlllist` | Web shell in the IIS worker | What the DLL actually does |
| `svchost.exe` (PID 1142) | Has a `malfind` hit (PAGE_EXECUTE_READWRITE private region) | `windows.malfind` | Injection target | Which thread / which technique |
| `update.exe` (illustrative, not in this dataset) | Unexpected binary name, low-numbered PID | `pslist` / `psscan` | Renamed loader | Provenance — need disk artifact |
| Orphaned process (illustrative, not in this dataset) | Appears in `psscan` but not `pslist` | `windows.psscan` vs `windows.pslist` | Process unlinked from the active list (rootkit hiding) or simply exited just before capture | Conclusive rootkit behavior |

**Q1:** Why is it useful to compare `pslist`, `psscan`, and `pstree` rather than trusting just one view?

`pslist` walks the active-process list, which is fast but easy to hide from. `psscan` scans memory for EPROCESS structures, including ones that have been unlinked from the list, so it catches rootkit hiding and recently exited processes. `pstree` shows the parent-child hierarchy, which surfaces anomalies such as "IIS spawned a shell." Each view answers a slightly different question. Cross-comparing them catches both rootkit-style hiding, where `psscan` has rows that `pslist` does not, and tree-structural anomalies that only `pstree` shows.

**Q2:** Why do odd parent-child relationships matter in incident response?

Parent-child relationships are the cheapest anomaly signal Windows gives you. `services.exe` should spawn services, `wininit.exe` should spawn the boot tree, and `Explorer.exe` should spawn user-launched applications. `WINWORD.EXE` should not spawn `powershell.exe`, and `w3wp.exe` should not spawn `cmd.exe`. When the parent does not match the expected lifecycle, you have a strong lead with very little parsing effort. The WEB-APP-03 case is built on exactly this pattern. A `w3wp.exe` that spawns both `cmd.exe` and `powershell.exe` is structurally impossible in legitimate IIS operation.

**Q3:** Why is process path context sometimes as important as the process name itself?

A `powershell.exe` from `C:\Windows\System32\WindowsPowerShell\v1.0\` is the legitimate binary. A `powershell.exe` from `C:\Users\Public\` is almost certainly malware. The name alone is not informative, but the binary path is. The same goes for `svchost.exe`: `C:\Windows\System32\svchost.exe` is normal, and anywhere else is not. Always pull the full path before declaring a process name suspicious.

---

## Task 6 — Review Command Lines and Loaded DLLs

**Sample table (three processes from Task 5):**

| Process | Command-Line Clue | DLL / Module Clue | Why It Matters | What Still Needs Corroboration |
|---|---|---|---|---|
| `powershell.exe` (PID 3704) | `-NoProfile -WindowStyle Hidden -EncodedCommand <base64>` — base64 decodes to an `Invoke-WebRequest` → `IEX` cradle pointing at the C2 | No `dlllist` for this PID in the dataset; one `malfind` private region with `MZ` header (in-memory PE) | The encoded loader cradle is essentially conclusive for malicious PowerShell | Whether the decoded payload actually executed — needs network confirmation |
| `w3wp.exe` (PID 2860) | Standard IIS worker command-line | Loaded `cmdshell.dll` from `C:\Windows\Temp\` at 2024-11-21 10:19:14 | A DLL from `C:\Windows\Temp\` loaded into IIS is essentially never legitimate. It loaded 32 seconds after the shells spawned, so it is follow-on staging, not what launched them | What `cmdshell.dll` exposes — needs strings / binary analysis |
| `svchost.exe` (PID 1142) | Normal `-k` group argument | `malfind` PAGE_EXECUTE_READWRITE private region; handles into this process from PID 3704 | Indicates injection target — PowerShell injected into svchost | Which thread is executing the injected region; whether it's pre- or post-injection |

**Q1:** Why are command lines often more revealing than process names alone?

A process named `powershell.exe` is meaningless on its own, because PowerShell runs on every Windows host every day. The command line tells you what it was *told* to do. `-EncodedCommand <base64>`, an `-ExecutionPolicy Bypass`, a `-NoProfile -WindowStyle Hidden` triplet, or a `-Command "IEX (New-Object Net.WebClient).DownloadString(...)"` is direct evidence of malicious intent in the invocation itself. The same is true for `cmd.exe` (what was the `/c` argument?), `rundll32.exe` (which DLL and which export?), and `regsvr32.exe` (which COM target?).

**Q2:** Why can unusual DLLs or modules increase concern about a process?

Most legitimate Windows binaries load a predictable set of DLLs from `C:\Windows\System32\`. A `cmdshell.dll` loaded into `w3wp.exe` from `C:\Windows\Temp\` is two anomalies stacked: an unfamiliar DLL name *and* a non-standard load path. Either alone is suspicious, and both together are essentially conclusive. DLL review also catches reflective DLL injection, where a DLL has no on-disk backing, and DLL side-loading, where a legitimately named DLL sits in an unexpected directory.

**Q3:** Why should DLL review still be interpreted carefully rather than treated as proof of malware by itself?

Some legitimate applications load DLLs from unusual paths, such as third-party plugins, anti-cheat shims, virtualization helpers, and some endpoint agents. JIT engines and .NET runtimes generate memory regions that look superficially like injected code to `malfind`. The defensible reading is "a DLL loaded from `C:\Windows\Temp\` into `w3wp.exe` is highly suspicious and warrants follow-up." Confirm it by pulling the DLL, hashing it, submitting it to threat intel, and reversing it if needed. Do not skip those steps.

---

## Task 7 — Review Network Connections

**Sample table (three WEB-APP-03 findings plus two illustrative patterns that are not in this dataset):**

| Process / PID | Local Address | Remote Address | Why It Stands Out | What It Might Suggest |
|---|---|---|---|---|
| `powershell.exe` (3704) | `10.0.8.34:49918` | `91.214.47.22:443` | ESTABLISHED outbound; same C2 IP as WKSTN-221 dataset | Same attacker across hosts; C2 attribution |
| `System` (4) | `0.0.0.0:443` and `10.0.8.34:443` | `10.0.6.118:52312` | Port 443 belongs to PID 4, not `w3wp.exe`, because IIS listens through the HTTP.sys kernel driver | Expected IIS listener. The inbound connection from `10.0.6.118` opened at 10:17:55, 47 seconds before the shells spawned, so check it against the IIS logs |
| `svchost.exe` (1142) | None in `netscan` | n/a | Has a `malfind` hit but the injected region may have its own sockets | Injection persistence vehicle |
| `update.exe` (illustrative, not in this dataset) | `10.0.8.34:<ephemeral>` | unfamiliar IP:443 | Binary name does not match observed network behavior | Renamed loader |
| Dead connection (illustrative, not in this dataset) | (recorded by `netscan` as CLOSE_WAIT) | (suspicious IP) | Closed but still in memory | Recent C2 conversation that has just terminated |

**Q1:** Why is memory often one of the best places to connect network activity to a process?

`netscan` reads socket structures (Tcpip!_TCP_ENDPOINT, _TCP_LISTENER) and attributes each connection to the owning process by PID. That per-process attribution is exactly what perimeter network sources cannot give you. A firewall log shows the host had a session to `91.214.47.22:443`, but it cannot tell you *which process on that host* owned it. Memory closes that gap directly.

**Q2:** Why is a suspicious remote IP not automatically proof of C2 by itself?

An unfamiliar IP could belong to cloud infrastructure shared by legitimate and malicious tenants, such as Cloudflare, AWS, or Hetzner. It could also be a misconfigured legitimate service, or a one-off destination the user reached for a non-malicious reason. The strong case requires the IP, the owning process, and the protocol pattern, plus, ideally, threat-intel context or a recurring beacon cadence. A single packet capture to an unfamiliar IP is a lead, not a verdict.

**Q3:** Why do process, time, and network context matter together?

Process tells you who owned the connection. Time tells you when the connection happened in the larger incident timeline, for example by matching the encoded-command timestamp or the file creation of an injected DLL. Network context, meaning protocol, port, byte counts, and repetition cadence, tells you what kind of communication it was: beacon, data pull, or interactive. The combination is what makes a connection report defensible, and any one of them alone is incomplete.

---

## Task 8 — Run Malware-Oriented Review

**Sample table (three WEB-APP-03 findings plus one illustrative pattern that is not in this dataset):**

| Process | Malfind / Suspicious Region Finding | Why It Matters | Follow-Up Action |
|---|---|---|---|
| `powershell.exe` (3704) | `PAGE_EXECUTE_READWRITE` private region with `MZ` PE header at region start; no backing file | Fully-formed binary loaded into memory but not on disk — reflective load | Dump the region, hash the contents, submit to threat intel, reverse if needed |
| `svchost.exe` (1142) | `PAGE_EXECUTE_READWRITE` private region with `MZ` header at region start | Injection target — corroborated by handles from PID 3704 into this process | Dump and review the region; check thread creation events in EDR |
| `w3wp.exe` (2860) | `PAGE_EXECUTE_READWRITE` private region with `MZ` header at region start | A second in-memory PE inside the IIS worker, at a different address from the `cmdshell.dll` module | Dump and inspect; compare with the `cmdshell.dll` on disk and the other two regions |
| (Illustrative, not in this dataset) | Process with executable memory and unusual VAD layout | Could be JIT (benign) or reflective injection (malicious) | Strings + region dump to distinguish |

**Q1:** Why is `malfind` useful in injected-code or memory-resident implant cases?

`malfind` looks for memory regions that are executable, writable, and private, which is typical of injection, and whose content has no backing file on disk. That combination is rare in legitimate code and very common in injected payloads. A `malfind` hit immediately gives you a region to dump and inspect, so you do not have to search every process by hand. In the WEB-APP-03 case it flags exactly the three processes most likely to be the implant chain.

**Q2:** Why is a `malfind` hit only the beginning of the analysis?

Some legitimate runtime systems produce regions that match `malfind`'s heuristics, such as JIT compilers in browsers and .NET, virtualization helpers, and some EDR agents. A `malfind` hit means "this is worth dumping and reviewing," not "this is malware." The follow-up is to dump the region, look at strings, and check for an `MZ` PE header, the definitive sign of an in-memory binary. Then compare against known-good baselines if you have them.

**Q3:** Why is process dumping or region dumping useful after an initial suspicious hit?

Dumping recovers the actual payload code, which is what threat-intel, signature, and reverse-engineering work needs. A `malfind` hit by itself does not tell you whether the region contains shellcode, a reflective DLL, or a fully PE-formatted binary. Dumping gives you bytes you can hash, submit to multi-AV, and run YARA against. If you have the skills, you can also reverse them to recover IOCs that did not appear in the initial memory pass.

---

## Task 9 — Correlate the Memory Findings

**Sample table (three leads from WEB-APP-03):**

| Suspicious Lead | Supporting Artifact 1 | Supporting Artifact 2 | Supporting Artifact 3 | Combined Interpretation | Confidence |
|---|---|---|---|---|---|
| IIS web shell | `w3wp.exe` → `cmd.exe` and `w3wp.exe` → `powershell.exe` in `pstree` | `cmdshell.dll` loaded into `w3wp.exe` from `C:\Windows\Temp\` (`dlllist`) | Service `WindowsHealthCollector` with `C:\Windows\Temp\whcs.exe` (`svcscan`) — same staging directory | Web shell in the IIS worker, follow-on DLL staging, and service-style persistence | High |
| Active C2 from PowerShell | `powershell.exe` 3704 cmdline `-EncodedCommand` decoded to `Invoke-WebRequest`/`IEX` cradle | ESTABLISHED TCP from PID 3704 to `91.214.47.22:443` (`netscan`) | Same `91.214.47.22` IP appears in WKSTN-221 dataset | Active C2 to known infrastructure | High |
| Injection into svchost | `malfind` hit on PID 1142 (`svchost.exe`) | Handles into PID 1142 from PID 3704 (`handles`) | `whcs_ctrl` named pipe handle in 3704 (control channel) | PowerShell injected into svchost and maintains a named-pipe control channel | High |

**Q1:** Why is correlation more valuable than a single suspicious plugin hit?

Each plugin has its own false-positive profile. `malfind` can flag JIT code. `pstree` anomalies can sometimes reflect unusual but legitimate launches. `netscan` can show short-lived connections to cloud providers. When three independent plugins all point at the same process tree, it is implausible that all of them are false positives at once. That multi-source convergence is what turns "suspicious" into "confidently malicious."

**Q2:** Why should responders describe confidence instead of certainty in many memory cases?

Memory snapshots are point-in-time, partial, and dependent on tool interpretation. Even strong findings are inferences from data structures the kernel was maintaining at the moment of capture. Describing confidence, as in "high confidence the host is running an IIS web shell with active C2," signals the analytical maturity of the conclusion. It also leaves room to update the conclusion when more evidence arrives. Certainty in a memory finding is rarely warranted before cross-source corroboration.

**Q3:** Which combinations of memory findings would most strongly justify escalation?

Three combinations that meet most escalation bars:

1. An impossible process tree, such as `w3wp.exe → cmd.exe → powershell.exe` or `WINWORD.EXE → powershell.exe → mshta.exe`, plus an encoded PowerShell command line.
2. A `malfind` hit with an `MZ` header in a private region of a non-runtime process, plus a `netscan` ESTABLISHED connection from that process to an external IP.
3. A DLL loaded into a system service from `C:\Windows\Temp\` or `C:\Users\Public\`, plus a service record pointing to a binary in the same directory.

Any of these is enough to escalate to active containment.

---

## Task 10 — Separate Strong Support from Overclaims

| Statement | Classification | Why |
|---|---|---|
| A suspicious process was present in memory | Strongly supported | `pslist`/`psscan` is direct evidence — the structure was there |
| A suspicious process had an unusual parent-child relationship | Strongly supported | `pstree` shows the relationship explicitly |
| The process was definitely controlled by an external attacker | Suggested but needs corroboration | Need network evidence to a controlled endpoint plus attribution context |
| A suspicious network connection was associated with a process of interest | Strongly supported | `netscan` PID attribution is direct |
| Memory contains indications of code injection or suspicious regions | Strongly supported (as a finding, not as a verdict) | `malfind` hits are well-defined; what they mean is interpretive |
| The suspicious process stole credentials from the user | Not supported by these artifacts alone | Memory may suggest LSASS access; theft requires more evidence |
| The host shows signs consistent with a memory-resident implant | Strongly supported (when multiple findings converge) | `malfind` + `netscan` + impossible `pstree` + DLL from Temp is exactly this picture |
| The attacker used this process for data exfiltration | Suggested but needs corroboration | Need byte counts, content recovery, or destination context to confirm |

**Six added statements (sample):**

| Statement | Classification | Why |
|---|---|---|
| `cmdshell.dll` loaded into `w3wp.exe` from `C:\Windows\Temp\` is a web-shell mechanism | Suggested but needs corroboration | Path and DLL name are diagnostic of malicious staging. It loaded at 10:19:14, 32 seconds after the shells spawned, so it did not launch them. Its role needs strings or binary analysis |
| `91.214.47.22` is attacker infrastructure | Suggested but needs corroboration | Same IP across hosts is suggestive; threat-intel or WHOIS context is the next step |
| The encoded PowerShell command's payload executed | Suggested but needs corroboration | The cradle is in memory; need network confirmation or recovered payload to confirm execution |
| PowerShell injected code into `svchost.exe` | Strongly supported | `malfind` + handles from 3704 → 1142 is direct evidence |
| The attacker exfiltrated data from this host | Not supported by these artifacts alone | Need byte counts, content review, or destination evidence |
| The implant survives reboot | Not supported by these artifacts alone | `svcscan` records `WindowsHealthCollector` as `SERVICE_DEMAND_START`, so it does not start at boot on its own. Confirm the registry `Start` value and look for another trigger, such as a scheduled task |

---

## Task 11 — Build a Memory-Hunt Timeline

**Sample 10-row timeline (WEB-APP-03):**

| Time (UTC) | Artifact Source | Event or Observation | Process / Region / Connection | Why It Matters |
|---|---|---|---|---|
| 2024-11-21 10:18:42 | `pslist` / `pstree` | `w3wp.exe` spawned `cmd.exe` and `powershell.exe` in the same second | 2860 → 3580, 2860 → 3704 | Impossible-for-IIS parent-child relationship |
| 2024-11-21 10:18:42 | `pslist` + `cmdline` | PowerShell 3704 created with `-EncodedCommand` | PID 3704 | Encoded loader cradle |
| 2024-11-21 10:19:01 | `netscan` | ESTABLISHED TCP `10.0.8.34:49918 → 91.214.47.22:443` | PID 3704 | Active C2, 19 seconds after PowerShell started |
| 2024-11-21 10:19:14 | `dlllist` | `cmdshell.dll` load timestamp into `w3wp.exe` | PID 2860 | Follow-on staging. It loaded after the shells and the C2 connection, so it did not launch them |
| No timestamp (present at capture) | `malfind` | `MZ`-headed private region in PowerShell 3704 | PID 3704 | Reflective loader payload |
| No timestamp (present at capture) | `handles` | PID 3704 holds Process and Thread handles into PID 1142, plus the `whcs_ctrl` named pipe | 3704 → 1142 (`whcs_ctrl` pipe) | Injection into svchost with control pipe |
| No timestamp (present at capture) | `malfind` | `MZ`-headed PAGE_EXECUTE_READWRITE region in svchost | PID 1142 | Injection target confirmed |
| No timestamp (present at capture) | `svcscan` | `WindowsHealthCollector` service present, `SERVICE_STOPPED`, binary `C:\Windows\Temp\whcs.exe` | Service record | Persistence vehicle from same staging directory |
| No timestamp (present at capture) | `malfind` | `MZ`-headed region in `w3wp.exe` itself | PID 2860 | The IIS worker is also carrying injected code |
| 2024-11-21 10:42:11 | `windows.info` (`SystemTime`) | Memory captured | WEB-APP-03 image | The "as-of" timestamp the whole memory analysis describes |

The `cmdline` plugin records no time, so the second row uses the process creation time from `pslist`. The `malfind`, `handles`, and `svcscan` rows also carry no timestamps. They describe state at the 10:42:11 capture, not when each event happened.

**Q1:** Which timeline entries appear most central to the possible implant theory?

The load-bearing entries are the `cmdshell.dll` load timestamp, the `w3wp.exe` that spawned both `cmd.exe` and `powershell.exe`, the `-EncodedCommand` PowerShell invocation, the ESTABLISHED TCP from PID 3704 to `91.214.47.22:443`, and the `malfind` hits with `MZ` headers in non-runtime processes. Each one is independently strong, and together they describe a single coherent implant.

**Q2:** Which entries are supportive but not decisive?

The named-pipe handle name (`whcs_ctrl`) and the `WindowsHealthCollector` service in `svcscan` are supporting context. They corroborate the injection target and the persistence direction but are not themselves the load-bearing evidence. Likewise, the `malfind` hit on `w3wp.exe` also begins with an `MZ` header, but no handle or connection ties it to the other findings. It supports the broader chain and is weaker than the PID 3704 hit, which has tied-back C2.

**Q3:** What major gaps remain after the memory hunt?

Four major gaps remain. The first is how the web shell got there originally, which needs IIS logs and a file-creation timeline for `cmdshell.dll`. The second is when `WindowsHealthCollector` was registered, which needs System.evtx EID 7045 or registry timestamps. The third is what the `MZ`-headed region in PowerShell actually does, which needs a binary dump and reverse engineering. The fourth is whether other hosts on the network are running the same implant, which needs an EDR sweep for `cmdshell.dll`, `whcs.exe`, `91.214.47.22`, and the encoded-command pattern.

---

## Task 12 — Write the Analyst Note

**Sample analyst note:**

Memory acquisition of WEB-APP-03 (Windows Server 2019 build 17763, acquired 2024-11-21 10:42 UTC) shows a coherent in-memory implant chain. The process tree shows the IIS worker process `w3wp.exe` (PID 2860) as the direct parent of both `cmd.exe` (PID 3580) and `powershell.exe` (PID 3704), created at 2024-11-21 10:18:42 UTC. IIS workers do not spawn shells in legitimate operation. PowerShell PID 3704 was launched with `-NoProfile -WindowStyle Hidden -EncodedCommand <base64>`, and the decoded payload is an `Invoke-WebRequest` → `IEX` cradle pointed at the external C2. At 2024-11-21 10:19:14 UTC, 32 seconds after the shells spawned, `w3wp.exe` loaded a non-Microsoft DLL named `cmdshell.dll` from `C:\Windows\Temp\`. That path and name are essentially never legitimate in a production IIS worker.

`netscan` shows an ESTABLISHED TCP connection from PID 3704 (`powershell.exe`) at `10.0.8.34:49918` to `91.214.47.22:443`. The same IP appears in the WKSTN-221 dataset, suggesting the same attacker across hosts. `malfind` flags three processes (3704, 1142, 2860) with `PAGE_EXECUTE_READWRITE` private regions. All three regions begin with an `MZ` header, consistent with in-memory PEs. `handles` shows PID 3704 holding Process and Thread handles into PID 1142 (`svchost.exe`) and a named pipe `\\.\pipe\whcs_ctrl`, indicating injection into svchost with a control channel. `svcscan` shows a service `WindowsHealthCollector` with binary path `C:\Windows\Temp\whcs.exe`, currently stopped, in the same staging directory as the `cmdshell.dll` load.

Strongly supported: a memory-resident implant chain is present, with an IIS worker that spawned shells, an encoded PowerShell cradle as the second stage, active C2 to `91.214.47.22:443`, injection into svchost, and a service-style persistence record rooted in `C:\Windows\Temp\`. Still requiring corroboration: when the implant was originally installed (need MFT $STANDARD_INFORMATION and IIS logs); the full payload behavior of the in-memory PE (need region dump + analysis); whether other hosts carry the same implant (need EDR sweep for IOCs). Recommended next: dump and hash the `MZ`-headed region in PID 3704; pull MFT and IIS logs around 2024-11-21 10:19; sweep EDR across the environment for `cmdshell.dll`, `whcs.exe`, `91.214.47.22`, and the encoded-command pattern; consider containment of WEB-APP-03 with memory captured.

---

## Task 13 — Write an Analyst Handoff Note

**Sample handoff note:**

```
Case Reference:    IR-2024-1121-WEBAPP03
Author:            (your name)
Date/Time (UTC):   2024-11-21 11:30

Most Important Memory Findings:
- pstree: w3wp.exe (2860) spawned cmd.exe (3580) and powershell.exe (3704),
  both at 2024-11-21 10:18:42
- dlllist: cmdshell.dll loaded into w3wp.exe from C:\Windows\Temp\ at
  2024-11-21 10:19:14
- malfind: PAGE_EXECUTE_READWRITE regions in PIDs 3704, 1142, 2860;
  all three begin with an MZ header (in-memory PE)
- svcscan: WindowsHealthCollector service, binary C:\Windows\Temp\whcs.exe

Most Important Process / Network Leads:
- powershell.exe PID 3704 with -EncodedCommand decoding to
  Invoke-WebRequest / IEX cradle
- ESTABLISHED TCP from PID 3704 at 10.0.8.34:49918 → 91.214.47.22:443
  (same IP as WKSTN-221 dataset)
- handles from PID 3704 into PID 1142 (svchost) + named pipe \\.\pipe\whcs_ctrl

What Is Strongly Supported:
- Memory-resident implant chain across IIS, PowerShell, and svchost
- Active C2 to 91.214.47.22:443 attributable to PID 3704
- Injection from PowerShell into svchost
- Persistence service registered with binary in C:\Windows\Temp\

What Is Suggested but Not Confirmed:
- 91.214.47.22 is attacker-controlled (need threat-intel context)
- Implant survives reboot (need to confirm WindowsHealthCollector
  start mode and current binary on disk)
- Same actor on other hosts (need EDR sweep)

Recommended Next Steps:
1. Dump the MZ region in PID 3704; hash and submit to threat intel
2. Pull MFT + IIS logs around 2024-11-21 10:19 for cmdshell.dll origin
3. EDR sweep across the environment for cmdshell.dll, whcs.exe,
   91.214.47.22, and the encoded-command pattern

Open Questions:
- How was the original web shell delivered?
- Are credentials in LSASS likely compromised (Mimikatz-style)?
- Should WEB-APP-03 be contained now or kept live for monitoring?

Notes for Incoming Analyst:
The three malfind hits, the impossible pstree, the encoded PowerShell, and the
ESTABLISHED C2 are all the same case — do not treat them as separate leads.
Acquisition was clean (one non-fatal smear warning); image hash recorded.
Memory is the load-bearing evidence here; disk corroboration is the gap to close.
```

---

## Task 14 — Reflection

**1. Why memory matters**

Memory is where fileless and EDR-aware tradecraft lives. Reflective loaders, encoded PowerShell cradles, process-hollowed implants, in-memory C2 beacons, and plaintext credentials in LSASS leave no clean evidence on disk if the attacker is competent. Disk-only investigations of those cases produce confidently incomplete reports. Memory analysis is what makes those incidents tractable. The WEB-APP-03 case is a textbook example: the `cmdshell.dll` load timestamp and the malfind regions are the central facts, and disk alone would barely show them.

**2. Live state versus durable state**

Disk artifacts record what was *configured*: files present, registry values set, services registered. Memory records what is *happening right now*: which processes have sockets open, which DLLs are loaded into which address spaces, and which threads are running injected code. In an active incident, the live-state view answers "is the implant still talking?" and "what is it talking to?" A configuration-only view cannot answer either question. Memory is uniquely valuable while the implant is still alive on the host.

**3. Caution in interpretation**

Memory findings are compelling and often dramatic, which makes overclaiming them tempting. A `malfind` hit is not automatically malware, because JIT compilers produce similar regions. An ESTABLISHED connection to an unfamiliar IP is not automatically C2, because cloud providers host both legitimate and malicious tenants. The discipline is to describe what each finding directly supports: the structure was there, the connection was open, the region had this content. Then let the convergence of findings carry the broader interpretation.

**4. Correlation remains essential**

Memory is one input. The strongest cases pair it with disk artifacts such as MFT timestamps, file SHA-1 hashes, and registry persistence. They add logs, such as EID 7045 for service install, 4688 for process create, and IIS access logs. They also add EDR telemetry, such as process-tree confirmation, network attribution, and file-write events, plus user-activity evidence. The WEB-APP-03 case has high memory confidence on its own. It becomes defensible in court only when the memory findings are joined with the file-creation timeline for `cmdshell.dll`, the registry record of `WindowsHealthCollector`'s install, and the EDR sweep across other hosts for the same `91.214.47.22`.

---

## Ready-to-move-on self-check

Before starting Lab 08, confirm you can answer these three questions cold. If any feel wobbly, revisit the relevant task.

1. **What does it mean when `pstree` shows `w3wp.exe` as the parent of `cmd.exe` or `powershell.exe`?**  *Answer:* IIS workers do not legitimately spawn interactive shells. This is the classic web-shell pattern, and it is essentially diagnostic on its own. In the WEB-APP-03 data, `w3wp.exe` (PID 2860) is the direct parent of both shells, so the chain is two siblings rather than `cmd.exe → powershell.exe`. The rest of the memory hunt confirms the shape of the implant rather than establishing whether one is there.
2. **What makes a `malfind` hit highly suggestive of injection rather than legitimate JIT?**  *Answer:* The region is `PAGE_EXECUTE_READWRITE` and private, with no backing file. Most diagnostically, it starts with an `MZ` PE header, which means a fully formed binary is in memory with no on-disk source. JIT regions exist but rarely contain a PE header.
3. **Why is the `netscan` plugin uniquely valuable compared to perimeter network logs?**  *Answer:* It attributes each socket directly to the owning process by PID. Perimeter logs show "the host had a session" but not "which process on the host owned it." Memory closes that attribution gap.

---

## Walkthrough ↔ workbook bridges

> After Walkthrough Step 1, revisit Task 4.Q1 (confirming OS context). The `windows.info` output showing Windows Server 2019 build 17763 x64 is the specific sanity check your workbook answer was describing abstractly. Without that line of output, every subsequent plugin in the walkthrough would be unreliable.

> After Walkthrough Step 2, revisit Task 5.Q2 (odd parent-child relationships). `w3wp.exe` (PID 2860) spawning both `cmd.exe` (PID 3580) and `powershell.exe` (PID 3704) is the exact "impossible-for-the-service" pattern the workbook was asking you to think about. IIS workers never legitimately spawn shells.

> After Walkthrough Step 3, revisit Task 6.Q1 (command lines more revealing than names). The `-NoProfile -WindowStyle Hidden -EncodedCommand` triple, decoding to an `Invoke-WebRequest` / `IEX` cradle to the C2, is the concrete command-line content that turns "a PowerShell ran" into "this PowerShell was an in-memory loader cradle."

> After Walkthrough Step 4, revisit Task 7.Q1 (memory connecting network to process). The ESTABLISHED TCP `10.0.8.34:49918 → 91.214.47.22:443` attributed by `netscan` to PID 3704 is the per-process attribution the workbook was describing. Perimeter logs would show the IP, but only memory ties it to PowerShell.

> After Walkthrough Step 5, revisit Task 8.Q1 (`malfind` and injection). The three `PAGE_EXECUTE_READWRITE` private regions in PIDs 3704, 1142, and 2860 are the textbook injection-and-reflective-loader signature, and all three regions carry an `MZ` header.
