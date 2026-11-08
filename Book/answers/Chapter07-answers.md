# Chapter 7 — Review Question and Exercise Answers

*Sample answers for the Review Questions and Practical Exercises at the end of [`Chapter07.md`](../Chapter07.md). These are reference answers, not the only correct answers — your wording will differ and that is fine. What matters is whether your reasoning covers the same ground. For the corresponding lab, see [`Labs/Lab07/task-answers.md`](../../Labs/Lab07/task-answers.md).*

---

## Review Questions

**1. Why is memory acquisition uniquely time-sensitive compared to most disk artifact collection?**

Disk artifacts persist across reboots and survive most routine system activity. An MFT record, a Prefetch file, or a registry value written last Tuesday is still there next Tuesday. Memory is the opposite. Normal operation continuously overwrites it, memory pressure pages it out, and a reboot clears it almost entirely. Once it is gone there is no recovery path, and you cannot go back and re-acquire what was running an hour ago. That is why the operational rule in an active incident is *capture memory first, analyze later*. The acquisition takes minutes, and every minute of delay costs evidence that no other source preserves. Containment actions such as isolating or powering off a host are themselves destructive to memory, so you have to make the acquisition decision before the containment decision.

**2. What kinds of attacker techniques produce evidence in memory but little or none on disk?**

Fileless techniques, broadly. Reflective DLL loading maps a module into a process without ever writing it to the file system, so there is no file for the MFT or Amcache to record. In-memory PowerShell — an `-EncodedCommand` cradle that downloads and `IEX`-executes a payload — leaves a command line and a script block but no binary. Process hollowing creates a legitimate process in a suspended state and replaces its image with malicious code, so the on-disk binary is benign. Process injection puts attacker code in the address space of `svchost.exe`, `explorer.exe`, or another trusted host process. In-memory credential theft reads LSASS without dropping a tool. Living-off-the-land tradecraft that uses only signed Microsoft binaries produces disk evidence that looks entirely normal. The anomaly is in the arguments and the parentage, and memory records both.

**3. What does `pstree` output reveal that `pslist` alone does not?**

`pstree` makes structural anomalies visible at a glance rather than by inference. `pslist` gives you a flat enumeration: name, PID, PPID, start time, and thread and handle counts. The parent PID is present, but you have to reconstruct the hierarchy by hand across dozens of rows. `pstree` renders the hierarchy directly in indented form. That matters because parent-child relationships are the cheapest anomaly signal Windows gives you. `w3wp.exe → cmd.exe → powershell.exe` is structurally impossible on a healthy IIS host, and `OUTLOOK.EXE → POWERSHELL.EXE → CMD.EXE` is the canonical phishing-macro chain. You can find those chains in `pslist` output, but only if you already suspect them. `pstree` shows them to you.

**4. Why is the `cmdline` plugin one of the highest-value triage commands?**

The command line records what a process was *told to do*, which is where intent lives. Process names on modern Windows are almost never informative on their own, because `powershell.exe`, `rundll32.exe`, `cmd.exe`, and `certutil.exe` run legitimately on nearly every host every day. `-NoProfile -WindowStyle Hidden -EncodedCommand <base64>` is a loader cradle. `-ExecutionPolicy Bypass` next to a path in `%TEMP%` is a red flag. So is a `rundll32.exe` invocation naming an unfamiliar DLL and export, or a `cmd.exe /c` piping into another interpreter. The plugin is also cheap. One run covers the whole image, and the highest-value hits usually jump out on a visual scan. Decode encoded blobs immediately. A base64 string that resolves to a download cradle is one of the most common decisive findings in modern Windows incidents.

**5. What does a difference between `pslist` and `psscan` output suggest about the system?**

A process that appears in `psscan` but not `pslist` has two common explanations, one benign and one alarming. `pslist` walks the kernel's doubly-linked list of active processes. `psscan` scans memory directly for `EPROCESS` structures, whether or not they are still linked into that list. The benign explanation is that the process exited shortly before capture and its structure had not yet been reused. That case is very common, and it is the reason a delta is not automatically alarming. The alarming explanation is that the process was deliberately unlinked from the active list. That is a classic direct kernel object manipulation (DKOM) rootkit technique, and it means something on the host is actively hiding. To tell the two apart, look at the process itself: its name, its path, its exit time if recorded, and whether other artifacts such as Prefetch, Amcache, and event logs corroborate a normal lifecycle.

**6. How does `malfind` decide that a memory region is suspicious?**

`malfind` walks the Virtual Address Descriptor (VAD) tree for each process. It flags regions that combine three characteristics: executable *and* writable memory protection (typically `PAGE_EXECUTE_READWRITE`), private rather than mapped memory, and no backing file on disk. Legitimate code is normally loaded from a mapped image file and is executable but not writable. A region that is both writable and executable with no file behind it is the signature of code written into the process at runtime, which is exactly what injection and reflective loading do. `malfind` then prints a hex dump of the region's first bytes. An `MZ` header (`4D 5A 90 00`) there is the single most diagnostic detail available, because it means a fully formed PE exists in memory with no on-disk source.

**7. Why does `netscan` output need to be cross-referenced against the process list?**

A PID alone is not a finding. `netscan` gives you the socket four-tuple, the connection state, and an owning PID. To know whether the connection is meaningful, you need the process name, the full image path, the command line, and the parent. A connection to an unfamiliar IP owned by `chrome.exe` is background browsing. The same connection owned by a `powershell.exe` that is a grandchild of the IIS worker is C2. PIDs are also reused over time, so on a busy host a stale socket structure can carry a PID that now belongs to a different process. Cross-referencing against `pslist`/`psscan` catches that. The combination is what makes the finding defensible, because per-process attribution is the specific thing memory gives you that perimeter network logs cannot.

**8. What handling considerations apply to the output of `lsadump`, `cachedump`, and `hashdump`?**

That output is live credential material: NTLM hashes, cached domain credential verifiers, LSA secrets, and, in poorly configured environments, plaintext. Anyone who obtains it can use it directly for authentication, which makes it more dangerous than most forensic output. Treat it as the most sensitive artifact in the case folder. Store it encrypted and restrict access to the minimum set of responders who need it. Keep it out of shared drives, ticketing systems, chat, and report appendices, and record its handling in the chain of custody. The output should also inform containment, not just documentation. If these credentials were sitting in memory on a compromised host, assume they are compromised and drive password resets and Kerberos key rotation accordingly. Finally, do not run these plugins reflexively. Run them when the case needs the answer.

**9. When would you use MemProcFS rather than command-line Volatility plugins?**

Use MemProcFS when you do not yet know what you are looking for. It mounts the image as a virtual file system, so exploration becomes `dir`, `findstr`, `Get-Content`, and a text editor rather than one plugin invocation per question. You can browse `M:\name\` to see what processes exist, then open a specific process's `cmdline\`, `modules\`, and `handles\` in sequence. A responder who is not a Volatility specialist can look around productively, too. Its output is easier to share, because a copied directory tree is more legible to a colleague than a folder of plugin output. Volatility is the better choice when you have a specific hypothesis and want the encoded heuristics. `windows.malfind`, `windows.svcscan`, and the credential plugins do analytical work that a file-system view does not. Most practitioners use both, starting with MemProcFS for navigation and dropping into Volatility for targeted plugins.

**10. How do memory findings best combine with disk-based evidence to produce defensible conclusions?**

Memory tells you what was happening at one instant. Disk tells you what was configured and when. Each covers the other's blind spot. A `malfind` hit in `powershell.exe` says code was injected. A Prefetch entry and an Amcache SHA-1 say which binary ran and give you a hash for threat intel. An MFT `$STANDARD_INFORMATION` creation timestamp says when the staging file appeared. A registry `Services` key or a System log EID 7045 says persistence was established, and when. Memory rarely establishes *how the implant got there* or *when the intrusion began*. Those are disk and log questions. The strongest conclusions are the ones where the sources agree. The memory image shows the process running, the disk shows the binary that produced it, and the logs show it starting at a time consistent with both. When the sources disagree, that disagreement is itself the next thing to investigate.

---

## Practical Exercises

**1. Capture a memory image from your lab VM with WinPmem or DumpIt. Compute and record a SHA-256 hash.**

**What you should end up with:** A raw memory image whose size is roughly the VM's RAM allocation, plus a recorded SHA-256 digest, tool name and version, output path, and acquisition wall-clock time in UTC.

**How to get there:** Run the acquisition tool from removable or network-attached storage rather than the system disk, so you are not writing evidence onto the volume you may later image. `winpmem.exe -o E:\evidence\LABVM_<date>.raw`, then `Get-FileHash -Algorithm SHA256 E:\evidence\LABVM_<date>.raw`. Record the hash before doing anything else with the file, and note any warnings the tool emitted during driver load.

**What good looks like:** Your notes record the hash with its algorithm and the time you computed it, and re-hashing the file later produces the same value. The acquisition record names the tool version — "WinPmem 4.0.rc2," not "WinPmem." Warnings such as smear or partial page coverage are documented even though the image was produced successfully. A noisy acquisition record is more defensible than a silent one.

**2. Run `windows.info` against the image and document the OS version, build, and kernel base address.**

**What you should end up with:** A short block of notes recording OS family and SKU, build number, architecture, kernel base address, and the system time recorded in the image.

**How to get there:** `vol.py -f LABVM.raw windows.info`. To work this against shipped data instead of your own capture, use [`Data/WEB-APP-03/volatility-info.txt`](../../Data/WEB-APP-03/volatility-info.txt), the equivalent output for the lab scenario (Windows Server 2019, build 17763, x64).

**What good looks like:** The plugin completes without symbol errors, and the system time in the output is consistent with your recorded acquisition time. This plugin is the sanity check for the whole analysis. If `windows.info` fails, no other plugin will produce trustworthy output, and the right response is to triage the acquisition rather than push on. Record this block at the top of your notes so every downstream finding inherits the host, OS, and time context.

**3. Run `windows.pslist`, `windows.psscan`, and `windows.pstree` and identify any processes that appear in one output but not another.**

**What you should end up with:** Three saved outputs plus a short delta list: any PID present in `psscan` but absent from `pslist`, with your assessment of why.

**How to get there:** Run all three, save each to a file named for the plugin, then diff the PID columns. On Linux: `awk '{print $1}' psscan.txt | sort -u > a; awk '{print $1}' pslist.txt | sort -u > b; comm -23 a b`. On a clean lab VM you may find a few recently exited processes and nothing else, which is a valid result.

**What good looks like:** You can explain each delta rather than just list it. Recently exited processes are the ordinary explanation, so check them against the image's system time. A live, plausible-looking process visible only to `psscan` is the interesting case, and it warrants pulling its path and command line. Reporting "no delta" on a clean VM is a legitimate outcome. Fabricating a rootkit is not.

**4. Run `windows.cmdline` and identify three processes whose command lines you can fully justify based on lab activity.**

**What you should end up with:** Three rows tying a process name and PID to a command line and to something you actually did on the VM.

**How to get there:** `vol.py -f LABVM.raw windows.cmdline`. Pick processes you launched deliberately — a browser, a text editor, a PowerShell session — and map each command line to the action. Then look at what you *cannot* justify and note it.

**What good looks like:** The exercise's real payoff is the residue: the processes whose command lines you cannot immediately account for. On a clean lab VM, those all resolve to Windows components and installed software. Working out which is which builds the baseline that makes anomalies visible on a real host. Compare against [`Data/WEB-APP-03/volatility-cmdline.txt`](../../Data/WEB-APP-03/volatility-cmdline.txt) to see what an unjustifiable command line looks like.

**5. Run `windows.netscan` and tie at least two network endpoints to their owning processes.**

**What you should end up with:** A short table: local address/port, remote address/port, state, PID, process name, image path, and your interpretation.

**How to get there:** `vol.py -f LABVM.raw windows.netscan`, then join the PID column against your `pslist` output to get names and paths. On a lab VM your established connections will mostly be Windows Update, telemetry, and whatever browser you left open.

**What good looks like:** Every row has both halves — the socket *and* the owning process with its path. A row that stops at "PID 4216 talked to 20.x.x.x" is half a finding. The shipped equivalent is [`Data/WEB-APP-03/volatility-netscan.txt`](../../Data/WEB-APP-03/volatility-netscan.txt). There, the ESTABLISHED connection to `91.214.47.22:443` owned by the suspicious `powershell.exe` sits alongside the expected listeners on 80, 443, 445, 3389, and 5985. The contrast between "expected listener" and "unexpected outbound" is the thing to internalize.

**6. Run `windows.malfind` and inspect any hits, dumping the relevant memory regions and reviewing their strings.**

**What you should end up with:** A list of hits with PID, process name, region base address, protection flags, and your assessment of whether each is likely benign.

**How to get there:** `vol.py -f LABVM.raw windows.malfind`, then dump regions of interest with `windows.vadinfo --pid <PID> --dump` and run `strings` over the output. Expect hits on a clean VM. Browsers, the .NET runtime, and some endpoint agents all produce writable-executable private regions through JIT compilation.

**What good looks like:** You can explain why each hit is or is not concerning, rather than treating the plugin output as a verdict. The discriminator to look for is an `MZ` header (`4D 5A 90 00`) at the region start, which means a full PE lives in memory with no file behind it. See [`Data/WEB-APP-03/volatility-malfind.txt`](../../Data/WEB-APP-03/volatility-malfind.txt) for that pattern. JIT regions rarely carry a PE header. "Three hits, all in JIT-producing runtimes, none with PE headers, assessed benign" is a good answer.

**7. Pick one suspicious-looking process (or fabricate one with a benign test binary) and dump its memory regions. Use `strings` and a hex editor to inspect them.**

**What you should end up with:** A directory of dumped region files, a strings extract, and a short note on what the strings revealed.

**How to get there:** If nothing on the VM is genuinely suspicious, manufacture a controlled test: run a benign binary that you built or downloaded, note its PID, and dump it. `vol.py -f LABVM.raw -o ./dumps/ windows.vadinfo --pid <PID> --dump`, then `strings -a ./dumps/* | sort -u | less`. Open one region in a hex editor and find the PE header, section names, and the import table.

**What good looks like:** You can locate structure in a dumped region: a `MZ`/`PE` header, section names such as `.text` and `.rdata`, and readable strings such as URLs, file paths, or registry keys. The point is procedural familiarity. If you know what dumping produces and how to read it, you will not stall when a real case needs it under time pressure. Also note what dumping does *not* give you. The region may be partially paged out, and gaps are normal.

**8. Run `windows.svcscan` and `windows.dlllist` against your image and identify any unsigned modules or services with unusual binary paths.**

**What you should end up with:** Two outputs plus a filtered short list of services whose `ImagePath` is outside `%SystemRoot%\System32` and `%ProgramFiles%`, and DLLs loaded from outside standard load paths.

**How to get there:** `vol.py -f LABVM.raw windows.svcscan` and `vol.py -f LABVM.raw windows.dlllist --pid <PID>` for processes of interest. Filter the service output on image path. On a clean VM, the survivors will be third-party software you installed, and identifying each one is the exercise.

**What good looks like:** You end up with a defensible baseline: "these seven services run from non-standard paths, and here is what each one is." The pattern to recognize is in [`Data/WEB-APP-03/volatility-svcscan.txt`](../../Data/WEB-APP-03/volatility-svcscan.txt) and [`volatility-dlllist.txt`](../../Data/WEB-APP-03/volatility-dlllist.txt): a `WindowsHealthCollector` service with a binary in `C:\Windows\Temp\`, and a `cmdshell.dll` loaded into the IIS worker from the same directory. Two anomalies, an unfamiliar name and a non-standard path, stacked in the same directory make that pair conclusive rather than merely odd.

**9. Build a one-page memory triage note for your lab image that lists the plugins you ran, the time of each run, the Volatility version, and the most notable findings.**

**What you should end up with:** A single markdown page with a header block (host, OS, acquisition tool and version, image hash, acquisition time UTC), a table of plugin runs, and a short findings section.

**How to get there:** Keep the note open while you work rather than reconstructing it afterward. For each plugin, record the exact invocation, the analysis-host time you ran it, the output file name, and one line on what it showed. Close with three to five sentences of interpretation separating what is supported from what needs corroboration.

**What good looks like:** Another analyst could re-run your entire analysis from the note alone and get the same output. Tool versions are specific. Every finding names the plugin that produced it. The interpretation section distinguishes "the structure was present in memory," which is direct evidence, from "this process was attacker-controlled," an inference that requires more. Section 7.3.8 of the chapter is the checklist, and the note is that checklist filled in.

**10. For one finding, build a short corroboration table that ties the memory observation to a Prefetch entry, an Amcache hash, or a registry value.**

**What you should end up with:** A table with one row per corroborating source: memory observation, corroborating artifact, what the artifact adds, and the resulting confidence.

**How to get there:** Pick a process from your memory analysis and pull the disk-side evidence for the same binary: `PECmd` over `%SystemRoot%\Prefetch\`, `AmcacheParser` over `Amcache.hve`, and `RECmd` over `SYSTEM` for a service key. If you are working the shipped data rather than your own VM, the cross-source pattern is visible between [`Data/WEB-APP-03/`](../../Data/WEB-APP-03/) and [`Data/WKSTN-221/`](../../Data/WKSTN-221/). The same C2 IP `91.214.47.22` appears in the WEB-APP-03 `netscan` output and in `WKSTN-221/network-flow.csv`. That is cross-host corroboration rather than cross-artifact.

**What good looks like:** The table shows each source adding something the others do not. Memory adds live state and per-process attribution, Prefetch adds execution confirmation and run count, Amcache adds a hash suitable for threat intel, and the registry adds persistence configuration and a last-write timestamp. The confidence column moves up as sources converge, and the table shows *why* it moved rather than asserting it.

---

## Common mistakes on this chapter

- **Treating `psscan` output as definitive without corroboration.** A process visible to `psscan` but not `pslist` gets read as "hidden by a rootkit" far more often than the evidence warrants. The ordinary explanation is much more common: the process exited shortly before capture, and its `EPROCESS` structure had not been reused. Check the exit time, the image path, and whether Prefetch or event logs show a normal lifecycle before you write "rootkit" in your notes.

- **Reporting `malfind` hits as malware findings.** `malfind` is a heuristic that flags writable-executable private memory with no backing file. Browsers, the .NET runtime, Java, and several endpoint agents all generate regions that match. A hit is a lead that tells you which region to dump, not a verdict. Two things upgrade a hit. The first is content, such as an `MZ` header at the region start, recognizable shellcode, or strings tying it to other evidence. The second is corroboration from another plugin pointing at the same process.

- **Skipping `windows.info` and going straight to the interesting plugins.** Every downstream plugin depends on correctly resolved symbols for the specific Windows build. If you skip the confirmation step, you either get a hard failure later or, worse, output that is subtly wrong. Off-by-a-few-bytes fields and misparsed structures can look plausible enough to write down. Thirty seconds of `windows.info` prevents an entire analysis built on bad structure offsets.

- **Treating a memory image as a complete account of the incident.** Memory is a single-instant snapshot. It does not tell you how the implant arrived, when the intrusion began, what was exfiltrated before the capture, or whether other hosts are affected. Because memory findings are dramatic and specific, they are easy to overweight, especially when you are new to memory forensics. The chapter's own framing is the correction: memory is rarely the whole investigation but often the decisive part of it.

- **Running credential plugins reflexively and handling the output carelessly.** `lsadump`, `cachedump`, and `hashdump` produce live, usable authentication material. Dropping that output into a shared case folder, a ticket, or a report appendix converts a forensic artifact into an active exposure. Run them when the case actually needs the answer, store the output encrypted with restricted access, and let the result drive credential resets rather than sitting in a document.

- **Recording plugin names without versions or invocations.** "Volatility showed injected code in PowerShell" is not reproducible. "Volatility 3 v2.5.2, `windows.malfind`, run against `WEB-APP-03_memory.raw` (SHA-256 recorded), output saved to `malfind_20241121.txt`" is. Memory analysis output is interpretive enough that the exact tool and version change results between runs. That makes the provenance discipline load-bearing rather than bureaucratic.
