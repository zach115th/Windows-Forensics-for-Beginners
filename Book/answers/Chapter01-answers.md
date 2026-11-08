# Chapter 1 — Review Question and Exercise Answers

*Sample answers for the Review Questions and Practical Exercises at the end of [`Chapter01.md`](../Chapter01.md). These are reference answers, not the only correct answers. Your wording will differ, and that is fine. What matters is whether your reasoning covers the same ground. For the corresponding lab, see [`Labs/Lab01/task-answers.md`](../../Labs/Lab01/task-answers.md).*

---

## Review Questions

**1. Why is digital forensics different from ordinary IT troubleshooting?**

They have different objectives, and the objective changes every decision downstream. Troubleshooting asks "how do I fix this?" and is measured on time to restore service. Forensics asks "how do I prove what happened?" and is measured on whether the findings survive review. Reboots, profile resets, reimages, and malware cleanups are all reasonable administrative moves. Every one of them can also destroy volatile evidence, alter timestamps, roll logs, or overwrite the very artifacts that would have answered the question. Restoration still matters, but the responder has to make the speed-versus-preservation tradeoff deliberately and document the choice rather than stumble into it. The practical test: if you cannot explain later why you touched the system the way you did, you were troubleshooting, not responding.

**2. What are the five major phases of digital forensics, and why do they overlap during incident response?**

The five phases are Identification, Collection, Preservation, Analysis, and Reporting. Identification decides which systems, accounts, logs, and data sources are relevant. Collection is controlled acquisition from those sources. Preservation covers hashing, access control, and protecting the original. Analysis interprets artifacts and tests explanations. Reporting communicates findings, gaps, and recommended actions. The phases look sequential on paper and almost never run that way in a live incident. You identify a second host while analyzing the first collection, go back to collect from it, and start reporting an interim picture to leadership before analysis is finished. That overlap is normal, not a process failure. Documentation has to stay constant regardless of sequence: what was done, when, why, and what evidence justified the next step.

**3. Why do Windows-native artifacts remain valuable even when EDR and SIEM are present?**

EDR and SIEM coverage is conditional. It depends on collection logic, sensor health, ingestion success, retention windows, parsing rules, deployment coverage, and on the attacker not having disabled or evaded the tools. Windows itself produces native artifacts as a side effect of normal operation, so they exist independently of any of those conditions. They routinely cover activity that predates sensor deployment, falls outside SIEM retention, was never parsed into a useful field, or occurred while the sensor was off. The relationship is complementary rather than competitive: EDR usually tells you *where to look*, and native artifacts usually tell you *what actually happened on the host*.

**4. What risks arise when collection occurs without documented authorization or clearly defined scope?**

The first risk is legal exposure. Collecting from a system or a user's data without authority can breach employment agreements, privacy law, contracts, or internal policy. It can turn a security incident into a second, self-inflicted problem. Second, technically valid findings become contestable. If the collection was unauthorized, the analysis built on it may be excluded, discounted, or challenged regardless of quality. Third, undefined scope creates risk in both directions. Collect too little and the investigation fails. Collect too much and the organization absorbs unnecessary privacy, regulatory, and discovery burden. The specific failure to watch for is scope creep: encountering relevant-looking data outside the original scope and quietly taking it. The correct move is to document the discovery, assess the need, and get authorization to expand.

**5. Why should analysis be performed on working copies rather than preserved originals?**

Because analysis touches things. Mounting an image, running a parser, opening a hive, indexing a file set — any of it can alter the source, or at minimum make it harder to demonstrate that the source was unaltered. Preserving the original in a controlled, access-limited location and analyzing a verified copy means the original remains ground truth for the life of the case. If the working copy is corrupted, mishandled, or contested, you produce a fresh copy from the original and verify it by hash. The approach also makes the process easier to explain. "The original was acquired, hashed, stored, and never analyzed directly" closes a whole category of questions from counsel or a reviewer.

**6. What are the practical advantages of using a separate virtual evidence disk in a training lab?**

It separates evidence from the operating system, which mirrors how responders package triage output in the real world. It gives you a discrete container you can hash, export, and treat as a single evidence item, so chain-of-custody practice has something concrete to attach to. It makes exercises repeatable, because you can detach, snapshot, or replace the evidence disk without rebuilding the whole VM. And it produces an NTFS volume with a known starting state. That makes later file-system exercises cleaner, because you know which activity you generated and which the OS generated on its own. Assigning a consistent drive letter such as `E:` and labeling it clearly keeps the discipline from breaking down across chapters.

**7. Why is a baseline snapshot so important in a forensic lab environment?**

Because forensic learning requires destroying things and then starting over from a known state. A snapshot with an explicit name such as `Baseline-Clean` lets you run simulated malicious activity, timestomp files, install questionable software, or make a mess of the registry, then revert and repeat the exercise without days of rebuild. It also gives you a comparison point. Knowing exactly what a clean host looks like makes an anomaly visible later. The snapshot has to be paired with baseline notes — hostname, OS version and build, timezone, local accounts, installed tools and versions, audit policy state, logging state, snapshot name and date. The chapter's rule of thumb applies: if you cannot rebuild the environment from the notes, the notes are not good enough.

**8. What kinds of investigative questions can Windows artifacts help answer?**

The operational ones that drive containment and scoping. Did a binary execute on this host, when, and how many times (Prefetch, Amcache, UserAssist)? Which user account was involved and how did they log on (Security.evtx logon events)? Did files get created, renamed, staged, or deleted (MFT, USN Journal)? Was persistence established (registry autoruns, services, scheduled tasks)? Did a user open or access specific documents (LNK files, Jump Lists, RecentDocs)? Was removable media attached, and which device (USBSTOR, MountedDevices, shellbags)? Did a process use the network, and how much data moved (SRUM, network telemetry)? What was running at the moment of capture (memory)? The skill being built is the mapping itself — going from question to artifact quickly, before the clock is running.

---

## Practical Exercises

**1. Build a Windows 10 or 11 VM with host-only networking and document its configuration.**

**What you should end up with:** A running Windows 10 or 11 guest in VirtualBox, VMware Workstation, or Hyper-V, on a host-only network, plus a written configuration record.

**How to get there:** Allocate at least 2 vCPU, 4 GB RAM (8 GB preferred), and a 60 GB primary disk. Set the network adapter to host-only rather than NAT or bridged. If you need NAT temporarily to pull tools down, note that you did and switch back. Create a second local account in addition to the built-in administrator so later exercises produce multi-user artifacts. Set and record the timezone — UTC is worth considering because it removes a conversion step from every timeline you build afterward.

**What good looks like:** Your configuration note names the hostname, OS edition and build number (`winver` or `Get-ComputerInfo`), timezone, both local account names, the network mode and the reason you chose it, and the disk layout. A second person should be able to rebuild the same VM from your note without asking you a question. If the note says "Windows 11, 8 GB, host-only" and nothing else, it is not yet documentation.

**2. Add a secondary evidence disk, populate it with realistic files, and hash the backing virtual disk file.**

**What you should end up with:** A second NTFS virtual disk mounted at a consistent letter such as `E:`, containing realistic content, and a recorded SHA-256 of the `.vdi`/`.vmdk`/`.vhdx` file on the host.

**How to get there:** Add the disk in the hypervisor, initialize and format it NTFS inside the guest, and label it. Populate it with a genuine mix: Office documents, images, a script or two, an archive, and a renamed executable in a staging-style folder. The renamed executable pays off in Chapters 4 and 6. Shut the guest down cleanly so nothing writes to the backing file while you hash. On the host, compute the hash: `Get-FileHash -Algorithm SHA256 'C:\VMs\lab\evidence.vhdx'` on Windows, or `sha256sum evidence.vdi` on Linux/macOS.

**What good looks like:** You have a 64-character hex digest recorded alongside the file name, the file size, the date and time of hashing in UTC, and the tool you used. Recompute the hash a second time without touching the disk in between and confirm it matches. That repetition is the point of the exercise. If the VM was running when you hashed, the value will not be stable, so redo it powered off.

**3. Create a basic chain-of-custody log for the simulated evidence item.**

**What you should end up with:** A completed chain-of-custody record for the evidence disk from exercise 2. `Labs/Lab01/CoC_Template.md` and the `.docx` template in `Labs/Lab01/Lab01_03/` give you the form.

**How to get there:** Assign a unique evidence identifier, such as `LAB01-EVID-001`. Fill in a description of the item, the source system, acquisition date and time in UTC, who collected it, storage location, hash algorithm and value, and then one row per transfer or analysis event. Then actually use it: make a working copy of the disk file, log the copy as an event, hash the copy, and record that the hashes match.

**What good looks like:** The log answers "who touched this, when, and what did they do to it" for every moment between acquisition and now, with no unexplained gaps. The hash appears at acquisition and at least once again at verification. If someone reads only your CoC record, they should be able to state confidently that the file being analyzed is the file that was collected.

**4. Write an analyst opening note for a suspicious workstation scenario.**

**What you should end up with:** A short structured note that opens a case. Half a page is plenty.

**How to get there:** Invent or borrow a scenario. An EDR alert on a finance workstation is a realistic default. Write down: what was reported and by whom, the time it was reported, what is currently known as fact, what is assumed, what is unknown, and what evidence should be collected first and why. Keep facts and assumptions in visibly separate sections rather than mixed into a narrative.

**What good looks like:** Nothing in your "known" section is actually an inference from the alert text. The note names at least two things that are unknown. A note with no unknowns at case opening has already decided the answer. It should also name a first collection action concrete enough to execute. "Capture memory before isolating, then collect $MFT, $J, Security.evtx, and Prefetch" qualifies. "Collect artifacts" does not.

**5. Create a personal reference list of at least twelve Windows artifacts and the IR questions they help answer.**

**What you should end up with:** A two-column table you actually keep, mapping artifact to the questions it answers.

**How to get there:** Start from section 1.2.2 and extend it. A reasonable 14: MFT (did the file exist, when was it created), USN Journal (what was created/renamed/deleted and in what order), Security.evtx (who logged on, how, and what processes started), System.evtx (service installs, system state changes), PowerShell Operational (script content, if logging was enabled), SYSTEM hive (services, USB history, network config), SOFTWARE hive (installed software, machine-level persistence), NTUSER.DAT (per-user activity, UserAssist, TypedPaths), Prefetch (did it run, when, how many times), Amcache (what binaries the system saw, with hashes), SRUM (which process used the network and how much), LNK and Jump Lists (which files were opened, from which volume), browser history (what was visited or downloaded), memory (what was running right now). Add a third column for where the artifact lives on disk and you have something usable in a real engagement.

**What good looks like:** The questions are phrased operationally, not categorically. "Execution" is a category; "did `update.exe` run on this host, and how many times" is a question. Appendix E, the Windows Forensics Quick Reference, is effectively the book's own version of this table. After you write yours, compare it against Appendix E to check what you missed.

**6. Document the limitations of your lab and propose three improvements for later chapters.**

**What you should end up with:** An honest half-page assessment plus three concrete, prioritized improvements.

**How to get there:** Work through the four questions in section 1.4.10 — what can this lab teach well, what can it not teach yet, what risks exist if it is misconfigured or exposed, and what should be improved next. Be specific about the gaps: a single workstation VM cannot model domain authentication, lateral movement, Kerberos abuse, or multi-host timelines. It probably has default audit policy, which means no process command-line auditing and thin 4688 data. It has no EDR sensor and no Sysmon, so you will have no telemetry of your own when Chapter 9 and Appendix C cover them.

**What good looks like:** Your improvements are things you could actually do, in order. For example: (1) enable command-line process auditing and PowerShell Script Block Logging so later chapters have real data to parse, (2) install Sysmon with a public configuration for Chapter 9 and Appendix C, (3) add a domain controller VM on an internal-only network for Appendix A material. Vague improvements such as "make it more realistic" do not count. Naming a limitation you are choosing to accept is as valuable as naming one you plan to fix.

---

## Common mistakes on this chapter

- **Treating the five phases as a checklist to complete in order.** Newcomers get uncomfortable when identification and analysis run at the same time and try to force sequence. The phases are a vocabulary for describing work, not a workflow gate. What actually has to be sequential is *preserve before you alter*, and that is a much narrower constraint.
- **Believing chain of custody only matters if the case goes to court.** Most incidents never reach a courtroom, but every one of them can still end up in front of HR, counsel, an insurer, a regulator, a customer, or the analyst who picks the case up six months later. The controls exist to make findings trustworthy, and trust is far cheaper to preserve than to rebuild.
- **Hashing the evidence disk while the VM is still running.** The hypervisor is still writing to the backing file, so the hash is not reproducible and the exercise teaches the wrong lesson. Shut the guest down cleanly first, then hash, then hash again to confirm stability.
- **Assuming EDR coverage makes native artifacts optional.** This is the most consequential misconception in the chapter, because it holds right up until the incident where the sensor was disabled, deployed after the intrusion started, or never installed on the host that mattered. Native artifacts are the fallback that does not depend on your security stack having been healthy.
- **Writing lab notes that only make sense to the person who built the lab.** "Set up VM, added tools" is not a baseline record. The test is rebuild-ability: hostname, build number, timezone, accounts, tool versions, audit policy, snapshot name and date. Tool versions in particular get skipped, and they are exactly what you need when a parser produces different output six months later.
- **Confusing artifact awareness with artifact collection.** The point of section 1.2.4 is that you make prioritization decisions from knowledge you already have, because the incident does not pause while you look things up. Knowing what *not* to collect, and being able to justify it, is part of the skill — not a shortcut around it.

---

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) book series.*
