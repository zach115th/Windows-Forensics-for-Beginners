# Chapter 3 — Review Question and Exercise Answers

*Sample answers for the Review Questions and Practical Exercises at the end of [`Chapter03.md`](../Chapter03.md). These are reference answers, not the only correct answers — your wording will differ and that is fine. What matters is whether your reasoning covers the same ground. For the corresponding lab, see [`Labs/Lab03/task-answers.md`](../../Labs/Lab03/task-answers.md).*

---

## Review Questions

**1. Why is full disk imaging no longer practical as the default response for many Windows incidents?**

The operational math has changed. Enterprise systems are routinely measured in terabytes, imaging one of them takes hours, collection storage is finite, and incidents usually involve more than one host. While a responder is occupied preserving one disk in full, volatile evidence on the other affected systems ages out: memory is lost to reboots, journals wrap, sessions close. A policy of "image everything suspicious immediately" sounds thorough. In practice it consumes the responder time that scoping needs, which delays every downstream decision, including containment. None of that makes full imaging obsolete. It makes imaging a decision that has to be justified rather than a default applied automatically.

**2. What kinds of cases still justify full imaging despite the operational cost?**

Cases where the preservation value plausibly exceeds the collection cost. The chapter's list is a good working set: the system is high-value or business-critical; legal or regulatory preservation is likely; attacker tooling appears to have been deleted, so unallocated space and slack matter; broad re-analysis may be needed later; the incident may lead to contractual disputes or external review; or the host appears central to the attacker's persistence, privilege abuse, or lateral movement. In practice that means domain controllers, finance and HR servers, sensitive application servers, and endpoints tied to possible data exposure or an insider allegation. The common thread is that someone other than the response team is likely to want to look at this host again, later, with different questions.

**3. Why is targeted triage not simply a lesser or weaker form of collection?**

Because a well-designed triage package is a *selected* collection set tied to specific investigative questions, not a partial one produced by running out of time. It deliberately captures the artifacts most likely to answer active-threat, execution, persistence, impact, and scope questions. Those include MFT and USN data, registry hives, key event logs, Prefetch, Amcache, SRUM, shell artifacts, browser history, scheduled tasks and services, user profile artifacts, and memory where volatility matters. That set answers most incident response questions faster than a full image would. It also scales across many hosts, which is what actually determines how quickly scope gets established. Triage is weaker only in one dimension: "artifacts nobody thought to ask for." The honest response is to name that as residual risk rather than pretend it does not exist.

**4. What categories of evidence make memory acquisition especially valuable?**

The evidence that never existed on disk in usable form, or that disappears the moment the system changes state: running processes and their state, full command-line arguments, injected code, fileless malware, active and recent network socket state, PowerShell remnants, decrypted content, logon sessions and tokens and credentials, clipboard and console history, and references to files, registry keys, and named pipes. If the working hypothesis involves web shells, short-lived PowerShell, in-memory beacons, or process injection, memory is often the highest-value target on the host. It may be the only place the answer exists. It is also the source that an ordinary, well-intentioned remediation action is most likely to destroy.

**5. Why should memory often be captured before shutdown or containment actions?**

Because containment destroys it. A reboot, shutdown, reimage, service restart, network isolation that trips a watchdog, or an unplanned crash can all remove the best evidence on the host. None of those actions are reversible. The rule is simple: if memory matters for this case, capture it before you change the system's state. Memory does not always come first. In some cases active spread makes immediate isolation the right call, and memory is the accepted loss. What the chapter insists on is that skipping or deferring memory capture be a conscious, documented decision. It should not be something that happened because someone rebooted the box while the team was talking.

**6. What information must be documented for a full disk image to be trustworthy later?**

Case reference; hostname; acquisition date and time in UTC; who performed the acquisition and who authorized it; source device description, serial or identifier, and interface; whether a write blocker was used and, if not, why; imaging tool and version; output format; destination path; the image file name or the segmented file names; hash algorithm and hash values; and any errors, interruptions, or notes. The two fields most often skipped are the source device identifier and the write-blocker justification. They are exactly the two a reviewer will probe. The first matters because imaging the wrong disk is both an operational and an evidentiary failure. The second matters because "we didn't use one" with a reason is defensible, and without a reason it is not.

**7. Why should original images and memory captures be preserved separately from working copies?**

Because the original is ground truth, and analysis is an activity that touches things. Keep the original in a controlled location, write-protected or logically protected, and you can resolve any dispute about what changed by producing a fresh verified copy. Skipping the separation under time pressure produces three predictable problems: accidental modification of the source, confusion about which file is which when several copies exist, and an inability to answer "how do you know the evidence you analyzed matches what you collected." Hashing at acquisition is what makes the separation meaningful. The hash is how you prove a working copy is equivalent to the original.

**8. How do operational constraints affect the defensibility of a triage strategy?**

Documented constraints are what make a proportionate decision look reasonable instead of lazy. Defensible does not mean perfect. It means reasonable, documented, and proportionate to the facts available at the time. A reviewer six months later cannot evaluate whether deferring a server was sensible unless they know the context: two higher-priority hosts competing for a two-person team, and leadership needing same-day scope. Record staffing levels, storage limits, maintenance windows, business disruption concerns, and legal preservation requirements. That record converts "we didn't get to it" into "we made this tradeoff for this reason." The composite engagement in section 3.4 makes the point concretely: the artifact that protected the team afterward was not the timeline but the triage decision memo.

**9. Why does acknowledging residual risk strengthen rather than weaken a collection plan?**

Because a plan that claims to answer everything is not credible, and a reviewer who finds an unacknowledged gap will discount everything else in it. Naming the residual risks demonstrates that the team understood the consequences of its choices. Those risks include some hosts not receiving deep collection immediately, volatile evidence lost on lower-priority systems before responders reach them, and same-day scope conclusions resting on partial data. They also include deferred systems potentially proving more important than current indicators suggest, and artifacts outside the triage set not being preserved. Naming them also has an operational payoff. Written residual risks are the list you revisit when new facts arrive, which is what makes the strategy revisable rather than merely defended.

**10. What kinds of new facts should trigger a triage strategy revision?**

Anything that changes a host's likely evidence value or the incident's scope. New authentication evidence tying an account to a system that was previously out of scope. Large-scale file access or copy activity on a share. Suspicious macro or script execution on a host that had received only Tier 1 collection. VPN or remote access activity from an unexpected source. Discovery of credential theft, which immediately promotes domain controllers and any host where those credentials were used. Evidence that attacker tooling was deleted, which raises the value of a full image on that host. Confirmation that an alerted host was a false positive, which frees capacity. The chapter requires each revision to be tied to a specific triggering fact and recorded with a timestamp. Revision without a stated trigger reads as inconsistency. Revision with one reads as disciplined adaptation.

---

## Practical Exercises

**1. Compare three Windows hosts with different business and investigative value and assign full imaging, targeted triage, or deferred collection to each.**

**What you should end up with:** A three-row decision table with the assignment and, more importantly, the reasoning for each.

**How to get there:** Pick hosts that genuinely differ, such as a domain controller with suspicious authentication activity, a finance workstation that generated the original EDR alert, and a conference-room print server that appeared in one lateral-movement log line. Score each across the dimensions in 3.4.2: business criticality, likelihood of relevant evidence, volatility risk, scope value, operational disruption risk, and legal preservation value. Then assign a tier and a collection depth.

**What good looks like:** The assignments are not all the same, and the reasoning distinguishes *criticality* from *evidence likelihood*, two things that get conflated constantly. A domain controller is critical but may hold thin host-level evidence. The alerting workstation may be operationally trivial and hold everything. Your table should also state what you gave up on the deferred host and what would promote it.

**2. Build a minimum viable Windows triage package for a suspicious user workstation.**

**What you should end up with:** An explicit artifact list — paths, not categories — that constitutes your Tier 1 collection.

**How to get there:** Work from 3.1.3 and make it concrete. `$MFT` and `$Extend\$UsnJrnl:$J`. `%SystemRoot%\System32\winevt\Logs\` for at least Security, System, Application, PowerShell Operational, TaskScheduler, and TerminalServices logs. `%SystemRoot%\System32\config\` for SYSTEM, SOFTWARE, SAM, SECURITY plus `.LOG1`/`.LOG2`. Per-user `NTUSER.DAT` and `UsrClass.dat` with their transaction logs. `%SystemRoot%\Prefetch\`. `%SystemRoot%\AppCompat\Programs\Amcache.hve`. `%SystemRoot%\System32\sru\`. `%APPDATA%\Microsoft\Windows\Recent\` including `AutomaticDestinations`. Browser history databases. `%SystemRoot%\System32\Tasks\`. `%SystemRoot%\INF\setupapi.dev.log`.

**What good looks like:** Every entry maps to a question you can name. If you cannot say which of the six IR question categories an artifact serves, it does not belong in a *minimum viable* package. The package should also be small enough to collect in minutes. If yours takes an hour, it is a Tier 2 set, and you should say so.

**3. Design a PowerShell triage script structure that creates a case directory, copies selected artifacts, compresses them, and hashes the result.**

**What you should end up with:** A script skeleton with clear phases. Structure and comments are enough, and a working script is better.

**How to get there:** Structure it as: parameter block (case ID, hostname, output root), create a timestamped case directory, write a collection manifest header, copy each artifact group into a subfolder while logging success or failure per item, compress the case directory, compute `Get-FileHash -Algorithm SHA256` on the archive, and append the hash plus the tool version and the exact invocation to the manifest. Locked files such as `$MFT` and live registry hives cannot be copied with `Copy-Item`. The script needs a raw-handle approach or a tool such as KAPE, RawCopy, or FTK Imager, and the design should acknowledge that rather than silently fail.

**What good looks like:** The script logs what it *failed* to collect as prominently as what it collected. A triage script that quietly skips a locked hive produces a collection that looks complete and is not. The manifest should be readable as a standalone evidence record: host, operator, start and end times in UTC, per-artifact status, archive name, size, and hash.

**4. Practice hashing a sample archive and recording the result in a simple evidence handling record.**

**What you should end up with:** A hash recorded in an evidence record, verified twice.

**How to get there:** Take the archive from exercise 3, or any sample archive. Run `Get-FileHash -Algorithm SHA256 .\triage.zip` and record the digest, the file size, the UTC time, the tool, and the operator. Copy the archive to a second location, hash the copy, and record that the values match. If you have a Linux analysis host, `sha256sum` the same file there and confirm the value is identical across platforms.

**What good looks like:** The record contains the hash at acquisition and at least one independent verification. The cross-tool or cross-platform check is worth doing once deliberately, because it makes concrete why hashing works as an integrity control rather than a tool-specific assertion.

**5. Write a management-facing note explaining why the team did not image every host immediately.**

**What you should end up with:** A short memo in business language, not forensic jargon, that a CISO could forward.

**How to get there:** State what was collected and from how many hosts. State the alternative (imaging every host) and its cost in responder-hours and calendar time. State what that cost would have bought and what it would have delayed. Then state the residual risk you accepted, plus the conditions under which you would escalate a host to full imaging. The composite in section 3.4 is the model: 40 endpoints, two full images, 35 triage collections, three excluded as known false positives, 32 hours instead of 6 days.

**What good looks like:** It quantifies. "Imaging all forty hosts would have occupied the team through Wednesday, during which the active intruder would have had three additional days of access" lands with an executive in a way that "full imaging is operationally impractical" does not. It also names the escalation path explicitly, so the note reads as a decision the team owns rather than a corner it cut.

**6. Plan a full disk imaging workflow for a high-value Windows server with legal preservation concerns.**

**What you should end up with:** An ordered workflow covering authorization, coordination, acquisition, verification, and storage.

**How to get there:** Start with authorization and the legal hold instruction in writing. Coordinate the maintenance window with the business owner. Identify the source device precisely by serial, interface, and capacity, and record it before touching anything. Decide the acquisition mode and document the reason: offline with a write blocker if the server can be taken down, live if it cannot. Capture memory *first* if the host will be powered down. Image with a named tool and version to a documented destination and format, and hash during acquisition. Verify the hash independently afterward, store the original under access control, and produce a working copy for analysis.

**What good looks like:** The workflow states explicitly whether a write blocker is used and why or why not, and it captures memory before shutdown rather than after. Every documented field from 3.2.3 has a place to be filled in. If the plan does not survive the business owner saying "you cannot take this offline until Sunday," it is not a plan. Add the live-acquisition branch and its documented limitations.

**7. Build a live memory acquisition workflow for a production Windows system and document the operational tradeoffs.**

**What you should end up with:** A procedure plus an honest tradeoff section.

**How to get there:** Choose a tool appropriate to the environment, such as WinPmem, DumpIt, FTK Imager, or EDR live response, and record the version. Write the destination to external or network storage rather than the source volume, so you are not overwriting evidence on the disk you may image next. Record everything from 3.3.6: case reference, hostname, collection time in UTC, reason for the capture, who authorized it, current system status, tool and version, the exact command, output name and location, approximate size, hash, whether `pagefile.sys` and `hiberfil.sys` were also collected, warnings or errors, and the next planned collection step.

**What good looks like:** The tradeoff section is specific rather than boilerplate. The capture changes running system state, briefly consumes memory and I/O on a production host, and produces a file the size of physical RAM. It can fail or destabilize sensitive systems, and not all of the captured content will be interpretable. Also plan for the pagefile and hibernation file explicitly. They are the most commonly forgotten part of the memory picture, and they carry paged-out content the live capture may miss.

**8. Create a triage strategy note that prioritizes hosts, acknowledges constraints, and defines escalation triggers.**

**What you should end up with:** A single document covering everything in 3.4.7.

**How to get there:** List the known hosts with a one-line initial assessment each. State the primary triage objectives in question form. Rank the hosts and assign collection tiers. Name the operational constraints: responder count, storage, maintenance windows, leadership deadlines, legal preservation instructions. List the residual risks. Define the escalation triggers explicitly. Set the next review point with a time on it.

**What good looks like:** The escalation triggers are testable conditions, not sentiments. "Escalate any host to Tier 3 if credential theft is confirmed on it, if it authenticates to a domain controller with the compromised account, or if attacker tooling is found deleted rather than present." A next review point with an actual clock time makes the note a living document instead of a one-time artifact.

**9. Revise the triage strategy when new facts expand incident scope and document what changed.**

**What you should end up with:** A dated revision entry appended to the exercise 8 note, not a rewritten version of it.

**How to get there:** Introduce a plausible new fact, such as a 4624 Type 3 logon from the compromised workstation's account to a file server at 03:12, or the discovery that a deferred host holds the only copy of a dataset the attacker accessed. Record the fact, its source, and its timestamp. State which host priorities changed and to what. State what collection action follows and by when. State what the revision costs: which previously planned work is now deferred.

**What good looks like:** The original note is intact and the revision sits below it with its own timestamp, so the reasoning history is preserved. This is the same discipline as the case log in Chapter 2: do not rewrite the record to look like you were right from the start. A reviewer should be able to see what was known at each point and judge the decision against that, which is the only fair standard.

---

## Common mistakes on this chapter

- **Treating "full image" as the rigorous choice and "triage" as the shortcut.** This framing is wrong and it produces bad incidents. A targeted collection tied to named questions, executed across every affected host in the first two hours, answers scope faster than a full image of one machine, and scope is what containment waits on. The rigor lives in whether the choice was reasoned and documented, not in how many bytes were copied.
- **Rebooting or containing before capturing memory, then noting it afterward.** Once the box is down, no amount of documentation recovers process state, sockets, injected code, or credentials. If memory matters, it comes before the state change. Deciding to skip it is legitimate. Discovering you skipped it is not.
- **Documenting the collection but not the reasoning.** Collection records reliably capture tool, version, command, and hash, and reliably omit *why this host and not that one*. Six months later, the technical record is the easy part to reproduce. The decision rationale is the part nobody can reconstruct. The triage decision memo is the artifact that protects the team.
- **Forgetting the pagefile and hibernation file.** They are memory-derived evidence sitting on disk, they survive the reboot that destroyed the live capture opportunity, and they are cheap to collect during any imaging or triage pass. They do not replace a live memory image, but leaving them behind is a gap with no upside.
- **Writing residual risk sections that say nothing.** "Some evidence may not have been collected" is a hedge, not an acknowledgment of risk. Name the specific hosts, the specific artifacts, and the specific conclusions that would be affected. That list is also your revision checklist when new facts arrive.
- **Treating the triage strategy as a document you write once.** A plan that never changes across a multi-day incident is stale, not stable. Each revision tied to a named triggering fact with a timestamp reads as disciplined adaptation. Silence in the record while priorities visibly shift reads as improvisation.

---

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) book series.*
