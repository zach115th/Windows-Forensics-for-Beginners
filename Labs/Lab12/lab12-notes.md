# Lab 12 — Analyst Notes
**Ransomware Incident Response**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Lab Environment:** ___________________________  
**Case Reference:** IR-2024-ACCTFS01  
**Host Under Investigation:** ___________________________  
**Accounts of Interest:** ___________________________  
**Ransomware Family / Extension:** ___________________________  

---

## Task 1 — Manage the Clocks and Write the Preservation Request

> Do the thing that has to happen in the first hour, before any artifact is opened.

**Part A — Name the clocks.**

| Clock | Who sets it | What it pressures you to do | Investigative cost if it wins |
|---|---|---|---|
| Recovery | | | |
| Negotiation | | | |
| Notification | | | |
| Insurance | | | |

**Part B — The preservation request (max 150 words, sent 07:20).**

```
[Your preservation request here]
```

**Part C — Acquisition order.**

| Item | Order (1–7) | Why here |
|---|---|---|
| Memory image of `ACCT-FS01` | | |
| Disk image of `ACCT-FS01` | | |
| Domain controller Security logs | | |
| Jump host (`JUMP-01`) disk and logs | | |
| Perimeter firewall / VPN logs | | |
| Backup platform logs and catalog state | | |
| EDR telemetry export | | |

**Part D — Your client.**

| Question | Answer |
|---|---|
| Who do you believe your client is? | |
| How would you confirm it? | |
| What changes in your reporting depending on the answer? | |

**1. Why is the memory capture urgent in a way that the disk image is not?**
```
[Your response here]
```

**2. The four clocks conflict. Which conflict is the responder's job to name out loud, and to whom?**
```
[Your response here]
```

**3. What is lost, specifically and permanently, if `ACCT-FS01` is reimaged at 14:00?**
```
[Your response here]
```

---

## Task 2 — Receive the Case and Inventory the Inputs

> Start where real responders start — with whatever the previous shift left behind.

**Part A — Collection inventory.**

| Question | Answer |
|---|---|
| Which artifact classes are available? | |
| Which files were collected from a host other than `ACCT-FS01`, and why are they here? | |
| What is missing that you would want, and what would each missing item have told you? | |
| How many rows are in `security-evtx.csv`, and what is the timestamp of the first one? | |
| What does that first row tell you about everything you will *not* find in that file? | |

**Part B — Evidence integrity.**

| Evidence Item | Source Path | SHA-256 (first 16) | Working Copy? | Notes |
|---|---|---|---|---|
| `mft.csv` | | | | |
| `usn-journal.csv` | | | | |
| `encrypted-files-inventory.csv` | | | | |
| `security-evtx.csv` | | | | |
| `dc-security-evtx.csv` | | | | |
| `jumphost-security-evtx.csv` | | | | |
| `system-evtx.csv` | | | | |
| `defender-evtx.csv` | | | | |
| `terminalservices-evtx.csv` | | | | |
| `powershell-evtx.csv` | | | | |
| `prefetch.csv` | | | | |
| `amcache.csv` | | | | |
| `shimcache.csv` | | | | |
| `registry-runkeys.csv` | | | | |
| `network-flow.csv` | | | | |
| `srum.csv` | | | | |
| `ransom-note.txt` | | | | |
| `rclone-conf-recovered.txt` | | | | |
| `vssadmin-list-shadows.txt` | | | | |

**Part C — What the ransom note gives you.**

| Item from the note | Value | Who needs it |
|---|---|---|
| Family / strain indicator | | |
| Encrypted-file extension | | |
| Victim identifier | | |
| Contact channel | | |
| Claimed exfiltration volume | | |
| Stated deadline structure | | |

**1. The note claims data was copied before encryption. What evidentiary weight does that claim carry, and why?**
```
[Your response here]
```

**2. Why should one copy of the note be preserved as evidence rather than deleted with the rest of the encrypted set?**
```
[Your response here]
```

**3. Which two items in your Part C table would you send to threat intelligence within the first hour, and what would you hope to get back?**
```
[Your response here]
```

---

## Task 3 — Map the Kill Chain to Artifacts

> Build the lookup table you will use for the rest of the lab. At least eight rows.

| Stage | Artifact(s) in this dataset | Survived the log clear? | What it proves |
|---|---|---|---|
| Initial access | | | |
| Persistence | | | |
| Credential access | | | |
| Discovery | | | |
| Lateral movement | | | |
| Collection and staging | | | |
| Exfiltration | | | |
| Defense evasion | | | |
| Encryption | | | |

**1. Which stages have evidence *only* from sources outside `ACCT-FS01`? What does that tell you about collection priorities on the next case?**
```
[Your response here]
```

**2. Which single artifact class in your table would you least want to lose, and why?**
```
[Your response here]
```

**3. How does the Prefetch-flush caveat change how you write the "encryption performed locally" finding?**
```
[Your response here]
```

---

## Task 4 — Sweep the Encrypted Extension

> Produce the blast-radius numbers the recovery team cannot plan without.

| Measure | Value |
|---|---|
| Total encrypted file count | |
| Total encrypted data volume (bytes / GiB) | |
| Number of affected directories | |
| Directory with the highest **file count** | |
| Directory with the highest **data volume** | |
| Earliest `$SI` Modified across the encrypted set | |
| Latest `$SI` Modified across the encrypted set | |

**Per-directory breakdown (top eight by count, plus top three by volume):**

| Directory | File count | Bytes | Share of total count | Share of total volume |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

**1. The count ranking and the volume ranking put different directories at the top. Which ranking does the recovery team need, and which does counsel need?**
```
[Your response here]
```

**2. `C:\Shares\Finance\Reports\Archive` has no `.vaulted` files. Two competing explanations, and the evidence that separates them:**
```
[Your response here]
```

**3. Why is every number here explicitly preliminary, and what does that mean for a 09:00 executive update?**
```
[Your response here]
```

---

## Task 5 — Establish the Encryption Window from the USN Journal

> Derive the window from the file-system record, not from the ransom note.

**Part A — Binning.**

| Measure | Value |
|---|---|
| First minute bin with encryption-consistent activity | |
| Last minute bin with encryption-consistent activity | |
| Duration | |
| Total USN records inside the window | |
| Peak records in a single minute | |
| Lowest records in a single minute *inside* the window | |
| Typical records per minute in the two hours *before* the window | |

**Part B — Signature properties.**

| Property | Present? | Evidence |
|---|---|---|
| Sustained high rate | | |
| Uniform reason-code sequence per file | | |
| Rename pairs, new name = old name + extension | | |
| Records grouped by directory in a deterministic walk order | | |
| Interleaved note creation at directory boundaries | | |

**Part C — The trough.**

| Question | Answer |
|---|---|
| Which minutes? | |
| What caused it? | |
| How could it be misread? | |

**1. Why is the USN Journal a better source for the encryption window than the `$SI` Modified timestamps on the encrypted files?**
```
[Your response here]
```

**2. What would the per-minute curve look like if the encryption had been performed over SMB from three hosts simultaneously?**
```
[Your response here]
```

**3. Which of your conclusions depend on the *rate*, and which depend only on the *shape*?**
```
[Your response here]
```

---

## Task 6 — Map the Blast Radius from Ransom-Note Placement

> Filter the MFT for the note filename and sort by `$SI` Born. All 24 directories.

| Order | Directory | Note `$SI` Born (UTC) | Gap from previous | Files in directory |
|---|---|---|---|---|
| 1 | | | — | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |
| 6 | | | | |
| 7 | | | | |
| 8 | | | | |
| 9 | | | | |
| 10 | | | | |
| 11 | | | | |
| 12 | | | | |
| 13 | | | | |
| 14 | | | | |
| 15 | | | | |
| 16 | | | | |
| 17 | | | | |
| 18 | | | | |
| 19 | | | | |
| 20 | | | | |
| 21 | | | | |
| 22 | | | | |
| 23 | | | | |
| 24 | | | | |

**1. What does note placement give you that a per-file extension sweep does not?**
```
[Your response here]
```

**2. Which consecutive pair has the largest gap, and what explains it?**
```
[Your response here]
```

**3. If a second host carried the same note filename but a different victim identifier, what would that suggest and what would you do?**
```
[Your response here]
```

**4. What does the presence of `C:\Users\svc-backup\Documents` in the encrypted set tell you about the account the encryptor ran as?**
```
[Your response here]
```

---

## Task 7 — Prove Where the Encryption Ran

> Local execution or remote SMB encryption? Prove it, do not assume it.

| Evidence | Local execution predicts | Remote SMB execution predicts | What this dataset shows |
|---|---|---|---|
| 4688 for the encryptor | | | |
| Prefetch entry for the encryptor | | | |
| Amcache / ShimCache entry | | | |
| Encryptor binary on disk (MFT) | | | |
| Security 5140 / 5145 volume | | | |
| Network flow to port 445 during the window | | | |

**Conclusion:** ___________________________  **Confidence:** ___________________________

**1. Which single piece of evidence is strongest for your conclusion, and what is its weakness?**
```
[Your response here]
```

**2. If Prefetch had been disabled, what would you still have, and would the conclusion survive?**
```
[Your response here]
```

**3. What single query would you run first on the next case to avoid hunting a binary that never existed?**
```
[Your response here]
```

---

## Task 8 — Reconstruct the Defense-Evasion Sequence

> Rebuild a chain whose primary evidence source was deliberately destroyed. At least six steps.

| # | Time (UTC) | Action | Evidencing artifact(s) | 4688 survived? |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |
| 6 | | | | |
| 7 | | | | |
| 8 | | | | |

| Measure | Value |
|---|---|
| Interval from the first evasion action to the first encrypted file | |
| Interval from the log clear to the first encrypted file | |
| Account named in the 1102 record | |
| Earliest surviving record in `security-evtx.csv` | |

**1. What two separate findings does the single 1102 record establish?**
```
[Your response here]
```

**2. Defender quarantined actor tooling days before it was disabled. Why is that "a gift"?**
```
[Your response here]
```

**3. What does the exclusion-then-disable ordering tell you about the actor's operational discipline?**
```
[Your response here]
```

**4. Name three evidence sources a log-clearing actor commonly forgets, and what each contributed here.**
```
[Your response here]
```

---

## Task 9 — Chain Backwards to Patient Zero

> One confirmed link at a time, from the encryptor to the entry point.

**Part A — Anchor on the encryptor.**

| Question | Answer | Source |
|---|---|---|
| What process performed the encryption? | | |
| What account did it run as? | | |
| When did the binary arrive on disk? | | |
| How long between arrival and execution? | | |

**Part B — Account-centric timeline for `FINANCE\svc-backup` (at least twelve rows).**

| Time (UTC) | Event ID | Host | Logon type / detail | Normal or anomalous | Why |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |

**The account's established pattern was:**
```
[Your response here]
```

**The behaviour diverges at:** ___________________________

**Part C — Host hops.**

| Hop | From | To | Source-side artifact | Destination-side artifact |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |

**Part D — Entry-point confirmation.**

| Measure | Value | Source |
|---|---|---|
| Failed-logon count | | |
| Burst start / end | | |
| Successful logon time | | |
| Logon type | | |
| Source IP | | |
| Independent corroboration #1 | | |
| Independent corroboration #2 | | |

**Part E — The dwell-window sentence, as it would appear in the report:**
```
[Your response here]
```

**1. A domain admin account appears partway through the dwell window. When, and what does that tell you about a host you have not looked at?**
```
[Your response here]
```

**2. What is the one sentence that would have saved the team in the chapter's field composite?**
```
[Your response here]
```

**3. Why is the domain controller Security log the highest-priority collection on day one?**
```
[Your response here]
```

---

## Task 10 — Investigate Staging and the Transfer Tool

> Reconstruct a directory the actor deleted.

**Part A — The staging directory.**

| Measure | Value | Source |
|---|---|---|
| When was the directory created? | | |
| How many archive volumes? | | |
| Total staged bytes | | |
| Staging start / end | | |
| When was the directory deleted? | | |
| What else was in it besides the archives? | | |

**Part B — What was actually collected.**

| Source directory in the archive command | Encrypted file count in that tree | Notes |
|---|---|---|
| | | |
| | | |
| | | |
| | | |
| | | |

**Part C — The transfer tool.**

| Artifact | What it shows | Value |
|---|---|---|
| Prefetch | | |
| Amcache | | |
| ShimCache | | |
| MFT | | |
| Recovered configuration | | |
| Command line | | |
| Persistence reference | | |

**1. What does the archive-volume naming cost you when counsel asks which records were affected, and what partially compensates?**
```
[Your response here]
```

**2. What would an rclone `--log-file` have changed about your final confidence tier?**
```
[Your response here]
```

**3. Why is `rclone.conf` "the highest-value single artifact in an exfiltration case"?**
```
[Your response here]
```

---

## Task 11 — Bound the Egress and Write the Exfiltration Finding

> The question with the shortest legal fuse. Answer it honestly.

**Part A — Volume evidence.**

| Source | Measure | Value |
|---|---|---|
| `network-flow.csv` | Session count to `185.220.101.44` | |
| `network-flow.csv` | Total bytes sent to that destination | |
| `network-flow.csv` | First / last session time | |
| `network-flow.csv` | Prior contact with that destination? | |
| `srum.csv` | `rclone.exe` bytes sent, by bucket | |
| `srum.csv` | `rclone.exe` total bytes sent | |
| Staged set | Total archive bytes | |

**Part B — Sanity check.**

| Comparison | Value | Interpretation |
|---|---|---|
| Egress ÷ staged | | |
| SRUM ÷ staged | | |
| Conclusion about transfer completion | | |

**Part C — The confounder.**

| Question | Answer |
|---|---|
| Which legitimate transfer is larger than the exfiltration? | |
| Why is volume alone not the signal? | |

**Part D — The tiered finding.**

| Tier | Applies here? | Why / why not |
|---|---|---|
| Confirmed | | |
| Highly likely | | |
| Possible / cannot be excluded | | |
| No evidence found | | |
| Cannot be determined | | |

**Exfiltration finding (one paragraph, tier stated explicitly, evidence named, at least two gaps named):**
```
[Your response here]
```

**1. What single additional artifact would move this finding to "Confirmed"?**
```
[Your response here]
```

**2. Explain to a non-technical executive, in two sentences, the difference between "no evidence found" and "cannot be determined".**
```
[Your response here]
```

**3. The leak site publishes a matching directory listing next week. How does that change your finding, and how does it not?**
```
[Your response here]
```

---

## Task 12 — Deliver the Four Recovery Assessments

> Every row needs a confidence level and an explicit statement of what would raise it.

| Assessment | Your answer | Primary evidence | Confidence | What would raise it |
|---|---|---|---|---|
| Scope confidence | | | | |
| Actor presence | | | | |
| Backup trustworthiness | | | | |
| Reinfection risk | | | | |

**Part A — Persistence inventory (at least four entries).**

| Mechanism | Artifact | Established (UTC) | Would survive a restore? |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |

**Part B — Backup viability.**

| Question | Answer | Basis |
|---|---|---|
| Do the backups exist? | | |
| Are they clean? | | |
| Are they complete? | | |

**Part C — Remediation prerequisites (at least six, each a verifiable statement).**

1.
2.
3.
4.
5.
6.

**1. Which assessment can you give with the highest confidence, and which with the lowest?**
```
[Your response here]
```

**2. A backup taken on 2024-11-10 is offered as the restore point. Your response, and the evidence for it:**
```
[Your response here]
```

**3. Why is "we checked the backup image for the persistence artifacts we found in production" worth more than "we believe the backup is clean"?**
```
[Your response here]
```

---

## Task 13 — Write the Incident Summary and Handoff

> Turn thirteen tasks of findings into two documents someone else can act on.

**Part A — Scoping deliverable.**

| Field | ACCT-FS01 |
|---|---|
| Encryption start (UTC) | |
| Encryption stop (UTC) | |
| Duration | |
| Encrypted file count | |
| Encrypted data volume | |
| Affected directories | |
| Directories excluded | |
| Encryption performed locally? | |
| Shadow copies available? | |

**Part B — Incident summary (1–3 pages).**
```
[Your incident summary here — scope, evidence sources, dwell window with retention
boundary, kill chain narrative, exfiltration finding with tier, the four recovery
assessments, gaps and uncertainties, recommended next steps]
```

**Part C — Handoff note.**
```
Case Reference:
Author:
Date/Time (UTC):

Primary Questions:
-

Confirmed Findings:
-

Findings With Stated Confidence Below "Confirmed":
-

Dwell Window (with retention boundary):
-

Exfiltration Finding (tier + basis + gaps):
-

Persistence Not Yet Remediated:
-

Remediation Prerequisites Before Restore:
1.
2.
3.

Open Questions:
-

Preservation Issues to Escalate:
-

Notes for Incoming Analyst:
```

**Part D — "Do you think we should pay?" (max four sentences, verbatim):**
```
[Your response here]
```

**1. Which sentence in your summary is most likely to be quoted out of context, and how did you phrase it defensively?**
```
[Your response here]
```

**2. Why does advocating a position on payment cost you neutrality on everything else in the same report?**
```
[Your response here]
```

**3. What did this case reveal about logging and preservation posture that belongs in the recommendations rather than the findings?**
```
[Your response here]
```

---

## Walkthrough Working Space

> Use this section to record the raw output of the Hands-On Walkthrough queries before you distil them into the task tables above.

| Step | Query run | Result | Matches expected? |
|---|---|---|---|
| 1 — Ransom note | | | |
| 2 — Extension sweep | | | |
| 3 — Note placement | | | |
| 4 — USN binning | | | |
| 5 — Local execution | | | |
| 6 — Evasion sequence | | | |
| 7 — Backwards chain | | | |
| 8 — Staging and egress | | | |
| 9 — Persistence and assessments | | | |

**Any step where your result differed from the expected value — record it here with your explanation:**
```
[Your response here]
```

---

## Case Log

> Contemporaneous notes. Timestamp every entry.

| Time (UTC) | Action taken | Result / observation |
|---|---|---|
| | | |
| | | |
| | | |
| | | |
| | | |
| | | |
| | | |
| | | |

---

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
