# Chapter 10 — Review Question and Exercise Answers

*Sample answers for the Review Questions and Practical Exercises at the end of [`Chapter10.md`](../Chapter10.md). These are reference answers, not the only correct answers. Your wording will differ, and that is fine. What matters is whether your reasoning covers the same ground. For the corresponding lab, see [`Labs/Lab10/task-answers.md`](../../Labs/Lab10/task-answers.md).*

---

## Review Questions

**1. Why does a chronological view often produce stronger conclusions than artifact-by-artifact analysis?**

Artifact-by-artifact analysis answers localized questions, such as *did this binary run*, *did this file exist*, and *did this connection happen*, and each answer is a fragment. A chronological view puts the fragments in the order events actually occurred, which is where causation becomes visible. A file created 33 seconds after a PowerShell process launched, executed 52 seconds after that, and deleted under three minutes later is a sequence, not three coincidences. The time ordering also makes multi-source corroboration visible at a glance. When the MFT, Prefetch, Security log, and network flow all place the same event at the same moment, the finding is much harder to dispute than any one of them alone. Independent subsystems were never designed to agree with each other, so when they do, the convergence itself is evidence.

**2. In what circumstances is a super timeline the right choice, and in what circumstances is a targeted timeline?**

A super timeline is right when the question is broad and the relevant window is unknown. It also needs an investigation that will run long enough that re-filtering existing data beats re-extracting it, plus the storage, processing capacity, and time to build and load tens of millions of rows. Deep post-containment analysis, long-running intrusion investigations, and cases where you expect to return with new hypotheses all fit. A targeted timeline is right when speed matters, when the window is known or narrowable from host evidence, when the output has to be readable by a non-specialist, and when the analysis is iterative: you build it, learn something, and rebuild. Active incident response is almost always the second case. The common failure is defaulting to the super timeline because it is thorough, then spending the first four hours of an incident building something nobody can read.

**3. Why is normalizing all timestamps to UTC standard practice?**

Artifact sources record time in inconsistent ways, and mixing them silently corrupts the ordering. Some tools emit UTC, some emit the analysis host's local time, some emit the evidence host's local time, and some vary by artifact within a single output. Merging without normalizing produces a timeline where events appear in the wrong sequence. That inverts causation and produces conclusions that are not merely imprecise but backwards. UTC also removes daylight saving transitions, which otherwise create an hour where timestamps are ambiguous or appear to run backwards. And it makes cross-host and cross-timezone correlation mechanical. The discipline is to confirm each tool's output timezone rather than assume it, and to convert during the merge. Record the timezone of every source in the timeline metadata so a reviewer can check your conversions.

**4. What is the practical effect of clock skew on cross-host correlation?**

Skew shifts every timestamp produced by a host by the same amount, so a host running five seconds fast makes all of its artifacts appear five seconds later than they occurred. Within a single host that is harmless, because relative ordering is preserved and internal sequences remain correct. Across hosts it is corrosive. Events that were simultaneous appear sequential, events that were sequential appear simultaneous or reversed, and a lateral movement reconstruction that depends on "the outbound connection preceded the inbound logon" can invert. Domain-synchronized hosts usually drift only seconds, which is tolerable for most IR questions. Isolated, misconfigured, or virtualized hosts with poor time sources can drift much further. To handle skew, record each host's reported time at collection (`w32tm /query /status`) and document the known skew as timeline metadata. Correct for it where the analysis actually depends on sub-minute cross-host ordering.

**5. What columns should appear in a useful merged timeline at minimum?**

Seven: the normalized UTC timestamp; the artifact source (which tool or artifact produced the entry); a plain-language event description; a source detail field carrying the source-specific context (file path, event ID, process name, IP address); a significance annotation explaining why the entry matters to the case; a confidence rating; and a notes field for analyst commentary. The first four make the merge possible and the entry traceable back to its origin. The last three turn sorted data into analysis. Without significance and confidence, a timeline is a data dump that shifts the interpretive work onto the reader. This is also the schema that maps onto collaborative platforms: the same columns rename cleanly into IRIS-NG's `event_date` / `event_source` / `event_title` / `event_content` / `event_tags` fields.

**6. What is a pivot event, and how does it shape iterative timeline expansion?**

A pivot event is an entry you are confident belongs to the incident, such as a first execution in Prefetch, a suspicious 4688, a confirmed C2 connection, an EDR detection, or a deliberate deletion. It anchors curation: you examine a window around it, typically ±10 to ±15 minutes initially, and pull in entries that share a process, file, user, or network endpoint. The method's value comes from iteration. Each newly discovered related entry becomes a candidate pivot with its own window, so the timeline grows outward along the actual causal chain rather than expanding uniformly in time. That is how a curated few hundred rows ends up covering a multi-hour incident. A naive fixed-window approach either misses the earlier stages or drags in thousands of irrelevant rows.

**7. Why are annotations as important as the timeline entries themselves?**

Raw entries carry data but not meaning, and the analyst who curated the timeline is the only person who currently holds the reasoning. A row reading `2024-11-14 14:20:11 | MFT | update.exe created in Temp` is verifiable but inert. Adding *significance: payload staged 33 seconds after the encoded PowerShell launched; the delay is consistent with a download cradle* and *confidence: High — Prefetch, which NTFS did not write, shows the same binary ran 52 seconds later* converts it into an argument. Annotations also survive the analyst: a timeline read six months later by a different responder, or by counsel, or by a reviewer, is only as useful as its explanations. Writing them also checks your own reasoning. An entry whose significance you cannot articulate probably should not be in the curated set.

**8. What does a confidence rating express, and how should each level be assigned?**

A confidence rating expresses how much weight the entry can bear, based on how many independent sources support it and how directly. High is for entries where multiple independent artifacts agree. A process creation confirmed by Security 4688, Prefetch, and Amcache is High because three subsystems that do not share a mechanism all record it. Medium is for entries supported by a single reliable artifact that is doing what it was designed to do: an MFT record showing a file creation time, with nothing contradicting it. Low is for entries that are indirect, inferred, or ambiguous, such as an inferred access time, a shellbag whose timestamp semantics are uncertain, or a gap read as deliberate cleanup. The rating is a statement about evidence, not about how strongly you believe the narrative. Mixing those two is how timelines end up with every row marked High.

**9. Why is the final narrative paragraph often the most important output of timeline work?**

It is the part that gets read and acted on. Leadership, counsel, HR, and most of the IR team will not read a 300-row CSV, but they will read four sentences describing what happened in order. The narrative is also a validation test on the timeline itself: if you cannot write a coherent paragraph from the curated entries, the timeline has gaps, contradictions, or unexamined assumptions you have not noticed. The requirement that every sentence be derivable from a specific row keeps the narrative honest. No inference sneaks in without a supporting entry, and any claim that lacks one is exposed immediately. Written that way, the paragraph is at once the executive summary, the working hypothesis, and an index into the underlying evidence.

**10. How does discipline around curation distinguish a strong timeline from a noisy one?**

Curation means every entry earns its place by advancing the narrative or supporting an entry that does. Everything else is set aside: kept in the merged source but excluded from the curated view. A noisy timeline includes everything within the window because filtering felt like it risked losing something. The result is a document nobody reads end to end, in which the load-bearing entries are indistinguishable from background. The disciplined version is small enough to read, which means the reader can actually verify it. Curation also makes silence meaningful: in a deliberately curated timeline a gap is a decision you can interrogate, whereas in a bulk dump it is invisible. Bulk is easy. Clarity is the work.

---

## Practical Exercises

**1. From a chosen lab incident, gather CSV outputs for MFT, Security event log, Prefetch, and SRUM. Place all four files in a single directory.**

**What you should end up with:** A working directory containing four CSVs, plus a manifest recording each file's source artifact, the tool and version that produced it, and its hash.

**How to get there:** If you are working the shipped data, [`Data/WKSTN-221/`](../../Data/WKSTN-221/) has all four ready: `mft.csv`, `security-evtx.csv`, `prefetch.csv`, and `srum.csv`. They are formatted as MFTECmd, EvtxECmd, PECmd, and srum-dump output respectively. If you are working your own lab image, run each tool over the corresponding artifact and drop the output here.

**What good looks like:** The manifest exists before you start merging. It is the provenance record every later finding will point back to, and reconstructing it afterward from memory is where errors enter. Note each file's row count too. It is a cheap sanity check that the merge did not silently drop a source.

**2. Confirm the timezone of each tool's output. Document any conversions needed to bring all sources to UTC.**

**What you should end up with:** A four-row table: source, tool, native output timezone, how you confirmed it, and the conversion applied.

**How to get there:** Do not assume. Check the tool documentation, check for a `Z` suffix or explicit offset in the column values, and verify against an event whose true time you know independently, such as a logon you performed or an event that also appears in a source you have already confirmed. Eric Zimmerman tools generally emit UTC. SRUM output and some SQLite-derived exports frequently do not.

**What good looks like:** Each row names how you verified, not just what you concluded. The shipped WKSTN-221 CSVs are all UTC, which makes this exercise short against that data. The skill it builds is the habit of checking, because the one source you assume is the one that inverts your sequence. Cross-verification against a known event is the technique to internalize.

**3. Build a merged CSV containing entries from all four sources, sorted by UTC timestamp.**

**What you should end up with:** A single CSV using the §10.4.3 schema — Timestamp (UTC), Artifact Source, Event Description, Source Detail, Significance, Confidence, Notes — with entries from all four inputs, sorted ascending by time.

**How to get there:** A spreadsheet works: normalize each source into the seven columns, concatenate, sort. For repeatability, a short Python or PowerShell script per source is better. It reads the native CSV, maps its columns into the common schema, tags the Artifact Source, and emits the normalized rows. [`Labs/Lab10/timeline-template.csv`](../../Labs/Lab10/timeline-template.csv) is the target header shape, with an IRIS-compatible variant alongside it.

**What good looks like:** The Source Detail column preserves enough of the original record to trace the row back: the full file path, the event ID and account, the executable name and run count. Significance and Confidence can be empty at this stage; you fill them during curation. Save the merged file separately from the curated one so you can re-curate later without re-merging.

**4. Identify a pivot event in your merged timeline (a Prefetch first-execution, a suspicious EID 4688, etc.). Curate the merged data down to the entries within ±15 minutes of the pivot.**

**What you should end up with:** A curated CSV covering a roughly 30-minute window, with the pivot marked, containing only entries you have judged relevant.

**How to get there:** In the WKSTN-221 data the natural pivot is `update.exe` first execution at `14:21:03` UTC: Prefetch run count 1, corroborated by Security EID 4688. A ±15 minute window spans about `14:06` to `14:36`. It captures the LNK creation at `14:18:55`, the `OUTLOOK.EXE → POWERSHELL.EXE` spawn at `14:19:38`, the outbound connection at `14:19:42`, the file creation at `14:20:11`, the large transfer at `14:21:55`, the deletion at `14:23:44`, the network logon at `14:31:05`, and the explicit credential use at `14:33:18`.

**What good looks like:** Curation is subtractive as well as additive. Exclude background rows inside the window rather than keeping everything that falls in it. State your inclusion rule explicitly, such as same process, same file, same user, or same network endpoint, so the exclusions are defensible rather than arbitrary. Note that the `14:33:18` EID 4648 sits at the edge of the window and is the entry that should prompt widening it.

**5. Annotate each curated entry with significance and a confidence rating.**

**What you should end up with:** The curated CSV with Significance and Confidence populated on every row, and a note on what the entry does not prove where that matters.

**How to get there:** For each row, write one sentence on why it matters to the case, then assign confidence by counting independent corroborating sources. The `update.exe` execution is High — Prefetch, EID 4688, and Amcache all record it. The file creation at `14:20:11` is only Medium on MFT and USN Journal alone, because NTFS wrote both and they count as one source (§10.7.2). Amcache's SHA-1 and Prefetch's run count come from outside NTFS, and they raise the claim that the binary existed to High. The `14:21:55` transfer is High if both `network-flow.csv` and `srum.csv` support it. An inferred user action with only a shellbag behind it is Low.

**What good looks like:** Confidence varies across rows. If everything is High, you are rating your belief in the narrative rather than the evidence for each entry. The "does not prove" notes matter most on the strongest-looking rows: the outbound connection to `91.214.47.22` is high-confidence as an observation but does not by itself establish that the destination is attacker infrastructure or that data was exfiltrated.

**6. Add at least one entry from a different artifact source (LNK, registry, Amcache, or network) that corroborates the pivot event.**

**What you should end up with:** At least one additional row from a fifth source, positioned in the timeline, with its corroborating relationship stated in the Significance field.

**How to get there:** From the shipped data, `amcache.csv` supplies the SHA-1 for `update.exe`, which corroborates identity rather than just occurrence. `lnk-files.csv` has the `Q4_Payroll_Review.xlsm` LNK created at `14:18:55` that sets up the delivery hypothesis. `network-flow.csv` and [`Data/network/proxy-logs.csv`](../../Data/network/proxy-logs.csv) both carry the `91.214.47.22` sessions, the latter with the `FINANCE\payroll-admin` username attached.

**What good looks like:** The added entry contributes something the existing rows do not, rather than restating them. Amcache adds a hash usable for cross-host hunting and threat intel. The proxy log adds authenticated user attribution that flow data lacks. Say which in the Significance field, because "corroborates" is weaker than "adds the binary hash, enabling environment-wide hunting."

**7. Identify a gap in the timeline — a window with no entries — and document what the gap might mean.**

**What you should end up with:** A named window with start and end times, a list of the sources that would normally produce entries in it, and two or three candidate explanations.

**How to get there:** Scan the curated timeline for stretches with no rows. In the WKSTN-221 window, the interval between the `14:23:44` deletion and the `14:31:05` network logon is a natural candidate: roughly 7 minutes with no recorded activity in the middle of an active incident.

**What good looks like:** You enumerate explanations rather than committing to one. Candidates for that gap: quiet attacker dwell between stages; activity that occurred but produced no artifact in the sources you merged, since interactive keyboard work leaves little; activity captured by a source not in your input set, such as memory, EDR, or the destination host's logs; or deliberately removed evidence. The right output is a list plus the specific next collection that would distinguish between them. Here, that means FILESVR-03's logs and any EDR telemetry for the same window.

**8. Write a one-paragraph narrative summary of the incident, drawn entirely from the curated timeline.**

**What you should end up with:** Four to eight sentences in plain language, each traceable to a specific curated row.

**How to get there:** Walk the curated timeline in order and write one sentence per consequential entry, with the artifact source in parentheses. The chapter's §10.4.7 worked example is the model, and the WKSTN-221 data supports a similar paragraph: file opened and recorded as a LNK at `14:18:55`; `powershell.exe` launched as a child of `outlook.exe` with an encoded command line at `14:19:38` (EID 4688); outbound connection to `91.214.47.22:443` at `14:19:42` (flow); `update.exe` created in `Temp\` at `14:20:11` (MFT, USN); executed at `14:21:03` (Prefetch, 4688); roughly 184 KB out and 2.3 MB in at `14:21:55` (flow, SRUM); deleted at `14:23:44` (USN); explicit credential use to FILESVR-03 at `14:33:18` (EID 4648).

**What good looks like:** No sentence contains a claim you cannot point to a row for. Watch specifically for smuggled inference. Writing "the attacker exfiltrated 184 KB of payroll data" when the timeline supports only "184 KB was sent outbound to an external address" is the failure mode. Keep the artifact citations in, because they let a reader verify without asking you.

**9. Repeat the exercise for a second lab scenario and reuse the merge script or template you built the first time.**

**What you should end up with:** A second merged and curated timeline from a different dataset, plus notes on what you had to change in the tooling.

**How to get there:** [`Data/HR-WS17/`](../../Data/HR-WS17/) is the natural second scenario. It is an insider exfiltration rather than an intrusion, with `mft.csv`, `usn-journal.csv`, `security-evtx.csv`, `prefetch.csv`, `srum.csv`, plus shell and USB artifacts. The pivot there is different in kind: instead of a first execution, it is the USB device installation at `17:42:08` or the personal OneDrive account's first sign-in at `17:46:02`.

**What good looks like:** The merge tooling required only column mapping changes, not a rewrite. That is the payoff of building it as a per-source normalizer rather than a one-off. Your notes should also capture what the second scenario taught you about pivots: an insider case has no single "first execution" moment, so the pivot is a channel event, and the window curation runs outward from it in both directions.

**10. Document the tool versions, source files, and timezone conversions for each timeline you produce.**

**What you should end up with:** A provenance block accompanying each timeline: input files with hashes, the tool and version that produced each, the native timezone of each, the conversion applied, the merge script and version, and the analyst and date.

**How to get there:** Keep it as a header block in the timeline document or a sibling markdown file, and write it as you go. Retrofitting provenance introduces errors, because you will misremember which tool version produced which file.

**What good looks like:** Another analyst could rebuild your timeline from the block alone and get a byte-identical result, or identify precisely why they did not. Tool versions are specific, not generic. The timezone conversion is stated per source, since that is the field most likely to be questioned and the hardest to reconstruct after the fact.

---

## Common mistakes on this chapter

- **Building a super timeline when a targeted one answers the question.** This is the signature error on this material. Plaso over a full disk image produces tens of millions of rows and takes hours to build and more to load. In an active incident, it delivers its first useful output long after the decisions that needed it were made. The chapter is explicit: super timelines suit broad questions, unknown windows, and long-running analysis. Host evidence such as an EDR alert, a Prefetch first-execution, or a 4688 may already give you a window. If it does, a targeted timeline of a few hundred rows answers the question faster and produces something people will actually read.

- **Merging sources without confirming each one's timezone.** Tools disagree about time representation, and a single source silently emitting local time reorders your entire timeline. The damage is worse than imprecision, because reversed ordering inverts causation. A reconstruction claiming the payload was created before the process that downloaded it is wrong in a way that discredits everything around it. Confirm each source against a known event, convert during the merge, and record the conversion.

- **Rating everything High confidence.** Confidence describes the evidence for a specific entry, not your conviction about the narrative. A uniformly High timeline tells the reader nothing and signals that the ratings were not thought about. High belongs to entries where multiple independent artifacts agree. Medium belongs to a single reliable source, and Low to indirect or ambiguous evidence. Variation across rows is what makes the column informative.

- **Producing a timeline with no annotations.** A time-sorted CSV of raw artifact rows is a data dump, not analysis. It shifts the entire interpretive burden onto a reader who does not have the context you do. Significance and Confidence are the columns that make it a document. Writing them also catches entries that do not belong in the curated set.

- **Letting inference leak into the narrative paragraph.** The rule is that every sentence must be derivable from a curated row. "Approximately 184 KB was sent outbound to 91.214.47.22" is supported. "The attacker exfiltrated payroll data" is not. It substitutes a conclusion about content and intent for an observation about volume and destination. This paragraph is the part non-technical readers act on, which makes it the worst place for an unsupported claim.

- **Deleting excluded entries instead of setting them aside.** Curation removes rows from the working view, not from the merged source. Investigations reopen, hypotheses change, and the row you dismissed as background on day one is sometimes the one that matters on day four. Keep the full merged CSV, curate into a separate file, and record the inclusion rule you applied so the curation can be redone against a different question.
