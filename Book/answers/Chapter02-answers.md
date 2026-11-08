# Chapter 2 — Review Question and Exercise Answers

*Sample answers for the Review Questions and Practical Exercises at the end of [`Chapter02.md`](../Chapter02.md). These are reference answers, not the only correct answers — your wording will differ and that is fine. What matters is whether your reasoning covers the same ground. For the corresponding lab, see [`Labs/Lab02/task-answers.md`](../../Labs/Lab02/task-answers.md).*

---

## Review Questions

**1. Why is a question-driven forensic investigation usually more defensible than a tool-driven one?**

A question-driven investigation is more defensible because it is traceable: every collection action has a stated reason, and every conclusion points back to the question it was answering. It starts by naming what has to be proven or disproven. That decides what to collect, in what order, and how to read it. A tool-driven investigation collects first and decides what the evidence means afterward. The result is unfocused evidence sets, duplicated effort, and conclusions that are hard to explain to anyone who was not sitting next to you. The question-driven approach is also faster in practice, because you stop parsing artifacts that cannot change the answer. The tool-driven failure mode is seductive because collecting feels like progress. Exporting event logs and parsing the MFT are useful things to do, but doing them without a reason still wastes the first two hours of an incident.

**2. What are the six major categories of incident response questions described in this chapter?**

The six categories are active threat, initial access, execution, persistence, impact, and scope. Active threat asks whether the attacker is still present or operating right now, here or elsewhere. Initial access asks how they got in: a document, a script, stolen credentials, or an exposed remote service. Execution asks what processes, scripts, or binaries ran, under what user context, and when. Persistence asks whether they established something that survives reboot, logoff, or partial remediation. Impact asks what was accessed, staged, modified, deleted, encrypted, or transferred. Scope asks which other hosts, accounts, services, shares, or data stores may be involved. A working question list should touch every one of these even if some start at low priority, because the categories you skip are the ones that surprise you later. Active threat and scope drive containment decisions. Impact is the one leadership and legal will ask about first.

**3. Why is it dangerous to treat alert language as though it were artifact-verified fact?**

An alert mixes direct telemetry, detection-engine interpretation, and inference from absence, and it does not label which is which. "Suspicious PowerShell observed after the user opened an attachment" may contain a genuinely recorded process chain, an engine's opinion that the behavior was suspicious, and an assumed causal link between the attachment and the process. Treating the interpretation as fact anchors the investigation to a story — usually a phishing story — and makes contradicting evidence harder to see. Statements framed as absence are the most dangerous of the three: "no lateral movement detected" and "no data loss occurred" almost always mean only that nothing generated an alert. The discipline is to break the alert into individual claims and ask, for each one, what the source is and what artifact would confirm or challenge it.

**4. What is the difference between triage and analysis?**

Triage is rapid assessment aimed at decisions. Analysis is careful interpretation aimed at conclusions. Triage answers how urgent this is, whether an active threat is present, whether immediate containment is required, and what to collect first. It typically draws on suspicious processes, active connections, session state, key logs, EDR telemetry, and whether the host is even online. It should produce an explicit containment recommendation: isolate now, collect then isolate, or defer and observe. Record the reasoning rather than leaving it implied. Analysis comes later, works against collected evidence rather than the live system, tests hypotheses, and produces the findings that go into the report. Confusing the two costs time in both directions: deep-diving during triage delays containment, and treating triage impressions as findings puts unverified claims into a report.

**5. Why should hypotheses include elimination conditions, not just confirmation conditions?**

A hypothesis you can only confirm is not a hypothesis. It is a conclusion you have already reached. Defining in advance what evidence would *disprove* the statement is the main structural defense against confirmation bias. Confirmation bias is the failure mode that turns a plausible early theory into an eight-hour detour. If your hypothesis is "a malicious document triggered PowerShell execution," the elimination conditions are concrete: no Office process in the parent chain, no document open in the relevant window, PowerShell invocation predating the mail delivery. If you write those down before you look, you will notice them when they appear. It also improves the report, because "we tested and eliminated X" is a stronger statement than silence about X.

**6. How does a forensic timeline strengthen conclusions drawn from individual artifacts?**

Individual artifacts are ambiguous. Correlated artifacts are not. A Prefetch entry alone tells you a binary ran. Add a matching MFT creation record, a 4688 process-creation event, and an outbound connection in the same two-minute window, and the story becomes very difficult to explain any other way. The timeline is where that convergence becomes visible, because it puts events from different sources on a single axis and exposes both the alignment and the gaps. A good timeline is curated rather than dumped: every entry carries a timestamp, the source artifact, the event description, its significance, and a confidence level. That last field separates a timeline that supports a finding from a spreadsheet that merely contains data.

**7. Why are real-time notes more reliable than retroactive documentation?**

Retroactive notes are reconstructions, not records, and reconstructions are systematically wrong in predictable ways. The details that blur first are the ones that matter. They include exactly when an action was taken, whether the host was isolated before or after the memory capture, and the exact command syntax used. They also include whether a tool threw an error, whether the analyst considered a conclusion tentative at the time, and where the output was written. Memory also quietly rewrites intent. You remember having believed the thing that turned out to be true. Real-time logging costs a few seconds per action. It preserves the actual investigative history, wrong turns included, and that is what makes the record credible rather than tidy.

**8. What information should be present in a handoff note for an active investigation?**

The note needs enough that the incoming analyst can work without interviewing you. It covers what the case is and its current status, what has been completed, what evidence has been collected and where it lives, and what has been analyzed and what has not. It states what is known as fact, what remains unknown, the active hypotheses and their current standing, the known evidence gaps, and the next actions in priority order. Record containment state explicitly: whether the host is isolated, when that happened, and who authorized it. That is the detail most likely to cause a damaging assumption. Escalation and notification expectations should also carry over. The common failure is a handoff note that reads as a summary of what you did rather than a briefing on what happens next.

**9. What are the practical benefits of standardizing documentation and collection workflows across a team?**

The benefits are consistency, speed, and transferability. When every case log, command record, and timeline entry has the same shape, an analyst can pick up any case without learning a new format. Reviews get faster, and quality does not depend on which responder caught the page. Standard collection workflows reduce decision fatigue at 2 a.m. and make results comparable across hosts and across incidents. You can diff two hosts meaningfully only if they were collected the same way. Standardization also surfaces gaps as a program-level issue rather than an individual one. If the standard workflow calls for PowerShell operational logs and they are consistently missing, that is a logging deficiency you can fix organizationally. Finally, it makes newer responders productive faster, because the worksheet encodes why each artifact matters.

**10. What should a responder include in an investigation plan built from a raw alert?**

The plan should include a factual alert summary stripped of speculation, what is known, what is assumed, the active hypotheses, and the systems and accounts in scope. It should give the containment decision with its reasoning, prioritized investigative questions, and the first evidence collection actions in order. It should also list known evidence gaps and any compensating sources, immediate next actions, and escalation or notification expectations. The plan does not need to be long. The target is 15 to 20 minutes of work. It does not need to be right, either. It needs to be executable. Use the test the chapter names: could another analyst pick this up cold and start working from it? If the document only makes sense to its author, it is notes, not a plan.

---

## Practical Exercises

**1. Take a vague Windows endpoint alert and write twelve specific investigative questions organized by category.**

**What you should end up with:** Twelve questions grouped under the six categories from 2.1.2, each one specific enough to be answered yes or no against a named evidence source.

**How to get there:** Start with a deliberately thin alert — "EDR flagged suspicious script activity on FIN-WS23, user reported nothing unusual." Write two questions per category. Force specificity by including a host, an account, a time window, or an artifact in each question. "Was PowerShell used?" becomes "Did `powershell.exe` execute on FIN-WS23 with encoded or obfuscated arguments between 13:00 and 16:00 UTC on the alert date, and under which user context?"

**What good looks like:** Every question names something testable. Read each one and ask "what artifact answers this?" If you cannot name one within a few seconds, the question is still too vague. You should also be able to prioritize them. At least two should be active-threat questions you would answer before making a containment call. The impact and scope questions should be recognizably lower urgency but not absent.

**2. Build a reusable question-to-evidence worksheet for a common Windows workstation compromise scenario.**

**What you should end up with:** A table of question, evidence source, artifact path or event ID, and expected corroborating source, general enough to reuse on the next case. `Labs/Lab02/Lab02_01/question-evidence-worksheet.md` is the scaffold.

**How to get there:** Work down the six categories. Execution maps to Prefetch (`%SystemRoot%\Prefetch\`), Amcache, Security.evtx 4688, Sysmon EID 1, and PowerShell Operational 4104. Initial access maps to browser history, Outlook OST, LNK files, Office recent-file keys, and Security.evtx logon events. Persistence maps to `Run`/`RunOnce`, `Services` (with System.evtx 7045), scheduled tasks, Winlogon hooks, and WMI subscriptions. Impact maps to MFT, USN Journal, SRUM, shellbags, and network telemetry. Scope maps off-host to DC logs, file server access, VPN, and mail gateway.

**What good looks like:** The worksheet holds up when you change the scenario. If swapping "phishing on a workstation" for "suspected credential abuse on a server" requires rewriting every row, you built a case artifact rather than a reusable framework. Include an explicit column for "what makes this source unavailable," such as Prefetch off on servers, Script Block Logging not enabled, or a wrapped journal. That column turns the worksheet into a gap-detection tool.

**3. Create a triage checklist for the first five minutes of a live host response.**

**What you should end up with:** A short ordered checklist, ideally fitting on one screen, that a responder could follow under pressure.

**How to get there:** Order by volatility and by decision value. Confirm host identity and whether it is online. Capture the current process list, active network connections, and logged-on sessions. Check EDR for the alert context and any related detections. Note whether the user is at the keyboard. Check whether the attacker appears active right now. Then produce the containment recommendation. Every item should specify how you do it in your environment: EDR live response, PowerShell, or a triage script. "Check running processes" is not executable at 2 a.m.

**What good looks like:** The checklist ends in a decision, not in a pile of output. It should also record what was *not* done and why. If your checklist includes deep analysis steps such as parsing the MFT, you have written a collection plan rather than a triage checklist. Move those items out.

**4. Draft a documented containment decision for a host with a live outbound connection and justify the risk accepted.**

**What you should end up with:** A short written decision naming the option chosen, the reasoning, who authorized it, and the trigger conditions that would force reassessment.

**How to get there:** Lay out the three options from 2.4.4 honestly. Immediate isolation stops spread and protects other systems but destroys volatile evidence and closes off visibility into the C2 channel. Collect-then-isolate preserves memory and connection state but accepts minutes of continued attacker access. Observation has intelligence value in rare cases and carries the most operational risk. Pick one, and write down what you gave up to get it.

**What good looks like:** The note states the risk you accepted in plain terms, such as "we accepted up to 10 additional minutes of attacker access on this host to capture memory and active socket state before isolation." It also names the triggers that would change the decision: new authentication to another host, encryption activity, or data volume spiking on the outbound flow. A decision with no stated tradeoff and no reassessment trigger is not documented. It is only recorded.

**5. Write a structured volatile and persistent evidence collection workflow for a Windows workstation.**

**What you should end up with:** An ordered collection procedure covering volatile-first acquisition, then persistent artifacts, with tools, output paths, and hashing steps.

**How to get there:** Volatile first: memory image, then process list, active connections, logged-on users, and any live command history, because all of it is gone at reboot. Then persistent: `$MFT` and `$J`, Security/System/Application/PowerShell Operational EVTX, SYSTEM/SOFTWARE/SAM/SECURITY and per-user NTUSER.DAT and UsrClass.dat hives with their transaction logs, Prefetch, Amcache, SRUM, LNK and Jump Lists, browser databases. Specify the tool and version for each step, the destination path, and where the hash gets recorded.

**What good looks like:** Volatility, not convenience, justifies the order. The workflow also says what happens to the output: packaged, hashed, and logged into the case record. A scripted triage collector such as KAPE covers most of the persistent set in one pass. If you use one, the workflow should still name what the target collects rather than treating the tool as a black box.

**6. Build a facts, assumptions, and hypotheses register from a sample alert.**

**What you should end up with:** A three-section register where every fact cites a named source, every assumption is labeled as unverified, and every hypothesis has both confirmation and elimination conditions.

**How to get there:** Take the alert apart claim by claim as in 2.4.2. A recorded parent-child process chain from EDR telemetry is a fact. Cite the telemetry. That the user was physically at the keyboard is an assumption unless a logon type and session record say otherwise. That a macro-enabled document triggered the execution is a hypothesis. Write what would confirm it: an Office process as parent, the document in `Recent\`, and a matching MFT creation. Then write what would eliminate it: no Office process in the chain, or execution predating mail delivery.

**What good looks like:** Nothing in the facts column is an interpretation. The most common error is promoting "the attachment was malicious" from the alert text into the facts section. The fact is that an alert asserted it, which is a different statement. Each hypothesis should be one you would be equally willing to disprove.

**7. Construct a timeline from mixed Windows artifacts and annotate each entry with source and confidence.**

**What you should end up with:** A curated timeline table with timestamp, source artifact, event, significance, and confidence for each row.

**How to get there:** You can do this against real shipped data rather than inventing entries. `Data/WKSTN-221/` contains `mft.csv`, `usn-journal.csv`, `prefetch.csv`, `security-evtx.csv`, `powershell-evtx.csv`, `srum.csv`, and `network-flow.csv` for a single coherent scenario. The `example-curated-timeline.csv` file in the same folder shows what a finished curated timeline looks like. Pull entries from at least three of those sources within a common window, normalize everything to UTC, and sort.

**What good looks like:** The timeline is short. Between 12 and 20 well-chosen rows beat 200 dumped ones, and curation is the skill being exercised. Confidence should vary across rows. An entry corroborated by three sources is High, while a single ambiguous shellbag timestamp is Medium at best. Compare your result against `example-curated-timeline.csv` and pay attention to what that file left out.

**8. Write a case opening note and analyst handoff note for an active Windows incident.**

**What you should end up with:** Two short documents: one that opens the case and one that hands it over mid-flight.

**How to get there:** The opening note covers what was reported, by whom, when, what is known, what is assumed, what is unknown, and the first collection priorities. The handoff note covers the full list from 2.3.7: case status, what is done, what evidence exists and where, what has been analyzed, known and unknown, active hypotheses, evidence gaps, and prioritized next actions — plus containment state and who authorized it.

**What good looks like:** The handoff note is written for the reader, not the writer. To test it, put it away for a day, come back, and try to resume work from the note alone. Anything you have to reconstruct from memory is a gap in the note. Named next actions in priority order are the single highest-value element. A handoff that ends with "continue investigating" has handed over nothing.

**9. Create a one-page investigation plan that another responder could execute without further explanation.**

**What you should end up with:** A single page containing every element listed in 2.4.6.

**How to get there:** Combine the outputs of exercises 1, 4, 5, and 6: the prioritized questions, the containment decision, the collection order, and the facts/assumptions/hypotheses register. Then add the factual alert summary, scope, evidence gaps, immediate next actions, and escalation expectations. Keep it to a page by cutting narrative, not content.

**What good looks like:** Hand it to someone who was not in the room and ask them to state the first three things they would do. If they can, the plan works. If they ask clarifying questions first, note which ones. Those questions map directly to the sections you underspecified. The plan should also be honest about gaps. Noting that PowerShell Script Block Logging was not enabled belongs in the plan, because it changes what the next analyst should attempt.

**10. Draft a personal documentation standard that you would apply to every future case.**

**What you should end up with:** A short written standard covering case log format, command record fields, timeline entry fields, findings language, and handoff content.

**How to get there:** Decide the format before the incident, which is the entire point of 2.3.8. Specify the command record fields from 2.3.4: tool, version, platform, operator, working directory, exact command, output location, size and hash, and errors or deviations. Specify how you will distinguish facts from conclusions from assumptions in your own writing. Many analysts use an explicit prefix or a dedicated column. Specify when entries get written: during the action, not after it.

**What good looks like:** The standard survives a bad day. Under pressure, you will abandon anything that takes more than a few seconds per entry, and a standard you abandon is worse than a lighter one you keep. Apply the rule of thumb from the chapter as your acceptance test: if a note would not make sense to a future analyst, counsel, or regulator who was not present, the standard is not demanding enough.

---

## Common mistakes on this chapter

- **Copying the alert's language into the facts column.** This is the single most common error in the whole chapter, and it propagates through everything downstream. "EDR reported suspicious PowerShell" is a fact about the alert. "Suspicious PowerShell ran" is a claim about the host. Keeping those separate at minute five prevents an anchored, phishing-shaped investigation at hour five.
- **Reading "no X detected" as "X did not happen."** Absence of alerts is absence of detection, not absence of activity. The correct framing is the one from 2.1.5: "we cannot confirm X because the relevant source was unavailable" is a completely different statement from "we confirmed X did not happen." Conflating them is how scoping stops too early.
- **Writing hypotheses that can only be confirmed.** If you never wrote down what would disprove your theory, you will not notice the evidence that does. This is how experienced responders lose hours to a plausible wrong story. The fix is purely procedural: write the elimination conditions at the same time you write the hypothesis.
- **Dumping the timeline instead of curating it.** A super-timeline with every MFT row in it is a data source, not a timeline. The value comes from selection plus the significance and confidence annotations. A timeline with no confidence column implicitly claims every entry is equally solid, which is never true.
- **Deferring notes until the "real work" is done.** Retroactive documentation loses exactly the details that matter: command syntax, error messages, the order of isolation versus capture, and what you actually believed at the time. It also quietly launders wrong turns out of the record, so the final account looks cleaner and is less credible.
- **Treating the six-phase workflow as a sequence to defend rather than a map to stay oriented by.** Real incidents run phases in parallel and revisit them. That is normal. The workflow exists to tell you where you are when three things are happening at once, not to be executed in order.

---

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) book series.*
