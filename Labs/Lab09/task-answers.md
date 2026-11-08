# Lab 09 — Task Answer Key

*Sample answers for the workbook-style Tasks in `Labs/Lab09/ReadMe.md`. Reference answers, not the only correct answers — a defensible answer that names the right evidence and acknowledges the right uncertainty is the goal. For the Hands-On Walkthrough at the end of the lab, see `walkthrough-answers.md`.*

---

## Task 1 — Identify the Key Log Types for IR

**Sample table:**

| Log Type | What It Commonly Contains | Why It Matters in IR | Limitation |
|---|---|---|---|
| Security | Logon success/failure, privilege use, account/group changes, process creation (4688) when audited | Anchors who-and-when. Most lateral-movement and credential signals live here | Audit policy is host-specific; rolls over quickly under load |
| System | Service install (7045), start/stop (7036), unexpected shutdowns, driver loads, time-change | Catches persistence via services and host-state changes the user did not initiate | Lower signal density than Security; lots of benign chatter |
| Application | Application-specific warnings, crashes, MSI installer activity | Useful for app-specific cases (Outlook, Office, third-party tools) | Format and quality vary wildly by vendor; not a primary hunt source |
| Microsoft-Windows-PowerShell / Operational | EID 4103 pipeline, 4104 script block, 4105/4106 start/stop | Single best source for what PowerShell actually did, including decoded `-EncodedCommand` content | Off by default on older builds; ScriptBlockLogging needs explicit enablement |
| Microsoft-Windows-TaskScheduler / Operational | EID 106/140/141 task created/updated/deleted, 200/201 action started/completed | Catches scheduled-task persistence and time-bombed payloads | Disabled-by-default channel on some images; admins may not enable it |
| Microsoft-Windows-Windows Defender / Operational | EID 1116/1117 detection, 5001 RTP disabled, 5007 config changed | Surfaces both real detections and tampering (exclusions added, RTP disabled) | Only useful if Defender is the AV in use; can be turned off pre-incident |

**Q1: Why is the Security log often the first place responders look?**

It carries the authentication, privilege, and process-creation evidence that anchors most of an investigation: who logged on, from where, when, with what privilege, and what they ran. Even when other channels are missing, a competently configured Security log gives you the spine of a timeline. It is also the channel attackers most often target for clearing or tampering, which is itself a tell.

**Q2: Why are Operational logs often more useful than the general Application log for focused hunting?**

Operational channels are scoped to a single feature, such as PowerShell, Task Scheduler, or Defender, so the event IDs are stable and the signal-to-noise ratio is much higher. The general Application log mixes vendor warnings, crash dumps, MSI installer chatter, and printer queues. It is useful occasionally, but you cannot build reusable hunt filters against it the way you can against `Microsoft-Windows-PowerShell/Operational`. Targeted hunting wants narrow, predictable channels.

**Q3: Why should responders know which logs were enabled before trusting the absence of evidence?**

"No 4688 events" can mean nothing happened, or it can mean process-creation auditing was never turned on. The same logic applies to script block logging, command-line auditing, and the Task Scheduler operational channel, all of which are off or partial by default on many images. Without confirming the audit policy in effect, an absence finding is unsafe. Pull the effective audit policy and the channel enablement state before concluding that quiet logs equal a quiet host.

---

## Task 2 — Identify the Main Challenges in Event Log Analysis

**Sample table (with four added challenges):**

| Challenge | Why It Happens | Why It Matters | How You Would Mitigate It |
|---|---|---|---|
| Volume and noise | Default audit policy logs huge volumes of benign activity (4624 LogonType 5, 4672 on every service start) | Important events drown in noise; analysts give up scrolling | Pre-built filters, baseline subtraction, SIEM-side suppressions of known noise |
| Retention limits / overwrite | Default `.evtx` file size is small (~20MB Security); high-EPS hosts overwrite hours of data | The events you care about may already be gone before triage starts | Increase log size, forward to WEF/SIEM, collect early during triage |
| Time skew | Hosts drift; some lab/standalone hosts never had reliable NTP | Cross-host correlation collapses; "happened after" claims become indefensible | Normalize to UTC, document host time offset against a reference, prefer central-collection timestamps |
| Incomplete logging | Audit policy never enabled key categories (process creation, script block) | Real activity leaves no log evidence; absence becomes ambiguous | Verify effective audit policy at acquisition; document gaps in the case file |
| Log clearing (added) | Attacker action or admin misstep wipes channels (EID 1102) | Erases evidence and signals intent, but also breaks chain-of-custody | Watch for 1102 itself; forward logs off-host; preserve System volume snapshots |
| Renamed-binary masquerading (added) | Attacker runs `svchost.exe` from `C:\Users\Public\` | 4688 `NewProcessName` looks legitimate without path scrutiny | Filter on parent process and full path, not just executable name |
| Service account churn (added) | Built-in service accounts (SYSTEM, NETWORK SERVICE, scheduled-task identities) generate huge 4624/4672 volume | Real human and attacker logons get buried | Filter `TargetUserName` against known service-account list; focus on LogonType 2/3/10 |
| Per-host audit drift (added) | Local GPO overrides domain policy, golden-image divergence | Two ostensibly identical hosts produce wildly different log coverage | Maintain a known-good audit policy baseline; periodically audit drift |

**Q1: Why can noisy logs be just as dangerous as missing logs?**

Noise produces the same operational outcome as silence: the responder cannot find the events that matter in time. A workstation generating 50,000 4624s a day because of a misconfigured service is as opaque as one not logging at all. Worse, noisy logs lull responders into thinking coverage is fine when in practice no one is reading them. Pre-filtered hunt logic is the only sustainable answer.

**Q2: Why is time normalization important before building timelines?**

If two hosts are off by even a few minutes, the order of operations across them looks wrong. Your "PowerShell from Host A caused the lateral move to Host B" claim then collapses on review. Normalizing every source to UTC and documenting any known skew before you start ordering events keeps the timeline defensible. This matters most when external evidence such as firewall or proxy logs is involved, because its clock may be the most reliable in the room.

**Q3: Why is "nothing suspicious in the logs" often a weaker conclusion than it sounds?**

Because it conflates two different findings: "the logs we have show nothing suspicious" versus "no suspicious activity occurred." The absence is ambiguous until you confirm what was being audited, the retention horizon at the time of the activity, and whether clearing events fired. Write "no evidence in this scope" rather than "no evidence," and note explicitly what was checked and what was out of scope.

---

## Task 3 — Collect Security and PowerShell Logs

**Sample collection record:**

| Field | Value |
|---|---|
| Host / VM Name | `WKSTN-221` (finance workstation, Windows 10 22H2) |
| Logs Exported | `Security.evtx`, `System.evtx`, `Microsoft-Windows-PowerShell%4Operational.evtx`, `Microsoft-Windows-TaskScheduler%4Operational.evtx`, `Microsoft-Windows-Windows Defender%4Operational.evtx` |
| Export Method | `wevtutil epl <channel> <out.evtx>` from elevated PowerShell on the live host, hashed immediately after |
| Output Folder | `\\evidence\IR-2024-0142\WKSTN-221\evtx\` |
| Collection Date/Time (UTC) | 2024-11-14 16:05 UTC |
| Notes / Issues | Security `.evtx` was 18 MB and rolling at ~3,000 events/hour; oldest events visible were from 2024-11-13 22:14 UTC, so any pre-spray reconnaissance is already gone |

**Q1: Why is exporting the raw `.evtx` useful even if you also parse the logs later?**

The raw `.evtx` is the original, and every other artifact derives from it. Holding the source means you can re-parse with a different tool or run new filters against the same data months later. You can also hand the file to a court-admissible workflow without re-acquiring from a host that may no longer exist. Parsed CSVs are convenient but lossy. They drop fields, reformat timestamps, and cannot be re-validated against the source without it.

**Q2: Why should the source host and collection time be documented?**

Every later finding traces back to "on this host, at this collection time, this is what was visible." Without that anchor, the same `Security.evtx` could plausibly be from any of dozens of hosts in the environment. The collection time also bounds the retention horizon. If you collected at 16:05 UTC and the oldest event is from 22:14 the previous day, you know your visibility window without re-checking later.

**Q3: Why might you also want System or Task Scheduler logs in the same hunt pack?**

Persistence and execution often leave evidence outside the Security channel. EID 7045 (System) is the canonical service-install event. EID 106/140 (TaskScheduler) catch scheduled-task creation and modification. Both are common persistence vectors that produce nothing useful in the Security log. If you collect them together as a bundle, you do not have to re-collect when the next finding points at a non-Security channel.

---

## Task 4 — Define Suspicious Event Patterns

**Sample table (with four added patterns):**

| Suspicious Pattern | Why It Matters | Primary Log(s) | What It Might Suggest |
|---|---|---|---|
| Multiple failed logons followed by a success | Classic brute-force / password-spray outcome | Security 4625 → 4624 | Credential compromise or guessed password |
| Service installation / creation | Common persistence mechanism | System 7045, Security 4697 | Attacker installed a service for persistence or impersonation |
| PowerShell execution from unusual locations | LotL pattern; `powershell.exe` running outside `System32` is almost always wrong | Security 4688, PowerShell 4103/4104 | In-memory loader, second-stage execution |
| Scheduled task creation or modification | Persistence and time-bombed payloads | TaskScheduler 106/140/141, Security 4698/4702 | Persistence or scheduled C2 callback |
| Explicit-credential lateral movement (added) | EID 4648 fires when user supplies credentials to a remote target | Security 4648 | RunAs / `net use /user:` / mapped-drive auth — strong lateral signal |
| Defender tamper or exclusions added (added) | Attackers carve a safe path before dropping tools | Defender 5001/5007 | Pre-payload preparation |
| Log clearing (added) | Direct attempt to destroy evidence | Security 1102, System 104 | Hostile activity or sloppy admin — both warrant follow-up |
| Encoded PowerShell command line (added) | `-EncodedCommand`, `FromBase64String`, `IEX` patterns | Security 4688, PowerShell 4104 | Obfuscated execution; almost always worth review |

**Q1: Why should hunt-pack patterns focus on responder value rather than every possible event ID?**

Windows has over 4,000 documented event IDs, and chasing all of them produces a hunt pack no one reads. A useful pack covers the dozen or so patterns that account for most real-world findings: failed-then-success authentication, anomalous parent-child process pairs, service install, scheduled-task creation, log clearing, suspicious PowerShell. Coverage matters less than catching the patterns that recur across cases.

**Q2: Why are event patterns usually stronger than single isolated events?**

A single 4625 is a typo. Five 4625s from the same external IP followed by a 4624 is a successful spray. A single 4688 for PowerShell is normal. A 4688 where the parent is `OUTLOOK.EXE` and the command line contains `-EncodedCommand` is the entire kill chain. Patterns express the contextual relationship that gives an event its meaning, and isolated event IDs are just data points.

**Q3: Why should patterns be tied to specific IR questions?**

Every pattern in the pack should answer a "did X happen here?" question: did someone brute-force this account, did persistence get installed, did PowerShell run from a weird path? Tying patterns to questions keeps the pack disciplined and makes it obvious which question is unanswered when a hunt comes back empty. A pattern with no associated question is usually just trivia.

---

## Task 5 — Map Patterns to Filters or Saved Searches

**Sample filter table:**

| Suspicious Pattern | Filter / Search Definition | Tool or Platform | Why This Filter Is Useful |
|---|---|---|---|
| Multiple failed logons followed by a success | Group 4625 by `IpAddress`, alert where count ≥ 3 within 10 minutes followed by a 4624 from the same IP | SIEM (Splunk/Sentinel) or EvtxECmd CSV + grouping | Catches password spray without flagging every single typo |
| Service installation / creation | `EventID = 7045 AND ImagePath NOT IN (known-good list)` | EvtxECmd CSV + PowerShell `Where-Object` | Anchors on the install event; image-path whitelist suppresses normal installs |
| PowerShell execution from unusual locations | `EventID = 4688 AND NewProcessName LIKE '%powershell%' AND CommandLine MATCHES 'EncodedCommand\|FromBase64String\|IEX'` | PowerShell over EvtxECmd CSV (see `Find-EncodedPowerShell` in walkthrough Step 6) | Catches obfuscated execution; tunable by extending the regex |
| Scheduled task creation or modification | `EventID IN (4698, 4702) OR Channel = 'Microsoft-Windows-TaskScheduler/Operational' AND EventID IN (106, 140)` | SIEM correlation, or filtered XML in Event Viewer | Catches persistence; pairs with 4688 for what the task ran |
| Explicit-credential lateral movement (added) | `EventID = 4648 AND TargetServerName != $env:COMPUTERNAME` | EvtxECmd CSV + PowerShell | Filters out RunAs-as-self; surfaces real cross-host credential use |
| Defender tamper (added) | `EventID IN (5001, 5007)` from Defender Operational | EvtxECmd CSV | Surfaces both real-time-protection disablement and exclusion-list edits |
| Log clearing (added) | `Channel = 'Security' AND EventID = 1102` OR `Channel = 'System' AND EventID = 104` | Event Viewer custom view, SIEM saved search | Rare in normal operation; almost always worth review |
| RDP / network logon from external (added) | `EventID = 4624 AND LogonType IN (3, 10) AND IpAddress NOT IN (internal CIDR list)` | SIEM with IP-list lookup | Surfaces remote successful logons from outside the corporate range |

**Q1: Why is filter logic more reusable than freeform manual hunting?**

A filter you can name, version, and run against any new EVTX dump in a single command is operational. A "remember to look at 4688 with weird parents" mental note is not. With reusable filters, every responder on the team produces the same finding from the same data, and junior analysts can run them without senior oversight. The pack itself also improves over time as cases reveal gaps. Freeform hunting is fine for the first hour of a novel case, but it cannot be the whole workflow.

**Q2: Why should filters be documented in plain language as well as technical syntax?**

The syntax tells the machine what to do, and the plain-language description tells the next analyst what it means. Six months from now, the responder running your filter needs to know what a hit indicates, what the common false positives are, and what to do next. None of that is visible from the regex alone. Documentation is also how your filter survives a tool migration. The Splunk syntax may not survive a move to Sentinel, but the plain-language description ports cleanly.

**Q3: Why is it useful to record which tool or platform each filter was designed for?**

Filter syntax is platform-specific. A Splunk SPL query, a Sentinel KQL query, an EvtxECmd PowerShell pipeline, and an Event Viewer XML custom view all express the same hunt differently, and each fails silently when ported without translation. Recording the platform makes the pack portable. An analyst on a different stack knows immediately whether to use the filter as-is or rewrite it for theirs.

---

## Task 6 — Build the Hunt Pack Documentation File

**Sample documented hunt (example for the encoded-PowerShell pattern, one of the six minimum):**

```
Hunt Name:           Encoded-PowerShell-Spawned-By-Office
Purpose:             Detect obfuscated PowerShell launched as a child of an
                     Office application — the canonical phishing-loader pattern.
Primary Log(s):      Security (Channel: Security)
Primary EIDs:        4688 (process creation)
Filter Logic:        EventID = 4688
                     AND NewProcessName LIKE '%powershell.exe'
                     AND ParentProcessName MATCHES '(OUTLOOK|WINWORD|EXCEL|POWERPNT)\.EXE'
                     AND CommandLine MATCHES 'EncodedCommand|FromBase64String|IEX'
Positive-Hit Means:  Office spawning encoded PowerShell — almost always malicious.
                     Move to high-priority triage immediately.
False Positives:     Legitimate Office add-ins that use PowerShell are rare but
                     possible. Confirm against the host's installed add-ins list.
Follow-Up:           - PowerShell 4104 script block content for the same time
                     - 4688 children of the same powershell.exe PID
                     - Network egress to whatever the script pulled
                     - Prefetch for any new binaries
```

**Q1: Why is false-positive guidance important in a reusable hunt pack?**

Without it, every analyst who runs the filter reinvents the triage flowchart and burns the same hours on the same benign hits. False-positive guidance tells the next responder which hits to dismiss quickly and which to escalate. That preserves the pack's signal-to-noise ratio over time. A pack with no false-positive guidance gets ignored within a quarter, because the team tires of investigating the same noise.

**Q2: Why should follow-up artifacts be included in the documentation?**

A hunt hit is the start of a question, not the end of it. Naming the next three artifacts to check turns a single positive into a workflow: the script block content, the child process tree, the network egress. Without that list, triage stops at "the filter fired," and senior analysts spend time pointing out the same standard correlations every case.

**Q3: Why is this documentation as important as the filters themselves?**

A filter without documentation is a piece of regex no one trusts. The documentation makes the pack a shared team asset rather than a personal cheat sheet. It captures the reasoning, the known limitations, the next steps, and the audience. Team membership always changes, and the documentation is what survives an analyst's departure.

---

## Task 7 — Generate Test Events in the Lab

**Sample test-action table:**

| Test Action | Expected Log Pattern | Approximate Time (UTC) | Which Hunt Should Catch It |
|---|---|---|---|
| Six failed logons from a remote IP against `testuser` | Security 4625 x6 with same `IpAddress` | 2024-11-14 19:00 UTC | Spray-pattern hunt |
| Successful logon after the failures | Security 4624 LogonType 3 from same IP | 19:02 UTC | Spray-followed-by-success correlation |
| Scheduled task creation via `schtasks.exe /create` | Security 4698 + TaskScheduler 106 | 19:05 UTC | Scheduled-task creation hunt |
| `powershell.exe -EncodedCommand <base64>` from Excel | Security 4688 with Excel parent + PS 4104 | 19:08 UTC | Encoded-PS-from-Office hunt |
| `sc.exe create` followed by start | System 7045 + 7036 | 19:11 UTC | Service-install hunt |
| `wevtutil cl Security` to clear the log | Security 1102 (the clear event itself is logged) | 19:15 UTC | Log-clearing hunt |
| Defender exclusion added via PowerShell | Defender Operational 5007 | 19:17 UTC | Defender-tamper hunt |
| RDP from external IP to lab host | Security 4624 LogonType 10 from non-RFC1918 IP | 19:20 UTC | External-RDP hunt |

**Q1: Why is it important to test hunts against known lab actions?**

You verify two things at once: the filter fires on the activity it is supposed to catch, and it produces a finding clear enough to act on. A filter that looks correct on paper but never fires is worse than no filter, because it produces false confidence. The cause may be a wrong field name, a wrong EID, or a missed property. Testing closes that gap before a real case depends on it.

**Q2: Why should you record approximate timestamps of your test activity?**

The timestamps are how you confirm that the hits the filter produces correspond to the actions you took, rather than incidental background activity. Without the timestamp record, "the filter fired" is ambiguous. It may have fired on the test action or on some other 4688 in the same window. Logging your test times turns validation into something you can prove.

**Q3: Why is a hunt pack incomplete if it has never been validated?**

A theoretical filter and a working filter look identical until the moment you need one. Untested hunt packs are full of fields that do not exist on this Windows build, regexes that do not match the actual command-line format, and EIDs that fire in a different channel than the documentation assumed. The first real case is the worst time to discover any of those problems.

---

## Task 8 — Test and Refine the Filters

**Sample tuning record:**

| Hunt Name | Expected Hit? | Actual Result | Adjustment Needed? | Notes |
|---|---|---|---|---|
| Spray-pattern (≥3 4625 same IP) | Yes | 4 hits from `185.193.126.47` on WKSTN-221, threshold worked | No | Held the line at 3; tested at 2 and produced internal-typo noise |
| Service install (7045 non-standard image path) | Yes | 0 hits in lab data, but fired correctly on a synthetic `sc create` | No | Negative on the dataset is correct — no service install in scope |
| Encoded-PowerShell-from-Office | Yes | 1 hit on WKSTN-221 at 14:19:38 — `OUTLOOK.EXE → powershell.exe -EncodedCommand` | No | Filter caught the canonical hit cleanly |
| Scheduled-task creation | Yes | 0 hits in WKSTN-221 dataset; fired on the synthetic test | No | Working as intended for what is in scope |
| Log clearing (Security 1102) | No (lab data has no clears) | 0 hits | Documented as expected | Will fire on the test action; held in reserve |
| Explicit-credential 4648 | Yes | 1 hit, 14:33:18, `payroll-admin → FILESVR-03` | No | Cleanly identified the lateral-move signal |

**Q1: Why is filter tuning part of the DFIR workflow, not a sign of failure?**

The first version of any filter is a guess. Tuning is how you discover that the field is named `TargetUserName` on this Windows build but `Account_Name` after EvtxECmd parses it. It also shows when the threshold is too tight or too loose, or when the regex misses a legitimate variant. A team that ships version 1 filters and never adjusts them has built a static artifact. A team that ships v1 and iterates over six months has built a hunt program.

**Q2: Why can a technically correct filter still be operationally weak?**

A filter can be syntactically valid and return the right hits, yet still be unusable. The false-positive rate may be too high, the runtime too long, or the output too verbose. The hits may arrive without the context an analyst needs to triage. Operational strength is about whether someone can act on the result quickly under stress, not whether the SQL parses. Tuning addresses both halves.

**Q3: Why should you note both successful detections and misses?**

Successful detections build confidence and let you cite the filter in a finding. Misses tell you where the coverage gaps are: which activity types the pack does not yet handle, which event IDs are missing, and which audit policies need to be enabled environment-wide. Recording both is how a hunt pack matures across cases instead of stagnating after release.

---

## Task 9 — Package the Hunt Pack for Reuse

**Sample naming-convention table:**

| Item | Naming Convention | Example |
|---|---|---|
| Filter file | `<channel>-<pattern>-v<MAJOR>.<MINOR>.<ext>` | `security-spray-then-success-v1.2.kql` |
| Hunt documentation section | Markdown H2 with the hunt name verbatim | `## Encoded-PowerShell-Spawned-By-Office` |
| Test note | `<YYYY-MM-DD>-<host>-<hunt-name>.md` | `2024-11-14-WKSTN-221-spray-pattern.md` |
| Sample exported log | `<host>-<channel>-<YYYY-MM-DD>.evtx` | `WKSTN-221-Security-2024-11-14.evtx` |

**Q1: Why is a reusable folder structure important if you want to share the hunt pack with a team?**

A predictable structure means anyone on the team knows where to find a filter, where to add a new one, and where the sample logs and test notes live. Without it, the pack becomes a personal toolkit that no one else can extend, and the team loses the multiplier effect of shared work. The structure also makes the pack reviewable. Code review on a flat folder of one-off scripts is much harder than on a project with clear conventions.

**Q2: Why should sample logs or test notes be included when possible?**

Sample logs let the next analyst run your filter without re-acquiring evidence from a host that may no longer exist. Test notes capture the conditions under which the filter was validated: the Windows build, the audit policy, and the tool version. All of these matter when the filter mysteriously stops working a year later. Both are part of the answer to "does this filter actually work?"

**Q3: Why does packaging matter almost as much as the hunt logic itself?**

Hunt logic that no one else can run is hunt logic that no one else benefits from. Packaging is what turns a working filter on one analyst's laptop into a team asset. It covers folder structure, naming conventions, documentation, and sample data. The most analytically interesting filter in your collection is useless if onboarding to it takes a week.

---

## Task 10 — Separate Strong Support from Overclaims

**Sample classification table:**

| Statement | Classification | Why |
|---|---|---|
| The host recorded multiple failed logons followed by a success | Strongly supported | 4625 → 4624 from the same source IP is a direct, well-defined evidence pattern |
| A service-installation-related event occurred | Strongly supported | 7045 is a single, unambiguous event with high evidentiary weight |
| PowerShell activity from an unusual path deserves deeper review | Strongly supported | The recommendation is for review, not for a conclusion — the action is calibrated to the evidence |
| The attacker definitely gained interactive control of the host | Not supported by these events alone | A 4624 success could be the legitimate user; need additional artifacts (process tree, NTFS, network) to conclude interactive control |
| A scheduled task was created or modified | Strongly supported | 4698/4702 or TaskScheduler 106/140 are direct creation/modification events |
| The new task was definitely used for persistence by malware | Suggested but needs corroboration | Task creation is not equal to malware persistence; need the task action, the binary, and execution evidence |
| The hunt pack successfully identified suspicious patterns worth follow-up | Strongly supported | The deliverable here is identification of leads, not adjudication of guilt |
| Event logs alone prove the full scope of the incident | Not supported by these events alone | Scope requires corroboration with file-system, network, memory, and host telemetry |

**Six analyst-written additional statements (sample):**

| Statement | Classification | Why |
|---|---|---|
| `185.193.126.47` was responsible for the password spray | Strongly supported | 4 of 5 4625 events on this host trace to that single IP within a 42-second window (04:00:00 to 04:00:42 UTC), each against a different account |
| The spray was successful | Suggested but needs corroboration | The 4624 success on this host came from `10.0.4.17`, not the spray IP — these need to be reconciled before claiming success |
| The encoded PowerShell at 14:19:38 was the initial-access payload | Strongly supported | Outlook-spawned, encoded, immediately followed by outbound TCP/443 to 91.214.47.22 — the chain is end-to-end visible |
| `payroll-admin` is the attacker's account | Not supported by these events alone | The account fired the suspicious events, but the events are equally consistent with compromise of a legitimate account |
| Defender was not tampered with | Suggested but needs corroboration | Absence of 5001/5007 on this host means none occurred *if Defender Operational was enabled* — confirm before claiming |
| All lateral movement from this host has been observed | Not supported by these events alone | Logs only show what was captured; need correlated evidence from FILESVR-03 to assess full scope |

---

## Task 11 — Write an Event Log Hunt Pack Summary

**Sample summary:**

> The hunt pack assembled in this lab covers eight high-value Windows event patterns: password-spray (≥3 4625 followed by 4624 from the same source IP), service install (7045 with non-standard image path), encoded PowerShell from Office (4688 with Office parent and encoded command line), scheduled-task creation (4698/4702 and TaskScheduler 106/140), explicit-credential lateral movement (4648 cross-host), Defender tamper (5001/5007), log clearing (Security 1102 and System 104), and external RDP success (4624 LogonType 3/10 from non-internal CIDR). Logs collected: Security, System, PowerShell Operational, TaskScheduler Operational, and Defender Operational from `WKSTN-221`, exported via `wevtutil epl` at 2024-11-14 16:05 UTC, hashed and copied to evidence storage.
>
> Lab-generated test events covered all eight patterns. The pack caught every test action it was designed to catch, including the canonical Outlook-to-encoded-PowerShell pattern, the explicit-credential lateral move (`payroll-admin → FILESVR-03` at 14:33:18 UTC), and the spray pattern from `185.193.126.47` (4 failed logons in 42 seconds). No 4624 came from that IP, so the success leg of the spray correlation did not fire. The spray and encoded-PowerShell hunts produced single-host hits with high confidence. The service-install, scheduled-task, log-clear, Defender-tamper, and external-RDP hunts produced expected negatives against the WKSTN-221 dataset and fired correctly against synthetic test data.
>
> What the pack does well: detects the eight named patterns deterministically against EvtxECmd CSV output, runs end-to-end in under a minute on a single host, and produces tagged, attributable findings that can be quoted in case reports. What still requires other artifacts: confirming that 4624 successes correspond to legitimate or attacker logons (requires process-tree correlation), establishing scope across hosts (requires central-collection or per-host runs), and proving in-memory activity that left no event-log trace (requires memory analysis). The pack is a leads-generator, not a case-closer. Downstream correlation with NTFS, Registry, network, and memory evidence remains essential.

---

## Task 12 — Write an Analyst Handoff Note

**Sample handoff note:**

```
Case Reference:    IR-2024-0142
Author:            J. Responder
Date/Time (UTC):   2024-11-14 18:30

Logs Collected:
- Security.evtx (WKSTN-221) — 18 MB, oldest event 2024-11-13 22:14 UTC
- System.evtx (WKSTN-221)
- Microsoft-Windows-PowerShell/Operational.evtx (WKSTN-221)
- Microsoft-Windows-TaskScheduler/Operational.evtx (WKSTN-221)
- Microsoft-Windows-Windows Defender/Operational.evtx (WKSTN-221)
- Exported via wevtutil epl at 16:05 UTC, hashed at collection

Most Important Hunt Patterns:
- Spray-then-success (Security 4625 → 4624 same source IP, threshold ≥3)
- Encoded-PowerShell-from-Office (4688 + parent in Office set + encoded cmdline)
- Explicit-credential lateral movement (4648 with non-self TargetServerName)
- Scheduled-task creation (4698/4702, TaskScheduler 106/140)
- Service install (7045 with non-standard image path)

Filters That Worked Well:
- Spray pattern caught 185.193.126.47 at 04:00 UTC, 4 failed in 42 seconds,
  no 4624 success from that IP
- Encoded-PS-from-Office caught the OUTLOOK.EXE → powershell.exe at 14:19:38
- 4648 explicit-credential caught payroll-admin → FILESVR-03 at 14:33:18

Filters That Need Tuning:
- Service-install filter — 0 hits on the lab data, but the "non-standard image
  path" allowlist is too short for production. It will flag quarterly patch
  installs. Extend it with this environment's update-management paths
- Spray-threshold of ≥3 — confirm against more historical data; consider sliding
  window rather than fixed count

Recommended Next Steps:
1. Run the spray-pattern hunt against the rest of the workstation fleet to find
   other hosts the same source IP touched
2. Pull FILESVR-03's Security log to corroborate the 4648 lateral attempt and
   determine whether the file server accepted the connection
3. Correlate the encoded-PowerShell command-line with PS Operational 4104 to
   recover the decoded script content (already done for WKSTN-221; needed for
   any sibling hosts)

Open Questions:
- Did the spray (admin, administrator, root, svc-admin) succeed on any other host?
- Did the FILESVR-03 connection at 14:33:18 lead to file access?
- Are there other internal hosts that the same external IP touched?

Notes for Incoming Analyst:
The pack is a leads generator. Every hit needs correlation with NTFS, process
trees, and network telemetry before it becomes a case finding. The spray and
the encoded-PS findings on WKSTN-221 are high-confidence and cleanly evidenced;
treat everything else as a lead to be developed.
```

---

## Task 13 — Reflection

**Q1: Why hunt packs matter**

A hunt pack converts the institutional knowledge of one experienced responder into a tool any analyst on the team can run. Starting from scratch in every case wastes the most valuable input the team has, which is what it learned in previous incidents. It also produces inconsistent results between cases handled by different analysts. A maintained pack also resists analyst turnover. When the senior responder leaves, the pack remains, and the next hire can ramp up against documented, tested filters rather than inheriting a folder of one-off scripts.

**Q2: Pattern hunting versus raw review**

Single events are usually ambiguous and almost always too numerous to review by hand. A 4624 is a logon and a 4625 is a failed logon, but neither tells you anything by itself in a busy environment. Patterns encode the part of the analysis that distinguishes signal from noise: the relationships between events, the parent-child process pairs, the threshold-based clustering. Pattern hunting also scales. It produces the same findings whether you have 100 events or 100 million.

**Q3: Validation matters**

A filter that has never been tested against the activity it claims to catch is a hypothesis, not a tool. Validation closes the gap between "the regex looks right" and "the filter fires reliably on this Windows build, against this audit policy, through this parser." It also calibrates the false-positive rate before a real case depends on it. Discovering during incident response that your spray-pattern filter triggers on every service-account refresh is much more expensive than discovering it in a lab.

**Q4: Correlation remains essential**

An event-log hit is a lead, not a conclusion. The 4648 explicit-credential event tells you a user attempted to authenticate to a remote target. It does not tell you whether the connection succeeded, whether files were accessed, or whether the account was compromised. Leads become defensible findings when you pair event-log hits with other evidence. NTFS evidence shows whether the file was opened, process artifacts show what spawned the activity, network telemetry shows whether data left, and Registry data shows whether persistence was installed. Logs anchor the timeline, and the other artifact classes flesh out what happened around each anchor.

---

## Ready-to-move-on self-check

**1. Which event ID fires when a user supplies explicit credentials to a remote target, and why does it matter for lateral-movement hunts?**

EID 4648. It indicates a "RunAs"-style or `net use /user:` credential supply against a non-self target. That is the canonical lateral-movement primitive, and it does not show up cleanly anywhere else.

**2. What is the difference between "no evidence in the logs" and "no evidence the activity occurred"?**

The first is bounded by what was being audited and what is still in retention. The second is an unsupportable claim without confirming both. Saying "no 4688 events for that period" only means something if process-creation auditing was on.

**3. Why does a hunt pack need plain-language documentation alongside the syntax?**

The syntax tells the machine what to do. The description tells the next analyst what it means, what the common false positives are, and what to do next. A filter without documentation cannot be inherited.

---

## Walkthrough ↔ workbook bridges

These bridges connect the workbook tasks (this file) to specific values produced by the Hands-On Walkthrough against `Data/WKSTN-221/security-evtx.csv` and `powershell-evtx.csv`.

- **Task 4 (define patterns) ↔ Walkthrough Step 2.** The "multiple failed logons followed by a success" pattern fires in the data: 4 EID 4625 events from `185.193.126.47` clustered around 04:00 UTC on 2024-11-14, followed by 4624 successes. The success at 14:31:05, though, came from `10.0.4.17`, not the spray IP. That gap is why "the spray was successful" needs corroboration rather than a strong-support claim (see Task 10).

- **Task 4 ↔ Walkthrough Step 3.** The explicit-credential lateral-movement pattern surfaces as a single 4648 row at 14:33:18 UTC: `payroll-admin → FILESVR-03` from `cmd.exe`. That one row matches one of the eight named patterns with full evidentiary weight. It is the textbook example of why pattern-based hunting beats raw EID review.

- **Task 4 ↔ Walkthrough Step 4.** The encoded-PowerShell-from-Office pattern fires once: 4688 at 14:19:38 UTC with `OUTLOOK.EXE` parent, `powershell.exe -EncodedCommand` child, `payroll-admin` user. The base64 in the command line decodes to the `Invoke-WebRequest` cradle visible in PowerShell 4104 (walkthrough Step 5).

- **Task 8 (filter testing) ↔ Walkthrough Step 5.** The PowerShell 4104 script-block hunt produces 4 rows after 2024-11-14 12:00 — the download, the XOR decode loop with key `F1nd4nc3K3y!`, the rename, and the `Start-Process update.exe` execution. The four-stage payload is visible in cleartext only because ScriptBlockLogging was enabled. Without it, Task 5's filter on `-EncodedCommand` alone would surface the launch but never the content.

- **Task 10 (overclaim discipline) ↔ Walkthrough Step 3.** Step 3 produces evidence of an *attempted* explicit-credential authentication against `FILESVR-03`, not confirmation that the connection succeeded or that files were accessed. The 4648 fires on credential supply, not on session establishment. Claiming "the attacker accessed FILESVR-03" from this single event is exactly the overclaim Task 10 trains against.
