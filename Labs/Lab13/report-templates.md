Incident Reporting Templates
**Executive Brief · Incident Report · Containment Decision Record · Lessons Learned**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Version:** 1.0  
**Created:** ___________________________  
**Last Updated:** ___________________________  
**Owner:** ___________________________  

---

## How to Use These Templates

These are working skeletons, not lab exercises. They are meant to leave this folder.

1. Copy this file into your case folder under `00_Admin\` at the moment the case opens, not at the moment you start writing.
2. Fill the header block of each template immediately — case reference, author, classification, distribution. A document without those four fields cannot be released, and filling them later is how the wrong version reaches the wrong reader.
3. Work the templates in the order the incident needs them, which is almost never the order they appear here. The containment decision record (§3) is usually first, written in real time. The executive brief (§1) is usually second, within the first two hours. Write the incident report (§2) once the investigation stabilizes, and the lessons-learned entry (§4) within two weeks, while detail is still recoverable.
4. Delete sections that do not apply, but delete them deliberately. Inexperienced writers drop Sections 3.4 and 5 of the incident report by accident. Those two sections distinguish "we looked and cleared it" from "we did not look."
5. Update the master copy whenever a real case teaches you that a field was missing.

### The confidence scale — publish this inside every report that uses it

| Level | Definition | Test |
|---|---|---|
| **Confirmed** | Supported by two or more independent artifact sources that agree, or by one authoritative source where no plausible alternative explanation exists. | Could I defend this in a deposition with only the evidence in the appendix? |
| **Probable** | Supported by a single reliable source, with no contradicting evidence. A benign explanation exists but would require an unlikely coincidence. | Would I be genuinely surprised to learn I was wrong? |
| **Possible** | The evidence is consistent with this statement, but it is equally consistent with at least one plausible alternative. | Can I state the competing explanation? If yes, this is Possible, not Probable. |
| **Undetermined** | No evidence supports or refutes the statement. The source that would have answered it was unavailable, cleared, not retained, or never generated. | Do I know *which* source would have answered this? Name it. |

Three rules make the scale work. *Independent* means the sources could not have inherited the same error. Every finding carries exactly one level, so split any finding that does not. **Undetermined is a finding, not a blank**: it appears in the report with the named missing source.

### Words to strike before release

*likely · probably · seems · appears · may have · could have · believed to be · presumably · obviously · clearly · sophisticated · advanced · highly targeted*

The first ten are confidence claims without definitions. The last three describe your impression of the attacker rather than the evidence, and they have a habit of appearing in press coverage.

### Things that do not belong in any of these documents

- Attribution to a named actor or nation state, unless you have the intelligence basis for it
- Blame directed at individuals. "The user opened a malicious attachment" is a fact. "The user should have known better" is not.
- Cost, liability, or notification-obligation estimates, unless that is your role
- Speculation about attacker motive
- Unqualified negatives — "no evidence of X was identified" without saying which sources you checked and what coverage they had

---

## §1 — The One-Page Executive Brief

> One page. Actually one page: if it is two pages, it is a different document. Written for a reader with five minutes, no forensic background, and a decision to make. Reissue on a cadence, not on completeness. An update that arrives on time saying "nothing changed" beats a complete one that arrives Thursday.

```markdown
# Incident Brief — [Short name]                    Ref: [IR-YYYY-MM-NNN]
As of: [date/time UTC] | Status: [Active / Contained / Eradicated / Closed]
Prepared by: [name, role] | Classification: [ ] | Distribution: [ ]

## Bottom line
[Two or three sentences. What happened, what it means for the business, what is
being done. No jargon, no event IDs, no IP addresses, no tool names. If the reader
stops here, they must not be misinformed.]

## What we know
- [3–5 bullets. Plain language. One thing per bullet.]
- 
- 

## What we do not know yet
- [2–3 bullets. Each with when you expect to know.]
- 

## Business impact
[Systems affected. Users affected. Data categories involved or in question — name
only categories the evidence supports. Service status. Write "under assessment"
where it is under assessment; do not write "none" where you mean "not yet known".]

## Actions taken
| When (UTC) | Action | By |
|---|---|---|
|  |  |  |
|  |  |  |

## Decisions needed from leadership
1. [Decision] — needed by [when] — because [consequence of delay]
2. 

## Next update: [date/time UTC]
```

**Release checklist for the brief**

- [ ] Fits on one page at 11 pt with normal margins
- [ ] "What we do not know yet" is populated and each bullet has an expected time
- [ ] "Decisions needed" contains at least one real decision with a deadline — otherwise this is an FYI and will not be read
- [ ] No word from the banned list appears
- [ ] No data category is named that the findings do not support at a stated confidence level
- [ ] "Next update" has a real time on it, and someone owns sending it

---

## §2 — The Incident Report

> The durable document. It outlives the incident. Insurers, auditors, and counsel read it, and it is the reference when someone asks in 18 months what happened. Versioned. Revised as findings change, with the version history visible, because a silently edited report is worse than a superseded one.

```markdown
# Incident Report — [Name]                         Ref: [IR-YYYY-MM-NNN]

| Version | Date | Author | Classification | Distribution | Change |
|---|---|---|---|---|---|
| 0.1 |  |  |  |  | Initial draft |
|  |  |  |  |  |  |

**Response coordinator:** [the person running the response, usually this report's primary author]
**Confidence scale used in this report:** [paste the four-level table above]

---

## 1. Executive Summary
[One page. Standalone — readable without the rest of the document. Plain language.
This is not a shortened version of Section 4; it is the §1 brief, matured.]

## 2. Incident Timeline
[Curated, not raw. Attacker actions and responder actions in ONE chronology,
visually distinguished. Insurers and regulators both want the interval between
discovery and containment, and a merged chronology answers that at a glance.]

| Time (UTC) | Actor | Event | Source artifact | Confidence |
|---|---|---|---|---|
|  | Attacker / Responder |  |  |  |

## 3. Scope
### 3.1 Systems in scope, and how scope was determined
[Name the method, not just the result. "Hunted hash X and C2 Y across N endpoints
via EDR" is a scoping method. "We looked" is not.]

| Host | Role | Basis for inclusion | Confidence |
|---|---|---|---|

### 3.2 Accounts in scope
| Account | Type | Basis for inclusion | Rotated? (date/time) |
|---|---|---|---|

### 3.3 Data in scope
[Include personal data explicitly: what type, and whether it was accessed,
disclosed, altered, or destroyed. Notification analysis starts here.]

| Category | Volume | Basis | Confidence |
|---|---|---|---|

**Where the affected data resides:** [jurisdictions or regions — notification law follows the data]
**Third parties involved or affected:** [vendors, customers, partners, service providers]
**Business owners of the affected systems and data:** [names or roles]

### 3.4 Systems and accounts examined and ruled out
[THE SECTION MOST OFTEN OMITTED. This is how a reader distinguishes "the attacker
did not touch the domain controllers" from "we did not look at the domain
controllers." Include what you checked, how, and what coverage that check had.]

| Host / account | What was checked | Coverage / limitation | Outcome |
|---|---|---|---|

## 4. Findings
[Numbered. Each in the four-part form below. One confidence level per finding.]

### 4.1 Initial access
### 4.2 Execution and tooling
### 4.3 Persistence
### 4.4 Credential access and lateral movement
### 4.5 Collection, staging, and exfiltration
### 4.6 Anti-forensics and cleanup
### 4.7 Root cause
[Separate the immediate cause, such as the exposed RDP service or the phished
credential, from the underlying weaknesses in people, process, technology, or
policy that allowed it. Describe gaps in controls and procedures, not the
mistakes of individuals. State how you know, at what confidence, which
questions are still open, and what evidence would change the assessment. Note
any connection to past incidents.]

## 5. Evidence Gaps
[THE OTHER SECTION MOST OFTEN OMITTED, and where the confidence scale earns its
keep. One row per gap. Every Undetermined finding in Section 4 should appear here.]

| # | What could not be determined | Which source would have answered it | Why it was unavailable | What it prevents concluding |
|---|---|---|---|---|

## 6. Response Actions
[Detection, containment, eradication, recovery, and closure, each with timestamps
AND the decision rationale. Start with detection: what detected the incident, and
which teams were involved. Paste the containment decision records from §3 of
this file here.]

| Time (UTC) | Action | Host / scope | Authorized by | Rationale | Evidence cost accepted |
|---|---|---|---|---|---|

### 6.1 Eradication verification
[The verification pass, with dates and outcomes — not a claim that it was done.]

### 6.2 Recovery
[Restore points selected, and the earliest-confirmed-compromise timestamp they
were selected against. Backup validation performed. Staged restoration order.]

### 6.3 Closure
[When and on what basis the active response ended: the criteria applied, the
risks that remain, and who took part in the decision. If the response is still
running, name the criteria not yet met.]

## 7. Recommendations
[Prioritized. Each: action, owner, rationale, and whether it is remediation
(closes this incident) or hardening (reduces the next one). Recommendations
without owners are not recommendations.]

| # | Recommendation | Remediation or hardening | Owner | Due | Finding it addresses |
|---|---|---|---|---|---|

## 8. Lessons Learned
[A summary of the post-incident review (§4 of this file), not a replacement for
it. Lead with what worked well and why, including luck, because that is what
you keep. Then people, process, and technology: what to change in each, and
where the response departed from the plan or playbook.]

## 9. Appendices
[See §2a below.]
```

> Sections 4.7, 6.3, and 8, along with the coordinator and data-location lines, adapt the shape of Lenny Zeltser's [incident report template](https://zeltser.com/good-incident-reports) (with Elisabetta Tiani; CC BY 4.0).

### §2a — The Technical Appendix

> Written for the analyst who comes after you: an incoming responder, a peer reviewer, a retained expert, or you in a year. The test is whether a competent analyst with the appendix and the evidence could re-derive your findings without speaking to you. If they could not, something in C, D, or G is missing.

```markdown
A. Chain of custody records      [Every item, every transfer, every hash]
B. Evidence inventory            [Item, host, acquisition method, tool, version,
                                  operator, SHA-256, storage location]
C. Tooling and commands          [Exact invocations, versions, platform, output paths]
D. Full timeline                 [The uncurated merged timeline Section 2 was drawn from]
E. Indicators of compromise      [Hashes, IPs, domains, filenames, paths, registry keys,
                                  service names, task names, WMI consumer names, mutexes,
                                  user-agent strings, account names]
F. Detection content produced    [Sigma rules, EDR queries, SIEM saved searches — each
                                  tagged with this case reference]
G. Artifact excerpts             [The specific rows, keys, and log entries cited in
                                  the findings]
H. Analyst notes                 [The case log. Unedited.]
```

### §2b — The Finding Skeleton

> Use this for every numbered finding in Section 4. The fourth part is the one that gets dropped and the one that protects you. Every finding has a boundary. If you do not draw it, the reader will draw it somewhere more generous than the evidence supports.

```markdown
**Finding N — [One line: host, account, action, object.]**

**Basis:** [The artifacts, with enough identifying detail that another analyst can
retrieve them — file name, event ID, record number, exact timestamp, exact byte
count, run count, hash. Name the source file or log channel. If you are relying on
two sources, say explicitly why they are independent.]

**Confidence:** [Confirmed / Probable / Possible / Undetermined] — [one clause of
reason if the level is not self-evident from the basis]

**What this does not establish:** [The boundary. What a reader might reasonably
infer from the above that the evidence does not actually support. Where a competing
benign explanation exists, name it and say whether it was ruled out and how.]

**Recommended action:** [Only where the finding drives one. Cross-reference the
recommendation number in Section 7.]
```

**Self-check before a finding leaves your drafts**

- [ ] The claim names a host, an account, a time, and an object
- [ ] Every artifact cited actually exists and is retrievable from the appendix
- [ ] Exactly one confidence level, and it survives its own test
- [ ] Byte counts have a *direction*, not just a magnitude
- [ ] "What this does not establish" is populated and is not a formality
- [ ] No banned word appears
- [ ] Nothing in it is an inference wearing the costume of an observation

---

## §3 — The Containment Decision Record

> Written in real time, in the case log, at the moment the decision is made. Ninety seconds now, and not reconstructable in nine months. Every containment action destroys evidence. This record is where you show that you chose which loss to accept rather than discovering it afterwards.

```markdown
## Containment Decision — [Host / scope]           Ref: [IR-YYYY-MM-NNN]

**Time (UTC):** 
**Host / scope:** 
**Option chosen:** [Monitor only / Perimeter or DNS block / Account disable /
  EDR host isolation / VLAN quarantine / Physical disconnect / Hypervisor suspend
  + snapshot / Graceful shutdown / Hard power-off]
**Authorized by:** [Name, role, and how the authorization was given — verbal on
  the bridge, email, ticket. Reference the artifact if one exists.]
**Decided by:** [You.]

**Captured before containment:**
| Item | Tool + version | Time (UTC) | Output path | SHA-256 / CoC ref |
|---|---|---|---|---|
|  |  |  |  |  |

**Reason for this option over the next one down the list:**
[Why not the less destructive option above it? Why not the more thorough one below?
Time, access, tooling, business impact, network team availability — name the real
constraint. "It's what we always do" is not a reason.]

**Evidence cost accepted:**
[Specific categories, not "some evidence". Live connection state. Process memory.
Ongoing attacker behaviour. In-flight session state. Say what you will not be able
to answer later because of this action.]

**Business impact accepted:**
[Users, services, duration. Who was informed and when.]

**Attacker-awareness assessment:**
[Will the attacker notice? What is the plausible reaction — accelerate, go quiet,
burn access, deploy a destructive payload? Does that change the sequencing of the
other hosts?]

**Reassessment trigger:**
[The specific new fact that reopens this decision. "If the same hash appears on a
second host, re-evaluate whether estate-wide containment is required."]

**Recorded by:** [Analyst] at [time UTC]
```

**Prose form**, for a case log that does not take structured entries:

> `[TIME] UTC — [option] applied to [host]. Authorized by [name] ([role]). [What was captured first, with tool, version, and hash reference]. [Option] chosen over [alternative] because [real constraint]. Evidence cost accepted: [specific categories]. Trigger for reassessment: [specific new fact]. — [analyst initials]`

---

## §4 — The Lessons-Learned Entry

> Hold the review within two weeks, while detail is still recoverable. Bring the responders, the system owners, the detection engineers, and someone with budget authority into the room. Work from the timeline in the incident report, not from memory. Every output gets an owner and a date. Outputs without owners are not outputs.

```markdown
# Post-Incident Review — [Name]                    Ref: [IR-YYYY-MM-NNN]
Held: [date] | Facilitator: [name] | Attendees: [names, roles]
Worked from: Incident Report v[N], Section 2 timeline

## Measured intervals
| Interval | Value | How measured |
|---|---|---|
| First attacker action → first alert |  | [artifact timestamps] |
| First alert → responder engaged |  |  |
| Responder engaged → containment |  |  |
| Containment → eradication verified |  |  |
| Eradication verified → service restored |  |  |

## 1. What let this happen?
[The control that was missing, misconfigured, or bypassed. One thing, named.]

| Action | Owner | Due | Remediation or hardening |
|---|---|---|---|

## 2. What delayed detection?
[The specific interval, and what would have shortened it. Not "better monitoring".]

| Action | Owner | Due | Remediation or hardening |
|---|---|---|---|

## 3. What slowed the response?
[Access we did not have. Tooling we could not deploy. Data we had not retained.
Decisions that waited on someone unreachable.]

| Action | Owner | Due | Remediation or hardening |
|---|---|---|---|

## 4. What worked, and is it repeatable?
[THE QUESTION THAT GETS SKIPPED. This is how good practice becomes standard
practice. Name the thing, then name the action that makes it a default rather
than a lucky choice by one analyst.]

| What worked | Action to make it repeatable | Owner | Due |
|---|---|---|---|

---

## Detection content produced by this case
[Tag everything with the case reference so a future engineer can find the incident
that produced the rule — and retire it deliberately when the threat is dead.]

| Type | Name / ID | Platform | Deployed | FP rate checked (date) | Retirement criterion |
|---|---|---|---|---|---|
| Sigma rule |  |  |  |  |  |
| Hunt-pack entry |  |  |  |  |  |
| Blocklist entry |  |  |  |  |  |

## Logging gaps identified
[A gap tied to a specific finding gets funded. The same gap presented as general
best practice does not. Write them tied. The window in which the organization will
act on logging recommendations closes fast — this is the moment.]

**Gap L-N:** [Specific condition, with the number that makes it concrete —
  "capped at 20 MB and rolls over in approximately 36 hours on [host]".]
[Which findings are Undetermined or degraded as a direct result — by number.]
**Change:** [The specific configuration change, with the specific target value.]
**Owner:** [Named team.]
**Cost:** [Licence, storage, engineering time, collector capacity — what it
  actually costs, so it can be budgeted rather than aspired to.]

## Case closure checklist
- [ ] Final report version issued and distributed per its classification
- [ ] Evidence retention period set per legal hold or policy, with a disposal date
      and a named owner
- [ ] Chain of custody closed out for every item
- [ ] Detection content deployed, and its false-positive rate checked after two weeks
- [ ] Lessons-learned actions logged in the system that tracks work here, with owners
- [ ] Case folder archived per the naming standard, and findable by search
```

---

## Quick Reference — Containment Options by Evidence Cost

> Least to most destructive of evidence. Two entries deserve emphasis. Hypervisor snapshot on a virtual host is the one containment action with essentially no evidence cost. Responders routinely forget it because they reach for the EDR console by reflex. Account disable looks free because it does not touch the host, but killing sessions can terminate the exact processes whose memory you need. Sequence it after capture, not before.

| Option | Preserves | Destroys or costs |
|---|---|---|
| Monitor only | Everything, including live attacker behaviour | Accepts ongoing attacker action |
| Perimeter / DNS block of C2 | Memory, disk, processes, local lateral movement | Attacker may switch infrastructure; does not stop on-host action |
| Account disable / lockout | Everything on the host | Kills sessions unpredictably; may lose process memory state; loud |
| EDR host isolation | Memory, processes, disk, volatile state | Live connections drop; attacker learns; collection now via the EDR channel |
| VLAN quarantine / switchport ACL | Memory, processes, disk; can allow a collection path | Same session loss; slower; depends on the network team |
| Physical disconnect | Memory, processes, disk | Same, plus no remote collection — someone must be at the machine |
| **Hypervisor suspend + snapshot** | **A memory image *and* disk state, atomically** | **Nothing, done correctly. Best-case containment for a VM.** |
| Graceful shutdown | Disk, most persistent artifacts | **All memory.** Fires shutdown handlers and any attacker cleanup wired to them |
| Hard power-off | Disk as-is; no handlers fire | **All memory.** File system inconsistency risk; stale hibernation file |

**Default sequence for a live compromised host:** document the decision and the clock → capture memory (or snapshot, if it is a VM) → capture volatile network and process state → contain with the least destructive option that stops the harm → disable accounts and rotate credentials → collect persistent artifacts. Disk is patient.

**Credential rotation order:** confirmed attacker-used accounts → local administrator passwords on in-scope hosts → service accounts present on any compromised host → privileged domain accounts → `krbtgt` twice, with the replication interval between → bulk user population if credential dumping was confirmed where many users had sessions → certificates, API keys, and tokens. Rotate after the hosts holding those credentials are contained and before service is restored.

**The one override on all of it:** if data is actively being destroyed — ransomware encrypting, a wiper running, an attacker deleting logs in real time — contain first and document what was lost.

---

*Incident Reporting Templates — Windows Forensics for Beginners*  
*Version 1.0 — Update this document whenever a real case teaches you that a field was missing.*
