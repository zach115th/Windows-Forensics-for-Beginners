# Lab 13 — Analyst Notes
**Reporting, Containment, and Recovery**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Case Reference (live intrusion):** IR-2024-11-014 — WKSTN-221  
**Case Reference (insider, Task 5/9 only):** IR-2024-11-009 — HR-WS17  

---

## Task 1 — Sort the Output by Audience

| Audience | The decision they are making in the next 24 h | One Case File item to foreground | One to omit, and why | Failure mode if you get it wrong |
|---|---|---|---|---|
| Incoming responder (night shift) | | | | |
| IR manager | | | | |
| CFO / executive leadership | | | | |
| Legal counsel | | | | |
| Affected business unit (Finance team lead) | | | | |
| Legal counsel + HR (HR-WS17) | | | | |

**1. Which two audiences deserve special care, and what goes wrong when you write for them as you would for a technical peer?**

```
[Your response here]
```

**2. The CFO already heard "there was a hack in finance" from a third party. Does that change what goes in the brief, or only the order?**

```
[Your response here]
```

**3. Which single Case File item would you refuse to put in any of the six documents at this stage, and what would have to change?**

```
[Your response here]
```

---

## Task 2 — Fact, Inference, Assumption

| # | Statement | F / I / A | Underlying fact, or what breaks if it fails |
|---|---|---|---|
| 1 | Prefetch `UPDATE.EXE-89A4B22C.pf` — run count 1, last run 14:21:03 | | |
| 2 | `update.exe` executed once at 14:21:03 | | |
| 3 | The user opened `Q4_Payroll_Review.xlsm` at 14:18:55 | | |
| 4 | An LNK referencing `Q4_Payroll_Review.xlsm` was created at 14:18:55 | | |
| 5 | The system clock was accurate to within a few seconds of true UTC | | |
| 6 | The attacker created the WMI subscription at 14:23:02 | | |
| 7 | A WMI consumer `WindowsUpdateConsumer` exists in `root\subscription` with filter and binding, created 14:23:02 | | |
| 8 | `10.0.4.17` is controlled by the attacker | | |
| 9 | 4,218,421 bytes moved from WKSTN-221 to `10.0.4.17` over SMB, 14:31:05–14:33:14 | | |
| 10 | The data transferred to `10.0.4.17` consisted of finance documents | | |

**1. Which Case File event bears directly on statement 5, and does it strengthen or weaken the assumption?**

```
[Your response here]
```

**2. If statement 8 turns out to be wrong, what has to be re-argued?**

```
[Your response here]
```

**3. Which statement would you not put in a report at all, in any form? Why?**

```
[Your response here]
```

---

## Task 3 — Rewrite One Finding at Four Confidence Levels

Subject: **what left WKSTN-221 and where it went.**

| Level | Finding (one sentence) | Artifacts that put it at this level | The §13.2.2 test, applied |
|---|---|---|---|
| Confirmed | | | |
| Probable | | | |
| Possible | | | |
| Undetermined | | | |

**1. Why is your Undetermined source missing — cleared, not retained, never generated, or not yet collected? Which is most embarrassing to write down, and why write it anyway?**

```
[Your response here]
```

**2. Check your Probable finding against Rule 2. Is there a clause inside it that is only Possible? Split it here if so.**

```
[Your response here]
```

**3. Of "likely exfiltrated a significant amount of sensitive payroll data" — which parts does the evidence support, contradict, and neither?**

```
[Your response here]
```

---

## Task 4 — Build Three Findings in the Four-Part Form

**Finding 1 — Initial access and execution chain**

```markdown
**Finding 1 — **
**Basis:** 
**Confidence:** 
**What this does not establish:** 
```

**Finding 2 — Persistence established on WKSTN-221**

```markdown
**Finding 2 — **
**Basis:** 
**Confidence:** 
**What this does not establish:** 
```

**Finding 3 — Lateral movement to FILESVR-03**

```markdown
**Finding 3 — **
**Basis:** 
**Confidence:** 
**What this does not establish:** 
```

**1. For Finding 2, did you split or combine the two persistence mechanisms? What was the deciding argument?**

```
[Your response here]
```

**2. Which single artifact from an uncollected host would move Finding 3 up one level? Name host, artifact, field.**

```
[Your response here]
```

**3. Write the sentence reporting that Run keys and Services were clean, in a form a hostile reviewer cannot over-read.**

```
[Your response here]
```

---

## Task 5 — The Same Finding, Three Audiences

| Reader | Constraint | Your version |
|---|---|---|
| Incoming responder | Artifact-level; ≥1 named artifact, ≥1 exact figure, explicit "not yet checked" with path | |
| IR manager | No artifact names; scope, growth trigger, one resource ask; <120 words | |
| CFO | No EIDs / IPs / tools / hashes; what is not known and when; **<80 words** | |

**Fourth version — legal counsel, IR-2024-11-009 (HR-WS17).** *Which of the three named pricing files can we establish left the host, by what route, at what confidence?*

```
[Your response here]
```

**1. Point at the exact phrase carrying the uncertainty in each of your three IR-2024-11-014 versions.**

```
[Your response here]
```

**2. What did you cut to make the CFO version fit under 80 words, and what risk did you accept?**

```
[Your response here]
```

**3. Why does the legal audience invert the emphasis toward what is *not* established?**

```
[Your response here]
```

---

## Task 6 — Run the Adversarial Reviewer Test

| # | Sentence | The word or omission that fails | What the evidence actually supports | Verdict |
|---|---|---|---|---|
| 1 | "…a sophisticated actor." | | | |
| 2 | "…gaining access via a phishing email…" | | | |
| 3 | "…quickly established persistence and moved laterally … using advanced techniques." | | | |
| 4 | "…likely exfiltrated a significant amount of sensitive payroll data to their C2…" | | | |
| 5 | "…before we were able to respond." | | | |
| 6 | "No evidence of further lateral movement was identified." | | | |
| 7 | "The host has been cleaned and returned to the user." | | | |

**The five §13.2.5 questions, applied to the draft as a whole:**

```
- Which word is doing work the evidence does not support?
- If this artifact could be produced by benign activity, did I say so and rule it out?
- Does any conclusion rest on a single source described as if it were several?
- Is any assumption stated only implicitly?
- Would removing one finding collapse three others? Are the dependencies visible?
```

**Rewritten finding set:**

```markdown
[Your rewritten findings here — expect three or four numbered findings]
```

**On the `network-flow.csv` `Notes` column ("Large outbound transfer — possible exfil"):** how should parser output containing a human's opinion column be treated in a finding's Basis?

```
[Your response here]
```

**1. Why is sentence 7 more dangerous in this report than any of the six forensic sentences above it?**

```
[Your response here]
```

**2. Which of the five questions does the draft fail most severely? Quote the dependency or hidden single source.**

```
[Your response here]
```

**3. The two-sentence message you would actually send the author.**

```
[Your response here]
```

---

## Task 7 — Rank Containment Options by Evidence Cost

**Part A — Ranking**

| Host | 1st choice | 2nd choice | 3rd choice | Ruled out immediately, and why |
|---|---|---|---|---|
| WKSTN-221 | | | | |
| FILESVR-03 | | | | |
| 10.0.4.17 | | | | |

**Part B — Evidence cost of the first choice**

| Host | Chosen option | Preserves | Destroys or costs | Acceptable? Why |
|---|---|---|---|---|
| WKSTN-221 | | | | |
| FILESVR-03 | | | | |
| 10.0.4.17 | | | | |

**Part C — Sequence from 17:30 UTC**

| # | Time (UTC) | Action | Host | Why this position |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |
| 6 | | | | |
| 7 | | | | |
| 8 | | | | |

**1. Which host has the near-zero-evidence-cost option, which option is it, and why is it forgotten?**

```
[Your response here]
```

**2. Two specific costs of disabling `payroll-admin` at 17:35, before anything else.**

```
[Your response here]
```

**3. Three-step plan to locate `10.0.4.17`, in execution order.**

```
[Your response here]
```

**4. What single new fact at 17:45 makes you abandon the sequence and cut the network?**

```
[Your response here]
```

---

## Task 8 — Write the Containment Decision Record

| Field | WKSTN-221 | FILESVR-03 |
|---|---|---|
| Time (UTC) | | |
| Option chosen | | |
| Authorized by | | |
| Reason this option and not the next one down | | |
| Evidence cost accepted | | |
| Reassessment trigger | | |
| Captured before containment (tool, hash ref) | | |

**Prose version (paste from `report-templates.md` §3):**

```
[WKSTN-221 record]
```

```
[FILESVR-03 record]
```

**1. How long did the WKSTN-221 record actually take, and which field slowed you down?**

```
[Your response here]
```

**2. What if the authorizing person later says they do not recall authorizing it? What in your record protects you?**

```
[Your response here]
```

**3. FILESVR-03 has 40 users and an objecting business owner. Where in the record does that objection belong?**

```
[Your response here]
```

---

> **Clock moves to 2024-11-17 for Tasks 9–13.**

---

## Task 9 — Rebuild or Clean

| Factor | WKSTN-221 | FILESVR-03 | 10.0.4.17 | HR-WS17 |
|---|---|---|---|---|
| Attacker access level | | | | |
| Tooling observed | | | | |
| Persistence found | | | | |
| Kernel-level activity | | | | |
| Dwell time | | | | |
| Host role | | | | |
| Rebuild cost | | | | |
| Confidence in scope | | | | |
| **Decision** | | | | |
| **One-sentence justification** | | | | |

**What does "rebuild or clean" even mean for HR-WS17, a host already imaged and in an evidence locker?**

```
[Your response here]
```

**1. Did any live host genuinely justify cleaning? Write the justification as a reviewer will read it in six months.**

```
[Your response here]
```

**2. `10.0.4.17` was domain-joined and uninventoried for eighteen months. Which factors does that move, and how far?**

```
[Your response here]
```

**3. If the 14:33 explicit-credential logon had gone to DC02 instead of FILESVR-03 — what changes, and how far does the conversation escalate?**

```
[Your response here]
```

---

## Task 10 — Credential Rotation, In Order

**Part A**

| # | Category | Applies? | What specifically | Before/after containment; before/after restore | Owner |
|---|---|---|---|---|---|
| 1 | Confirmed attacker-used accounts | | | | |
| 2 | Local administrator passwords | | | | |
| 3 | Service accounts on compromised hosts | | | | |
| 4 | Privileged domain accounts | | | | |
| 5 | `krbtgt`, twice | | | | |
| 6 | Bulk user population | | | | |
| 7 | Certificates, API keys, tokens | | | | |

**Part B — The specific decisions**

*`svc-backup` authenticated at 02:14 on 2024-11-14 via `BackupServiceSync`. Was that credential exposed? Confidence? Action? Cost of being wrong in either direction?*

```
[Your response here]
```

*No memory image covers the intrusion window. Does that make the credential-exposure question easier or harder to answer conservatively, and what does a conservative answer look like in the report?*

```
[Your response here]
```

*`10.0.4.17` was domain-joined and unmanaged for eighteen months. What does that do to categories 2 and 4?*

```
[Your response here]
```

**1. What goes wrong if you rotate at 17:35 on 14 November, before WKSTN-221 is isolated?**

```
[Your response here]
```

**2. Three category-7 items that plausibly exist in a finance department and would not appear on anyone's rotation list.**

```
[Your response here]
```

**3. Is `krbtgt` rotation justified as scoped on 2024-11-17? Argue both sides, then commit.**

```
[Your response here]
```

---

## Task 11 — Build the Eradication Verification Checklist

**Part A — The three questions**

| # | Question | Answer | Confidence | Reinfection risk if Possible/Undetermined |
|---|---|---|---|---|
| 1 | All persistence identified? | | | |
| 2 | All attacker-accessible credentials rotated? | | | |
| 3 | Entry point closed? | | | |

**Part B — Persistence verification checklist**

| # | Mechanism | How to check | Found in this case? | Verified clear on (host / date) |
|---|---|---|---|---|
| 1 | Run / RunOnce | | No | |
| 2 | Services | | No | |
| 3 | Scheduled Tasks | | **Yes** — `WindowsUpdateSync`, 14:22:58 | |
| 4 | WMI event subscriptions | | **Yes** — `WindowsUpdateConsumer`, 14:23:02 | |
| 5 | COM hijacks | | | |
| 6 | IFEO debuggers | | | |
| 7 | AppInit / AppCert DLLs | | | |
| 8 | Winlogon Shell / Userinit | | | |
| 9 | LSA and SSP providers | | | |
| 10 | Office add-ins and templates | | | |
| 11 | Startup folders | | | |
| 12 | BITS jobs | | | |
| 13 | Accessibility-tool replacements | | | |
| 14 | Attacker-installed RMM / remote access | | | |
| 15 | *(your addition)* | | | |

**Part C — The §13.5.5 verification pass**

| Step | Concrete action for IR-2024-11-014 | Owner | Done when |
|---|---|---|---|
| Re-hunt full IOC set | | | |
| Re-check persistence on formerly-compromised hosts | | | |
| Positively test the entry point is closed | | | |
| Confirm rotation actually completed | | | |
| Elevated monitoring for a defined period | | | |

**1. What would an analyst enumerating only `root\subscription` have missed, and why is that the mistake an adversary wants?**

```
[Your response here]
```

**2. Does a persistence mechanism that never fired belong in the eradication checklist? In the IOC list? Argue both.**

```
[Your response here]
```

**3. What was the entry point, what would "closed" mean, and what positive test demonstrates it?**

```
[Your response here]
```

---

## Task 12 — Write the One-Page Executive Brief

**Version 1 — as of 2024-11-14 17:45 UTC** (paste from `report-templates.md` §1)

```markdown
[Your one-page brief here]
```

**Version 2 — as of 2024-11-17**

```markdown
[Your second brief here]
```

**1. What did the page limit force you to cut from the 14 November brief, and did cutting it change what the CFO would decide?**

```
[Your response here]
```

**2. Compare your payroll-data sentence against your Task 3 Confirmed and Undetermined findings. Did translation quietly upgrade it?**

```
[Your response here]
```

**3. What is the §13.1.3 failure mode around good news and cadence, and how does version 2 avoid it?**

```
[Your response here]
```

---

## Task 13 — Close the Loop: Detection Content, Logging Gaps, Lessons Learned

**Part A — Sigma rules**

*Rule 1:*

```yaml
[Your rule here]
```

Which Case File artifact would make it fire, and at what timestamp?

```
[Your response here]
```

*Rule 2:*

```yaml
[Your rule here]
```

Which Case File artifact would make it fire, and at what timestamp?

```
[Your response here]
```

**Part B — Sort the harvest**

| Category | Items from IR-2024-11-014 | Where it goes | Shelf life |
|---|---|---|---|
| Atomic indicators | | | |
| Behavioral detections | | | |
| Hunt-pack entries (generalized) | | | |
| Detection gaps (had the log, no rule) | | | |
| Logging gaps (did not have the log) | | | |

*New hunt-pack entry, in your Lab 09 hunt-pack format, generalized:*

```markdown
[Your hunt-pack entry here]
```

**Part C — Costed logging gaps**

```markdown
**Gap L-1:** 
**Change:** 
**Owner:** 
**Cost:** 
```

```markdown
**Gap L-2:** 
**Change:** 
**Owner:** 
**Cost:** 
```

```markdown
**Gap L-3:** 
**Change:** 
**Owner:** 
**Cost:** 
```

**Part D — Lessons learned**

| Question | Answer for IR-2024-11-014 | Resulting action | Owner | Due |
|---|---|---|---|---|
| What let this happen? | | | | |
| What delayed detection? | | | | |
| What slowed the response? | | | | |
| What worked, and is it repeatable? | | | | |

**1. What was the interval between first attacker action and first alert, and which control would have shortened it most?**

```
[Your response here]
```

**2. Name one thing that genuinely worked, and write the action that makes it repeatable.**

```
[Your response here]
```

**3. Write the retirement criterion for one of your two Sigma rules.**

```
[Your response here]
```

---

## Additional Notes

> Use this space for anything that came up during the lab — sentences you caught yourself writing and had to strike, arguments you had with the model answers, phrasing you want to reuse, or gaps in your own organization's reporting standard that this lab exposed.

```
[Free text]
```

---

*Lab 13 Notes — Windows Forensics for Beginners*
*Keep this file in your `Labs/Lab13/` folder alongside the `ReadMe.md`.*
