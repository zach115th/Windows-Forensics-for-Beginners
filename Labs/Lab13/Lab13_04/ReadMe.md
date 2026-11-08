# Lab 13.4 — Containment Without Destroying Evidence

**Supporting Section 13.4: Containment Without Destroying Evidence**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Every containment action destroys evidence. The question is never whether to accept evidence loss. It is which loss you choose, and whether you choose it deliberately.

Under pressure, most teams have a different conversation: "isolate it" or "leave it up." They discover the evidence cost afterwards, usually when someone asks a question the missing evidence would have answered. This sub-exercise runs the conversation the other way round: cost first, choice second, record third.

You have three hosts with different properties. One is a physical workstation with a healthy EDR agent and a user still logged on. One is a virtual server you have hypervisor access to, with no EDR agent and 40 concurrent users. One is an unidentified box inside your own network that has already read 4.2 MB off the workstation. You cannot contain it because you cannot find it.

The right answer is different for each. For one of them, the right answer costs essentially no evidence at all. Responders routinely forget it, because the EDR console is the reflex.

---

## What This Lab Covers

This lab supports the following concepts from Section 13.4:

| Section | Topic |
|---|---|
| 13.4.1 | Containment options ranked by evidence cost |
| 13.4.2 | Memory first, then contain — and the one override |
| 13.4.3 | The containment decision flow (Figure 13.3) |
| 13.4.4 | Containment is a decision, and decisions get documented |
| 13.4.5 | Tipping the attacker off |

---

## Learning Objectives

By completing this lab, you will be able to:

- Rank the nine containment options by their cost to volatile and persistent evidence
- Choose a containment option per host, accounting for host role, virtualization, EDR coverage, and business impact
- Sequence memory capture, containment, and credential rotation defensibly
- Identify the one override that reverses the default sequence
- Walk the Figure 13.3 decision flow against a live case and find the branch that is hardest to answer honestly
- Write a containment decision record that answers a reviewer's questions in advance
- Assess how visible a containment action is to the attacker and what they plausibly do about it

---

## Estimated Time

60–80 minutes

---

## Prerequisites

- Chapter 13 §13.4 read, with the §13.4.1 option table and Figure 13.3 to hand
- Labs 13.1–13.3 completed, or equivalent familiarity with the WKSTN-221 case
- `report-templates.md` from the parent `Lab13/` folder — §3 is the Containment Decision Record skeleton used in Task 5
- A text editor or markdown editor
- Your `lab13-notes.md` file, in the parent `Lab13/` folder

---

## Scenario

It is 2024-11-14 17:30 UTC. **Nothing has been contained.** IR decided at 14:25 to monitor and collect before isolating, and that decision has not been revisited.

WKSTN-221 is still on the network and powered on. `payroll-admin` is still logged on, and `91.214.47.22` is still reachable from the finance VLAN. The IR manager wants a containment recommendation with the evidence cost stated. He wants it before the CFO brief at 18:00 so he can say containment is under way.

### The environment

| | |
|---|---|
| Domain | `finance.local` — single domain, two DCs (DC01, DC02) |
| **WKSTN-221** | Physical desktop, 10.0.4.32, Windows 11 23H2. EDR agent installed and healthy. **Not a VM.** User logged on. |
| **FILESVR-03** | 10.0.4.18, Windows Server 2019, **VMware VM on a cluster your team has hypervisor access to**. Hosts `Finance$`. ~40 concurrent users during business hours. **No EDR agent** — servers were excluded from the rollout on performance grounds. State unknown; nothing collected. |
| **10.0.4.17** | Unidentified. Not in the CMDB. DHCP lease exists. The MAC matches no inventoried asset. Annotated in the triage flow data as an adversary-controlled pivot. |
| Logging | Security log 20 MB on workstations, wraps in ~36 h. PowerShell Script Block Logging enabled. **No Windows Event Forwarding. No host DNS query logging.** Perimeter flow records retained 14 days. No packet capture anywhere. |
| Backups | FILESVR-03 backed up nightly at 01:00 UTC to a backup appliance on the same domain. |

### What the attacker did, and what is still live

| Time (UTC) | Event |
|---|---|
| 14:19:38 | `OUTLOOK.EXE` spawns `POWERSHELL.EXE` with `-EncodedCommand` (EID 4688) |
| 14:21:03 | `update.exe` executes — Prefetch `UPDATE.EXE-89A4B22C.pf`, **RunCount 1** |
| 14:21:55 | TCP/443 to `91.214.47.22`, process `update.exe` — **184,221 bytes sent / 2,415,891 received** |
| 14:22:58 | Scheduled task `\Microsoft\Windows\WindowsUpdate\WindowsUpdateSync` created — `LastTaskResult 0x41303`, **never executed** |
| 14:23:02 | WMI subscription in `root\subscription` — filter `WindowsUpdateFilter`, consumer `WindowsUpdateConsumer`, **binding present. Live persistence.** |
| 14:23:44 | `update.exe` deleted from `Temp\` |
| 14:31:05–14:33:14 | Inbound SMB from **`10.0.4.17`** — **4,218,421 bytes read off WKSTN-221** |
| 14:33:18 | EID 4648, `TargetServerName=FILESVR-03` (10.0.4.18), `ProcessName=…\cmd.exe` |
| 14:33:42–14:35:00 | Outbound SMB to FILESVR-03 — 184,221 sent, 8,421 received |

Standing facts at 17:30: **no memory capture has been attempted on any host**. The binary was deleted and no sample recovered. FILESVR-03 has not been collected. The pivot at `10.0.4.17` has no asset record and no owner. Nobody has hunted the `update.exe` hash anywhere.

---

## Background: The Ranking Is the Whole Argument

Chapter §13.4.1 orders the options from least to most destructive of evidence. Two entries deserve emphasis before you start:

- **Hypervisor suspend + snapshot** on a virtual host is the one containment action with essentially no evidence cost. It captures memory *and* disk atomically. Responders routinely forget it because they reach for the EDR console by reflex.
- **Account disable** is often treated as low-impact because it does not touch the host. But killing sessions can terminate the exact processes whose memory you need. Sequence it after capture, not before.

> **IR Reality Check:** Containment is visible. A capable attacker who sees a host go dark, an account disabled, or a C2 domain sinkholed will respond. They may accelerate exfiltration, deploy ransomware early, burn current access to protect a persistence mechanism you have not found, or go quiet for weeks. Once scope is understood, that argues for containing broadly and at once rather than one host at a time.

---

## Lab Tasks

---

### Task 1 — Rank the Options Cold

**Objective:** Internalize the evidence-cost ordering before applying it.

Close the chapter. Rank these nine options from least to most destructive of evidence, then open §13.4.1 and check.

`monitor only` · `perimeter/DNS block of C2` · `account disable` · `EDR host isolation` · `VLAN quarantine` · `physical network disconnect` · `hypervisor suspend + snapshot` · `graceful shutdown` · `hard power-off`

| Rank | Your ordering (from memory) | The chapter's ordering | Preserves | Destroys or costs |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |
| 6 | | | | |
| 7 | | | | |
| 8 | | | | |
| 9 | | | | |

Then answer:

**1. Where did your ordering differ from the chapter's? For each difference, decide whether you were wrong or whether the chapter's ordering rests on an assumption your reasoning did not share.**

**2. One option sits far higher in the chapter's ranking than most responders expect. Which, and why does the surprise persist?**

**3. Graceful shutdown and hard power-off both destroy all memory. State the two reasons the chapter still separates them, and name the case in which you would deliberately choose the more violent one.**

---

### Task 2 — Choose Per Host

**Objective:** Apply the ranking to three hosts whose properties are not the same.

**Part A — Rank your top three per host, most preferred first.**

| Host | 1st choice | 2nd choice | 3rd choice | The option you rule out immediately, and why |
|---|---|---|---|---|
| WKSTN-221 (physical, EDR healthy, user logged on, live) | | | | |
| FILESVR-03 (VM you control, no EDR, 40 users, state unknown) | | | | |
| 10.0.4.17 (unidentified, no asset record, adversary-controlled) | | | | |

**Part B — State the evidence cost of your first choice for each.**

| Host | Chosen option | Evidence it preserves | Evidence it destroys or costs | Is that loss acceptable? Why |
|---|---|---|---|---|
| WKSTN-221 | | | | |
| FILESVR-03 | | | | |
| 10.0.4.17 | | | | |

Then answer:

**1. One of the three hosts has an option available that costs essentially no evidence at all, and Chapter 13 says responders routinely forget it. Which host, which option, and why is it forgotten?**

**2. FILESVR-03 has no EDR agent. Name two containment options this removes from the table and one it makes more attractive.**

**3. You cannot isolate `10.0.4.17` because you cannot find it. Write the three-step plan to locate it, in execution order, using only the evidence in the Scenario plus infrastructure you would reasonably have.**

---

### Task 3 — Sequence It

**Objective:** Reconcile "memory first" (§13.4.2) with containing "broadly and at once" (§13.4.5).

These two pieces of guidance pull against each other in this incident. Memory-first says capture before you contain. Contain-broadly says do not give the attacker a sequence of warnings. Resolve it.

Write the ordered action list from 17:30 UTC, with a time estimate against each step.

| # | Time (UTC) | Action | Host | Why this position in the sequence |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |
| 6 | | | | |
| 7 | | | | |
| 8 | | | | |

Constraints:

- The default sequence in §13.4.2 has six steps. Your list must show where each of them lands, or explain why one does not apply here.
- WKSTN-221 has no memory capture tooling deployed and is physical. Say what that does to step 2, and do not quietly skip it.
- Credential rotation appears in the §13.4.2 sequence. Note where it goes. The detail is Lab 13.5's problem.

Then answer:

**1. The `payroll-admin` account is the attacker's confirmed identity on this incident. Disabling it looks free — it touches no host. Name two specific things it costs you if you do it at 17:35, before anything else in your sequence.**

**2. What single new fact arriving at 17:45 would make you abandon this entire sequence and cut the network immediately?**

**3. Chapter §13.4.2 gives one override that reverses the whole default. State it, and say why the calculation flips — what evidence do you lose by capturing memory first when it applies?**

---

### Task 4 — Walk the Decision Flow

**Objective:** Run Figure 13.3 against each host and find the branch that is hardest to answer honestly.

For each host, record the path you take through the flow and the answer you gave at each decision node.

| Node | WKSTN-221 | FILESVR-03 | 10.0.4.17 |
|---|---|---|---|
| Active destruction in progress? | | | |
| Is the host a VM you control? | | | |
| Memory capture feasible now? | | | |
| Scope known? | | | |
| **Terminal action** | | | |

Then answer:

**1. Chapter §13.4.3 says the middle path is the common one and its hardest branch is "the honest assessment of whether scope is actually known." Answer it for this incident at 17:30 UTC, and defend the answer.**

**2. If you answered "scope not known," the flow sends you to "block C2 at perimeter, keep host live and watched" — which requires both authority and telemetry. Do you have both here? What specifically is missing?**

**3. The flow has a reassessment loop with three named triggers: new host, new account, destructive action. Write the concrete version of each for this incident — what would actually reach you, and through which channel?**

---

### Task 5 — Write the Containment Decision Records

**Objective:** Produce the case log entries that answer a reviewer's questions in advance (§13.4.4).

Chapter §13.4.4 requires five things: time, option chosen, authorizing person, reason, and evidence cost accepted. The worked example adds a sixth worth keeping — a named reassessment trigger.

Use the skeleton in `report-templates.md` §3. Write a record for WKSTN-221 and one for FILESVR-03.

| Field | WKSTN-221 | FILESVR-03 |
|---|---|---|
| Time (UTC) | | |
| Option chosen | | |
| Authorized by (name, role, how the authorization was given) | | |
| Reason for this option and not the next one down the list | | |
| Evidence cost accepted (specific categories) | | |
| Business impact accepted | | |
| Attacker-awareness assessment | | |
| Reassessment trigger | | |
| What was captured before containment, with tool and hash reference | | |

Each should be a dense paragraph or a short structured block — not a page. Then write the WKSTN-221 record again in the **prose form** given at the end of `report-templates.md` §3, for a case log that does not take structured entries.

Your record must survive this test: hand it to someone who was not there, nine months from now, and they should not need to ask you a single question about *why*.

Then answer:

**1. Chapter 13 says writing this entry takes 90 seconds. Time yourself. How long did the WKSTN-221 one actually take, and which field slowed you down?**

**2. Your record names an authorizing person. What happens to the record — and to you — if that person later says they do not recall authorizing it? What in your record protects against that?**

**3. FILESVR-03 has 40 concurrent users and a business owner who will object. Where in the record does that objection belong: in the reason, in the evidence cost, or somewhere else entirely?**

---

### Task 6 — Tipping the Attacker Off

**Objective:** Assess visibility and plausible attacker response (§13.4.5).

**Part A.** For each action in your Task 3 sequence, assess how visible it is and what the attacker plausibly does.

| Action | Visible to the attacker? | How they would notice | Plausible response | Does that change your sequencing? |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |

**Part B.** The chapter argues that, once scope is understood, you should contain broadly and at once. Piecemeal containment gives the attacker a sequence of warnings and time to adapt between them. Take the opposite position and argue for staged containment in *this* incident. Then say which argument wins and why.

Then answer:

**1. What is the worst realistic attacker response to your first containment action, and what would it cost the organization?**

**2. The chapter says the pressure to contain the first host immediately has to be weighed against the value of understanding scope first. In this incident, how much scope understanding would another two hours actually buy you? Be specific about what you would learn.**

**3. `10.0.4.17` is inside your network and you cannot find it. Does that make broad-and-at-once containment more attractive or less? Argue it.**

---

### Task 7 — Reflection

Answer each in 3–5 sentences.

**1. Choosing the loss**
"You are never choosing whether to accept a loss, only which loss." Has that changed how you would answer "should we isolate it?" on a real call? How?

**2. The forgotten option**
Hypervisor snapshot is the cheapest containment available and the one most often missed. What would you put in your own team's runbook to stop it being missed?

**3. Ninety seconds now, impossible in nine months**
The containment decision record is trivial to write in the moment and unreconstructable later. Why does it still get skipped, and what would make it habitual?

**4. Containment is visible**
Does knowing the attacker will see your containment make you more inclined to move fast or more inclined to prepare? Justify the answer against this incident specifically.

---

## Deliverables Checklist

Your `lab13-notes.md` should contain:

- [ ] **Task 1** — Cold ranking against the chapter's ranking, with preserves/costs, plus three written responses
- [ ] **Task 2** — Per-host option ranking (Part A) and evidence cost (Part B), plus three written responses
- [ ] **Task 3** — Ordered action sequence from 17:30 UTC with time estimates, plus three written responses
- [ ] **Task 4** — Figure 13.3 walkthrough for all three hosts, plus three written responses
- [ ] **Task 5** — Containment decision records for WKSTN-221 and FILESVR-03, plus the prose-form version, plus three written responses
- [ ] **Task 6** — Attacker-visibility table and the staged-versus-broad argument, plus three written responses
- [ ] **Task 7** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab13/
├── lab13-notes.md  ← Your working notes file (whole lab)
└── Lab13_04/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **Every containment action destroys evidence.** You choose which loss, not whether to accept one.
- **Hypervisor suspend and snapshot is the cheapest containment available.** It captures memory and disk atomically for a VM you control. Responders forget it because the EDR console is the reflex.
- **Account disable is not free.** It kills sessions unpredictably and can terminate the exact processes whose memory you needed. Sequence it after capture.
- **Memory first, then contain — unless data is actively being destroyed.** That is the one override, and it is the ransomware case.
- **The hardest branch in the decision flow is "is scope actually known?"** An honest answer separates a deliberate monitor-and-collect from a stall.
- **A containment decision record takes 90 seconds and cannot be reconstructed in nine months.** Time, option, authorizer, reason, evidence cost accepted, reassessment trigger.
- **Containment is visible.** Piecemeal containment gives the attacker a sequence of warnings and time to adapt between them.

---

**Next:** Lab 13.5 — Eradication and the Reinfection Question

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
