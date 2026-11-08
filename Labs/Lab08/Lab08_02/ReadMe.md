# Lab 8.2 — Key IR Use Cases

**Supporting Section 8.2: Key IR Use Cases**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Network evidence is only useful if it helps answer the incident-response questions that matter.

In real cases, responders analyze packets to determine whether data left the environment, identify attacker infrastructure, reconstruct internal movement, and decide what to block right now. Those are operational questions, not academic ones.

This lab focuses on the four key network-forensics use cases introduced in Chapter 8:

- Confirming exfiltration
- Identifying C2 endpoints and infrastructure
- Understanding lateral movement paths
- Supporting blocking decisions for IPs and domains

The goal is to think about network evidence the way an incident responder does, as a means of answering urgent scoping, containment, and reporting questions. By the end of this lab, you should be able to map each use case to the right evidence sources, explain what strong support would look like, and distinguish disciplined findings from overclaims.

---

## What This Lab Covers

This lab supports the following concepts from Section 8.2:

| Section | Topic |
|---|---|
| 8.2.1 | Confirming exfiltration |
| 8.2.2 | Identifying C2 endpoints and infrastructure |
| 8.2.3 | Understanding lateral movement paths |
| 8.2.4 | Supporting blocking decisions |

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain the major incident-response use cases for network evidence
- Distinguish exfiltration indicators from normal outbound traffic
- Identify patterns consistent with C2 or suspicious infrastructure
- Use network evidence to reason about lateral movement paths
- Evaluate when an IP, domain, or service is a reasonable blocking candidate
- Separate strong support from incomplete or ambiguous network findings
- Write concise notes that link network observations to operational IR decisions

---

## Estimated Time

45–65 minutes

---

## Prerequisites

- Completion of Lab 8.1, or equivalent familiarity with packet captures, flow logs, Windows ETL traces, and application logs
- A text editor or markdown editor
- Your `lab08-notes.md` file
- Optional: sample packet captures, flow logs, proxy logs, VPN logs, or Windows host trace data

---

## Scenario

You are investigating suspicious activity from **FIN-WS23** during a short incident window. The case team has four urgent questions:

1. Was there exfiltration?
2. Did the host talk to likely C2 infrastructure?
3. Did the attacker move laterally inside the environment?
4. What should we block right now without causing unnecessary disruption?

Available evidence may include:

- Packet captures
- Firewall or NetFlow/IPFIX records
- Proxy or VPN logs
- Host-side network context from Windows
- Supporting host artifacts from earlier phases of the investigation

Your task is to evaluate each of these IR use cases, determine what evidence best supports them, and practice reporting your findings in disciplined, operational language.

---

## Background: The Question Drives the Analysis

The same packet stream can matter for very different reasons depending on the case question.

A long-lived outbound connection may matter because it suggests:

- Possible beaconing
- Possible exfiltration
- A likely block candidate
- A correlation point with process or memory findings

Likewise, a burst of internal connections may matter because it suggests:

- Lateral movement
- Service discovery
- Remote execution
- Benign administrative activity that still needs explanation

The responder's job is to connect network observations to practical decisions.

| IR Use Case | Main Question |
|---|---|
| **Exfiltration** | Did meaningful data likely leave the system or environment? |
| **C2 identification** | Which endpoints or domains may represent attacker control or staging? |
| **Lateral movement** | Which internal paths may show spread, remote access, or pivoting? |
| **Blocking support** | What can be blocked now to reduce risk without overreacting? |

> **IR Reality Check:** Strong network evidence often supports urgent action, but it does not always answer motive, user intent, or malware family by itself.

---

## Lab Tasks

---

### Task 1 — Define the Four Key IR Use Cases

**Objective:** Build a practical understanding of the use cases in Section 8.2.

For each use case below, explain in plain language what the responder is trying to answer.

| IR Use Case | What the Responder Is Trying to Determine | Why It Matters |
|---|---|---|
| Confirming exfiltration | | |
| Identifying C2 endpoints and infrastructure | | |
| Understanding lateral movement paths | | |
| Supporting blocking decisions | | |

Then answer:

1. Why do these questions matter more to responders than protocol trivia alone?
2. Why can the same connection matter for more than one use case?
3. Why should these use cases influence what evidence source you prioritize?

---

### Task 2 — Map Each Use Case to the Best Evidence Sources

**Objective:** Connect each IR question to the evidence sources most likely to answer it.

Fill in the table below.

| IR Use Case | Best Evidence Source(s) to Check First | Why |
|---|---|---|
| Confirming exfiltration | | |
| Identifying C2 endpoints and infrastructure | | |
| Understanding lateral movement paths | | |
| Supporting blocking decisions | | |

Then add a second layer of detail:

| Use Case | Best Host Artifact(s) to Correlate | Why Host Correlation Matters |
|---|---|---|
| Exfiltration | | |
| C2 identification | | |
| Lateral movement | | |
| Blocking support | | |

Then answer:

1. Why is network evidence often stronger when paired with host context?
2. Why might packet captures and flow logs play different roles in the same use case?
3. Why can application logs be decisive for some questions even when packet data exists?

---

### Task 3 — Confirming Exfiltration

**Objective:** Practice reasoning about whether data likely left the host or environment.

Assume you are evaluating possible exfiltration from FIN-WS23.

Fill in the table below.

| Exfiltration Indicator | Why It Might Matter | What It Does Not Prove by Itself |
|---|---|---|
| Large outbound transfer | | |
| Long-lived outbound session | | |
| Transfer to unusual remote destination | | |
| Data sent shortly after sensitive file access | | |
| Repeated outbound traffic bursts | | |
| Transfer to cloud-storage or file-sharing service | | |

Add at least five more exfiltration indicators of your own.

Then answer:

1. Why is "large outbound transfer" important but still incomplete by itself?
2. Why does timing correlation with sensitive-file access strengthen an exfiltration theory?
3. Why can legitimate business traffic resemble exfiltration at first glance?

Afterward, complete this table:

| Evidence Pattern | Exfiltration Assessment | Why |
|---|---|---|
| Large HTTPS transfer to normal SaaS provider | | |
| Large transfer to unfamiliar IP on unusual port | | |
| Small repeated bursts to a suspicious endpoint | | |
| Transfer to approved enterprise cloud storage | | |

---

### Task 4 — Identifying C2 Endpoints and Infrastructure

**Objective:** Practice identifying communications that may represent attacker control or staging.

Fill in the table below.

| Possible C2 Indicator | Why It Matters | What It Does Not Prove by Itself |
|---|---|---|
| Repeated periodic outbound connections | | |
| Long-lived idle-looking sessions | | |
| Contact with unusual IPs or domains | | |
| Use of uncommon ports | | |
| Traffic aligned with suspicious process activity | | |
| Connections persisting after user inactivity | | |

Add at least five more C2 indicators of your own.

Then answer:

1. Why do repeated periodic connections often raise suspicion?
2. Why is a suspicious IP still only a lead until it is contextualized?
3. Why is process-to-connection correlation especially important in possible C2 cases?

Afterward, complete this table:

| Connection Pattern | C2 Assessment | Why |
|---|---|---|
| Beacon-like repeated outbound HTTPS connections | | |
| One-time user-driven browser connection | | |
| Long-lived session owned by suspicious process | | |
| External connection from known enterprise agent | | |

---

### Task 5 — Understanding Lateral Movement Paths

**Objective:** Use network evidence to reason about internal attacker movement.

Assume the team suspects internal spread from FIN-WS23.

Fill in the table below.

| Lateral-Movement Indicator | Why It Matters | What It Does Not Prove by Itself |
|---|---|---|
| Internal host-to-host connection burst | | |
| Access to administrative ports or services | | |
| Connections to multiple internal servers in short succession | | |
| Traffic aligned with suspicious credentials or logons | | |
| Remote execution–like timing with host artifacts | | |
| Internal SMB, RDP, WinRM, or RPC activity | | |

Add at least five more lateral-movement indicators of your own.

Then answer:

1. Why is internal traffic often more important than external traffic during scoping?
2. Why can normal admin behavior resemble lateral movement?
3. Why is host correlation especially important in internal-movement analysis?

Afterward, complete this table:

| Internal Traffic Pattern | Lateral-Movement Assessment | Why |
|---|---|---|
| Repeated RDP connections to admin servers | | |
| One-time SMB access to a normal file share | | |
| WinRM or RPC activity tied to suspicious user context | | |
| Broad scanning-like internal connection spread | | |

---

### Task 6 — Supporting Blocking Decisions

**Objective:** Practice deciding when network evidence is strong enough to support containment.

Blocking is high-impact. Done too quickly, it can break business operations. Done too slowly, it can leave the attacker active.

Fill in the table below.

| Possible Blocking Candidate | Why It Might Be Considered | What You Would Want Before Recommending a Block |
|---|---|---|
| External IP | | |
| Domain | | |
| Port / protocol combination | | |
| URL path or web resource | | |
| Internal host communicating suspiciously | | |

Add at least five more block-candidate categories of your own.

Then answer:

1. Why should responders be cautious before blocking based on a single suspicious session?
2. Why can a domain be harder to block safely than a single IP in some environments?
3. Why should blocking decisions consider both evidence strength and business impact?

Afterward, complete this table:

| Candidate | Blocking Assessment | Why |
|---|---|---|
| Single suspicious external IP with repeated beaconing | | |
| Entire SaaS domain with mixed business use | | |
| Internal host making suspicious lateral connections | | |
| Rare port used only in attacker-like traffic | | |

---

### Task 7 — Correlate the Four Use Cases in One Scenario

**Objective:** Practice seeing how one network pattern can affect multiple IR decisions.

Assume the following evidence exists for FIN-WS23:

- A repeated outbound HTTPS connection to an unfamiliar IP every 90 seconds
- A 75 MB outbound transfer during the suspected incident window
- Internal SMB and RDP traffic to two peer systems shortly afterward
- Proxy logs showing a browser visit to a cloud file-sharing portal earlier in the day

For each observation, map which IR use case or use cases it most strongly supports.

| Observation | Exfiltration? | C2? | Lateral Movement? | Blocking? | Why |
|---|---|---|---|---|---|
| Repeated outbound HTTPS every 90 seconds | | | | | |
| 75 MB outbound transfer | | | | | |
| Internal SMB and RDP activity | | | | | |
| Browser visit to file-sharing portal | | | | | |

Then answer:

1. Which observation is strongest for exfiltration review?
2. Which is strongest for C2 assessment?
3. Which is strongest for lateral movement analysis?
4. Which would you most likely escalate into an immediate block discussion, and why?

---

### Task 8 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined operational language around network use cases.

Classify each statement below as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by this evidence alone

| Statement | Classification | Why |
|---|---|---|
| The host communicated with an unfamiliar external IP during the incident window | | |
| The communication pattern is consistent with possible beaconing | | |
| The attacker definitely controlled the remote IP | | |
| A large outbound transfer deserves deeper exfiltration review | | |
| Internal traffic suggests possible lateral movement paths | | |
| The user intentionally stole data | | |
| A suspicious endpoint may be a reasonable temporary blocking candidate | | |
| The observed network traffic proves malicious exfiltration occurred | | |

Then write six additional statements of your own and classify them the same way.

> **Guidance:** The goal is to connect network evidence to action without claiming more than the data supports.

---

### Task 9 — Write a Key Use Cases Analyst Summary

**Objective:** Produce a concise working-note summary that ties network evidence to operational IR needs.

Write a 3–5 paragraph analyst summary describing how the FIN-WS23 network evidence relates to the four key IR use cases:

- Exfiltration
- C2 identification
- Lateral movement
- Blocking support

Your summary should include:

- Which use case appears most strongly supported
- Which observations matter most
- What is strongly supported by the evidence
- What still needs host, memory, or log correlation
- What immediate next steps you would recommend

Write it as an internal working note, not a final incident report.

---

### Task 10 — Reflection

Answer the following in 3–5 sentences each.

**1. Why use cases matter**
Why is network analysis more effective when responders start from operational questions like exfiltration, C2, lateral movement, and blocking?

**2. Same data, different meaning**
Why can the same network observation matter differently depending on the use case?

**3. Caution in containment**
Why should responders be especially careful when turning suspicious network observations into blocking recommendations?

**4. Correlation remains essential**
Why do these network use cases become much stronger when paired with host, memory, proxy, VPN, or application-log evidence?

---

## Deliverables Checklist

Your `lab08-notes.md` should contain:

- [ ] **Task 1** — Four-use-case definition table with written responses
- [ ] **Task 2** — Evidence-source mapping tables
- [ ] **Task 3** — Exfiltration-indicator table with added indicators and assessment table
- [ ] **Task 4** — C2-indicator table with added indicators and assessment table
- [ ] **Task 5** — Lateral-movement-indicator table with added indicators and assessment table
- [ ] **Task 6** — Blocking-candidate table with added categories and assessment table
- [ ] **Task 7** — Cross-use-case scenario correlation table with written responses
- [ ] **Task 8** — Strong support vs overclaim exercise
- [ ] **Task 9** — Key Use Cases analyst summary
- [ ] **Task 10** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab08/
├── lab08-notes.md  ← Your working notes file (whole lab)
└── Lab08_02/
    └── ReadMe.md       ← This file
```

---

## Key Takeaways

- **Network evidence is operationally valuable because it answers urgent IR questions.** Exfiltration, C2, lateral movement, and blocking are the questions that drive action.
- **The same observation can support multiple use cases.** A long-lived outbound session may matter for C2, exfiltration review, and blocking at the same time.
- **Strong indicators are not always final proof.** Large transfers, repeated beaconing, or internal admin-protocol traffic still require disciplined interpretation.
- **Blocking decisions need both evidence and caution.** Good containment is evidence-based and business-aware.
- **Correlation is what makes network use cases defensible.** Host, memory, proxy, VPN, and application context often determine whether a suspicious pattern is incident-relevant.

---

**Next:** Lab 8.3 — Capture and IR-Focused Analysis

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
