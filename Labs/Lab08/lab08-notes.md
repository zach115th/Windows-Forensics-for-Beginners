# Lab 08 — Analyst Notes
**Network Forensics on Windows**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Lab Environment:** ___________________________  
**Case Reference:** IR-2024-FINWS23  

---

## Task 1 — Sources of Network Evidence

> Fill in the table. Then answer the three short-response questions below.

| Evidence Source | What It Is | What It Helps Answer | Limitation |
|---|---|---|---|
| Packet captures | | | |
| Flow logs | | | |
| Windows ETL traces | | | |
| Application logs | | | |

**1. Why are packet captures usually richer than flow logs?**

```
[Your response here]
```

**2. Why are flow logs still useful even when you do not have full packet data?**

```
[Your response here]
```

**3. Why are application logs often necessary to understand user or service context?**

```
[Your response here]
```

---

## Task 2 — Map Network Evidence to Key IR Questions

> For each question, identify the best evidence source(s) to check first.
> Then add at least six additional questions of your own.

| Investigative Question | Best Evidence Source(s) to Check First | Why |
|---|---|---|
| Was data likely transferred off the host? | | |
| Which remote IP did the host communicate with? | | |
| Did the host maintain a long-lived outbound connection? | | |
| Did the host communicate with unusual internal systems? | | |
| What content was transferred over a session, if recoverable? | | |
| Which domain or service should we consider blocking? | | |
| | | |
| | | |
| | | |
| | | |
| | | |
| | | |

**1. Why is "best source" sometimes different for visibility versus proof?**

```
[Your response here]
```

**2. Why do some network questions require multiple sources rather than one?**

```
[Your response here]
```

**3. Why is a host-focused question often incomplete without network timing?**

```
[Your response here]
```

---

## Task 3 — Generate Controlled Traffic in the Lab

> Document the traffic you generated during the activity window.
> Include at least three additional activities of your own.

| Activity | Source Host | Destination | Approximate Time (UTC) | Why You Included It |
|---|---|---|---|---|
| Web browsing | | | | |
| Connection to test server | | | | |
| | | | | |
| | | | | |
| | | | | |

**1. Why is it useful to generate both normal and suspicious traffic in a lab?**

```
[Your response here]
```

**2. Why should you record the approximate times of your actions?**

```
[Your response here]
```

**3. Why does a known-good ground truth help when learning packet analysis?**

```
[Your response here]
```

---

## Task 4 — Capture the Traffic

> Record details about the capture used for analysis.

| Field | Value |
|---|---|
| Capture tool | |
| Capture location (host / monitoring VM / sensor) | |
| Source host under review | |
| Capture file name | |
| Capture start time (UTC) | |
| Capture end time (UTC) | |
| Notes / warnings | |

**1. Why does capture location matter?**

```
[Your response here]
```

**2. Why should you record capture start and end times carefully?**

```
[Your response here]
```

**3. Why can a host capture and a SPAN/sensor capture produce different visibility?**

```
[Your response here]
```

---

## Task 5 — Filter by Host and Time Window

> Record the filters and methods you used to narrow the capture.

| Filter Goal | Filter or Method Used | Why It Matters |
|---|---|---|
| Narrow to source host | | |
| Narrow to time window | | |
| Narrow to suspicious destination(s) | | |
| Narrow to unusual port(s) | | |

**1. Why is narrowing by host and time window one of the most important first steps?**

```
[Your response here]
```

**2. Why can an unfiltered packet capture hide the important activity in noise?**

```
[Your response here]
```

**3. Why should your notes record the exact filtering logic you used?**

```
[Your response here]
```

---

## Task 6 — Identify Interesting Streams

> Record at least six streams or connection patterns worth noting.

| Stream / Connection | Why It Stands Out | What It Might Suggest | What It Does Not Prove |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |

**1. Why do long-lived connections often deserve attention in C2 cases?**

```
[Your response here]
```

**2. Why can large transfers matter in exfiltration review?**

```
[Your response here]
```

**3. Why is an unusual port only a lead, not a conclusion?**

```
[Your response here]
```

---

## Task 7 — Reconstruct Content or Session Context

> Record what you recovered or observed via Follow Stream / Export Objects / protocol dissection.

| Stream | Reconstruction Method | What You Recovered or Observed | Why It Matters | Limitation |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

**1. Why is stream following useful in IR-focused packet review?**

```
[Your response here]
```

**2. Why is reconstructing content not always possible or appropriate?**

```
[Your response here]
```

**3. Why should responders document both what they recovered and what they could not recover?**

```
[Your response here]
```

---

## Task 8 — Map the Network Activity to Likely Host Context

> Identify the host artifacts you would want next to map traffic to a process, user, or action.

| Network Finding | Best Host Artifact(s) to Correlate Next | Why |
|---|---|---|
| Suspicious outbound connection | | |
| Large transfer to test server | | |
| Browser traffic to a suspicious site | | |
| Connection on an unusual port | | |
| Repeated internal host-to-host session | | |

**1. Why is packet data often stronger when paired with process or memory evidence?**

```
[Your response here]
```

**2. Why is browser history useful when packet data suggests web access?**

```
[Your response here]
```

**3. Why is process-to-connection mapping often critical before briefing leadership?**

```
[Your response here]
```

---

## Task 9 — Build a Timeline Snippet

> Include at least eight entries where possible.

| Time (UTC) | Source | Destination | Activity | Why It Matters |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

**1. Why is a timeline snippet more useful than a loose list of packet observations?**

```
[Your response here]
```

**2. Which entries appear most central to the attacker-activity theory?**

```
[Your response here]
```

**3. What additional host or log artifacts would make the timeline stronger?**

```
[Your response here]
```

---

## Task 10 — Separate Strong Support from Overclaims

> Classify each statement: Strongly supported / Suggested but needs corroboration / Not supported by this evidence alone.
> Then add six additional statements of your own.

| Statement | Classification | Why |
|---|---|---|
| The host connected to a suspicious test server during the 15-minute window | | |
| A long-lived outbound session occurred during the capture window | | |
| The attacker definitely exfiltrated sensitive data | | |
| A large transfer to an unusual destination deserves deeper review | | |
| The observed IP is part of attacker-controlled infrastructure | | |
| The connection pattern is consistent with possible beaconing | | |
| This IP or domain may be a candidate for temporary blocking | | |
| The observed session was initiated intentionally by the user | | |
| | | |
| | | |
| | | |
| | | |
| | | |
| | | |

---

## Task 11 — Network Findings Summary

> 3–5 paragraphs. Working-note summary, not a final incident conclusion.
> Cover the most important streams, what the evidence suggests (normal browsing, suspicious external contact, large transfer, internal movement), what content you reconstructed, what is strongly supported, and what still needs host/memory/flow/application correlation.

```
[Paragraph 1 — most important connections or streams identified]
```

```
[Paragraph 2 — what the evidence suggests about activity]
```

```
[Paragraph 3 — content or session context reconstructed]
```

```
[Paragraph 4 — what is strongly supported by the evidence]
```

```
[Paragraph 5 — what still requires correlation with host, memory, flow, or application logs]
```

---

## Task 12 — Analyst Handoff Note

> Use the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Most Important Network Findings:
- 

Most Important Streams / Destinations:
- 

What Is Strongly Supported:
- 

What Is Suggested but Not Confirmed:
- 

Recommended Next Artifacts:
1.
2.
3.

Open Questions:
- 

Notes for Incoming Analyst:
```

---

## Task 13 — Reflection

**1. Why network evidence matters**
*Why is network evidence often one of the fastest ways to understand attacker scope and behavior?*

```
[Your response here]
```

---

**2. Content versus pattern**
*Why can session patterns, duration, and transfer size matter even when you cannot reconstruct full content?*

```
[Your response here]
```

---

**3. Correlation is essential**
*Why should packet findings usually be paired with host, memory, or application-log evidence before drawing stronger conclusions?*

```
[Your response here]
```

---

**4. Blocking decisions and caution**
*Why should responders be careful before recommending blocks based only on a single suspicious connection?*

```
[Your response here]
```

---

## Additional Notes

> Use this space for anything that came up during the lab — questions, observations, connections to real incidents, things to follow up on, or ideas for improving your process.

```
[Free text]
```

---

*Lab 08 Notes — Windows Forensics for Beginners*
*Keep this file in your `Labs/Lab08/` folder alongside the `ReadMe.md`.*
