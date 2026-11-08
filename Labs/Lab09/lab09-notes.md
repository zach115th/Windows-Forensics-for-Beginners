# Lab 09 — Analyst Notes
**Windows Event Logs**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Lab Environment:** ___________________________  
**Case Reference:** ___________________________  

---

## Task 1 — Identify the Key Log Types for IR

> Fill in the table below.

| Log Type | What It Commonly Contains | Why It Matters in IR | Limitation |
|---|---|---|---|
| Security | | | |
| System | | | |
| Application | | | |
| Microsoft-Windows-PowerShell / Operational | | | |
| Microsoft-Windows-TaskScheduler / Operational | | | |
| Microsoft-Windows-Windows Defender / Operational | | | |

> **1. Why is the Security log often the first place responders look?**

```
[Your response here]
```

> **2. Why are Operational logs often more useful than the general Application log for focused hunting?**

```
[Your response here]
```

> **3. Why should responders know which logs were enabled before trusting the absence of evidence?**

```
[Your response here]
```

---

## Task 2 — Identify the Main Challenges in Event Log Analysis

> Fill in the table below. Add at least four more challenges of your own.

| Challenge | Why It Happens | Why It Matters | How You Would Mitigate It |
|---|---|---|---|
| Volume and noise | | | |
| Retention limits / overwrite | | | |
| Time skew | | | |
| Incomplete logging configuration | | | |
| | | | |
| | | | |
| | | | |
| | | | |

> **1. Why can noisy logs be just as dangerous as missing logs?**

```
[Your response here]
```

> **2. Why is time normalization important before building timelines?**

```
[Your response here]
```

> **3. Why is "nothing suspicious in the logs" often a weaker conclusion than it sounds?**

```
[Your response here]
```

---

## Task 3 — Collect Security and PowerShell Logs

> Record your collection details below.

| Field | Value |
|---|---|
| Host / VM Name | |
| Logs Exported | |
| Export Method | |
| Output Folder | |
| Collection Date/Time (UTC) | |
| Notes / Issues | |

> **1. Why is exporting the raw `.evtx` useful even if you also parse the logs later?**

```
[Your response here]
```

> **2. Why should the source host and collection time be documented?**

```
[Your response here]
```

> **3. Why might you also want System or Task Scheduler logs in the same hunt pack?**

```
[Your response here]
```

---

## Task 4 — Define Suspicious Event Patterns

> Define at least eight suspicious or high-value patterns to hunt for. Add at least four more patterns of your own.

| Suspicious Pattern | Why It Matters | Primary Log(s) | What It Might Suggest |
|---|---|---|---|
| Multiple failed logons followed by a success | | | |
| Service installation / creation | | | |
| PowerShell execution from unusual locations | | | |
| Scheduled task creation or modification | | | |
| | | | |
| | | | |
| | | | |
| | | | |

> **1. Why should hunt-pack patterns focus on responder value rather than every possible event ID?**

```
[Your response here]
```

> **2. Why are event patterns usually stronger than single isolated events?**

```
[Your response here]
```

> **3. Why should patterns be tied to specific IR questions?**

```
[Your response here]
```

---

## Task 5 — Map Patterns to Filters or Saved Searches

> Convert suspicious patterns into reusable search logic. Add at least four more of your own.

| Suspicious Pattern | Filter / Search Definition | Tool or Platform | Why This Filter Is Useful |
|---|---|---|---|
| Multiple failed logons followed by a success | | | |
| Service installation / creation | | | |
| PowerShell execution from unusual locations | | | |
| Scheduled task creation or modification | | | |
| | | | |
| | | | |
| | | | |
| | | | |

> **1. Why is filter logic more reusable than freeform manual hunting?**

```
[Your response here]
```

> **2. Why should filters be documented in plain language as well as technical syntax?**

```
[Your response here]
```

> **3. Why is it useful to record which tool or platform each filter was designed for?**

```
[Your response here]
```

---

## Task 6 — Build the Hunt Pack Documentation File

> Document each hunt in a structured way. Use this format for at least six hunts.

**Hunt 1**

```
Hunt Name:
Purpose:
Primary Log(s):
Primary Event IDs / Patterns:
Filter Logic:
What a Positive Hit Might Mean:
Common False Positives:
Follow-Up Artifacts:
```

**Hunt 2**

```
Hunt Name:
Purpose:
Primary Log(s):
Primary Event IDs / Patterns:
Filter Logic:
What a Positive Hit Might Mean:
Common False Positives:
Follow-Up Artifacts:
```

**Hunt 3**

```
Hunt Name:
Purpose:
Primary Log(s):
Primary Event IDs / Patterns:
Filter Logic:
What a Positive Hit Might Mean:
Common False Positives:
Follow-Up Artifacts:
```

**Hunt 4**

```
Hunt Name:
Purpose:
Primary Log(s):
Primary Event IDs / Patterns:
Filter Logic:
What a Positive Hit Might Mean:
Common False Positives:
Follow-Up Artifacts:
```

**Hunt 5**

```
Hunt Name:
Purpose:
Primary Log(s):
Primary Event IDs / Patterns:
Filter Logic:
What a Positive Hit Might Mean:
Common False Positives:
Follow-Up Artifacts:
```

**Hunt 6**

```
Hunt Name:
Purpose:
Primary Log(s):
Primary Event IDs / Patterns:
Filter Logic:
What a Positive Hit Might Mean:
Common False Positives:
Follow-Up Artifacts:
```

> **1. Why is false-positive guidance important in a reusable hunt pack?**

```
[Your response here]
```

> **2. Why should follow-up artifacts be included in the documentation?**

```
[Your response here]
```

> **3. Why is this documentation as important as the filters themselves?**

```
[Your response here]
```

---

## Task 7 — Generate Test Events in the Lab

> Record at least six test events or test actions. Add at least two more actions of your own.

| Test Action | Expected Log Pattern | Approximate Time (UTC) | Which Hunt Should Catch It |
|---|---|---|---|
| Failed logon attempts | | | |
| Successful logon after failures | | | |
| Scheduled task creation | | | |
| PowerShell execution | | | |
| | | | |
| | | | |

> **1. Why is it important to test hunts against known lab actions?**

```
[Your response here]
```

> **2. Why should you record approximate timestamps of your test activity?**

```
[Your response here]
```

> **3. Why is a hunt pack incomplete if it has never been validated?**

```
[Your response here]
```

---

## Task 8 — Test and Refine the Filters

> Document the results below.

| Hunt Name | Expected Hit? | Actual Result | Adjustment Needed? | Notes |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

> **1. Why is filter tuning part of the DFIR workflow, not a sign of failure?**

```
[Your response here]
```

> **2. Why can a technically correct filter still be operationally weak?**

```
[Your response here]
```

> **3. Why should you note both successful detections and misses?**

```
[Your response here]
```

---

## Task 9 — Package the Hunt Pack for Reuse

> Record the location and structure of your reusable hunt pack folder.

```
Hunt Pack Root Path:
Created By:
Date Created (UTC):
Notes:
```

**Folder structure confirmed:**

```
Windows-EventLog-HuntPack/
├── README.md
├── hunt-pack.md
├── filters/
│   ├── security/
│   ├── powershell/
│   ├── system/
│   └── taskscheduler/
├── sample-logs/
└── test-notes/
```

> Define naming conventions.

| Item | Naming Convention | Example |
|---|---|---|
| Filter file | | |
| Hunt documentation section | | |
| Test note | | |
| Sample exported log | | |

> **1. Why is a reusable folder structure important if you want to share the hunt pack with a team?**

```
[Your response here]
```

> **2. Why should sample logs or test notes be included when possible?**

```
[Your response here]
```

> **3. Why does packaging matter almost as much as the hunt logic itself?**

```
[Your response here]
```

---

## Task 10 — Separate Strong Support from Overclaims

> Classify each statement. Then write six additional statements of your own and classify them the same way.

| Statement | Classification | Why |
|---|---|---|
| The host recorded multiple failed logons followed by a success | | |
| A service-installation-related event occurred | | |
| PowerShell activity from an unusual path deserves deeper review | | |
| The attacker definitely gained interactive control of the host | | |
| A scheduled task was created or modified | | |
| The new task was definitely used for persistence by malware | | |
| The hunt pack successfully identified suspicious patterns worth follow-up | | |
| Event logs alone prove the full scope of the incident | | |
| | | |
| | | |
| | | |
| | | |
| | | |
| | | |

---

## Task 11 — Write an Event Log Hunt Pack Summary

> Write a 3–5 paragraph analyst summary describing:
> - Which logs you collected
> - Which suspicious patterns your hunt pack focuses on
> - Which test events you generated and whether the hunts caught them
> - What the hunt pack is designed to detect well
> - What still requires other artifacts or deeper analysis

```
[Your event log hunt pack summary here — 3 to 5 paragraphs]
```

---

## Task 12 — Write an Analyst Handoff Note

> Use the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Logs Collected:
- 

Most Important Hunt Patterns:
- 

Filters That Worked Well:
- 

Filters That Need Tuning:
- 

Recommended Next Steps:
1.
2.
3.

Open Questions:
- 

Notes for Incoming Analyst:
```

---

## Task 13 — Reflection

**1. Why hunt packs matter**
*Why is a reusable hunt pack more valuable than starting from scratch in every Windows incident?*

```
[Your response here]
```

---

**2. Pattern hunting versus raw review**
*Why are event-log patterns usually more useful than isolated single-event review?*

```
[Your response here]
```

---

**3. Validation matters**
*Why should responders test their filters instead of assuming they work because the logic looks correct?*

```
[Your response here]
```

---

**4. Correlation remains essential**
*Why do event-log hits become much stronger when paired with execution artifacts, Registry data, NTFS, or network evidence?*

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

*Lab 09 Notes — Windows Forensics for Beginners*
*Keep this file in your `Labs/Lab09/` folder alongside the `ReadMe.md`.*
