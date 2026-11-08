# Lab 11 — Analyst Notes
**Forensic Challenge: Investigating Unauthorized Data Exfiltration**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Lab Environment:** ___________________________  
**Case Reference:** IR-Exfil-Capstone  
**Host Under Investigation:** ___________________________  
**User Account(s) of Interest:** ___________________________  

---

## Task 1 — Plan and Simulate the Incident

> Document the simulated actions you performed on the Windows VM. Add at least four more incident actions of your own to the table.

| Simulated Action | Approximate Time (UTC) | Why You Included It |
|---|---|---|
| Create Confidential folder | | |
| Copy files to removable media | | |
| Copy or upload files to cloud destination | | |
| Use archive tool or PowerShell | | |
| | | |
| | | |
| | | |
| | | |

**1. Why is it useful to simulate both USB and cloud pathways in the same case?**
```
[Your response here]
```

**2. Why should the scenario include some normal-looking user activity as noise?**
```
[Your response here]
```

**3. Why is realistic timing important for the later investigation?**
```
[Your response here]
```

---

## Task 2 — Preserve Evidence and Confirm Integrity

> Acquire or prepare disk image, memory image, and exported logs/artifacts. Confirm hashes and create working copies.

| Evidence Item | Original Path / Source | Hash Algorithm | Hash Value | Working Copy Created? | Notes |
|---|---|---|---|---|---|
| Disk image | | SHA-256 | | | |
| Memory image | | SHA-256 | | | |
| Event log exports | | SHA-256 | | | |
| Registry hives | | SHA-256 | | | |
| Browser artifacts | | SHA-256 | | | |

**1. Why should the original evidence be left untouched once verified?**
```
[Your response here]
```

**2. Why does hashing matter even in a training case?**
```
[Your response here]
```

**3. Why is chain-of-custody discipline still useful in internal investigations?**
```
[Your response here]
```

---

## Task 3 — Build the Initial Case Scope

> Write at least ten investigative questions you want the case to answer, then group them into categories.

| # | Investigative Question | Why It Matters |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |
| 7 | | |
| 8 | | |
| 9 | | |
| 10 | | |

**Question grouping:**

| Category | Question Numbers |
|---|---|
| User activity | |
| File staging | |
| Removable media | |
| Cloud / browser activity | |
| Timeline / sequence | |
| Memory / live-state follow-up | |

**1. Why is question definition especially important in a case with many artifact types?**
```
[Your response here]
```

**2. Why can this kind of case become unfocused without a clear question set?**
```
[Your response here]
```

**3. Why should your final report answer the same questions you started with?**
```
[Your response here]
```

---

## Task 4 — Investigate File Staging with MFT and USN

> Add at least six findings.

| File / Path | Artifact Source | Why It Matters | What It Suggests | What It Does Not Prove |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

**1. Why are archive creation and staging paths important in an exfiltration case?**
```
[Your response here]
```

**2. Why do deleted records often become more interesting in these cases?**
```
[Your response here]
```

**3. Why should file-system findings be correlated rather than treated as proof of exfiltration by themselves?**
```
[Your response here]
```

---

## Task 5 — Investigate User Access with Shell Items and Registry

> Add at least six findings.

| Finding | Source Artifact | Why It Matters | What It Suggests | Limitation |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

**1. Why is user-hive provenance especially important here?**
```
[Your response here]
```

**2. Why are folder-browsing artifacts useful even when they do not prove copying?**
```
[Your response here]
```

**3. Why do these artifacts become much stronger when timed against the staging activity?**
```
[Your response here]
```

---

## Task 6 — Confirm or Challenge USB Involvement

> Add at least six findings.

| USB-Related Finding | Source Artifact | Why It Matters | What It Suggests | What It Does Not Prove |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

**1. What evidence supports simple device recognition?**
```
[Your response here]
```

**2. What evidence supports likely browsing or file access on the device?**
```
[Your response here]
```

**3. What additional evidence would make you more confident about copying to USB?**
```
[Your response here]
```

---

## Task 7 — Investigate Cloud / Browser Exfiltration

> Add at least six findings.

| Cloud / Browser Finding | Source Artifact | Why It Matters | What It Suggests | Limitation |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

**1. Why is cloud evidence often more difficult to prove from the endpoint alone?**
```
[Your response here]
```

**2. Why do browser artifacts matter even if OneDrive or another sync client is present?**
```
[Your response here]
```

**3. What would you want from provider-side logs if this were a real enterprise case?**
```
[Your response here]
```

---

## Task 8 — Review Event Logs and Build Context

> Add at least six findings.

| Event-Log Finding | Log Source | Why It Matters | What It Suggests | Limitation |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

**1. Why do logs help anchor the case in time?**
```
[Your response here]
```

**2. Why should missing log events be interpreted carefully?**
```
[Your response here]
```

**3. Which event patterns are most valuable in a user-driven exfiltration case?**
```
[Your response here]
```

---

## Task 9 — Review Memory for In-Memory Tools or Context

> Add at least four findings or negative findings.

| Memory Finding | Why It Matters | What It Suggests | What It Does Not Prove |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |

**1. Why can memory be especially valuable if the exfiltration involved short-lived tools?**
```
[Your response here]
```

**2. Why are negative memory findings still worth documenting?**
```
[Your response here]
```

**3. Why should memory findings be correlated with disk and log artifacts rather than treated alone?**
```
[Your response here]
```

---

## Task 10 — Build the Incident Timeline

> Merge findings from earlier tasks into a focused timeline. Include at least twelve entries if possible.

| Time (UTC) | Artifact Type | Event Description | Context | Why It Matters |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

**Channel analysis — events by exfiltration path:**

| Path | Supporting Events (from timeline) | Strength |
|---|---|---|
| USB / removable media | | High / Medium / Low |
| Cloud / browser upload | | High / Medium / Low |
| Cloud sync client | | High / Medium / Low |
| Archive-and-transfer | | High / Medium / Low |
| Ambiguous / weakly supportive | | n/a |

**1. Which events are most central to the suspected exfiltration?**
```
[Your response here]
```

**2. Which events support the USB path?**
```
[Your response here]
```

**3. Which events support the cloud path?**
```
[Your response here]
```

**4. Which events are ambiguous or only weakly supportive?**
```
[Your response here]
```

---

## Task 11 — Determine What Most Likely Happened

**1. What happened?**
```
[Your response here]
```

**2. Which host and user account were involved?**
```
[Your response here]
```

**3. How did the data most likely leave the system?**
```
[Your response here]
```

**4. What evidence most strongly supports that conclusion?**
```
[Your response here]
```

**5. What alternate explanations remain possible?**
```
[Your response here]
```

**Conclusion table:**

| Conclusion | Evidence That Strongly Supports It | Evidence That Only Suggests It | Confidence |
|---|---|---|---|
| User account involved | | | High / Med / Low |
| USB involvement | | | High / Med / Low |
| Cloud involvement | | | High / Med / Low |
| Staging activity | | | High / Med / Low |
| Likely exfil path | | | High / Med / Low |

---

## Task 12 — Write the Case Summary

> Produce the 1–3 page case summary described in the chapter. Save the finished version as `case-summary.md` alongside this notes file.

**Deliverable filename:** `case-summary.md`

**Scope of the investigation:**
```
[Your response here]
```

**Main evidence sources used:**
```
[Your response here]
```

**Most important findings:**
```
[Your response here]
```

**Timeline-based narrative:**
```
[Your response here]
```

**Strength of conclusions:**
```
[Your response here]
```

**Gaps or uncertainties:**
```
[Your response here]
```

**Recommended next steps:**
```
[Your response here]
```

---

## Task 13 — Write Remediations and Control Recommendations

> Add at least eight entries.

| Recommendation | Why It Matters | Priority |
|---|---|---|
| | | |
| | | |
| | | |
| | | |
| | | |
| | | |
| | | |
| | | |

**Deliverable filename:** `recommendations.md`

**1. Why should recommendations include both immediate remediation and longer-term controls?**
```
[Your response here]
```

**2. Why do logging and artifact-collection improvements often belong in the recommendations?**
```
[Your response here]
```

**3. Why should the recommendations reflect the uncertainties of the case instead of pretending the evidence is perfect?**
```
[Your response here]
```

---

## Task 14 — Write an Analyst Handoff Note

> Save the finished version as `final-handoff.md` alongside this notes file.

**Deliverable filename:** `final-handoff.md`

```
Case Reference:
Author:
Date/Time (UTC):

Primary Question:
- 

Most Important Findings:
- 

Most Strongly Supported Conclusions:
- 

What Is Suggested but Not Fully Confirmed:
- 

Likely Exfiltration Path(s):
- 

Recommended Next Actions:
1.
2.
3.

Open Questions:
- 

Notes for Incoming Analyst:
```

---

## Task 15 — Reflection

**1. Why correlation matters most in exfiltration cases**
*Why is unauthorized-data-exfiltration work usually won or lost through cross-artifact correlation rather than one single artifact?*
```
[Your response here]
```

---

**2. USB versus cloud ambiguity**
*Why can it be difficult to distinguish between removable-media and cloud exfiltration if the endpoint evidence is incomplete?*
```
[Your response here]
```

---

**3. Case-writing discipline**
*Why is it important that the case summary separate strongly supported findings from likely but unconfirmed conclusions?*
```
[Your response here]
```

---

**4. From artifacts to decisions**
*Why should the outcome of a forensic challenge like this be not just findings, but remediation and control recommendations?*
```
[Your response here]
```

---

## Final Deliverables — File Inventory

> Confirm each finished deliverable is saved into the case folder before handoff.

| Deliverable | Filename | Status |
|---|---|---|
| Lab notes (this file) | `lab11-notes.md` | [ ] |
| Case summary | `case-summary.md` | [ ] |
| Recommendations section | `recommendations.md` | [ ] |
| Final handoff note | `final-handoff.md` | [ ] |
| Closure note | `closure-note.md` | [ ] |
| Merged timeline | `merged-timeline.csv` | [ ] |
| Hash manifest | `hashes.txt` | [ ] |

---

## Additional Notes

> Use this space for anything that came up during the lab — questions, observations, connections to real incidents, things to follow up on, or ideas for improving your process.
```
[Free text]
```

---

*Lab 11 Notes — Windows Forensics for Beginners*
*Keep this file in your `Labs/Lab11/` folder alongside the `ReadMe.md`.*
