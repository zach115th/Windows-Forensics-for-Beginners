# Lab 06 — Analyst Notes
**Shell Items, Removable Devices, and Application Artifacts**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Lab Environment:** ___________________________  
**Case Reference:** FIN-WS23  

---

## Task 1 — Identify Which Artifacts Answer Which Questions

> Map common IR questions to the shell and application artifacts most likely to answer them first.

| Investigative Question | Best Artifact(s) to Check First | Why |
|---|---|---|
| Was a suspicious EXE likely executed? | | |
| Did the user likely open a sensitive document? | | |
| Was a folder on removable media browsed in Explorer? | | |
| Which program opened a particular file? | | |
| Did a process use unusual network resources? | | |
| Was a specific archive or document accessed from Downloads? | | |
| Was a removable device likely involved in file staging? | | |
| Did the user interact with a suspicious program through the GUI? | | |

**Six additional questions of your own:**

| Investigative Question | Best Artifact(s) to Check First | Why |
|---|---|---|
| | | |
| | | |
| | | |
| | | |
| | | |
| | | |

**1. Why is this question-to-artifact approach better than parsing everything at once?**

```
[Your response here]
```

**2. Why do some questions require multiple artifacts rather than one?**

```
[Your response here]
```

**3. Why is "evidence of execution" different from "evidence of file presence"?**

```
[Your response here]
```

---

## Task 2 — Review LNK Files and Jump Lists

> Use shortcut and recent-item artifacts to identify likely file access and path context.

| Artifact Type | What It Can Reveal | Why It Matters | Limitation |
|---|---|---|---|
| LNK files | | | |
| Automatic Jump Lists | | | |
| Custom Jump Lists | | | |

**1. Why are LNK files useful when the original file has been deleted or moved?**

```
[Your response here]
```

**2. Why do Jump Lists help tie a file to a specific application?**

```
[Your response here]
```

**3. Why should you be careful not to overstate what a shortcut proves by itself?**

```
[Your response here]
```

**Items of interest table — add at least four more of your own:**

| Item of Interest | Path or File | Artifact Source | Why It Would Matter |
|---|---|---|---|
| Suspicious EXE in Downloads | | | |
| Sensitive document | | | |
| Removable-media path | | | |
| Network share path | | | |
| | | | |
| | | | |
| | | | |
| | | | |

---

## Task 3 — Review Prefetch and Amcache

> Identify evidence of execution and executable context.

| Artifact | What It Can Reveal | Why It Matters in IR | Limitation |
|---|---|---|---|
| Prefetch | | | |
| Amcache | | | |

**1. Why is Prefetch often one of the first artifacts responders check for execution?**

```
[Your response here]
```

**2. Why is Amcache useful even when Prefetch is unavailable or incomplete?**

```
[Your response here]
```

**3. Why should a responder avoid claiming too much from one execution artifact alone?**

```
[Your response here]
```

**Focused review table — add at least five more entries of your own:**

| Suspected Program or File | Artifact to Check | What Finding Would Increase Concern |
|---|---|---|
| `tool.exe` in Downloads | | |
| `runme.bat` in ProgramData | | |
| PowerShell | | |
| Archive extractor or scripting tool | | |
| | | |
| | | |
| | | |
| | | |
| | | |

---

## Task 4 — Review SRUM and UserAssist

> Use system resource usage and user-interaction artifacts to assess behavior.

| Artifact | What It Helps Answer | Why It Matters | Limitation |
|---|---|---|---|
| SRUM | | | |
| UserAssist | | | |

**1. Why is SRUM especially useful in exfiltration or beaconing investigations?**

```
[Your response here]
```

**2. Why is UserAssist helpful for GUI-driven user behavior but incomplete for execution analysis overall?**

```
[Your response here]
```

**3. Why might SRUM and Prefetch together be stronger than either one alone?**

```
[Your response here]
```

**Behavior-pattern table — at least six entries:**

| Behavior Pattern | Artifact(s) to Use | Why It Matters |
|---|---|---|
| Suspicious process with network usage | | |
| GUI launch of suspicious program | | |
| Unexpected resource usage by an application | | |
| | | |
| | | |
| | | |

---

## Task 5 — Review Shellbags and Folder Navigation Evidence

> Determine whether folders on local disks, removable devices, or network shares were browsed.

| Artifact | What It Can Reveal | Why It Matters | Limitation |
|---|---|---|---|
| Shellbags | | | |
| Explorer-related history | | | |
| Typed paths | | | |

**1. Why are Shellbags useful even when the underlying folder no longer exists?**

```
[Your response here]
```

**2. Why can folder-browsing evidence matter in a removable-media case?**

```
[Your response here]
```

**3. Why is browsing a folder different from proving a file was copied?**

```
[Your response here]
```

**Folders or path types — add at least six more of your own:**

| Folder or Path Type | Why It Is Relevant |
|---|---|
| USB volume path | |
| OneDrive or sync-root path | |
| Downloads | |
| Desktop | |
| | |
| | |
| | |
| | |
| | |
| | |

---

## Task 6 — Profile Removable Device Involvement

> Correlate removable-device evidence with shell and application artifacts.

| Question | Best Artifact(s) | What Would Strengthen the Theory |
|---|---|---|
| Was a USB storage device connected? | | |
| Was the device browsed in Explorer? | | |
| Were files likely opened from the device? | | |
| Were suspicious files staged near the same time? | | |
| Is there evidence consistent with file movement involving removable media? | | |

**1. Why is device connection only the starting point in a removable-media investigation?**

```
[Your response here]
```

**2. Why is correlation between device artifacts and file-access artifacts so important?**

```
[Your response here]
```

**3. What additional evidence would you want before briefing leadership that removable media was likely involved?**

```
[Your response here]
```

---

## Task 7 — Correlate Browser, Email, and Search Artifacts

> Tie document access and suspicious execution to possible delivery or user behavior.

| Artifact Source | What It May Reveal | Why It Matters |
|---|---|---|
| Browser history | | |
| Browser downloads | | |
| Email artifacts or mail client clues | | |
| Search index or related search evidence | | |
| RecentDocs / LNK correlation | | |

**Add at least five more relevant supporting artifacts or sub-artifacts of your own:**

| Artifact Source | What It May Reveal | Why It Matters |
|---|---|---|
| | | |
| | | |
| | | |
| | | |
| | | |

**1. Why can browser and email artifacts be critical in determining initial access?**

```
[Your response here]
```

**2. Why is download evidence helpful when paired with Prefetch or Jump Lists?**

```
[Your response here]
```

**3. Why should responders be cautious about assuming the user knowingly caused the event?**

```
[Your response here]
```

---

## Task 8 — Build a Behavioral Timeline

> Turn shell, application, and removable-device findings into a usable incident sequence. Aim for at least twelve entries.

| Time (UTC) | Artifact Source | Event or Observation | File / Path / Device | Why It Matters |
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

**1. Which entries appear most central to the case theory?**

```
[Your response here]
```

**2. Which entries may be supportive but not central?**

```
[Your response here]
```

**3. What gaps remain after this timeline?**

```
[Your response here]
```

---

## Task 9 — Separate Strong Support from Overclaims

> Practice reporting only what the artifacts actually support.

| Statement | Classification | Why |
|---|---|---|
| A suspicious executable likely executed on the host | | |
| The user opened a document from a removable device | | |
| The removable device was used to copy sensitive files off the system | | |
| A folder associated with a USB device was browsed in Explorer | | |
| A program showed network-usage patterns worth further review | | |
| The user intentionally exfiltrated data | | |
| A specific application likely opened a particular document | | |
| A suspicious archive in Downloads was part of the incident chain | | |

**Six additional statements of your own:**

| Statement | Classification | Why |
|---|---|---|
| | | |
| | | |
| | | |
| | | |
| | | |
| | | |

---

## Task 10 — Write a Shell and Application Artifact Summary

> Write a 3–5 paragraph analyst summary describing what the shell, removable-device, and application artifacts suggest about activity on FIN-WS23.

```
[Your shell and application artifact summary here — 3 to 5 paragraphs]
```

---

## Task 11 — Write an Analyst Handoff Note

> Make your findings easy for another responder to continue.

```
Case Reference:       FIN-WS23
Author:
Date/Time (UTC):

Most Important Shell / Application Findings:
- 

Most Important Removable-Device Findings:
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

## Task 12 — Reflection

**1. Why these artifacts matter**
*Why are shell and application artifacts so useful in incident response compared with relying only on logs or file listings?*

```
[Your response here]
```

---

**2. User interaction versus execution**
*Why is it important to distinguish between a file being present, a file being opened, and a program being executed?*

```
[Your response here]
```

---

**3. Removable-device caution**
*Why should responders avoid claiming USB exfiltration too early, even when a device and suspicious files both appear in the case?*

```
[Your response here]
```

---

**4. Correlation is the real value**
*Why are LNK, Jump Lists, Prefetch, SRUM, Shellbags, and Registry artifacts strongest when used together?*

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

*Lab 06 Notes — Windows Forensics for Beginners*
*Keep this file in your `Labs/Lab06/` folder alongside the `ReadMe.md`.*
