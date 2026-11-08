# Lab 05 — Analyst Notes
**Windows Registry and Cloud Storage Forensics**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Lab Environment:** ___________________________  
**Case Reference:** IR-2024-HRLT12  

---

## Task 1 — Identify the Core Windows Registry Hives for IR

> Fill in the table below. Focus on what each hive helps you answer in an incident, not only on formal definitions.

| Hive | Scope | Typical Path | Why It Matters in IR |
|---|---|---|---|
| **SYSTEM** | | | |
| **SOFTWARE** | | | |
| **SAM** | | | |
| **SECURITY** | | | |
| **NTUSER.DAT** | | | |
| **USRCLASS.DAT** | | | |

**1. Why do responders need both system hives and user hives?**
```
[Your response here]
```

**2. Why is NTUSER.DAT often more useful for user activity questions than SOFTWARE?**
```
[Your response here]
```

**3. Why should you care about hive provenance and the user profile path from which a hive was taken?**
```
[Your response here]
```

---

## Task 2 — Hunt for Persistence and Suspicious Startup Configuration

> List the Registry locations you would check first for persistence on HR-LT12. Add at least five more locations of your own beyond the seeded rows.

| Registry Path or Area | Why It Matters | What a Suspicious Finding Might Look Like |
|---|---|---|
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | | |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | | |
| `HKLM\SYSTEM\CurrentControlSet\Services` | | |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce` | | |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` | | |
| | | |
| | | |
| | | |
| | | |
| | | |

**1. Why is a startup entry in a user hive often important even if nothing appears in system-wide autoruns?**
```
[Your response here]
```

**2. Why does path context matter when judging whether a Run key value is suspicious?**
```
[Your response here]
```

**3. Why should you avoid assuming every unusual startup entry is malicious?**
```
[Your response here]
```

---

## Task 3 — Investigate USB and Removable Device History

> Identify the Registry areas you would review first for USB / removable-media questions. Add at least four more areas or supporting artifacts of your own.

| Registry Path or Area | What It May Reveal | Why It Matters |
|---|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` | | |
| Mounted devices / volume mapping areas | | |
| Device class / storage-related keys | | |
| User shell or folder-history areas | | |
| | | |
| | | |
| | | |
| | | |

**1. Why is USB vendor/model/serial data useful in an investigation?**
```
[Your response here]
```

**2. Why is device presence not the same as proof that files were copied?**
```
[Your response here]
```

**3. What artifacts would you want to correlate with USB history to strengthen a data-transfer theory?**
```
[Your response here]
```

---

## Task 4 — Review Remote Access and User Activity Clues

> Identify Registry areas relevant to remote access, user behavior, and possible lateral activity. Add at least five more areas of your own.

| Registry Path or Area | What It Helps Answer | Why It Matters in IR |
|---|---|---|
| RDP-related configuration keys | | |
| UserAssist | | |
| Typed paths / Explorer history areas | | |
| Shell-related history or shellbags-related areas | | |
| RecentDocs-related areas | | |
| | | |
| | | |
| | | |
| | | |
| | | |

**1. Why is UserAssist useful even though it reflects GUI-driven activity rather than everything that ran on the system?**
```
[Your response here]
```

**2. Why can typed paths and Explorer history matter in a staging or exfiltration investigation?**
```
[Your response here]
```

**3. Why should remote-access configuration findings be correlated with logs rather than treated as proof of connection by themselves?**
```
[Your response here]
```

---

## Task 5 — Identify Cloud Sync Client Evidence

> Identify the local evidence sources you would want to examine for OneDrive / cloud-sync questions on HR-LT12. Add at least five more sources of your own.

| Artifact Source | What It May Reveal | Why It Matters |
|---|---|---|
| Registry keys related to OneDrive or sync configuration | | |
| Local sync root folder | | |
| Client logs | | |
| Local databases or configuration files | | |
| User profile directories tied to sync activity | | |
| | | |
| | | |
| | | |
| | | |
| | | |

**1. Why is local cloud-client configuration often important even if you do not yet have provider-side logs?**
```
[Your response here]
```

**2. Why do account identifiers and sync-root paths matter?**
```
[Your response here]
```

**3. Why should a responder distinguish "cloud client installed" from "files actually synchronized"?**
```
[Your response here]
```

---

## Task 6 — Correlate Registry and Cloud Findings into Investigative Questions

> Write at least ten specific investigative questions you want the Registry and cloud-storage artifacts to answer for HR-LT12.

1. 
2. 
3. 
4. 
5. 
6. 
7. 
8. 
9. 
10. 

**Question grouping:**

| Category | Question Numbers |
|---|---|
| Persistence | |
| Removable media | |
| User activity / execution | |
| Remote access | |
| Cloud sync / data movement | |

**Five-question artifact mapping:**

| Question | Primary Artifact Source | Secondary / Corroborating Artifact |
|---|---|---|
| | | |
| | | |
| | | |
| | | |
| | | |

---

## Task 7 — Separate Strong Registry Findings from Overclaims

> Classify each statement as: Strongly supported / Suggested but needs corroboration / Not supported by these artifacts alone.

| Statement | Classification | Why |
|---|---|---|
| A OneDrive-related configuration key exists for the user profile | | |
| Sensitive files were exfiltrated to a threat actor-controlled cloud account | | |
| A USB storage device with a specific vendor and serial was connected to the host | | |
| Files were definitely copied to that USB device | | |
| A suspicious executable path is referenced in a Run key | | |
| The executable ran successfully at every logon | | |
| UserAssist shows the user likely interacted with a program through the GUI | | |
| The user intentionally used OneDrive to steal data | | |

**Four additional statements of your own:**

| Statement | Classification | Why |
|---|---|---|
| | | |
| | | |
| | | |
| | | |

---

## Task 8 — Build a Registry and Cloud Correlation Timeline

> Create a mini-timeline with at least ten entries if possible.

| Time (UTC) | Artifact Source | Event or Observation | Key / Path / Artifact | Why It Matters |
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

**1. Why is a timeline more useful than isolated key findings?**
```
[Your response here]
```

**2. Which events in your timeline appear most central to the case theory?**
```
[Your response here]
```

**3. What additional artifact types outside the Registry would you want next?**
```
[Your response here]
```

---

## Task 9 — Write a Registry and Cloud Findings Summary

> Write a 3–5 paragraph analyst summary describing what your Registry and cloud-storage review indicates about HR-LT12. Cover the most important Registry findings, evidence suggestive of persistence/removable media/remote access/cloud sync, what is strongly supported, what still requires corroboration, and what you recommend reviewing next. Write it as a working-note summary, not a final incident report.

```
[Your Registry and cloud findings summary here — 3 to 5 paragraphs]
```

---

## Task 10 — Write an Analyst Handoff Note

> Summarize the most important follow-up items for another responder. Make it easy for another responder to continue the investigation without reconstructing your logic from scratch.

```
Case Reference:       IR-2024-HRLT12
Author:
Date/Time (UTC):

Most Important Registry Findings:
- 

Most Important Cloud-Related Findings:
- 

What Is Strongly Supported:
- 

What Still Needs Corroboration:
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

## Task 11 — Reflection

**1. Why the Registry matters in IR**
*Why is the Registry often one of the most valuable evidence sources even when the suspicious file is gone?*
```
[Your response here]
```

---

**2. Configuration versus action**
*Why should responders distinguish between evidence that something was configured and evidence that it was actually used?*
```
[Your response here]
```

---

**3. Cloud sync versus exfiltration**
*Why is local evidence of OneDrive or another sync client useful, but not by itself proof of malicious data exfiltration?*
```
[Your response here]
```

---

**4. Correlation over certainty**
*Why are Registry findings strongest when paired with NTFS, logs, execution artifacts, and user-activity evidence?*
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

*Lab 05 Notes — Windows Forensics for Beginners*  
*Keep this file in your `Labs/Lab05/` folder alongside the `ReadMe.md`.*
