# Lab 3.3 — Analyst Notes
**Memory Acquisition Basics**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Lab Environment:** ___________________________  
**Case Reference:** IR-2024-WEBAPP03  

---

## Task 1 — Memory Acquisition Decision for WEB-APP-03

**Part A — Decision summary**

| Host | Recommended Action | Priority |
|---|---|---|
| WEB-APP-03 | | |

---

**Part B — Decision rationale**

**1. Which facts from the scenario most strongly support capturing memory immediately?**

```
[Your response here]
```

---

**2. What operational concerns could make memory capture harder or riskier on WEB-APP-03?**

```
[Your response here]
```

---

**3. Should memory be captured before any containment action, shutdown, or remediation step? Why?**

```
[Your response here]
```

---

**4. What single piece of new information would change your recommendation — and in which direction?**

```
[Your response here]
```

---

## Task 2 — Investigative Questions Mapped to Memory Evidence

> At least 8 questions. Each must be specific and answerable from a named memory evidence category.

| # | Investigative Question | Memory Evidence That May Help Answer It |
|---|---|---|
| 1 | Is a suspicious or unexpected process currently running on WEB-APP-03? | Active process list — name, PID, parent PID, full path |
| 2 | What command line was associated with the brief PowerShell execution? | Process memory — command-line arguments in process environment block |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |
| 7 | | |
| 8 | | |

---

## Task 3 — Memory Acquisition Workflow

**Stage 1 — Pre-Collection Checks**

> Write 6–8 steps. Cover authorization, system stability, storage readiness, tool availability,
> and whether other volatile data should be captured first.

```
1. Confirm authorization — case reference, approving manager, scope of collection
2. Confirm the host is stable enough for live collection — check for crash indicators,
   high CPU/memory load, or pending restarts
3. 
4. 
5. 
6. 
7. 
8. 
```

---

**Stage 2 — Tool Selection**

| Item | Your Choice / Notes |
|---|---|
| **Acquisition tool** | |
| **Why selected** | |
| **Output format** | |
| **Expected output size** | |
| **Destination path** | |
| **Operational concerns** | |

---

**Stage 3 — Acquisition Execution**

| Step | Action | Notes |
|---|---|---|
| 1 | Record system time (UTC) and local time before starting | Time skew matters for later correlation |
| 2 | Confirm destination path is writable and has sufficient free space | |
| 3 | Transfer acquisition tool to destination — do not run from suspect system | |
| 4 | Execute acquisition tool with administrator privileges | |
| 5 | Record exact command line used | |
| 6 | Monitor acquisition progress — note any errors or warnings | |
| 7 | Record completion time (UTC) | |
| 8 | Do not reboot or shut down host until capture is confirmed complete | |

**Exact command used:**

```
[Paste exact command here]
```

**Tool output / status messages:**

```
[Paste relevant output here]
```

---

**Stage 4 — Hashing and Integrity Recording**

```
When memory image was hashed:           
File(s) hashed:                         
Hash algorithm used:                    SHA-256
Hash record storage location:           
Why integrity matters for volatile acquisitions:
```

**Hash command used:**

```powershell
[Paste exact command here]
```

**Raw hash output:**

```
[Paste output here]
```

---

**Stage 5 — Post-Acquisition Handling**

```
Storage location for memory image:       
Working copy created:                    [Yes / No]
Original write-protected:                [Yes / No — method:]
Pagefile collected:                      [Yes / No — reason:]
Hibernation file collected:              [Yes / No — reason:]
Chain of custody updated:                [Yes / No]
Case notes updated:                      [Yes / No]
Next collection step:                    
```

---

## Task 4 — Risks and Limitations of Live Memory Collection

**Part A — Risk table**

| Risk or Limitation | Why It Matters | How You Would Mitigate or Document It |
|---|---|---|
| Live collection changes system state | | |
| Memory image can be very large | | |
| Acquisition may affect system performance | | |
| Tool may fail, hang, or crash the host | | |
| Not all memory content is interpretable | | |
| Encrypted or protected regions may limit visibility | | |
| Collection tool leaves artifacts on the system | | |

---

**Part B — Written analysis**

**1. Why is live memory collection still forensically defensible even though it changes the running system?**

```
[Your response here]
```

---

**2. Why is "we didn't want to touch the live host" not always sufficient reason to skip memory capture?**

```
[Your response here]
```

---

## Task 5 — Memory Acquisition Documentation Requirements

**Part A — Acquisition record**

> Complete every field. If unknown at time of collection, note what is unknown and when it will be resolved.

| Field | What Should Be Recorded | Why It Matters |
|---|---|---|
| Case reference | | |
| Hostname | | |
| Acquisition date/time (UTC) | | |
| Acquired by | | |
| Authorized by | | |
| Acquisition tool | | |
| Tool version | | |
| Exact command used | | |
| Output file name | | |
| Output path | | |
| Approximate file size | | |
| Hash algorithm | | |
| Hash value | | |
| System state at time of collection | | |
| Pagefile collected | | |
| Hibernation file collected | | |
| Errors or warnings | | |
| Notes / observations | | |

---

**Part B — Short answers**

**1. Why does recording the exact command used matter beyond just noting the tool name?**

```
[Your response here]
```

---

**2. Why should system state notes — active users, server load, running services — be recorded at collection time?**

```
[Your response here]
```

---

**3. Why do errors and partial failures need to be documented even if the image file was created successfully?**

```
[Your response here]
```

---

## Task 6 — Memory Collection Note

> Every field must be completed. If unknown at time of writing, note what is unknown and when it will be resolved.

```
# Memory Acquisition Note — WEB-APP-03
Case Reference:            
Author:                    
Date/Time (UTC):           

Host:                      WEB-APP-03
Reason for Memory Capture: 
Authorized By:             
System Status at Collection:

Tool Selected:             
Tool Version:              
Command Used:              
Output File Name:          
Output Destination:        
Approximate Output Size:   

Hash Algorithm:            SHA-256
Hash Value:                
Hash Verified:             [Yes / No]

Pagefile Collected:        [Yes / No — reason:]
Hibernation File Collected:[Yes / No — reason:]

Operational Considerations:
Errors / Warnings:         
Notes:                     
Next Step:                 
```

---

## Task 7 — Memory vs. Disk Prioritization

> For each scenario, state your priority decision and explain your reasoning.

| Scenario | Priority Decision | Reasoning |
|---|---|---|
| Suspected fileless malware with active outbound C2 connection still live | | |
| Low-value kiosk with malware detection, already scheduled for rebuild | | |
| High-value server with signs of short-lived PowerShell execution — no reboot yet | | |
| Workstation where primary concern is deleted attacker tools on disk | | |
| System actively crashing — may not survive a memory capture attempt | | |
| Server where attacker logged in via RDP 20 minutes ago and session may still be active | | |

---

## Task 8 — Reflection

**1. Why memory is different**
*Why does memory acquisition require faster decision-making than most disk artifact collection? What makes the window uniquely narrow?*

```
[Your response here]
```

---

**2. The cost of delay**
*What specific evidence types disappear if memory capture is delayed until after containment or reboot? Give at least two concrete examples from the WEB-APP-03 scenario.*

```
[Your response here]
```

---

**3. Documentation as protection**
*How does documenting the reason for memory capture protect you if someone later questions why you performed live collection on a production server actively serving users?*

```
[Your response here]
```

---

**4. The limits of memory alone**
*Why is a memory capture powerful but not a complete replacement for disk evidence? What categories of evidence require both sources to be fully understood?*

```
[Your response here]
```

---

## Additional Notes

```
[Free text — questions, observations, connections to real work, things to follow up on]
```

---

*Lab 3.3 Notes — Windows Forensics for Beginners*  
*Keep this file in your `Labs/Lab03/Lab03_03/` folder alongside the `ReadMe.md`.*
