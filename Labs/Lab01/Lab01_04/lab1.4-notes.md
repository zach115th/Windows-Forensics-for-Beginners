# Lab 1.4 — Analyst Notes
**Standing Up a Windows IR Lab**  
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Analyst:** ___________________________  
**Date Started:** ___________________________  
**Date Completed:** ___________________________  
**Host OS:** ___________________________  
**Hypervisor:** ___________________________  

---

## Task 1 — VM Configuration

> Document your VM settings completely. These details matter if you need to rebuild or share your environment.
VM Name:
Hostname:
OS Version:
Hypervisor:
Hypervisor Version:
RAM Allocated:
vCPUs:
Primary Disk Size:
Network Mode:
Local Accounts:
Timezone:
Notes:
---

## Task 2 — Network Mode Decision

> Document your network mode choice and the reasoning behind it.
Network Mode Selected:
Internet Access:               [Yes / No]
Reason for Choice:
Safety Tradeoffs Accepted:
Planned Changes During Labs:
Notes:
---

## Task 3 — Secondary Disk Configuration

> Record the secondary disk details. Drive letter E: is recommended for consistency across labs.
Secondary Disk File Name:
Disk Format:
Disk Size:
Drive Letter:
Volume Label:
Intended Purpose:
Notes:
---

## Task 4 — Sample User Data

> Record what you added to the VM and where. Be specific — you'll be hunting for these artifacts in later labs.

**Files created:**
File Types Added:
Locations Used:
Desktop:
Documents:
Downloads:
E:\Temp:
E:\Exports:
**Actions taken to generate artifacts:**
Files Opened:
Applications Used:
PowerShell Commands Run:
Browser Activity:        [Yes / No — note sites visited if applicable]
Notes:
---

## Task 5 — Tool Installation Record

> Record the version of every tool installed. Tool output can differ between versions.

| Tool | Source | Version Installed | Install Date | Notes |
|---|---|---|---|---|
| EZ Tools Suite | ericzimmerman.github.io | | | |
| MFTECmd | Included in EZ Tools | | | |
| Registry Explorer | Included in EZ Tools | | | |
| EvtxECmd | Included in EZ Tools | | | |
| PECmd | Included in EZ Tools | | | |
| LECmd | Included in EZ Tools | | | |
| JLECmd | Included in EZ Tools | | | |
| SBECmd | Included in EZ Tools | | | |
| Timeline Explorer | Included in EZ Tools | | | |
| FTK Imager | exterro.com | | | |
| Autopsy | autopsy.com | | | |
| 7-Zip | 7-zip.org | | | |
| Sysinternals Suite | learn.microsoft.com/sysinternals | | | |
| Notepad++ | notepad-plus-plus.org | | | |
| DB Browser for SQLite | sqlitebrowser.org | | | |

**Tool installation path:**
C:\Tools\
---

## Task 6 — Baseline State Documentation

> Record the clean state of the VM before any simulated attacker activity. This is your reference point for all future labs.
Hostname:
Windows Version:
Build Number:
System Timezone:
Current Date/Time (UTC):
Local User Accounts:
Snapshot Name:           Baseline-Clean
Snapshot Taken (UTC):
Installed Tools:
Audit Policy Status:
PowerShell Logging:      [Enabled / Disabled]
Notes:
**PowerShell output** *(paste here or reference saved file)*:
Saved to: E:\Exports\baseline_[date].txt
[Or paste Get-ComputerInfo / Get-LocalUser / Get-Process output here]
---

## Task 7 — Lab Folder Structure

> Record the root path of your lab folder on the host machine.
Lab Root Path:
Host OS:
Notes:
**Folder structure confirmed:**
[ ] WindowsForensicsLab
[ ] Lab01
[ ] Lab01\Lab1.1
[ ] Lab01\Lab1.2
[ ] Lab01\Lab1.3
[ ] Lab01\Lab1.4
[ ] Lab02
[ ] Lab03
[ ] Evidence
[ ] Tools
[ ] Templates\
---

## Task 8 — Lab Readiness Assessment

> Write 1–2 paragraphs answering: Is the lab ready? What are its current limitations? What would you improve? What risks exist if this VM touched a production network?
[Your response here]
---

## Optional Enhancement Notes

> Document any optional enhancements you completed.

**A — Multiple user accounts**
Accounts Created:
Actions Taken:
Artifacts Expected:
Notes:
**B — Audit policy configuration**
Categories Enabled:
Method Used:         [Group Policy / auditpol]
Verified Working:    [Yes / No]
Notes:
**C — PowerShell logging**
Script Block Logging:  [Enabled / Disabled]
Module Logging:        [Enabled / Disabled]
Verified Working:      [Yes / No]
Test Script Run:
Notes:
**D — Simulated removable media**
Device Type:         [USB / Virtual removable disk]
Files Copied:
Ejected and Reconnected: [Yes / No]
Artifacts Expected:  [USBSTOR registry, shellbags, LNK files]
Notes:
**E — Second VM**
Second VM Name:
OS Version:
Network Mode:
Purpose:
Notes:
---

## Additional Notes

> Use this space for anything that came up during the lab — hardware limitations, configuration decisions, things to revisit, or ideas for improving your environment.
[Free text]
---

*Lab 1.4 Notes — Windows Forensics for Beginners*  
*Keep this file in your `Labs/Lab01/Lab01_04/` folder alongside the `ReadMe.md`.*
