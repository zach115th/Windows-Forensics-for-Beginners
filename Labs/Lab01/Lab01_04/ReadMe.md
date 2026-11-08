# Lab 1.4 — Standing Up a Windows IR Lab

**Supporting Section 1.4: Standing Up a Windows IR Lab**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Every lab in this book depends on a safe, controlled Windows environment. Before you parse an MFT, carve memory, or analyze registry hives, you need a place where you can generate artifacts intentionally, test tools without consequences, and make mistakes without affecting anything real.

This lab builds that foundation. The goal is a practical, repeatable Windows VM setup you can rely on for every exercise that follows, not a complex enterprise simulation. A well-built lab makes forensic learning faster. A poorly built one creates friction at exactly the wrong moment.

By the end of this lab you will have a documented, isolated Windows environment with a clean baseline snapshot, a secondary evidence disk, and a folder structure that keeps your work organized across every future lab.

---

## Learning Objectives

By completing this lab, you will be able to:

- Deploy a Windows 10 or 11 VM suitable for IR practice
- Make and document a defensible network isolation decision
- Add and configure a secondary virtual disk for evidence and artifact work
- Populate the VM with realistic sample data that will generate useful artifacts in later labs
- Document a clean system baseline before generating any suspicious activity
- Organize lab materials in a repeatable, consistent folder structure
- Assess the readiness and limitations of your lab environment

---

## Estimated Time

30–60 minutes (longer if downloading Windows media for the first time)

---

## Prerequisites

**Host system requirements:**
- Virtualization-capable CPU (Intel VT-x or AMD-V enabled in BIOS)
- Minimum 8 GB RAM (4 GB allocated to VM, rest for host). 16 GB is comfortable and lets you give the VM 8 GB
- Minimum 100 GB free disk space (VM + secondary disk + snapshots)

**Hypervisor — choose one:**

| Hypervisor | Notes |
|---|---|
| VMware Workstation Pro | Best snapshot and network flexibility; now free for personal use |
| VirtualBox | Free, cross-platform, good for most lab use |
| Hyper-V | Built into Windows 10/11 Pro and Enterprise; no download required |

**Windows media:**
- Windows 10 or 11 ISO — evaluation copies are available free from Microsoft's evaluation center
- A product key is not required for lab use; evaluation installations run for 90 days

**Tools to install inside the VM** (covered in Task 5):
- PowerShell (built in)
- 7-Zip
- Sysinternals Suite
- EZ Tools (Eric Zimmerman's forensic tools)
- FTK Imager

---

## Lab Tasks

---

### Task 1 — Build the Windows VM

**Objective:** Create a functional Windows VM with documented, reproducible configuration.

Create a new VM using your chosen hypervisor with the following minimum specifications:

| Setting | Recommended Value |
|---|---|
| RAM | 4 GB minimum, 8 GB preferred |
| CPUs | 2 vCPUs |
| Primary disk | 60 GB (dynamically allocated is fine) |
| OS | Windows 10 or Windows 11 (any edition) |
| Network | Host-Only (configure in Task 2) |

After installation completes:

1. Set the computer hostname to something memorable and lab-specific, such as `DFIR-LAB-01`. Avoid generic names such as `DESKTOP-ABC123`, because you'll be referencing this hostname in artifact analysis throughout the book.
2. Create a standard local user account named `labuser` in addition to the default administrator account. Having two accounts generates richer artifacts in later labs.
3. Set the system timezone to UTC. Consistent timestamps across your lab environment will matter when you start building timelines.

Document your configuration in `lab1.4-notes.md`:

```
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
```

---

### Task 2 — Choose and Document Your Network Mode

**Objective:** Make a deliberate, documented network isolation decision.

Network configuration is a safety and realism tradeoff. Review the options below and choose the one that fits your goals, then document your reasoning.

| Mode | Internet Access | Host Access | VM-to-VM | Best For |
|---|---|---|---|---|
| **No network** | No | No | No | Maximum isolation; simplest |
| **Host-Only** | No | Yes | Yes (same host) | Recommended default for this book |
| **NAT** | Yes (via host) | Limited | No | Tool downloads, then switch to Host-Only |
| **Internal Network** | No | No | Yes | Multi-VM lab scenarios |
| **Bridged** | Yes (direct) | Yes | Yes | Realistic simulation; highest risk |

**Recommendation for this book:** Start with **Host-Only**. It lets your host and VM communicate without exposing the VM to the internet or your production network, which is useful for copying files and tools.

If you need internet access to download tools, temporarily switch to NAT, complete your downloads, then switch back to Host-Only before generating any artifacts.

Document your decision:

```
Network Mode Selected:  
Internet Access:        [Yes / No]
Reason for Choice:      
Safety Tradeoffs Accepted:  
```

---

### Task 3 — Add a Secondary Virtual Disk

**Objective:** Attach a secondary disk that will serve as your evidence and artifact workspace throughout the book.

Add a second virtual disk to your VM with these settings:

| Setting | Value |
|---|---|
| Size | 20–40 GB |
| Format | VMDK (VMware), VHD/VHDX (Hyper-V), VDI (VirtualBox) |
| Allocation | Dynamically allocated |

After adding the disk, boot the VM and complete setup:

1. Open **Disk Management** (`diskmgmt.msc`)
2. Initialize the new disk (MBR is fine for lab use)
3. Create a simple volume and format as **NTFS**
4. Assign drive letter **E:** (keeps it consistent across labs)
5. Label the volume `EVIDENCE`

Document the disk:

```
Secondary Disk File Name:   
Disk Format:                
Disk Size:                  
Drive Letter:               E:
Volume Label:               EVIDENCE
Intended Purpose:           
```

> **Why a separate disk?** Keeping evidence and artifacts on a separate virtual disk makes it easier to snapshot, export, attach to analysis VMs, and keep isolated from your primary OS disk. This mirrors how real IR triage collections are packaged.

---

### Task 4 — Populate the VM with Sample User Data

**Objective:** Generate realistic artifacts that later labs will analyze.

The files you add now will create LNK files, jump list entries, Prefetch records, MFT entries, and USN Journal activity — the exact artifacts you'll be learning to parse in later chapters.

Perform the following actions inside the VM as `labuser`:

**1. Create a realistic file set**

Place files in the following locations. Mix file types, because the variety matters for artifact generation.

| Location | Files to Create |
|---|---|
| `Desktop` | A shortcut, a `.txt` file, a `.ps1` script |
| `Documents` | A `.docx`, a `.xlsx`, a subfolder with more files |
| `Downloads` | A `.zip` archive, a renamed executable (e.g., copy `notepad.exe` → `update_v2.exe`) |
| `E:\Temp` | A folder of mixed files simulating a staging directory |
| `E:\Exports` | An empty folder — you'll fill this in later labs |

**2. Open some of the files**

Open at least five of the files you created using different applications. This generates UserAssist entries, jump list activity, and LNK files. The more varied the activity, the richer the artifact set.

**3. Run a few PowerShell commands**

Open PowerShell as `labuser` and run a few benign commands. This generates PowerShell operational log entries you'll analyze later:

```powershell
Get-Process
Get-NetTCPConnection
whoami /all
Get-ChildItem C:\Users\labuser\Documents
```

**4. Browse the web briefly** *(only if using NAT mode)*

If your VM has internet access, visit a few sites and run a search. Then switch back to Host-Only mode. This generates browser history artifacts.

Document what you did:

```
File Types Added:     
Locations Used:       
Files Opened:         
PowerShell Commands Run: 
Browser Activity:     [Yes / No]
Notes:                
```

---

### Task 5 — Install Forensic Tools

**Objective:** Set up the tools you will use throughout the book.

Install the following inside the VM. Record the version of each. Tool output can differ between versions, and version documentation is part of forensic methodology.

| Tool | Source | Purpose | Version Installed |
|---|---|---|---|
| **Eric Zimmerman tool suite** | ericzimmerman.github.io | NTFS / registry / shell / log parsers (MFTECmd, EvtxECmd, RECmd, Registry Explorer, PECmd, LECmd, JLECmd, SBECmd, AmcacheParser, Timeline Explorer) | |
| **FTK Imager** | exterro.com/digital-forensics-software/ftk-imager | Disk and memory imaging, hash verification, image preview | |
| **KAPE** | kroll.com/.../kroll-artifact-parser-extractor-kape | Triage collection + chained parsing (free for individual / non-commercial use) | |
| **Hayabusa** | github.com/Yamato-Security/hayabusa | Sigma-rule-based EVTX threat hunting with MITRE ATT&CK mapping | |
| **Volatility 3** | volatilityfoundation.org | Plugin-driven memory image analysis | |
| **MemProcFS** | github.com/ufrisk/MemProcFS | Memory image mounted as virtual file system; navigation-friendly exploratory analysis (install alongside Volatility 3 — they complement each other) | |
| **Arsenal Image Mounter** | arsenalrecon.com/downloads | Mount E01 / VHDX / raw images as physical disks | |
| **Cyber Triage** *(optional)* | cybertriage.com/download-eval | Guided IR triage tool, free evaluation tier | |
| **Autopsy** | autopsy.com | Full-image deep-dive forensic suite | |
| **Wireshark** | wireshark.org | Packet capture analysis | |
| **7-Zip** | 7-zip.org | Archive handling | |
| **Sysinternals Suite** | learn.microsoft.com/sysinternals | Process Explorer, Autoruns, Sysmon, etc. | |
| **Notepad++** | notepad-plus-plus.org | Text editor with regex search | |
| **DB Browser for SQLite** | sqlitebrowser.org | Browser history / OneDrive sync DB analysis | |

> **Alternative environment:** the [SANS SIFT Workstation](https://www.sans.org/tools/sift-workstation) is a free Ubuntu-based VM appliance pre-loaded with Sleuth Kit, Volatility, Plaso, Autopsy, RegRipper, and most of the Linux-side tooling this book references. A second VM running SIFT alongside your Windows lab VM gives you a Linux analysis host without leaving the lab environment. See **Appendix D — Tooling Reference for Windows IR** for the full annotated list and where each tool fits in the workflow.

Create a folder at `C:\Tools\` and extract or install tools there. Keep tool installers in `C:\Tools\_Installers\` so you can rebuild quickly if needed.

---

### Task 6 — Document the Baseline State

**Objective:** Record the clean state of the VM before you introduce any simulated attacker activity.

This baseline is your reference point. When you start generating suspicious artifacts in later labs, you'll compare against it to understand what changed.

Collect and record the following inside the VM:

**System information** (run in PowerShell):
```powershell
# System info
Get-ComputerInfo | Select-Object CsName, WindowsProductName, WindowsVersion, OsArchitecture, TimeZone

# Local users
Get-LocalUser | Select-Object Name, Enabled, LastLogon

# Running processes
Get-Process | Select-Object Name, Id, Path | Sort-Object Name

# Installed software
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName
```

Save the output to `E:\Exports\baseline_[date].txt`.

**Manual records:**

```
Hostname:                
Windows Version:         
Build Number:            
System Timezone:         
Current Date/Time (UTC): 
Local User Accounts:     
Snapshot Name:           Baseline-Clean
Snapshot Taken:          [Date/Time UTC]
Installed Tools:         
Audit Policy Status:     [Run: auditpol /get /category:* ]
PowerShell Logging:      [Enabled / Disabled]
Notes:                   
```

After completing this step, take a **snapshot** and name it `Baseline-Clean`. You will revert to this snapshot at the start of labs that require a clean system state.

---

### Task 7 — Set Up Your Lab Folder Structure

**Objective:** Create a consistent, repeatable organization system for all lab materials.

On your **host machine**, create the following folder structure. This is where you'll store notes, exports, tool output, and evidence files across every lab in the book.

```
WindowsForensicsLab\
├── Lab01\
│   ├── Lab1.1\
│   │   ├── README.md
│   │   └── lab1.1-notes.md
│   ├── Lab1.2\
│   ├── Lab1.3\
│   └── Lab1.4\
│       ├── README.md
│       ├── lab1.4-notes.md
│       └── baseline_[date].txt
├── Lab02\
├── Lab03\
├── Evidence\
│   └── [evidence files go here]
├── Tools\
│   └── [tool installers and references]
└── Templates\
    ├── CoC_Template.md
    └── analyst-note-template.md
```

Document the root path of your lab folder:

```
Lab Root Path:    
Host OS:          
Notes:            
```

---

### Task 8 — Lab Readiness Assessment

**Objective:** Honestly assess whether your lab is ready and what its limitations are.

Write 1–2 paragraphs answering:

1. Is the lab ready for the forensic exercises ahead? What would prevent you from starting Lab 2 right now?
2. What are the current limitations of your setup — in terms of realism, isolation, tool coverage, or hardware?
3. What would you improve or expand once you're further into the book?
4. What safety risks would exist if this VM were accidentally connected to a production network?

---

## Optional Enhancements

Complete any of the following to extend your lab environment:

**A — Multiple user accounts**
Create two additional local user accounts (`analyst` and `hr-user`) and log on to each briefly. This generates per-user artifacts, such as NTUSER.DAT, shellbags, and UserAssist, that make later analysis more realistic.

**B — Audit policy configuration**
Enable advanced audit logging via Group Policy or `auditpol`. Document which categories you enabled and why. This will make your Security.evtx logs far more useful.

**C — PowerShell logging**
Enable Script Block Logging and Module Logging via Group Policy. Verify they're working by running a test script and checking the PowerShell operational log.

**D — Simulated removable media**
Attach a small USB drive or create a virtual removable disk. Copy files to it, safely eject it, then reconnect. This generates the shellbag, USBSTOR registry, and LNK artifacts you'll analyze in Lab 6.

**E — Second VM**
Build a second minimal Windows VM on an internal-only network. This gives you a two-host environment for lateral movement simulation in later labs.

---

## Deliverables Checklist

Your `lab1.4-notes.md` should contain:

- [ ] **Task 1** — VM configuration record with all fields completed
- [ ] **Task 2** — Network mode selection and documented reasoning
- [ ] **Task 3** — Secondary disk configuration record
- [ ] **Task 4** — Sample data summary (file types, locations, actions taken)
- [ ] **Task 5** — Tool installation record with versions
- [ ] **Task 6** — Baseline state documentation and confirmed snapshot
- [ ] **Task 7** — Lab folder structure created and root path recorded
- [ ] **Task 8** — Lab readiness assessment (1–2 paragraphs)

---

## Files in This Folder

```
Lab01/
└── Lab01_04/
    ├── ReadMe.md        ← This file
    └── lab1.4-notes.md  ← Your working notes file
```

---

## Key Takeaways

- **A documented lab is a reproducible lab.** If you can't rebuild your environment from your notes, your notes aren't good enough.
- **Isolation protects you.** Host-Only networking prevents a misconfigured lab from touching your production environment.
- **The baseline snapshot is your safety net.** Every destructive lab exercise starts with a revert. Get in the habit now.
- **Artifacts start accumulating immediately.** Every file you open, every command you run, and every application you install leaves a trace. That's the point, and it's exactly what you'll be analyzing.
- **Tool versions matter.** Record them every time. Forensic methodology requires knowing exactly what produced your output.

---

**Next:** Lab 02 — The Forensic Investigation Process for IR

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
