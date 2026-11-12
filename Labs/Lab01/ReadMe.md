# Lab 01 — Windows Forensics Foundations

**Supporting [Chapter 1: Windows Forensics in Incident Response](../../Book/Chapter01.md)**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Before you can analyze MFT records, parse registry hives, or carve memory, you need two things: a safe place to practice and a disciplined approach to evidence handling. This lab builds both.

Lab 01 covers the foundational skills that underpin every investigation in this book. The technical work here is intentionally simple. The goal is to internalize habits that will protect you and your findings when the stakes are real.

Lab 01 is also the lab most likely to go wrong, because it is the only one that depends on your hardware. A VM that will not boot, a hypervisor fighting Hyper-V for the same CPU extensions, and Windows Defender quietly deleting your forensic tools are all normal first-day experiences. This lab covers those failures explicitly, so you spend your evening doing forensics rather than debugging virtualization.

> **If you don't have a hypervisor at all, you are not stuck.** See [Working Without a VM](#working-without-a-vm) below. Labs 04 through 12 ship pre-parsed artifact data in [`Data/`](../../Data/) and can be worked from Windows, macOS, or Linux with nothing but Python and a text editor.

---

## What This Lab Covers

This lab supports the following sections from Chapter 1:

| Section | Topic | Sub-exercise |
|---|---|---|
| 1.1 | What is Digital Forensics? | [`Lab01_01/`](Lab01_01/ReadMe.md) |
| 1.2 | Why Windows Matters in Incident Response | [`Lab01_02/`](Lab01_02/ReadMe.md) |
| 1.3 | Authorization, Legal Considerations, and Chain of Custody | [`Lab01_03/`](Lab01_03/ReadMe.md) |
| 1.4 | Standing Up a Windows IR Lab | [`Lab01_04/`](Lab01_04/ReadMe.md) |

The four sub-exercises go deeper on each section. This top-level lab is the end-to-end run: build the environment, prove it works, create an evidence item, and document it the way you would document a real one.

---

## Learning Objectives

By completing this lab, you will be able to:

- Explain the five phases of digital forensics and how IR compresses them
- Describe why Windows-specific artifacts are critical to incident scoping
- Build a functional, isolated Windows forensics lab environment
- Diagnose and resolve the common failures that stop a lab build — virtualization extensions, hypervisor conflicts, insufficient memory, Secure Boot, and antivirus quarantine
- Add an antivirus path exclusion for forensic tooling, and explain why the same action on a production host is a different decision entirely
- Verify that every installed tool actually runs, against a known input, before you depend on it
- Operate a snapshot workflow you can revert to reliably between labs
- Draft a basic evidence-handling workflow appropriate for internal review or legal scrutiny
- Compute and record SHA-256 file hashes as part of evidence documentation
- Complete a chain-of-custody record for a simulated evidence item
- Articulate authorization and collection scope considerations before taking forensic action
- Describe, in outline, the acquisition decision every one of these preparations exists to serve

---

## Estimated Time and Difficulty

**Difficulty:** Beginner

**First time through the material:** 2–3 h (add 30–60 min if you are downloading Windows media)

**Refresh (already familiar with the chapter):** 45–60 min

**Without a hypervisor (documentation path only):** 45–75 min

> **Key terms used in this lab:** evidence integrity, chain of custody, hashing, working copy, volatile evidence, triage. See the consolidated [Glossary](../../Book/Glossary.md) for definitions. The chapter cross-references in each entry take you back to the deeper coverage in `Book/`.

---

## Prerequisites

**Host machine:**

| Requirement | Minimum | Comfortable |
|---|---|---|
| CPU | 64-bit with virtualization extensions (Intel VT-x / AMD-V) **enabled in firmware** | 4+ physical cores |
| Host RAM | 8 GB (4 GB to the VM) | 16 GB (8 GB to the VM) |
| Free disk | 100 GB (60 GB primary + 20 GB evidence disk + snapshot growth) | 200 GB, ideally SSD/NVMe |
| Privileges | Local administrator on the host, to install a hypervisor | |

**Software:**

- A hypervisor — [VMware Workstation Pro](https://www.vmware.com/products/desktop-hypervisor.html) (free for personal use), [VirtualBox](https://www.virtualbox.org/), or Hyper-V (built into Windows 10/11 Pro and Enterprise)
- A Windows 10 or Windows 11 ISO — evaluation copies are available free from the Microsoft Evaluation Center and run for 90 days without a product key
- Basic familiarity with Windows administration

No prior forensics experience is required.

> **Guidance:** The 100 GB figure is not padding. A 60 GB dynamically-allocated primary disk grows toward its ceiling as you install tools and generate artifacts. The evidence disk adds 20 GB, and every snapshot you keep holds a delta on top of that. Running out of disk mid-lab corrupts snapshot chains, which is the one failure mode in this lab that can cost you real work.

---

## Working Without a VM

You can work this book without a hypervisor. Not every reader has a spare 100 GB and a virtualization-capable machine, and some readers work from a locked-down corporate laptop where installing a hypervisor is not an option.

Labs 04 through 12 each include a **Hands-On Walkthrough** backed by pre-parsed artifact data in [`Data/`](../../Data/). That data is the CSV output you would have had after running `MFTECmd`, `EvtxECmd`, `PECmd`, `RECmd`, `Volatility`, and friends against a triage collection. It is plain text, and it opens in Excel, in any text editor, or in three lines of Python, on any operating system.

**Minimum alternative setup:** Python 3.8 or later, and a text editor. Confirm it works:

```bash
python3 -c "import csv; r=list(csv.DictReader(open('Data/WKSTN-221/prefetch.csv'))); print(len(r), 'rows'); print(r[0]['ExecutableName'], r[0]['RunCount'], r[0]['LastRun'])"
```

Expected output: `20 rows`, followed by `POWERSHELL.EXE 3 2024-11-14 14:19:38.0000000`. If you see that, you can work every walkthrough in the book.

**What to do with each Lab 01 task on the no-VM path:**

| Task | With a VM | Without a VM |
|---|---|---|
| 1.1 Build the VM | Full build | **Skip.** Install what runs natively on your OS instead: Python 3, 7-Zip, [DB Browser for SQLite](https://sqlitebrowser.org/), a text editor with regex search, and [Volatility 3](https://www.volatilityfoundation.org/) |
| 1.2 Evidence disk | Second virtual disk, populated | **Substitute.** Create an archive of `Data/WKSTN-221/` and treat that archive as your evidence item |
| 1.3 Hash the evidence | Unchanged | **Unchanged.** `sha256sum`, `shasum -a 256`, or `Get-FileHash` — all fine |
| 1.4 Chain of custody | Unchanged | **Unchanged.** This is a paperwork discipline, not a technical one |
| 1.5 Authorization reflection | Unchanged | **Unchanged** |
| 1.6 Smoke test | Full toolchain | **Reduced.** Verify Python, Volatility 3 (`vol -h`), and CSV reading. Record versions the same way |
| 1.7 Snapshot discipline | Hypervisor snapshots | **Read it, then substitute.** Keep `Data/` read-only and always work on copies — the same lesson, enforced by file permissions instead of snapshots |

**What you give up.** Be honest with yourself about these costs:

- You will not generate your own artifacts, so you will not see the direct link between an action you took and the record it left. That link is the single most useful intuition in this field.
- You will not practice **live acquisition** with FTK Imager, WinPmem, or KAPE against a running host. That is the part of the job with the highest consequence for getting it wrong.
- You will not capture memory, so Lab 07's Volatility work is done against supplied plugin output rather than an image you took.
- You will not experience your own tooling changing the evidence under you, which is the lesson Chapter 3 spends a section on.

Labs 01, 02, and 03 are workbook-style and unaffected. Labs 04 through 12 all have backing data, and Lab 13 works from their output. If you later get access to a hypervisor, come back and do Tasks 1.1, 1.2, 1.6, and 1.7 properly. They will take an evening, and they are worth it.

---

## Scenario

You've just joined an IR team, and your first assignment is preparation, not a breach. Your manager wants confirmation that the team has a safe, documented environment for practicing forensics and a repeatable evidence-handling process before the next real incident lands.

Your job: build the lab, prove the toolchain works, create a simulated evidence item, and document everything as if legal or a regulator were going to review it.

> **IR Reality Check:** Build days exist so that incident days are boring. You should not discover that your copy of MFTECmd is missing its .NET runtime at 02:00, with an executive waiting on a scope answer. Teams get caught out by this more often than they admit.

---

## Background: The Decision This Lab Exists to Serve

All this preparation is *for* one decision, and you should know it on day one.

Every artifact chapter in this book eventually funnels into one moment: there is a machine in front of you, the clock is running, and you have to decide what to take off it and in what order. Chapter 3 §3.7 develops that as a full **acquisition decision tree**. Here is the beginner's version:

```
                    Machine in front of you
                              │
        ┌─────────────────────┴─────────────────────┐
        │                                           │
   POWERED OFF                                 POWERED ON
        │                                           │
   DO NOT POWER IT ON                    ┌──────────┴──────────┐
        │                                │                     │
   Encrypted? Find the key first.    No admin              Admin rights
        │                                │                     │
   Image with forensic boot media    User-context     1. CAPTURE MEMORY FIRST
   or a write-blocker                triage + EDR.    2. Triage collection (KAPE)
        │                            Document the     3. Full disk image — only if
   Collect hiberfil.sys,             constraint.         triage left the question
   pagefile.sys, swapfile.sys                            unanswered
```

Two branches cost you evidence permanently if you get them wrong: the two in capitals.

**Never power on a machine you were handed powered off.** `RunOnce` keys fire and delete themselves, Prefetch and Amcache take new writes, and timestamps move.

**On a live host, capture memory before anything else.** Memory is not the most valuable artifact, but it is the only one where *your own actions* are the main threat to it.

Now map this lab onto that tree:

| What you build in Lab 01 | What it becomes on the tree |
|---|---|
| The VM | The machine in front of you — the safe version |
| The secondary evidence disk (Task 1.2) | The thing you image |
| The SHA-256 hash (Task 1.3) | What makes the image defensible |
| The chain-of-custody record (Task 1.4) | What makes it survive review |
| The authorization reflection (Task 1.5) | The check that happens *before* you reach the tree at all |
| The toolchain and smoke test (Task 1.6) | Steps 1–3 of the right-hand branch |
| Snapshot discipline (Task 1.7) | Working-copy discipline — Chapter 3 §3.2.5 |

You do not need to understand the tree in depth yet. Read it, keep it in the back of your mind, and come back to Chapter 3 §3.7 when you get there.

---

## Lab Tasks

---

### Task 1.1 — Build a Windows Forensics VM

**Objective:** Create an isolated Windows environment for safe forensic practice.

1. Install your hypervisor of choice and create a new VM with the following minimum specs:
   - 2 vCPUs, 4 GB RAM (8 GB preferred), 60 GB primary disk
   - Windows 10 or 11 (any edition)
2. Set the network adapter to **Host-Only** to prevent the VM from reaching the internet during labs. If you need internet access to download tools, switch temporarily to NAT, finish your downloads, then switch back before generating any artifacts.
3. Set the hostname to something lab-specific, such as `DFIR-LAB-01` rather than `DESKTOP-ABC123`. You will be reading this hostname out of artifacts for the rest of the book. Create a standard user named `labuser` alongside the administrator, and set the system timezone to **UTC**.
4. Take a **snapshot** immediately, before installing anything, and name it `OS-Only`. `Baseline-Clean` comes later, once the tools are installed and the evidence disk holds sample activity. Task 1.7 explains why.
5. Install the following free tools inside the VM. You'll use them throughout the book:

| Tool | Purpose |
|---|---|
| [Eric Zimmerman tool suite](https://ericzimmerman.github.io/) | NTFS / registry / shell / log parsers (MFTECmd, EvtxECmd, RECmd, Registry Explorer, PECmd, LECmd, JLECmd, SBECmd, AmcacheParser, Timeline Explorer) |
| [FTK Imager](https://www.exterro.com/digital-forensics-software/ftk-imager) | Disk and memory imaging, hash verification, image preview |
| [KAPE](https://www.kroll.com/en/services/cyber/incident-response/kroll-artifact-parser-extractor-kape) | Triage collection + chained parsing (free for individual / non-commercial use) |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) | Sigma-rule-based EVTX threat hunting, MITRE ATT&CK mapping |
| [Volatility 3](https://www.volatilityfoundation.org/) | Plugin-driven memory image analysis |
| [MemProcFS](https://github.com/ufrisk/MemProcFS) | Memory image as virtual file system (install alongside Volatility 3 — they complement each other) |
| [Arsenal Image Mounter](https://arsenalrecon.com/downloads/) | Mount E01 / VHDX / raw images as physical disks |
| [Autopsy](https://www.autopsy.com/) | Full-image deep-dive forensic suite |
| [Wireshark](https://www.wireshark.org/) | Packet capture analysis |
| [Sysinternals Suite](https://learn.microsoft.com/sysinternals) | Process Explorer, Autoruns, Sysmon, etc. |
| [7-Zip](https://www.7-zip.org/) | Archive handling |
| [Notepad++](https://notepad-plus-plus.org/) | Text editor with regex search |
| [DB Browser for SQLite](https://sqlitebrowser.org/) | Browser history / OneDrive sync DB analysis |

Extract or install everything under `C:\Tools\`, and keep the installers in `C:\Tools\_Installers\` so you can rebuild the environment quickly.

This is the full working set the book assumes you have. **[Lab 01.4](Lab01_04/ReadMe.md) Task 5** walks through installing each one and capturing the version for your tool-checklist. [Appendix D](../../Book/AppendixD.md) gives a paragraph on each tool: what it does, its license, and where it fits in the IR workflow.

> **Note:** Keep a record of each tool version you install in [`tool-checklist.md`](tool-checklist.md). Tool output can differ between versions, and version documentation is part of good forensic practice.

> **If any of this fails:** it probably will, at least once. See [Troubleshooting Your Lab Build](#troubleshooting-your-lab-build) below for symptom-to-fix guidance, and [Antivirus Exclusions, Done Safely](#antivirus-exclusions-done-safely) if your EZ Tools or KAPE files disappear after extraction. That is Defender doing its job, and it is expected.

> **Optional but recommended — Linux companion VM (SANS SIFT Workstation).** Several tools the book references are Linux-native or work most naturally on Linux: [Plaso / log2timeline](https://github.com/log2timeline/plaso) (super-timeline generation), `fls` and `mmls` from [The Sleuth Kit](https://www.sleuthkit.org/), [Volatility 3](https://www.volatilityfoundation.org/) plugins that target Linux memory artifacts, [RegRipper](https://github.com/keydet89/RegRipper3.0) variants, and most community DFIR write-ups that assume an Ubuntu host.
>
> The simplest way to get all of these without curating them by hand is to stand up a second VM running the [**SANS SIFT Workstation**](https://www.sans.org/tools/sift-workstation). SIFT is a free Ubuntu-based VM appliance pre-loaded with Sleuth Kit, Volatility 2 + 3, Plaso, Autopsy, RegRipper, and dozens of smaller utilities. To run it alongside the Windows VM:
>
> 1. Download the SIFT VMware/VirtualBox appliance from `sans.org/tools/sift-workstation` (free, SANS account required).
> 2. Import the appliance into the same hypervisor.
> 3. Configure the network adapter to **Host-Only** to match your Windows lab VM, so the two can share evidence files over a private network without reaching the internet.
> 4. Take a snapshot named `Baseline-Clean` once the appliance is updated.
> 5. Optionally share an evidence folder between host and SIFT using a shared-folder mount, so the same MFT/EVTX/memory image you analyze on Windows is reachable from Linux too.
>
> A second VM is optional. You can complete every lab in this book end-to-end on the Windows VM alone. But once you want to run Plaso, follow a SANS course exercise, or compare a Linux-tool result against a Windows-tool result on the same artifact, the SIFT VM saves an afternoon of dependency hunting. See **[Appendix D §D.11](../../Book/AppendixD.md)** for the full annotated entry.

---

### Task 1.2 — Create a Simulated Evidence Disk

**Objective:** Generate a controlled evidence item that you will hash and document.

1. In your hypervisor, add a **second virtual disk** to your VM: 40 GB, dynamically allocated, stored as a single file. [Appendix H](../../Book/AppendixH.md) has the steps for VMware Workstation Pro, VirtualBox, Hyper-V, UTM and Parallels Desktop.
2. Boot the VM and initialize the disk in Disk Management (`diskmgmt.msc`). Format it as NTFS, assign drive letter **`E:`**, and label the volume `EVIDENCE`. Appendix H §H.6 walks through each dialog and gives a PowerShell equivalent.
3. Populate the disk with realistic-looking sample data:
   - A few `.docx` and `.xlsx` files
   - A folder of images
   - A PowerShell script (`.ps1`)
   - A subfolder named `Temp` containing a renamed executable, such as `notepad.exe` renamed to `update.exe`
4. **Open several of the files** using different applications, and run a couple of PowerShell commands. This activity makes the disk interesting later. You are generating LNK files, jump lists, Prefetch records, UserAssist entries, and USN Journal activity that Labs 04 through 06 will teach you to read.
5. Safely eject or unmount the disk, then shut down the VM cleanly.
6. On your **host machine**, locate the virtual disk file: `.vmdk`, `.vdi`, `.vhdx`, `.qcow2` or `.hds`. Appendix H §H.7 shows where each hypervisor keeps it.

> **Why this matters:** the renamed executable in `E:\Temp` is not decoration. In Lab 04 you will find it in the MFT with a `.exe` header and an innocuous name. In Lab 06 you will find the LNK file that proves someone opened it. Planting it now, deliberately, means you know the ground truth when you later have to prove it from artifacts alone. That is how you learn to trust an artifact — by testing it against something you already know.

---

### Task 1.3 — Hash the Evidence

**Objective:** Compute a cryptographic hash of your evidence item and record it.

On your host machine, compute a SHA-256 hash of the virtual disk file.

**PowerShell (Windows host):**
```powershell
Get-FileHash -Algorithm SHA256 "C:\Path\To\Your\evidence-disk.vmdk"
```

**Linux host:**
```bash
sha256sum /path/to/evidence-disk.vmdk
```

**macOS host:**
```bash
shasum -a 256 /path/to/evidence-disk.qcow2
```

Shut the VM down before you hash. A running VM keeps writing to the file. On Parallels Desktop, hash the `.hds` file inside the disk's `.hdd` folder, as Appendix H §H.7 explains.

Record the hash value. You will use it in Task 1.4.

Then do it a second time, deliberately, and confirm the two values match. This feels pointless the first time, but it is the whole discipline in miniature: a hash you computed once is a claim, and a hash you verified is evidence.

Record the following alongside the value, because a bare hash with no context answers no questions later:

```
File Path:          
File Size (bytes):  
Algorithm:          SHA-256
Hash Value:         
Computed By:        
Date/Time (UTC):    
Tool + Version:     (e.g., PowerShell 5.1 Get-FileHash / coreutils 9.4 sha256sum)
Verified (2nd run): [Yes / No]  Match: [Yes / No]
```

> **Why this matters:** If the hash of your evidence file changes between now and when you analyze it, something went wrong: accidental writes, file corruption, or worse. The hash is your proof that the evidence hasn't changed.

> **Guidance:** MD5 and SHA-1 still appear in forensic tooling and in older case files, and you will encounter both. They remain adequate for detecting accidental corruption, but both are broken against deliberate collision attacks. Use SHA-256 as your default for anything you might have to defend, and record which algorithm you used every time. Chapter 1 §1.3.4 covers the reasoning.

---

### Task 1.4 — Complete a Chain-of-Custody Record

**Objective:** Document your evidence item using the provided template.

Open [`CoC_Template.md`](CoC_Template.md) from this folder and complete one entry for the virtual disk you created in Task 1.2. Fill in every field, and leave nothing blank.

If a field doesn't apply, write `N/A` and explain why. Blank fields in a real CoC form raise questions.

**Fields to complete:**

| Field | Description |
|---|---|
| Evidence ID | Assign a unique identifier (e.g., `LAB01-001`) |
| Description | What is this item? |
| Source System | Hostname, VM name, or device description |
| Date/Time Acquired | When you created and hashed the disk |
| Acquired By | Your name or initials |
| Hash Algorithm | SHA-256 |
| Hash Value | The value from Task 1.3 |
| Storage Location | Where the file is stored now |
| Notes | Anything relevant to the handling of this item |

Then exercise the rest of the template, because a chain of custody is a *log*, not a form you fill in once:

- Add a **handling entry** for the moment you computed the hash.
- Add a **transfer entry** simulating a handoff to a colleague. Even if the colleague is fictional, practice recording who, when, why, and in what condition.
- Add a **verification entry** re-hashing the file after the simulated transfer, and record whether the value still matches.

> **Why this matters:** the question a chain of custody answers is not "who owns this file" but "can anyone demonstrate that this file was altered while in our care, and if so, when and by whom." A record with one entry cannot answer that. A record with a gap in the middle answers it badly. Chapter 1 §1.3.3 covers the full argument.

---

### Task 1.5 — Authorization and Scope Reflection

**Objective:** Practice thinking about authorization before taking forensic action — a habit that protects you in real incidents.

Answer the following questions in [`reflection.md`](reflection.md) (3–5 sentences each):

1. **Authorization:** In a real incident, what would you need before imaging a Windows workstation? Who has authority to grant it in your organization (or a hypothetical one)?

2. **Scope creep:** You're collecting event logs from a compromised server and you notice the logs also contain personal employee data. What should you do? Who should you tell?

3. **Chain of custody:** Why does chain of custody matter if your organization has no plans to involve law enforcement? Give at least two reasons.

4. **The 2 a.m. problem:** You get a call that a server is actively being used by an attacker. The security director tells you to "just image everything and sort it out later." What's right about that instinct, and what's risky about it?

5. **The exclusion you just added:** In Task 1.1 you added an antivirus exclusion for `C:\Tools\` on your lab VM. Describe the approval path you would need before doing the same thing on a production server, and name one person or team who would need to know about it.

---

### Task 1.6 — Smoke-Test the Toolchain

**Objective:** Prove that every tool you installed actually runs, against a known input, before you depend on it.

Installing a tool and running a tool are different things. A missing .NET runtime, a quarantined binary, a Python that never made it onto `PATH`, or a Hayabusa rule set that was never downloaded all look identical to a successful install until the moment you need output. Find those failures now. A 10-minute smoke test turns each one from an incident-day surprise into a build-day chore.

**Step 1 — Create a known file.** Inside the VM:

```powershell
New-Item -ItemType Directory -Path E:\SmokeTest -Force | Out-Null
"Windows Forensics for Beginners - smoke test" | Out-File E:\SmokeTest\known.txt -Encoding utf8
Get-FileHash -Algorithm SHA256 E:\SmokeTest\known.txt
```

You now have a file whose name, contents, and creation time you know exactly. Every check below either finds it or produces output you can sanity-check against something you already know.

**Step 2 — Collect the locked artifacts with KAPE.** Windows keeps the registry hives and `$MFT` open while it runs, so neither `copy` nor Explorer can read them. KAPE reads them straight from the NTFS volume instead. Open an administrator PowerShell prompt and run two collections:

```powershell
cd C:\Tools\KAPE
.\kape.exe --tsource C: --tdest E:\SmokeTest\kape\system --target RegistryHivesSystem
.\kape.exe --tsource E: --tdest E:\SmokeTest\kape\evidence --target '$MFT'
```

The first run copies the `SYSTEM`, `SOFTWARE`, `SAM` and `SECURITY` hives along with their `.LOG1` and `.LOG2` transaction logs. The second copies the `$MFT` of `E:`, the volume that holds `known.txt`. Keep the single quotes around `'$MFT'`: without them PowerShell reads `$MFT` as an empty variable, and KAPE receives no target name.

KAPE rebuilds each file's source path under the destination, with the drive letter as the first folder. `SOFTWARE` therefore lands at `E:\SmokeTest\kape\system\C\Windows\System32\config\SOFTWARE`, and `$MFT` at `E:\SmokeTest\kape\evidence\E\$MFT`. Each run also writes a copy log, a CSV in the destination folder that records every file KAPE copied.

> **Why not `reg save`?** `reg save` asks the registry to write a fresh copy of a hive. That copy omits the deleted keys and values still sitting in the original file's free space. It also leaves out the `.LOG1` and `.LOG2` transaction logs. Nor can it reach hives that Windows has not loaded under `HKLM` or `HKU`, such as `Amcache.hve` or a logged-off user's `NTUSER.DAT`. KAPE copies the original bytes, so the deleted records and the logs come with them. Registry Explorer and RECmd use those logs to replay changes Windows had not yet written into the hive.

**Step 3 — Parse the collection with KAPE modules.** KAPE modules run the parsers for you against what the targets collected. A module expects its parser in KAPE's `Modules\bin` folder, so copy two tools there first:

- `MFTECmd.exe` into `C:\Tools\KAPE\Modules\bin\`
- the whole `RECmd` folder, which includes its `BatchExamples` subfolder, into `C:\Tools\KAPE\Modules\bin\RECmd\`

Then run both modules in one pass:

```powershell
.\kape.exe --msource E:\SmokeTest\kape --mdest E:\SmokeTest\kape-out --module 'MFTECmd_$MFT,RECmd_SoftwareASEPs'
```

`MFTECmd_$MFT` parses the collected `$MFT`. `RECmd_SoftwareASEPs` runs RECmd's batch file of `SOFTWARE`-hive autostart keys, including the `Run` key, across the collected hives. KAPE writes each module's CSV output into a folder named for its category, `FileSystem` or `Registry`, under `E:\SmokeTest\kape-out\`.

> **If you cannot use KAPE.** Downloading KAPE requires a free registration with Kroll. Using it to deliver services to a client requires a paid license, as Appendix D §D.3 explains. FTK Imager does the same collection by hand. For the hives, choose **File → Obtain Protected Files**, select **Password recovery and all registry files**, and save to `E:\SmokeTest\ftk\`. For `$MFT`, choose **File → Add Evidence Item → Logical Drive → `E:`**, expand `[root]`, right-click `$MFT` and select **Export Files** to the same folder. If Registry Explorer later reports that a hive is dirty, export that hive's `.LOG1` and `.LOG2` files from `C:\Windows\System32\config\` the same way. Then point the commands in Step 4 at `E:\SmokeTest\ftk\` instead of the KAPE paths, and skip the two KAPE rows.

**Step 4 — Run each tool once and record the result.** Run the commands from the same administrator PowerShell prompt. The single quotes again keep `$MFT` in the paths literal.

| # | Tool | Invocation | Passes if |
|---|---|---|---|
| 1 | KAPE targets | The two collections in Step 2 | Both destinations hold a copy log, and `E:\SmokeTest\kape\evidence\E\$MFT` is larger than zero bytes |
| 2 | KAPE modules | The module run in Step 3 | `E:\SmokeTest\kape-out\FileSystem\` holds an MFTECmd CSV with a row for `known.txt`, and `Registry\` holds a RECmd CSV |
| 3 | MFTECmd | `MFTECmd.exe -f 'E:\SmokeTest\kape\evidence\E\$MFT' --csv E:\SmokeTest\out` | CSV written, and it contains a row for `known.txt` |
| 4 | EvtxECmd | `EvtxECmd.exe -f C:\Windows\System32\winevt\Logs\System.evtx --csv E:\SmokeTest\out` | CSV written with more than zero event rows |
| 5 | PECmd | `PECmd.exe -d C:\Windows\Prefetch --csv E:\SmokeTest\out` | CSV includes an entry for a tool you ran in the last hour |
| 6 | RECmd | `RECmd.exe -f E:\SmokeTest\kape\system\C\Windows\System32\config\SOFTWARE --kn "Microsoft\Windows\CurrentVersion\Run"` | Run-key values printed |
| 7 | Timeline Explorer | Open the MFTECmd CSV from row 3 | Grid loads, and you can filter to `known.txt` |
| 8 | Registry Explorer | Open `E:\SmokeTest\kape\system\C\Windows\System32\config\SYSTEM` | Hive loads. If it reports a dirty hive, let it replay the `.LOG1` and `.LOG2` files KAPE collected beside it |
| 9 | FTK Imager | **File → Add Evidence Item → Logical Drive → `E:`** | `[root]\SmokeTest\known.txt` appears in the evidence tree |
| 10 | Volatility 3 | `vol -h` (or `python vol.py -h`) | Plugin list prints without a traceback |
| 11 | Hayabusa | `hayabusa.exe update-rules` then `hayabusa.exe csv-timeline -d C:\Windows\System32\winevt\Logs -o E:\SmokeTest\hayabusa.csv` | Rules update (needs NAT briefly) and a CSV is produced |
| 12 | 7-Zip / Notepad++ / DB Browser | Open any file of the right type | Application launches and displays content |
| 13 | Autopsy | Create a case, add `E:` as a logical drive | Ingest completes and the file tree shows `SmokeTest\known.txt` |

Collecting locked files with a triage tool is itself the lesson. Lab 03 applies the same KAPE approach to a live host, and Lab 02's collection plan names KAPE targets for the same reason.

**Step 5 — Record it.** For every tool, fill in the version column in [`tool-checklist.md`](tool-checklist.md), and note anything that needed a workaround in that file's Update Log. If a tool failed, work the [Troubleshooting](#troubleshooting-your-lab-build) table before moving on.

```
Smoke Test Date (UTC):     
Tools Tested:              ___ of ___
Tools Passing:             
Tools Failing (and why):   
Workarounds Applied:       
```

---

### Task 1.7 — Establish Snapshot Discipline

**Objective:** Build a snapshot workflow you can actually revert to, and understand why that habit maps onto real evidence handling.

A snapshot you never tested is not a safety net. It is a belief about a safety net. Set up the workflow and then prove it works.

**Step 1 — Take the standard set.** Three snapshots carry you through the whole book:

| Snapshot name | Take it when | What it contains | Revert to it when |
|---|---|---|---|
| `OS-Only` | After OS install, UTC timezone, `labuser` created — **before any tools** | Nothing but Windows | You need a genuinely pristine host, or you want to rebuild the tool set from scratch |
| `Baseline-Clean` | After Task 1.6's smoke test passes | Windows + `C:\Tools\` + the AV exclusion + the `E:` evidence disk | **Your working default.** Most labs start here |
| `Lab01-Complete` | End of this lab | The above + sample data + your Task 1.2 evidence disk | You want the artifact-rich state Labs 04–06 read from |

`Baseline-Clean` follows Chapter 1 §1.4.7. Take it only once the VM is configured, the evidence disk holds sample activity, and the tools are installed. Later labs revert to it, so it has to contain all three.

Beyond those three, take a `LabNN-Pre` snapshot before any lab that writes to the guest, and a `LabNN-Complete` at the end of any lab whose state you want to keep.

**Step 2 — Name them like an analyst, not like a user.** `Snapshot 3` tells you nothing three weeks later. Use `<state>-<qualifier>` and write a one-line description in the hypervisor's description field: what is installed, what has been run, and what the known-good condition is.

**Step 3 — Decide powered-on or powered-off, deliberately.**

- A **powered-off** snapshot is smaller, faster to take, and reverts cleanly. Use it for the three standard snapshots above.
- A **powered-on** (live) snapshot also captures the VM's RAM. That is a larger file, but it is useful later. A live snapshot's memory file is a real memory image you can point Volatility 3 at in Lab 07 without acquiring one from inside the guest.

**Step 4 — Test the revert, now, before you need it.** This is the part people skip:

1. With `Baseline-Clean` taken, create a junk file: `New-Item C:\revert-test.txt`.
2. Revert to `Baseline-Clean`.
3. Confirm `C:\revert-test.txt` is gone and `C:\Tools\` is intact.

If that drill does not behave exactly as described, fix it now. A revert that silently fails is worse than no snapshot at all, because you will trust it.

**Step 5 — Prune.** Long snapshot chains slow guest disk I/O measurably and consume space unpredictably. Keep `OS-Only`, `Baseline-Clean`, the current lab's snapshot, and nothing else. Never delete `Baseline-Clean`.

Record your snapshot inventory:

| Snapshot Name | Date/Time (UTC) | Powered On? | Size | Description |
|---|---|---|---|---|
| `OS-Only` | | | | |
| `Baseline-Clean` | | | | |
| `Lab01-Complete` | | | | |

> **Why this matters:** the habit you are building is not "use snapshots." It is *never do irreversible work on the only copy of something*. In this lab the stakes are an evening of rebuilding. On a real case, the same instinct keeps you working on a verified working copy rather than the original image (Chapter 3 §3.2.5). A habit of making changes to a machine you cannot roll back eventually becomes a change to evidence you cannot undo.

---

## Troubleshooting Your Lab Build

Almost every lab build hits at least one of these. None of them mean you did anything wrong.

| Symptom | Likely cause | Fix |
|---|---|---|
| VM won't start: *"VT-x/AMD-V is not available"* or *"hardware acceleration is disabled"* | Virtualization extensions disabled in firmware — the default on many OEM machines | Reboot into BIOS/UEFI, enable **Intel VT-x / VTx** or **AMD-V / SVM Mode**. Some firmware needs a full power-off (not a warm reboot) before the change takes effect |
| VirtualBox or VMware crawls, or refuses to start, on a Windows host | Hyper-V has claimed the CPU extensions. WSL2, Docker Desktop, Windows Sandbox, Memory Integrity, and Credential Guard all silently enable it | Either use Hyper-V as your hypervisor, or turn it off: uninstall the *Hyper-V*, *Virtual Machine Platform*, and *Windows Hypervisor Platform* Windows features, disable Memory Integrity in Windows Security → Device Security, run `bcdedit /set hypervisorlaunchtype off`, and reboot. Recent VMware and VirtualBox builds can coexist with Hyper-V but at a real performance cost |
| Cloud VM: *"this platform does not support nested virtualization"* | Most standard cloud instance types do not expose VT-x to guests | Use a nested-virtualization-capable or bare-metal instance type, or take the [no-VM path](#working-without-a-vm). Do not spend an afternoon fighting this — the pre-parsed data path is a legitimate way to work the book |
| Host swaps constantly; VM freezes or the host becomes unusable | RAM oversubscribed — you gave the VM more than the host can spare | Drop the VM to 4 GB, close browsers and Teams/Slack on the host. A host with 8 GB total should not allocate more than 4 GB to a guest |
| Windows 11 install refuses: *"This PC can't run Windows 11"* | Windows 11 requires TPM 2.0 and Secure Boot; the VM has neither by default | Enable **vTPM** and **Secure Boot** in the VM's settings (all three major hypervisors support both), or install Windows 10 instead — every lab in this book works on Windows 10 |
| Arsenal Image Mounter, WinPmem, or Sysmon fail to load a driver | Secure Boot is blocking an unsigned or revoked kernel driver | Use the vendor's current signed release. If a tool genuinely needs it, disable Secure Boot **in the lab VM only** — never as a habit on your host, and document that you did it |
| EZ Tools, KAPE, or Hayabusa files vanish after extraction; the folder is smaller than the archive | Windows Defender real-time protection quarantined them. These are dual-use tools and the detection is not a false positive in the usual sense | See [Antivirus Exclusions, Done Safely](#antivirus-exclusions-done-safely) below. Do **not** simply disable real-time protection wholesale |
| `MFTECmd.exe` exits instantly, or *"You must install .NET to run this application"* | The .NET runtime the tool was built against is missing | Install the .NET Desktop Runtime version named in the tool's release notes. EZ Tools ship separate .NET 6 and .NET 9 builds — download the one matching a runtime you have, or install the runtime |
| `vol` / `vol.py` — *"python is not recognized"* | Python missing, or installed without being added to `PATH` | Install Python 3.8+ from python.org and tick **Add python.exe to PATH**. Verify with `python --version` in a *new* shell |
| Snapshot fails: *"not enough space"* or the VM refuses to resume | Snapshot deltas have filled the host disk | Free host disk, delete stale snapshots (keep `Baseline-Clean`), and never let the host drop below ~15% free while a VM is running |
| No **Host-Only** adapter option | The hypervisor's host-only network has not been created | VirtualBox: *File → Tools → Network Manager → Create*. VMware: *Edit → Virtual Network Editor*. Hyper-V: *Virtual Switch Manager → New → Internal* |
| Copy/paste and drag-drop from host to guest don't work | Guest Additions / VMware Tools not installed | Install them — but note that doing so installs drivers and services inside the guest, which changes your baseline. Install them **before** taking `Baseline-Clean`, not after |
| Hayabusa `update-rules` fails; Autopsy can't download modules | The VM is on Host-Only and has no internet, as designed | Switch to NAT, complete the download, switch back to Host-Only. Record the window in your notes — anything the VM did with internet access is a change to your baseline |

> **Guidance:** When something here costs you more than 30 minutes, write down what you tried and move on to the next task. Lab 01 is not a virtualization course. Tasks 1.3, 1.4, and 1.5 are the parts that make you a better responder, and they need no VM at all.

---

## Antivirus Exclusions, Done Safely

Windows Defender will quarantine forensic tools. It is the single most common Lab 01 failure, it happens silently, and it is worth understanding rather than working around blindly.

**Why it happens.** [Eric Zimmerman's tools](https://ericzimmerman.github.io/), [KAPE](https://www.kroll.com/en/services/cyber/incident-response/kroll-artifact-parser-extractor-kape), [Hayabusa](https://github.com/Yamato-Security/hayabusa), and several Sysinternals binaries (`PsExec` above all) do things that malware also does: read raw volumes, parse credential-bearing hives, execute remotely, dump memory. Defender's detection is not really a false positive. It is a correct observation about a dual-use capability, made without knowing who is holding the tool.

**Fixing it on your lab VM.** From an administrator PowerShell prompt inside the VM:

```powershell
# Add the exclusion
Add-MpPreference -ExclusionPath 'C:\Tools\'

# Confirm it took effect
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath

# Restore anything already quarantined, then re-extract the archives
Start-Process "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -ArgumentList '-Restore -All' -Wait
```

Add the exclusion **before** you extract the tool archives, because restoring from quarantine is fiddlier than never being quarantined. If you later want the VM back to a stock posture:

```powershell
Remove-MpPreference -ExclusionPath 'C:\Tools\'
```

Record the exclusion in the Update Log of [`tool-checklist.md`](tool-checklist.md). It is a deliberate change to your environment, and your environment is part of your methodology.

**Why doing this on a production host is a different decision entirely.**

An exclusion is not a temporary suppression. It is a durable configuration change that lives in the registry at `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`, survives reboots, and creates a directory where nothing will ever be scanned again. On a machine you own and have isolated, that is a reasonable trade. On a production host, and especially on a host under investigation, it is a different action with different consequences:

- It is a **change-controlled action**. It needs an approval path, a named approver, and a documented rollback. In most organizations, the endpoint security team owns that decision, not the responder.
- It **degrades detection on a live asset** for as long as it remains in place, and exclusions have a way of outliving the reason they were added.
- It **contaminates the host you are investigating.** You have modified the configuration of a system whose configuration is evidence.
- Most importantly: **attackers do exactly this.** Adding an exclusion for the directory you are about to stage tooling in is a standard step in a human-operated intrusion. `Book/AppendixG.md` §G.7.4 covers it. In the appendix's phrase, a Defender exclusion path matching the directory an attacker later used is *"close to a confession."* The registry key carries a `LastWriteTime`, which dates the change.

The practical rules that follow from this:

1. Exclusions belong in your **lab**, not on hosts under investigation.
2. When you find an unexpected exclusion on a host you are investigating, treat it as a **finding**, not a nuisance. Note the path, note the key's `LastWriteTime`, and check what was later written to that directory.
3. If operational necessity forces an exclusion on a production host during a response, record who approved it, when it was added, and when it was removed — and expect to be asked about it.

> **Why this matters:** you are about to make a configuration change that you would write up as an indicator of compromise if someone else made it on a different machine. Understanding *why* the same technical action is benign in one context and damning in another is most of what separates a responder from a tool operator. Lab 09 offers Defender exclusions as a hunt-pack pattern, keyed on Defender event 5007 (configuration changed). Lab 12 has you reading this same `Exclusions\Paths` key on a ransomware-hit file server, and you will recognize its shape when you get there.

---

## Deliverables Checklist

When you complete this lab, you should have:

- [ ] **Task 1.1** — A running Windows forensics VM, Host-Only, UTC, with `C:\Tools\` populated and an `OS-Only` snapshot
- [ ] **Task 1.2** — A secondary `E:` virtual disk populated with simulated evidence, including the renamed executable in `E:\Temp`
- [ ] **Task 1.3** — A SHA-256 hash of the virtual disk file, computed twice, with the full hash record block filled in
- [ ] **Task 1.4** — A completed `CoC_Template.md` with all fields filled in, plus handling, transfer, and verification entries
- [ ] **Task 1.5** — A `reflection.md` with responses to all five scenario questions
- [ ] **Task 1.6** — A completed smoke test: every tool run once, results recorded, versions written into `tool-checklist.md`
- [ ] **Task 1.7** — Three named snapshots, a tested revert, and a completed snapshot inventory table
- [ ] **Troubleshooting** — Any workaround you applied recorded in the `tool-checklist.md` Update Log

*Working the no-VM path? Tasks 1.3, 1.4, 1.5, and the reduced 1.6 are your deliverables, plus the substitutions in the [Working Without a VM](#working-without-a-vm) table.*

---

## Files in This Folder

```
Lab01/
├── ReadMe.md                     ← This file
├── CoC_Template.md               ← Chain of custody template
├── reflection.md                 ← Reflection exercise template (fill in your answers)
├── tool-checklist.md             ← Recommended tools and version tracking sheet
├── task-answers.md               ← Sample answers for Tasks 1.1–1.5
├── Lab01_01/                     ← §1.1 What is Digital Forensics?
│   ├── ReadMe.md
│   └── lab1.1-notes.md
├── Lab01_02/                     ← §1.2 Why Windows Matters in IR
│   ├── ReadMe.md
│   └── lab1.2-notes.md
├── Lab01_03/                     ← §1.3 Authorization, Legal, Chain of Custody
│   ├── ReadMe.md
│   ├── lab1.3-notes.md
│   └── chain_of_custody_template.docx
└── Lab01_04/                     ← §1.4 Standing Up a Windows IR Lab
    ├── ReadMe.md
    └── lab1.4-notes.md
```

Lab 01 has no rollup notes file, because the per-sub-exercise notes cover it. Record this top-level lab's work in `Lab01_04/lab1.4-notes.md`, `CoC_Template.md`, `reflection.md`, and `tool-checklist.md`.

---

> **Going deeper:** [Appendix D](../../Book/AppendixD.md) (Tooling Reference for Windows IR) gives an annotated entry for every tool in Task 1.1 — what it does, its license, and where it fits in the workflow. [Appendix E](../../Book/AppendixE.md) (Windows Forensics Quick Reference) condenses every artifact path, event ID, and tool invocation in the book onto a few pages. Print it and keep it next to the VM. [Appendix G](../../Book/AppendixG.md) (Anti-Forensics and Evidence Tampering) §G.7.4 covers the defensive-tooling tampering pattern that makes the Defender exclusion in this lab worth thinking carefully about. And Chapter 3 §3.7 develops the full acquisition decision tree this lab only sketches.

---

## Key Takeaways

- **The five phases are a mental model, not a sequence.** Identification, Collection, Preservation, Analysis, Reporting rarely happen cleanly in order during IR. You will loop back and repeat them as the investigation develops.
- **Windows artifacts matter because Windows dominates.** Most enterprise intrusions touch a Windows system. MFT, registry hives, shell items, Prefetch, SRUM, event logs, and memory give you the visibility to answer IR questions with evidence rather than assumption.
- **Forensics without authorization is a liability.** Even in fast-moving incidents, a brief check — do I have permission, am I collecting the right scope, am I documenting my actions — protects you, your organization, and the validity of your findings.
- **A tool you have not run is a tool you do not have.** The smoke test in Task 1.6 exists because installed and working are different states, and the gap between them only becomes visible under pressure.
- **Never do irreversible work on the only copy.** Snapshot discipline in the lab is the same instinct as working-copy discipline on a real case. Build the habit where the cost of failure is an evening, not a case.
- **The same action can be routine or damning depending on context.** An antivirus exclusion on your isolated lab VM is housekeeping. The identical exclusion on a production host is a change-controlled decision, and one added by someone else may be an indicator of compromise.
- **Everything here serves one decision.** Powered on or powered off, admin or not, memory first or write-blocker first. Chapter 3 §3.7 develops that decision properly. This lab makes you ready to act on it.

---

## Next Steps

When you've completed Lab 01, take a snapshot of your VM and label it `Lab01-Complete`. You'll build on this environment in Lab 02.

 **Lab 02** covers the forensic investigation process for IR, including triage workflows, artifact prioritization, and designing a repeatable IR playbook.

---

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*

---
