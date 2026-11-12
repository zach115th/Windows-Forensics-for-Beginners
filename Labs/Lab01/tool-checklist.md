# Lab Tool Checklist and Version Tracker

**Windows Forensics for Beginners — Lab Environment**  
**Last Updated:** ___________________________  
**Environment:** ___________________________  (e.g., VMware Workstation / VirtualBox / Hyper-V)

---

## Why Track Tool Versions?

Forensic tool output can differ between versions. If you share findings with a colleague, testify about your analysis, or revisit a case months later, you need to know exactly which version of each tool produced which output. Fill this in as you install tools — don't rely on memory.

---

## Core Tools (Required for This Book)

| Tool | Purpose | Source | Version Installed | Install Date | Notes |
|---|---|---|---|---|---|
| **EZ Tools Suite** | MFT, registry, shell items, timeline | [ericzimmerman.github.io](https://ericzimmerman.github.io/) | | | |
| **MFTECmd** | Parse MFT and USN Journal | Included in EZ Tools | | | |
| **Registry Explorer** | Registry hive analysis | Included in EZ Tools | | | |
| **RECmd** | Command-line registry parsing | Included in EZ Tools | | | |
| **LECmd** | LNK file parser | Included in EZ Tools | | | |
| **JLECmd** | Jump list parser | Included in EZ Tools | | | |
| **PECmd** | Prefetch parser | Included in EZ Tools | | | |
| **SBECmd** | Shellbag parser | Included in EZ Tools | | | |
| **EvtxECmd** | Event log parser | Included in EZ Tools | | | |
| **Timeline Explorer** | CSV timeline viewer | Included in EZ Tools | | | |
| **FTK Imager** | Disk and memory acquisition | [exterro.com](https://www.exterro.com/ftk-imager) | | | |
| **KAPE** | Triage collection and chained parsing | [kroll.com](https://www.kroll.com/en/services/cyber/incident-response/kroll-artifact-parser-extractor-kape) | | | Free registration to download |
| **Autopsy** | General forensic analysis platform | [autopsy.com](https://www.autopsy.com) | | | |
| **Volatility 3** | Memory forensics framework | [volatilityfoundation.org](https://www.volatilityfoundation.org) | | | |
| **WinPmem** | Memory acquisition | [github.com/Velocidex/WinPmem](https://github.com/Velocidex/WinPmem) | | | |

---

## Supporting Tools (Recommended)

| Tool | Purpose | Source | Version Installed | Install Date | Notes |
|---|---|---|---|---|---|
| **RegRipper** | Automated registry key extraction | [github.com/keydet89/RegRipper3.0](https://github.com/keydet89/RegRipper3.0) | | | |
| **Chainsaw** | Event log hunting (Sigma rules) | [github.com/WithSecureLabs/chainsaw](https://github.com/WithSecureLabs/chainsaw) | | | |
| **Hayabusa** | Fast Windows event log analysis | [github.com/Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa) | | | |
| **SRUM-DUMP** | SRUM database parser | [github.com/MarkBaggett/srum-dump](https://github.com/MarkBaggett/srum-dump) | | | |
| **Nirsoft tools** | Various Windows artifact utilities | [nirsoft.net](https://www.nirsoft.net) | | | |
| **CyberChef** | Data decoding and transformation | [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef) | | | |
| **7-Zip** | Archive and compression utility | [7-zip.org](https://www.7-zip.org) | | | |
| **Notepad++** | Text/log viewer | [notepad-plus-plus.org](https://notepad-plus-plus.org) | | | |
| **DB Browser for SQLite** | SQLite database viewer | [sqlitebrowser.org](https://sqlitebrowser.org) | | | |

---

## Python Environment (Optional but Recommended)

Some labs and scripts require Python 3. Track your environment here.

| Item | Details |
|---|---|
| **Python Version** | |
| **pip Version** | |
| **Virtual Environment Tool** | (e.g., venv, conda) |
| **Key Packages Installed** | |

---

## Alternative Analysis Environment (Optional)

A free Ubuntu-based VM appliance loaded with Linux-native forensic tooling that complements the Windows VM. Useful for Plaso, Sleuth Kit, Volatility's Linux side, and following along with SANS course material.

| Item | Details |
|---|---|
| **[SANS SIFT Workstation](https://www.sans.org/tools/sift-workstation)** — installed? | Yes / No |
| SIFT VM Name | |
| SIFT Version | |
| Install Date | |
| Snapshot Name | `Baseline-Clean` (recommended) |
| Network Mode | Host-Only (matches Windows lab VM) |
| Shared evidence folder with Windows VM | Path / Mode |
| Notes | |

---

## Lab Environment Summary

| Item | Details |
|---|---|
| **Host OS** | |
| **Host RAM** | |
| **Host Storage (free)** | |
| **Hypervisor** | |
| **Hypervisor Version** | |
| **VM OS** | |
| **VM RAM Allocated** | |
| **VM Disk Size (primary)** | |
| **VM Disk Size (evidence)** | |
| **Network Mode** | Host-Only (recommended) |
| **Baseline Snapshot Name** | `Baseline-Clean` |

---

## Update Log

Record significant changes to your lab environment here.

| Date | Change | Reason |
|---|---|---|
| | | |
| | | |
| | | |

---

*Tool Checklist — Windows Forensics for Beginners, Lab 01*  
*Keep this file updated throughout the book. Your lab environment is part of your forensic methodology.*
