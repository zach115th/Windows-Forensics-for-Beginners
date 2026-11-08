# Labs — Windows Forensics for Beginners

This folder contains the 13 hands-on labs that pair with the book in [`../Book/`](../Book/). Each lab corresponds to one chapter, and the labs are designed to be worked in order. Later labs, especially 04–12, can stand alone if you already have the prerequisite environment from Lab 01. Chapter 14 is the closing chapter and has no lab — its §14.6 is itself a self-assessment exercise.

## Lab Index

| # | Title | Supports | Primary Dataset | Hands-On Walkthrough | What You'll Do |
|---|---|---|---|:---:|---|
| 01 | [Windows Forensics Foundations](Lab01/ReadMe.md) | [Ch 1](../Book/Chapter01.md) | — | No | Stand up the analyst VM, install the tooling baseline, take a clean baseline snapshot, and practice chain-of-custody documentation. |
| 02 | [The Forensic Investigation Process for IR](Lab02/ReadMe.md) | [Ch 2](../Book/Chapter02.md) | — | No | Translate a vague alert into a scoped investigation plan: questions, evidence, hypotheses, and a defensible answer. |
| 03 | [Digital Forensics and Advanced Data Triage](Lab03/ReadMe.md) | [Ch 3](../Book/Chapter03.md) | — | No | Design per-host triage strategy, build a scoped collection script, and write the management justification memo for not imaging everything. **Includes a chapter-scoped [capstone challenge](Lab03/Capstone/ReadMe.md).** |
| 04 | [Windows File System Forensics (NTFS)](Lab04/ReadMe.md) | [Ch 4](../Book/Chapter04.md) | `Data/WKSTN-221/` | Yes | Parse `$MFT` and the USN journal; interpret MACB timestamps; correlate NTFS evidence with execution and event-log artifacts. |
| 05 | [Windows Registry and Cloud Storage Forensics](Lab05/ReadMe.md) | [Ch 5](../Book/Chapter05.md) | `Data/HR-LT12/` | Yes | Hunt persistence keys, USB-device history, and OneDrive sync database evidence on an HR-laptop scenario. |
| 06 | [Shell Items, Removable Devices, and Application Artifacts](Lab06/ReadMe.md) | [Ch 6](../Book/Chapter06.md) | `Data/FIN-WS23/` | Yes | Parse LNK files, Jump Lists, Prefetch, Shellbags, UserAssist, Amcache, browser history; reconstruct user activity. |
| 07 | [Memory Forensics](Lab07/ReadMe.md) | [Ch 7](../Book/Chapter07.md) | `Data/WEB-APP-03/` | Yes | Analyze a memory image with Volatility 3 plugin output (or MemProcFS); find suspicious processes, injected modules, and network sockets. |
| 08 | [Network Forensics on Windows](Lab08/ReadMe.md) | [Ch 8](../Book/Chapter08.md) | `Data/network/` | Yes | Work simulated PCAP, flow, DNS, and proxy data; identify suspicious streams; map connections back to host processes. |
| 09 | [Windows Event Logs](Lab09/ReadMe.md) | [Ch 9](../Book/Chapter09.md) | `Data/WKSTN-221/` | Yes | Build a reusable hunt pack against Security/System/PowerShell logs; run [Hayabusa](https://github.com/Yamato-Security/hayabusa); validate filters against [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack). |
| 10 | [Timeline Analysis](Lab10/ReadMe.md) | [Ch 10](../Book/Chapter10.md) | `Data/WKSTN-221/` | Yes | Merge MFT, USN, event-log, Prefetch, SRUM, and network-flow CSVs into one timeline; pivot on a suspicious event; write the focused ±10–15 minute narrative. |
| 11 | [Forensic Challenge: Investigating Unauthorized Data Exfiltration](Lab11/ReadMe.md) | [Ch 11](../Book/Chapter11.md) | `Data/HR-WS17/` | Yes | Capstone. End-to-end exfiltration investigation across triage, NTFS, registry, shell, network, event logs, timeline, and final case write-up. |
| 12 | [Ransomware Incident Response](Lab12/ReadMe.md) | [Ch 12](../Book/Chapter12.md) | `Data/ACCT-FS01/` | Yes | Scope an encryption event across 418 files, find patient zero six days back through a cleared Security log, and answer whether data left before encryption. |
| 13 | [Reporting, Containment, and Recovery](Lab13/ReadMe.md) | [Ch 13](../Book/Chapter13.md) | — (uses earlier labs' output) | No | Turn analysis into decisions: findings at stated confidence, containment ranked by evidence cost, rebuild-vs-clean, the executive brief, and a Sigma rule back into the hunt pack. |

## Capstones

This book has **two** capstone challenges, at different scopes:

- **Lab 03 Capstone** — [`Lab03/Capstone/`](Lab03/Capstone/ReadMe.md). Chapter-scoped. *Forensic Challenge: Multi-Host Triage and Acquisition Under Pressure.* A judgment lab rather than a parser lab: six hosts, competing priorities, leadership pressure, and the choice between imaging everything and triaging smart. Pairs with Chapter 3.
- **Lab 11** — [`Lab11/`](Lab11/ReadMe.md). Book-wide. *Forensic Challenge: Investigating Unauthorized Data Exfiltration.* The whole lab is the capstone; it pulls every artifact class from Chapters 4–10 into one HR-WS17 exfiltration investigation.

Other labs don't have capstones — they're per-chapter artifact-skill labs. The two capstones exist because Chapter 3's triage decision-making and the book as a whole benefit from a scenario challenge that goes beyond per-section tasks.

## Walkthroughs in the last two labs

Labs 12 and 13 are the last two, and only one of them has a walkthrough. That is deliberate:

- **Lab 12 has one** — a nine-step walkthrough against `Data/ACCT-FS01/`, the largest dataset in the book. It holds 3,301 USN records, 418 encrypted files, and event logs from three hosts, because the file server's own Security log was cleared.
- **Lab 13 does not**, because it has no dataset of its own. It consumes what you produced in Labs 04, 09, 10, and 11 and asks you to turn it into decisions and documents. If you skipped those labs, work Lab 13 against the Case File section it ships instead.

## Conventions

- Each lab folder has a top-level `ReadMe.md` (the assignment). Labs 02–13 also have `labNN-notes.md`, an analyst-notes template you fill in as you work. Lab 01 has no rollup notes file and uses its per-section notes files instead.
- Every lab has per-section sub-folders (`LabNN_MM/`) with their own ReadMes. In Labs 01–04, each sub-folder also holds a per-section notes file. In Labs 05–13, the sub-folders hold the sub-exercise ReadMe without a notes file.
- The `Labs/Lab10/timeline-template.csv` and `Labs/Lab10/timeline-template-iris.csv` are starter spreadsheets — beginner-friendly headers and an [IRIS-NG](https://github.com/zach115th/iris-ng)-compatible variant respectively. See [Appendix D §D.14](../Book/AppendixD.md) for context on collaborative timeline platforms.
- File-naming inside the labs is intentionally inconsistent in places, such as `Lab01/Lab01_01/lab1.1-notes.md` versus `Lab02/Lab02_01/lab02.1-notes.md`. The variation is documented in [`../CLAUDE.md`](../CLAUDE.md). Don't normalize without checking the cross-references first.

## How to Use the Labs

1. **Start with Lab 01** to set up the environment if you don't already have a Windows analysis VM. The labs assume Eric Zimmerman's tools, MemProcFS / Volatility 3, Wireshark, KAPE, and either Cyber Triage or SIFT are available — see [Appendix D](../Book/AppendixD.md) for the full tool list.
2. **Work the chapter first**, then the lab. The lab assumes you've read the chapter and understand its key terms.
3. **Nine of 13 labs** (04–12) include a Hands-On Walkthrough at the end that uses the simulated CSV data in `../Data/`. Each walkthrough's expected counts have been verified against the backing data. If your numbers don't match, your filter is probably wrong, not the data.
4. **Fill in the analyst-notes template (`labNN-notes.md`)** as you go. The notes file is the deliverable, and the ReadMe is the prompt. Don't write your answers in the ReadMe.

## See Also

- [`../Book/`](../Book/) — the book chapters and appendices (canonical content)
- [`../Data/`](../Data/) — simulated forensic CSVs that back the Hands-On Walkthroughs
- [`../Book/AppendixE.md`](../Book/AppendixE.md) — one-page-density Windows forensics quick reference

---

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) project.*
