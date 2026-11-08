# Windows Forensics for Beginners

*A Practical Guide for Incident Responders*

This repository holds the book **Windows Forensics for Beginners**, its companion labs, and the simulated data the labs use. Every file is Markdown, CSV, or plain text, apart from one `.docx` template, the cover image, and the per-host Python generators that rebuild the data. There is no application to build or test.

## Who this is for

The book is for incident responders, SOC analysts, EDR-tuning engineers, and other blue-team practitioners who must work out what happened on a Windows host. It teaches investigation under time pressure with incomplete information. It does not cover academic forensic theory or e-discovery.

You need basic Windows administration skills and some security experience. You do not need to be a seasoned examiner.

## What's in here

```
.
├── Book/               The 14-chapter manuscript, 7 appendices, preface, glossary,
│                       per-chapter answer keys, and the cover page
├── Labs/               13 hands-on labs (Lab01–Lab13) with sub-exercises, notes
│                       templates, and answer keys
├── Data/               Simulated parser output for each lab's scenario (CSV / text),
│                       each host with a deterministic generator script
├── CONTRIBUTING.md     How to contribute, and the conventions to preserve
├── STYLE.md            House writing style (Lenny Zeltser's guidance, applied)
├── CLAUDE.md           Agent / contributor guidance for working in this repo
└── Windows Forensics for Beginners.md  Lower-fidelity single-file copy of the book
```

**Cover page:** [`Book/Cover.md`](Book/Cover.md)

### `Book/`

| File | Topic |
|---|---|
| `ReadMe.md` | Preface |
| `Chapter01.md` | Windows Forensics in Incident Response |
| `Chapter02.md` | The Forensic Investigation Process for IR |
| `Chapter03.md` | Digital Forensics and Advanced Data Triage |
| `Chapter04.md` | Windows File System Forensics (NTFS) |
| `Chapter05.md` | Registry and Cloud Storage |
| `Chapter06.md` | Shell Items, Removable Devices, and Application Artifacts |
| `Chapter07.md` | Memory Forensics |
| `Chapter08.md` | Network Forensics on Windows |
| `Chapter09.md` | Windows Event Logs |
| `Chapter10.md` | Timeline Analysis |
| `Chapter11.md` | Capstone — Investigating Unauthorized Data Exfiltration |
| `Chapter12.md` | Ransomware Incident Response |
| `Chapter13.md` | Reporting, Containment, and Recovery |
| `Chapter14.md` | Conclusion and Next Steps |
| `AppendixA.md` | Lateral Movement, Credential Abuse, and Active Directory |
| `AppendixB.md` | Cloud Identity and Microsoft 365 Forensics |
| `AppendixC.md` | EDR Platforms and Sysmon |
| `AppendixD.md` | Tooling Reference for Windows IR |
| `AppendixE.md` | Windows Forensics Quick Reference |
| `AppendixF.md` | Industry and Certification Alignment |
| `AppendixG.md` | Anti-Forensics and Evidence Tampering |
| `Glossary.md` | Consolidated key terms, with chapter cross-references |
| `answers/` | Review-question and practical-exercise answer keys, one file per chapter |

### `Labs/`

Labs 01–13 mirror Chapters 1–13. Each lab has:

- A top-level `ReadMe.md` with scenario, tasks, and deliverables
- Sub-exercise folders (`LabNN_MM/`) corresponding to chapter sections
- An analyst-notes scaffold (`labNN-notes.md`) the student fills in
- A `task-answers.md` sample answer key for the workbook tasks
- For Lab01–Lab04, additional per-section notes templates

Labs 04 through 12 each include a **Hands-On Walkthrough** with commands against the `Data/` datasets, and a `walkthrough-answers.md` with verified expected output. Each walkthrough gives both PowerShell and Python, so you can work the labs from Windows, macOS, or Linux.

There are two capstones. **Lab 03 `Capstone/`** is a triage-judgment challenge scoped to Chapter 3. **Lab 11** is the book-wide capstone.

### `Data/`

Simulated parser output, organized by host, lets you work the analysis tasks without a Windows VM.

| Folder | Scenario | Used by |
|---|---|---|
| `WKSTN-221/` | Office macro → PowerShell → CMD chain, outbound C2, lateral move to FILESVR-03 | Lab02, 03, 04, 09, 10 |
| `HR-LT12/` | HR laptop with persistence + USB activity + OneDrive sync | Lab05 |
| `FIN-WS23/` | Finance workstation, Word → PowerShell, mixed shell artifacts | Lab06 |
| `WEB-APP-03/` | IIS server with suspected web shell — Volatility output | Lab07 |
| `HR-WS17/` | Departing-employee multi-channel exfiltration (USB + personal OneDrive) | Lab11 capstone |
| `ACCT-FS01/` | Ransomware on an accounting file server: RDP initial access, six-day dwell, rclone exfiltration, encryption | Lab12 |
| `network/` | Standalone network telemetry (flow, proxy, DNS, firewall) | Lab08 |

See `Data/README.md` for the full file inventory and caveats on the simulated nature of the data.

## How to use this repository

**If you're new to forensics:** read in order. Start with the preface in `Book/ReadMe.md`, then work through Chapters 1 to 14 and their labs.

**If you already work in IR:** use the artifact chapters as refreshers: NTFS (`Chapter04.md`), registry (`Chapter05.md`), shell items (`Chapter06.md`), memory (`Chapter07.md`), event logs (`Chapter09.md`), and timelines (`Chapter10.md`). Lab 11 is the integration exercise.

**If you don't have a Windows VM:** work the labs against the simulated CSVs in `Data/`. Labs 04 through 12 ship Hands-On Walkthroughs with verified expected output.

**If you lead IR teams:** adapt the labs into internal training scenarios. The Lab 11 and `Lab03/Capstone/` exercises suit tabletop or live-fire training.

## Conventions

- File naming uses mixed-case `ReadMe.md` (capital M). Don't normalize to `README.md` — it's a project convention.
- Tool names are linked on first use (Eric Zimmerman's tools, Autopsy, FTK Imager, Volatility, etc.).
- All timestamps in the labs and datasets are UTC.
- The book is beginner-friendly but written for IR practitioners. Reader notes at the top of Chapters 1–3 tell experienced readers what to skim, and the appendices add depth on lateral movement, cloud identity, EDR, and anti-forensics.
- Prose follows [`STYLE.md`](STYLE.md).

## Status

The book is complete in draft. The labs support self-study and internal training. Labs 01–03 and 13 are workbook-style, and Labs 04–12 add walkthroughs against the `Data/` datasets. See `CONTRIBUTING.md` and `CLAUDE.md` for contributor guidance.

---

Project repository for *Windows Forensics for Beginners — A Practical Guide for Incident Responders*.
