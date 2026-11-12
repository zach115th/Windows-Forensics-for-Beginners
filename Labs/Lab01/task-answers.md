# Lab 01 — Task Answer Key

*Sample answers for the workbook-style Tasks 1.1–1.5 in `Labs/Lab01/ReadMe.md`. These are reference answers, not the only correct answers. Your wording may legitimately differ. The reasoning matters more than the prose. Lab 01 has no Hands-On Walkthrough, so this answer key is the only calibration for the lab.*

---

## Task 1.1 — Build a Windows Forensics VM

This task is procedural. The deliverable is the VM itself, the `OS-Only` snapshot, and the installed tool list. There are no reflective questions, but the choices you make here have downstream consequences.

**What a defensible build looks like:**

- Host-Only networking is non-negotiable for a practice lab. The first time you accidentally execute a sample in a VM that reaches the internet is the last time you'll forget that rule. If a lab task ever requires real network access, make that decision deliberately, not by default.
- The `Baseline-Clean` snapshot, which you take in Task 1.7 once the tools pass the smoke test, is what makes the lab repeatable. You revert to it between labs so that artifact contamination from Lab N doesn't bleed into Lab N+1. That matters most when Labs 04 onward depend on a clean MFT, USN Journal, and registry state.
- The tool inventory matters in two ways. First, version drift between EZ Tools releases is real. Column names in MFTECmd output, for instance, have shifted across versions. Recording the version next to each install means you can reproduce a parse months later. Second, tools that you can't install on the VM, such as KAPE or FTK Imager full edition with its licensing prompts, are the ones that bite during a real incident. Better to discover that now.

**Sample completed tool checklist entry:**

| Tool | Version | Source | SHA-256 (installer) | Install Date | Notes |
|---|---|---|---|---|---|
| EZ Tools (MFTECmd) | 1.2.3.5 | ericzimmerman.github.io | `a4f1...` | 2024-11-12 | Net 6 runtime also installed |
| Autopsy | 4.21.0 | autopsy.com | `b223...` | 2024-11-12 | Standard install path |
| FTK Imager (free) | 4.7.1.2 | exterro.com | `c91d...` | 2024-11-12 | Requires registration form |
| Registry Explorer | 2.0.0.0 | ericzimmerman.github.io | `de42...` | 2024-11-12 | Same .NET runtime as MFTECmd |
| WinPMEM | 4.0.1 | github.com/Velocidex/WinPmem | `f102...` | 2024-11-12 | Memory acquisition |

The hash column matters. Six months from now, if you need to re-download MFTECmd 1.2.3.5 because the version you analyzed with is no longer the current release, you can verify you have the same binary by comparing hashes.

**Common pitfalls to avoid:**

- Skipping the snapshot. The first lab where you have to wipe the VM because you can't roll back will teach the lesson. Better to skip the lesson.
- Putting the VM on a NAT'd or bridged adapter "just for setup, I'll change it later." You won't.
- Treating the optional SIFT companion VM as a nice-to-have all the way through Lab 11. It isn't strictly required, but the moment you want Plaso super-timelines or Volatility 3 against a Linux memory image, the SIFT VM saves a real afternoon.
- Letting Windows Update run unattended on the lab VM. Updates change artifact behavior in subtle ways, such as Prefetch retention policies, the Amcache schema, and ETW provider lists. Pin the VM's patch level and document it.

---

## Task 1.2 — Create a Simulated Evidence Disk

Also procedural: you produce a populated secondary disk, then shut down cleanly. There are no reflective questions. A few notes make the rest of the lab go more smoothly:

- The renamed `notepad.exe` to `update.exe` in `\Temp\` is a deliberate echo of the WKSTN-221 scenario you'll meet in Lab 04. Start treating "trusted system binary in an unexpected path" as a flag now. The habit pays off.
- "Safely eject" matters because an unclean detach can leave the virtual disk in a dirty state, which alters the file system journals you might later want to parse. The whole point of forensic preservation is that the disk you hash is the disk you analyze.
- Note where the host puts the virtual disk file, because Task 1.3 needs the full path. VMware keeps `.vmdk` files next to the `.vmx` in the VM's folder. Hyper-V keeps `.vhdx` files in the folder `(Get-VMHost).VirtualHardDiskPath` returns. Appendix H §H.7 shows how to ask each hypervisor for the exact path.

**Sample disk contents that produce interesting artifacts:**

- `\Documents\Q4_Payroll_Review.xlsx`, `\Documents\Vendor_Contracts.docx`, `\Documents\Year_End_Forecast.xlsx` — realistic file names give the lab context.
- `\Images\` with five or six JPGs from any source (vacation photos work fine).
- `\Scripts\backup-rotation.ps1` — a one-line PowerShell script that just writes a log entry. Do not run it, because its presence is enough.
- `\Temp\update.exe` — the renamed `notepad.exe`. Optionally also `\Temp\config.dat` (any small binary file) to add staging texture.
- A subfolder `\Drafts\` with an outdated `.docx` to give the disk a sense of normal user activity.

The diversity matters because some labs reference these files. The "evidence disk" you produce here is what you'll practice mounting and parsing in later labs.

---

## Task 1.3 — Hash the Evidence

Procedural. Run the hash, record the value. There are no reflective questions, but two operational habits make this step worth doing carefully:

- Run the hash command twice and confirm both results match before recording. The cost of a typo in a chain-of-custody record is high. The cost of running `Get-FileHash` twice is zero.
- Record the *full* hash, the algorithm, and the path. `Hash: a3f5...` with no algorithm is not a forensic record.
- The "why this matters" blockquote in the lab is the point of the entire exercise: the hash is what lets you prove later that the evidence hasn't changed. If you skip this in a real engagement and the defense asks "how do you know this file hasn't been altered since collection?", "I assume it wasn't" is not an answer.

**Sample completed hash record:**

```
File:           C:\Users\me\Documents\Virtual Machines\LAB-WIN11-01\evidence-disk.vmdk
Algorithm:      SHA-256
Hash:           22952a9d2d5eaabe2dbe320dfd3e9dcfd5707273ad82cc625424be5e38b2c97c
                (64 characters, lowercase hex. Illustrative value: yours will differ.)
Hashed By:      A. Analyst (AAN)
Date/Time:      2024-11-14T19:42:13Z (UTC)
Tool:           Get-FileHash (PowerShell 5.1.22621.2506)
Verification:   Run a second time; matched.
```

Tools that produce SHA-256 differ in output format. PowerShell returns uppercase hex by default, and `sha256sum` returns lowercase. Normalize to lowercase in your records so comparisons across tools work without ambiguity.

---

## Task 1.4 — Complete a Chain-of-Custody Record

Procedural: fill in every field of `CoC_Template.md`. There are no reflective questions, but the most common failure mode is leaving fields blank "because they don't apply." Write `N/A — reason` instead.

**Sample completed CoC entry:**

```
Evidence ID:        LAB01-001
Description:        VMware virtual disk (VMDK), 15 GB, NTFS-formatted, populated with
                    simulated payroll documents, sample images, a benign PowerShell
                    script, and a renamed executable (notepad.exe -> Temp\update.exe).
                    Created for Lab 01 evidence-handling practice.
Source System:      LAB-WIN11-01 (VMware Workstation VM hosted on analyst workstation
                    DESKTOP-AAN42); secondary disk attached as drive E:.
Date/Time Acquired: 2024-11-14T19:42:13Z (UTC)
Acquired By:        A. Analyst (AAN), IR Team
Hash Algorithm:     SHA-256
Hash Value:         22952a9d2d5eaabe2dbe320dfd3e9dcfd5707273ad82cc625424be5e38b2c97c
Storage Location:   D:\IR-Lab\Lab01\evidence-disk.vmdk on encrypted external drive
                    (WD My Passport, S/N WX12C8A04, BitLocker-protected; recovery
                    key escrowed with IR Manager).
Notes:              Lab exercise — not real evidence. VM was powered off cleanly
                    before host-side hash. Tool versions: PowerShell 5.1.22621.2506
                    on Windows 11 23H2. No file modifications between disk creation
                    and hash.
```

A few field-by-field notes for your own entry:

| Field | What a Defensible Entry Looks Like |
|---|---|
| Evidence ID | `LAB01-001` (or your team's naming convention). Must be unique within the case. |
| Description | `VMware virtual disk, 15 GB, NTFS, populated with simulated payroll documents and a renamed executable (update.exe). Created for Lab 01 evidence-handling practice.` Be specific enough that a stranger reading it in two years can identify the item. |
| Source System | `LAB-WIN11-01 (VirtualBox VM, host: <hostname>)` — both the VM identity and the underlying host. |
| Date/Time Acquired | UTC, ISO-8601. `2024-11-14T17:42:00Z`. Local time is fine as long as you label it; UTC removes ambiguity. |
| Acquired By | Full name plus initials. Initials alone aren't enough if there are two people on the team with the same ones. |
| Hash Algorithm | `SHA-256`. Spell out the bit length. |
| Hash Value | The full 64-character hex string. No truncation. |
| Storage Location | Full path on the host, plus the drive's identifier if it's removable. `D:\IR-Lab\Lab01\evidence-disk.vmdk on encrypted external drive WD-Passport-S/N-WX12...` |
| Notes | Anything that wouldn't be obvious to a reviewer. Tool versions used to hash, any oddities, who was present. |

---

## Task 1.5 — Authorization and Scope Reflection

**Reflective question 1 (paraphrased):** What authorization would you need before imaging a Windows workstation in a real incident, and who can grant it?

In a real engagement you need documented authorization from someone with both the legal authority and the operational standing to grant it. That is typically the incident commander acting on delegated authority from the General Counsel or a Chief Information Security Officer. HR and Legal should be in the loop if the host is assigned to an identifiable employee. The form matters less than the paper trail. A short email confirming scope is what protects you if the action is later questioned: "authorized to image WKSTN-047 and collect Windows event logs in service of IR-2024-0142, scope limited to that host." In organizations with a published IR plan, your authorization is usually pre-granted within the documented playbook. Even then, recording who invoked the playbook and when is part of the record. The two failure modes to avoid are (a) imaging on a verbal hallway request with no written follow-up and (b) waiting hours for written authorization while volatile evidence evaporates. The right pattern is to act on documented standing authority and confirm scope in writing as soon as you can.

**Reflective question 2 (paraphrased):** You're collecting event logs from a compromised server and notice the logs contain personal employee data. What do you do, and who do you tell?

Stop, document what you've already collected, and notify the case lead and your privacy or legal contact before continuing. Incidental collection of personal data during a legitimate forensic action is not automatically a problem, but proceeding without flagging it can become one, particularly under GDPR, HIPAA, or any framework with a data-minimization requirement. The defensible move is to narrow the collection scope and to record both the discovery and the scoping decision in your case notes. Filter the event logs to the relevant time window and event IDs rather than copying entire EVTX files wholesale. The wrong move is to pretend you didn't notice. Reviewers will eventually notice the same thing, and the question "why didn't you flag this when you saw it?" doesn't have a good answer.

**Reflective question 3 (paraphrased):** Why does chain of custody matter when your organization has no plans to involve law enforcement? Give at least two reasons.

First, you don't always know on day one whether law enforcement, regulators, or civil litigation will eventually become involved. Incidents that start as "internal cleanup" routinely become regulatory disclosures, insurance claims, or wrongful-termination lawsuits months later. At that point your collection record has to stand on its own. Second, chain of custody is what makes findings defensible *internally* — to executives, to the board, to other teams whose access you'll need to revoke based on your conclusions. A finding that "user X accessed sensitive data on date Y" is only actionable if the evidence supporting it can be traced from acquisition through analysis without gaps. Third, and most under-rated, chain of custody protects *you*: if something later goes wrong with the evidence, the record shows what state it was in when it left your hands and who had it after.

**Reflective question 4 (paraphrased):** The "2 a.m. problem" — the security director says "just image everything and sort it out later." What's right about that instinct, and what's risky?

The right instinct is the urgency. If the attacker is still active, volatile evidence is being destroyed by the second, and a containment delay can let lateral movement spread to systems you haven't identified yet. There's also genuine virtue in preserving broadly when you can't yet articulate which artifacts will matter. Over-collection is recoverable, and under-collection often isn't. There are three risks. First, imaging takes hours per host, and during those hours an active attacker can do serious damage if no one is hunting them in parallel. Second, "everything" without scope creates a downstream analysis burden that delays findings. Third, unscoped collection can sweep up personal data, third-party material, or systems outside your authorization, creating legal exposure. The defensible response is to collect volatile evidence immediately on the highest-priority host: memory, network state, and running processes. Kick off a targeted triage on the rest, and reserve full imaging for hosts where the value clearly justifies the time. Document that decision in real time so the rationale survives the night.

**Reflective question 5 (paraphrased):** What approval path would you need before adding the same `C:\Tools\` antivirus exclusion on a production server, and who needs to know?

Treat it as a change request, not a troubleshooting step. The endpoint security team usually owns Defender policy, so the request goes to them through your change process. It needs a named approver, a stated reason, the exact path, and a removal date. On a server, the system owner signs off too, as does the change advisory board or its emergency equivalent during an incident. Tell the SOC before the change lands. An exclusion added from an admin prompt on a production host looks exactly like attacker defense evasion, and the analyst who sees the alert should already know it is yours. Record who approved it, when it was added, and when it was removed. If the host is under investigation, the better answer is usually no exclusion at all. Run the tools from external media or through EDR live response instead, because the exclusion changes the configuration you are there to examine.

---

## Ready-to-move-on self-check

Before starting Lab 02, confirm you can answer these three questions cold. If any of them feel wobbly, revisit the relevant task in this lab.

1. **A coworker hashes an evidence file on acquisition and a different value comes back when you re-hash it three days later. What does that tell you, and what's your next step?**
   *Answer:* It tells you something has changed about that file: an accidental write, file corruption, or the file you're hashing is not the file that was originally collected. Stop further analysis on that artifact, document the discrepancy in the case notes, and trace the chain-of-custody record to find when the file was last known-good.

2. **Why is a chain-of-custody record valuable even when no law enforcement involvement is expected?**
   *Answer:* Because the engagement may become a regulatory disclosure, civil matter, or board-level escalation later, and because the record is what makes findings defensible internally. Executives and other teams need to trust the evidence chain before they act on your conclusions.

3. **You're asked to "image everything" on a host under active compromise. Name one thing you should collect before you start the image, and explain why.**
   *Answer:* Memory, and ideally running process and network connection state. Memory is the most volatile evidence on the host. Every minute that passes loses some of it, and an active attacker's process artifacts, injected code, and live network sessions exist only there. Disk imaging is slow and disk evidence is durable, so capturing volatile state first is the order that minimizes loss.

---

*Lab 01 has no Hands-On Walkthrough, so this answer key has no walkthrough↔workbook bridges. Lab 04 is the first lab where that section becomes relevant.*

---

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
