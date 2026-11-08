# Lab 10 — Hands-On Walkthrough Sample Answers

*Sample answers for the Hands-On Walkthrough section of `Labs/Lab10/ReadMe.md`. These are reference answers. Your filter, environment, and tool version may legitimately produce slightly different values. The interpretation matters more than the exact number.*

---

## Step 1 — Load the inputs

**Expected output:** Five normalized object collections in the six-column timeline schema (`Time (UTC)`, `Source Artifact`, `Event Description`, `Significance`, `Confidence`, `Notes`):

| Source | Rows | Time field used |
|---|---|---|
| MFT | 77 | `Created0x10` |
| USN | 51 | `UpdateTimestamp` |
| Security EVTX | 38 | `TimeCreated` |
| Prefetch | 20 | `LastRun` |
| Network | 20 | `FlowStart` |

**Verified via:** `python3 -c "import csv; [print(f, len(list(csv.DictReader(open(f))))) for f in ['Data/WKSTN-221/mft.csv','Data/WKSTN-221/usn-journal.csv','Data/WKSTN-221/security-evtx.csv','Data/WKSTN-221/prefetch.csv','Data/WKSTN-221/network-flow.csv']]"`

**Interpretation:** The five inputs project into a single normalized schema. Each artifact source contributes a different facet. The MFT contributes "what existed and when," USN contributes "what changed," Security EVTX contributes "what was recorded by audit policy," Prefetch contributes "what executed," and Network flow contributes "what went on the wire." The merge is the join that makes cross-source alignment visible.

---

## Step 2 — Merge into a single timeline

**Expected output:** **206 rows** (77 + 51 + 38 + 20 + 20 = 206).

**Verified via:**

`python3 -c "import csv; print(sum(len(list(csv.DictReader(open(f)))) for f in ['Data/WKSTN-221/mft.csv','Data/WKSTN-221/usn-journal.csv','Data/WKSTN-221/security-evtx.csv','Data/WKSTN-221/prefetch.csv','Data/WKSTN-221/network-flow.csv']))"`

Per-file breakdown:

`python3 -c "import csv; [print(f.split('/')[-1], len(list(csv.DictReader(open(f))))) for f in ['Data/WKSTN-221/mft.csv','Data/WKSTN-221/usn-journal.csv','Data/WKSTN-221/security-evtx.csv','Data/WKSTN-221/prefetch.csv','Data/WKSTN-221/network-flow.csv']]"`

**Interpretation:** The merge returns exactly the 206 entries the lab expects. Sorting by `[DateTime]'Time (UTC)'` interleaves events from all five sources into a single chronological stream. At this step, the artifacts stop being separate views and become a single timeline.

---

## Step 3 — Curate around a pivot event

**Expected output:** Filtering the 206-row merged timeline to a 30-minute window around the Prefetch pivot (14:21:03 UTC ± 15 minutes, so 14:06:03 to 14:36:03) returns **78 rows** (`from datetime import datetime, timedelta`-based window count). The pre-curated example file `Data/WKSTN-221/example-curated-timeline.csv` holds 40 rows, and **39 rows of incident-relevant entries** fall in the same window. The 40th is the 14:38:00 logoff, just after the window ends. An analyst built the file by filtering out routine system noise and adding rows from sources outside the five-file merge, such as the Jump List, PowerShell 4104, Amcache, and SRUM.

**Verified via:** `python3 -c "import csv; from datetime import datetime, timedelta; pivot=datetime(2024,11,14,14,21,3); ev=[]; [ev.extend(((datetime.strptime(r[t].split('.')[0],'%Y-%m-%d %H:%M:%S'),s) for r in csv.DictReader(open(f)) if r[t])) for f, t, s in [('Data/WKSTN-221/mft.csv','Created0x10','MFT'),('Data/WKSTN-221/usn-journal.csv','UpdateTimestamp','USN'),('Data/WKSTN-221/security-evtx.csv','TimeCreated','Security'),('Data/WKSTN-221/prefetch.csv','LastRun','Prefetch'),('Data/WKSTN-221/network-flow.csv','FlowStart','Network')]]; print(len([e for e in ev if pivot-timedelta(minutes=15) <= e[0] <= pivot+timedelta(minutes=15)]))"`

**Interpretation:** The readme describes the expected narrative around the pivot:
1. User opens `Q4_Payroll_Review.xlsm` (MFT and USN rows for the `Q4_Payroll_Review.lnk` shortcut at 14:18:55)
2. `OUTLOOK.EXE -> POWERSHELL.EXE` EID 4688 at 14:19:38 with EncodedCommand
3. Outbound TCP/443 to 91.214.47.22 (Network) starting 14:19:42
4. `update.exe` creation in Temp (MFT/USN) at 14:20:11. The USN rows show it created as `b.tmp` and renamed to `update.exe` on the same MFT record (22417)
5. **Prefetch first-run at 14:21:03 (the pivot)**
6. Large `update.exe` flow to 91.214.47.22 at 14:21:55 (Network). SRUM is not in the merge, so its byte counts appear only in the curated file
7. `update.exe` deletion via USN at 14:23:44
8. EID 4648 explicit-credential to FILESVR-03 at 14:33:18

Pivoting around `update.exe` execution is defensible because that one event is when "preparation" became "action." Every entry within ±15 minutes is either part of the staging chain leading to it or part of the post-execution behavior flowing from it.

---

## Step 4 — Annotate with significance and confidence

**Expected output:** The final exported CSV (`wkstn221-timeline.csv`) carries the same six column headers as `timeline-template.csv`. Rows whose `Event Description` matches the four `switch -Wildcard` patterns get tagged:

- `*update.exe*` -> Significance "Attacker tooling"
- `*POWERSHELL.EXE*` -> Significance "Suspicious child of OUTLOOK.EXE"
- `*explicit credentials*` -> Significance "Lateral movement signal" (matches the EID 4648 description "Logon attempted with explicit credentials")
- `*Flow*91.214.47.22*` -> Significance "C2 candidate"

Run against the 78-row window, the rules tag 16 rows: 10 "Attacker tooling", 4 "C2 candidate", 1 "Suspicious child of OUTLOOK.EXE", and 1 "Lateral movement signal" (the 14:33:18 EID 4648). The four USN rows for `b.tmp` stay untagged, although they belong to the same MFT record as `update.exe`. A filename rule finds a file's current name, not its history. Match on `EntryNumber` 22417 in `usn-journal.csv` to pull them in.

The script sets Confidence by source: Network = `High (sensor + EDR)`, MFT = `High`, USN = `High`, default = `Medium`. The reference output `Data/WKSTN-221/example-curated-timeline.csv` (40 rows) shows what a finished analyst-rated version looks like with HIGH/MEDIUM/LOW classifications.

**Verified via:** Inspect the column structure of `Data/WKSTN-221/example-curated-timeline.csv`: `head -1 Data/WKSTN-221/example-curated-timeline.csv` returns `Time (UTC),Source Artifact,Event Description,Significance,Confidence,Notes` — same six headers as `timeline-template.csv`.

**Interpretation:** The annotation step turns a sorted log into an analyst product. Significance answers "why does this row matter?" and Confidence answers "how strongly do I believe it?" A handoff to another analyst or a written report needs both. Cross-source rows earn HIGH confidence because two independent artifact sources agree. An example is a USN `FILE_DELETE` corroborated by the MFT `InUse=False` flag and the Prefetch run.

---

## Step 5 — Write the narrative paragraph

**Expected output:** A 5–7 sentence paragraph that walks the pivot window in plain language. The reference paragraph in the readme:

> *At 14:18:55 UTC the user opened `Q4_Payroll_Review.xlsm`. Forty-three seconds later, `outlook.exe` spawned `powershell.exe` with an encoded command line, which then established an outbound TCP/443 connection to `91.214.47.22`. A binary named `update.exe` was created in the user's `Temp\` directory at 14:20:11 UTC and executed at 14:21:03 UTC. A later connection to the same IP, at 14:21:55 UTC, received approximately 2.3 MB and sent roughly 184 KB. The binary was deleted at 14:23:44 UTC. About 9.5 minutes later the same account authenticated to FILESVR-03 with explicit credentials.*

Each clause maps to one row of the curated timeline:

| Sentence Clause | Source Row |
|---|---|
| Q4_Payroll_Review.xlsm at 14:18:55 | JumpList / LNK |
| OUTLOOK.EXE -> PowerShell -EncodedCommand at 14:19:38 | EID 4688 (security-evtx) |
| Outbound TCP/443 to 91.214.47.22 at 14:19:42 | Network flow |
| `update.exe` created at 14:20:11 | MFT + USN |
| First-run at 14:21:03 | Prefetch |
| ~2.3 MB inbound, ~184 KB outbound | Network flow (14:21:55 large flow) |
| Deleted at 14:23:44 | USN FileDelete |
| Lateral move at 14:33:18 | EID 4648 |

**Verified via:** `head -3 Data/WKSTN-221/example-curated-timeline.csv` and cross-reference each sentence with a row in that file.

**Interpretation:** A narrative paragraph is the deliverable that survives the case. Months later, a reviewer or new analyst can read it without re-running the queries. It also translates cleanly into a case study, an internal incident review, or a customer-facing report. Every claim in the paragraph maps back to a specific row of the source CSV, and that mapping tests whether the narrative is faithful or embellished.

---

## Summary

Five reproducible counts:

| Step | Reproducible result |
|---|---|
| 1 | 5 sources normalized to common schema |
| 2 | 206 merged rows (77+51+38+20+20) |
| 3 | 78 rows in the ±15-minute pivot window (39 of the 40 rows in the curated example file fall inside it) |
| 4 | Same six-column schema as `timeline-template.csv`; reference file at `Data/WKSTN-221/example-curated-timeline.csv` |
| 5 | 8-clause narrative paragraph maps row-for-row to the curated CSV |

Every super-timeline and SIEM-driven incident reconstruction reduces to this merge-sort-filter-annotate-narrate workflow. Once you have the five inputs in a common schema, the rest is mechanical.
