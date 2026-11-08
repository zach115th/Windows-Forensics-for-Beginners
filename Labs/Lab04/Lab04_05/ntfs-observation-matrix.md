# NTFS Observation Matrix
**Windows Endpoint File-System Forensics — Reusable Reference**
*Windows Forensics for Beginners: A Practical Guide for Incident Responders*

---

**Version:** 1.0
**Created:** ___________________________
**Last Updated:** ___________________________
**Author:** ___________________________
**Case Reference:** ___________________________

---

## How to Use This Worksheet

This matrix is a living reference for capturing NTFS findings across cases. For each new investigation:

1. Copy it into your case folder under `04_NTFS/`.
2. Work through each category. Skip rows that don't apply; document why.
3. Pull supporting data from `mft.csv`, `usn-journal.csv`, and Prefetch / Amcache where relevant.
4. Note evidence gaps explicitly — `$MFT` corruption, unallocated entries you couldn't recover, USN windows that have rolled over.
5. Cross-reference into your timeline (Lab 10).

The strength of NTFS evidence is rarely one row in one file — it is the same file appearing in `$MFT`, `$J` (USN), Prefetch, Amcache, and an event log, all aligned in time. This matrix is the place you capture that alignment.

---

## Category 1 — File-of-Interest Identification

> Which files are central to the case? Capture them by `EntryNumber` + path + size.

| # | File / Path | `EntryNumber` | `InUse` | Size | Why It Matters | Notes |
|---|---|---|---|---|---|---|
| 1.1 | | | | | | |
| 1.2 | | | | | | |
| 1.3 | | | | | | |
| 1.4 | *(add as needed)* | | | | | |

---

## Category 2 — MACB Timestamp Analysis

> Compare `$STANDARD_INFORMATION` (`0x10`) and `$FILE_NAME` (`0x30`) timestamps. Divergence is your timestomping signal.

| # | File | `Created0x10` | `Created0x30` | Delta | `LastModified0x10` | `LastModified0x30` | Tamper Suspected? | Notes |
|---|---|---|---|---|---|---|---|---|
| 2.1 | | | | | | | | |
| 2.2 | | | | | | | | |
| 2.3 | | | | | | | | |

> **Interpretation:** if `Created0x10` and `Created0x30` disagree by more than the OS's normal jitter (~1 second), or if `$SI` looks "older" than `$FN`, the file's `$STANDARD_INFORMATION` may have been rewritten by a tool like `SetFileTime`. `$FN` is the harder-to-tamper-with witness.

---

## Category 3 — USN Journal Activity

> Cross-reference USN events with MFT entries. The USN gives motion; the MFT gives state.

| # | Timestamp (UTC) | USN Reason | File | Path | Corresponds to MFT Row? | Notes |
|---|---|---|---|---|---|---|
| 3.1 | | | | | | |
| 3.2 | | | | | | |
| 3.3 | | | | | | |
| 3.4 | | | | | | |

> **Common reason codes** — `FileCreate`, `DataExtend`, `DataOverwrite`, `RenameNewName`, `RenameOldName`, `FileDelete`, `Close`. A sequence like `FileCreate` → `DataExtend` → `Close` → `Rename*` → `FileDelete` for the same `EntryNumber` is the canonical "download → stage → execute → cleanup" pattern.

---

## Category 4 — Path Anomalies

> Suspicious paths that warrant follow-up regardless of timestamps.

| # | Path Pattern | Why It's Suspicious | File(s) Matched | Notes |
|---|---|---|---|---|
| 4.1 | `\Users\*\AppData\Local\Temp\*.exe` | Executables in user-writable Temp | | |
| 4.2 | `\ProgramData\*\*.exe` (recent) | Recent writes to a system-managed path | | |
| 4.3 | `\Windows\Tasks\*` (recent) | Scheduled-task drop locations | | |
| 4.4 | `\$Recycle.Bin\*` (recent, executable) | Hidden-in-plain-sight execution | | |
| 4.5 | *(add)* | | | |

---

## Category 5 — Alternate Data Streams and Zone Identifiers

> Files with non-default streams or Mark-of-the-Web context.

| # | File | Stream Name | Zone | Source URL (if present) | Notes |
|---|---|---|---|---|---|
| 5.1 | | `Zone.Identifier` | | | |
| 5.2 | | | | | |
| 5.3 | | | | | |

---

## Category 6 — Cross-Source Corroboration

> Every NTFS finding should ideally line up with at least one other artifact source. This is where Lab 04's NTFS evidence connects to Labs 05–10.

| # | NTFS Finding | Corroborating Source | Specific Row / Field | Aligned in Time? | Confidence |
|---|---|---|---|---|---|
| 6.1 | | Prefetch | | | |
| 6.2 | | Amcache | | | |
| 6.3 | | Security 4688 | | | |
| 6.4 | | USN | | | |
| 6.5 | | Registry | | | |

Confidence ratings:
- **HIGH** — ≥ 2 independent sources agree on the same file at the same timestamp
- **MEDIUM** — single reliable source
- **LOW** — indirect signal, or single low-confidence source

---

## Category 7 — Evidence Gaps

> Document the negative space honestly.

| # | What's Missing | Why It Matters | Did You Try to Recover? | Notes |
|---|---|---|---|---|
| 7.1 | | | | |
| 7.2 | | | | |

---

## Wrap-up

**Most important NTFS finding for this case:**
___________________________

**One sentence that summarizes the NTFS evidence for the case summary:**
___________________________

**Items to escalate to the timeline (Lab 10):**
1.
2.
3.

---

*NTFS Observation Matrix — Windows Forensics for Beginners. Copy into your case folder; update the master when you discover a new pattern.*
