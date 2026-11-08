# HR-LT12 — Simulated Triage Dataset

Anchor scenario for Lab 05 (Windows Registry and Cloud Storage Forensics). Used to practice persistence triage, USB history reconstruction, shellbag interpretation, and OneDrive sync-database analysis from a Windows endpoint.

## Scenario

`HR-LT12` is an HR department laptop assigned to user `hr-user` (domain `FINANCE`). The host stores sensitive personnel and compensation files. On **2024-11-13**, a manager reported that the laptop "felt slow at startup" and that an HR colleague had seen a Q4 salary spreadsheet appear on a personal device that was never authorized to receive it. The SOC initiated a triage collection.

Three threads of activity are present in the data:

- **Persistence (2024-11-08 19:06 UTC).** A new `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value named `HpHotkeyMonitor` was written, pointing at `C:\Users\hr-user\AppData\Local\hp-hotkey\hpkey.exe`. The path imitates a legitimate HP utility but lives entirely under the user-writable AppData tree.
- **Removable media (2024-11-12 16:42 UTC).** A Kingston DataTraveler USB stick (VID `0951`, PID `1666`, serial `001A92053B7CBE3196B40A0F`) was first installed on the host, mounted as `E:`, and used to browse `E:\HR\Confidential\` and subfolders. The same volume was last removed at 17:31 UTC the same day.
- **OneDrive personal account (2024-11-12 16:55–17:10 UTC).** A second OneDrive account (`hr.user.personal@outlook.com`) appears alongside the corporate `hr-user@finance.example.com` account. The personal account's sync database records eight HR files entering its sync queue inside the incident window.

The earlier part of 2024-11-12 contains normal HR activity — Outlook, Edge, an Excel file open from the corporate OneDrive — that should not be confused with the incident.

## Key timestamps (UTC)

| Time | Event | Source artifact |
|---|---|---|
| 2024-11-08 19:06:42 | `HpHotkeyMonitor` Run value created under HKCU | `registry-runkeys.csv` |
| 2024-11-08 19:06:51 | `hpkey.exe` written to `AppData\Local\hp-hotkey\` | (correlate with MFT/USN if collected) |
| 2024-11-12 09:14:00 | Normal-day Outlook + Edge activity begins | (background noise) |
| 2024-11-12 16:42:08 | Kingston DataTraveler first installation | `setupapi-dev-log.txt`, `usbstor.csv` |
| 2024-11-12 16:42:14 | Volume `{f1d2e9a4-...}` bound to drive `E:` | `mountpoints.csv` |
| 2024-11-12 16:43:11 | `E:\HR\Confidential\` first interacted (shellbag) | `shellbags.csv` |
| 2024-11-12 16:44:02 | `E:\HR\Confidential\Salary_Data\` first interacted | `shellbags.csv` |
| 2024-11-12 16:55:18 | First file enters Personal OneDrive sync queue | `onedrive-syncdb.csv` |
| 2024-11-12 17:09:47 | Last file in personal-OneDrive sync window | `onedrive-syncdb.csv` |
| 2024-11-12 17:31:02 | Kingston DataTraveler removed | `usbstor.csv` |

## Files

| File | Description | Rows |
|---|---|---|
| `registry-runkeys.csv` | `Run` / `RunOnce` values across HKLM and HKCU, including the `HpHotkeyMonitor` persistence | 16 |
| `registry-services.csv` | Service definitions from `HKLM\SYSTEM\CurrentControlSet\Services` | 23 |
| `usbstor.csv` | `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` device history | ~7 |
| `mountpoints.csv` | `HKLM\SYSTEM\MountedDevices` volume GUID → drive letter mappings | ~11 |
| `shellbags.csv` | Shellbag entries from `UsrClass.dat` for `hr-user` | ~18 |
| `onedrive-accounts.csv` | `HKCU\Software\Microsoft\OneDrive\Accounts` for both Business1 and Personal | 2 |
| `onedrive-syncdb.csv` | Rows from the Personal account's `<UserCid>SyncEngineDatabase.db` for the incident window | 8 |
| `setupapi-dev-log.txt` | Plaintext extract from `%SystemRoot%\INF\setupapi.dev.log` covering the Kingston install | 71 lines |
| `security-evtx.csv` | Parsed Security event log — logons, process creation around the persistence write and the USB session, EID 6416 for the new external device | 32 |
| `system-evtx.csv` | Parsed System event log — PnP driver install (EID 219 / 20001 / 20003), volume-healthy for `E:`, service state changes | 22 |

## What you will and won't find

The dataset is curated, not exhaustive. It contains:

- A clear (but not screaming) Run-key persistence under `hr-user`'s NTUSER.DAT
- USB history with one device that aligns to the incident window and several earlier benign devices
- Mounted-device mappings sufficient to bind the suspect volume to drive `E:` at the right moment
- Shellbag entries that show the user navigated into HR-confidential folders on the USB
- Two OneDrive accounts in registry export form, with sync-db rows for the personal account only

It does not contain:

- An MFT, USN journal, or Prefetch export — Lab 05 is registry-and-cloud focused, so those collections are intentionally out of scope here. Cross-correlation with those sources is left as a "what would you collect next" exercise in Lab 5.4.
- Provider-side OneDrive audit logs. The `onedrive-syncdb.csv` represents what is recoverable from the local SQLite database, not what the cloud tenant would show.
- A memory image. The `WEB-APP-03/` dataset is the intended source for memory-based exercises.

## Tooling assumptions

The CSVs are formatted to match what an analyst would have after running:

- [`RECmd`](https://ericzimmerman.github.io/) (or `Registry Explorer`) over the collected hives for the registry exports
- [`SBECmd`](https://ericzimmerman.github.io/) for the shellbag CSV
- DB Browser for SQLite (or a Python script) over the OneDrive `SyncEngineDatabase.db`
- Direct text extraction from `%SystemRoot%\INF\setupapi.dev.log`

## Note on the event logs

`security-evtx.csv` and `system-evtx.csv` use the exact column layout of
`Data/WKSTN-221/security-evtx.csv` and `system-evtx.csv`, so exports from the
two hosts can be concatenated into a single timeline without reconciling
schemas.

They are here to let you *corroborate* the registry findings, not to replace
them. Three things are deliberate:

- The `reg.exe add` process-creation event at **2024-11-08 19:06:42** carries
  the same value name, the same data, and the same second as the
  `HpHotkeyMonitor` row in `registry-runkeys.csv`. The EID 4657 immediately
  after it is the registry-audit view of the same write. Two independent
  witnesses to one action.
- **`hpkey.exe` never appears as an EID 4688 — anywhere.** Not at the
  2024-11-11 logon, not at the 2024-11-12 logon, not once. The Run value
  exists; there is no execution evidence for it in this log. That absence is
  the whole point of Lab 5.2 Task 6: "the value is present" and "the malware
  ran at every logon" are different claims, and only the first one is
  supported here. Do not add an execution event to "complete" the story.
- The USB events (EID 4688 for `drvinst.exe`, EID 6416 "a new external device
  was recognized") land on the same second as the USBSTOR install time, and
  the System log's EID 219 / 20001 / 20003 / 98 sequence covers 16:42:08 to
  16:42:14. With `setupapi-dev-log.txt` and `usbstor.csv` that is four sources
  agreeing on the device timeline — enough to call it confirmed.

## Note on the persistence value

The Run value name `HpHotkeyMonitor` is intentionally close to a legitimate HP utility name. Path context — `AppData\Local\hp-hotkey\hpkey.exe` rather than `Program Files\HP\...` — is what makes it suspicious. Lab 5.2 Task 6 ("Strong findings vs overclaims") exists in part to keep responders from collapsing "value exists" into "malware ran successfully at every logon."

## Note on registry `LastWriteTime`

`registry-runkeys.csv` reports **one `LastWriteTime` per key**, repeated on every
value row under that key. That is not a flattening artifact of the export — it is
how the registry works. `LastWriteTime` is a property of the **key**; individual
values carry no timestamp of their own.

The practical consequence, and the reason the column looks redundant: a recent
`LastWriteTime` tells you that *something* under the key changed, not *which*
value changed, and not what it changed from. You cannot date an individual Run
value from this column alone. To attribute a specific value to a specific time
you need a second source — registry transaction logs (`.LOG1` / `.LOG2`), a prior
copy of the hive from a Volume Shadow Copy, or a corroborating artifact such as
the MFT record of the binary the value points at.

Chapter 5 §5.1.2 covers the mechanism; Chapter 10 §10.5 covers the trap it sets
when you drop these rows into a timeline.

---

*Simulated HR-LT12 dataset — Windows Forensics for Beginners*
