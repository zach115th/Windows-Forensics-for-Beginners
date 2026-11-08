# Lab 05 — Hands-On Walkthrough Sample Answers

*Sample answers for the Hands-On Walkthrough section of `Labs/Lab05/ReadMe.md`. These are reference answers — your filter, your environment, and your tool version may legitimately produce slightly different values. The interpretation matters more than the exact number.*

---

## Step 1 — Find the persistence entry

**Expected output:** **1 row** — `HpHotkeyMonitor` under `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`, `ValueData=C:\Users\hr-user\AppData\Local\hp-hotkey\hpkey.exe`, `ValueType=RegSz`, `LastWriteTime=2024-11-08 19:06:42`. The CSV's existing `Notes` column already flags this row as suspicious because the name imitates an HP utility but the path is in user-writable AppData.

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/HR-LT12/registry-runkeys.csv'))); [print(r) for r in rows if 'AppData' in r['ValueData'] and 'Microsoft' not in r['ValueData']]"`

**Interpretation:** The CSV contains 16 Run-key rows total. The filter excludes the legitimate Microsoft-vendored `OneDrive` and `Teams` Run keys, which also live under AppData, and surfaces the third-party-looking entry that references no Microsoft path. Persistence that runs a non-Microsoft target from a user-profile path is almost never a legitimate vendor. The `LastWriteTime` of 2024-11-08 19:06:42 UTC places its installation four days before the suspected exfiltration window.

---

## Step 2 — Profile the Kingston USB

**Expected output:** **3 Kingston entries** in `usbstor.csv` (out of 7 total devices). The one matching the incident window is:

- SerialNumber `001A92053B7CBE3196B40A0F`
- FirstConnected = LastConnected = `2024-11-12 16:42:08` (single connection)
- VolumeGuid `{f1d2e9a4-77c0-4b91-83be-ab4a0ed1c6e5}`

The other two Kingston DataTravelers have earlier histories. `001A92038A1FAE6132B40A0F` was first connected on 2024-09-02 and last on 2024-10-21, the pattern of a device in regular use. `001A92038F1C4A1932B70B12` appears once, in a 40-minute session on 2024-08-15, so its `FirstConnected` and `LastConnected` are also identical.

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/HR-LT12/usbstor.csv'))); [print(r['SerialNumber'], r['FirstConnected'], r['LastConnected']) for r in rows if 'Kingston' in r['FriendlyName']]"`

**Interpretation:** A single-connection USB whose `FirstConnected` equals `LastConnected` is characteristic of an attacker-supplied or one-off drive — exactly what you'd expect for an exfiltration-grade USB. The September–October Kingston shows a recurring-use pattern consistent with a legitimate user device. The August Kingston was also a one-off, but three months before the incident window. Single-connection status narrows the field, and timing picks out the 2024-11-12 device as the case-relevant one. Hold on to the volume GUID for the next step.

---

## Step 3 — Bind the volume GUID to a drive letter

**Expected output:** **1 row** — `\DosDevices\E:` bound to volume `{f1d2e9a4-77c0-4b91-83be-ab4a0ed1c6e5}`, `DriveLetter=E:`, `DeviceType=RemovableMedia`, `LinkedDeviceInstanceId=USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler_3.0\001A92053B7CBE3196B40A0F`, `LastWriteTime=2024-11-12 16:42:14`.

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/HR-LT12/mountpoints.csv'))); [print(r) for r in rows if r['VolumeGuid']=='{f1d2e9a4-77c0-4b91-83be-ab4a0ed1c6e5}']"`

**Interpretation:** This row binds the Kingston device from Step 2 to drive letter `E:` six seconds after the USBSTOR enumeration. The `LinkedDeviceInstanceId` carries the same serial number, which conclusively binds the device record to the drive letter the user saw in Explorer. From here, every shellbag, LNK, and Recent-item artifact under `E:\` traces back to this exact physical device.

---

## Step 4 — Confirm folder navigation on the USB

**Expected output:** **4 rows**:

| AbsolutePath | FirstInteracted | LastInteracted |
|---|---|---|
| `E:\HR` | 2024-11-12 16:43:02 | 2024-11-12 17:30:41 |
| `E:\HR\Confidential` | 2024-11-12 16:43:11 | 2024-11-12 17:28:09 |
| `E:\HR\Confidential\Salary_Data` | 2024-11-12 16:44:02 | 2024-11-12 17:08:55 |
| `E:\HR\Confidential\Personnel` | 2024-11-12 16:46:14 | 2024-11-12 17:02:18 |

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/HR-LT12/shellbags.csv'))); [print(r['AbsolutePath'], r['FirstInteracted'], r['LastInteracted']) for r in rows if r['AbsolutePath'].startswith('E:\\HR')]"`

**Interpretation:** All four shellbag paths fall within the 2024-11-12 16:42–17:31 UTC window — minutes after the Kingston was bound to `E:` in Step 3. Shellbags survive after the USB is removed. They are the most reliable single piece of evidence that the user, not just an automated process, browsed sensitive HR content on the device. The directory names alone (`Salary_Data`, `Personnel`) signal what the user was looking at.

---

## Step 5 — Identify the personal OneDrive account

**Expected output:** **2 rows** in `onedrive-accounts.csv`:

| AccountId | Email | LastWriteTime |
|---|---|---|
| Business1 | hr-user@finance.example.com | 2024-09-04 09:11:42 |
| Personal | hr.user.personal@outlook.com | 2024-11-12 16:51:33 |

The Business1 account points to a SharePoint endpoint (`finance-my.sharepoint.com`) and a tenant ID. The Personal account points to a consumer OneDrive endpoint (`d.docs.live.net`) and has no tenant. The `Personal` row's `LastWriteTime` (16:51:33 UTC) falls inside the 16:42–17:30 USB window from Steps 3–4.

**Verified via:** `python3 -c "import csv; [print(r['AccountId'], r['Email'], r['LastWriteTime']) for r in csv.DictReader(open('Data/HR-LT12/onedrive-accounts.csv'))]"`

**Interpretation:** A personal Microsoft account configured on a managed corporate laptop is itself worth following, regardless of whether anything was synced. The personal account's registry `LastWriteTime` falls inside the same window as the USB activity. That temporal alignment turns "policy violation" into "investigation lead."

---

## Step 6 — List files synchronized to the personal account

**Expected output:** **8 rows**, all with `SyncState=Synchronized`, all timestamped between 16:55 and 17:10 UTC on 2024-11-12:

| FileName | LastSync |
|---|---|
| Q4_Salary_Review.xlsx | 16:55:42 |
| Personnel_Roster.xlsx | 16:57:51 |
| Compensation_Bands_2024.xlsx | 17:00:38 |
| Severance_Calc_Q4.xlsx | 17:02:31 |
| Disciplinary_Cases_2024.docx | 17:04:39 |
| Org_Chart_Confidential.pdf | 17:07:08 |
| Bonus_Pool_FY25_Draft.xlsx | 17:08:34 |
| Exit_Interviews_2024.docx | 17:10:12 |

**Verified via:** `python3 -c "import csv; [print(r['FileName'], r['LastSync'], r['SyncState']) for r in csv.DictReader(open('Data/HR-LT12/onedrive-syncdb.csv'))]"`

**Interpretation:** All eight files match the HR-confidential subject matter of the folders browsed on the USB in Step 4. The 15-minute upload sequence (16:55 → 17:10) overlaps the USB attachment window. Combined with Step 5's personal-account identification, this is the cloud half of a possible two-channel finding. The sync queue shows HR files headed for the personal account, and Step 4 shows the same folders browsed on the USB. Neither artifact proves the files left the organization. The queue needs provider-side confirmation that the uploads completed, and browsing a folder is not copying it.

---

## Summary

Six registry, shell, and cloud sources. Five align to the **2024-11-12 16:42–17:31 UTC** window. The sixth, the Run key, was planted four days earlier:

| Step | Source | Finding |
|---|---|---|
| 1 | NTUSER.DAT Run key | `HpHotkeyMonitor` persistence pointing to user-AppData binary |
| 2 | USBSTOR | One-off Kingston DataTraveler (single connection) |
| 3 | MountedDevices | Kingston bound to `E:` |
| 4 | Shellbags | User browsed `E:\HR\Confidential\Salary_Data` and `\Personnel` |
| 5 | OneDrive accounts | Personal account `hr.user.personal@outlook.com` configured at 16:51:33 |
| 6 | OneDrive sync database | 8 HR-confidential files synced 16:55–17:10 |

These six findings are enough to populate every cell in the Tasks 2–6 analyst-notes scaffold. They also give Task 9's findings summary its capstone framing. Persistence was configured days earlier. On incident day, the user attached an unfamiliar USB, browsed sensitive folders on it, and within minutes signed in to a personal OneDrive account that synchronized eight HR-confidential documents.
