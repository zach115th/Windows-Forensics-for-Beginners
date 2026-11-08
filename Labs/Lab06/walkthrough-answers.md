# Lab 06 — Hands-On Walkthrough Sample Answers

*Sample answers for the Hands-On Walkthrough section of `Labs/Lab06/ReadMe.md`. These are reference answers — your filter, your environment, and your tool version may legitimately produce slightly different values. The interpretation matters more than the exact number.*

---

## Step 1 — Find the suspicious binary in Prefetch

**Expected output:** Sorting all 21 Prefetch rows by `LastRun` ascending, the only single-run entry of interest is `DL.EXE` — `RunCount=1`, `LastRun=2024-11-13 06:59:14`, `Hash=7C81B3A4`, `FilesCount=32`. The first five rows by `LastRun` are routine system binaries (`NOTEPAD.EXE`, `WINLOGON.EXE`, `SVCHOST.EXE`, `USERINIT.EXE`, `SEARCHFILTERHOST.EXE`) — `DL.EXE` is the standout when scanned for `RunCount=1`.

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/FIN-WS23/prefetch.csv'))); [print(r['ExecutableName'], r['RunCount'], r['LastRun']) for r in rows if r['RunCount']=='1']"`

**Interpretation:** A single-run binary in Prefetch with a recent `LastRun` is one of the cleanest "this is new on this host" signals. The 06:59:14 timestamp lands about 27 minutes after a phishing-newsletter visit (Step 7) and 74 seconds after the macro-enabled document was opened (Step 3). The timing alone is enough to escalate.

---

## Step 2 — Pull the binary's hash from Amcache

**Expected output:** **1 row** — `FullPath=C:\Users\j.smith\Downloads\dl.exe`, `FileSize=142336`, `Sha1=b8e3f4d12a89c4e5670123456789abcdef0123ab`, `Sha256=7c1a4f8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567`, `Created=2024-11-13 06:59:08`, `LastModified=2024-11-13 06:59:08.5`, `Compiled=2024-11-12 02:14:00`, `IsPeFile=True`, `BinaryType=pe64bit`, `ProductName=Downloader`, `Publisher=` (empty).

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/FIN-WS23/amcache.csv'))); [print(r) for r in rows if 'dl.exe' in r['FullPath'].lower()]"`

**Interpretation:** The user-profile `Downloads` path tells you the binary was downloaded, not installed. An empty `Publisher` and a generic `ProductName=Downloader` are both unsigned-binary tells. Submit the SHA-256 to threat intel. The compile timestamp from the day before (2024-11-12 02:14 UTC) is the threat-actor build date, which is useful for cross-host hunting.

---

## Step 3 — Confirm the parent process via Jump Lists

**Expected output:** **4 rows** for `Microsoft Word`:

| EntryNumber | LastModified | LocalPath |
|---|---|---|
| 1 | 2024-11-13 06:58:00 | C:\Users\j.smith\Downloads\Q4_Vendor_Review.docm |
| 2 | 2024-11-12 14:22:18 | C:\Users\j.smith\Documents\Q3_Close_Notes.docx |
| 3 | 2024-11-04 09:00:00 | C:\Users\j.smith\Documents\Expense_Policy.docx |
| 4 | 2024-11-13 09:16:42 | F:\Vendors\Confidential\Bank_Account_Notes.docx |

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/FIN-WS23/jump-lists.csv'))); [print(r['EntryNumber'], r['LastModified'], r['LocalPath']) for r in rows if r['AppDescription']=='Microsoft Word']"`

**Interpretation:** Entry 1 is `Q4_Vendor_Review.docm`, the macro-enabled file the user opened at 06:58:00, **74 seconds before** `DL.EXE` ran. The `.docm` extension carries macros, and the timing strongly suggests the delivery chain Word -> macro -> shell -> loader. Entry 4 (`F:\Vendors\Confidential\Bank_Account_Notes.docx` at 09:16:42) is later access from the SanDisk USB, which Steps 4–6 examine.

---

## Step 4 — Profile the SanDisk USB

**Expected output:** **1 SanDisk row** — `SanDisk Cruzer Glide USB Device`, `SerialNumber=4C530001190405104544`, `FirstConnected=LastConnected=2024-11-13 09:14:08`, `VolumeGuid={b4d722a1-1142-11ef-8a4f-0c9d92841421}`. Single-day, single-connection device.

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/FIN-WS23/usbstor.csv'))); [print(r['FriendlyName'], r['SerialNumber'], r['FirstConnected'], r['LastConnected']) for r in rows if 'SanDisk' in r['FriendlyName']]"`

**Interpretation:** A single-connection USB is the same one-off-device pattern you saw in Lab 05 with the Kingston DataTraveler. Carry the volume GUID `{b4d722a1-1142-11ef-8a4f-0c9d92841421}` forward to Step 5. Its first eight hex digits match the LNK volume serial `B4D7-22A1` only because the dataset is simulated. Real volume GUIDs and volume serials are unrelated, so do not bind on that match.

---

## Step 5 — Bind the USB volume serial to LNK files

**Expected output:** **2 LNK rows** with `VolumeSerialNumber=B4D7-22A1`:

| SourceFile | LocalPath | TargetModified |
|---|---|---|
| `C:\Users\j.smith\AppData\Roaming\Microsoft\Windows\Recent\Vendor_Confidential_Roster.lnk` | `F:\Vendors\Confidential\Vendor_Confidential_Roster.xlsx` | 2024-10-22 16:42:00 |
| `C:\Users\j.smith\AppData\Roaming\Microsoft\Windows\Recent\Bank_Account_Notes.lnk` | `F:\Vendors\Confidential\Bank_Account_Notes.docx` | 2024-09-04 14:22:00 |

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/FIN-WS23/lnk-files.csv'))); [print(r['SourceFile'], r['LocalPath'], r['TargetModified']) for r in rows if r['VolumeSerialNumber']=='B4D7-22A1']"`

**Interpretation:** The volume serial `B4D7-22A1`, label `CRUZER`, and drive type `RemovableMedia` place both files on the `F:` volume. They do not name the device. A volume serial is a file-system value assigned at format time, and it is unrelated to the USBSTOR device serial (Chapter 6 §6.5.1). The volume binds to the device through a separate chain. System EID 98 at 09:14:12 records volume `{b4d722a1-1142-11ef-8a4f-0c9d92841421}` as `F:`, and `usbstor.csv` assigns that GUID to SanDisk serial `4C530001190405104544`. The LNKs were created at 09:16:18 and 09:16:42, inside the 09:14:08–09:24:47 connection window. The dataset has no `MountedDevices` export, so the chain is partial. Pull `MountedDevices` from the `SYSTEM` hive to complete it. Windows generated these two LNKs *on this host* when the user opened those two specific files on the USB. They are direct evidence of file-open activity from the device, not just navigation. The `TargetModified` dates in September and October 2024 record when the source files on the USB were last modified, not when the user opened them on FIN-WS23.

---

## Step 6 — Confirm folder navigation on the USB

**Expected output:** **4 rows** with `AbsolutePath` starting with `F:`:

| AbsolutePath | FirstInteracted | LastInteracted |
|---|---|---|
| `F:\` | 2024-11-13 09:14:21 | 2024-11-13 09:24:47 |
| `F:\Vendors` | 2024-11-13 09:14:42 | 2024-11-13 09:15:32 |
| `F:\Vendors\Confidential` | 2024-11-13 09:15:32 | 2024-11-13 09:16:42 |
| `F:\Personal` | 2024-11-13 09:14:42 | 2024-11-13 09:14:55 |

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/FIN-WS23/shellbags.csv'))); [print(r['AbsolutePath'], r['FirstInteracted'], r['LastInteracted']) for r in rows if r['AbsolutePath'].startswith('F:')]"`

**Interpretation:** Three shellbags trace the path to the confidential folder (`F:\`, `F:\Vendors`, `F:\Vendors\Confidential`), and a fourth records a brief detour into `F:\Personal`. All four are timestamped within the 09:14–09:25 USB connection window. The first `F:\` interaction, at 09:14:21, comes nine seconds after System EID 98 reports the volume as `F:` at 09:14:12, as it must: Explorer cannot browse a volume before it is mounted. Shellbags survive after the USB is removed, so this evidence remains intact. The three paths to the confidential folder meet the walkthrough's "at least 3 rows" minimum, and the fourth (`F:\Personal`) is bonus context.

---

## Step 7 — Look for the delivery vector in browser history

**Expected output:** **2 rows** for `finance-news-daily`:

| VisitTime | URL | Transition |
|---|---|---|
| 2024-11-13 06:31:42 | `https://finance-news-daily.example.com/2024/11/q4-vendor-roundup` | link |
| 2024-11-13 06:32:18 | `https://finance-news-daily.example.com/download?file=Q4_Vendor_Review.docm&id=8841ab` | link |

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/FIN-WS23/browser-history.csv'))); [print(r['VisitTime'], r['URL'], r['Transition']) for r in rows if 'finance-news-daily' in r['URL']]"`

**Interpretation:** The user made a two-step journey: the landing page first, then a `download?file=Q4_Vendor_Review.docm` URL 36 seconds later. The `Transition=link` value indicates the user clicked into both pages rather than typing the URLs. The download URL's filename matches the document opened at 06:58 in Step 3, which is the document that triggered `DL.EXE` at 06:59. That's the full delivery chain: phishing page (06:31) -> document download (06:32) -> document open and macro execution (06:58) -> loader run (06:59).

---

## Summary

Seven independent shell, device, and browser sources each point to a different step of the same incident:

| Step | Source | Finding |
|---|---|---|
| 1 | Prefetch | `DL.EXE` first run at 06:59:14 |
| 2 | Amcache | SHA-256 hash + user-profile path + empty publisher |
| 3 | Jump Lists | `Q4_Vendor_Review.docm` opened at 06:58:00 (one minute before DL.EXE) |
| 4 | USBSTOR | Single-connection SanDisk Cruzer Glide |
| 5 | LNK files | Two confidential files opened from the USB |
| 6 | Shellbags | Confidential folder navigation on `F:\Vendors\Confidential\` |
| 7 | Browser history | Phishing landing -> document download chain |

The host shows two suspicious activities on the same morning: a malware-delivery chain starting at 06:31 on 2024-11-13, and USB-mediated access to confidential files about two hours later, at 09:14. Each chain is independently defensible, and together they make the case for FIN-WS23.
