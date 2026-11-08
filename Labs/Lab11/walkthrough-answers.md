# Lab 11 — Hands-On Walkthrough Sample Answers

*Sample answers for the Hands-On Walkthrough section of `Labs/Lab11/ReadMe.md`. These are reference answers. Your filter, environment, and tool version may legitimately produce slightly different values, and the interpretation matters more than the exact number.*

---

## Step 1 — Read the target hashes

**Expected output:** Three legal-provided SHA-256 reference hashes:

| File | SHA-256 |
|---|---|
| `Q4_Customer_Pricing.xlsx` | `7a4b8c12d3e5f6789012345678901234567890abcdef1234567890abcdef1234` |
| `Pricing_Strategy_Confidential.docx` | `9b9cdc69c1c24e2b3142a4b5d6e7f8901234567890abcdef1234567890abcdef` |
| `Margins_Q3.xlsx` | `12dc1ea8e34b6a0b8b2c1a4f8b3d4e5f67890abcdef1234567890abcdef12345` |

**Verified via:** `cat Data/HR-WS17/pricing-files-known-hashes.txt`

**Interpretation:** These are the ground-truth hashes for comparing any candidate file you recover during the investigation. A match is strong evidence that the file is one of the legal-target documents. A non-match does not exonerate, because files may have been re-saved, edited, archived, or compressed. The embedded note in the hash file is explicit on this point.

---

## Step 2 — Confirm staging activity in MFT and USN

**Expected output:** **10 `FileDelete` rows** in `usn-journal.csv`. The full list, sorted by `UpdateTimestamp`:

| Timestamp | FileName | ParentPath |
|---|---|---|
| 17:55:11 | Q4_Customer_Pricing.xlsx | Users\hr-user\AppData\Local\Temp |
| 17:55:11 | Pricing_Strategy_Confidential.docx | Users\hr-user\AppData\Local\Temp |
| 17:55:11.5 | Q4_Customer_Pricing.xlsx | Users\hr-user\AppData\Local\Temp |
| 17:55:11.5 | Pricing_Strategy_Confidential.docx | Users\hr-user\AppData\Local\Temp |
| 17:55:48 | ~$Q4_Customer_Pricing.xlsx | Users\hr-user\AppData\Local\Temp |
| 17:57:42 | Q4_Customer_Pricing.xlsx | HR\Pricing |
| 17:57:42 | Pricing_Strategy_Confidential.docx | HR\Pricing |
| 17:57:42 | Margins_Q3.xlsx | HR\Pricing |
| 17:57:42 | Pricing | HR |
| 17:57:42.5 | HR | . |

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/HR-WS17/usn-journal.csv'))); [print(r['UpdateTimestamp'], r['FileName'], r['ParentPath']) for r in sorted([r for r in rows if 'FileDelete' in r['UpdateReasons']], key=lambda x: x['UpdateTimestamp'])]"`

**Interpretation:** The deletions come in two separate cleanup waves. The staging copies in `\Temp` go first at 17:55, then the original `HR\Pricing` directory itself plus the three target files at 17:57:42. The 17:55 deletions match the OneDrive-client log "outside sync root" warnings exactly (Step 8). All three legal-target files (`Q4_Customer_Pricing.xlsx`, `Pricing_Strategy_Confidential.docx`, `Margins_Q3.xlsx`) appear in the 17:57:42 batch, which confirms the files existed on the host. The deletion of the parent folders (`HR`, `HR\Pricing`) is itself a defensive-cleanup signal.

---

## Step 3 — Profile the Kingston USB

**Expected output:** **2 Kingston rows** in `usbstor.csv`. The case-relevant one:

- SerialNumber `001A92053B7CBE3196B40A0F`
- FirstConnected `2024-11-12 17:42:08`
- LastRemovalTime `2024-11-12 17:58:30`
- VolumeGuid `{f1d2e9a4-77c0-4b91-83be-ab4a0ed1c6e5}`

Connection duration: **16 minutes 22 seconds**. The device was attached from 17:42:08 to 17:58:30, which exactly frames the 17:55–17:57 deletion window from Step 2.

The other Kingston (serial `001A92038A1FAE6132B40A0F`) was last connected 2024-10-21. It predates the incident and is not relevant.

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/HR-WS17/usbstor.csv'))); [print(r['SerialNumber'], r['FirstConnected'], r['LastRemovalTime'], r['VolumeGuid']) for r in rows if 'Kingston' in r['FriendlyName']]"`

**Interpretation:** The device window (17:42:08 – 17:58:30) is the exfiltration envelope. The volume GUID `{f1d2e9a4-77c0-4b91-83be-ab4a0ed1c6e5}` is the *same* as the device in the HR-LT12 dataset (Lab 05). In a real investigation, that would be a multi-host correlation finding. Within this lab, the two scenarios are independent, so treat the GUID match as a curriculum convenience, not evidence that links the two cases.

---

## Step 4 — Confirm the user browsed sensitive folders on the USB

**Expected output:** **3 shellbag rows** under `E:\Confidential`:

| AbsolutePath | FirstInteracted |
|---|---|
| `E:\Confidential` | 2024-11-12 17:43:11 |
| `E:\Confidential\Pricing` | 2024-11-12 17:43:42 |
| `E:\Confidential\HR` | 2024-11-12 17:43:42 |

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/HR-WS17/shellbags.csv'))); [print(r['AbsolutePath'], r['FirstInteracted']) for r in rows if 'E:\\\\Confidential' in r['AbsolutePath']]"`

**Interpretation:** The user navigated *into* `E:\Confidential\Pricing\`, the pricing folder named in the legal request. The `FirstInteracted` timestamps (17:43:11 – 17:43:42) fall about a minute after the USB was connected (17:42:08). Shellbags persist after the USB is removed, so this evidence remains intact even though the device is gone. The `E:\Confidential\HR` row at the same second as `\Pricing` indicates the user opened both sibling folders.

---

## Step 5 — Bind LNK files to the Kingston volume

**Expected output:** **3 LNK rows** with `VolumeSerialNumber=F1D2E9A4`:

| SourceFile | LocalPath | TargetModified |
|---|---|---|
| `...\Recent\Q4_Customer_Pricing (E).lnk` | `E:\Confidential\Pricing\Q4_Customer_Pricing.xlsx` | 2024-11-12 17:44:18 |
| `...\Recent\Pricing_Strategy_Confidential (E).lnk` | `E:\Confidential\Pricing\Pricing_Strategy_Confidential.docx` | 2024-11-12 17:44:55 |
| `...\Recent\Margins_Q3 (E).lnk` | `E:\Confidential\Pricing\Margins_Q3.xlsx` | 2024-11-12 17:45:32 |

**Verified via:** `python3 -c "import csv; rows=list(csv.DictReader(open('Data/HR-WS17/lnk-files.csv'))); [print(r['SourceFile'], r['LocalPath'], r['TargetModified']) for r in rows if r['VolumeSerialNumber']=='F1D2E9A4']"`

**Interpretation:** All three legal-target files were opened from the Kingston volume between 17:44:18 and 17:45:32, barely a minute after the user navigated into `E:\Confidential\Pricing\` (Step 4). The "(E)" suffix in the LNK filenames is a Windows convention for showing the drive letter of the target. Volume serial `F1D2E9A4` ties directly to the Kingston `{f1d2e9a4-...}` GUID from Step 3. Together, USBSTOR, shellbags, and LNK give the USB exfiltration channel three independent corroborating sources.

---

## Step 6 — Identify the personal OneDrive account

**Expected output:** **2 accounts** in `onedrive-accounts.csv`:

| AccountName | AccountType | UserEmail | FirstAdded | LastSignIn |
|---|---|---|---|---|
| Business1 | OneDriveForBusiness | hr-user@finance.example.com | 2024-08-19 14:11:14 | 2024-11-12 08:42:54 |
| Personal | OneDrivePersonal | hr.user.personal@outlook.com | **2024-11-12 17:46:02** | **2024-11-12 17:46:02** |

**Verified via:** `python3 -c "import csv; [print(r['AccountName'], r['AccountType'], r['UserEmail'], r['FirstAdded'], r['LastSignIn']) for r in csv.DictReader(open('Data/HR-WS17/onedrive-accounts.csv'))]"`

**Interpretation:** The Personal account was *first added* and *first signed in* at 17:46:02, 30 seconds after the user finished opening the three pricing files from the USB (Step 5). The corporate account was last signed in earlier the same day at 08:42:54, when its client started shortly after the 08:42:11 logon, which is normal start-of-day behavior. The Personal account is brand new on this host and active inside the incident window. The embedded `Notes` field flags this as "first signed in inside the incident window." Adding a personal Microsoft account on a managed corporate laptop minutes after browsing legal-target pricing files is the conduct that turns this from a policy concern into a forensic finding.

---

## Step 7 — Confirm pricing files synced to the personal account

**Expected output:** **2 rows** in `onedrive-syncdb.csv`:

| FileName | FileSize | UploadCompletedUtc | Sha256ContentHash |
|---|---|---|---|
| Q4_Customer_Pricing.xlsx | 1842184 | 2024-11-12 17:47:18 | `7a4b8c12d3e5f6789012345678901234567890abcdef1234567890abcdef1234` |
| Pricing_Strategy_Confidential.docx | 1248421 | 2024-11-12 17:49:18 | `9b9cdc69c1c24e2b3142a4b5d6e7f8901234567890abcdef1234567890abcdef` |

**Both `Sha256ContentHash` values match the legal-provided hashes from Step 1 byte-for-byte.**

**Verified via:** `python3 -c "import csv; [print(r['FileName'], r['FileSize'], r['UploadCompletedUtc'], r['Sha256ContentHash']) for r in csv.DictReader(open('Data/HR-WS17/onedrive-syncdb.csv'))]"` and compare against `Data/HR-WS17/pricing-files-known-hashes.txt`.

**Interpretation:** This is the moment the case becomes prosecutable. The Personal OneDrive sync database records two synced pricing files, and their SHA-256 hashes match the canonical pricing data legal asked about. `Margins_Q3.xlsx`, which appears in the legal hash list, is *not* in the sync database. Only two of the three target files crossed via OneDrive, even though all three were opened from the USB (Step 5). Whether the third file left by any channel besides USB remains an open question.

---

## Step 8 — Cross-check the OneDrive client log

**Expected output:** OneDrive client log entries showing chunked uploads for both pricing files between 17:46 and 17:49 UTC:

```
2024-11-12T17:46:42.184Z [INF] [FileWatcher] LocalChange detected: ...\Pricing-Backup\Q4_Customer_Pricing.xlsx created (size=1842184)
2024-11-12T17:46:42.221Z [INF] [SyncEngine] File enqueued for upload: Q4_Customer_Pricing.xlsx
2024-11-12T17:46:42.318Z [INF] [Uploader] Beginning upload Q4_Customer_Pricing.xlsx
2024-11-12T17:47:18.418Z [INF] [Uploader] Upload complete Q4_Customer_Pricing.xlsx ItemId=01ABCDEF234567890ABCDEF1 SHA256=7a4b8c12d3e5f6789012345678901234567890abcdef1234567890abcdef1234
2024-11-12T17:48:41.214Z [INF] [FileWatcher] LocalChange detected: ...\Pricing-Backup\Pricing_Strategy_Confidential.docx created (size=1248421)
2024-11-12T17:48:41.244Z [INF] [SyncEngine] File enqueued for upload: Pricing_Strategy_Confidential.docx
2024-11-12T17:48:41.421Z [INF] [Uploader] Beginning upload Pricing_Strategy_Confidential.docx
2024-11-12T17:49:18.214Z [INF] [Uploader] Upload complete Pricing_Strategy_Confidential.docx ItemId=01ABCDEF234567890ABCDEF2 SHA256=9b9cdc69c1c24e2b3142a4b5d6e7f8901234567890abcdef1234567890abcdef
```

The upload SHA-256 in the client log matches the same hash in Step 1 (legal reference) and Step 7 (sync database): three independent sources, identical hashes.

**Verified via:** `grep -E "Q4_Customer_Pricing|Pricing_Strategy" Data/HR-WS17/onedrive-logs-extract.txt`

**Interpretation:** With the same SHA-256 in the legal-provided reference, the sync database, and the OneDrive client log, this finding is effectively unrebuttable. The client log also has two `[WRN] LocalChange detected outside sync root` lines at 17:55:18. Those are the Temp-folder deletions from Step 2, which the OneDrive client *saw and explicitly ignored* because it does not sync `\AppData\Local\Temp\`. They corroborate that the staging was in Temp and the upload came from the OneDrive sync root, two distinct directories.

---

## Step 9 — Look for the webmail upload (probable but unconfirmed channel)

**Expected output:** **4 rows** for `outlook.live`:

| VisitTime | Url | Title |
|---|---|---|
| 17:51:04 | `https://outlook.live.com/mail/0/` | Mail - hr.user.personal@outlook.com - Outlook |
| 17:52:11 | `https://outlook.live.com/mail/0/deeplink/compose` | New message - Outlook |
| 17:54:42 | `https://outlook.live.com/mail/0/sentitems` | Sent Items - Outlook |
| 17:55:48 | `https://outlook.live.com/mail/0/` | Mail - hr.user.personal@outlook.com - Outlook |

**Verified via:** `python3 -c "import csv; [print(r['VisitTime'], r['Url'], r['Title']) for r in csv.DictReader(open('Data/HR-WS17/browser-history.csv')) if 'outlook.live' in r['Url'].lower()]"`

**Interpretation:** The rows form a webmail-send chain from the *same personal account* used in OneDrive (Step 6): inbox -> compose -> sent items -> back to inbox. This four-step user journey is consistent with composing and sending a single message with attachments. The host artifacts cannot prove an attachment crossed, because that would require provider-side data from Microsoft. Document this as "probable channel" rather than confirmed. The third pricing file, `Margins_Q3.xlsx`, is a candidate for this channel. It is present in the LNK evidence but missing from the OneDrive sync database.

---

## Step 10 — Build the channel-analysis table

**Expected output:** The capstone deliverable table consolidating Steps 2–9:

| Channel | Result | Evidence |
|---|---|---|
| **USB (Kingston `001A92053B7CBE3196B40A0F`)** | Confirmed | USBSTOR + MountedDevices + 3 shellbag rows under `E:\Confidential` (one of them `E:\Confidential\Pricing`) + 3 LNK files with matching volume serial — all three legal-target files opened from the device |
| **Personal OneDrive (`hr.user.personal@outlook.com`)** | Confirmed | Accounts registry first-add at 17:46:02 + sync database (2 files) + OneDrive client log (2 uploads); SHA-256 matches legal reference for **2 of 3** target files (`Q4_Customer_Pricing.xlsx`, `Pricing_Strategy_Confidential.docx`) |
| **Webmail (Outlook.com)** | Probable, unverified from host | Browser history shows compose -> send -> sent-items chain at 17:51–17:54 from the same personal account; attachment content not recoverable from host artifacts alone — would require cooperation with the email provider. Candidate channel for the third file (`Margins_Q3.xlsx`). |
| **Local mail client / Bluetooth / print** | Ruled out | No evidence of mail-client send activity, no Bluetooth file transfer artifacts, no unusual print activity in the artifact set |

**Verified via:** Composition of Steps 2–9 above.

**Interpretation:** A defensible exfiltration finding has this structure: two confirmed channels (USB and Personal OneDrive), one probable-but-host-unverified channel (webmail), and several explicitly ruled-out channels. Of the three legal-target files, two are positively matched by hash via OneDrive, and all three were opened from the USB. One, `Margins_Q3.xlsx`, is accounted for only by the USB channel. It is a candidate for the webmail channel, but no host artifact ties it there. The Task 12 summary deliverable follows directly from this table.

---

## Summary

The walkthrough takes 10 reproducible steps across every artifact category in the book. It hash-matches **two of the three** pricing files against the legal-provided reference through three independent sources. The third, `Margins_Q3.xlsx`, is absent from every cloud artifact and travelled by USB alone:

| Step | Source | Finding |
|---|---|---|
| 1 | Reference | 3 SHA-256 hashes from Legal |
| 2 | USN journal | 10 FileDelete events (Temp + HR\Pricing cleanup) |
| 3 | USBSTOR | Kingston attached 17:42:08 – 17:58:30 (16 min) |
| 4 | Shellbags | User browsed `E:\Confidential\Pricing\` |
| 5 | LNK | All 3 target files opened from Kingston volume |
| 6 | OneDrive accounts | Personal account first signed in at 17:46:02 |
| 7 | OneDrive sync DB | 2 of 3 target files synced; hashes match |
| 8 | OneDrive client log | Chunked upload trace + matching SHA-256 |
| 9 | Browser history | Webmail compose/send chain at 17:51–17:54 |
| 10 | Channel table | 2 confirmed, 1 probable, others ruled out |
