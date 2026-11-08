#!/usr/bin/env python3
"""Deterministic generator for the simulated HR-WS17 dataset.

Attack narrative
================
HR-WS17 is a Windows 10 HR/finance workstation belonging to user
``hr-user`` (``FINANCE\\hr-user``). The user is an HR analyst with
legitimate access to ``C:\\HR\\Pricing\\``, a folder containing three
files that legal has flagged as sensitive:

  * ``Q4_Customer_Pricing.xlsx``
    SHA-256 = ``7a4b8c12d3e5f6789012345678901234567890abcdef1234567890abcdef1234``
  * ``Pricing_Strategy_Confidential.docx``
    SHA-256 = ``9b9cdc69c1c24e2b3142a4b5d6e7f8901234567890abcdef1234567890abcdef``
  * ``Margins_Q3.xlsx``
    SHA-256 = ``12dc1ea8e34b6a0b8b2c1a4f8b3d4e5f67890abcdef1234567890abcdef12345``

On 2024-11-12 — the user's last day at the company — between 17:35 and
18:00 UTC, the user exfiltrates these files through two confirmed
channels and one probable channel:

  1. **USB (confirmed).** A Kingston DataTraveler 3.0 (serial
     ``001A92053B7CBE3196B40A0F``) is plugged in at 17:42:08 UTC. The
     volume is bound to drive ``E:`` with volume GUID
     ``{f1d2e9a4-77c0-4b91-83be-ab4a0ed1c6e5}`` and volume serial number
     ``F1D2E9A4``. The user navigates ``E:\\Confidential\\Pricing\\``
     (shellbags) and opens each pricing file from the USB path; LNKs
     are created in ``Recent\\`` carrying the USB volume serial number.
     The device is removed at 17:58:30.
  2. **Personal OneDrive (confirmed).** The user signs into a personal
     Microsoft account ``hr.user.personal@outlook.com`` at 17:46:02
     (first activation on the device). Two pricing files are uploaded
     into ``Pricing-Backup\\`` between 17:46:42 and 17:49:18; the local
     OneDrive sync database records ``UploadComplete`` rows with the
     legal-provided SHA-256 hashes, and the client log shows chunked
     upload progress.
  3. **Webmail (probable, not confirmed).** At 17:51:04 ``msedge.exe``
     navigates to ``https://outlook.live.com/mail/0/``, the user
     composes and sends a message, and signs out. SRUM shows outbound
     bytes for ``msedge.exe`` in the 18:00 bucket, but no specific
     upload payload is recoverable from the host.

The earlier part of 2024-11-12 contains normal HR-team activity —
Outlook, corporate SharePoint, several Excel files opened from local
and OneDrive-for-Business paths — that should not be confused with the
incident. Two transient copies of pricing files are also staged in
``%TEMP%\\`` at 17:39 and deleted at 17:55. The ``C:\\HR\\Pricing\\``
directory itself is deleted at 17:57:42 (cleanup activity is its own
evidence). The user logs off at 18:02:14 — the last session of their
employment.

This script regenerates every file under ``Data/HR-WS17/`` from the
above narrative. Hand-coded "key event" rows preserve the attack story;
filler "noise" rows fill out plausible volumes for the day. Output is
byte-identical across runs given the same ``RANDOM_SEED``.

The SHA-256 hashes in ``pricing-files-known-hashes.txt`` are
load-bearing: the same hash for ``Q4_Customer_Pricing.xlsx`` must
appear in ``onedrive-syncdb.csv`` and ``onedrive-logs-extract.txt``;
likewise for ``Pricing_Strategy_Confidential.docx``. ``Margins_Q3.xlsx``
appears only as a host-side hash reference (its USB copy was made but
it never reached OneDrive — that asymmetry is itself an analytical
point in Lab 11). If you change one of these hashes in this file, you
must change it everywhere or the Lab 11 walkthrough breaks.

Usage
=====
    python3 generate.py                     # write files in current dir
    python3 generate.py --dry-run           # print plan only
    python3 generate.py --out-dir /tmp/x    # write to scratch dir
"""

from __future__ import annotations

import argparse
import csv
import os
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Dict, List

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Fixed seed -> byte-identical output across runs. Spelled as a hex
# constant with the letters of "HRWS17" mapped to legal hex digits
# (H->8, R->2, W->0, S->5) so the seed reads "82057017". Override with
# --seed if you want a different stream.
RANDOM_SEED = 0x82057017

HOSTNAME = "HR-WS17"
FQDN = "HR-WS17.finance.local"
DOMAIN = "FINANCE"
USER = "hr-user"
USER_SID = "S-1-5-21-1234567890-1234567890-1234567890-1518"
SYSTEM_SID = "S-1-5-18"
WKSTN_IP = "10.0.4.51"          # used only in noise events
BACKUP_HOST = "BACKUP-SCHED"
BACKUP_IP = "10.0.4.42"

# Removable media (the suspect device).
USB_VENDOR_ID = "0951"
USB_PRODUCT_ID = "1666"
USB_REVISION = "0100"
USB_SERIAL = "001A92053B7CBE3196B40A0F"
USB_FRIENDLY = "Kingston DataTraveler 3.0 USB Device"
USB_VOL_GUID = "{f1d2e9a4-77c0-4b91-83be-ab4a0ed1c6e5}"
USB_VOL_SERIAL = "F1D2E9A4"
USB_VOL_LABEL = "KINGSTON"

# Fixed-disk volume (the system volume, where the pricing folder lives).
SYS_VOL_GUID = "{8a4c7e02-0000-0000-0000-100000000000}"
SYS_VOL_SERIAL = "8A4C7E02"
SYS_VOL_LABEL = "SYSTEM"
SYS_VOL_FULL_GUID = "\\VOLUME{01dac0f4-4d8e8421-}"
SYS_VOL_CREATED = "2024-08-04 11:02:18.0000000"

# Personal OneDrive.
PERSONAL_EMAIL = "hr.user.personal@outlook.com"
PERSONAL_CID = "a8b9c1d2e3f4a5b6"
PERSONAL_FOLDER_ITEMID = "01ABCDEF234567890ABCDEF0"
PERSONAL_Q4_ITEMID = "01ABCDEF234567890ABCDEF1"
PERSONAL_DOCX_ITEMID = "01ABCDEF234567890ABCDEF2"
ONEDRIVE_VERSION = "24.196.0929.0001"

# Corporate OneDrive (Business1) — present but not used for exfil.
BUSINESS_EMAIL = "hr-user@finance.example.com"
BUSINESS_CID = "b1c2d3e4f5a6b7c8"
BUSINESS_TENANT_ID = "4f8b3d4e-5f67-4890-abcd-ef1234567890"
BUSINESS_TENANT_NAME = "Finance Corp"

# Load-bearing SHA-256 hashes (must match pricing-files-known-hashes.txt).
SHA256_Q4 = "7a4b8c12d3e5f6789012345678901234567890abcdef1234567890abcdef1234"
SHA256_DOCX = "9b9cdc69c1c24e2b3142a4b5d6e7f8901234567890abcdef1234567890abcdef"
SHA256_MARGINS = "12dc1ea8e34b6a0b8b2c1a4f8b3d4e5f67890abcdef1234567890abcdef12345"

# Pricing file sizes (must match across MFT, USN, LNK, jump-lists, syncdb).
SIZE_Q4 = 1842184
SIZE_DOCX = 1248421
SIZE_MARGINS = 684221

# Anchor times (UTC). All timestamps below sit on the same case date.
DAY = "2024-11-12"
T_LOGON = "2024-11-12 08:42:11"
# The corporate (Business1) OneDrive client is launched from the HKCU Run
# key by explorer.exe, so it cannot start before explorer does (08:42:42).
T_CORP_ONEDRIVE = "2024-11-12 08:42:54"
# The morning Edge session — first browser-history visit is 08:48:42.
T_EDGE_MORNING = "2024-11-12 08:48:31"
T_OPEN_Q4 = "2024-11-12 17:38:42"
T_COPY_Q4_TEMP = "2024-11-12 17:39:05"
T_OPEN_DOCX = "2024-11-12 17:39:18"
T_COPY_DOCX_TEMP = "2024-11-12 17:39:18"
T_OPEN_MARGINS = "2024-11-12 17:39:42"
T_7Z = "2024-11-12 17:40:11"
T_USB_INSERT = "2024-11-12 17:42:08"
T_USB_BOUND = "2024-11-12 17:42:14"
T_E_CONF = "2024-11-12 17:43:11"
T_E_PRICING = "2024-11-12 17:43:42"
T_LNK_Q4_USB = "2024-11-12 17:44:18"
T_LNK_DOCX_USB = "2024-11-12 17:44:55"
T_LNK_MARGINS_USB = "2024-11-12 17:45:32"
T_ONEDRIVE_LAUNCH = "2024-11-12 17:46:02"
T_ONEDRIVE_Q4_DONE = "2024-11-12 17:47:18"
T_ONEDRIVE_DOCX = "2024-11-12 17:48:41"
T_ONEDRIVE_DOCX_DONE = "2024-11-12 17:49:18"
T_WEBMAIL_OPEN = "2024-11-12 17:51:04"
T_TEMP_DELETE = "2024-11-12 17:55:11"
T_PRICING_DELETE = "2024-11-12 17:57:42"
T_USB_REMOVE = "2024-11-12 17:58:30"
T_LOGOFF = "2024-11-12 18:02:14"


# ---------------------------------------------------------------------------
# CSV / text headers (exact match to existing files on disk)
# ---------------------------------------------------------------------------

HEADERS: Dict[str, List[str]] = {
    "mft.csv": [
        "EntryNumber", "ParentEntryNumber", "InUse", "ParentPath",
        "FileName", "Extension", "FileSize", "IsDirectory",
        "Created0x10", "LastModified0x10", "LastRecordChange0x10",
        "LastAccess0x10", "Created0x30", "LastModified0x30",
    ],
    "usn-journal.csv": [
        "USN", "EntryNumber", "ParentEntryNumber", "FileName", "Extension",
        "ParentPath", "FullPath", "UpdateTimestamp", "UpdateReasons",
    ],
    "security-evtx.csv": [
        "RecordNumber", "TimeCreated", "EventID", "Channel", "Provider",
        "Computer", "UserName", "Level", "Description", "Payload",
    ],
    "prefetch.csv": [
        "SourceFilename", "ExecutableName", "Hash", "RunCount", "LastRun",
        "PreviousRun0", "PreviousRun1", "PreviousRun2",
        "FilesCount", "VolumeName", "VolumeSerialNumber", "VolumeCreated",
    ],
    "amcache.csv": [
        "FullPath", "FileExtension", "FileSize", "Sha1", "Sha256",
        "FileVersion", "ProductName", "Publisher",
        "Created", "LastModified", "Compiled", "IsPeFile", "BinaryType",
    ],
    "srum.csv": [
        "Timestamp", "ApplicationName", "UserSID", "InterfaceLuid",
        "BytesSent", "BytesReceived", "EventTimestamp",
    ],
    "lnk-files.csv": [
        "SourceFile", "SourceCreated", "SourceModified", "SourceAccessed",
        "TargetCreated", "TargetModified", "TargetAccessed", "FileSize",
        "RelativePath", "WorkingDirectory", "LocalPath",
        "VolumeSerialNumber", "VolumeLabel", "DriveType", "MachineId",
    ],
    "jump-lists.csv": [
        "SourceFile", "AppId", "AppDescription", "EntryNumber",
        "LastModified", "CreationTime",
        "TargetCreated", "TargetModified", "LocalPath", "Hostname",
        "VolumeSerialNumber", "FileSize",
    ],
    "shellbags.csv": [
        "BagPath", "AbsolutePath", "ShellType",
        "FirstInteracted", "LastInteracted", "MRUPosition", "NodeSlot",
    ],
    "usbstor.csv": [
        "DeviceClass", "VendorId", "ProductId", "Revision", "SerialNumber",
        "FriendlyName", "FirstConnected", "LastConnected",
        "LastInsertTime", "LastRemovalTime", "ParentIdPrefix",
        "DeviceInstanceId", "VolumeGuid",
    ],
    "mountpoints.csv": [
        "KeyPath", "ValueName", "VolumeGuid", "DriveLetter", "DeviceType",
        "LinkedDeviceInstanceId", "LastWriteTime", "Notes",
    ],
    "onedrive-accounts.csv": [
        "AccountName", "AccountType", "UserEmail", "UserCid",
        "DisplayName", "SyncFolderPath", "TenantId", "TenantName",
        "FirstAdded", "LastSignIn", "Notes",
    ],
    "onedrive-syncdb.csv": [
        "AccountUserCid", "ItemId", "ParentItemId", "LocalPath",
        "RemotePath", "FileName", "FileExtension", "FileSize",
        "SyncState", "LastModified", "LastChangeUtc", "EnqueuedUtc",
        "UploadCompletedUtc", "Sha256ContentHash",
    ],
    "browser-history.csv": [
        "VisitId", "VisitTime", "Url", "Title", "VisitDuration",
        "VisitCount", "TypedCount", "FromVisit", "Transition",
        "UserProfile",
    ],
    "shimcache.csv": [
        "ControlSet", "CacheEntryPosition", "Path", "LastModifiedTimeUTC",
        "Executed", "Duplicate", "SourceFile",
    ],
    "recyclebin.csv": [
        "SourceName", "FileType", "FileName", "FileSize", "DeletedOn",
        "SourceCreated", "SourceModified",
    ],
}

# --- ShimCache -------------------------------------------------------------
# Export taken with ``AppCompatCacheParser -c 1`` (ControlSet001 only), so
# ``Duplicate`` is False throughout — a duplicate is only reported when the
# same path/timestamp pair also turns up in a second control set.
SHIMCACHE_CONTROLSET = "1"
SHIMCACHE_SOURCE = "C:\\Windows\\System32\\config\\SYSTEM"
# HR-WS17 is Windows 10. The "executed" InsertFlag that pre-Windows-8 cache
# formats carried is no longer populated, so AppCompatCacheParser reports
# ``NA`` on every row. A ShimCache hit proves the binary was present and
# enumerated, not that it ran. Leave this column alone.
SHIMCACHE_EXECUTED = "NA"

# --- Recycle Bin -----------------------------------------------------------
RECYCLE_BIN = f"C:\\$Recycle.Bin\\{USER_SID}"
# The user emptied the Recycle Bin at 17:58:02, between the C:\HR\Pricing
# deletion (17:57:42) and the USB removal (17:58:30).
T_BIN_EMPTIED = "2024-11-12 17:58:02"

# --- Memory acquisition ----------------------------------------------------
# IT ran WinPmem against the live host during the offboarding preservation,
# immediately before the user's final logoff and the FTK Imager disk
# acquisition. That is why the user's session is still active in the process
# list: Excel, Word, Edge and both OneDrive instances are still resident.
MEM_ACQ_TIME = "2024-11-12 18:01:12"
BOOT_TIME = "2024-11-12 02:14:00"
HOST_IP = "10.0.4.51"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def ts(s: str, frac: str = ".0000000") -> str:
    """Return a normalized timestamp string ``YYYY-MM-DD HH:MM:SS.fffffff``."""
    if "." in s:
        # Preserve an explicit fractional component if the caller passed one.
        return s
    return s + frac


def parse_ts(s: str) -> datetime:
    base = s.split(".", 1)[0]
    return datetime.strptime(base, "%Y-%m-%d %H:%M:%S")


def fmt_ts(dt: datetime, frac: str = ".0000000") -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") + frac


# ---------------------------------------------------------------------------
# Generators (one per output file)
# ---------------------------------------------------------------------------

def generate_mft(rng: random.Random) -> List[Dict[str, str]]:
    """Hand-coded MFT entries reproducing the committed file's structure.

    Includes the system volume root, ``Users\\hr-user`` profile,
    ``C:\\HR\\Pricing\\`` (now deleted — InUse=False), the transient
    copies in ``Temp\\``, the LNK files in ``Recent\\``, the OneDrive
    client install, and standard background entries (event logs,
    registry hives, prefetch).
    """
    rows: List[Dict[str, str]] = []

    def add(entry, parent, in_use, ppath, name, ext, size, is_dir,
            c10, m10, r10, a10, c30=None, m30=None):
        rows.append({
            "EntryNumber": str(entry), "ParentEntryNumber": str(parent),
            "InUse": str(in_use), "ParentPath": ppath, "FileName": name,
            "Extension": ext, "FileSize": str(size),
            "IsDirectory": str(is_dir),
            "Created0x10": ts(c10), "LastModified0x10": ts(m10),
            "LastRecordChange0x10": ts(r10), "LastAccess0x10": ts(a10),
            "Created0x30": ts(c30 if c30 else c10),
            "LastModified0x30": ts(m30 if m30 else m10),
        })

    # --- System / volume entries ------------------------------------------
    add(5, 5, True, ".", "$MFT", "", 2147483648, False,
        "2024-08-04 11:02:18", "2024-11-12 18:02:14",
        "2024-11-12 18:02:14", "2024-11-12 18:02:14",
        "2024-08-04 11:02:18", "2024-08-04 11:02:18")
    add(9, 5, True, ".", "$Extend", "", 0, True,
        "2024-08-04 11:02:18", "2024-08-04 11:02:18",
        "2024-08-04 11:02:18", "2024-08-04 11:02:18")
    add(36, 5, True, ".", "Windows", "", 0, True,
        "2024-08-04 11:02:18", "2024-11-12 03:14:00",
        "2024-11-12 03:14:00", "2024-11-12 18:02:14",
        "2024-08-04 11:02:18", "2024-08-04 11:02:18")
    add(1289, 36, True, "Windows", "System32", "", 0, True,
        "2024-08-04 11:02:18.5000000", "2024-11-12 03:14:00.5000000",
        "2024-11-12 03:14:00.5000000", "2024-11-12 18:02:14",
        "2024-08-04 11:02:18.5000000", "2024-08-04 11:02:18.5000000")

    # --- User profile -----------------------------------------------------
    add(2104, 5, True, ".", "Users", "", 0, True,
        "2024-08-04 11:05:42", "2024-08-19 14:11:08",
        "2024-08-19 14:11:08", "2024-11-12 18:02:14",
        "2024-08-04 11:05:42", "2024-08-04 11:05:42")
    add(2118, 2104, True, "Users", USER, "", 0, True,
        "2024-08-19 14:11:08", "2024-11-12 18:02:14",
        "2024-11-12 18:02:14", "2024-11-12 18:02:14",
        "2024-08-19 14:11:08", "2024-08-19 14:11:08")
    add(2218, 2118, True, f"Users\\{USER}",
        "NTUSER.DAT", "DAT", 3145728, False,
        "2024-08-19 14:11:08", "2024-11-12 18:02:14",
        "2024-11-12 18:02:14", "2024-11-12 18:02:14",
        "2024-08-19 14:11:08", "2024-08-19 14:11:08")
    add(2308, 2118, True, f"Users\\{USER}", "Documents", "", 0, True,
        "2024-08-19 14:11:09", "2024-11-12 16:42:00",
        "2024-11-12 16:42:00", T_OPEN_Q4,
        "2024-08-19 14:11:09", "2024-08-19 14:11:09")
    add(2309, 2118, True, f"Users\\{USER}", "Downloads", "", 0, True,
        "2024-08-19 14:11:09", "2024-11-08 09:32:14",
        "2024-11-08 09:32:14", "2024-11-12 13:55:00",
        "2024-08-19 14:11:09", "2024-08-19 14:11:09")
    add(2310, 2118, True, f"Users\\{USER}", "Desktop", "", 0, True,
        "2024-08-19 14:11:09", "2024-11-12 09:42:00",
        "2024-11-12 09:42:00", "2024-11-12 09:42:00",
        "2024-08-19 14:11:09", "2024-08-19 14:11:09")
    add(2311, 2118, True, f"Users\\{USER}", "AppData", "", 0, True,
        "2024-08-19 14:11:09", T_TEMP_DELETE,
        T_TEMP_DELETE, T_TEMP_DELETE,
        "2024-08-19 14:11:09", "2024-08-19 14:11:09")
    add(2545, 2311, True, f"Users\\{USER}\\AppData", "Local", "", 0, True,
        "2024-08-19 14:11:09", T_TEMP_DELETE,
        T_TEMP_DELETE, T_TEMP_DELETE,
        "2024-08-19 14:11:09", "2024-08-19 14:11:09")
    add(2546, 2545, True, f"Users\\{USER}\\AppData\\Local",
        "Temp", "", 0, True,
        "2024-08-19 14:11:09", T_TEMP_DELETE,
        T_TEMP_DELETE, T_TEMP_DELETE,
        "2024-08-19 14:11:09", "2024-08-19 14:11:09")
    add(2548, 2311, True, f"Users\\{USER}\\AppData", "Roaming", "", 0, True,
        "2024-08-19 14:11:09", T_LNK_MARGINS_USB,
        T_LNK_MARGINS_USB, T_LNK_MARGINS_USB,
        "2024-08-19 14:11:09", "2024-08-19 14:11:09")
    # AppData\Local\Microsoft\OneDrive — created at OneDrive client install
    # time for the corporate account (first logon, 2024-08-19, just before
    # the Business1 account's FirstAdded of 14:11:14), written to during the
    # personal-account sync window.
    add(2580, 2545, True, f"Users\\{USER}\\AppData\\Local",
        "Microsoft", "", 0, True,
        "2024-08-19 14:11:09", T_ONEDRIVE_DOCX_DONE,
        T_ONEDRIVE_DOCX_DONE, T_ONEDRIVE_DOCX_DONE,
        "2024-08-19 14:11:09", "2024-08-19 14:11:09")
    add(2592, 2580,
        True, f"Users\\{USER}\\AppData\\Local\\Microsoft",
        "OneDrive", "", 0, True,
        "2024-08-19 14:11:09", T_ONEDRIVE_DOCX_DONE,
        T_ONEDRIVE_DOCX_DONE, T_ONEDRIVE_DOCX_DONE,
        "2024-08-19 14:11:09", "2024-08-19 14:11:09")
    add(2593, 2592,
        True, f"Users\\{USER}\\AppData\\Local\\Microsoft\\OneDrive",
        "logs", "", 0, True,
        "2024-08-19 14:11:09", T_ONEDRIVE_DOCX_DONE,
        T_ONEDRIVE_DOCX_DONE, T_ONEDRIVE_DOCX_DONE,
        "2024-08-19 14:11:09", "2024-08-19 14:11:09")

    # --- Documents / Downloads / Desktop content --------------------------
    # Recycled 2024-10-22 11:18:44 (recyclebin.csv DeletedOn); the record
    # change time carries the deletion, as for the other deleted entries.
    add(9421, 2308, False, f"Users\\{USER}\\Documents",
        "Old_Pricing_Notes.docx", "docx", 128442, False,
        "2024-09-04 14:22:18", "2024-09-04 14:22:18",
        "2024-10-22 11:18:44", "2024-10-22 11:14:00",
        "2024-09-04 14:22:18", "2024-09-04 14:22:18")
    add(9422, 2308, True, f"Users\\{USER}\\Documents",
        "HR_Onboarding.docx", "docx", 42891, False,
        "2024-08-22 14:22:18", "2024-08-22 14:22:18",
        "2024-08-22 14:22:18", "2024-11-08 09:14:00",
        "2024-08-22 14:22:18", "2024-08-22 14:22:18")
    add(14108, 2309, True, f"Users\\{USER}\\Downloads",
        "benefits_2025.pdf", "pdf", 1284221, False,
        "2024-11-08 09:42:00", "2024-11-08 09:42:00",
        "2024-11-08 09:42:00", "2024-11-08 13:18:00",
        "2024-11-08 09:42:00", "2024-11-08 09:42:00")

    # --- The pricing folder (now deleted — InUse=False) -------------------
    # Cleanup activity is itself evidence — the readme spells this out.
    add(20418, 5, False, ".", "HR", "", 0, True,
        "2024-08-22 11:14:00", T_PRICING_DELETE,
        T_PRICING_DELETE, T_PRICING_DELETE,
        "2024-08-22 11:14:00", "2024-08-22 11:14:00")
    add(20419, 20418, False, "HR", "Pricing", "", 0, True,
        "2024-08-22 11:14:00", T_PRICING_DELETE,
        T_PRICING_DELETE, T_PRICING_DELETE,
        "2024-08-22 11:14:00", "2024-08-22 11:14:00")
    add(20420, 20419, False, "HR\\Pricing",
        "Q4_Customer_Pricing.xlsx", "xlsx", SIZE_Q4, False,
        "2024-09-22 11:14:00", "2024-11-08 14:18:42",
        "2024-11-08 14:18:42", T_OPEN_Q4,
        "2024-09-22 11:14:00", "2024-11-08 14:18:42")
    add(20421, 20419, False, "HR\\Pricing",
        "Pricing_Strategy_Confidential.docx", "docx", SIZE_DOCX, False,
        "2024-08-22 11:14:00", "2024-10-22 11:14:00",
        "2024-10-22 11:14:00", T_OPEN_DOCX,
        "2024-08-22 11:14:00", "2024-10-22 11:14:00")
    add(20422, 20419, False, "HR\\Pricing",
        "Margins_Q3.xlsx", "xlsx", SIZE_MARGINS, False,
        "2024-08-22 11:14:00", "2024-09-30 16:42:00",
        "2024-09-30 16:42:00", T_OPEN_MARGINS,
        "2024-08-22 11:14:00", "2024-09-30 16:42:00")

    # --- Transient copies in Temp\ (deleted at 17:55:11) ------------------
    # These are the load-bearing "staging" artifacts for the USB and
    # OneDrive channels. They share the same FileSize as the source
    # files (a hash collision against the legal-provided values is
    # plausible because the files were copied byte-for-byte; the labs
    # walk through computing the hash from carve recovery, not from MFT).
    add(22417, 2546, False, f"Users\\{USER}\\AppData\\Local\\Temp",
        "Q4_Customer_Pricing.xlsx", "xlsx", SIZE_Q4, False,
        T_COPY_Q4_TEMP, "2024-11-12 17:39:05.5000000",
        T_TEMP_DELETE, T_LNK_Q4_USB,
        T_COPY_Q4_TEMP, "2024-11-12 17:39:05.5000000")
    add(22418, 2546, False, f"Users\\{USER}\\AppData\\Local\\Temp",
        "Pricing_Strategy_Confidential.docx", "docx", SIZE_DOCX, False,
        T_COPY_DOCX_TEMP, "2024-11-12 17:39:18.5000000",
        T_TEMP_DELETE, T_LNK_DOCX_USB,
        T_COPY_DOCX_TEMP, "2024-11-12 17:39:18.5000000")
    # Excel lock file (~$...) — created when the user opens the workbook,
    # deleted at 17:55:48 when it is closed (usn-journal.csv FileDelete).
    add(22419, 2546, False, f"Users\\{USER}\\AppData\\Local\\Temp",
        "~$Q4_Customer_Pricing.xlsx", "xlsx", 165, False,
        T_OPEN_Q4, T_OPEN_Q4,
        "2024-11-12 17:55:48", T_OPEN_Q4,
        T_OPEN_Q4, T_OPEN_Q4)
    # Benign Office install leftover (noise).
    add(22420, 2546, True, f"Users\\{USER}\\AppData\\Local\\Temp",
        "wmsetup.log", "log", 4218, False,
        "2024-08-19 14:11:14", "2024-08-19 14:11:14",
        "2024-08-19 14:11:14", "2024-08-19 14:11:14",
        "2024-08-19 14:11:14", "2024-08-19 14:11:14")
    # 7-Zip staging archive — created by 7zG.exe at 17:40 from the Temp copy
    # of Q4_Customer_Pricing.xlsx (see the EID 4688 command line), still
    # present. No channel artifact references the archive itself, so it is
    # a staging finding to extract and hash, not a transfer. InUse=True
    # keeps it inspectable on disk.
    add(22421, 2546, True, f"Users\\{USER}\\AppData\\Local\\Temp",
        "pricing-staging.zip", "zip", 1721184, False,
        T_7Z, "2024-11-12 17:40:14",
        "2024-11-12 17:40:14", "2024-11-12 17:40:14",
        T_7Z, "2024-11-12 17:40:14")

    # --- LNK files in Recent\ --------------------------------------------
    # Parent is Roaming\Microsoft\Windows (entry 2552, not in this extract).
    add(4318, 2552,
        True, f"Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows",
        "Recent", "", 0, True,
        "2024-08-19 14:11:09", T_LNK_MARGINS_USB,
        T_LNK_MARGINS_USB, T_LNK_MARGINS_USB,
        "2024-08-19 14:11:09", "2024-08-19 14:11:09")
    # Local-path LNKs (C:\HR\Pricing\...)
    for entry, name, size, t in [
        (4319, "Q4_Customer_Pricing.lnk", 1842, "2024-11-12 17:38:42.5000000"),
        (4320, "Pricing_Strategy_Confidential.lnk", 1921, T_OPEN_DOCX),
        (4321, "Margins_Q3.lnk", 1782, "2024-11-12 17:39:42"),
    ]:
        add(entry, 4318, True,
            f"Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
            name, "lnk", size, False, t, t, t, t, t, t)
    # USB-path LNKs (E:\Confidential\Pricing\...). The "(E)" suffix in
    # the file name is what Windows uses when a second LNK is created
    # for the same logical file on a different volume.
    for entry, name, size, t in [
        (4322, "Q4_Customer_Pricing (E).lnk", 1942, T_LNK_Q4_USB),
        (4323, "Pricing_Strategy_Confidential (E).lnk", 2018, T_LNK_DOCX_USB),
        (4324, "Margins_Q3 (E).lnk", 1882, T_LNK_MARGINS_USB),
    ]:
        add(entry, 4318, True,
            f"Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
            name, "lnk", size, False, t, t, t, t, t, t)
    # Benign LNK (noise).
    add(4325, 4318, True,
        f"Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
        "benefits_2025.lnk", "lnk", 1684, False,
        "2024-11-08 09:42:00", "2024-11-08 13:18:00",
        "2024-11-08 13:18:00", "2024-11-08 13:18:00",
        "2024-11-08 09:42:00", "2024-11-08 09:42:00")

    # --- Prefetch directory + entries ------------------------------------
    # %SystemRoot%\Prefetch — a child of Windows (36), not of System32.
    add(6422, 36, True, "Windows", "Prefetch", "", 0, True,
        "2024-08-04 11:02:18.5000000", T_WEBMAIL_OPEN,
        T_WEBMAIL_OPEN, T_WEBMAIL_OPEN,
        "2024-08-04 11:02:18.5000000", "2024-08-04 11:02:18.5000000")
    for entry, name, size, c10, m10 in [
        (6423, "EXCEL.EXE-7A4B8C12.pf", 29844,
         "2024-08-19 14:11:14", T_OPEN_Q4),
        (6424, "WINWORD.EXE-89B23C41.pf", 32184,
         "2024-08-19 14:11:14", T_OPEN_DOCX),
        (6425, "ONEDRIVE.EXE-3A1B2C4D.pf", 42184,
         "2024-08-19 14:11:14", T_ONEDRIVE_LAUNCH),
        (6426, "MSEDGE.EXE-3142A4B7.pf", 84218,
         "2024-08-19 14:11:14", T_WEBMAIL_OPEN),
        (6427, "7ZG.EXE-A1B2C3D4.pf", 18244,
         T_7Z, T_7Z),
    ]:
        add(entry, 6422, True, "Windows\\Prefetch",
            name, "pf", size, False, c10, m10, m10, m10, c10, m10)

    # --- Event log files (referenced in MFT but body lives in evtx CSV) ---
    # winevt\Logs; its parent winevt (1290) is not in this extract.
    add(1291, 1290, True, "Windows\\System32\\winevt", "Logs", "", 0, True,
        "2024-08-04 11:02:18.5000000", T_LOGOFF,
        T_LOGOFF, T_LOGOFF,
        "2024-08-04 11:02:18.5000000", "2024-08-04 11:02:18.5000000")
    add(1292, 1291, True, "Windows\\System32\\winevt\\Logs",
        "Security.evtx", "evtx", 67108864, False,
        "2024-08-04 11:02:18.5000000", T_LOGOFF,
        T_LOGOFF, T_LOGOFF,
        "2024-08-04 11:02:18.5000000", "2024-08-04 11:02:18.5000000")

    return rows


def generate_usn_journal(rng: random.Random) -> List[Dict[str, str]]:
    """USN Journal: pricing-file open + temp copy + LNK + delete + cleanup.

    The USN is a chronological change log. We populate it with one or
    more records per filesystem mutation in the attack window, plus a
    little background noise from earlier in the day.
    """
    rows: List[Dict[str, str]] = []
    base_usn = 1842892160

    # USNs are assigned after every row is added (see the end of this
    # function): rows are put in time order first, so the USN rises with
    # UpdateTimestamp exactly as it does in a real $UsnJrnl:$J.
    def add(entry, parent, name, ext, ppath, t, reasons):
        rows.append({
            "USN": "",
            "EntryNumber": str(entry), "ParentEntryNumber": str(parent),
            "FileName": name, "Extension": ext,
            "ParentPath": ppath,
            "FullPath": f"{ppath}\\{name}" if ppath else name,
            "UpdateTimestamp": ts(t), "UpdateReasons": reasons,
        })

    # Local open of Q4 (BasicInfoChange when Excel touches the file).
    add(20420, 20419, "Q4_Customer_Pricing.xlsx", "xlsx", "HR\\Pricing",
        T_OPEN_Q4, "BasicInfoChange")
    # Local-path LNK created for Q4.
    add(4319, 4318, "Q4_Customer_Pricing.lnk", "lnk",
        f"Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
        "2024-11-12 17:38:42.5000000",
        "FileCreate|DataExtend|FileClose")
    # Excel lock file (~$) created in Temp.
    add(22419, 2546, "~$Q4_Customer_Pricing.xlsx", "xlsx",
        f"Users\\{USER}\\AppData\\Local\\Temp",
        T_OPEN_Q4, "FileCreate|DataExtend")
    # Q4 copied into Temp (the staging path used for both USB and OneDrive).
    add(22417, 2546, "Q4_Customer_Pricing.xlsx", "xlsx",
        f"Users\\{USER}\\AppData\\Local\\Temp",
        T_COPY_Q4_TEMP, "FileCreate|DataExtend")
    add(22417, 2546, "Q4_Customer_Pricing.xlsx", "xlsx",
        f"Users\\{USER}\\AppData\\Local\\Temp",
        "2024-11-12 17:39:05.5000000", "DataExtend|FileClose")
    # Pricing_Strategy.docx copied into Temp.
    add(22418, 2546, "Pricing_Strategy_Confidential.docx", "docx",
        f"Users\\{USER}\\AppData\\Local\\Temp",
        T_COPY_DOCX_TEMP, "FileCreate|DataExtend")
    add(22418, 2546, "Pricing_Strategy_Confidential.docx", "docx",
        f"Users\\{USER}\\AppData\\Local\\Temp",
        "2024-11-12 17:39:18.5000000", "DataExtend|FileClose")
    # Local-path LNKs for the two docs the user opened second/third.
    add(4320, 4318, "Pricing_Strategy_Confidential.lnk", "lnk",
        f"Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
        T_OPEN_DOCX, "FileCreate|DataExtend|FileClose")
    add(4321, 4318, "Margins_Q3.lnk", "lnk",
        f"Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
        T_OPEN_MARGINS, "FileCreate|DataExtend|FileClose")
    # Margins last-access refresh after the user opens it briefly.
    add(20422, 20419, "Margins_Q3.xlsx", "xlsx", "HR\\Pricing",
        T_OPEN_MARGINS, "BasicInfoChange")
    # USB-path LNKs (created at copy time, one per pricing file).
    add(4322, 4318, "Q4_Customer_Pricing (E).lnk", "lnk",
        f"Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
        T_LNK_Q4_USB, "FileCreate|DataExtend|FileClose")
    add(4323, 4318, "Pricing_Strategy_Confidential (E).lnk", "lnk",
        f"Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
        T_LNK_DOCX_USB, "FileCreate|DataExtend|FileClose")
    add(4324, 4318, "Margins_Q3 (E).lnk", "lnk",
        f"Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
        T_LNK_MARGINS_USB, "FileCreate|DataExtend|FileClose")
    # Temp copies re-touched when the user copies them to E:. Only the
    # Q4 update is recorded — Word's docx temp is less noisy in practice.
    add(22417, 2546, "Q4_Customer_Pricing.xlsx", "xlsx",
        f"Users\\{USER}\\AppData\\Local\\Temp",
        T_LNK_Q4_USB, "BasicInfoChange")
    # 7-Zip staging archive — created at 17:40 (still present on disk).
    add(22421, 2546, "pricing-staging.zip", "zip",
        f"Users\\{USER}\\AppData\\Local\\Temp",
        T_7Z, "FileCreate|DataExtend|FileClose")
    # OneDrive activity — sync engine writes to the local SQLite +
    # rotates the diagnostics log.
    add(2592, 2580, "OneDrive", "",
        f"Users\\{USER}\\AppData\\Local\\Microsoft",
        T_ONEDRIVE_LAUNCH, "DataExtend")
    # The personal account's log lives in logs\Personal\ (entry 2594, not in
    # the MFT extract); the file itself is entry 2595. Entry 2593 is the
    # logs\ directory.
    od_personal_logs = (f"Users\\{USER}\\AppData\\Local\\Microsoft"
                        "\\OneDrive\\logs\\Personal")
    add(2595, 2594, "SyncDiagnostics-2024-11-12.log", "log",
        od_personal_logs, T_ONEDRIVE_LAUNCH, "DataExtend")
    add(2595, 2594, "SyncDiagnostics-2024-11-12.log", "log",
        od_personal_logs, T_ONEDRIVE_DOCX, "DataExtend")
    add(2595, 2594, "SyncDiagnostics-2024-11-12.log", "log",
        od_personal_logs, T_ONEDRIVE_DOCX_DONE, "DataExtend|FileClose")
    # Personal-OneDrive sync folder + the two uploaded files materialized
    # locally (these are the SHA-256-bound objects). The sync root sits in
    # the profile folder (2118). Pricing-Backup is created at 17:46:14, the
    # moment the client log's FileWatcher reports it; each pricing file is
    # written and closed in the second the FileWatcher reports it at full
    # size, before its upload begins.
    add(22431, 2118, "OneDrive", "",
        f"Users\\{USER}", T_ONEDRIVE_LAUNCH, "FileCreate|DataExtend")
    add(22432, 22431, "Pricing-Backup", "",
        f"Users\\{USER}\\OneDrive", "2024-11-12 17:46:14",
        "FileCreate|DataExtend")
    add(22433, 22432, "Q4_Customer_Pricing.xlsx", "xlsx",
        f"Users\\{USER}\\OneDrive\\Pricing-Backup",
        "2024-11-12 17:46:42", "FileCreate|DataExtend")
    add(22433, 22432, "Q4_Customer_Pricing.xlsx", "xlsx",
        f"Users\\{USER}\\OneDrive\\Pricing-Backup",
        "2024-11-12 17:46:42.5000000", "DataExtend|FileClose")
    add(22434, 22432, "Pricing_Strategy_Confidential.docx", "docx",
        f"Users\\{USER}\\OneDrive\\Pricing-Backup",
        T_ONEDRIVE_DOCX, "FileCreate|DataExtend")
    add(22434, 22432, "Pricing_Strategy_Confidential.docx", "docx",
        f"Users\\{USER}\\OneDrive\\Pricing-Backup",
        "2024-11-12 17:48:41.5000000", "DataExtend|FileClose")
    # Cleanup pass — Temp copies + ~$ deleted before logoff.
    add(22417, 2546, "Q4_Customer_Pricing.xlsx", "xlsx",
        f"Users\\{USER}\\AppData\\Local\\Temp",
        T_TEMP_DELETE, "FileDelete")
    add(22417, 2546, "Q4_Customer_Pricing.xlsx", "xlsx",
        f"Users\\{USER}\\AppData\\Local\\Temp",
        "2024-11-12 17:55:11.5000000", "FileDelete|FileClose")
    add(22418, 2546, "Pricing_Strategy_Confidential.docx", "docx",
        f"Users\\{USER}\\AppData\\Local\\Temp",
        T_TEMP_DELETE, "FileDelete")
    add(22418, 2546, "Pricing_Strategy_Confidential.docx", "docx",
        f"Users\\{USER}\\AppData\\Local\\Temp",
        "2024-11-12 17:55:11.5000000", "FileDelete|FileClose")
    add(22419, 2546, "~$Q4_Customer_Pricing.xlsx", "xlsx",
        f"Users\\{USER}\\AppData\\Local\\Temp",
        "2024-11-12 17:55:48", "FileDelete|FileClose")
    # The C:\HR\Pricing\ directory itself is deleted (anti-forensics).
    add(20420, 20419, "Q4_Customer_Pricing.xlsx", "xlsx", "HR\\Pricing",
        T_PRICING_DELETE, "FileDelete")
    add(20421, 20419, "Pricing_Strategy_Confidential.docx", "docx",
        "HR\\Pricing", T_PRICING_DELETE, "FileDelete")
    add(20422, 20419, "Margins_Q3.xlsx", "xlsx", "HR\\Pricing",
        T_PRICING_DELETE, "FileDelete")
    add(20419, 20418, "Pricing", "", "HR", T_PRICING_DELETE, "FileDelete")
    add(20418, 5, "HR", "", ".",
        "2024-11-12 17:57:42.5000000", "FileDelete|FileClose")
    # Registry hive flushes (USBSTOR install, MountedDevices binding, etc.)
    # Two NTUSER and two hive entries are enough to anchor the chain;
    # extra flushes don't help the lab analyst and bloat the journal.
    add(2218, 2118, "NTUSER.DAT", "DAT", f"Users\\{USER}",
        T_USB_BOUND, "DataExtend")
    add(2218, 2118, "NTUSER.DAT", "DAT", f"Users\\{USER}",
        T_LOGOFF, "DataExtend")
    add(1297, 1295, "SYSTEM", "", "Windows\\System32\\config",
        T_USB_BOUND, "DataExtend")
    add(1296, 1295, "SOFTWARE", "", "Windows\\System32\\config",
        T_ONEDRIVE_LAUNCH, "DataExtend")
    # Prefetch updates triggered by first runs.
    add(6425, 6422, "ONEDRIVE.EXE-3A1B2C4D.pf", "pf",
        "Windows\\Prefetch",
        T_ONEDRIVE_LAUNCH, "DataExtend")
    add(6427, 6422, "7ZG.EXE-A1B2C3D4.pf", "pf",
        "Windows\\Prefetch",
        T_7Z, "FileCreate|DataExtend")
    # Late-day SRUM rollup and Security log close — bookend the dataset.
    add(1306, 1305, "SRUDB.dat", "dat", "Windows\\System32\\sru",
        "2024-11-12 18:00:00", "DataExtend")
    add(1292, 1291, "Security.evtx", "evtx",
        "Windows\\System32\\winevt\\Logs",
        T_LOGOFF, "DataExtend")
    # Background "noise" rows — benign activity earlier in the week.
    add(14108, 2309, "benefits_2025.pdf", "pdf",
        f"Users\\{USER}\\Downloads",
        "2024-11-08 09:42:00", "FileCreate|DataExtend|FileClose")
    add(9422, 2308, "HR_Onboarding.docx", "docx",
        f"Users\\{USER}\\Documents",
        "2024-11-08 09:14:00", "BasicInfoChange")

    # Put the journal in time order (stable, so same-instant rows keep the
    # order they were added in) and number it: one USN per record, 64 bytes
    # apart.
    _ = rng
    rows.sort(key=lambda r: r["UpdateTimestamp"])
    for i, r in enumerate(rows):
        r["USN"] = str(base_usn + i * 64)
    return rows


def generate_security_evtx(rng: random.Random) -> List[Dict[str, str]]:
    """Security event log: logons + process creation around the window."""
    rows: List[Dict[str, str]] = []

    def add(rec, t, eid, user, desc, payload):
        rows.append({
            "RecordNumber": str(rec), "TimeCreated": ts(t),
            "EventID": str(eid), "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": FQDN, "UserName": user, "Level": "Information",
            "Description": desc, "Payload": payload,
        })

    # --- Early-morning system context -------------------------------------
    add(3284011, "2024-11-12 03:14:00.1248421", 4624, "SYSTEM",
        "Successful logon",
        "TargetUserName=SYSTEM TargetDomainName=NT AUTHORITY LogonType=5 "
        "LogonProcessName=Advapi "
        "ProcessName=C:\\Windows\\System32\\services.exe "
        "IpAddress=- ElevatedToken=Yes")

    # --- Interactive logon (normal start of day) --------------------------
    add(3284108, "2024-11-12 08:42:11.4842311", 4624, "SYSTEM",
        "Successful logon",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=2 "
        "LogonProcessName=User32 "
        "ProcessName=C:\\Windows\\System32\\winlogon.exe "
        f"IpAddress=127.0.0.1 WorkstationName={HOSTNAME}")
    add(3284109, "2024-11-12 08:42:11.5012834", 4672, USER,
        "Special privileges assigned",
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        "PrivilegeList=SeShutdownPrivilege SeUndockPrivilege "
        "SeIncreaseWorkingSetPrivilege SeTimeZonePrivilege")
    # ProcessId values are hex, as EvtxECmd renders them. Where the process
    # is still alive in volatility-pslist.txt, the value is that PID in hex
    # (explorer 2468 = 0x9A4, OUTLOOK 3024 = 0xBD0, EXCEL 4218 = 0x107A,
    # WINWORD 4258 = 0x10A2, dllhost 5842 = 0x16D2, OneDrive 6428 = 0x191C,
    # msedge 6604 = 0x19CC).
    add(3284144, "2024-11-12 08:42:42.1224821", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\Explorer.EXE ProcessId=0x9A4 "
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        "ParentProcessName=C:\\Windows\\System32\\userinit.exe "
        "TokenElevationType=%%1936 "
        "CommandLine=C:\\Windows\\Explorer.EXE")
    add(3284188, "2024-11-12 08:48:14.0124211", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Program Files\\Microsoft Office\\root\\Office16"
        "\\OUTLOOK.EXE "
        f"ProcessId=0xBD0 SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        "TokenElevationType=%%1938 "
        'CommandLine="C:\\Program Files\\Microsoft Office\\root\\Office16'
        '\\OUTLOOK.EXE"')

    # --- Morning / midday normal activity ---------------------------------
    # Edge is launched before the first browser-history visit (08:48:42);
    # this instance has exited by the 18:01:12 memory capture.
    add(3284191, T_EDGE_MORNING + ".4214211", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Program Files (x86)\\Microsoft\\Edge\\Application"
        "\\msedge.exe "
        f"ProcessId=0x3F88 SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        "TokenElevationType=%%1938 "
        'CommandLine="C:\\Program Files (x86)\\Microsoft\\Edge\\Application'
        '\\msedge.exe"')
    add(3284214, "2024-11-12 09:32:11.4218421", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Program Files\\Microsoft Office\\root\\Office16"
        "\\EXCEL.EXE "
        f"ProcessId=0x3024 SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        "TokenElevationType=%%1938 "
        'CommandLine="C:\\Program Files\\Microsoft Office\\root\\Office16'
        '\\EXCEL.EXE" /e')

    # --- The exfil window -------------------------------------------------
    # Excel opens C:\HR\Pricing\Q4_Customer_Pricing.xlsx
    add(3284401, T_OPEN_Q4, 4688, USER,
        "Process created",
        "NewProcessName=C:\\Program Files\\Microsoft Office\\root\\Office16"
        "\\EXCEL.EXE "
        f"ProcessId=0x107A SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        "TokenElevationType=%%1938 "
        'CommandLine="C:\\Program Files\\Microsoft Office\\root\\Office16'
        '\\EXCEL.EXE" "C:\\HR\\Pricing\\Q4_Customer_Pricing.xlsx"')
    # Word opens C:\HR\Pricing\Pricing_Strategy_Confidential.docx
    add(3284402, T_OPEN_DOCX, 4688, USER,
        "Process created",
        "NewProcessName=C:\\Program Files\\Microsoft Office\\root\\Office16"
        "\\WINWORD.EXE "
        f"ProcessId=0x10A2 SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        "TokenElevationType=%%1938 "
        'CommandLine="C:\\Program Files\\Microsoft Office\\root\\Office16'
        '\\WINWORD.EXE" "C:\\HR\\Pricing\\Pricing_Strategy_Confidential.docx"')
    # 7-Zip GUI launched to stage an archive (not the eventual exfil
    # channel, but its presence is part of the case).
    add(3284410, T_7Z, 4688, USER,
        "Process created",
        "NewProcessName=C:\\Program Files\\7-Zip\\7zG.exe "
        f"ProcessId=0x4318 SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        "TokenElevationType=%%1938 "
        'CommandLine="C:\\Program Files\\7-Zip\\7zG.exe" a -tzip '
        '"C:\\Users\\hr-user\\AppData\\Local\\Temp\\pricing-staging.zip" '
        '"C:\\Users\\hr-user\\AppData\\Local\\Temp\\Q4_Customer_Pricing.xlsx"')
    # USB device install (DrvInst).
    add(3284442, "2024-11-12 17:42:08.0214821", 4688, "SYSTEM",
        "Process created",
        "NewProcessName=C:\\Windows\\System32\\drvinst.exe "
        "ProcessId=0x4844 SubjectUserName=SYSTEM "
        "ParentProcessName=C:\\Windows\\System32\\svchost.exe "
        "TokenElevationType=%%1936 "
        f'CommandLine=DrvInst.exe "8" "201" '
        f'"USB\\VID_{USB_VENDOR_ID}&PID_{USB_PRODUCT_ID}\\{USB_SERIAL}"')
    # Explorer relaunch — Windows sometimes spawns a factory Explorer
    # window when a new removable drive is mounted. The factory instance is
    # COM-activated by svchost (DcomLaunch); userinit.exe exited at 08:43:04
    # (volatility-pslist.txt) and cannot be its parent.
    add(3284444, "2024-11-12 17:42:42", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\Explorer.EXE ProcessId=0x4880 "
        f"SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\System32\\svchost.exe "
        "TokenElevationType=%%1938 "
        "CommandLine=C:\\Windows\\Explorer.EXE "
        "/factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b}")
    # OneDrive.exe spawned at 17:46 — the personal-account first activation.
    # Created at 17:46:02.0, ahead of its own 17:46:02.184 sign-in log line.
    add(3284451, T_ONEDRIVE_LAUNCH, 4688, USER,
        "Process created",
        "NewProcessName=C:\\Users\\hr-user\\AppData\\Local\\Microsoft"
        "\\OneDrive\\OneDrive.exe "
        f"ProcessId=0x191C SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        "TokenElevationType=%%1938 "
        'CommandLine="C:\\Users\\hr-user\\AppData\\Local\\Microsoft'
        '\\OneDrive\\OneDrive.exe" /background')
    # Edge navigates to webmail at 17:51.
    add(3284452, "2024-11-12 17:51:04.5811542", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Program Files (x86)\\Microsoft\\Edge\\Application"
        "\\msedge.exe "
        f"ProcessId=0x19CC SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        "TokenElevationType=%%1938 "
        'CommandLine="C:\\Program Files (x86)\\Microsoft\\Edge\\Application'
        '\\msedge.exe" --new-window https://outlook.live.com/mail/0/')
    # cmd.exe /c del — explicit cleanup of the Temp copies. Created at
    # 17:55:11.0, the instant of the first FileDelete in usn-journal.csv.
    add(3284468, T_TEMP_DELETE, 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\System32\\cmd.exe "
        f"ProcessId=0x5421 SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        "TokenElevationType=%%1938 "
        'CommandLine="cmd.exe" /c del /f /q '
        '"C:\\Users\\hr-user\\AppData\\Local\\Temp\\Q4_Customer_Pricing.xlsx" '
        '"C:\\Users\\hr-user\\AppData\\Local\\Temp'
        '\\Pricing_Strategy_Confidential.docx"')
    # Explorer relaunch — the user cleared HR\Pricing from Explorer,
    # sending the files to the Recycle Bin (recyclebin.csv $I records; no
    # rd.exe or rmdir in the trail).
    add(3284470, T_PRICING_DELETE, 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\Explorer.EXE ProcessId=0x5482 "
        f"SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        "TokenElevationType=%%1938 "
        "CommandLine=C:\\Windows\\Explorer.EXE")
    # Logoff at end of day.
    add(3284514, "2024-11-12 18:02:14.4218421", 4634, "SYSTEM",
        "Logoff",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=2")

    # --- Background / noise events ----------------------------------------
    add(3284002, "2024-11-12 03:00:11", 4688, "SYSTEM",
        "Process created",
        "NewProcessName=C:\\Windows\\System32\\svchost.exe ProcessId=0x12C8 "
        "SubjectUserName=SYSTEM "
        "ParentProcessName=C:\\Windows\\System32\\services.exe "
        "CommandLine=C:\\Windows\\System32\\svchost.exe -k netsvcs -p")
    add(3284140, "2024-11-12 08:42:42", 4624, "SYSTEM",
        "Successful logon",
        "TargetUserName=DWM-1 TargetDomainName=Window Manager LogonType=2 "
        "LogonProcessName=Advapi "
        "ProcessName=C:\\Windows\\System32\\winlogon.exe")
    add(3283942, "2024-11-12 02:14:08.4218421", 4625, "SYSTEM",
        "Failed logon",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=3 "
        f"IpAddress={BACKUP_IP} FailureReason=%%2313 Status=0xC000006D "
        f"SubStatus=0xC000006A WorkstationName={BACKUP_HOST}")
    add(3283958, "2024-11-12 02:14:14", 4624, "SYSTEM",
        "Successful logon",
        f"TargetUserName=svc-backup TargetDomainName={DOMAIN} LogonType=3 "
        f"LogonProcessName=Kerberos ProcessName=- IpAddress={BACKUP_IP} "
        f"WorkstationName={BACKUP_HOST}")
    add(3283962, "2024-11-12 02:14:48", 4634, "SYSTEM",
        "Logoff",
        "TargetUserName=svc-backup LogonType=3")
    add(3284318, "2024-11-12 12:32:04", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Program Files (x86)\\Microsoft\\EdgeWebView"
        "\\Application\\msedgewebview2.exe "
        f"ProcessId=0x3848 SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        'CommandLine="C:\\Program Files (x86)\\Microsoft\\EdgeWebView'
        '\\Application\\msedgewebview2.exe"')
    add(3284356, "2024-11-12 14:00:14", 4624, "SYSTEM",
        "Successful logon",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=11 "
        f"LogonProcessName=NtLmSsp IpAddress=- WorkstationName={HOSTNAME}")
    add(3284443, T_USB_BOUND, 4688, "SYSTEM",
        "Process created",
        "NewProcessName=C:\\Windows\\System32\\dllhost.exe "
        "ProcessId=0x16D2 SubjectUserName=SYSTEM "
        "ParentProcessName=C:\\Windows\\System32\\svchost.exe "
        "CommandLine=C:\\Windows\\System32\\dllhost.exe "
        "/Processid:{3EB3C877-1F16-487C-9050-104DBCD66683}")

    return rows


def generate_prefetch(rng: random.Random) -> List[Dict[str, str]]:
    """Prefetch entries for the executables observed in the timeline.

    Run counts and PreviousRun timestamps roughly reflect a host that
    has been live for ~3 months. Any entry with RunCount >= 4 fills all
    three PreviousRun columns, as PECmd would. ``7ZG.EXE`` has run count
    1 — its first and only execution is in the incident window.
    """
    rows: List[Dict[str, str]] = []

    def add(src, exe, h, rc, last, p0="", p1="", p2="", files=84):
        rows.append({
            "SourceFilename": src, "ExecutableName": exe,
            "Hash": h, "RunCount": str(rc),
            "LastRun": ts(last),
            "PreviousRun0": ts(p0) if p0 else "",
            "PreviousRun1": ts(p1) if p1 else "",
            "PreviousRun2": ts(p2) if p2 else "",
            "FilesCount": str(files), "VolumeName": SYS_VOL_FULL_GUID,
            "VolumeSerialNumber": SYS_VOL_SERIAL,
            "VolumeCreated": SYS_VOL_CREATED,
        })

    add("EXCEL.EXE-7A4B8C12.pf", "EXCEL.EXE", "7A4B8C12", 142,
        T_OPEN_Q4, "2024-11-12 09:32:11", "2024-11-08 13:14:21",
        "2024-11-04 09:32:00", files=221)
    add("WINWORD.EXE-89B23C41.pf", "WINWORD.EXE", "89B23C41", 84,
        T_OPEN_DOCX, "2024-11-08 09:14:00", "2024-11-04 13:14:00",
        "2024-10-22 11:14:22", files=184)
    # 7ZG.EXE run count 1 — first-time execution at 17:40:11.
    add("7ZG.EXE-A1B2C3D4.pf", "7ZG.EXE", "A1B2C3D4", 1,
        T_7Z, files=18)
    add("ONEDRIVE.EXE-3A1B2C4D.pf", "ONEDRIVE.EXE", "3A1B2C4D", 142,
        T_ONEDRIVE_LAUNCH, T_CORP_ONEDRIVE, "2024-11-11 17:42:00",
        "2024-11-11 08:42:00", files=84)
    add("MSEDGE.EXE-3142A4B7.pf", "MSEDGE.EXE", "3142A4B7", 221,
        T_WEBMAIL_OPEN, T_EDGE_MORNING, "2024-11-11 14:42:00",
        "2024-11-11 09:14:00", files=184)
    add("OUTLOOK.EXE-3D2A41C8.pf", "OUTLOOK.EXE", "3D2A41C8", 184,
        "2024-11-12 08:48:14", "2024-11-11 08:42:11", "2024-11-08 08:42:11",
        "2024-11-04 08:42:11", files=322)
    # Last run is the 17:57:42 Explorer launch (EID 4688), after the
    # 17:42:42 factory window.
    add("EXPLORER.EXE-3142A4B6.pf", "EXPLORER.EXE", "3142A4B6", 222,
        T_PRICING_DELETE, "2024-11-12 17:42:42", "2024-11-12 08:42:42",
        "2024-11-11 17:42:00", files=512)
    add("CMD.EXE-4A81B364.pf", "CMD.EXE", "4A81B364", 12,
        T_TEMP_DELETE, "2024-11-08 11:14:21", "2024-10-22 09:14:08",
        "2024-09-19 14:11:08", files=42)
    add("SVCHOST.EXE-12C8B921.pf", "SVCHOST.EXE", "12C8B921", 42,
        "2024-11-12 03:00:11", "2024-11-11 22:00:00",
        "2024-11-11 03:00:11", "2024-11-10 03:00:11", files=184)
    add("WINLOGON.EXE-A8B9421C.pf", "WINLOGON.EXE", "A8B9421C", 21,
        "2024-11-12 02:14:14", "2024-11-11 22:00:14",
        "2024-11-11 02:14:00", "2024-11-10 02:14:00", files=84)
    add("USERINIT.EXE-A8B95612.pf", "USERINIT.EXE", "A8B95612", 21,
        "2024-11-12 08:42:42", "2024-11-11 08:42:00",
        "2024-11-08 08:42:00", "2024-11-07 08:42:00", files=42)
    add("TASKHOSTW.EXE-7B2A4181.pf", "TASKHOSTW.EXE", "7B2A4181", 84,
        "2024-11-12 14:00:00", "2024-11-12 13:00:00",
        "2024-11-12 12:00:00", "2024-11-12 11:00:00", files=32)
    add("DLLHOST.EXE-9B23C144.pf", "DLLHOST.EXE", "9B23C144", 42,
        T_USB_BOUND, "2024-11-12 14:30:00", "2024-11-12 11:00:00",
        "2024-11-12 08:42:48", files=16)
    add("RUNDLL32.EXE-3142A4B8.pf", "RUNDLL32.EXE", "3142A4B8", 68,
        T_USB_BOUND, "2024-11-12 09:32:00", "2024-11-11 17:42:00",
        "2024-11-11 09:32:00", files=42)
    # drvinst.exe — runs each time a new USB device is installed; this
    # is its fifth recorded run, one per device in usbstor.csv. The run
    # times match each device's FirstConnected value (the CD-ROM's
    # 2024-08-12 run is the fifth, beyond the three PreviousRun columns).
    add("DRVINST.EXE-A1142B83.pf", "DRVINST.EXE", "A1142B83", 5,
        T_USB_INSERT, "2024-09-19 14:05:12", "2024-09-02 13:31:44",
        "2024-08-19 15:22:31", files=12)
    return rows


def generate_amcache(rng: random.Random) -> List[Dict[str, str]]:
    """Amcache rows for every PE that ran on the host.

    Amcache is one of the spots an analyst would look for a SHA-1
    hash of the exfil tool. We include 7zG.exe (the user's only
    archive utility on the host), OneDrive.exe (the personal-account
    upload engine), and the standard system binaries.
    """
    rows: List[Dict[str, str]] = []

    def add(path, ext, size, sha1, sha256, ver, product, publisher,
            created, modified, compiled, is_pe=True, bin_type="pe64bit"):
        rows.append({
            "FullPath": path, "FileExtension": ext, "FileSize": str(size),
            "Sha1": sha1, "Sha256": sha256, "FileVersion": ver,
            "ProductName": product, "Publisher": publisher,
            "Created": ts(created), "LastModified": ts(modified),
            "Compiled": ts(compiled),
            "IsPeFile": str(is_pe), "BinaryType": bin_type,
        })

    add("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
        ".exe", 3842184,
        "f4c6a4218421842184218421842184218421842e",
        "8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678a4f8b",
        "16.0.18025.20030", "Microsoft Office", "Microsoft Corporation",
        "2024-08-19 14:11:09", "2024-11-04 11:00:00",
        "2024-10-28 03:14:00")
    add("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        ".exe", 4218214,
        "e3b5a4218421842184218421842184218421842d",
        "4f8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678a4f",
        "16.0.18025.20030", "Microsoft Office", "Microsoft Corporation",
        "2024-08-19 14:11:09", "2024-11-04 11:00:00",
        "2024-10-28 03:14:00")
    add("C:\\Program Files\\7-Zip\\7zG.exe", ".exe", 536872,
        "a8b9c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8",
        "1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef12345678ab",
        "23.01.00.0", "7-Zip", "Igor Pavlov",
        "2024-09-19 14:42:11", "2024-09-19 14:42:11",
        "2023-06-20 12:00:00")
    add("C:\\Program Files\\7-Zip\\7z.exe", ".exe", 478208,
        "b9c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9",
        "2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef12345678abcd",
        "23.01.00.0", "7-Zip", "Igor Pavlov",
        "2024-09-19 14:42:11", "2024-09-19 14:42:11",
        "2023-06-20 12:00:00")
    add("C:\\Users\\hr-user\\AppData\\Local\\Microsoft\\OneDrive"
        "\\OneDrive.exe",
        ".exe", 2842184,
        "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d1",
        "3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef12345678abcdef",
        ONEDRIVE_VERSION, "Microsoft OneDrive", "Microsoft Corporation",
        "2024-08-19 14:11:09", "2024-11-12 03:14:00",
        "2024-11-04 03:14:00")
    add("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        ".exe", 3842184,
        "bce44218421842184218421842184218421842a5",
        "0abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f678901",
        "118.0.2088.76", "Microsoft Edge", "Microsoft Corporation",
        "2024-10-04 11:14:00", "2024-11-12 03:14:00",
        "2024-11-04 03:14:00")
    add("C:\\Windows\\Explorer.EXE", ".exe", 4818421,
        "a5d7b4218421842184218421842184218421842f",
        "3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d",
        "10.0.19041.5247", "Microsoft Windows", "Microsoft Corporation",
        "2024-08-04 11:02:18.5000000", "2024-08-04 11:02:18.5000000",
        "2024-07-22 11:14:00")
    add("C:\\Windows\\System32\\cmd.exe", ".exe", 289792,
        "c1b3a4218421842184218421842184218421842b",
        "2c1a4f8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567",
        "10.0.19041.5247", "Microsoft Windows", "Microsoft Corporation",
        "2024-08-04 11:02:18.5000000", "2024-08-04 11:02:18.5000000",
        "2024-07-22 11:14:00")
    add("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
        ".exe", 38422144,
        "d2b4a4218421842184218421842184218421842c",
        "1a4f8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678a",
        "16.0.18025.20030", "Microsoft Office", "Microsoft Corporation",
        "2024-08-19 14:11:09", "2024-11-04 11:00:00",
        "2024-10-28 03:14:00")
    add("C:\\Windows\\System32\\drvinst.exe", ".exe", 68192,
        "abd34218421842184218421842184218421842f4",
        "90abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f67890",
        "10.0.19041.5247", "Microsoft Windows", "Microsoft Corporation",
        "2024-08-04 11:02:18.5000000", "2024-08-04 11:02:18.5000000",
        "2024-07-22 11:14:00")
    add("C:\\Windows\\System32\\rundll32.exe", ".exe", 72192,
        "bce14218421842184218421842184218421842a5",
        "abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f6789012",
        "10.0.19041.5247", "Microsoft Windows", "Microsoft Corporation",
        "2024-08-04 11:02:18.5000000", "2024-08-04 11:02:18.5000000",
        "2024-07-22 11:14:00")
    add("C:\\Windows\\System32\\svchost.exe", ".exe", 82048,
        "cdf54218421842184218421842184218421842b6",
        "bcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f67890123",
        "10.0.19041.5247", "Microsoft Windows", "Microsoft Corporation",
        "2024-08-04 11:02:18.5000000", "2024-08-04 11:02:18.5000000",
        "2024-07-22 11:14:00")
    return rows


def generate_srum(rng: random.Random) -> List[Dict[str, str]]:
    """SRUM per-process network usage, bucketed at hour boundaries.

    The 18:00 bucket captures the OneDrive upload window (BytesSent
    spike) and the msedge webmail activity (BytesSent for the
    composed message). The 17:30 bucket is the pre-exfil baseline,
    and earlier buckets are normal daytime usage.
    """
    rows: List[Dict[str, str]] = []

    def add(t, app, sid, sent, recv, evt=None):
        rows.append({
            "Timestamp": ts(t),
            "ApplicationName": app, "UserSID": sid,
            "InterfaceLuid": "1689399632855040",
            "BytesSent": str(sent), "BytesReceived": str(recv),
            "EventTimestamp": ts(evt if evt else t),
        })

    # Morning baseline.
    add("2024-11-12 09:00:00", "outlook.exe", USER_SID, 184221, 2418421)
    add("2024-11-12 09:00:00", "msedge.exe", USER_SID, 42184, 1842184)
    add("2024-11-12 09:00:00", "onedrive.exe", USER_SID, 11421, 84221)
    # Midday.
    add("2024-11-12 12:00:00", "outlook.exe", USER_SID, 84221, 1842184)
    add("2024-11-12 12:00:00", "msedge.exe", USER_SID, 42184, 2184221)
    add("2024-11-12 12:00:00", "svchost.exe", SYSTEM_SID, 8421, 42184)
    # Pre-exfil snapshot (17:30 bucket — corporate OneDrive only).
    add("2024-11-12 17:30:00", "outlook.exe", USER_SID, 42184, 184221)
    add("2024-11-12 17:30:00", "onedrive.exe", USER_SID, 12184, 84221)
    # The exfil window — 18:00 bucket aggregates 17:30 through 18:00.
    # OneDrive.exe BytesSent ~ 3.1 MB matches the two-file upload
    # summary in the OneDrive log ("BytesUploaded=3090605").
    add("2024-11-12 18:00:00", "onedrive.exe", USER_SID, 3184221, 184421)
    # msedge.exe BytesSent jumps to ~684 KB in the same bucket —
    # consistent with a small attachment uploaded through webmail
    # (suggestive, not conclusive).
    add("2024-11-12 18:00:00", "msedge.exe", USER_SID, 684221, 1842184)
    add("2024-11-12 18:00:00", "outlook.exe", USER_SID, 11421, 84221)
    add("2024-11-12 18:00:00", "svchost.exe", SYSTEM_SID, 11421, 84221)
    return rows


def generate_lnk_files(rng: random.Random) -> List[Dict[str, str]]:
    """LNK metadata — six pricing-related LNKs plus benign noise.

    Two LNKs per pricing file: one for the local C:\\HR\\Pricing
    path (system VolumeSerial 8A4C7E02) and one for the USB
    E:\\Confidential\\Pricing path (Kingston VolumeSerial F1D2E9A4).
    The label "KINGSTON" and DriveType "RemovableMedia" are how an
    analyst confirms the USB binding.
    """
    rows: List[Dict[str, str]] = []

    def add(src, sc, sm, sa, tc, tm, ta, size, rel, wd, lp,
            volser, label, dt, machine="hr-ws17"):
        rows.append({
            "SourceFile": src,
            "SourceCreated": ts(sc), "SourceModified": ts(sm),
            "SourceAccessed": ts(sa),
            "TargetCreated": ts(tc), "TargetModified": ts(tm),
            "TargetAccessed": ts(ta), "FileSize": str(size),
            "RelativePath": rel, "WorkingDirectory": wd, "LocalPath": lp,
            "VolumeSerialNumber": volser, "VolumeLabel": label,
            "DriveType": dt, "MachineId": machine,
        })

    recent = (f"C:\\Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows"
              "\\Recent")
    # --- Local C:\HR\Pricing LNKs (three) --------------------------------
    add(f"{recent}\\Q4_Customer_Pricing.lnk",
        "2024-11-12 17:38:42.5000000", "2024-11-12 17:38:42.5000000",
        "2024-11-12 17:38:42.5000000",
        "2024-09-22 11:14:00", "2024-11-08 14:18:42", T_OPEN_Q4,
        SIZE_Q4,
        "..\\..\\..\\..\\..\\..\\..\\HR\\Pricing\\Q4_Customer_Pricing.xlsx",
        "C:\\HR\\Pricing", "C:\\HR\\Pricing\\Q4_Customer_Pricing.xlsx",
        SYS_VOL_SERIAL, SYS_VOL_LABEL, "FixedHardDisk")
    add(f"{recent}\\Pricing_Strategy_Confidential.lnk",
        T_OPEN_DOCX, T_OPEN_DOCX, T_OPEN_DOCX,
        "2024-08-22 11:14:00", "2024-10-22 11:14:00", T_OPEN_DOCX,
        SIZE_DOCX,
        "..\\..\\..\\..\\..\\..\\..\\HR\\Pricing"
        "\\Pricing_Strategy_Confidential.docx",
        "C:\\HR\\Pricing",
        "C:\\HR\\Pricing\\Pricing_Strategy_Confidential.docx",
        SYS_VOL_SERIAL, SYS_VOL_LABEL, "FixedHardDisk")
    add(f"{recent}\\Margins_Q3.lnk",
        T_OPEN_MARGINS, T_OPEN_MARGINS, T_OPEN_MARGINS,
        "2024-08-22 11:14:00", "2024-09-30 16:42:00", T_OPEN_MARGINS,
        SIZE_MARGINS,
        "..\\..\\..\\..\\..\\..\\..\\HR\\Pricing\\Margins_Q3.xlsx",
        "C:\\HR\\Pricing", "C:\\HR\\Pricing\\Margins_Q3.xlsx",
        SYS_VOL_SERIAL, SYS_VOL_LABEL, "FixedHardDisk")
    # --- USB E:\Confidential\Pricing LNKs (three) ------------------------
    # The Kingston volume serial F1D2E9A4 + DriveType RemovableMedia is
    # the binding the chapter relies on to confirm the USB channel.
    add(f"{recent}\\Q4_Customer_Pricing (E).lnk",
        T_LNK_Q4_USB, T_LNK_Q4_USB, T_LNK_Q4_USB,
        T_LNK_Q4_USB, T_LNK_Q4_USB, T_LNK_Q4_USB,
        SIZE_Q4,
        "Confidential\\Pricing\\Q4_Customer_Pricing.xlsx",
        "E:\\Confidential\\Pricing",
        "E:\\Confidential\\Pricing\\Q4_Customer_Pricing.xlsx",
        USB_VOL_SERIAL, USB_VOL_LABEL, "RemovableMedia")
    add(f"{recent}\\Pricing_Strategy_Confidential (E).lnk",
        T_LNK_DOCX_USB, T_LNK_DOCX_USB, T_LNK_DOCX_USB,
        T_LNK_DOCX_USB, T_LNK_DOCX_USB, T_LNK_DOCX_USB,
        SIZE_DOCX,
        "Confidential\\Pricing\\Pricing_Strategy_Confidential.docx",
        "E:\\Confidential\\Pricing",
        "E:\\Confidential\\Pricing\\Pricing_Strategy_Confidential.docx",
        USB_VOL_SERIAL, USB_VOL_LABEL, "RemovableMedia")
    add(f"{recent}\\Margins_Q3 (E).lnk",
        T_LNK_MARGINS_USB, T_LNK_MARGINS_USB, T_LNK_MARGINS_USB,
        T_LNK_MARGINS_USB, T_LNK_MARGINS_USB, T_LNK_MARGINS_USB,
        SIZE_MARGINS,
        "Confidential\\Pricing\\Margins_Q3.xlsx",
        "E:\\Confidential\\Pricing",
        "E:\\Confidential\\Pricing\\Margins_Q3.xlsx",
        USB_VOL_SERIAL, USB_VOL_LABEL, "RemovableMedia")
    # --- Benign noise LNKs (not part of the exfil chain) -----------------
    add(f"{recent}\\benefits_2025.lnk",
        "2024-11-08 09:42:00", "2024-11-08 13:18:00", "2024-11-08 13:18:00",
        "2024-11-08 09:42:00", "2024-11-08 09:42:00", "2024-11-08 13:18:00",
        1284221,
        "..\\..\\..\\..\\..\\..\\Downloads\\benefits_2025.pdf",
        f"C:\\Users\\{USER}\\Downloads",
        f"C:\\Users\\{USER}\\Downloads\\benefits_2025.pdf",
        SYS_VOL_SERIAL, SYS_VOL_LABEL, "FixedHardDisk")
    add(f"{recent}\\HR_Onboarding.lnk",
        "2024-08-22 14:22:18", "2024-11-08 09:14:00", "2024-11-08 09:14:00",
        "2024-08-22 14:22:18", "2024-08-22 14:22:18", "2024-11-08 09:14:00",
        42891,
        "..\\..\\..\\..\\..\\..\\Documents\\HR_Onboarding.docx",
        f"C:\\Users\\{USER}\\Documents",
        f"C:\\Users\\{USER}\\Documents\\HR_Onboarding.docx",
        SYS_VOL_SERIAL, SYS_VOL_LABEL, "FixedHardDisk")
    add(f"{recent}\\Old_Pricing_Notes.lnk",
        "2024-09-04 14:22:18", "2024-10-22 11:14:00", "2024-10-22 11:14:00",
        "2024-09-04 14:22:18", "2024-09-04 14:22:18", "2024-10-22 11:14:00",
        128442,
        "..\\..\\..\\..\\..\\..\\Documents\\Old_Pricing_Notes.docx",
        f"C:\\Users\\{USER}\\Documents",
        f"C:\\Users\\{USER}\\Documents\\Old_Pricing_Notes.docx",
        SYS_VOL_SERIAL, SYS_VOL_LABEL, "FixedHardDisk")
    add(f"{recent}\\Q3_Forecast.lnk",
        "2024-09-22 11:14:00", "2024-10-15 11:14:00", "2024-10-15 11:14:00",
        "2024-09-22 11:14:00", "2024-09-22 11:14:00", "2024-10-15 11:14:00",
        184221,
        "..\\..\\..\\..\\..\\..\\..\\HR\\Forecasting\\Q3_Forecast.xlsx",
        "C:\\HR\\Forecasting",
        "C:\\HR\\Forecasting\\Q3_Forecast.xlsx",
        SYS_VOL_SERIAL, SYS_VOL_LABEL, "FixedHardDisk")
    add(f"{recent}\\benefits_overview.lnk",
        "2024-11-04 09:14:00", "2024-11-08 09:32:00", "2024-11-08 09:32:00",
        "2024-11-04 09:14:00", "2024-11-04 09:14:00", "2024-11-08 09:32:00",
        42184,
        "..\\..\\..\\..\\..\\..\\Downloads\\benefits_overview.pdf",
        f"C:\\Users\\{USER}\\Downloads",
        f"C:\\Users\\{USER}\\Downloads\\benefits_overview.pdf",
        SYS_VOL_SERIAL, SYS_VOL_LABEL, "FixedHardDisk")
    add(f"{recent}\\timesheet_template.lnk",
        "2024-10-22 13:18:00", "2024-10-22 13:30:00", "2024-10-22 13:30:00",
        "2024-10-22 13:18:00", "2024-10-22 13:18:00", "2024-10-22 13:30:00",
        38712,
        "..\\..\\..\\..\\..\\..\\Documents\\timesheet_template.xlsx",
        f"C:\\Users\\{USER}\\Documents",
        f"C:\\Users\\{USER}\\Documents\\timesheet_template.xlsx",
        SYS_VOL_SERIAL, SYS_VOL_LABEL, "FixedHardDisk")
    return rows


def generate_jump_lists(rng: random.Random) -> List[Dict[str, str]]:
    """Excel + Word + Explorer jump lists.

    The Excel jump list has both ``C:\\HR\\Pricing\\...`` and
    ``E:\\Confidential\\Pricing\\...`` MRU entries. The Word jump
    list mirrors that for the .docx. The Explorer jump list shows
    one entry with the Kingston volume serial — the user navigated
    to ``E:\\`` from File Explorer at 17:43:42.
    """
    rows: List[Dict[str, str]] = []

    def add(src, app_id, app_desc, n, lm, ct, tc, tm, lp, volser, size):
        rows.append({
            "SourceFile": src, "AppId": app_id, "AppDescription": app_desc,
            "EntryNumber": str(n),
            "LastModified": ts(lm), "CreationTime": ts(ct),
            "TargetCreated": ts(tc) if tc else "",
            "TargetModified": ts(tm) if tm else "",
            "LocalPath": lp, "Hostname": "hr-ws17",
            "VolumeSerialNumber": volser,
            "FileSize": str(size) if size else "",
        })

    excel_id = "12dc1ea8e34b6a0b"
    excel_src = f"{excel_id}.automaticDestinations-ms"
    add(excel_src, excel_id, "Microsoft Excel", 1,
        T_LNK_Q4_USB, T_LNK_Q4_USB, T_LNK_Q4_USB, T_LNK_Q4_USB,
        "E:\\Confidential\\Pricing\\Q4_Customer_Pricing.xlsx",
        USB_VOL_SERIAL, SIZE_Q4)
    add(excel_src, excel_id, "Microsoft Excel", 2,
        T_LNK_MARGINS_USB, T_LNK_MARGINS_USB,
        T_LNK_MARGINS_USB, T_LNK_MARGINS_USB,
        "E:\\Confidential\\Pricing\\Margins_Q3.xlsx",
        USB_VOL_SERIAL, SIZE_MARGINS)
    add(excel_src, excel_id, "Microsoft Excel", 3,
        T_OPEN_Q4, T_OPEN_Q4,
        "2024-09-22 11:14:00", "2024-11-08 14:18:42",
        "C:\\HR\\Pricing\\Q4_Customer_Pricing.xlsx",
        SYS_VOL_SERIAL, SIZE_Q4)
    add(excel_src, excel_id, "Microsoft Excel", 4,
        T_OPEN_MARGINS, T_OPEN_MARGINS,
        "2024-08-22 11:14:00", "2024-09-30 16:42:00",
        "C:\\HR\\Pricing\\Margins_Q3.xlsx",
        SYS_VOL_SERIAL, SIZE_MARGINS)
    add(excel_src, excel_id, "Microsoft Excel", 5,
        "2024-10-15 11:14:00", "2024-09-22 11:14:00",
        "2024-09-22 11:14:00", "2024-09-22 11:14:00",
        "C:\\HR\\Forecasting\\Q3_Forecast.xlsx",
        SYS_VOL_SERIAL, 184221)

    word_id = "9b9cdc69c1c24e2b"   # matches the docx SHA-256 prefix
    word_src = f"{word_id}.automaticDestinations-ms"
    add(word_src, word_id, "Microsoft Word", 1,
        T_LNK_DOCX_USB, T_LNK_DOCX_USB, T_LNK_DOCX_USB, T_LNK_DOCX_USB,
        "E:\\Confidential\\Pricing\\Pricing_Strategy_Confidential.docx",
        USB_VOL_SERIAL, SIZE_DOCX)
    add(word_src, word_id, "Microsoft Word", 2,
        T_OPEN_DOCX, T_OPEN_DOCX,
        "2024-08-22 11:14:00", "2024-10-22 11:14:00",
        "C:\\HR\\Pricing\\Pricing_Strategy_Confidential.docx",
        SYS_VOL_SERIAL, SIZE_DOCX)
    add(word_src, word_id, "Microsoft Word", 3,
        "2024-11-08 09:14:00", "2024-08-22 14:22:18",
        "2024-08-22 14:22:18", "2024-08-22 14:22:18",
        f"C:\\Users\\{USER}\\Documents\\HR_Onboarding.docx",
        SYS_VOL_SERIAL, 42891)
    add(word_src, word_id, "Microsoft Word", 4,
        "2024-10-22 11:14:00", "2024-09-04 14:22:18",
        "2024-09-04 14:22:18", "2024-09-04 14:22:18",
        f"C:\\Users\\{USER}\\Documents\\Old_Pricing_Notes.docx",
        SYS_VOL_SERIAL, 128442)

    # Explorer jump list — one entry referencing the USB volume serial.
    add("1b4dd67f29cb1962.automaticDestinations-ms",
        "1b4dd67f29cb1962", "File Explorer", 1,
        T_E_PRICING, T_E_PRICING, "", "",
        "", USB_VOL_SERIAL, 0)

    return rows


def generate_shellbags(rng: random.Random) -> List[Dict[str, str]]:
    """Shellbags showing both normal local navigation and E:\\ traversal.

    The E:\\Confidential\\Pricing entries at 17:43 are the
    user-attribution-quality evidence that the user (not a background
    process) opened the USB and went specifically to the pricing folder.
    """
    rows: List[Dict[str, str]] = []

    def add(bag, abs_, st, first, last, mru, node):
        rows.append({
            "BagPath": bag, "AbsolutePath": abs_, "ShellType": st,
            "FirstInteracted": ts(first), "LastInteracted": ts(last),
            "MRUPosition": str(mru), "NodeSlot": str(node),
        })

    add("BagMRU\\0", "Desktop", "Desktop",
        "2024-08-19 14:11:09", "2024-11-12 17:42:42", 0, 0)
    add("BagMRU\\0\\1", "My Computer", "RootFolder",
        "2024-08-19 14:11:09", T_E_CONF, 1, 1)
    add("BagMRU\\0\\1\\0", "C:\\", "Drive",
        "2024-08-19 14:11:14", T_OPEN_Q4, 0, 2)
    add("BagMRU\\0\\1\\0\\3", "C:\\HR", "Directory",
        "2024-08-22 11:14:00", T_OPEN_Q4, 3, 8)
    add("BagMRU\\0\\1\\0\\3\\0", "C:\\HR\\Pricing", "Directory",
        "2024-08-22 11:14:00", T_OPEN_DOCX, 0, 9)
    add("BagMRU\\0\\1\\0\\3\\1", "C:\\HR\\Forecasting", "Directory",
        "2024-09-22 11:14:00", "2024-10-15 11:14:00", 1, 10)
    add("BagMRU\\0\\1\\0\\1",
        f"C:\\Users\\{USER}\\Documents", "Directory",
        "2024-08-19 14:11:09", "2024-11-12 09:14:00", 1, 3)
    add("BagMRU\\0\\1\\0\\2",
        f"C:\\Users\\{USER}\\Downloads", "Directory",
        "2024-08-19 14:11:09", "2024-11-08 13:18:00", 2, 4)
    add("BagMRU\\0\\1\\0\\4",
        f"C:\\Users\\{USER}\\OneDrive - Finance Corp", "Directory",
        "2024-09-19 14:11:09", "2024-11-12 11:14:22", 4, 11)
    # E:\ — first interacted at 17:43:11 (right after the volume is bound).
    add("BagMRU\\0\\1\\1", "E:\\", "Drive",
        T_E_CONF, T_E_PRICING, 1, 15)
    add("BagMRU\\0\\1\\1\\0", "E:\\Confidential", "Directory",
        T_E_CONF, T_E_PRICING, 0, 16)
    add("BagMRU\\0\\1\\1\\0\\0",
        "E:\\Confidential\\Pricing", "Directory",
        T_E_PRICING, T_LNK_MARGINS_USB, 0, 17)
    add("BagMRU\\0\\1\\1\\0\\1",
        "E:\\Confidential\\HR", "Directory",
        T_E_PRICING, T_E_PRICING, 1, 18)
    add("BagMRU\\0\\1\\1\\1", "E:\\Photos", "Directory",
        T_E_CONF, T_E_CONF, 1, 19)
    add("BagMRU\\0\\2", "Network", "Hierarchy",
        "2024-08-19 14:11:09", "2024-11-04 09:32:00", 2, 5)
    return rows


def generate_usbstor(rng: random.Random) -> List[Dict[str, str]]:
    """USBSTOR registry rows — five devices in install order.

    The Kingston DataTraveler with serial 001A92053B7CBE3196B40A0F is
    the suspect device. The earlier Kingston with serial
    001A92038A1FAE6132B40A0F (different revision) rules out reuse —
    if someone tries to argue the device is one the user has plugged in
    before, point at the serial number, not the model.
    """
    rows: List[Dict[str, str]] = []

    def add(cls, vid, pid, rev, ser, friendly, first, last, ins, rem,
            parent, devid, volguid):
        rows.append({
            "DeviceClass": cls, "VendorId": vid, "ProductId": pid,
            "Revision": rev, "SerialNumber": ser, "FriendlyName": friendly,
            "FirstConnected": ts(first), "LastConnected": ts(last),
            "LastInsertTime": ts(ins), "LastRemovalTime": ts(rem),
            "ParentIdPrefix": parent, "DeviceInstanceId": devid,
            "VolumeGuid": volguid,
        })

    # Suspect device.
    add("Disk", USB_VENDOR_ID, USB_PRODUCT_ID, USB_REVISION, USB_SERIAL,
        USB_FRIENDLY, T_USB_INSERT, T_USB_INSERT, T_USB_INSERT,
        T_USB_REMOVE, "c&1eaf73b9&0",
        f"USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0"
        f"&Rev_1.00\\{USB_SERIAL}&0",
        USB_VOL_GUID)
    # Earlier benign SanDisk.
    add("Disk", "0781", "5575", "0832", "4C530001220615116192",
        "SanDisk Cruzer Glide USB Device",
        "2024-09-19 14:05:12", "2024-09-19 14:05:12",
        "2024-09-19 14:05:12", "2024-09-19 14:37:50",
        "9&3d0a812c&0",
        "USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer_Glide"
        "&Rev_8.32\\4C530001220615116192&0",
        "{72b1e088-9f3c-4d56-aa1b-58e3201abf10}")
    # Earlier generic mass storage.
    add("Disk", "058F", "6387", "0100", "058F0O1111B1",
        "Generic Mass-Storage USB Device",
        "2024-08-19 15:22:31", "2024-08-19 15:22:31",
        "2024-08-19 15:22:31", "2024-08-19 15:58:07",
        "7&2c1b3e9d&0",
        "USBSTOR\\Disk&Ven_Generic&Prod_Mass-Storage"
        "&Rev_1.00\\058F0O1111B1&0",
        "{a83d2c11-6e7a-4f02-9c5a-0db3e6f51122}")
    # Earlier Kingston — DIFFERENT serial, different revision (1.10).
    add("Disk", USB_VENDOR_ID, "1620", "0110",
        "001A92038A1FAE6132B40A0F",
        "Kingston DataTraveler 3.0 USB Device",
        "2024-09-02 13:31:44", "2024-10-21 13:02:19",
        "2024-10-21 13:02:19", "2024-10-21 13:40:55",
        "8&14a9f102&0",
        "USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0"
        "&Rev_1.10\\001A92038A1FAE6132B40A0F&0",
        "{c1f4a7d8-2b39-4e15-8a0c-7d9e44351e77}")
    # Old promotional CD-ROM — the oldest device, connected during IT build
    # after the OS install (system volume created 2024-08-04 11:02:18).
    add("CdRom", "058F", "A001", "0100", "058FA001CD0001",
        "USB CD-ROM Promotional Disk",
        "2024-08-12 09:14:00", "2024-08-12 09:14:00",
        "2024-08-12 09:14:00", "2024-08-12 09:39:42",
        "5&0c8a32fd&0",
        "USBSTOR\\CdRom&Ven_Generic&Prod_USB_CD-ROM"
        "&Rev_1.00\\058FA001CD0001&0",
        "{31ae6f02-8b1c-4d7f-90a9-fe2c1378ab44}")
    return rows


def generate_mountpoints(rng: random.Random) -> List[Dict[str, str]]:
    """HKLM\\System\\MountedDevices bindings.

    Two rows for the suspect Kingston device:
      - ``\\DosDevices\\E:`` binds the volume GUID to drive letter E:
      - ``\\??\\Volume{...}`` is the canonical volume entry
    Both must reference the same DeviceInstanceId for the binding to
    be unambiguous. The chapter asks "what drive letter was the
    Kingston device bound to?" — the answer comes from these two rows.
    """
    rows: List[Dict[str, str]] = []

    def add(key, name, vguid, drive, dt, linked, lwt, notes):
        rows.append({
            "KeyPath": key, "ValueName": name, "VolumeGuid": vguid,
            "DriveLetter": drive, "DeviceType": dt,
            "LinkedDeviceInstanceId": linked,
            "LastWriteTime": ts(lwt), "Notes": notes,
        })

    add("HKLM\\System\\MountedDevices", "\\DosDevices\\C:",
        SYS_VOL_GUID, "C:", "FixedDisk",
        f"STORAGE\\Volume\\{SYS_VOL_GUID}",
        "2024-08-04 11:02:18", "System volume (NTFS)")
    add("HKLM\\System\\MountedDevices", "\\DosDevices\\D:",
        "{2f3a91b5-0000-0000-0000-501f00000000}", "D:", "FixedDisk",
        "STORAGE\\Volume\\{2f3a91b5-0000-0000-0000-501f00000000}",
        "2024-08-04 11:02:18", "Recovery partition")
    add("HKLM\\System\\MountedDevices",
        "\\??\\Volume{a83d2c11-6e7a-4f02-9c5a-0db3e6f51122}",
        "", "", "RemovableMedia",
        "USBSTOR\\Disk&Ven_Generic&Prod_Mass-Storage\\058F0O1111B1",
        "2024-08-19 15:22:31",
        "Generic mass-storage device — historical mount")
    add("HKLM\\System\\MountedDevices",
        "\\??\\Volume{72b1e088-9f3c-4d56-aa1b-58e3201abf10}",
        "", "", "RemovableMedia",
        "USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer_Glide\\4C530001220615116192",
        "2024-09-19 14:05:12",
        "SanDisk Cruzer Glide — historical mount")
    add("HKLM\\System\\MountedDevices",
        "\\??\\Volume{c1f4a7d8-2b39-4e15-8a0c-7d9e44351e77}",
        "", "", "RemovableMedia",
        "USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0"
        "\\001A92038A1FAE6132B40A0F",
        "2024-10-21 13:02:19",
        "Earlier Kingston DataTraveler — different serial "
        "(rules out reuse)")
    add("HKLM\\System\\MountedDevices", "\\DosDevices\\E:",
        USB_VOL_GUID, "E:", "RemovableMedia",
        f"USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0\\{USB_SERIAL}",
        T_USB_BOUND,
        "Suspect volume — Kingston DataTraveler bound to E: at last "
        "connection")
    add("HKLM\\System\\MountedDevices",
        f"\\??\\Volume{USB_VOL_GUID}",
        "", "", "RemovableMedia",
        f"USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0\\{USB_SERIAL}",
        T_USB_BOUND,
        "Same volume GUID as E: binding above — confirms identity")
    add("HKLM\\System\\MountedDevices", "\\DosDevices\\Z:",
        "{1a2b3c4d-5e6f-4071-9081-aa11bb22cc33}", "Z:", "NetworkShare",
        "\\\\fileserver01.finance.example.com\\HRShare",
        "2024-09-12 08:14:55",
        "Mapped drive to corporate HR share (logon script)")
    # Registry values carry no timestamp of their own: LastWriteTime belongs
    # to the KEY. Every value under MountedDevices therefore reports the
    # key's most recent write, the same rule the book teaches for Run keys
    # (Ch5 section 5.1.2, Ch10 section 10.5). The per-device history lives
    # in USBSTOR and setupapi, not here.
    key_lwt = max(r["LastWriteTime"] for r in rows)
    for r in rows:
        r["LastWriteTime"] = key_lwt
    return rows


def generate_onedrive_accounts(rng: random.Random) -> List[Dict[str, str]]:
    """Both the corporate (Business1) and personal OneDrive accounts.

    The Business1 account is benign — it has been around since the
    user's hire date and is the SCCM-deployed corporate sign-in.
    The Personal account first appears in the registry at 17:46:02
    UTC — INSIDE the incident window. That timestamp is itself
    evidence: the user did not have a long-standing personal account
    on this device; they signed in specifically to exfiltrate.
    """
    rows: List[Dict[str, str]] = []

    def add(name, atype, email, cid, display, sync, tenant_id, tenant,
            first, last, notes):
        rows.append({
            "AccountName": name, "AccountType": atype,
            "UserEmail": email, "UserCid": cid,
            "DisplayName": display, "SyncFolderPath": sync,
            "TenantId": tenant_id, "TenantName": tenant,
            "FirstAdded": ts(first), "LastSignIn": ts(last),
            "Notes": notes,
        })

    add("Business1", "OneDriveForBusiness",
        BUSINESS_EMAIL, BUSINESS_CID, "HR User (Finance Corp)",
        f"C:\\Users\\{USER}\\OneDrive - Finance Corp",
        BUSINESS_TENANT_ID, BUSINESS_TENANT_NAME,
        "2024-08-19 14:11:14", T_CORP_ONEDRIVE,
        "Corporate-managed account; SCCM-deployed")
    add("Personal", "OneDrivePersonal",
        PERSONAL_EMAIL, PERSONAL_CID, "HR User",
        f"C:\\Users\\{USER}\\OneDrive",
        "", "",
        T_ONEDRIVE_LAUNCH, T_ONEDRIVE_LAUNCH,
        "Personal Microsoft account — first signed in inside the "
        "incident window")
    return rows


def generate_onedrive_syncdb(rng: random.Random) -> List[Dict[str, str]]:
    """OneDrive personal-account sync database rows.

    Sha256ContentHash MUST match the values in
    pricing-files-known-hashes.txt for the lab's "compare the hash of
    the uploaded blob against the legal-provided hash" step to work.
    """
    rows: List[Dict[str, str]] = []

    def add(cid, item, parent, local, remote, name, ext, size,
            state, lm, lcu, enq, completed, sha256):
        rows.append({
            "AccountUserCid": cid, "ItemId": item, "ParentItemId": parent,
            "LocalPath": local, "RemotePath": remote,
            "FileName": name, "FileExtension": ext, "FileSize": str(size),
            "SyncState": state,
            "LastModified": ts(lm), "LastChangeUtc": ts(lcu),
            "EnqueuedUtc": ts(enq), "UploadCompletedUtc": ts(completed),
            "Sha256ContentHash": sha256,
        })

    add(PERSONAL_CID, PERSONAL_Q4_ITEMID, PERSONAL_FOLDER_ITEMID,
        f"C:\\Users\\{USER}\\OneDrive\\Pricing-Backup"
        "\\Q4_Customer_Pricing.xlsx",
        "/personal/hr_user_personal_outlook_com/Documents/Pricing-Backup"
        "/Q4_Customer_Pricing.xlsx",
        "Q4_Customer_Pricing.xlsx", "xlsx", SIZE_Q4,
        "UploadComplete",
        "2024-11-08 14:18:42", "2024-11-12 17:46:42", "2024-11-12 17:46:42",
        T_ONEDRIVE_Q4_DONE, SHA256_Q4)
    add(PERSONAL_CID, PERSONAL_DOCX_ITEMID, PERSONAL_FOLDER_ITEMID,
        f"C:\\Users\\{USER}\\OneDrive\\Pricing-Backup"
        "\\Pricing_Strategy_Confidential.docx",
        "/personal/hr_user_personal_outlook_com/Documents/Pricing-Backup"
        "/Pricing_Strategy_Confidential.docx",
        "Pricing_Strategy_Confidential.docx", "docx", SIZE_DOCX,
        "UploadComplete",
        "2024-10-22 11:14:00", T_ONEDRIVE_DOCX, T_ONEDRIVE_DOCX,
        T_ONEDRIVE_DOCX_DONE, SHA256_DOCX)
    return rows


def generate_browser_history(rng: random.Random) -> List[Dict[str, str]]:
    """Edge SQLite history rows — mostly background, with the webmail trail.

    The 17:50-17:57 sequence is the load-bearing webmail evidence:
      14829 — login.live.com (typed)
      14830 — login.live.com/login.srf (linked from above)
      14831 — outlook.live.com/mail/0/ (signed-in inbox)
      14832 — /deeplink/compose (new message — note this URL exists in
              cache, but its content does not)
      14833 — /sentitems (the message was sent)
      14835 — login.live.com/logout.srf (user signed out)
    """
    rows: List[Dict[str, str]] = []

    def add(visit, t, url, title, dur, vc, tc, fv, trans, profile="Default"):
        rows.append({
            "VisitId": str(visit), "VisitTime": ts(t),
            "Url": url, "Title": title,
            "VisitDuration": str(dur),
            "VisitCount": str(vc), "TypedCount": str(tc),
            "FromVisit": str(fv), "Transition": trans,
            "UserProfile": profile,
        })

    # Morning corporate Outlook.
    add(14821, "2024-11-12 08:48:42",
        "https://outlook.office.com/mail/inbox",
        f"Inbox - {BUSINESS_EMAIL} - Outlook",
        184, 42, 12, 0, "LINK|FROM_ADDRESS_BAR")
    add(14822, "2024-11-12 09:14:08",
        "https://finance.sharepoint.com/sites/HR/Shared%20Documents"
        "/Forms/AllItems.aspx",
        "All Documents - HR - Finance Corp",
        212, 18, 2, 0, "LINK")
    add(14823, "2024-11-12 09:32:11",
        "https://outlook.office.com/mail/inbox/id/AAQk...",
        f"RE: Q4 pricing review - {BUSINESS_EMAIL}",
        68, 1, 0, 14821, "LINK")
    add(14824, "2024-11-12 11:14:22",
        "https://www.bing.com/search?q=excel+conditional+formatting"
        "+entire+row",
        "excel conditional formatting entire row - Search",
        42, 3, 0, 0, "TYPED")
    add(14825, "2024-11-12 11:14:55",
        "https://support.microsoft.com/en-us/office/use-conditional-"
        "formatting-to-highlight-information",
        "Use conditional formatting to highlight information - "
        "Microsoft Support",
        124, 1, 0, 14824, "LINK")
    add(14826, "2024-11-12 12:18:00",
        "https://www.bbc.com/news", "Home - BBC News",
        84, 8, 2, 0, "TYPED")
    add(14827, "2024-11-12 12:32:04",
        "https://outlook.office.com/calendar/view/workweek",
        f"Calendar - {BUSINESS_EMAIL} - Outlook",
        212, 12, 0, 0, "LINK|FROM_ADDRESS_BAR")
    add(14828, "2024-11-12 13:42:18",
        "https://learn.microsoft.com/en-us/office/troubleshoot/excel/"
        "excel-formula-issues",
        "Troubleshoot Excel formula issues - Office",
        184, 2, 0, 0, "LINK")
    # --- Webmail trail (the load-bearing part of the channel) -----------
    add(14829, "2024-11-12 17:50:42",
        "https://login.live.com/?wa=wsignin1.0",
        "Sign in to your Microsoft account",
        18, 3, 1, 0, "TYPED")
    add(14830, "2024-11-12 17:50:58",
        "https://login.live.com/login.srf",
        "Sign in to your Microsoft account",
        28, 2, 0, 14829, "LINK")
    add(14831, T_WEBMAIL_OPEN,
        "https://outlook.live.com/mail/0/",
        f"Mail - {PERSONAL_EMAIL} - Outlook",
        184, 1, 1, 14830, "LINK")
    add(14832, "2024-11-12 17:52:11",
        "https://outlook.live.com/mail/0/deeplink/compose",
        "New message - Outlook",
        142, 1, 0, 14831, "LINK")
    add(14833, "2024-11-12 17:54:42",
        "https://outlook.live.com/mail/0/sentitems",
        "Sent Items - Outlook",
        32, 1, 0, 14832, "LINK")
    add(14834, "2024-11-12 17:55:48",
        "https://outlook.live.com/mail/0/",
        f"Mail - {PERSONAL_EMAIL} - Outlook",
        84, 1, 0, 14833, "LINK")
    add(14835, "2024-11-12 17:57:18",
        "https://login.live.com/logout.srf",
        "Signed out - Microsoft account",
        12, 1, 0, 14834, "LINK")
    # Jobs-search activity earlier in the afternoon (motive context).
    add(14836, "2024-11-12 14:18:00",
        "https://www.linkedin.com/feed/",
        "LinkedIn",
        184, 4, 1, 0, "TYPED")
    add(14837, "2024-11-12 14:32:11",
        "https://www.linkedin.com/jobs/search",
        "Jobs - LinkedIn",
        142, 4, 0, 14836, "LINK")
    add(14838, "2024-11-12 15:42:08",
        "https://www.indeed.com/jobs?q=pricing+analyst&l=",
        "pricing analyst Jobs - Indeed",
        212, 2, 1, 0, "TYPED")
    add(14839, "2024-11-08 13:18:00",
        "https://benefits.financecorp.example.com/2025-overview",
        "2025 Benefits Overview - Finance Corp",
        184, 1, 0, 0, "LINK")
    add(14840, "2024-11-12 17:58:41",
        "https://outlook.office.com/mail/sentitems",
        f"Sent Items - {BUSINESS_EMAIL} - Outlook",
        42, 8, 0, 0, "LINK|FROM_ADDRESS_BAR")
    return rows


# ---------------------------------------------------------------------------
# Plain-text generators (not CSV — these write directly to file)
# ---------------------------------------------------------------------------

def generate_pricing_hashes_text() -> str:
    """The legal-reference SHA-256 file.

    This is the SOURCE OF TRUTH for the three hashes. If you change a
    hash here, you MUST also change the same hash in:
      - generate_onedrive_syncdb (Sha256ContentHash for the two files)
      - generate_onedrive_logs   (SHA256= in the Upload complete lines)
    Margins_Q3.xlsx never reaches OneDrive; its hash is only here.
    """
    lines = [
        "Pricing files — known SHA-256 hashes",
        "Provided by Legal as the reference target for the HR-WS17 "
        "investigation.",
        "Acquisition date: 2024-11-12 (host preserved at offboarding; "
        "case opened later — see note below)",
        "",
        ("File Name                                | SHA-256"),
        f"Q4_Customer_Pricing.xlsx                 | {SHA256_Q4}",
        f"Pricing_Strategy_Confidential.docx       | {SHA256_DOCX}",
        f"Margins_Q3.xlsx                          | {SHA256_MARGINS}",
        "",
        "Notes:",
        ("- Hashes generated against the canonical copies held by Legal at "
         "the time the case was opened (2024-12-03)."),
        ("- Compare any candidate file recovered from the host, the USB "
         "device, the personal OneDrive blob,"),
        ("  or any other source against these values. A match is strong "
         "evidence; a non-match is informative"),
        ("  (the file may have been re-saved, edited, archived, or "
         "compressed)."),
        ("- For files inside an archive (zip/7z), hash the file after "
         "extraction, not the archive itself."),
        "",
    ]
    return "\n".join(lines)


def generate_onedrive_logs_text() -> str:
    """The personal-account SyncDiagnostics log extract.

    Mirrors what the OneDrive client writes to
    %LOCALAPPDATA%\\Microsoft\\OneDrive\\logs\\Personal\\
    SyncDiagnostics-YYYY-MM-DD.log. SHA-256 values on the
    ``Upload complete`` lines must match
    ``pricing-files-known-hashes.txt`` and ``onedrive-syncdb.csv``.
    """
    lines = [
        "; Extract from %LOCALAPPDATA%\\Microsoft\\OneDrive\\logs\\"
        "Personal\\SyncDiagnostics-2024-11-12.log",
        f"; Account: {PERSONAL_EMAIL} (Personal)",
        f"; UserCid: {PERSONAL_CID}",
        f"; Client version: {ONEDRIVE_VERSION}",
        "; All timestamps UTC.",
        "",
        f"2024-11-12T17:46:02.184Z [INF] [SyncEngine] Account "
        f"'{PERSONAL_EMAIL}' (Personal) sign-in succeeded. "
        f"CID={PERSONAL_CID}",
        f"2024-11-12T17:46:02.214Z [INF] [SyncEngine] Initializing "
        f"sync root: C:\\Users\\{USER}\\OneDrive",
        "2024-11-12T17:46:02.821Z [INF] [SyncEngine] Sync root "
        "initialized. ScopeCount=1 ItemCount=0",
        "2024-11-12T17:46:03.142Z [INF] [Telemetry] Personal-account "
        "first activation on this device.",
        f"2024-11-12T17:46:14.421Z [INF] [FileWatcher] LocalChange "
        f"detected: C:\\Users\\{USER}\\OneDrive\\Pricing-Backup created",
        "2024-11-12T17:46:14.448Z [INF] [SyncEngine] Folder enqueued "
        "for upload: /personal/hr_user_personal_outlook_com/Documents"
        "/Pricing-Backup",
        f"2024-11-12T17:46:18.218Z [INF] [Uploader] Folder created on "
        f"server. ItemId={PERSONAL_FOLDER_ITEMID}",
        f"2024-11-12T17:46:42.184Z [INF] [FileWatcher] LocalChange "
        f"detected: C:\\Users\\{USER}\\OneDrive\\Pricing-Backup"
        f"\\Q4_Customer_Pricing.xlsx created (size={SIZE_Q4})",
        "2024-11-12T17:46:42.221Z [INF] [SyncEngine] File enqueued "
        "for upload: Q4_Customer_Pricing.xlsx",
        f"2024-11-12T17:46:42.318Z [INF] [Uploader] Beginning upload "
        f"Q4_Customer_Pricing.xlsx (size={SIZE_Q4})",
        "2024-11-12T17:46:48.214Z [INF] [Uploader] Chunk 1/3 "
        f"transferred (655360/{SIZE_Q4} bytes)",
        "2024-11-12T17:46:58.842Z [INF] [Uploader] Chunk 2/3 "
        f"transferred (1310720/{SIZE_Q4} bytes)",
        "2024-11-12T17:47:12.184Z [INF] [Uploader] Chunk 3/3 "
        f"transferred ({SIZE_Q4}/{SIZE_Q4} bytes)",
        f"2024-11-12T17:47:18.418Z [INF] [Uploader] Upload complete "
        f"Q4_Customer_Pricing.xlsx ItemId={PERSONAL_Q4_ITEMID} "
        f"SHA256={SHA256_Q4}",
        "2024-11-12T17:47:18.512Z [INF] [SyncEngine] Item state "
        "UploadComplete recorded in SyncEngineDatabase.db",
        f"2024-11-12T17:48:41.214Z [INF] [FileWatcher] LocalChange "
        f"detected: C:\\Users\\{USER}\\OneDrive\\Pricing-Backup"
        f"\\Pricing_Strategy_Confidential.docx created (size={SIZE_DOCX})",
        "2024-11-12T17:48:41.244Z [INF] [SyncEngine] File enqueued "
        "for upload: Pricing_Strategy_Confidential.docx",
        f"2024-11-12T17:48:41.421Z [INF] [Uploader] Beginning upload "
        f"Pricing_Strategy_Confidential.docx (size={SIZE_DOCX})",
        "2024-11-12T17:48:48.218Z [INF] [Uploader] Chunk 1/2 "
        f"transferred (655360/{SIZE_DOCX} bytes)",
        "2024-11-12T17:49:12.421Z [INF] [Uploader] Chunk 2/2 "
        f"transferred ({SIZE_DOCX}/{SIZE_DOCX} bytes)",
        f"2024-11-12T17:49:18.214Z [INF] [Uploader] Upload complete "
        f"Pricing_Strategy_Confidential.docx ItemId={PERSONAL_DOCX_ITEMID} "
        f"SHA256={SHA256_DOCX}",
        "2024-11-12T17:49:18.318Z [INF] [SyncEngine] Item state "
        "UploadComplete recorded in SyncEngineDatabase.db",
        "2024-11-12T17:49:42.184Z [INF] [SyncEngine] No pending items. "
        "Sync queue idle.",
        "2024-11-12T17:50:00.142Z [INF] [Telemetry] Sync session "
        "summary: ItemsUploaded=2 BytesUploaded=3090605 Errors=0 "
        "Duration=00:03:58",
        f"2024-11-12T17:55:18.418Z [WRN] [FileWatcher] LocalChange "
        f"detected outside sync root: C:\\Users\\{USER}\\AppData\\Local"
        f"\\Temp\\Q4_Customer_Pricing.xlsx deleted (ignored)",
        f"2024-11-12T17:55:18.421Z [WRN] [FileWatcher] LocalChange "
        f"detected outside sync root: C:\\Users\\{USER}\\AppData\\Local"
        f"\\Temp\\Pricing_Strategy_Confidential.docx deleted (ignored)",
        "2024-11-12T17:58:42.184Z [INF] [Heartbeat] Sync engine idle. "
        "AccountState=Healthy QueueDepth=0",
        f"2024-11-12T18:01:18.214Z [INF] [SyncEngine] Account "
        f"'{PERSONAL_EMAIL}' sign-out requested by user",
        f"2024-11-12T18:01:18.421Z [INF] [SyncEngine] Account "
        f"'{PERSONAL_EMAIL}' signed out. SyncRootDetached=False "
        "CacheRetained=True",
        "2024-11-12T18:02:08.184Z [INF] [SyncEngine] Process exit. "
        "Reason=UserLogoff",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# ShimCache / AppCompatCache
# ---------------------------------------------------------------------------

def generate_shimcache(rng: random.Random) -> List[Dict[str, str]]:
    """AppCompatCacheParser-style output for the HR-WS17 SYSTEM hive.

    This is an insider-data-theft case, so nothing here is malware. The
    value of the file is that it is a fourth, independent execution-adjacent
    source alongside Prefetch, Amcache and the Security log — and it covers
    two binaries the others do not both cover:

    * ``7zG.exe`` sits high in the cache (it ran at 17:40:11) and
      ``7z.exe``, its command-line sibling, sits just below it. ``7z.exe``
      appears in ``amcache.csv`` but has **no Prefetch entry**; ShimCache is
      the second artifact that shows it was there at all.
    * ``OneDrive.exe`` and ``msedge.exe`` both appear with file timestamps
      from earlier in the month — the cache records the *binary's* mtime,
      not when the user ran it. Reading these as run times is the classic
      ShimCache mistake and this dataset will punish it.

    Ordering is insertion order, most-recent first. It is not, and must not
    be, sorted by ``LastModifiedTimeUTC``.
    """
    _ = rng
    rows: List[Dict[str, str]] = []

    def add(path: str, last_modified: str) -> None:
        rows.append({
            "ControlSet": SHIMCACHE_CONTROLSET,
            "CacheEntryPosition": str(len(rows)),
            "Path": path,
            "LastModifiedTimeUTC": ts(last_modified),
            "Executed": SHIMCACHE_EXECUTED,
            "Duplicate": "False",
            "SourceFile": SHIMCACHE_SOURCE,
        })

    sys32 = "C:\\Windows\\System32"
    office = "C:\\Program Files\\Microsoft Office\\root\\Office16"
    os_build = "2024-08-04 11:02:18.5000000"
    office_mtime = "2024-11-04 11:00:00.0000000"
    sevenzip_mtime = "2024-09-19 14:42:11.0000000"

    # --- Exfiltration window (most recent first) --------------------------
    add("C:\\Windows\\Explorer.EXE", os_build)
    add(f"{sys32}\\cmd.exe", os_build)
    add("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "2024-11-12 03:14:00.0000000")
    add(f"C:\\Users\\{USER}\\AppData\\Local\\Microsoft\\OneDrive\\"
        "OneDrive.exe", "2024-11-12 03:14:00.0000000")
    add(f"C:\\Users\\{USER}\\AppData\\Local\\Microsoft\\OneDrive\\"
        f"{ONEDRIVE_VERSION}\\FileSyncHelper.exe",
        "2024-11-12 03:14:00.0000000")
    add(f"{sys32}\\dllhost.exe", os_build)
    add(f"{sys32}\\rundll32.exe", os_build)
    add(f"{sys32}\\drvinst.exe", os_build)
    add("C:\\Program Files\\7-Zip\\7zG.exe", sevenzip_mtime)
    # 7z.exe has an Amcache row but no Prefetch entry — ShimCache is the
    # corroborating source.
    add("C:\\Program Files\\7-Zip\\7z.exe", sevenzip_mtime)
    add(f"{office}\\WINWORD.EXE", office_mtime)
    add(f"{office}\\EXCEL.EXE", office_mtime)

    # --- Earlier the same day ---------------------------------------------
    add(f"{sys32}\\taskhostw.exe", os_build)
    add("C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\"
        "msedgewebview2.exe", "2024-11-12 03:14:00.0000000")
    add(f"{office}\\OUTLOOK.EXE", office_mtime)
    add(f"{sys32}\\userinit.exe", os_build)
    add(f"{sys32}\\svchost.exe", os_build)
    add(f"{sys32}\\winlogon.exe", os_build)

    # --- Background: unchanged for weeks ----------------------------------
    add(f"{sys32}\\SearchIndexer.exe", os_build)
    add(f"{sys32}\\SearchProtocolHost.exe", os_build)
    add(f"{sys32}\\SearchFilterHost.exe", os_build)
    add(f"{sys32}\\RuntimeBroker.exe", os_build)
    add(f"{sys32}\\sihost.exe", os_build)
    add(f"{sys32}\\ctfmon.exe", os_build)
    add(f"{sys32}\\dwm.exe", os_build)
    add(f"{sys32}\\LogonUI.exe", os_build)
    add(f"{sys32}\\lsass.exe", os_build)
    add(f"{sys32}\\services.exe", os_build)
    add(f"{sys32}\\spoolsv.exe", os_build)
    add(f"{sys32}\\consent.exe", os_build)
    add(f"{sys32}\\wermgr.exe", os_build)
    add(f"{sys32}\\smartscreen.exe", os_build)
    add(f"{sys32}\\WmiPrvSE.exe", os_build)
    add(f"{sys32}\\backgroundTaskHost.exe", os_build)
    add(f"{sys32}\\NOTEPAD.EXE", os_build)
    add(f"{sys32}\\SnippingTool.exe", os_build)
    add("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\"
        "4.18.24090.11-0\\MsMpEng.exe", "2024-11-04 03:14:00.0000000")
    add("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\"
        "4.18.24090.11-0\\MpCmdRun.exe", "2024-11-04 03:14:00.0000000")
    add("C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\"
        "OfficeClickToRun.exe", office_mtime)
    add("C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\"
        "MicrosoftEdgeUpdate.exe", "2024-11-04 03:14:00.0000000")
    return rows


# ---------------------------------------------------------------------------
# Recycle Bin
# ---------------------------------------------------------------------------

def generate_recyclebin(rng: random.Random) -> List[Dict[str, str]]:
    """``RBCmd``-style output for ``C:\\$Recycle.Bin\\<SID>\\``.

    One row per ``$I`` metadata file: ``SourceName`` is the ``$I`` file's own
    path, ``FileName`` is the original full path recorded inside it,
    ``DeletedOn`` is the deletion timestamp it stores.

    **The three pricing rows are orphaned ``$I`` records.** The user deleted
    the ``C:\\HR\\Pricing\\`` contents to the Recycle Bin at 17:57:42 and
    then emptied the bin twenty seconds later (see ``T_BIN_EMPTIED``), which
    unlinks both the ``$I`` metadata and the ``$R`` payload. These three
    ``$I`` records were recovered from unallocated space and parsed
    individually; the matching ``$R`` files could not be recovered. That
    distinction matters for the report: the ``$I`` proves *which* files were
    deleted and *when*, but it does not give you their contents back, so
    hash comparison against ``pricing-files-known-hashes.txt`` is not
    available through this channel.

    The 17:57:42 ``DeletedOn`` values line up to the second with the
    ``FileDelete`` rows in ``usn-journal.csv`` and with the ``InUse=False``
    MFT entries 20420-20422 — three sources, one deletion event.

    Note also what is absent. The two transient copies staged in ``%TEMP%``
    were removed at 17:55:11 by ``cmd.exe /c del``, and ``del`` bypasses the
    Recycle Bin entirely, so they have no ``$I`` record at all. Nothing from
    the ``E:`` volume appears here either — removable media does not use the
    system volume's Recycle Bin.
    """
    _ = rng
    rows: List[Dict[str, str]] = []

    def add(tag, ftype, name, size, deleted, created, modified):
        ext = "" if ftype == "Directory" else name[name.rfind("."):]
        rows.append({
            "SourceName": f"{RECYCLE_BIN}\\$I{tag}{ext}",
            "FileType": ftype,
            "FileName": name,
            "FileSize": str(size),
            "DeletedOn": ts(deleted),
            "SourceCreated": ts(created),
            "SourceModified": ts(modified),
        })

    docs = f"C:\\Users\\{USER}\\Documents"
    desk = f"C:\\Users\\{USER}\\Desktop"
    dl = f"C:\\Users\\{USER}\\Downloads"

    # --- The three pricing files (orphaned $I, $R purged) -----------------
    # Sizes, created and modified values are taken straight from MFT entries
    # 20420 / 20421 / 20422 — an $I record stores the source file's own
    # timestamps, so they must agree.
    add("A1B2C3", "File", "C:\\HR\\Pricing\\Q4_Customer_Pricing.xlsx",
        SIZE_Q4, T_PRICING_DELETE, "2024-09-22 11:14:00",
        "2024-11-08 14:18:42")
    add("D4E5F6", "File",
        "C:\\HR\\Pricing\\Pricing_Strategy_Confidential.docx",
        SIZE_DOCX, T_PRICING_DELETE, "2024-08-22 11:14:00",
        "2024-10-22 11:14:00")
    add("A7B8C9", "File", "C:\\HR\\Pricing\\Margins_Q3.xlsx",
        SIZE_MARGINS, T_PRICING_DELETE, "2024-08-22 11:14:00",
        "2024-09-30 16:42:00")

    # --- Ordinary earlier deletions (intact $I + $R pairs) ----------------
    add("B1C2D3", "File", f"{docs}\\Old_Pricing_Notes.docx", 128442,
        "2024-10-22 11:18:44", "2024-09-04 14:22:18",
        "2024-09-04 14:22:18")
    add("E4F5A6", "File", f"{desk}\\Pricing_scratch.xlsx", 24118,
        "2024-11-08 16:42:11", "2024-11-08 09:14:00",
        "2024-11-08 16:04:22")
    add("C7D8E9", "Directory", f"{docs}\\Q2 Archive", 4218442,
        "2024-10-04 10:22:18", "2024-04-02 09:14:00",
        "2024-07-11 15:42:00")
    add("F1A2B3", "File", f"{dl}\\open_enrollment_2025.pdf", 1842114,
        "2024-11-08 13:22:00", "2024-11-08 09:42:00",
        "2024-11-08 09:42:00")
    add("D4E5A6", "File", f"{desk}\\meeting_notes.txt", 2184,
        "2024-09-19 15:02:11", "2024-09-19 14:11:00",
        "2024-09-19 14:58:42")
    return rows


# ---------------------------------------------------------------------------
# Volatility 3 output (memory)
# ---------------------------------------------------------------------------
#
# Format note: Volatility 3's plain-text renderer joins fields with single
# TAB characters after a two-line banner. The committed WEB-APP-03 dataset
# has those tabs expanded at tabstop 8, and these files do the same, so the
# two hosts' memory output can be read with identical tooling. Build rows
# with ``vrow()``, then ``vrender()`` applies ``expandtabs(8)`` once at the
# end. Do NOT hand-pad columns with spaces.

VOL_BANNER = [
    "Volatility 3 Framework 2.5.2",
    "Progress:  100.00" + " " * 15 + "PDB scanning finished",
]


def vrow(*fields) -> List[str]:
    """Build one tab-delimited Volatility row from positional fields."""
    return [str(f) for f in fields]


def vrender(blocks) -> str:
    """Join blocks into file content, expanding tabs at tabstop 8."""
    lines: List[str] = []
    for b in blocks:
        lines.append("\t".join(b) if isinstance(b, list) else b)
    return ("\n".join(lines) + "\n").expandtabs(8)


# (pid, ppid, name, offset, threads, sessionid, wow64, create, exit)
#
# The user's session is still live: WinPmem ran at 18:01:12, sixty-two
# seconds before the 18:02:14 logoff. Two facts in this table do the
# forensic work:
#
#   * There are **two OneDrive.exe processes**. PID 3184 started at 08:42:54,
#     launched by explorer.exe shortly after the 08:42:11 logon (the
#     corporate Business1 account). PID 6428 started at
#     17:46:02 — mid-session, matching the Personal account's FirstAdded
#     value in onedrive-accounts.csv to the second. A second sync client
#     appearing in the middle of the afternoon is the single clearest
#     memory-side indicator of the personal-account channel.
#   * ``7zG.exe`` (17:40:11) and ``cmd.exe`` (17:55:11) are **absent** —
#     both had already exited by acquisition time. Prefetch and the Security
#     log still have them. Memory is a snapshot, not a history, and the
#     capstone answer should say so rather than treating the gap as a
#     contradiction.
VOL_PROCS = [
    (4, 0, "System", "0xb28c4e07d040", 172, "N/A", "False",
     "2024-11-12 02:14:00.000000", "N/A"),
    (88, 4, "Registry", "0xb28c4e0a3080", 4, "N/A", "False",
     "2024-11-12 02:14:00.000000", "N/A"),
    (356, 4, "smss.exe", "0xb28c4f6c0040", 2, "N/A", "False",
     "2024-11-12 02:14:02.000000", "N/A"),
    (472, 464, "csrss.exe", "0xb28c50f47140", 11, "0", "False",
     "2024-11-12 02:14:06.000000", "N/A"),
    (556, 548, "wininit.exe", "0xb28c50f96080", 1, "0", "False",
     "2024-11-12 02:14:07.000000", "N/A"),
    (564, 548, "csrss.exe", "0xb28c50fa6080", 13, "1", "False",
     "2024-11-12 02:14:07.000000", "N/A"),
    (648, 548, "winlogon.exe", "0xb28c51214080", 4, "1", "False",
     "2024-11-12 02:14:14.000000", "N/A"),
    (704, 556, "services.exe", "0xb28c511ad080", 7, "0", "False",
     "2024-11-12 02:14:08.000000", "N/A"),
    (724, 556, "lsass.exe", "0xb28c511c8080", 10, "0", "False",
     "2024-11-12 02:14:08.000000", "N/A"),
    (836, 704, "svchost.exe", "0xb28c5142a080", 22, "0", "False",
     "2024-11-12 02:14:09.000000", "N/A"),
    (908, 704, "svchost.exe", "0xb28c51488080", 14, "0", "False",
     "2024-11-12 02:14:09.000000", "N/A"),
    (984, 704, "svchost.exe", "0xb28c514e2080", 18, "0", "False",
     "2024-11-12 02:14:09.000000", "N/A"),
    (1042, 704, "svchost.exe", "0xb28c5155c080", 9, "0", "False",
     "2024-11-12 02:14:10.000000", "N/A"),
    (1188, 704, "svchost.exe", "0xb28c5161a080", 12, "0", "False",
     "2024-11-12 02:14:11.000000", "N/A"),
    (1284, 648, "fontdrvhost.exe", "0xb28c516c4080", 5, "1", "False",
     "2024-11-12 02:14:14.000000", "N/A"),
    (1348, 648, "dwm.exe", "0xb28c51742080", 14, "1", "False",
     "2024-11-12 02:14:15.000000", "N/A"),
    (1584, 704, "spoolsv.exe", "0xb28c518a1080", 8, "0", "False",
     "2024-11-12 02:14:18.000000", "N/A"),
    (1712, 704, "MsMpEng.exe", "0xb28c5194c080", 28, "0", "False",
     "2024-11-12 02:14:20.000000", "N/A"),
    (1884, 704, "SearchIndexer.exe", "0xb28c51a2e080", 16, "0", "False",
     "2024-11-12 02:14:24.000000", "N/A"),
    (2104, 704, "SecurityHealthService.exe", "0xb28c51b18080", 6, "0",
     "False", "2024-11-12 02:14:28.000000", "N/A"),
    (2288, 984, "sihost.exe", "0xb28c51c04080", 9, "1", "False",
     "2024-11-12 08:42:11.000000", "N/A"),
    (2344, 984, "taskhostw.exe", "0xb28c51c9a080", 8, "1", "False",
     "2024-11-12 08:42:11.000000", "N/A"),
    (2412, 2384, "userinit.exe", "0xb28c51d12080", 0, "1", "False",
     "2024-11-12 08:42:42.000000", "2024-11-12 08:43:04.000000"),
    (2468, 2412, "explorer.exe", "0xb28c51db8080", 74, "1", "False",
     "2024-11-12 08:42:42.000000", "N/A"),
    (2596, 984, "RuntimeBroker.exe", "0xb28c51e64080", 12, "1", "False",
     "2024-11-12 08:42:48.000000", "N/A"),
    (2704, 2468, "ctfmon.exe", "0xb28c51f02080", 11, "1", "False",
     "2024-11-12 08:42:52.000000", "N/A"),
    (3024, 2468, "OUTLOOK.EXE", "0xb28c52148080", 42, "1", "False",
     "2024-11-12 08:48:14.000000", "N/A"),
    # Business1 OneDrive — started with the logon.
    (3184, 2468, "OneDrive.exe", "0xb28c5221c080", 24, "1", "False",
     "2024-11-12 08:42:54.000000", "N/A"),
    (4218, 2468, "EXCEL.EXE", "0xb28c52488080", 31, "1", "False",
     "2024-11-12 17:38:42.000000", "N/A"),
    (4258, 2468, "WINWORD.EXE", "0xb28c5250a080", 27, "1", "False",
     "2024-11-12 17:39:18.000000", "N/A"),
    (5842, 984, "dllhost.exe", "0xb28c52618080", 7, "1", "False",
     "2024-11-12 17:42:14.000000", "N/A"),
    # Personal OneDrive — started mid-afternoon. This is the row.
    (6428, 2468, "OneDrive.exe", "0xb28c526f4080", 26, "1", "False",
     "2024-11-12 17:46:02.000000", "N/A"),
    (6604, 2468, "msedge.exe", "0xb28c527a8080", 44, "1", "False",
     "2024-11-12 17:51:04.000000", "N/A"),
    (6648, 6604, "msedge.exe", "0xb28c5282c080", 12, "1", "False",
     "2024-11-12 17:51:04.000000", "N/A"),
    (6702, 6604, "msedge.exe", "0xb28c528b0080", 18, "1", "False",
     "2024-11-12 17:51:05.000000", "N/A"),
    (6744, 6604, "msedge.exe", "0xb28c52934080", 15, "1", "False",
     "2024-11-12 17:51:06.000000", "N/A"),
    (7108, 984, "WmiPrvSE.exe", "0xb28c52a18080", 9, "0", "False",
     "2024-11-12 17:57:44.000000", "N/A"),
    # The acquisition tool itself. Every memory image contains the
    # footprint of whatever captured it; documenting that in the report is
    # part of a defensible acquisition record.
    (7284, 2468, "winpmem_mini_x6", "0xb28c52ac2080", 3, "1", "False",
     "2024-11-12 18:01:12.000000", "N/A"),
    (7290, 7284, "conhost.exe", "0xb28c52b44080", 4, "1", "False",
     "2024-11-12 18:01:12.000000", "N/A"),
]


def generate_volatility_pslist() -> str:
    """``vol.py -f HR-WS17-memory.raw windows.pslist``."""
    blocks = list(VOL_BANNER)
    blocks.append("")
    blocks.append(vrow("PID", "PPID", "ImageFileName", "Offset(V)",
                       "Threads", "Handles", "SessionId", "Wow64",
                       "CreateTime", "ExitTime", "File output"))
    blocks.append("")
    for (pid, ppid, name, off, thr, sid, wow, ctime, etime) in VOL_PROCS:
        blocks.append(vrow(pid, ppid, name, off, thr, "-", sid, wow,
                           ctime, etime, "Disabled"))
    return vrender(blocks)


def generate_volatility_netscan() -> str:
    """``vol.py -f HR-WS17-memory.raw windows.netscan``.

    No C2, no beacon, no listener an adversary put there — this is an
    insider case and the sockets are all ordinary business traffic. The
    finding is *which* ordinary traffic: PID 6428 (the second OneDrive
    instance) holds two established TCP/443 sockets to the consumer
    OneDrive endpoint ``d.docs.live.net``, which the corporate instance
    (PID 3184) never touches — it talks only to the tenant SharePoint
    address. Two sync clients, two destinations, one host.
    """
    blocks = list(VOL_BANNER)
    blocks.append("")
    blocks.append(vrow("Offset", "Proto", "LocalAddr", "LocalPort",
                       "ForeignAddr", "ForeignPort", "State", "PID",
                       "Owner", "Created"))
    blocks.append("")

    conns = [
        # Listeners.
        ("0xb28c53a0c010", "TCPv4", "0.0.0.0", 135, "0.0.0.0", 0,
         "LISTENING", 836, "svchost.exe", "2024-11-12 02:14:09.000000"),
        ("0xb28c53a0c180", "TCPv6", "::", 135, "::", 0, "LISTENING",
         836, "svchost.exe", "2024-11-12 02:14:09.000000"),
        ("0xb28c53a0c2f0", "TCPv4", "0.0.0.0", 445, "0.0.0.0", 0,
         "LISTENING", 4, "System", "2024-11-12 02:14:00.000000"),
        ("0xb28c53a0c460", "TCPv4", "0.0.0.0", 5040, "0.0.0.0", 0,
         "LISTENING", 1042, "svchost.exe",
         "2024-11-12 02:14:10.000000"),
        ("0xb28c53a0c5d0", "TCPv4", "127.0.0.1", 49670, "0.0.0.0", 0,
         "LISTENING", 3184, "OneDrive.exe",
         "2024-11-12 08:42:55.000000"),
        ("0xb28c53a0c740", "TCPv4", "127.0.0.1", 51884, "0.0.0.0", 0,
         "LISTENING", 6428, "OneDrive.exe",
         "2024-11-12 17:46:03.000000"),
        # Corporate mail / SharePoint — the normal-day baseline.
        ("0xb28c53a1a010", "TCPv4", HOST_IP, 51204, "52.96.128.45", 443,
         "ESTABLISHED", 3024, "OUTLOOK.EXE",
         "2024-11-12 08:48:16.000000"),
        ("0xb28c53a1a180", "TCPv4", HOST_IP, 51208, "52.96.128.45", 443,
         "ESTABLISHED", 3024, "OUTLOOK.EXE",
         "2024-11-12 08:48:16.000000"),
        ("0xb28c53a1a2f0", "TCPv4", HOST_IP, 51442, "13.107.42.14", 443,
         "ESTABLISHED", 3184, "OneDrive.exe",
         "2024-11-12 08:42:57.000000"),
        ("0xb28c53a1a460", "TCPv4", HOST_IP, 51448, "13.107.42.14", 443,
         "CLOSE_WAIT", 3184, "OneDrive.exe",
         "2024-11-12 14:00:18.000000"),
        # Personal OneDrive — the exfiltration channel.
        ("0xb28c53a2a010", "TCPv4", HOST_IP, 52108, "13.107.42.12", 443,
         "ESTABLISHED", 6428, "OneDrive.exe",
         "2024-11-12 17:46:04.000000"),
        ("0xb28c53a2a180", "TCPv4", HOST_IP, 52112, "13.107.42.12", 443,
         "ESTABLISHED", 6428, "OneDrive.exe",
         "2024-11-12 17:46:44.000000"),
        ("0xb28c53a2a2f0", "TCPv4", HOST_IP, 52118, "40.126.32.78", 443,
         "CLOSED", 6428, "OneDrive.exe",
         "2024-11-12 17:46:02.000000"),
        # Webmail session. PID 6604 starts at 17:51:04, so none of its
        # sockets can be older than that.
        ("0xb28c53a3a010", "TCPv4", HOST_IP, 52404, "40.126.32.78", 443,
         "CLOSE_WAIT", 6604, "msedge.exe",
         "2024-11-12 17:51:04.000000"),
        ("0xb28c53a3a180", "TCPv4", HOST_IP, 52408, "52.96.128.51", 443,
         "ESTABLISHED", 6604, "msedge.exe",
         "2024-11-12 17:51:04.000000"),
        ("0xb28c53a3a2f0", "TCPv4", HOST_IP, 52412, "52.96.128.51", 443,
         "ESTABLISHED", 6604, "msedge.exe",
         "2024-11-12 17:52:11.000000"),
        ("0xb28c53a3a460", "TCPv4", HOST_IP, 52418, "13.107.21.200", 443,
         "TIME_WAIT", 6604, "msedge.exe",
         "2024-11-12 17:53:04.000000"),
        # Background OS traffic.
        ("0xb28c53a4a010", "TCPv4", HOST_IP, 50218, "13.107.4.50", 443,
         "CLOSE_WAIT", 908, "svchost.exe",
         "2024-11-12 03:00:14.000000"),
        ("0xb28c53a4a180", "TCPv4", HOST_IP, 50442, "13.107.42.14", 443,
         "ESTABLISHED", 1712, "MsMpEng.exe",
         "2024-11-12 12:00:04.000000"),
        ("0xb28c53a4a2f0", "UDPv4", HOST_IP, 55004, "*", 0, "",
         1188, "svchost.exe", "2024-11-12 02:14:11.000000"),
        ("0xb28c53a4a460", "UDPv4", HOST_IP, 138, "*", 0, "",
         4, "System", "2024-11-12 02:14:00.000000"),
    ]
    for (off, proto, la, lp, fa, fp, state, pid, owner, created) in conns:
        blocks.append(vrow(off, proto, la, lp, fa, fp, state, pid, owner,
                           created))
    return vrender(blocks)


def generate_volatility_cmdline() -> str:
    """``vol.py -f HR-WS17-memory.raw windows.cmdline``.

    The two Office command lines still carry ``C:\\HR\\Pricing\\`` paths —
    the folder that was deleted at 17:57:42 and is ``InUse=False`` in the
    MFT by the time the disk was imaged. Memory holds the argument strings
    that the file system no longer resolves, and they match the 17:38:42 /
    17:39:18 EID 4688 command lines character for character.

    Note what the command lines do *not* show: the ``E:\\Confidential\\
    Pricing\\`` copies opened at 17:44-17:45. Office is single-instance, so
    those later opens were handed to the already-running EXCEL.EXE and
    WINWORD.EXE over DDE and never appeared on a command line. The LNK
    files are the evidence for those opens; memory is not. Knowing which
    artifact answers which question is the point.
    """
    blocks = list(VOL_BANNER)
    blocks.append("")
    blocks.append(vrow("PID", "Process", "Args"))
    blocks.append("")

    sys32 = "C:\\Windows\\system32"
    office = "C:\\Program Files\\Microsoft Office\\root\\Office16"
    onedrive = (f"C:\\Users\\{USER}\\AppData\\Local\\Microsoft\\OneDrive\\"
                "OneDrive.exe")
    edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    unreadable = "Required memory at 0x20 is not valid (process exited?)"

    args = {
        4: unreadable,
        88: unreadable,
        356: "\\SystemRoot\\System32\\smss.exe",
        472: f"%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows "
             "SharedSection=1024,20480,768 Windows=On "
             "SubSystemType=Windows ServerDll=basesrv,1 "
             "ServerDll=winsrv:UserServerDllInitialization,3 "
             "ServerDll=sxssrv,4 ProfileControl=Off "
             "MaxRequestThreads=16",
        556: "wininit.exe",
        564: f"%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows "
             "SharedSection=1024,20480,768 Windows=On "
             "SubSystemType=Windows ServerDll=basesrv,1 "
             "ServerDll=winsrv:UserServerDllInitialization,3 "
             "ServerDll=sxssrv,4 ProfileControl=Off "
             "MaxRequestThreads=16",
        648: "winlogon.exe",
        704: f"{sys32}\\services.exe",
        724: f"{sys32}\\lsass.exe",
        836: f"{sys32}\\svchost.exe -k DcomLaunch -p",
        908: f"{sys32}\\svchost.exe -k netsvcs -p",
        984: f"{sys32}\\svchost.exe -k UnistackSvcGroup",
        1042: f"{sys32}\\svchost.exe -k LocalServiceNoNetwork -p",
        1188: f"{sys32}\\svchost.exe -k LocalServiceNetworkRestricted -p",
        1284: f"{sys32}\\fontdrvhost.exe",
        1348: '"dwm.exe"',
        1584: f"{sys32}\\spoolsv.exe",
        1712: '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\'
              '4.18.24090.11-0\\MsMpEng.exe"',
        1884: f"{sys32}\\SearchIndexer.exe /Embedding",
        2104: '"C:\\Windows\\System32\\SecurityHealthService.exe"',
        2288: f"{sys32}\\sihost.exe",
        2344: f"{sys32}\\taskhostw.exe KEYROAMING",
        2412: unreadable,
        2468: "C:\\Windows\\Explorer.EXE",
        2596: f"{sys32}\\RuntimeBroker.exe -Embedding",
        2704: '"ctfmon.exe"',
        3024: f'"{office}\\OUTLOOK.EXE"',
        3184: f'"{onedrive}" /background',
        # The two rows the capstone hangs on.
        4218: f'"{office}\\EXCEL.EXE" '
              '"C:\\HR\\Pricing\\Q4_Customer_Pricing.xlsx"',
        4258: f'"{office}\\WINWORD.EXE" '
              '"C:\\HR\\Pricing\\Pricing_Strategy_Confidential.docx"',
        5842: f"{sys32}\\DllHost.exe "
              "/Processid:{3EB3C877-1F16-487C-9050-104DBCD66683}",
        6428: f'"{onedrive}" /background',
        6604: f'"{edge}" --new-window https://outlook.live.com/mail/0/',
        6648: f'"{edge}" --type=crashpad-handler '
              '--database=C:\\Users\\hr-user\\AppData\\Local\\Microsoft\\'
              'Edge\\User Data\\Crashpad --annotation=plat=Win64',
        6702: f'"{edge}" --type=gpu-process --gpu-preferences=WAAAA',
        6744: f'"{edge}" --type=renderer --lang=en-GB '
              "--js-flags=--harmony --renderer-client-id=5",
        7108: f"{sys32}\\wbem\\wmiprvse.exe -Embedding",
        7284: "winpmem_mini_x64_rc2.exe "
              "\\\\10.0.4.12\\ir$\\HR-WS17\\HR-WS17-memory.raw",
        7290: "\\??\\C:\\WINDOWS\\system32\\conhost.exe 0xffffffff "
              "-ForceV1",
    }
    for (pid, _ppid, name, *_rest) in VOL_PROCS:
        blocks.append(vrow(pid, name, args[pid]))
    return vrender(blocks)


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

GENERATORS: Dict[str, Callable[[random.Random], List[Dict[str, str]]]] = {
    "mft.csv": generate_mft,
    "usn-journal.csv": generate_usn_journal,
    "security-evtx.csv": generate_security_evtx,
    "prefetch.csv": generate_prefetch,
    "amcache.csv": generate_amcache,
    "srum.csv": generate_srum,
    "lnk-files.csv": generate_lnk_files,
    "jump-lists.csv": generate_jump_lists,
    "shellbags.csv": generate_shellbags,
    "usbstor.csv": generate_usbstor,
    "mountpoints.csv": generate_mountpoints,
    "onedrive-accounts.csv": generate_onedrive_accounts,
    "onedrive-syncdb.csv": generate_onedrive_syncdb,
    "browser-history.csv": generate_browser_history,
    "shimcache.csv": generate_shimcache,
    "recyclebin.csv": generate_recyclebin,
}

# Plain-text outputs that don't go through DictWriter.
TEXT_OUTPUTS: Dict[str, Callable[[], str]] = {
    "pricing-files-known-hashes.txt": generate_pricing_hashes_text,
    "onedrive-logs-extract.txt": generate_onedrive_logs_text,
    "volatility-pslist.txt": generate_volatility_pslist,
    "volatility-netscan.txt": generate_volatility_netscan,
    "volatility-cmdline.txt": generate_volatility_cmdline,
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def write_csv(path: Path, fields: List[str],
              rows: List[Dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        # QUOTE_MINIMAL matches the existing files (only quote fields
        # that contain commas, quotes, or newlines).
        writer = csv.DictWriter(fh, fieldnames=fields,
                                quoting=csv.QUOTE_MINIMAL,
                                lineterminator="\n",
                                extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({f: row.get(f, "") for f in fields})


def write_text(path: Path, content: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate the HR-WS17 simulated dataset.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be written; do not touch "
                             "files.")
    parser.add_argument("--out-dir", default=".",
                        help="Directory to write files into (default: cwd).")
    parser.add_argument("--seed", type=lambda x: int(x, 0),
                        default=RANDOM_SEED,
                        help="Override the random seed.")
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir).resolve()

    print(f"HR-WS17 generator — seed=0x{args.seed:X}")
    print(f"Output directory: {out_dir}")
    if args.dry_run:
        print("Mode: --dry-run (no files written)")
    print()

    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    # CSV outputs.
    for filename, generator in GENERATORS.items():
        # Reseed per filename so adding/removing a generator does not
        # disturb the others' output.
        local_rng = random.Random((args.seed ^ hash(filename)) & 0xFFFFFFFF)
        rows = generator(local_rng)
        fields = HEADERS[filename]
        target = out_dir / filename
        print(f"  {filename:<32} -> {len(rows):>4} rows "
              f"({len(fields)} columns)")
        if not args.dry_run:
            write_csv(target, fields, rows)

    # Plain-text outputs.
    for filename, gen in TEXT_OUTPUTS.items():
        target = out_dir / filename
        content = gen()
        line_count = content.count("\n")
        print(f"  {filename:<32} -> {line_count:>4} lines (plain text)")
        if not args.dry_run:
            write_text(target, content)

    if args.dry_run:
        print("\nDry run complete. Re-run without --dry-run to write "
              "files.")
    else:
        print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
