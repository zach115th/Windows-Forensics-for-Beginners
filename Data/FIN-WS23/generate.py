#!/usr/bin/env python3
"""Deterministic generator for the simulated FIN-WS23 dataset.

Attack narrative
================
FIN-WS23 is a Windows 10 finance workstation joined to the FINANCE
domain, assigned to user ``j.smith`` (FINANCE\\j.smith). On 2024-11-13
at 06:28:11 UTC, ``j.smith`` interactively logs on at the start of the
business day and starts Edge at 06:30:00. While reading a finance-news
blog reached from an email link (06:31:42), the user lands on a
download page for ``Q4_Vendor_Review.docm`` (06:32:18). The
macro-enabled Word document is saved to
``C:\\Users\\j.smith\\Downloads\\`` at 06:42:14 and double-clicked
at 06:57:48 — the shell writes the Recent LNK and Word's Jump-List
entry, Word opens the document at 06:58:00, and the embedded macro
spawns ``POWERSHELL.EXE`` at 06:58:30 (parent WINWORD.EXE — anomalous).

PowerShell drops a 64-bit downloader named ``dl.exe`` into the user's
Downloads directory at 06:59:08 (sha1
``b8e3f4d12a89c4e5670123456789abcdef0123ab``) and executes it at
06:59:14 (Prefetch run count 1 — the headline indicator).  ``dl.exe``
opens an outbound TCP/443 connection to a low-reputation host, then
the user runs ``cmd.exe`` at 07:14:22 and issues a small recon
sequence (``ipconfig /all``, ``whoami /all``, ``net``) at 07:14:42 —
07:15:11.

The interactive session continues through the morning. At 09:14:08
the user inserts a SanDisk Cruzer Glide USB device (VID 0781, PID
5567, serial ``4C530001190405104544``) which mounts as ``F:`` with
volume serial ``B4D7-22A1`` and label ``CRUZER``.  Shellbags are
written for ``F:\\Vendors\\Confidential\\`` at 09:15:32, and LNK
files are created at 09:16:18 / 09:16:42 for two documents opened
from that USB path:

  - ``Vendor_Confidential_Roster.xlsx`` (Excel jump list entry 3)
  - ``Bank_Account_Notes.docx``        (Word jump list entry 4)

The USB is removed at 09:24:47. The last Edge visit in the activity
window is at 09:30:42 (a search about the drive disconnecting), and
the user relaunches Edge from Explorer at 09:31:00.

This script regenerates every CSV under ``Data/FIN-WS23/`` from the
above narrative. Hand-coded "key event" rows preserve the attack
story (the ``dl.exe`` execution chain, the LNK trail, the USB attach
+ shellbag + LNK correlation, the suspect browser download URL);
random "noise" rows fill out plausible volumes. Output is
byte-identical across runs given the same ``RANDOM_SEED``.

Usage
=====
    python3 generate.py                     # write CSVs in current dir
    python3 generate.py --dry-run           # print plan only
    python3 generate.py --out-dir /tmp/x    # write to scratch dir
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Dict, List

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Fixed seed -> byte-identical output across runs. Spelled as a hex
# literal with the letters of "FINWS23" mapped to legal hex digits
# (F->F, I->1, N->A, W->0, S->5 → "F1AW523" but we keep only legal
# hex digits, giving "F1A0523"). Override with --seed if you want a
# different stream.
RANDOM_SEED = 0x0F1A0523

HOSTNAME = "FIN-WS23"
FQDN = "FIN-WS23.finance.local"
DOMAIN = "FINANCE"
USER = "j.smith"
USER_SID = "S-1-5-21-3892914712-2384921031-1294712880-1241"

# Local fixed-disk volume (C:)
VOL_SERIAL = "3C8BFF21"
VOL_LABEL = "OS"
VOL_GUID = "\\VOLUME{01dac0f4-728341a2-}"
VOL_CREATED = "2024-08-12 09:18:42"

# Removable SanDisk Cruzer (F:)
USB_VOL_SERIAL = "B4D7-22A1"
USB_VOL_LABEL = "CRUZER"
USB_VENDOR_ID = "0781"
USB_PRODUCT_ID = "5567"
USB_REVISION = "8.07"
USB_SERIAL = "4C530001190405104544"
USB_FRIENDLY = "SanDisk Cruzer Glide USB Device"
USB_VOL_GUID = "{b4d722a1-1142-11ef-8a4f-0c9d92841421}"

# Anchor times (UTC) — the FIN-WS23 narrative timeline.
DAY = "2024-11-13"
T_LOGON = "2024-11-13 06:28:11"
T_SHELL_START = "2024-11-13 06:28:14"   # userinit -> Explorer
T_EDGE_START = "2024-11-13 06:30:00"
T_DOCM_DOWNLOAD = "2024-11-13 06:42:14"
T_LURE_LNK = "2024-11-13 06:57:48"
T_WINWORD_OPEN = "2024-11-13 06:58:00"
T_PS_SPAWN = "2024-11-13 06:58:30"
T_DL_DROP = "2024-11-13 06:59:08"
T_DL_RUN = "2024-11-13 06:59:14"
T_DL_NETSPIKE = "2024-11-13 06:59:42"
T_CMD_RECON = "2024-11-13 07:14:22"
T_USB_ATTACH = "2024-11-13 09:14:08"
T_USB_SHELLBAG = "2024-11-13 09:15:32"
T_USB_LNK_1 = "2024-11-13 09:16:18"
T_USB_LNK_2 = "2024-11-13 09:16:42"
T_USB_REMOVE = "2024-11-13 09:24:47"
T_LAST_EDGE = "2024-11-13 09:31:00"


# ---------------------------------------------------------------------------
# CSV headers (exact match to existing files — verified with `diff`).
# ---------------------------------------------------------------------------

HEADERS: Dict[str, List[str]] = {
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
    "userassist.csv": [
        "ProgramName", "RunCounter", "FocusCount", "FocusTime",
        "LastExecuted",
    ],
    "shellbags.csv": [
        "BagPath", "AbsolutePath", "ShellType",
        "FirstInteracted", "LastInteracted", "MRUPosition", "NodeSlot",
    ],
    "browser-history.csv": [
        "VisitTime", "URL", "Title", "VisitCount", "TypedCount",
        "LastVisitTime", "ReferrerURL", "Transition",
    ],
    "usbstor.csv": [
        "DeviceClass", "VendorId", "ProductId", "Revision",
        "SerialNumber", "FriendlyName", "FirstConnected", "LastConnected",
        "LastInsertTime", "LastRemovalTime", "ParentIdPrefix",
        "DeviceInstanceId", "VolumeGuid",
    ],
    "shimcache.csv": [
        "ControlSet", "CacheEntryPosition", "Path", "LastModifiedTimeUTC",
        "Executed", "Duplicate", "SourceFile",
    ],
    "recyclebin.csv": [
        "SourceName", "FileType", "FileName", "FileSize", "DeletedOn",
        "SourceCreated", "SourceModified",
    ],
    # Event-log headers are copied verbatim from Data/WKSTN-221 so the two
    # hosts' exports can be concatenated into one timeline without
    # reconciling columns. Do not "improve" these column names.
    "security-evtx.csv": [
        "RecordNumber", "TimeCreated", "EventID", "Channel", "Provider",
        "Computer", "UserName", "Level", "Description", "Payload",
    ],
    "system-evtx.csv": [
        "RecordNumber", "TimeCreated", "EventID", "Channel", "Provider",
        "Computer", "Level", "Description", "Payload",
    ],
}

# --- ShimCache -------------------------------------------------------------
# The export was taken with ``AppCompatCacheParser -c 1`` (ControlSet001
# only), so ``Duplicate`` is False on every row: a duplicate is only
# reported when the same path/timestamp pair also appears in a second
# control set.
SHIMCACHE_CONTROLSET = "1"
SHIMCACHE_SOURCE = "C:\\Windows\\System32\\config\\SYSTEM"
# FIN-WS23 is Windows 10, so the "executed" InsertFlag that older cache
# formats carried is simply not populated and AppCompatCacheParser reports
# ``NA``. Chapter 6 makes a point of this: a ShimCache row proves the file
# was *present and enumerated*, not that it ran. Do not fill this column.
SHIMCACHE_EXECUTED = "NA"

# --- Recycle Bin -----------------------------------------------------------
RECYCLE_BIN = f"C:\\$Recycle.Bin\\{USER_SID}"

# Device instance path as the PnP stack writes it into event-log payloads.
# Note the raw four-digit revision (``Rev_0100``-style) is absent here —
# the USB\ form carries only VID/PID and serial.
USB_DEVICE_PATH = (
    f"USB\\VID_{USB_VENDOR_ID}&PID_{USB_PRODUCT_ID}\\{USB_SERIAL}"
)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def ts(s: str, frac: str = ".0000000") -> str:
    """Return a normalized timestamp string ``YYYY-MM-DD HH:MM:SS.fffffff``.

    Most committed CSVs use the seven-digit fractional second suffix
    even when the value is exactly on the second; this helper appends
    one when the caller didn't supply one explicitly.
    """
    if "." in s:
        return s
    return s + frac


def parse_ts(s: str) -> datetime:
    base = s.split(".", 1)[0]
    return datetime.strptime(base, "%Y-%m-%d %H:%M:%S")


def fmt_ts(dt: datetime, frac: str = ".0000000") -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") + frac


def jitter(rng: random.Random, base: datetime, max_seconds: int) -> datetime:
    return base + timedelta(seconds=rng.randint(0, max_seconds))


# Common path prefixes — declared once so every generator stays consistent.
RECENT = f"C:\\Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\Recent"
DOCS = f"C:\\Users\\{USER}\\Documents"
DESK = f"C:\\Users\\{USER}\\Desktop"
DOWNS = f"C:\\Users\\{USER}\\Downloads"
APPDATA_LOCAL = f"C:\\Users\\{USER}\\AppData\\Local"


# ---------------------------------------------------------------------------
# Generators (one per output file). Each takes a Random instance and
# returns a list of dict rows. The dispatch table below maps filename
# to generator; a per-file local RNG keeps streams independent.
# ---------------------------------------------------------------------------

def generate_lnk_files(rng: random.Random) -> List[Dict[str, str]]:
    """Recent LNK files (``%APPDATA%\\Microsoft\\Windows\\Recent\\*.lnk``).

    Hand-coded entries preserve:
      - The Q4_Vendor_Review.docm lure LNK at the start of the attack
      - Two LNKs created from ``F:\\Vendors\\Confidential\\``
        (Vendor_Confidential_Roster.xlsx, Bank_Account_Notes.docx)
        with the USB volume serial B4D7-22A1 / label CRUZER, DriveType
        RemovableMedia
      - Plausible background LNKs for documents touched in the
        days leading up to the incident
    """
    rows: List[Dict[str, str]] = []

    def add(source, sc, sm, sa, tc, tm, ta, sz, rel, wd, lp,
            vol=VOL_SERIAL, label=VOL_LABEL, drive="FixedHardDisk"):
        rows.append({
            "SourceFile": source,
            "SourceCreated": ts(sc), "SourceModified": ts(sm),
            "SourceAccessed": ts(sa),
            "TargetCreated": ts(tc), "TargetModified": ts(tm),
            "TargetAccessed": ts(ta), "FileSize": str(sz),
            "RelativePath": rel, "WorkingDirectory": wd, "LocalPath": lp,
            "VolumeSerialNumber": vol, "VolumeLabel": label,
            "DriveType": drive, "MachineId": HOSTNAME.lower(),
        })

    # ---- The lure: Q4_Vendor_Review.docm in Downloads (06:57:48 create,
    # 06:58:00 modify/access — Word's first open triggers all three).
    add(f"{RECENT}\\Q4_Vendor_Review.lnk",
        "2024-11-13 06:57:48", "2024-11-13 06:58:00",
        "2024-11-13 06:58:00",
        "2024-11-13 06:42:14", "2024-11-13 06:42:14",
        "2024-11-13 06:58:00", 184221,
        "..\\..\\..\\..\\..\\..\\Downloads\\Q4_Vendor_Review.docm",
        DOWNS, f"{DOWNS}\\Q4_Vendor_Review.docm")

    # ---- Plausible recent business documents (local C: drive).
    add(f"{RECENT}\\Vendor_List_2024.lnk",
        "2024-10-04 11:14:22", "2024-11-12 14:22:18",
        "2024-11-12 14:22:18",
        "2024-10-04 11:14:00", "2024-10-04 11:14:00",
        "2024-11-12 14:22:18", 42891,
        "..\\..\\..\\..\\..\\..\\Documents\\Vendor_List_2024.xlsx",
        DOCS, f"{DOCS}\\Vendor_List_2024.xlsx")
    add(f"{RECENT}\\Q3_Close_Notes.lnk",
        "2024-09-22 09:14:08", "2024-11-08 13:42:00",
        "2024-11-08 13:42:00",
        "2024-09-22 09:14:00", "2024-09-22 09:14:00",
        "2024-11-08 13:42:00", 28471,
        "..\\..\\..\\..\\..\\..\\Documents\\Q3_Close_Notes.docx",
        DOCS, f"{DOCS}\\Q3_Close_Notes.docx")
    add(f"{RECENT}\\Budget_FY25_Draft.lnk",
        "2024-10-15 11:08:30", "2024-11-12 16:14:33",
        "2024-11-12 16:14:33",
        "2024-10-15 11:08:00", "2024-11-04 09:30:42",
        "2024-11-12 16:14:33", 184221,
        "..\\..\\..\\..\\..\\..\\Documents\\Budget_FY25_Draft.xlsx",
        DOCS, f"{DOCS}\\Budget_FY25_Draft.xlsx")
    # Re-opened in Word on 11-04 (Word Jump List entry 3, Word Prefetch
    # run): the LNK was rewritten then, so SourceModified moves with the
    # embedded TargetAccessed value.
    add(f"{RECENT}\\Expense_Policy.lnk",
        "2024-09-19 14:42:00", "2024-11-04 09:00:00",
        "2024-11-04 09:00:00",
        "2024-09-19 14:42:00", "2024-09-19 14:42:00",
        "2024-11-04 09:00:00", 18421,
        "..\\..\\..\\..\\..\\..\\Documents\\Expense_Policy.docx",
        DOCS, f"{DOCS}\\Expense_Policy.docx")
    add(f"{RECENT}\\Notes.lnk",
        "2024-11-08 10:42:00", "2024-11-12 16:30:00",
        "2024-11-12 16:30:00",
        "2024-11-08 10:42:00", "2024-11-12 16:30:00",
        "2024-11-12 16:30:00", 2184,
        "..\\..\\..\\..\\..\\..\\Desktop\\Notes.txt",
        DESK, f"{DESK}\\Notes.txt")
    add(f"{RECENT}\\Tax_Forms_2024.lnk",
        "2024-09-04 14:11:00", "2024-11-04 09:30:00",
        "2024-11-04 09:30:00",
        "2024-09-04 14:11:00", "2024-09-04 14:22:00",
        "2024-11-04 09:30:00", 28471,
        "..\\..\\..\\..\\..\\..\\Documents\\Tax_Forms_2024.docx",
        DOCS, f"{DOCS}\\Tax_Forms_2024.docx")
    add(f"{RECENT}\\AP_Aging.lnk",
        "2024-08-22 17:14:08", "2024-11-08 10:05:33",
        "2024-11-08 10:05:33",
        "2024-08-22 16:42:11", "2024-08-22 17:14:08",
        "2024-11-08 10:05:33", 892471,
        "..\\..\\..\\..\\..\\..\\Documents\\AP_Aging.xlsx",
        DOCS, f"{DOCS}\\AP_Aging.xlsx")
    add(f"{RECENT}\\benefits_2025.lnk",
        "2024-11-08 10:42:00", "2024-11-08 14:18:00",
        "2024-11-08 14:18:00",
        "2024-11-08 10:42:00", "2024-11-08 10:42:00",
        "2024-11-08 14:18:00", 1248421,
        "..\\..\\..\\..\\..\\..\\Downloads\\benefits_2025.pdf",
        DOWNS, f"{DOWNS}\\benefits_2025.pdf")
    add(f"{RECENT}\\timesheet_template.lnk",
        "2024-10-22 13:18:00", "2024-10-22 13:30:00",
        "2024-10-22 13:30:00",
        "2024-10-22 13:18:00", "2024-10-22 13:18:00",
        "2024-10-22 13:30:00", 38712,
        "..\\..\\..\\..\\..\\..\\Downloads\\timesheet_template.xlsx",
        DOWNS, f"{DOWNS}\\timesheet_template.xlsx")

    # ---- The USB pair (F:\Vendors\Confidential\*). Drive type =
    # RemovableMedia, volume serial = the F: serial. RelativePath
    # uses the F$ admin-share convention LECmd emits when the volume
    # GUID is recovered from the LNK's TrackerDataBlock.
    add(f"{RECENT}\\Vendor_Confidential_Roster.lnk",
        "2024-11-13 09:16:18", "2024-11-13 09:16:18",
        "2024-11-13 09:16:18",
        "2024-08-14 11:14:00", "2024-10-22 16:42:00",
        "2024-11-13 09:16:18", 212481,
        "..\\..\\..\\..\\..\\..\\..\\..\\F$\\Vendors\\Confidential\\Vendor_Confidential_Roster.xlsx",
        "F:\\Vendors\\Confidential",
        "F:\\Vendors\\Confidential\\Vendor_Confidential_Roster.xlsx",
        vol=USB_VOL_SERIAL, label=USB_VOL_LABEL, drive="RemovableMedia")
    add(f"{RECENT}\\Bank_Account_Notes.lnk",
        "2024-11-13 09:16:42", "2024-11-13 09:16:42",
        "2024-11-13 09:16:42",
        "2024-09-04 14:11:00", "2024-09-04 14:22:00",
        "2024-11-13 09:16:42", 38421,
        "..\\..\\..\\..\\..\\..\\..\\..\\F$\\Vendors\\Confidential\\Bank_Account_Notes.docx",
        "F:\\Vendors\\Confidential",
        "F:\\Vendors\\Confidential\\Bank_Account_Notes.docx",
        vol=USB_VOL_SERIAL, label=USB_VOL_LABEL, drive="RemovableMedia")

    # ---- Tail-end background noise.
    add(f"{RECENT}\\Onboarding_Checklist.lnk",
        "2024-09-19 14:42:00", "2024-09-19 14:42:00",
        "2024-09-19 14:42:00",
        "2024-09-19 14:42:00", "2024-09-19 14:42:00",
        "2024-09-19 14:42:00", 18421,
        "..\\..\\..\\..\\..\\..\\Documents\\Onboarding_Checklist.xlsx",
        DOCS, f"{DOCS}\\Onboarding_Checklist.xlsx")
    # Last opened late on 11-12 in the Excel instance started at 16:14:33
    # (no new Prefetch run). It cannot be 11-13 before the logon.
    add(f"{RECENT}\\Q4_Tasks.lnk",
        "2024-10-01 09:14:00", "2024-11-12 16:52:40",
        "2024-11-12 16:52:40",
        "2024-10-01 09:14:00", "2024-11-04 09:30:00",
        "2024-11-12 16:52:40", 21455,
        "..\\..\\..\\..\\..\\..\\Desktop\\Q4_Tasks.xlsx",
        DESK, f"{DESK}\\Q4_Tasks.xlsx")

    # rng kept around for future noise expansion.
    _ = rng
    return rows


def generate_jump_lists(rng: random.Random) -> List[Dict[str, str]]:
    """JLECmd AutomaticDestinations rows.

    Hand-coded so that:
      - Word entry 1 is the lure (Q4_Vendor_Review.docm)
      - Excel entry 3 and Word entry 4 are the F:\\Vendors\\Confidential
        documents (USB volume serial = B4D7-22A1)
      - Explorer entry 1 is F:\\Vendors\\Confidential (the USB browse)
      - Outlook / Edge entries have no file target (typical pattern)
    """
    rows: List[Dict[str, str]] = []

    def add(appid, app_desc, n, lm, ct, tc, tm, lp, sz,
            vol=VOL_SERIAL):
        rows.append({
            "SourceFile": f"{appid}.automaticDestinations-ms",
            "AppId": appid, "AppDescription": app_desc,
            "EntryNumber": str(n),
            "LastModified": ts(lm) if lm else "",
            "CreationTime": ts(ct) if ct else "",
            "TargetCreated": ts(tc) if tc else "",
            "TargetModified": ts(tm) if tm else "",
            "LocalPath": lp, "Hostname": HOSTNAME.lower(),
            "VolumeSerialNumber": vol,
            "FileSize": str(sz) if sz else "",
        })

    # Reusable AppId GUIDs (well-known LECmd/JLECmd mappings).
    word = "9b9cdc69c1c24e2b"
    excel = "12dc1ea8e34b6a0b"
    outlook = "00fe1d4e09f74f7d"
    notepad = "918e0ecb43d17e23"
    explorer = "1b4dd67f29cb1962"
    edge = "ad62c5ad4ac45c97"

    # ---- Word jump list: lure + plausible Word doc history. Entry 4
    # is the USB document Bank_Account_Notes.docx (drive serial B4D7-22A1).
    add(word, "Microsoft Word", 1,
        "2024-11-13 06:58:00", "2024-11-13 06:57:48",
        "2024-11-13 06:42:14", "2024-11-13 06:42:14",
        f"{DOWNS}\\Q4_Vendor_Review.docm", 184221)
    add(word, "Microsoft Word", 2,
        "2024-11-12 14:22:18", "2024-09-22 09:14:08",
        "2024-09-22 09:14:00", "2024-09-22 09:14:00",
        f"{DOCS}\\Q3_Close_Notes.docx", 28471)
    add(word, "Microsoft Word", 3,
        "2024-11-04 09:00:00", "2024-09-19 14:42:00",
        "2024-09-19 14:42:00", "2024-09-19 14:42:00",
        f"{DOCS}\\Expense_Policy.docx", 18421)
    add(word, "Microsoft Word", 4,
        "2024-11-13 09:16:42", "2024-11-13 09:16:42",
        "2024-09-04 14:11:00", "2024-09-04 14:22:00",
        "F:\\Vendors\\Confidential\\Bank_Account_Notes.docx", 38421,
        vol=USB_VOL_SERIAL)

    # ---- Excel jump list: business workbooks + the USB roster (entry 3).
    add(excel, "Microsoft Excel", 1,
        "2024-11-12 16:14:33", "2024-10-15 11:08:30",
        "2024-10-15 11:08:00", "2024-11-04 09:30:42",
        f"{DOCS}\\Budget_FY25_Draft.xlsx", 184221)
    add(excel, "Microsoft Excel", 2,
        "2024-11-12 14:22:18", "2024-10-04 11:14:22",
        "2024-10-04 11:14:00", "2024-10-04 11:14:00",
        f"{DOCS}\\Vendor_List_2024.xlsx", 42891)
    add(excel, "Microsoft Excel", 3,
        "2024-11-13 09:16:18", "2024-11-13 09:16:18",
        "2024-08-14 11:14:00", "2024-10-22 16:42:00",
        "F:\\Vendors\\Confidential\\Vendor_Confidential_Roster.xlsx",
        212481, vol=USB_VOL_SERIAL)
    add(excel, "Microsoft Excel", 4,
        "2024-11-08 10:05:33", "2024-08-22 17:14:08",
        "2024-08-22 16:42:11", "2024-08-22 17:14:08",
        f"{DOCS}\\AP_Aging.xlsx", 892471)
    add(excel, "Microsoft Excel", 5,
        "2024-11-12 16:52:40", "2024-10-01 09:14:00",
        "2024-10-01 09:14:00", "2024-11-04 09:30:00",
        f"{DESK}\\Q4_Tasks.xlsx", 21455)

    # ---- Outlook: just process-level activity, no file target.
    add(outlook, "Microsoft Outlook", 1,
        "2024-11-13 06:42:14", "2024-11-13 06:42:14",
        None, None, "", None)

    # ---- Notepad: only Notes.txt this week.
    add(notepad, "Notepad", 1,
        "2024-11-12 16:30:00", "2024-11-08 10:42:00",
        "2024-11-08 10:42:00", "2024-11-12 16:30:00",
        f"{DESK}\\Notes.txt", 2184)

    # ---- Explorer: pinned + most-recent folder history. Entry 1 is
    # the USB confidential folder — high-signal for the lab.
    add(explorer, "File Explorer", 1,
        "2024-11-13 09:15:32", "2024-11-13 09:15:32",
        None, None, "F:\\Vendors\\Confidential", None,
        vol=USB_VOL_SERIAL)
    add(explorer, "File Explorer", 2,
        "2024-11-13 06:57:30", "2024-11-13 06:57:30",
        None, None, f"C:\\Users\\{USER}\\Downloads", None)
    add(explorer, "File Explorer", 3,
        "2024-11-12 16:14:33", "2024-11-12 16:14:33",
        None, None, f"C:\\Users\\{USER}\\Documents", None)

    # ---- Edge: browser activity (no file target).
    add(edge, "Microsoft Edge", 1,
        "2024-11-13 09:31:00", "2024-11-13 06:30:00",
        None, None, "", None)

    _ = rng
    return rows


def generate_prefetch(rng: random.Random) -> List[Dict[str, str]]:
    """Prefetch entries — ``DL.EXE`` RunCount=1 is the headline indicator.

    Hand-coded entries for the executable runs in the timeline + a
    broader catalog of legitimate Windows/Office executables that any
    finance workstation would accumulate. Layout (VolumeName /
    VolumeSerial / VolumeCreated) matches the committed CSV exactly.
    """
    rows: List[Dict[str, str]] = []

    def add(name, exe, h, runs, last, p0, p1, p2, files):
        rows.append({
            "SourceFilename": name, "ExecutableName": exe, "Hash": h,
            "RunCount": str(runs),
            "LastRun": ts(last) if last else "",
            "PreviousRun0": ts(p0) if p0 else "",
            "PreviousRun1": ts(p1) if p1 else "",
            "PreviousRun2": ts(p2) if p2 else "",
            "FilesCount": str(files), "VolumeName": VOL_GUID,
            "VolumeSerialNumber": VOL_SERIAL,
            "VolumeCreated": ts(VOL_CREATED),
        })

    # Every row lists min(RunCount, 4) run times, newest first, and every
    # 4688 in security-evtx.csv for one of these images appears among
    # them (Prefetch run time = process start, to the second).
    #
    # ---- Story-defining rows. WINWORD opens the lure, PowerShell
    # spawns from it, DL.EXE runs once, then cmd.exe takes over the
    # interactive recon role at 07:14. Word's last run is the 09:16:42
    # open of Bank_Account_Notes.docx from the USB; the lure open at
    # 06:58:00 is PreviousRun0.
    add("WINWORD.EXE-89B23C41.pf", "WINWORD.EXE", "89B23C41", 38,
        "2024-11-13 09:16:42", "2024-11-13 06:58:00",
        "2024-11-12 14:22:18", "2024-11-08 13:42:00", 184)
    add("POWERSHELL.EXE-022A1141.pf", "POWERSHELL.EXE", "022A1141", 4,
        "2024-11-13 06:58:30", "2024-10-22 13:18:00",
        "2024-09-19 14:42:11", "2024-08-28 10:31:52", 184)
    add("DL.EXE-7C81B3A4.pf", "DL.EXE", "7C81B3A4", 1,
        "2024-11-13 06:59:14", "", "", "", 32)
    add("CMD.EXE-4A81B364.pf", "CMD.EXE", "4A81B364", 12,
        "2024-11-13 07:14:22", "2024-11-13 06:58:30",
        "2024-11-08 11:14:21", "2024-10-22 09:14:08", 42)
    # Excel last run is the USB roster open at 09:16:18.
    add("EXCEL.EXE-7A4B8C12.pf", "EXCEL.EXE", "7A4B8C12", 84,
        "2024-11-13 09:16:18", "2024-11-12 16:14:33",
        "2024-11-12 14:22:18", "2024-11-08 10:05:33", 221)
    add("OUTLOOK.EXE-3D2A41C8.pf", "OUTLOOK.EXE", "3D2A41C8", 212,
        "2024-11-13 06:42:14", "2024-11-12 17:00:00",
        "2024-11-12 08:42:11", "2024-11-08 08:42:11", 322)
    # 11-08 10:42:00 is the run that created and opened Desktop\Notes.txt
    # (Notes.lnk SourceCreated, Notepad Jump List CreationTime).
    add("NOTEPAD.EXE-D7BA5828.pf", "NOTEPAD.EXE", "D7BA5828", 18,
        "2024-11-12 16:30:00", "2024-11-08 13:42:00",
        "2024-11-08 10:42:00", "2024-10-22 11:14:00", 21)

    # ---- Recon utilities. WHOAMI's 06:58:30 run is the child of the
    # macro's ``cmd.exe /c whoami``; 07:14:55 is the interactive one.
    add("IPCONFIG.EXE-22341A8B.pf", "IPCONFIG.EXE", "22341A8B", 3,
        "2024-11-13 07:14:42", "2024-10-04 14:21:00",
        "2024-09-22 11:14:00", "", 8)
    add("WHOAMI.EXE-A1142B83.pf", "WHOAMI.EXE", "A1142B83", 3,
        "2024-11-13 07:14:55", "2024-11-13 06:58:30",
        "2024-09-19 14:11:18", "", 8)
    add("NET.EXE-89AB3214.pf", "NET.EXE", "89AB3214", 5,
        "2024-11-13 07:15:11", "2024-11-08 09:14:11",
        "2024-10-22 14:18:00", "2024-09-19 11:14:00", 18)

    # ---- Background OS / shell / browser executions (noise).
    add("SVCHOST.EXE-12C8B921.pf", "SVCHOST.EXE", "12C8B921", 84,
        "2024-11-13 03:00:11", "2024-11-12 22:00:00",
        "2024-11-12 03:00:11", "2024-11-11 22:00:00", 184)
    # Three Explorer starts on 11-13: logon (userinit), the 07:16:04
    # window used to delete the lure, and the 09:15:32 /factory window.
    add("EXPLORER.EXE-3142A4B6.pf", "EXPLORER.EXE", "3142A4B6", 221,
        "2024-11-13 09:15:32", "2024-11-13 07:16:04",
        T_SHELL_START, "2024-11-12 08:42:00", 512)
    add("WINLOGON.EXE-A8B9421C.pf", "WINLOGON.EXE", "A8B9421C", 28,
        "2024-11-13 02:14:14", "2024-11-12 22:00:14",
        "2024-11-12 02:14:00", "2024-11-11 22:00:14", 84)
    add("USERINIT.EXE-A8B95612.pf", "USERINIT.EXE", "A8B95612", 28,
        T_SHELL_START, "2024-11-12 08:42:00",
        "2024-11-11 08:42:00", "2024-11-08 08:42:00", 42)
    add("TASKHOSTW.EXE-7B2A4181.pf", "TASKHOSTW.EXE", "7B2A4181", 118,
        "2024-11-13 09:00:00", "2024-11-13 08:00:00",
        "2024-11-13 07:00:00", "2024-11-13 06:28:15", 32)
    # Newest first: the interactive cmd.exe at 07:14:22, then the
    # macro's cmd.exe /c whoami at 06:58:30.
    add("CONHOST.EXE-9B23C144.pf", "CONHOST.EXE", "9B23C144", 52,
        "2024-11-13 07:14:22", "2024-11-13 06:58:30",
        "2024-11-12 09:32:00", "2024-11-08 11:14:21", 16)
    # Edge starts at 06:30:00 (4688, Jump List CreationTime) and again
    # from Explorer at 09:31:00. On 11-12 it started at 08:43:05, just
    # after that day's 08:42 logon (browsing at 14:22 and 16:18), and was
    # restarted at 16:42.
    add("MSEDGE.EXE-3142A4B7.pf", "MSEDGE.EXE", "3142A4B7", 164,
        "2024-11-13 09:31:00", T_EDGE_START,
        "2024-11-12 16:42:00", "2024-11-12 08:43:05", 84)
    add("MSEDGEWEBVIEW2.EXE-A41C8B23.pf", "MSEDGEWEBVIEW2.EXE",
        "A41C8B23", 212,
        "2024-11-13 09:31:00", T_EDGE_START,
        "2024-11-12 16:42:00", "2024-11-12 08:43:06", 68)
    # Per-user process: its 11-12 morning run follows that day's 08:42
    # logon (USERINIT), not 06:42.
    add("ONEDRIVE.EXE-2B41C893.pf", "ONEDRIVE.EXE", "2B41C893", 184,
        "2024-11-13 06:42:30", "2024-11-12 17:00:00",
        "2024-11-12 08:42:30", "2024-11-11 08:42:30", 42)
    add("RUNDLL32.EXE-3142A4B8.pf", "RUNDLL32.EXE", "3142A4B8", 42,
        "2024-11-13 09:14:08", "2024-11-12 11:14:00",
        "2024-11-08 09:14:00", "2024-11-04 10:12:37", 21)
    add("SEARCHFILTERHOST.EXE-7C81B3A5.pf", "SEARCHFILTERHOST.EXE",
        "7C81B3A5", 68,
        "2024-11-13 06:30:00", "2024-11-13 03:30:00",
        "2024-11-12 22:30:00", "2024-11-12 18:30:00", 12)

    _ = rng
    return rows


def generate_amcache(rng: random.Random) -> List[Dict[str, str]]:
    """Amcache: first-seen / metadata for executables, including ``dl.exe``.

    The committed CSV uses an empty ``Publisher`` for ``dl.exe`` (no
    signed publisher info, consistent with an unknown downloader). The
    ``Compiled`` timestamp predates the dataset's collection by a day.
    """
    rows: List[Dict[str, str]] = []

    def add(path, ext, size, sha1, sha256, ver, prod, pub,
            created, modified, compiled):
        rows.append({
            "FullPath": path, "FileExtension": ext, "FileSize": str(size),
            "Sha1": sha1, "Sha256": sha256, "FileVersion": ver,
            "ProductName": prod, "Publisher": pub,
            "Created": ts(created), "LastModified": ts(modified),
            "Compiled": ts(compiled), "IsPeFile": "True",
            "BinaryType": "pe64bit",
        })

    win = "Microsoft Windows"
    msft = "Microsoft Corporation"

    # ---- The headline indicator. Publisher is intentionally empty.
    add(f"C:\\Users\\{USER}\\Downloads\\dl.exe", ".exe", 142336,
        "b8e3f4d12a89c4e5670123456789abcdef0123ab",
        "7c1a4f8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567",
        "1.0.0.0", "Downloader", "",
        "2024-11-13 06:59:08", "2024-11-13 06:59:08.5000000",
        "2024-11-12 02:14:00")

    # ---- Legitimate Windows / Office / Edge / OneDrive binaries.
    add("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        ".exe", 452608,
        "a89b4218421842184218421842184218421842c1",
        "8b2c1a4f8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345",
        "5.1.19041.5247", win, msft,
        "2024-08-12 09:21:14.5000000", "2024-08-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add("C:\\Windows\\System32\\cmd.exe", ".exe", 289792,
        "c1b3a4218421842184218421842184218421842b",
        "2c1a4f8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567",
        "10.0.19041.5247", win, msft,
        "2024-08-12 09:21:14.5000000", "2024-08-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        ".exe", 4218214,
        "e3b5a4218421842184218421842184218421842d",
        "4f8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678a4f",
        "16.0.18025.20030", "Microsoft Office", msft,
        "2024-08-19 14:11:09", "2024-11-12 11:00:00",
        "2024-11-08 03:14:00")
    add("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
        ".exe", 3842184,
        "f4c6a4218421842184218421842184218421842e",
        "8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678a4f8b",
        "16.0.18025.20030", "Microsoft Office", msft,
        "2024-08-19 14:11:09", "2024-11-12 11:00:00",
        "2024-11-08 03:14:00")
    add("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
        ".exe", 38422144,
        "d2b4a4218421842184218421842184218421842c",
        "1a4f8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678a",
        "16.0.18025.20030", "Microsoft Office", msft,
        "2024-08-19 14:11:09", "2024-11-12 11:00:00",
        "2024-11-08 03:14:00")
    add("C:\\Windows\\Explorer.EXE", ".exe", 4818421,
        "a5d7b4218421842184218421842184218421842f",
        "3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d",
        "10.0.19041.5247", win, msft,
        "2024-08-12 09:21:14.5000000", "2024-08-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add("C:\\Windows\\System32\\NOTEPAD.EXE", ".exe", 184320,
        "b6e8a4218421842184218421842184218421842a",
        "4e5f67890abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e",
        "10.0.19041.5247", win, msft,
        "2024-08-12 09:21:14.5000000", "2024-08-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add("C:\\Windows\\System32\\ipconfig.exe", ".exe", 42184,
        "c7f9a4218421842184218421842184218421842b",
        "5f67890abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f",
        "10.0.19041.5247", win, msft,
        "2024-08-12 09:21:14.5000000", "2024-08-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add("C:\\Windows\\System32\\whoami.exe", ".exe", 68192,
        "abd34218421842184218421842184218421842f4",
        "90abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f67890",
        "10.0.19041.5247", win, msft,
        "2024-08-12 09:21:14.5000000", "2024-08-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add("C:\\Windows\\System32\\net.exe", ".exe", 42184,
        "e9b14218421842184218421842184218421842d2",
        "7890abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f678",
        "10.0.19041.5247", win, msft,
        "2024-08-12 09:21:14.5000000", "2024-08-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        ".exe", 3214814,
        "bb14a4218421842184218421842184218421842b",
        "abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f6789013",
        "118.0.2088.76", "Microsoft Edge", msft,
        "2024-09-04 11:14:00", "2024-11-12 12:32:04",
        "2024-09-22 03:14:00")
    add("C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\msedgewebview2.exe",
        ".exe", 3842184,
        "bce44218421842184218421842184218421842a5",
        "0abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f678901",
        "118.0.2088.76", "Microsoft Edge WebView2", msft,
        "2024-10-04 11:14:00", "2024-11-12 12:32:04",
        "2024-09-22 03:14:00")
    add("C:\\Windows\\System32\\svchost.exe", ".exe", 82048,
        "cdf54218421842184218421842184218421842b6",
        "abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f6789012",
        "10.0.19041.5247", win, msft,
        "2024-08-12 09:21:14.5000000", "2024-08-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add(f"C:\\Users\\{USER}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
        ".exe", 2218421,
        "d12e4218421842184218421842184218421842c7",
        "bcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f67890124",
        "23.244.1118.0001", "Microsoft OneDrive", msft,
        "2024-09-12 11:00:00", "2024-11-08 11:00:00",
        "2024-10-22 03:14:00")
    add("C:\\Windows\\System32\\rundll32.exe", ".exe", 72192,
        "e234a4218421842184218421842184218421842d",
        "cdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f678901234",
        "10.0.19041.5247", win, msft,
        "2024-08-12 09:21:14.5000000", "2024-08-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add("C:\\Windows\\System32\\conhost.exe", ".exe", 628224,
        "f3454218421842184218421842184218421842e0",
        "def1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f67890123ab",
        "10.0.19041.5247", win, msft,
        "2024-08-12 09:21:14.5000000", "2024-08-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add("C:\\Windows\\System32\\SearchFilterHost.exe", ".exe", 42184,
        "a4564218421842184218421842184218421842f1",
        "ef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f67890123abc",
        "10.0.19041.5247", win, msft,
        "2024-08-12 09:21:14.5000000", "2024-08-12 09:21:14.5000000",
        "2024-08-22 11:14:00")

    _ = rng
    return rows


def generate_srum(rng: random.Random) -> List[Dict[str, str]]:
    """SRUM 30-minute rollups: bytes per app per user.

    Each ``Timestamp`` closes the interval it summarizes, as a real SRUM
    record is written at the end of the period it covers: the 07:00 rows
    cover 06:30-07:00. A process therefore appears only in buckets that
    end after it started.

    The 07:00 and 07:30 buckets attribute outbound bytes to ``dl.exe``
    — those rows back the lab's "find which process exfiltrated when"
    question. The interface LUID matches the committed CSV.
    """
    luid = "1689399632855040"
    rows: List[Dict[str, str]] = []

    def add(t, app, sid, sent, recv):
        rows.append({
            "Timestamp": ts(t), "ApplicationName": app, "UserSID": sid,
            "InterfaceLuid": luid,
            "BytesSent": str(sent), "BytesReceived": str(recv),
            "EventTimestamp": ts(t),
        })

    # ---- 06:30 bucket (06:00-06:30) — pre-incident background. Only
    # SYSTEM: j.smith logs on at 06:28:11 and Edge, Outlook and OneDrive
    # do not start until 06:30:00 / 06:42:14 / 06:42:30.
    add("2024-11-13 06:30:00", "svchost.exe", "S-1-5-18", 21841, 184221)

    # ---- 07:00 bucket (06:30-07:00) — the lure browsing and download,
    # DL.EXE first run + initial outbound.
    add("2024-11-13 07:00:00", "outlook.exe", USER_SID, 84221, 2184221)
    add("2024-11-13 07:00:00", "powershell.exe", USER_SID, 184221, 2415891)
    # dl.exe big outbound — the exfil candidate signal.
    add("2024-11-13 07:00:00", "dl.exe", USER_SID, 1428421, 4842184)
    add("2024-11-13 07:00:00", "winword.exe", USER_SID, 11421, 184221)
    add("2024-11-13 07:00:00", "msedge.exe", USER_SID, 128421, 3842184)
    add("2024-11-13 07:00:00", "msedgewebview2.exe", USER_SID, 21841, 842184)
    add("2024-11-13 07:00:00", "onedrive.exe", USER_SID, 42184, 128421)
    add("2024-11-13 07:00:00", "svchost.exe", "S-1-5-18", 11421, 84221)

    # ---- 07:30 bucket — dl.exe continues with smaller traffic.
    add("2024-11-13 07:30:00", "outlook.exe", USER_SID, 72184, 1842184)
    add("2024-11-13 07:30:00", "dl.exe", USER_SID, 84221, 184221)
    add("2024-11-13 07:30:00", "powershell.exe", USER_SID, 11421, 21841)
    add("2024-11-13 07:30:00", "onedrive.exe", USER_SID, 21841, 84221)

    # ---- 09:00 bucket (08:30-09:00) — mail and browsing; Excel is not
    # running yet. 09:30 bucket (09:00-09:30) — the USB session, with
    # Excel open on the roster from 09:16:18.
    add("2024-11-13 09:00:00", "outlook.exe", USER_SID, 124221, 1842184)
    add("2024-11-13 09:00:00", "msedge.exe", USER_SID, 84221, 2184221)
    add("2024-11-13 09:30:00", "outlook.exe", USER_SID, 84221, 1842184)
    add("2024-11-13 09:30:00", "msedge.exe", USER_SID, 128421, 3214184)
    add("2024-11-13 09:30:00", "excel.exe", USER_SID, 1142, 21841)

    _ = rng
    return rows


def generate_userassist(rng: random.Random) -> List[Dict[str, str]]:
    """UserAssist GUI-launch counters decoded from NTUSER.DAT.

    Rows for the canonical Known-Folder GUIDs:
      {6D809377-...}  → C:\\Program Files
      {7C5A40EF-...}  → C:\\Program Files (x86)
      {F38BF404-...}  → C:\\Windows
      {0762D272-...}  → C:\\Users
      {C1BAE2D0-...}  → C:\\Program Files\\WindowsApps

    Also includes ``UEME_CTLSESSION`` and ``UEME_RUNPATH`` rollup
    counters that RECmd emits alongside the per-program rows.
    """
    rows: List[Dict[str, str]] = []

    def add(name, runs, focus_count, focus_time, last):
        rows.append({
            "ProgramName": name, "RunCounter": str(runs),
            "FocusCount": str(focus_count), "FocusTime": focus_time,
            "LastExecuted": ts(last) if last else "",
        })

    pf = "{6D809377-6AF0-444B-8957-A3773F02200E}"      # Program Files
    pf86 = "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}"     # Program Files (x86)
    win = "{F38BF404-1D43-42F2-9305-67DE0B28FC23}"      # Windows
    users = "{0762D272-C50A-4BB0-A382-697DCD729B80}"    # Users
    wapps = "{C1BAE2D0-10DF-4334-BEDD-7AA20B227A9D}"    # WindowsApps

    # ---- The Office apps. Word and Excel both last launched from
    # Explorer for the USB documents (09:16:42 / 09:16:18); Word's
    # 06:58:00 lure open is the launch before that.
    add(f"{pf}\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        38, 184, "02:14:18", "2024-11-13 09:16:42")
    add(f"{pf}\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
        84, 221, "04:42:11", "2024-11-13 09:16:18")
    add(f"{pf}\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
        212, 632, "18:42:00", "2024-11-13 06:42:14")

    # ---- Console / scripting. UserAssist records only shell launches,
    # so the macro's powershell.exe at 06:58:30 (parent WINWORD.EXE) is
    # NOT here: the last GUI launch is the 10-22 run, and the counter is
    # one below Prefetch's RunCount of 4. cmd.exe at 07:14:22 was started
    # from Explorer, so it is counted.
    add(f"{win}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        3, 3, "00:08:42", "2024-10-22 13:18:00")
    add(f"{win}\\System32\\cmd.exe",
        12, 8, "00:14:21", "2024-11-13 07:14:22")
    add(f"{win}\\System32\\notepad.exe",
        18, 14, "00:32:11", "2024-11-12 16:30:00")

    # ---- Browser + Explorer.
    add(f"{pf86}\\Microsoft\\Edge\\Application\\msedge.exe",
        164, 512, "12:42:11", "2024-11-13 09:31:00")
    # explorer.exe lives in C:\Windows, the {F38BF404} (Windows) folder —
    # the same path Amcache, ShimCache and the 4688s record.
    add(f"{win}\\explorer.exe",
        221, 884, "28:42:11", "2024-11-13 09:15:32")

    # ---- Accessory apps (background noise).
    add(f"{win}\\System32\\mspaint.exe",
        3, 2, "00:11:42", "2024-11-08 13:42:00")
    add(f"{win}\\System32\\calc.exe",
        42, 18, "00:42:11", "2024-11-12 11:18:00")
    add(f"{win}\\System32\\SnippingTool.exe",
        18, 12, "00:21:42", "2024-11-12 14:30:00")
    add(f"{users}\\{USER}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
        184, 28, "01:14:11", "2024-11-13 06:42:30")

    # ---- UserAssist rollup counters (always present in RECmd output).
    add("UEME_CTLSESSION", 42, 0, "00:00:00", T_LOGON)
    add("UEME_RUNPATH", 1142, 0, "00:00:00", "2024-11-13 09:31:00")

    # ---- More noise: Acrobat, MMC, Teams, taskmgr, charmap, 7zFM.
    add(f"{pf}\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe",
        12, 18, "00:42:18", "2024-11-08 14:18:00")
    add(f"{win}\\System32\\mmc.exe",
        4, 4, "00:11:08", "2024-09-22 11:14:00")
    add(f"{win}\\System32\\taskmgr.exe",
        8, 6, "00:18:00", "2024-11-12 16:42:00")
    add(f"{wapps}\\Communications\\Microsoft.Teams\\ms-teams.exe",
        68, 184, "06:14:11", "2024-11-13 09:22:00")
    add(f"{win}\\System32\\charmap.exe",
        2, 1, "00:02:18", "2024-09-19 14:42:00")
    add(f"{pf}\\7-Zip\\7zFM.exe",
        6, 4, "00:11:42", "2024-10-22 13:30:00")

    _ = rng
    return rows


def generate_shellbags(rng: random.Random) -> List[Dict[str, str]]:
    """Shellbag entries from NTUSER.DAT / UsrClass.dat.

    The F:\\Vendors\\Confidential\\ branch is the high-signal evidence
    that the user browsed the USB volume after attach. Bag paths
    mirror SBECmd output: ``BagMRU\\<slot>\\...``.
    """
    rows: List[Dict[str, str]] = []

    def add(bag, abs_path, kind, first, last, mru, slot):
        rows.append({
            "BagPath": bag, "AbsolutePath": abs_path,
            "ShellType": kind,
            "FirstInteracted": ts(first), "LastInteracted": ts(last),
            "MRUPosition": str(mru), "NodeSlot": str(slot),
        })

    # ---- Desktop / My Computer root branches.
    add("BagMRU\\0", "Desktop", "RootFolder",
        "2024-08-12 09:21:14", "2024-11-13 09:31:00", 0, 1)
    add("BagMRU\\0\\1", "My Computer", "RootFolder",
        "2024-08-12 09:21:14", "2024-11-13 09:15:32", 1, 2)

    # ---- C: drive branch — daily user folders.
    add("BagMRU\\0\\1\\0", "C:\\", "Drive",
        "2024-08-12 09:21:14", "2024-11-13 09:15:32", 0, 3)
    add("BagMRU\\0\\1\\0\\0", "C:\\Users", "Directory",
        "2024-08-12 09:21:14", "2024-11-13 06:57:30", 0, 4)
    add("BagMRU\\0\\1\\0\\0\\0", f"C:\\Users\\{USER}", "Directory",
        "2024-08-19 14:11:09", "2024-11-13 09:16:42", 0, 5)
    add("BagMRU\\0\\1\\0\\0\\0\\0", f"C:\\Users\\{USER}\\Documents",
        "Directory", "2024-08-19 14:11:09", "2024-11-12 16:14:33", 0, 6)
    add("BagMRU\\0\\1\\0\\0\\0\\1", f"C:\\Users\\{USER}\\Downloads",
        "Directory", "2024-08-22 11:14:00", "2024-11-13 06:57:30", 1, 7)
    add("BagMRU\\0\\1\\0\\0\\0\\2", f"C:\\Users\\{USER}\\Desktop",
        "Directory", "2024-08-19 14:11:09", "2024-11-12 16:30:00", 2, 8)
    add("BagMRU\\0\\1\\0\\0\\0\\3", f"C:\\Users\\{USER}\\AppData",
        "Directory", "2024-09-22 11:14:00", "2024-10-22 13:30:00", 3, 9)

    # ---- F: drive branch — the USB / removable media trail. A drive is
    # a child of My Computer (BagMRU\0\1), a sibling of C:\, not a
    # folder under it. F:\ is first browsed at 09:14:21, after the
    # device attaches (09:14:08) and NTFS reports the F: volume
    # healthy (EID 98, 09:14:12) — Explorer cannot open F:\ before the
    # volume exists. The Confidential subdir's first interaction
    # (09:15:32) precedes the Excel/Word document opens (09:16:18 /
    # 09:16:42).
    add("BagMRU\\0\\1\\1", "F:\\", "Drive",
        "2024-11-13 09:14:21", "2024-11-13 09:24:47", 2, 10)
    add("BagMRU\\0\\1\\1\\0", "F:\\Vendors", "Directory",
        "2024-11-13 09:14:42", "2024-11-13 09:15:32", 0, 11)
    add("BagMRU\\0\\1\\1\\0\\0", "F:\\Vendors\\Confidential",
        "Directory",
        "2024-11-13 09:15:32", "2024-11-13 09:16:42", 0, 12)
    add("BagMRU\\0\\1\\1\\1", "F:\\Personal", "Directory",
        "2024-11-13 09:14:42", "2024-11-13 09:14:55", 1, 13)

    # ---- Network branch + a sibling Downloads\old folder (noise).
    add("BagMRU\\0\\2", "Network", "RootFolder",
        "2024-09-12 11:00:00", "2024-11-08 14:18:00", 3, 14)
    add("BagMRU\\0\\2\\0", "\\\\filesvr-fin\\Shared", "NetworkShare",
        "2024-09-12 11:00:00", "2024-11-08 14:18:00", 0, 15)
    add("BagMRU\\0\\1\\0\\0\\0\\1\\0",
        f"C:\\Users\\{USER}\\Downloads\\old", "Directory",
        "2024-10-22 13:30:00", "2024-11-08 11:14:00", 4, 16)

    _ = rng
    return rows


def generate_browser_history(rng: random.Random) -> List[Dict[str, str]]:
    """Edge / Chromium browser history.

    Hand-coded so the lab can:
      - Trace the docm download chain (06:30 inbox -> finance-news-daily
        -> /download?file=Q4_Vendor_Review.docm)
      - Observe a second suspicious "drive-share.example.net" download
        URL during the morning (08:14)
      - Find ordinary background browsing (Bing searches, Teams,
        intranet) to make filtering non-trivial
    """
    rows: List[Dict[str, str]] = []

    def add(t, url, title, vc, tc, ref, trans):
        rows.append({
            "VisitTime": ts(t), "URL": url, "Title": title,
            "VisitCount": str(vc), "TypedCount": str(tc),
            "LastVisitTime": ts(t), "ReferrerURL": ref,
            "Transition": trans,
        })

    # ---- The lure chain: inbox -> blog post -> download URL.
    add("2024-11-13 06:30:18",
        "https://outlook.office365.com/mail/inbox",
        "Inbox - j.smith - Outlook", 184, 12, "", "typed")
    add("2024-11-13 06:31:42",
        "https://finance-news-daily.example.com/2024/11/q4-vendor-roundup",
        "Q4 Vendor Roundup - Finance News Daily", 1, 0,
        "https://outlook.office365.com/mail/inbox", "link")
    add("2024-11-13 06:32:18",
        ("https://finance-news-daily.example.com/download"
         "?file=Q4_Vendor_Review.docm&id=8841ab"),
        "Download - Q4_Vendor_Review.docm", 1, 0,
        ("https://finance-news-daily.example.com/2024/11/"
         "q4-vendor-roundup"), "link")

    # ---- Morning rhythm: inbox reload, dashboard, vendor list.
    add("2024-11-13 06:42:11",
        "https://outlook.office365.com/mail/inbox",
        "Inbox - j.smith - Outlook", 184, 12, "", "reload")
    add("2024-11-13 06:43:55",
        "https://intranet.finance.example.com/dashboard",
        "Finance Dashboard", 142, 8, "", "typed")
    add("2024-11-13 06:55:00",
        "https://intranet.finance.example.com/vendors/q4",
        "Q4 Vendor List", 42, 2,
        "https://intranet.finance.example.com/dashboard", "link")

    # ---- Excel help searches (legitimate looking).
    add("2024-11-13 07:18:42",
        "https://www.bing.com/search?q=excel+pivot+slicer+date+range",
        "excel pivot slicer date range - Bing", 1, 0, "", "typed")
    add("2024-11-13 07:19:14",
        ("https://support.microsoft.com/en-us/office/"
         "insert-a-slicer-to-filter-data-"
         "249f966b-a9d5-4b0f-b31a-12651785d29d"),
        "Insert a slicer to filter data - Microsoft Support", 1, 0,
        "https://www.bing.com/search?q=excel+pivot+slicer+date+range",
        "link")

    # ---- Teams / OneDrive / suspicious drive-share.
    add("2024-11-13 07:42:08",
        "https://teams.microsoft.com/_", "Microsoft Teams",
        68, 4, "", "typed")
    add("2024-11-13 08:05:18",
        "https://onedrive.live.com/personal/", "OneDrive",
        21, 0, "", "startup")
    add("2024-11-13 08:14:00",
        "https://drive-share.example.net/d/8841abf2/preview",
        "Shared - vendor_packet.zip", 1, 0,
        "https://outlook.office365.com/mail/inbox", "link")
    add("2024-11-13 08:14:42",
        "https://drive-share.example.net/d/8841abf2/download",
        "Download vendor_packet.zip - 12.4 MB", 1, 0,
        "https://drive-share.example.net/d/8841abf2/preview", "link")

    # ---- Mid-morning: intranet, weather, more searches.
    add("2024-11-13 08:32:14",
        "https://intranet.finance.example.com/dashboard",
        "Finance Dashboard", 142, 8, "", "reload")
    add("2024-11-13 08:48:00",
        "https://www.weather.example.com/", "Local Weather",
        68, 4, "", "typed")
    add("2024-11-13 09:00:14",
        "https://outlook.office365.com/mail/inbox",
        "Inbox - j.smith - Outlook", 184, 12, "", "reload")
    add("2024-11-13 09:08:18",
        "https://intranet.finance.example.com/vendors/onboard",
        "Vendor Onboarding", 18, 1,
        "https://intranet.finance.example.com/dashboard", "link")

    # ---- USB-related troubleshooting searches (tells the analyst the
    # user struggled with the removable drive — corroborates timing).
    add("2024-11-13 09:18:42",
        "https://www.bing.com/search?q=open+xlsx+from+usb+read+only",
        "open xlsx from usb read only - Bing", 1, 0, "", "typed")
    add("2024-11-13 09:19:14",
        ("https://answers.microsoft.com/en-us/msoffice/forum/all/"
         "excel-read-only-from-usb-drive"),
        "Excel read only from USB drive - Microsoft Community",
        1, 0,
        "https://www.bing.com/search?q=open+xlsx+from+usb+read+only",
        "link")
    add("2024-11-13 09:22:11",
        "https://teams.microsoft.com/_", "Microsoft Teams",
        68, 4, "", "typed")
    add("2024-11-13 09:24:42",
        "https://outlook.office365.com/mail/inbox",
        "Inbox - j.smith - Outlook", 184, 12, "", "reload")
    add("2024-11-13 09:28:00",
        "https://intranet.finance.example.com/dashboard",
        "Finance Dashboard", 142, 8, "", "reload")
    add("2024-11-13 09:30:42",
        "https://www.bing.com/search?q=usb+drive+suddenly+disconnect",
        "usb drive suddenly disconnect - Bing", 1, 0, "", "typed")

    # ---- Yesterday's tail (mainly to widen the window) — kept at the
    # end on purpose since the committed CSV is not in chronological
    # order and parser output usually emerges sorted by VisitTime DESC
    # then chunked.
    add("2024-11-12 16:18:00",
        "https://intranet.finance.example.com/budgets/fy25",
        "FY25 Budget Workspace", 42, 2,
        "https://intranet.finance.example.com/dashboard", "link")
    add("2024-11-12 14:22:00",
        "https://outlook.office365.com/mail/inbox",
        "Inbox - j.smith - Outlook", 184, 12, "", "reload")
    add("2024-11-08 13:42:00",
        "https://www.bing.com/search?q=monthly+expense+report+template",
        "monthly expense report template - Bing", 1, 0, "", "typed")

    _ = rng
    return rows


def generate_usbstor(rng: random.Random) -> List[Dict[str, str]]:
    """``HKLM\\System\\CurrentControlSet\\Enum\\USBSTOR`` enumeration.

    Hand-coded entries:
      - The SanDisk Cruzer Glide (VID 0781 / PID 5567) is the focus of
        Lab 06. Its volume GUID ``{b4d722a1-1142-...}`` matches the
        VolumeSerialNumber ``B4D7-22A1`` used in the F: LNK records.
      - Other devices are historical (last connected days/weeks ago).
      - One USBSTOR\\CdRom entry is included to verify the analyst can
        ignore non-Disk classes.
    """
    rows: List[Dict[str, str]] = []

    def add(dclass, vid, pid, rev, ser, name, fc, lc, lit, lrt,
            parent, did, vguid):
        rows.append({
            "DeviceClass": dclass, "VendorId": vid, "ProductId": pid,
            "Revision": rev, "SerialNumber": ser, "FriendlyName": name,
            "FirstConnected": ts(fc), "LastConnected": ts(lc),
            "LastInsertTime": ts(lit), "LastRemovalTime": ts(lrt),
            "ParentIdPrefix": parent, "DeviceInstanceId": did,
            "VolumeGuid": vguid,
        })

    # ---- The SanDisk Cruzer — the lab's USB.
    add("USBSTOR\\Disk", USB_VENDOR_ID, USB_PRODUCT_ID, USB_REVISION,
        USB_SERIAL, USB_FRIENDLY,
        T_USB_ATTACH, T_USB_ATTACH, T_USB_ATTACH, T_USB_REMOVE,
        "8&1c4abb9d&0",
        ("USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer_Glide&Rev_8.07\\"
         f"{USB_SERIAL}&0"),
        USB_VOL_GUID)

    # ---- Historical devices — different vendors, ranges, dates.
    add("USBSTOR\\Disk", "058F", "6387", "0100",
        "058F63876387", "Generic Mass Storage USB Device",
        "2024-09-22 11:14:00", "2024-10-15 14:18:00",
        "2024-10-15 14:18:00", "2024-10-15 14:42:11",
        "8&2d3abc8e&0",
        ("USBSTOR\\Disk&Ven_Generic&Prod_Mass_Storage&Rev_0100\\"
         "058F63876387&0"),
        "{a1c84218-8841-11ee-9b3a-0c9d92841421}")
    add("USBSTOR\\Disk", "0951", "1666", "1100",
        "E0D55EA579C8F1718841BA12",
        "Kingston DataTraveler 3.0 USB Device",
        "2024-08-22 11:00:00", "2024-08-22 16:42:11",
        "2024-08-22 16:42:11", "2024-08-22 17:14:08",
        "8&3e4cdd2f&0",
        ("USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_1100\\"
         "E0D55EA579C8F1718841BA12&0"),
        "{c2143421-7821-11ee-aa42-0c9d92841421}")
    add("USBSTOR\\Disk", "090C", "1000", "1100",
        "FBA000000000028841",
        "Silicon Motion Flash Drive USB Device",
        "2024-09-19 14:42:00", "2024-09-19 15:14:00",
        "2024-09-19 15:14:00", "2024-09-19 15:18:00",
        "8&4f5dee30&0",
        ("USBSTOR\\Disk&Ven_SiliconMotion&Prod_Flash_Drive&Rev_1100\\"
         "FBA000000000028841&0"),
        "{d3258411-9941-11ee-bb42-0c9d92841421}")
    add("USBSTOR\\Disk", "0BC2", "231A", "0100",
        "WX31AA8841BA", "WD My Passport 25EE USB Device",
        "2024-08-19 11:14:09", "2024-09-04 09:14:00",
        "2024-09-04 09:14:00", "2024-09-04 11:42:00",
        "8&5a6eff41&0",
        ("USBSTOR\\Disk&Ven_WD&Prod_My_Passport_25EE&Rev_0100\\"
         "WX31AA8841BA&0"),
        "{e4368421-aa42-11ee-cc41-0c9d92841421}")
    # CdRom class — present on most workstations as a leftover
    # entry from imaging tools or virtual CD drives; included so the
    # analyst learns to filter on DeviceClass.
    add("USBSTOR\\CdRom", "0420", "9999", "1.00",
        "VirtualUSBCDXX9412", "Virtual USB CD Drive",
        "2024-08-12 09:21:14", "2024-08-12 09:21:14",
        "2024-08-12 09:21:14", "2024-08-12 09:21:14",
        "8&6b7faa42&0",
        ("USBSTOR\\CdRom&Ven_Virtual&Prod_USBCD&Rev_1.00\\"
         "VirtualUSBCDXX9412&0"),
        "")

    _ = rng
    return rows


# ---------------------------------------------------------------------------
# ShimCache / AppCompatCache
# ---------------------------------------------------------------------------

def generate_shimcache(rng: random.Random) -> List[Dict[str, str]]:
    """AppCompatCacheParser-style output for the FIN-WS23 SYSTEM hive.

    Position 0 is ``dl.exe``. Two details are worth the responder's time:

    * The path is ``dl.exe``, lower case — ShimCache preserves the on-disk
      name, whereas ``prefetch.csv`` shows ``DL.EXE`` because Prefetch
      upper-cases it. Same binary, two spellings; matching them is part of
      the Chapter 6 exercise.
    * ``LastModifiedTimeUTC`` is 06:59:08, the moment PowerShell wrote the
      file — half a second before Amcache's ``LastModified``
      (06:59:08.5) and six seconds before the Prefetch first run. Three artifacts, three slightly
      different clocks on the same event.

    Ordering is insertion order (most recent first), *not* timestamp
    order — several older OS binaries further down this list have newer
    file timestamps than rows above them.
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
    ps_home = f"{sys32}\\WindowsPowerShell\\v1.0"
    os_build = "2024-08-12 09:21:14.5000000"

    # --- Incident window --------------------------------------------------
    add(f"C:\\Users\\{USER}\\Downloads\\dl.exe",
        "2024-11-13 06:59:08.0000000")
    add(f"{sys32}\\net1.exe", os_build)
    add(f"{sys32}\\net.exe", os_build)
    add(f"{sys32}\\whoami.exe", os_build)
    add(f"{sys32}\\ipconfig.exe", os_build)
    add(f"{sys32}\\conhost.exe", os_build)
    add(f"{sys32}\\cmd.exe", os_build)
    add(f"{ps_home}\\powershell.exe", os_build)
    add(f"{office}\\WINWORD.EXE", "2024-11-12 11:00:00.0000000")

    # --- Same-day, post-incident (USB session) ----------------------------
    add(f"{office}\\EXCEL.EXE", "2024-11-12 11:00:00.0000000")
    add(f"{sys32}\\rundll32.exe", os_build)
    add(f"{sys32}\\drvinst.exe", os_build)
    add("C:\\Windows\\Explorer.EXE", os_build)

    # --- Recent background ------------------------------------------------
    add(f"{office}\\OUTLOOK.EXE", "2024-11-12 11:00:00.0000000")
    add(f"{sys32}\\NOTEPAD.EXE", os_build)
    add("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "2024-11-12 12:32:04.0000000")
    add("C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\"
        "msedgewebview2.exe", "2024-11-12 12:32:04.0000000")
    add(f"C:\\Users\\{USER}\\AppData\\Local\\Microsoft\\OneDrive\\"
        "OneDrive.exe", "2024-11-08 11:00:00.0000000")
    add(f"{sys32}\\SearchFilterHost.exe", os_build)
    add(f"{sys32}\\SearchProtocolHost.exe", os_build)
    add(f"{sys32}\\SearchIndexer.exe", os_build)
    add(f"{sys32}\\taskhostw.exe", os_build)
    add(f"{sys32}\\svchost.exe", os_build)
    add(f"{sys32}\\dllhost.exe", os_build)
    add(f"{sys32}\\RuntimeBroker.exe", os_build)
    add(f"{sys32}\\sihost.exe", os_build)
    add(f"{sys32}\\ctfmon.exe", os_build)
    add(f"{sys32}\\userinit.exe", os_build)
    add(f"{sys32}\\winlogon.exe", os_build)
    add(f"{sys32}\\lsass.exe", os_build)
    add(f"{sys32}\\services.exe", os_build)
    add(f"{sys32}\\dwm.exe", os_build)
    add(f"{sys32}\\LogonUI.exe", os_build)
    add(f"{sys32}\\consent.exe", os_build)
    add(f"{sys32}\\wermgr.exe", os_build)
    add(f"{sys32}\\smartscreen.exe", os_build)
    add(f"{sys32}\\WmiPrvSE.exe", os_build)
    add(f"{sys32}\\spoolsv.exe", os_build)
    add("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\"
        "4.18.24090.11-0\\MsMpEng.exe", "2024-11-08 03:14:00.0000000")
    add("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\"
        "4.18.24090.11-0\\MpCmdRun.exe", "2024-11-08 03:14:00.0000000")
    add("C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\"
        "OfficeClickToRun.exe", "2024-11-12 11:00:00.0000000")
    add("C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\"
        "MicrosoftEdgeUpdate.exe", "2024-09-22 03:14:00.0000000")
    return rows


# ---------------------------------------------------------------------------
# Recycle Bin
# ---------------------------------------------------------------------------

def generate_recyclebin(rng: random.Random) -> List[Dict[str, str]]:
    """``RBCmd``-style output for ``C:\\$Recycle.Bin\\<SID>\\``.

    Each row is one ``$I`` metadata file. ``SourceName`` is the ``$I``
    file's own path on disk; ``FileName`` is the original full path the
    ``$I`` records; ``DeletedOn`` is the deletion time stored inside it.

    The row that matters for Lab 06 is ``Q4_Vendor_Review.docm`` — the lure
    document. It was deleted at 07:16:04, seventeen minutes after ``dl.exe``
    ran, and the ``SourceCreated`` / ``SourceModified`` pair still matches
    the ``TargetCreated`` / ``TargetModified`` values in the
    ``Q4_Vendor_Review.lnk`` row of ``lnk-files.csv``. The LNK survives the
    deletion, so the two artifacts corroborate each other: the LNK proves it
    was opened, the ``$I`` proves it was then thrown away.

    Nothing from the ``F:\\`` volume appears here. Deletions on removable
    media do not use the fixed disk's Recycle Bin, and that absence is a
    real finding rather than a gap in the dataset.
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
    dl = f"C:\\Users\\{USER}\\Downloads"
    desk = f"C:\\Users\\{USER}\\Desktop"

    # --- Incident-relevant -------------------------------------------------
    add("8A4C1F", "File", f"{dl}\\Q4_Vendor_Review.docm", 184221,
        "2024-11-13 07:16:04", "2024-11-13 06:42:14",
        "2024-11-13 06:42:14")

    # --- Ordinary housekeeping deletions ----------------------------------
    add("B12E90", "File", f"{docs}\\Vendor_List_2023.xlsx", 38214,
        "2024-11-12 14:24:11", "2023-10-04 11:14:00",
        "2024-01-18 09:42:00")
    add("C3D7A2", "File", f"{desk}\\Q3_Tasks.xlsx", 21455,
        "2024-11-04 09:31:18", "2024-07-01 09:14:00",
        "2024-09-30 16:42:00")
    add("D5F8B4", "File", f"{dl}\\invoice_scan_0912.pdf", 482114,
        "2024-10-22 13:32:00", "2024-09-12 10:18:00",
        "2024-09-12 10:18:00")
    add("E7A1C6", "Directory", f"{docs}\\Old Vendor Quotes", 1284221,
        "2024-10-15 15:02:44", "2023-08-22 11:14:00",
        "2024-06-14 14:22:18")
    add("F9B3D8", "File", f"{desk}\\scratch.txt", 1842,
        "2024-10-08 11:18:22", "2024-10-08 10:42:00",
        "2024-10-08 11:04:11")
    add("A2C5E1", "File", f"{docs}\\Expense_Policy_v1.docx", 17284,
        "2024-09-19 14:44:08", "2024-02-14 09:14:00",
        "2024-08-30 11:22:00")
    add("B4D7F3", "File", f"{dl}\\setup_reader_2024.exe", 148021184,
        "2024-09-04 10:02:11", "2024-09-04 09:58:42",
        "2024-09-04 09:58:42")
    return rows


# ---------------------------------------------------------------------------
# Security event log
# ---------------------------------------------------------------------------

def generate_security_evtx(rng: random.Random) -> List[Dict[str, str]]:
    """EvtxECmd-style export of ``Security.evtx``.

    Chapter 6 is about shell and application artifacts, and this log is
    here to be the *control* against them — every claim the shell artifacts
    make should be checkable here:

    * ``WINWORD.EXE`` -> ``powershell.exe`` at 06:58:30 is the parent/child
      pair the EDR alert fired on; the Prefetch run times for both
      binaries agree with it to the second.
    * Record numbers rise with ``TimeCreated``. At logon the DWM-1 4624
      comes first, then j.smith's 4624 and, immediately after it, the
      4672 for the same logon.
    * ``dl.exe`` at 06:59:14 has ``ParentProcessName=powershell.exe`` — the
      link Prefetch and Amcache cannot give you, because neither records
      lineage.
    * The 09:14:08 ``drvinst.exe`` 4688 and the 6416 beside it are the
      log-side witnesses for the USBSTOR install time.
    * The two 4688s at 09:16:18 / 09:16:42 name the ``F:\\Vendors\\
      Confidential\\`` documents on their command lines, matching the two
      removable-media LNK rows.
    """
    _ = rng
    rows: List[Dict[str, str]] = []

    def add(rec, t, eid, user, desc, payload):
        rows.append({
            "RecordNumber": str(rec), "TimeCreated": ts(t),
            "EventID": str(eid), "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": FQDN, "UserName": user, "Level": "Information",
            "Description": desc, "Payload": payload,
        })

    sys32 = "C:\\Windows\\System32"
    ps_exe = f"{sys32}\\WindowsPowerShell\\v1.0\\powershell.exe"
    office = "C:\\Program Files\\Microsoft Office\\root\\Office16"
    edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    dl_exe = f"C:\\Users\\{USER}\\Downloads\\dl.exe"
    subj = f"SubjectUserName={USER} SubjectDomainName={DOMAIN}"

    # --- Overnight noise ---------------------------------------------------
    add(2941002, "2024-11-13 02:14:08.4218421", 4625, "SYSTEM",
        "Failed logon",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=3 "
        "IpAddress=10.0.4.42 FailureReason=%%2313 Status=0xC000006D "
        "SubStatus=0xC000006A WorkstationName=BACKUP-SCHED")
    add(2941004, "2024-11-13 02:14:14.0000000", 4624, "SYSTEM",
        "Successful logon",
        f"TargetUserName=svc-backup TargetDomainName={DOMAIN} LogonType=3 "
        "LogonProcessName=Kerberos ProcessName=- IpAddress=10.0.4.42 "
        "WorkstationName=BACKUP-SCHED")
    add(2941006, "2024-11-13 02:14:52.0000000", 4634, "SYSTEM", "Logoff",
        "TargetUserName=svc-backup LogonType=3")
    add(2941012, "2024-11-13 03:00:11.1248421", 4624, "SYSTEM",
        "Successful logon",
        "TargetUserName=SYSTEM TargetDomainName=NT AUTHORITY LogonType=5 "
        f"LogonProcessName=Advapi ProcessName={sys32}\\services.exe "
        "IpAddress=- ElevatedToken=Yes")
    add(2941014, "2024-11-13 03:00:11.4214821", 4688, "SYSTEM",
        "Process created",
        f"NewProcessName={sys32}\\svchost.exe ProcessId=0x12C8 "
        f"SubjectUserName={HOSTNAME}$ SubjectDomainName={DOMAIN} "
        f"ParentProcessName={sys32}\\services.exe "
        f"CommandLine={sys32}\\svchost.exe -k netsvcs -p")

    # --- Start of day ------------------------------------------------------
    # The logon precedes every user-session artifact of the day: Edge
    # starts at 06:30:00 and the first browser visit is 06:30:18.
    add(2941107, ts(T_LOGON, ".2000000"), 4624, "SYSTEM",
        "Successful logon",
        "TargetUserName=DWM-1 TargetDomainName=Window Manager LogonType=2 "
        f"LogonProcessName=Advapi ProcessName={sys32}\\winlogon.exe")
    add(2941108, ts(T_LOGON, ".4842311"), 4624, "SYSTEM",
        "Successful logon",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=2 "
        f"LogonProcessName=User32 ProcessName={sys32}\\winlogon.exe "
        f"IpAddress=127.0.0.1 WorkstationName={HOSTNAME}")
    add(2941109, ts(T_LOGON, ".5012834"), 4672, USER,
        "Special privileges assigned",
        f"{subj} PrivilegeList=SeShutdownPrivilege SeUndockPrivilege "
        "SeIncreaseWorkingSetPrivilege SeTimeZonePrivilege")
    add(2941112, ts(T_SHELL_START, ".1224821"), 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\Explorer.EXE ProcessId=0x1A2C "
        f"{subj} ParentProcessName={sys32}\\userinit.exe "
        "TokenElevationType=%%1936 CommandLine=C:\\Windows\\Explorer.EXE")
    # Edge's first start of the day matches its Prefetch PreviousRun0 and
    # Jump List CreationTime. Outlook's start matches its Prefetch,
    # UserAssist and Jump List time (06:42:14).
    add(2941114, ts(T_EDGE_START), 4688, USER,
        "Process created",
        f"NewProcessName={edge} ProcessId=0x2F14 {subj} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        f'TokenElevationType=%%1938 CommandLine="{edge}"')
    add(2941118, "2024-11-13 06:42:14.5000000", 4688, USER,
        "Process created",
        f"NewProcessName={office}\\OUTLOOK.EXE ProcessId=0x2148 {subj} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        f'TokenElevationType=%%1938 CommandLine="{office}\\OUTLOOK.EXE"')

    # --- The macro chain ---------------------------------------------------
    add(2941204, ts(T_WINWORD_OPEN, ".0214821"), 4688, USER,
        "Process created",
        f"NewProcessName={office}\\WINWORD.EXE ProcessId=0x3F88 {subj} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        f'TokenElevationType=%%1938 CommandLine="{office}\\WINWORD.EXE" '
        f'/n "C:\\Users\\{USER}\\Downloads\\Q4_Vendor_Review.docm"')
    add(2941208, ts(T_PS_SPAWN, ".4218921"), 4688, USER,
        "Process created",
        f"NewProcessName={ps_exe} ProcessId=0x4128 {subj} "
        f"ParentProcessName={office}\\WINWORD.EXE "
        'TokenElevationType=%%1938 CommandLine="powershell.exe" -NoProfile '
        "-WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand "
        "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACcA"
        "aAB0AHQAcABzADoALwAvAGYAaQBuAGEAbgBjAGUALQBuAGUAdwBzAC0AZABhAGkA"
        "bAB5AC4AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AYQAvAGQAJwAgAC0ATwB1AHQA"
        "RgBpAGwAZQAgACQAZQBuAHYAOgBVAFMARQBSAFAAUgBPAEYASQBMAEUAXABEAG8A"
        "dwBuAGwAbwBhAGQAcwBcAGQAbAAuAGUAeABlAA==")
    add(2941209, ts(T_PS_SPAWN, ".5811542"), 4688, USER,
        "Process created",
        f"NewProcessName={sys32}\\cmd.exe ProcessId=0x4184 {subj} "
        f"ParentProcessName={ps_exe} TokenElevationType=%%1938 "
        'CommandLine="cmd.exe" /c whoami')
    add(2941210, ts(T_PS_SPAWN, ".8124581"), 4688, USER,
        "Process created",
        f"NewProcessName={sys32}\\conhost.exe ProcessId=0x4188 {subj} "
        f"ParentProcessName={sys32}\\cmd.exe TokenElevationType=%%1938 "
        "CommandLine=\\??\\C:\\WINDOWS\\system32\\conhost.exe "
        "0xffffffff -ForceV1")
    # The headline row: dl.exe, parented by powershell.exe.
    add(2941214, ts(T_DL_RUN, ".4214582"), 4688, USER,
        "Process created",
        f"NewProcessName={dl_exe} ProcessId=0x4421 {subj} "
        f"ParentProcessName={ps_exe} TokenElevationType=%%1938 "
        f'CommandLine="{dl_exe}"')

    # --- Recon sequence ----------------------------------------------------
    add(2941308, ts(T_CMD_RECON, ".0124211"), 4688, USER,
        "Process created",
        f"NewProcessName={sys32}\\cmd.exe ProcessId=0x4824 {subj} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        'TokenElevationType=%%1938 CommandLine="cmd.exe"')
    add(2941310, "2024-11-13 07:14:42.0000000", 4688, USER,
        "Process created",
        f"NewProcessName={sys32}\\ipconfig.exe ProcessId=0x4828 {subj} "
        f"ParentProcessName={sys32}\\cmd.exe TokenElevationType=%%1938 "
        "CommandLine=ipconfig /all")
    add(2941312, "2024-11-13 07:14:55.0000000", 4688, USER,
        "Process created",
        f"NewProcessName={sys32}\\whoami.exe ProcessId=0x482C {subj} "
        f"ParentProcessName={sys32}\\cmd.exe TokenElevationType=%%1938 "
        "CommandLine=whoami /all")
    add(2941314, "2024-11-13 07:15:11.0000000", 4688, USER,
        "Process created",
        f"NewProcessName={sys32}\\net.exe ProcessId=0x4830 {subj} "
        f"ParentProcessName={sys32}\\cmd.exe TokenElevationType=%%1938 "
        "CommandLine=net group \"Domain Admins\" /domain")
    add(2941315, "2024-11-13 07:15:11.5000000", 4688, USER,
        "Process created",
        f"NewProcessName={sys32}\\net1.exe ProcessId=0x4834 {subj} "
        f"ParentProcessName={sys32}\\net.exe TokenElevationType=%%1938 "
        "CommandLine=C:\\Windows\\system32\\net1 group "
        "\"Domain Admins\" /domain")
    add(2941402, "2024-11-13 07:16:04.0000000", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\Explorer.EXE ProcessId=0x4A18 "
        f"{subj} ParentProcessName=C:\\Windows\\Explorer.EXE "
        "TokenElevationType=%%1938 CommandLine=C:\\Windows\\Explorer.EXE")

    # --- USB session -------------------------------------------------------
    add(2941602, ts(T_USB_ATTACH, ".0214821"), 4688, "SYSTEM",
        "Process created",
        f"NewProcessName={sys32}\\drvinst.exe ProcessId=0x5844 "
        f"SubjectUserName={HOSTNAME}$ SubjectDomainName={DOMAIN} "
        f"ParentProcessName={sys32}\\svchost.exe "
        'TokenElevationType=%%1936 CommandLine=DrvInst.exe "8" "201" '
        f'"{USB_DEVICE_PATH}"')
    add(2941603, ts(T_USB_ATTACH, ".8421042"), 6416, USER,
        "A new external device was recognized by the system",
        f"{subj} SubjectUserSid={USER_SID} ClassName=DiskDrive "
        "ClassId={4d36e967-e325-11ce-bfc1-08002be10318} "
        f"DeviceId={USB_DEVICE_PATH} DeviceDescription={USB_FRIENDLY}")
    add(2941608, ts(T_USB_SHELLBAG), 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\Explorer.EXE ProcessId=0x5880 "
        f"{subj} ParentProcessName={sys32}\\userinit.exe "
        "TokenElevationType=%%1938 CommandLine=C:\\Windows\\Explorer.EXE "
        "/factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b}")
    add(2941612, ts(T_USB_LNK_1), 4688, USER,
        "Process created",
        f"NewProcessName={office}\\EXCEL.EXE ProcessId=0x5918 {subj} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        f'TokenElevationType=%%1938 CommandLine="{office}\\EXCEL.EXE" '
        '"F:\\Vendors\\Confidential\\Vendor_Confidential_Roster.xlsx"')
    add(2941614, ts(T_USB_LNK_2), 4688, USER,
        "Process created",
        f"NewProcessName={office}\\WINWORD.EXE ProcessId=0x5944 {subj} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        f'TokenElevationType=%%1938 CommandLine="{office}\\WINWORD.EXE" '
        '"F:\\Vendors\\Confidential\\Bank_Account_Notes.docx"')
    add(2941702, ts(T_LAST_EDGE), 4688, USER,
        "Process created",
        f"NewProcessName={edge} ProcessId=0x6114 {subj} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        f'TokenElevationType=%%1938 CommandLine="{edge}"')
    add(2941802, "2024-11-13 12:04:18.0000000", 4634, "SYSTEM", "Logoff",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=2")
    rows.sort(key=lambda r: (r["TimeCreated"], int(r["RecordNumber"])))
    return rows


# ---------------------------------------------------------------------------
# System event log
# ---------------------------------------------------------------------------

def generate_system_evtx(rng: random.Random) -> List[Dict[str, str]]:
    """EvtxECmd-style export of ``System.evtx``.

    Mostly service-state noise, with one thing worth having: the PnP trail
    for the SanDisk Cruzer (EID 219 driver load, EID 20001 / 20003 driver
    and service install, EID 98 volume-healthy for ``F:``). Those give a
    second source for the 09:14:08 attach time that ``usbstor.csv`` asserts,
    and the EID 98 row is the one that ties the drive *letter* to the volume
    GUID independently of ``MountedDevices``.
    """
    _ = rng
    rows: List[Dict[str, str]] = []

    def add(rec, t, eid, provider, desc, payload):
        rows.append({
            "RecordNumber": str(rec), "TimeCreated": ts(t),
            "EventID": str(eid), "Channel": "System",
            "Provider": provider, "Computer": FQDN,
            "Level": "Information", "Description": desc,
            "Payload": payload,
        })

    scm = "Service Control Manager"
    pnp = "Microsoft-Windows-Kernel-PnP"
    upnp = "Microsoft-Windows-UserPnp"

    add(214102, "2024-11-13 02:00:00.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=Windows Update State=Running")
    add(214104, "2024-11-13 02:14:11.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=Volume Shadow Copy State=Running")
    add(214106, "2024-11-13 02:48:00.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=Volume Shadow Copy State=Stopped")
    add(214108, "2024-11-13 03:00:11.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=Background Intelligent Transfer Service State=Running")
    add(214112, "2024-11-13 03:42:18.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=Windows Update State=Stopped")
    # Tied to the logon (06:28:11), so it precedes — and is numbered
    # below — the 06:30:00 Windows Search event.
    add(214116, ts(T_LOGON), 7036, scm, "Service state changed",
        "ServiceName=User Profile Service State=Running")
    add(214118, "2024-11-13 06:30:00.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=Windows Search State=Running")
    add(214124, "2024-11-13 06:42:18.0000000", 6013, "EventLog",
        "System uptime", "The system uptime is 16358 seconds.")
    add(214132, "2024-11-13 06:59:20.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=Windows Error Reporting Service State=Running")
    add(214134, "2024-11-13 07:04:44.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=Windows Error Reporting Service State=Stopped")
    add(214138, "2024-11-13 07:18:00.0000000", 7040, scm,
        "Service start type changed",
        "ServiceName=Windows Update StartType changed from demand start "
        "to auto start")

    # --- SanDisk Cruzer attach --------------------------------------------
    add(214202, ts(T_USB_ATTACH), 219, pnp, "Driver loaded for device",
        f"DeviceInstanceId={USB_DEVICE_PATH} DriverName=usbstor.inf "
        "ClassGuid={36fc9e60-c465-11cf-8056-444553540000} Status=0x0")
    add(214203, "2024-11-13 09:14:09.0000000", 20001, upnp,
        "Driver installation completed",
        "Driver Management concluded the process to install driver "
        "disk.inf_amd64_9c3f7b2a1d04e881\\disk.inf for Device Instance ID "
        f"{USB_DEVICE_PATH} with the following status: 0x0.")
    add(214204, "2024-11-13 09:14:10.0000000", 20003, upnp,
        "Service installation for device completed",
        "Driver Management has concluded the process to add Service disk "
        f"for Device Instance ID {USB_DEVICE_PATH} with the following "
        "status: 0x0.")
    add(214206, "2024-11-13 09:14:12.0000000", 98,
        "Microsoft-Windows-Ntfs", "Volume is healthy",
        f"Volume {USB_VOL_GUID} (F:) is healthy. No action is needed.")
    add(214208, "2024-11-13 09:14:14.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=Portable Device Enumerator Service State=Running")
    # EID 225 prints the PID in decimal; 22656 is 0x5880, the Explorer
    # window the Security log shows starting at 09:15:32.
    add(214240, ts(T_USB_REMOVE), 225, pnp, "Device removal request",
        "The application \\Device\\HarddiskVolume3\\Windows\\explorer.exe "
        "with process id 22656 stopped the removal or ejection for the "
        f"device {USB_DEVICE_PATH}.")
    add(214242, "2024-11-13 09:24:49.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=Portable Device Enumerator Service State=Stopped")

    add(214302, "2024-11-13 12:04:22.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=User Profile Service State=Stopped")
    add(214304, "2024-11-13 12:04:41.0000000", 6006, "EventLog",
        "Event log service stopped",
        "The Event log service was stopped.")
    rows.sort(key=lambda r: (r["TimeCreated"], int(r["RecordNumber"])))
    return rows


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

GENERATORS: Dict[str, Callable[[random.Random], List[Dict[str, str]]]] = {
    "lnk-files.csv": generate_lnk_files,
    "jump-lists.csv": generate_jump_lists,
    "prefetch.csv": generate_prefetch,
    "amcache.csv": generate_amcache,
    "srum.csv": generate_srum,
    "userassist.csv": generate_userassist,
    "shellbags.csv": generate_shellbags,
    "browser-history.csv": generate_browser_history,
    "usbstor.csv": generate_usbstor,
    "shimcache.csv": generate_shimcache,
    "recyclebin.csv": generate_recyclebin,
    "security-evtx.csv": generate_security_evtx,
    "system-evtx.csv": generate_system_evtx,
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def write_csv(path: Path, fields: List[str], rows: List[Dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        # QUOTE_MINIMAL matches the committed CSVs — only quote fields
        # that contain commas, quotes, or newlines.
        writer = csv.DictWriter(fh, fieldnames=fields,
                                quoting=csv.QUOTE_MINIMAL,
                                lineterminator="\n", extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            # DictWriter would otherwise raise when a key is missing
            # from the row dict; replace missing values with "".
            writer.writerow({f: row.get(f, "") for f in fields})


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate the FIN-WS23 simulated dataset.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be written; do not "
                             "touch files.")
    parser.add_argument("--out-dir", default=".",
                        help="Directory to write CSVs into "
                             "(default: cwd).")
    parser.add_argument("--seed", type=lambda x: int(x, 0),
                        default=RANDOM_SEED,
                        help="Override the random seed.")
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir).resolve()

    print(f"FIN-WS23 generator — seed=0x{args.seed:X}")
    print(f"Output directory: {out_dir}")
    if args.dry_run:
        print("Mode: --dry-run (no files written)")
    print()

    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for filename, generator in GENERATORS.items():
        # Reseed per file so adding / removing a generator does not
        # disturb other files' output.
        local_rng = random.Random((args.seed ^ hash(filename)) & 0xFFFFFFFF)
        rows = generator(local_rng)
        fields = HEADERS[filename]
        target = out_dir / filename
        print(f"  {filename:<24} -> {len(rows):>4} rows "
              f"({len(fields)} columns)")
        if not args.dry_run:
            write_csv(target, fields, rows)

    if args.dry_run:
        print("\nDry run complete. Re-run without --dry-run to write files.")
    else:
        print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
