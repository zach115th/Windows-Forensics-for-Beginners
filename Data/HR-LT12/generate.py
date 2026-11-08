#!/usr/bin/env python3
"""Deterministic generator for the simulated HR-LT12 dataset.

Attack narrative
================
HR-LT12 is an HR department laptop assigned to user ``hr-user`` in the
``FINANCE`` domain. On 2024-11-13 a manager reported that the laptop
"felt slow at startup" and that a Q4 salary spreadsheet had appeared on
an unauthorized personal device. Triage of the host surfaces three
correlated threads:

1. **Persistence (2024-11-08 19:06:42 UTC).** A new HKCU Run value named
   ``HpHotkeyMonitor`` was written, pointing at
   ``C:\\Users\\hr-user\\AppData\\Local\\hp-hotkey\\hpkey.exe``. The
   name imitates a legitimate HP utility but the binary lives entirely
   under user-writable AppData.
2. **Removable media (2024-11-12 16:42:08 UTC).** A Kingston
   DataTraveler USB stick — VID ``0951``, PID ``1666``, serial
   ``001A92053B7CBE3196B40A0F`` — is first installed on the host,
   bound to drive ``E:`` at 16:42:14, then browsed into
   ``E:\\HR\\Confidential\\Salary_Data\\`` and
   ``E:\\HR\\Confidential\\Personnel\\``. The same volume is removed at
   17:31:02.
3. **OneDrive personal account (2024-11-12 16:55-17:10 UTC).** A second
   OneDrive account (``hr.user.personal@outlook.com``) is configured
   alongside the corporate account, and its local sync database
   records eight HR-confidential files entering the sync queue inside
   the incident window.

Earlier on 2024-11-12 the host shows normal HR activity — Outlook,
Edge, an Excel file open from the corporate OneDrive — that should not
be confused with the incident.

This script regenerates every CSV (and the ``setupapi-dev-log.txt``
text file) under ``Data/HR-LT12/`` from the above narrative. Hand-coded
"key event" rows preserve the attack story; a small amount of random
"noise" (older USB inserts, benign mount entries, etc.) fills out
plausible volumes. Output is byte-identical across runs given the same
``RANDOM_SEED``.

Usage
=====
    python3 generate.py                     # write files in current dir
    python3 generate.py --dry-run           # print plan only
    python3 generate.py --out-dir /tmp/x    # write to scratch dir
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
import zlib
from pathlib import Path
from typing import Callable, Dict, List

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Fixed seed -> byte-identical output across runs. Spelled as a hex
# literal with the letters of "HRLT12" mapped to legal hex digits
# (H->A, R->5, L->C, T->D) so it reads "0A5CD12". Override with --seed
# if you want a different stream.
RANDOM_SEED = 0x0A5CD12

HOSTNAME = "HR-LT12"
DOMAIN = "FINANCE"
USER = "hr-user"
USER_SID = "S-1-5-21-2918273645-1928374650-9182736450-1108"

# Suspect Kingston DataTraveler — the incident-window USB.
SUSPECT_USB_VID = "0951"
SUSPECT_USB_PID = "1666"
SUSPECT_USB_REV = "0100"
SUSPECT_USB_SERIAL = "001A92053B7CBE3196B40A0F"
SUSPECT_USB_FRIENDLY = "Kingston DataTraveler 3.0 USB Device"
SUSPECT_VOLUME_GUID = "{f1d2e9a4-77c0-4b91-83be-ab4a0ed1c6e5}"
SUSPECT_PARENT_PREFIX = "c&1eaf73b9&0"
# DeviceInstanceId uses the dotted revision display form ("1.00"),
# not the raw 4-digit revision code in the registry key. usbstor's
# parser converts ``0100`` -> ``1.00`` when building this string.
SUSPECT_DEVINST = (
    "USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0"
    f"&Rev_1.00\\{SUSPECT_USB_SERIAL}&0"
)
SUSPECT_DRIVE_LETTER = "E:"

# Personal OneDrive account (incident).
PERSONAL_ONEDRIVE_EMAIL = "hr.user.personal@outlook.com"
PERSONAL_CID = "a3f9c12b71d4e608"
BUSINESS_ONEDRIVE_EMAIL = "hr-user@finance.example.com"
BUSINESS_CID = "5e1c8a47b30f9d62"

# Persistence value (the suspicious HKCU Run entry).
PERSIST_VALUE_NAME = "HpHotkeyMonitor"
PERSIST_VALUE_DATA = f"C:\\Users\\{USER}\\AppData\\Local\\hp-hotkey\\hpkey.exe"
PERSIST_LWT = "2024-11-08 19:06:42.0000000"

# Anchor times (UTC).
T_PERSIST_WRITE = "2024-11-08 19:06:42"
T_USB_INSTALL = "2024-11-12 16:42:08"
T_USB_DRIVE_BIND = "2024-11-12 16:42:14"
T_USB_REMOVE = "2024-11-12 17:31:02"
T_OD_FIRST = "2024-11-12 16:55:18"
T_OD_LAST = "2024-11-12 17:09:47"


# ---------------------------------------------------------------------------
# CSV headers (exact match to the committed files — verified by diffing
# header rows against the on-disk copies).
# ---------------------------------------------------------------------------

HEADERS: Dict[str, List[str]] = {
    "registry-runkeys.csv": [
        "Hive", "KeyPath", "ValueName", "ValueData", "ValueType",
        "LastWriteTime", "Notes",
    ],
    "registry-services.csv": [
        "ServiceName", "DisplayName", "ImagePath", "StartType", "Type",
        "LastWriteTime", "Description",
    ],
    "usbstor.csv": [
        "DeviceClass", "VendorId", "ProductId", "Revision",
        "SerialNumber", "FriendlyName", "FirstConnected", "LastConnected",
        "LastInsertTime", "LastRemovalTime", "ParentIdPrefix",
        "DeviceInstanceId", "VolumeGuid",
    ],
    "mountpoints.csv": [
        "KeyPath", "ValueName", "VolumeGuid", "DriveLetter", "DeviceType",
        "LinkedDeviceInstanceId", "LastWriteTime", "Notes",
    ],
    "shellbags.csv": [
        "BagPath", "AbsolutePath", "ShellType",
        "FirstInteracted", "LastInteracted", "MRUPosition", "NodeSlot",
    ],
    "onedrive-accounts.csv": [
        "AccountId", "Email", "ServiceEndpointUri", "UserFolder",
        "UserCid", "OneAuthAccountId", "ConfiguredTenantsClient",
        "LastWriteTime",
    ],
    "onedrive-syncdb.csv": [
        "ItemId", "ItemPath", "ParentResourceId", "FileName", "Size",
        "ContentHash", "LastChange", "LastSync", "SyncState",
    ],
    # Event-log headers are copied verbatim from Data/WKSTN-221 so that a
    # responder can concatenate the two hosts' exports into one timeline
    # without reconciling columns. Do not "improve" these column names.
    "security-evtx.csv": [
        "RecordNumber", "TimeCreated", "EventID", "Channel", "Provider",
        "Computer", "UserName", "Level", "Description", "Payload",
    ],
    "system-evtx.csv": [
        "RecordNumber", "TimeCreated", "EventID", "Channel", "Provider",
        "Computer", "Level", "Description", "Payload",
    ],
}

FQDN = f"{HOSTNAME}.finance.local"

# USB-bus device instance path as the PnP stack writes it into event
# payloads: VID/PID plus serial, with no revision component. Compare the
# USBSTOR disk instance ID above, which carries the dotted ``Rev_1.00``.
SUSPECT_DEVICE_PATH = (
    f"USB\\VID_{SUSPECT_USB_VID}&PID_{SUSPECT_USB_PID}\\{SUSPECT_USB_SERIAL}"
)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def stable_seed(base: int, tag: str) -> int:
    """Per-file seed derived from ``base`` and the output filename.

    ``hash()`` on ``str`` is salted per process in Python 3 (see
    ``PYTHONHASHSEED``), so it cannot be used here. ``zlib.crc32`` is stable
    across interpreter runs, which keeps two invocations byte-identical.
    """
    return (base ^ zlib.crc32(tag.encode("utf-8"))) & 0xFFFFFFFF


def ts(s: str, frac: str = ".0000000") -> str:
    """Return a normalized timestamp string ``YYYY-MM-DD HH:MM:SS.fffffff``.

    If ``s`` already contains a fractional component we leave it alone;
    otherwise we tack ``frac`` on the end. This mirrors the WKSTN-221
    helper exactly.
    """
    if not s:
        return ""
    if "." in s:
        return s
    return s + frac


# ---------------------------------------------------------------------------
# Generators (one per output file)
# ---------------------------------------------------------------------------

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
    """HKLM + HKCU Run / RunOnce values, including the HpHotkeyMonitor
    persistence value the lab is built around.

    Most rows are factory-image and corporate-onboarding noise. The single
    scenario-defining row is the ``HpHotkeyMonitor`` NTUSER.DAT entry
    written on 2024-11-08 19:06:42 — its path under AppData is the tell.
    """
    rows: List[Dict[str, str]] = []

    def add(hive, key, vname, vdata, vtype, lwt, notes):
        rows.append({
            "Hive": hive, "KeyPath": key, "ValueName": vname,
            "ValueData": vdata, "ValueType": vtype,
            "LastWriteTime": ts(lwt) if lwt else "", "Notes": notes,
        })

    # HKLM SOFTWARE Run — factory image + corporate onboarding.
    add("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\Run",
        "SecurityHealth",
        "%windir%\\system32\\SecurityHealthSystray.exe",
        "RegExpandSz", "2024-08-04 11:02:18.0000000",
        "Built-in Defender tray")
    add("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\Run",
        "RTKAUDUService",
        "C:\\Program Files\\Realtek\\Audio\\HDA\\RtkAudUService64.exe -s",
        "RegSz", "2024-08-04 11:02:18.0000000", "Realtek audio")
    add("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\Run",
        "HotKeysCmds", "C:\\Windows\\System32\\hkcmd.exe",
        "RegSz", "2024-08-04 11:02:18.0000000",
        "Intel hotkey utility (factory image)")
    add("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\Run",
        "IgfxTray", "C:\\Windows\\System32\\igfxtray.exe",
        "RegSz", "2024-08-04 11:02:18.0000000",
        "Intel graphics tray (factory image)")
    add("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\Run",
        "OneDrive",
        '"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe" /background',
        "RegSz", "2024-09-03 08:41:22.0000000",
        "Per-machine OneDrive autostart")
    add("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\Run",
        "MicrosoftTeams",
        '"C:\\Program Files\\Microsoft\\Teams\\current\\Teams.exe" '
        '--processStart Teams.exe',
        "RegSz", "2024-09-03 08:41:22.0000000", "Teams autostart")
    add("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "DELETE_NULL_KEY", "", "RegSz",
        "2024-08-04 11:02:18.0000000", "Empty default")
    add("SOFTWARE",
        "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        "", "", "", "", "No values present")
    add("SOFTWARE", "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "", "", "", "", "No 32-bit Run entries")

    # HKCU NTUSER.DAT — corporate OneDrive + Teams + the *suspect* value.
    add("NTUSER.DAT", "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "OneDrive",
        f'"C:\\Users\\{USER}\\AppData\\Local\\Microsoft\\OneDrive'
        f'\\OneDrive.exe" /background',
        "RegSz", "2024-09-03 08:42:14.0000000",
        "Per-user OneDrive autostart (corporate account first run)")
    add("NTUSER.DAT", "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "com.squirrel.Teams.Teams",
        f'"C:\\Users\\{USER}\\AppData\\Local\\Microsoft\\Teams'
        f'\\Update.exe" --processStart "Teams.exe"',
        "RegSz", "2024-09-03 08:42:14.0000000",
        "Teams Squirrel updater")
    # ---- Scenario-defining persistence row ----
    add("NTUSER.DAT", "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        PERSIST_VALUE_NAME, PERSIST_VALUE_DATA, "RegSz",
        PERSIST_LWT,
        "Suspicious — name imitates HP utility but path is in "
        "user-writable AppData")
    add("NTUSER.DAT",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "", "", "", "", "No values present")
    add("NTUSER.DAT",
        "Software\\Microsoft\\Windows\\CurrentVersion\\"
        "Explorer\\Shell Folders",
        "Startup",
        f"C:\\Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\"
        "Start Menu\\Programs\\Startup",
        "RegSz", "2024-09-03 08:42:14.0000000",
        "Default startup folder path")

    # Winlogon defaults — included so analysts can quickly confirm
    # nothing was tampered with there either.
    add("SOFTWARE", "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "Userinit", "C:\\Windows\\system32\\userinit.exe,",
        "RegSz", "2024-08-04 11:02:18.0000000", "Default Userinit")
    add("SOFTWARE", "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "Shell", "explorer.exe",
        "RegSz", "2024-08-04 11:02:18.0000000", "Default Shell")

    rows = _normalize_key_lastwrite(rows)
    return rows


def generate_registry_services(rng: random.Random) -> List[Dict[str, str]]:
    """``HKLM\\SYSTEM\\CurrentControlSet\\Services`` definitions.

    All benign — registry-services.csv in this lab is included as a
    "show me what an unmodified service hive looks like" reference. The
    persistence in this scenario is in HKCU Run, not in a service.
    """
    rows: List[Dict[str, str]] = []

    def add(name, display, image, start, kind, lwt, desc):
        rows.append({
            "ServiceName": name, "DisplayName": display,
            "ImagePath": image, "StartType": start, "Type": kind,
            "LastWriteTime": ts(lwt) if lwt else "", "Description": desc,
        })

    add("W32Time", "Windows Time",
        "C:\\Windows\\system32\\svchost.exe -k LocalService -p",
        "Manual", "Win32_OwnProcess",
        "2024-08-04 11:02:18.0000000",
        "Maintains date and time synchronization")
    add("WinDefend", "Microsoft Defender Antivirus Service",
        '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform'
        '\\4.18.2410.0-0\\MsMpEng.exe"',
        "Automatic", "Win32_OwnProcess",
        "2024-11-11 02:47:39.0000000",
        "Helps protect users from malware")
    add("ClickToRunSvc", "Microsoft Office Click-to-Run Service",
        '"C:\\Program Files\\Common Files\\Microsoft Shared'
        '\\ClickToRun\\OfficeClickToRun.exe"',
        "Automatic", "Win32_OwnProcess",
        "2024-09-03 08:41:22.0000000", "Office Click-to-Run")
    add("Spooler", "Print Spooler",
        "C:\\Windows\\System32\\spoolsv.exe",
        "Automatic", "Win32_OwnProcess",
        "2024-08-04 11:02:18.0000000", "Manages print jobs")
    add("WSearch", "Windows Search",
        '"C:\\Windows\\system32\\SearchIndexer.exe" /Embedding',
        "Automatic_Delayed", "Win32_OwnProcess",
        "2024-08-04 11:02:18.0000000", "Provides content indexing")
    add("BITS", "Background Intelligent Transfer Service",
        "C:\\Windows\\System32\\svchost.exe -k netsvcs -p",
        "Manual", "Win32_ShareProcess",
        "2024-08-04 11:02:18.0000000",
        "Transfers files in the background")
    add("wuauserv", "Windows Update",
        "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
        "Manual", "Win32_ShareProcess",
        "2024-08-04 11:02:18.0000000",
        "Enables detection download install of updates")
    add("LanmanServer", "Server",
        "C:\\Windows\\System32\\svchost.exe -k netsvcs -p",
        "Automatic", "Win32_ShareProcess",
        "2024-08-04 11:02:18.0000000",
        "Supports file print and named-pipe sharing")
    add("LanmanWorkstation", "Workstation",
        "C:\\Windows\\System32\\svchost.exe -k NetworkService -p",
        "Automatic", "Win32_ShareProcess",
        "2024-08-04 11:02:18.0000000",
        "Creates and maintains client network connections")
    add("Dnscache", "DNS Client",
        "C:\\Windows\\System32\\svchost.exe -k NetworkService -p",
        "Automatic", "Win32_ShareProcess",
        "2024-08-04 11:02:18.0000000",
        "Caches DNS names and registers")
    add("EventLog", "Windows Event Log",
        "C:\\Windows\\System32\\svchost.exe -k "
        "LocalServiceNetworkRestricted -p",
        "Automatic", "Win32_ShareProcess",
        "2024-08-04 11:02:18.0000000",
        "Manages events and event logs")
    add("RpcSs", "Remote Procedure Call",
        "C:\\Windows\\system32\\svchost.exe -k rpcss -p",
        "Automatic", "Win32_ShareProcess",
        "2024-08-04 11:02:18.0000000", "RPC subsystem")
    add("TermService", "Remote Desktop Services",
        "C:\\Windows\\System32\\svchost.exe -k NetworkService",
        "Manual", "Win32_ShareProcess",
        "2024-08-04 11:02:18.0000000",
        "Allows users to connect interactively")
    add("UserManager", "User Manager",
        "C:\\Windows\\System32\\svchost.exe -k netsvcs -p",
        "Automatic", "Win32_ShareProcess",
        "2024-08-04 11:02:18.0000000",
        "Provides applications with access to user state")
    add("mpsdrv", "Windows Firewall Authorization Driver",
        "C:\\Windows\\System32\\drivers\\mpsdrv.sys",
        "Manual", "Kernel",
        "2024-08-04 11:02:18.0000000", "Windows Firewall driver")
    add("edgeupdate", "Microsoft Edge Update Service",
        '"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate'
        '\\MicrosoftEdgeUpdate.exe" /svc',
        "Automatic_Delayed", "Win32_OwnProcess",
        "2024-09-03 08:41:22.0000000", "Keeps Edge up to date")
    add("edgeupdatem", "Microsoft Edge Update Service (m)",
        '"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate'
        '\\MicrosoftEdgeUpdate.exe" /medsvc',
        "Manual", "Win32_OwnProcess",
        "2024-09-03 08:41:22.0000000", "Edge update worker service")
    add("SgrmBroker", "System Guard Runtime Monitor Broker",
        '"C:\\Windows\\system32\\SgrmBroker.exe"',
        "Automatic", "Win32_OwnProcess",
        "2024-08-04 11:02:18.0000000", "System integrity monitoring")
    add("SecurityHealthService", "Windows Security Service",
        "C:\\Windows\\system32\\SecurityHealthService.exe",
        "Manual", "Win32_OwnProcess",
        "2024-08-04 11:02:18.0000000",
        "Handles all unified security service notifications")
    add("USBSTOR", "USB Mass Storage Driver",
        "C:\\Windows\\System32\\drivers\\USBSTOR.SYS",
        "Manual", "KernelDriver",
        "2024-08-04 11:02:18.0000000",
        "USB mass storage class driver")
    add("HpQcvWmi", "HP Comm Recovery Service",
        '"C:\\Program Files\\HP\\Comm Recovery\\HpQcvWmi.exe"',
        "Manual", "Win32_OwnProcess",
        "2024-08-04 11:02:18.0000000",
        "HP factory imaging recovery helper")
    add("WlanSvc", "WLAN AutoConfig",
        "C:\\Windows\\System32\\svchost.exe -k "
        "LocalSystemNetworkRestricted -p",
        "Manual", "Win32_ShareProcess",
        "2024-08-04 11:02:18.0000000", "Manages wireless connections")
    add("DiagTrack", "Connected User Experiences and Telemetry",
        "C:\\Windows\\System32\\svchost.exe -k utcsvc -p",
        "Automatic", "Win32_OwnProcess",
        "2024-08-04 11:02:18.0000000",
        "Diagnostic and telemetry agent")
    return rows


def generate_usbstor(rng: random.Random) -> List[Dict[str, str]]:
    """``HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR`` device history.

    Five earlier benign storage devices + one promotional CD-ROM provide
    noise. The scenario-defining row is the *third* Kingston DataTraveler
    (serial ``001A92053B7CBE3196B40A0F``, VID/PID 0951/1666) — the same
    vendor and friendly name as two earlier benign devices (one of them
    with the same VID/PID) but a different serial. That ambiguity is the
    lab's "don't conflate vendors" moment.

    ``LastConnected`` is the ``0066`` last-arrival time (Ch5 §5.2.4), so it
    equals ``LastInsertTime`` on every row. A device inserted once has
    ``FirstConnected == LastConnected``.
    """
    rows: List[Dict[str, str]] = []

    def add(dev_class, vid, pid, rev, serial, friendly,
            first, last, last_ins, last_rem, parent, dev_inst, vol_guid):
        rows.append({
            "DeviceClass": dev_class, "VendorId": vid, "ProductId": pid,
            "Revision": rev, "SerialNumber": serial,
            "FriendlyName": friendly,
            "FirstConnected": ts(first), "LastConnected": ts(last),
            "LastInsertTime": ts(last_ins),
            "LastRemovalTime": ts(last_rem),
            "ParentIdPrefix": parent, "DeviceInstanceId": dev_inst,
            "VolumeGuid": vol_guid,
        })

    # Generic mass-storage stick — single connection.
    add("Disk", "058F", "6387", "0100", "058F0O1111B1",
        "Generic Mass-Storage USB Device",
        "2024-08-19 13:08:42", "2024-08-19 13:08:42",
        "2024-08-19 13:08:42", "2024-08-19 13:51:04",
        "7&2c1b3e9d&0",
        "USBSTOR\\Disk&Ven_Generic&Prod_Mass-Storage&Rev_1.00"
        "\\058F0O1111B1&0",
        "{a83d2c11-6e7a-4f02-9c5a-0db3e6f51122}")
    # Earlier *benign* Kingston DataTraveler (rev 1.10, different serial).
    add("Disk", "0951", "1620", "0110", "001A92038A1FAE6132B40A0F",
        SUSPECT_USB_FRIENDLY,
        "2024-09-02 10:14:09", "2024-10-21 09:47:30",
        "2024-10-21 09:47:30", "2024-10-21 10:24:17",
        "8&14a9f102&0",
        "USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_1.10"
        "\\001A92038A1FAE6132B40A0F&0",
        "{c1f4a7d8-2b39-4e15-8a0c-7d9e44351e77}")
    # SanDisk Cruzer Glide — benign.
    add("Disk", "0781", "5575", "0832", "4C530001220615116192",
        "SanDisk Cruzer Glide USB Device",
        "2024-09-19 11:42:00", "2024-09-19 11:42:00",
        "2024-09-19 11:42:00", "2024-09-19 12:21:44",
        "9&3d0a812c&0",
        "USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer_Glide&Rev_8.32"
        "\\4C530001220615116192&0",
        "{72b1e088-9f3c-4d56-aa1b-58e3201abf10}")
    # Verbatim — benign.
    add("Disk", "18A5", "0302", "0110", "07601A2E3F4B02C13D9E6101",
        "Verbatim STORE N GO USB Device",
        "2024-10-08 14:21:18", "2024-10-08 14:21:18",
        "2024-10-08 14:21:18", "2024-10-08 15:05:39",
        "a&5e9c021d&0",
        "USBSTOR\\Disk&Ven_Verbatim&Prod_STORE_N_GO&Rev_1.10"
        "\\07601A2E3F4B02C13D9E6101&0",
        "{e0a7c321-188d-4e0b-b6f2-9a83f1a67bd3}")
    # ---- Scenario-defining USB row ----
    add("Disk", SUSPECT_USB_VID, SUSPECT_USB_PID, SUSPECT_USB_REV,
        SUSPECT_USB_SERIAL, SUSPECT_USB_FRIENDLY,
        T_USB_INSTALL, T_USB_INSTALL, T_USB_INSTALL, T_USB_REMOVE,
        SUSPECT_PARENT_PREFIX, SUSPECT_DEVINST,
        SUSPECT_VOLUME_GUID)
    # Promotional USB CD-ROM — historical.
    add("CdRom", "058F", "A001", "0100", "058FA001CD0001",
        "USB CD-ROM Promotional Disk",
        "2024-07-22 09:14:00", "2024-07-22 09:14:00",
        "2024-07-22 09:14:00", "2024-07-22 09:39:42",
        "5&0c8a32fd&0",
        "USBSTOR\\CdRom&Ven_Generic&Prod_USB_CD-ROM&Rev_1.00"
        "\\058FA001CD0001&0",
        "{31ae6f02-8b1c-4d7f-90a9-fe2c1378ab44}")
    # Earlier *different* Kingston device — Aug. Same friendly name as
    # the suspect but completely different serial.
    add("Disk", "0951", "1666", "0100", "001A92038F1C4A1932B70B12",
        SUSPECT_USB_FRIENDLY,
        "2024-08-15 12:07:33", "2024-08-15 12:07:33",
        "2024-08-15 12:07:33", "2024-08-15 12:48:00",
        "6&7d3b91c0&0",
        "USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_1.00"
        "\\001A92038F1C4A1932B70B12&0",
        "{4d1ab8e2-9e0f-44c7-8a52-d0e93b7ff088}")

    # NOTE: order intentionally matches the committed file (chronology
    # of FirstConnected is non-monotonic). Don't sort.
    return rows


def generate_mountpoints(rng: random.Random) -> List[Dict[str, str]]:
    """``HKLM\\SYSTEM\\MountedDevices`` — volume GUID -> drive letter map.

    The two scenario-defining rows are the ``\\DosDevices\\E:`` binding
    that ties drive ``E:`` to the suspect Kingston volume at 16:42:14,
    and the matching ``\\??\\Volume{...}`` row that confirms the same
    volume GUID. Together they let an analyst go from "what was on E:"
    to "exactly which physical device was it."
    """
    rows: List[Dict[str, str]] = []

    def add(key, vname, vguid, drive, dev_type, linked, lwt, notes):
        rows.append({
            "KeyPath": key, "ValueName": vname, "VolumeGuid": vguid,
            "DriveLetter": drive, "DeviceType": dev_type,
            "LinkedDeviceInstanceId": linked,
            "LastWriteTime": ts(lwt) if lwt else "", "Notes": notes,
        })

    base = "HKLM\\System\\MountedDevices"

    add(base, "\\DosDevices\\C:",
        "{8a4c7e02-0000-0000-0000-100000000000}", "C:", "FixedDisk",
        "STORAGE\\Volume\\{8a4c7e02-0000-0000-0000-100000000000}",
        "2024-08-04 11:02:18.0000000", "System volume (NTFS)")
    add(base, "\\DosDevices\\D:",
        "{2f3a91b5-0000-0000-0000-501f00000000}", "D:", "FixedDisk",
        "STORAGE\\Volume\\{2f3a91b5-0000-0000-0000-501f00000000}",
        "2024-08-04 11:02:18.0000000", "Recovery partition")
    add(base, "\\??\\Volume{a83d2c11-6e7a-4f02-9c5a-0db3e6f51122}",
        "", "", "RemovableMedia",
        "USBSTOR\\Disk&Ven_Generic&Prod_Mass-Storage\\058F0O1111B1",
        "2024-08-19 13:08:42.0000000",
        "Generic mass-storage device — historical mount")
    add(base, "\\??\\Volume{c1f4a7d8-2b39-4e15-8a0c-7d9e44351e77}",
        "", "", "RemovableMedia",
        "USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0"
        "\\001A92038A1FAE6132B40A0F",
        "2024-10-21 09:47:30.0000000",
        "Earlier Kingston DataTraveler — different serial")
    add(base, "\\??\\Volume{72b1e088-9f3c-4d56-aa1b-58e3201abf10}",
        "", "", "RemovableMedia",
        "USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer_Glide"
        "\\4C530001220615116192",
        "2024-09-19 11:42:00.0000000",
        "SanDisk Cruzer Glide — historical mount")
    add(base, "\\??\\Volume{e0a7c321-188d-4e0b-b6f2-9a83f1a67bd3}",
        "", "", "RemovableMedia",
        "USBSTOR\\Disk&Ven_Verbatim&Prod_STORE_N_GO"
        "\\07601A2E3F4B02C13D9E6101",
        "2024-10-08 14:21:18.0000000",
        "Verbatim STORE N GO — historical mount")
    add(base, "\\??\\Volume{4d1ab8e2-9e0f-44c7-8a52-d0e93b7ff088}",
        "", "", "RemovableMedia",
        "USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0"
        "\\001A92038F1C4A1932B70B12",
        "2024-08-15 12:07:33.0000000",
        "Earlier Kingston DataTraveler — different serial")
    # ---- Scenario-defining mountpoint rows ----
    add(base, f"\\DosDevices\\{SUSPECT_DRIVE_LETTER}",
        SUSPECT_VOLUME_GUID, SUSPECT_DRIVE_LETTER, "RemovableMedia",
        f"USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0"
        f"\\{SUSPECT_USB_SERIAL}",
        f"{T_USB_DRIVE_BIND}.0000000",
        "Suspect volume — Kingston DataTraveler bound to E: at "
        "last connection")
    add(base, f"\\??\\Volume{SUSPECT_VOLUME_GUID}",
        "", "", "RemovableMedia",
        f"USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0"
        f"\\{SUSPECT_USB_SERIAL}",
        f"{T_USB_DRIVE_BIND}.0000000",
        "Same volume GUID as E: binding above — confirms identity")
    add(base, "\\??\\Volume{31ae6f02-8b1c-4d7f-90a9-fe2c1378ab44}",
        "", "", "CdRom",
        "USBSTOR\\CdRom&Ven_Generic&Prod_USB_CD-ROM\\058FA001CD0001",
        "2024-07-22 09:14:00.0000000",
        "Promotional USB CD-ROM — historical mount")
    # Mapped drive Z: from logon script — included so analysts can
    # see what a non-USB removable looks like in this view.
    add(base, "\\DosDevices\\Z:",
        "{1a2b3c4d-5e6f-4071-9081-aa11bb22cc33}", "Z:", "NetworkShare",
        "\\\\fileserver01.finance.example.com\\HRShare",
        "2024-09-12 08:14:55.0000000",
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


def generate_shellbags(rng: random.Random) -> List[Dict[str, str]]:
    """``UsrClass.dat`` shellbags for ``hr-user``.

    Includes the standard Desktop/MyComputer ancestors plus the
    incident-window navigation into ``E:\\HR\\Confidential\\Salary_Data``
    and ``E:\\HR\\Confidential\\Personnel``, the ``hp-hotkey`` folder
    under AppData (corroborates the persistence path), and the personal
    OneDrive ``HR_Backup`` folder (corroborates the sync database).
    """
    rows: List[Dict[str, str]] = []

    def add(bag, abs_path, shell_type, first, last, mru, slot):
        rows.append({
            "BagPath": bag, "AbsolutePath": abs_path,
            "ShellType": shell_type,
            "FirstInteracted": ts(first), "LastInteracted": ts(last),
            "MRUPosition": str(mru), "NodeSlot": str(slot),
        })

    # Baseline ancestors.
    add("Desktop", "Desktop", "Desktop",
        "2024-09-03 08:42:14", "2024-11-12 17:28:55", 0, 1)
    add("Desktop\\My Computer", "My Computer", "RootFolder",
        "2024-09-03 08:42:14", "2024-11-12 17:14:08", 0, 2)
    add("Desktop\\My Computer\\C:\\", "C:\\", "Drive",
        "2024-09-03 08:42:14", "2024-11-12 16:38:01", 1, 3)
    add("Desktop\\My Computer\\C:\\Users\\hr-user\\Documents",
        "C:\\Users\\hr-user\\Documents", "Directory",
        "2024-09-03 08:42:14", "2024-11-12 14:18:33", 2, 8)
    add("Desktop\\My Computer\\C:\\Users\\hr-user\\Documents\\HR_Records",
        "C:\\Users\\hr-user\\Documents\\HR_Records", "Directory",
        "2024-09-19 10:14:00", "2024-11-12 14:18:33", 3, 9)
    add("Desktop\\My Computer\\C:\\Users\\hr-user\\Downloads",
        "C:\\Users\\hr-user\\Downloads", "Directory",
        "2024-09-03 08:42:14", "2024-11-08 19:05:18", 4, 10)
    # Persistence corroboration — hr-user opened the folder in Explorer.
    add("Desktop\\My Computer\\C:\\Users\\hr-user\\AppData\\Local\\hp-hotkey",
        "C:\\Users\\hr-user\\AppData\\Local\\hp-hotkey", "Directory",
        "2024-11-08 19:06:08", "2024-11-08 19:06:51", 12, 21)
    # Corporate OneDrive — normal pre-incident activity.
    add("Desktop\\My Computer\\C:\\Users\\hr-user\\OneDrive - FINANCE",
        "C:\\Users\\hr-user\\OneDrive - FINANCE", "Directory",
        "2024-09-04 09:11:42", "2024-11-12 11:42:00", 5, 11)
    add("Desktop\\My Computer\\C:\\Users\\hr-user\\OneDrive - FINANCE"
        "\\HR Documents",
        "C:\\Users\\hr-user\\OneDrive - FINANCE\\HR Documents",
        "Directory",
        "2024-09-12 13:18:00", "2024-11-12 11:42:00", 6, 12)
    # Personal OneDrive — created during the incident window.
    add("Desktop\\My Computer\\C:\\Users\\hr-user\\OneDrive - Personal",
        "C:\\Users\\hr-user\\OneDrive - Personal", "Directory",
        "2024-11-12 16:51:33", "2024-11-12 17:10:42", 7, 18)
    add("Desktop\\My Computer\\C:\\Users\\hr-user\\OneDrive - Personal"
        "\\HR_Backup",
        "C:\\Users\\hr-user\\OneDrive - Personal\\HR_Backup",
        "Directory",
        "2024-11-12 16:54:05", "2024-11-12 17:10:42", 8, 19)
    # ---- Scenario-defining E: drive shellbags ----
    add("Desktop\\My Computer\\E:\\", "E:\\", "Drive",
        "2024-11-12 16:42:55", "2024-11-12 17:30:41", 9, 14)
    add("Desktop\\My Computer\\E:\\HR", "E:\\HR", "Directory",
        "2024-11-12 16:43:02", "2024-11-12 17:30:41", 10, 15)
    add("Desktop\\My Computer\\E:\\HR\\Confidential",
        "E:\\HR\\Confidential", "Directory",
        "2024-11-12 16:43:11", "2024-11-12 17:28:09", 11, 16)
    add("Desktop\\My Computer\\E:\\HR\\Confidential\\Salary_Data",
        "E:\\HR\\Confidential\\Salary_Data", "Directory",
        "2024-11-12 16:44:02", "2024-11-12 17:08:55", 12, 17)
    add("Desktop\\My Computer\\E:\\HR\\Confidential\\Personnel",
        "E:\\HR\\Confidential\\Personnel", "Directory",
        "2024-11-12 16:46:14", "2024-11-12 17:02:18", 13, 20)
    # Recent Places — bookends the user's shell navigation.
    add("Desktop\\Recent Places", "Recent Places", "RootFolder",
        "2024-09-03 08:42:14", "2024-11-12 17:09:50", 0, 4)
    add("Desktop\\My Computer\\C:\\Users\\hr-user\\AppData\\Roaming"
        "\\Microsoft\\Windows\\Recent",
        "C:\\Users\\hr-user\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
        "Directory",
        "2024-09-03 08:42:14", "2024-11-12 17:09:50", 15, 5)
    return rows


def generate_onedrive_accounts(rng: random.Random) -> List[Dict[str, str]]:
    """Two-row OneDrive accounts table.

    Row 1: corporate (Business1) — long-lived, configured 2024-09-04.
    Row 2: personal (Personal) — configured at 2024-11-12 16:51:33 UTC,
    inside the incident window. The presence of *two* accounts on an HR
    laptop, with one being a consumer ``@outlook.com`` mailbox, is the
    finding.
    """
    rows: List[Dict[str, str]] = []

    def add(acct_id, email, endpoint, folder, cid, oneauth, tenants, lwt):
        rows.append({
            "AccountId": acct_id, "Email": email,
            "ServiceEndpointUri": endpoint, "UserFolder": folder,
            "UserCid": cid, "OneAuthAccountId": oneauth,
            "ConfiguredTenantsClient": tenants,
            "LastWriteTime": ts(lwt) if lwt else "",
        })

    add("Business1", BUSINESS_ONEDRIVE_EMAIL,
        "https://finance-my.sharepoint.com/personal/"
        "hr-user_finance_example_com/",
        f"C:\\Users\\{USER}\\OneDrive - FINANCE",
        BUSINESS_CID,
        "b27a3e9f-1d0c-4b88-a4c1-3e8f1a209d44",
        "18b3d2c0-7a4e-49ea-9c16-2f3b88a14e02",
        "2024-09-04 09:11:42.0000000")
    add("Personal", PERSONAL_ONEDRIVE_EMAIL,
        f"https://d.docs.live.net/{PERSONAL_CID}/",
        f"C:\\Users\\{USER}\\OneDrive - Personal",
        PERSONAL_CID,
        "e9f48a21-6c33-4b07-9a62-5d12f0e4a3b1",
        "",
        "2024-11-12 16:51:33.0000000")
    return rows


def generate_onedrive_syncdb(rng: random.Random) -> List[Dict[str, str]]:
    """Personal OneDrive ``<UserCid>SyncEngineDatabase.db`` rows.

    Eight files, all HR-confidential, all entering the sync queue
    between 16:55:18 and 17:09:47 UTC on 2024-11-12. The pattern —
    small filename set, all under the new ``HR_Backup`` folder, all
    ``Synchronized`` state — is what bridges from "USB navigation" to
    "data left the corporate boundary."

    Schema note: this lab's syncdb uses ``ItemId / ItemPath /
    ParentResourceId / FileName / Size / ContentHash / LastChange /
    LastSync / SyncState``. The ``HR-WS17`` lab uses a different schema;
    do not normalize across labs (see ``Data/HR-WS17/README.md``).
    """
    rows: List[Dict[str, str]] = []
    base = f"C:\\Users\\{USER}\\OneDrive - Personal\\HR_Backup"
    parent_resource = f"{PERSONAL_CID}!1024"

    def add(item_id_suffix, name, size, content_hash, change, sync):
        rows.append({
            "ItemId": f"01J7K2A8B9C0D1E2F3G4{item_id_suffix}",
            "ItemPath": f"{base}\\{name}",
            "ParentResourceId": parent_resource,
            "FileName": name, "Size": str(size),
            "ContentHash": content_hash,
            "LastChange": ts(change), "LastSync": ts(sync),
            "SyncState": "Synchronized",
        })

    # Eight rows; identifiers/hashes hand-coded so the file is stable.
    # Each LastSync is 20-30 seconds after LastChange — matches the
    # OneDrive client's typical upload cadence on a residential link.
    add("H5", "Q4_Salary_Review.xlsx", 1842117,
        "3F9A1C7B204E88D6E1F0AB23C4D5E6F7A8B9C0D1",
        "2024-11-12 16:55:18", "2024-11-12 16:55:42")
    add("H6", "Personnel_Roster.xlsx", 742068,
        "B81C0FA2D34E7591A0B6C5D4E3F2A1B0C9D8E7F6",
        "2024-11-12 16:57:22", "2024-11-12 16:57:51")
    add("H7", "Compensation_Bands_2024.xlsx", 318422,
        "7C2B0DE19F4A88216351F0A7B8C9D0E1F2A3B4C5",
        "2024-11-12 17:00:14", "2024-11-12 17:00:38")
    add("H8", "Severance_Calc_Q4.xlsx", 184501,
        "42E1A3B07C9D6F801023AABBCCDD11FF22334455",
        "2024-11-12 17:02:09", "2024-11-12 17:02:31")
    add("H9", "Disciplinary_Cases_2024.docx", 98244,
        "A0B1C2D3E4F5061728394A5B6C7D8E9F00112233",
        "2024-11-12 17:04:18", "2024-11-12 17:04:39")
    add("HA", "Org_Chart_Confidential.pdf", 2104822,
        "5544332211FFEEDDCCBBAA9988776655443322B1",
        "2024-11-12 17:06:42", "2024-11-12 17:07:08")
    add("HB", "Bonus_Pool_FY25_Draft.xlsx", 612488,
        "11FFEEDDCCBBAA00112233445566778899AABBCC",
        "2024-11-12 17:08:11", "2024-11-12 17:08:34")
    add("HC", "Exit_Interviews_2024.docx", 221080,
        "9988776655443322110011223344556677889900",
        "2024-11-12 17:09:47", "2024-11-12 17:10:12")
    return rows


# ---------------------------------------------------------------------------
# setupapi-dev-log.txt — not a CSV but reproduced from the same
# narrative. Two sections: USB device install (16:42:08-09) and the
# volume-mount Section that binds the new volume to drive E: at
# 16:42:13-14. Generated as a list of lines so the dispatch table
# below can treat it like any other output target.
# ---------------------------------------------------------------------------

def generate_setupapi_dev_log(rng: random.Random) -> List[str]:
    """Plaintext extract from ``%SystemRoot%\\INF\\setupapi.dev.log``.

    Reproduces the two sections that record the suspect Kingston install
    and its subsequent ``\\DosDevices\\E:`` binding. Times in the body
    match ``T_USB_INSTALL`` and ``T_USB_DRIVE_BIND``.
    """
    lines: List[str] = [
        "[Device Install Log]",
        "     OS Version = 10.0.19045",
        "     Service Pack = 0.0",
        "     Suite = 0x0100",
        "     ProductType = 1",
        "     Architecture = amd64",
        "",
        "[BeginLog]",
        "",
        # Boot time agrees with System EID 6013 at 09:12:38 (uptime
        # 25718 s -> booted 02:03:59.882, after the 02:00 Windows Update
        # start). Keep the two in step.
        "[Boot Session: 2024/11/12 02:03:59.882]",
        "",
        f">>>  [Setup online Device Install (Hardware initiated) - "
        f"USB\\VID_{SUSPECT_USB_VID}&PID_{SUSPECT_USB_PID}"
        f"\\{SUSPECT_USB_SERIAL}]",
        ">>>  Section start 2024/11/12 16:42:08.421",
        "     ump: Creating Install Process: DrvInst.exe 16:42:08.428",
        "     ndv: Retrieving device info...",
        "     ndv: Setting device parameters...",
        "     ndv: Searching Driver Store and Device Path...",
        "     dvi: {Build Driver List} 16:42:08.510",
        "     dvi:      Searching for hardware ID(s):",
        f"     dvi:           usb\\vid_{SUSPECT_USB_VID}"
        f"&pid_{SUSPECT_USB_PID}&rev_{SUSPECT_USB_REV}",
        f"     dvi:           usb\\vid_{SUSPECT_USB_VID}"
        f"&pid_{SUSPECT_USB_PID}",
        "     dvi:      Searching for compatible ID(s):",
        "     dvi:           usb\\class_08&subclass_06&prot_50",
        "     dvi:           usb\\class_08&subclass_06",
        "     dvi:           usb\\class_08",
        "     dvi: {Build Driver List - exit(0x00000000)} 16:42:08.612",
        "     dvi: {DIF_SELECTBESTCOMPATDRV} 16:42:08.614",
        "     dvi:      Class GUID of device changed to: "
        "{36fc9e60-c465-11cf-8056-444553540000}.",
        "     dvi:      Selected driver installs from section "
        "[USBSTOR_BULK.NT] in 'usbstor.inf'.",
        "     dvi:      Selected: usbstor.inf_amd64_5d40123abc781ee9"
        "\\usbstor.inf",
        "     dvi:      Description - [USB Mass Storage Device]",
        "     dvi:      Manufacturer - [Compatible USB storage device]",
        "     dvi:      Provider     - [Microsoft]",
        "     dvi:      Mfg Rank     - 0x00000000, Type Rank - 0x00ff2000",
        "     dvi: {DIF_SELECTBESTCOMPATDRV - exit(0x00000000)} "
        "16:42:08.701",
        "     ndv: Driver selection complete.",
        "     ndv: {Core Device Install} 16:42:08.812",
        "     dvi: Set selected driver complete.",
        f"     dvi: {{Plug and Play Service: Device Install for "
        f"USB\\VID_{SUSPECT_USB_VID}&PID_{SUSPECT_USB_PID}"
        f"\\{SUSPECT_USB_SERIAL}}}",
        "     ndv:      Driver INF Path:    C:\\Windows\\INF"
        "\\usbstor.inf",
        "     ndv:      Driver Node Name:   usbstor.inf:"
        "Generic.Mfg.NTamd64:USBSTOR_BULK.NT:10.0.19041.1:"
        "USB\\Class_08&SubClass_06&Prot_50",
        "     dvi:      Class GUID:         "
        "{36fc9e60-c465-11cf-8056-444553540000}",
        "     dvi:      Class Name:         USB",
        "     dvi:      Driver Date:        06/21/2006",
        "     dvi:      Driver Version:     10.0.19041.1",
        "     dvi:      Driver Provider:    Microsoft",
        "     dvi: Searching for hardware ID(s):",
        f"     dvi:      usb\\vid_{SUSPECT_USB_VID}&pid_{SUSPECT_USB_PID}"
        f"&rev_{SUSPECT_USB_REV}",
        f"     dvi:      usb\\vid_{SUSPECT_USB_VID}"
        f"&pid_{SUSPECT_USB_PID}",
        f"     dvi: {{Install Device - "
        f"USB\\VID_{SUSPECT_USB_VID}&PID_{SUSPECT_USB_PID}"
        f"\\{SUSPECT_USB_SERIAL}}} 16:42:09.014",
        "     dvi:      Parent device: USB\\ROOT_HUB30\\4&1eaf73b9&0&0",
        f"     dvi:      Friendly name: {SUSPECT_USB_FRIENDLY}",
        f"     dvi:      Serial number: {SUSPECT_USB_SERIAL}",
        "     ndv: Installing files...",
        "     dvi: Class installer: Enter 16:42:09.118",
        "     dvi: Class installer: Exit",
        "     dvi: Default installer: Enter 16:42:09.224",
        "     dvi: Default installer: Exit",
        "     ndv: {Core Device Install - exit(0x00000000)} 16:42:09.612",
        "<<<  Section end 2024/11/12 16:42:09.812",
        "<<<  [Exit status: SUCCESS]",
        "",
        f">>>  [Setup online Device Install (Hardware initiated) - "
        f"STORAGE\\Volume\\{SUSPECT_VOLUME_GUID}]",
        ">>>  Section start 2024/11/12 16:42:13.708",
        f"     dvi: Volume mount point assigned: "
        f"\\DosDevices\\{SUSPECT_DRIVE_LETTER}",
        f"     dvi: VolumeGuid: {SUSPECT_VOLUME_GUID}",
        f"     dvi: Friendly Name: Removable Disk "
        f"({SUSPECT_DRIVE_LETTER})",
        "     dvi: Class GUID: {71a27cdd-812a-11d0-bec7-08002be2092f}",
        # NTFS, not exFAT: System EID 98 for E: comes from the
        # Microsoft-Windows-Ntfs provider, which only reports NTFS volumes.
        "     dvi: Filesystem detected: NTFS",
        "<<<  Section end 2024/11/12 16:42:14.221",
        "<<<  [Exit status: SUCCESS]",
    ]
    return lines


# ---------------------------------------------------------------------------
# Security event log
# ---------------------------------------------------------------------------

def generate_security_evtx(rng: random.Random) -> List[Dict[str, str]]:
    """EvtxECmd-style export of ``Security.evtx``.

    Lab 05 is a registry-and-cloud lab, so this log exists to let the
    responder *corroborate* registry findings against process and logon
    activity — not to hand them the answer. Three things are deliberate:

    * The ``reg.exe add`` at 19:06:42 on 2024-11-08 carries the exact same
      value name, data and second as the ``HpHotkeyMonitor`` row in
      ``registry-runkeys.csv``. That is the intended cross-check.
    * ``hpkey.exe`` **never appears as a 4688** — not at the 11-11 logon,
      not at the 11-12 logon, not anywhere. The Run value exists; there is
      no execution evidence for it in this log. Lab 5.2 Task 6 ("strong
      findings vs overclaims") depends on that absence, so do not add one.
    * The USB events (4688 for ``drvinst.exe``, 6416 for the new external
      device) land on the same second as the USBSTOR install time, giving
      an independent second source for the device timeline.
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
    edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    outlook = ("C:\\Program Files\\Microsoft Office\\root\\Office16\\"
               "OUTLOOK.EXE")
    onedrive = (f"C:\\Users\\{USER}\\AppData\\Local\\Microsoft\\OneDrive\\"
                "OneDrive.exe")

    # --- 2024-11-08: the evening the Run value was written ---------------
    add(2841002, "2024-11-08 08:41:18.4218421", 4624, "SYSTEM",
        "Successful logon",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=2 "
        f"LogonProcessName=User32 ProcessName={sys32}\\winlogon.exe "
        f"IpAddress=127.0.0.1 WorkstationName={HOSTNAME}")
    add(2841003, "2024-11-08 08:41:18.5012834", 4672, USER,
        "Special privileges assigned",
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        "PrivilegeList=SeShutdownPrivilege SeUndockPrivilege "
        "SeIncreaseWorkingSetPrivilege SeTimeZonePrivilege")
    add(2841004, "2024-11-08 08:41:22.1224821", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\Explorer.EXE ProcessId=0x1A2C "
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        f"ParentProcessName={sys32}\\userinit.exe "
        "TokenElevationType=%%1936 CommandLine=C:\\Windows\\Explorer.EXE")
    add(2841118, "2024-11-08 18:52:14.0124211", 4688, USER,
        "Process created",
        f"NewProcessName={edge} ProcessId=0x2F14 "
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        f'TokenElevationType=%%1938 CommandLine="{edge}"')
    add(2841142, "2024-11-08 19:06:22.4218921", 4688, USER,
        "Process created",
        f"NewProcessName={ps_exe} ProcessId=0x3184 "
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        'TokenElevationType=%%1938 CommandLine="powershell.exe" '
        "-ExecutionPolicy Bypass -WindowStyle Hidden -File "
        f"C:\\Users\\{USER}\\Downloads\\hp_hotkey_fix.ps1")
    add(2841143, "2024-11-08 19:06:24.0124581", 4688, USER,
        "Process created",
        f"NewProcessName={sys32}\\conhost.exe ProcessId=0x3188 "
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        f"ParentProcessName={ps_exe} TokenElevationType=%%1938 "
        "CommandLine=\\??\\C:\\WINDOWS\\system32\\conhost.exe "
        "0xffffffff -ForceV1")
    add(2841144, "2024-11-08 19:06:42.0000000", 4688, USER,
        "Process created",
        f"NewProcessName={sys32}\\reg.exe ProcessId=0x31A4 "
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        f"ParentProcessName={ps_exe} TokenElevationType=%%1938 "
        'CommandLine=reg add "HKCU\\Software\\Microsoft\\Windows\\'
        'CurrentVersion\\Run" /v ' + PERSIST_VALUE_NAME +
        f' /t REG_SZ /d "{PERSIST_VALUE_DATA}" /f')
    add(2841145, "2024-11-08 19:06:42.5000000", 4657, USER,
        "Registry value modified",
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        "ObjectName=\\REGISTRY\\USER\\" + USER_SID +
        "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
        f"ObjectValueName={PERSIST_VALUE_NAME} OperationType=%%1905 "
        f"NewValue={PERSIST_VALUE_DATA} NewValueType=%%1873 "
        f"ProcessName={sys32}\\reg.exe")
    add(2841152, "2024-11-08 19:14:08.0000000", 4634, "SYSTEM", "Logoff",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=2")

    # --- 2024-11-11: an ordinary day. Note what is NOT here. -------------
    add(2841418, "2024-11-11 08:42:04.4218421", 4624, "SYSTEM",
        "Successful logon",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=2 "
        f"LogonProcessName=User32 ProcessName={sys32}\\winlogon.exe "
        f"IpAddress=127.0.0.1 WorkstationName={HOSTNAME}")
    add(2841419, "2024-11-11 08:42:08.1224821", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\Explorer.EXE ProcessId=0x1B44 "
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        f"ParentProcessName={sys32}\\userinit.exe "
        "TokenElevationType=%%1936 CommandLine=C:\\Windows\\Explorer.EXE")
    add(2841420, "2024-11-11 08:42:11.0000000", 4688, USER,
        "Process created",
        f"NewProcessName={onedrive} ProcessId=0x1B88 "
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        f'TokenElevationType=%%1938 CommandLine="{onedrive}" /background')
    add(2841488, "2024-11-11 17:22:41.0000000", 4634, "SYSTEM", "Logoff",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=2")

    # --- 2024-11-12: the incident day ------------------------------------
    add(2841902, "2024-11-12 03:00:11.0000000", 4688, "SYSTEM",
        "Process created",
        f"NewProcessName={sys32}\\svchost.exe ProcessId=0x12C8 "
        f"SubjectUserName={HOSTNAME}$ SubjectDomainName={DOMAIN} "
        f"ParentProcessName={sys32}\\services.exe "
        f"CommandLine={sys32}\\svchost.exe -k netsvcs -p")
    add(2841914, "2024-11-12 09:12:44.4218421", 4624, "SYSTEM",
        "Successful logon",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=2 "
        f"LogonProcessName=User32 ProcessName={sys32}\\winlogon.exe "
        f"IpAddress=127.0.0.1 WorkstationName={HOSTNAME}")
    add(2841915, "2024-11-12 09:12:44.5012834", 4672, USER,
        "Special privileges assigned",
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        "PrivilegeList=SeShutdownPrivilege SeUndockPrivilege "
        "SeIncreaseWorkingSetPrivilege SeTimeZonePrivilege")
    add(2841916, "2024-11-12 09:13:02.1224821", 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\Explorer.EXE ProcessId=0x1C08 "
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        f"ParentProcessName={sys32}\\userinit.exe "
        "TokenElevationType=%%1936 CommandLine=C:\\Windows\\Explorer.EXE")
    add(2841918, "2024-11-12 09:14:00.0000000", 4688, USER,
        "Process created",
        f"NewProcessName={outlook} ProcessId=0x2148 "
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        f'TokenElevationType=%%1938 CommandLine="{outlook}"')
    add(2841919, "2024-11-12 09:14:33.0000000", 4688, USER,
        "Process created",
        f"NewProcessName={edge} ProcessId=0x2214 "
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        f'TokenElevationType=%%1938 CommandLine="{edge}"')
    # USB attach — same second as the USBSTOR install record, and just
    # after setupapi's "Creating Install Process: DrvInst.exe 16:42:08.428".
    add(2842108, ts(T_USB_INSTALL, ".4284821"), 4688, "SYSTEM",
        "Process created",
        f"NewProcessName={sys32}\\drvinst.exe ProcessId=0x4844 "
        f"SubjectUserName={HOSTNAME}$ SubjectDomainName={DOMAIN} "
        f"ParentProcessName={sys32}\\svchost.exe "
        'TokenElevationType=%%1936 CommandLine=DrvInst.exe "8" "201" '
        f'"{SUSPECT_DEVICE_PATH}"')
    add(2842109, ts(T_USB_INSTALL, ".8421042"), 6416, USER,
        "A new external device was recognized by the system",
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        f"SubjectUserSid={USER_SID} ClassName=DiskDrive "
        "ClassId={4d36e967-e325-11ce-bfc1-08002be10318} "
        f"DeviceId={SUSPECT_DEVICE_PATH} "
        f"DeviceDescription={SUSPECT_USB_FRIENDLY}")
    add(2842112, ts(T_USB_DRIVE_BIND), 4688, USER,
        "Process created",
        "NewProcessName=C:\\Windows\\Explorer.EXE ProcessId=0x4880 "
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        f"ParentProcessName={sys32}\\userinit.exe "
        "TokenElevationType=%%1938 CommandLine=C:\\Windows\\Explorer.EXE "
        "/factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b}")
    # Personal OneDrive sign-in — matches the Personal account's
    # LastWriteTime in onedrive-accounts.csv to the second.
    add(2842144, "2024-11-12 16:51:33.0000000", 4688, USER,
        "Process created",
        f"NewProcessName={onedrive} ProcessId=0x5128 "
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        f'TokenElevationType=%%1938 CommandLine="{onedrive}" /background')
    add(2842146, "2024-11-12 16:52:04.0000000", 4688, USER,
        "Process created",
        f"NewProcessName={edge} ProcessId=0x5184 "
        f"SubjectUserName={USER} SubjectDomainName={DOMAIN} "
        "ParentProcessName=C:\\Windows\\Explorer.EXE "
        f'TokenElevationType=%%1938 CommandLine="{edge}" --new-window '
        "https://login.live.com/")
    add(2842211, ts(T_USB_REMOVE), 4688, "SYSTEM",
        "Process created",
        f"NewProcessName={sys32}\\dllhost.exe ProcessId=0x5882 "
        f"SubjectUserName={HOSTNAME}$ SubjectDomainName={DOMAIN} "
        f"ParentProcessName={sys32}\\svchost.exe "
        f"CommandLine={sys32}\\dllhost.exe "
        "/Processid:{3EB3C877-1F16-487C-9050-104DBCD66683}")
    add(2842284, "2024-11-12 17:42:18.4218421", 4634, "SYSTEM", "Logoff",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=2")

    # --- Background noise -------------------------------------------------
    add(2841882, "2024-11-12 02:14:08.4218421", 4625, "SYSTEM",
        "Failed logon",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=3 "
        "IpAddress=10.0.4.42 FailureReason=%%2313 Status=0xC000006D "
        "SubStatus=0xC000006A WorkstationName=BACKUP-SCHED")
    add(2841884, "2024-11-12 02:14:14.0000000", 4624, "SYSTEM",
        "Successful logon",
        f"TargetUserName=svc-backup TargetDomainName={DOMAIN} LogonType=3 "
        "LogonProcessName=Kerberos ProcessName=- IpAddress=10.0.4.42 "
        "WorkstationName=BACKUP-SCHED")
    add(2841886, "2024-11-12 02:14:48.0000000", 4634, "SYSTEM", "Logoff",
        "TargetUserName=svc-backup LogonType=3")
    add(2841888, "2024-11-12 03:00:02.0000000", 4624, "SYSTEM",
        "Successful logon",
        "TargetUserName=SYSTEM TargetDomainName=NT AUTHORITY LogonType=5 "
        f"LogonProcessName=Advapi ProcessName={sys32}\\services.exe "
        "IpAddress=- ElevatedToken=Yes")
    add(2841912, "2024-11-12 09:12:44.2000000", 4624, "SYSTEM",
        "Successful logon",
        "TargetUserName=DWM-1 TargetDomainName=Window Manager LogonType=2 "
        f"LogonProcessName=Advapi ProcessName={sys32}\\winlogon.exe")
    add(2842102, "2024-11-12 14:00:14.0000000", 4624, "SYSTEM",
        "Successful logon",
        f"TargetUserName={USER} TargetDomainName={DOMAIN} LogonType=11 "
        f"LogonProcessName=NtLmSsp IpAddress=- WorkstationName={HOSTNAME} "
        "(cached credentials — laptop off the corporate network)")
    rows.sort(key=lambda r: (r["TimeCreated"], int(r["RecordNumber"])))
    return rows


# ---------------------------------------------------------------------------
# System event log
# ---------------------------------------------------------------------------

def generate_system_evtx(rng: random.Random) -> List[Dict[str, str]]:
    """EvtxECmd-style export of ``System.evtx``.

    The point of this file for Lab 05 is the PnP trail: EID 20001
    (``Microsoft-Windows-UserPnp``, "driver installation completed") and
    EID 219 (``Microsoft-Windows-Kernel-PnP``, "driver loaded") give a
    second, independent witness to the Kingston install that
    ``setupapi-dev-log.txt`` and ``usbstor.csv`` already describe. Three
    sources agreeing on 16:42:08-16:42:14 is the kind of corroboration the
    chapter asks for before calling a device timeline confirmed.
    """
    _ = rng
    rows: List[Dict[str, str]] = []

    def add(rec, t, eid, provider, desc, payload):
        rows.append({
            "RecordNumber": str(rec), "TimeCreated": ts(t),
            "EventID": str(eid), "Channel": "System",
            "Provider": provider, "Computer": FQDN,
            "Level": "Information",
            "Description": desc, "Payload": payload,
        })

    scm = "Service Control Manager"
    pnp = "Microsoft-Windows-Kernel-PnP"
    upnp = "Microsoft-Windows-UserPnp"

    # --- 2024-11-08 (persistence evening) --------------------------------
    add(184108, "2024-11-08 08:41:02.0000000", 6005, "EventLog",
        "Event log service started",
        "The Event log service was started.")
    add(184112, "2024-11-08 19:06:18.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=Windows Error Reporting Service State=Running")
    # The restart is requested before hr-user's 19:14:08 logoff (4634),
    # which it causes.
    add(184118, "2024-11-08 19:14:02.0000000", 1074, "User32",
        "System shutdown initiated",
        f"Process C:\\Windows\\System32\\shutdown.exe ({HOSTNAME}) has "
        f"initiated the restart of computer {HOSTNAME} on behalf of user "
        f"{DOMAIN}\\{USER} Reason=Other (Unplanned) ShutdownType=restart")

    # --- 2024-11-12 (incident day) ---------------------------------------
    add(184402, "2024-11-12 02:00:00.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=Windows Update State=Running")
    add(184404, "2024-11-12 02:14:11.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=Volume Shadow Copy State=Running")
    add(184406, "2024-11-12 02:48:00.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=Volume Shadow Copy State=Stopped")
    add(184408, "2024-11-12 03:00:11.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=Background Intelligent Transfer Service State=Running")
    add(184412, "2024-11-12 09:12:38.0000000", 6013, "EventLog",
        "System uptime",
        "The system uptime is 25718 seconds.")
    add(184414, "2024-11-12 09:12:44.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=User Profile Service State=Running")
    add(184418, "2024-11-12 12:04:22.0000000", 7040, scm,
        "Service start type changed",
        "ServiceName=Windows Update StartType changed from demand start "
        "to auto start")

    # --- The Kingston insertion: three System-log witnesses ---------------
    add(184502, "2024-11-12 16:42:08.0000000", 219, pnp,
        "Driver loaded for device",
        f"DeviceInstanceId={SUSPECT_DEVICE_PATH} "
        "DriverName=usbstor.inf ClassGuid="
        "{36fc9e60-c465-11cf-8056-444553540000} Status=0x0")
    add(184503, "2024-11-12 16:42:09.0000000", 20001, upnp,
        "Driver installation completed",
        "Driver Management concluded the process to install driver "
        "disk.inf_amd64_9c3f7b2a1d04e881\\disk.inf for Device Instance ID "
        f"{SUSPECT_DEVICE_PATH} with the following status: 0x0.")
    add(184504, "2024-11-12 16:42:10.0000000", 20003, upnp,
        "Service installation for device completed",
        "Driver Management has concluded the process to add Service "
        f"disk for Device Instance ID {SUSPECT_DEVICE_PATH} with the "
        "following status: 0x0.")
    add(184506, ts(T_USB_DRIVE_BIND), 98, "Microsoft-Windows-Ntfs",
        "Volume is healthy",
        f"Volume {SUSPECT_VOLUME_GUID} ({SUSPECT_DRIVE_LETTER}) is "
        "healthy. No action is needed.")
    add(184508, "2024-11-12 16:42:16.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=Portable Device Enumerator Service State=Running")
    # EID 225 renders the PID in decimal: 18560 is the 0x4880 Explorer
    # that security-evtx.csv records starting at 16:42:14.
    add(184540, ts(T_USB_REMOVE), 225, pnp,
        "Device removal request",
        "The application \\Device\\HarddiskVolume3\\Windows\\explorer.exe "
        f"with process id 18560 stopped the removal or ejection for the "
        f"device {SUSPECT_DEVICE_PATH}.")
    add(184541, "2024-11-12 17:31:04.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=Portable Device Enumerator Service State=Stopped")

    # --- End of day -------------------------------------------------------
    add(184580, "2024-11-12 17:42:22.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=User Profile Service State=Stopped")
    add(184582, "2024-11-12 17:42:41.0000000", 6006, "EventLog",
        "Event log service stopped",
        "The Event log service was stopped.")
    add(184584, "2024-11-13 07:02:18.0000000", 6005, "EventLog",
        "Event log service started",
        "The Event log service was started.")
    add(184586, "2024-11-13 07:02:20.0000000", 6013, "EventLog",
        "System uptime", "The system uptime is 8 seconds.")
    add(184588, "2024-11-13 07:04:11.0000000", 7036, scm,
        "Service state changed",
        "ServiceName=Windows Defender Antivirus Service State=Running")
    rows.sort(key=lambda r: (r["TimeCreated"], int(r["RecordNumber"])))
    return rows


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

# CSV generators (each returns a list of dict rows keyed by the headers
# above).
GENERATORS: Dict[str, Callable[[random.Random], List[Dict[str, str]]]] = {
    "registry-runkeys.csv": generate_registry_runkeys,
    "registry-services.csv": generate_registry_services,
    "usbstor.csv": generate_usbstor,
    "mountpoints.csv": generate_mountpoints,
    "shellbags.csv": generate_shellbags,
    "onedrive-accounts.csv": generate_onedrive_accounts,
    "onedrive-syncdb.csv": generate_onedrive_syncdb,
    "security-evtx.csv": generate_security_evtx,
    "system-evtx.csv": generate_system_evtx,
}

# Plain-text generators (return a list of lines, no header).
TEXT_GENERATORS: Dict[str, Callable[[random.Random], List[str]]] = {
    "setupapi-dev-log.txt": generate_setupapi_dev_log,
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def write_csv(path: Path, fields: List[str],
              rows: List[Dict[str, str]]) -> None:
    """Write a CSV with LF line endings and QUOTE_MINIMAL quoting (matches
    the committed files on disk)."""
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields,
                                quoting=csv.QUOTE_MINIMAL,
                                lineterminator="\n",
                                extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({f: row.get(f, "") for f in fields})


def write_text(path: Path, lines: List[str]) -> None:
    """Write a plain-text file with LF line endings and a trailing newline."""
    with path.open("w", encoding="utf-8", newline="") as fh:
        fh.write("\n".join(lines))
        fh.write("\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate the HR-LT12 simulated dataset.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be written; do not "
                             "touch files.")
    parser.add_argument("--out-dir", default=".",
                        help="Directory to write files into "
                             "(default: cwd).")
    parser.add_argument("--seed", type=lambda x: int(x, 0),
                        default=RANDOM_SEED,
                        help="Override the random seed.")
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir).resolve()

    print(f"HR-LT12 generator — seed=0x{args.seed:X}")
    print(f"Output directory: {out_dir}")
    if args.dry_run:
        print("Mode: --dry-run (no files written)")
    print()

    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    # CSV outputs.
    for filename, generator in GENERATORS.items():
        # Reseed per-file so adding/removing a generator does not
        # disturb the other files' output streams. Same pattern as the
        # WKSTN-221 script.
        local_rng = random.Random(stable_seed(args.seed, filename))
        rows = generator(local_rng)
        fields = HEADERS[filename]
        target = out_dir / filename
        print(f"  {filename:<32} -> {len(rows):>4} rows "
              f"({len(fields)} columns)")
        if not args.dry_run:
            write_csv(target, fields, rows)

    # Text outputs.
    for filename, text_gen in TEXT_GENERATORS.items():
        local_rng = random.Random(stable_seed(args.seed, filename))
        lines = text_gen(local_rng)
        target = out_dir / filename
        print(f"  {filename:<32} -> {len(lines):>4} lines (text)")
        if not args.dry_run:
            write_text(target, lines)

    if args.dry_run:
        print("\nDry run complete. Re-run without --dry-run to write files.")
    else:
        print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
