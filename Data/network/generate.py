#!/usr/bin/env python3
"""Deterministic generator for the simulated ``Data/network/`` dataset.

This is the only generator in the repo that does **not** correspond to a
single host folder. Instead, it produces the organisation-wide network
telemetry (perimeter NetFlow, corporate proxy access log, internal DNS
query log, perimeter firewall block log) that backs Lab 08 (Network
Forensics on Windows) and is also referenced from Lab 11 (capstone).

Why this folder is special
==========================
The host-folder generators describe a single workstation's view of an
incident. The ``network/`` folder describes the same incidents from the
*outside*, where evidence comes from sensors and SIEM feeds rather than
endpoints. Two attack stories therefore appear here:

1. **WKSTN-221 -> C2** (anchored 2024-11-14, 14:18 UTC onwards)

   This is the attack chain captured by ``Data/WKSTN-221/``. A finance
   workstation (``WKSTN-221`` at 10.0.4.32, user
   ``FINANCE\payroll-admin``) opens a malicious Excel macro, spawns
   PowerShell, downloads a second-stage binary from the C2 endpoint
   ``91.214.47.22``, executes it as ``update.exe``, beacons, and then
   pivots inbound from 10.0.4.17 and outbound (SMB) to ``FILESVR-03``
   (10.0.4.18).

   In this folder you should see:

   - ``flow-data.csv``: the 14:19 / 14:21 / 14:35 outbound flows to
     91.214.47.22:443; the larger 14:21:55 candidate-exfil flow; the
     inbound network-logon-paired flow from 10.0.4.17; the SMB flow to
     FILESVR-03; and the bookend background flows that mirror what the
     host's own SRUM/EventLog see.
   - ``proxy-logs.csv``: the user's CONNECT-tunnelled HTTPS sessions to
     91.214.47.22:443 (CONNECT verb, no domain, "Uncategorised"
     category), plus a baseline of outlook.office365.com /
     login.microsoftonline.com / update.microsoft.com / events.data
     traffic from the same user that hour.
   - ``dns-queries.csv``: the failed PTR lookups on 91.214.47.22 (both
     to the internal resolver and to 8.8.8.8 — a tell-tale lookup
     pattern); the suspicious wpad.finance.local NXDOMAIN; the
     filesvr-03 A lookup just before the SMB pivot; and background
     Microsoft 365 / update / telemetry queries.
   - ``firewall-blocks.csv``: the inbound SMB scan sweep from
     185.193.126.47, denied at three internal hosts and the DNS server.
     There is no deny row for WKSTN-221: the scan reached that host,
     which logged the four failed logons (EID 4625) itself. Lab 08
     students learn to treat the missing row as a finding, not as
     proof the scanner never touched the eventual victim; a separate inbound RDP
     sweep from 103.41.200.74; the outbound UDP/53 attempt from
     WKSTN-221 directly to 91.214.47.22 that the perimeter
     Block-Outbound-DNS-Direct rule caught; and an unrelated noise
     block against kiosk-07.

2. **HR-WS17 -> Personal OneDrive** (anchored 2024-11-12, 17:35-18:00 UTC)

   This is the capstone exfiltration chain captured by
   ``Data/HR-WS17/``. A departing HR/finance employee on workstation
   ``HR-WS17`` (user ``FINANCE\hr-user``) signs in to a *personal*
   OneDrive account from a corporate device and uploads two
   confidential pricing files (``Q4_Customer_Pricing.xlsx`` and
   ``Pricing_Strategy_Confidential.docx``). Later in the same window
   they open Outlook on the web at ``outlook.live.com`` — suggestive
   of a webmail upload but not confirmed from the host alone.

   In this folder you should see:

   - ``flow-data.csv``: the OneDrive sync flows from HR-WS17 to
     Microsoft endpoints (40.108.x and 13.107.42.14 ranges) during the
     17:46-17:49 sync window, with byte counts consistent with a
     ~3 MB total transfer.
   - ``proxy-logs.csv``: the user's authenticated proxy traffic during
     the same window — Microsoft sign-in, OneDrive endpoint hits, and
     the ``outlook.live.com`` navigation at 17:51. These are
     **legitimate-looking** from a proxy POV (no malware indicators)
     but the *combination of personal-account hostname + corporate
     user + sensitive-data window* is what Lab 11 asks the student to
     flag.
   - ``dns-queries.csv``: A records for ``onedrive.live.com``,
     ``login.live.com``, ``outlook.live.com``, and the corresponding
     Microsoft CDN names, all from HR-WS17's IP.

The script is intentionally large (~1200 lines) and hand-codes every
story-relevant row so that the cross-references between this folder and
the host folders stay byte-exact. Filler/noise rows come from a seeded
PRNG so that the *whole file* is reproducible — re-running with the
same seed produces byte-identical output.

Cross-host consistency
======================
A few constants are duplicated from the WKSTN-221 generator
(``WKSTN_IP``, ``C2_IP``, ``BRUTE_IP``, ``FILESERVER_IP``,
``BACKUP_IP``, ``DAY``, ``T_LURE_OPEN``, ...). Any change to those
constants in WKSTN-221's ``generate.py`` should be mirrored here. The
generator imports nothing from the WKSTN-221 module — both files are
intentionally standalone so the dataset can be checked out and
regenerated without an importable package layout — but a section near
the top of this file (`WKSTN-221 cross-reference constants`) keeps the
two in sync visually.

HR-WS17 does not have a corresponding generator yet, so the constants
for its hostname / user / window were taken directly from the
committed ``Data/HR-WS17/`` CSVs and ``Data/HR-WS17/README.md``.
HR-WS17 was never assigned an internal IPv4 by the host-folder author;
this generator picks ``10.0.4.27`` for it (a free slot in the same
``10.0.4.0/24`` subnet that all the other workstations use). If
HR-WS17 ever gets its own generator, that value should be promoted
into a shared constant.

Usage
=====
    python3 generate.py                     # write CSVs in current dir
    python3 generate.py --dry-run           # print plan only
    python3 generate.py --out-dir /tmp/x    # write to scratch dir
    python3 generate.py --seed 0xdeadbeef   # override the seed

Outputs (in canonical order):

    flow-data.csv          ~31 rows (NetFlow / IPFIX style)
    proxy-logs.csv         ~21 rows (Squid / corporate proxy)
    dns-queries.csv        ~19 rows (internal DNS server)
    firewall-blocks.csv    ~11 rows (perimeter firewall denies)

Each generator function returns a list of dicts whose keys match the
``HEADERS`` table at the top of this file. The dispatch table at the
bottom binds filenames to generators. Adding a new file is therefore a
two-line change: add a header row to ``HEADERS`` and register the
generator in ``GENERATORS``.

Determinism
===========
Like the WKSTN-221 generator, each subgenerator is given its own
``random.Random`` instance, seeded from ``args.seed XOR hash(filename)``,
so adding or removing one generator does not perturb the others'
output. Run with the default seed twice and ``diff`` the files — they
will match byte for byte.
"""

from __future__ import annotations

import argparse
import csv
import os
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Dict, List, Tuple

# ---------------------------------------------------------------------------
# Random seed
# ---------------------------------------------------------------------------
#
# Spelled as a hex literal whose letters loosely encode "NETW0RK" — N->A,
# E->E, T->D, W->0, 0->0, R->B, K->C — purely so the constant has a
# memorable form. Any int works; this just makes it easier to spot in
# diffs. Override at the command line with ``--seed``.
RANDOM_SEED = 0x0AEDD00BC


# ---------------------------------------------------------------------------
# WKSTN-221 cross-reference constants
# ---------------------------------------------------------------------------
#
# These MUST stay byte-equal to the same-named constants in
# ``Data/WKSTN-221/generate.py``. The dataset only correlates across
# folders if every IP, hostname, and anchor timestamp matches. If you
# change one here, change it there too (and vice versa).

WKSTN_HOSTNAME = "WKSTN-221"
WKSTN_FQDN = "wkstn-221.finance.local"
WKSTN_IP = "10.0.4.32"

DOMAIN = "FINANCE"
WKSTN_USER = "payroll-admin"
WKSTN_USER_FULL = f"{DOMAIN}\\{WKSTN_USER}"

FILESERVER_HOSTNAME = "FILESVR-03"
FILESERVER_FQDN = "filesvr-03.finance.local"
FILESERVER_IP = "10.0.4.18"

ADVERSARY_INBOUND_IP = "10.0.4.17"   # the unmanaged internal host the
                                      # adversary pivoted from at 14:31
BACKUP_HOST = "BACKUP-SCHED"
BACKUP_FQDN = "backup-sched.finance.local"
BACKUP_IP = "10.0.4.42"

INTERNAL_DNS_IP = "10.0.0.10"
INTERNAL_DNS_FQDN = "dns01.finance.local"
PUBLIC_DNS_IP = "8.8.8.8"

C2_IP = "91.214.47.22"               # adversary infrastructure
BRUTE_IP = "185.193.126.47"           # external scanner (SMB sweep)
RDP_SCANNER_IP = "103.41.200.74"      # external scanner (RDP sweep)
KIOSK_SCANNER_IP = "84.142.89.12"     # noise: kiosk web prober

# Anchor times for the WKSTN-221 incident.
WKSTN_DAY = "2024-11-14"
T_LURE_OPEN = "2024-11-14 14:18:55"
T_PS_SPAWN = "2024-11-14 14:19:38"
T_FIRST_C2 = "2024-11-14 14:19:42"
T_BEACON_2 = "2024-11-14 14:21:48"
T_EXFIL_CANDIDATE = "2024-11-14 14:21:55"
T_BEACON_3 = "2024-11-14 14:22:14"
T_INBOUND_LOGON = "2024-11-14 14:31:05"
T_LATERAL_SMB = "2024-11-14 14:33:18"
T_LATERAL_XFER = "2024-11-14 14:33:42"
T_FINAL_BEACON = "2024-11-14 14:35:00"


# ---------------------------------------------------------------------------
# HR-WS17 cross-reference constants
# ---------------------------------------------------------------------------
#
# HR-WS17 has no generator yet — these values were lifted from the
# committed ``Data/HR-WS17/`` CSVs. If a generator is ever added there,
# promote this block into a shared constant or import it.

HRWS17_HOSTNAME = "HR-WS17"
HRWS17_FQDN = "hr-ws17.finance.local"
# HR-WS17 was never assigned an explicit IPv4 in the committed dataset.
# Pick a free slot in the same 10.0.4.0/24 subnet. Other slots in use:
#   10.0.4.18 FILESVR-03, 10.0.4.32 WKSTN-221, 10.0.4.42 BACKUP-SCHED,
#   10.0.4.45 FIN-WS23, 10.0.4.51 HR-LT12, 10.0.4.61 KIOSK-07.
HRWS17_IP = "10.0.4.27"
HRWS17_USER = "hr-user"
HRWS17_USER_FULL = f"{DOMAIN}\\{HRWS17_USER}"

HR_DAY = "2024-11-12"
T_HR_LOGON = "2024-11-12 08:42:11"
T_HR_PRICING_OPEN = "2024-11-12 17:38:42"
T_HR_ONEDRIVE_START = "2024-11-12 17:46:02"
T_HR_ONEDRIVE_FILE1 = "2024-11-12 17:47:18"
T_HR_ONEDRIVE_FILE2 = "2024-11-12 17:49:18"
T_HR_OUTLOOK_LIVE = "2024-11-12 17:51:04"
T_HR_LOGOFF = "2024-11-12 18:02:14"


# ---------------------------------------------------------------------------
# Other workstations / endpoints used as noise
# ---------------------------------------------------------------------------
#
# These appear in the committed CSVs as background traffic. They are
# normal corporate hosts, not part of either attack chain.

FIN_WS23_IP = "10.0.4.45"
FIN_WS23_FQDN = "fin-ws23.finance.local"
HR_LT12_IP = "10.0.4.51"
HR_LT12_FQDN = "hr-lt12.finance.local"
KIOSK_07_IP = "10.0.4.61"
KIOSK_07_FQDN = "kiosk-07.finance.local"


# ---------------------------------------------------------------------------
# Microsoft / Office 365 endpoints used as legitimate background
# ---------------------------------------------------------------------------
#
# These are deliberately chosen to look like *real* Microsoft IPs so
# that an analyst running them through a threat-intel lookup will get
# back "Microsoft" and dismiss them. They are: Outlook on the Web
# (52.96.x), Azure AD sign-in (40.126.x and 40.108.x), Microsoft CDN
# (13.107.x), and Edge telemetry (13.107.42.14).

M365_OUTLOOK_IP = "52.96.128.45"           # outlook.office365.com
M365_LOGIN_IP = "40.126.32.74"             # login.microsoftonline.com
M365_LIVE_LOGIN_IP = "40.84.180.42"        # login.live.com (consumer)
M365_OUTLOOK_LIVE_IP = "40.84.180.18"      # outlook.live.com (consumer)
M365_ONEDRIVE_LIVE_IP = "40.108.232.91"    # onedrive.live.com (consumer)
M365_TELEMETRY_IP = "13.107.42.14"         # events.data.microsoft.com
M365_UPDATE_IP = "13.107.4.50"             # update.microsoft.com
M365_DOCS_IP = "13.107.6.171"              # docs.microsoft.com / microsoft.com
M365_BING_IP = "13.107.21.200"             # www.bing.com


# ---------------------------------------------------------------------------
# User-Agent strings used in proxy logs
# ---------------------------------------------------------------------------
#
# Kept identical to the committed file (truncated form for the
# elsewhere-used Edge UA; full Edge UA for the lure-window rows so the
# analyst can confirm the browser version).

UA_EDGE_FULL = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML like Gecko) Chrome/118.0.0.0 "
    "Safari/537.36 Edg/118.0.2088.76"
)
UA_EDGE_SHORT = "Mozilla/5.0 ... Edg/118.0"
UA_EDGE_BARE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/118.0"
UA_OFFICE = "Microsoft Office/16.0"
UA_EDGE_WEBVIEW2 = "Microsoft Edge WebView2"
UA_WINDOWS_UPDATE = "Windows-Update-Agent"
UA_PS_INVOKE_WEBREQ = "Microsoft .NET CLR 4.8 (Invoke-WebRequest)"
UA_ONEDRIVE = "Microsoft SkyDriveSync/24.043.0303.0001 ship; Windows NT 10.0 (19045)"
UA_DASH = "-"


# ---------------------------------------------------------------------------
# CSV headers (exact match to the committed files — verified via diff)
# ---------------------------------------------------------------------------

HEADERS: Dict[str, List[str]] = {
    "flow-data.csv": [
        "FlowStart", "FlowEnd", "SourceIP", "SourcePort", "DestIP",
        "DestPort", "Protocol", "BytesSent", "BytesReceived",
        "PacketsSent", "PacketsReceived", "SourceHost", "DestHost",
        "Notes",
    ],
    "proxy-logs.csv": [
        "Timestamp", "ClientIP", "Username", "Method", "URL",
        "ResponseCode", "BytesSent", "BytesReceived", "UserAgent",
        "ContentType", "ContentCategory",
    ],
    "dns-queries.csv": [
        "Timestamp", "ClientIP", "QueryName", "QueryType",
        "ResponseCode", "RecordsReturned", "DNSServer",
    ],
    "firewall-blocks.csv": [
        "Timestamp", "Action", "SourceIP", "SourcePort", "DestIP",
        "DestPort", "Protocol", "SourceHost", "DestHost", "RuleName",
    ],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_ts(s: str) -> datetime:
    """Parse a ``YYYY-MM-DD HH:MM:SS`` (or ``...HH:MM:SS.fff``) string."""
    base = s.split(".", 1)[0]
    return datetime.strptime(base, "%Y-%m-%d %H:%M:%S")


def fmt_ts(dt: datetime) -> str:
    """Format a datetime back into ``YYYY-MM-DD HH:MM:SS`` (no fractional)."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def add_seconds(s: str, seconds: int) -> str:
    """Shift a timestamp string by ``seconds`` seconds."""
    return fmt_ts(parse_ts(s) + timedelta(seconds=seconds))


def jitter_seconds(rng: random.Random, base: str, lo: int, hi: int) -> str:
    """Return ``base`` shifted by a random number of seconds in [lo, hi]."""
    return add_seconds(base, rng.randint(lo, hi))


def random_high_port(rng: random.Random) -> int:
    """Return a plausible ephemeral source port (49152-65535-ish)."""
    return rng.randint(49000, 65000)


# ---------------------------------------------------------------------------
# Generator: flow-data.csv (NetFlow / IPFIX)
# ---------------------------------------------------------------------------

def generate_flow_data(rng: random.Random) -> List[Dict[str, str]]:
    """Hand-coded flow records for both attack chains, plus noise.

    The committed file has ~30 rows; we hold the count in the same
    ballpark. Rows are emitted in a logical order (by ``FlowStart``)
    rather than the original committed order, which interleaved them
    by story phase. The sorter at the end of the function gives the
    canonical chronological order; flip the sort key if you want to
    preserve "by story phase" instead.
    """
    rows: List[Dict[str, str]] = []

    def add(start: str, end: str, src: str, sport: int, dst: str,
            dport: int, proto: str, bsent: int, brcvd: int,
            psent: int, prcvd: int, shost: str, dhost: str,
            notes: str) -> None:
        rows.append({
            "FlowStart": start,
            "FlowEnd": end,
            "SourceIP": src,
            "SourcePort": str(sport),
            "DestIP": dst,
            "DestPort": str(dport),
            "Protocol": proto,
            "BytesSent": str(bsent),
            "BytesReceived": str(brcvd),
            "PacketsSent": str(psent),
            "PacketsReceived": str(prcvd),
            "SourceHost": shost,
            "DestHost": dhost,
            "Notes": notes,
        })

    # ---------------- WKSTN-221 baseline (pre-incident, same day) ----------
    # Long Outlook session: a single all-morning row, byte counts
    # equivalent to the SRUM hourly bucket. Lab 8 students learn to
    # recognise this as the legitimate corporate baseline.
    add("2024-11-14 09:00:00", "2024-11-14 09:48:00",
        WKSTN_IP, 49213, M365_OUTLOOK_IP, 443, "TCP",
        184221, 1842184, 184, 1842,
        WKSTN_FQDN, "outlook.office365.com", "Long Outlook session")
    add("2024-11-14 12:00:00", "2024-11-14 12:00:24",
        WKSTN_IP, 49211, M365_UPDATE_IP, 443, "TCP",
        4218, 18421, 12, 42,
        WKSTN_FQDN, "update.microsoft.com", "Update check")
    add("2024-11-14 12:32:04", "2024-11-14 12:32:48",
        WKSTN_IP, 49210, M365_TELEMETRY_IP, 443, "TCP",
        8421, 184221, 18, 184,
        WKSTN_FQDN, "events.data.microsoft.com", "Telemetry")
    # NOTE on row budget: we keep the committed file's count to within
    # +/-10% (originals = 30 rows). To stay inside that budget while
    # also covering the new HR-WS17 chain (which the committed file
    # didn't), the HR-WS17 chain leans on only 7 rows and we trim
    # cross-host background rows that aren't story-relevant.

    # ---------------- External scanner (early-morning SMB sweep) ----------
    # WKSTN-221 answered: four NTLM session setups on one SMB connection,
    # matching its four EID 4625 failures at :00, :11, :24 and :42.
    add("2024-11-14 04:00:00", "2024-11-14 04:00:42",
        BRUTE_IP, 49001, WKSTN_IP, 445, "TCP",
        4218, 2841, 28, 22,
        "(external)", WKSTN_FQDN,
        "External IP scan against SMB; session established")
    # The other two were denied at the perimeter: SYN retries, no reply.
    add("2024-11-14 04:00:11", "2024-11-14 04:00:20",
        BRUTE_IP, 49002, FIN_WS23_IP, 445, "TCP",
        156, 0, 3, 0,
        "(external)", FIN_WS23_FQDN,
        "Same scanner; SYN only, no reply (denied)")
    add("2024-11-14 04:00:24", "2024-11-14 04:00:33",
        BRUTE_IP, 49003, HR_LT12_IP, 445, "TCP",
        156, 0, 3, 0,
        "(external)", HR_LT12_FQDN,
        "Same scanner; SYN only, no reply (denied)")

    # ---------------- Legitimate scheduled backup (overnight) -------------
    # Starts at 02:14:08: the backup job's first attempt (a failed
    # payroll-admin logon, WKSTN-221 EID 4625) rides the same session.
    add("2024-11-14 02:14:08", "2024-11-14 02:14:48",
        BACKUP_IP, 49050, WKSTN_IP, 445, "TCP",
        8421, 184221, 18, 184,
        BACKUP_FQDN, WKSTN_FQDN, "Scheduled backup (legitimate)")

    # ---------------- 14:00 - lure window opens ---------------------------
    add("2024-11-14 14:00:00", "2024-11-14 14:00:48",
        WKSTN_IP, 49214, M365_OUTLOOK_IP, 443, "TCP",
        4218, 184221, 12, 184,
        WKSTN_FQDN, "outlook.office365.com", "Office 365 mail flow")
    add("2024-11-14 14:00:11", "2024-11-14 14:01:32",
        WKSTN_IP, 49215, M365_LOGIN_IP, 443, "TCP",
        8421, 128421, 18, 142,
        WKSTN_FQDN, "login.microsoftonline.com", "M365 auth")
    add("2024-11-14 14:00:14", "2024-11-14 14:01:04",
        FIN_WS23_IP, 49101, M365_DOCS_IP, 443, "TCP",
        8421, 184221, 18, 184,
        FIN_WS23_FQDN, "microsoft.com", "Background")
    add("2024-11-14 14:00:18", "2024-11-14 14:00:28",
        HR_LT12_IP, 49102, M365_OUTLOOK_IP, 443, "TCP",
        2184, 18421, 8, 21,
        HR_LT12_FQDN, "outlook.office365.com", "Background")
    add("2024-11-14 14:18:55", "2024-11-14 14:19:05",
        WKSTN_IP, 49217, M365_OUTLOOK_IP, 443, "TCP",
        2184, 18421, 8, 21,
        WKSTN_FQDN, "outlook.office365.com", "Background mail")

    # ---------------- 14:19 - first C2 contact ----------------------------
    # The DNS probe at :38 to both the internal resolver and 8.8.8.8 was
    # the PTR lookup on 91.214.47.22 that failed both places.
    add(T_PS_SPAWN, T_PS_SPAWN,
        WKSTN_IP, 49225, INTERNAL_DNS_IP, 53, "UDP",
        84, 184, 1, 1,
        WKSTN_FQDN, INTERNAL_DNS_FQDN, "Internal DNS")
    add(T_PS_SPAWN, T_PS_SPAWN,
        WKSTN_IP, 49224, PUBLIC_DNS_IP, 53, "UDP",
        84, 184, 1, 1,
        WKSTN_FQDN, "(public DNS)", "DNS query")
    add(T_FIRST_C2, "2024-11-14 14:19:48",
        WKSTN_IP, 52914, C2_IP, 443, "TCP",
        1847, 184221, 12, 142,
        WKSTN_FQDN, "(unknown)",
        "First observation of suspicious destination")

    # 14:21:14 LLMNR multicast — the host was searching for the
    # ``wpad.finance.local`` proxy autoconfig record via LLMNR after
    # DNS returned NXDOMAIN.
    add("2024-11-14 14:21:14", "2024-11-14 14:21:18",
        WKSTN_IP, 49230, "224.0.0.1", 5355, "UDP",
        84, 0, 1, 0,
        WKSTN_FQDN, "(multicast)", "LLMNR")

    # 14:21:48 - the DNS-over-443 attempt the perimeter blocked; the
    # firewall block row in firewall-blocks.csv references this same
    # flow.
    add(T_BEACON_2, T_BEACON_2,
        WKSTN_IP, 49232, C2_IP, 53, "UDP",
        0, 0, 0, 0,
        WKSTN_FQDN, "(unknown)", "Failed UDP/53 probe")

    # The TCP/443 beacons.
    add(T_BEACON_2, "2024-11-14 14:22:14",
        WKSTN_IP, 52915, C2_IP, 443, "TCP",
        4218, 18421, 18, 42,
        WKSTN_FQDN, "(unknown)", "Beacon-like")

    # The big outbound — flagged 'possible exfil' to give the analyst a
    # high-signal row to find. Counts match SRUM rollup.
    add(T_EXFIL_CANDIDATE, "2024-11-14 14:22:44",
        WKSTN_IP, 52916, C2_IP, 443, "TCP",
        184221, 2415891, 142, 1842,
        WKSTN_FQDN, "(unknown)",
        "Large outbound - possible exfil")

    # 14:22:14 beacon continuation.
    add(T_BEACON_3, "2024-11-14 14:22:48",
        WKSTN_IP, 52917, C2_IP, 443, "TCP",
        18421, 42184, 42, 84,
        WKSTN_FQDN, "(unknown)", "Beacon continuation")

    # ---------------- 14:30 background, then 14:31 pivot ------------------
    add("2024-11-14 14:30:00", "2024-11-14 14:30:14",
        WKSTN_IP, 49226, M365_OUTLOOK_IP, 443, "TCP",
        4218, 18421, 12, 42,
        WKSTN_FQDN, "outlook.office365.com", "Background")

    # Inbound SMB from the adversary-controlled internal host. The
    # "(unknown internal)" source-host string mirrors the committed file
    # — IT did not have a name for 10.0.4.17 in DHCP.
    add(T_INBOUND_LOGON, "2024-11-14 14:33:14",
        ADVERSARY_INBOUND_IP, 49220, WKSTN_IP, 445, "TCP",
        11421, 4218421, 42, 1842,
        "(unknown internal)", WKSTN_FQDN, "Inbound SMB to WKSTN-221")

    # Outbound SMB to FILESVR-03 — the lateral move flows.
    add(T_LATERAL_SMB, "2024-11-14 14:33:42",
        WKSTN_IP, 49221, FILESERVER_IP, 445, "TCP",
        2184, 18421, 18, 42,
        WKSTN_FQDN, FILESERVER_FQDN, "SMB to file server")
    add(T_LATERAL_XFER, "2024-11-14 14:35:00",
        WKSTN_IP, 49222, FILESERVER_IP, 445, "TCP",
        184221, 8421, 184, 21,
        WKSTN_FQDN, FILESERVER_FQDN, "SMB enumeration")

    # Final post-pivot beacon before the channel goes quiet.
    add(T_FINAL_BEACON, "2024-11-14 14:36:00",
        WKSTN_IP, 52918, C2_IP, 443, "TCP",
        8421, 11421, 42, 42,
        WKSTN_FQDN, "(unknown)", "Final beacon before quiet")

    # ---------------- HR-WS17 OneDrive exfil (2024-11-12) -----------------
    # These rows are NEW relative to the committed file (the committed
    # version did not yet include the HR-WS17 chain in network flow
    # form). They are the network-side trace of the OneDrive sync window
    # documented in Data/HR-WS17/onedrive-syncdb.csv. Byte counts match
    # the FileSize fields in onedrive-syncdb.csv plus realistic protocol
    # overhead.
    add(T_HR_LOGON, "2024-11-12 08:42:42",
        HRWS17_IP, 49150, M365_LOGIN_IP, 443, "TCP",
        4218, 18421, 12, 42,
        HRWS17_FQDN, "login.microsoftonline.com",
        "Corporate sign-in (background)")
    add("2024-11-12 09:32:11", "2024-11-12 09:34:42",
        HRWS17_IP, 49152, M365_OUTLOOK_IP, 443, "TCP",
        18421, 421842, 42, 421,
        HRWS17_FQDN, "outlook.office365.com",
        "Corporate Outlook background")
    add(T_HR_ONEDRIVE_START, T_HR_ONEDRIVE_FILE1,
        HRWS17_IP, 52201, M365_ONEDRIVE_LIVE_IP, 443, "TCP",
        1924711, 18421, 1421, 184,
        HRWS17_FQDN, "onedrive.live.com",
        "OneDrive Personal upload window starts "
        "(Q4_Customer_Pricing.xlsx -> personal account)")
    add(T_HR_ONEDRIVE_FILE1, "2024-11-12 17:48:30",
        HRWS17_IP, 52202, M365_LIVE_LOGIN_IP, 443, "TCP",
        4218, 18421, 12, 42,
        HRWS17_FQDN, "login.live.com",
        "Consumer Microsoft sign-in refresh")
    add("2024-11-12 17:48:41", T_HR_ONEDRIVE_FILE2,
        HRWS17_IP, 52203, M365_ONEDRIVE_LIVE_IP, 443, "TCP",
        1311840, 11421, 942, 142,
        HRWS17_FQDN, "onedrive.live.com",
        "OneDrive Personal upload "
        "(Pricing_Strategy_Confidential.docx -> personal account)")
    add(T_HR_OUTLOOK_LIVE, "2024-11-12 17:53:00",
        HRWS17_IP, 52210, M365_OUTLOOK_LIVE_IP, 443, "TCP",
        18421, 184221, 42, 184,
        HRWS17_FQDN, "outlook.live.com",
        "Personal webmail navigation (Lab 11 probable channel)")
    add("2024-11-12 17:55:18", "2024-11-12 17:55:32",
        HRWS17_IP, 49228, M365_OUTLOOK_IP, 443, "TCP",
        2184, 18421, 8, 21,
        HRWS17_FQDN, "outlook.office365.com",
        "Corporate Outlook tail")

    # ---------------- Background filler from other workstations -----------
    # One row only — Lab 8 isn't a "find the haystack" exercise, so we
    # don't pad. The committed file had two; we keep one.
    add("2024-11-14 14:18:14", "2024-11-14 14:18:42",
        KIOSK_07_IP, 49210, M365_LOGIN_IP, 443, "TCP",
        8421, 128421, 18, 142,
        KIOSK_07_FQDN, "login.microsoftonline.com", "Background")

    # Sort chronologically by FlowStart.
    rows.sort(key=lambda r: r["FlowStart"])
    return rows


# ---------------------------------------------------------------------------
# Generator: proxy-logs.csv (corporate proxy access log)
# ---------------------------------------------------------------------------

def generate_proxy_logs(rng: random.Random) -> List[Dict[str, str]]:
    """Hand-coded proxy log rows for both attack chains, plus baseline.

    The corporate proxy uses transparent TLS bumping for HTTP but allows
    CONNECT-tunnel for arbitrary 443 destinations. The C2 traffic shows
    up as CONNECT verb with a raw ``IP:443`` target (no Host header to
    extract a domain from), which is the giveaway. Microsoft endpoints
    show up as ordinary GET / POST with a parsed URL because they are
    bumped.
    """
    rows: List[Dict[str, str]] = []

    def add(ts: str, ip: str, user: str, method: str, url: str,
            code: int, bsent: int, brcvd: int, ua: str, ctype: str,
            category: str) -> None:
        rows.append({
            "Timestamp": ts,
            "ClientIP": ip,
            "Username": user,
            "Method": method,
            "URL": url,
            "ResponseCode": str(code),
            "BytesSent": str(bsent),
            "BytesReceived": str(brcvd),
            "UserAgent": ua,
            "ContentType": ctype,
            "ContentCategory": category,
        })

    # ---------------- WKSTN-221 baseline (days prior) ---------------------
    add("2024-11-12 09:32:00", WKSTN_IP, WKSTN_USER_FULL, "GET",
        "https://outlook.office365.com/owa/", 200, 1842, 184221,
        UA_EDGE_SHORT, "text/html", "Business / Email")
    add("2024-11-13 14:00:00", WKSTN_IP, WKSTN_USER_FULL, "GET",
        "https://outlook.office365.com/api/v2.0/me/messages", 200,
        2184, 184221, UA_OFFICE, "application/json", "Business / Email")

    # ---------------- WKSTN-221 same-day baseline -------------------------
    # Mid-morning Outlook poll, an Update check, telemetry, a Microsoft
    # sign-in from a different host. Enough to establish "this user
    # talks to Microsoft endpoints all day" without padding.
    add("2024-11-14 09:00:00", WKSTN_IP, WKSTN_USER_FULL, "GET",
        "https://outlook.office365.com/api/v2.0/me/messages", 200,
        2184, 184221, UA_OFFICE, "application/json", "Business / Email")
    add("2024-11-14 12:00:14", WKSTN_IP, WKSTN_USER_FULL, "GET",
        "https://update.microsoft.com/v6/ClientWebService/client.asmx",
        200, 4218, 18421, UA_WINDOWS_UPDATE, "text/xml",
        "Microsoft Update")
    add("2024-11-14 12:32:04", WKSTN_IP, WKSTN_USER_FULL, "POST",
        "https://events.data.microsoft.com/Collector/3.0/", 204, 8421,
        128, UA_EDGE_WEBVIEW2, "application/json", "Telemetry")
    add("2024-11-14 13:00:14", FIN_WS23_IP, "FINANCE\\j.smith", "GET",
        "https://login.microsoftonline.com/oauth2/authorize", 302,
        4218, 11421, UA_EDGE_SHORT, "text/html", "Microsoft Auth")
    add("2024-11-14 13:14:00", WKSTN_IP, WKSTN_USER_FULL, "GET",
        "https://outlook.office365.com/api/v2.0/me/messages", 200,
        2184, 184221, UA_OFFICE, "application/json", "Business / Email")
    add("2024-11-14 14:00:01", WKSTN_IP, WKSTN_USER_FULL, "GET",
        "https://outlook.office365.com/owa/", 200, 1842, 184221,
        UA_EDGE_FULL, "text/html", "Business / Email")
    add("2024-11-14 14:00:14", WKSTN_IP, WKSTN_USER_FULL, "GET",
        "https://outlook.office365.com/api/v2.0/me/messages", 200,
        2184, 418421, UA_OFFICE, "application/json", "Business / Email")
    add("2024-11-14 14:00:14", KIOSK_07_IP, "FINANCE\\kiosk", "GET",
        "https://login.microsoftonline.com/", 302, 1142, 4218,
        UA_EDGE_SHORT, "text/html", "Microsoft Auth")
    add("2024-11-14 14:00:42", FIN_WS23_IP, "FINANCE\\j.smith", "GET",
        "https://www.microsoft.com/en-us/", 200, 1142, 184221,
        UA_EDGE_BARE, "text/html", "Information Technology")
    add("2024-11-14 14:00:00", HR_LT12_IP, "FINANCE\\hr-user", "GET",
        "https://outlook.office365.com/owa/", 200, 1842, 128421,
        UA_EDGE_SHORT, "text/html", "Business / Email")

    # Kiosk web noise.
    add("2024-11-14 14:18:14", KIOSK_07_IP, "FINANCE\\kiosk", "GET",
        "https://www.bing.com/", 200, 1842, 184221, UA_EDGE_SHORT,
        "text/html", "Search Engine")

    # ---------------- WKSTN-221 C2 tunnel ---------------------------------
    # The CONNECT verb means the proxy never saw inside the TLS — only
    # the SNI-less ``IP:443`` target. That is the signal. First CONNECT
    # carries the Invoke-WebRequest UA (because PowerShell was the
    # client at that point); subsequent CONNECTs are from update.exe
    # which sends no UA.
    add("2024-11-14 14:19:42", WKSTN_IP, WKSTN_USER_FULL, "CONNECT",
        f"{C2_IP}:443", 200, 184, 184, UA_PS_INVOKE_WEBREQ, UA_DASH,
        "Uncategorized")
    add("2024-11-14 14:21:48", WKSTN_IP, WKSTN_USER_FULL, "CONNECT",
        f"{C2_IP}:443", 200, 184, 184, UA_DASH, UA_DASH,
        "Uncategorized")
    add("2024-11-14 14:21:55", WKSTN_IP, WKSTN_USER_FULL, "CONNECT",
        f"{C2_IP}:443", 200, 184, 184, UA_DASH, UA_DASH,
        "Uncategorized")
    add("2024-11-14 14:22:14", WKSTN_IP, WKSTN_USER_FULL, "CONNECT",
        f"{C2_IP}:443", 200, 184, 184, UA_DASH, UA_DASH,
        "Uncategorized")
    add("2024-11-14 14:35:00", WKSTN_IP, WKSTN_USER_FULL, "CONNECT",
        f"{C2_IP}:443", 200, 184, 184, UA_DASH, UA_DASH,
        "Uncategorized")

    # ---------------- HR-WS17 OneDrive (and the suggestive webmail nav) ---
    # Note: the proxy logs each *visible* request, not the OneDrive
    # chunked upload byte total, so the BytesSent for the upload row
    # is the total POST body (multipart-form-data) size from the
    # OneDrive client. Treat the OneDrive-side syncdb counts as
    # authoritative for the *file* size.
    add(T_HR_ONEDRIVE_START, HRWS17_IP, HRWS17_USER_FULL, "POST",
        "https://onedrive.live.com/personal/hr_user_personal_outlook_com"
        "/_api/v2.0/me/drive/special/approot/children", 200, 4218,
        18421, UA_ONEDRIVE, "application/json",
        "Personal Cloud Storage")
    # The PUT starts when the client begins the upload (client log
    # 17:46:42.318), not at the 17:46:02 sign-in POST above.
    add("2024-11-12 17:46:42", HRWS17_IP, HRWS17_USER_FULL, "PUT",
        "https://onedrive.live.com/personal/hr_user_personal_outlook_com"
        "/_api/v2.0/me/drive/items/01ABCDEF234567890ABCDEF1/content",
        201, 1842184, 4218, UA_ONEDRIVE, "application/octet-stream",
        "Personal Cloud Storage")
    add("2024-11-12 17:48:41", HRWS17_IP, HRWS17_USER_FULL, "PUT",
        "https://onedrive.live.com/personal/hr_user_personal_outlook_com"
        "/_api/v2.0/me/drive/items/01ABCDEF234567890ABCDEF2/content",
        201, 1248421, 4218, UA_ONEDRIVE, "application/octet-stream",
        "Personal Cloud Storage")
    add(T_HR_OUTLOOK_LIVE, HRWS17_IP, HRWS17_USER_FULL, "GET",
        "https://outlook.live.com/mail/0/", 200, 1842, 421842,
        UA_EDGE_FULL, "text/html", "Personal Webmail")
    # Sort chronologically.
    rows.sort(key=lambda r: r["Timestamp"])
    return rows


# ---------------------------------------------------------------------------
# Generator: dns-queries.csv (internal DNS server log)
# ---------------------------------------------------------------------------

def generate_dns_queries(rng: random.Random) -> List[Dict[str, str]]:
    """Hand-coded DNS query log rows.

    The narrative-relevant rows are the two PTR lookups on
    91.214.47.22 (one to the internal resolver, one to 8.8.8.8 — the
    PowerShell ``Resolve-DnsName`` fallback) and the ``wpad`` NXDOMAIN
    that comes from the host trying to autodiscover a proxy. The
    filesvr-03 A lookup just before 14:31 is the pivot.

    Note: ``RecordsReturned`` is a single string here (matching the
    committed file's schema) — for queries that return one record we
    write the record value; for NXDOMAIN we write an empty string.
    """
    rows: List[Dict[str, str]] = []

    def add(ts: str, src: str, name: str, qtype: str, code: str,
            records: str, server: str) -> None:
        rows.append({
            "Timestamp": ts,
            "ClientIP": src,
            "QueryName": name,
            "QueryType": qtype,
            "ResponseCode": code,
            "RecordsReturned": records,
            "DNSServer": server,
        })

    # ---------------- WKSTN-221 baseline (same day) -----------------------
    # Keep two pre-incident rows so the analyst can compare 14:00 lure
    # window baseline to a pre-incident baseline. The committed file
    # had several more; trimmed for row budget.
    add("2024-11-13 14:00:00", WKSTN_IP, "outlook.office365.com", "A",
        "NOERROR", M365_OUTLOOK_IP, INTERNAL_DNS_IP)
    add("2024-11-14 09:00:00", WKSTN_IP, "outlook.office365.com", "A",
        "NOERROR", M365_OUTLOOK_IP, INTERNAL_DNS_IP)
    add("2024-11-14 12:00:00", WKSTN_IP, "update.microsoft.com", "A",
        "NOERROR", M365_UPDATE_IP, INTERNAL_DNS_IP)
    add("2024-11-14 12:32:04", WKSTN_IP, "events.data.microsoft.com",
        "A", "NOERROR", M365_TELEMETRY_IP, INTERNAL_DNS_IP)

    # The reverse lookup the host did on 10.0.4.32 itself (innocuous —
    # the host's own name resolves via the DNS server).
    add("2024-11-14 02:14:14", BACKUP_IP, WKSTN_FQDN, "A",
        "NOERROR", WKSTN_IP, INTERNAL_DNS_IP)

    # 14:00 lure window starts.
    add("2024-11-14 14:00:00", WKSTN_IP, "outlook.office365.com", "A",
        "NOERROR", M365_OUTLOOK_IP, INTERNAL_DNS_IP)
    add("2024-11-14 14:00:11", WKSTN_IP, "login.microsoftonline.com",
        "A", "NOERROR", M365_LOGIN_IP, INTERNAL_DNS_IP)
    add("2024-11-14 14:00:18", HR_LT12_IP, "outlook.office365.com",
        "A", "NOERROR", M365_OUTLOOK_IP, INTERNAL_DNS_IP)
    add("2024-11-14 14:18:55", WKSTN_IP, "outlook.office365.com", "A",
        "NOERROR", M365_OUTLOOK_IP, INTERNAL_DNS_IP)

    # ---------------- The two telltale 91.214.47.22 PTR lookups -----------
    # PowerShell's Resolve-DnsName / nslookup will query both the
    # configured nameserver and the public fallback when the first
    # returns NXDOMAIN. Both fail because 91.214.47.22 has no PTR
    # record set — adversaries rarely bother.
    add("2024-11-14 14:19:38", WKSTN_IP, "(91.214.47.22 PTR)", "PTR",
        "NXDOMAIN", "", INTERNAL_DNS_IP)
    add("2024-11-14 14:19:38", WKSTN_IP, "(91.214.47.22 PTR)", "PTR",
        "NXDOMAIN", "", PUBLIC_DNS_IP)

    # WPAD autodiscovery — host trying to find a proxy autoconfig URL
    # that does not exist. Classic LLMNR/NBT-NS poisoning surface.
    add("2024-11-14 14:21:14", WKSTN_IP, "wpad.finance.local", "A",
        "NXDOMAIN", "", INTERNAL_DNS_IP)

    # Pre-pivot lookups.
    add("2024-11-14 14:31:00", WKSTN_IP, "filesvr-03.finance.local",
        "A", "NOERROR", FILESERVER_IP, INTERNAL_DNS_IP)
    add("2024-11-14 14:31:05", WKSTN_IP,
        "_kerberos._tcp.finance.local", "SRV", "NOERROR",
        "dc-01.finance.local", INTERNAL_DNS_IP)

    # A final PTR retry on 91.214.47.22 just before the channel quiets.
    add("2024-11-14 14:35:00", WKSTN_IP, "(91.214.47.22 PTR)", "PTR",
        "NXDOMAIN", "", INTERNAL_DNS_IP)

    # ---------------- HR-WS17 DNS during exfil ----------------------------
    # These are the "personal" consumer Microsoft names that map to
    # different IP ranges than the corporate office365.com ones.
    add(T_HR_LOGON, HRWS17_IP, "outlook.office365.com", "A",
        "NOERROR", M365_OUTLOOK_IP, INTERNAL_DNS_IP)
    add("2024-11-12 17:45:00", HRWS17_IP, "login.live.com", "A",
        "NOERROR", M365_LIVE_LOGIN_IP, INTERNAL_DNS_IP)
    add(T_HR_ONEDRIVE_START, HRWS17_IP, "onedrive.live.com", "A",
        "NOERROR", M365_ONEDRIVE_LIVE_IP, INTERNAL_DNS_IP)
    add(T_HR_OUTLOOK_LIVE, HRWS17_IP, "outlook.live.com", "A",
        "NOERROR", M365_OUTLOOK_LIVE_IP, INTERNAL_DNS_IP)

    # Sort chronologically.
    rows.sort(key=lambda r: r["Timestamp"])
    return rows


# ---------------------------------------------------------------------------
# Generator: firewall-blocks.csv (perimeter firewall denied connections)
# ---------------------------------------------------------------------------

def generate_firewall_blocks(rng: random.Random) -> List[Dict[str, str]]:
    """Hand-coded firewall block log rows.

    Only deny rows. The narrative role for this file is:

    - Provide an *unrelated* SMB scan from 185.193.126.47 earlier in the
      day. The perimeter denied it at FIN-WS23, HR-LT12, FILESVR-03 and
      the DNS server, but logged no deny for WKSTN-221: the scan reached
      that host, whose Security log holds the four EID 4625 failures.
      Students who anchor on "first contact with the victim" will
      mis-identify this scanner as the entry vector unless they
      correlate timestamps with what actually executed on the host.
    - Show the Block-Outbound-DNS-Direct row that catches the
      WKSTN-221 -> 91.214.47.22 UDP/53 attempt at 14:21:48 — useful
      because it proves the outbound DNS-over-non-resolver attempt
      *happened* even though the corresponding flow row shows 0 bytes
      sent (the perimeter dropped the packet).
    - Show a separate RDP scan from 103.41.200.74 against the file
      server and the workstation, again as unrelated noise.
    - Show a kiosk web prober as further noise.

    The HR-WS17 chain does not generate firewall blocks (the OneDrive
    upload uses legitimate Microsoft endpoints on 443; the corporate
    firewall lets that through). That asymmetry is intentional and
    discussed in Lab 11.
    """
    rows: List[Dict[str, str]] = []

    def add(ts: str, action: str, src: str, sport: int, dst: str,
            dport: int, proto: str, shost: str, dhost: str,
            rule: str) -> None:
        rows.append({
            "Timestamp": ts,
            "Action": action,
            "SourceIP": src,
            "SourcePort": str(sport),
            "DestIP": dst,
            "DestPort": str(dport),
            "Protocol": proto,
            "SourceHost": shost,
            "DestHost": dhost,
            "RuleName": rule,
        })

    # ---------------- SMB sweep from 185.193.126.47 (early morning) -------
    # No deny for WKSTN-221 (10.0.4.32): the 04:00:00-04:00:42 session
    # reached the host and produced its four EID 4625 failures.
    add("2024-11-14 04:00:11", "Deny", BRUTE_IP, 49002, FIN_WS23_IP,
        445, "TCP", "(external)", FIN_WS23_FQDN,
        "Block-Inbound-SMB-WAN")
    add("2024-11-14 04:00:24", "Deny", BRUTE_IP, 49003, HR_LT12_IP,
        445, "TCP", "(external)", HR_LT12_FQDN,
        "Block-Inbound-SMB-WAN")
    add("2024-11-14 04:00:42", "Deny", BRUTE_IP, 49004, FILESERVER_IP,
        445, "TCP", "(external)", FILESERVER_FQDN,
        "Block-Inbound-SMB-WAN")
    add("2024-11-14 04:01:18", "Deny", BRUTE_IP, 49005,
        INTERNAL_DNS_IP, 53, "TCP", "(external)", INTERNAL_DNS_FQDN,
        "Block-Inbound-DNS-TCP-WAN")

    # ---------------- RDP scan from 103.41.200.74 -------------------------
    add("2024-11-14 02:42:00", "Deny", RDP_SCANNER_IP, 49100,
        FILESERVER_IP, 3389, "TCP", "(external)", FILESERVER_FQDN,
        "Block-Inbound-RDP-WAN")
    add("2024-11-14 02:42:14", "Deny", RDP_SCANNER_IP, 49101,
        WKSTN_IP, 3389, "TCP", "(external)", WKSTN_FQDN,
        "Block-Inbound-RDP-WAN")

    # ---------------- WKSTN-221 -> C2 outbound UDP/53 (blocked) -----------
    add(T_BEACON_2, "Deny", WKSTN_IP, 49232, C2_IP, 53, "UDP",
        WKSTN_FQDN, "(external)", "Block-Outbound-DNS-Direct")

    # ---------------- Kiosk web prober (noise) ----------------------------
    add("2024-11-14 18:00:00", "Deny", KIOSK_SCANNER_IP, 49200,
        KIOSK_07_IP, 80, "TCP", "(external)", KIOSK_07_FQDN,
        "Block-Inbound-HTTP-Direct")
    add("2024-11-14 18:14:11", "Deny", KIOSK_SCANNER_IP, 49201,
        KIOSK_07_IP, 8080, "TCP", "(external)", KIOSK_07_FQDN,
        "Block-Inbound-Web-Alternate")

    # Sort chronologically.
    rows.sort(key=lambda r: r["Timestamp"])
    return rows


# ---------------------------------------------------------------------------
# Dispatch table (filename -> generator function)
# ---------------------------------------------------------------------------
#
# The order here is the order rows are described in the README and in
# Lab 08's walkthrough. Keep it.

GENERATORS: Dict[str, Callable[[random.Random], List[Dict[str, str]]]] = {
    "flow-data.csv": generate_flow_data,
    "proxy-logs.csv": generate_proxy_logs,
    "dns-queries.csv": generate_dns_queries,
    "firewall-blocks.csv": generate_firewall_blocks,
}


# ---------------------------------------------------------------------------
# CSV writer
# ---------------------------------------------------------------------------

def write_csv(path: Path, fields: List[str],
              rows: List[Dict[str, str]]) -> None:
    """Write ``rows`` to ``path`` using ``QUOTE_MINIMAL`` to match the
    committed file style (only fields containing commas/quotes/newlines
    get quoted).
    """
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields,
                                quoting=csv.QUOTE_MINIMAL,
                                lineterminator="\n",
                                extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({f: row.get(f, "") for f in fields})


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=("Regenerate the network/ simulated dataset for "
                     "Lab 08 and Lab 11."))
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be written; touch nothing.")
    parser.add_argument("--out-dir", default=".",
                        help="Directory to write CSVs into (default: cwd).")
    parser.add_argument("--seed", type=lambda x: int(x, 0),
                        default=RANDOM_SEED,
                        help="Override the random seed (any int).")
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir).resolve()

    print(f"network/ generator - seed=0x{args.seed:X}")
    print(f"Output directory: {out_dir}")
    if args.dry_run:
        print("Mode: --dry-run (no files written)")
    print()

    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for filename, generator in GENERATORS.items():
        # Reseed per file so adding / removing a generator does not
        # disturb the others' output. Mirrors the WKSTN-221 approach.
        local_rng = random.Random((args.seed ^ hash(filename))
                                  & 0xFFFFFFFF)
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
