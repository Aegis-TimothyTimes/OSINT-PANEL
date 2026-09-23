#!/usr/bin/env python3
"""
AEGIS OSINT control panel v2 — tools with plain-English cards plus a
one-click background-dossier builder with export.

Tools live user-local under ~/osint-tools (no Kali repo surgery).
Nmap needs one sudo apt; Maltego needs its .deb + free account.
"""
import os
import re
import shlex
import shutil
import urllib.parse
import subprocess
import sys
import zipfile

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QApplication, QCheckBox, QGridLayout, QHBoxLayout,
                               QLabel, QLineEdit, QMainWindow, QMessageBox,
                               QPushButton, QTabWidget, QTextEdit, QVBoxLayout,
                               QWidget)

HOME = os.path.expanduser("~")
TOOLS = os.path.join(HOME, "osint-tools")
BIN = os.path.join(HOME, ".local", "bin")
sys.path.insert(0, TOOLS)
if os.environ.get("AEGIS_SYSTEM"):
    # .deb launch: system bundle wins deterministically, so stale
    # per-user copies can never shadow an upgrade. Last insert(0)
    # takes position 0 — that ordering is the whole point.
    sys.path.insert(0, "/usr/share/aegis-osint")

PANEL_VERSION = "2.5.0"  # bump on any card/tab/engine change
TC_HOST = "192.168.1.225"  # ThinkCentre LAN IP (see handoff; .local flaps)

STYLE = """
QMainWindow, QWidget { background: #1a1d24; }
QLabel { color: #d7dce2; }
QLabel#title { color: #4da3ff; font-size: 16px; font-weight: bold; }
QLabel#card { color: #ffffff; font-size: 13px; font-weight: bold; }
QLabel#desc { color: #9aa4b2; font-size: 11px; }
QLabel#status { color: #8a93a3; font-size: 11px; }
QLabel#icon { background: #10131a; border: 1px solid #2a2f3a; }
QLineEdit { background: #2a2f3a; color: #d7dce2; padding: 6px; }
QTextEdit { background: #10131a; color: #c8d0dc; font-family: monospace; }
QPushButton { background: #2a2f3a; color: #d7dce2; padding: 8px;
              min-height: 34px; font-size: 13px; }
QPushButton:hover { background: #4da3ff; color: #111; }
QPushButton#go { background: #2e7d4f; color: white; font-weight: bold;
                 padding: 10px; }
QPushButton#go:hover { background: #3a9c64; }
QTabWidget::pane { border: 1px solid #2a2f3a; }
QTabBar::tab { background: #2a2f3a; color: #d7dce2; padding: 8px 18px; }
QTabBar::tab:selected { background: #4da3ff; color: #111; }
QCheckBox { color: #d7dce2; }
QComboBox { background: #2a2f3a; color: #d7dce2; padding: 6px;
            min-height: 24px; }
QComboBox QAbstractItemView { background: #2a2f3a; color: #d7dce2; }
QFrame#card { background: #22262f; border: 1px solid #2a2f3a; }
"""

# name, what it does (field-agent plain English), runner key
CARDS = [
    ("theHarvester",
     "Emails, subdomains and hosts tied to a domain, pulled from public "
     "sources (certificate logs, search engines). First stop for any domain.",
     "harvester"),
    ("Amass",
     "Deep subdomain enumeration using dozens of public archives. Slower "
     "than the others; runs passive (quiet) in dossiers.",
     "amass"),
    ("Sublist3r",
     "Fast subdomain finder via search engines and public indexes. Quick "
     "win before the heavy tools.",
     "sublist3r"),
    ("Sherlock",
     "Takes one username and checks hundreds of sites for accounts. Needs "
     "a second clue (bio, photo) before you attribute anything.",
     "sherlock"),
    ("SpiderFoot",
     "Automated all-in-one scans (100+ modules) with a web UI. Point it at "
     "a target and let it work in the background.",
     "spiderfoot"),
    ("Recon-ng",
     "Interactive recon framework: workspaces, modules, API keys. 109 "
     "modules ship installed — add your own API keys with `keys add` "
     "inside for full power.",
     "reconng"),
    ("Nmap",
     "Network mapper: what hosts are up, what ports answer, what software "
     "talks back. ACTIVE probing — authorized targets only.",
     "nmap"),
    ("ExifTool",
     "Reads metadata baked into files: camera, GPS, timestamps, author. "
     "Drop a photo in and see what it confesses.",
     "exiftool"),
    ("Maltego",
     "Link-analysis graph: people, domains, companies as connected maps. "
     "Needs its installer + free Community account.",
     "maltego"),
    ("BLE Map",
     "Bluetooth Low Energy mapper: discovers nearby BLE devices (phones, "
     "tags, wearables) via bettercap. Needs sudo + this laptop's hci0.",
     "blemap"),
    ("WiFi Deauth",
     "Disconnects clients from an access point (bettercap). LAB AND "
     "AUTHORIZED NETWORKS ONLY — this is an active attack.",
     "deauth"),
    ("PhoneInfoga",
     "Phone-number footprint: carrier, country, line type, plus public "
     "directory and breach-adjacent lookups. Type number in +E164 below.",
     "phoneinfoga"),
    ("holehe",
     "Email-to-accounts check: tests an address against 100+ sites and "
     "reports where it's registered. Sherlock's counterpart for emails.",
     "holehe"),
    ("Maigret",
     "Username hunt across 3000+ sites with document parsing — Sherlock's "
     "heavier sibling. Slower, wider net.",
     "maigret"),
    ("Photon",
     "Crawls a website and extracts emails, subdomains, endpoints and "
     "files. Give it a domain and let it spider.",
     "photon"),
    ("gau",
     "Historic URLs for a domain from web archives (AlienVault, Common "
     "Crawl). Finds forgotten endpoints and subdomains. Instant.",
     "gau"),
    ("Pagodo",
     "Runs Google-Hacking-Database dorks scoped to the domain, no API key. "
     "SLOW by design (~40-60s pause per dork); results saved as JSON + TXT.",
     "pagodo"),
    ("Wayback",
     "Time-travel the domain via the Internet Archive: snapshot list in "
     "the Console, latest good capture opened in your browser. The "
     "archive naps sometimes — the card says so instead of failing.",
     "wayback"),
    ("Video Intel",
     "Paste a video/image URL below: metadata docked (title, uploader, "
     "date, thumbnail), no download. Lens/TinEye buttons reverse-search "
     "an image URL in your browser.",
     "video"),
    ("Email Headers",
     "Paste raw message headers: hop-by-hop route, delays, SPF/DKIM/"
     "DMARC verdicts, reply-to mismatch flags. Fully offline.",
     "emailhdr"),
]


# Retro pixel icons, drawn in code so the installer stays a 5-file bundle
# (no PNG assets to ship or lose). 12x12 grids: '.' transparent,
# '#' tool colour, '+' near-white detail.
ICON_ART = {
    "harvester": ([
        "............",
        ".##########.",
        ".##......##.",
        ".#.#....#.#.",
        ".#..#..#..#.",
        ".#...##...#.",
        ".#...##...#.",
        ".#........#.",
        ".#...++++.#.",
        ".#...++++.#.",
        ".#........#.",
        ".##########.",
    ], "#ffd23f"),
    "amass": ([
        "............",
        "...##.......",
        "...#.##.....",
        "....#..##...",
        "..##.#...#..",
        ".#...##.#.#.",
        ".#....#.##..",
        "..#..#...#..",
        "...##.##.#..",
        ".....#..##..",
        "......##....",
        "............",
    ], "#ff5c5c"),
    "sublist3r": ([
        "............",
        "..##........",
        "..##..#####.",
        "..##........",
        "..##..#####.",
        "..##........",
        "..##..#####.",
        "..##........",
        "..##..#####.",
        "..##........",
        "..##........",
        "............",
    ], "#4da3ff"),
    "sherlock": ([
        "............",
        "....#####...",
        "...##...##..",
        "..##.....##.",
        "..#.......#.",
        "..#.......#.",
        "..##.....##.",
        "...##...##..",
        "....#####...",
        ".....##.....",
        "......##....",
        ".......##...",
    ], "#b388ff"),
    "spiderfoot": ([
        ".#........#.",
        "..#......#..",
        "...#....#...",
        "....######..",
        ".#...##...#.",
        ".....##.....",
        ".....##.....",
        ".....##.....",
        "....##.##...",
        "...##...##..",
        "...#.....#..",
        "............",
    ], "#ff8c42"),
    "reconng": ([
        "............",
        ".##########.",
        ".##########.",
        ".#........#.",
        ".#.##.....#.",
        ".#..##....#.",
        ".#...##...#.",
        ".#.....##.#.",
        ".#......###.",
        ".#........#.",
        ".##########.",
        ".##########.",
    ], "#59d6c9"),
    "nmap": ([
        "....#####...",
        "...##...##..",
        "..#.......+.",
        "..#.....++..",
        "..#....++...",
        "..#...++....",
        "..#.++++++..",
        "..#.......#.",
        "...##...##..",
        "....#####...",
        "............",
        "............",
    ], "#50fa7b"),
    "exiftool": ([
        "............",
        ".....#####..",
        ".....#...#..",
        ".##########.",
        ".##########.",
        ".##......##.",
        ".##..####.#.",
        ".##..####.#.",
        ".##......##.",
        ".##########.",
        ".##########.",
        "............",
    ], "#f368e0"),
    "maltego": ([
        "..#......#..",
        "...#....#...",
        "....#..#....",
        ".....##.....",
        ".....##.....",
        "..########..",
        ".....##.....",
        ".....##.....",
        "....#..#....",
        "...#....#...",
        "..#......#..",
        "............",
    ], "#48dbfb"),
    "blemap": ([
        ".....##.....",
        ".....#.#....",
        ".....#..#...",
        "..#..#..#...",
        "...#.#.#....",
        "....###.....",
        "....###.....",
        "...#.#.#....",
        "..#..#..#...",
        ".....#..#...",
        ".....#.#....",
        ".....##.....",
    ], "#5f8bff"),
    "deauth": ([
        ".....#......",
        ".....#......",
        "....###.....",
        "...##.##....",
        "..##...##...",
        "..#.....#...",
        ".+..........",
        "..+.........",
        "...+........",
        "....+.......",
        ".....+......",
        "......+.....",
    ], "#ff5555"),
    "phoneinfoga": ([
        "............",
        "..##....##..",
        "..###..###..",
        "..########..",
        "...######...",
        "....####....",
        "............",
        "............",
        "............",
        "............",
        "............",
        "............",
    ], "#7bed9f"),
    "holehe": ([
        "............",
        "....#####...",
        "...##...##..",
        "..##..###.#.",
        "..#.######..",
        "..#.######..",
        "..#.####....",
        "..##..###...",
        "...##...##..",
        "....#####...",
        "............",
        "............",
    ], "#ffa502"),
    "maigret": ([
        ".....##.....",
        "....####....",
        "....####....",
        ".....##.....",
        ".....##.....",
        "...######...",
        "..###..###..",
        "..##....##..",
        "..##....##..",
        "..#......#..",
        "............",
        "............",
    ], "#70a1ff"),
    "photon": ([
        "....#####...",
        "...##...##..",
        "..#.##.##.#.",
        "..#..###..#.",
        "..#.#####.#.",
        "..#.#####.#.",
        "..#..###..#.",
        "..#.##.##.#.",
        "...##...##..",
        "....#####...",
        "............",
        "............",
    ], "#ff6b81"),
    "gau": ([
        "....#####...",
        "...##+++##..",
        "..##..+..##.",
        "..#...++++#.",
        "..#...++++#.",
        "..#.......#.",
        "..##.....##.",
        "...##...##..",
        "....#####...",
        "............",
        "............",
        "............",
    ], "#26de81"),
    "pagodo": ([
        "....#####...",
        "...##.......",
        "..##........",
        "..#.........",
        "..#.#####...",
        "..#.#...#...",
        "..#.#####...",
        "..#.........",
        "..##........",
        "...##.......",
        "....#####...",
        "............",
    ], "#fbbc05"),
    "wayback": ([
        "..########..",
        "...##..##...",
        "....##.##...",
        ".....###....",
        ".....###....",
        "....##.##...",
        "...##..##...",
        "..########..",
        "............",
        "............",
        "............",
        "............",
    ], "#a29bfe"),
    "video": ([
        "..####......",
        "..#####.....",
        "..######....",
        "..#######...",
        "..########..",
        "..########..",
        "..#######...",
        "..######....",
        "..#####.....",
        "..####......",
        "............",
        "............",
    ], "#ff7675"),
    "emailhdr": ([
        "....###.....",
        "....###.....",
        ".....#......",
        ".....#......",
        "..#######...",
        "..#######...",
        ".....#......",
        ".....#......",
        "....###.....",
        "....###.....",
        "............",
        "............",
    ], "#55efc4"),
}


def tool_icon(key, size=48):
    """Render a retro pixel icon for a tool card. No image files needed."""
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor, QPixmap, QPainter
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    art = ICON_ART.get(key)
    if not art:
        return pm
    rows, fg = art
    n = len(rows)
    cell = max(1, size // n)
    px = QPainter(pm)
    for y, row in enumerate(rows):
        for x, ch in enumerate(row):
            if ch == "#":
                px.fillRect(x * cell, y * cell, cell, cell, QColor(fg))
            elif ch == "+":
                px.fillRect(x * cell, y * cell, cell, cell,
                            QColor("#f5f6fa"))
    px.end()
    return pm


# Curated zero-key dork pack. "Quick scan" mirrors
# pagodo/quick_dorks.txt — keep the two in sync.
DORK_SETS = [
    ("Quick scan", "Highest signal — the same 10 the Pagodo card runs.", [
        ("Open directories", 'intitle:"index of" "parent directory"'),
        ("Admin pages", "inurl:admin"),
        ("Login pages", "inurl:login"),
        ("PDFs", "filetype:pdf"),
        ("Spreadsheets", "filetype:xls OR filetype:xlsx"),
        ("Backup files", "filetype:bak OR filetype:old OR filetype:backup"),
        ("SQL dumps", "filetype:sql"),
        ("Log files", "filetype:log"),
        ("PHP info pages", 'intitle:"phpinfo" "PHP Version"'),
        ("Password strings", 'intext:"db_password" OR intext:"db_passwd"'),
    ]),
    ("Open directories", "Folders Google wandered into.", [
        ("Any index listing", 'intitle:"index of"'),
        ("Backup folders", "inurl:/backup/"),
        ("Listing pages", '"directory listing for"'),
    ]),
    ("Login portals", "Doors worth knowing about — no knocking.", [
        ("WordPress logins", "inurl:wp-login"),
        ("Titled logins", 'intitle:"login"'),
        ("Auth pages", "inurl:auth"),
    ]),
    ("Config and secrets", "Indexed files that confess too much.", [
        ("Env files", "inurl:.env"),
        ("PHP info", 'intitle:"phpinfo"'),
        ("Config files", "filetype:config"),
    ]),
    ("Cameras and devices", "Publicly reachable lenses and boxes.", [
        ("Webcams", 'intitle:"webcam"'),
        ("Network cameras", 'intitle:"network camera"'),
        ("Viewer pages", "inurl:view/view.shtml"),
    ]),
    ("Documents", "Papers and sheets about the target.", [
        ("Word docs", "filetype:doc OR filetype:docx"),
        ("Text files", "filetype:txt"),
        ("Presentations", "filetype:ppt OR filetype:pptx"),
    ]),
]


def sys_info():
    """This machine + this build. Stdlib only — no new dependencies."""
    import platform
    import socket
    try:
        os_label = platform.platform()
    except Exception:                                       # noqa: BLE001
        os_label = f"{platform.system()} {platform.release()}"
    info = [("Panel", f"AEGIS OSINT Panel v{PANEL_VERSION} — "
                      f"{len(CARDS)} tools, {len(DORK_SETS)} dork sets"),
            ("Operator", os.environ.get("USER", "?")),
            ("Hostname", socket.gethostname()),
            ("OS", os_label),
            ("Python", platform.python_version())]
    try:
        with open("/proc/cpuinfo", errors="replace") as fh:
            model = next((l.split(":", 1)[1].strip() for l in fh
                          if l.startswith("model name")), "?")
        info.append(("CPU", f"{model} × {os.cpu_count()}"))
    except OSError:
        info.append(("CPU", f"{os.cpu_count()} cores"))
    try:
        mem = {}
        with open("/proc/meminfo") as fh:
            for l in fh:
                k, v = l.split(":")
                if k in ("MemTotal", "MemAvailable"):
                    mem[k] = int(v.split()[0]) // 1024
        info.append(("RAM",
                     f"{mem.get('MemAvailable', '?')} MB free / "
                     f"{mem.get('MemTotal', '?')} MB"))
    except (OSError, ValueError):
        pass
    try:
        du = shutil.disk_usage(HOME)
        info.append(("Disk (home)",
                     f"{du.free // 2**30} GB free / "
                     f"{du.total // 2**30} GB"))
    except OSError:
        pass
    try:
        with open("/proc/uptime") as fh:
            up = int(float(fh.read().split()[0]))
        info.append(("Uptime", f"{up // 3600}h {(up % 3600) // 60}m"))
    except (OSError, ValueError):
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # no traffic sent, reveals local IP
        info.append(("LAN IP", s.getsockname()[0]))
        s.close()
    except OSError:
        pass
    for f in ("panel.py", "dossier.py", "keys.py", "users.py",
              "install-osint-panel.sh", "README.md",
              "OPERATIONS-MANUAL.md"):
        try:
            st = os.stat(os.path.join(TOOLS, f))
            from datetime import datetime
            ts = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d")
            info.append((f, f"{st.st_size // 1024} KB, {ts}"))
        except OSError:
            info.append((f, "MISSING"))
    return info


def tc_probe(timeout=2):
    """ThinkCentre ports 22/80: 'open' / 'closed-or-filtered'."""
    import socket
    out = {}
    for port in (22, 80, 11434):
        try:
            s = socket.create_connection((TC_HOST, port), timeout=timeout)
            s.close()
            out[port] = "open"
        except OSError:
            out[port] = "—"
    return out


def dork_url(template, domain, engine="Google"):
    q = f"site:{domain} {template}" if domain else template
    base = {
        "Google": "https://www.google.com/search?q=",
        "Bing": "https://www.bing.com/search?q=",
        "DuckDuckGo": "https://duckduckgo.com/?q=",
        "Brave": "https://search.brave.com/search?q=",
    }.get(engine, "https://www.google.com/search?q=")
    return base + urllib.parse.quote_plus(q)


def term(cmd, workdir=HOME):
    subprocess.Popen(["gnome-terminal", f"--working-directory={workdir}",
                      "--", "bash", "-ic", f"{cmd}; exec bash"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def have(prog):
    return (shutil.which(prog) is not None
            or os.path.exists(os.path.join(BIN, prog))
            or os.path.exists(os.path.join(HOME, "bin", prog)))


def run_tool(key, domain, username, number, email, status_fn,
             user=None):
    # External-terminal path: ONLY EXTERNAL_ONLY keys route here (GUI app,
    # or sudo tools needing a real TTY). Everything else runs docked via
    # build_argv + console_run. There is one launcher per tool on purpose.
    import users as _U
    if user is not None and not _U.can_run(user, key):
        status_fn(f"{key}: not authorized")
        return
    if key == "maltego" and have("maltego"):
        subprocess.Popen(["maltego"], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    elif key == "blemap":
        # Caplet boots ble.recon itself: no more "no modules running".
        term("echo 'BLE mapper — sudo password, then:  ble.show  to list.'; "
             f"sudo '{HOME}/bin/bettercap' -caplet '{TOOLS}/wireless/ble.cap'")
    elif key == "deauth":
        # Full guided setup: unmanage from NetworkManager (it otherwise
        # retakes the card mid-attack = the error spray), monitor mode,
        # then caplet boots wifi.recon + prints the table after ~8s.
        # Channel hopping during recon is NORMAL scanning, not failure.
        term("IFACE=$(ls /sys/class/net | grep -m1 '^wl' || echo wlp0s20f3); "
             "echo \"Wifi interface: $IFACE\"; "
             "command -v iw >/dev/null || "
             "{ echo 'Need iw first: sudo apt install -y iw'; }; "
             "echo 'Stepping NetworkManager aside (it fights monitor mode)…'; "
             "sudo nmcli dev set $IFACE managed no; "
             "sudo ip link set $IFACE down && "
             "sudo iw dev $IFACE set type monitor && "
             "sudo ip link set $IFACE up && "
             f"echo 'Recon sweeping all channels (~8s, hopping is normal)…' && "
             f"sudo '{HOME}/bin/bettercap' -iface $IFACE "
             f"-caplet '{TOOLS}/wireless/deauth.cap'; "
             "echo '---'; echo \"Restore when done: "
             "sudo nmcli dev set $IFACE managed yes\"")
    status_fn(key)


# Tools that must keep an external terminal: sudo needs a real TTY for the
# password prompt, Maltego is its own GUI app. launch() routes on this set.
EXTERNAL_ONLY = {"maltego", "blemap", "deauth"}


def _bin(prog):
    """Absolute path for PATH-installed tools. Desktop launches often
    lack ~/.local/bin on PATH while the installer-shell self-test has
    it — resolve here so checks and cards agree."""
    found = (shutil.which(prog)
             or os.path.join(BIN, prog)
             or os.path.join(HOME, "bin", prog))
    if found and os.path.exists(found):
        return found
    return shutil.which(prog) or prog


def build_argv(key, domain, username, number, email, url=""):
    """argv + workdir for a docked QProcess run. None = launch externally."""
    if key == "harvester" and domain:
        # Sources verified keyless on theHarvester 5.x. bing/threatcrowd
        # are NOT supported in v5 and abort the run — never re-add blindly.
        return ([f"{TOOLS}/venv-harvester/bin/theHarvester", "-d", domain,
                 "-b", "crtsh,hackertarget,otx,rapiddns,urlscan,certspotter,"
                       "duckduckgo"],
                f"{TOOLS}/theHarvester")
    if key == "amass" and domain:
        return ([f"{HOME}/bin/amass", "enum", "-passive", "-d", domain],
                HOME)
    if key == "sublist3r" and domain:
        return ([sys.executable, f"{TOOLS}/Sublist3r/sublist3r.py",
                 "-d", domain], HOME)
    if key == "sherlock" and username:
        return ([f"{BIN}/sherlock", username], HOME)
    if key == "spiderfoot":
        return ([f"{TOOLS}/venv-spider/bin/python",
                 f"{TOOLS}/spiderfoot/sf.py", "-l", "127.0.0.1:5001"],
                f"{TOOLS}/spiderfoot")
    if key == "reconng":
        return ([sys.executable, f"{TOOLS}/recon-ng/recon-ng"], HOME)
    if key == "nmap" and domain:
        return (["nmap", "-sV", "-F", domain], HOME)
    if key == "phoneinfoga" and number:
        return ([f"{HOME}/bin/phoneinfoga", "scan", "-n", number], HOME)
    if key == "holehe" and email:
        return ([f"{BIN}/holehe", email], HOME)
    if key == "maigret" and username:
        return ([f"{BIN}/maigret", username, "--timeout", "15"], HOME)
    if key == "photon" and domain:
        return ([sys.executable, f"{TOOLS}/Photon/photon.py",
                 "-u", domain, "-t", "10"], f"{TOOLS}/Photon")
    if key == "gau" and domain:
        # Pinned providers: gau's defaults include dead endpoints that hang
        # or empty the run (verified 2026-09-21). otx+wayback respond.
        # Filename sanitized like pagodo's tag — raw domain could escape.
        tag = re.sub(r"[^\w.-]+", "_", domain)
        return (["bash", "-c",
                 f"'{HOME}/bin/gau' --subs --providers otx,wayback "
                 f"{shlex.quote(domain)} | tee "
                 f"{shlex.quote('gau-' + tag + '.txt')}"], HOME)
    if key == "pagodo" and domain:
        # Quick file (10 dorks), not the 7944-line GHDB dump — a full run
        # takes hours by design. Results land next to gau's, in $HOME.
        tag = re.sub(r"[^\w.-]+", "_", domain)
        return ([sys.executable, f"{TOOLS}/pagodo/pagodo.py",
                 "-d", domain, "-g", f"{TOOLS}/pagodo/quick_dorks.txt",
                 "-o", f"pagodo-{tag}.json", "-s", f"pagodo-{tag}.txt",
                 "-z", f"pagodo-{tag}.log"], HOME)
    if key == "video" and url:
        # Metadata only, no download: fast, no disk surprises.
        return ([_bin("yt-dlp"), "--no-playlist", "--skip-download",
                 "--print", "%(title)s | %(uploader)s | %(upload_date)s",
                 "--print", "thumbnail: %(thumbnail)s", url], HOME)
    return None


def _open_when_up(url="http://127.0.0.1:5001/", tries=90):
    """Open the browser on first HTTP 200, not blind (server needs ~10s)."""
    import threading as _th
    import time as _t
    import urllib.request as _u

    def _wait():
        for _ in range(tries):
            try:
                _u.urlopen(url, timeout=2).close()
                break
            except Exception:                               # noqa: BLE001
                _t.sleep(1)
        subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)

    _th.Thread(target=_wait, daemon=True).start()


class DossierThread(QThread):
    line = Signal(str)
    done = Signal(str)

    def __init__(self, case, domain, username, skip):
        super().__init__()
        self.case, self.domain, self.username, self.skip = (
            case, domain, username, skip)
        self.phone, self.email, self.photo = "", "", ""
        self.url, self.headers_file = "", ""
        self.notes, self.operator = "", "?"
        self.allowed = None

    def run(self):
        try:
            import dossier as D
        except ImportError:
            self.line.emit("dossier.py not found next to panel.py — "
                           "re-run the installer.")
            self.done.emit("")
            return
        import re
        try:
            cdir = D.build(re.sub(r"[^\w.-]+", "_", self.case), self.domain,
                           self.username, self.skip, on_log=self.line.emit,
                           phone=self.phone, email=self.email,
                           photo=self.photo,
                           url=self.url, headers_file=self.headers_file,
                           notes=self.notes, operator=self.operator,
                           allowed=self.allowed)
        except Exception as exc:                                # noqa: BLE001
            self.line.emit(f"dossier failed: {exc}")
            self.done.emit("")
            return
        self.line.emit(f"REPORT: {cdir}/REPORT.md")
        self.done.emit(cdir)


class Panel(QMainWindow):
    def __init__(self, user):
        super().__init__()
        import users as U
        self._U = U
        self.operator = user or {"name": "?", "admin": False,
                                 "tools": [], "tabs": {}}
        me = self.operator.get("name", "?")
        self.setWindowTitle(f"AEGIS OSINT Panel — {me}")
        self.setStyleSheet(STYLE)
        self.setMinimumWidth(640)
        tabs = QTabWidget()
        self.tabs = tabs
        tabs.addTab(self.tools_tab(), "Tools")
        if U.can_tab(self.operator, "dorks"):
            self.dorks_page = self.dorks_tab()
            tabs.addTab(self.dorks_page, "Dorks")
        if U.can_tab(self.operator, "dossier"):
            self.dossier_page = self.dossier_tab()
            tabs.addTab(self.dossier_page, "Dossier")
        if U.can_tab(self.operator, "keys"):
            tabs.addTab(self.keys_tab(), "Keys")
        self.console_page = self.console_tab()
        tabs.addTab(self.console_page, "Console")
        self.sys_page = self.sysinfo_tab()
        tabs.addTab(self.sys_page, "System")
        if U.is_admin(self.operator):
            tabs.addTab(self.users_tab(), "Users")
        self.status = QLabel("ready")
        self.status.setObjectName("status")
        self.status.setAlignment(Qt.AlignCenter)
        lay = QVBoxLayout()
        lay.addWidget(tabs)
        lay.addWidget(self.status)
        wrap = QWidget()
        wrap.setLayout(lay)
        self.setCentralWidget(wrap)

    # ---- tools tab
    def tools_tab(self):
        from PySide6.QtWidgets import QFrame, QScrollArea
        inner = QWidget()
        lay = QVBoxLayout(inner)
        head = QLabel("AEGIS  //  OSINT CONTROL")
        head.setObjectName("title")
        head.setAlignment(Qt.AlignCenter)
        lay.addWidget(head)
        self.domain = QLineEdit()
        self.domain.setPlaceholderText("target domain  (e.g. example.com)")
        lay.addWidget(self.domain)
        self.user = QLineEdit()
        self.user.setPlaceholderText("username  (for Sherlock)")
        lay.addWidget(self.user)
        self.phone = QLineEdit()
        self.phone.setPlaceholderText("phone in +E164  (for PhoneInfoga)")
        lay.addWidget(self.phone)
        self.email = QLineEdit()
        self.email.setPlaceholderText("email  (for holehe)")
        lay.addWidget(self.email)
        self.url = QLineEdit()
        self.url.setPlaceholderText(
            "video/image URL  (for Video Intel + reverse search)")
        lay.addWidget(self.url)
        grid = QGridLayout()
        lay.addLayout(grid)
        NEEDS = {"harvester": "Needs: domain", "amass": "Needs: domain",
                 "sublist3r": "Needs: domain", "sherlock": "Needs: username",
                 "spiderfoot": "Needs: nothing — opens web UI",
                 "reconng": "Needs: nothing (add API keys inside)",
                 "nmap": "Needs: domain (authorized targets only)",
                 "exiftool": "Needs: nothing — you attach a photo",
                 "maltego": "Needs: installer + free account",
                 "blemap": "Needs: sudo + bluetooth adapter (external terminal)",
                 "deauth": "Needs: sudo + lab authorization (external terminal)",
                 "phoneinfoga": "Needs: phone in +E164",
                 "holehe": "Needs: email", "maigret": "Needs: username",
                 "photon": "Needs: domain", "gau": "Needs: domain",
                 "pagodo": "Needs: domain — slow (~1min pause per dork); "
                           "Google sometimes rate-limits (429) so empty "
                           "runs mean wait + retry",
                 "wayback": "Needs: domain (archive naps — card says so)",
                 "video": "Needs: video/image URL below",
                 "emailhdr": "Needs: nothing — paste headers in the dialog"}
        for i, (name, desc, key) in enumerate(CARDS):
            card = QFrame()
            card.setObjectName("card")
            cl = QVBoxLayout(card)
            headrow = QHBoxLayout()
            icon = QLabel()
            icon.setObjectName("icon")
            icon.setPixmap(tool_icon(key))
            icon.setFixedSize(52, 52)
            icon.setAlignment(Qt.AlignCenter)
            t = QLabel(name)
            t.setObjectName("card")
            t.setWordWrap(True)
            headrow.addWidget(icon)
            headrow.addWidget(t, 1)
            d = QLabel(desc)
            d.setObjectName("desc")
            d.setWordWrap(True)
            b = QPushButton("Run")
            if self._U.can_run(self.operator, key):
                b.setToolTip(NEEDS.get(key, ""))
            else:
                b.setEnabled(False)
                b.setToolTip("Not authorized for your account — see admin")
            b.clicked.connect(lambda _=False, k=key: self.launch(k))
            cl.addLayout(headrow)
            cl.addWidget(d, 1)
            cl.addWidget(b)
            if key == "video":
                brow = QHBoxLayout()
                lens = QPushButton("Lens")
                lens.setToolTip("Reverse-search the URL in Google Lens")
                lens.clicked.connect(
                    lambda _=False: self._open_reviso("lens"))
                tiny = QPushButton("TinEye")
                tiny.setToolTip("Reverse-search the URL in TinEye")
                tiny.clicked.connect(
                    lambda _=False: self._open_reviso("tiny"))
                brow.addWidget(lens)
                brow.addWidget(tiny)
                cl.addLayout(brow)
            grid.addWidget(card, i // 4, i % 4)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(inner)
        wrap = QWidget()
        wraplay = QVBoxLayout(wrap)
        wraplay.addWidget(scroll)
        return wrap

    def launch(self, key):
        if not self._U.can_run(self.operator, key):
            QMessageBox.information(self, "Not authorized",
                                    "Your account may not run this tool.\n"
                                    "Ask your admin for access.")
            return
        d, u = self.domain.text().strip(), self.user.text().strip()
        if key in ("harvester", "amass", "sublist3r", "nmap", "photon",
                    "gau", "pagodo", "wayback") and not d:
            QMessageBox.information(self, "Need a domain",
                                    "Type the target domain first.")
            return
        if key in ("sherlock", "maigret") and not u:
            QMessageBox.information(self, "Need a username",
                                    "Type the username first.")
            return
        if key == "holehe":
            e = self.email.text().strip()
            if "@" not in e:
                QMessageBox.information(self, "Need an email",
                                        "Type the email address first.")
                return
        if key == "nmap" and not have("nmap"):
            QMessageBox.information(
                self, "Nmap needs sudo (once)",
                "Run in a terminal:\n\n"
                "  sudo apt update && sudo apt install -y nmap")
            return
        if key == "maltego" and not have("maltego"):
            QMessageBox.information(
                self, "Maltego needs its installer + account",
                "1. Download the .deb from maltego.com/downloads\n"
                "2. sudo dpkg -i <file>  (root, once)\n"
                "3. Free Community account on first run")
            return
        if key == "exiftool":
            self.exiftool_pick()
            return
        if key == "deauth":
            ok = QMessageBox.warning(
                self, "Authorization required",
                "WiFi deauthentication is an ACTIVE ATTACK.\n\n"
                "Only use it on networks you own or are explicitly "
                "authorized to test (your lab, a client engagement).\n\n"
                "Proceed to the guided terminal?",
                QMessageBox.Ok | QMessageBox.Cancel,
                QMessageBox.Cancel)
            if ok != QMessageBox.Ok:
                return
        if key == "phoneinfoga":
            n = self.phone.text().strip()
            if not n.startswith("+"):
                QMessageBox.information(
                    self, "Need a phone number",
                    "Type the number in +E164 format (e.g. +15551234567).")
                return
        number, email = self.phone.text().strip(), self.email.text().strip()
        if key in EXTERNAL_ONLY:
            run_tool(key, d, u, number, email,
                     lambda k: self.status.setText(
                         f"{k} launched (external terminal)"),
                     user=self.operator)
        elif key == "emailhdr":
            self.email_dialog()
        elif key == "wayback":
            self.wayback_lookup(d)
        elif key == "video":
            vurl = self.url.text().strip()
            if not vurl.startswith("http"):
                QMessageBox.information(self, "Need a URL",
                                        "Paste a video/image URL first.")
                return
            self.console_run(key, d, u, number, email, url=vurl)
        else:
            self.console_run(key, d, u, number, email)

    # ---- console tab (docked tool output)
    def console_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        head = QLabel("CONSOLE — tools run docked here "
                      "(sudo tools still open a terminal)")
        head.setObjectName("title")
        head.setAlignment(Qt.AlignCenter)
        lay.addWidget(head)
        self.console_log = QTextEdit()
        self.console_log.setReadOnly(True)
        self.console_log.setMinimumHeight(260)
        lay.addWidget(self.console_log, 1)
        row = QHBoxLayout()
        self.console_in = QLineEdit()
        self.console_in.setPlaceholderText(
            "type here, Enter sends to the running tool "
            "(e.g. recon-ng commands)")
        self.console_in.returnPressed.connect(self._console_send)
        send = QPushButton("Send")
        send.clicked.connect(self._console_send)
        stop = QPushButton("Stop")
        stop.clicked.connect(self._console_stop)
        row.addWidget(self.console_in, 1)
        row.addWidget(send)
        row.addWidget(stop)
        lay.addLayout(row)
        self.proc = None
        self.proc_key = ""
        self._stopping = False
        try:
            from dossier import clean as _clean
        except ImportError:
            _clean = lambda s: re.sub(r"\x1b\[[0-9;]*m", "", s)  # noqa: E731
        self._clean = _clean
        return w

    def console_run(self, key, domain, username, number, email, url=""):
        from PySide6.QtCore import QProcess
        if not self._U.can_run(self.operator, key):
            self.status.setText(f"{key}: not authorized")
            return
        built = build_argv(key, domain, username, number, email, url)
        if not built:
            self.console_log.append(
                f"[{key}: nothing to run — check the required input]")
            self.status.setText(f"{key}: missing input")
            return
        argv, workdir = built
        if self.proc is not None and self.proc.state() != QProcess.NotRunning:
            self._console_stop(silent=True)
            self.console_log.append("--- previous run stopped ---")
        self.console_log.append(f"\n$ {' '.join(argv)}\n")
        self.proc = QProcess(self)
        self.proc.setWorkingDirectory(workdir)
        self.proc.setProcessChannelMode(QProcess.MergedChannels)
        self.proc.readyReadStandardOutput.connect(self._console_read)
        self.proc.finished.connect(self._console_done)
        self.proc.start(argv[0], argv[1:])
        if not self.proc.waitForStarted(5000):
            self.console_log.append(
                "FAILED to start — is the tool installed? "
                "(see installer self-test)")
            self.proc = None
            return
        self.proc_key = key
        self.status.setText(f"{key} running — see Console tab")
        self.tabs.setCurrentWidget(self.console_page)
        if key == "spiderfoot":
            self.status.setText("spiderfoot starting…")
            _open_when_up()

    def _console_read(self):
        if not self.proc:
            return
        try:
            chunk = bytes(
                self.proc.readAllStandardOutput()).decode("utf-8",
                                                          errors="replace")
        except Exception:                                       # noqa: BLE001
            return
        text = self._clean(chunk)
        if text.strip():
            from PySide6.QtGui import QTextCursor
            cur = self.console_log.textCursor()
            cur.movePosition(QTextCursor.End)
            cur.insertText(text if text.endswith("\n") else text + "\n")
            self.console_log.setTextCursor(cur)

    def _console_done(self, code, status):
        from PySide6.QtCore import QProcess
        key = self.proc_key or "tool"
        if getattr(self, "_stopping", False):
            self.console_log.append(f"\n[{key} stopped]")
            self._stopping = False  # consumed — _console_stop won't repeat it
        elif status == QProcess.CrashExit:
            self.console_log.append(f"\n[{key} crashed, exit {code}]")
        else:
            self.console_log.append(f"\n[{key} finished, exit {code}]")
        self.status.setText(f"{key} finished (exit {code})")

    def _console_send(self):
        from PySide6.QtCore import QProcess
        if not self.proc or self.proc.state() == QProcess.NotRunning:
            return
        line = self.console_in.text()
        self.proc.write((line + "\n").encode())
        from PySide6.QtGui import QTextCursor
        cur = self.console_log.textCursor()
        cur.movePosition(QTextCursor.End)
        cur.insertText(f"> {line}\n")
        self.console_log.setTextCursor(cur)
        self.console_in.clear()

    def _console_stop(self, silent=False):
        from PySide6.QtCore import QProcess
        if self.proc and self.proc.state() != QProcess.NotRunning:
            self._stopping = True
            self.proc.kill()
            self.proc.waitForFinished(3000)
            if not silent and self._stopping:
                # finished slot never ran (edge) — note it here
                self.console_log.append("[stopped]")
            self._stopping = False
            self.status.setText(f"{self.proc_key} stopped")

    # ---- dorks tab (zero-key Google dork pack)
    def dorks_tab(self):
        from PySide6.QtWidgets import QFrame, QScrollArea
        inner = QWidget()
        lay = QVBoxLayout(inner)
        head = QLabel("DORKS — search indexes, zero keys needed")
        head.setObjectName("title")
        head.setAlignment(Qt.AlignCenter)
        lay.addWidget(head)
        note = QLabel("Tap a dork to open it in your browser, scoped to the "
                      "domain. Indexed does not mean still there — verify "
                      "live before reporting anything.")
        note.setObjectName("desc")
        note.setWordWrap(True)
        lay.addWidget(note)
        self.dork_domain = QLineEdit()
        self.dork_domain.setPlaceholderText(
            "scope domain  (e.g. example.com — empty = whole web)")
        lay.addWidget(self.dork_domain)
        engrow = QHBoxLayout()
        englab = QLabel("Search with:")
        englab.setObjectName("desc")
        from PySide6.QtWidgets import QComboBox
        self.dork_engine = QComboBox()
        self.dork_engine.addItems(["Google", "Bing", "DuckDuckGo", "Brave"])
        self.dork_engine.setToolTip(
            "Different engines, different rate limits — if one says no, "
            "try another. Same dork, same domain.")
        engrow.addWidget(englab)
        engrow.addWidget(self.dork_engine, 1)
        lay.addLayout(engrow)
        grid = QGridLayout()
        lay.addLayout(grid)
        for i, (cat, desc, dorks) in enumerate(DORK_SETS):
            card = QFrame()
            card.setObjectName("card")
            cl = QVBoxLayout(card)
            t = QLabel(cat)
            t.setObjectName("card")
            d = QLabel(desc)
            d.setObjectName("desc")
            d.setWordWrap(True)
            cl.addWidget(t)
            cl.addWidget(d)
            for label, template in dorks:
                b = QPushButton(label)
                b.setToolTip(template)
                b.clicked.connect(
                    lambda _=False, tp=template: self._open_dork(tp))
                cl.addWidget(b)
            cl.addStretch(1)
            grid.addWidget(card, i // 3, i % 3)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(inner)
        wrap = QWidget()
        wraplay = QVBoxLayout(wrap)
        wraplay.addWidget(scroll)
        return wrap

    def _open_dork(self, template):
        d = self.dork_domain.text().strip()
        engine = self.dork_engine.currentText()
        url = dork_url(template, d, engine)
        subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        shown = f"site:{d} {template}" if d else template
        self.status.setText(f"dork opened ({engine}): {shown}")

    def console_print(self, text):
        """Native output line in the Console tab (non-QProcess sources)."""
        from PySide6.QtGui import QTextCursor
        cur = self.console_log.textCursor()
        cur.movePosition(QTextCursor.End)
        cur.insertText(text if text.endswith("\n") else text + "\n")
        self.console_log.setTextCursor(cur)

    def _open_reviso(self, engine):
        u = self.url.text().strip()
        if not u.startswith("http"):
            QMessageBox.information(self, "Need a URL",
                                    "Paste a video/image URL first.")
            return
        import urllib.parse
        if engine == "lens":
            link = ("https://lens.google.com/uploadbyurl?url="
                    + urllib.parse.quote(u, safe=""))
        else:
            link = ("https://tineye.com/search?url="
                    + urllib.parse.quote(u, safe=""))
        subprocess.Popen(["xdg-open", link], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        self.status.setText(f"reverse search opened ({engine})")

    def _open_archive_fallback(self, domain):
        link = f"https://web.archive.org/web/*/{domain}"
        subprocess.Popen(["xdg-open", link], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        self.status.setText("archive lookup opened in browser")

    def wayback_lookup(self, domain):
        import urllib.parse
        import urllib.request
        self.tabs.setCurrentWidget(self.console_page)
        self.console_print(f"$ wayback {domain}")
        q = urllib.parse.quote(domain + "/*", safe="")
        api = (f"https://web.archive.org/cdx/search/cdx?url={q}"
               "&output=text&fl=timestamp,original,statuscode"
               "&collapse=urlkey&limit=60")
        try:
            req = urllib.request.Request(api,
                                         headers={"User-Agent": "AEGIS-panel"})
            raw = urllib.request.urlopen(req, timeout=30).read().decode(
                "utf-8", errors="replace")
        except Exception as exc:                                # noqa: BLE001
            self.console_print(f"archive unreachable ({exc}) — "
                               "opening live lookup instead")
            self._open_archive_fallback(domain)
            return
        rows = [l.split(" ") for l in raw.splitlines() if l.strip()]
        if not rows or len(rows[0]) < 3 or not rows[0][0].isdigit():
            # IA serves its HTML "temporarily offline" page with HTTP 200
            self.console_print("archive is napping (non-CDX reply) — "
                               "opening live lookup instead")
            self._open_archive_fallback(domain)
            return
        good = [r for r in rows if len(r) >= 3 and r[2].startswith("2")]
        for ts, url, code in rows[:60]:
            self.console_print(f"{ts} {code} {url}")
        if good:
            ts, url, _ = good[-1]
            link = f"https://web.archive.org/web/{ts}/{url}"
            self.console_print(f"opening latest good capture: {link}")
            subprocess.Popen(["xdg-open", link], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        else:
            self.console_print("no good captures in range — "
                               "opening live lookup")
            self._open_archive_fallback(domain)
        self.status.setText(
            f"wayback: {len(rows)} snapshots, {len(good)} good")

    def email_dialog(self):
        from PySide6.QtWidgets import QDialog
        try:
            from dossier import analyze_email_headers
        except ImportError:
            QMessageBox.warning(self, "Missing engine",
                                "dossier.py must sit next to panel.py.")
            return
        dlg = QDialog(self)
        dlg.setWindowTitle("Email headers — route analysis (offline)")
        dlg.resize(620, 520)
        lay = QVBoxLayout(dlg)
        lay.addWidget(QLabel("Paste raw headers below, then Analyze:"))
        src = QTextEdit()
        src.setPlaceholderText("From: ...\nReceived: ...\n...")
        lay.addWidget(src, 1)
        go = QPushButton("Analyze")
        lay.addWidget(go)
        out = QTextEdit()
        out.setReadOnly(True)
        lay.addWidget(out, 1)
        def _go():
            lines, warns = analyze_email_headers(src.toPlainText())
            show = list(lines)
            if warns:
                show += ["", "FLAGS:"] + [f"! {w}" for w in warns]
            out.setPlainText("\n".join(show) if show
                             else "(nothing parseable — paste raw headers)")
            self.status.setText("headers analyzed (offline)")
        go.clicked.connect(_go)
        dlg.exec()

    # ---- system tab (build screen: machine + AEGIS + link status)
    def sysinfo_tab(self):
        from PySide6.QtWidgets import QFormLayout, QScrollArea
        w = QWidget()
        lay = QVBoxLayout(w)
        head = QLabel("SYSTEM — this machine, this build")
        head.setObjectName("title")
        head.setAlignment(Qt.AlignCenter)
        lay.addWidget(head)
        self.sys_form = QFormLayout()
        box = QWidget()
        box.setLayout(self.sys_form)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(box)
        lay.addWidget(scroll, 1)
        self.tc_label = QLabel("ThinkCentre: probing…")
        self.tc_label.setObjectName("desc")
        lay.addWidget(self.tc_label)
        row = QHBoxLayout()
        ref = QPushButton("Refresh")
        ref.clicked.connect(self._sys_refresh)
        row.addStretch(1)
        row.addWidget(ref)
        lay.addLayout(row)
        self._sys_refresh()
        return w

    def _sys_refresh(self):
        from PySide6.QtCore import QTimer
        while self.sys_form.rowCount():
            self.sys_form.removeRow(0)
        for k, v in sys_info():
            lab = QLabel(str(v))
            lab.setObjectName("desc" if k in ("Panel",) else "")
            lab.setTextInteractionFlags(
                lab.textInteractionFlags() | Qt.TextSelectableByMouse)
            self.sys_form.addRow(f"{k}:", lab)
        self.tc_label.setText("ThinkCentre: probing…")
        QTimer.singleShot(50, self._tc_probe)

    def _tc_probe(self):
        try:
            got = tc_probe()
        except Exception:                                   # noqa: BLE001
            got = {}
        self.tc_label.setText(
            "ThinkCentre "
            f"{TC_HOST} — ssh:{got.get(22, '?')} "
            f"http:{got.get(80, '?')} ollama:{got.get(11434, '?')}")

    # ---- users tab (admin only: operators + per-tool grants)
    def users_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        head = QLabel("OPERATORS — who may run what")
        head.setObjectName("title")
        head.setAlignment(Qt.AlignCenter)
        lay.addWidget(head)
        note = QLabel("Passwords are hashed (PBKDF2), never stored. "
                      "New accounts start with nothing — grant explicitly. "
                      "The last admin cannot be deleted.")
        note.setObjectName("desc")
        note.setWordWrap(True)
        lay.addWidget(note)
        self._users_box = QVBoxLayout()
        lay.addLayout(self._users_box)
        addrow = QHBoxLayout()
        self._new_name = QLineEdit()
        self._new_name.setPlaceholderText("new operator name")
        self._new_pass = QLineEdit()
        self._new_pass.setPlaceholderText("password")
        self._new_pass.setEchoMode(QLineEdit.Password)
        self._new_admin = QCheckBox("admin")
        addbtn = QPushButton("Add")
        addbtn.clicked.connect(self._user_add)
        addrow.addWidget(self._new_name, 1)
        addrow.addWidget(self._new_pass, 1)
        addrow.addWidget(self._new_admin)
        addrow.addWidget(addbtn)
        lay.addLayout(addrow)
        lay.addStretch(1)
        self._users_refresh()
        return w

    def _users_refresh(self):
        while self._users_box.count():
            item = self._users_box.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for name in self._U.list_users():
            rec = self._U.load().get(name, {})
            row = QHBoxLayout()
            lab = QLabel(f"{name}"
                         + ("  [admin]" if rec.get("admin") else ""))
            if not rec.get("admin"):
                tools = rec.get("tools", [])
                lab.setToolTip(f"{len(tools)} tools: "
                               + ", ".join(tools[:12])
                               + ("…" if len(tools) > 12 else ""))
            edit = QPushButton("Grants…")
            edit.clicked.connect(
                lambda _=False, n=name: self._grants_dialog(n))
            dele = QPushButton("Delete")
            dele.clicked.connect(
                lambda _=False, n=name: self._user_delete(n))
            row.addWidget(lab, 1)
            row.addWidget(edit)
            row.addWidget(dele)
            wrap = QWidget()
            wrap.setLayout(row)
            self._users_box.addWidget(wrap)

    def _user_add(self):
        if not self._U.is_admin(self.operator):
            return
        ok, note = self._U.add_user(self._new_name.text(),
                                    self._new_pass.text(),
                                    admin=self._new_admin.isChecked())
        if not ok:
            QMessageBox.warning(self, "Add operator", note)
            return
        self._new_name.clear()
        self._new_pass.clear()
        self._new_admin.setChecked(False)
        self._users_refresh()
        self.status.setText(note)

    def _user_delete(self, name):
        if not self._U.is_admin(self.operator):
            return
        if name == self.operator.get("name"):
            QMessageBox.warning(self, "Delete operator",
                                "You cannot delete yourself mid-shift.")
            return
        ok = QMessageBox.question(
            self, "Delete operator",
            f"Remove {name}? Their grants vanish with them.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No)
        if ok != QMessageBox.Yes:
            return
        good, note = self._U.delete_user(name)
        if not good:
            QMessageBox.warning(self, "Delete operator", note)
            return
        self._users_refresh()
        self.status.setText(note)

    def _grants_dialog(self, name):
        if not self._U.is_admin(self.operator):
            return
        from PySide6.QtWidgets import (QCheckBox, QDialog, QFormLayout,
                                       QScrollArea)
        rec = self._U.load().get(name, {})
        if not rec:
            return
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Grants — {name}")
        dlg.resize(420, 560)
        lay = QVBoxLayout(dlg)
        admin = QCheckBox("admin (everything, incl. Users tab)")
        admin.setChecked(bool(rec.get("admin")))
        lay.addWidget(admin)
        grades = QLabel("Tool grants (ignored for admins):")
        grades.setObjectName("desc")
        lay.addWidget(grades)
        box = QWidget()
        form = QFormLayout(box)
        current = set(rec.get("tools", []))
        checks = {}
        for tname, desc, tkey in CARDS:
            cb = QCheckBox(tname)
            cb.setToolTip(desc)
            cb.setChecked(tkey in current)
            form.addRow(cb)
            checks[tkey] = cb
        tabs = rec.get("tabs", {})
        tchecks = {}
        for t in ("dossier", "dorks", "keys"):
            cb = QCheckBox(f"{t} tab")
            cb.setChecked(bool(tabs.get(t)))
            form.addRow(cb)
            tchecks[t] = cb
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(box)
        lay.addWidget(scroll, 1)
        save = QPushButton("Save grants")
        def _save():
            tools = [k for k, cb in checks.items() if cb.isChecked()]
            tbs = {t: cb.isChecked() for t, cb in tchecks.items()}
            good, note = self._U.set_grants(
                name, admin=admin.isChecked(), tools=tools, tabs=tbs)
            if not good:
                QMessageBox.warning(dlg, "Grants", note)
                return
            self._users_refresh()
            self.status.setText(note)
            dlg.accept()
        save.clicked.connect(_save)
        lay.addWidget(save)
        dlg.exec()

    def exiftool_pick(self):
        from PySide6.QtWidgets import QDialog, QFileDialog, QTextEdit
        path, _ = QFileDialog.getOpenFileName(
            self, "Attach a photo",
            os.path.expanduser("~/Pictures"),
            "Images (*.jpg *.jpeg *.png *.tiff *.heic *.webp);;All files (*)")
        if not path:
            return
        exe = (shutil.which("exiftool")
               or f"{TOOLS}/Image-ExifTool-13.55/exiftool")
        try:
            hi = subprocess.run(
                [exe, "-s", "-s", "-s",
                 "-GPSLatitude", "-GPSLongitude", "-GPSPosition",
                 "-Make", "-Model", "-CreateDate", "-DateTimeOriginal",
                 "-Artist", "-Author", "-Software", path],
                capture_output=True, text=True, timeout=60).stdout
            full = subprocess.run(
                [exe, path],
                capture_output=True, text=True, timeout=60).stdout
        except Exception as exc:                                # noqa: BLE001
            QMessageBox.warning(self, "ExifTool failed", str(exc))
            return
        lines = [l for l in hi.splitlines() if l.strip()]
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Metadata — {os.path.basename(path)}")
        dlg.resize(560, 460)
        lay = QVBoxLayout(dlg)
        gps = [l for l in lines if re.match(r"-?\d+\.\d+", l)]
        lay.addWidget(QLabel(
            "GPS found — verify on a map before acting:"
            if gps else "Highlights:"))
        txt = QTextEdit()
        txt.setReadOnly(True)
        txt.setPlainText("\n".join(lines) if lines else
                         "(no GPS / device / author tags found)")
        lay.addWidget(txt)
        lay.addWidget(QLabel("Full dump:"))
        full_txt = QTextEdit()
        full_txt.setReadOnly(True)
        full_txt.setPlainText(full)
        lay.addWidget(full_txt)
        dlg.exec()
        self.status.setText(f"exiftool -> {os.path.basename(path)}")

    # ---- dossier tab
    def dossier_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        head = QLabel("BACKGROUND DOSSIER — one subject, full sweep")
        head.setObjectName("title")
        head.setAlignment(Qt.AlignCenter)
        lay.addWidget(head)
        self.case = QLineEdit()
        self.case.setPlaceholderText("case name  (e.g. smith-j-2026)")
        self.ddomain = QLineEdit()
        self.ddomain.setPlaceholderText("domain  (optional if username given)")
        self.duser = QLineEdit()
        self.duser.setPlaceholderText("username  (optional)")
        self.dphone = QLineEdit()
        self.dphone.setPlaceholderText("phone +E164  (optional)")
        self.demail = QLineEdit()
        self.demail.setPlaceholderText("email  (optional)")
        lay.addWidget(self.case)
        lay.addWidget(self.ddomain)
        lay.addWidget(self.duser)
        lay.addWidget(self.dphone)
        lay.addWidget(self.demail)
        self.durl = QLineEdit()
        self.durl.setPlaceholderText("video/image URL  (optional)")
        lay.addWidget(self.durl)
        self.photo_path = ""
        self.headers_path = ""
        attachrow = QHBoxLayout()
        photobtn = QPushButton("Attach photo…")
        photobtn.clicked.connect(self._pick_photo)
        headersbtn = QPushButton("Attach headers…")
        headersbtn.clicked.connect(self._pick_headers)
        self.attach_label = QLabel("attachments: none")
        self.attach_label.setObjectName("desc")
        attachrow.addWidget(photobtn)
        attachrow.addWidget(headersbtn)
        attachrow.addWidget(self.attach_label, 1)
        lay.addLayout(attachrow)
        notelab = QLabel("field notes (your context, appended verbatim):")
        notelab.setObjectName("desc")
        lay.addWidget(notelab)
        self.dnotes = QTextEdit()
        self.dnotes.setPlaceholderText("What do you know that the tools "
                                       "don't? Goes into the report as-is.")
        self.dnotes.setMaximumHeight(80)
        lay.addWidget(self.dnotes)
        row = QHBoxLayout()
        row.addWidget(QLabel("Skip slow ones:"))
        self.skip_amass = QCheckBox("Amass")
        self.skip_sher = QCheckBox("Sherlock")
        self.skip_nmap = QCheckBox("Nmap (active)")
        for c in (self.skip_amass, self.skip_sher, self.skip_nmap):
            row.addWidget(c)
        lay.addLayout(row)
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Skip slow ones (2):"))
        self.skip_pagodo = QCheckBox("Pagodo (~10min)")
        self.skip_photon = QCheckBox("Photon (slow)")
        self.skip_maigret = QCheckBox("Maigret (slow)")
        for c in (self.skip_pagodo, self.skip_photon, self.skip_maigret):
            row2.addWidget(c)
        lay.addLayout(row2)
        auth = QLabel("Active probing (nmap) only against authorized targets.")
        auth.setObjectName("desc")
        lay.addWidget(auth)
        go = QPushButton("Build dossier")
        go.setObjectName("go")
        go.clicked.connect(self.build)
        lay.addWidget(go)
        self.go_btn = go
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(180)
        lay.addWidget(self.log)
        brow = QHBoxLayout()
        self.open_report = QPushButton("Open report")
        self.open_report.clicked.connect(self._open_report)
        self.open_folder = QPushButton("Open case folder")
        self.open_folder.clicked.connect(self._open_folder)
        self.export = QPushButton("Export zip")
        self.export.clicked.connect(self._export)
        self.print_btn = QPushButton("Print / PDF")
        self.print_btn.clicked.connect(self._print_report)
        self.print_btn.setToolTip("Opens the styled report in your "
                                  "browser — Print there → Save as PDF")
        for b in (self.open_report, self.open_folder, self.export,
                  self.print_btn):
            brow.addWidget(b)
        lay.addLayout(brow)
        histrow = QHBoxLayout()
        histlab = QLabel("past cases:")
        histlab.setObjectName("desc")
        from PySide6.QtWidgets import QComboBox
        self.case_pick = QComboBox()
        self.case_pick.setToolTip("Reopen any previous case")
        self.case_pick.activated.connect(self._pick_case)
        histgo = QPushButton("Refresh")
        histgo.clicked.connect(self._refresh_cases)
        histdel = QPushButton("Delete")
        histdel.setToolTip("Permanently delete the selected case")
        histdel.clicked.connect(self._delete_case)
        histrow.addWidget(histlab)
        histrow.addWidget(self.case_pick, 1)
        histrow.addWidget(histgo)
        histrow.addWidget(histdel)
        lay.addLayout(histrow)
        self.cdir = None
        self._refresh_cases(silent=True)
        return w

    def _cases_dir(self):
        return os.path.join(TOOLS, "cases")

    def _refresh_cases(self, silent=False):
        try:
            names = sorted((d for d in os.listdir(self._cases_dir())
                            if os.path.isdir(
                                os.path.join(self._cases_dir(), d))),
                           reverse=True)
        except OSError:
            names = []
        self.case_pick.clear()
        self.case_pick.addItem("— pick a past case —")
        for n in names[:50]:
            self.case_pick.addItem(n)
        if not silent:
            self.status.setText(f"{len(names)} past cases")

    def _pick_case(self, idx):
        if idx <= 0:
            return
        name = os.path.basename(self.case_pick.itemText(idx))
        cdir = os.path.realpath(os.path.join(self._cases_dir(), name))
        if os.path.dirname(cdir) != os.path.realpath(self._cases_dir()):
            return
        rep = os.path.join(cdir, "REPORT.md")
        if os.path.isfile(rep):
            self.cdir = cdir
            self.status.setText(f"case reopened: {cdir}")
            self.log.append(f"Reopened {name} — report buttons live.")
        else:
            self.status.setText(f"{name}: no REPORT.md inside")

    def _delete_case(self):
        name = os.path.basename(self.case_pick.currentText())
        target = os.path.realpath(os.path.join(self._cases_dir(), name))
        if name.startswith("—") or os.path.dirname(target) != os.path.realpath(
                self._cases_dir()):
            return
        ok = QMessageBox.question(
            self, "Delete case",
            f"Permanently delete {name}?\nRaw evidence goes with it.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if ok != QMessageBox.Yes:
            return
        try:
            import shutil
            shutil.rmtree(target)
            if self.cdir and os.path.realpath(self.cdir) == target:
                self.cdir = None
            self._refresh_cases(silent=True)
            self.status.setText(f"deleted: {name}")
            self.log.append(f"Deleted {name}.")
        except OSError as exc:                                # noqa: BLE001
            QMessageBox.warning(self, "Delete case", str(exc))

    def _print_report(self):
        if self.cdir:
            subprocess.Popen(["xdg-open", f"{self.cdir}/REPORT.html"],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            self.status.setText("report opened — Print → Save as PDF")

    def _pick_photo(self):
        from PySide6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getOpenFileName(
            self, "Attach evidence photo",
            os.path.expanduser("~/Pictures"),
            "Images (*.jpg *.jpeg *.png *.tiff *.heic *.webp)")
        if path:
            self.photo_path = path
            self._attach_refresh()

    def _attach_refresh(self):
        bits = []
        if self.photo_path:
            bits.append(os.path.basename(self.photo_path))
        if self.headers_path:
            bits.append(os.path.basename(self.headers_path))
        self.attach_label.setText(
            "attachments: " + ", ".join(bits) if bits
            else "attachments: none")

    def _pick_headers(self):
        from PySide6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getOpenFileName(
            self, "Attach headers file (raw .txt)",
            os.path.expanduser("~"),
            "Text (*.txt *.eml);;All files (*)")
        if path:
            self.headers_path = path
            self._attach_refresh()

    def build(self):
        case = self.case.text().strip()
        if not case:
            QMessageBox.information(self, "Need a case name",
                                    "Name the case first (e.g. smith-j-2026).")
            return
        if not any([self.ddomain.text().strip(), self.duser.text().strip(),
                    self.dphone.text().strip(), self.demail.text().strip(),
                    self.durl.text().strip(), self.headers_path,
                    self.photo_path]):
            QMessageBox.information(self, "Need a subject",
                                    "Give a domain, username, phone, email, "
                                    "URL, headers file, or photo.")
            return
        skip = set()
        if self.skip_amass.isChecked():
            skip.add("amass")
        if self.skip_sher.isChecked():
            skip.add("sherlock")
        if self.skip_nmap.isChecked():
            skip.add("nmap")
        if self.skip_pagodo.isChecked():
            skip.add("pagodo")
        if self.skip_photon.isChecked():
            skip.add("photon")
        if self.skip_maigret.isChecked():
            skip.add("maigret")
        self.log.clear()
        self.log.append("Starting — tools run in sequence, gaps never abort.")
        self.go_btn.setEnabled(False)
        self.go_btn.setText("Building… (watch the log)")
        self.thread = DossierThread(case, self.ddomain.text().strip(),
                                    self.duser.text().strip(), skip)
        self.thread.phone = self.dphone.text().strip()
        self.thread.email = self.demail.text().strip()
        self.thread.photo = self.photo_path
        self.thread.url = self.durl.text().strip()
        self.thread.headers_file = self.headers_path
        self.thread.notes = self.dnotes.toPlainText().strip()
        self.thread.operator = self.operator.get("name", "?")
        if self._U.is_admin(self.operator):
            self.thread.allowed = None  # admins: everything
        else:
            self.thread.allowed = set(self.operator.get("tools", []))
        self.thread.line.connect(self.log.append)
        self.thread.done.connect(self._done)
        self.thread.start()

    def _done(self, cdir):
        self.go_btn.setEnabled(True)
        self.go_btn.setText("Build dossier")
        if not cdir:
            self.status.setText("dossier failed — see log")
            return
        self.cdir = cdir
        self.status.setText(f"dossier ready: {cdir}")
        self.log.append("Done. REPORT.md + REPORT.html compiled.")

    # ---- keys tab
    def keys_tab(self):
        import keys as K
        w = QWidget()
        lay = QVBoxLayout(w)
        head = QLabel("API KEYS — unlock the tools' full sources")
        head.setObjectName("title")
        head.setAlignment(Qt.AlignCenter)
        lay.addWidget(head)
        note = QLabel("Keys live only in ~/.config/aegis/keys.json (mode 600). "
                      "Deploy writes them into recon-ng + theHarvester configs "
                      "on this machine — nowhere else.")
        note.setObjectName("desc")
        note.setWordWrap(True)
        lay.addWidget(note)
        from PySide6.QtWidgets import QFormLayout
        form = QFormLayout()
        self._key_rows = {}
        for name, (use, _, _) in K.KNOWN.items():
            row = QHBoxLayout()
            lab = QLabel(f"{name}")
            lab.setToolTip(use)
            st = QLabel()
            st.setObjectName("desc")
            setbtn = QPushButton("Set")
            setbtn.clicked.connect(
                lambda _=False, n=name: self._key_set(n))
            clrbtn = QPushButton("Clear")
            clrbtn.clicked.connect(
                lambda _=False, n=name: self._key_clear(n))
            row.addWidget(lab, 1)
            row.addWidget(st, 1)
            row.addWidget(setbtn)
            row.addWidget(clrbtn)
            form.addRow(f"{name} — {use}", row)
            self._key_rows[name] = st
        lay.addLayout(form)
        self._keys_refresh()
        dep = QPushButton("Deploy keys to tools")
        dep.setObjectName("go")
        dep.clicked.connect(self._keys_deploy)
        lay.addWidget(dep)
        return w

    def _keys_refresh(self):
        import keys as K
        for name, st in self._key_rows.items():
            st.setText(K.masked(K.load()).get(name, "—"))

    def _key_set(self, name):
        from PySide6.QtWidgets import QInputDialog, QLineEdit
        if not self._U.can_tab(self.operator, "keys"):
            return
        import keys as K
        val, ok = QInputDialog.getText(
            self, f"Set {name}", K.KNOWN[name][0] + ":",
            QLineEdit.Password)
        if ok and val.strip():
            allk = K.load()
            allk[name] = val.strip()
            K.save(allk)
            self._keys_refresh()
            self.status.setText(f"key stored: {name}")

    def _key_clear(self, name):
        if not self._U.can_tab(self.operator, "keys"):
            return
        import keys as K
        allk = K.load()
        allk.pop(name, None)
        K.save(allk)
        self._keys_refresh()

    def _keys_deploy(self):
        if not self._U.can_tab(self.operator, "keys"):
            return
        import keys as K
        ok, notes = K.deploy(K.load())
        QMessageBox.information(self, "Deploy",
                                "\n".join(notes) + f"\n\n{ok} values written.")
        self.status.setText("keys deployed")

    def _open_report(self):
        if self.cdir:
            subprocess.Popen(["xdg-open", f"{self.cdir}/REPORT.md"],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)

    def _open_folder(self):
        if self.cdir:
            subprocess.Popen(["xdg-open", self.cdir],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)

    def _export(self):
        if not self.cdir:
            return
        try:
            dest = f"{self.cdir}.zip"
            with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(self.cdir):
                    for f in files:
                        p = os.path.join(root, f)
                        zf.write(p, os.path.relpath(p, os.path.dirname(self.cdir)))
            self.status.setText(f"exported: {dest}")
            subprocess.Popen(["xdg-open", os.path.dirname(dest)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as exc:                                # noqa: BLE001
            QMessageBox.warning(self, "Export", str(exc))


def _prompt_creds(parent, title, subtitle, need_confirm=False):
    """Username + password dialog. Returns (name, pw) or (None, None)."""
    from PySide6.QtWidgets import QDialog, QFormLayout, QDialogButtonBox
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    lay = QVBoxLayout(dlg)
    sub = QLabel(subtitle)
    sub.setObjectName("desc")
    sub.setWordWrap(True)
    lay.addWidget(sub)
    form = QFormLayout()
    name = QLineEdit()
    pw = QLineEdit()
    pw.setEchoMode(QLineEdit.Password)
    form.addRow("Operator:", name)
    form.addRow("Password:", pw)
    pw2 = None
    if need_confirm:
        pw2 = QLineEdit()
        pw2.setEchoMode(QLineEdit.Password)
        form.addRow("Confirm:", pw2)
    lay.addLayout(form)
    btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
    btns.accepted.connect(dlg.accept)
    btns.rejected.connect(dlg.reject)
    lay.addWidget(btns)
    if dlg.exec() != QDialog.Accepted:
        return None, None
    if need_confirm and pw.text() != pw2.text():
        QMessageBox.warning(parent, title, "Passwords do not match.")
        return None, None
    return name.text().strip(), pw.text()


def login_flow():
    """Gate: first run creates the admin, otherwise 3 login tries.
    Returns a user dict, or None (quit)."""
    import users as U
    if not U.list_users():
        for _ in range(3):
            name, pw = _prompt_creds(
                None, "Create admin",
                "No operators yet. Create the admin account — full "
                "access, manages everyone else. This shows once.",
                need_confirm=True)
            if name is None:
                return None
            ok, note = U.add_user(name, pw, admin=True)
            if ok:
                return U.verify(name, pw)
        return None
    for _ in range(3):
        name, pw = _prompt_creds(None, "AEGIS OSINT Panel",
                                 "Operator login. Three tries, then out.")
        if name is None:
            return None
        user = U.verify(name, pw)
        if user:
            return user
    return None


if __name__ == "__main__":
    import sys
    from PySide6.QtGui import QIcon
    app = QApplication(sys.argv)
    app.setApplicationName("AEGIS OSINT Panel")
    # Binds the window to OSINT-Panel.desktop so the taskbar shows the
    # desktop icon instead of a generic gear.
    try:
        app.setDesktopFileName("OSINT-Panel")
    except AttributeError:
        pass  # Qt < 5.7: WM_CLASS fallback below still applies
    app.setWindowIcon(QIcon.fromTheme("security-high"))
    me = login_flow()
    if me is None:
        sys.exit(0)
    win = Panel(me)  # keep a reference: unreferenced windows GC unmapped
    win.show()
    sys.exit(app.exec())
