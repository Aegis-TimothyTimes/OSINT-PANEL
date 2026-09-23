#!/usr/bin/env python3
"""
AEGIS dossier engine — one subject in, background dossier out.

Runs the user-local OSINT stack against a case (domain and/or username),
collects raw outputs, and compiles REPORT.md: findings first, then methods,
then gaps. A failed tool degrades to a logged gap — it never aborts the run.

AUTHORIZATION: active probing (nmap) must only target systems you are
authorized to test. Passive sources (crt.sh, OSINT aggregators) are
public-data lookups. The report header records this distinction.

    python3 dossier.py --case CASE --domain example.com --username jdoe
    python3 dossier.py --case CASE --domain example.com --skip sherlock,amass

Cases land in ~/osint-tools/cases/CASE_<stamp>/ with raw/ + REPORT.md.
"""
import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys

HOME = os.path.expanduser("~")
TOOLS = os.path.join(HOME, "osint-tools")
CASES = os.path.join(TOOLS, "cases")
BIN = os.path.join(HOME, ".local", "bin")

HARVESTER = os.path.join(TOOLS, "venv-harvester", "bin", "theHarvester")
AMASS = os.path.join(HOME, "bin", "amass")
SUBLIST3R = os.path.join(TOOLS, "Sublist3r", "sublist3r.py")
SHERLOCK = os.path.join(BIN, "sherlock")

# Sources verified working keyless against theHarvester 5.0.0 (2026-09-20).
# NOTE: `bing` and `threatcrowd` are NOT supported in v5 — including them
# aborts the whole run with "[!] Invalid source." Do not re-add blindly.
HARVESTER_SOURCES = "crtsh,hackertarget,otx,rapiddns,urlscan,certspotter,duckduckgo"

TIMEOUTS = {"sublist3r": 600, "harvester": 600, "amass": 900,
            "sherlock": 900, "nmap": 600, "phone": 300, "holehe": 600,
            "maigret": 900, "photon": 900, "gau": 300, "pagodo": 1200,
            "video": 300}

PHONEINFOGA = os.path.join(HOME, "bin", "phoneinfoga")
HOLEHE = os.path.join(BIN, "holehe")
EXIFTOOL = os.path.join(TOOLS, "Image-ExifTool-13.55", "exiftool")
MAIGRET = os.path.join(BIN, "maigret")
PHOTON = os.path.join(TOOLS, "Photon", "photon.py")
GAU = os.path.join(HOME, "bin", "gau")
PAGODO = os.path.join(TOOLS, "pagodo", "pagodo.py")
PAGODO_QUICK = os.path.join(TOOLS, "pagodo", "quick_dorks.txt")
YTDLP = "yt-dlp"  # PATH binary; run() reports it missing, never raises


def log(runlog, msg, on_log=None):
    line = f"{datetime.datetime.now():%H:%M:%S} {msg}"
    print(line, flush=True)
    runlog.write(line + "\n")
    runlog.flush()
    if on_log is not None:
        try:
            on_log(line)
        except Exception:                               # noqa: BLE001
            pass  # GUI gone; file log already has it


def run(cmd, outfile, timeout, runlog, cwd=None, on_log=None):
    """Run cmd -> outfile. Returns (ok, note). Never raises."""
    start = datetime.datetime.now()
    try:
        with open(outfile, "w") as fh:
            subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT,
                           timeout=timeout, cwd=cwd or HOME)
        dt = (datetime.datetime.now() - start).total_seconds()
        log(runlog, f"OK   {outfile} ({dt:.0f}s)", on_log)
        return True, f"completed in {dt:.0f}s"
    except subprocess.TimeoutExpired:
        log(runlog, f"TIMEOUT {outfile} after {timeout}s (partial kept)",
            on_log)
        return False, f"timed out after {timeout}s — partial results"
    except FileNotFoundError as exc:
        log(runlog, f"MISSING {outfile}: {exc}", on_log)
        return False, f"tool not installed: {exc}"
    except Exception as exc:                                    # noqa: BLE001
        log(runlog, f"FAIL {outfile}: {exc}", on_log)
        return False, str(exc)


ANSI = re.compile(r"\x1b\[[0-9;]*m")


def clean(line):
    return ANSI.sub("", line).strip()


def parse_subdomains(path):
    subs = set()
    try:
        with open(path, errors="replace") as fh:
            for raw in fh:
                line = clean(raw).lower()
                if re.fullmatch(r"[a-z0-9_.-]+\.[a-z]{2,}", line or ""):
                    subs.add(line)
    except OSError:
        pass
    return sorted(subs)


def parse_harvester(path):
    emails, hosts, ips = set(), set(), set()
    try:
        with open(path, errors="replace") as fh:
            for raw in fh:
                line = clean(raw)
                if "@" in line and re.fullmatch(r"[\w.+-]+@[\w.-]+\.\w+", line):
                    emails.add(line.lower())
                elif re.fullmatch(r"\d+\.\d+\.\d+\.\d+", line):
                    ips.add(line)
                elif re.fullmatch(r"[a-z0-9_.-]+\.[a-z]{2,}", line.lower()):
                    hosts.add(line.lower())
    except OSError:
        pass
    return sorted(emails), sorted(hosts), sorted(ips)


def parse_sherlock_txt(path):
    """Sherlock's --json breaks on fresh paths; parse stdout instead.
    Claimed lines look like: [+] SiteName: https://..."""
    found = []
    try:
        with open(path, errors="replace") as fh:
            for raw in fh:
                line = clean(raw)
                m = re.match(r"\[\+\]\s*(.+?):\s*(https?://\S+)", line)
                if m:
                    found.append((m.group(1).strip(), m.group(2).strip()))
    except OSError:
        pass
    return found


def parse_phone(path, max_lines=60):
    """Keep section headers + substantive lines; dork-URL floods capped."""
    out, urls = [], 0
    try:
        with open(path, errors="replace") as fh:
            for raw in fh:
                line = clean(raw).rstrip()
                if not line or set(line) <= set("*=- "):
                    continue
                if line.startswith(("http", "URL:")):
                    urls += 1
                    if urls <= 12:
                        out.append(line.strip())
                    continue
                out.append(line)
                if len(out) >= max_lines:
                    out.append(f"…({urls} lookup URLs total, see raw)")
                    break
    except OSError:
        pass
    return out


def parse_exif_highlights(path):
    hi = []
    try:
        with open(path, errors="replace") as fh:
            for raw in fh:
                line = clean(raw)
                if re.match(r"(GPS|Make|Model|Create|Date|Artist|Author|"
                            r"Software|Lens|Serial)", line):
                    hi.append(line.strip())
    except OSError:
        pass
    return hi[:30]


def parse_nmap(path):
    ports, addrs = [], ""
    try:
        with open(path, errors="replace") as fh:
            for raw in fh:
                line = clean(raw)
                m = re.match(r"(\d+/\w+)\s+(\w+)\s+(\S+)(?:\s+(.*))?", line)
                if m and m.group(2) == "open":
                    ports.append((m.group(1), m.group(3),
                                  (m.group(4) or "").strip()))
                m2 = re.match(r"Nmap scan report for (\S+)", line)
                if m2:
                    addrs = m2.group(1)
    except OSError:
        pass
    return addrs, ports


def analyze_email_headers(raw):
    """Parse raw headers -> (summary_lines, warnings). Stdlib only, fully
    offline. Shared by the panel dialog and the dossier run."""
    import email
    from email import policy
    from email.utils import getaddresses
    lines, warns = [], []
    try:
        msg = email.message_from_string(raw, policy=policy.default)
    except Exception as exc:                                # noqa: BLE001
        return [], [f"could not parse headers: {exc}"]
    for h in ("From", "To", "Date", "Subject", "Message-ID", "Reply-To",
              "X-Mailer", "User-Agent"):
        v = msg.get(h)
        if v:
            lines.append(f"{h}: {v}")
    recvd = msg.get_all("Received", [])
    lines.append(f"Hops: {len(recvd)}")
    for i, r in enumerate(reversed(recvd)):  # origin first
        hop = re.sub(r"\s+", " ",
                     str(r).replace("\n", " ").replace("\r", "")).strip()
        lines.append(f"hop{i}: {hop[:220]}")
    auth = (str(msg.get("Authentication-Results", "")) + "\n"
            + str(msg.get("Received-SPF", "")))
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(mech + r"\s*=\s*(\w+)", auth, re.I)
        verdict = m.group(1).lower() if m else "not stated"
        lines.append(f"{mech.upper()}: {verdict}")
        if verdict in ("fail", "softfail", "temperror"):
            warns.append(f"{mech.upper()} {verdict} — treat sender "
                         "claims skeptically")
    froms = [a[1] for a in getaddresses([str(msg.get("From", ""))])]
    replies = [a[1] for a in getaddresses([str(msg.get("Reply-To", ""))])]
    if replies and froms and replies[0].lower() != froms[0].lower():
        warns.append(f"Reply-To ({replies[0]}) differs from From "
                     f"({froms[0]}) — classic phish flag")
    return lines, warns


def fetch_wayback(domain, limit=100, timeout=25):
    """CDX snapshot list -> (rows, note). rows: [(ts, url, code)].
    Never raises; the Archive naps (it serves its offline page with
    HTTP 200), so shape-check the reply, not just the status."""
    import urllib.parse
    import urllib.request
    q = urllib.parse.quote(domain + "/*", safe="")
    api = (f"https://web.archive.org/cdx/search/cdx?url={q}"
           f"&output=text&fl=timestamp,original,statuscode"
           f"&collapse=urlkey&limit={limit}")
    try:
        req = urllib.request.Request(api,
                                     headers={"User-Agent": "AEGIS-dossier"})
        raw = urllib.request.urlopen(req, timeout=timeout).read().decode(
            "utf-8", errors="replace")
    except Exception as exc:                                # noqa: BLE001
        return [], f"archive unreachable ({exc})"
    rows = [l.split(" ") for l in raw.splitlines() if l.strip()]
    if not rows or len(rows[0]) < 3 or not rows[0][0].isdigit():
        return [], "archive napping (non-CDX reply) — retry later"
    return [(r[0], r[1], r[2] if len(r) > 2 else "") for r in rows], "ok"


def parse_url_list(path, cap=500):
    """One-URL-per-line outputs (gau). Returns [urls]."""
    out = []
    try:
        with open(path, errors="replace") as fh:
            for raw in fh:
                line = clean(raw)
                if line.startswith("http") and len(out) < cap:
                    out.append(line)
    except OSError:
        pass
    return out


def parse_pagodo_json(path, url_cap=10):
    """Pagodo results JSON -> (total_urls, dorks_hit, sample_urls)."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return 0, 0, []
    dorks = data.get("dorks", {})
    hit = {k: v for k, v in dorks.items()
           if isinstance(v, dict) and v.get("urls_size")}
    total = sum(v.get("urls_size", 0) for v in hit.values())
    sample = []
    for v in hit.values():
        for u in v.get("urls", []):
            if len(sample) >= url_cap:
                break
            sample.append(u)
        if len(sample) >= url_cap:
            break
    return total, len(hit), sample


def parse_photon_dir(photon_dir, domain):
    """Photon drops per-target files under its workdir. Harvest emails +
    subdomains/paths from whatever text it left. Returns (emails, subs)."""
    emails, subs, target = set(), set(), ""
    try:
        cands = [d for d in os.listdir(photon_dir)
                 if os.path.isdir(os.path.join(photon_dir, d))
                 and domain in d]
    except OSError:
        return [], []
    if not cands:
        return [], []
    target = sorted(cands)[-1]
    for root, _, files in os.walk(os.path.join(photon_dir, target)):
        for f in files:
            if not f.endswith((".txt", ".csv", ".json")):
                continue
            try:
                with open(os.path.join(root, f), errors="replace") as fh:
                    blob = fh.read()
            except OSError:
                continue
            for m in re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", blob):
                emails.add(m.lower())
            for m in re.findall(r"https?://([a-z0-9_.-]+\.[a-z]{2,})",
                                blob.lower()):
                if domain in m:
                    subs.add(m)
    return sorted(emails), sorted(subs)


def _go(allowed, skip, key):
    """Module runs iff not skipped AND (no grant system or explicitly
    granted). CLI passes allowed=None (machine owner = all)."""
    return key not in skip and (allowed is None or key in allowed)


def build(case, domain, username, skip, on_log=None, phone="",
          email="", photo="", url="", headers_file="", notes="",
          operator="?", allowed=None):
    case = re.sub(r"[^\w.-]+", "_", case)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M")
    cdir = os.path.join(CASES, f"{case}_{stamp}")
    if os.path.dirname(os.path.realpath(cdir)) != os.path.realpath(CASES):
        raise ValueError(f"unsafe case name: {case!r}")
    if len(notes) > 20000:
        notes = notes[:20000] + "\n[…field notes truncated at 20k…]"
    raw = os.path.join(cdir, "raw")
    os.makedirs(raw, exist_ok=True)
    runlog = open(os.path.join(cdir, "run.log"), "w")
    log(runlog, f"CASE {case} domain={domain} username={username} "
                f"skip={sorted(skip)}", on_log)

    results, gaps = {}, []
    subs_all = set()

    if domain and _go(allowed, skip, "sublist3r"):
        p = os.path.join(raw, "sublist3r.txt")
        ok, note = run([sys.executable, SUBLIST3R, "-d", domain, "-o", p],
                       p, TIMEOUTS["sublist3r"], runlog, on_log=on_log)
        subs = parse_subdomains(p)
        subs_all.update(subs)
        results["sublist3r"] = (ok, note, subs)
        if not ok:
            gaps.append(f"Sublist3r: {note}.")

    if domain and _go(allowed, skip, "harvester"):
        p = os.path.join(raw, "harvester.txt")
        ok, note = run([HARVESTER, "-d", domain, "-b", HARVESTER_SOURCES],
                       p, TIMEOUTS["harvester"], runlog,
                       cwd=os.path.join(TOOLS, "theHarvester"),
                       on_log=on_log)
        emails, hosts, ips = parse_harvester(p)
        subs_all.update(hosts)
        results["harvester"] = (ok, note, emails, hosts, ips)
        if not ok:
            gaps.append(f"theHarvester: {note}.")
        try:
            with open(p, errors="replace") as fh:
                blob = fh.read()
            if "Invalid source" in blob:
                gaps.append("theHarvester rejected a source name — Harvester "
                            "source list needs updating (see HARVESTER_SOURCES "
                            "in dossier.py). Results below are partial.")
        except OSError:
            pass

    if domain and _go(allowed, skip, "amass"):
        p = os.path.join(raw, "amass.txt")
        ok, note = run([AMASS, "enum", "-passive", "-d", domain],
                       p, TIMEOUTS["amass"], runlog, on_log=on_log)
        subs = parse_subdomains(p)
        subs_all.update(subs)
        results["amass"] = (ok, note, subs)
        if not ok:
            gaps.append(f"Amass: {note}.")

    gau_urls = []
    if domain and _go(allowed, skip, "gau"):
        p = os.path.join(raw, "gau.txt")
        ok, note = run([GAU, "--subs", "--providers", "otx,wayback",
                        domain], p, TIMEOUTS["gau"], runlog, on_log=on_log)
        gau_urls = parse_url_list(p)
        results["gau"] = (ok, note, gau_urls)
        if not ok:
            gaps.append(f"gau: {note}.")
        elif not gau_urls:
            gaps.append("gau completed with zero historic URLs.")

    ptotal, phit, psample = 0, 0, []
    if domain and _go(allowed, skip, "pagodo"):
        pj = os.path.join(raw, "pagodo.json")
        pt = os.path.join(raw, "pagodo.txt")
        pl = os.path.join(raw, "pagodo.log")
        pc = os.path.join(raw, "pagodo_console.txt")
        ok, note = run([sys.executable, PAGODO, "-d", domain,
                        "-g", PAGODO_QUICK, "-o", pj, "-s", pt, "-z", pl],
                       pc, TIMEOUTS["pagodo"], runlog,
                       cwd=os.path.join(TOOLS, "pagodo"), on_log=on_log)
        if ok:
            ptotal, phit, psample = parse_pagodo_json(pj)
        results["pagodo"] = (ok, note, ptotal, phit, psample)
        if not ok:
            gaps.append(f"Pagodo: {note}.")

    wrows, wnote = [], ""
    if domain and _go(allowed, skip, "wayback"):
        log(runlog, "wayback: querying CDX…", on_log)
        wrows, wnote = fetch_wayback(domain)
        p = os.path.join(raw, "wayback.txt")
        try:
            with open(p, "w") as fh:
                fh.write("\n".join(f"{a} {b} {c}" for a, b, c in wrows)
                         + "\n")
        except OSError:
            pass
        wgood = [r for r in wrows if len(r) > 2 and r[2].startswith("2")]
        results["wayback"] = (bool(wrows), wnote, wrows, wgood)
        log(runlog, f"wayback: {len(wrows)} snapshots ({wnote})", on_log)
        if not wrows:
            gaps.append(f"Wayback: {wnote}.")

    pemails, psubs = [], []
    if domain and _go(allowed, skip, "photon"):
        p = os.path.join(raw, "photon.txt")
        ok, note = run([sys.executable, PHOTON, "-u", domain, "-t", "10"],
                       p, TIMEOUTS["photon"], runlog,
                       cwd=os.path.join(TOOLS, "Photon"), on_log=on_log)
        pemails, psubs = parse_photon_dir(os.path.join(TOOLS, "Photon"),
                                          domain)
        subs_all.update(psubs)
        results["photon"] = (ok, note, pemails, psubs)
        if not ok:
            gaps.append(f"Photon: {note}.")

    found = []
    if username and _go(allowed, skip, "sherlock"):
        p = os.path.join(raw, "sherlock.txt")
        ok, note = run([SHERLOCK, "--no-color", username],
                       p, TIMEOUTS["sherlock"], runlog, on_log=on_log)
        found = parse_sherlock_txt(p)
        results["sherlock"] = (ok, note, found)
        if not ok:
            gaps.append(f"Sherlock: {note}.")
        elif not found:
            gaps.append("Sherlock completed with zero claimed accounts.")

    mfound = []
    if username and _go(allowed, skip, "maigret"):
        p = os.path.join(raw, "maigret.txt")
        ok, note = run([MAIGRET, username, "--timeout", "15",
                        "--top-sites", "100"],
                       p, TIMEOUTS["maigret"], runlog, on_log=on_log)
        mfound = parse_sherlock_txt(p)  # same [+] claim-line shape
        results["maigret"] = (ok, note, mfound)
        if not ok:
            gaps.append(f"Maigret: {note}.")
        elif not found and not mfound:
            gaps.append("Maigret completed with zero parsed claims "
                        "(top-100 sites; see raw).")

    nmap_note, nmap_ports, nmap_target = None, [], ""
    if domain and _go(allowed, skip, "nmap"):
        p = os.path.join(raw, "nmap.txt")
        ok, note = run(["nmap", "-sV", "-F", "--host-timeout", "120s",
                        domain], p, TIMEOUTS["nmap"], runlog, on_log=on_log)
        nmap_note = (ok, note)
        results["nmap"] = (ok, note)
        nmap_target, nmap_ports = parse_nmap(p)
        if not ok:
            gaps.append(f"Nmap: {note}.")

    phone_lines, exif_lines, photo_name = [], [], ""
    if phone and _go(allowed, skip, "phone"):
        p = os.path.join(raw, "phoneinfoga.txt")
        ok, note = run([PHONEINFOGA, "scan", "-n", phone],
                       p, TIMEOUTS["phone"], runlog, on_log=on_log)
        phone_lines = parse_phone(p)
        results["phone"] = (ok, note)
        if not ok:
            gaps.append(f"PhoneInfoga: {note}.")
        elif not phone_lines:
            gaps.append("PhoneInfoga completed with no parsed sections.")
    if email and _go(allowed, skip, "holehe"):
        p = os.path.join(raw, "holehe.txt")
        ok, note = run([HOLEHE, email],
                       p, TIMEOUTS["holehe"], runlog, on_log=on_log)
        try:
            with open(p, errors="replace") as fh:
                claimed = [clean(l) for l in fh.readlines()
                           if "[+]" in clean(l)] if ok else []
        except OSError:
            claimed = []
            ok = False
        results["holehe"] = (ok, note, claimed)
        if not ok:
            gaps.append(f"holehe: {note}.")
    if photo and os.path.isfile(photo) and _go(allowed, skip, "exiftool"):
        try:
            if os.path.getsize(photo) > 200_000_000:
                gaps.append("Photo over 200MB — skipped (attach smaller).")
                photo = ""
        except OSError:
            pass
    if photo and os.path.isfile(photo):
        photo_name = os.path.basename(photo)
        dest = os.path.join(cdir, "photos", photo_name)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy(photo, dest)
        p = os.path.join(raw, "exif.txt")
        ok, note = run([EXIFTOOL, dest], p, 120, runlog, on_log=on_log)
        exif_lines = parse_exif_highlights(p)
        if not ok:
            gaps.append(f"ExifTool: {note}.")

    video_lines = []
    if url and _go(allowed, skip, "video"):
        p = os.path.join(raw, "video.txt")
        ok, note = run([YTDLP, "--no-playlist", "--skip-download",
                        "--print",
                        "%(title)s | %(uploader)s | %(upload_date)s",
                        "--print", "thumbnail: %(thumbnail)s", url],
                       p, TIMEOUTS["video"], runlog, on_log=on_log)
        try:
            with open(p, errors="replace") as fh:
                video_lines = [clean(l) for l in fh if clean(l)][:20]
        except OSError:
            pass
        results["video"] = (ok, note, video_lines, url)
        if not ok:
            gaps.append(f"Video Intel: {note}.")

    hdr_lines, hdr_warns = [], []
    if headers_file and os.path.isfile(headers_file) \
            and _go(allowed, skip, "emailhdr"):
        try:
            with open(headers_file, errors="replace") as fh:
                hdr_lines, hdr_warns = analyze_email_headers(fh.read())
        except OSError as exc:
            gaps.append(f"Headers file unreadable: {exc}.")
        results["emailhdr"] = (bool(hdr_lines), "", hdr_lines, hdr_warns,
                               os.path.basename(headers_file))
        if not hdr_lines and not hdr_warns:
            gaps.append("Headers file produced nothing parseable.")

    needs = {"sublist3r": bool(domain), "harvester": bool(domain),
             "amass": bool(domain), "sherlock": bool(username),
             "maigret": bool(username), "nmap": bool(domain),
             "phone": bool(phone), "holehe": bool(email),
             "exiftool": bool(photo), "gau": bool(domain),
             "pagodo": bool(domain), "wayback": bool(domain),
             "photon": bool(domain), "video": bool(url),
             "emailhdr": bool(headers_file)}
    denied = sorted(k for k, want in needs.items()
                    if want and k not in skip and allowed is not None
                    and k not in allowed)
    for k in denied:
        gaps.append(f"{k}: not granted by admin.")

    write_report(cdir, case, domain, username, results, gaps, subs_all,
                 found, nmap_note, nmap_target, nmap_ports,
                 phone_lines, exif_lines, photo_name, notes, operator,
                 denied)
    write_html(cdir)
    runlog.close()
    return cdir


def write_report(cdir, case, domain, username, results, gaps, subs_all,
                 found, nmap_note, nmap_target="", nmap_ports=(),
                 phone_lines=(), exif_lines=(), photo_name="", notes="",
                 operator="?", denied=()):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    L = [f"# Background dossier — {case}", f"_Compiled {now} (AEGIS panel)_",
         f"_Operator: {operator}_", "", "## Findings"]
    if subs_all:
        L += [f"### Subdomains/hosts ({len(subs_all)})",
              *[f"- `{s}`" for s in sorted(subs_all)[:200]]]
        if len(subs_all) > 200:
            L.append(f"- …and {len(subs_all) - 200} more in `raw/`.")
    if "harvester" in results:
        _, _, emails, _, ips = results["harvester"]
        if emails:
            L += ["", f"### Emails ({len(emails)})",
                  *[f"- {e}" for e in emails[:100]]]
        if ips:
            L += ["", f"### IPs ({len(ips)})", *[f"- `{i}`" for i in ips]]
    if found:
        L += ["", f"### Username hits ({len(found)})",
              *[f"- {s}: {u}" for s, u in found]]
    if "maigret" in results:
        _, _, mfound = results["maigret"]
        if mfound:
            L += ["", f"### Username hits, wider net ({len(mfound)})",
                  *[f"- {s}: {u}" for s, u in mfound[:200]]]
    if "gau" in results:
        _, _, gau_urls = results["gau"]
        if gau_urls:
            L += ["", f"### Historic URLs ({len(gau_urls)})",
                  *[f"- {u}" for u in gau_urls[:50]]]
            if len(gau_urls) > 50:
                L.append(f"- …and {len(gau_urls) - 50} more in `raw/gau.txt`.")
    if "pagodo" in results:
        _, _, ptotal, phit, psample = results["pagodo"]
        if ptotal:
            L += ["", f"### Dork hits ({ptotal} URLs across {phit} dorks)",
                  *[f"- {u}" for u in psample]]
    if "wayback" in results:
        _, _, wrows, wgood = results["wayback"]
        if wrows:
            L += ["", f"### Snapshots ({len(wrows)} total, "
                       f"{len(wgood)} good)"]
            if wgood:
                ts, url, _ = wgood[-1]
                L.append(f"- Latest good capture: "
                         f"https://web.archive.org/web/{ts}/{url}")
            L += [f"- {a} {c} {b}" for a, b, c in wrows[:30]]
    if "photon" in results:
        _, _, pemails, psubs = results["photon"]
        if pemails:
            L += ["", f"### Crawled emails ({len(pemails)})",
                  *[f"- {e}" for e in pemails[:50]]]
        if psubs:
            L += ["", f"### Crawled subdomains ({len(psubs)})",
                  *[f"- `{s}`" for s in psubs[:50]]]
    if "video" in results:
        _, _, video_lines, vurl = results["video"]
        if video_lines:
            L += ["", "### Video metadata",
                  f"- source: {vurl}",
                  *[f"- {l}" for l in video_lines]]
    if "emailhdr" in results:
        _, _, hdr_lines, hdr_warns, hname = results["emailhdr"]
        if hdr_lines or hdr_warns:
            L += ["", f"### Email route (`{hname}`)"]
            L += [f"- {l}" for l in hdr_lines[:30]]
            L += [f"- FLAG: {w}" for w in hdr_warns]
    if "holehe" in results:
        _, _, claimed = results["holehe"]
        if claimed:
            L += ["", f"### Email registered on ({len(claimed)})",
                  *[f"- {c}" for c in claimed[:100]]]
    if phone_lines:
        L += ["", "### Phone footprint",
              *[f"- {l}" for l in phone_lines[:60]]]
    if exif_lines or photo_name:
        L += ["", f"### Photo evidence (`photos/{photo_name}`)"]
        L += [f"- {l}" for l in exif_lines] or \
            ["- No GPS/device/author tags found."]
    if nmap_ports:
        L += ["", f"### Open ports on {nmap_target or domain} "
                   f"({len(nmap_ports)})",
              "| Port | Service | Version |",
              "|---|---|---|",
              *[f"| {p} | {s} | {v} |" for p, s, v in nmap_ports],
              "Version strings as reported, not verified."]
    elif nmap_note and nmap_note[0]:
        L += ["", "### Open services (nmap -sV -F)",
              "Scan completed with no open ports. See `raw/nmap.txt`."]
    positive = (subs_all or found or (nmap_note and nmap_note[0])
                or phone_lines or exif_lines or photo_name
                or ("holehe" in results and results["holehe"][2])
                or ("harvester" in results
                    and (results["harvester"][2] or results["harvester"][3]
                         or results["harvester"][4]))
                or ("maigret" in results and results["maigret"][2])
                or ("gau" in results and results["gau"][2])
                or ("pagodo" in results and results["pagodo"][2])
                or ("wayback" in results and results["wayback"][2])
                or ("photon" in results
                    and (results["photon"][2] or results["photon"][3]))
                or ("video" in results and results["video"][2])
                or ("emailhdr" in results
                    and (results["emailhdr"][2] or results["emailhdr"][3])))
    if not positive:
        L.append("_No positive findings from completed sources._")
    if notes.strip():
        L += ["", "## Field notes (operator, verbatim)",
              notes.strip()]
    def _m(key, label):
        if key in results:
            return f"- {label} — " + results[key][1]
        if key in (denied or ()):
            return f"- {label} — not granted by admin"
        return f"- {label} — skipped"
    L += ["", "## Methods",
          _m("sublist3r", "Sublist3r subdomain enumeration"),
          f"- theHarvester sources: `{HARVESTER_SOURCES}` (no-key sources)"
          + (" — " + results["harvester"][1] if "harvester" in results
             else " — not granted by admin" if "harvester" in (denied or ())
             else " — skipped"),
          _m("amass", "Amass passive enum (no direct probing)"),
          _m("sherlock", "Sherlock username sweep"),
          _m("maigret", "Maigret username sweep, top-100 sites"),
          _m("gau", "gau historic URLs (otx+wayback providers)"),
          _m("pagodo", "Pagodo GHDB quick file, 10 dorks"),
          _m("wayback", "Wayback CDX snapshots"),
          _m("photon", "Photon crawl (emails + subdomains)"),
          _m("nmap", "Nmap service versions "
                     "(ACTIVE probing — authorized targets only)"),
          _m("video", "Video metadata (yt-dlp, no download)"),
          _m("emailhdr", "Email header route analysis (offline)"),
          _m("phone", "PhoneInfoga number footprint"),
          _m("holehe", "holehe email-account check"),
          ("- Photo metadata (`photos/" + photo_name + "`) — completed"
           if photo_name else
           "- Photo metadata — not granted by admin"
           if "exiftool" in (denied or ()) else
           "- Photo metadata — skipped (no photo attached)"),
          "- Not in automated runs (by design): SpiderFoot/Recon-ng "
          "(interactive consoles), BLE/Deauth (hardware radio + active "
          "attack), Maltego (GUI app), ExifTool card (file picker)."]
    L += ["", "## Gaps & caveats",
          "- Absence in these outputs is not absence in the world.",
          "- Aggregator hits need primary-source confirmation before action.",
          "- Username hits need a second discriminator (bio, photo, location) "
            "before attribution — name/handle alone is never enough."]
    L += [f"- {g}" for g in gaps] or []
    L += ["", "## Raw evidence", "`raw/` holds every tool's unedited output "
          "plus `run.log` with per-tool timings."]
    with open(os.path.join(cdir, "REPORT.md"), "w") as fh:
        fh.write("\n".join(L) + "\n")


def write_html(cdir):
    """Single-file styled handoff report. Hand-rolled tags only, no deps."""
    import html as H
    src = os.path.join(cdir, "REPORT.md")
    try:
        lines = open(src, encoding="utf-8").read().splitlines()
    except OSError:
        return
    out = ["<!DOCTYPE html><html><head><meta charset='utf-8'>",
           "<title>AEGIS dossier</title><style>",
           "body{font-family:sans-serif;max-width:900px;margin:2em auto;"
           "background:#14161c;color:#d7dce2;padding:0 1em}",
           "h1{color:#4da3ff}h2{color:#7cc4ff;border-bottom:1px solid #2a2f3a}"
           "code{background:#22262f;padding:1px 5px}"
           "table{border-collapse:collapse}td,th{border:1px solid #2a2f3a;"
           "padding:4px 10px}li{margin:3px 0}</style></head><body>"]
    in_list = False
    for ln in lines:
        if ln.startswith("|") and ln.endswith("|"):
            cells = [H.escape(c.strip()) for c in ln.strip("|").split("|")]
            if set(ln.replace("|", "").strip()) <= set("-: "):
                continue
            tag = "th" if not in_list else "td"
            out.append("<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells)
                       + "</tr>")
            in_list = True
            continue
        if in_list and not ln.startswith("|"):
            in_list = False
        if ln.startswith("### "):
            out.append(f"<h3>{H.escape(ln[4:])}</h3>")
        elif ln.startswith("## "):
            out.append(f"<h2>{H.escape(ln[3:])}</h2>")
        elif ln.startswith("# "):
            out.append(f"<h1>{H.escape(ln[2:])}</h1>")
        elif ln.startswith("- "):
            item = re.sub(r"`([^`]+)`", r"<code>\1</code>", H.escape(ln[2:]))
            out.append(f"<ul><li>{item}</li></ul>")
        elif not ln.strip():
            out.append("<br>")
        else:
            out.append(f"<p>{H.escape(ln)}</p>")
    out.append("</body></html>")
    with open(os.path.join(cdir, "REPORT.html"), "w") as fh:
        fh.write("\n".join(out))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True)
    ap.add_argument("--domain", default="")
    ap.add_argument("--username", default="")
    ap.add_argument("--phone", default="")
    ap.add_argument("--email", default="")
    ap.add_argument("--photo", default="")
    ap.add_argument("--url", default="",
                    help="video/image URL for the Video Intel module")
    ap.add_argument("--headers-file", default="",
                    help="raw headers .txt for the route-analysis module")
    ap.add_argument("--notes", default="",
                    help="operator field notes, appended verbatim")
    ap.add_argument("--notes-file", default="",
                    help="same, read from a file (for long notes)")
    ap.add_argument("--operator", default="?",
                    help="operator name stamped on the report")
    ap.add_argument("--skip", default="",
                     help="comma list: sublist3r,harvester,amass,sherlock,"
                          "maigret,nmap,phone,holehe,gau,pagodo,wayback,"
                          "photon,video,emailhdr")
    args = ap.parse_args()
    if not args.domain and not args.username and not args.phone \
            and not args.email and not args.url and not args.headers_file:
        ap.error("give at least --domain, --username, --phone, --email, "
                 "--url or --headers-file")
    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    notes = args.notes
    if args.notes_file:
        try:
            with open(args.notes_file, errors="replace") as fh:
                notes = fh.read().strip()
        except OSError as exc:
            ap.error(f"cannot read --notes-file: {exc}")
    cdir = build(re.sub(r"[^\w.-]+", "_", args.case), args.domain,
                 args.username, skip, phone=args.phone, email=args.email,
                 photo=args.photo, url=args.url,
                 headers_file=args.headers_file, notes=notes,
                 operator=args.operator)
    print(f"DOSSIER: {cdir}")


if __name__ == "__main__":
    main()
