# AEGIS OSINT Panel — Operations Manual

Field manual for operators. Everything here runs user-local on your
machine: no Kali repos, no system surgery, no paid anything required.
Most tools work with zero keys; keys make some of them dramatically
better (Keys tab).

Install: `chmod +x install-osint-panel.sh && ./install-osint-panel.sh`.
One sudo prompt, ~2GB downloads, ends with a 23-check self-test —
all PASS means double-click **OSINT Panel**. Any FAIL: re-run (it
resumes), then see Troubleshooting.

Type once at the top of the Tools tab (domain / username / phone /
email / video URL), then Run on any card. Hover a Run button for
what it needs. Output runs docked in the Console tab, except the
three noted below.

---

## 1. theHarvester — domain emails, hosts, subdomains

Needs: domain. First stop for any domain. Pulls from certificate
logs and search engines (keyless sources, pinned — do not add
bing/threatcrowd, they abort v5 runs). Output: terminal-style log
in Console. Slow-ish; dossiers run it at 10 minutes max.

## 2. Amass — deep subdomain enum

Needs: domain. Dozens of public archives, passive (quiet) by
default. The slowest card — check "skip slow ones" box in Dossier
to drop it from a run. Dossier timeout 15 minutes.

## 3. Sublist3r — fast subdomain sweep

Needs: domain. Search-engine based, quick win before the heavy
tools. Dossier parses its `-o` file directly.

## 4. Sherlock — username across hundreds of sites

Needs: username. Reports claimed accounts as `Site: URL` lines.
A hit is NOT attribution — needs a second discriminator (bio,
photo, location) before a name attaches to it.

## 5. SpiderFoot — automated 100+ module scans

Needs: nothing (opens web UI on :5001). Starts its server docked,
opens your browser on first HTTP 200 (up to 90s on slow boxes).
Stop the Console run to kill the server. Port busy? Something else
sits on 5001.

## 6. Recon-ng — interactive recon framework

Needs: nothing to launch; API keys inside for full power (109
marketplace modules ship installed). Fully interactive — type at
the Console input line. `keys add` inside, or use the Keys tab +
Deploy.

## 7. Nmap — ports and service versions

Needs: domain. ACTIVE probing — **authorized targets only**,
always. `-sV -F`, host timeout 2 minutes in dossiers.

## 8. ExifTool — photo metadata

Needs: nothing to launch — attach a photo via the picker. Shows
GPS/device/author highlights plus full dump. No metadata (common —
messengers strip it) is itself a finding; note it. GPS: verify on
a map before acting.

## 9. Maltego — link-analysis graphs

Needs: installer + free Community account (panel guides you;
cannot auto-install). Launches externally — its own GUI app.
Graph rule: people link to the hub ONLY, never manufacture
association between people.

## 10. BLE Map — nearby Bluetooth devices

Needs: sudo + this machine's bluetooth adapter. Opens an EXTERNAL
terminal (sudo needs a real TTY) with the caplet pre-booted, then
`ble.show` lists devices. Installer writes the caplet; re-running
the installer restores it.

## 11. WiFi Deauth — disconnect clients from an AP

Needs: sudo + a monitor-capable radio + LAB/AUTHORIZATION. Auth
gate first (a warning dialog — this is an active attack), then a
guided terminal: steps NetworkManager aside, enters monitor mode,
recon sweeps (~8s of channel hopping = normal scanning), target
table prints. Restore command printed at the end. Panel needs a
real monitor-mode adapter (most laptop Intel cards lack it; a
classic AR9271/RT3070 USB or ESP32-class radio does it).

## 12. PhoneInfoga — phone-number footprint

Needs: number in +E164 (`+15551234567`). Carrier, country, line
type, public lookups. Dossier caps the section at 60 lines.

## 13. holehe — email registered where

Needs: email. Tests 100+ sites, `[+]` lines are claims. Sherlock's
counterpart for emails.

## 14. Maigret — username across 3000+ sites

Needs: username. Sherlock's heavier sibling: `--timeout 15`,
top-100 sites in dossiers. Dossier parses `[+]` claim lines;
see raw for the rest.

## 15. Photon — website crawler

Needs: domain. Extracts emails, subdomains, endpoints, files.
Runs from its own directory (relative paths — do not "fix" the
workdir). Dossier harvests its output files for emails + subs.

## 16. gau — historic URLs from web archives

Needs: domain. Providers pinned to otx+wayback (defaults include
dead endpoints — never re-add blindly). Instant usually; saves
`gau-<domain>.txt`. Dossier caps at 500 raw, 50 in report.

## 17. Pagodo — GHDB dorks vs a domain

Needs: domain. Runs the 10-dork quick file (NOT the 7944-line
GHDB dump — a full run takes hours). ~40–60s pause per dork BY
DESIGN (Google rate-limits scrapers). Results: JSON + TXT + log
next to gau's files. Empty run + 429s in the log = rate-limit,
never "target is clean" — wait and retry, or use the Dorks tab.

## 18. Wayback — time-travel a domain

Needs: domain. Lists CDX snapshots in Console, opens the latest
good capture in your browser. The Archive naps (it serves its
offline page as HTTP 200) — the card detects that and says so
instead of failing, opening a live lookup for retry.

## 19. Video Intel — video/image URL metadata

Needs: URL in the top field. yt-dlp metadata only (title,
uploader, date, thumbnail) — nothing downloaded. Lens/TinEye
buttons reverse-search an IMAGE url in your browser.

## 20. Email Headers — route analysis, offline

Needs: nothing to launch — paste raw headers in the dialog.
Hop-by-hop route, SPF/DKIM/DMARC verdicts, Reply-To mismatch
flags. Fully offline, nothing leaves the machine.

---

## Dorks tab — zero-key dork pack

Six categories (quick scan mirrors Pagodo's 10), four engines
(Google/Bing/DuckDuckGo/Brave — different rate-limit buckets).
Scope domain at the top (empty = whole web), tap a dork, opens
in browser. Full query in every tooltip. Indexed ≠ still there —
verify live before reporting.

## Dossier tab — one subject, full sweep

Inputs: case name (required) + any of domain/username/phone/
email/URL + photo + headers file + field notes (your context,
appended verbatim to the report). Skip boxes drop slow modules
(Amass, Sherlock, Nmap-active, Pagodo-~10min, Photon, Maigret).
Build runs everything in sequence with a live log; gaps never
abort — a failed tool becomes a logged gap. Output per case:
`REPORT.md` + styled `REPORT.html` + `raw/` + `run.log`, Export
zip for handoff, Print/PDF via the browser. The past-cases picker
reopens any previous case. Every runnable module rides the run;
Methods lists each with its result or skip reason, plus what stays
out by design (interactive/server/hardware/GUI tools).

## Login & operators

First launch creates the admin. Every launch after: operator login
(three tries). Admins use the Users tab: add operators, per-tool
grants (20 checkboxes), tab access (Dossier/Dorks/Keys), admin flag.
New accounts start with NOTHING — grant explicitly. Ungranted Run
buttons render dimmed with "see admin" tooltips; the launch path
re-checks server-side-of-GUI, so greyed buttons can't be forced.
Last admin undeletable; you can't delete yourself mid-shift.
Passwords PBKDF2-hashed, vault 0600. Every dossier is stamped with
the operator name.

## System tab — build screen

Machine stats, panel version, bundle manifest with dates,
ThinkCentre link status (ssh/http/ollama). Refresh re-probes.
Nothing here is privileged — every operator sees it.

## Keys tab — 13 API slots, one vault

Paste once, Deploy writes into recon-ng + theHarvester configs
on THIS machine only. Vault file `~/.config/aegis/keys.json`,
mode 600. Keys stay on the machine — never into chats, tickets,
or shared drives. Most tools work keyless; Shodan/GitHub/Censys
class tools need theirs.

## Console tab — docked output

Live log, input line (Enter sends keystrokes — recon-ng works
here), Stop button. New run stops the old one. Sudo/GUI tools
(BLE, Deauth, Maltego) stay external — tooltips say so. ExifTool
and Email Headers use dialogs instead.

---

## Rules of the road

1. Active probing (nmap, deauth, Marauder-class attacks) only on
   systems you own or are explicitly authorized to test. Passive
   reads (archives, cert logs, dorks, headers) are public data.
2. A hit is not attribution. Second discriminator minimum.
3. Indexed is not live. Re-check before reporting.
4. Keys stay on the machine. Reports state methods honestly.

## Troubleshooting

Panel icon does nothing → run `python3 ~/osint-tools/panel.py`
once; the error prints. Usual: Qt display lib
(`sudo apt install -y libxcb-cursor0`).
SpiderFoot no connection → up to 90s on slow boxes; port clash
otherwise. Recon-ng no modules → `marketplace refresh` +
`marketplace install all` inside. Harvester "Invalid source" →
edit HARVESTER_SOURCES in dossier.py to your version's list.
Pagodo empty → 429, wait + retry or Dorks tab. Archive napping
→ card says so, retry later. yt-dlp site fail → update yt-dlp,
retry. Deauth errors → needs monitor-mode radio + `iw`; Intel
laptop cards lack monitor mode — USB/classic adapter required.
Maltego → .deb + free account, panel guides.

## Uninstall

```bash
rm -rf ~/osint-tools ~/bin/amass ~/bin/gau ~/bin/bettercap \
  ~/bin/phoneinfoga ~/.recon-ng ~/.theHarvester ~/Desktop/OSINT-Panel.desktop \
  ~/Desktop/OPERATIONS-MANUAL.md
python3 -m pip uninstall -y sherlock-project holehe maigret PySide6 yt-dlp
```

(Apt packages left alone deliberately. Every component downloads
from official upstreams at install; licenses belong to authors.
Reports you produce are your work — handle per authorization.)
