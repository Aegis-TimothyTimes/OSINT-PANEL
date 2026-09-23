#!/usr/bin/env bash
# AEGIS OSINT Panel — standalone installer (no LLM components).
#
# Installs 20 OSINT tools fully user-local (no system surgery, no Kali repos)
# plus a one-click Qt control panel and desktop icon. Safe to re-run:
# every step skips what is already present.
#
# Only root-needed bits (prompted once): nmap, display libs, terminal,
# downloader/utils (curl, iw, gnome-terminal, xdg-utils, python3-pip/venv).
# Maltego is NOT auto-installed (account + .deb) — the panel guides the user.
#
# Tested on: Linux Mint 22.3 (Ubuntu 24.04 base), Python 3.12 system.
# Needs: internet, git, wget, ~2GB disk for tools/venvs.
#
# Usage:  chmod +x install-osint-panel.sh && ./install-osint-panel.sh
set -euo pipefail

TOOLS="${HOME}/osint-tools"
BIN="${HOME}/bin"
LOCALBIN="${HOME}/.local/bin"
AMASS_VER="v5.1.1"          # verified 2026-09-20
EXIF_VER="13.55"            # latest on CPAN 2026-09-20
PY_VER="3.14"               # theHarvester requires >=3.14

say()  { printf "\n\033[1;36m==> %s\033[0m\n" "$1"; }
warn() { printf "\033[1;33m    ! %s\033[0m\n" "$1"; }
have() { command -v "$1" >/dev/null 2>&1 || [ -x "${LOCALBIN}/$1" ] \
         || [ -x "${BIN}/$1" ]; }

mkdir -p "${TOOLS}" "${BIN}"
export PATH="${LOCALBIN}:${BIN}:${PATH}"

# Fresh-box staging: the bundle rides together. Copy any sibling files
# that are beside this installer but missing in TOOLS — otherwise a
# run-from-Downloads install yields a dead desktop icon.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for f in panel.py dossier.py keys.py users.py README.md OPERATIONS-MANUAL.md; do
  if [ ! -s "${TOOLS}/$f" ] && [ -s "${HERE}/$f" ]; then
    cp "${HERE}/$f" "${TOOLS}/" && echo "    staged $f"
  fi
done

# ---------------------------------------------------------- system packages
say "System packages (one sudo prompt; tools + panel display + terminal)"
if ! have nmap || ! have gnome-terminal || ! have xdg-open || ! have curl \
   || ! have iw || ! ldconfig -p 2>/dev/null | grep -q xcb-cursor; then
  sudo apt-get update && sudo apt-get install -y nmap libxcb-cursor0 \
    libportaudio2 git wget unzip curl iw gnome-terminal xdg-utils \
    python3-pip python3-venv ca-certificates build-essential dkms
else
  echo "    system packages present"
fi
command -v git >/dev/null || { echo "git is required — install it first."; exit 1; }

# ------------------------------------------------------------------- uv
say "uv (user-local Python manager)"
if [ ! -x "${LOCALBIN}/uv" ]; then
  curl -LsSf https://astral.sh/uv/install.sh -o /tmp/uv-install.sh
  sh /tmp/uv-install.sh >/dev/null
  rm -f /tmp/uv-install.sh
fi
"${LOCALBIN}/uv" python install "${PY_VER}" >/dev/null 2>&1 || true
echo "    uv ready"

# ------------------------------------------------- pip tools (system python)
say "Sherlock + holehe + Maigret (system Python 3.12, --user)"
python3 -m pip install --user --break-system-packages --prefer-binary \
  sherlock-project holehe maigret 2>&1 | tail -1 || true
[ -f "${TOOLS}/Sublist3r/sublist3r.py" ] || \
{ rm -rf "${TOOLS}/Sublist3r"; git clone --depth 1 https://github.com/aboul3la/Sublist3r.git \
    "${TOOLS}/Sublist3r"; }
python3 -m pip install --user --break-system-packages --prefer-binary \
  -r "${TOOLS}/Sublist3r/requirements.txt" 2>&1 | tail -1 || true

# ------------------------------------------------------- theHarvester (3.14)
say "theHarvester (needs Python >=3.14: isolated venv)"
if [ ! -x "${TOOLS}/venv-harvester/bin/theHarvester" ]; then
  [ -f "${TOOLS}/theHarvester/theHarvester.py" ] || \
  { rm -rf "${TOOLS}/theHarvester"; git clone --depth 1 https://github.com/laramies/theHarvester.git \
      "${TOOLS}/theHarvester"; }
  [ -d "${TOOLS}/venv-harvester" ] || \
  "${LOCALBIN}/uv" venv --python "${PY_VER}" "${TOOLS}/venv-harvester"
  "${LOCALBIN}/uv" pip install --python \
    "${TOOLS}/venv-harvester/bin/python" "${TOOLS}/theHarvester" 2>&1 | tail -1 || true
else
  echo "    theHarvester present"
fi

# ------------------------------------------------------------- recon-ng
say "Recon-ng (+ marketplace modules)"
[ -f "${TOOLS}/recon-ng/recon-ng" ] || \
{ rm -rf "${TOOLS}/recon-ng"; git clone --depth 1 https://github.com/lanmaster53/recon-ng.git \
    "${TOOLS}/recon-ng"; }
python3 -m pip install --user --break-system-packages --prefer-binary \
  -r "${TOOLS}/recon-ng/REQUIREMENTS" 2>&1 | tail -1 || true
printf 'marketplace refresh\nmarketplace install all\nexit\n' | \
  python3 "${TOOLS}/recon-ng/recon-ng" --no-analytics 2>&1 | tail -1 || \
  warn "marketplace refresh failed — run inside recon-ng later"
echo "    recon-ng modules installed (API keys are operator-supplied)"

# ------------------------------------------------------------ spiderfoot
say "SpiderFoot (isolated 3.14 venv; dep names differ from imports)"
[ -f "${TOOLS}/spiderfoot/sf.py" ] || \
{ rm -rf "${TOOLS}/spiderfoot"; git clone --depth 1 https://github.com/smicallef/spiderfoot.git \
    "${TOOLS}/spiderfoot"; }
[ -d "${TOOLS}/venv-spider" ] || \
  "${LOCALBIN}/uv" venv --python "${PY_VER}" "${TOOLS}/venv-spider"
UVPY="${TOOLS}/venv-spider/bin/python"
"${LOCALBIN}/uv" pip install --python "${UVPY}" \
  -r "${TOOLS}/spiderfoot/requirements.txt" >/dev/null 2>&1 || true
# Import-name -> package-name fixes requirements.txt doesn't cover.
# NOTE: never install the bare `docx` package (dead Py2 stub that breaks
# imports) — the real one is python-docx. And SpiderFoot (2023-era) needs
# secure v0 API, NOT v2:
"${LOCALBIN}/uv" pip install --python "${UVPY}" "secure==0.3.0" \
  >/dev/null 2>&1 || true
for i in $(seq 1 25); do
  MISSING=$("${UVPY}" "${TOOLS}/spiderfoot/sf.py" --help 2>&1 \
    | grep -oP "No module named '\K[^']+" | head -1 || true)
  [ -z "${MISSING}" ] && break
  case "${MISSING}" in
    dns) PKG=dnspython;; PIL) PKG=pillow;; OpenSSL) PKG=pyOpenSSL;;
    yaml) PKG=pyyaml;; bs4) PKG=beautifulsoup4;; docx) PKG=python-docx;;
    pptx) PKG=python-pptx;; *) PKG="${MISSING}";;
  esac
  "${LOCALBIN}/uv" pip install --python "${UVPY}" "${PKG}" >/dev/null 2>&1 || true
done
"${UVPY}" "${TOOLS}/spiderfoot/sf.py" --help >/dev/null 2>&1 \
  && echo "    spiderfoot imports clean" \
  || warn "spiderfoot still missing deps — rerun this script"
# Panel launches it from its own dir (relative template paths); panel.py
# already does this — do not "fix" it back to $HOME.

# ----------------------------------------------------------------- amass
say "Amass ${AMASS_VER} (prebuilt binary)"
if [ ! -x "${BIN}/amass" ]; then
  wget -q "https://github.com/owasp-amass/amass/releases/download/${AMASS_VER}/amass_linux_amd64.tar.gz" \
    -O /tmp/amass.tgz
  tar xzf /tmp/amass.tgz -C /tmp/
  cp /tmp/amass_linux_amd64/amass "${BIN}/amass" && chmod +x "${BIN}/amass"
  rm -rf /tmp/amass.tgz /tmp/amass_linux_amd64
fi
"${BIN}/amass" --version 2>&1 | head -1

# --------------------------------------------------------------- exiftool
say "ExifTool ${EXIF_VER} (pure-perl, runs in place)"
if [ ! -x "${TOOLS}/Image-ExifTool-${EXIF_VER}/exiftool" ]; then
  wget -q "https://cpan.metacpan.org/authors/id/E/EX/EXIFTOOL/Image-ExifTool-${EXIF_VER}.tar.gz" \
    -O /tmp/exif.tar.gz
  tar xzf /tmp/exif.tar.gz -C "${TOOLS}/"
  rm -f /tmp/exif.tar.gz
fi
"${TOOLS}/Image-ExifTool-${EXIF_VER}/exiftool" -ver

# -------------------------------------------------------------- bettercap
say "Bettercap v2.41.7 (BLE mapper + wifi toolkit, single binary)"
if [ ! -x "${BIN}/bettercap" ]; then
  wget -q "https://github.com/bettercap/bettercap/releases/download/v2.41.7/bettercap_linux_amd64.zip" \
    -O /tmp/bc.zip
  unzip -o /tmp/bc.zip -d /tmp/bc_ex/ >/dev/null
  cp /tmp/bc_ex/bettercap "${BIN}/bettercap" && chmod +x "${BIN}/bettercap"
  rm -rf /tmp/bc.zip /tmp/bc_ex
fi
"${BIN}/bettercap" -version 2>&1 | head -1
echo "    NOTE: capture needs sudo; wifi deauth needs monitor mode + the"
echo "    iw package (sudo apt install -y iw) and an authorized target."
# Bettercap caplets drive the panel's wireless cards. They are tiny
# static files — written here so fresh boxes get them, not just old ones.
mkdir -p "${TOOLS}/wireless"
cat > "${TOOLS}/wireless/ble.cap" <<'EOF'
# AEGIS BLE mapper — auto-starts the radio modules so there is no
# "no modules running" state. Run: sudo bettercap -caplet ble.cap
# Boot sequence recons, waits, then SHOWS the device table.
# Then:  ble.show   (refresh list — names, RSSI, addresses)
ble.recon on
sleep 5
ble.show
EOF
cat > "${TOOLS}/wireless/deauth.cap" <<'EOF'
# AEGIS wifi recon — AUTHORIZED LAB NETWORKS ONLY.
# Interface must ALREADY be in monitor mode (the panel sets that up first).
# Run: sudo bettercap -iface <mon-iface> -caplet deauth.cap
# Boot sequence below recons, waits, then SHOWS the target table.
# Then:  wifi.deauth <BSSID>  (one target — copy BSSID from the table)
#        wifi.deauth          (everyone in range — lab only, you included)
wifi.recon on
sleep 8
wifi.show
EOF
echo "    caplets: $(ls "${TOOLS}"/wireless/*.cap | wc -l) written"

# ------------------------------------------------------ photon + gau
say "Photon crawler + gau history"
[ -f "${TOOLS}/Photon/photon.py" ] || \
{ rm -rf "${TOOLS}/Photon"; git clone --depth 1 https://github.com/s0md3v/Photon.git \
    "${TOOLS}/Photon"; }
python3 -m pip install --user --break-system-packages --prefer-binary \
  -r "${TOOLS}/Photon/requirements.txt" 2>&1 | tail -1 || true
if [ ! -x "${BIN}/gau" ]; then
  wget -q "https://github.com/lc/gau/releases/download/v2.2.4/gau_2.2.4_linux_amd64.tar.gz" \
    -O /tmp/gau.tgz
  tar xzf /tmp/gau.tgz -C /tmp/ && cp /tmp/gau "${BIN}/gau"
  chmod +x "${BIN}/gau" && rm -rf /tmp/gau.tgz /tmp/gau
fi
"${BIN}/gau" --version 2>&1 | head -1

# --------------------------------------------------------------- pagodo
say "Pagodo (GHDB dork runner: passive, no API key)"
[ -f "${TOOLS}/pagodo/pagodo.py" ] || \
{ rm -rf "${TOOLS}/pagodo"; git clone --depth 1 https://github.com/opsdisk/pagodo.git \
    "${TOOLS}/pagodo"; }
python3 -m pip install --user --break-system-packages --prefer-binary \
  -r "${TOOLS}/pagodo/requirements.txt" 2>&1 | tail -1 || true
# Scraper MUST run from its own dir (relative dorks/ path) — same trap as
# spiderfoot's workdir. Refresh keeps the 7944-dork GHDB feed current;
# failure keeps the bundled list (never fatal).
(cd "${TOOLS}/pagodo" && python3 ghdb_scraper.py -s 2>&1 | tail -1) || \
  warn "GHDB refresh failed — bundled dorks list kept"
# Quick file (10 dorks) for docked runs — a full GHDB run takes hours.
# NOTE: keep in sync with DORK_SETS "Quick scan" in panel.py.
cat > "${TOOLS}/pagodo/quick_dorks.txt" <<'EOF'
intitle:"index of" "parent directory"
inurl:admin
inurl:login
filetype:pdf
filetype:xls OR filetype:xlsx
filetype:bak OR filetype:old OR filetype:backup
filetype:sql
filetype:log
intitle:"phpinfo" "PHP Version"
intext:"db_password" OR intext:"db_passwd"
EOF
echo "    quick file: $(wc -l < "${TOOLS}/pagodo/quick_dorks.txt") dorks"

# ------------------------------------------------- video intel (yt-dlp)
say "yt-dlp (video metadata, no download)"
python3 -m pip install --user --break-system-packages --prefer-binary -U \
  yt-dlp 2>&1 | tail -1 || true

# ------------------------------------------------------------ phoneinfoga
say "PhoneInfoga v2.11.0 (prebuilt binary)"
if [ ! -x "${BIN}/phoneinfoga" ]; then
  wget -q "https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_Linux_x86_64.tar.gz" \
    -O /tmp/pi.tgz
  tar xzf /tmp/pi.tgz -C /tmp/
  cp /tmp/phoneinfoga "${BIN}/phoneinfoga" && chmod +x "${BIN}/phoneinfoga"
  rm -rf /tmp/pi.tgz /tmp/phoneinfoga
fi
"${BIN}/phoneinfoga" version 2>&1 | head -1

# ---------------------------------------------------------- control panel
say "Control panel (Qt6 + YAML vault backend, user-local)"
python3 -m pip install --user --break-system-packages --prefer-binary \
  PySide6 pyyaml 2>&1 | tail -1 || true
DESK="${HOME}/Desktop"
[ -d "${DESK}" ] || DESK="${HOME}/.local/share/applications"
cat > "${DESK}/OSINT-Panel.desktop" <<EOF
[Desktop Entry]
Name=OSINT Panel
Comment=AEGIS one-click OSINT control panel
Exec=python3 ${TOOLS}/panel.py
Path=${TOOLS}
Icon=security-high
Terminal=false
Type=Application
Categories=Network;Security;
StartupNotify=true
EOF
chmod +x "${DESK}/OSINT-Panel.desktop"
gio set "${DESK}/OSINT-Panel.desktop" metadata::trusted true 2>/dev/null || true
echo "    launcher at ${DESK}/OSINT-Panel.desktop"
# Operations manual rides alongside the panel, on the desktop to be read.
if [ -f "${TOOLS}/OPERATIONS-MANUAL.md" ]; then
  cp "${TOOLS}/OPERATIONS-MANUAL.md" "${DESK}/" 2>/dev/null || true
  echo "    manual at ${DESK}/OPERATIONS-MANUAL.md"
else
  warn "OPERATIONS-MANUAL.md not beside the installer — copy the full bundle"
fi

# ------------------------------------------------------- self-test
say "Self-test (every entry point must resolve)"
pass=0; fail=0
check() { if eval "$1" >/dev/null 2>&1; then pass=$((pass+1));
            echo "    PASS $2"; else fail=$((fail+1));
            echo "    FAIL $2"; fi; }
check "${TOOLS}/venv-harvester/bin/theHarvester -h" theHarvester
check "${BIN}/amass --version" amass
check "python3 ${TOOLS}/Sublist3r/sublist3r.py --help" sublist3r
check "${LOCALBIN}/sherlock --version" sherlock
check "cd ${TOOLS}/spiderfoot && ${TOOLS}/venv-spider/bin/python -c 'import sf'" "spiderfoot-imports"
check "python3 ${TOOLS}/recon-ng/recon-ng --version" recon-ng
check "nmap --version" nmap
check "${TOOLS}/Image-ExifTool-${EXIF_VER}/exiftool -ver" exiftool
check "${BIN}/phoneinfoga version" phoneinfoga
check "${LOCALBIN}/holehe --version" holehe
check "${LOCALBIN}/maigret --version" maigret
check "${BIN}/gau --version" gau
check "${BIN}/bettercap -version" bettercap
check "python3 -c 'import PySide6'" panel-gui
check "python3 ${TOOLS}/Photon/photon.py --help" photon
check "python3 ${TOOLS}/pagodo/pagodo.py --help" pagodo
check "test -s ${TOOLS}/pagodo/quick_dorks.txt" pagodo-dorks
check "xdg-open --version" xdg-open
check "gnome-terminal --version" gnome-terminal
check "python3 -c 'import yaml'" keys-yaml
check "test -s ${TOOLS}/users.py" users-backend
check "yt-dlp --version" video-intel
check "curl --version" wayback-fetch
echo "    ${pass} passed, ${fail} failed"

cat <<EOF

$(printf "\033[1;32m==> Done. Double-click OSINT Panel.\033[0m")
  theHarvester / Amass / Sublist3r / Sherlock / Maigret / holehe /
  SpiderFoot / Recon-ng / Nmap / ExifTool / gau / Photon / Pagodo /
  PhoneInfoga / BLE+deauth (bettercap) + Wayback / Video Intel /
  Email Headers + the Dorks tab (zero-key pack)
  Maltego: panel guides its .deb + free account (not auto-installed).
   NOTE: panel.py, dossier.py, keys.py, users.py, README.md,
   OPERATIONS-MANUAL.md, LICENSE and .gitignore ship alongside this
   installer — copy the bundle together, and place the .py files in
   ~/osint-tools/ (the panel imports them for its tabs).
   Read README.md first, OPERATIONS-MANUAL.md second.
EOF
