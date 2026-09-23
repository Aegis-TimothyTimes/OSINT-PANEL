#!/usr/bin/env python3
"""
AEGIS key vault — one place for API keys, deployed to every tool.

Vault lives at ~/.config/aegis/keys.json (mode 0600, never leaves the
machine). The panel's Keys tab edits it; Deploy writes values into:
  - recon-ng keys.db (sqlite UPDATE, creates missing slots)
  - theHarvester api-keys.yaml (merged, existing entries preserved)

No keys are ever logged, printed, or transmitted anywhere except into
these two local configs.
"""
import json
import os
import sqlite3
import stat

VAULT = os.path.join(os.path.expanduser("~"), ".config", "aegis",
                     "keys.json")
HARVESTER_YAML = os.path.join(os.path.expanduser("~"), ".theHarvester",
                              "api-keys.yaml")
RECON_KEYS = os.path.join(os.path.expanduser("~"), ".recon-ng", "keys.db")

# vault-name: (plain-English use, harvester yaml path a.b, recon-ng slot)
KNOWN = {
    "shodan": ("Shodan device/service search", "shodan.key", "shodan_api"),
    "github": ("GitHub code search", "github.key", "github_api"),
    "bing": ("Bing search API", "bing.key", "bing_api"),
    "virustotal": ("VirusTotal lookups", "virustotal.key", "virustotal_api"),
    "hunter": ("Hunter.io email finder", "hunter.key", "hunter_io"),
    "hibp": ("HaveIBeenPwned breaches", None, "hibp_api"),
    "censys_id": ("Censys API ID", None, "censysio_id"),
    "censys_secret": ("Censys secret (also Harvester token)",
                      "censys.token", "censysio_secret"),
    "securitytrails": ("SecurityTrails DNS history", "securityTrails.key",
                       None),
    "criminalip": ("CriminalIP attack surface", "criminalip.key", None),
    "fullhunt": ("FullHunt attack surface", "fullhunt.key", None),
    "intelx": ("IntelX leak search", "intelx.key", None),
    "netlas": ("Netlas internet scan", "netlas.key", None),
}


def load():
    try:
        with open(VAULT) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save(keys):
    os.makedirs(os.path.dirname(VAULT), exist_ok=True)
    with open(VAULT, "w") as fh:
        json.dump(keys, fh, indent=2)
    os.chmod(VAULT, stat.S_IRUSR | stat.S_IWUSR)


def masked(keys):
    return {name: ("set (%d chars)" % len(keys[name]) if keys.get(name)
                   else "—") for name in KNOWN}


def deploy(keys):
    """Returns (ok_count, notes[]). Touches only local tool configs."""
    notes, ok = [], 0
    # recon-ng sqlite
    try:
        db = sqlite3.connect(RECON_KEYS)
        have = {r[0] for r in db.execute("SELECT name FROM keys")}
        for name, (_, _, slot) in KNOWN.items():
            if slot and keys.get(name):
                if slot in have:
                    db.execute("UPDATE keys SET value=? WHERE name=?",
                               (keys[name], slot))
                else:
                    db.execute("INSERT INTO keys VALUES (?, ?)",
                               (slot, keys[name]))
                ok += 1
        db.commit()
        db.close()
        notes.append("recon-ng keys.db updated")
    except Exception as exc:                                    # noqa: BLE001
        notes.append(f"recon-ng failed: {exc}")
    # harvester yaml
    try:
        import yaml
        with open(HARVESTER_YAML) as fh:
            data = yaml.safe_load(fh) or {}
        apis = data.setdefault("apikeys", {})
        for name, (_, hvpath, _) in KNOWN.items():
            if hvpath and keys.get(name):
                svc, field = hvpath.split(".")
                apis.setdefault(svc, {})[field] = keys[name]
                ok += 1
        with open(HARVESTER_YAML, "w") as fh:
            yaml.safe_dump(data, fh, default_flow_style=False)
        notes.append("theHarvester api-keys.yaml merged")
    except Exception as exc:                                    # noqa: BLE001
        notes.append(f"theHarvester failed: {exc}")
    return ok, notes
