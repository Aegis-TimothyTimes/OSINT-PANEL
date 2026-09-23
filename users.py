#!/usr/bin/env python3
"""
AEGIS operator vault — users, passwords, per-tool grants.

Store: ~/.config/aegis/users.json (mode 0600, this machine only).
Passwords NEVER stored: PBKDF2-HMAC-SHA256, per-user salt, 200k rounds.
Stdlib only — no new dependencies for the installer.

Grant model per user:
  {"salt": hex, "hash": hex, "admin": bool,
   "tools": ["harvester", ...],            # ignored when admin
   "tabs": {"dossier": bool, "dorks": bool, "keys": bool}}
Console is always visible; typing into it is harmless without
runnable tools (every launcher re-checks grants — see panel).
The panel builds grant editors from its own CARDS — this module treats
tool keys as opaque strings, so no cross-imports to keep in sync.
"""
import hashlib
import hmac
import json
import os
import secrets
import stat

USERS = os.path.join(os.path.expanduser("~"), ".config", "aegis",
                     "users.json")
ROUNDS = 200_000


def _path(path=None):
    return path or USERS


def load(path=None):
    try:
        with open(_path(path)) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save(users, path=None):
    p = _path(path)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(users, fh, indent=2)
    os.replace(tmp, p)


def hash_pw(password, salt=None):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                             bytes.fromhex(salt), ROUNDS)
    return salt, dk.hex()


def add_user(name, password, admin=False, tools=(), tabs=None,
             path=None):
    """Returns (ok, note). Refuses blanks and duplicates."""
    name = (name or "").strip()
    if not name or not password:
        return False, "name and password are both required"
    users = load(path)
    if name in users:
        return False, f"{name} already exists"
    salt, digest = hash_pw(password)
    users[name] = {"salt": salt, "hash": digest, "admin": bool(admin),
                   "tools": sorted(set(tools or ())),
                   "tabs": dict(tabs or {"dossier": False, "dorks": False,
                                         "keys": False})}
    save(users, path)
    return True, f"{name} added" + (" (admin)" if admin else "")


def verify(name, password, path=None):
    """Returns the user dict on success, None otherwise. Constant-time
    compare; unknown users take the same path as wrong passwords."""
    users = load(path)
    rec = users.get((name or "").strip(), {})
    salt = rec.get("salt", "00" * 16)
    _, digest = hash_pw(password or "", salt)
    if rec and hmac.compare_digest(digest, rec.get("hash", "")):
        return {"name": (name or "").strip(), **rec}
    return None


def set_grants(name, admin=None, tools=None, tabs=None, path=None):
    users = load(path)
    if name not in users:
        return False, "unknown user"
    if admin is not None and not admin and users[name].get("admin"):
        admins = sum(1 for n, u in users.items()
                     if u.get("admin") and n != name)
        if admins < 1:
            return False, "cannot demote the last admin"
    if admin is not None:
        users[name]["admin"] = bool(admin)
    if tools is not None:
        users[name]["tools"] = sorted(set(tools))
    if tabs is not None:
        users[name]["tabs"] = dict(tabs)
    save(users, path)
    return True, f"{name} updated"


def delete_user(name, path=None):
    users = load(path)
    if name not in users:
        return False, "unknown user"
    if sum(1 for u in users.values() if u.get("admin")) <= 1 \
            and users[name].get("admin"):
        return False, "cannot delete the last admin"
    del users[name]
    save(users, path)
    return True, f"{name} deleted"


def list_users(path=None):
    return sorted(load(path))


def is_admin(user):
    return bool((user or {}).get("admin"))


def can_run(user, key):
    if not user:
        return False
    if user.get("admin"):
        return True
    return key in (user.get("tools") or [])


def can_tab(user, tab):
    if not user:
        return False
    if user.get("admin"):
        return True
    return bool((user.get("tabs") or {}).get(tab))
