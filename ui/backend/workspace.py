"""Program Workspace store — per-engagement coverage tracking.

A workspace is a JSON file at ~/recon/workspaces/<key>.json holding a WSTG v4.2
checklist, a STRIDE threat model, bug-class progress, notes and a history log for
one bug-bounty program. Pure file store (no ES/DB deps) — the live host/finding
joins are done by the app-layer handlers. Reads never raise; a missing/corrupt
file returns None. Keys are sanitized to [A-Za-z0-9_-] so no path can traverse.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

from . import config, files

WORKSPACES_DIR = config.BASE_DIR / "workspaces"

# The active program (source of truth: scope/programs.json + target board).
GLASSDOOR_NAME = "Glassdoor Managed Bug Bounty Engagement"
GLASSDOOR_PLATFORM = "bugcrowd"

# valid states
WS_STATUS = {"active", "paused", "done"}
WSTG_STATUS = {"todo", "in-progress", "done", "na", "finding"}

# --- seed templates --------------------------------------------------------
# WSTG v4.2 canonical checklist: (CAT, category name, [official test names]).
# The list index +1 is the two-digit test number, so IDs are WSTG-<CAT>-<NN>
# in sequence (v4.2 == the first N tests of each category). 97 tests total.
_WSTG_SPEC: list[tuple[str, str, list[str]]] = [
    ("INFO", "Information Gathering", [
        "Conduct Search Engine Discovery Reconnaissance for Information Leakage",
        "Fingerprint Web Server",
        "Review Webserver Metafiles for Information Leakage",
        "Enumerate Applications on Webserver",
        "Review Webpage Content for Information Leakage",
        "Identify Application Entry Points",
        "Map Execution Paths Through Application",
        "Fingerprint Web Application Framework",
        "Fingerprint Web Application",
        "Map Application Architecture",
    ]),
    ("CONF", "Configuration and Deployment Management", [
        "Test Network Infrastructure Configuration",
        "Test Application Platform Configuration",
        "Test File Extensions Handling for Sensitive Information",
        "Review Old Backup and Unreferenced Files for Sensitive Information",
        "Enumerate Infrastructure and Application Admin Interfaces",
        "Test HTTP Methods",
        "Test HTTP Strict Transport Security",
        "Test RIA Cross Domain Policy",
        "Test File Permission",
        "Test for Subdomain Takeover",
        "Test Cloud Storage",
    ]),
    ("IDNT", "Identity Management", [
        "Test Role Definitions",
        "Test User Registration Process",
        "Test Account Provisioning Process",
        "Testing for Account Enumeration and Guessable User Account",
        "Testing for Weak or Unenforced Username Policy",
    ]),
    ("ATHN", "Authentication", [
        "Testing for Credentials Transported over an Encrypted Channel",
        "Testing for Default Credentials",
        "Testing for Weak Lock Out Mechanism",
        "Testing for Bypassing Authentication Schema",
        "Testing for Vulnerable Remember Password",
        "Testing for Browser Cache Weaknesses",
        "Testing for Weak Password Policy",
        "Testing for Weak Security Question Answer",
        "Testing for Weak Password Change or Reset Functionalities",
        "Testing for Weaker Authentication in Alternative Channel",
    ]),
    ("ATHZ", "Authorization", [
        "Testing Directory Traversal File Include",
        "Testing for Bypassing Authorization Schema",
        "Testing for Privilege Escalation",
        "Testing for Insecure Direct Object References",
    ]),
    ("SESS", "Session Management", [
        "Testing for Session Management Schema",
        "Testing for Cookies Attributes",
        "Testing for Session Fixation",
        "Testing for Exposed Session Variables",
        "Testing for Cross Site Request Forgery",
        "Testing for Logout Functionality",
        "Testing Session Timeout",
        "Testing for Session Puzzling",
        "Testing for Session Hijacking",
    ]),
    ("INPV", "Input Validation", [
        "Testing for Reflected Cross Site Scripting",
        "Testing for Stored Cross Site Scripting",
        "Testing for HTTP Verb Tampering",
        "Testing for HTTP Parameter Pollution",
        "Testing for SQL Injection",
        "Testing for LDAP Injection",
        "Testing for XML Injection",
        "Testing for SSI Injection",
        "Testing for XPath Injection",
        "Testing for IMAP SMTP Injection",
        "Testing for Code Injection",
        "Testing for Command Injection",
        "Testing for Format String Injection",
        "Testing for Incubated Vulnerability",
        "Testing for HTTP Splitting Smuggling",
        "Testing for HTTP Incoming Requests",
        "Testing for Host Header Injection",
        "Testing for Server-side Template Injection",
        "Testing for Server-Side Request Forgery",
    ]),
    ("ERRH", "Error Handling", [
        "Testing for Improper Error Handling",
        "Testing for Stack Traces",
    ]),
    ("CRYP", "Cryptography", [
        "Testing for Weak Transport Layer Security",
        "Testing for Padding Oracle",
        "Testing for Sensitive Information Sent via Unencrypted Channels",
        "Testing for Weak Encryption",
    ]),
    ("BUSL", "Business Logic", [
        "Test Business Logic Data Validation",
        "Test Ability to Forge Requests",
        "Test Integrity Checks",
        "Test for Process Timing",
        "Test Number of Times a Function Can Be Used Limits",
        "Testing for the Circumvention of Work Flows",
        "Test Defenses Against Application Misuse",
        "Test Upload of Unexpected File Types",
        "Test Upload of Malicious Files",
    ]),
    ("CLNT", "Client-side", [
        "Testing for DOM-Based Cross Site Scripting",
        "Testing for JavaScript Execution",
        "Testing for HTML Injection",
        "Testing for Client-side URL Redirect",
        "Testing for CSS Injection",
        "Testing for Client-side Resource Manipulation",
        "Testing Cross Origin Resource Sharing",
        "Testing for Cross Site Flashing",
        "Testing for Clickjacking",
        "Testing WebSockets",
        "Testing Web Messaging",
        "Testing Browser Storage",
        "Testing for Cross Site Script Inclusion",
    ]),
    ("APIT", "API Testing", [
        "API Reconnaissance",
    ]),
]

_STRIDE_CATS = {
    "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
    "I": "Information Disclosure", "D": "Denial of Service", "E": "Elevation of Privilege",
}

_CLASSES = [
    "idor", "bac", "xss-reflected", "xss-stored", "xss-dom", "sqli", "ssrf",
    "graphql-bola", "cache-deception", "takeover", "ssti", "open-redirect", "xxe",
    "csrf", "auth-bypass", "info-disclosure", "secrets", "bucket", "nday",
]


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _slug(s: str) -> str:
    """Sanitize to [A-Za-z0-9_-]; lowercased, collapsed, trimmed, capped."""
    s = re.sub(r"[^A-Za-z0-9_-]+", "-", (s or "").strip()).strip("-_")
    return s[:64].lower()


def _path(key: str) -> Path:
    """Resolve a workspace file path, confined to WORKSPACES_DIR (no traversal)."""
    slug = _slug(key)
    if not slug:
        raise ValueError("invalid workspace key")
    p = (WORKSPACES_DIR / f"{slug}.json").resolve()
    root = WORKSPACES_DIR.resolve()
    if root not in p.parents:
        raise ValueError("path traversal refused")
    return p


def _seed_wstg() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for cat, cat_name, names in _WSTG_SPEC:
        for i, name in enumerate(names, 1):
            items.append({
                "id": f"WSTG-{cat}-{i:02d}", "category": cat, "cat_name": cat_name,
                "name": name, "status": "todo", "note": "", "updated_at": None,
            })
    return items


def _new_workspace(key: str, name: str, platform: str) -> dict[str, Any]:
    ts = _now()
    return {
        "key": key, "name": name or key, "platform": platform or "",
        "added_at": ts, "status": "active", "current": False,
        "wstg": _seed_wstg(),
        "stride": {c: [] for c in _STRIDE_CATS},
        "classes": [{"cls": c, "status": "todo"} for c in _CLASSES],
        "notes": [],
        "history": [{"ts": ts, "event": f"workspace created ({platform or '?'})"}],
    }


# --- persistence -----------------------------------------------------------
def save(ws: dict[str, Any]) -> dict[str, Any]:
    """Atomically write a workspace to disk. Returns the workspace."""
    WORKSPACES_DIR.mkdir(parents=True, exist_ok=True)
    p = _path(ws["key"])
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(ws, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, p)
    return ws


def load(key: str) -> dict[str, Any] | None:
    """Read one workspace by key. Never raises — bad key/missing/corrupt → None."""
    try:
        p = _path(key)
    except ValueError:
        return None
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def list_all() -> list[dict[str, Any]]:
    """All workspaces, oldest-first by added_at. Corrupt files are skipped."""
    out: list[dict[str, Any]] = []
    try:
        for p in WORKSPACES_DIR.glob("*.json"):
            try:
                out.append(json.loads(p.read_text(encoding="utf-8", errors="replace")))
            except Exception:
                continue
    except Exception:
        pass
    out.sort(key=lambda w: w.get("added_at") or "")
    return out


def summarize(ws: dict[str, Any]) -> dict[str, int]:
    """Cheap, offline counts (findings/hosts are joined live by the caller)."""
    wstg = ws.get("wstg", [])
    classes = ws.get("classes", [])
    return {
        "wstg_total": len(wstg),
        "wstg_done": sum(1 for w in wstg if w.get("status") == "done"),
        "wstg_inprogress": sum(1 for w in wstg if w.get("status") == "in-progress"),
        "wstg_findings": sum(1 for w in wstg if w.get("status") == "finding"),
        "findings": 0,  # live-joined by the app layer
        "hosts": 0,     # live-joined by the app layer
        "classes_done": sum(1 for c in classes if c.get("status") not in (None, "", "todo")),
    }


# --- mutations -------------------------------------------------------------
def create(key: str, name: str | None = None, platform: str | None = None) -> dict[str, Any]:
    """Create+seed a workspace, or return the existing one (idempotent).

    The first-ever workspace is marked `current` so the UI always has an active one.
    """
    slug = _slug(key)
    if not slug:
        raise ValueError("invalid workspace key")
    existing = load(slug)
    if existing:
        return existing
    first = not list_all()
    ws = _new_workspace(slug, name or key, platform or "")
    if first:
        ws["current"] = True
        ws["history"].append({"ts": _now(), "event": "marked current"})
    return save(ws)


def update_wstg(key: str, wid: str, status: str, note: str | None = None) -> dict[str, Any]:
    ws = load(key)
    if not ws:
        raise KeyError(key)
    if status not in WSTG_STATUS:
        raise ValueError(f"invalid status: {status} (allowed: {sorted(WSTG_STATUS)})")
    item = next((w for w in ws["wstg"] if w["id"] == wid), None)
    if not item:
        raise KeyError(wid)
    item["status"] = status
    if note is not None:
        item["note"] = str(note)[:2000]
    item["updated_at"] = _now()
    ws["history"].append({"ts": item["updated_at"], "event": f"{wid} → {status}"})
    return save(ws)


def update_stride(key: str, cat: str, threat: str, sid: str | None = None,
                  note: str | None = None, status: str | None = None,
                  hosts: list[str] | None = None) -> dict[str, Any]:
    ws = load(key)
    if not ws:
        raise KeyError(key)
    cat = (cat or "").strip().upper()[:1]
    if cat not in _STRIDE_CATS:
        raise ValueError(f"invalid STRIDE category: {cat} (allowed: {sorted(_STRIDE_CATS)})")
    if not (threat or "").strip():
        raise ValueError("threat text required")
    bucket = ws["stride"].setdefault(cat, [])
    row = next((t for t in bucket if t.get("id") == sid), None) if sid else None
    ts = _now()
    if row is None:
        row = {"id": f"{cat}{len(bucket) + 1}", "threat": "", "note": "",
               "status": "open", "hosts": []}
        bucket.append(row)
        ws["history"].append({"ts": ts, "event": f"STRIDE {cat} threat added"})
    else:
        ws["history"].append({"ts": ts, "event": f"STRIDE {row['id']} updated"})
    row["threat"] = str(threat)[:500]
    if note is not None:
        row["note"] = str(note)[:2000]
    if status is not None:
        row["status"] = str(status)[:40]
    if hosts is not None:
        row["hosts"] = [str(h)[:255] for h in hosts][:50]
    return save(ws)


def set_class(key: str, cls: str, status: str) -> dict[str, Any]:
    ws = load(key)
    if not ws:
        raise KeyError(key)
    cls = (cls or "").strip().lower()
    status = (status or "").strip()
    if not cls or not status:
        raise ValueError("cls and status required")
    row = next((c for c in ws["classes"] if c["cls"] == cls), None)
    if row is None:
        row = {"cls": cls, "status": "todo"}
        ws["classes"].append(row)
    row["status"] = status[:40]
    ws["history"].append({"ts": _now(), "event": f"class {cls} → {status}"})
    return save(ws)


def add_note(key: str, text: str) -> dict[str, Any]:
    ws = load(key)
    if not ws:
        raise KeyError(key)
    text = (text or "").strip()
    if not text:
        raise ValueError("note text required")
    ts = _now()
    ws["notes"].append({"ts": ts, "text": text[:4000]})
    ws["history"].append({"ts": ts, "event": "note added"})
    return save(ws)


def set_status(key: str, status: str | None = None,
               current: bool | None = None) -> dict[str, Any]:
    ws = load(key)
    if not ws:
        raise KeyError(key)
    ts = _now()
    if status is not None:
        status = str(status).strip().lower()
        if status not in WS_STATUS:
            raise ValueError(f"invalid status: {status} (allowed: {sorted(WS_STATUS)})")
        ws["status"] = status
        ws["history"].append({"ts": ts, "event": f"status → {status}"})
    if current:
        # exactly one current workspace: unset it everywhere else first
        for other in list_all():
            if other.get("key") != ws["key"] and other.get("current"):
                other["current"] = False
                other.setdefault("history", []).append({"ts": ts, "event": "unset current"})
                save(other)
        ws["current"] = True
        ws["history"].append({"ts": ts, "event": "marked current"})
    elif current is False:
        ws["current"] = False
        ws["history"].append({"ts": ts, "event": "unset current"})
    return save(ws)


# --- candidates + seed -----------------------------------------------------
def _existing_names() -> set[str]:
    names: set[str] = set()
    for w in list_all():
        names.add((w.get("name") or "").lower())
        names.add((w.get("key") or "").lower())
    return names


def candidates(limit: int = 20) -> list[dict[str, Any]]:
    """High-scored programs from the target board not yet in a workspace."""
    taken = _existing_names()
    out: list[dict[str, Any]] = []
    try:
        for p in files.target_board().get("programs", []):
            name = (p.get("name") or "").strip()
            if not name or name.lower() in taken or _slug(name) in taken:
                continue
            out.append({
                "key": _slug(name), "name": name,
                "platform": p.get("platform") or "",
                "score": p.get("score"),
            })
            if len(out) >= limit:
                break
    except Exception:
        pass
    return out


def _discover_glassdoor() -> tuple[str, str]:
    """(name, platform) for Glassdoor from the target board, with a safe fallback."""
    try:
        for p in files.target_board().get("programs", []):
            if "glass" in (p.get("name") or "").lower():
                return (p["name"], p.get("platform") or GLASSDOOR_PLATFORM)
    except Exception:
        pass
    return (GLASSDOOR_NAME, GLASSDOOR_PLATFORM)


def ensure_seeded() -> dict[str, Any] | None:
    """One-time: if there are no workspaces yet, seed Glassdoor as the current one.

    Best-effort — a read-only FS or any error is swallowed so a read never fails.
    """
    try:
        if list_all():
            return None
        name, platform = _discover_glassdoor()
        return create("glassdoor", name, platform)
    except Exception:
        return None
