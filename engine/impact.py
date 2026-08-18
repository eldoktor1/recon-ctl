#!/usr/bin/env python3
"""
impact.py — shared primitives for turning DISCOVERY into IMPACT.

Every unauth lane in this pipeline stopped one step short of a finding: "a port is open",
"an endpoint returns data", "an actuator responds", "a bucket is readable". Those are the
same sentences a stranger's `nuclei` run produces an hour later, which makes them
duplicates. The finding is what you GOT.

This module is the shared half of that step, so every lane classifies credentials and
personal data the same way instead of each growing its own drifting copy:

    scan_secrets()   what credential material is recoverable here (redacted)
    classify_data()  is this real personal data, how much, and whose
    redact()         prove recovery without keeping the value

HARD LINE encoded here, not left to the caller:
  * Secrets are ALWAYS redacted. The functions cannot return a usable credential.
    We prove recovery is possible; we never keep or use the value.
  * Personal data is COUNTED and TYPED, never copied out. A finding says "1,200 records
    with email and phone", never the records themselves.
"""
from __future__ import annotations

import json
import re

# --------------------------------------------------------------------- secrets
# (name, pattern, chars_to_keep). Ordered roughly by how conclusive each one is.
SECRET_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("aws-access-key-id", re.compile(rb"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16})\b"), 8),
    ("aws-secret-key", re.compile(rb"(?i)aws.{0,24}secret.{0,24}[\"':=\s]([A-Za-z0-9/+=]{40})\b"), 4),
    ("private-key", re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), 0),
    ("gcp-service-account", re.compile(rb'"type"\s*:\s*"service_account".{0,400}?"private_key_id"\s*:\s*"([0-9a-f]{20,})"', re.S), 8),
    ("azure-storage-key", re.compile(rb"(?i)(?:AccountKey|SharedAccessKey)=([A-Za-z0-9+/=]{40,})"), 6),
    ("jdbc-with-password", re.compile(rb"(jdbc:[a-z0-9]+://[^\s\"']{4,90}[?&;](?:password|pwd)=[^\s\"'&]{3,})"), 26),
    ("db-password-prop", re.compile(rb"(?i)(?:spring\.datasource\.password|db[._-]?password|database[._-]?password|POSTGRES_PASSWORD|MYSQL_(?:ROOT_)?PASSWORD)[\"']?\s*[:=]\s*[\"']?([^\s\"',}]{4,64})"), 4),
    ("jwt-signing-secret", re.compile(rb"(?i)(?:jwt[._-]?secret|signing[._-]?key|token[._-]?secret|SECRET_KEY_BASE)[\"']?\s*[:=]\s*[\"']?([^\s\"',}]{8,90})"), 4),
    ("mongo-url", re.compile(rb"(mongodb(?:\+srv)?://[^\s\"':]{2,48}:[^\s\"'@]{3,}@[^\s\"'/]{4,})"), 18),
    ("postgres-url", re.compile(rb"(postgres(?:ql)?://[^\s\"':]{2,48}:[^\s\"'@]{3,}@[^\s\"'/]{4,})"), 16),
    ("redis-url", re.compile(rb"(redis://[^\s\"':]*:[^\s\"'@]{3,}@[^\s\"'/]{4,})"), 12),
    ("smtp-url", re.compile(rb"(smtps?://[^\s\"':]{2,48}:[^\s\"'@]{3,}@[^\s\"'/]{4,})"), 14),
    ("github-pat", re.compile(rb"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"), 8),
    ("slack-token", re.compile(rb"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), 10),
    ("stripe-secret", re.compile(rb"\b(sk_live_[0-9a-zA-Z]{20,})\b"), 8),
    ("sendgrid-key", re.compile(rb"\b(SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})\b"), 6),
    ("twilio-key", re.compile(rb"\b(SK[0-9a-fA-F]{32})\b"), 6),
    ("google-api-key", re.compile(rb"\b(AIza[0-9A-Za-z_\-]{35})\b"), 8),
    ("npm-token", re.compile(rb"\b(npm_[A-Za-z0-9]{36})\b"), 6),
    ("bearer-token", re.compile(rb"(?i)authorization[\"':\s]+bearer\s+([A-Za-z0-9._\-]{24,})"), 6),
]

# Public-by-DESIGN key shapes. These are meant to ship in a browser and are not secrets;
# treating them as findings is the documented ~53% false-positive source in this pipeline.
PUBLIC_BY_DESIGN = re.compile(
    rb"(?i)(pk_live_|pk_test_|pat-na1-|"                    # Stripe publishable, HubSpot public
    rb"\"?(?:apiKey|authDomain|projectId|storageBucket|messagingSenderId|appId)\"?\s*:|"  # Firebase web config
    rb"supabase[._-]?anon|anon[._-]?key|"                    # Supabase anon
    rb"client[._-]?id\"?\s*[:=]|"                            # OAuth client_id
    rb"NEXT_PUBLIC_|REACT_APP_PUBLIC_|VITE_PUBLIC_)")

# \xe2\x80\xa2 is the UTF-8 bullet used by masking UIs; a bytes pattern cannot hold it literally.
MASKED = re.compile(rb"^[\*x\xe2\x80\xa2]{3,}$|^\*+$|^<[^>]{2,30}>$|^\$\{[^}]+\}$|^%[A-Z_]+%$")
PLACEHOLDER = re.compile(
    rb"(?i)^(changeme|password|passwd|secret|example|test|dummy|your[_-]?\w+|xxx+|"
    rb"none|null|undefined|todo|placeholder|s3cret|admin|123456)\w{0,4}$")


def redact(name: str, raw: bytes, keep: int) -> str:
    """Prove a credential was recovered without ever returning a usable value."""
    s = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    if keep <= 0:
        return f"<{name}: present, {len(s)} chars>"
    head = s[:keep]
    return f"{head}{'*' * max(4, min(12, len(s) - keep))} (len={len(s)})"


def _is_junk(raw: bytes) -> bool:
    r = raw.strip()
    if not r or len(set(r)) <= 2:
        return True
    if MASKED.match(r) or PLACEHOLDER.match(r):
        return True
    return False


def scan_secrets(blob: bytes, source: str = "", limit: int = 40) -> list[dict]:
    """Recoverable credential material in `blob`, redacted. Public-by-design keys and
    masked/placeholder values are excluded — those are the documented FP population."""
    if not blob:
        return []
    out: list[dict] = []
    seen: set[str] = set()
    for name, rx, keep in SECRET_PATTERNS:
        for m in rx.finditer(blob):
            raw = m.group(1) if m.groups() else m.group(0)
            if _is_junk(raw):
                continue
            ctx = blob[max(0, m.start() - 60):m.end() + 20]
            if PUBLIC_BY_DESIGN.search(ctx):
                continue
            key = f"{name}:{raw[:24]!r}"
            if key in seen:
                continue
            seen.add(key)
            out.append({"kind": name, "source": source, "redacted": redact(name, raw, keep)})
            if len(out) >= limit:
                return out
    return out


# ------------------------------------------------------------------------ PII
# Each entry decides whether a response is REAL PERSONAL DATA rather than a schema,
# a docs page, or a list of countries.
PII_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("email", re.compile(rb"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
    ("phone", re.compile(rb"(?<![\d.])(?:\+\d{1,3}[\s.\-]?)?(?:\(\d{2,4}\)[\s.\-]?)?\d{3}[\s.\-]?\d{3,4}[\s.\-]?\d{2,4}(?![\d.])")),
    ("iban", re.compile(rb"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")),
    ("credit-card", re.compile(rb"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b")),
    ("ssn-us", re.compile(rb"\b\d{3}-\d{2}-\d{4}\b")),
    ("ip-address", re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("date-of-birth", re.compile(rb"(?i)\"(?:dob|date_of_birth|birth_?date|geboortedatum)\"\s*:\s*\"[^\"]{6,}\"")),
    ("postal-address", re.compile(rb"(?i)\"(?:address|street|address_line_?1|postcode|zip_?code)\"\s*:\s*\"[^\"]{3,}\"")),
    ("full-name", re.compile(rb"(?i)\"(?:first_?name|last_?name|full_?name|surname)\"\s*:\s*\"[A-Za-z][^\"]{1,60}\"")),
    ("national-id", re.compile(rb"(?i)\"(?:national_?id|passport|nin|bsn|ssn|tax_?id)\"\s*:\s*\"[^\"]{4,}\"")),
]

# Fields that mark an object as a *user record* rather than a config blob.
RECORD_KEYS = re.compile(
    rb"(?i)\"(?:user_?id|customer_?id|account_?id|member_?id|email|username|"
    rb"first_?name|last_?name|phone|created_?at|last_?login)\"\s*:")

# Documentation, schemas and examples that look like data but describe it instead.
SCHEMA_ISH = re.compile(
    rb"(?i)(\"\$schema\"|\"swagger\"|\"openapi\"|\"definitions\"|\"properties\"\s*:\s*\{|"
    rb"example\.(com|org|net)|@example\.|foo@bar|john\.?doe|jane\.?doe|test@test)")


def classify_data(blob: bytes, ctype: str = "", source: str = "") -> dict:
    """Decide whether a response is REAL personal data worth reporting.

    Returns {"is_pii": bool, "records": int, "kinds": [...], "unique_emails": int,
             "reason": str}. Counts and types only — never the data itself."""
    res = {"is_pii": False, "records": 0, "kinds": [], "unique_emails": 0,
           "bytes": len(blob or b""), "source": source, "reason": ""}
    if not blob or len(blob) < 80:
        res["reason"] = "body too small to carry a record set"
        return res

    if SCHEMA_ISH.search(blob[:8000]):
        res["reason"] = "looks like a schema, spec or documented example, not live data"
        return res

    hits: dict[str, int] = {}
    for name, rx in PII_PATTERNS:
        n = len(rx.findall(blob))
        if n:
            hits[name] = n

    emails = set(PII_PATTERNS[0][1].findall(blob))
    emails = {e for e in emails
              if not re.search(rb"(?i)(example|test|localhost|sentry|\.png|\.jpg|@2x)", e)}
    res["unique_emails"] = len(emails)

    # An IP address alone is not personal data in this context — it is in nearly every
    # log line and config file, and treating it as PII is pure noise.
    strong = {k: v for k, v in hits.items() if k != "ip-address"}
    records = len(RECORD_KEYS.findall(blob))
    res["records"] = max(len(emails), records // 4)
    res["kinds"] = sorted(strong)

    if not strong:
        res["reason"] = "no personal-data fields present"
        return res
    if res["records"] < 2 and len(emails) < 2:
        res["reason"] = (f"personal-data shapes present ({', '.join(strong)}) but fewer than "
                         f"two distinct subjects — not a record set")
        return res

    res["is_pii"] = True
    res["reason"] = (f"~{res['records']} record(s) carrying {', '.join(strong)}"
                     + (f"; {len(emails)} distinct email addresses" if emails else ""))
    return res


def severity_for(secrets: list[dict], pii: dict | None = None) -> tuple[int, float, str]:
    """(score, confidence, one-line impact) — honest, never inflated. Overclaiming is what
    gets reports closed N/A."""
    kinds = {s["kind"] for s in secrets}
    cloud = kinds & {"aws-access-key-id", "aws-secret-key", "gcp-service-account",
                     "azure-storage-key"}
    dbc = kinds & {"jdbc-with-password", "mongo-url", "postgres-url", "redis-url",
                   "db-password-prop"}
    signing = kinds & {"private-key", "jwt-signing-secret"}

    if cloud:
        return 20, 0.95, f"unauthenticated recovery of cloud credentials ({', '.join(sorted(cloud))})"
    if signing:
        return 19, 0.95, f"unauthenticated recovery of signing key material ({', '.join(sorted(signing))})"
    if dbc:
        return 18, 0.95, f"unauthenticated recovery of database credentials ({', '.join(sorted(dbc))})"
    if kinds:
        return 15, 0.9, f"unauthenticated recovery of API credentials ({', '.join(sorted(kinds))})"
    if pii and pii.get("is_pii"):
        n = pii["records"]
        sev = 17 if n >= 100 else 14 if n >= 10 else 11
        return sev, 0.9, f"unauthenticated exposure of ~{n} personal records ({', '.join(pii['kinds'])})"
    return 0, 0.0, "no impact demonstrated"


def verdict(blob: bytes, source: str = "") -> dict:
    """One call: what impact does this response body actually DEMONSTRATE?

    `score == 0` means nothing was recovered and nothing should be minted — however
    confident a model is that it found something. This is the gate that separates
    "an endpoint responded" from "here is what I got".
    """
    sec = scan_secrets(blob, source)
    pii = classify_data(blob, source=source)
    score, conf, headline = severity_for(sec, pii)
    return {"score": score, "confidence": conf, "impact": headline,
            "mint": score > 0,
            "secret_kinds": sorted({x["kind"] for x in sec}),
            "secrets": sec[:20], "personal_data": pii}


if __name__ == "__main__":
    import sys
    args = sys.argv[1:]
    data = sys.stdin.buffer.read()
    src = args[1] if len(args) > 1 else "stdin"
    if args and args[0] == "verdict":
        print(json.dumps(verdict(data, src)))
    else:
        print(json.dumps({"secrets": scan_secrets(data, src),
                          "data": classify_data(data, source=src)}, indent=2))
