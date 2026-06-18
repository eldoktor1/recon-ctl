#!/usr/bin/env python3
r"""unauth_expose_classify.py — the REAL-vs-FP discriminator for U1 (shadow-endpoint
unauthenticated data exposure). PRECISION-FIRST: better to miss than to surface an FP
(the whole "wide eyes, narrow hands" doctrine — see docs/OPERATING.md +
docs/knowledge/class-unauth-hunting.md play U1).

Reads ONE JSON object on stdin:
  {"host","endpoint","probe":<safe_probe_worker output>,"root":<safe_probe of '/'>}
Emits ONE JSON object on stdout:
  {"exposure":bool,"confidence":float,"reason":str,"evidence":{...REDACTED...}}

A finding is REAL only when ALL hold:
  1. probe.ok and status==200 (not 401/403/404/3xx — those are NOT leaks)
  2. it is NOT the SPA shell (a 200 returning the app index.html, same as '/', is the
     documented #1 FP — CLAUDE.md "SPA-shell 200")
  3. the body is genuine STRUCTURED/SENSITIVE data (data content-type or parseable JSON
     with sensitive field/value markers) — not a marketing page, not an empty/array, not
     a generic error
Evidence is REDACTED: we record PROOF the data leaked (field names, counts, content-type)
NEVER the raw PII/secret values (hard line: confirm exposure exists, never harvest).
Pure stdlib; read-only (issues no traffic — the caller already probed).
"""
import sys, json, re

DATA_CT = ("application/json", "application/ld+json", "application/x-ndjson",
           "application/xml", "text/xml", "text/csv", "application/csv",
           "application/vnd.api+json", "application/hal+json")
# sensitive FIELD-NAME markers (JSON keys / CSV headers / XML tags)
SENS_FIELDS = re.compile(
    r'\b(e?mail|phone|mobile|ssn|sin|nino|passport|dob|date_of_birth|birth'
    r'|first[_-]?name|last[_-]?name|full[_-]?name|address|street|postal|zip'
    r'|iban|bic|account[_-]?(no|number|id)|card[_-]?(no|number)|cvv|pan'
    r'|password|passwd|secret|api[_-]?key|token|authoriz|credential|private[_-]?key'
    r'|salary|tax|ssn|national[_-]?id|user[_-]?(id|name)|customer[_-]?id'
    r'|session|bearer|access[_-]?token|refresh[_-]?token)\b', re.I)
# sensitive VALUE patterns in the raw body
EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
JWT_RE   = re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}')
PHONE_RE = re.compile(r'(?<!\d)(\+?\d[\d\s().-]{7,}\d)(?!\d)')
KEYISH_RE = re.compile(r'(AKIA[0-9A-Z]{16}|sk_live_[0-9A-Za-z]{10,}|xox[baprs]-[0-9A-Za-z-]{10,}'
                       r'|ghp_[0-9A-Za-z]{20,})')
# public-by-design tokens — NOT a leak even if "key" appears (mirrors brief_filter). AIza
# (Google BROWSER api key) belongs here, not in KEYISH — it is meant to ship to clients.
PUBLIC_TOKEN = re.compile(r'(supabase.{0,3}anon|pk_(live|test)_|firebase.{0,3}config'
                          r'|client[_-]?id|AIza[0-9A-Za-z_-]{10,})', re.I)
SHELL_MARK = re.compile(r'(<div\s+id=["\'](root|app|__next)["\']|window\.__(NUXT|NEXT|INITIAL)'
                        r'|<app-root|ng-version|<!doctype html)', re.I)


def _ct(headers):
    return (headers or {}).get("content-type", "").split(";")[0].strip().lower()


def _shellish(body):
    """Looks like an SPA/HTML app shell (no data, just the bootstrap markup)."""
    return bool(SHELL_MARK.search(body or "")) or (body or "").lstrip()[:15].lower().startswith("<!doctype html")


def _similar_to_root(body, root_body):
    """Body is ~the same page as '/' (the SPA-catch-all returns index.html everywhere)."""
    if not root_body:
        return False
    a, b = (body or "").strip(), (root_body or "").strip()
    if not a:
        return False
    # near-equal length AND shared long prefix = the same shell
    if abs(len(a) - len(b)) <= max(40, int(0.05 * max(len(a), len(b)))):
        n = min(len(a), len(b), 400)
        if n and a[:n] == b[:n]:
            return True
    return False


def _redact(body):
    """Proof WITHOUT harvest: counts + masked samples, never raw values."""
    emails = EMAIL_RE.findall(body or "")
    phones = PHONE_RE.findall(body or "")
    jwts = JWT_RE.findall(body or "")
    keys = KEYISH_RE.findall(body or "")
    fields = sorted({m.group(0).lower() for m in SENS_FIELDS.finditer(body or "")})
    def mask(s):
        s = str(s)
        return (s[:2] + "***" + s[-2:]) if len(s) > 5 else "***"
    return {
        "sensitive_fields": fields[:20],
        "email_count": len(emails), "phone_count": len(phones),
        "jwt_count": len(jwts), "hardcoded_key_count": len(keys),
        "sample_email_masked": mask(emails[0]) if emails else "",
    }


def classify(obj):
    host = obj.get("host", ""); endpoint = obj.get("endpoint", "")
    probe = obj.get("probe") or {}; root = obj.get("root") or {}
    if not probe.get("ok") or probe.get("status") != 200:
        return {"exposure": False, "confidence": 0.0,
                "reason": f"status={probe.get('status')} ok={probe.get('ok')} — not a 200 unauth response"}
    body = probe.get("body_snippet", "") or ""
    ct = _ct(probe.get("headers"))
    root_body = (root or {}).get("body_snippet", "") if root.get("ok") else ""

    # FP gate 1: SPA shell / same-as-root → NOT a leak
    if _similar_to_root(body, root_body):
        return {"exposure": False, "confidence": 0.0, "reason": "SPA-shell: body matches '/' (client-side route, not an unauth leak)"}
    if ct.startswith("text/html") and _shellish(body):
        return {"exposure": False, "confidence": 0.0, "reason": "HTML app-shell markup, no server data"}

    red = _redact(body)
    has_field = bool(red["sensitive_fields"])
    has_value = (red["email_count"] + red["phone_count"] + red["jwt_count"] + red["hardcoded_key_count"]) > 0
    # real PII = emails / JWTs / real cred-keys (NOT phone — that regex is noisy on ids/versions)
    real_pii = (red["email_count"] + red["jwt_count"] + red["hardcoded_key_count"]) > 0
    is_data_ct = any(ct.startswith(x) for x in DATA_CT)
    json_ok = False
    if is_data_ct or body.lstrip()[:1] in ("{", "["):
        try:
            j = json.loads(body)
            json_ok = isinstance(j, (dict, list)) and (len(j) > 0)
        except Exception:
            json_ok = False

    # FP gate 2: public-by-design config (firebase web config / supabase anon / client_id /
    # Google AIza browser key). Suppress whenever there is no REAL PII value, even if a
    # field name like "apiKey" is present — those configs are meant to ship to clients.
    if PUBLIC_TOKEN.search(body) and not real_pii:
        return {"exposure": False, "confidence": 0.0, "reason": "public-by-design config (no private PII/creds) — not a leak"}

    # CONFIRM tiers (precision-first): need real sensitive signal, not just a 200.
    conf, reason = 0.0, ""
    if is_data_ct and (has_field or has_value):
        conf = 0.9 if has_value else 0.85
        reason = f"unauth {ct} returns sensitive data (fields={red['sensitive_fields'][:6]}, emails={red['email_count']}, jwts={red['jwt_count']}, keys={red['hardcoded_key_count']})"
    elif json_ok and (has_field or has_value):
        conf = 0.85 if has_value else 0.8
        reason = f"unauth JSON body with sensitive markers (fields={red['sensitive_fields'][:6]}, emails={red['email_count']})"
    elif has_value and (red["jwt_count"] or red["hardcoded_key_count"] or red["email_count"] >= 3):
        # non-data content-type but clearly leaking creds/PII in bulk (e.g. exposed page/log)
        conf = 0.7
        reason = f"unauth body leaks credentials/PII (jwts={red['jwt_count']}, keys={red['hardcoded_key_count']}, emails={red['email_count']})"
    else:
        return {"exposure": False, "confidence": 0.0,
                "reason": f"200 but no sensitive data signal (ct={ct or '?'}, fields={has_field}, values={has_value}) — not shippable"}

    return {"exposure": True, "confidence": conf, "reason": reason,
            "evidence": {"url": probe.get("url", f"https://{host}{endpoint}"),
                         "status": 200, "content_type": ct, "body_bytes": probe.get("body_bytes", 0),
                         "redacted": red}}


def main():
    try:
        obj = json.load(sys.stdin)
    except Exception as e:
        print(json.dumps({"exposure": False, "confidence": 0.0, "reason": f"bad-input:{e.__class__.__name__}"}))
        return 0
    print(json.dumps(classify(obj)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
