#!/usr/bin/env python3
"""v3 Phase C — platform report formatters.

One internal Finding -> a submission-ready report per platform. Output is for a
HUMAN to review and submit. Nothing here talks to a platform API or submits.
"""
from __future__ import annotations
from dataclasses import dataclass, field

# vuln_class -> (severity label, CVSS 3.1 base estimate, vector) — a STARTING POINT
# the human finalizes. Conservative; exposure-confirmation findings, not exploits.
CVSS = {
    "rce":            ("Critical", 9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "takeover":       ("High",     8.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
    "auth-bypass":    ("High",     8.1, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
    "sqli":           ("High",     8.6, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
    "data-leak":      ("High",     7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "info-disclosure":("Medium",   5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "xss":            ("Medium",   6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "misconfig":      ("Medium",   5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
}
DEFAULT_CVSS = ("Medium", 5.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")


@dataclass
class Finding:
    host: str
    url: str = ""
    program: str = ""
    platform: str = ""           # hackerone | bugcrowd | intigriti | (other)
    vuln_class: str = "info-disclosure"
    signal_class: str = ""
    title: str = ""
    evidence: dict = field(default_factory=dict)   # probe, template, matched_at, response (redacted)
    poc_steps: list = field(default_factory=list)
    scope_confirmation: str = ""
    confirmed_at: str = ""
    dup_status: str = "unknown"   # likely-dup | no-known-dup | unknown
    dup_detail: str = ""
    revalidated_at: str = ""
    authored: dict = field(default_factory=dict)   # Claude-authored report (severity/cvss/impact/poc/dedup)

    def cvss(self):
        return CVSS.get(self.vuln_class, DEFAULT_CVSS)


def _common(f: Finding) -> dict:
    sev, score, vector = f.cvss()
    matched = f.evidence.get("matched_at") or f.url or f.host
    probe = f.evidence.get("probe", "?")
    tmpl = f.evidence.get("template") or f.evidence.get("status") or "-"
    default_steps = [
        f"GET {matched}",
        f"Observe the confirmed indicator ({probe}: {tmpl}) returned without authentication.",
        "The exposure is the finding — no further exploitation was performed (read-only PoC).",
    ]
    default_impact = (f"Unauthenticated exposure of `{f.vuln_class}` surface on {f.host}. "
                      "PoC is read-only confirmation; no data was accessed or modified.")
    # Claude-authored content takes precedence (honest severity + real PoC); template is the fallback.
    a = f.authored or {}
    title = a.get("title") or f.title or f"{f.vuln_class.upper()} on {f.host}"
    sev = a.get("severity") or sev
    score = a.get("cvss_score") if a.get("cvss_score") is not None else score
    vector = a.get("cvss_vector") or vector
    steps = a.get("poc_steps") or f.poc_steps or default_steps
    impact = a.get("impact") or default_impact
    dedup = a.get("dedup_assessment") or ""
    return {"title": title, "sev": sev, "score": score, "vector": vector,
            "matched": matched, "probe": probe, "tmpl": tmpl, "steps": steps,
            "impact": impact, "dedup": dedup, "authored": bool(a)}


def render_hackerone(f: Finding) -> str:
    c = _common(f)
    steps = "\n".join(f"{i+1}. {s}" for i, s in enumerate(c["steps"]))
    return f"""## Summary
{c['title']} — confirmed unauthenticated exposure on `{f.host}` (program: {f.program}).

## Severity
{c['sev']} — CVSS:3.1 {c['score']} (`{c['vector']}`) — *researcher estimate; please re-rate as appropriate.*

## Steps To Reproduce
{steps}

## Proof of Concept
- Affected URL: `{c['matched']}`
- Confirmation: {c['probe']} / `{c['tmpl']}`
- Evidence (redacted): `{f.evidence.get('response','(see attached)')}`

## Impact
{c['impact']}

## Scope
{f.scope_confirmation or 'In scope (confirmed via recon-scope at confirmation time).'}

---
_dup pre-check: {f.dup_status} — {f.dup_detail}{(' · Claude: ' + c['dedup']) if c['dedup'] else ''}_  ·  _confirmed_at: {f.confirmed_at}  ·  revalidated: {f.revalidated_at or 'n/a'}_
"""


def render_bugcrowd(f: Finding) -> str:
    c = _common(f)
    steps = "\n".join(f"- {s}" for s in c["steps"])
    return f"""**Title:** {c['title']}

**VRT / Severity:** {c['sev']} (CVSS:3.1 {c['score']} — {c['vector']}) — researcher estimate

**Affected URL:** {c['matched']}

**Steps to Reproduce:**
{steps}

**Confirmation:** {c['probe']} — {c['tmpl']}
**Evidence (redacted):** {f.evidence.get('response','(attached)')}

**Impact:** {c['impact']}

**Scope:** {f.scope_confirmation or 'In scope (recon-scope confirmed).'}

_program: {f.program} · dup: {f.dup_status} ({f.dup_detail}) · confirmed {f.confirmed_at} · reval {f.revalidated_at or 'n/a'}_
"""


def render_intigriti(f: Finding) -> str:
    c = _common(f)
    steps = "\n".join(f"{i+1}. {s}" for i, s in enumerate(c["steps"]))
    return f"""# {c['title']}

**Endpoint:** {c['matched']}
**Severity (CVSS 3.1):** {c['sev']} / {c['score']} — `{c['vector']}` (researcher estimate)

## Description
Confirmed unauthenticated {f.vuln_class} exposure on `{f.host}` ({f.program}).

## PoC (read-only)
{steps}

Confirmation: **{c['probe']}** — `{c['tmpl']}`
Evidence (redacted): {f.evidence.get('response','(attached)')}

## Impact
{c['impact']}

## Scope
{f.scope_confirmation or 'In scope (recon-scope confirmed).'}

> dup pre-check: {f.dup_status} — {f.dup_detail} · confirmed {f.confirmed_at} · revalidated {f.revalidated_at or 'n/a'}
"""


_RENDERERS = {
    "hackerone": render_hackerone, "h1": render_hackerone,
    "bugcrowd": render_bugcrowd,
    "intigriti": render_intigriti,
}


def render(f: Finding) -> str:
    fn = _RENDERERS.get((f.platform or "").lower().strip())
    if fn:
        return fn(f)
    # generic fallback (yeswehack / unknown platform) — H1 markdown is the safest default
    return render_hackerone(f) + f"\n\n_NOTE: no dedicated formatter for platform '{f.platform}'; rendered generic._\n"
