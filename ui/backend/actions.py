"""Mutation + ops wrappers. All d0k-safe (no escalation): findings.db via ACL,
JSONL ledgers, killswitch/maintenance state files. Each returns a small result dict.
"""
from __future__ import annotations

from typing import Any

from . import config
from .runner import run_recon, run_state


async def outcome(fid: int, resolution: str, bounty: float = 0.0) -> dict[str, Any]:
    if resolution not in ("accepted", "dup", "na", "info"):
        return {"ok": False, "error": f"invalid resolution: {resolution}"}
    r = await run_state("outcome", str(fid), resolution, str(bounty))
    return {"ok": r.ok, "result": r.json() or r.stdout.strip(), "error": None if r.ok else r.stderr}


async def note(host: str, text: str) -> dict[str, Any]:
    r = await run_recon("note", host, text)
    return {"ok": r.ok, "result": r.stdout.strip(), "error": None if r.ok else r.stderr}


async def ignore(host: str, reason: str = "manual") -> dict[str, Any]:
    r = await run_recon("ignore", host, reason)
    return {"ok": r.ok, "result": r.stdout.strip(), "error": None if r.ok else r.stderr}


# valid dismiss verdicts (each contains a note_verdict STRONG_DEAD marker)
_DISMISS_KINDS = {
    "not-actionable": "not actionable / no exploitable impact",
    "fp": "false positive",
    "by-design": "by-design / expected behaviour",
    "dup": "duplicate",
    "exhausted": "worked to a dead-end / exhausted",
    "out-of-scope": "out of scope / not eligible",
}


async def dismiss(host: str, kind: str = "not-actionable", reason: str = "",
                  vuln_class: str = "") -> dict[str, Any]:
    """Stop re-serving a host — CLASS-SCOPED when a vuln_class is given, WHOLE-HOST otherwise.

    * vuln_class given -> a note that names the class + a fp/not-a-finding marker, WITHOUT any
      whole-host ('do not re-serve' / 'exhausted') phrasing. note_verdict scopes the kill to that
      single class (`dead-class`) so every other class on the host stays servable — this avoids
      the over-suppression bug where dismissing one class killed the whole host.
    * no vuln_class -> the legacy whole-host DEAD note (exhausted / by-design over the entire host).
    """
    kind = (kind or "not-actionable").strip().lower()
    vuln_class = (vuln_class or "").strip()
    if vuln_class:
        # class-scoped: name the class + fp marker; NO whole-host/do-not-re words on purpose.
        text = f"ui-dismiss [class-fp] {vuln_class}: {vuln_class} false positive / not a finding here."
        if reason:
            text += f" {reason.strip()}"
        r = await run_recon("note", host, text)
        return {"ok": r.ok, "result": r.stdout.strip(),
                "error": None if r.ok else r.stderr, "verdict": "dead-class", "vuln_class": vuln_class}
    label = _DISMISS_KINDS.get(kind, _DISMISS_KINDS["not-actionable"])
    # 'false positive' + 'do not re-serve' both trip note_verdict's whole-host dead classifier
    text = f"ui-dismiss [{kind}]: {label} — false positive / not a finding."
    if reason:
        text += f" {reason.strip()}"
    text += " do not re-serve unless new signal warrants."
    r = await run_recon("note", host, text)
    return {"ok": r.ok, "result": r.stdout.strip(), "error": None if r.ok else r.stderr, "verdict": "dead"}


async def mark_fp(host: str, template_id: str) -> dict[str, Any]:
    """Add the nuclei template to known_fp.txt AND drop a class-scoped dead note.

    template_id typically encodes the vuln class (e.g. `spring-actuator`, `graphql-*`), so naming
    it in the note lets note_verdict scope the kill to that class (a template_id with no recognised
    class stays `dead-ambiguous` = it does NOT kill the host — the safe fallback)."""
    r = await run_recon("fp", host, template_id)
    note_text = f"ui-fp [{template_id}]: {template_id} false positive / not a finding here."
    nr = await run_recon("note", host, note_text)
    return {"ok": r.ok, "result": r.stdout.strip(), "error": None if r.ok else r.stderr,
            "note_ok": nr.ok, "verdict": "dead-class"}


async def scope(host: str) -> dict[str, Any]:
    r = await run_recon("scope", host, timeout=45)
    return {"ok": r.ok, "result": r.stdout.strip(), "error": None if r.ok else r.stderr}


async def rate(profile: str) -> dict[str, Any]:
    r = await run_recon("rate", profile)
    return {"ok": r.ok, "result": r.stdout.strip(), "error": None if r.ok else r.stderr}


async def maintenance(mode: str) -> dict[str, Any]:
    if mode not in ("on", "off", "status"):
        return {"ok": False, "error": "mode must be on|off|status"}
    r = await run_recon("maintenance", mode)
    return {"ok": r.ok, "result": r.stdout.strip(), "error": None if r.ok else r.stderr}


def killswitch_set(lane: str, on: bool) -> dict[str, Any]:
    """Create/remove a per-lane killswitch file (state/kill/v2_<lane>)."""
    lane = lane.strip()
    if lane.startswith("v2_"):          # strip the prefix, not the char-set
        lane = lane[3:]
    if not lane or not lane.replace("_", "").replace("-", "").isalnum():
        return {"ok": False, "error": "invalid lane name"}
    path = config.KILL_DIR / f"v2_{lane}"
    try:
        config.KILL_DIR.mkdir(parents=True, exist_ok=True)
        if on:
            path.write_text("ui\n")
        elif path.exists():
            path.unlink()
        return {"ok": True, "lane": lane, "killed": on}
    except Exception as e:
        return {"ok": False, "error": str(e)}
