"""recon-ui backend — FastAPI app.

Single origin: serves the built SPA (ui/frontend/dist) + the /api surface.
Read routes are open on localhost; mutating/target routes are token + confirm
+ vpn gated (see safety.py). No pipeline logic lives here.
"""
from __future__ import annotations

import asyncio
import contextlib
import mimetypes
import re
from typing import Any

# PWA: ensure correct content types for the manifest + service worker
mimetypes.add_type("application/manifest+json", ".webmanifest")
mimetypes.add_type("text/javascript", ".js")

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import actions, claude_console, config, daemon, es, files, findings, safety, workspace
from .runner import run_observability, run_recon, run_state
from .tasks import LANES, manager

app = FastAPI(title="recon-ui", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)

_CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
    "script-src 'self'; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'"
)


@app.middleware("http")
async def security_gate(request: Request, call_next):
    # 1. Host-header allowlist — defeats DNS-rebinding.
    host = (request.headers.get("host") or "").lower()
    if host and host not in config.ALLOWED_HOSTS:
        return JSONResponse({"detail": f"host not allowed: {host}"}, status_code=403)

    # 2. Token on every /api route (reads included). Static SPA stays open so the
    #    page can load and prompt for the token.
    path = request.url.path
    if path.startswith("/api/"):
        if not safety.check_token(request.headers.get("x-recon-token")):
            return JSONResponse({"detail": "missing or invalid X-Recon-Token"}, status_code=401)

    resp: Response = await call_next(request)

    # 3. Hardened response headers on everything.
    resp.headers["Content-Security-Policy"] = _CSP
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Server"] = "recon-ui"  # drop the uvicorn version banner
    # Cache policy: content-hashed /assets/ can live forever; the SPA shell, SW,
    # manifest and all API responses must revalidate so a rebuild is picked up
    # immediately (stale index.html -> old bundle was the "old nav" bug).
    if path.startswith("/assets/"):
        resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    else:
        resp.headers["Cache-Control"] = "no-cache, must-revalidate"
    return resp


# --------------------------------------------------------------------------- status
def _ui_build() -> str:
    """Content hash of the currently-served bundle (the main JS asset filename changes every
    rebuild). A running tab compares this against the build it loaded and prompts a reload when
    it changes — so a rebuild is never silently stale behind SPA-internal navigation."""
    try:
        html = (config.FRONTEND_DIST / "index.html").read_text()
        m = re.search(r"/assets/(index-[A-Za-z0-9_-]+\.js)", html)
        return m.group(1) if m else ""
    except Exception:
        return ""


async def build_status() -> dict[str, Any]:
    es_health, = await asyncio.gather(es.cluster_health())
    return {
        "daemon": daemon.daemon_status(),
        "vpn": daemon.vpn_status(),
        "es": es_health,
        "queue": daemon.queue_depth(),
        "killswitches": daemon.killswitches(),
        "findings_by_state": findings.state_counts(),
        "ui_build": _ui_build(),
        "token_required": True,
    }


@app.get("/api/status")
async def api_status():
    return await build_status()


@app.get("/api/overview")
async def api_overview():
    """Everything the Command Center needs in one shot."""
    status = await build_status()
    return {
        **status,
        "recent_confirmed": findings.recent_confirmed(8),
        "tonight": files.latest_tonight(),
        "selfaudit": (daemon.selfaudit() or {}).get("summary") if daemon.selfaudit() else None,
    }


# --------------------------------------------------------------------------- findings (read)
@app.get("/api/findings")
async def api_findings(state: str | None = None, program: str | None = None,
                       vuln_class: str | None = None, verdict: str | None = None,
                       q: str | None = None, sort: str = "recent", order: str = "desc",
                       limit: int = 100, offset: int = 0):
    return findings.list_findings(state=state, program=program, vuln_class=vuln_class,
                                  verdict=verdict, q=q, sort=sort, order=order,
                                  limit=min(limit, 500), offset=offset)


@app.get("/api/findings/facets")
async def api_findings_facets():
    return findings.facets()


@app.get("/api/findings/{fid}")
async def api_finding(fid: int):
    f = findings.get_finding(fid)
    if not f:
        raise HTTPException(404, "finding not found")
    return f


# --------------------------------------------------------------------------- assets (read)
@app.get("/api/assets")
async def api_assets(q: str | None = None, program: str | None = None, priority: str | None = None,
                     cls: str | None = None, tech: str | None = None, kev: bool = False,
                     fresh: bool = False, pays: bool = False, include_benched: bool = False,
                     include_oos: bool = False, include_nopay: bool = False,
                     sort: str = "triage_score", order: str = "desc",
                     limit: int = 100, offset: int = 0):
    return await es.search(q=q, program=program, priority=priority, cls=cls, tech=tech, kev=kev,
                           fresh=fresh, pays=pays, include_benched=include_benched,
                           include_oos=include_oos, include_nopay=include_nopay,
                           sort=sort, order=order, limit=limit, offset=offset)


@app.get("/api/assets/facets")
async def api_asset_facets():
    return await es.facets()


# Each live-signal lead bucket maps to the vuln CLASS a class-scoped FP note would refute
# (matching tools/note_verdict.CLASS_PATTERNS keys). A host FP'd for that class drops from the
# bucket even without a host-wide kill. `fresh` is multi-class (newly-surfaced surface, no single
# class) → only a host-wide kill removes it.
_BUCKET_CLASS: dict[str, str | None] = {
    "takeover": "takeover", "takeover_lead": "takeover",
    "secrets": "secret", "kev": "nday", "fresh": None,
}


@app.get("/api/leads")
async def api_leads(pays_only: bool = True, include_dismissed: bool = False,
                    include_oos: bool = False, include_nopay: bool = False):
    # `pays_only` stays for back-compat: pays_only=False is the same as include_nopay=True.
    data = await es.active_leads(include_oos=include_oos,
                                 include_nopay=(include_nopay or not pays_only))
    if not include_dismissed:
        killed = files.killed_host_set()          # host-wide DEAD
        killed_cls = files.killed_host_classes()  # {host -> {class,…}} class-scoped FP
        for b in data.get("buckets", []):
            bcls = _BUCKET_CLASS.get(b.get("key"))
            hosts = b.get("hosts", [])

            def _dropped(h: dict) -> bool:
                hn = (h.get("host") or "").lower()
                if hn in killed:
                    return True  # host-wide kill
                # class-scoped FP on THIS bucket's class → drop (a just-FP'd host must not reappear)
                return bool(bcls) and bcls in killed_cls.get(hn, set())

            kept = [h for h in hosts if not _dropped(h)]
            drop = len(hosts) - len(kept)
            if drop:
                b["hosts"] = kept
                b["suppressed"] = drop
                if isinstance(b.get("count"), int):
                    b["count"] = max(0, b["count"] - drop)
    return data


# NOTE: keep this AFTER /api/assets/facets so "facets" isn't captured as a host
@app.get("/api/assets/{host}")
async def api_asset(host: str):
    d = await es.host_detail(host)
    if not d:
        raise HTTPException(404, "host not found")
    return d


# --------------------------------------------------------------------------- notes + benched (worked knowledge)
@app.get("/api/notes")
async def api_notes(q: str | None = None):
    return {"stats": files.notes_stats(), "items": files.notes(q=q)}


@app.get("/api/ignores")
async def api_ignores():
    return files.active_ignores()


# --------------------------------------------------------------------------- briefings (read)
@app.get("/api/briefings")
async def api_briefings():
    return files.list_briefings()


@app.get("/api/briefings/{name}")
async def api_briefing(name: str):
    body = files.read_briefing(name)
    if body is None:
        raise HTTPException(404, "briefing not found")
    return {"name": name, "body": body}


@app.get("/api/briefings/{name}/parsed")
async def api_briefing_parsed(name: str):
    """Structured sections+items (host chips, commands, severity) for the
    interactive worklist. Falls back to a raw section on parse failure."""
    p = files.parse_briefing(name)
    if p is None:
        raise HTTPException(404, "briefing not found")
    return p


@app.get("/api/tonight")
async def api_tonight():
    """The latest tonight_* briefing, parsed — powers the worklist + home widget."""
    p = files.latest_tonight_parsed()
    return p or {"error": "no tonight briefing generated yet", "sections": []}


@app.get("/api/telemetry/ai-accuracy")
async def api_ai_accuracy():
    res = await run_state("ai-accuracy")
    return res.json() or {"error": res.stderr or "unavailable"}


@app.get("/api/submissions")
async def api_submissions():
    return files.submissions()


@app.get("/api/selfaudit")
async def api_selfaudit():
    return daemon.selfaudit() or {"error": "no self-audit report"}


@app.get("/api/logs")
async def api_logs(tail: int = 200):
    return {"lines": daemon.tail_file(config.DAEMON_LOG, min(tail, 1000))}


# --------------------------------------------------------------------------- finding actions (mutating)
@app.post("/api/findings/{fid}/outcome")
async def api_outcome(fid: int, body: dict = Depends(safety.require_confirm)):
    res = body.get("resolution", "")
    return await actions.outcome(fid, res, float(body.get("bounty", 0) or 0))


@app.post("/api/hosts/{host}/note")
async def api_note(host: str, body: dict = Depends(safety.require_confirm)):
    text = (body.get("text") or "").strip()
    if not text:
        raise HTTPException(400, "note text required")
    return await actions.note(host, text)


@app.post("/api/hosts/{host}/ignore")
async def api_ignore(host: str, body: dict = Depends(safety.require_confirm)):
    return await actions.ignore(host, (body.get("reason") or "manual").strip())


@app.post("/api/hosts/{host}/dismiss")
async def api_dismiss(host: str, body: dict = Depends(safety.require_confirm)):
    """Mark a lead/host FP or not-actionable — records a DEAD-verdict note so it
    stops being re-served in the worklist + nightly briefing (until re-armed)."""
    return await actions.dismiss(host, (body.get("kind") or "not-actionable").strip(),
                                 (body.get("reason") or "").strip(),
                                 (body.get("vuln_class") or "").strip())


@app.post("/api/hosts/{host}/fp")
async def api_fp(host: str, body: dict = Depends(safety.require_confirm)):
    tid = (body.get("template_id") or "").strip()
    if not tid:
        raise HTTPException(400, "template_id required")
    return await actions.mark_fp(host, tid)


@app.get("/api/scope/{host}")
async def api_scope(host: str):
    return await actions.scope(host)


# --------------------------------------------------------------------------- hunt control (tasks)
@app.get("/api/lanes")
async def api_lanes():
    return [{"lane": k, **v} for k, v in LANES.items()]


@app.get("/api/lanes/activity")
async def api_lanes_activity():
    """Full daemon-lane view (~50 lanes): killswitch state + yield + liveness for EVERY
    supervised lane, not just the on-demand LANES. Read-only (token-gated by the middleware)."""
    yl = None
    try:
        r = await run_observability("json")
        j = r.json()
        if isinstance(j, dict):
            yl = (j.get("yield_audit") or {}).get("lanes")
    except Exception:
        yl = None
    return daemon.lane_activity(yl)


@app.get("/api/lanes/{lane}/log")
async def api_lane_log(lane: str, tail: int = 200):
    """Tail one lane's log (its own file if present, else the daemon log filtered to the lane)."""
    return {"lane": lane, "lines": daemon.lane_log(lane, min(max(tail, 1), 1000))}


@app.get("/api/tasks")
async def api_tasks():
    return manager.list()


@app.get("/api/tasks/{tid}")
async def api_task(tid: int):
    t = manager.get(tid)
    if not t:
        raise HTTPException(404, "task not found")
    return {**t.snapshot(), "lines": list(t.lines)}


@app.post("/api/hunt/{lane}")
async def api_hunt(lane: str, body: dict = Depends(safety.require_confirm)):
    spec = LANES.get(lane)
    if not spec:
        raise HTTPException(404, f"unknown lane: {lane}")
    if spec["target"]:
        safety.require_vpn_up()  # fail-closed for target-facing lanes
    argv = ["bash", str(config.RECON_CTL), spec["sub"]]
    extra = body.get("args")
    if isinstance(extra, list):
        argv += [str(a) for a in extra][:8]
    t = await manager.spawn(f"{lane}", argv)
    return t.snapshot()


@app.get("/api/claude/config")
async def api_claude_config():
    """Is the in-UI Claude co-pilot wired up, and which models are offered."""
    return claude_console.available()


@app.get("/api/claude/sessions")
async def api_claude_sessions():
    """List Co-Pilot conversations (newest first) so the operator can switch back in."""
    return claude_console.list_sessions()


@app.get("/api/claude/sessions/{sid}")
async def api_claude_session(sid: str):
    """Full transcript of one conversation, shaped for the chat UI."""
    if not claude_console.valid_session(sid):
        raise HTTPException(400, "bad session id")
    return {"session_id": sid, "turns": claude_console.load_transcript(sid)}


@app.post("/api/claude/sessions/{sid}/delete")
async def api_claude_session_delete(sid: str, body: dict = Depends(safety.require_confirm)):
    """Delete a Co-Pilot conversation (marker + transcript)."""
    if not claude_console.valid_session(sid):
        raise HTTPException(400, "bad session id")
    return claude_console.delete_session(sid)


@app.post("/api/claude/message")
async def api_claude_message(body: dict = Depends(safety.require_confirm)):
    """One conversational turn of the operator's driving console.

    Off-target by construction: the console runs `recon` commands + reads state;
    target-facing lanes it may invoke stay behind their own run_scanner/VPN gate,
    so no VPN gate is applied to the console turn itself.
    """
    message = (body.get("message") or "").strip()
    if not message:
        raise HTTPException(400, "message required")
    if len(message) > 16000:
        raise HTTPException(413, "message too long")
    sid = (body.get("session_id") or "").strip()
    if not claude_console.valid_session(sid):
        sid = claude_console.new_session_id()
    model = body.get("model")
    argv = claude_console.build_argv(sid, message, model)
    t = await manager.spawn(f"claude:{sid[:8]}", argv)
    return {**t.snapshot(), "session_id": sid}


@app.post("/api/verify")
async def api_verify(body: dict = Depends(safety.require_confirm)):
    host = (body.get("host") or "").strip()
    if not host:
        raise HTTPException(400, "host required")
    safety.require_vpn_up()
    argv = ["bash", str(config.RECON_CTL), "verify", host]
    t = await manager.spawn(f"verify:{host}", argv)
    return t.snapshot()


# Host-targeted on-demand actions — the operator drives a single host's whole
# test workflow from its drawer. Server-side whitelist: the client picks an
# action KEY, never an argv. (sub-args, target-facing?) — target lanes are
# VPN-gated fail-closed. These map to the same commands the copy-chips show.
HOST_ACTIONS: dict[str, tuple[list[str], bool, str]] = {
    "verify":       (["verify"], True, "Claude verify (multimodal + safe probes)"),
    "crawl":        (["params", "crawl-host"], True, "on-demand param crawl (katana+gau+CDX)"),
    "confirm-xss":  (["params", "confirm", "xss"], True, "XSS confirm (dalfox — must execute)"),
    "confirm-sqli": (["params", "confirm", "sqli"], True, "SQLi confirm ('vs'' diff → sqlmap)"),
    "arjun":        (["params", "arjun"], True, "active hidden-param discovery (arjun)"),
    "domxss":       (["domxss"], True, "DOM-XSS source→sink miner"),
    "graphql":      (["graphql", "check"], True, "GraphQL introspection → schema"),
    "wcd":          (["wcd", "confirm"], True, "web-cache deception confirm (WCVS)"),
}


@app.get("/api/host-actions")
async def api_host_actions():
    return [{"action": k, "target": v[1], "desc": v[2]} for k, v in HOST_ACTIONS.items()]


@app.post("/api/hosts/{host}/run")
async def api_host_run(host: str, body: dict = Depends(safety.require_confirm)):
    action = (body.get("action") or "").strip()
    spec = HOST_ACTIONS.get(action)
    if not spec:
        raise HTTPException(400, f"unknown host action: {action}")
    sub, target, _ = spec
    host = host.strip()
    if not host or any(c in host for c in " ;|&$`\n\t'\"\\"):
        raise HTTPException(400, "bad host")
    if target:
        safety.require_vpn_up()  # fail-closed for target-facing actions
    argv = ["bash", str(config.RECON_CTL), *sub, host]
    t = await manager.spawn(f"{action}:{host}", argv)
    return t.snapshot()


@app.post("/api/tasks/{tid}/stop")
async def api_task_stop(tid: int, body: dict = Depends(safety.require_confirm)):
    ok = await manager.stop(tid)
    if not ok:
        raise HTTPException(409, "task not running or not found")
    return {"ok": True}


@app.websocket("/api/tasks/{tid}/output")
async def ws_task_output(ws: WebSocket, tid: int):
    host = (ws.headers.get("host") or "").lower()
    if host and host not in config.ALLOWED_HOSTS:
        await ws.close(code=1008); return
    if not safety.check_token(ws.query_params.get("token")):
        await ws.close(code=1008); return
    await ws.accept()
    q = manager.subscribe(tid)
    if q is None:
        await ws.send_json({"type": "error", "error": "task not found"})
        await ws.close(); return
    try:
        while True:
            line = await q.get()
            if line is None:
                t = manager.get(tid)
                await ws.send_json({"type": "end", "state": t.state if t else "?"})
                break
            await ws.send_json({"type": "line", "data": line})
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    finally:
        manager.unsubscribe(tid, q)


# --------------------------------------------------------------------------- ops (daemon control)
@app.post("/api/daemon/maintenance")
async def api_maintenance(body: dict = Depends(safety.require_confirm)):
    return await actions.maintenance((body.get("mode") or "status").strip())


@app.post("/api/daemon/rate")
async def api_rate(body: dict = Depends(safety.require_confirm)):
    return await actions.rate((body.get("profile") or "status").strip())


@app.get("/api/killswitches")
async def api_killswitches():
    return daemon.killswitches()


@app.post("/api/killswitch/{lane}")
async def api_killswitch(lane: str, body: dict = Depends(safety.require_confirm)):
    return actions.killswitch_set(lane, bool(body.get("on")))


# --------------------------------------------------------------------------- telemetry + reports
@app.get("/api/telemetry/counters")
async def api_counters():
    r = await run_observability("json")
    return r.json() or {"error": r.stderr or "unavailable"}


@app.get("/api/reports")
async def api_reports():
    return files.reports()


@app.get("/api/targets")
async def api_targets():
    return files.target_board()


@app.post("/api/targets/onboard")
async def api_targets_onboard(body: dict = Depends(safety.require_confirm)):
    key = (body.get("key") or "").strip()
    if not key:
        raise HTTPException(400, "program key required")
    r = await run_recon("targets", "onboard", key, timeout=120)
    return {"ok": r.ok, "result": (r.stdout or r.stderr).strip()[-4000:]}


@app.get("/api/digest")
async def api_digest():
    r = await run_observability("json")
    return r.json() or {"error": r.stderr or "unavailable"}


# --------------------------------------------------------------------------- program workspace
@app.get("/api/workspaces")
async def api_workspaces():
    """All engagement workspaces (with offline + live-joined counts) + seed candidates."""
    workspace.ensure_seeded()
    out = []
    for ws in workspace.list_all():
        name = ws.get("name") or ws.get("key")
        counts = workspace.summarize(ws)
        try:
            counts["findings"] = findings.list_findings(program=name, limit=0)["total"]
        except Exception:
            pass
        try:
            counts["hosts"] = (await es.search(program=name, limit=0)).get("total") or 0
        except Exception:
            pass
        out.append({
            "key": ws["key"], "name": name, "platform": ws.get("platform"),
            "status": ws.get("status"), "current": ws.get("current", False),
            "added_at": ws.get("added_at"), "counts": counts,
        })
    return {"workspaces": out, "candidates": workspace.candidates()}


@app.post("/api/workspaces")
async def api_workspace_create(body: dict = Depends(safety.require_confirm)):
    """Create/activate a workspace (idempotent). Seeds WSTG+STRIDE+class templates."""
    key = (body.get("key") or "").strip()
    if not key:
        raise HTTPException(400, "workspace key required")
    try:
        return workspace.create(key, (body.get("name") or "").strip() or None,
                                (body.get("platform") or "").strip() or None)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/wstg/reference")
async def api_wstg_reference():
    """Static WSTG v4.2 reference (objective/how_to/tools/url per test) + the STRIDE guide.

    Read-only grounding for the Guided walkthrough so no test is glossed over."""
    return {"wstg": workspace.wstg_reference(), "stride": workspace.STRIDE_GUIDE}


@app.get("/api/workspaces/{key}")
async def api_workspace(key: str):
    """Full workspace + LIVE joins: in-scope+paying ES hosts and findings.db rows.

    Each WSTG item carries the merged static reference so the UI always has substance."""
    ws = workspace.load(key)
    if not ws:
        raise HTTPException(404, "workspace not found")
    name = ws.get("name") or ws.get("key")
    try:
        hosts = (await es.search(program=name, limit=200)).get("items", [])
    except Exception:
        hosts = []
    try:
        fnd = findings.list_findings(program=name, limit=200)["items"]
    except Exception:
        fnd = []
    ws["wstg"] = workspace.merge_reference(ws.get("wstg", []))
    return {**ws, "hosts": hosts, "findings": fnd}


@app.post("/api/workspaces/{key}/guide")
async def api_workspace_guide(key: str, body: dict = Depends(safety.require_confirm)):
    """AI-guided, program-specific guidance for one STRIDE/WSTG step.

    Off-target by construction (Claude reasoning over context, no target packets) so no VPN
    gate — it streams to the frontend over the existing task-output WS like the co-pilot."""
    ws = workspace.load(key)
    if not ws:
        raise HTTPException(404, "workspace not found")
    phase = (body.get("phase") or "").strip().lower()
    if phase not in ("stride", "wstg"):
        raise HTTPException(400, "phase must be 'stride' or 'wstg'")
    ident = (body.get("id") or "").strip()
    host = (body.get("host") or "").strip()
    if host and any(c in host for c in " ;|&$`\n\t'\"\\"):
        raise HTTPException(400, "bad host")
    if phase == "wstg" and ident not in workspace.wstg_reference():
        raise HTTPException(400, "unknown WSTG id")
    if phase == "stride" and ident.upper()[:1] not in workspace.STRIDE_GUIDE:
        raise HTTPException(400, "unknown STRIDE category")
    name = ws.get("name") or ws.get("key")
    try:
        hosts = (await es.search(program=name, limit=25)).get("items", [])
    except Exception:
        hosts = []
    endpoints = files.program_endpoints([h.get("host") for h in hosts])
    prompt = workspace.build_guide_prompt(ws, phase, ident, host, hosts, endpoints)
    sid = claude_console.new_session_id()
    argv = claude_console.build_argv(sid, prompt, body.get("model"))
    label = (ident or host or key)[:16]
    t = await manager.spawn(f"guide:{phase}:{label}", argv)
    return {**t.snapshot(), "session_id": sid, "task_id": t.id}


@app.post("/api/hosts/{host}/autonote")
async def api_host_autonote(host: str, body: dict = Depends(safety.require_confirm)):
    """Draft a concise host note (where testing of this host stands) via Claude.

    Off-target by construction (reasoning over ES/findings/existing-notes context, no target
    packets, no tool-driving) so no VPN gate — streams like the co-pilot. The frontend confirms/
    edits the draft, then persists it via POST /api/hosts/{host}/note."""
    if any(c in host for c in " ;|&$`\n\t'\"\\"):
        raise HTTPException(400, "bad host")
    try:
        doc = await es.host_detail(host)
    except Exception:
        doc = None
    try:
        fnd = findings.list_findings(q=host, limit=25).get("items", [])
    except Exception:
        fnd = []
    notes = (doc or {}).get("host_notes") or []
    prompt = workspace.build_host_note_prompt(host, doc, fnd, notes)
    sid = claude_console.new_session_id()
    argv = claude_console.build_argv(sid, prompt, body.get("model"))
    t = await manager.spawn(f"autonote:host:{host[:24]}", argv)
    return {**t.snapshot(), "session_id": sid, "task_id": t.id}


@app.post("/api/workspaces/{key}/autonote")
async def api_workspace_autonote(key: str, body: dict = Depends(safety.require_confirm)):
    """Draft a concise engagement-summary note for the program via Claude. Off-target (reasoning
    over ES/findings/coverage context) so no VPN gate; streams like the co-pilot. The frontend
    confirms/edits the draft, then persists it via POST /api/workspaces/{key}/note."""
    ws = workspace.load(key)
    if not ws:
        raise HTTPException(404, "workspace not found")
    name = ws.get("name") or ws.get("key")
    try:
        hosts = (await es.search(program=name, limit=25)).get("items", [])
    except Exception:
        hosts = []
    try:
        fnd = findings.list_findings(program=name, limit=30).get("items", [])
    except Exception:
        fnd = []
    endpoints = files.program_endpoints([h.get("host") for h in hosts])
    prompt = workspace.build_program_note_prompt(ws, hosts, endpoints, fnd)
    sid = claude_console.new_session_id()
    argv = claude_console.build_argv(sid, prompt, body.get("model"))
    t = await manager.spawn(f"autonote:prog:{key[:24]}", argv)
    return {**t.snapshot(), "session_id": sid, "task_id": t.id}


@app.post("/api/workspaces/{key}/wstg")
async def api_workspace_wstg(key: str, body: dict = Depends(safety.require_confirm)):
    wid = (body.get("id") or "").strip()
    status = (body.get("status") or "").strip()
    if not wid or not status:
        raise HTTPException(400, "id and status required")
    try:
        return workspace.update_wstg(key, wid, status, body.get("note"))
    except KeyError:
        raise HTTPException(404, "workspace or WSTG item not found")
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/workspaces/{key}/stride")
async def api_workspace_stride(key: str, body: dict = Depends(safety.require_confirm)):
    hosts = body.get("hosts")
    try:
        return workspace.update_stride(
            key, (body.get("cat") or "").strip(), (body.get("threat") or "").strip(),
            sid=(body.get("id") or "").strip() or None, note=body.get("note"),
            status=body.get("status"),
            hosts=hosts if isinstance(hosts, list) else None)
    except KeyError:
        raise HTTPException(404, "workspace not found")
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/workspaces/{key}/class")
async def api_workspace_class(key: str, body: dict = Depends(safety.require_confirm)):
    try:
        return workspace.set_class(key, (body.get("cls") or "").strip(),
                                   (body.get("status") or "").strip())
    except KeyError:
        raise HTTPException(404, "workspace not found")
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/workspaces/{key}/note")
async def api_workspace_note(key: str, body: dict = Depends(safety.require_confirm)):
    try:
        return workspace.add_note(key, (body.get("text") or "").strip())
    except KeyError:
        raise HTTPException(404, "workspace not found")
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/workspaces/{key}/stride/delete")
async def api_workspace_stride_delete(key: str, body: dict = Depends(safety.require_confirm)):
    cat = (body.get("cat") or "").strip()
    sid = (body.get("id") or "").strip()
    if not cat or not sid:
        raise HTTPException(400, "cat and id required")
    try:
        return workspace.delete_stride(key, cat, sid)
    except KeyError:
        raise HTTPException(404, "workspace not found")


@app.post("/api/workspaces/{key}/note/delete")
async def api_workspace_note_delete(key: str, body: dict = Depends(safety.require_confirm)):
    idx = body.get("index")
    if not isinstance(idx, int) or idx < 0:
        raise HTTPException(400, "valid index required")
    try:
        return workspace.delete_note(key, idx)
    except KeyError:
        raise HTTPException(404, "workspace not found")


@app.post("/api/workspaces/{key}/status")
async def api_workspace_status(key: str, body: dict = Depends(safety.require_confirm)):
    try:
        return workspace.set_status(key, body.get("status"), body.get("current"))
    except KeyError:
        raise HTTPException(404, "workspace not found")
    except ValueError as e:
        raise HTTPException(400, str(e))


# --------------------------------------------------------------------------- global search
@app.get("/api/search")
async def api_search(q: str):
    q = q.strip()
    if len(q) < 2:
        return {"hosts": [], "findings": [], "notes": [], "programs": []}
    import asyncio as _a

    async def hosts():
        # global search casts wide — include OOS + non-paying so nothing is hidden
        r = await es.search(q=q, limit=8, include_benched=True,
                            include_oos=True, include_nopay=True)
        return r.get("items", [])

    hosts_r, = await _a.gather(hosts())
    fnd = findings.list_findings(q=q, limit=8)["items"]
    nts = files.notes(q=q, limit=8)
    tb = files.target_board().get("programs", [])
    ql = q.lower()
    progs = [p for p in tb if ql in (p.get("name", "") + " " + p.get("key", "")).lower()][:8]
    return {"hosts": hosts_r, "findings": fnd, "notes": nts, "programs": progs}


# --------------------------------------------------------------------------- live stream
@app.websocket("/api/stream")
async def ws_stream(ws: WebSocket):
    # Host check + token via query param (WS can't carry custom headers in browsers).
    host = (ws.headers.get("host") or "").lower()
    if host and host not in config.ALLOWED_HOSTS:
        await ws.close(code=1008)
        return
    if not safety.check_token(ws.query_params.get("token")):
        await ws.close(code=1008)
        return
    await ws.accept()
    try:
        while True:
            await ws.send_json({"type": "status", "data": await build_status()})
            await asyncio.sleep(4)
    except (WebSocketDisconnect, asyncio.CancelledError):
        return
    except Exception:
        with contextlib.suppress(Exception):
            await ws.close()


# --------------------------------------------------------------------------- static SPA
if config.FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=str(config.FRONTEND_DIST / "assets")), name="assets")

    _DIST_ROOT = config.FRONTEND_DIST.resolve()

    @app.get("/{full_path:path}")
    async def spa(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(404, "not found")
        index = _DIST_ROOT / "index.html"
        if full_path:
            # confine to dist — resolve() collapses ../ so traversal can't escape
            cand = (_DIST_ROOT / full_path).resolve()
            if (cand == _DIST_ROOT or _DIST_ROOT in cand.parents) and cand.is_file():
                return FileResponse(str(cand))
        return FileResponse(str(index))
else:
    @app.get("/")
    async def placeholder():
        return JSONResponse({
            "recon-ui": "backend up",
            "frontend": "not built yet — run tools/start_ui.sh or vite build",
            "try": ["/api/status", "/api/overview", "/api/findings", "/api/assets"],
        })
