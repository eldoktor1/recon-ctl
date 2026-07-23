"""recon-ui backend — FastAPI app.

Single origin: serves the built SPA (ui/frontend/dist) + the /api surface.
Read routes are open on localhost; mutating/target routes are token + confirm
+ vpn gated (see safety.py). No pipeline logic lives here.
"""
from __future__ import annotations

import asyncio
import contextlib
import mimetypes
from typing import Any

# PWA: ensure correct content types for the manifest + service worker
mimetypes.add_type("application/manifest+json", ".webmanifest")
mimetypes.add_type("text/javascript", ".js")

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import actions, claude_console, config, daemon, es, files, findings, safety
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
async def build_status() -> dict[str, Any]:
    es_health, = await asyncio.gather(es.cluster_health())
    return {
        "daemon": daemon.daemon_status(),
        "vpn": daemon.vpn_status(),
        "es": es_health,
        "queue": daemon.queue_depth(),
        "killswitches": daemon.killswitches(),
        "findings_by_state": findings.state_counts(),
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
                       q: str | None = None, limit: int = 100, offset: int = 0):
    return findings.list_findings(state=state, program=program, vuln_class=vuln_class,
                                  verdict=verdict, q=q, limit=min(limit, 500), offset=offset)


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
                     limit: int = 100, offset: int = 0):
    return await es.search(q=q, program=program, priority=priority, cls=cls, tech=tech, kev=kev,
                           fresh=fresh, pays=pays, include_benched=include_benched,
                           limit=limit, offset=offset)


@app.get("/api/assets/facets")
async def api_asset_facets():
    return await es.facets()


@app.get("/api/leads")
async def api_leads(pays_only: bool = True):
    return await es.active_leads(pays_only=pays_only)


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


# --------------------------------------------------------------------------- global search
@app.get("/api/search")
async def api_search(q: str):
    q = q.strip()
    if len(q) < 2:
        return {"hosts": [], "findings": [], "notes": [], "programs": []}
    import asyncio as _a

    async def hosts():
        r = await es.search(q=q, limit=8, include_benched=True)
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
