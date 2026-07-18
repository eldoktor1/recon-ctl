"""Safety layer: token auth, anti-rebinding/CSRF, explicit-confirm, fail-closed VPN gate.

Threat model for a loopback control plane:
  - DNS-rebinding  -> Host-header allowlist (a rebinding page can't forge Host).
  - CSRF from a tab -> token in a CUSTOM header (forces CORS preflight we deny) + Origin check.
  - other localhost apps -> token they can't read (chmod 600, our origin's localStorage).
Mirrors the pipeline: target-facing actions are refused when vpn_down is present.
"""
from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, Request

from . import config, daemon


def check_token(value: str | None) -> bool:
    if not value:
        return False
    return hmac.compare_digest(value, config.ui_token())


def require_token(x_recon_token: str | None = Header(default=None)) -> None:
    if not check_token(x_recon_token):
        raise HTTPException(status_code=401, detail="missing or invalid X-Recon-Token")


async def require_confirm(request: Request) -> dict:
    """Mutating routes must send {"confirm": true} and a same-origin Origin."""
    origin = request.headers.get("origin")
    if origin and origin not in config.ALLOWED_ORIGINS:
        raise HTTPException(status_code=403, detail=f"cross-origin request refused ({origin})")
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not body.get("confirm"):
        raise HTTPException(status_code=428, detail='confirmation required: send {"confirm": true}')
    return body


def require_vpn_up() -> None:
    """Fail-closed gate for target-facing lanes."""
    v = daemon.vpn_status()
    if v["down"]:
        raise HTTPException(
            status_code=409,
            detail=f"target-facing action blocked: VPN down ({v.get('reason') or 'vpn_down present'})",
        )
