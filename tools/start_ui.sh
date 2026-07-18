#!/usr/bin/env bash
# recon-ui control. Prefers the systemd --user service (always-on: boot-start via
# linger + auto-restart). Falls back to a detached setsid process if not installed.
# Read-only w.r.t. the pipeline; never touches egress/daemon.
set -uo pipefail

REPO="/home/d0k/recon-pipeline"
UI="$REPO/ui"
BACKEND="$UI/backend"
FRONTEND="$UI/frontend"
VENV="$BACKEND/.venv"
HOST="${RECON_UI_HOST:-127.0.0.1}"
PORT="${RECON_UI_PORT:-8787}"
PIDFILE="$HOME/recon/state/recon_ui.pid"
LOG="$HOME/recon/logs/recon_ui.log"
UNIT="recon-ui.service"
UNIT_SRC="$UI/systemd/$UNIT"
UNIT_DST="$HOME/.config/systemd/user/$UNIT"
RUNNER="recon-ui-runner.service"
RUNNER_SRC="$UI/systemd/$RUNNER"
RUNNER_DST="$HOME/.config/systemd/user/$RUNNER"
TOKEN_FILE="$HOME/recon/state/ui_token"

cmd="${1:-start}"

_have_unit() { [[ -f "$UNIT_DST" ]]; }
_uctl() { systemctl --user "$@"; }

_ensure_token() {
  if [[ ! -s "$TOKEN_FILE" ]]; then
    mkdir -p "$(dirname "$TOKEN_FILE")"
    # 32 url-safe bytes, generated as d0k outside the service sandbox
    python3 -c "import secrets;print(secrets.token_urlsafe(24))" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
    echo "[start_ui] generated access token → $TOKEN_FILE"
  fi
}

_ensure_venv() {
  if [[ ! -x "$VENV/bin/python" ]]; then
    echo "[start_ui] creating venv…"
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install -q --upgrade pip
    "$VENV/bin/pip" install -q -r "$BACKEND/requirements.txt"
  fi
}

_ensure_build() {
  if [[ -f "$FRONTEND/package.json" ]]; then
    if [[ ! -d "$FRONTEND/dist" || "$FRONTEND/src" -nt "$FRONTEND/dist" ]]; then
      echo "[start_ui] building frontend…"
      ( cd "$FRONTEND" && { [[ -d node_modules ]] || npm install --silent; } )
      ( cd "$FRONTEND" && npm run build --silent )
    fi
  fi
}

# --- manual (non-systemd) fallback -----------------------------------------
_manual_running() {
  [[ -f "$PIDFILE" ]] || return 1
  local pid; pid="$(cat "$PIDFILE" 2>/dev/null)"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}
_manual_start() {
  if _manual_running; then echo "recon-ui already running (pid $(cat "$PIDFILE"))"; return 0; fi
  _ensure_venv; _ensure_build
  mkdir -p "$(dirname "$PIDFILE")" "$(dirname "$LOG")"
  echo "[start_ui] starting uvicorn on http://$HOST:$PORT (detached)"
  setsid "$VENV/bin/python" -m uvicorn ui.backend.app:app \
    --host "$HOST" --port "$PORT" --app-dir "$REPO" </dev/null >"$LOG" 2>&1 &
  echo $! > "$PIDFILE"; disown 2>/dev/null || true; sleep 2
  _manual_running && echo "recon-ui up: http://localhost:$PORT (pid $(cat "$PIDFILE"))" \
    || { echo "failed — see $LOG"; tail -20 "$LOG"; return 1; }
}
_manual_stop() {
  if _manual_running; then kill "$(cat "$PIDFILE")" && echo "recon-ui stopped"; else echo "recon-ui not running"; fi
  rm -f "$PIDFILE"
}

case "$cmd" in
  install)
    _ensure_token; _ensure_venv; _ensure_build
    _manual_stop >/dev/null 2>&1 || true
    mkdir -p "$(dirname "$UNIT_DST")"
    cp "$UNIT_SRC" "$UNIT_DST"
    cp "$RUNNER_SRC" "$RUNNER_DST"
    _uctl daemon-reload
    _uctl enable --now "$RUNNER"   # runner first so lanes can execute immediately
    _uctl enable --now "$UNIT"
    # linger => user services run at boot without an interactive login
    if ! loginctl show-user "$USER" 2>/dev/null | grep -q "Linger=yes"; then
      loginctl enable-linger "$USER" 2>/dev/null || \
        echo "[start_ui] NOTE: could not enable linger automatically; run: sudo loginctl enable-linger $USER"
    fi
    sleep 2
    _uctl --no-pager status "$UNIT" | head -5
    echo; echo "recon-ui installed as an always-on service → http://localhost:$PORT"
    echo "hunt runner: $(_uctl is-active "$RUNNER")"
    echo "access token: $(cat "$TOKEN_FILE" 2>/dev/null || echo '(generated on first request)')"
    ;;
  uninstall)
    _uctl disable --now "$UNIT" 2>/dev/null || true
    _uctl disable --now "$RUNNER" 2>/dev/null || true
    rm -f "$UNIT_DST" "$RUNNER_DST"; _uctl daemon-reload
    echo "recon-ui + runner services removed"
    ;;
  start)
    _ensure_token
    if _have_unit; then _uctl start "$RUNNER" 2>/dev/null; _uctl start "$UNIT" && echo "recon-ui started → http://localhost:$PORT"; else _manual_start; fi ;;
  stop)
    if _have_unit; then _uctl stop "$UNIT" "$RUNNER" && echo "recon-ui stopped"; else _manual_stop; fi ;;
  restart)
    if _have_unit; then _ensure_build; _uctl restart "$RUNNER" 2>/dev/null; _uctl restart "$UNIT" && echo "recon-ui restarted"; else bash "$0" stop; sleep 1; bash "$0" start; fi ;;
  status)
    if _have_unit; then _uctl --no-pager status "$UNIT" | head -6; echo "runner: $(_uctl is-active "$RUNNER" 2>/dev/null)"; else
      _manual_running && echo "recon-ui running (pid $(cat "$PIDFILE")) → http://localhost:$PORT" || echo "recon-ui not running"; fi ;;
  logs)
    if [[ "${2:-}" == "runner" ]]; then _uctl --no-pager -n "${3:-60}" -u "$RUNNER" 2>/dev/null || journalctl --user -n "${3:-60}" -u "$RUNNER";
    elif _have_unit; then _uctl --no-pager -n "${2:-60}" -u "$UNIT" 2>/dev/null || journalctl --user -n "${2:-60}" -u "$UNIT"; else tail -n "${2:-60}" "$LOG"; fi ;;
  token)
    cat "$TOKEN_FILE" 2>/dev/null || echo "(no token yet — start the service once to generate it)" ;;
  rebuild)
    _ensure_build; bash "$0" restart ;;
  *)
    echo "usage: start_ui.sh {install|uninstall|start|stop|restart|status|logs|token|rebuild}"; exit 2 ;;
esac
