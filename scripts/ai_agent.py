#!/usr/bin/env python3
"""ai_agent.py — full-capability agentic loop for the LOCAL brain (Claude fallback).

When Claude is rate-limited the co-pilot falls over to the local model. A plain chat model can
only TALK; this gives it REAL agency with the SAME tool parity as the Claude co-pilot: a `bash`
tool (drive the whole recon-ctl pipeline, curl through the Burp proxy, launch/drive Brave, read/
write files, git, python) plus `web_search`.

DUAL-MODE so it works with the best model for the job:
  * native tool-calling when the model exposes the `tools` capability (e.g. hermes3) — most reliable;
  * a model-agnostic ReAct text protocol (TOOL:/ARG:) otherwise, so pentest-tuned models whose
    Ollama build lacks `tools` (e.g. mythos-sec:8b) still act.

The GUARDRAIL is the DOCTRINE in the system prompt, NOT a crippled toolset (operator: "don't kill
it with guardrails"). Infra safety stays because it can't be bypassed: Mullvad is the OS-level sole
egress and vpn_down fail-closes the recon lanes.

Output is stream-json (one event per line) matching `claude -p --output-format stream-json`.

Usage: ai_agent.py <prompt>            (or prompt on stdin)
Env:   AGENT_MODEL, OLLAMA_URL, AI_AGENT_MAX_ROUNDS, AI_AGENT_BASH_TIMEOUT
"""
import os
import sys
import re
import json
import html
import subprocess
import urllib.request
import urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
MODEL = os.environ.get("AGENT_MODEL", "hermes3:8b")
MAX_ROUNDS = int(os.environ.get("AI_AGENT_MAX_ROUNDS", "12"))
BASH_TIMEOUT = int(os.environ.get("AI_AGENT_BASH_TIMEOUT", "120"))
OUT_CAP = 6000


def emit(o):
    sys.stdout.write(json.dumps(o) + "\n")
    sys.stdout.flush()


def emit_text(t):
    if t and t.strip():
        emit({"type": "assistant", "message": {"content": [{"type": "text", "text": t}]}})


def emit_tool_use(name, args):
    emit({"type": "assistant", "message": {"content": [{"type": "tool_use", "name": name, "input": args}]}})


def emit_tool_result(text, err=False):
    emit({"type": "user", "message": {"content": [{"type": "tool_result", "content": str(text)[:OUT_CAP], "is_error": err}]}})


# --- tools (full capability; doctrine-guarded, not toolset-crippled) ---------
def tool_bash(command):
    try:
        r = subprocess.run(["bash", "-lc", command], cwd=REPO,
                           capture_output=True, text=True, timeout=BASH_TIMEOUT)
        out = (r.stdout or "") + (("\n[stderr]\n" + r.stderr) if r.stderr.strip() else "")
        out = out.strip() or f"(no output, exit {r.returncode})"
        return out[:OUT_CAP], r.returncode != 0
    except subprocess.TimeoutExpired:
        return f"(timed out after {BASH_TIMEOUT}s)", True
    except Exception as e:
        return f"error: {e}", True


def tool_web_search(query):
    # POST the DuckDuckGo HTML form — a GET from a datacenter/VPN exit gets challenged, but the
    # form POST returns real results.
    try:
        data = urllib.parse.urlencode({"q": query}).encode()
        req = urllib.request.Request("https://html.duckduckgo.com/html/", data=data, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
            "Content-Type": "application/x-www-form-urlencoded"})
        body = urllib.request.urlopen(req, timeout=25).read().decode("utf-8", "replace")
        res = re.findall(r'result__a"[^>]*>(.*?)</a>.*?result__snippet"[^>]*>(.*?)</a>', body, re.S)
        strip = lambda x: html.unescape(re.sub("<[^>]+>", "", x)).strip()
        out = [f"- {strip(t)}: {strip(s)}" for t, s in res[:6]]
        return ("\n".join(out) or "(no results)"), False
    except Exception as e:
        return f"web_search error: {e}", True


def run_tool(name, arg):
    if name == "bash":
        return tool_bash(arg if isinstance(arg, str) else arg.get("command", ""))
    if name == "web_search":
        return tool_web_search(arg if isinstance(arg, str) else arg.get("query", ""))
    return f"unknown tool '{name}' (use bash or web_search)", True


def load_primer():
    for p in [os.path.join(REPO, "docs", "knowledge", "ai-system-primer.md"),
              os.path.expanduser("~/recon/state/ai_primer.txt")]:
        if os.path.isfile(p):
            try:
                return open(p, encoding="utf-8", errors="ignore").read()
            except Exception:
                pass
    return ""


DOCTRINE = (
    "You are the LOCAL brain running the recon pipeline while Claude is rate-limited, with the SAME "
    "tool parity as the primary co-pilot. USE the tools to probe, confirm, research, and note — narrate "
    "each move briefly, don't just describe. DOCTRINE (the only guardrail): only in-scope + paying hosts; "
    "the point is a WORKING PoC — prove it or move on; recon-not-attack (confirm an exposure exists, don't "
    "exploit past it into a data harvest); IDOR/BOLA uses TWO accounts the operator OWNS (never guessed "
    "third-party IDs); never move money, destroy, DoS, or run RCE-for-harm; confirm-then-STOP at proof; "
    "respect 429/403 and never get the Mullvad exit banned. Persist worked-knowledge with "
    "`recon note <host> \"...\"`. WHEN YOU GET STUCK or need current info — a CVE detail, an exploit "
    "technique, a framework-specific bypass, a disclosed report — use web_search FIRST before giving up; "
    "the internet almost always has an angle. Never declare a dead end without researching a fresh one."
)
TOOLS_DESC = (
    "bash = run a shell command on the operator's box (cwd = the repo): drives the whole recon-ctl "
    "pipeline (`recon <sub>`), curl (incl. `-x 127.0.0.1:8080` through Burp), Brave, files, git, python3. "
    "web_search = search the web (CVEs, exploit techniques, disclosed reports, framework bypasses)."
)
REACT_PROTOCOL = (
    "\n\nTOOLS — " + TOOLS_DESC + "\nTo CALL a tool, reply with EXACTLY this and NOTHING after it:\n"
    "TOOL: bash\nARG: <the shell command — for web_search put the query instead>\n\n"
    "I will run it and return the output as the next message; then you continue. When DONE, reply with "
    "your final answer as normal prose (NO 'TOOL:' line). Take as many tool steps as needed."
)
NATIVE_TOOLS = [
    {"type": "function", "function": {"name": "bash",
        "description": "Run a shell command on the operator's box (cwd=repo): recon-ctl pipeline, curl "
                       "(incl. -x 127.0.0.1:8080 through Burp), Brave, files, git, python3. Primary tool.",
        "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}}},
    {"type": "function", "function": {"name": "web_search",
        "description": "Search the web (CVEs, exploit techniques, disclosed reports, framework bypasses).",
        "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}},
]
TOOL_RE = re.compile(r'(?im)^\s*TOOL:\s*([a-z_]+)\s*$')


def model_has_native_tools():
    try:
        body = json.dumps({"model": MODEL}).encode()
        req = urllib.request.Request(OLLAMA_URL + "/api/show", data=body, headers={"Content-Type": "application/json"})
        caps = json.loads(urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "replace")).get("capabilities") or []
        return "tools" in caps
    except Exception:
        return False


def chat(messages, native):
    payload = {"model": MODEL, "messages": messages, "stream": False}
    if native:
        payload["tools"] = NATIVE_TOOLS
    req = urllib.request.Request(OLLAMA_URL + "/api/chat", data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=900).read().decode("utf-8", "replace"))


def main():
    prompt = sys.argv[1] if len(sys.argv) > 1 else (sys.stdin.read() if not sys.stdin.isatty() else "")
    if not prompt.strip():
        emit({"type": "error", "error": "no prompt"})
        sys.exit(1)
    native = model_has_native_tools()
    system = load_primer().strip() + "\n\n" + DOCTRINE + ("" if native else REACT_PROTOCOL)
    messages = [{"role": "system", "content": system}, {"role": "user", "content": prompt}]
    final, rnd, produced = "", 0, False
    for rnd in range(MAX_ROUNDS):
        try:
            resp = chat(messages, native)
        except Exception as e:
            emit({"type": "error", "error": f"ollama: {e}"})
            sys.exit(0 if produced else 1)   # nothing produced -> caller falls back to plain chat
        msg = resp.get("message", {}) or {}
        content = msg.get("content", "") or ""
        calls = []  # normalized [(name, arg)]

        if native and msg.get("tool_calls"):
            if content.strip():
                emit_text(content); produced = True
            for tc in msg["tool_calls"]:
                fn = tc.get("function") or {}
                a = fn.get("arguments") or {}
                if isinstance(a, str):
                    try:
                        a = json.loads(a)
                    except Exception:
                        a = {"command": a}
                calls.append((fn.get("name", ""), a))
            messages.append({"role": "assistant", "content": content, "tool_calls": msg["tool_calls"]})
        else:
            mt = TOOL_RE.search(content)
            if mt:
                name = mt.group(1).strip()
                ma = re.search(r'(?is)ARG:\s*(.+)$', content[mt.end():] if "ARG:" in content[mt.end():] else content)
                arg = (ma.group(1).strip().strip("`").strip() if ma else "")
                pre = content[:mt.start()].strip()
                if pre:
                    emit_text(pre); produced = True
                calls.append((name, arg))
                messages.append({"role": "assistant", "content": content})
            else:
                if content.strip():
                    emit_text(content); produced = True; final = content
                messages.append({"role": "assistant", "content": content})
                break

        if not calls:
            if content.strip() and not final:
                final = content
            break
        for name, arg in calls:
            emit_tool_use(name, arg if isinstance(arg, dict) else ({"command": arg} if name == "bash" else {"query": arg}))
            result, err = run_tool(name, arg)
            emit_tool_result(result, err)
            if native:
                messages.append({"role": "tool", "content": str(result)[:OUT_CAP]})
            else:
                messages.append({"role": "user", "content": f"[tool:{name} output]\n{str(result)[:OUT_CAP]}"})

    emit({"type": "result", "subtype": "success", "is_error": False,
          "result": final or "(done)", "num_turns": rnd + 1, "duration_ms": 0})
    sys.exit(0 if produced else 1)


if __name__ == "__main__":
    main()
