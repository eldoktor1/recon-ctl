import { useEffect, useMemo, useRef, useState } from "react";
import { api, getToken } from "../api";
import { useFetch } from "../hooks";
import { Badge, Dot, Empty, Spinner } from "../components/ui";
import { Btn, useToast } from "../components/controls";
import { Markdown } from "../components/Markdown";
import { getTask, setTask, clearTask } from "../taskStore";

// The in-UI Claude co-pilot. Each turn spawns a backend task that runs
// `recon_claude_console.sh` and streams stream-json events over the task WS.
// We render text blocks, tool calls, and results as a chat transcript.

interface ConsoleCfg { available: boolean; claude_bin: boolean; models: string[]; perm: string }

type Block =
  | { kind: "text"; text: string }
  | { kind: "tool"; name: string; input: string; result?: string; error?: boolean; image?: string }
  | { kind: "note"; text: string };

interface Usage { input: number; output: number; cacheRead: number; cacheWrite: number }
const ZERO: Usage = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
interface SessionMeta { session_id: string; title: string; turns: number; updated: number }

interface Turn {
  role: "user" | "assistant";
  blocks: Block[];
  live?: boolean;
  meta?: { ms?: number; turns?: number; usage?: Usage };
}

function toUsage(u: any): Usage {
  return {
    input: u?.input_tokens || 0,
    output: u?.output_tokens || 0,
    cacheRead: u?.cache_read_input_tokens || 0,
    cacheWrite: u?.cache_creation_input_tokens || 0,
  };
}
function addUsage(a: Usage, b: Usage): Usage {
  return { input: a.input + b.input, output: a.output + b.output,
    cacheRead: a.cacheRead + b.cacheRead, cacheWrite: a.cacheWrite + b.cacheWrite };
}
// total tokens the model actually processed for a turn (context in + generated out)
function turnTotal(u: Usage): number { return u.input + u.cacheRead + u.cacheWrite + u.output; }
function fmtTok(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(2) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(n >= 100_000 ? 0 : 1) + "k";
  return String(n);
}
function fmtReset(resetsAt?: number): string {
  if (!resetsAt) return "";
  const secs = resetsAt - Math.floor(Date.now() / 1000);
  if (secs <= 0) return "resetting…";
  const h = Math.floor(secs / 3600), m = Math.floor((secs % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

const SID_KEY = "recon_console_sid";
const MODEL_KEY = "recon_console_model";

function newSid(): string {
  // RFC4122 v4 — matches the backend's UUID guard
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

export default function Console() {
  const { data: cfg } = useFetch<ConsoleCfg>("/api/claude/config");
  const [sid, setSid] = useState<string>(() => localStorage.getItem(SID_KEY) || newSid());
  const [model, setModel] = useState<string>(() => localStorage.getItem(MODEL_KEY) || "opus");
  const [turns, setTurns] = useState<Turn[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [sessTok, setSessTok] = useState<Usage>(ZERO);
  const [rate, setRate] = useState<{ status?: string; resetsAt?: number; type?: string }>({});
  const [tid, setTid] = useState<number | null>(null);
  const [sessions, setSessions] = useState<SessionMeta[]>([]);
  const [showSessions, setShowSessions] = useState(false);
  const [, tick] = useState(0);
  useEffect(() => { const t = setInterval(() => tick((x) => x + 1), 30_000); return () => clearInterval(t); }, []);
  const wsRef = useRef<WebSocket | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const toast = useToast();

  useEffect(() => { localStorage.setItem(SID_KEY, sid); }, [sid]);
  useEffect(() => { localStorage.setItem(MODEL_KEY, model); }, [model]);
  useEffect(() => { scrollRef.current?.scrollTo(0, scrollRef.current.scrollHeight); }, [turns]);
  useEffect(() => () => wsRef.current?.close(), []);
  useEffect(() => { inputRef.current?.focus(); }, []);

  const pushAssistant = (mut: (t: Turn) => void) =>
    setTurns((ts) => {
      const copy = ts.slice();
      let last = copy[copy.length - 1];
      if (!last || last.role !== "assistant" || !last.live) {
        last = { role: "assistant", blocks: [], live: true };
        copy.push(last);
      } else {
        last = { ...last, blocks: last.blocks.slice() };
        copy[copy.length - 1] = last;
      }
      mut(last);
      return copy;
    });

  const handleEvent = (m: any) => {
    const type = m.type;
    if (type === "system" && m.subtype === "init") return; // silent init
    if (type === "assistant" && m.message?.content) {
      for (const c of m.message.content) {
        if (c.type === "text" && c.text?.trim()) {
          pushAssistant((t) => t.blocks.push({ kind: "text", text: c.text }));
        } else if (c.type === "tool_use") {
          const inp = summarizeInput(c.name, c.input);
          pushAssistant((t) => t.blocks.push({ kind: "tool", name: c.name, input: inp }));
        }
      }
    } else if (type === "user" && m.message?.content) {
      // attach tool_result to the most recent matching tool block
      for (const c of m.message.content) {
        if (c.type === "tool_result") {
          const { text, image } = extractToolResult(c.content);
          pushAssistant((t) => {
            for (let i = t.blocks.length - 1; i >= 0; i--) {
              const b = t.blocks[i];
              if (b.kind === "tool" && b.result === undefined) {
                b.result = text; b.error = !!c.is_error; if (image) b.image = image; break;
              }
            }
          });
        }
      }
    } else if (type === "rate_limit_event") {
      const ri = m.rate_limit_info;
      if (ri) setRate({ status: ri.status, resetsAt: ri.resetsAt, type: ri.rateLimitType });
    } else if (type === "result") {
      const usage = toUsage(m.usage);
      setSessTok((s) => addUsage(s, usage));
      pushAssistant((t) => {
        t.live = false;
        t.meta = { ms: m.duration_ms, turns: m.num_turns, usage };
        if (m.is_error && m.subtype !== "success") {
          t.blocks.push({ kind: "note", text: `⚠ ${m.subtype || "error"}: ${m.result || ""}` });
        }
      });
    } else if (type === "error") {
      pushAssistant((t) => { t.live = false; t.blocks.push({ kind: "note", text: `⚠ ${m.error}` }); });
    }
  };

  const send = async () => {
    const msg = input.trim();
    if (!msg || busy) return;
    setInput("");
    setTurns((ts) => [...ts, { role: "user", blocks: [{ kind: "text", text: msg }] }]);
    setBusy(true);
    try {
      const r = await api.action<{ id: number; session_id: string }>("/api/claude/message", {
        session_id: sid, message: msg, model,
      });
      if (r.session_id && r.session_id !== sid) setSid(r.session_id);
      setTid(r.id);
      setTask(`console:${r.session_id || sid}`, r.id);  // persist so returning reconnects the live turn
      openStream(r.id);
    } catch (e: any) {
      toast("err", e.message);
      pushAssistant((t) => { t.live = false; t.blocks.push({ kind: "note", text: `⚠ ${e.message}` }); });
      setBusy(false);
    }
  };

  const openStream = (tid: number) => {
    wsRef.current?.close();
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/api/tasks/${tid}/output?token=${encodeURIComponent(getToken())}`);
    wsRef.current = ws;
    ws.onmessage = (ev) => {
      try {
        const m = JSON.parse(ev.data);
        if (m.type === "line") { try { handleEvent(JSON.parse(m.data)); } catch {} }
        else if (m.type === "end") {
          setBusy(false);
          clearTask(`console:${sid}`);
          setTurns((ts) => ts.map((t) => (t.live ? { ...t, live: false } : t)));
        }
      } catch {}
    };
    ws.onerror = () => setBusy(false);
    // fallback: if the socket closes without a terminal `end` (WSL/VPN flap), don't
    // wedge the composer as busy — clear it and end any live turn.
    ws.onclose = () => {
      setBusy(false);
      setTurns((ts) => ts.map((t) => (t.live ? { ...t, live: false } : t)));
    };
  };

  // On mount, if a turn was still running when we navigated away, RECONNECT its live stream —
  // the backend kept it running and replays the buffered output — instead of losing it (and
  // tempting a wasteful re-send). Cleared on the turn's `end`.
  useEffect(() => {
    const t = getTask(`console:${sid}`);
    if (t != null) { setBusy(true); setTid(t); openStream(t); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const reset = () => {
    wsRef.current?.close();
    setSid(newSid());
    setTurns([]);
    setBusy(false);
    setTid(null);
    setSessTok(ZERO);
    toast("ok", "new conversation");
    inputRef.current?.focus();
  };

  // Interrupt the running turn. The conversation is NOT lost — the next message
  // resumes this same session, so stopping then typing = redirect.
  const stop = async () => {
    if (tid == null || !busy) return;
    try {
      await api.action(`/api/tasks/${tid}/stop`);
      pushAssistant((t) => {
        t.live = false;
        t.blocks.push({ kind: "note", text: "⏹ stopped — type a correction to redirect the co-pilot" });
      });
      setBusy(false);
      clearTask(`console:${sid}`);
      wsRef.current?.close();
      toast("ok", "stopped — your next message steers it");
      inputRef.current?.focus();
    } catch (e: any) { toast("err", e.message); }
  };

  const loadSessions = async () => {
    try { setSessions(await api.get<SessionMeta[]>("/api/claude/sessions")); } catch {}
  };
  useEffect(() => { if (showSessions) loadSessions(); }, [showSessions]);

  const loadSession = async (s: SessionMeta) => {
    if (busy) return;
    wsRef.current?.close();
    try {
      const r = await api.get<{ turns: Turn[] }>(`/api/claude/sessions/${s.session_id}`);
      setTurns(r.turns || []);
      setSid(s.session_id);
      setTid(null);
      setBusy(false);
      setSessTok(ZERO);
      setShowSessions(false);
      toast("ok", `resumed ${s.session_id.slice(0, 8)}`);
      setTimeout(() => scrollRef.current?.scrollTo(0, scrollRef.current.scrollHeight), 50);
    } catch (e: any) { toast("err", e.message); }
  };

  const deleteSession = async (s: SessionMeta) => {
    try {
      await api.action(`/api/claude/sessions/${s.session_id}/delete`);
      toast("ok", `deleted ${s.session_id.slice(0, 8)}`);
      if (s.session_id === sid) reset();   // was viewing it → drop into a fresh chat
      loadSessions();
    } catch (e: any) { toast("err", e.message); }
  };

  const notReady = cfg && (!cfg.available || !cfg.claude_bin);

  return (
    <div className="fade-in flex h-[calc(100vh-8rem)] flex-col">
      {/* header */}
      <div className="flex items-center justify-between pb-3">
        <div className="flex items-center gap-3">
          <h1 className="text-lg font-semibold">Co-Pilot</h1>
          <Badge color="var(--color-accent)">Claude · in the ship</Badge>
          {busy && <Dot color="var(--color-warn)" pulse />}
          <div className="relative">
            <Btn size="sm" onClick={() => setShowSessions((v) => !v)}>☰ sessions</Btn>
            {showSessions && (
              <SessionPanel sessions={sessions} currentSid={sid}
                onPick={loadSession} onDelete={deleteSession}
                onClose={() => setShowSessions(false)} onRefresh={loadSessions} />
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <TokenHUD sess={sessTok} rate={rate} />
          <select value={model} onChange={(e) => setModel(e.target.value)}
            className="mono rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2 py-1 text-xs text-[var(--color-ink-dim)]">
            {(cfg?.models || ["opus", "sonnet", "haiku"]).map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
          <Btn size="sm" onClick={reset}>new chat</Btn>
        </div>
      </div>

      {notReady && (
        <div className="mb-3 rounded-md border border-[var(--color-bad)]/40 bg-[var(--color-bad)]/10 px-3 py-2 text-xs text-[var(--color-ink-dim)]">
          Console not wired: {!cfg?.available ? "recon_claude_console.sh missing" : "claude CLI not found on this box"}.
        </div>
      )}

      {/* transcript */}
      <div ref={scrollRef} className="flex-1 space-y-3 overflow-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] p-4">
        {turns.length === 0 ? (
          <Welcome onPick={(q) => { setInput(q); setTimeout(() => inputRef.current?.focus(), 0); }} />
        ) : turns.map((t, i) => <TurnView key={i} turn={t} />)}
        {busy && <ThinkingRow />}
      </div>

      {/* input */}
      <div className="mt-3 flex items-end gap-2">
        <textarea
          ref={inputRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }}
          placeholder="Ask the co-pilot to drive the pipeline —  what do we have tonight? · run the briefing · scope <host> · verify finding 3"
          rows={2}
          className="mono flex-1 resize-none rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] px-3 py-2 text-sm text-[var(--color-ink)] placeholder:text-[var(--color-ink-faint)] focus:border-[var(--color-accent)] focus:outline-none"
        />
        {busy ? (
          <Btn variant="danger" onClick={stop}>⏹ stop</Btn>
        ) : (
          <Btn variant="primary" onClick={send} disabled={!input.trim()}>send ⏎</Btn>
        )}
      </div>
      <div className="mono mt-1 flex justify-between text-[10px] text-[var(--color-ink-faint)]">
        <span>session {sid.slice(0, 8)} · {model} · {cfg?.perm || "bypassPermissions"} · full tools · drives `recon` on your box</span>
        <span>Enter send · Shift+Enter newline · Stop then type = redirect</span>
      </div>
    </div>
  );
}

const QUICK = [
  "What do we have tonight? Run the briefing and summarize the top 3 actions.",
  "Show me the freshest in-scope paying hosts and what class each looks worth.",
  "Any confirmed findings waiting to be reported? List them with severity.",
  "Check docs/research for new digests or unapplied proposals I should see.",
  "What lanes look unhealthy right now? Check the daemon log.",
];

function SessionPanel({ sessions, currentSid, onPick, onDelete, onClose, onRefresh }: {
  sessions: SessionMeta[]; currentSid: string;
  onPick: (s: SessionMeta) => void; onDelete: (s: SessionMeta) => void;
  onClose: () => void; onRefresh: () => void;
}) {
  const [pending, setPending] = useState<string | null>(null);
  return (
    <>
      <div className="fixed inset-0 z-30" onClick={onClose} />
      <div className="absolute left-0 top-9 z-40 max-h-[70vh] w-80 overflow-auto rounded-lg border border-[var(--color-border-bright)] bg-[var(--color-panel)] p-2 shadow-2xl">
        <div className="mb-1 flex items-center justify-between px-1">
          <span className="mono text-[10px] uppercase tracking-wide text-[var(--color-ink-faint)]">conversations</span>
          <button onClick={onRefresh} className="mono text-xs text-[var(--color-ink-faint)] hover:text-[var(--color-ink)]" title="refresh">↻</button>
        </div>
        {!sessions.length ? (
          <div className="px-2 py-3 text-xs text-[var(--color-ink-faint)]">no saved conversations yet</div>
        ) : sessions.map((s) => (
          <div key={s.session_id}
            className={`group flex items-center gap-1 rounded-md pr-1 hover:bg-[var(--color-panel-2)] ${s.session_id === currentSid ? "bg-[var(--color-accent)]/12" : ""}`}>
            <button onClick={() => onPick(s)} className="min-w-0 flex-1 px-2 py-1.5 text-left">
              <div className="truncate text-xs text-[var(--color-ink)]">{s.title}</div>
              <div className="mono flex gap-2 text-[10px] text-[var(--color-ink-faint)]">
                <span>{s.session_id.slice(0, 8)}</span>
                <span>{s.turns} msg</span>
                <span>{fmtWhen(s.updated)}</span>
                {s.session_id === currentSid && <span className="text-[var(--color-accent)]">current</span>}
              </div>
            </button>
            {pending === s.session_id ? (
              <div className="flex shrink-0 items-center gap-1 pl-1">
                <button onClick={(e) => { e.stopPropagation(); onDelete(s); setPending(null); }}
                  title="confirm delete" className="rounded px-1 text-xs font-bold text-[var(--color-bad)]">✓ del</button>
                <button onClick={(e) => { e.stopPropagation(); setPending(null); }}
                  title="cancel" className="rounded px-1 text-xs text-[var(--color-ink-faint)]">✗</button>
              </div>
            ) : (
              <button onClick={(e) => { e.stopPropagation(); setPending(s.session_id); }}
                title="delete conversation"
                className="shrink-0 rounded px-1.5 py-1 text-xs text-[var(--color-ink-faint)] opacity-0 hover:text-[var(--color-bad)] group-hover:opacity-100">✕</button>
            )}
          </div>
        ))}
      </div>
    </>
  );
}

function fmtWhen(epochSecs: number): string {
  const secs = Math.floor(Date.now() / 1000) - Math.floor(epochSecs);
  if (secs < 60) return "now";
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

function TokenHUD({ sess, rate }: { sess: Usage; rate: { status?: string; resetsAt?: number; type?: string } }) {
  const total = turnTotal(sess);
  const limited = rate.status && rate.status !== "allowed";
  const reset = fmtReset(rate.resetsAt);
  return (
    <div className="mono flex items-center gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2.5 py-1 text-[10px]">
      <span className="text-[var(--color-ink-faint)]">session</span>
      <span className="text-[var(--color-ink)]" title="total tokens processed this conversation (input + cache + output)">{fmtTok(total)} tok</span>
      <span className="text-[var(--color-ink-faint)]">·</span>
      <span title="new input / generated output"><span className="text-[var(--color-ink-dim)]">↓{fmtTok(sess.input)}</span> <span className="text-[var(--color-ink-dim)]">↑{fmtTok(sess.output)}</span></span>
      <span className="text-[var(--color-good)]" title="reused from cache — the conservation payoff">⚡{fmtTok(sess.cacheRead)}</span>
      {reset && (
        <>
          <span className="text-[var(--color-ink-faint)]">·</span>
          <span title={`Max ${rate.type || "usage"} window`} style={{ color: limited ? "var(--color-bad)" : "var(--color-ink-faint)" }}>
            {limited ? "LIMIT" : "5h"} {reset}
          </span>
        </>
      )}
    </div>
  );
}

function Welcome({ onPick }: { onPick: (q: string) => void }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 text-center">
      <div className="max-w-md space-y-1">
        <p className="text-sm text-[var(--color-ink)]">You're inside the ship.</p>
        <p className="text-xs text-[var(--color-ink-dim)]">
          Full tool parity with Claude Code: run <span className="mono text-[var(--color-accent)]">recon</span> commands, read/edit the
          repo &amp; corpus, research the web, drive Burp and your logged-in Brave — right here, conversationally, under the same doctrine.
        </p>
      </div>
      <div className="grid w-full max-w-xl grid-cols-1 gap-2 sm:grid-cols-2">
        {QUICK.map((q) => (
          <button key={q} onClick={() => onPick(q)}
            className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] px-3 py-2 text-left text-xs text-[var(--color-ink-dim)] hover:border-[var(--color-accent)] hover:text-[var(--color-ink)]">
            {q}
          </button>
        ))}
      </div>
    </div>
  );
}

function TurnView({ turn }: { turn: Turn }) {
  if (turn.role === "user") {
    return (
      <div className="flex justify-end">
        <div className="max-w-[80%] rounded-lg rounded-br-sm border border-[var(--color-accent)]/30 bg-[var(--color-accent)]/10 px-3 py-2 text-sm text-[var(--color-ink)]">
          {turn.blocks.map((b, i) => b.kind === "text" ? <span key={i} className="whitespace-pre-wrap">{b.text}</span> : null)}
        </div>
      </div>
    );
  }
  return (
    <div className="flex justify-start">
      <div className="w-full max-w-[92%] space-y-2">
        {turn.blocks.map((b, i) => <BlockView key={i} block={b} />)}
        {turn.meta?.usage && (
          <div className="mono flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[10px] text-[var(--color-ink-faint)]">
            {turn.meta.ms ? <span>{(turn.meta.ms / 1000).toFixed(1)}s</span> : null}
            <span>·</span>
            <span title="new input tokens">↓ {fmtTok(turn.meta.usage.input)} in</span>
            <span title="generated output tokens">↑ {fmtTok(turn.meta.usage.output)} out</span>
            <span title="tokens read from prompt cache (cheap reuse)" className="text-[var(--color-good)]">⚡ {fmtTok(turn.meta.usage.cacheRead)} cached</span>
            {turn.meta.usage.cacheWrite > 0 && <span title="tokens written to cache (first load)">● {fmtTok(turn.meta.usage.cacheWrite)} write</span>}
            <span className="text-[var(--color-ink-dim)]">= {fmtTok(turnTotal(turn.meta.usage))} tot</span>
          </div>
        )}
      </div>
    </div>
  );
}

function BlockView({ block }: { block: Block }) {
  if (block.kind === "text") {
    return (
      <div className="rounded-lg rounded-bl-sm border border-[var(--color-border)] bg-[var(--color-panel)] px-3 py-2 text-sm text-[var(--color-ink)]">
        <Markdown text={block.text} />
      </div>
    );
  }
  if (block.kind === "note") {
    return <div className="mono text-xs text-[var(--color-warn)]">{block.text}</div>;
  }
  // tool
  const done = block.result !== undefined || block.image !== undefined;
  return (
    <details className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)]/60 text-xs" open={!!block.image}>
      <summary className="mono flex cursor-pointer items-center gap-2 px-3 py-1.5 text-[var(--color-ink-dim)]">
        <span className="text-[var(--color-info)]">⚙ {prettyToolName(block.name)}</span>
        <span className="flex-1 truncate text-[var(--color-ink-faint)]">{block.input}</span>
        {!done
          ? <Dot color="var(--color-warn)" pulse />
          : <Badge color={block.error ? "var(--color-bad)" : "var(--color-good)"}>{block.error ? "err" : "ok"}</Badge>}
      </summary>
      {block.result !== undefined && (block.result || !block.image) && (
        <pre className="mono max-h-64 overflow-auto whitespace-pre-wrap border-t border-[var(--color-border)] px-3 py-2 text-[11px] text-[var(--color-ink-dim)]">
          {block.result || "(no output)"}
        </pre>
      )}
      {block.image && (
        <div className="border-t border-[var(--color-border)] p-2">
          <img src={block.image} alt="browser screenshot"
            className="max-h-96 w-auto rounded border border-[var(--color-border)]" />
        </div>
      )}
    </details>
  );
}

function ThinkingRow() {
  return (
    <div className="flex items-center gap-2 px-1 text-xs text-[var(--color-ink-faint)]">
      <Spinner /> <span className="mono">co-pilot working…</span>
    </div>
  );
}

// --- helpers ---------------------------------------------------------------
// mcp__brave__take_screenshot  ->  brave·take_screenshot  (built-ins unchanged)
function prettyToolName(name: string): string {
  const m = /^mcp__([^_]+)__(.+)$/.exec(name);
  return m ? `${m[1]}·${m[2]}` : name;
}

function summarizeInput(name: string, input: any): string {
  if (!input) return "";
  switch (name) {
    case "Bash": return input.command || "";
    case "Read": return input.file_path || "";
    case "Grep": return `${input.pattern || ""}${input.path ? ` in ${input.path}` : ""}`;
    case "Glob": return input.pattern || "";
    case "WebSearch": return input.query || "";
    case "WebFetch": return input.url || "";
    case "Edit": case "Write": case "MultiEdit": return input.file_path || "";
    case "NotebookEdit": return input.notebook_path || "";
    case "Task": return `[${input.subagent_type || "agent"}] ${input.description || input.prompt || ""}`.slice(0, 160);
    case "TodoWrite": return Array.isArray(input.todos) ? `${input.todos.length} todos` : "";
  }
  // MCP tools (burp / brave / …): surface the most telling field, else compact JSON
  if (name.startsWith("mcp__")) {
    for (const k of ["url", "request", "host", "method", "expression", "function",
      "selector", "uid", "value", "query", "payload", "text", "port", "pageIdx"]) {
      const v = input[k];
      if (v != null && v !== "") return (typeof v === "string" ? v : JSON.stringify(v)).slice(0, 160);
    }
  }
  try { return JSON.stringify(input).slice(0, 160); } catch { return ""; }
}

// Tool results can carry text and/or an image block (e.g. a Brave screenshot).
function extractToolResult(content: any): { text: string; image?: string } {
  if (typeof content === "string") return { text: content };
  if (!Array.isArray(content)) return { text: "" };
  let text = "";
  let image: string | undefined;
  for (const c of content) {
    if (typeof c === "string") text += c + "\n";
    else if (c?.type === "text") text += (c.text || "") + "\n";
    else if (c?.type === "image" && c.source?.data) {
      image = `data:${c.source.media_type || "image/png"};base64,${c.source.data}`;
    }
  }
  return { text: text.trim(), image };
}
