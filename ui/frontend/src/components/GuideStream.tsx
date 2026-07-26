import { useEffect, useRef, useState } from "react";
import { getToken } from "../api";
import { Spinner } from "./ui";
import { Markdown } from "./Markdown";

// Compact label for a tool_use event streamed from a Claude task.
export function guideToolLabel(name: string, input: any): string {
  const pretty = /^mcp__([^_]+)__(.+)$/.exec(name);
  const nm = pretty ? `${pretty[1]}·${pretty[2]}` : name;
  let arg = "";
  if (input && typeof input === "object") {
    arg = input.command || input.file_path || input.pattern || input.url || input.query || "";
    if (!arg) { try { arg = JSON.stringify(input); } catch { /* ignore */ } }
  }
  return `${nm}${arg ? " " + String(arg).slice(0, 90) : ""}`;
}

type GuideSeg = { kind: "text"; text: string } | { kind: "tool"; label: string };

// Streams a task's stream-json (the shape `claude -p --output-format stream-json` emits, the same
// the Co-Pilot renders) and shows it as readable markdown — instead of raw JSON in a generic console.
// Fires onComplete with the full assistant text when the task ends, so the caller can capture it
// (record a trace, prefill a note draft, …). Reused by the Guided walkthrough and Auto-note.
export function GuideStream({ tid, onComplete }: { tid: number; onComplete?: (text: string) => void }) {
  const [segs, setSegs] = useState<GuideSeg[]>([]);
  const [running, setRunning] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const boxRef = useRef<HTMLDivElement>(null);
  const cbRef = useRef(onComplete); cbRef.current = onComplete;

  useEffect(() => {
    setSegs([]); setRunning(true); setErr(null);
    let text = "";          // accumulated assistant text for onComplete
    let resultText = "";
    let done = false;
    const finish = () => {
      if (done) return; done = true;
      setRunning(false);
      cbRef.current?.((text || resultText).trim());
    };
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/api/tasks/${tid}/output?token=${encodeURIComponent(getToken())}`);
    ws.onmessage = (ev) => {
      let m: any; try { m = JSON.parse(ev.data); } catch { return; }
      if (m.type === "line") {
        let e: any; try { e = JSON.parse(m.data); } catch { return; }
        if (e.type === "assistant" && e.message?.content) {
          for (const c of e.message.content) {
            if (c.type === "text" && c.text?.trim()) {
              text += c.text + "\n";
              setSegs((s) => [...s, { kind: "text", text: c.text }]);
            } else if (c.type === "tool_use") {
              setSegs((s) => [...s, { kind: "tool", label: guideToolLabel(c.name, c.input) }]);
            }
          }
        } else if (e.type === "result") {
          if (typeof e.result === "string") resultText = e.result;
          if (e.is_error && e.subtype !== "success") setErr(e.subtype || "error");
        }
      } else if (m.type === "end") { finish(); }
      else if (m.type === "error") { setErr((x) => x || m.error || "stream error"); finish(); }
    };
    ws.onerror = () => setErr((x) => x || "connection error");
    ws.onclose = () => finish();
    // programmatic close on unmount/tid-change: suppress the trailing onComplete
    return () => { done = true; ws.close(); };
  }, [tid]);

  useEffect(() => { boxRef.current?.scrollTo(0, boxRef.current.scrollHeight); }, [segs]);

  const hasText = segs.some((s) => s.kind === "text");
  return (
    <div className="mt-2 rounded-md border border-[var(--color-accent)]/40 bg-[var(--color-accent)]/5 p-3">
      <div className="mb-1.5 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-[var(--color-accent)]">
        <span>◎</span> Claude guidance
        {running
          ? <span className="inline-flex items-center gap-1 text-[var(--color-warn)]"><Spinner /> streaming…</span>
          : <span className="text-[var(--color-ink-faint)]">· task #{tid}</span>}
      </div>
      <div ref={boxRef} className="max-h-[440px] space-y-1.5 overflow-auto">
        {segs.map((s, i) => s.kind === "text"
          ? <Markdown key={i} text={s.text} />
          : <div key={i} className="mono flex items-center gap-1.5 text-[10px] text-[var(--color-ink-faint)]">
              <span className="text-[var(--color-info)]">⚙</span><span className="truncate">{s.label}</span>
            </div>)}
        {!hasText && running && <div className="mono text-[11px] text-[var(--color-ink-faint)]">waiting for Claude…</div>}
        {!hasText && !running && !err && <div className="mono text-[11px] text-[var(--color-ink-faint)]">(no guidance text returned)</div>}
      </div>
      {err && <div className="mono mt-1 text-[10px] text-[var(--color-bad)]">⚠ {err}</div>}
    </div>
  );
}
