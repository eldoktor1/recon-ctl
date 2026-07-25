import { useEffect, useRef, useState } from "react";
import { api, getToken } from "../api";
import { Badge } from "./ui";
import { Btn, useToast } from "./controls";
import { Dot } from "./ui";
import { useResizable } from "./useResizable";

export const taskColor: Record<string, string> = {
  running: "var(--color-warn)", done: "var(--color-good)", failed: "var(--color-bad)", stopped: "var(--color-ink-faint)",
};

// Strip ANSI SGR color codes so lane output (which colorizes for a TTY) reads
// cleanly in the browser instead of showing literal `\x1b[36m` escapes.
// eslint-disable-next-line no-control-regex
const ANSI_RE = /\x1b\[[0-9;]*m/g;
const stripAnsi = (s: string) => s.replace(ANSI_RE, "");

// Live task output drawer (bottom slide-up). Streams a task's stdout over the
// per-task WebSocket. Shared by Hunt Control, Leads, and the Command Center so
// any action that spawns a task (verify, lane launch) can show its output where
// it was fired — no hunting for the task on another page.
export function TaskConsole({ tid, onClose, onChanged }:
  { tid: number; onClose: () => void; onChanged?: () => void }) {
  const [lines, setLines] = useState<string[]>([]);
  const [state, setState] = useState("running");
  const boxRef = useRef<HTMLDivElement>(null);
  const toast = useToast();
  // drag-resize the streaming pane's HEIGHT (grip on the top edge); persisted.
  const { size: boxH, onGripDown } = useResizable({
    axis: "y", storageKey: "recon.taskconsole.h", initial: 320,
    min: 120, max: () => Math.round(window.innerHeight * 0.85),
  });

  useEffect(() => {
    setLines([]); setState("running");
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/api/tasks/${tid}/output?token=${encodeURIComponent(getToken())}`);
    ws.onmessage = (ev) => {
      try {
        const m = JSON.parse(ev.data);
        if (m.type === "line") setLines((l) => [...l, stripAnsi(m.data)]);
        else if (m.type === "end") { setState(m.state); onChanged?.(); }
        else if (m.type === "error") { setState("failed"); setLines((l) => [...l, `[error] ${m.error}`]); }
      } catch {}
    };
    return () => ws.close();
  }, [tid]);

  useEffect(() => { boxRef.current?.scrollTo(0, boxRef.current.scrollHeight); }, [lines]);

  const stop = async () => {
    try { await api.action(`/api/tasks/${tid}/stop`); toast("ok", "stop signal sent"); }
    catch (e: any) { toast("err", e.message); }
  };

  return (
    <div className="fixed inset-x-0 bottom-0 z-40 border-t border-[var(--color-border-bright)] bg-[var(--color-panel)] shadow-2xl fade-in">
      {/* drag grip — resize height */}
      <div onPointerDown={onGripDown} title="drag to resize"
        className="group flex h-2 cursor-ns-resize items-center justify-center border-b border-[var(--color-border)] hover:bg-[var(--color-panel-2)]">
        <span className="h-0.5 w-10 rounded-full bg-[var(--color-border-bright)] transition group-hover:bg-[var(--color-accent)]" />
      </div>
      <div className="flex items-center justify-between border-b border-[var(--color-border)] px-4 py-2">
        <div className="flex items-center gap-2">
          <Dot color={taskColor[state]} pulse={state === "running"} />
          <span className="mono text-xs text-[var(--color-ink)]">task #{tid}</span>
          <Badge color={taskColor[state]}>{state}</Badge>
        </div>
        <div className="flex items-center gap-2">
          {state === "running" && <Btn size="sm" variant="danger" onClick={stop}>stop</Btn>}
          <Btn size="sm" onClick={onClose}>close</Btn>
        </div>
      </div>
      <div ref={boxRef} style={{ height: boxH }}
        className="mono overflow-auto bg-[var(--color-bg)] p-3 text-[11px] leading-relaxed text-[var(--color-ink-dim)]">
        {lines.length === 0 ? <span className="text-[var(--color-ink-faint)]">waiting for output…</span> :
          lines.map((l, i) => <div key={i} className="whitespace-pre-wrap">{l}</div>)}
      </div>
    </div>
  );
}
