import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, type LaneActivity } from "../api";
import { useFetch } from "../hooks";
import { Panel, Stat, Badge, Empty, Spinner, Dot } from "../components/ui";
import { Btn, useToast } from "../components/controls";
import { fmtAgo } from "../format";

// Full C2 control + visibility over EVERY daemon lane: running/idle, yield,
// last-yield, target-facing, killswitch, and an expandable tail-log per lane.
export default function Lanes() {
  const { data, loading, refetch } = useFetch<LaneActivity[]>("/api/lanes/activity");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const toast = useToast();
  const qc = useQueryClient();

  // live poll
  useEffect(() => { const t = setInterval(refetch, 5000); return () => clearInterval(t); }, [refetch]);

  const lanes = (data || []).filter((l) => !q || l.lane.toLowerCase().includes(q.toLowerCase()) || l.desc.toLowerCase().includes(q.toLowerCase()));
  const running = (data || []).filter((l) => l.running).length;
  const yielding = (data || []).filter((l) => l.yield_count > 0).length;
  const killed = (data || []).filter((l) => l.killed).length;

  const target = lanes.filter((l) => l.target);
  const support = lanes.filter((l) => !l.target);

  const toggleKill = async (l: LaneActivity) => {
    const lane = l.lane.replace(/^v2_/, "");
    try {
      await api.action(`/api/killswitch/${encodeURIComponent(lane)}`, { on: !l.killed });
      toast("ok", `${l.lane} ${l.killed ? "re-enabled" : "killed"}`);
      qc.invalidateQueries();
    } catch (e: any) { toast("err", e.message); }
  };

  return (
    <div className="fade-in space-y-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h1 className="text-lg font-semibold">Lanes</h1>
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="filter lanes…"
          className="mono w-48 rounded-md border border-[var(--color-border-bright)] bg-[var(--color-panel)] px-3 py-1.5 text-xs outline-none focus:border-[var(--color-accent)]" />
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Lanes" value={data?.length ?? "—"} sub="autonomous daemon lanes" />
        <Stat label="Running" value={running} color="var(--color-good)" />
        <Stat label="Yielding" value={yielding} color="var(--color-accent)" sub="found something" />
        <Stat label="Killed" value={killed} color={killed ? "var(--color-warn)" : undefined} />
      </div>

      {loading && !data ? <Spinner /> : !data?.length ? <Empty hint="the daemon reports lane activity once it's running">no lane activity</Empty> : (
        <>
          <LaneGroup title="target-facing" hint="sends live traffic (Mullvad-gated)" lanes={target}
            expanded={expanded} onExpand={setExpanded} onToggleKill={toggleKill} />
          <LaneGroup title="support / off-target" hint="research, enumeration, telemetry — no target traffic" lanes={support}
            expanded={expanded} onExpand={setExpanded} onToggleKill={toggleKill} />
        </>
      )}
    </div>
  );
}

function LaneGroup({ title, hint, lanes, expanded, onExpand, onToggleKill }:
  { title: string; hint: string; lanes: LaneActivity[]; expanded: string | null;
    onExpand: (l: string | null) => void; onToggleKill: (l: LaneActivity) => void }) {
  if (!lanes.length) return null;
  return (
    <Panel title={<span>{title} <span className="ml-1 normal-case text-[var(--color-ink-faint)]">· {hint}</span></span>}
      right={<Badge>{lanes.length}</Badge>} className="!p-0">
      <div className="divide-y divide-[var(--color-border)]">
        {lanes.map((l) => (
          <LaneRow key={l.lane} l={l} open={expanded === l.lane}
            onExpand={() => onExpand(expanded === l.lane ? null : l.lane)} onToggleKill={() => onToggleKill(l)} />
        ))}
      </div>
    </Panel>
  );
}

function LaneRow({ l, open, onExpand, onToggleKill }:
  { l: LaneActivity; open: boolean; onExpand: () => void; onToggleKill: () => void }) {
  const yieldColor = l.yield_count > 0 ? "var(--color-accent)" : "var(--color-ink-faint)";
  const statusColor = l.killed ? "var(--color-bad)" : l.running ? "var(--color-good)" : "var(--color-ink-faint)";
  return (
    <div className={l.killed ? "opacity-60" : ""}>
      <div className="flex items-center gap-3 px-4 py-2.5">
        <button onClick={onExpand} title={open ? "collapse log" : "tail log"}
          className="shrink-0 text-[var(--color-ink-faint)] hover:text-[var(--color-ink)]">{open ? "▾" : "▸"}</button>
        <Dot color={statusColor} pulse={l.running && !l.killed} />
        <span className="mono w-32 shrink-0 truncate text-xs font-semibold text-[var(--color-ink)]" title={l.lane}>{l.lane}</span>
        <span className="hidden min-w-0 flex-1 truncate text-[11px] text-[var(--color-ink-dim)] md:block" title={l.desc}>{l.desc}</span>
        <div className="ml-auto flex shrink-0 items-center gap-2.5">
          <span className="mono text-[11px]" style={{ color: yieldColor }} title="findings/leads yielded">▲ {l.yield_count}</span>
          <span className="hidden text-[10px] text-[var(--color-ink-faint)] sm:inline" title="last yield">{l.last_yield_at ? fmtAgo(l.last_yield_at) : "—"}</span>
          {l.target ? <Badge color="var(--color-warn)" title="sends live target traffic">target</Badge> : <Badge color="var(--color-info)">support</Badge>}
          {l.killed && <Badge color="var(--color-bad)">killed</Badge>}
          <Btn size="sm" variant={l.killed ? "primary" : "danger"} onClick={onToggleKill}>
            {l.killed ? "enable" : "kill"}
          </Btn>
        </div>
      </div>
      {open && <LaneLog lane={l.lane} />}
    </div>
  );
}

function LaneLog({ lane }: { lane: string }) {
  const [lines, setLines] = useState<string[] | null>(null);
  const boxRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    let stop = false;
    const load = async () => {
      try { const r = await api.get<{ lines: string[] }>(`/api/lanes/${encodeURIComponent(lane)}/log?tail=200`); if (!stop) setLines(r.lines); }
      catch { if (!stop) setLines([]); }
    };
    load();
    const t = setInterval(load, 4000);
    return () => { stop = true; clearInterval(t); };
  }, [lane]);
  useEffect(() => { boxRef.current?.scrollTo(0, boxRef.current.scrollHeight); }, [lines]);
  return (
    <div className="border-t border-[var(--color-border)] bg-[var(--color-bg)] px-4 py-2">
      {lines == null ? <div className="py-3 text-center text-[11px] text-[var(--color-ink-faint)]">loading log…</div> :
        !lines.length ? <div className="py-3 text-center text-[11px] text-[var(--color-ink-faint)]">no log output yet</div> : (
        <div ref={boxRef} className="mono max-h-60 overflow-auto whitespace-pre-wrap text-[11px] leading-relaxed text-[var(--color-ink-dim)]">
          {lines.map((ln, i) => <div key={i}>{ln}</div>)}
        </div>
      )}
    </div>
  );
}
