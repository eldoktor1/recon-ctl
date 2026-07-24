import { useEffect, useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../api";
import { useFetch } from "../hooks";
import { Panel, Badge, Empty, Spinner, Dot } from "../components/ui";
import { Btn, useToast } from "../components/controls";
import { Markdown } from "../components/Markdown";
import { Worklist, type Parsed } from "../components/Worklist";
import { HostDrawer } from "../components/HostDrawer";
import { TaskConsole } from "../components/TaskConsole";
import { priorityColor, fmtAgo } from "../format";

interface Bucket { key: string; label: string; count: number; hosts: any[]; error?: string }
interface Leads { buckets: Bucket[] }
interface Brief { name: string; kind: string; date: string | null; mtime: number }

const bucketColor: Record<string, string> = {
  takeover: "var(--color-bad)", takeover_lead: "var(--color-warn)", secrets: "var(--color-warn)",
  kev: "var(--color-bad)", fresh: "var(--color-accent)",
};

// Ordered source switcher — one tab per useful briefing kind (latest wins).
const SOURCE_ORDER = [
  "tonight", "2IC_tonight", "hunter", "idor_candidates", "xss_candidates",
  "sqli_candidates", "graphql_candidates", "fresh", "targets",
];

export default function Leads() {
  const { data: leads } = useFetch<Leads>("/api/leads");
  const { data: briefs } = useFetch<Brief[]>("/api/briefings");
  const [host, setHost] = useState<string | null>(null);
  const [active, setActive] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [raw, setRaw] = useState(false);
  const [openTask, setOpenTask] = useState<number | null>(null);
  const toast = useToast();
  const qc = useQueryClient();
  const [vhost, setVhost] = useState("");

  const dismiss = async (h: string) => {
    try {
      await api.action(`/api/hosts/${encodeURIComponent(h)}/dismiss`, { kind: "not-actionable" });
      toast("ok", `${h} marked not-actionable — won't re-serve`);
      qc.invalidateQueries();
    } catch (e: any) { toast("err", e.message); }
  };

  // latest briefing per kind, ordered by SOURCE_ORDER then recency
  const sources = useMemo(() => {
    const latest: Record<string, Brief> = {};
    for (const b of briefs || []) {
      const cur = latest[b.kind];
      if (!cur || b.mtime > cur.mtime) latest[b.kind] = b;
    }
    const picked = Object.values(latest);
    return picked.sort((a, b) => {
      const ia = SOURCE_ORDER.findIndex((k) => a.kind.startsWith(k));
      const ib = SOURCE_ORDER.findIndex((k) => b.kind.startsWith(k));
      const ra = ia === -1 ? 99 : ia, rb = ib === -1 ? 99 : ib;
      return ra !== rb ? ra - rb : b.mtime - a.mtime;
    });
  }, [briefs]);

  useEffect(() => {
    if (!active && sources.length) {
      const t = sources.find((b) => b.kind.startsWith("tonight")) || sources[0];
      setActive(t.name);
    }
  }, [sources, active]);

  const launchVerify = async (h?: string) => {
    const target = (h ?? vhost).trim();
    if (!target) return;
    try {
      const t = await api.action<any>("/api/verify", { host: target });
      toast("ok", `verify #${t.id} started — streaming below`);
      setOpenTask(t.id);
      if (!h) setVhost("");
    } catch (e: any) { toast("err", e.message); }
  };

  return (
    <div className="fade-in space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-lg font-semibold">Tonight · Worklist</h1>
        <div className="flex items-center gap-2">
          <input value={vhost} onChange={(e) => setVhost(e.target.value)} placeholder="verify host…"
            onKeyDown={(e) => e.key === "Enter" && launchVerify()}
            className="mono w-44 rounded-md border border-[var(--color-border-bright)] bg-[var(--color-panel)] px-3 py-1.5 text-xs outline-none focus:border-[var(--color-accent)]" />
          <Btn size="sm" variant="primary" onClick={() => launchVerify()}>run verify</Btn>
        </div>
      </div>

      {/* interactive worklist */}
      <Panel
        title="worklist · actionable"
        right={
          <div className="flex items-center gap-2">
            <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="filter host/program…"
              className="mono w-40 rounded border border-[var(--color-border-bright)] bg-[var(--color-panel-2)] px-2 py-1 text-[11px] outline-none focus:border-[var(--color-accent)]" />
            <button onClick={() => setRaw((r) => !r)}
              className={`rounded border px-2 py-1 text-[10px] transition ${raw ? "border-[var(--color-accent)] text-[var(--color-accent)]" : "border-[var(--color-border-bright)] text-[var(--color-ink-faint)] hover:text-[var(--color-ink)]"}`}>
              raw md
            </button>
          </div>
        }
      >
        {/* source tabs */}
        {!sources.length ? <Spinner /> : (
          <div className="mb-3 flex flex-wrap gap-1.5">
            {sources.map((b) => (
              <button key={b.name} onClick={() => { setActive(b.name); setFilter(""); }}
                className={`rounded-md border px-2.5 py-1 text-[11px] transition ${active === b.name ? "border-[var(--color-accent)] text-[var(--color-accent)]" : "border-[var(--color-border-bright)] text-[var(--color-ink-dim)] hover:text-[var(--color-ink)]"}`}>
                {b.kind} <span className="text-[10px] text-[var(--color-ink-faint)]">· {b.date?.slice(5) || fmtAgo(b.mtime)}</span>
              </button>
            ))}
          </div>
        )}
        {active ? (
          raw ? <RawBriefing name={active} /> : <ParsedWorklist name={active} filter={filter} onHost={setHost} onVerify={launchVerify} onDismiss={dismiss} />
        ) : <Empty>no briefing selected</Empty>}
      </Panel>

      {/* live ES signal buckets */}
      <Panel title="active leads · live signals" right={<span className="text-[10px] text-[var(--color-ink-faint)]">not benched · pays</span>}>
        {!leads ? <Spinner /> : (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
            {leads.buckets.map((b) => (
              <div key={b.key} className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] p-3">
                <div className="mb-2 flex items-center gap-2">
                  <Dot color={bucketColor[b.key] || "var(--color-ink-dim)"} pulse={b.count > 0 && (b.key === "takeover" || b.key === "secrets")} />
                  <span className="flex-1 text-xs text-[var(--color-ink-dim)]">{b.label}</span>
                  <Badge color={b.count ? bucketColor[b.key] : "var(--color-ink-faint)"}>{b.count}</Badge>
                </div>
                {b.hosts.length === 0 ? <div className="text-[11px] text-[var(--color-ink-faint)]">none active</div> : (
                  <div className="space-y-0.5">
                    {b.hosts.slice(0, 6).map((h) => (
                      <div key={h.host} className="group flex items-center gap-2 rounded px-1.5 py-1 hover:bg-[var(--color-panel)]">
                        {h.triage_priority && <Badge color={priorityColor[h.triage_priority]}>{h.triage_priority}</Badge>}
                        <button onClick={() => setHost(h.host)} className="mono flex-1 truncate text-left text-[11px] text-[var(--color-ink)] hover:text-[var(--color-accent)]">{h.host}</button>
                        <span className="text-[10px] text-[var(--color-ink-faint)]">{h.triage_score}</span>
                        <button onClick={() => dismiss(h.host)} title="mark not-actionable — stop re-serving"
                          className="text-[11px] text-[var(--color-ink-faint)] opacity-0 transition hover:text-[var(--color-bad)] group-hover:opacity-100">✕</button>
                      </div>
                    ))}
                    {b.count > 6 && <div className="pl-1.5 pt-1 text-[10px] text-[var(--color-ink-faint)]">+{b.count - 6} more</div>}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Panel>

      {host && <HostDrawer host={host} onClose={() => setHost(null)} />}
      {openTask != null && <TaskConsole tid={openTask} onClose={() => setOpenTask(null)} />}
    </div>
  );
}

function ParsedWorklist({ name, filter, onHost, onVerify, onDismiss }:
  { name: string; filter: string; onHost: (h: string) => void; onVerify: (h: string) => void; onDismiss: (h: string) => void }) {
  const { data, loading } = useFetch<Parsed>(`/api/briefings/${encodeURIComponent(name)}/parsed`);
  if (loading && !data) return <Spinner />;
  if (!data) return <Empty>could not load</Empty>;
  return <Worklist parsed={data} filter={filter} onHost={onHost} onVerify={onVerify} onDismiss={onDismiss} />;
}

function RawBriefing({ name }: { name: string }) {
  const { data, loading } = useFetch<{ body: string }>(`/api/briefings/${encodeURIComponent(name)}`);
  if (loading && !data) return <Spinner />;
  if (!data) return <Empty>could not load</Empty>;
  return <div className="max-h-[70vh] overflow-auto"><Markdown text={data.body} /></div>;
}
