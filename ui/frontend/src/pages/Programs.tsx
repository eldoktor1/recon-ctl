import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { useFetch } from "../hooks";
import { Panel, Badge, Empty, Spinner, SortTh } from "../components/ui";
import { Btn, useToast } from "../components/controls";
import { TaskConsole } from "../components/TaskConsole";
import { LeadActions, useHostActions } from "../components/LeadActions";
import { HostDrawer } from "../components/HostDrawer";
import { api, type WorkspacesResp, type WorkspaceSummary, type WorkspaceCandidate,
  type WorkspaceDetail, type WstgItem, type StrideThreat, type WsHost,
  type WstgReference } from "../api";
import { priorityColor, stateColor, verdictColor, classColor, asArr, fmtAgo } from "../format";
import { isDemo, demoGuidance } from "../demo";

// workspace/checklist status → color (todo / in-progress / done / na / finding + program status)
const wsStatusColor: Record<string, string> = {
  todo: "var(--color-ink-faint)", "in-progress": "var(--color-warn)", done: "var(--color-good)",
  na: "var(--color-ink-faint)", finding: "var(--color-accent)",
  active: "var(--color-good)", paused: "var(--color-warn)",
};
const wsc = (s?: string) => wsStatusColor[s || ""] || "var(--color-ink-dim)";

const WSTG_STATUSES = ["todo", "in-progress", "done", "na", "finding"];
// class cycle: todo → in-progress → done → finding → todo
const CLASS_CYCLE = ["todo", "in-progress", "done", "finding"];
const STRIDE_COLS: { cat: keyof StrideBoardT; label: string }[] = [
  { cat: "S", label: "Spoofing" }, { cat: "T", label: "Tampering" }, { cat: "R", label: "Repudiation" },
  { cat: "I", label: "Info disclosure" }, { cat: "D", label: "Denial of service" }, { cat: "E", label: "Elevation of priv" },
];
type StrideBoardT = WorkspaceDetail["stride"];

// crosshair / target icon for the nav + rail
export function CrosshairIcon({ size = 15 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" aria-hidden="true">
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="2.4" fill="currentColor" stroke="none" />
      <line x1="12" y1="1.5" x2="12" y2="5.5" /><line x1="12" y1="18.5" x2="12" y2="22.5" />
      <line x1="1.5" y1="12" x2="5.5" y2="12" /><line x1="18.5" y1="12" x2="22.5" y2="12" />
    </svg>
  );
}

function CoverageBar({ done, total, height = 6, label }:
  { done: number; total: number; height?: number; label?: boolean }) {
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 overflow-hidden rounded-full bg-[var(--color-panel-2)]" style={{ height }}>
        <div className="h-full rounded-full transition-all"
          style={{ width: `${pct}%`, background: "var(--color-accent)" }} />
      </div>
      {label && <span className="mono shrink-0 text-[10px] text-[var(--color-ink-faint)]">{done}/{total} · {pct}%</span>}
    </div>
  );
}

export default function Programs() {
  const { data: list, loading: listLoading, refetch: refetchList } = useFetch<WorkspacesResp>("/api/workspaces");
  const qc = useQueryClient();
  const toast = useToast();
  const [sel, setSel] = useState<string | null>(null);
  const [openTask, setOpenTask] = useState<number | null>(null);
  const [sp, setSp] = useSearchParams();

  // Deep-link from the Target Board (/programs?key=…): select that workspace once,
  // then consume the param. Otherwise default to the current workspace.
  useEffect(() => {
    if (!list?.workspaces?.length) return;
    const urlKey = sp.get("key");
    if (urlKey) {
      if (list.workspaces.some((w) => w.key === urlKey)) setSel(urlKey);
      sp.delete("key"); setSp(sp, { replace: true });
      return;
    }
    if (!sel) setSel((list.workspaces.find((w) => w.current) || list.workspaces[0]).key);
  }, [list, sp]);

  const { data: ws, loading: wsLoading, refetch: refetchWs } =
    useFetch<WorkspaceDetail>(sel ? `/api/workspaces/${encodeURIComponent(sel)}` : null, [sel]);

  // moderate polling — detail every 20s, list every 40s
  useEffect(() => {
    const a = setInterval(() => refetchWs(), 20_000);
    const b = setInterval(() => refetchList(), 40_000);
    return () => { clearInterval(a); clearInterval(b); };
  }, [refetchWs, refetchList]);

  const refresh = () => { refetchWs(); refetchList(); qc.invalidateQueries(); };

  const addProgram = async (c: WorkspaceCandidate) => {
    try {
      await api.action(`/api/workspaces`, { key: c.key, name: c.name, platform: c.platform });
      toast("ok", `${c.name} — workspace started`);
      setSel(c.key); refresh();
    } catch (e: any) { toast("err", e.message); }
  };

  return (
    <div className="fade-in flex h-full min-h-0 gap-4">
      <ProgramRail list={list} loading={listLoading} sel={sel} onSelect={setSel} onAdd={addProgram} />

      <div className="flex min-w-0 flex-1 flex-col">
        {!sel ? (
          <Panel><Empty hint="pick a program from the left, or add one from the candidate picker">no program selected</Empty></Panel>
        ) : wsLoading && !ws ? <Spinner /> : !ws ? (
          <Panel><Empty>workspace failed to load</Empty></Panel>
        ) : (
          <WorkspaceView ws={ws} onChanged={refresh} onTask={setOpenTask} />
        )}
      </div>

      {openTask != null && <TaskConsole tid={openTask} onClose={() => setOpenTask(null)} onChanged={refresh} />}
    </div>
  );
}

// --- Left rail: program history + picker -------------------------------------
function ProgramRail({ list, loading, sel, onSelect, onAdd }:
  { list: WorkspacesResp | null; loading: boolean; sel: string | null;
    onSelect: (k: string) => void; onAdd: (c: WorkspaceCandidate) => void }) {
  const [picking, setPicking] = useState(false);
  const items = list?.workspaces || [];
  // current pinned at top, then by added_at desc
  const ordered = useMemo(() =>
    [...items].sort((a, b) => (Number(b.current) - Number(a.current)) || ((b.added_at || "") < (a.added_at || "") ? -1 : 1)),
    [items]);

  return (
    <aside className="flex w-64 shrink-0 flex-col rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)]">
      <div className="flex items-center justify-between border-b border-[var(--color-border)] px-3 py-2.5">
        <h2 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-[var(--color-ink-dim)]">
          <CrosshairIcon size={14} /> Programs
        </h2>
        <button onClick={() => setPicking((v) => !v)} title="add a program from candidates"
          className="mono rounded border border-[var(--color-accent)]/50 px-1.5 py-0.5 text-[10px] text-[var(--color-accent)] hover:bg-[var(--color-accent)]/10">
          {picking ? "✕ close" : "+ add"}
        </button>
      </div>

      {picking && (
        <div className="border-b border-[var(--color-border)] bg-[var(--color-panel-2)] p-2">
          <div className="mb-1.5 text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]">candidates · under-hunted EV</div>
          {(list?.candidates || []).length === 0 ? (
            <div className="px-1 py-2 text-[11px] text-[var(--color-ink-faint)]">no candidates queued</div>
          ) : (
            <div className="space-y-1">
              {list!.candidates.map((c) => (
                <button key={c.key} onClick={() => { onAdd(c); setPicking(false); }}
                  className="flex w-full items-center gap-2 rounded border border-[var(--color-border-bright)] px-2 py-1.5 text-left transition hover:border-[var(--color-accent)]">
                  <span className="min-w-0 flex-1 truncate text-[11px] text-[var(--color-ink)]">{c.name}</span>
                  {c.platform && <Badge>{c.platform}</Badge>}
                  {c.score != null && <span className="mono text-[10px] text-[var(--color-accent)]">{c.score}</span>}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="min-h-0 flex-1 space-y-1 overflow-auto p-2">
        {loading && !items.length ? <Spinner /> : !items.length ? (
          <Empty hint="+ add starts one from a candidate">no programs yet</Empty>
        ) : ordered.map((w) => (
          <RailRow key={w.key} w={w} active={w.key === sel} onClick={() => onSelect(w.key)} />
        ))}
      </div>
    </aside>
  );
}

function RailRow({ w, active, onClick }: { w: WorkspaceSummary; active: boolean; onClick: () => void }) {
  const c = w.counts;
  return (
    <button onClick={onClick}
      className={`w-full rounded-md border px-2.5 py-2 text-left transition ${active
        ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10"
        : "border-[var(--color-border)] hover:border-[var(--color-border-bright)] hover:bg-[var(--color-panel-2)]"}`}>
      <div className="flex items-center gap-1.5">
        {w.current && <span title="current program"><CrosshairIcon size={12} /></span>}
        <span className="min-w-0 flex-1 truncate text-[13px] font-medium text-[var(--color-ink)]">{w.name}</span>
        <span className="h-1.5 w-1.5 rounded-full" style={{ background: wsc(w.status) }} title={w.status} />
      </div>
      <div className="mt-1 flex items-center gap-1.5 text-[10px] text-[var(--color-ink-faint)]">
        {w.platform && <span className="mono">{w.platform}</span>}
        <span>·</span><span>{w.status}</span>
        <span className="ml-auto mono">{c.findings}◆ · {c.hosts}h</span>
      </div>
      <div className="mt-1.5"><CoverageBar done={c.wstg_done} total={c.wstg_total} height={4} label /></div>
    </button>
  );
}

// --- Workspace view: header + sub-tabs ---------------------------------------
type Tab = "guided" | "overview" | "wstg" | "stride" | "notes";

function WorkspaceView({ ws, onChanged, onTask }:
  { ws: WorkspaceDetail; onChanged: () => void; onTask: (tid: number) => void }) {
  const [tab, setTab] = useState<Tab>("guided");
  const toast = useToast();
  const done = ws.wstg.filter((w) => w.status === "done").length;
  const total = ws.wstg.length;
  const inprog = ws.wstg.filter((w) => w.status === "in-progress").length;
  const findingsN = ws.findings.length;
  const classesDone = ws.classes.filter((c) => c.status === "done" || c.status === "finding").length;

  const setStatus = async (body: { status?: string; current?: boolean }) => {
    try { await api.action(`/api/workspaces/${encodeURIComponent(ws.key)}/status`, body); toast("ok", "updated"); onChanged(); }
    catch (e: any) { toast("err", e.message); }
  };

  const tabs: { id: Tab; label: string }[] = [
    { id: "guided", label: "◎ Guided" }, { id: "overview", label: "Overview" },
    { id: "wstg", label: `WSTG · ${done}/${total}` },
    { id: "stride", label: "STRIDE" }, { id: "notes", label: "Notes / Timeline" },
  ];

  return (
    <div className="flex min-h-0 flex-1 flex-col space-y-4">
      {/* header */}
      <Panel>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="truncate text-lg font-semibold text-[var(--color-ink)]">{ws.name}</h1>
              {ws.platform && <Badge>{ws.platform}</Badge>}
              <Badge color={wsc(ws.status)} filled>{ws.status}</Badge>
              {ws.current && <Badge color="var(--color-accent)"><span className="inline-flex items-center gap-1"><CrosshairIcon size={10} />current</span></Badge>}
            </div>
            {ws.added_at && <div className="mt-1 text-[11px] text-[var(--color-ink-faint)]">started {fmtAgo(ws.added_at)}</div>}
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            {["active", "paused", "done"].map((s) => (
              <button key={s} onClick={() => setStatus({ status: s })} disabled={ws.status === s}
                className="mono rounded border px-2 py-1 text-[11px] transition disabled:opacity-100"
                style={ws.status === s
                  ? { borderColor: wsc(s), color: "#0a0e14", background: wsc(s) }
                  : { borderColor: "var(--color-border-bright)", color: "var(--color-ink-dim)" }}>
                {s}
              </button>
            ))}
            {!ws.current && <Btn size="sm" variant="primary" onClick={() => setStatus({ current: true })}>set current</Btn>}
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-4">
          <div className="min-w-[220px] flex-1">
            <div className="mb-1 flex items-center justify-between text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]">
              <span>WSTG coverage</span><span className="mono">{inprog} in progress</span>
            </div>
            <CoverageBar done={done} total={total} height={8} label />
          </div>
          <HeaderCount label="findings" value={findingsN} />
          <HeaderCount label="hosts" value={ws.hosts.length} />
          <HeaderCount label="classes done" value={`${classesDone}/${ws.classes.length}`} />
        </div>
      </Panel>

      {/* sub-tabs */}
      <div className="flex flex-wrap items-center gap-1.5">
        {tabs.map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`rounded-md border px-3 py-1.5 text-xs transition ${tab === t.id
              ? "border-[var(--color-accent)] text-[var(--color-accent)]"
              : "border-[var(--color-border-bright)] text-[var(--color-ink-dim)] hover:text-[var(--color-ink)]"}`}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "guided" && <GuidedTab ws={ws} onChanged={onChanged} onTask={onTask} />}
      {tab === "overview" && <OverviewTab ws={ws} onChanged={onChanged} onTask={onTask} />}
      {tab === "wstg" && <WstgTab ws={ws} onChanged={onChanged} />}
      {tab === "stride" && <StrideTab ws={ws} onChanged={onChanged} />}
      {tab === "notes" && <NotesTab ws={ws} onChanged={onChanged} />}
    </div>
  );
}

function HeaderCount({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-1.5 text-center">
      <div className="mono text-lg font-semibold leading-none text-[var(--color-ink)]">{value}</div>
      <div className="mt-1 text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]">{label}</div>
    </div>
  );
}

// --- Overview tab: hosts + findings + class grid -----------------------------
function OverviewTab({ ws, onChanged, onTask }:
  { ws: WorkspaceDetail; onChanged: () => void; onTask: (tid: number) => void }) {
  const hostActions = useHostActions();
  const [expanded, setExpanded] = useState<string | null>(null);
  const [drawer, setDrawer] = useState<string | null>(null);
  const [sort, setSort] = useState("triage_score");
  const [order, setOrder] = useState<"asc" | "desc">("desc");
  const toast = useToast();

  const onSort = (col: string) => {
    if (sort === col) setOrder((o) => (o === "asc" ? "desc" : "asc"));
    else { setSort(col); setOrder("desc"); }
  };
  const hosts = useMemo(() => {
    const dir = order === "asc" ? 1 : -1;
    return [...ws.hosts].sort((a: any, b: any) => {
      const av = a[sort] ?? "", bv = b[sort] ?? "";
      return av < bv ? -dir : av > bv ? dir : 0;
    });
  }, [ws.hosts, sort, order]);

  const cycleClass = async (cls: string, cur: string) => {
    const next = CLASS_CYCLE[(CLASS_CYCLE.indexOf(cur) + 1) % CLASS_CYCLE.length];
    try { await api.action(`/api/workspaces/${encodeURIComponent(ws.key)}/class`, { cls, status: next }); onChanged(); }
    catch (e: any) { toast("err", e.message); }
  };

  return (
    <div className="min-h-0 flex-1 space-y-4 overflow-auto pb-4">
      <Panel title="in-scope + paying hosts" right={<span className="text-[10px] text-[var(--color-ink-faint)]">{ws.hosts.length} · row → inline testing</span>} className="!p-0">
        {!hosts.length ? <div className="p-4"><Empty hint="run recon lanes to populate the program surface">no hosts yet</Empty></div> : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">
                <th className="w-6 px-2 py-2" />
                <SortTh label="pri" col="triage_priority" active={sort} order={order} onSort={onSort} />
                <SortTh label="host" col="host" active={sort} order={order} onSort={onSort} />
                <SortTh label="tech" />
                <SortTh label="classes" />
                <SortTh label="score" col="triage_score" active={sort} order={order} onSort={onSort} />
                <SortTh label="flags" align="right" className="!px-4" />
              </tr>
            </thead>
            <tbody>
              {hosts.map((h: WsHost) => (
                <HostRow key={h.host} h={h} expanded={expanded === h.host}
                  onToggle={() => setExpanded((e) => (e === h.host ? null : h.host))}
                  onDrawer={() => setDrawer(h.host)} actions={hostActions} onTask={onTask} onChanged={onChanged} />
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="findings" right={<Badge color="var(--color-accent)">{ws.findings.length}</Badge>}>
          {!ws.findings.length ? <Empty>no findings on this program</Empty> : (
            <div className="space-y-1.5">
              {ws.findings.map((f) => (
                <div key={f.id} className="flex items-center gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2.5 py-1.5">
                  <Badge color={stateColor[f.state] || "var(--color-ink-dim)"} filled>{f.state}</Badge>
                  <button onClick={() => setDrawer(f.host)} className="mono min-w-0 flex-1 truncate text-left text-[11px] text-[var(--color-ink)] hover:text-[var(--color-accent)]" title={f.host}>{f.host}</button>
                  {f.vuln_class && <Badge color={classColor[f.vuln_class] || "var(--color-ink-dim)"}>{f.vuln_class}</Badge>}
                  {f.ai_verdict && <Badge color={verdictColor[f.ai_verdict] || "var(--color-ink-dim)"}>{f.ai_verdict}</Badge>}
                  {f.score != null && <span className="mono shrink-0 text-[10px] text-[var(--color-ink-faint)]">{f.score}</span>}
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="bug-class coverage" right={<span className="text-[10px] text-[var(--color-ink-faint)]">click to cycle</span>}>
          {!ws.classes.length ? <Empty>no classes tracked</Empty> : (
            <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3">
              {ws.classes.map((c) => (
                <button key={c.cls} onClick={() => cycleClass(c.cls, c.status)} title={`${c.cls}: ${c.status} — click to advance`}
                  className="flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-left transition hover:border-[var(--color-border-bright)]"
                  style={{ borderColor: `${wsc(c.status)}55`, background: `${wsc(c.status)}12` }}>
                  <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: wsc(c.status) }} />
                  <span className="mono min-w-0 flex-1 truncate text-[11px] text-[var(--color-ink)]">{c.cls}</span>
                  <span className="text-[9px] uppercase tracking-wider text-[var(--color-ink-faint)]">{c.status === "in-progress" ? "wip" : c.status}</span>
                </button>
              ))}
            </div>
          )}
        </Panel>
      </div>

      {drawer && <HostDrawer host={drawer} onClose={() => setDrawer(null)} />}
    </div>
  );
}

function HostRow({ h, expanded, onToggle, onDrawer, actions, onTask, onChanged }:
  { h: WsHost; expanded: boolean; onToggle: () => void; onDrawer: () => void;
    actions: any[]; onTask: (tid: number) => void; onChanged: () => void }) {
  return (
    <>
      <tr className="border-b border-[var(--color-border)]/50 hover:bg-[var(--color-panel-2)]">
        <td className="px-2 py-2 text-center">
          <button onClick={onToggle} title={expanded ? "collapse" : "inline testing"}
            className="text-[var(--color-ink-faint)] hover:text-[var(--color-accent)]">{expanded ? "▾" : "▸"}</button>
        </td>
        <td className="px-2 py-2">{h.triage_priority && <Badge color={priorityColor[h.triage_priority] || "var(--color-ink-dim)"}>{h.triage_priority}</Badge>}</td>
        <td className="mono max-w-xs truncate px-2 py-2 text-xs text-[var(--color-ink)]">
          <button onClick={onDrawer} className="truncate hover:text-[var(--color-accent)]" title={h.host}>{h.host}</button>
        </td>
        <td className="max-w-[130px] truncate px-2 py-2 text-[11px] text-[var(--color-ink-faint)]">{asArr(h.tech).slice(0, 3).join(", ") || "—"}</td>
        <td className="max-w-[130px] truncate px-2 py-2 text-[11px] text-[var(--color-ink-faint)]">{asArr(h.triage_classes).slice(0, 3).join(", ") || "—"}</td>
        <td className="mono px-2 py-2 text-xs">{h.triage_score ?? "—"}</td>
        <td className="px-4 py-2 text-right">
          <div className="flex justify-end gap-1">
            {h.triage_true_fresh && <Badge color="var(--color-accent)">fresh</Badge>}
            {h.triage_kev_match && <Badge color="var(--color-bad)">kev</Badge>}
            {h.takeover_confirmed && <Badge color="var(--color-bad)">takeover</Badge>}
            {h.js_secret_hit && <Badge color="var(--color-warn)">secret</Badge>}
            {!!h.host_notes_count && <Badge>📝{h.host_notes_count}</Badge>}
          </div>
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-[var(--color-border)]/50 bg-[var(--color-bg)]">
          <td colSpan={7} className="px-4 py-2.5">
            <div className="flex items-center gap-2">
              <span className="text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]">test · VPN-gated:</span>
              <LeadActions host={h.host} vulnClass={asArr(h.triage_classes)[0] || null} actions={actions} onTask={onTask} onChanged={onChanged} />
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// --- Guided walkthrough: STRIDE → WSTG, one step at a time, AI-driven --------
type GuideStep = { phase: "stride" | "wstg"; key: string };

function GuidedTab({ ws, onChanged, onTask }:
  { ws: WorkspaceDetail; onChanged: () => void; onTask: (tid: number) => void }) {
  const toast = useToast();
  const hostActions = useHostActions();
  const { data: ref } = useFetch<WstgReference>("/api/wstg/reference");
  const enc = encodeURIComponent(ws.key);
  const [idx, setIdx] = useState(0);
  const [host, setHost] = useState("");
  const [canned, setCanned] = useState<string | null>(null);
  const [showMap, setShowMap] = useState(false);

  // ordered walkthrough: 6 STRIDE categories, then all WSTG tests in canonical order
  const steps = useMemo<GuideStep[]>(() => [
    ...STRIDE_COLS.map((c) => ({ phase: "stride" as const, key: c.cat })),
    ...ws.wstg.map((w) => ({ phase: "wstg" as const, key: w.id })),
  ], [ws.wstg]);

  const wstgById = useMemo(() => new Map(ws.wstg.map((w) => [w.id, w])), [ws.wstg]);
  const isCovered = (s: GuideStep) =>
    s.phase === "stride" ? (ws.stride[s.key as keyof StrideBoardT] || []).length > 0
      : (wstgById.get(s.key)?.status || "todo") !== "todo";

  const strideCovered = STRIDE_COLS.filter((c) => (ws.stride[c.cat] || []).length > 0).length;
  const wstgCovered = ws.wstg.filter((w) => w.status !== "todo").length;

  // reset per-step scratch when the focus changes
  useEffect(() => { setHost(""); setCanned(null); }, [idx]);

  const clamped = Math.min(idx, Math.max(0, steps.length - 1));
  const step = steps[clamped];

  const jumpNextUncovered = () => {
    for (let i = 1; i <= steps.length; i++) {
      const j = (clamped + i) % steps.length;
      if (!isCovered(steps[j])) { setIdx(j); return; }
    }
    toast("ok", "every step is covered — nothing left uncovered");
  };

  const guide = async (phase: "stride" | "wstg", id: string, h?: string) => {
    if (isDemo()) { setCanned(demoGuidance(phase, id)); return; }
    setCanned(null);
    try {
      const t = await api.action<{ id: number }>(`/api/workspaces/${enc}/guide`,
        { phase, id, host: h || undefined });
      toast("ok", `Claude guidance #${t.id} — streaming below`);
      onTask(t.id);
    } catch (e: any) { toast("err", e.message); }
  };

  if (!steps.length) return <Panel><Empty>walkthrough not initialized</Empty></Panel>;

  return (
    <div className="min-h-0 flex-1 space-y-3 overflow-auto pb-4">
      {/* progress header */}
      <Panel>
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-[var(--color-ink)]">
            <span className="text-[var(--color-accent)]">◎</span> Guided engagement
          </div>
          <div className="min-w-[160px] flex-1">
            <div className="mb-0.5 flex items-center justify-between text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]">
              <span>STRIDE threat model</span><span className="mono">{strideCovered}/{STRIDE_COLS.length}</span>
            </div>
            <CoverageBar done={strideCovered} total={STRIDE_COLS.length} height={6} />
          </div>
          <div className="min-w-[160px] flex-1">
            <div className="mb-0.5 flex items-center justify-between text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]">
              <span>WSTG · {ws.wstg.length} tests</span><span className="mono">{wstgCovered}/{ws.wstg.length}</span>
            </div>
            <CoverageBar done={wstgCovered} total={ws.wstg.length} height={6} />
          </div>
          <Btn size="sm" variant="primary" onClick={jumpNextUncovered}>next uncovered →</Btn>
          <button onClick={() => setShowMap((v) => !v)}
            className="mono rounded border border-[var(--color-border-bright)] px-2 py-1 text-[11px] text-[var(--color-ink-dim)] hover:text-[var(--color-ink)]">
            {showMap ? "hide map" : "all steps"}
          </button>
        </div>
        {showMap && <StepMap ws={ws} steps={steps} focus={clamped} isCovered={isCovered} onPick={setIdx} />}
      </Panel>

      {/* step nav */}
      <div className="flex items-center justify-between gap-2">
        <button onClick={() => setIdx((i) => Math.max(0, i - 1))} disabled={clamped === 0}
          className="mono rounded border border-[var(--color-border-bright)] px-2.5 py-1 text-[11px] text-[var(--color-ink-dim)] hover:text-[var(--color-ink)] disabled:opacity-40">
          ← prev
        </button>
        <span className="mono text-[11px] text-[var(--color-ink-faint)]">
          step {clamped + 1} / {steps.length} · {step.phase === "stride" ? "STRIDE" : "WSTG"}
        </span>
        <button onClick={() => setIdx((i) => Math.min(steps.length - 1, i + 1))} disabled={clamped === steps.length - 1}
          className="mono rounded border border-[var(--color-border-bright)] px-2.5 py-1 text-[11px] text-[var(--color-ink-dim)] hover:text-[var(--color-ink)] disabled:opacity-40">
          next →
        </button>
      </div>

      {step.phase === "stride"
        ? <StrideGuideStep ws={ws} cat={step.key} guideCat={ref?.stride?.[step.key]} onChanged={onChanged}
            onGuide={() => guide("stride", step.key)} canned={canned} onNext={jumpNextUncovered} />
        : <WstgGuideStep ws={ws} item={wstgById.get(step.key)!} host={host} setHost={setHost}
            actions={hostActions} onTask={onTask} onChanged={onChanged}
            onGuide={() => guide("wstg", step.key, host)} canned={canned} onNext={jumpNextUncovered} />}
    </div>
  );
}

// compact "all steps" map — comprehensiveness made visible, nothing silently skipped
function StepMap({ ws, steps, focus, isCovered, onPick }:
  { ws: WorkspaceDetail; steps: GuideStep[]; focus: number;
    isCovered: (s: GuideStep) => boolean; onPick: (i: number) => void }) {
  const wstgGroups = useMemo(() => {
    const m = new Map<string, { cat: string; cat_name: string; items: { i: number; it: WstgItem }[] }>();
    steps.forEach((s, i) => {
      if (s.phase !== "wstg") return;
      const it = ws.wstg.find((w) => w.id === s.key)!;
      const g = m.get(it.category) || { cat: it.category, cat_name: it.cat_name, items: [] };
      g.items.push({ i, it }); m.set(it.category, g);
    });
    return Array.from(m.values());
  }, [steps, ws.wstg]);

  return (
    <div className="mt-3 space-y-2 border-t border-[var(--color-border)] pt-3">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="mono w-16 shrink-0 text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]">STRIDE</span>
        {steps.map((s, i) => s.phase === "stride" && (
          <button key={s.key} onClick={() => onPick(i)} title={s.key}
            className={`mono rounded border px-1.5 py-0.5 text-[10px] ${i === focus ? "border-[var(--color-accent)] text-[var(--color-accent)]" : "border-[var(--color-border-bright)]"}`}
            style={{ color: i === focus ? undefined : wsc(isCovered(s) ? "done" : "todo") }}>
            {s.key}
          </button>
        ))}
      </div>
      {wstgGroups.map((g) => (
        <div key={g.cat} className="flex flex-wrap items-center gap-1">
          <span className="mono w-16 shrink-0 truncate text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]" title={g.cat_name}>{g.cat}</span>
          {g.items.map(({ i, it }) => (
            <button key={it.id} onClick={() => onPick(i)} title={`${it.id} · ${it.name} — ${it.status}`}
              className={`mono h-5 w-6 rounded border text-[9px] ${i === focus ? "border-[var(--color-accent)]" : "border-[var(--color-border)]"}`}
              style={{ color: wsc(it.status), background: `${wsc(it.status)}18` }}>
              {it.id.split("-")[2]}
            </button>
          ))}
        </div>
      ))}
    </div>
  );
}

function GuideBox({ canned }: { canned: string | null }) {
  if (canned == null) return null;
  return (
    <div className="mt-2 rounded-md border border-[var(--color-accent)]/40 bg-[var(--color-accent)]/5 p-3">
      <div className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-[var(--color-accent)]">
        <span>◎</span> Claude guidance <span className="text-[var(--color-ink-faint)]">(demo · canned)</span>
      </div>
      <div className="mono whitespace-pre-wrap text-[11px] leading-relaxed text-[var(--color-ink-dim)]">{canned}</div>
    </div>
  );
}

function StrideGuideStep({ ws, cat, guideCat, onChanged, onGuide, canned, onNext }:
  { ws: WorkspaceDetail; cat: string; guideCat?: { name: string; prompt: string; examples: string[] };
    onChanged: () => void; onGuide: () => void; canned: string | null; onNext: () => void }) {
  const toast = useToast();
  const [val, setVal] = useState("");
  const threats = ws.stride[cat as keyof StrideBoardT] || [];
  const add = async () => {
    if (!val.trim()) return;
    try { await api.action(`/api/workspaces/${encodeURIComponent(ws.key)}/stride`, { cat, threat: val.trim() }); setVal(""); toast("ok", "threat added"); onChanged(); }
    catch (e: any) { toast("err", e.message); }
  };
  const label = STRIDE_COLS.find((c) => c.cat === cat)?.label || guideCat?.name || cat;
  return (
    <Panel title={<span className="flex items-center gap-2"><span className="mono text-[var(--color-accent)]">{cat}</span>{label}<Badge>STRIDE</Badge></span>}
      right={<Badge>{threats.length} threats</Badge>}>
      {guideCat && (
        <>
          <p className="text-[12px] leading-relaxed text-[var(--color-ink-dim)]">{guideCat.prompt}</p>
          {guideCat.examples?.length > 0 && (
            <ul className="mt-2 space-y-1">
              {guideCat.examples.map((e, i) => (
                <li key={i} className="flex gap-2 text-[11px] text-[var(--color-ink-faint)]">
                  <span className="text-[var(--color-accent)]">▹</span><span>{e}</span>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Btn size="sm" variant="primary" onClick={onGuide}>◎ Guide me (Claude)</Btn>
        <span className="text-[10px] text-[var(--color-ink-faint)]">program-specific threats for this category → streams below</span>
      </div>
      <GuideBox canned={canned} />
      <div className="mt-3 space-y-1">
        {threats.map((t, i) => (
          <div key={t.id || i} className="flex items-start gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2.5 py-1.5">
            <span className="mt-0.5 h-2 w-2 shrink-0 rounded-full" style={{ background: wsc(t.status) }} />
            <span className="min-w-0 flex-1 text-[11px] text-[var(--color-ink)]">{t.threat}</span>
          </div>
        ))}
        {!threats.length && <div className="px-1 py-1 text-[10px] text-[var(--color-ink-faint)]">no threats logged for this category yet</div>}
      </div>
      <div className="mt-2 flex items-center gap-2">
        <input value={val} onChange={(e) => setVal(e.target.value)} onKeyDown={(e) => e.key === "Enter" && add()}
          placeholder="+ add a concrete threat for this category…"
          className="mono flex-1 rounded border border-[var(--color-border-bright)] bg-[var(--color-panel-2)] px-2 py-1 text-[11px] outline-none focus:border-[var(--color-accent)]" />
        <Btn size="sm" onClick={add}>add</Btn>
        <Btn size="sm" variant="primary" onClick={onNext}>next →</Btn>
      </div>
    </Panel>
  );
}

const GUIDE_STATUSES = ["done", "finding", "na", "in-progress"];

function WstgGuideStep({ ws, item, host, setHost, actions, onTask, onChanged, onGuide, canned, onNext }:
  { ws: WorkspaceDetail; item: WstgItem; host: string; setHost: (h: string) => void;
    actions: any[]; onTask: (tid: number) => void; onChanged: () => void;
    onGuide: () => void; canned: string | null; onNext: () => void }) {
  const toast = useToast();
  const [note, setNote] = useState(item.note || "");
  useEffect(() => { setNote(item.note || ""); }, [item.id]);
  const post = async (status: string) => {
    try { await api.action(`/api/workspaces/${encodeURIComponent(ws.key)}/wstg`, { id: item.id, status, note }); toast("ok", `${item.id} → ${status}`); onChanged(); }
    catch (e: any) { toast("err", e.message); }
  };
  const mark = async (status: string) => { await post(status); onNext(); };

  return (
    <Panel
      title={<span className="flex items-center gap-2"><span className="mono text-[var(--color-ink-faint)]">{item.id}</span>{item.name}</span>}
      right={<div className="flex items-center gap-2"><Badge>{item.cat_name}</Badge><Badge color={wsc(item.status)} filled>{item.status}</Badge></div>}>
      {/* static reference — always shown so nothing is glossed over */}
      <div className="space-y-2">
        {item.objective && (
          <div><span className="text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]">objective</span>
            <p className="text-[12px] leading-relaxed text-[var(--color-ink)]">{item.objective}</p></div>
        )}
        {item.how_to && (
          <div><span className="text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]">how to test</span>
            <p className="text-[12px] leading-relaxed text-[var(--color-ink-dim)]">{item.how_to}</p></div>
        )}
        <div className="flex flex-wrap items-center gap-2">
          {item.tools && item.tools.split(",").map((t, i) => (
            <span key={i} className="mono rounded border border-[var(--color-border-bright)] bg-[var(--color-panel-2)] px-1.5 py-0.5 text-[10px] text-[var(--color-ink-dim)]">{t.trim()}</span>
          ))}
          {item.wstg_url && (
            <a href={item.wstg_url} target="_blank" rel="noreferrer"
              className="mono text-[10px] text-[var(--color-accent)] hover:underline">WSTG ↗</a>
          )}
        </div>
      </div>

      {/* AI guidance */}
      <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-[var(--color-border)] pt-3">
        <Btn size="sm" variant="primary" onClick={onGuide}>◎ Guide me (Claude)</Btn>
        <span className="text-[10px] text-[var(--color-ink-faint)]">comprehensive, program-specific steps for this test → streams below</span>
      </div>
      <GuideBox canned={canned} />

      {/* inline testing on a chosen host */}
      <div className="mt-3 border-t border-[var(--color-border)] pt-3">
        <div className="mb-1.5 flex flex-wrap items-center gap-2">
          <span className="text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]">run on host · VPN-gated</span>
          <select value={host} onChange={(e) => setHost(e.target.value)}
            className="mono max-w-[260px] rounded border border-[var(--color-border-bright)] bg-[var(--color-panel-2)] px-2 py-1 text-[11px] outline-none focus:border-[var(--color-accent)]">
            <option value="">— pick a host —</option>
            {ws.hosts.map((h) => <option key={h.host} value={h.host} style={{ background: "var(--color-panel)" }}>{h.host}</option>)}
          </select>
        </div>
        {host
          ? <LeadActions host={host} vulnClass={null} actions={actions} onTask={onTask} onChanged={onChanged} />
          : <div className="text-[10px] text-[var(--color-ink-faint)]">pick a host to run the relevant tools without leaving this step</div>}
      </div>

      {/* status + advance */}
      <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-[var(--color-border)] pt-3">
        <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="note / evidence…"
          onKeyDown={(e) => e.key === "Enter" && post(item.status)}
          className="mono min-w-[180px] flex-1 rounded border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2 py-1 text-[11px] outline-none focus:border-[var(--color-accent)]" />
        {GUIDE_STATUSES.map((s) => (
          <button key={s} onClick={() => mark(s)} title={`mark ${item.id} ${s} and advance`}
            className="mono rounded border px-2 py-1 text-[11px] transition"
            style={{ borderColor: `${wsc(s)}66`, color: wsc(s), background: `${wsc(s)}12` }}>
            {s === "in-progress" ? "wip" : s}
          </button>
        ))}
        <Btn size="sm" variant="primary" onClick={onNext}>next test →</Btn>
      </div>
    </Panel>
  );
}

// --- WSTG tab: OWASP checklist grouped by category ---------------------------
function WstgTab({ ws, onChanged }: { ws: WorkspaceDetail; onChanged: () => void }) {
  const toast = useToast();
  const groups = useMemo(() => {
    const m = new Map<string, { cat: string; cat_name: string; items: WstgItem[] }>();
    for (const it of ws.wstg) {
      const g = m.get(it.category) || { cat: it.category, cat_name: it.cat_name, items: [] };
      g.items.push(it); m.set(it.category, g);
    }
    return Array.from(m.values());
  }, [ws.wstg]);

  const post = async (body: { id: string; status: string; note?: string }) => {
    try { await api.action(`/api/workspaces/${encodeURIComponent(ws.key)}/wstg`, body); onChanged(); }
    catch (e: any) { toast("err", e.message); }
  };

  return (
    <div className="min-h-0 flex-1 space-y-3 overflow-auto pb-4">
      {groups.map((g) => {
        const done = g.items.filter((i) => i.status === "done").length;
        return (
          <Panel key={g.cat}
            title={<span className="flex items-center gap-2"><span className="mono text-[var(--color-ink-faint)]">{g.cat}</span>{g.cat_name}</span>}
            right={<div className="w-40"><CoverageBar done={done} total={g.items.length} label /></div>}>
            <div className="space-y-1">
              {g.items.map((it) => <WstgRow key={it.id} it={it} onPost={post} />)}
            </div>
          </Panel>
        );
      })}
      {!groups.length && <Panel><Empty>WSTG checklist not initialized</Empty></Panel>}
    </div>
  );
}

function WstgRow({ it, onPost }: { it: WstgItem; onPost: (b: { id: string; status: string; note?: string }) => void }) {
  const [note, setNote] = useState(it.note || "");
  useEffect(() => { setNote(it.note || ""); }, [it.note]);
  const saveNote = () => { if (note !== (it.note || "")) onPost({ id: it.id, status: it.status, note }); };
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2.5 py-1.5">
      <span className="mono shrink-0 text-[10px] text-[var(--color-ink-faint)]" style={{ minWidth: 92 }}>{it.id}</span>
      <span className="min-w-[160px] flex-1 text-[12px] text-[var(--color-ink)]">{it.name}</span>
      <input value={note} onChange={(e) => setNote(e.target.value)} onBlur={saveNote}
        onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()} placeholder="note…"
        className="mono w-48 rounded border border-[var(--color-border)] bg-[var(--color-panel)] px-2 py-1 text-[11px] outline-none focus:border-[var(--color-accent)]" />
      <select value={it.status} onChange={(e) => onPost({ id: it.id, status: e.target.value, note })}
        className="mono shrink-0 rounded border px-2 py-1 text-[11px] outline-none"
        style={{ borderColor: `${wsc(it.status)}66`, color: wsc(it.status), background: `${wsc(it.status)}12` }}>
        {WSTG_STATUSES.map((s) => <option key={s} value={s} style={{ background: "var(--color-panel)", color: "var(--color-ink)" }}>{s}</option>)}
      </select>
    </div>
  );
}

// --- STRIDE tab: 6-column threat board ---------------------------------------
function StrideTab({ ws, onChanged }: { ws: WorkspaceDetail; onChanged: () => void }) {
  const toast = useToast();
  const add = async (cat: string, threat: string) => {
    if (!threat.trim()) return;
    try { await api.action(`/api/workspaces/${encodeURIComponent(ws.key)}/stride`, { cat, threat: threat.trim() }); onChanged(); }
    catch (e: any) { toast("err", e.message); }
  };
  const update = async (cat: string, t: StrideThreat, status: string) => {
    try { await api.action(`/api/workspaces/${encodeURIComponent(ws.key)}/stride`, { cat, id: t.id, threat: t.threat, note: t.note, status }); onChanged(); }
    catch (e: any) { toast("err", e.message); }
  };
  return (
    <div className="min-h-0 flex-1 overflow-auto pb-4">
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {STRIDE_COLS.map((col) => (
          <StrideColumn key={col.cat} label={col.label} cat={col.cat}
            threats={ws.stride[col.cat] || []} onAdd={(v) => add(col.cat, v)} onCycle={(t) => update(col.cat, t, nextStride(t.status))} />
        ))}
      </div>
    </div>
  );
}
function nextStride(cur?: string) {
  const seq = ["todo", "in-progress", "finding", "na"];
  return seq[(seq.indexOf(cur || "todo") + 1) % seq.length];
}

function StrideColumn({ label, cat, threats, onAdd, onCycle }:
  { label: string; cat: string; threats: StrideThreat[]; onAdd: (v: string) => void; onCycle: (t: StrideThreat) => void }) {
  const [val, setVal] = useState("");
  const submit = () => { onAdd(val); setVal(""); };
  return (
    <div className="flex flex-col rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)]">
      <div className="flex items-center justify-between border-b border-[var(--color-border)] px-3 py-2">
        <span className="text-xs font-semibold text-[var(--color-ink)]"><span className="mono text-[var(--color-accent)]">{cat}</span> · {label}</span>
        <Badge>{threats.length}</Badge>
      </div>
      <div className="flex-1 space-y-1.5 p-2">
        {threats.map((t, i) => (
          <div key={t.id || i} className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2 py-1.5">
            <div className="flex items-start gap-1.5">
              <button onClick={() => onCycle(t)} title={`${t.status || "todo"} — click to cycle`}
                className="mt-0.5 h-2 w-2 shrink-0 rounded-full" style={{ background: wsc(t.status) }} />
              <span className="min-w-0 flex-1 text-[11px] text-[var(--color-ink)]">{t.threat}</span>
            </div>
            {t.note && <div className="mt-1 pl-3.5 text-[10px] text-[var(--color-ink-faint)]">{t.note}</div>}
            {t.hosts && t.hosts.length > 0 && (
              <div className="mt-1 flex flex-wrap gap-1 pl-3.5">
                {t.hosts.map((h) => <span key={h} className="mono truncate rounded bg-[var(--color-panel)] px-1 py-0.5 text-[9px] text-[var(--color-ink-faint)]" style={{ maxWidth: 150 }}>{h}</span>)}
              </div>
            )}
          </div>
        ))}
        {!threats.length && <div className="px-1 py-2 text-[10px] text-[var(--color-ink-faint)]">no threats</div>}
      </div>
      <div className="border-t border-[var(--color-border)] p-2">
        <input value={val} onChange={(e) => setVal(e.target.value)} onKeyDown={(e) => e.key === "Enter" && submit()}
          placeholder="+ add threat…"
          className="mono w-full rounded border border-[var(--color-border-bright)] bg-[var(--color-panel-2)] px-2 py-1 text-[11px] outline-none focus:border-[var(--color-accent)]" />
      </div>
    </div>
  );
}

// --- Notes / Timeline tab ----------------------------------------------------
function NotesTab({ ws, onChanged }: { ws: WorkspaceDetail; onChanged: () => void }) {
  const toast = useToast();
  const [text, setText] = useState("");
  const add = async () => {
    if (!text.trim()) return;
    try { await api.action(`/api/workspaces/${encodeURIComponent(ws.key)}/note`, { text: text.trim() }); setText(""); toast("ok", "note saved"); onChanged(); }
    catch (e: any) { toast("err", e.message); }
  };
  return (
    <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 overflow-auto pb-4 lg:grid-cols-2">
      <Panel title="notes">
        <div className="mb-3 flex items-start gap-2">
          <textarea value={text} onChange={(e) => setText(e.target.value)} rows={2} placeholder="add a program note…"
            onKeyDown={(e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) add(); }}
            className="mono flex-1 resize-none rounded-md border border-[var(--color-border-bright)] bg-[var(--color-panel-2)] px-2.5 py-1.5 text-[11px] outline-none focus:border-[var(--color-accent)]" />
          <Btn size="sm" variant="primary" onClick={add}>add</Btn>
        </div>
        {!ws.notes.length ? <Empty>no notes yet</Empty> : (
          <div className="space-y-1.5">
            {ws.notes.map((n, i) => (
              <div key={i} className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2.5 py-1.5">
                <div className="text-[10px] text-[var(--color-ink-faint)]">{fmtAgo(n.ts)}</div>
                <div className="mt-0.5 text-[12px] text-[var(--color-ink)]">{n.text}</div>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <Panel title="timeline · history">
        {!ws.history.length ? <Empty>no history yet</Empty> : (
          <ol className="relative space-y-3 border-l border-[var(--color-border)] pl-4">
            {ws.history.map((h, i) => (
              <li key={i} className="relative">
                <span className="absolute -left-[21px] top-1 h-2 w-2 rounded-full" style={{ background: "var(--color-accent)" }} />
                <div className="text-[12px] text-[var(--color-ink)]">{h.event}</div>
                <div className="text-[10px] text-[var(--color-ink-faint)]">{fmtAgo(h.ts)}</div>
              </li>
            ))}
          </ol>
        )}
      </Panel>
    </div>
  );
}
