import { useState } from "react";
import { useFetch } from "../hooks";
import { Panel, Badge, Empty, Spinner } from "../components/ui";
import { LeadActions, useHostActions } from "../components/LeadActions";
import { HostDrawer } from "../components/HostDrawer";
import { TaskConsole } from "../components/TaskConsole";
import { getTask, setTask, clearTask } from "../taskStore";
import { priorityColor, classColor, asArr } from "../format";

interface HClass { cls: string; label: string; count: number; confirm: string; cmd: string; kb: string; kb_exists: boolean }
interface HTargets { meta: HClass; total: number; items: any[] }

// Hunter by vuln-class: pick a class → its in-scope+paying targets (ES triage_classes), the SAFE
// confirm primitive, the on-demand command, and the KB methodology. Targets are testable inline.
export default function Hunter() {
  const { data } = useFetch<{ classes: HClass[] }>("/api/hunter/classes");
  const [sel, setSel] = useState<string | null>(null);
  const [drawer, setDrawer] = useState<string | null>(null);
  const [openTask, setOpenTask] = useState<number | null>(() => getTask("drawer:hunter"));
  const actions = useHostActions();
  const { data: targets, loading, refetch } = useFetch<HTargets>(sel ? `/api/hunter/${sel}` : null, [sel]);

  const onTask = (tid: number) => { setOpenTask(tid); setTask("drawer:hunter", tid); };
  const closeTask = () => { setOpenTask(null); clearTask("drawer:hunter"); };

  return (
    <div className="fade-in space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="text-lg font-semibold">Hunter · by vuln class</h1>
        <span className="text-xs text-[var(--color-ink-faint)]">pick a class → its in-scope+paying targets, the SAFE confirm primitive, and the KB method</span>
      </div>

      {!data ? <Spinner /> : (
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
          {data.classes.map((c) => (
            <button key={c.cls} onClick={() => setSel(c.cls === sel ? null : c.cls)}
              className={`rounded-lg border p-3 text-left transition ${c.cls === sel
                ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10"
                : "border-[var(--color-border)] hover:border-[var(--color-border-bright)] hover:bg-[var(--color-panel-2)]"}`}>
              <div className="flex items-center justify-between gap-2">
                <span className="min-w-0 truncate text-[13px] font-medium text-[var(--color-ink)]">{c.label}</span>
                <Badge color={c.count > 0 ? "var(--color-accent)" : "var(--color-ink-faint)"}>{c.count}</Badge>
              </div>
              <div className="mono mt-1 text-[10px] text-[var(--color-ink-faint)]">{c.cls}</div>
            </button>
          ))}
        </div>
      )}

      {sel && targets?.meta && (
        <Panel
          title={<span className="flex items-center gap-2">{targets.meta.label}<Badge color={classColor[sel] || "var(--color-ink-dim)"}>{sel}</Badge></span>}
          right={<Badge color="var(--color-accent)">{targets.total} targets</Badge>}>
          <div className="mb-3 grid grid-cols-1 gap-2 md:grid-cols-2">
            <div className="rounded border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2.5 py-1.5">
              <div className="text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]">safe confirm primitive</div>
              <div className="text-[11px] text-[var(--color-ink)]">{targets.meta.confirm}</div>
            </div>
            <div className="rounded border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2.5 py-1.5">
              <div className="text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]">on-demand · method</div>
              <div className="mono text-[11px] text-[var(--color-accent)]">{targets.meta.cmd || "operator-driven"}</div>
              {targets.meta.kb_exists && (
                <a href={`https://github.com/eldoktor1/recon-ctl/blob/main/docs/knowledge/${targets.meta.kb}`}
                  target="_blank" rel="noreferrer" className="text-[10px] text-[var(--color-info)] hover:underline">{targets.meta.kb} ↗</a>
              )}
            </div>
          </div>
          {loading && !targets.items.length ? <Spinner /> : !targets.items.length ? (
            <Empty hint="widen recon for this class, or it isn't present on the current in-scope+paying surface">no targets for this class yet</Empty>
          ) : (
            <div className="space-y-1">
              {targets.items.map((h) => (
                <HunterRow key={h.host} h={h} cls={sel} actions={actions}
                  onTask={onTask} onDrawer={() => setDrawer(h.host)} onChanged={refetch} />
              ))}
            </div>
          )}
        </Panel>
      )}

      {drawer && <HostDrawer host={drawer} onClose={() => setDrawer(null)} onChanged={refetch} />}
      {openTask != null && <TaskConsole tid={openTask} onClose={closeTask} onChanged={() => { clearTask("drawer:hunter"); refetch(); }} />}
    </div>
  );
}

function HunterRow({ h, cls, actions, onTask, onDrawer, onChanged }:
  { h: any; cls: string; actions: any[]; onTask: (tid: number) => void; onDrawer: () => void; onChanged: () => void }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)]">
      <div className="flex items-center gap-2 px-2.5 py-1.5">
        <button onClick={() => setExpanded((v) => !v)} title={expanded ? "collapse" : "inline testing"}
          className="text-[var(--color-ink-faint)] hover:text-[var(--color-accent)]">{expanded ? "▾" : "▸"}</button>
        {h.triage_priority && <Badge color={priorityColor[h.triage_priority] || "var(--color-ink-dim)"}>{h.triage_priority}</Badge>}
        <button onClick={onDrawer} title={h.host}
          className="mono min-w-0 flex-1 truncate text-left text-xs text-[var(--color-ink)] hover:text-[var(--color-accent)]">{h.host}</button>
        <span className="hidden max-w-[180px] truncate text-[10px] text-[var(--color-ink-faint)] sm:inline">{asArr(h.tech).slice(0, 3).join(", ")}</span>
        {h.triage_true_fresh && <Badge color="var(--color-accent)">fresh</Badge>}
        {h.triage_kev_match && <Badge color="var(--color-bad)">kev</Badge>}
        <span className="mono shrink-0 text-[10px] text-[var(--color-ink-faint)]">{h.triage_score ?? ""}</span>
      </div>
      {expanded && (
        <div className="border-t border-[var(--color-border)] px-2.5 py-2">
          <div className="mb-1 text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]">test · VPN-gated</div>
          <LeadActions host={h.host} vulnClass={cls} actions={actions} onTask={onTask} onChanged={onChanged} />
        </div>
      )}
    </div>
  );
}
