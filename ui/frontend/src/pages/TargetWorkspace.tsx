import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useFetch } from "../hooks";
import { api } from "../api";
import { Panel, Badge, Empty, Spinner } from "../components/ui";
import { Btn } from "../components/controls";
import { LeadActions, useHostActions } from "../components/LeadActions";
import { AutoNote } from "../components/AutoNote";
import { TaskConsole } from "../components/TaskConsole";
import { getTask, setTask, clearTask } from "../taskStore";
import { priorityColor, classColor, stateColor, verdictColor, asArr } from "../format";

// A focused per-TARGET cockpit: one host, all the test tools, its findings, and an exhaustion
// note-log — where you work a surfaced lead until every angle is exhausted. Reached from the
// worklist (🔬 exhaust) when verify turns something up.
export default function TargetWorkspace() {
  const { host = "" } = useParams();
  const nav = useNavigate();
  const enc = encodeURIComponent(host);
  const { data: asset, refetch: refetchAsset } = useFetch<any>(host ? `/api/assets/${enc}` : null, [host]);
  const { data: findings, refetch: refetchF } = useFetch<{ items: any[] }>(host ? `/api/findings?q=${enc}&limit=50` : null, [host]);
  const actions = useHostActions();
  const [openTask, setOpenTask] = useState<number | null>(() => getTask(`drawer:target:${host}`));
  const onTask = (tid: number) => { setOpenTask(tid); setTask(`drawer:target:${host}`, tid); };
  const closeTask = () => { setOpenTask(null); clearTask(`drawer:target:${host}`); };
  const refresh = () => { refetchAsset(); refetchF(); };

  return (
    <div className="fade-in space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Btn size="sm" onClick={() => nav(-1)}>← back</Btn>
        <h1 className="mono truncate text-lg font-semibold text-[var(--color-ink)]">{host}</h1>
        {asset?.triage_priority && <Badge color={priorityColor[asset.triage_priority]} filled>{asset.triage_priority}</Badge>}
        {asset?.triage_program && <Badge>{asset.triage_program}</Badge>}
        <span className="text-xs text-[var(--color-ink-faint)]">exhaust this lead — test every angle, note as you go</span>
      </div>

      <Panel title="target">
        {!asset ? <Spinner /> : (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <div className="space-y-1">
              <Row k="score" v={asset.triage_score} />
              <Row k="tech" v={asArr(asset.tech).join(", ")} />
              <Row k="classes" v={asArr(asset.triage_classes).join(", ")} />
              <Row k="title" v={asset.title} />
            </div>
            <div className="flex flex-wrap content-start gap-1">
              {asset.triage_pays && <Badge color="var(--color-good)">pays</Badge>}
              {asset.triage_true_fresh && <Badge color="var(--color-accent)">fresh</Badge>}
              {asset.triage_kev_match && <Badge color="var(--color-bad)">kev</Badge>}
              {asset.takeover_confirmed && <Badge color="var(--color-bad)">takeover</Badge>}
              {asset.js_secret_hit && <Badge color="var(--color-warn)">secret</Badge>}
              {!!asset.host_notes_count && <Badge>📝{asset.host_notes_count}</Badge>}
            </div>
          </div>
        )}
      </Panel>

      <Panel title="test · VPN-gated" right={<span className="text-[10px] text-[var(--color-ink-faint)]">confirm each class' SAFE primitive; chain until exhausted</span>}>
        <LeadActions host={host} vulnClass={asArr(asset?.triage_classes)[0] || null} actions={actions} onTask={onTask} onChanged={refresh} />
      </Panel>

      <Panel title="findings on this target" right={<Badge color="var(--color-accent)">{findings?.items?.length ?? 0}</Badge>}>
        {!findings ? <Spinner /> : !findings.items.length ? <Empty>no findings yet — keep testing</Empty> : (
          <div className="space-y-1">
            {findings.items.map((f) => (
              <div key={f.id} className="flex items-center gap-2 rounded border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2.5 py-1.5">
                <Badge color={stateColor[f.state] || "var(--color-ink-dim)"} filled>{f.state}</Badge>
                {f.vuln_class && <Badge color={classColor[f.vuln_class] || "var(--color-ink-dim)"}>{f.vuln_class}</Badge>}
                {f.ai_verdict && <Badge color={verdictColor[f.ai_verdict] || "var(--color-ink-dim)"}>{f.ai_verdict}</Badge>}
                <span className="mono min-w-0 flex-1 truncate text-[11px] text-[var(--color-ink-dim)]" title={f.url || f.host}>{f.url || f.host}</span>
                {f.score != null && <span className="mono text-[10px] text-[var(--color-ink-faint)]">{f.score}</span>}
              </div>
            ))}
          </div>
        )}
      </Panel>

      <Panel title="notes · exhaustion log">
        <AutoNote title="host note" storeKey={`autonote:host:${host}`}
          hint="log what you tried + the outcome; auto-draft where this target stands"
          spawn={() => api.action<any>(`/api/hosts/${enc}/autonote`)}
          onSave={async (text) => { const r = await api.action(`/api/hosts/${enc}/note`, { text }); refresh(); return r; }} />
      </Panel>

      {openTask != null && <TaskConsole tid={openTask} onClose={closeTask} onChanged={() => { clearTask(`drawer:target:${host}`); refresh(); }} />}
    </div>
  );
}

function Row({ k, v }: { k: string; v?: any }) {
  if (v == null || v === "") return null;
  return (
    <div className="flex gap-3">
      <span className="w-20 shrink-0 text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]">{k}</span>
      <span className="mono flex-1 break-all text-[11px] text-[var(--color-ink-dim)]">{v}</span>
    </div>
  );
}
