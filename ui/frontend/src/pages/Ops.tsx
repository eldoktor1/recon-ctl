import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { useFetch, useLiveStatus } from "../hooks";
import { Panel, Stat, Badge, Empty, Spinner, Dot } from "../components/ui";
import { Btn, useToast, ConfirmModal } from "../components/controls";
import { fmtDuration } from "../format";

const RATE_PROFILES = ["light", "easy", "medium", "full", "reset"];

export default function Ops() {
  const { status } = useLiveStatus();
  const toast = useToast();
  const [confirm, setConfirm] = useState<null | { title: string; body: string; run: () => Promise<any> }>(null);
  const [newKill, setNewKill] = useState("");
  const d = status?.daemon;
  const ks = status?.killswitches || [];

  const act = (title: string, body: string, run: () => Promise<any>) => setConfirm({ title, body, run });
  const doAction = async () => {
    if (!confirm) return;
    try { const r = await confirm.run(); toast(r?.ok === false ? "err" : "ok", r?.ok === false ? (r.error || "failed") : (r?.result || "done")); }
    catch (e: any) { toast("err", e.message); }
    finally { setConfirm(null); }
  };

  return (
    <div className="fade-in space-y-5">
      <h1 className="text-lg font-semibold">Daemon / Ops</h1>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Daemon" value={d?.alive ? "UP" : "DOWN"} color={d?.alive ? "var(--color-good)" : "var(--color-bad)"}
          sub={d?.alive ? `pid ${d.pid}` : "stopped"} />
        <Stat label="Uptime" value={fmtDuration(d?.uptime_sec)} sub={`${d?.lane_procs ?? 0} lane procs`} />
        <Stat label="Maintenance" value={d?.maintenance ? "ON" : "off"} color={d?.maintenance ? "var(--color-warn)" : undefined} />
        <Stat label="Killswitches" value={ks.length} color={ks.length ? "var(--color-warn)" : undefined} />
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        {/* controls */}
        <Panel title="controls">
          <div className="space-y-4">
            <div>
              <div className="mb-2 text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">maintenance mode</div>
              <div className="flex gap-2">
                <Btn size="sm" variant={d?.maintenance ? "ghost" : "primary"}
                  onClick={() => act("Maintenance OFF?", "Resumes normal daemon operation.", () => api.action("/api/daemon/maintenance", { mode: "off" }))}>turn off</Btn>
                <Btn size="sm" variant={d?.maintenance ? "primary" : "ghost"}
                  onClick={() => act("Maintenance ON?", "Pauses the daemon's scanning at the next cycle.", () => api.action("/api/daemon/maintenance", { mode: "on" }))}>turn on</Btn>
              </div>
            </div>
            <div>
              <div className="mb-2 text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">rate profile</div>
              <div className="flex flex-wrap gap-2">
                {RATE_PROFILES.map((p) => (
                  <Btn key={p} size="sm" onClick={() => act(`Set rate: ${p}?`, `Applies the "${p}" throttle profile to scanning.`, () => api.action("/api/daemon/rate", { profile: p }))}>{p}</Btn>
                ))}
              </div>
            </div>
          </div>
        </Panel>

        {/* killswitches */}
        <Panel title="killswitches" right={<Badge color={ks.length ? "var(--color-warn)" : "var(--color-ink-dim)"}>{ks.length} active</Badge>}>
          <div className="space-y-2">
            {ks.length === 0 && <div className="text-xs text-[var(--color-ink-faint)]">no lanes killed</div>}
            {ks.map((k: any) => (
              <div key={k.lane} className="flex items-center gap-2">
                <Dot color="var(--color-bad)" />
                <span className="mono flex-1 text-xs text-[var(--color-ink)]">{k.lane}</span>
                <Btn size="sm" onClick={() => act(`Re-enable ${k.lane}?`, "Removes the killswitch; the lane resumes next cycle.", () => api.action(`/api/killswitch/${k.lane.replace(/^v2_/, "")}`, { on: false }))}>enable</Btn>
              </div>
            ))}
            <div className="flex items-center gap-2 border-t border-[var(--color-border)] pt-3">
              <input value={newKill} onChange={(e) => setNewKill(e.target.value)} placeholder="lane name (e.g. kr)"
                className="mono flex-1 rounded border border-[var(--color-border-bright)] bg-[var(--color-bg)] px-2 py-1 text-xs" />
              <Btn size="sm" variant="danger" disabled={!newKill.trim()}
                onClick={() => act(`Kill lane ${newKill}?`, `Creates state/kill/v2_${newKill.trim()} — disables that lane.`, () => api.action(`/api/killswitch/${newKill.trim()}`, { on: true }).then((r) => { setNewKill(""); return r; }))}>kill</Btn>
            </div>
          </div>
        </Panel>
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <SelfAudit />
        <LogTail />
      </div>

      <ConfirmModal open={!!confirm} title={confirm?.title || ""} body={confirm?.body} onConfirm={doAction} onCancel={() => setConfirm(null)} />
    </div>
  );
}

function SelfAudit() {
  const { data } = useFetch<any>("/api/selfaudit");
  return (
    <Panel title="self-audit" right={data?._age_sec != null ? <Badge>{Math.round(data._age_sec / 3600)}h ago</Badge> : undefined}>
      {!data ? <Spinner /> : data.error ? <Empty>{data.error}</Empty> : (
        <pre className="mono max-h-72 overflow-auto whitespace-pre-wrap text-[11px] text-[var(--color-ink-dim)]">
          {JSON.stringify(data.summary || data, null, 2).slice(0, 3000)}
        </pre>
      )}
    </Panel>
  );
}

function LogTail() {
  const [lines, setLines] = useState<string[]>([]);
  const boxRef = useRef<HTMLDivElement>(null);
  const load = async () => { try { const r = await api.get<{ lines: string[] }>("/api/logs?tail=120"); setLines(r.lines); } catch {} };
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);
  useEffect(() => { boxRef.current?.scrollTo(0, boxRef.current.scrollHeight); }, [lines]);
  return (
    <Panel title="daemon log" right={<span className="text-[10px] text-[var(--color-ink-faint)]">5s</span>}>
      <div ref={boxRef} className="mono max-h-72 overflow-auto whitespace-pre-wrap text-[11px] leading-relaxed text-[var(--color-ink-dim)]">
        {lines.length === 0 ? <Empty>no log lines</Empty> : lines.map((l, i) => <div key={i}>{l}</div>)}
      </div>
    </Panel>
  );
}
