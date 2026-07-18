import { useEffect } from "react";
import { useFetch } from "../hooks";
import type { Overview } from "../api";
import { Panel, Stat, Badge, Dot, Empty, Spinner } from "../components/ui";
import { fmtDuration, fmtNum, stateColor, verdictColor, priorityColor } from "../format";

const STATE_ORDER = ["confirmed", "reported", "submitted", "verifying", "scored", "discovered", "dismissed", "lead_exhausted"];

export default function CommandCenter() {
  const { data, loading, refetch } = useFetch<Overview>("/api/overview");

  useEffect(() => {
    const t = setInterval(refetch, 10000);
    return () => clearInterval(t);
  }, [refetch]);

  if (!data && loading) return <Spinner />;
  if (!data) return <Empty>backend unreachable</Empty>;

  const fbs = data.findings_by_state || {};
  const totalFindings = Object.values(fbs).reduce((a, b) => a + b, 0);
  const actionable = (fbs.confirmed || 0) + (fbs.reported || 0);
  const d = data.daemon;

  return (
    <div className="fade-in space-y-5">
      <div className="flex items-baseline justify-between">
        <h1 className="text-lg font-semibold">Command Center</h1>
        <span className="text-xs text-[var(--color-ink-faint)]">auto-refresh · 10s</span>
      </div>

      {/* headline stats */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-6">
        <Stat label="Actionable" value={actionable} color="var(--color-good)"
          sub={`${fbs.confirmed || 0} confirmed · ${fbs.reported || 0} reported`} />
        <Stat label="Submitted" value={fbs.submitted || 0} color="var(--color-accent)" />
        <Stat label="Findings" value={fmtNum(totalFindings)} sub={`${fbs.dismissed || 0} dismissed`} />
        <Stat label="Daemon" value={d.alive ? "UP" : "DOWN"}
          color={d.alive ? "var(--color-good)" : "var(--color-bad)"}
          sub={d.alive ? `${fmtDuration(d.uptime_sec)} · ${d.lane_procs} lanes` : "stopped"} />
        <Stat label="Queue" value={fmtNum(data.queue?.inbox ?? 0)} sub={`${data.queue?.done ?? 0} done`} />
        <Stat label="ES docs" value={fmtNum(data.es?.docs)} color="var(--color-info)"
          sub={data.es?.reachable ? data.es.status : "offline"} />
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        {/* findings by state */}
        <Panel title="Findings by state" className="lg:col-span-1">
          <div className="space-y-2">
            {STATE_ORDER.filter((s) => fbs[s]).map((s) => {
              const n = fbs[s];
              const pct = totalFindings ? (n / totalFindings) * 100 : 0;
              return (
                <div key={s} className="flex items-center gap-3">
                  <div className="flex w-32 items-center gap-2">
                    <Dot color={stateColor[s] || "var(--color-ink-faint)"} />
                    <span className="text-xs text-[var(--color-ink-dim)]">{s}</span>
                  </div>
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-[var(--color-panel-2)]">
                    <div className="h-full rounded-full" style={{ width: `${pct}%`, background: stateColor[s] || "var(--color-ink-faint)" }} />
                  </div>
                  <span className="mono w-10 text-right text-xs text-[var(--color-ink)]">{n}</span>
                </div>
              );
            })}
          </div>
        </Panel>

        {/* system health */}
        <Panel title="System" className="lg:col-span-2">
          <div className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm md:grid-cols-3">
            <HealthRow label="VPN / egress" ok={data.vpn.up}
              value={data.vpn.up ? "Mullvad up" : "DOWN"} detail={data.vpn.reason || undefined} />
            <HealthRow label="Elasticsearch" ok={!!data.es.reachable}
              value={data.es.reachable ? `${data.es.status}` : "offline"}
              detail={data.es.reachable ? `${data.es.active_shards} shards` : data.es.error} />
            <HealthRow label="Daemon" ok={d.alive}
              value={d.alive ? `pid ${d.pid}` : "stopped"}
              detail={d.alive ? `${d.lane_procs} lane procs` : undefined} />
            <HealthRow label="Maintenance" ok={!d.maintenance} value={d.maintenance ? "ON" : "off"} invert />
            <HealthRow label="Keepalive" ok={!d.keepalive_tripped} value={d.keepalive_tripped ? "TRIPPED" : "ok"} invert />
            <HealthRow label="Killswitches" ok={data.killswitches.length === 0}
              value={data.killswitches.length ? `${data.killswitches.length} active` : "none"} invert
              detail={data.killswitches.map((k) => k.lane).join(", ") || undefined} />
          </div>
        </Panel>
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        {/* recent confirmed */}
        <Panel title="Recent confirmed" right={<Badge color="var(--color-good)">{data.recent_confirmed.length}</Badge>}>
          {data.recent_confirmed.length === 0 ? (
            <Empty>nothing confirmed yet</Empty>
          ) : (
            <div className="space-y-1">
              {data.recent_confirmed.map((f) => (
                <div key={f.id} className="flex items-center gap-2 rounded-md px-2 py-1.5 hover:bg-[var(--color-panel-2)]">
                  <Badge color={stateColor[f.state]}>{f.state}</Badge>
                  <span className="mono truncate text-xs text-[var(--color-ink)]" title={f.host}>{f.host}</span>
                  {f.vuln_class && <span className="text-xs text-[var(--color-ink-faint)]">{f.vuln_class}</span>}
                  <div className="ml-auto flex items-center gap-2">
                    {f.ai_verdict && <Badge color={verdictColor[f.ai_verdict] || "var(--color-ink-dim)"}>{f.ai_verdict}</Badge>}
                    {f.priority && <Badge color={priorityColor[f.priority]}>{f.priority}</Badge>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        {/* tonight's briefing */}
        <Panel title="Tonight" right={data.tonight?.date ? <Badge>{data.tonight.date}</Badge> : undefined}>
          {!data.tonight ? (
            <Empty>no briefing generated yet</Empty>
          ) : (
            <div className="mono max-h-72 space-y-0.5 overflow-auto text-[12px] leading-relaxed text-[var(--color-ink-dim)]">
              {data.tonight.preview.map((line, i) => (
                <div key={i} className={line.startsWith("#") ? "font-semibold text-[var(--color-ink)]" : ""}>{line}</div>
              ))}
              {data.tonight.line_count > data.tonight.preview.length && (
                <div className="pt-1 text-[var(--color-ink-faint)]">
                  … +{data.tonight.line_count - data.tonight.preview.length} more lines
                </div>
              )}
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}

function HealthRow({ label, ok, value, detail, invert }:
  { label: string; ok: boolean; value: string; detail?: string; invert?: boolean }) {
  const color = ok ? "var(--color-good)" : invert ? "var(--color-warn)" : "var(--color-bad)";
  return (
    <div>
      <div className="text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">{label}</div>
      <div className="mt-1 flex items-center gap-2">
        <Dot color={color} pulse={!ok && !invert} />
        <span className="mono text-sm" style={{ color }}>{value}</span>
      </div>
      {detail && <div className="mt-0.5 truncate text-[11px] text-[var(--color-ink-faint)]" title={detail}>{detail}</div>}
    </div>
  );
}
