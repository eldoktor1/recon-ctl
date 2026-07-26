import { useFetch } from "../hooks";
import { Panel, Stat, Badge, Empty, Spinner, Dot } from "../components/ui";
import { verdictColor, fmtNum } from "../format";

export default function Telemetry() {
  const { data: acc, error: accErr } = useFetch<any>("/api/telemetry/ai-accuracy");
  const { data: subs, error: subsErr } = useFetch<any[]>("/api/submissions");

  const vd = acc?.verdict_distribution || {};
  const outcomes = acc?.submission_outcomes || {};
  const totalV = Object.values(vd).reduce((a: number, b: any) => a + (b?.count || 0), 0);
  const bounties = (subs || []).reduce((a, s) => a + (Number(s.bounty) || 0), 0);

  return (
    <div className="fade-in space-y-5">
      <h1 className="text-lg font-semibold">Telemetry</h1>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="AI reviewed" value={fmtNum(acc?.reviewed_total)} />
        <Stat label="Verdicts" value={fmtNum(totalV)} sub="fp · needs-human · real" />
        <Stat label="Submissions" value={fmtNum(subs?.length)} />
        <Stat label="Bounties" value={`$${fmtNum(bounties)}`} color="var(--color-good)" />
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Panel title="verdict distribution">
          {!acc ? (accErr ? <Empty hint={accErr}>couldn't load AI accuracy</Empty> : <Spinner />) : (
            <div className="space-y-2">
              {Object.entries(vd).map(([k, raw]: [string, any]) => {
                const v = raw || {};
                const count = v.count || 0;
                const pct = totalV ? (count / totalV) * 100 : 0;
                return (
                  <div key={k} className="flex items-center gap-3">
                    <div className="flex w-28 items-center gap-2">
                      <Dot color={verdictColor[k] || "var(--color-ink-dim)"} />
                      <span className="text-xs text-[var(--color-ink-dim)]">{k}</span>
                    </div>
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-[var(--color-panel-2)]">
                      <div className="h-full rounded-full" style={{ width: `${pct}%`, background: verdictColor[k] || "var(--color-ink-dim)" }} />
                    </div>
                    <span className="mono w-16 text-right text-xs text-[var(--color-ink)]">{count} <span className="text-[var(--color-ink-faint)]">·{Math.round((v.avg_conf || 0) * 100)}%</span></span>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>

        <Panel title="submission outcomes">
          {!Object.keys(outcomes).length ? <Empty>no recorded outcomes yet</Empty> : (
            <div className="space-y-2">
              {Object.entries(outcomes).map(([k, v]: [string, any]) => (
                <div key={k} className="flex items-center justify-between rounded-md bg-[var(--color-panel-2)] px-3 py-2">
                  <span className="text-sm text-[var(--color-ink-dim)]">{k}</span>
                  <span className="mono text-sm text-[var(--color-ink)]">{v && typeof v === "object" ? (v.count ?? JSON.stringify(v)) : String(v)}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      <Panel title="submissions ledger" right={<Badge>{subs?.length ?? 0}</Badge>}>
        {!subs ? (subsErr ? <Empty hint={subsErr}>couldn't load submissions</Empty> : <Spinner />) : !subs.length ? <Empty>no submissions logged</Empty> : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] text-left text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">
                <th className="py-2 pr-2 font-medium">host</th>
                <th className="px-2 py-2 font-medium">class</th>
                <th className="px-2 py-2 font-medium">platform</th>
                <th className="px-2 py-2 font-medium">status</th>
                <th className="px-2 py-2 text-right font-medium">bounty</th>
                <th className="px-2 py-2 text-right font-medium">when</th>
              </tr>
            </thead>
            <tbody>
              {subs.slice(0, 100).map((s, i) => (
                <tr key={i} className="border-b border-[var(--color-border)]/50">
                  <td className="mono max-w-xs truncate py-2 pr-2 text-xs text-[var(--color-ink)]">{s.host || "—"}</td>
                  <td className="px-2 py-2 text-xs text-[var(--color-ink-dim)]">{s.class || s.vuln_class || "—"}</td>
                  <td className="px-2 py-2 text-xs text-[var(--color-ink-faint)]">{s.platform || "—"}</td>
                  <td className="px-2 py-2">{s.status && <Badge>{s.status}</Badge>}</td>
                  <td className="mono px-2 py-2 text-right text-xs text-[var(--color-good)]">{s.bounty ? `$${s.bounty}` : "—"}</td>
                  <td className="px-2 py-2 text-right text-[11px] text-[var(--color-ink-faint)]">{(s.submitted_at || s.date || s.created_at || "").slice(0, 10)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
