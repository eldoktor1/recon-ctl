import { useFetch } from "../hooks";
import { Panel, Stat, Badge, Empty, Spinner } from "../components/ui";
import { fmtNum } from "../format";

export default function Digest() {
  const { data } = useFetch<any>("/api/digest");
  if (!data) return <Spinner />;
  if (data.error) return <Empty>{data.error}</Empty>;

  // fields can be counts OR lists-of-objects depending on the pipeline version
  const num = (x: any): number => (Array.isArray(x) ? x.length : typeof x === "number" ? x : x ? 1 : 0);
  const prim = (v: any): string => (v == null ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v));

  const halts: any[] = Array.isArray(data.halted_now) ? data.halted_now : data.halted_now ? [data.halted_now] : [];
  const spend = Number(data.api_spend_usd || 0);
  const ceil = Number(data.spend_ceiling_usd || 0);
  const vol = data.per_program_volume || {};
  const dismiss = data.dismiss_reasons || {};
  const yieldAudit = data.yield_audit || {};
  const states = data.state_distribution || {};

  return (
    <div className="fade-in space-y-5">
      <div className="flex items-baseline justify-between">
        <h1 className="text-lg font-semibold">Digest</h1>
        <span className="text-xs text-[var(--color-ink-faint)]">{data.day} · ops audit</span>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Halted lanes" value={halts.length} color={halts.length ? "var(--color-bad)" : "var(--color-good)"} />
        <Stat label="Active failures" value={num(data.failures_active)} color={num(data.failures_active) ? "var(--color-warn)" : undefined} />
        <Stat label="LLM spend" value={`$${spend.toFixed(2)}`} sub={ceil ? `of $${ceil} ceiling` : undefined}
          color={ceil && spend / ceil > 0.8 ? "var(--color-warn)" : "var(--color-accent)"} />
        <Stat label="Awaiting submit" value={num(data.review_queue_awaiting_submit)} color="var(--color-info)" />
      </div>

      {halts.length > 0 && (
        <Panel title="⚠ halted now">
          <div className="space-y-1">
            {halts.map((h, i) => <div key={i} className="mono text-xs text-[var(--color-bad)]">{typeof h === "string" ? h : JSON.stringify(h)}</div>)}
          </div>
        </Panel>
      )}

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Panel title="per-program request volume">
          {!Object.keys(vol).length ? <Empty>no volume today</Empty> : (
            <div className="max-h-72 space-y-1 overflow-auto">
              {Object.entries(vol).sort((a: any, b: any) => num(b[1]) - num(a[1])).map(([k, v]: any) => (
                <div key={k} className="flex items-center justify-between text-xs">
                  <span className="truncate text-[var(--color-ink-dim)]">{k}</span>
                  <span className="mono text-[var(--color-ink)]">{typeof v === "number" ? fmtNum(v) : prim(v)}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="lane yield audit">
          {!Object.keys(yieldAudit).length ? <Empty>no yield data</Empty> : (
            <div className="max-h-72 space-y-1 overflow-auto">
              {Object.entries(yieldAudit).map(([k, v]: any) => {
                const zero = v === 0 || v?.silent_zero || v?.status === "silent-zero";
                return (
                  <div key={k} className="flex items-center justify-between text-xs">
                    <span className="truncate text-[var(--color-ink-dim)]">{k}</span>
                    <Badge color={zero ? "var(--color-warn)" : "var(--color-good)"}>{typeof v === "object" ? JSON.stringify(v).slice(0, 30) : String(v)}</Badge>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>

        <Panel title="dismiss reasons">
          {!Object.keys(dismiss).length ? <Empty>none</Empty> : (
            <div className="space-y-1">
              {Object.entries(dismiss).sort((a: any, b: any) => num(b[1]) - num(a[1])).map(([k, v]: any) => (
                <div key={k} className="flex items-center justify-between text-xs">
                  <span className="truncate text-[var(--color-ink-dim)]">{k}</span>
                  <span className="mono text-[var(--color-ink)]">{prim(v)}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="finding states">
          <div className="space-y-1">
            {Object.entries(states).map(([k, v]: any) => (
              <div key={k} className="flex items-center justify-between text-xs">
                <span className="text-[var(--color-ink-dim)]">{k}</span>
                <span className="mono text-[var(--color-ink)]">{prim(v)}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}
