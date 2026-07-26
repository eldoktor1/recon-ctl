import { useState } from "react";
import { useFetch } from "../hooks";
import { Panel, Badge, Empty, Spinner } from "../components/ui";
import { Drawer } from "../components/controls";

export default function Reports() {
  const { data, error } = useFetch<any[]>("/api/reports");
  const [sel, setSel] = useState<any | null>(null);

  return (
    <div className="fade-in space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="text-lg font-semibold">Reports</h1>
        <span className="text-xs text-[var(--color-ink-faint)]">{data?.length ?? "—"} in review queue</span>
      </div>

      <Panel className="!p-0">
        {!data ? (error ? <Empty hint={error}>couldn't load reports</Empty> : <Spinner />) : !data.length ? <Empty>report review queue is empty</Empty> : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] text-left text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">
                <th className="px-4 py-2 font-medium">id</th>
                <th className="px-2 py-2 font-medium">host</th>
                <th className="px-2 py-2 font-medium">program</th>
                <th className="px-2 py-2 font-medium">platform</th>
                <th className="px-4 py-2 text-right font-medium">title</th>
              </tr>
            </thead>
            <tbody>
              {data.map((r, i) => (
                <tr key={i} onClick={() => setSel(r)} className="cursor-pointer border-b border-[var(--color-border)]/50 hover:bg-[var(--color-panel-2)]">
                  <td className="mono px-4 py-2 text-xs text-[var(--color-ink-faint)]">#{r.finding_id ?? r.id ?? i}</td>
                  <td className="mono max-w-xs truncate px-2 py-2 text-xs text-[var(--color-ink)]">{r.host || "—"}</td>
                  <td className="px-2 py-2 text-xs text-[var(--color-ink-dim)]">{r.program || "—"}</td>
                  <td className="px-2 py-2 text-xs text-[var(--color-ink-faint)]">{r.platform || "—"}</td>
                  <td className="max-w-sm truncate px-4 py-2 text-right text-xs text-[var(--color-ink-dim)]">{r.title || r.vuln_class || r.signal_class || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      {sel && (
        <Drawer open onClose={() => setSel(null)} width={680}
          title={<span className="mono text-sm text-[var(--color-ink)]">{sel.host || `report #${sel.finding_id}`}</span>}>
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2">
              {sel.program && <Badge>{sel.program}</Badge>}
              {sel.platform && <Badge color="var(--color-info)">{sel.platform}</Badge>}
              {sel.severity && <Badge color="var(--color-warn)">{sel.severity}</Badge>}
            </div>
            <pre className="mono max-h-[70vh] overflow-auto whitespace-pre-wrap rounded bg-[var(--color-bg)] p-4 text-[11px] text-[var(--color-ink-dim)]">
              {JSON.stringify(sel, null, 2)}
            </pre>
          </div>
        </Drawer>
      )}
    </div>
  );
}
