import { useState } from "react";
import { useFetch } from "../hooks";
import { Panel, Stat, Badge, Empty, Spinner } from "../components/ui";
import { HostDrawer } from "../components/HostDrawer";
import { fmtAgo } from "../format";

interface Note { host: string; note: string; source?: string; program?: string; created_at?: string; root_domain?: string }
interface NotesResp { stats: { total: number; hosts: number; by_source: Record<string, number> }; items: Note[] }
interface Ignore { host: string; reason?: string; added_at?: string; expires_at?: string }

export default function Notes() {
  const [q, setQ] = useState("");
  const [host, setHost] = useState<string | null>(null);
  const [tab, setTab] = useState<"notes" | "benched">("notes");
  const { data } = useFetch<NotesResp>(`/api/notes${q ? `?q=${encodeURIComponent(q)}` : ""}`, [q]);
  const { data: ignores } = useFetch<Ignore[]>("/api/ignores");

  return (
    <div className="fade-in space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="text-lg font-semibold">Notes &amp; worked-knowledge</h1>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Notes" value={data?.stats.total ?? "—"} />
        <Stat label="Hosts noted" value={data?.stats.hosts ?? "—"} />
        <Stat label="Benched now" value={ignores?.length ?? "—"} color={ignores?.length ? "var(--color-warn)" : undefined} sub="7-day TTL" />
        <Stat label="Manual notes" value={data?.stats.by_source?.manual ?? "—"} color="var(--color-accent)" />
      </div>

      <div className="flex items-center gap-2">
        <button onClick={() => setTab("notes")} className={`rounded-md px-3 py-1.5 text-xs ${tab === "notes" ? "bg-[var(--color-accent)]/12 text-[var(--color-accent)]" : "text-[var(--color-ink-dim)] hover:text-[var(--color-ink)]"}`}>notes ({data?.stats.total ?? 0})</button>
        <button onClick={() => setTab("benched")} className={`rounded-md px-3 py-1.5 text-xs ${tab === "benched" ? "bg-[var(--color-accent)]/12 text-[var(--color-accent)]" : "text-[var(--color-ink-dim)] hover:text-[var(--color-ink)]"}`}>benched ({ignores?.length ?? 0})</button>
        {tab === "notes" && (
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="search notes / hosts…"
            className="mono ml-auto w-64 rounded-md border border-[var(--color-border-bright)] bg-[var(--color-panel)] px-3 py-1.5 text-xs outline-none focus:border-[var(--color-accent)]" />
        )}
      </div>

      {tab === "notes" ? (
        <Panel className="!p-0">
          {!data ? <Spinner /> : !data.items.length ? <Empty>no notes match</Empty> : (
            <div className="max-h-[64vh] overflow-auto">
              {data.items.map((n, i) => (
                <div key={i} onClick={() => setHost(n.host)}
                  className="cursor-pointer border-b border-[var(--color-border)]/50 px-4 py-2.5 hover:bg-[var(--color-panel-2)]">
                  <div className="flex items-center gap-2">
                    <span className="mono truncate text-xs text-[var(--color-ink)]" title={n.host}>{n.host}</span>
                    {n.source && <Badge>{n.source}</Badge>}
                    {n.program && <span className="text-[10px] text-[var(--color-ink-faint)]">{n.program}</span>}
                    <span className="ml-auto text-[10px] text-[var(--color-ink-faint)]">{n.created_at?.slice(0, 10) || fmtAgo(0)}</span>
                  </div>
                  <div className="mt-1 text-xs text-[var(--color-ink-dim)]">{n.note}</div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      ) : (
        <Panel className="!p-0">
          {!ignores ? <Spinner /> : !ignores.length ? <Empty>nothing benched</Empty> : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--color-border)] text-left text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">
                  <th className="px-4 py-2 font-medium">host</th>
                  <th className="px-2 py-2 font-medium">reason</th>
                  <th className="px-4 py-2 text-right font-medium">expires</th>
                </tr>
              </thead>
              <tbody>
                {ignores.map((g, i) => (
                  <tr key={i} onClick={() => setHost(g.host)} className="cursor-pointer border-b border-[var(--color-border)]/50 hover:bg-[var(--color-panel-2)]">
                    <td className="mono max-w-xs truncate px-4 py-2 text-xs text-[var(--color-ink)]">{g.host}</td>
                    <td className="px-2 py-2 text-xs text-[var(--color-ink-dim)]">{g.reason || "—"}</td>
                    <td className="px-4 py-2 text-right text-[11px] text-[var(--color-ink-faint)]">{g.expires_at?.slice(0, 10) || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      )}

      {host && <HostDrawer host={host} onClose={() => setHost(null)} />}
    </div>
  );
}
