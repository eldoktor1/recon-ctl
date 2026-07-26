import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useFetch } from "../hooks";
import { Panel, Stat, Badge, Empty, Spinner } from "../components/ui";
import { Btn, useToast } from "../components/controls";
import { HostDrawer } from "../components/HostDrawer";

interface Note { host: string; note: string; source?: string; program?: string; created_at?: string; root_domain?: string }
interface NotesResp { stats: { total: number; hosts: number; by_source: Record<string, number> }; items: Note[] }
interface Ignore { host: string; reason?: string; added_at?: string; expires_at?: string }

export default function Notes() {
  const [sp] = useSearchParams();
  const [q, setQ] = useState(sp.get("q") || "");
  const [host, setHost] = useState<string | null>(null);
  const [tab, setTab] = useState<"notes" | "benched">("notes");
  const [adding, setAdding] = useState(false);
  const { data, refetch } = useFetch<NotesResp>(`/api/notes${q ? `?q=${encodeURIComponent(q)}` : ""}`, [q]);
  const { data: ignores } = useFetch<Ignore[]>("/api/ignores");

  return (
    <div className="fade-in space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="text-lg font-semibold">Notes &amp; worked-knowledge</h1>
        <Btn variant="primary" size="sm" onClick={() => setAdding(true)}>+ add note</Btn>
      </div>
      {adding && <AddNote onClose={() => setAdding(false)} onSaved={() => { setAdding(false); refetch(); }} initialHost={sp.get("q") || ""} />}

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
                    <span className="ml-auto text-[10px] text-[var(--color-ink-faint)]">{n.created_at?.slice(0, 10) || "—"}</span>
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

function AddNote({ onClose, onSaved, initialHost }: { onClose: () => void; onSaved: () => void; initialHost: string }) {
  const [host, setHost] = useState(initialHost);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const toast = useToast();

  const save = async () => {
    if (!host.trim() || !text.trim()) return;
    setBusy(true);
    try {
      const r = await api.action<any>(`/api/hosts/${encodeURIComponent(host.trim())}/note`, { text: text.trim() });
      if (r?.ok === false) { toast("err", r.error || "failed"); setBusy(false); return; }
      toast("ok", `noted ${host.trim()}`);
      onSaved();
    } catch (e: any) { toast("err", e.message); setBusy(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center p-4 pt-[14vh]" onClick={onClose}>
      <div className="absolute inset-0 bg-black/60" />
      <div className="relative w-[min(92vw,520px)] rounded-xl border border-[var(--color-border-bright)] bg-[var(--color-panel)] p-6 fade-in" onClick={(e) => e.stopPropagation()}>
        <h3 className="mb-4 text-base font-semibold text-[var(--color-ink)]">Add note</h3>
        <label className="mb-1 block text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">host</label>
        <input value={host} onChange={(e) => setHost(e.target.value)} autoFocus placeholder="host.example.com"
          className="mono mb-3 w-full rounded-md border border-[var(--color-border-bright)] bg-[var(--color-bg)] px-3 py-2 text-sm text-[var(--color-ink)] outline-none focus:border-[var(--color-accent)]" />
        <label className="mb-1 block text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">note</label>
        <textarea value={text} onChange={(e) => setText(e.target.value)} rows={4}
          onKeyDown={(e) => { if ((e.metaKey || e.ctrlKey) && e.key === "Enter") save(); }}
          placeholder="worked-knowledge — what you found / why it's dead / next angle…"
          className="w-full resize-y rounded-md border border-[var(--color-border-bright)] bg-[var(--color-bg)] px-3 py-2 text-sm text-[var(--color-ink)] outline-none focus:border-[var(--color-accent)]" />
        <p className="mt-1.5 text-[11px] text-[var(--color-ink-faint)]">permanent note (source: manual) · mirrors to ES · ⌘↵ to save</p>
        <div className="mt-4 flex justify-end gap-2">
          <Btn size="sm" onClick={onClose}>cancel</Btn>
          <Btn size="sm" variant="primary" disabled={busy || !host.trim() || !text.trim()} onClick={save}>{busy ? "saving…" : "save note"}</Btn>
        </div>
      </div>
    </div>
  );
}
