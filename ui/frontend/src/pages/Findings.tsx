import { useEffect, useState } from "react";
import { api, type Finding } from "../api";
import { useFetch } from "../hooks";
import { Panel, Badge, Empty, Spinner } from "../components/ui";
import { Drawer, Btn, useToast, ConfirmModal } from "../components/controls";
import { stateColor, verdictColor, priorityColor, fmtAgo } from "../format";

interface FindingList { total: number; items: Finding[]; limit: number; offset: number }
interface Facets { state: string[]; program: string[]; vuln_class: string[]; ai_verdict: string[] }

const RESOLUTIONS = ["accepted", "dup", "na", "info"] as const;

export default function Findings() {
  const [filters, setFilters] = useState<Record<string, string>>({});
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<number | null>(null);
  const { data: facets } = useFetch<Facets>("/api/findings/facets");

  const qs = new URLSearchParams({ limit: "60", offset: String(offset) });
  Object.entries(filters).forEach(([k, v]) => v && qs.set(k, v));
  if (q) qs.set("q", q);
  const { data, loading, refetch } = useFetch<FindingList>(`/api/findings?${qs}`, [offset, JSON.stringify(filters), q]);

  const setF = (k: string, v: string) => { setOffset(0); setFilters((f) => ({ ...f, [k]: v })); };

  return (
    <div className="fade-in space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="text-lg font-semibold">Findings</h1>
        <span className="text-xs text-[var(--color-ink-faint)]">{data?.total ?? "—"} total</span>
      </div>

      {/* filter bar */}
      <div className="flex flex-wrap items-center gap-2">
        <input
          value={q} onChange={(e) => { setOffset(0); setQ(e.target.value); }}
          placeholder="search host / url / program…"
          className="mono w-64 rounded-md border border-[var(--color-border-bright)] bg-[var(--color-panel)] px-3 py-1.5 text-xs outline-none focus:border-[var(--color-accent)]"
        />
        <Select label="state" value={filters.state} opts={facets?.state} onChange={(v) => setF("state", v)} />
        <Select label="class" value={filters.vuln_class} opts={facets?.vuln_class} onChange={(v) => setF("vuln_class", v)} />
        <Select label="verdict" value={filters.verdict} opts={facets?.ai_verdict} onChange={(v) => setF("verdict", v)} />
        <Select label="program" value={filters.program} opts={facets?.program} onChange={(v) => setF("program", v)} />
        {(Object.values(filters).some(Boolean) || q) && (
          <Btn size="sm" onClick={() => { setFilters({}); setQ(""); setOffset(0); }}>clear</Btn>
        )}
      </div>

      <Panel className="!p-0">
        {loading && !data ? <Spinner /> : !data?.items.length ? <Empty>no findings match</Empty> : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] text-left text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">
                <th className="px-4 py-2 font-medium">state</th>
                <th className="px-2 py-2 font-medium">host</th>
                <th className="px-2 py-2 font-medium">class</th>
                <th className="px-2 py-2 font-medium">verdict</th>
                <th className="px-2 py-2 font-medium">score</th>
                <th className="px-2 py-2 font-medium">program</th>
                <th className="px-4 py-2 text-right font-medium">updated</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((f) => (
                <tr key={f.id} onClick={() => setSelected(f.id)}
                  className="cursor-pointer border-b border-[var(--color-border)]/50 hover:bg-[var(--color-panel-2)]">
                  <td className="px-4 py-2"><Badge color={stateColor[f.state]}>{f.state}</Badge></td>
                  <td className="mono max-w-xs truncate px-2 py-2 text-xs text-[var(--color-ink)]" title={f.host}>{f.host}</td>
                  <td className="px-2 py-2 text-xs text-[var(--color-ink-dim)]">{f.vuln_class || "—"}</td>
                  <td className="px-2 py-2">{f.ai_verdict && <Badge color={verdictColor[f.ai_verdict] || "var(--color-ink-dim)"}>{f.ai_verdict}</Badge>}</td>
                  <td className="mono px-2 py-2 text-xs">{f.score ?? "—"}</td>
                  <td className="max-w-[140px] truncate px-2 py-2 text-xs text-[var(--color-ink-faint)]" title={f.program}>{f.program || "—"}</td>
                  <td className="px-4 py-2 text-right text-xs text-[var(--color-ink-faint)]">{fmtAgo(f.state_changed_at || f.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      {data && data.total > 60 && (
        <div className="flex items-center justify-center gap-3">
          <Btn size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 60))}>← prev</Btn>
          <span className="text-xs text-[var(--color-ink-faint)]">{offset + 1}–{Math.min(offset + 60, data.total)} of {data.total}</span>
          <Btn size="sm" disabled={offset + 60 >= data.total} onClick={() => setOffset(offset + 60)}>next →</Btn>
        </div>
      )}

      {selected != null && <FindingDrawer id={selected} onClose={() => setSelected(null)} onChanged={refetch} />}
    </div>
  );
}

function Select({ label, value, opts, onChange }:
  { label: string; value?: string; opts?: string[]; onChange: (v: string) => void }) {
  return (
    <select value={value || ""} onChange={(e) => onChange(e.target.value)}
      className="mono rounded-md border border-[var(--color-border-bright)] bg-[var(--color-panel)] px-2 py-1.5 text-xs text-[var(--color-ink-dim)] outline-none focus:border-[var(--color-accent)]">
      <option value="">{label}: all</option>
      {(opts || []).map((o) => <option key={o} value={o}>{o}</option>)}
    </select>
  );
}

function FindingDrawer({ id, onClose, onChanged }: { id: number; onClose: () => void; onChanged: () => void }) {
  const { data, loading, refetch } = useFetch<any>(`/api/findings/${id}`);
  const toast = useToast();
  const [confirm, setConfirm] = useState<null | { title: string; body: string; run: () => Promise<any> }>(null);
  const [busy, setBusy] = useState(false);
  const [bounty, setBounty] = useState("0");

  const doAction = async () => {
    if (!confirm) return;
    setBusy(true);
    try {
      const r = await confirm.run();
      toast(r?.ok === false ? "err" : "ok", r?.ok === false ? (r.error || "failed") : "done");
      refetch(); onChanged();
    } catch (e: any) {
      toast("err", e.message || "failed");
    } finally {
      setBusy(false); setConfirm(null);
    }
  };

  return (
    <Drawer open onClose={onClose} width={620}
      title={data ? <span className="mono text-sm text-[var(--color-ink)]">{data.host}</span> : "…"}>
      {loading && !data ? <Spinner /> : !data ? <Empty>not found</Empty> : (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-2">
            <Badge color={stateColor[data.state]} filled>{data.state}</Badge>
            {data.vuln_class && <Badge>{data.vuln_class}</Badge>}
            {data.ai_verdict && <Badge color={verdictColor[data.ai_verdict]}>{data.ai_verdict} · {Math.round((data.ai_confidence || 0) * 100)}%</Badge>}
            {data.priority && <Badge color={priorityColor[data.priority]}>{data.priority}</Badge>}
            <span className="mono text-xs text-[var(--color-ink-faint)]">#{data.id} · score {data.score}</span>
          </div>

          <Field label="url"><span className="mono break-all text-xs text-[var(--color-info)]">{data.url || "—"}</span></Field>
          <Field label="program">{data.program || "—"}</Field>
          {data.ai_reason && <Field label="ai reason"><span className="text-xs">{data.ai_reason}</span></Field>}

          {data.ai_report && <Collapse title="ai report"><pre className="mono max-h-64 overflow-auto whitespace-pre-wrap text-[11px] text-[var(--color-ink-dim)]">{JSON.stringify(data.ai_report, null, 2)}</pre></Collapse>}
          {data.evidence && <Collapse title="evidence"><pre className="mono max-h-64 overflow-auto whitespace-pre-wrap text-[11px] text-[var(--color-ink-dim)]">{JSON.stringify(data.evidence, null, 2)}</pre></Collapse>}

          {data.audit_log?.length > 0 && (
            <Field label="timeline">
              <div className="space-y-1">
                {data.audit_log.map((a: any, i: number) => (
                  <div key={i} className="flex items-center gap-2 text-[11px]">
                    <span className="mono text-[var(--color-ink-faint)]">{(a.created_at || "").slice(5, 16)}</span>
                    <span className="text-[var(--color-ink-dim)]">{a.event || a.action || a.to_state || JSON.stringify(a).slice(0, 60)}</span>
                  </div>
                ))}
              </div>
            </Field>
          )}

          {/* actions */}
          <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] p-4">
            <div className="mb-3 text-[11px] font-semibold uppercase tracking-wider text-[var(--color-ink-faint)]">record outcome</div>
            <div className="mb-3 flex items-center gap-2">
              <span className="text-xs text-[var(--color-ink-dim)]">bounty $</span>
              <input value={bounty} onChange={(e) => setBounty(e.target.value)}
                className="mono w-24 rounded border border-[var(--color-border-bright)] bg-[var(--color-bg)] px-2 py-1 text-xs" />
            </div>
            <div className="flex flex-wrap gap-2">
              {RESOLUTIONS.map((res) => (
                <Btn key={res} size="sm" variant={res === "accepted" ? "primary" : "ghost"}
                  onClick={() => setConfirm({
                    title: `Mark #${data.id} ${res}?`,
                    body: `Records the platform outcome "${res}"${res === "accepted" ? ` with $${bounty} bounty` : ""}. Feeds the learning stores.`,
                    run: () => api.action(`/api/findings/${data.id}/outcome`, { resolution: res, bounty: parseFloat(bounty) || 0 }),
                  })}>{res}</Btn>
              ))}
            </div>
            <div className="mt-4 flex flex-wrap gap-2 border-t border-[var(--color-border)] pt-3">
              <Btn size="sm" onClick={() => setConfirm({
                title: `Ignore ${data.host}?`, body: "Benches the host for 7 days and records a note.",
                run: () => api.action(`/api/hosts/${encodeURIComponent(data.host)}/ignore`, { reason: `ui: finding #${data.id}` }),
              })}>ignore host 7d</Btn>
              <Btn size="sm" onClick={() => {
                const text = prompt(`Note for ${data.host}:`);
                if (text) setConfirm({ title: "Add note?", body: text, run: () => api.action(`/api/hosts/${encodeURIComponent(data.host)}/note`, { text }) });
              }}>add note</Btn>
            </div>
          </div>
        </div>
      )}
      <ConfirmModal open={!!confirm} title={confirm?.title || ""} body={confirm?.body} confirmLabel={busy ? "…" : "Confirm"}
        onConfirm={doAction} onCancel={() => setConfirm(null)} />
    </Drawer>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-1 text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">{label}</div>
      <div className="text-sm text-[var(--color-ink-dim)]">{children}</div>
    </div>
  );
}

function Collapse({ title, children }: { title: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-lg border border-[var(--color-border)]">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center justify-between px-3 py-2 text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)] hover:text-[var(--color-ink)]">
        {title}<span>{open ? "−" : "+"}</span>
      </button>
      {open && <div className="border-t border-[var(--color-border)] p-3">{children}</div>}
    </div>
  );
}
