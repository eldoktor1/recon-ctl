import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useFetch } from "../hooks";
import { Panel, Badge, Empty, Spinner, Dot, SortTh } from "../components/ui";
import { Btn } from "../components/controls";
import { HostDrawer } from "../components/HostDrawer";
import { priorityColor, asArr } from "../format";

interface Asset {
  host: string; triage_program?: string; triage_priority?: string; triage_score?: number;
  triage_classes?: string[]; triage_kev_match?: boolean; triage_true_fresh?: boolean;
  triage_pays?: boolean; triage_in_scope?: boolean; triage_ignored?: boolean; takeover_confirmed?: boolean;
  js_secret_hit?: boolean; tech?: string[]; host_notes_count?: number;
}
interface AssetList { total: number; items: Asset[]; error?: string }
interface Facets { programs?: { value: string; count: number }[]; classes?: { value: string; count: number }[]; priorities?: { value: string; count: number }[] }

const TECH_CHIPS = ["wordpress", "jira", "graphql", "spring", "jenkins", "gitlab", "confluence",
  "tomcat", "drupal", "laravel", "django", "grafana", "elasticsearch", "kibana", "swagger", "nginx", "apache"];

export default function Assets() {
  const [sp] = useSearchParams();
  const [q, setQ] = useState(sp.get("q") || "");
  const [tech, setTech] = useState("");
  const [filters, setFilters] = useState<Record<string, string>>({});
  const [toggles, setToggles] = useState<Record<string, boolean>>({});
  const [selected, setSelected] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);
  const [sort, setSort] = useState("triage_score");
  const [order, setOrder] = useState<"asc" | "desc">("desc");
  const { data: facets } = useFetch<Facets>("/api/assets/facets");

  const qs = new URLSearchParams({ limit: "60", offset: String(offset), sort, order });
  if (q) qs.set("q", q);
  if (tech) qs.set("tech", tech);
  Object.entries(filters).forEach(([k, v]) => v && qs.set(k, v));
  Object.entries(toggles).forEach(([k, v]) => v && qs.set(k, "true"));
  const { data, loading } = useFetch<AssetList>(`/api/assets?${qs}`, [q, tech, JSON.stringify(filters), JSON.stringify(toggles), offset, sort, order]);

  const tog = (k: string) => { setOffset(0); setToggles((t) => ({ ...t, [k]: !t[k] })); };
  const setF = (k: string, v: string) => { setOffset(0); setFilters((f) => ({ ...f, [k]: v })); };
  const setTechF = (t: string) => { setOffset(0); setTech(t); };
  // click a header: toggle asc/desc if same column, else new column (default desc)
  const onSort = (col: string) => {
    setOffset(0);
    if (sort === col) setOrder((o) => (o === "asc" ? "desc" : "asc"));
    else { setSort(col); setOrder("desc"); }
  };
  const anyFilter = q || tech || Object.values(filters).some(Boolean) || Object.values(toggles).some(Boolean);

  return (
    <div className="fade-in space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="text-lg font-semibold">Asset Explorer</h1>
        <span className="text-xs text-[var(--color-ink-faint)]">
          {data?.total?.toLocaleString() ?? "—"} match · in-scope + paying by default
        </span>
      </div>

      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <input value={q} onChange={(e) => { setOffset(0); setQ(e.target.value); }} placeholder="host contains…"
            className="mono w-56 rounded-md border border-[var(--color-border-bright)] bg-[var(--color-panel)] px-3 py-1.5 text-xs outline-none focus:border-[var(--color-accent)]" />
          <input value={tech} onChange={(e) => setTechF(e.target.value)} placeholder="tech / keyword…"
            className="mono w-48 rounded-md border border-[var(--color-border-bright)] bg-[var(--color-panel)] px-3 py-1.5 text-xs outline-none focus:border-[var(--color-accent)]" />
          <Select label="program" value={filters.program} opts={facets?.programs} onChange={(v) => setF("program", v)} />
          <Select label="class" value={filters.cls} opts={facets?.classes} onChange={(v) => setF("cls", v)} />
          <Select label="priority" value={filters.priority} opts={facets?.priorities} onChange={(v) => setF("priority", v)} />
          {["pays", "fresh", "kev"].map((k) => <Toggle key={k} label={k} on={!!toggles[k]} onClick={() => tog(k)} />)}
          <Toggle label="incl. benched" on={!!toggles.include_benched} onClick={() => tog("include_benched")} />
          <Toggle label="incl. out-of-scope" on={!!toggles.include_oos} onClick={() => tog("include_oos")} />
          <Toggle label="incl. non-paying" on={!!toggles.include_nopay} onClick={() => tog("include_nopay")} />
          {anyFilter && <Btn size="sm" onClick={() => { setQ(""); setTech(""); setFilters({}); setToggles({}); setOffset(0); }}>clear</Btn>}
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">tech:</span>
          {TECH_CHIPS.map((t) => (
            <button key={t} onClick={() => setTechF(tech === t ? "" : t)}
              className="rounded px-2 py-0.5 text-[11px] transition"
              style={{ color: tech === t ? "#0a0e14" : "var(--color-ink-dim)", background: tech === t ? "var(--color-accent)" : "var(--color-panel-2)" }}>{t}</button>
          ))}
        </div>
      </div>

      <Panel className="!p-0">
        {loading && !data ? <Spinner /> : data?.error ? <Empty>ES error: {data.error.slice(0, 120)}</Empty> :
          !data?.items.length ? <Empty hint={anyFilter ? "loosen a filter or enable the out-of-scope / non-paying toggles" : "the index is scope+pays filtered by default"}>no assets match</Empty> : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">
                <SortTh label="pri" col="triage_priority" active={sort} order={order} onSort={onSort} className="!px-4" />
                <SortTh label="host" col="host" active={sort} order={order} onSort={onSort} />
                <SortTh label="tech" />
                <SortTh label="program" />
                <SortTh label="score" col="triage_score" active={sort} order={order} onSort={onSort} />
                <SortTh label="flags" align="right" className="!px-4" />
              </tr>
            </thead>
            <tbody>
              {data.items.map((a) => (
                <tr key={a.host} onClick={() => setSelected(a.host)}
                  className="cursor-pointer border-b border-[var(--color-border)]/50 hover:bg-[var(--color-panel-2)]">
                  <td className="px-4 py-2">{a.triage_priority && <Badge color={priorityColor[a.triage_priority] || "var(--color-ink-dim)"}>{a.triage_priority}</Badge>}</td>
                  <td className="mono max-w-sm truncate px-2 py-2 text-xs text-[var(--color-ink)]" title={a.host}>{a.host}</td>
                  <td className="max-w-[130px] truncate px-2 py-2 text-[11px] text-[var(--color-ink-faint)]">{asArr(a.tech).slice(0, 3).join(", ") || "—"}</td>
                  <td className="max-w-[120px] truncate px-2 py-2 text-xs text-[var(--color-ink-faint)]">{a.triage_program || "—"}</td>
                  <td className="mono px-2 py-2 text-xs">{a.triage_score ?? "—"}</td>
                  <td className="px-4 py-2 text-right">
                    <div className="flex justify-end gap-1">
                      <Badge color={a.triage_in_scope === false ? "var(--color-bad)" : "var(--color-good)"} title={a.triage_in_scope === false ? "out of scope" : "in scope"}>{a.triage_in_scope === false ? "oos" : "scope"}</Badge>
                      <Badge color={a.triage_pays ? "var(--color-good)" : "var(--color-ink-faint)"} title={a.triage_pays ? "pays" : "no payout"}>{a.triage_pays ? "$" : "×$"}</Badge>
                      {a.triage_true_fresh && <Badge color="var(--color-accent)">fresh</Badge>}
                      {a.triage_kev_match && <Badge color="var(--color-bad)">kev</Badge>}
                      {a.takeover_confirmed && <Badge color="var(--color-bad)">takeover</Badge>}
                      {a.js_secret_hit && <Badge color="var(--color-warn)">secret</Badge>}
                      {a.triage_ignored && <Badge color="var(--color-ink-faint)">benched</Badge>}
                      {!!a.host_notes_count && <Badge>📝{a.host_notes_count}</Badge>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      {data && data.total > 60 && offset + 120 <= Math.min(data.total, 10000) && (
        <div className="flex items-center justify-center gap-3">
          <Btn size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 60))}>← prev</Btn>
          <span className="text-xs text-[var(--color-ink-faint)]">{offset + 1}–{offset + 60}</span>
          <Btn size="sm" onClick={() => setOffset(offset + 60)}>next →</Btn>
        </div>
      )}

      {selected && <HostDrawer host={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function Toggle({ label, on, onClick }: { label: string; on: boolean; onClick: () => void }) {
  return (
    <button onClick={onClick} className="flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs transition"
      style={{ borderColor: on ? "var(--color-accent)" : "var(--color-border-bright)", color: on ? "var(--color-accent)" : "var(--color-ink-faint)" }}>
      <Dot color={on ? "var(--color-accent)" : "var(--color-ink-faint)"} />{label}
    </button>
  );
}

function Select({ label, value, opts, onChange }:
  { label: string; value?: string; opts?: { value: string; count: number }[]; onChange: (v: string) => void }) {
  return (
    <select value={value || ""} onChange={(e) => onChange(e.target.value)}
      className="mono max-w-[160px] rounded-md border border-[var(--color-border-bright)] bg-[var(--color-panel)] px-2 py-1.5 text-xs text-[var(--color-ink-dim)] outline-none focus:border-[var(--color-accent)]">
      <option value="">{label}: all</option>
      {(opts || []).map((o) => <option key={o.value} value={o.value}>{o.value} ({o.count})</option>)}
    </select>
  );
}
