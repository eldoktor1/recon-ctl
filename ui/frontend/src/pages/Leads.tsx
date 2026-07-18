import { useEffect, useState } from "react";
import { api } from "../api";
import { useFetch } from "../hooks";
import { Panel, Badge, Empty, Spinner, Dot } from "../components/ui";
import { Btn, useToast } from "../components/controls";
import { Markdown } from "../components/Markdown";
import { HostDrawer } from "../components/HostDrawer";
import { priorityColor, fmtAgo } from "../format";

interface Bucket { key: string; label: string; count: number; hosts: any[]; error?: string }
interface Leads { buckets: Bucket[] }
interface Brief { name: string; kind: string; date: string | null; mtime: number }

const bucketColor: Record<string, string> = {
  takeover: "var(--color-bad)", takeover_lead: "var(--color-warn)", secrets: "var(--color-warn)",
  kev: "var(--color-bad)", fresh: "var(--color-accent)",
};

export default function Leads() {
  const { data: leads } = useFetch<Leads>("/api/leads");
  const { data: briefs } = useFetch<Brief[]>("/api/briefings");
  const [host, setHost] = useState<string | null>(null);
  const [active, setActive] = useState<string | null>(null);
  const toast = useToast();
  const [vhost, setVhost] = useState("");

  useEffect(() => {
    if (!active && briefs?.length) {
      const t = briefs.find((b) => b.kind.startsWith("tonight")) || briefs[0];
      setActive(t.name);
    }
  }, [briefs, active]);

  const launchVerify = async () => {
    if (!vhost.trim()) return;
    try { const t = await api.action<any>("/api/verify", { host: vhost.trim() }); toast("ok", `verify task #${t.id} → Hunt Control`); setVhost(""); }
    catch (e: any) { toast("err", e.message); }
  };

  // curated candidate worklists (already product-class/tenant filtered by the pipeline)
  const CANDIDATE_KINDS = ["idor_candidates", "xss_candidates", "sqli_candidates", "graphql_candidates", "hunter", "2IC_tonight", "fresh"];
  const candidates = (briefs || []).filter((b) => CANDIDATE_KINDS.some((k) => b.kind.startsWith(k)))
    .sort((a, b) => b.mtime - a.mtime)
    .filter((b, i, arr) => arr.findIndex((x) => x.kind === b.kind) === i); // latest per kind

  return (
    <div className="fade-in space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="text-lg font-semibold">Leads</h1>
        <div className="flex items-center gap-2">
          <input value={vhost} onChange={(e) => setVhost(e.target.value)} placeholder="verify host…"
            onKeyDown={(e) => e.key === "Enter" && launchVerify()}
            className="mono w-48 rounded-md border border-[var(--color-border-bright)] bg-[var(--color-panel)] px-3 py-1.5 text-xs outline-none focus:border-[var(--color-accent)]" />
          <Btn size="sm" variant="primary" onClick={launchVerify}>run verify</Btn>
        </div>
      </div>

      {/* active signal leads */}
      <Panel title="active leads · live signals" right={<span className="text-[10px] text-[var(--color-ink-faint)]">not benched · pays</span>}>
        {!leads ? <Spinner /> : (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
            {leads.buckets.map((b) => (
              <div key={b.key} className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] p-3">
                <div className="mb-2 flex items-center gap-2">
                  <Dot color={bucketColor[b.key] || "var(--color-ink-dim)"} pulse={b.count > 0 && (b.key === "takeover" || b.key === "secrets")} />
                  <span className="flex-1 text-xs text-[var(--color-ink-dim)]">{b.label}</span>
                  <Badge color={b.count ? bucketColor[b.key] : "var(--color-ink-faint)"}>{b.count}</Badge>
                </div>
                {b.hosts.length === 0 ? <div className="text-[11px] text-[var(--color-ink-faint)]">none active</div> : (
                  <div className="space-y-0.5">
                    {b.hosts.slice(0, 6).map((h) => (
                      <button key={h.host} onClick={() => setHost(h.host)}
                        className="flex w-full items-center gap-2 rounded px-1.5 py-1 text-left hover:bg-[var(--color-panel)]">
                        {h.triage_priority && <Badge color={priorityColor[h.triage_priority]}>{h.triage_priority}</Badge>}
                        <span className="mono flex-1 truncate text-[11px] text-[var(--color-ink)]">{h.host}</span>
                        <span className="text-[10px] text-[var(--color-ink-faint)]">{h.triage_score}</span>
                      </button>
                    ))}
                    {b.count > 6 && <div className="pl-1.5 pt-1 text-[10px] text-[var(--color-ink-faint)]">+{b.count - 6} more</div>}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Panel>

      {/* curated candidate worklists */}
      <Panel title="candidate worklists · curated & deduped">
        {!candidates.length ? <Empty>no candidate briefings</Empty> : (
          <div className="flex flex-wrap gap-2">
            {candidates.map((b) => (
              <button key={b.name} onClick={() => setActive(b.name)}
                className={`rounded-md border px-3 py-1.5 text-xs transition ${active === b.name ? "border-[var(--color-accent)] text-[var(--color-accent)]" : "border-[var(--color-border-bright)] text-[var(--color-ink-dim)] hover:text-[var(--color-ink)]"}`}>
                {b.kind} <span className="text-[10px] text-[var(--color-ink-faint)]">· {b.date?.slice(5) || fmtAgo(b.mtime)}</span>
              </button>
            ))}
          </div>
        )}
      </Panel>

      {/* briefing viewer */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[240px_1fr]">
        <Panel title="all briefings" className="!p-2">
          <div className="max-h-[60vh] space-y-0.5 overflow-auto">
            {!briefs ? <Spinner /> : briefs.map((b) => (
              <button key={b.name} onClick={() => setActive(b.name)}
                className={`flex w-full items-center gap-2 rounded-md px-2.5 py-1.5 text-left text-xs transition ${active === b.name ? "bg-[var(--color-accent)]/12 text-[var(--color-accent)]" : "text-[var(--color-ink-dim)] hover:bg-[var(--color-panel-2)]"}`}>
                <span className="flex-1 truncate">{b.kind}</span>
                <span className="text-[10px] text-[var(--color-ink-faint)]">{b.date?.slice(5) || fmtAgo(b.mtime)}</span>
              </button>
            ))}
          </div>
        </Panel>
        <Panel title={active || "briefing"} className="min-h-[50vh]">
          {active ? <BriefingBody name={active} /> : <Empty>pick a briefing</Empty>}
        </Panel>
      </div>

      {host && <HostDrawer host={host} onClose={() => setHost(null)} />}
    </div>
  );
}

function BriefingBody({ name }: { name: string }) {
  const { data, loading } = useFetch<{ body: string }>(`/api/briefings/${encodeURIComponent(name)}`);
  if (loading && !data) return <Spinner />;
  if (!data) return <Empty>could not load</Empty>;
  return <div className="max-h-[62vh] overflow-auto"><Markdown text={data.body} /></div>;
}
