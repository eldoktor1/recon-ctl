import { useCallback, useEffect, useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useFetch } from "../hooks";
import { Panel, Badge, Empty, Spinner, Dot } from "../components/ui";
import { Btn, useToast } from "../components/controls";
import { Markdown } from "../components/Markdown";
import type { Parsed } from "../components/Worklist";
import { HostDrawer } from "../components/HostDrawer";
import { TaskConsole } from "../components/TaskConsole";
import { CompactLeadRow } from "../components/CompactLeadRow";
import { LeadActions, useHostActions } from "../components/LeadActions";
import { api } from "../api";
import { priorityColor, fmtAgo, classFromSection, severityRank } from "../format";

interface BucketHost { host: string; triage_priority?: string; triage_score?: number; triage_pays?: boolean; triage_in_scope?: boolean }
interface Bucket { key: string; label: string; count: number; hosts: BucketHost[]; error?: string }
interface Leads { buckets: Bucket[]; suppressed?: number; noted_hosts?: string[] }
interface Brief { name: string; kind: string; date: string | null; mtime: number }

const bucketColor: Record<string, string> = {
  takeover: "var(--color-bad)", takeover_lead: "var(--color-warn)", secrets: "var(--color-warn)",
  kev: "var(--color-bad)", fresh: "var(--color-accent)",
};

const SOURCE_ORDER = [
  "tonight", "2IC_tonight", "hunter", "idor_candidates", "xss_candidates",
  "sqli_candidates", "graphql_candidates", "fresh", "targets",
];

// hosts that aren't real TARGETS — bug-bounty platform / infra domains that leak into the
// worklist from program-header bullets (e.g. an engagement URL `https://bugcrowd.com/...`).
const NON_TARGET_HOSTS = new Set([
  "bugcrowd.com", "hackerone.com", "intigriti.com", "app.intigriti.com", "yeswehack.com",
  "github.com", "gitlab.com", "owasp.org",
]);

// A single deduped lead, merged across every briefing source it appears in.
interface ULead {
  key: string;
  host: string | null;
  vulnClass: string | null;
  severity: string | null;
  score: number | null;
  program: string | null;
  summary: string;
  sources: string[];
  suppressed: boolean;
  raws: { source: string; raw: string }[];
}

// Invisible fetcher: one per source, streams its parsed briefing up to the parent
// so the worklist can merge + dedupe across ALL sources at once.
function SourceFetcher({ name, kind, onData }:
  { name: string; kind: string; onData: (kind: string, p: Parsed | null) => void }) {
  const { data } = useFetch<Parsed>(`/api/briefings/${encodeURIComponent(name)}/parsed`);
  useEffect(() => { onData(kind, data ?? null); }, [kind, data, onData]);
  return null;
}

export default function Leads() {
  const [inclOos, setInclOos] = useState(false);
  const [inclNopay, setInclNopay] = useState(false);
  const qsLeads = new URLSearchParams();
  if (inclOos) qsLeads.set("include_oos", "true");
  if (inclNopay) qsLeads.set("include_nopay", "true");
  const { data: leads } = useFetch<Leads>(`/api/leads?${qsLeads}`, [inclOos, inclNopay]);
  const { data: briefs } = useFetch<Brief[]>("/api/briefings");
  const hostActions = useHostActions();

  const [host, setHost] = useState<string | null>(null);
  const [source, setSource] = useState<string>("all");
  const [filter, setFilter] = useState("");
  const [showHidden, setShowHidden] = useState(false);
  const [unseenOnly, setUnseenOnly] = useState(false);  // "drain rubbish" — only never-worked targets
  const [openTask, setOpenTask] = useState<number | null>(null);
  const [vhost, setVhost] = useState("");
  const toast = useToast();
  const qc = useQueryClient();

  const refresh = useCallback(() => qc.invalidateQueries(), [qc]);

  // latest briefing per kind, dropping STALE one-off sources (keep the curated core always,
  // and any other kind only while it's fresh) so the chip row doesn't accumulate 40-day rubbish.
  const SOURCE_FRESH_S = 14 * 86400;
  const sources = useMemo(() => {
    const latest: Record<string, Brief> = {};
    for (const b of briefs || []) {
      const cur = latest[b.kind];
      if (!cur || b.mtime > cur.mtime) latest[b.kind] = b;
    }
    const now = Date.now() / 1000;
    return Object.values(latest)
      .filter((b) => SOURCE_ORDER.some((k) => b.kind.startsWith(k)) || now - b.mtime < SOURCE_FRESH_S)
      .sort((a, b) => {
        const ia = SOURCE_ORDER.findIndex((k) => a.kind.startsWith(k));
        const ib = SOURCE_ORDER.findIndex((k) => b.kind.startsWith(k));
        const ra = ia === -1 ? 99 : ia, rb = ib === -1 ? 99 : ib;
        return ra !== rb ? ra - rb : b.mtime - a.mtime;
      });
  }, [briefs]);

  // collect parsed briefings from the SourceFetcher children
  const [parsedByKind, setParsedByKind] = useState<Record<string, Parsed | null>>({});
  const onData = useCallback((kind: string, p: Parsed | null) => {
    setParsedByKind((prev) => (prev[kind] === p ? prev : { ...prev, [kind]: p }));
  }, []);

  // hosts we've already worked (have a note) — for the "drain rubbish" unseen-only filter
  const notedSet = useMemo(() => new Set((leads?.noted_hosts || []).map((h) => h.toLowerCase())), [leads]);

  // score-by-host from the live ES buckets, to enrich briefing rows
  const scoreByHost = useMemo(() => {
    const m: Record<string, number> = {};
    for (const b of leads?.buckets || [])
      for (const h of b.hosts) if (h.triage_score != null) m[h.host.toLowerCase()] = h.triage_score;
    return m;
  }, [leads]);

  // MERGE + DEDUPE across sources by host
  const merged = useMemo(() => {
    const map = new Map<string, ULead>();
    for (const [kind, parsed] of Object.entries(parsedByKind)) {
      if (!parsed || (source !== "all" && kind !== source)) continue;
      for (const sec of parsed.sections || []) {
        const cls = classFromSection(sec.title);
        for (const it of sec.items) {
          const h = it.hosts[0] || null;
          const key = h ? h.toLowerCase() : `∅:${it.label}`;
          const summary = (it.label || it.raw.split("\n")[0] || "").replace(/[*_`]/g, "").trim();
          const ex = map.get(key);
          if (!ex) {
            map.set(key, {
              key, host: h, vulnClass: cls, severity: it.severity || null,
              score: h ? scoreByHost[h.toLowerCase()] ?? null : null,
              program: it.program || null, summary,
              sources: [kind.replace(/_candidates$/, "")], suppressed: !!it.suppressed,
              raws: [{ source: kind, raw: it.raw }],
            });
          } else {
            if (!ex.sources.includes(kind.replace(/_candidates$/, ""))) ex.sources.push(kind.replace(/_candidates$/, ""));
            if (severityRank(it.severity) > severityRank(ex.severity)) ex.severity = it.severity || ex.severity;
            if (!ex.vulnClass && cls) ex.vulnClass = cls;
            if (!ex.program && it.program) ex.program = it.program;
            ex.suppressed = ex.suppressed && !!it.suppressed; // shown if actionable in ANY source
            ex.raws.push({ source: kind, raw: it.raw });
          }
        }
      }
    }
    const f = filter.trim().toLowerCase();
    return Array.from(map.values())
      // worklist = actionable TARGET rows only: must have a real host, and not a bug-bounty
      // platform/infra host (program-header + metadata-bullet leaks are hostless or platform hosts)
      .filter((l) => l.host && !NON_TARGET_HOSTS.has(l.host.toLowerCase()))
      .filter((l) => showHidden || !l.suppressed)
      .filter((l) => !unseenOnly || !notedSet.has((l.host || "").toLowerCase()))
      .filter((l) => !f || (l.host || "").toLowerCase().includes(f) || l.summary.toLowerCase().includes(f) || (l.program || "").toLowerCase().includes(f) || l.sources.join(" ").includes(f))
      .sort((a, b) => (severityRank(b.severity) - severityRank(a.severity)) || ((b.score ?? 0) - (a.score ?? 0)));
  }, [parsedByKind, source, filter, showHidden, unseenOnly, notedSet, scoreByHost]);

  const hiddenCount = useMemo(() => {
    let n = 0;
    for (const [kind, parsed] of Object.entries(parsedByKind)) {
      if (!parsed || (source !== "all" && kind !== source)) continue;
      for (const sec of parsed.sections || []) for (const it of sec.items) if (it.suppressed) n++;
    }
    return n;
  }, [parsedByKind, source]);

  const launchVerify = async (h?: string) => {
    const target = (h ?? vhost).trim();
    if (!target) return;
    try {
      const t = await api.action<{ id: number }>("/api/verify", { host: target });
      toast("ok", `verify #${t.id} started — streaming below`);
      setOpenTask(t.id);
      if (!h) setVhost("");
    } catch (e: any) { toast("err", e.message); }
  };

  const loading = !briefs;

  return (
    <div className="fade-in space-y-4">
      {/* invisible source loaders */}
      {sources.map((b) => <SourceFetcher key={b.name} name={b.name} kind={b.kind} onData={onData} />)}

      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-lg font-semibold">Tonight · Worklist</h1>
        <div className="flex items-center gap-2">
          <input value={vhost} onChange={(e) => setVhost(e.target.value)} placeholder="verify host…"
            onKeyDown={(e) => e.key === "Enter" && launchVerify()}
            className="mono w-44 rounded-md border border-[var(--color-border-bright)] bg-[var(--color-panel)] px-3 py-1.5 text-xs outline-none focus:border-[var(--color-accent)]" />
          <Btn size="sm" variant="primary" onClick={() => launchVerify()}>run verify</Btn>
        </div>
      </div>

      <Panel
        title="worklist · actionable"
        right={
          <div className="flex flex-wrap items-center gap-1.5">
            <button onClick={() => setUnseenOnly((v) => !v)}
              title="drain the rubbish — hide targets we've already worked (have a note), leaving only NEW ones to inspect"
              className={`flex items-center gap-1.5 rounded border px-2 py-1 text-[10px] transition ${unseenOnly
                ? "border-[var(--color-accent)] text-[var(--color-accent)] bg-[var(--color-accent)]/10"
                : "border-[var(--color-border-bright)] text-[var(--color-ink-faint)] hover:text-[var(--color-ink-dim)]"}`}>
              🧹 {unseenOnly ? "unseen only" : "drain seen"}
            </button>
            <ScopeToggle label="incl. out-of-scope" on={inclOos} onClick={() => setInclOos((v) => !v)} />
            <ScopeToggle label="incl. non-paying" on={inclNopay} onClick={() => setInclNopay((v) => !v)} />
            <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="filter…"
              className="mono w-36 rounded border border-[var(--color-border-bright)] bg-[var(--color-panel-2)] px-2 py-1 text-[11px] outline-none focus:border-[var(--color-accent)]" />
          </div>
        }
      >
        {/* source selector — "all" = deduped across every briefing */}
        {loading ? <Spinner /> : (
          <div className="mb-3 flex flex-wrap items-center gap-1.5">
            <SourceTab label="all sources" active={source === "all"} onClick={() => setSource("all")} />
            {sources.map((b) => (
              <SourceTab key={b.name} label={`${b.kind} · ${b.date?.slice(5) || fmtAgo(b.mtime)}`}
                active={source === b.kind} onClick={() => setSource(b.kind)} />
            ))}
          </div>
        )}

        {hiddenCount > 0 && (
          <button onClick={() => setShowHidden((v) => !v)}
            className="mb-2 flex w-full items-center gap-2 rounded-md border border-dashed border-[var(--color-border-bright)] px-3 py-1.5 text-[11px] text-[var(--color-ink-faint)] hover:text-[var(--color-ink-dim)]">
            <span>⊘</span>
            <span className="flex-1 text-left">{hiddenCount} suppressed — worked &amp; killed / benched (won't re-serve)</span>
            <span className="text-[var(--color-accent)]">{showHidden ? "hide" : "show"}</span>
          </button>
        )}

        {loading ? null : !merged.length ? (
          <Empty hint={filter ? "clear the filter or widen scope toggles" : "briefings regenerate at 6:30pm — or run a lane from Hunt Control"}>
            {filter ? "no leads match the filter" : "no actionable leads right now"}
          </Empty>
        ) : (
          <div className="space-y-1.5">
            {merged.map((l) => (
              <CompactLeadRow key={l.key}
                severity={l.severity} host={l.host} vulnClass={l.vulnClass} score={l.score}
                summary={l.summary} sources={l.sources} onHost={setHost}
                right={l.host ? (
                  <LeadActions host={l.host} vulnClass={l.vulnClass} actions={hostActions}
                    onTask={setOpenTask} onChanged={refresh} />
                ) : undefined}
                expandable={
                  <div className="space-y-2">
                    {l.program && <div className="text-[10px] text-[var(--color-ink-faint)]">program: {l.program}</div>}
                    {l.raws.map((r, i) => (
                      <div key={i}>
                        {l.raws.length > 1 && <div className="mono mb-0.5 text-[9px] uppercase tracking-wider text-[var(--color-ink-faint)]">{r.source}</div>}
                        <Markdown text={r.raw} />
                      </div>
                    ))}
                  </div>
                }
              />
            ))}
          </div>
        )}
      </Panel>

      {/* live ES signal buckets */}
      <Panel title="active leads · live signals"
        right={
          <div className="flex items-center gap-2 text-[10px] text-[var(--color-ink-faint)]">
            {leads?.suppressed ? <span title="out-of-scope / non-paying leads hidden">{leads.suppressed} suppressed</span> : null}
            <span>{inclOos || inclNopay ? "widened" : "in-scope · pays"}</span>
          </div>
        }>
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
                      <div key={h.host} className="group flex items-center gap-2 rounded px-1.5 py-1 hover:bg-[var(--color-panel)]">
                        {h.triage_priority && <Badge color={priorityColor[h.triage_priority]}>{h.triage_priority}</Badge>}
                        <button onClick={() => setHost(h.host)} className="mono flex-1 truncate text-left text-[11px] text-[var(--color-ink)] hover:text-[var(--color-accent)]">{h.host}</button>
                        <span className="text-[10px] text-[var(--color-ink-faint)]">{h.triage_score}</span>
                        <button onClick={() => launchVerify(h.host)} title="run Claude verify"
                          className="text-[10px] text-[var(--color-accent)] opacity-0 transition group-hover:opacity-100">⚡</button>
                      </div>
                    ))}
                    {b.count > 6 && <div className="pl-1.5 pt-1 text-[10px] text-[var(--color-ink-faint)]">+{b.count - 6} more</div>}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Panel>

      {host && <HostDrawer host={host} onClose={() => setHost(null)} onChanged={refresh} />}
      {openTask != null && <TaskConsole tid={openTask} onClose={() => setOpenTask(null)} />}
    </div>
  );
}

function SourceTab({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button onClick={onClick}
      className={`rounded-md border px-2.5 py-1 text-[11px] transition ${active ? "border-[var(--color-accent)] text-[var(--color-accent)]" : "border-[var(--color-border-bright)] text-[var(--color-ink-dim)] hover:text-[var(--color-ink)]"}`}>
      {label}
    </button>
  );
}

function ScopeToggle({ label, on, onClick }: { label: string; on: boolean; onClick: () => void }) {
  return (
    <button onClick={onClick} title={on ? "showing widened set" : "hidden by default"}
      className="flex items-center gap-1.5 rounded border px-2 py-1 text-[10px] transition"
      style={{ borderColor: on ? "var(--color-accent)" : "var(--color-border-bright)", color: on ? "var(--color-accent)" : "var(--color-ink-faint)" }}>
      <Dot color={on ? "var(--color-accent)" : "var(--color-ink-faint)"} />{label}
    </button>
  );
}
