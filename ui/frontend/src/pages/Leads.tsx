// The worklist: confirmed vulns only.
//
// Source is /api/worklist (ui/backend/worklist.py): findings.db rows a lane MINTED, behind a
// strict FP gate. It no longer reads the briefings. The old page turned every briefing bullet
// with a hostname into a lead row, so notes like "SECURE" and "leakchain clean" sat on the board
// as work; on 2026-11-14 all 80 rows were false positives (operator: "does the opposite of what
// I want ... show only serious real vulns"). Briefings are still readable on the Digest page.
//
// Two tiers, nothing else: READY (Claude consensus said real: file it) and CHECK (minted, not yet
// judged). Everything the gate threw out is one line of counts at the bottom, never rows.
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { useFetch } from "../hooks";
import { Badge, Spinner } from "../components/ui";
import { Btn, useToast, ConfirmModal } from "../components/controls";
import { fmtAgo, severityColor, classColor } from "../format";
import { FindingDrawer } from "./Findings";

export interface WorkItem {
  id: number;
  host: string;
  url: string | null;
  program: string | null;
  vuln_class: string | null;
  score: number;
  severity: "critical" | "high" | "medium";
  verdict: string | null;
  confidence: number | null;
  impact: string;
  minted_at: string | null;
  age_days: number | null;
}

export interface WorklistData {
  ready: WorkItem[];
  check: WorkItem[];
  held: Record<string, number>;
  held_total: number;
  filed: number;
  newest_mint: string | null;
  gate: { serious_min_score: number; stale_days: number; fanout_max: number };
}

// a quiet mint feed is a symptom, not a calm night: past this, say so on the empty state
const QUIET_DAYS = 7;

export default function Leads() {
  const { data, refetch } = useFetch<WorklistData>("/api/worklist");
  const [open, setOpen] = useState<number | null>(null);
  const [reject, setReject] = useState<WorkItem | null>(null);
  const toast = useToast();
  const navigate = useNavigate();

  const doReject = async (w: WorkItem) => {
    try {
      await api.action(`/api/findings/${w.id}/reject`, { reason: "operator: not real (worklist)" });
      toast("ok", `${w.host}: dismissed, signature learned`);
      refetch();
    } catch (e: any) { toast("err", e.message); }
  };

  const total = data ? data.ready.length + data.check.length : 0;

  return (
    <div className="fade-in mx-auto max-w-5xl space-y-6">
      <header>
        <h1 className="text-lg font-semibold">Worklist</h1>
        <p className="mt-1 text-xs text-[var(--color-ink-faint)]">
          Confirmed vulns with recovered impact. Anything that looks like a false positive is held back.
        </p>
      </header>

      {!data ? <Spinner /> : total === 0 ? <Quiet data={data} /> : (
        <>
          <Tier title="Ready to report" hint="survived the consensus panel" items={data.ready}
            onOpen={setOpen} onWorkspace={(h) => navigate(`/target/${encodeURIComponent(h)}`)} onReject={setReject} />
          <Tier title="Check before reporting" hint="minted, not yet judged real" items={data.check}
            onOpen={setOpen} onWorkspace={(h) => navigate(`/target/${encodeURIComponent(h)}`)} onReject={setReject} />
        </>
      )}

      {data && <GateLine data={data} />}

      {open != null && <FindingDrawer id={open} onClose={() => setOpen(null)} onChanged={refetch} />}
      <ConfirmModal open={!!reject} danger confirmLabel="Not real"
        title={`Not real: ${reject?.host ?? ""}?`}
        body="Dismisses the finding and remembers its signature, so the same pattern is held back from now on."
        onConfirm={() => { const w = reject; setReject(null); if (w) doReject(w); }}
        onCancel={() => setReject(null)} />
    </div>
  );
}

function Tier({ title, hint, items, onOpen, onWorkspace, onReject }: {
  title: string; hint: string; items: WorkItem[];
  onOpen: (id: number) => void; onWorkspace: (host: string) => void; onReject: (w: WorkItem) => void;
}) {
  if (!items.length) return null;
  return (
    <section>
      <div className="mb-2 flex items-baseline gap-2">
        <h2 className="text-sm font-semibold">{title}</h2>
        <span className="mono text-xs text-[var(--color-ink-faint)]">{items.length}</span>
        <span className="text-[11px] text-[var(--color-ink-faint)]">{hint}</span>
      </div>
      <div className="divide-y divide-[var(--color-border)] overflow-hidden rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)]">
        {items.map((w) => (
          <div key={w.id} className="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:gap-4">
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <Badge color={severityColor[w.severity]} filled>{w.severity.toUpperCase()}</Badge>
                <button onClick={() => onOpen(w.id)} title="open the finding"
                  className="mono truncate text-sm text-[var(--color-ink)] hover:text-[var(--color-accent)]">{w.host}</button>
                {w.vuln_class && <Badge color={classColor[w.vuln_class.split("-")[0]] || "var(--color-ink-dim)"}>{w.vuln_class}</Badge>}
              </div>
              <p className="mt-1 line-clamp-2 text-xs text-[var(--color-ink-dim)]" title={w.impact}>{w.impact}</p>
              <div className="mt-1 text-[10px] text-[var(--color-ink-faint)]">
                {w.program && <span>{w.program} · </span>}
                minted {w.minted_at ? fmtAgo(w.minted_at) : "?"}
                {w.confidence != null && <span> · confidence {Math.round(w.confidence * 100)}%</span>}
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-1.5">
              <Btn size="sm" variant="primary" onClick={() => onWorkspace(w.host)}>Open</Btn>
              <Btn size="sm" onClick={() => onOpen(w.id)}>Details</Btn>
              <Btn size="sm" variant="danger" onClick={() => onReject(w)}>Not real</Btn>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function Quiet({ data }: { data: WorklistData }) {
  const last = data.newest_mint ? Date.parse(data.newest_mint) : NaN;
  const days = Number.isNaN(last) ? null : Math.floor((Date.now() - last) / 86_400_000);
  const stalled = days == null || days > QUIET_DAYS;
  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] px-6 py-10 text-center">
      <div className="text-sm text-[var(--color-ink)]">Nothing real to work on.</div>
      <div className="mt-1 text-xs text-[var(--color-ink-faint)]">
        No finding has passed the gate.
        {data.newest_mint && <> Newest mint {fmtAgo(data.newest_mint)}.</>}
      </div>
      {stalled && (
        <div className="mt-3 text-xs text-[var(--color-warn)]">
          {days == null ? "Nothing has ever been minted." : `Nothing minted in ${days} days.`} If the lanes are running,
          that silence is worth a look on the Lanes page.
        </div>
      )}
    </div>
  );
}

function GateLine({ data }: { data: WorklistData }) {
  const g = data.gate;
  const held = Object.entries(data.held);
  return (
    <footer className="space-y-1 border-t border-[var(--color-border)] pt-3 text-[11px] text-[var(--color-ink-faint)]">
      <div>
        Gate: impact score {g.serious_min_score}+, judged within {g.stale_days} days, endpoint on at most {g.fanout_max} hosts,
        no FP verdict, note, bench or known FP signature.
      </div>
      <div>
        {held.length
          ? <>Held back: {held.map(([r, n]) => `${n} ${r}`).join(" · ")}.</>
          : <>Nothing held back.</>}
        {data.filed > 0 && <> {data.filed} already filed (Reports).</>}
      </div>
    </footer>
  );
}
