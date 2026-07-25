import { useState, type ReactNode } from "react";
import { Badge } from "./ui";
import { severityColor, classColor } from "../format";

// One compact, scannable lead row — the single shared rendering used by both the
// unified Leads worklist and the Command Center "Tonight" preview (no more three
// divergent copies). host chip + class tag + score + one-line summary, with the
// full raw detail tucked behind an expand chevron.
export function CompactLeadRow({
  severity, host, vulnClass, score, summary, sources, emoji,
  onHost, right, expandable,
}: {
  severity?: string | null;
  host?: string | null;
  vulnClass?: string | null;
  score?: number | null;
  summary: string;
  sources?: string[];
  emoji?: string;
  onHost?: (h: string) => void;
  right?: ReactNode;         // action slot (LeadActions / a verify button)
  expandable?: ReactNode;    // raw detail revealed by the chevron
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)]">
      <div className="flex items-center gap-2 px-2.5 py-1.5">
        {expandable ? (
          <button onClick={() => setOpen((o) => !o)} title={open ? "collapse" : "expand detail"}
            className="shrink-0 text-[var(--color-ink-faint)] hover:text-[var(--color-ink)]">{open ? "▾" : "▸"}</button>
        ) : emoji ? <span className="shrink-0 text-xs">{emoji}</span> : null}

        {severity && <Badge color={severityColor[severity.toLowerCase()] || "var(--color-ink-dim)"} filled>{severity.toUpperCase()}</Badge>}

        {host ? (
          <button onClick={() => onHost?.(host)} title="open host detail"
            className="mono shrink-0 truncate text-[11px] text-[var(--color-ink)] hover:text-[var(--color-accent)]" style={{ maxWidth: 260 }}>
            {host}
          </button>
        ) : null}

        {vulnClass && <Badge color={classColor[vulnClass] || "var(--color-ink-dim)"}>{vulnClass}</Badge>}
        {score != null && <span className="mono shrink-0 text-[10px] text-[var(--color-ink-faint)]" title="triage score">{score}</span>}

        <span className="min-w-0 flex-1 truncate text-[11px] text-[var(--color-ink-dim)]" title={summary}>{summary}</span>

        {sources && sources.length > 0 && (
          <span className="hidden shrink-0 items-center gap-1 lg:flex">
            {sources.map((s) => <span key={s} className="mono rounded bg-[var(--color-panel)] px-1 py-0.5 text-[9px] text-[var(--color-ink-faint)]">{s}</span>)}
          </span>
        )}

        {right && <div className="ml-auto shrink-0 lg:ml-2">{right}</div>}
      </div>
      {open && expandable && (
        <div className="border-t border-[var(--color-border)] px-3 py-2">{expandable}</div>
      )}
    </div>
  );
}
