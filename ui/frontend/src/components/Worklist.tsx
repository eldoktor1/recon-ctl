import { useState } from "react";
import { Badge, Empty } from "./ui";
import { CopyChip } from "./controls";
import { Markdown } from "./Markdown";
import { severityColor } from "../format";

// --- shape (matches ui/backend/files.py parse_briefing) ----------------------
export interface WLItem {
  raw: string;
  label: string;
  hosts: string[];
  commands: string[];
  program: string | null;
  severity: string | null;
  suppressed?: boolean;
  suppress_reason?: string | null;
}
export interface WLSection {
  id: number;
  emoji: string;
  title: string;
  count: number;
  items: WLItem[];
  suppressed_count?: number;
}
export interface Parsed {
  name: string;
  kind?: string | null;
  date?: string | null;
  mtime?: number;
  title?: string;
  sections: WLSection[];
  error?: string;
}

// Sections whose hosts want a one-click confirm we can synthesize from the host.
function suggestedCommands(sectionTitle: string, host: string): string[] {
  const t = sectionTitle.toLowerCase();
  if (t.startsWith("xss")) return [`recon-params confirm xss ${host}`, `recon-params confirm sqli ${host}`];
  if (t.includes("graphql")) return [`recon-graphql ${host}`];
  if (t.includes("web-cache") || t.includes("cache")) return [`recon-wcd confirm ${host}`];
  return [];
}

function itemMatches(it: WLItem, f: string): boolean {
  if (!f) return true;
  const hay = (it.raw + " " + it.hosts.join(" ") + " " + (it.program || "")).toLowerCase();
  return hay.includes(f);
}

export function WorklistItem({ it, section, onHost, onVerify, onDismiss }:
  { it: WLItem; section: WLSection; onHost: (h: string) => void;
    onVerify?: (h: string) => void; onDismiss?: (h: string) => void }) {
  const cmds = it.commands.length
    ? it.commands
    : (it.hosts[0] ? suggestedCommands(section.title, it.hosts[0]) : []);
  return (
    <div className={`rounded-lg border p-3 ${it.suppressed ? "border-[var(--color-border)] bg-[var(--color-panel)] opacity-60" : "border-[var(--color-border)] bg-[var(--color-panel-2)]"}`}>
      {/* affordance toolbar */}
      <div className="mb-2 flex flex-wrap items-center gap-1.5">
        {it.suppressed && <Badge color="var(--color-ink-faint)">hidden · {it.suppress_reason}</Badge>}
        {it.severity && (
          <Badge color={severityColor[it.severity] || "var(--color-ink-dim)"} filled>
            {it.severity.toUpperCase()}
          </Badge>
        )}
        {it.hosts.map((h) => (
          <button key={h} onClick={() => onHost(h)}
            className="mono rounded border border-[var(--color-border-bright)] bg-[var(--color-panel)] px-1.5 py-0.5 text-[11px] text-[var(--color-ink)] transition hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]"
            title="open host detail">
            {h}
          </button>
        ))}
        {it.program && <span className="text-[10px] text-[var(--color-ink-faint)]">[{it.program}]</span>}
        <div className="ml-auto flex items-center gap-1.5">
          {onVerify && it.hosts[0] && (
            <button onClick={() => onVerify(it.hosts[0])}
              className="rounded border border-[var(--color-accent)]/50 px-2 py-0.5 text-[10px] text-[var(--color-accent)] transition hover:bg-[var(--color-accent)]/10"
              title="run Claude verify on this host">
              ⚡ verify
            </button>
          )}
          {onDismiss && it.hosts[0] && !it.suppressed && (
            <button onClick={() => onDismiss(it.hosts[0])}
              className="rounded border border-[var(--color-border-bright)] px-2 py-0.5 text-[10px] text-[var(--color-ink-faint)] transition hover:border-[var(--color-bad)] hover:text-[var(--color-bad)]"
              title="mark FP / not-actionable — stop re-serving this host">
              ✕ not actionable
            </button>
          )}
        </div>
      </div>
      {/* the original briefing text (fidelity) */}
      <Markdown text={it.raw} />
      {/* copy-paste commands */}
      {cmds.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5 border-t border-[var(--color-border)] pt-2">
          {cmds.map((c, i) => <CopyChip key={i} text={c} label={c} />)}
        </div>
      )}
    </div>
  );
}

export function Worklist({ parsed, filter = "", onHost, onVerify, onDismiss, maxPerSection }:
  { parsed: Parsed; filter?: string; onHost: (h: string) => void;
    onVerify?: (h: string) => void; onDismiss?: (h: string) => void; maxPerSection?: number }) {
  const f = filter.trim().toLowerCase();
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set());
  const [showHidden, setShowHidden] = useState(false);
  const toggle = (id: number) =>
    setCollapsed((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });

  const hiddenTotal = parsed.sections.reduce(
    (a, s) => a + s.items.filter((it) => it.suppressed && itemMatches(it, f)).length, 0);

  const sections = parsed.sections
    .map((s) => ({ ...s, _items: s.items.filter((it) => itemMatches(it, f) && (showHidden || !it.suppressed)) }))
    .filter((s) => s._items.length > 0);

  if (parsed.error) return <Empty>parse error: {parsed.error}</Empty>;
  if (!sections.length && !hiddenTotal) return <Empty>{f ? "no worklist items match" : "no actionable items in this briefing"}</Empty>;

  return (
    <div className="space-y-3">
      {hiddenTotal > 0 && (
        <button onClick={() => setShowHidden((v) => !v)}
          className="flex w-full items-center gap-2 rounded-md border border-dashed border-[var(--color-border-bright)] px-3 py-1.5 text-[11px] text-[var(--color-ink-faint)] hover:text-[var(--color-ink-dim)]">
          <span>⊘</span>
          <span className="flex-1 text-left">{hiddenTotal} hidden — worked &amp; killed / benched (won't re-serve)</span>
          <span className="text-[var(--color-accent)]">{showHidden ? "hide" : "show"}</span>
        </button>
      )}
      {sections.map((s) => {
        const isOpen = !collapsed.has(s.id);
        const shown = maxPerSection ? s._items.slice(0, maxPerSection) : s._items;
        return (
          <div key={s.id} className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)]">
            <button onClick={() => toggle(s.id)}
              className="flex w-full items-center gap-2 border-b border-[var(--color-border)] px-3 py-2 text-left hover:bg-[var(--color-panel-2)]">
              <span className="text-sm">{s.emoji}</span>
              <span className="flex-1 text-xs font-semibold uppercase tracking-wider text-[var(--color-ink-dim)]">{s.title}</span>
              <Badge color={s._items.length ? "var(--color-accent)" : "var(--color-ink-faint)"}>{s._items.length}</Badge>
              <span className="text-[var(--color-ink-faint)]">{isOpen ? "▾" : "▸"}</span>
            </button>
            {isOpen && (
              <div className="space-y-2 p-3">
                {shown.map((it, i) => (
                  <WorklistItem key={i} it={it} section={s} onHost={onHost} onVerify={onVerify} onDismiss={onDismiss} />
                ))}
                {maxPerSection && s._items.length > maxPerSection && (
                  <div className="pl-1 text-[10px] text-[var(--color-ink-faint)]">+{s._items.length - maxPerSection} more in this section</div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
