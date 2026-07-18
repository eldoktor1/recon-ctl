import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { Badge } from "./ui";
import { stateColor, priorityColor } from "../format";

const PAGES: { label: string; to: string; hint: string }[] = [
  { label: "Command Center", to: "/", hint: "overview" },
  { label: "Findings", to: "/findings", hint: "triage" },
  { label: "Asset Explorer", to: "/assets", hint: "hosts / tech" },
  { label: "Leads", to: "/leads", hint: "active signals" },
  { label: "Notes", to: "/notes", hint: "worked-knowledge" },
  { label: "Target Board", to: "/targets", hint: "programs" },
  { label: "Digest", to: "/digest", hint: "ops audit" },
  { label: "Hunt Control", to: "/hunt", hint: "launch lanes" },
  { label: "Daemon / Ops", to: "/ops", hint: "controls" },
  { label: "Telemetry", to: "/telemetry", hint: "ai accuracy" },
  { label: "Reports", to: "/reports", hint: "review queue" },
  { label: "Settings", to: "/settings", hint: "token" },
];

interface Item { type: string; label: string; sub?: string; badge?: { text: string; color: string }; to: string }

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const [results, setResults] = useState<any>(null);
  const nav = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);

  // global Cmd/Ctrl-K
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault(); setOpen((o) => !o);
      } else if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);

  useEffect(() => { if (open) { setQ(""); setResults(null); setSel(0); setTimeout(() => inputRef.current?.focus(), 30); } }, [open]);

  // debounced global search
  useEffect(() => {
    if (q.trim().length < 2) { setResults(null); return; }
    const t = setTimeout(async () => {
      try { setResults(await api.get<any>(`/api/search?q=${encodeURIComponent(q.trim())}`)); } catch {}
    }, 180);
    return () => clearTimeout(t);
  }, [q]);

  const items: Item[] = useMemo(() => {
    const ql = q.trim().toLowerCase();
    const out: Item[] = [];
    for (const p of PAGES) {
      if (!ql || p.label.toLowerCase().includes(ql) || p.hint.includes(ql))
        out.push({ type: "page", label: p.label, sub: p.hint, to: p.to });
    }
    if (results) {
      for (const h of results.hosts || [])
        out.push({ type: "host", label: h.host, sub: h.triage_program,
          badge: h.triage_priority ? { text: h.triage_priority, color: priorityColor[h.triage_priority] } : undefined,
          to: `/assets?q=${encodeURIComponent(h.host)}` });
      for (const f of results.findings || [])
        out.push({ type: "finding", label: f.host, sub: `${f.vuln_class || ""} · ${f.state}`,
          badge: { text: f.state, color: stateColor[f.state] || "var(--color-ink-dim)" },
          to: `/findings?q=${encodeURIComponent(f.host)}` });
      for (const n of results.notes || [])
        out.push({ type: "note", label: n.host, sub: (n.note || "").slice(0, 60), to: `/notes?q=${encodeURIComponent(n.host)}` });
      for (const p of results.programs || [])
        out.push({ type: "program", label: p.name, sub: `${p.platform} · ${p.payout ? "$" + p.payout : "pays"}`, to: `/targets?q=${encodeURIComponent(p.name)}` });
    }
    return out;
  }, [q, results]);

  useEffect(() => { setSel((s) => Math.min(s, Math.max(0, items.length - 1))); }, [items.length]);

  if (!open) return null;

  const go = (it: Item) => { setOpen(false); nav(it.to); };
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(items.length - 1, s + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(0, s - 1)); }
    else if (e.key === "Enter" && items[sel]) { e.preventDefault(); go(items[sel]); }
  };

  const typeLabel: Record<string, string> = { page: "go to", host: "host", finding: "finding", note: "note", program: "program" };

  return (
    <div className="fixed inset-0 z-[60] flex items-start justify-center pt-[12vh]" onClick={() => setOpen(false)}>
      <div className="absolute inset-0 bg-black/60" />
      <div className="relative w-[min(92vw,620px)] overflow-hidden rounded-xl border border-[var(--color-border-bright)] bg-[var(--color-panel)] shadow-2xl fade-in" onClick={(e) => e.stopPropagation()}>
        <input ref={inputRef} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onKey}
          placeholder="jump to a page, host, finding, note, program…"
          className="mono w-full border-b border-[var(--color-border)] bg-transparent px-4 py-3.5 text-sm text-[var(--color-ink)] outline-none placeholder:text-[var(--color-ink-faint)]" />
        <div className="max-h-[52vh] overflow-auto p-1.5">
          {items.length === 0 ? (
            <div className="px-3 py-6 text-center text-xs text-[var(--color-ink-faint)]">{q.length < 2 ? "type to search everything" : "no matches"}</div>
          ) : items.map((it, i) => (
            <button key={i} onMouseEnter={() => setSel(i)} onClick={() => go(it)}
              className={`flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-left ${i === sel ? "bg-[var(--color-accent)]/12" : ""}`}>
              <span className="mono w-14 shrink-0 text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]">{typeLabel[it.type]}</span>
              <span className="mono flex-1 truncate text-sm text-[var(--color-ink)]">{it.label}</span>
              {it.badge && <Badge color={it.badge.color}>{it.badge.text}</Badge>}
              {it.sub && <span className="max-w-[42%] truncate text-[11px] text-[var(--color-ink-faint)]">{it.sub}</span>}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-3 border-t border-[var(--color-border)] px-3 py-1.5 text-[10px] text-[var(--color-ink-faint)]">
          <span>↑↓ move</span><span>↵ open</span><span>esc close</span><span className="ml-auto mono">⌘K</span>
        </div>
      </div>
    </div>
  );
}
