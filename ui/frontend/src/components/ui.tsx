import type { ReactNode } from "react";

export function Panel({ title, right, children, className = "" }:
  { title?: ReactNode; right?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] ${className}`}>
      {title && (
        <div className="flex items-center justify-between border-b border-[var(--color-border)] px-4 py-2.5">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--color-ink-dim)]">{title}</h3>
          {right}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
}

export function Stat({ label, value, sub, color }:
  { label: string; value: ReactNode; sub?: ReactNode; color?: string }) {
  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] px-4 py-3">
      <div className="text-[11px] font-medium uppercase tracking-wider text-[var(--color-ink-faint)]">{label}</div>
      <div className="mono mt-1 text-2xl font-semibold leading-none" style={color ? { color } : undefined}>{value}</div>
      {sub && <div className="mt-1.5 text-xs text-[var(--color-ink-dim)]">{sub}</div>}
    </div>
  );
}

export function Dot({ color, pulse = false }: { color: string; pulse?: boolean }) {
  return (
    <span
      className={`inline-block h-2 w-2 rounded-full ${pulse ? "live-dot" : ""}`}
      style={{ background: color, boxShadow: `0 0 6px ${color}` }}
    />
  );
}

export function Badge({ children, color = "var(--color-ink-dim)", filled = false, title }:
  { children: ReactNode; color?: string; filled?: boolean; title?: string }) {
  return (
    <span
      title={title}
      className="mono inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium"
      style={
        filled
          ? { background: color, color: "#0a0e14" }
          : { color, border: `1px solid ${color}44`, background: `${color}14` }
      }
    >
      {children}
    </span>
  );
}

export function Pill({ label, value, color, pulse }:
  { label: string; value: string; color: string; pulse?: boolean }) {
  return (
    <div className="flex items-center gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-1.5">
      <Dot color={color} pulse={pulse} />
      <span className="text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">{label}</span>
      <span className="mono text-xs font-semibold text-[var(--color-ink)]">{value}</span>
    </div>
  );
}

export function Empty({ children, hint }: { children: ReactNode; hint?: ReactNode }) {
  return (
    <div className="py-10 text-center">
      <div className="text-sm text-[var(--color-ink-faint)]">{children}</div>
      {hint && <div className="mt-1.5 text-xs text-[var(--color-ink-faint)] opacity-70">{hint}</div>}
    </div>
  );
}

// Clickable sortable table header. `sortKey` set => active-column arrow + toggle.
// Columns whose key isn't in the backend's allowed set pass no `col` (static).
export function SortTh({ label, col, active, order, onSort, align = "left", className = "" }:
  { label: string; col?: string; active?: string; order?: "asc" | "desc";
    onSort?: (col: string) => void; align?: "left" | "right"; className?: string }) {
  const isActive = !!col && col === active;
  const arrow = isActive ? (order === "asc" ? "▲" : "▼") : "";
  const clickable = !!col && !!onSort;
  return (
    <th className={`px-2 py-2 font-medium ${align === "right" ? "text-right" : "text-left"} ${clickable ? "cursor-pointer select-none hover:text-[var(--color-ink-dim)]" : ""} ${isActive ? "text-[var(--color-accent)]" : ""} ${className}`}
      onClick={clickable ? () => onSort!(col!) : undefined}
      title={clickable ? `sort by ${label}` : undefined}>
      <span className="inline-flex items-center gap-1">{label}{arrow && <span className="text-[9px]">{arrow}</span>}</span>
    </th>
  );
}

export function Spinner() {
  return (
    <div className="flex items-center justify-center py-8">
      <div className="h-5 w-5 animate-spin rounded-full border-2 border-[var(--color-border-bright)] border-t-[var(--color-accent)]" />
    </div>
  );
}
