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

export function Badge({ children, color = "var(--color-ink-dim)", filled = false }:
  { children: ReactNode; color?: string; filled?: boolean }) {
  return (
    <span
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

export function Empty({ children }: { children: ReactNode }) {
  return <div className="py-8 text-center text-sm text-[var(--color-ink-faint)]">{children}</div>;
}

export function Spinner() {
  return (
    <div className="flex items-center justify-center py-8">
      <div className="h-5 w-5 animate-spin rounded-full border-2 border-[var(--color-border-bright)] border-t-[var(--color-accent)]" />
    </div>
  );
}
