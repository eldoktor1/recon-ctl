export function fmtDuration(sec: number | null | undefined): string {
  if (sec == null) return "—";
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// Coerce a possibly-scalar ES field (tech/classes can be string or array) to an array.
export function asArr(v: any): any[] {
  return Array.isArray(v) ? v : v == null || v === "" ? [] : [v];
}

export function fmtNum(n: number | null | undefined): string {
  if (n == null) return "—";
  return n.toLocaleString();
}

export function fmtAgo(ts: string | number | null | undefined): string {
  if (ts == null) return "—";
  const then = typeof ts === "number" ? ts * 1000 : Date.parse(ts);
  if (isNaN(then)) return "—";
  const s = Math.floor((Date.now() - then) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const priorityColor: Record<string, string> = {
  P0: "var(--color-p0)",
  P1: "var(--color-p1)",
  P2: "var(--color-p2)",
  P3: "var(--color-p3)",
};

export const stateColor: Record<string, string> = {
  confirmed: "var(--color-good)",
  reported: "var(--color-info)",
  submitted: "var(--color-accent)",
  verifying: "var(--color-warn)",
  scored: "var(--color-ink-dim)",
  discovered: "var(--color-ink-faint)",
  dismissed: "var(--color-ink-faint)",
  lead_exhausted: "var(--color-ink-faint)",
};

export const verdictColor: Record<string, string> = {
  real: "var(--color-good)",
  fp: "var(--color-bad)",
  "needs-human": "var(--color-warn)",
};
