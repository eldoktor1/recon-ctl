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

// Severity tags parsed out of briefing worklist items ([elite]/[HIGH]/LEAD/…).
export const severityColor: Record<string, string> = {
  critical: "var(--color-bad)",
  elite: "var(--color-accent)",
  high: "var(--color-p1)",
  medium: "var(--color-p2)",
  low: "var(--color-p3)",
  lead: "var(--color-warn)",
  p0: "var(--color-p0)",
  p1: "var(--color-p1)",
  p2: "var(--color-p2)",
  p3: "var(--color-p3)",
};

// Rough ordering so a merged (deduped) lead can keep the strongest severity tag.
const SEVERITY_RANK: Record<string, number> = {
  critical: 6, p0: 6, elite: 5, high: 5, p1: 5, medium: 3, p2: 3,
  lead: 2, low: 1, p3: 1,
};
export function severityRank(s?: string | null): number {
  return s ? SEVERITY_RANK[s.toLowerCase()] ?? 0 : 0;
}

// Vuln-class → accent color for the compact lead tag.
export const classColor: Record<string, string> = {
  xss: "var(--color-p1)",
  sqli: "var(--color-bad)",
  idor: "var(--color-accent)",
  bola: "var(--color-accent)",
  bac: "var(--color-accent)",
  graphql: "var(--color-info)",
  ssrf: "var(--color-bad)",
  takeover: "var(--color-bad)",
  secret: "var(--color-warn)",
  cache: "var(--color-info)",
  wcd: "var(--color-info)",
  kev: "var(--color-bad)",
  nday: "var(--color-p1)",
  bucket: "var(--color-warn)",
};

// Derive a vuln-class token from a briefing section title (for the compact tag
// + the class-scoped Mark-FP dead note).
export function classFromSection(title?: string | null): string | null {
  if (!title) return null;
  const t = title.toLowerCase();
  if (t.includes("xss")) return "xss";
  if (t.includes("sqli") || t.includes("sql injection")) return "sqli";
  if (t.includes("graphql")) return "graphql";
  if (t.includes("idor") || t.includes("bola")) return "idor";
  if (t.includes("bac") || t.includes("access control") || t.includes("privesc")) return "bac";
  if (t.includes("ssrf")) return "ssrf";
  if (t.includes("takeover")) return "takeover";
  if (t.includes("secret") || t.includes("leak")) return "secret";
  if (t.includes("cache") || t.includes("wcd")) return "cache";
  if (t.includes("bucket") || t.includes("s3")) return "bucket";
  if (t.includes("kev") || t.includes("cve") || t.includes("n-day") || t.includes("nday")) return "nday";
  return null;
}
