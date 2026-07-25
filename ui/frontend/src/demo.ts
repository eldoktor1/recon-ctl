// Demo mode — renders the whole UI fully populated WITHOUT a live backend or
// token. Enable with ?demo=1 in the URL or the Settings toggle (localStorage).
// Fixtures are obviously synthetic (example.com hosts, fake findings) so nobody
// mistakes a screenshot for real target data.

const DEMO_KEY = "recon_demo";

export function isDemo(): boolean {
  try {
    if (typeof location !== "undefined" && new URLSearchParams(location.search).has("demo")) return true;
    return localStorage.getItem(DEMO_KEY) === "1";
  } catch {
    return false;
  }
}
export function setDemo(on: boolean) {
  try {
    if (on) localStorage.setItem(DEMO_KEY, "1");
    else localStorage.removeItem(DEMO_KEY);
  } catch { /* ignore */ }
}

// --- fixtures ----------------------------------------------------------------
const now = Date.now();
const ago = (m: number) => new Date(now - m * 60_000).toISOString();

const STATUS = {
  daemon: { pid: 4242, alive: true, uptime_sec: 187_400, lane_procs: 12, maintenance: false, disabled: false, keepalive_tripped: false },
  vpn: { up: true, down: false, reason: null },
  es: { status: "green", nodes: 1, active_shards: 24, unassigned_shards: 0, docs: 2_793_411, reachable: true },
  queue: { inbox: 38, done: 15_204 },
  killswitches: [{ lane: "v2_permute", killed: true, since: now / 1000 - 3600 }],
  findings_by_state: { confirmed: 3, reported: 2, submitted: 5, verifying: 1, scored: 41, discovered: 128, dismissed: 96, lead_exhausted: 60 },
};

const FINDINGS = [
  { id: 6001, host: "api.acme-demo.example.com", url: "https://api.acme-demo.example.com/v2/orders/1042", program: "Acme (demo)", vuln_class: "idor", state: "confirmed", score: 82, priority: "P1", ai_verdict: "real", ai_confidence: 0.91, created_at: ago(180), updated_at: ago(40), state_changed_at: ago(40) },
  { id: 6002, host: "shop.globex-demo.example.com", url: "https://shop.globex-demo.example.com/search?q=", program: "Globex (demo)", vuln_class: "xss", state: "reported", score: 74, priority: "P2", ai_verdict: "real", ai_confidence: 0.87, created_at: ago(600), updated_at: ago(120), state_changed_at: ago(120) },
  { id: 6003, host: "gql.initech-demo.example.com", url: "https://gql.initech-demo.example.com/graphql", program: "Initech (demo)", vuln_class: "graphql", state: "submitted", score: 69, priority: "P2", ai_verdict: "real", ai_confidence: 0.8, created_at: ago(2400), updated_at: ago(300), state_changed_at: ago(300) },
  { id: 6004, host: "assets.hooli-demo.example.com", program: "Hooli (demo)", vuln_class: "bucket", state: "verifying", score: 61, priority: "P3", ai_verdict: "needs-human", ai_confidence: 0.55, created_at: ago(90), updated_at: ago(20), state_changed_at: ago(20) },
  { id: 6005, host: "legacy.umbrella-demo.example.com", url: "https://legacy.umbrella-demo.example.com/", program: "Umbrella (demo)", vuln_class: "takeover", state: "scored", score: 58, priority: "P3", ai_verdict: "fp", ai_confidence: 0.7, created_at: ago(5000), updated_at: ago(1400), state_changed_at: ago(1400) },
];

const ASSETS = Array.from({ length: 24 }).map((_, i) => {
  const progs = ["Acme (demo)", "Globex (demo)", "Initech (demo)", "Hooli (demo)"];
  const techs = [["nginx", "react"], ["apache", "php", "wordpress"], ["spring", "java"], ["graphql", "node"]];
  const pris = ["P1", "P2", "P2", "P3", "P3"];
  return {
    host: `host${i + 1}.${["acme", "globex", "initech", "hooli"][i % 4]}-demo.example.com`,
    triage_program: progs[i % 4],
    triage_priority: pris[i % 5],
    triage_score: 90 - i * 2,
    triage_classes: [["idor"], ["xss", "sqli"], ["graphql"], ["ssrf"]][i % 4],
    triage_kev_match: i % 7 === 0,
    triage_true_fresh: i % 5 === 0,
    triage_pays: true,
    triage_in_scope: true,
    triage_ignored: false,
    takeover_confirmed: i % 11 === 0,
    js_secret_hit: i % 6 === 0,
    tech: techs[i % 4],
    host_notes_count: i % 4 === 0 ? (i % 3) + 1 : 0,
  };
});

const LANES = [
  { lane: "jsintel", desc: "mine each host's JS for the hidden API surface (jsluice + sourcemapper)", target: true, killed: false, yield_count: 214, last_yield_at: ago(6), running: true },
  { lane: "ai-hunter", desc: "Claude reasons over endpoints → ranked BAC/IDOR hypotheses → safe probes", target: true, killed: false, yield_count: 31, last_yield_at: ago(22), running: true },
  { lane: "params", desc: "XSS/SQLi reflected-param crawl + catalog (producer/consumer)", target: true, killed: false, yield_count: 88, last_yield_at: ago(14), running: true },
  { lane: "graphql", desc: "introspection schema → sensitive mutation/IDOR/injection worklist", target: true, killed: false, yield_count: 12, last_yield_at: ago(50), running: false },
  { lane: "buckets", desc: "provenance-seeded cloud-bucket exposure (read-only S3Scanner)", target: true, killed: false, yield_count: 4, last_yield_at: ago(180), running: false },
  { lane: "nday", desc: "version-reason KEV/CVE matches in the race window", target: true, killed: false, yield_count: 7, last_yield_at: ago(120), running: true },
  { lane: "permute", desc: "alterx permutations → puredns resolve → new in-scope hosts", target: false, killed: true, yield_count: 0, last_yield_at: null, running: false },
  { lane: "uncover", desc: "Shodan/Censys dorks scoped to in-scope certs → new hosts", target: false, killed: false, yield_count: 2, last_yield_at: ago(400), running: false },
  { lane: "blindxss", desc: "persistent interactsh collector + crafted per-host beacon", target: true, killed: false, yield_count: 0, last_yield_at: null, running: true },
  { lane: "wcd", desc: "safe detect-only web-cache deception/poisoning surfacer", target: true, killed: false, yield_count: 1, last_yield_at: ago(900), running: false },
  { lane: "ghleaks", desc: "GitHub code-search → trufflehog-verify live leaked secrets", target: false, killed: false, yield_count: 9, last_yield_at: ago(240), running: false },
  { lane: "research", desc: "Claude web-research: new CVEs/tools/KB (Anthropic→web, not target)", target: false, killed: false, yield_count: 5, last_yield_at: ago(60), running: true },
  { lane: "selfaudit", desc: "~25 invariant checks → dated report (dry every 6h)", target: false, killed: false, yield_count: 0, last_yield_at: ago(360), running: false },
  { lane: "briefing", desc: "6:30pm ranked TONIGHT card (BAC/IDOR + ready-to-submit)", target: false, killed: false, yield_count: 1, last_yield_at: ago(30), running: false },
];

const HOST_ACTIONS = [
  { action: "verify", target: true, desc: "run the Claude multimodal verify + safe probes" },
  { action: "crawl", target: true, desc: "katana + gau + CDX param crawl of this host" },
  { action: "confirm-xss", target: true, desc: "dalfox — reflected XSS must EXECUTE (not just reflect)" },
  { action: "confirm-sqli", target: true, desc: "safe ' vs '' differential, then sqlmap to verify" },
  { action: "arjun", target: true, desc: "active hidden-parameter discovery (polite, GET-only)" },
  { action: "domxss", target: true, desc: "DOM-XSS source→sink miner (dalfox deep-domxss)" },
  { action: "graphql", target: true, desc: "introspection schema → ranked worklist" },
  { action: "wcd", target: true, desc: "web-cache deception detect (unique cache-buster)" },
];

const LEAD_BUCKETS = {
  buckets: [
    { key: "takeover", label: "dangling / takeover leads", count: 2, hosts: [
      { host: "legacy.umbrella-demo.example.com", triage_priority: "P2", triage_score: 58, triage_pays: true, triage_in_scope: true },
      { host: "old-cdn.hooli-demo.example.com", triage_priority: "P3", triage_score: 44, triage_pays: true, triage_in_scope: true },
    ] },
    { key: "secrets", label: "live leaked secrets (verified)", count: 1, hosts: [
      { host: "app.initech-demo.example.com", triage_priority: "P1", triage_score: 77, triage_pays: true, triage_in_scope: true },
    ] },
    { key: "kev", label: "KEV / n-day candidates", count: 1, hosts: [
      { host: "gw.acme-demo.example.com", triage_priority: "P2", triage_score: 66, triage_pays: true, triage_in_scope: true },
    ] },
    { key: "fresh", label: "fresh CT-surfaced hosts", count: 3, hosts: [
      { host: "new1.globex-demo.example.com", triage_priority: "P2", triage_score: 62, triage_pays: true, triage_in_scope: true },
      { host: "new2.globex-demo.example.com", triage_priority: "P3", triage_score: 51, triage_pays: true, triage_in_scope: true },
      { host: "beta.acme-demo.example.com", triage_priority: "P3", triage_score: 49, triage_pays: true, triage_in_scope: true },
    ] },
  ],
  suppressed: 7,
};

const BRIEFINGS = [
  { name: "tonight_2026-07-25.md", kind: "tonight", date: "2026-07-25", mtime: now / 1000 - 1800 },
  { name: "idor_candidates_2026-07-25.md", kind: "idor_candidates", date: "2026-07-25", mtime: now / 1000 - 2000 },
  { name: "xss_candidates_2026-07-25.md", kind: "xss_candidates", date: "2026-07-25", mtime: now / 1000 - 2100 },
];

function parsedBriefing(name: string) {
  const kind = name.split("_")[0];
  if (kind === "idor") {
    return { name, kind: "idor_candidates", date: "2026-07-25", title: "IDOR candidates", sections: [
      { id: 1, emoji: "🎯", title: "IDOR / BOLA — ranked", count: 2, items: [
        { raw: "**api.acme-demo.example.com** `/v2/orders/{id}` — numeric object-ref, financial, enumerable. 2-account swap.", label: "/v2/orders/{id} numeric object-ref, financial — 2-account swap", hosts: ["api.acme-demo.example.com"], commands: [], program: "Acme (demo)", severity: "high" },
        { raw: "**app.initech-demo.example.com** `/api/users/{uuid}/profile` — uuid harvestable via JS endpoint list.", label: "/api/users/{uuid}/profile — uuid harvestable", hosts: ["app.initech-demo.example.com"], commands: [], program: "Initech (demo)", severity: "medium" },
      ] },
    ] };
  }
  if (kind === "xss") {
    return { name, kind: "xss_candidates", date: "2026-07-25", title: "XSS candidates", sections: [
      { id: 1, emoji: "⚡", title: "XSS — top unique lanes", count: 2, items: [
        { raw: "**shop.globex-demo.example.com** `?q=` reflects unencoded in HTML context — dalfox confirm.", label: "?q= reflects unencoded — dalfox confirm", hosts: ["shop.globex-demo.example.com"], commands: ["recon-params confirm xss shop.globex-demo.example.com"], program: "Globex (demo)", severity: "high" },
        { raw: "**api.acme-demo.example.com** `?redirect=` open-redirect + reflection candidate.", label: "?redirect= open-redirect + reflection candidate", hosts: ["api.acme-demo.example.com"], commands: [], program: "Acme (demo)", severity: "medium" },
      ] },
    ] };
  }
  return { name, kind: "tonight", date: "2026-07-25", title: "Tonight", sections: [
    { id: 1, emoji: "🎯", title: "BAC / IDOR to test", count: 2, items: [
      { raw: "**api.acme-demo.example.com** `/v2/orders/{id}` — numeric object-ref, financial. Own two accounts → swap.", label: "/v2/orders/{id} — numeric object-ref, financial", hosts: ["api.acme-demo.example.com"], commands: [], program: "Acme (demo)", severity: "high" },
      { raw: "**gql.initech-demo.example.com** unauth GraphQL mutation `deleteInvoice` reachable — human confirm.", label: "unauth GraphQL mutation deleteInvoice reachable", hosts: ["gql.initech-demo.example.com"], commands: ["recon-graphql gql.initech-demo.example.com"], program: "Initech (demo)", severity: "elite" },
    ] },
    { id: 2, emoji: "⚡", title: "XSS / SQLi reflected-param", count: 1, items: [
      { raw: "**shop.globex-demo.example.com** `?q=` reflects unencoded — dalfox confirm.", label: "?q= reflects unencoded — dalfox confirm", hosts: ["shop.globex-demo.example.com"], commands: ["recon-params confirm xss shop.globex-demo.example.com"], program: "Globex (demo)", severity: "high" },
    ] },
    { id: 3, emoji: "📦", title: "cloud-bucket exposure", count: 1, items: [
      { raw: "**assets.hooli-demo.example.com** references `hooli-demo-uploads` — public-read, verify sensitivity.", label: "hooli-demo-uploads public-read — verify content sensitivity", hosts: ["assets.hooli-demo.example.com"], commands: [], program: "Hooli (demo)", severity: "lead" },
    ] },
  ] };
}

const CLAUDE_CONFIG = {
  provider: "anthropic",
  providers: ["anthropic", "openai", "google", "local"],
  wired: true,
  model: "claude-opus-4-8",
  auth: "max-oauth",
};

const LANE_LOG = {
  lines: [
    "[jsintel] cycle start — 42 in-scope+paying hosts queued",
    "[jsintel] host=api.acme-demo.example.com — 3 .map reconstructed, 61 endpoints",
    "[jsintel] host=api.acme-demo.example.com — jsluice urls: +14 (graphql, extranet)",
    "[jsintel] trufflehog --only-verified: 0 live secrets (1 candidate → review)",
    "[jsintel] host=shop.globex-demo.example.com — 22 endpoints, 0 secrets",
    "[jsintel] yield: +37 endpoints written to endpoints.jsonl",
    "[jsintel] cycle done in 214s — sleeping",
  ],
};

// --- resolver ----------------------------------------------------------------
// Return a fixture for a GET path, or undefined to fall through to real fetch.
export function demoGet(path: string): unknown | undefined {
  const p = path.split("?")[0];
  if (p === "/api/status") return STATUS;
  if (p === "/api/overview") return { ...STATUS, recent_confirmed: FINDINGS.filter((f) => f.state === "confirmed" || f.state === "reported"), tonight: { name: BRIEFINGS[0].name, date: "2026-07-25", preview: [], line_count: 24 } };
  if (p === "/api/leads") return LEAD_BUCKETS;
  if (p === "/api/briefings") return BRIEFINGS;
  if (p === "/api/tonight") return parsedBriefing("tonight");
  if (p.startsWith("/api/briefings/") && p.endsWith("/parsed")) {
    const name = decodeURIComponent(p.slice("/api/briefings/".length, -"/parsed".length));
    return parsedBriefing(name);
  }
  if (p.startsWith("/api/briefings/")) return { body: "# demo briefing\n\nSynthetic briefing content for demo mode." };
  if (p === "/api/assets/facets") return { programs: [{ value: "Acme (demo)", count: 6 }, { value: "Globex (demo)", count: 6 }, { value: "Initech (demo)", count: 6 }, { value: "Hooli (demo)", count: 6 }], classes: [{ value: "idor", count: 6 }, { value: "xss", count: 6 }, { value: "graphql", count: 6 }], priorities: [{ value: "P1", count: 5 }, { value: "P2", count: 9 }, { value: "P3", count: 10 }] };
  if (p === "/api/assets") return { total: ASSETS.length, items: ASSETS };
  if (p.startsWith("/api/assets/")) { const h = decodeURIComponent(p.slice("/api/assets/".length)); return ASSETS.find((a) => a.host === h) || ASSETS[0]; }
  if (p === "/api/findings/facets") return { state: ["confirmed", "reported", "submitted", "verifying", "scored"], program: ["Acme (demo)", "Globex (demo)", "Initech (demo)", "Hooli (demo)"], vuln_class: ["idor", "xss", "graphql", "bucket", "takeover"], ai_verdict: ["real", "fp", "needs-human"] };
  if (p === "/api/findings") return { total: FINDINGS.length, items: FINDINGS, limit: 60, offset: 0 };
  if (p.startsWith("/api/findings/")) { const id = parseInt(p.slice("/api/findings/".length), 10); return FINDINGS.find((f) => f.id === id) || FINDINGS[0]; }
  if (p === "/api/lanes/activity") return LANES;
  if (p.startsWith("/api/lanes/") && p.endsWith("/log")) return LANE_LOG;
  if (p === "/api/lanes") return LANES.filter((l) => l.target).map((l) => ({ lane: l.lane, sub: l.lane, target: l.target, desc: l.desc }));
  if (p === "/api/host-actions") return HOST_ACTIONS;
  if (p === "/api/claude/config") return CLAUDE_CONFIG;
  if (p === "/api/tasks") return [];
  if (p === "/api/selfaudit") return { summary: { high: 0, medium: 1, checks: 25, ok: 24 }, _age_sec: 3600 };
  if (p === "/api/logs") return { lines: LANE_LOG.lines };
  if (p.startsWith("/api/scope/")) return { result: "in-scope: true · pays: true · program: Acme (demo)" };
  return undefined;
}

// Mutating POSTs in demo mode just acknowledge (with a fake task id).
export function demoAction(): { ok: true; id: number } {
  return { ok: true, id: Math.floor(Math.random() * 9000) + 1000 };
}
