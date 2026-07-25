// Thin API client. Token is kept in localStorage and sent on mutating routes.

import { isDemo, demoGet, demoAction } from "./demo";

const TOKEN_KEY = "recon_ui_token";

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) || "";
}
export function setToken(t: string) {
  localStorage.setItem(TOKEN_KEY, t.trim());
}
export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}
// Verify a token against the backend; returns true if accepted.
export async function verifyToken(t: string): Promise<boolean> {
  try {
    const r = await fetch("/api/status", { headers: { "X-Recon-Token": t.trim() } });
    return r.ok;
  } catch {
    return false;
  }
}

async function req<T>(path: string, opts: RequestInit = {}, _auth = false): Promise<T> {
  // Demo mode: serve synthetic fixtures without touching the backend.
  if (isDemo()) {
    const method = (opts.method || "GET").toUpperCase();
    if (method === "GET") {
      const fix = demoGet(path);
      if (fix !== undefined) return fix as T;
    } else {
      return demoAction() as unknown as T;
    }
  }
  const headers: Record<string, string> = { ...(opts.headers as any) };
  if (opts.body) headers["Content-Type"] = "application/json";
  // token is required on every /api route (reads included)
  const tok = getToken();
  if (tok) headers["X-Recon-Token"] = tok;
  const r = await fetch(path, { ...opts, headers });
  if (!r.ok) {
    let detail = r.statusText;
    try {
      detail = (await r.json()).detail || detail;
    } catch {}
    // token rotated/invalidated mid-session -> drop it and return to the unlock gate
    if (r.status === 401 && getToken()) {
      clearToken();
      location.reload();
    }
    throw new ApiError(r.status, detail);
  }
  const ct = r.headers.get("content-type") || "";
  return (ct.includes("json") ? await r.json() : ((await r.text()) as any)) as T;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export const api = {
  get: <T>(p: string) => req<T>(p),
  post: <T>(p: string, body?: any) =>
    req<T>(p, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
  // mutating action — always carries the explicit confirm flag the backend requires
  action: <T>(p: string, body: any = {}) =>
    req<T>(p, { method: "POST", body: JSON.stringify({ ...body, confirm: true }) }),
};

// --- types (partial, expand per phase) ---
export interface Status {
  daemon: { pid: number | null; alive: boolean; uptime_sec: number | null; lane_procs: number;
    maintenance: boolean; disabled: boolean; keepalive_tripped: boolean };
  vpn: { up: boolean; down: boolean; reason: string | null };
  es: { status?: string; nodes?: number; active_shards?: number; unassigned_shards?: number;
    docs?: number; reachable: boolean; error?: string };
  queue: Record<string, number>;
  killswitches: { lane: string; killed: boolean; since: number }[];
  findings_by_state: Record<string, number>;
}

export interface Overview extends Status {
  recent_confirmed: Finding[];
  tonight: { name: string; date: string | null; preview: string[]; line_count: number } | null;
}

export interface Finding {
  id: number; host: string; url?: string; program?: string;
  signal_class?: string; vuln_class?: string; state: string; score?: number;
  priority?: string | null; confidence?: number; ai_verdict?: string;
  ai_confidence?: number; resolution?: string | null; bounty?: number;
  created_at?: string; updated_at?: string; state_changed_at?: string;
}

// Live per-lane activity row (GET /api/lanes/activity).
export interface LaneActivity {
  lane: string; desc: string; target: boolean; killed: boolean;
  yield_count: number; last_yield_at: string | number | null; running: boolean;
}

// AI provider config (GET /api/claude/config).
export interface ClaudeConfig {
  provider?: string; providers?: string[]; wired?: boolean;
  model?: string; auth?: string;
}

// --- Program Workspace (GET /api/workspaces + /api/workspaces/{key}) ----------
export interface WsCounts {
  wstg_total: number; wstg_done: number; wstg_inprogress: number;
  findings: number; hosts: number; classes_done: number;
}
export interface WorkspaceSummary {
  key: string; name: string; platform?: string; status: string;
  current: boolean; added_at?: string; counts: WsCounts;
}
export interface WorkspaceCandidate { key: string; name: string; platform?: string; score?: number }
export interface WorkspacesResp { workspaces: WorkspaceSummary[]; candidates: WorkspaceCandidate[] }

// status ∈ todo | in-progress | done | na | finding
export interface WstgItem {
  id: string; category: string; cat_name: string; name: string;
  status: string; note?: string; updated_at?: string;
}
export interface StrideThreat {
  id?: string; threat: string; note?: string; status?: string; hosts?: string[];
}
export interface StrideBoard {
  S: StrideThreat[]; T: StrideThreat[]; R: StrideThreat[];
  I: StrideThreat[]; D: StrideThreat[]; E: StrideThreat[];
}
export interface ClassProgress { cls: string; status: string }
export interface WsNote { ts: string; text: string }
export interface WsEvent { ts: string; event: string }
// ES asset row scoped to the program (partial — only what the table renders).
export interface WsHost {
  host: string; triage_program?: string; triage_priority?: string; triage_score?: number;
  triage_classes?: string[]; triage_pays?: boolean; triage_in_scope?: boolean;
  triage_kev_match?: boolean; triage_true_fresh?: boolean; js_secret_hit?: boolean;
  takeover_confirmed?: boolean; tech?: string[]; host_notes_count?: number;
}
export interface WorkspaceDetail {
  key: string; name: string; platform?: string; status: string; current: boolean; added_at?: string;
  wstg: WstgItem[]; stride: StrideBoard; classes: ClassProgress[];
  notes: WsNote[]; history: WsEvent[]; hosts: WsHost[]; findings: Finding[];
}
