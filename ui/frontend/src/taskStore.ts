// Persist "which task is active for a given UI context" across navigation, so a running
// (or already-finished) agent stream can be RECONNECTED instead of re-spawned — re-spawning
// wastes tokens. The backend keeps the task running independent of any WebSocket and replays
// its full buffered output on reconnect (subscribe() in tasks.py), so all the frontend has to
// do is remember the tid and open the socket again.

const TASK_KEY = "recon_active_tasks";
const NUM_KEY = "recon_ui_nums";
const DONE_KEY = "recon_task_done";
const TTL_MS = 6 * 3600_000; // tasks are pruned server-side (~60 kept); expire our refs after 6h

type Entry = { tid: number; ts: number };

function readObj<T>(key: string): T {
  try { return JSON.parse(localStorage.getItem(key) || "{}"); } catch { return {} as T; }
}
function writeObj(key: string, v: unknown) {
  try { localStorage.setItem(key, JSON.stringify(v)); } catch { /* quota/private mode */ }
}

// --- active-task association (key -> tid) ---
export function getTask(key: string): number | null {
  const e = (readObj<Record<string, Entry>>(TASK_KEY))[key];
  return e && Date.now() - e.ts < TTL_MS ? e.tid : null;
}
export function setTask(key: string, tid: number) {
  const s = readObj<Record<string, Entry>>(TASK_KEY);
  s[key] = { tid, ts: Date.now() };
  writeObj(TASK_KEY, s);
}
export function clearTask(key: string) {
  const s = readObj<Record<string, Entry>>(TASK_KEY);
  if (key in s) { delete s[key]; writeObj(TASK_KEY, s); }
}

// --- small persisted numbers (e.g. the current guided step per workspace) ---
export function getNum(key: string, fallback = 0): number {
  const v = (readObj<Record<string, number>>(NUM_KEY))[key];
  return typeof v === "number" ? v : fallback;
}
export function setNum(key: string, n: number) {
  const s = readObj<Record<string, number>>(NUM_KEY);
  s[key] = n;
  writeObj(NUM_KEY, s);
}

// --- idempotent "already handled this task's completion" guard (per tid) ---
// Returns true the FIRST time a tid is seen (caller should act on completion), false after —
// so reconnecting to a finished task doesn't re-run side effects (e.g. re-record a note).
export function claimDone(tid: number): boolean {
  try {
    const arr: number[] = JSON.parse(localStorage.getItem(DONE_KEY) || "[]");
    if (arr.includes(tid)) return false;
    arr.push(tid);
    localStorage.setItem(DONE_KEY, JSON.stringify(arr.slice(-300)));
    return true;
  } catch { return true; }
}
