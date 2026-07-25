import { useFetch } from "../hooks";
import { api } from "../api";
import { useToast } from "./controls";

export interface HostAction { action: string; target: boolean; desc: string }

// Fetch the target-facing action whitelist once; shared by every lead row.
export function useHostActions() {
  return useFetch<HostAction[]>("/api/host-actions").data || [];
}

// Prettier labels for the action buttons.
const LABEL: Record<string, string> = {
  verify: "Verify", crawl: "Crawl", "confirm-xss": "XSS", "confirm-sqli": "SQLi",
  arjun: "Arjun", domxss: "DOM-XSS", graphql: "GraphQL", wcd: "WCD",
};
// Which actions surface as primary buttons vs. the overflow menu.
const PRIMARY = ["verify", "confirm-xss", "confirm-sqli"];

// Compact, keyboard-friendly per-lead testing controls. Every button maps to a
// backend endpoint — test straight from the worklist, no trip to the Co-Pilot.
export function LeadActions({ host, vulnClass, actions, onTask, onChanged }:
  { host: string; vulnClass?: string | null; actions: HostAction[];
    onTask?: (tid: number) => void; onChanged?: () => void }) {
  const toast = useToast();
  const enc = encodeURIComponent(host);

  // target-facing test — spawns a task, streams into the shared TaskConsole.
  const run = async (action: string) => {
    try {
      const t = await api.action<{ id: number }>(`/api/hosts/${enc}/run`, { action });
      toast("ok", `${LABEL[action] || action} #${t.id} — streaming below`);
      onTask?.(t.id);
    } catch (e: any) { toast("err", e.message); }
  };

  const markFP = async () => {
    const r = prompt(`Mark ${host}${vulnClass ? ` (${vulnClass})` : ""} as FALSE POSITIVE.\nWrites a class-scoped dead note. Optional reason:`, "");
    if (r === null) return; // cancelled
    try {
      await api.action(`/api/hosts/${enc}/dismiss`, { kind: "fp", vuln_class: vulnClass || undefined, reason: r || undefined });
      toast("ok", `${host} marked FP${vulnClass ? ` · ${vulnClass}` : ""} — won't re-serve`);
      onChanged?.();
    } catch (e: any) { toast("err", e.message); }
  };

  const note = async () => {
    const t = prompt(`Note for ${host}:`);
    if (!t) return;
    try { await api.action(`/api/hosts/${enc}/note`, { text: t }); toast("ok", "note saved"); onChanged?.(); }
    catch (e: any) { toast("err", e.message); }
  };

  const ignore = async () => {
    const r = prompt(`Bench ${host} for 7 days.\nReason:`, "ui: manual bench");
    if (r === null) return;
    try { await api.action(`/api/hosts/${enc}/ignore`, { reason: r || "ui: manual bench" }); toast("ok", `${host} benched 7d`); onChanged?.(); }
    catch (e: any) { toast("err", e.message); }
  };

  const primary = actions.filter((a) => PRIMARY.includes(a.action));
  const overflow = actions.filter((a) => !PRIMARY.includes(a.action));

  const btn = "mono rounded border px-2 py-0.5 text-[10px] transition";

  return (
    <div className="flex flex-wrap items-center gap-1">
      {primary.map((a) => (
        <button key={a.action} onClick={() => run(a.action)} title={a.desc}
          className={`${btn} border-[var(--color-accent)]/50 text-[var(--color-accent)] hover:bg-[var(--color-accent)]/10`}>
          {a.action === "verify" ? "⚡ " : ""}{LABEL[a.action] || a.action}
        </button>
      ))}

      {overflow.length > 0 && (
        <details className="relative">
          <summary className={`${btn} list-none cursor-pointer border-[var(--color-border-bright)] text-[var(--color-ink-faint)] hover:text-[var(--color-ink)] marker:hidden`}
            title="more target-facing tests">⋯ more</summary>
          <div className="absolute right-0 z-20 mt-1 w-40 rounded-md border border-[var(--color-border-bright)] bg-[var(--color-panel-2)] p-1 shadow-xl">
            {overflow.map((a) => (
              <button key={a.action} onClick={() => run(a.action)} title={a.desc}
                className="mono block w-full rounded px-2 py-1 text-left text-[11px] text-[var(--color-ink-dim)] transition hover:bg-[var(--color-panel)] hover:text-[var(--color-accent)]">
                {LABEL[a.action] || a.action}
              </button>
            ))}
          </div>
        </details>
      )}

      <span className="mx-0.5 h-3 w-px bg-[var(--color-border-bright)]" />

      <button onClick={markFP} title="mark FALSE POSITIVE — class-scoped dead note, stops re-serving"
        className={`${btn} border-[var(--color-border-bright)] text-[var(--color-ink-faint)] hover:border-[var(--color-bad)] hover:text-[var(--color-bad)]`}>
        Mark FP
      </button>
      <button onClick={note} title="add a worked-knowledge note"
        className={`${btn} border-[var(--color-border-bright)] text-[var(--color-ink-faint)] hover:text-[var(--color-ink)]`}>
        Note
      </button>
      <button onClick={ignore} title="bench this host for 7 days"
        className={`${btn} border-[var(--color-border-bright)] text-[var(--color-ink-faint)] hover:text-[var(--color-ink)]`}>
        Ignore
      </button>
    </div>
  );
}
