import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../api";
import { useFetch } from "../hooks";
import { Empty, Spinner, Badge } from "./ui";
import { Drawer, Btn, useToast, ConfirmModal } from "./controls";
import { TaskConsole } from "./TaskConsole";
import { AutoNote } from "./AutoNote";
import { priorityColor, asArr } from "../format";

interface HostAction { action: string; target: boolean; desc: string }

// Shared host detail + actions drawer (used by Assets, Leads, Notes).
// `onChanged` fires after a mutating action (dismiss/ignore/note) so the opener's lists refetch —
// e.g. a just-FP'd host drops out of the Leads worklist without waiting for the poll.
export function HostDrawer({ host, onClose, onChanged }:
  { host: string; onClose: () => void; onChanged?: () => void }) {
  const { data, loading } = useFetch<any>(`/api/assets/${encodeURIComponent(host)}`);
  const { data: hostActions } = useFetch<HostAction[]>("/api/host-actions");
  const qc = useQueryClient();
  const toast = useToast();
  const [scopeOut, setScopeOut] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<null | { title: string; body: string; run: () => Promise<any> }>(null);
  const [busy, setBusy] = useState(false);
  const [openTask, setOpenTask] = useState<number | null>(null);

  const runScope = async () => {
    setScopeOut("checking…");
    try { const r = await api.get<any>(`/api/scope/${encodeURIComponent(host)}`); setScopeOut(r.result || r.error || "(no output)"); }
    catch (e: any) { setScopeOut(e.message); }
  };

  const runAction = async (action: string) => {
    try {
      const t = await api.action<any>(`/api/hosts/${encodeURIComponent(host)}/run`, { action });
      toast("ok", `${action} #${t.id} — streaming below`);
      setOpenTask(t.id);
    } catch (e: any) { toast("err", e.message); }
  };
  const testRow = hostActions && hostActions.length > 0 && (
    <div>
      <div className="mb-1.5 text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">test / run · target-facing (VPN-gated)</div>
      <div className="flex flex-wrap gap-1.5">
        {hostActions.map((a) => (
          <button key={a.action} onClick={() => runAction(a.action)} title={a.desc}
            className="mono rounded-md border border-[var(--color-border-bright)] px-2 py-1 text-[11px] text-[var(--color-ink-dim)] transition hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]">
            {a.action}
          </button>
        ))}
      </div>
    </div>
  );
  const doAction = async () => {
    if (!confirm) return;
    setBusy(true);
    try {
      const r = await confirm.run();
      const failed = r?.ok === false;
      toast(failed ? "err" : "ok", failed ? r.error : "done");
      if (!failed) { qc.invalidateQueries(); onChanged?.(); }  // lists refetch after a mutating action
    }
    catch (e: any) { toast("err", e.message); }
    finally { setBusy(false); setConfirm(null); }
  };

  return (
   <>
    <Drawer open onClose={onClose} width={600} resizeKey="recon.hostdrawer.w" title={<span className="mono text-sm text-[var(--color-ink)]">{host}</span>}>
      {loading && !data ? <Spinner /> : !data ? (
        <div className="space-y-4">
          <Empty>not in ES asset index</Empty>
          <div className="flex flex-wrap gap-2 border-t border-[var(--color-border)] pt-4">
            <Btn size="sm" onClick={runScope}>scope check</Btn>
            <Btn size="sm" onClick={() => { const t = prompt(`Note for ${host}:`); if (t) setConfirm({ title: "Add note?", body: t, run: () => api.action(`/api/hosts/${encodeURIComponent(host)}/note`, { text: t }) }); }}>add note</Btn>
          </div>
          <div className="border-t border-[var(--color-border)] pt-4">{testRow}</div>
          {scopeOut && <pre className="mono max-h-56 overflow-auto whitespace-pre-wrap rounded bg-[var(--color-bg)] p-3 text-[11px] text-[var(--color-ink-dim)]">{scopeOut}</pre>}
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            {data.triage_priority && <Badge color={priorityColor[data.triage_priority]} filled>{data.triage_priority}</Badge>}
            {data.triage_pays && <Badge color="var(--color-good)">pays</Badge>}
            {data.triage_true_fresh && <Badge color="var(--color-accent)">fresh</Badge>}
            {data.triage_kev_match && <Badge color="var(--color-bad)">kev</Badge>}
            {data.takeover_confirmed && <Badge color="var(--color-bad)">takeover</Badge>}
            {data.js_secret_hit && <Badge color="var(--color-warn)">secret</Badge>}
            <span className="mono text-xs text-[var(--color-ink-faint)]">score {data.triage_score}</span>
          </div>
          <Row k="program" v={data.triage_program} />
          <Row k="title" v={data.title} />
          <Row k="tech" v={asArr(data.tech).join(", ")} />
          <Row k="classes" v={asArr(data.triage_classes).join(", ")} />
          <Row k="payout tier" v={data.triage_payout_tier} />
          {asArr(data.triage_kev_cves).length ? <Row k="kev cves" v={asArr(data.triage_kev_cves).join(", ")} /> : null}
          {data.takeover_cname && <Row k="cname" v={data.takeover_cname} />}
          {data.ignore_expires_at && <Row k="benched until" v={data.ignore_expires_at} />}

          {data.host_notes?.length > 0 && (
            <div>
              <div className="mb-1 text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">notes ({data.host_notes.length})</div>
              <div className="space-y-1">
                {data.host_notes.map((n: any, i: number) => (
                  <div key={i} className="rounded bg-[var(--color-panel-2)] px-2 py-1 text-xs text-[var(--color-ink-dim)]">
                    <span className="mono text-[var(--color-ink-faint)]">[{(n.created_at || "").slice(0, 10)} {n.source}]</span> {n.note}
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="flex flex-wrap gap-2 border-t border-[var(--color-border)] pt-4">
            <Btn size="sm" onClick={runScope}>scope check</Btn>
            <Btn size="sm" onClick={() => { const t = prompt(`Note for ${host}:`); if (t) setConfirm({ title: "Add note?", body: t, run: () => api.action(`/api/hosts/${encodeURIComponent(host)}/note`, { text: t }) }); }}>add note</Btn>
            <Btn size="sm" onClick={() => setConfirm({ title: `Ignore ${host}?`, body: "Benches for 7 days + records a note.", run: () => api.action(`/api/hosts/${encodeURIComponent(host)}/ignore`, { reason: "ui: manual bench" }) })}>ignore 7d</Btn>
            <Btn size="sm" variant="danger" onClick={() => { const r = prompt(`Mark ${host} not-actionable / FP.\nOptional reason:`, "") ?? undefined; if (r !== undefined) setConfirm({ title: `Not actionable: ${host}?`, body: "Records a DEAD verdict — stops re-serving this host in the worklist + nightly briefing until a later 'resume' note re-arms it.", run: () => api.action(`/api/hosts/${encodeURIComponent(host)}/dismiss`, { kind: "not-actionable", reason: r }) }); }}>not actionable</Btn>
          </div>
          {testRow}
          <div className="border-t border-[var(--color-border)] pt-4">
            <AutoNote title="host note"
              hint="end of testing → auto-draft where this host stands"
              storeKey={`autonote:host:${host}`}
              spawn={() => api.action<any>(`/api/hosts/${encodeURIComponent(host)}/autonote`)}
              onSave={async (text) => { const r = await api.action(`/api/hosts/${encodeURIComponent(host)}/note`, { text }); qc.invalidateQueries(); onChanged?.(); return r; }} />
          </div>
          {scopeOut && <pre className="mono max-h-56 overflow-auto whitespace-pre-wrap rounded bg-[var(--color-bg)] p-3 text-[11px] text-[var(--color-ink-dim)]">{scopeOut}</pre>}
        </div>
      )}
      <ConfirmModal open={!!confirm} title={confirm?.title || ""} body={confirm?.body} confirmLabel={busy ? "…" : "Confirm"} onConfirm={doAction} onCancel={() => setConfirm(null)} />
    </Drawer>
    {openTask != null && <TaskConsole tid={openTask} onClose={() => setOpenTask(null)} />}
   </>
  );
}

function Row({ k, v }: { k: string; v?: string }) {
  if (!v) return null;
  return (
    <div className="flex gap-3 text-sm">
      <span className="w-24 shrink-0 text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">{k}</span>
      <span className="mono flex-1 break-all text-xs text-[var(--color-ink-dim)]">{v}</span>
    </div>
  );
}
