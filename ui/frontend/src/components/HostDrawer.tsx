import { useState } from "react";
import { api } from "../api";
import { useFetch } from "../hooks";
import { Empty, Spinner, Badge } from "./ui";
import { Drawer, Btn, useToast, ConfirmModal } from "./controls";
import { priorityColor, asArr } from "../format";

// Shared host detail + actions drawer (used by Assets, Leads, Notes).
export function HostDrawer({ host, onClose }: { host: string; onClose: () => void }) {
  const { data, loading } = useFetch<any>(`/api/assets/${encodeURIComponent(host)}`);
  const toast = useToast();
  const [scopeOut, setScopeOut] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<null | { title: string; body: string; run: () => Promise<any> }>(null);
  const [busy, setBusy] = useState(false);

  const runScope = async () => {
    setScopeOut("checking…");
    try { const r = await api.get<any>(`/api/scope/${encodeURIComponent(host)}`); setScopeOut(r.result || r.error || "(no output)"); }
    catch (e: any) { setScopeOut(e.message); }
  };
  const doAction = async () => {
    if (!confirm) return;
    setBusy(true);
    try { const r = await confirm.run(); toast(r?.ok === false ? "err" : "ok", r?.ok === false ? r.error : "done"); }
    catch (e: any) { toast("err", e.message); }
    finally { setBusy(false); setConfirm(null); }
  };

  return (
    <Drawer open onClose={onClose} width={600} title={<span className="mono text-sm text-[var(--color-ink)]">{host}</span>}>
      {loading && !data ? <Spinner /> : !data ? (
        <div className="space-y-4">
          <Empty>not in ES asset index</Empty>
          <div className="flex flex-wrap gap-2 border-t border-[var(--color-border)] pt-4">
            <Btn size="sm" onClick={runScope}>scope check</Btn>
            <Btn size="sm" onClick={() => { const t = prompt(`Note for ${host}:`); if (t) setConfirm({ title: "Add note?", body: t, run: () => api.action(`/api/hosts/${encodeURIComponent(host)}/note`, { text: t }) }); }}>add note</Btn>
          </div>
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
          </div>
          {scopeOut && <pre className="mono max-h-56 overflow-auto whitespace-pre-wrap rounded bg-[var(--color-bg)] p-3 text-[11px] text-[var(--color-ink-dim)]">{scopeOut}</pre>}
        </div>
      )}
      <ConfirmModal open={!!confirm} title={confirm?.title || ""} body={confirm?.body} confirmLabel={busy ? "…" : "Confirm"} onConfirm={doAction} onCancel={() => setConfirm(null)} />
    </Drawer>
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
