import { useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { api } from "../api";
import { useFetch } from "../hooks";
import { Panel, Badge, Empty, Spinner } from "../components/ui";
import { Btn, useToast, ConfirmModal } from "../components/controls";

interface Program {
  rank: number; platform: string; key: string; name: string; url?: string; score: number;
  why?: string; pays?: boolean; payout?: number; authed?: boolean; n_authed?: number; roots?: string[];
}
interface Board { generated?: string; count?: number; programs: Program[]; error?: string }

export default function TargetBoard() {
  const { data, error } = useFetch<Board>("/api/targets");
  const [sp] = useSearchParams();
  const [q, setQ] = useState(sp.get("q") || "");
  const [confirm, setConfirm] = useState<Program | null>(null);
  const toast = useToast();
  const navigate = useNavigate();

  // Bridge: fresh program on the board -> start (or reuse) its workspace and jump
  // straight into it to work it systematically (STRIDE + WSTG).
  const work = async (p: Program) => {
    try {
      await api.action(`/api/workspaces`, { key: p.key, name: p.name, platform: p.platform });
      toast("ok", `${p.name} — workspace ready`);
      navigate(`/programs?key=${encodeURIComponent(p.key)}`);
    } catch (e: any) { toast("err", e.message); }
  };

  const onboard = async () => {
    if (!confirm) return;
    try { const r = await api.action<any>("/api/targets/onboard", { key: confirm.key }); toast(r?.ok === false ? "err" : "ok", r?.ok === false ? "onboard failed" : `onboarded ${confirm.name}`); }
    catch (e: any) { toast("err", e.message); }
    finally { setConfirm(null); }
  };

  const ql = q.trim().toLowerCase();
  const progs = (data?.programs || []).filter((p) =>
    !ql || (p.name + " " + p.platform + " " + (p.why || "")).toLowerCase().includes(ql));

  return (
    <div className="fade-in space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="text-lg font-semibold">Target Board</h1>
        <span className="text-xs text-[var(--color-ink-faint)]">{data?.count ?? "—"} under-hunted programs · {data?.generated}</span>
      </div>

      <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="filter programs / platform…"
        className="mono w-72 rounded-md border border-[var(--color-border-bright)] bg-[var(--color-panel)] px-3 py-1.5 text-xs outline-none focus:border-[var(--color-accent)]" />

      <Panel className="!p-0">
        {!data ? (error ? <Empty hint={error}>couldn't load the target board</Empty> : <Spinner />) : data.error ? <Empty>{data.error}</Empty> : !progs.length ? <Empty>no programs</Empty> : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] text-left text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">
                <th className="px-4 py-2 font-medium">#</th>
                <th className="px-2 py-2 font-medium">program</th>
                <th className="px-2 py-2 font-medium">platform</th>
                <th className="px-2 py-2 font-medium">payout</th>
                <th className="px-2 py-2 font-medium">why</th>
                <th className="px-2 py-2 font-medium">score</th>
                <th className="px-4 py-2 text-right font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {progs.slice(0, 200).map((p) => (
                <tr key={p.key} className="border-b border-[var(--color-border)]/50 hover:bg-[var(--color-panel-2)]">
                  <td className="mono px-4 py-2 text-xs text-[var(--color-ink-faint)]">{p.rank}</td>
                  <td className="max-w-xs truncate px-2 py-2 text-xs text-[var(--color-ink)]" title={p.name}>{p.name}</td>
                  <td className="px-2 py-2 text-xs text-[var(--color-ink-dim)]">{p.platform}</td>
                  <td className="mono px-2 py-2 text-xs text-[var(--color-good)]">{p.payout ? `$${p.payout}` : p.pays ? "pays" : "—"}</td>
                  <td className="max-w-[220px] truncate px-2 py-2 text-[11px] text-[var(--color-ink-faint)]" title={p.why}>{p.why || "—"}</td>
                  <td className="mono px-2 py-2 text-xs text-[var(--color-accent)]">{p.score}</td>
                  <td className="px-4 py-2 text-right"><span className="inline-flex justify-end gap-2"><Btn size="sm" onClick={() => setConfirm(p)}>onboard</Btn><Btn size="sm" onClick={() => work(p)}>work →</Btn></span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <ConfirmModal open={!!confirm} title={`Onboard ${confirm?.name}?`}
        body={<span>Seeds this program's roots into the validator queue (<span className="mono text-[var(--color-accent)]">recon targets onboard</span>). {confirm?.roots?.length ? `${confirm.roots.length} roots.` : ""}</span>}
        confirmLabel="Onboard" onConfirm={onboard} onCancel={() => setConfirm(null)} />
    </div>
  );
}
