import { useEffect, useState } from "react";
import { api } from "../api";
import { useFetch, useLiveStatus } from "../hooks";
import { Panel, Badge, Empty, Spinner, Dot } from "../components/ui";
import { Btn, useToast, ConfirmModal } from "../components/controls";
import { TaskConsole, taskColor } from "../components/TaskConsole";

interface Lane { lane: string; sub: string; target: boolean; desc: string }
interface Task { id: number; label: string; state: string; returncode: number | null; line_count: number }

export default function Hunt() {
  const { data: lanes } = useFetch<Lane[]>("/api/lanes");
  const { status } = useLiveStatus();
  const [tasks, setTasks] = useState<Task[]>([]);
  const [openTask, setOpenTask] = useState<number | null>(null);
  const [confirm, setConfirm] = useState<null | { lane: Lane }>(null);
  const toast = useToast();
  const vpnUp = status?.vpn?.up ?? true;

  const loadTasks = async () => { try { setTasks(await api.get<Task[]>("/api/tasks")); } catch {} };
  useEffect(() => { loadTasks(); const t = setInterval(loadTasks, 3000); return () => clearInterval(t); }, []);

  const launch = async () => {
    if (!confirm) return;
    try {
      const t = await api.action<Task>(`/api/hunt/${confirm.lane.lane}`);
      toast("ok", `${confirm.lane.lane} launched · task #${t.id}`);
      setOpenTask(t.id); loadTasks();
    } catch (e: any) { toast("err", e.message); }
    finally { setConfirm(null); }
  };

  return (
    <div className="fade-in space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="text-lg font-semibold">Hunt Control</h1>
        <div className="flex items-center gap-2 text-xs">
          <Dot color={vpnUp ? "var(--color-good)" : "var(--color-bad)"} pulse={!vpnUp} />
          <span className="text-[var(--color-ink-dim)]">{vpnUp ? "VPN up — target lanes armed" : "VPN DOWN — target lanes blocked"}</span>
        </div>
      </div>

      {/* lane launcher */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {!lanes ? <Spinner /> : lanes.map((l) => {
          const blocked = l.target && !vpnUp;
          return (
            <div key={l.lane} className="flex flex-col rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] p-4">
              <div className="flex items-center gap-2">
                <span className="mono text-sm font-semibold text-[var(--color-ink)]">{l.lane}</span>
                {l.target ? <Badge color="var(--color-warn)">target</Badge> : <Badge color="var(--color-info)">off-target</Badge>}
              </div>
              <p className="mt-1.5 flex-1 text-xs leading-relaxed text-[var(--color-ink-dim)]">{l.desc}</p>
              <div className="mt-3">
                <Btn size="sm" variant="primary" disabled={blocked} onClick={() => setConfirm({ lane: l })}>
                  {blocked ? "VPN down" : "launch"}
                </Btn>
              </div>
            </div>
          );
        })}
      </div>

      {/* tasks */}
      <Panel title="tasks" right={<Badge>{tasks.length}</Badge>}>
        {!tasks.length ? <Empty>no tasks launched this session</Empty> : (
          <div className="space-y-1">
            {tasks.map((t) => (
              <div key={t.id} onClick={() => setOpenTask(t.id)}
                className="flex cursor-pointer items-center gap-3 rounded-md px-2 py-1.5 hover:bg-[var(--color-panel-2)]">
                <Dot color={taskColor[t.state]} pulse={t.state === "running"} />
                <span className="mono text-xs text-[var(--color-ink)]">#{t.id}</span>
                <span className="mono flex-1 truncate text-xs text-[var(--color-ink-dim)]">{t.label}</span>
                <Badge color={taskColor[t.state]}>{t.state}{t.returncode != null && t.state !== "running" ? ` · ${t.returncode}` : ""}</Badge>
                <span className="text-[11px] text-[var(--color-ink-faint)]">{t.line_count} lines</span>
              </div>
            ))}
          </div>
        )}
      </Panel>

      {openTask != null && <TaskConsole tid={openTask} onClose={() => setOpenTask(null)} onChanged={loadTasks} />}

      <ConfirmModal open={!!confirm}
        title={`Launch ${confirm?.lane.lane}?`}
        danger={confirm?.lane.target}
        body={confirm ? (
          <span>
            Runs <span className="mono text-[var(--color-accent)]">recon {confirm.lane.sub}</span> as a background task.
            {confirm.lane.target && <span className="mt-2 block text-[var(--color-warn)]">⚠ Target-facing — sends live traffic through Mullvad. Only in-scope + paying hosts are ever touched by the lane.</span>}
          </span>
        ) : ""}
        confirmLabel="Launch" onConfirm={launch} onCancel={() => setConfirm(null)} />
    </div>
  );
}
