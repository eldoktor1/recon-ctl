import { clearToken, getToken } from "../api";
import { useLiveStatus } from "../hooks";
import { Panel, Badge, Dot } from "../components/ui";
import { Btn, useToast } from "../components/controls";

export default function Settings() {
  const { status, connected } = useLiveStatus();
  const toast = useToast();
  const tok = getToken();
  const masked = tok ? tok.slice(0, 4) + "…" + tok.slice(-4) : "(none)";

  return (
    <div className="fade-in space-y-5">
      <h1 className="text-lg font-semibold">Settings</h1>

      <Panel title="access">
        <div className="space-y-3 text-sm">
          <Row k="token (this browser)" v={<span className="mono">{masked}</span>} />
          <div className="flex gap-2">
            <Btn size="sm" variant="danger" onClick={() => { clearToken(); toast("info", "token cleared — reloading"); setTimeout(() => location.reload(), 600); }}>
              log out (clear token)
            </Btn>
          </div>
          <p className="text-xs text-[var(--color-ink-faint)]">
            To rotate: delete <span className="mono">~/recon/state/ui_token</span>, run <span className="mono">recon ui restart</span>, then log in with the new token (<span className="mono">recon ui token</span>).
          </p>
        </div>
      </Panel>

      <Panel title="security posture">
        <div className="grid grid-cols-1 gap-2 text-sm sm:grid-cols-2">
          {[
            ["loopback bind only", "127.0.0.1:8787"],
            ["Host-header allowlist", "anti DNS-rebinding"],
            ["token on every /api route", "reads + writes"],
            ["CSRF-proof mutations", "custom header + Origin + confirm"],
            ["fail-closed VPN gate", "target lanes"],
            ["sandboxed service", "NoNewPrivileges, caps dropped"],
          ].map(([k, v]) => (
            <div key={k} className="flex items-center gap-2 rounded-md bg-[var(--color-panel-2)] px-3 py-2">
              <Dot color="var(--color-good)" />
              <span className="flex-1 text-[var(--color-ink)]">{k}</span>
              <span className="text-[11px] text-[var(--color-ink-faint)]">{v}</span>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="runtime">
        <div className="space-y-2 text-sm">
          <Row k="websocket" v={<Badge color={connected ? "var(--color-good)" : "var(--color-warn)"}>{connected ? "connected" : "polling"}</Badge>} />
          <Row k="daemon" v={<span className="mono text-xs">{status?.daemon?.alive ? `pid ${status.daemon.pid} · ${status.daemon.lane_procs} lanes` : "down"}</span>} />
          <Row k="elasticsearch" v={<span className="mono text-xs">{status?.es?.reachable ? `${status.es.status} · ${status.es.docs?.toLocaleString()} docs` : "offline"}</span>} />
          <Row k="control" v={<span className="mono text-xs text-[var(--color-ink-faint)]">recon ui status | logs | restart | token</span>} />
        </div>
      </Panel>
    </div>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-center gap-3">
      <span className="w-48 shrink-0 text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">{k}</span>
      <span className="text-[var(--color-ink-dim)]">{v}</span>
    </div>
  );
}
