import { clearToken, getToken, type ClaudeConfig } from "../api";
import { useFetch, useLiveStatus } from "../hooks";
import { Panel, Badge, Dot, Spinner } from "../components/ui";
import { Btn, useToast } from "../components/controls";
import { isDemo, setDemo } from "../demo";

export default function Settings() {
  const { status, connected } = useLiveStatus();
  const toast = useToast();
  const tok = getToken();
  const masked = tok ? tok.slice(0, 4) + "…" + tok.slice(-4) : "(none)";
  const demo = isDemo();

  return (
    <div className="fade-in space-y-5">
      <h1 className="text-lg font-semibold">Settings</h1>

      <AIEngine />

      <Panel title="demo mode">
        <div className="space-y-3 text-sm">
          <div className="flex items-center gap-3">
            <Dot color={demo ? "var(--color-accent)" : "var(--color-ink-faint)"} pulse={demo} />
            <span className="flex-1 text-[var(--color-ink-dim)]">
              Render the UI fully populated with <span className="text-[var(--color-ink)]">synthetic fixtures</span> — no live backend or token. Ideal for screenshots and evaluating the repo.
            </span>
            <Btn size="sm" variant={demo ? "danger" : "primary"}
              onClick={() => { setDemo(!demo); toast("info", demo ? "demo off — reloading" : "demo on — reloading"); setTimeout(() => { location.href = location.pathname; }, 500); }}>
              {demo ? "turn off" : "turn on"}
            </Btn>
          </div>
          <p className="text-xs text-[var(--color-ink-faint)]">Also enable ad-hoc with <span className="mono">?demo=1</span> in the URL. Fixtures use obviously-fake <span className="mono">example.com</span> hosts.</p>
        </div>
      </Panel>

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

const PROVIDER_LABEL: Record<string, string> = {
  anthropic: "Anthropic (Claude)", openai: "OpenAI (GPT)", google: "Google (Gemini)",
  local: "Local / self-hosted",
};

function AIEngine() {
  const { data, loading } = useFetch<ClaudeConfig>("/api/claude/config");
  const toast = useToast();
  const active = data?.provider || "anthropic";
  const providers = data?.providers?.length ? data.providers : [active];

  return (
    <Panel title="AI engine"
      right={data ? <Badge color={data.wired ? "var(--color-good)" : "var(--color-warn)"}>{data.wired ? "co-pilot wired" : "not wired"}</Badge> : undefined}>
      {loading && !data ? <Spinner /> : (
        <div className="space-y-4 text-sm">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <Row k="active provider" v={<span className="mono text-[var(--color-accent)]">{PROVIDER_LABEL[active] || active}</span>} />
            {data?.model && <Row k="model" v={<span className="mono text-xs">{data.model}</span>} />}
            {data?.auth && <Row k="auth" v={<span className="mono text-xs">{data.auth}</span>} />}
          </div>

          <div>
            <div className="mb-2 text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">available providers</div>
            <div className="flex flex-wrap gap-2">
              {providers.map((p) => {
                const on = p === active;
                return (
                  <button key={p} onClick={() => { if (!on) toast("info", "provider is set on the backend — this panel reflects the active engine"); }}
                    title={on ? "active engine" : "reported available — switch on the backend"}
                    className="flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs transition"
                    style={{ borderColor: on ? "var(--color-accent)" : "var(--color-border-bright)", color: on ? "var(--color-accent)" : "var(--color-ink-dim)" }}>
                    <Dot color={on ? "var(--color-accent)" : "var(--color-ink-faint)"} pulse={on} />
                    {PROVIDER_LABEL[p] || p}
                  </button>
                );
              })}
            </div>
          </div>

          <p className="text-xs leading-relaxed text-[var(--color-ink-faint)]">
            The engine drives ANALYZE → VERIFY → MONITOR and the in-app Co-Pilot. Other models can be plugged in as the provider —
            each vendor requires enrollment in its own <span className="text-[var(--color-ink-dim)]">cyber / security verification program</span> before it may be used
            for offensive-security testing. The active provider is configured on the backend; this panel reflects what it reports.
          </p>
        </div>
      )}
    </Panel>
  );
}
