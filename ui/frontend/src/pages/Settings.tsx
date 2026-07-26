import { useState } from "react";
import { api, clearToken, getToken, type ClaudeConfig } from "../api";
import { useFetch, useLiveStatus } from "../hooks";
import { Panel, Badge, Dot, Spinner } from "../components/ui";
import { Btn, useToast } from "../components/controls";
import { TaskConsole } from "../components/TaskConsole";
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

      <AIModelWizard />

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

interface AIModelsResp {
  ollama_up: boolean;
  ollama_models: { name: string; size_gb: number }[];
  agent_model: string;
  recommended: string;
  claude: { bin?: boolean; available?: boolean; provider?: string; provider_label?: string };
  fallback: { active_provider: string; fallback_active: boolean; claude_reset_at: string | null };
}

// Interactive wizard: connect Claude (primary) + pick/pull the local fallback AGENT model.
function AIModelWizard() {
  const { data, loading, refetch } = useFetch<AIModelsResp>("/api/ai/models");
  const toast = useToast();
  const [pullName, setPullName] = useState("");
  const [pullTask, setPullTask] = useState<number | null>(null);

  const setAgent = async (model: string) => {
    try { await api.action("/api/ai/agent-model", { model }); toast("ok", `local agent → ${model}`); refetch(); }
    catch (e: any) { toast("err", e.message); }
  };
  const pull = async (model: string) => {
    const m = model.trim(); if (!m) return;
    try { const t = await api.action<{ id: number }>("/api/ai/pull", { model: m }); toast("ok", `pulling ${m} — streaming below`); setPullTask(t.id); setPullName(""); }
    catch (e: any) { toast("err", e.message); }
  };

  const models = data
    ? (data.ollama_models.some((m) => m.name === data.agent_model) ? data.ollama_models : [{ name: data.agent_model, size_gb: 0 }, ...data.ollama_models])
    : [];
  const hasRec = !!data?.ollama_models.some((m) => m.name.startsWith("hermes3"));

  return (
    <Panel title="AI models · wizard"
      right={data?.fallback?.fallback_active ? <Badge color="var(--color-warn)">on local fallback</Badge> : <Badge color="var(--color-good)">Claude active</Badge>}>
      {loading && !data ? <Spinner /> : !data ? <div className="text-xs text-[var(--color-ink-faint)]">unavailable</div> : (
        <div className="space-y-3 text-sm">
          {/* Claude — primary */}
          <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] p-3">
            <div className="mb-1 flex items-center gap-2">
              <Dot color={data.claude.available && data.claude.bin ? "var(--color-good)" : "var(--color-bad)"} />
              <span className="font-semibold text-[var(--color-ink)]">Claude — primary brain</span>
              <Badge>{data.claude.provider_label || "Anthropic"}</Badge>
            </div>
            <div className="text-[11px] text-[var(--color-ink-dim)]">
              {data.claude.bin ? "CLI found on the box." : "claude CLI not found on the box."} Runs on your Max subscription (no API key).
              For full offensive-security capability, enroll in Anthropic's Cyber Verification Program.
            </div>
            <div className="mono mt-1.5 flex flex-wrap items-center gap-3 text-[10px] text-[var(--color-ink-faint)]">
              <span>connect: run <span className="text-[var(--color-accent)]">claude</span> → <span className="text-[var(--color-accent)]">/login</span></span>
              <a href="https://portal.anthropic.com/programs/cvp" target="_blank" rel="noreferrer" className="text-[var(--color-info)] hover:underline">apply for CVP ↗</a>
            </div>
          </div>

          {/* Local agent — fallback */}
          <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] p-3">
            <div className="mb-2 flex items-center gap-2">
              <Dot color={data.ollama_up ? "var(--color-good)" : "var(--color-bad)"} pulse={data.fallback.fallback_active} />
              <span className="font-semibold text-[var(--color-ink)]">Local agent — fallback when Claude is rate-limited</span>
              {data.fallback.fallback_active && <Badge color="var(--color-warn)">active now</Badge>}
            </div>
            {!data.ollama_up ? (
              <div className="text-[11px] text-[var(--color-bad)]">Ollama not reachable at 127.0.0.1:11434 — start it: <span className="mono">systemctl --user start ollama</span> (or <span className="mono">ollama serve</span>).</div>
            ) : (
              <>
                <div className="mb-1.5 flex flex-wrap items-center gap-2">
                  <span className="text-[11px] text-[var(--color-ink-faint)]">agent model:</span>
                  <select value={data.agent_model} onChange={(e) => setAgent(e.target.value)}
                    className="mono rounded border border-[var(--color-border-bright)] bg-[var(--color-panel)] px-2 py-1 text-[11px] outline-none focus:border-[var(--color-accent)]">
                    {models.map((m) => <option key={m.name} value={m.name}>{m.name}{m.size_gb ? ` · ${m.size_gb}GB` : ""}</option>)}
                  </select>
                  {data.agent_model === data.recommended && <Badge color="var(--color-good)">recommended</Badge>}
                </div>
                <div className="text-[10px] text-[var(--color-ink-faint)]">
                  {data.ollama_models.length} installed · best tool-driving pick: <span className="mono text-[var(--color-accent)]">{data.recommended}</span> (native tool-calling + low-refusal). The agent gets bash + web_search parity with the co-pilot.
                </div>
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <input value={pullName} onChange={(e) => setPullName(e.target.value)} onKeyDown={(e) => e.key === "Enter" && pull(pullName)}
                    placeholder="pull a model… e.g. hermes3:8b"
                    className="mono min-w-[180px] flex-1 rounded border border-[var(--color-border-bright)] bg-[var(--color-panel)] px-2 py-1 text-[11px] outline-none focus:border-[var(--color-accent)]" />
                  <Btn size="sm" onClick={() => pull(pullName)}>pull</Btn>
                  {!hasRec && <Btn size="sm" variant="primary" onClick={() => pull("hermes3:8b")}>pull hermes3:8b</Btn>}
                </div>
              </>
            )}
          </div>
        </div>
      )}
      {pullTask != null && <TaskConsole tid={pullTask} onClose={() => setPullTask(null)} onChanged={refetch} />}
    </Panel>
  );
}
