import { type ReactNode, useEffect, useRef, useState } from "react";
import { NavLink, Route, Routes, useLocation } from "react-router-dom";
import { useLiveStatus, StatusProvider } from "./hooks";
import { Pill } from "./components/ui";
import { fmtNum } from "./format";
import CommandCenter from "./pages/CommandCenter";
import Programs, { CrosshairIcon } from "./pages/Programs";
import Console from "./pages/Console";
import Hunter from "./pages/Hunter";
import TokenGate from "./pages/TokenGate";
import Findings from "./pages/Findings";
import Assets from "./pages/Assets";
import Leads from "./pages/Leads";
import Notes from "./pages/Notes";
import Hunt from "./pages/Hunt";
import Lanes from "./pages/Lanes";
import Ops from "./pages/Ops";
import Telemetry from "./pages/Telemetry";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import TargetBoard from "./pages/TargetBoard";
import Digest from "./pages/Digest";
import { ToastProvider } from "./components/controls";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Logo } from "./components/Logo";
import { CommandPalette } from "./components/CommandPalette";
import { isDemo } from "./demo";

interface NavItem { to: string; label: string; icon: ReactNode; phase?: string }

const NAV: NavItem[] = [
  { to: "/", label: "Command Center", icon: "◎" },
  { to: "/console", label: "Co-Pilot", icon: "✧" },
  { to: "/programs", label: "Programs", icon: <CrosshairIcon size={15} /> },
  { to: "/hunter", label: "Hunter · Class", icon: "☣" },
  { to: "/findings", label: "Findings", icon: "◆" },
  { to: "/assets", label: "Asset Explorer", icon: "❑" },
  { to: "/leads", label: "Leads", icon: "✦" },
  { to: "/notes", label: "Notes", icon: "✎" },
  { to: "/targets", label: "Target Board", icon: "◈" },
  { to: "/hunt", label: "Hunt Control", icon: "➤" },
  { to: "/lanes", label: "Lanes", icon: "≣" },
  { to: "/ops", label: "Daemon / Ops", icon: "⚙" },
  { to: "/digest", label: "Digest", icon: "▦" },
  { to: "/telemetry", label: "Telemetry", icon: "▤" },
  { to: "/reports", label: "Reports", icon: "✉" },
  { to: "/settings", label: "Settings", icon: "⧉" },
];

// "Claude back in Xh Ym" from the ISO reset time (recomputed each status tick)
function fmtBackIn(iso?: string | null): string {
  if (!iso) return "";
  const secs = Math.floor((new Date(iso).getTime() - Date.now()) / 1000);
  if (secs <= 0) return "any moment";
  const h = Math.floor(secs / 3600), m = Math.floor((secs % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

function TopBar() {
  const { status, connected, staleMs } = useLiveStatus();
  const d = status?.daemon;
  const vpn = status?.vpn;
  const es = status?.es;
  const ai = status?.ai;
  const stale = staleMs > 12_000;
  const openPalette = () => window.dispatchEvent(new KeyboardEvent("keydown", { key: "k", metaKey: true }));
  return (
    <header className="flex items-center justify-between border-b border-[var(--color-border)] bg-[var(--color-panel)]/80 px-5 py-2.5 backdrop-blur">
      <div className="flex items-center gap-3">
        <button onClick={openPalette}
          className="mono flex items-center gap-2 rounded-md border border-[var(--color-border-bright)] bg-[var(--color-panel-2)] px-3 py-1 text-[11px] text-[var(--color-ink-faint)] hover:text-[var(--color-ink-dim)]">
          <span>⌕ search…</span><span className="rounded bg-[var(--color-bg)] px-1">⌘K</span>
        </button>
        <span
          className={`inline-block h-2 w-2 rounded-full ${connected && !stale ? "live-dot" : ""}`}
          style={{ background: connected && !stale ? "var(--color-good)" : connected ? "var(--color-warn)" : "var(--color-ink-faint)" }}
          title={!connected ? "reconnecting…" : stale ? "stale — no update >12s" : "live"}
        />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {isDemo() && (
          <span className="mono rounded border border-[var(--color-accent)] bg-[var(--color-accent)]/10 px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-[var(--color-accent)]" title="synthetic fixtures — no live backend">demo</span>
        )}
        <Pill label="daemon" value={d?.alive ? `up · ${d.lane_procs} lanes` : "down"}
          color={d?.alive ? "var(--color-good)" : "var(--color-bad)"} pulse={d?.alive} />
        <Pill label="vpn" value={vpn?.up ? "mullvad" : "DOWN"}
          color={vpn?.up ? "var(--color-good)" : "var(--color-bad)"} pulse={!vpn?.up} />
        <Pill label="es" value={es?.reachable ? `${es.status} · ${fmtNum(es.docs)}` : "offline"}
          color={es?.reachable ? (es.status === "green" ? "var(--color-good)" : "var(--color-warn)") : "var(--color-bad)"} />
        {ai?.fallback_active && (
          <Pill label="ai" pulse color="var(--color-warn)"
            value={`local · Claude back ${fmtBackIn(ai.claude_reset_at) ? "in " + fmtBackIn(ai.claude_reset_at) : "soon"}`} />
        )}
      </div>
    </header>
  );
}

function Sidebar() {
  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-[var(--color-border)] bg-[var(--color-panel)]">
      <div className="flex items-center gap-2.5 border-b border-[var(--color-border)] px-5 py-4">
        <Logo size={26} spin />
        <div className="flex items-baseline gap-1">
          <span className="mono text-lg font-bold text-[var(--color-accent)]">recon</span>
          <span className="mono text-lg font-light text-[var(--color-ink-faint)]">/ ctl</span>
        </div>
      </div>
      <nav className="flex-1 space-y-0.5 p-2">
        {NAV.map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            end={n.to === "/"}
            className={({ isActive }) =>
              `group flex items-center gap-3 rounded-md px-3 py-2 text-sm transition ${
                isActive
                  ? "bg-[var(--color-accent)]/12 text-[var(--color-accent)]"
                  : "text-[var(--color-ink-dim)] hover:bg-[var(--color-panel-2)] hover:text-[var(--color-ink)]"
              }`
            }
          >
            <span className="inline-flex w-4 justify-center text-center text-base">{n.icon}</span>
            <span className="flex-1">{n.label}</span>
            {n.phase && (
              <span className="mono text-[10px] text-[var(--color-ink-faint)] opacity-0 group-hover:opacity-100">{n.phase}</span>
            )}
          </NavLink>
        ))}
      </nav>
      <div className="border-t border-[var(--color-border)] px-4 py-3 text-[10px] text-[var(--color-ink-faint)]">
        <span className="mono">recon-ui v0.1</span> · single-operator
      </div>
    </aside>
  );
}

export default function App() {
  // Demo mode renders the fully-populated UI without a backend or token.
  if (isDemo()) {
    return (
      <ToastProvider>
        <AppShell />
      </ToastProvider>
    );
  }
  return (
    <ToastProvider>
      <TokenGate>
        <AppShell />
      </TokenGate>
    </ToastProvider>
  );
}

// Detect a rebuild while a tab is open: the status stream carries the served bundle hash; if it
// changes from the one we loaded with, the running JS is stale — offer a one-click reload so a
// deploy is never silently missed (SPA-internal navigation never re-fetches the bundle on its own).
function UpdateBanner() {
  const { status } = useLiveStatus();
  const loaded = useRef<string | null>(null);
  const [stale, setStale] = useState(false);
  useEffect(() => {
    const b = status?.ui_build;
    if (!b) return;
    if (loaded.current === null) { loaded.current = b; return; }
    if (b !== loaded.current) setStale(true);
  }, [status?.ui_build]);
  if (!stale) return null;
  return (
    <div className="fixed inset-x-0 top-0 z-50 flex items-center justify-center gap-3 bg-[var(--color-accent)] px-4 py-2 text-[13px] font-medium text-[#0a0e14] shadow-lg">
      <span>A new version of recon·ctl is available.</span>
      <button onClick={() => location.reload()}
        className="rounded bg-[#0a0e14] px-3 py-1 text-[12px] font-semibold text-[var(--color-accent)] hover:opacity-90">
        Reload now
      </button>
    </div>
  );
}

function AppShell() {
  const loc = useLocation();
  return (
    <StatusProvider>
    <UpdateBanner />
    <CommandPalette />
    <div className="flex h-full">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <main className="flex-1 overflow-auto p-5">
          <ErrorBoundary resetKey={loc.pathname}>
          <Routes>
            <Route path="/" element={<CommandCenter />} />
            <Route path="/console" element={<Console />} />
            <Route path="/programs" element={<Programs />} />
            <Route path="/hunter" element={<Hunter />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/leads" element={<Leads />} />
            <Route path="/notes" element={<Notes />} />
            <Route path="/targets" element={<TargetBoard />} />
            <Route path="/hunt" element={<Hunt />} />
            <Route path="/lanes" element={<Lanes />} />
            <Route path="/ops" element={<Ops />} />
            <Route path="/digest" element={<Digest />} />
            <Route path="/telemetry" element={<Telemetry />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
          </ErrorBoundary>
        </main>
      </div>
    </div>
    </StatusProvider>
  );
}
