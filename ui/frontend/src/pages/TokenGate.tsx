import { useEffect, useState } from "react";
import { getToken, setToken, verifyToken } from "../api";
import { Logo } from "../components/Logo";

// Blocks the app until a valid token is provided. Token is checked against the
// backend (which requires it on every /api route). Stored in localStorage.
export default function TokenGate({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(false);
  const [ok, setOk] = useState(false);
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    (async () => {
      const t = getToken();
      if (t && (await verifyToken(t))) setOk(true);
      setReady(true);
    })();
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setChecking(true);
    setError(null);
    if (await verifyToken(value)) {
      setToken(value);
      setOk(true);
    } else {
      setError("Token rejected. Get it with: recon ui token");
    }
    setChecking(false);
  };

  if (!ready) return null;
  if (ok) return <>{children}</>;

  return (
    <div className="flex h-full items-center justify-center">
      <form onSubmit={submit} className="w-[min(92vw,420px)] rounded-xl border border-[var(--color-border)] bg-[var(--color-panel)] p-7 fade-in">
        <div className="mb-1 flex items-center gap-3">
          <Logo size={40} spin />
          <div className="flex items-baseline gap-1.5">
            <span className="mono text-2xl font-bold text-[var(--color-accent)]">recon</span>
            <span className="mono text-2xl font-light text-[var(--color-ink-faint)]">/ ctl</span>
          </div>
        </div>
        <p className="mb-5 text-sm text-[var(--color-ink-dim)]">
          Local control plane. Enter the access token to continue.
        </p>
        <input
          type="password"
          autoFocus
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="access token"
          className="mono w-full rounded-md border border-[var(--color-border-bright)] bg-[var(--color-bg)] px-3 py-2.5 text-sm text-[var(--color-ink)] outline-none focus:border-[var(--color-accent)]"
        />
        {error && <div className="mt-2 text-xs text-[var(--color-bad)]">{error}</div>}
        <button
          type="submit"
          disabled={checking || !value}
          className="mt-4 w-full rounded-md bg-[var(--color-accent)] px-4 py-2.5 text-sm font-semibold text-[#0a0e14] transition hover:brightness-110 disabled:opacity-40"
        >
          {checking ? "Verifying…" : "Unlock"}
        </button>
        <p className="mono mt-4 text-[11px] leading-relaxed text-[var(--color-ink-faint)]">
          token lives in ~/recon/state/ui_token (chmod 600)<br />
          print it: <span className="text-[var(--color-ink-dim)]">recon ui token</span>
        </p>
      </form>
    </div>
  );
}
