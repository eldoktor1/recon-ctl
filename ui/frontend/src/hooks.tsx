import { createContext, useContext, useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, getToken, clearToken, type Status } from "./api";

// Generic fetch on TanStack Query — cached, deduped, race-safe, keeps previous
// data while refetching. Backward-compatible shape: {data, error, loading, refetch}.
export function useFetch<T>(path: string | null, deps: any[] = []) {
  const q = useQuery<T>({
    queryKey: [path, ...deps],
    queryFn: async ({ signal }) => {
      const r = await fetch(path as string, {
        headers: { "X-Recon-Token": getToken() },
        signal,
      });
      if (!r.ok) {
        let detail = r.statusText;
        try { detail = (await r.json()).detail || detail; } catch {}
        if (r.status === 401 && getToken()) { clearToken(); location.reload(); }
        const err: any = new Error(detail);
        err.status = r.status;
        throw err;
      }
      return r.json();
    },
    enabled: !!path,
    placeholderData: (prev) => prev,  // no empty flash between pages/filters
  });
  return {
    data: (q.data ?? null) as T | null,
    error: q.error ? (q.error as Error).message : null,
    loading: q.isLoading,
    refetch: q.refetch,
  };
}

// --- shared live status (ONE websocket for the whole app) --------------------
interface StatusCtx { status: Status | null; connected: boolean; staleMs: number }
const Ctx = createContext<StatusCtx>({ status: null, connected: false, staleMs: 0 });
export const useLiveStatus = () => useContext(Ctx);

export function StatusProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<Status | null>(null);
  const [connected, setConnected] = useState(false);
  const [staleMs, setStaleMs] = useState(0);
  const lastMsg = useRef<number>(Date.now());

  useEffect(() => {
    let stop = false;
    let ws: WebSocket | null = null;
    let attempt = 0;
    let hbTimer: any;
    let reconnectTimer: any;

    const poll = async () => { try { setStatus(await api.get<Status>("/api/status")); lastMsg.current = Date.now(); } catch {} };

    const scheduleReconnect = () => {
      if (stop) return;
      const backoff = Math.min(30_000, 500 * 2 ** attempt) + Math.random() * 400;
      attempt++;
      reconnectTimer = setTimeout(connect, backoff);
    };

    const connect = () => {
      if (stop) return;
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/api/stream?token=${encodeURIComponent(getToken())}`);
      ws.onopen = () => { setConnected(true); attempt = 0; lastMsg.current = Date.now(); };
      ws.onmessage = (ev) => {
        lastMsg.current = Date.now();
        try { const m = JSON.parse(ev.data); if (m.type === "status") setStatus(m.data); } catch {}
      };
      ws.onclose = () => { setConnected(false); if (!stop) scheduleReconnect(); };
      ws.onerror = () => { try { ws?.close(); } catch {} };
    };

    // heartbeat watchdog: server pushes every 4s; if silent >12s the socket is a
    // zombie (WSL/VPN flap) — force a reconnect and poll to stay fresh.
    hbTimer = setInterval(() => {
      const age = Date.now() - lastMsg.current;
      setStaleMs(age);
      if (age > 12_000 && ws && ws.readyState === WebSocket.OPEN) {
        try { ws.close(); } catch {}
      }
      if (age > 8_000) poll();
    }, 2_000);

    poll();
    connect();
    return () => {
      stop = true;
      clearInterval(hbTimer);
      clearTimeout(reconnectTimer);
      try { ws?.close(); } catch {}
    };
  }, []);

  return <Ctx.Provider value={{ status, connected, staleMs }}>{children}</Ctx.Provider>;
}
