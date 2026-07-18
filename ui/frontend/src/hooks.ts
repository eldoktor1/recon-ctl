import { useEffect, useRef, useState } from "react";
import { api, getToken, type Status } from "./api";

// Live status via WebSocket, with polling fallback if the socket drops.
export function useLiveStatus(): { status: Status | null; connected: boolean } {
  const [status, setStatus] = useState<Status | null>(null);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let stop = false;
    let pollTimer: any;

    const poll = async () => {
      try {
        setStatus(await api.get<Status>("/api/status"));
      } catch {}
    };

    const connect = () => {
      if (stop) return;
      const proto = location.protocol === "https:" ? "wss" : "ws";
      const ws = new WebSocket(`${proto}://${location.host}/api/stream?token=${encodeURIComponent(getToken())}`);
      wsRef.current = ws;
      ws.onopen = () => setConnected(true);
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.type === "status") setStatus(msg.data);
        } catch {}
      };
      ws.onclose = () => {
        setConnected(false);
        if (!stop) {
          poll();
          pollTimer = setInterval(poll, 5000);
          setTimeout(() => {
            clearInterval(pollTimer);
            connect();
          }, 6000);
        }
      };
      ws.onerror = () => ws.close();
    };

    poll();
    connect();
    return () => {
      stop = true;
      clearInterval(pollTimer);
      wsRef.current?.close();
    };
  }, []);

  return { status, connected };
}

// Generic one-shot fetch with loading/error/refetch.
export function useFetch<T>(path: string | null, deps: any[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = async () => {
    if (!path) return;
    setLoading(true);
    setError(null);
    try {
      setData(await api.get<T>(path));
    } catch (e: any) {
      setError(e.message || "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, ...deps]);

  return { data, error, loading, refetch: load };
}
