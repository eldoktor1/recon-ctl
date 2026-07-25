import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { useResizable } from "./useResizable";

// --- Toast --------------------------------------------------------------------
interface Toast { id: number; kind: "ok" | "err" | "info"; msg: string }
const ToastCtx = createContext<(kind: Toast["kind"], msg: string) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

let _tid = 0;
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((kind: Toast["kind"], msg: string) => {
    const id = ++_tid;
    setToasts((t) => [...t, { id, kind, msg }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4200);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-80 flex-col gap-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            className="pointer-events-auto rounded-md border px-3 py-2 text-sm shadow-lg fade-in"
            style={{
              background: "var(--color-panel-2)",
              borderColor:
                t.kind === "ok" ? "var(--color-good)" : t.kind === "err" ? "var(--color-bad)" : "var(--color-border-bright)",
              color: t.kind === "err" ? "var(--color-bad)" : "var(--color-ink)",
            }}
          >
            {t.msg}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

// --- Copy-to-clipboard chip ---------------------------------------------------
export function CopyChip({ text, label, icon = "⧉" }:
  { text: string; label?: string; icon?: string }) {
  const toast = useToast();
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setDone(true);
      toast("ok", "copied to clipboard");
      setTimeout(() => setDone(false), 1200);
    } catch {
      toast("err", "clipboard blocked");
    }
  };
  return (
    <button onClick={copy} title={`copy: ${text}`}
      className="mono inline-flex max-w-full items-center gap-1 rounded border border-[var(--color-border-bright)] bg-[var(--color-panel-2)] px-1.5 py-0.5 text-[10px] text-[var(--color-ink-dim)] transition hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]">
      <span className="shrink-0">{done ? "✓" : icon}</span>
      <span className="truncate">{label || text}</span>
    </button>
  );
}

// --- Drawer (right slide-over) ------------------------------------------------
// `resizeKey` (optional) makes the WIDTH drag-resizable via a left-edge grip, persisted
// under that localStorage key. Without it the drawer keeps its fixed `width`.
export function Drawer({ open, onClose, title, children, width = 560, resizeKey }:
  { open: boolean; onClose: () => void; title?: ReactNode; children: ReactNode;
    width?: number; resizeKey?: string }) {
  const { size, onGripDown } = useResizable({
    axis: "x", storageKey: resizeKey || "recon.drawer.__unused", initial: width,
    min: 360, max: () => Math.round(window.innerWidth * 0.94),
  });
  if (!open) return null;
  const w = resizeKey ? `${size}px` : `min(94vw, ${width}px)`;
  return (
    <div className="fixed inset-0 z-40">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div
        className="absolute right-0 top-0 flex h-full flex-col border-l border-[var(--color-border)] bg-[var(--color-panel)] shadow-2xl fade-in"
        style={{ width: w, maxWidth: "94vw" }}
      >
        {resizeKey && (
          <div onPointerDown={onGripDown} title="drag to resize"
            className="group absolute left-0 top-0 z-10 flex h-full w-2 -translate-x-1/2 cursor-ew-resize items-center justify-center">
            <span className="h-10 w-0.5 rounded-full bg-[var(--color-border-bright)] transition group-hover:bg-[var(--color-accent)]" />
          </div>
        )}
        <div className="flex items-center justify-between border-b border-[var(--color-border)] px-5 py-3">
          <div className="min-w-0 flex-1 truncate">{title}</div>
          <button onClick={onClose} className="ml-3 rounded px-2 py-1 text-[var(--color-ink-dim)] hover:bg-[var(--color-panel-2)] hover:text-[var(--color-ink)]">✕</button>
        </div>
        <div className="flex-1 overflow-auto p-5">{children}</div>
      </div>
    </div>
  );
}

// --- Confirm modal ------------------------------------------------------------
export function ConfirmModal({ open, title, body, danger, confirmLabel = "Confirm", onConfirm, onCancel }:
  { open: boolean; title: string; body: ReactNode; danger?: boolean; confirmLabel?: string;
    onConfirm: () => void; onCancel: () => void }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60" onClick={onCancel} />
      <div className="relative w-[min(92vw,440px)] rounded-xl border border-[var(--color-border-bright)] bg-[var(--color-panel)] p-6 fade-in">
        <h3 className="text-base font-semibold text-[var(--color-ink)]">{title}</h3>
        <div className="mt-2 text-sm text-[var(--color-ink-dim)]">{body}</div>
        <div className="mt-5 flex justify-end gap-2">
          <button onClick={onCancel} className="rounded-md border border-[var(--color-border-bright)] px-4 py-2 text-sm text-[var(--color-ink-dim)] hover:text-[var(--color-ink)]">Cancel</button>
          <button
            onClick={onConfirm}
            className="rounded-md px-4 py-2 text-sm font-semibold text-[#0a0e14]"
            style={{ background: danger ? "var(--color-bad)" : "var(--color-accent)" }}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

// --- Button -------------------------------------------------------------------
export function Btn({ children, onClick, variant = "ghost", disabled, size = "md" }:
  { children: ReactNode; onClick?: () => void; variant?: "primary" | "ghost" | "danger"; disabled?: boolean; size?: "sm" | "md" }) {
  const base = "inline-flex items-center gap-1.5 rounded-md font-medium transition disabled:opacity-40 disabled:cursor-not-allowed";
  const sz = size === "sm" ? "px-2.5 py-1 text-xs" : "px-3.5 py-2 text-sm";
  const styles =
    variant === "primary"
      ? "bg-[var(--color-accent)] text-[#0a0e14] hover:brightness-110"
      : variant === "danger"
      ? "border border-[var(--color-bad)]/50 text-[var(--color-bad)] hover:bg-[var(--color-bad)]/10"
      : "border border-[var(--color-border-bright)] text-[var(--color-ink-dim)] hover:text-[var(--color-ink)] hover:bg-[var(--color-panel-2)]";
  return (
    <button onClick={onClick} disabled={disabled} className={`${base} ${sz} ${styles}`}>
      {children}
    </button>
  );
}
