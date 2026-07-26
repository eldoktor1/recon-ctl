import { useCallback, useEffect, useRef, useState } from "react";

type Axis = "x" | "y";

// Drag-to-resize primitive for the docked panels (TaskConsole height, HostDrawer width).
// The grip sits on the edge that faces the viewport centre, so dragging TOWARD that origin
// (top for a bottom-docked panel, left for a right-docked drawer) GROWS the panel — hence
// `delta = dragStart - pointer`. Size persists to localStorage per `storageKey` and is
// re-clamped to [min, max()] on drag and on window resize. No external deps.
export function useResizable(opts: {
  axis: Axis; storageKey: string; initial: number; min: number; max: () => number;
  // default false: grip faces the viewport centre (docked panels), dragging toward it grows.
  // true: grip is on the trailing edge (bottom/right of an inline box), dragging AWAY grows.
  growTowardPointer?: boolean;
}) {
  const { axis, storageKey, initial, min, max } = opts;
  const dir = opts.growTowardPointer ? 1 : -1;

  const [size, setSize] = useState<number>(() => {
    try {
      const v = Number(localStorage.getItem(storageKey));
      if (v && !Number.isNaN(v)) return v;
    } catch { /* ignore */ }
    return initial;
  });
  const sizeRef = useRef(size); sizeRef.current = size;
  const drag = useRef<{ start: number; base: number } | null>(null);

  const clamp = useCallback((v: number) => Math.max(min, Math.min(max(), v)), [min, max]);

  useEffect(() => {
    const onMove = (e: PointerEvent) => {
      if (!drag.current) return;
      const pos = axis === "y" ? e.clientY : e.clientX;
      setSize(clamp(drag.current.base + dir * (pos - drag.current.start)));
    };
    const onUp = () => {
      if (!drag.current) return;
      drag.current = null;
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
      try { localStorage.setItem(storageKey, String(Math.round(sizeRef.current))); } catch { /* ignore */ }
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    };
  }, [axis, clamp, storageKey, dir]);

  // keep the panel inside the viewport when it shrinks
  useEffect(() => {
    const onResize = () => setSize((s) => clamp(s));
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, [clamp]);

  const onGripDown = useCallback((e: React.PointerEvent) => {
    e.preventDefault();
    drag.current = { start: axis === "y" ? e.clientY : e.clientX, base: sizeRef.current };
    document.body.style.userSelect = "none";
    document.body.style.cursor = axis === "y" ? "ns-resize" : "ew-resize";
  }, [axis]);

  return { size, onGripDown };
}
