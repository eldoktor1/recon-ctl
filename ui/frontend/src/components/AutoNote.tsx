import { useState } from "react";
import { Btn, useToast } from "./controls";
import { GuideStream } from "./GuideStream";
import { getTask, setTask, clearTask } from "../taskStore";

// Reusable note affordance for the workspace: an always-available OPTIONAL note (type + save)
// PLUS a Claude "auto-draft" that summarizes where testing stands and fills the box for you to
// confirm/edit before saving. Used for per-host notes (end of testing a host) and per-program
// engagement notes. Nothing is written until you click save — the draft is a suggestion.
//
// `storeKey` persists the draft task across navigation (e.g. closing the host drawer): returning
// RECONNECTS to the still-running/finished draft instead of re-spawning it (which wastes tokens).
export function AutoNote({ title, hint, spawn, onSave, storeKey, rows = 3 }:
  { title: string; hint?: string;
    spawn: () => Promise<{ task_id?: number; id?: number }>;
    onSave: (text: string) => Promise<any>;
    storeKey?: string; rows?: number }) {
  const toast = useToast();
  const [draft, setDraft] = useState("");
  const [tid, setTid] = useState<number | null>(() => (storeKey ? getTask(storeKey) : null));
  const [gen, setGen] = useState(() => !!(storeKey && getTask(storeKey)));  // reconnecting?
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const dropTask = () => { if (storeKey) clearTask(storeKey); setTid(null); setGen(false); };

  const autoDraft = async () => {
    setGen(true); setSaved(false); setTid(null);
    try {
      const t = await spawn();
      const id = t.task_id ?? t.id;
      if (id == null) throw new Error("no task id returned");
      setTid(id);
      if (storeKey) setTask(storeKey, id);   // persist for reconnect-on-return
    } catch (e: any) { toast("err", e.message); setGen(false); }
  };

  // Fill the box with the AI draft only if the operator hasn't already typed their own note.
  const onDraftDone = (text: string) => {
    setGen(false);
    if (text) setDraft((d) => (d.trim() ? d : text));
  };

  const save = async () => {
    const text = draft.trim();
    if (!text) { toast("err", "note is empty"); return; }
    setSaving(true);
    try { await onSave(text); toast("ok", `${title} saved`); setSaved(true); setDraft(""); dropTask(); }
    catch (e: any) { toast("err", e.message); }
    finally { setSaving(false); }
  };

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[11px] uppercase tracking-wider text-[var(--color-ink-faint)]">{title}</span>
        <Btn size="sm" onClick={autoDraft} disabled={gen}>{gen ? "◎ drafting…" : "◎ auto-draft (Claude)"}</Btn>
        {hint && <span className="text-[10px] text-[var(--color-ink-faint)]">{hint}</span>}
      </div>
      <textarea value={draft} onChange={(e) => { setDraft(e.target.value); setSaved(false); }}
        rows={rows} placeholder="type a note, or auto-draft one — then save…"
        className="mono w-full resize-y rounded border border-[var(--color-border-bright)] bg-[var(--color-panel-2)] px-2 py-1.5 text-[11px] text-[var(--color-ink)] outline-none focus:border-[var(--color-accent)]" />
      <div className="flex items-center gap-2">
        <Btn size="sm" variant="primary" onClick={save} disabled={saving || !draft.trim()}>{saving ? "saving…" : "save note"}</Btn>
        {saved && <span className="text-[10px] text-[var(--color-good)]">✓ saved</span>}
      </div>
      {tid != null && <GuideStream tid={tid} onComplete={onDraftDone} />}
    </div>
  );
}
