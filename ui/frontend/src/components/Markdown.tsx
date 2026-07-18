import type { ReactNode } from "react";

// Minimal, safe markdown → React (no dangerouslySetInnerHTML). Handles headings,
// bold, inline code, list items, blockquotes, hr, and links. Good enough for the
// pipeline's own briefings/reports.
function inline(text: string, key: string): ReactNode[] {
  const out: ReactNode[] = [];
  // split on `code`, **bold**, and [text](url)
  const re = /(`[^`]+`|\*\*[^*]+\*\*|\[[^\]]+\]\([^)]+\))/g;
  let last = 0, m: RegExpExecArray | null, i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith("`")) {
      out.push(<code key={`${key}-${i}`} className="mono rounded bg-[var(--color-panel-2)] px-1 py-0.5 text-[var(--color-accent)]">{tok.slice(1, -1)}</code>);
    } else if (tok.startsWith("**")) {
      out.push(<strong key={`${key}-${i}`} className="font-semibold text-[var(--color-ink)]">{tok.slice(2, -2)}</strong>);
    } else {
      const mm = /\[([^\]]+)\]\(([^)]+)\)/.exec(tok)!;
      out.push(<span key={`${key}-${i}`} className="text-[var(--color-info)]">{mm[1]}</span>);
    }
    last = m.index + tok.length;
    i++;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export function Markdown({ text }: { text: string }) {
  const lines = text.split("\n");
  return (
    <div className="space-y-1.5 text-sm leading-relaxed text-[var(--color-ink-dim)]">
      {lines.map((raw, i) => {
        const line = raw.replace(/\r$/, "");
        if (!line.trim()) return <div key={i} className="h-2" />;
        if (/^#{1,6}\s/.test(line)) {
          const level = line.match(/^#+/)![0].length;
          const txt = line.replace(/^#+\s/, "");
          const cls = level <= 1 ? "text-base font-bold text-[var(--color-ink)] mt-2"
            : level === 2 ? "text-sm font-semibold text-[var(--color-accent)] mt-3"
            : "text-sm font-semibold text-[var(--color-ink)] mt-2";
          return <div key={i} className={cls}>{inline(txt, `h${i}`)}</div>;
        }
        if (/^[-*]\s/.test(line)) {
          return (
            <div key={i} className="flex gap-2 pl-2">
              <span className="text-[var(--color-ink-faint)]">·</span>
              <span className="flex-1">{inline(line.replace(/^[-*]\s/, ""), `li${i}`)}</span>
            </div>
          );
        }
        if (/^>\s?/.test(line)) {
          return <div key={i} className="border-l-2 border-[var(--color-border-bright)] pl-3 italic">{inline(line.replace(/^>\s?/, ""), `q${i}`)}</div>;
        }
        if (/^(-{3,}|_{3,})$/.test(line.trim())) {
          return <hr key={i} className="my-2 border-[var(--color-border)]" />;
        }
        return <div key={i}>{inline(line, `p${i}`)}</div>;
      })}
    </div>
  );
}
