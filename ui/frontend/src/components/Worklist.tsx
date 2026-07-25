// Parsed-briefing shapes (matches ui/backend/files.py parse_briefing).
// The interactive rendering moved to CompactLeadRow + the unified Leads worklist
// (deduped across sources, inline testing controls); this module now just carries
// the shared types consumed by Leads and the Command Center "Tonight" preview.

export interface WLItem {
  raw: string;
  label: string;
  hosts: string[];
  commands: string[];
  program: string | null;
  severity: string | null;
  suppressed?: boolean;
  suppress_reason?: string | null;
}

export interface WLSection {
  id: number;
  emoji: string;
  title: string;
  count: number;
  items: WLItem[];
  suppressed_count?: number;
}

export interface Parsed {
  name: string;
  kind?: string | null;
  date?: string | null;
  mtime?: number;
  title?: string;
  sections: WLSection[];
  error?: string;
}
