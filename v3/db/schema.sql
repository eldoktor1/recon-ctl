-- =============================================================================
-- v3 Phase B — SQLite finding-STATE store (complement to ES, not a migration).
--   ES   = "what assets exist"  (recon_alive, search/analytics)
--   SQLite = "where each finding is in its lifecycle"  (this file)
-- WAL mode + guarded transitions give transactional per-finding state and crash
-- safety — retiring triage's stale-priority / survivors-only flat-file bug class.
-- =============================================================================
PRAGMA journal_mode = WAL;       -- crash-safe, concurrent reader/writer
PRAGMA synchronous  = NORMAL;
PRAGMA foreign_keys = ON;

-- ---- findings: the lifecycle -------------------------------------------------
-- states: discovered -> scored -> verifying -> confirmed -> reported
--                                          \-> lead_exhausted   -> submitted
--                                          \-> dismissed
CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY,
    dedup_key       TEXT NOT NULL UNIQUE,         -- host|signal_class|vuln_class — one row per logical finding
    host            TEXT NOT NULL,
    url             TEXT,
    program         TEXT,
    tier            TEXT NOT NULL DEFAULT 'FINANCIAL',  -- Gate 0 classification (fail-safe default)
    signal_class    TEXT,                          -- gate probe class (version|unauth-surface|xss|...)
    vuln_class      TEXT,                          -- triage vuln class (rce|xss|takeover|...)
    state           TEXT NOT NULL DEFAULT 'discovered',
    score           INTEGER DEFAULT 0,
    priority        TEXT,
    confidence      REAL NOT NULL DEFAULT 0,       -- 0.0-1.0 deterministic evidence confidence (gate)
    review_tier     TEXT,                          -- immediate (>=0.85) | batch (0.70-0.84) | weekly (<0.70)
    -- Claude-Max validation agent (headless `claude -p`, no API) — the accuracy layer.
    ai_verdict      TEXT,                          -- real | fp | needs-human | NULL(=not yet reviewed)
    ai_confidence   REAL,                          -- Claude's 0.0-1.0 relevancy/exploitability confidence
    ai_reason       TEXT,                          -- Claude's one-line justification (adversarial)
    ai_reviewed_at  TEXT,
    fp_signature    TEXT NOT NULL,                 -- stable signature for FP/dup matching
    evidence        TEXT,                          -- JSON: probe, template, matched_at, redacted response
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 5,
    last_error      TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    state_changed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    verifying_since TEXT,                           -- set on entry to 'verifying'; NULL otherwise (crash-resume key)
    ttl_at          TEXT                            -- candidate expiry → lead_exhausted
);
CREATE INDEX IF NOT EXISTS idx_findings_state    ON findings(state);
CREATE INDEX IF NOT EXISTS idx_findings_host     ON findings(host);
CREATE INDEX IF NOT EXISTS idx_findings_program  ON findings(program);
CREATE INDEX IF NOT EXISTS idx_findings_fpsig    ON findings(fp_signature);
CREATE INDEX IF NOT EXISTS idx_findings_verifying ON findings(state, verifying_since);

-- ---- false_positive_signatures: stop re-deriving killed FPs ------------------
-- Every recon-ignore + dismissed finding + gate-exhausted lead writes a row.
-- Queried BEFORE scanning so the system goes quieter over time.
CREATE TABLE IF NOT EXISTS false_positive_signatures (
    id          INTEGER PRIMARY KEY,
    signature   TEXT NOT NULL UNIQUE,
    reason      TEXT,
    source      TEXT,                  -- recon-ignore | dismissed | gate-exhausted
    hit_count   INTEGER NOT NULL DEFAULT 0,   -- times re-encountered and suppressed
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    last_seen_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_fp_sig ON false_positive_signatures(signature);

-- ---- failure_patterns: rate-limit / ban recovery ----------------------------
CREATE TABLE IF NOT EXISTS failure_patterns (
    id            INTEGER PRIMARY KEY,
    pattern_type  TEXT NOT NULL,       -- rate-limit | ban | captcha | http-403-streak | timeout | dns-fail
    target        TEXT NOT NULL,       -- host or program the failure is scoped to
    detail        TEXT,
    count         INTEGER NOT NULL DEFAULT 1,
    recovery_state TEXT NOT NULL DEFAULT 'active',  -- active | backoff | recovered | halted
    backoff_until TEXT,                -- categorized exponential backoff target time
    first_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    last_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE(pattern_type, target)
);
CREATE INDEX IF NOT EXISTS idx_fail_target ON failure_patterns(target, recovery_state);

-- ---- audit_log: every state transition (Phase E observability source) -------
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY,
    finding_id  INTEGER,
    event       TEXT NOT NULL,         -- transition | probe | promote | halt | skip-fp | spend | ...
    from_state  TEXT,
    to_state    TEXT,
    detail      TEXT,
    at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);

-- ---- run_counters: per-program daily volume + LLM spend ceilings (Phase D) ---
CREATE TABLE IF NOT EXISTS run_counters (
    id          INTEGER PRIMARY KEY,
    day         TEXT NOT NULL,         -- YYYY-MM-DD (UTC)
    scope       TEXT NOT NULL,         -- program name | 'GLOBAL'
    metric      TEXT NOT NULL,         -- requests | llm_spend_usd | tests | confirmed | staged | halted
    value       REAL NOT NULL DEFAULT 0,
    UNIQUE(day, scope, metric)
);
CREATE INDEX IF NOT EXISTS idx_counters_day ON run_counters(day, scope, metric);

-- ---- knowledge_base: RAG-lite learning over past verified outcomes ------------
-- The article uses sqlite-vec semantic embeddings ("seen this stack before? what
-- broke?"). We adapt that to a NO-API, no-embedding-dependency design: every Claude
-- verdict writes a compact profile row here; the analysis/verify agents retrieve the
-- most relevant prior outcomes by tech-stack + vuln-class keyword match and inject
-- them into Claude's prompt as context. Claude does the semantic matching in-context.
-- Net effect matches the article: the system gets quieter and smarter over time,
-- avoiding mistakes (and noise) it has already reasoned through. (Can be upgraded to
-- true vectors later by adding an embedding column + sqlite-vec; the API stays same.)
CREATE TABLE IF NOT EXISTS knowledge_base (
    id            INTEGER PRIMARY KEY,
    host          TEXT,
    root_domain   TEXT,                  -- grouping key for "same target family"
    program       TEXT,
    tech          TEXT,                  -- comma-joined stack tags (primary retrieval dim)
    signal_class  TEXT,
    vuln_class    TEXT,
    verdict       TEXT NOT NULL,         -- real | fp | needs-human (the outcome that happened)
    confidence    REAL,
    reason        TEXT,                  -- Claude's one-line rationale (the learned lesson)
    profile       TEXT,                  -- normalized "tech | class | title" free-text for LIKE search
    source        TEXT,                  -- ai-verify | ai-analyze | operator
    hit_count     INTEGER NOT NULL DEFAULT 0,  -- times retrieved as context (usefulness signal)
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    last_seen_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_kb_tech       ON knowledge_base(tech);
CREATE INDEX IF NOT EXISTS idx_kb_vulnclass  ON knowledge_base(vuln_class);
CREATE INDEX IF NOT EXISTS idx_kb_rootdomain ON knowledge_base(root_domain);
CREATE INDEX IF NOT EXISTS idx_kb_verdict    ON knowledge_base(verdict);
