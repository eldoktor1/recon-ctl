# Triage full-rescore coverage + index-hygiene analysis — 2026-06-23

Follow-up to 8c772c2 (band-aid: FULL fetch capped at TRIAGE_MAX_CANDIDATES=200k + 14GiB ulimit).

## Measured state of recon_alive (single shard, ES 8.17.4)
| metric | value |
|---|---|
| all docs | 2,779,457 |
| 30d + status 200-599 (full-mode candidate window) | 2,673,828 |
| has `triage_at` | 2,779,411 (99.998%) |
| **missing `triage_at`** | **46** |
| `triage_in_scope=true` | 1,420,297 (~51%) |
| `triage_pays=true` | 1,381,250 (~50%) |
| ignore_active (range) | 0 |

## Bloat: top root_domains by doc count
| docs | root | note |
|---|---|---|
| **1,392,755** | **tumblr.com** | **50.1% of the whole index** — per-user blog sprawl `<username>.tumblr.com`, mostly 404/429/302, score 5, 849,527 tagged in_scope+pays=true |
| 168,952 | etsy.com | likely seller-subdomain sprawl |
| 152,736 | taobao.com | shop-subdomain sprawl |
| 95,663 | 1688.com | |
| 59,846 | tmall.com | |
| 7,279 | *.unifi-hosting.ui.com | shared-tenant (doctrine hard-line) |
| 188 | meraki *-spare-* | product-class (`csNNN-spare-2037.meraki.com`) |

root_domain cardinality: 42,068 distinct roots.

## Problem with the band-aid (8c772c2)
Full mode sorts by `_doc` + search_after → the 200k cap always covers the SAME first
200k docs → the ~2.5M tail never gets a full re-score (stale scope/cluster penalties on
unchanged tail docs go stale). Incremental still re-scores docs when they change.

## Deliverable 1 — rotate coverage (operator-confirmed)
Changed full-mode sort `_doc` → `[{triage_at:{order:asc,missing:_last}},{host:{order:asc}}]`.
- `mark_triage_seen` stamps `triage_at=now` on EVERY fetched doc at cycle start → the
  re-scored batch becomes the newest, sorts LAST next run → consecutive full runs rotate
  oldest-first through the whole index.
- `host` is a `keyword` AND the `_id` (unique) → `(triage_at, host)` is a UNIQUE sort tuple
  → search_after pagination has NO skip/dup even without a PIT. (triage_at is written ONLY
  by triage itself, under flock — never mutated concurrently mid-fetch.)
- `missing:_last`: the 46 never-triaged docs sort last (never reached under the 200k cap)
  and are covered by INCREMENTAL mode (`must_not exists triage_at` should-clause).
- Pagination captures the WHOLE sort tuple and feeds it back as search_after, preserving
  JSON types (date sort = numeric epoch-millis, host = string).

## Deliverable 2 — index hygiene (operator-confirmed: exclude from FULL query)
Added env-configurable denylist to the FULL query `must_not` (NOT ingest pruning —
reversible, keeps incremental coverage of changes, freezes only the FULL rotation):
- `TRIAGE_FULL_EXCLUDE_ROOTS` (default `tumblr.com`) — exact root_domain terms.
- `TRIAGE_FULL_EXCLUDE_HOSTS` (default `*.unifi-hosting.ui.com,*-spare-*`) — host wildcards.
Excluded docs keep existing triage state; incremental still re-scores them on change. Blank
either var for a one-off unfiltered full pass.

## Verification (2026-06-23 / 24)
- `bash -n scripts/triage.sh` — clean.
- New FULL query validated live: exclusions cut the pool **2,673,782 → 1,275,238** (−52%);
  composite-sort search_after across 2 pages = **0 overlap/skip** (handles the same-`triage_at`
  tie correctly); host wildcards are cheap (es_took 270–303ms/page, no regression).
- Manual `TRIAGE_MODE=full` runs (partial — see env note) collectively re-fetched +
  `mark_triage_seen`-stamped **400,000** docs:
  - **No OOM**: dmesg oom-line count fixed at 1 (pre-existing) before/after; mem_available
    18–19 GB throughout; peak observed jq/curl RSS tiny. The cluster slurp is bounded by the
    inherited 200k cap (memory-safety already proven by 8c772c2 in production).
  - **No scope corruption**: `triage_in_scope`=1,420,321, `triage_pays`=1,381,273,
    `has_triage_at`=2,779,441 — IDENTICAL before and after the 400k writeback.
  - **Excluded sprawl untouched**: the tumblr sample doc was byte-identical before/after
    (never fetched by full mode).
  - **Rotation confirmed**: `fresh<25m`=400,000 freshly stamped; `stale>1h` shrank by exactly
    400,000 (2,778,624 → 2,378,624); newest `triage_at` docs are meaningful non-tumblr hosts.

### Env note — WSL relay wedge blocked single-shot end-to-end completion
Triage launched from an ephemeral `wsl.exe` one-shot (Bash bg / setsid / foreground /
`systemd-run --user`) is reaped the instant the jq scoring phase spikes CPU: the WSL interop
relay wedges (VM stays up, relay drops — the residual symptom in the WSL-wedge memory). This
is environmental and orthogonal to this change — the operator's long-lived daemon runs full
triage to completion normally. Only `fetch_es_data` was modified; the score → enrich → slurp
→ `update_es_scores` writeback path is unchanged from the shipped band-aid. The next daemon
full-run completes the slurp+score-writeback end-to-end naturally; recon-audit/watchdog alarm
if triage breaks.

NOT doing ingest-level pruning/deletion in this change (bigger, irreversible, separate).
Observed but out of scope: stale multi-GB `reconrun`-owned `/tmp/tmp.*` raw files leaked from
killed pre-band-aid daemon triage runs — candidate for a separate temp-file-cleanup pass.
