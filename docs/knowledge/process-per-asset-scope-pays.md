# Per-asset bounty eligibility — how `pays` is really derived

**Status:** fixed 2026-09-05. Read this before touching `recon_scope_db.sh`,
`recon_scope_check.sh`, or anything that gates on `pays` / `triage_pays`.

## The rule

**A program paying bounties does NOT mean every asset in its scope pays.**
HackerOne carries `eligible_for_bounty` on each in-scope asset, and a paying
program routinely marks part of its surface submission-only. Intigriti does the
same with a per-target `impact: "No Bounty"` tag. `pays` must always come from
the asset that actually matched, never from the program header.

This is the machine half of [[exclusion-gate-before-investing]] — 6 reports, 0
paid, all lost on eligibility rather than validity. The scope gate was answering
the wrong question.

## What was wrong (before 2026-09-05)

`recon_scope_db.sh` set `pays` from the program-level `.offers_bounties` bool and
flattened `.targets.in_scope[]` to a list of bare `asset_identifier` strings,
throwing `eligible_for_bounty` away. `recon_scope_check.sh` then reported the
program value for every host under any of those patterns.

Reference case — `hackerone/logitech`:

| | |
|---|---|
| in-scope URL/WILDCARD assets | 58 |
| bounty-eligible | 15 |
| `*.logitech.com` | `eligible_for_bounty: false` |
| `*.streamlabs.com` | `eligible_for_bounty: true` |
| ES `recon_alive` hosts on the program | 717 |
| hosts on payable surface | 122 (106 reachable — see the glob gap below) |
| ES hosts gated `triage_pays: true` | **717** |

`pays` is the money gate on essentially every lane — `recon_jsintel.sh`
`in_scope_now`, `recon_safe_probe.sh`, the xss/sqli confirm gates, the IDOR
ranker, `recon_nday.sh`, the bucket/GraphQL/WCD/kr/permute lanes, the briefings —
so all of them were spending budget on surface that can never pay.

Estate-wide, `recon_scope_check` flipped **9,145** ES hosts from `pays:true` to
`pays:false` and, as a side effect of the resolution fix below, **1,209** the
other way.

## What each feed actually carries

Fields as they appear in `arkadiyt/bounty-targets-data` (verified 2026-09-05):

| platform | per-asset eligibility field | notes |
|---|---|---|
| **hackerone** | `eligible_for_bounty` (bool), plus `eligible_for_submission`, `max_severity` | present on 100% of assets, never null. 2,912 of 3,115 assets on paying programs are eligible; **30 of 205 paying programs are partial**, 2 have none |
| **intigriti** | `impact` — `"No Bounty"` / `Tier 1..3` / null | the program-level `all_no_bounty` check already existed; it is now applied per target too |
| **bugcrowd** | *none* | feed target fields are `type/target/uri/name/ipAddress` only. Bugcrowd shows per-target reward ranges on the brief but the feed does not carry them — **check the brief manually before investing in a bugcrowd target** |
| **yeswehack** | *none* | `target/type` only |
| **federacy** | *none* | `target/type` only |

Platforms without the field inherit the program value per asset, so the
downstream shape is uniform and a future feed change is a one-line edit.

## The shape now

`scope/programs.json`, every platform:

```jsonc
{
  "pays": true,                    // offers bounties AND >=1 asset is eligible
  "in_scope":        [...],        // ALL in-scope assets — SUBMISSION scope, shape unchanged
  "in_scope_assets": [ { "asset": "...", "pays": bool, "submit": bool, "max_severity": "critical" } ],
  "in_scope_paying": [...],        // assets that can pay
  "in_scope_nopay":  [...]         // submission-only assets
}
```

`in_scope` deliberately keeps every asset and its old string shape: those hosts
are still **in scope for submission**, they just cannot pay. Existing consumers
that read `.in_scope[] | select(type == "string")` keep working.

`scope/inscope_patterns.tsv` — **7 columns**, one row per ASSET:

```
1 pattern  2 handle  3 platform  4 pays  5 payout_tier  6 max_severity  7 submit
```

Column 4 is now the per-asset value, so every consumer already filtering
`$4=="true"` (`recon_discovery.sh` paying-roots, `recon_true_fresh.sh`
paying-roots, `recon_scope_check.sh`) inherited the fix with no edit. Columns 6-7
are appended, so 4- and 5-column readers still parse.

## Resolution: most-specific asset wins, then best-paying program

`recon_scope_check.sh` resolves in two stages:

1. **Within a program**, the MOST SPECIFIC matching asset governs. An exact host
   beats any wildcard; a longer wildcard apex beats a shorter one. This is what
   makes `jira.logitech.com` (`eligible:false`) stop inheriting `*.logitech.com`,
   while `www.logitech.com` (`eligible:true`) keeps paying on the same program.
2. **Across programs**, the best payout tier wins, tie-broken by file order — a
   host in scope on both a paying program and a VDP is still worth money.

The stage-1 tie-break (paying wins at equal specificity) exists because the TSV
strips the scheme and path off an asset, so a path-scoped asset collapses onto a
host pattern. All 3 such collisions in the current feed are exactly that, and in
every one the paying row is the correct answer for a bare host:

| pattern | paying row | non-paying row it collides with |
|---|---|---|
| `*.ui.com` | `*.ui.com` | `https://*.ui.com/distributors/`, `https://*.ui.com/training/partners/` |
| `www.logitech.com` | `www.logitech.com` | `https://www.logitech.com/blog` |
| `w1.uzleuven.be` | `w1.uzleuven.be` | a `No Bounty`-tagged path on the same host |

A non-paying PATH does not make the HOST non-paying — and we do not carry paths
in the pattern table, so the host-level answer has to be the permissive one.

Stage 2 also fixed a real bug: the old matcher kept only the FIRST row per
pattern, so when `*.vrbo.com` appeared under both `expediagroup` (VDP,
`offers_bounties:false`) and `expediagroup_bbp` (paying), file order decided, and
1,209 genuinely payable hosts were gated `pays:false`. Buckets now hold every row.

`recon_scope_check.sh <host>` gained `max_severity` and `eligible_for_submission`
for the matched asset. `pattern` is now the SPECIFIC asset that decided `pays`,
not merely some matching pattern.

## Verification

```bash
bash scripts/recon_scope_check.sh jira.logitech.com   # pays:false, in_scope:true, pattern *inherited* from the exact asset
bash scripts/recon_scope_check.sh dev.streamlabs.com  # pays:true  via *.streamlabs.com
bash scripts/recon_scope_check.sh www.logitech.com    # pays:true  — exact eligible asset beats *.logitech.com
```

Regression over 60,261 hosts, old matcher+TSV vs new: **`in_scope` changed on 0
hosts**, platform 0, program 14 (all VDP→paying corrections), pays 170 T→F / 14
F→T. Submission scope is byte-identical; only the money gate moved.

## ES writeback

`triage_pays` / `triage_in_scope` / `triage_out_of_scope` / `triage_payout_tier` /
`triage_program` / `triage_platform` are written by `triage.sh:update_es_scores()`
straight from `recon_scope_check.sh --batch`, so they are only as current as the
last time triage rotated that doc. FULL triage sorts most-stale-first under
`TRIAGE_MAX_CANDIDATES`, so on a ~530k-doc index a derivation change takes several
cycles to reach every host.

`scripts/recon_scope_resync.sh` (also `recon_ctl.sh scope-resync`) is the one-shot
correction — recompute every alive host against the current scope DB, write back
only the docs that differ:

```bash
bash scripts/recon_scope_resync.sh            # dry run: report drift
bash scripts/recon_scope_resync.sh --apply    # write the corrections
```

Guards: refuses to run against a TSV with `< MIN_PATTERNS` (10,000) rows, and
refuses to write if `>= MAX_PCT` (50%) of the index would change — that is a
broken scope DB, not a scope fix. It does NOT re-score: `triage_score` /
`triage_priority` carry the tier and pays bonuses, and re-deriving them here would
fork triage's scoring math. Scores self-correct on the next rotation; the gates
every lane reads are corrected immediately. Localhost ES + the local TSV only — no
egress, no target traffic.

Run it after any change to how scope is derived. Ordinary daily feed drift does
not need it — triage rotation handles that.

**Backfill applied 2026-09-05:** 25,644 of 529,623 docs corrected (9,145 of them
`triage_pays`). `logitech` went from 717/717 `triage_pays:true` to 106/717, with
all 717 still `triage_in_scope:true`.

## Discovery budget

`recon_ctl.sh cmd_bulk` now enumerates `in_scope_paying` (falling back to
`in_scope`) when filtered to paying programs — subfinder-ing `*.logitech.com`
spends the whole discovery budget on unpayable surface. Paying wildcard roots
982 → 896, direct hosts 3,167 → 3,062. `--all` is unchanged.

## Known gap: mid-label glob patterns (pre-existing, NOT introduced here)

The matcher only understands a leading `*.`. Patterns with a glob anywhere else
never match anything:

- `*vc.logitech.com` (eligible) — 16 live logitech hosts sit under it and are
  reported `pays:false`. This is the whole 106-vs-122 difference.
- `analytics-*.8x8.com`, `api*.netflix.com`, `*.logitechg.com*`, `*-api-*.acronis.com`

258 of 41,100 TSV patterns, **139 of them on paying assets**. The failure is
conservative — hosts are under-reported as non-paying, never over-reported as
paying — so it costs opportunity, not compliance. Fixing it needs a real glob
matcher, which is a different change from this one: the current design is an
O(labels) hash lookup and a glob pass cannot use it.

## Rules

- `pays` comes from the matched ASSET. Never re-derive it from a program bool.
- `in_scope` and `pays` are different questions. An asset can be in scope for
  submission and pay nothing; that is a valid, common state, not a bug.
- When adding a platform normalizer, look for the per-target eligibility field
  FIRST and emit `in_scope_assets`. If the feed has none, say so in a comment
  next to the fallback so the next person does not assume it was checked.
- After changing how scope is derived, run `scope-resync` — do not wait for
  triage rotation to catch up on a money gate.

## Sources

- `~/recon/scope/raw/hackerone.json` — `targets.in_scope[].eligible_for_bounty`,
  `.eligible_for_submission`, `.max_severity`
- `~/recon/scope/raw/intigriti.json` — `targets.in_scope[].impact`
- `scripts/recon_scope_db.sh`, `scripts/recon_scope_check.sh`,
  `scripts/recon_scope_resync.sh`, `scripts/triage.sh:update_es_scores()`
- `scripts/recon_target_select.py:89` already read `eligible_for_bounty` when
  picking programs — the program picker was right, the scope gate was not.
