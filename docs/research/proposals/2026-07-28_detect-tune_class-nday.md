# PROPOSAL (proposal) for docs/knowledge/class-nday.md — detect-tune 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## Watch-list addition: CVE-2026-61511 — vBulletin pre-auth RCE (version-fingerprint only, never auto-trigger)
vBulletin 5.x ≤5.7.5, 6.x ≤6.2.1 — `eval()`-reachable via `ajax/render/[template]` (`pagenav` template),
public PoC out. SAFE confirm = version/banner fingerprint only (vBulletin version string, forum footer,
`/core/misc.php?do=` behavior) — do NOT send the actual `ajax/render/pagenav` payload; triggering it is
RCE, not a differential, and outside our safe-probe primitive. Version match without a safe differential
stays LEAD, same as every other KEV/CVE class (class-nday.md rule #3).
Source: https://www.bleepingcomputer.com/news/security/vbulletin-fixes-critical-pre-auth-rce-flaw-with-public-exploit/
