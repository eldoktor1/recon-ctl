# =============================================================================
# recon_fp_footer.py — the SINGLE source of the ZERO-FP discipline footer stamped
# on EVERY pick-stage worklist (recon_mood lanes + the xss/sqli candidates briefing).
#
# A pick (mood/lane/ranker) only SURFACES leads — every line it emits is a LEAD, not a
# finding. FP-elimination happens DOWNSTREAM at the same chokepoints every finding passes,
# no matter how it was picked. No pick can lower this bar (the bar lives after the pick).
# Keep it here so the doctrine text can't drift between files.
# =============================================================================
FP_FOOTER = (
 "\n---\n**ZERO-FP — every line above is a LEAD, not a finding. To clear the bar:**\n"
 "1. **CONFIRM (per-class SAFE primitive must FIRE):** a pattern/tech/host/signal match is a LEAD; only "
 "the primitive firing = CONFIRMED — xss→dalfox EXECUTES (reflection≠XSS), sqli→`'`vs`''` differential, "
 "takeover→claimability (NXDOMAIN/NoSuchBucket), ssrf/xxe→OOB canary, cve→in-range RUNNING version. "
 "catch-all-200 / SPA-shell / stale-tech / version-only ≠ bug.\n"
 "2. **CLAUDE VERIFY (hard gate):** nothing reaches a report without the consensus panel "
 "(exploitability + scope-reward + evidence-repro) returning `real`; the reporter hard-gates on "
 "ai_verdict='real'. Confident FPs die in one cheap pass.\n"
 "3. **IMPACT-GATE:** theoretical/no-impact (CORS reflect, missing headers, self-XSS, "
 "info-disclosure-without-impact) = N/A → skip. **NOTE every FP/skip inline** so it's never re-walked.\n"
)
