# PROPOSAL (proposal) for docs/knowledge/tech-varnish.md — detect-tune 2026-07-11
_Review and apply manually; not auto-merged into the KB._

## Unauthenticated PURGE fingerprint (safe, OPTIONS-only), 2026-07-11
Known misconfig class: Varnish deployments that accept `PURGE` requests without auth
(unauthenticated cache invalidation / potential poisoning primitive). Safe detection: send
`OPTIONS` to the host and check the `Allow:` response header for `PURGE` with no auth challenge
present — zero-risk (no actual PURGE issued). Treat a hit as a LEAD; actually sending PURGE is a
state-changing action and stays operator-gated, not part of the autonomous safe-probe set.
