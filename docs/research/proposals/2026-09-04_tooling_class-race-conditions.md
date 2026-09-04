# PROPOSAL (proposal) for docs/knowledge/class-race-conditions.md — tooling 2026-09-04
_Review and apply manually; not auto-merged into the KB._

## Tooling (added 2026-09-04)
- **`nxenon/h2spacex`** (github.com/nxenon/h2spacex, 230★, actively developed) — Scapy-based CLI/
  library implementing Kettle's HTTP/2 single-packet ("last-frame-sync") attack: batches N requests
  into one TCP write so they arrive server-side simultaneously, turning a network-race into a
  near-guaranteed local-odds race. Use for double-redeem/double-apply/limit-bypass PoCs on an OWNED
  account (`feedback_active_poc_doctrine`: minimal, confirm-then-stop). Complements `QuicDrawH3`
  (evaluated 2026-08-23) which covers the HTTP/3-terminating slice of our estate — h2spacex covers
  the HTTP/2 slice. Neither is wired into an autonomous lane; both are operator-driven WSTG BUSL tools.
