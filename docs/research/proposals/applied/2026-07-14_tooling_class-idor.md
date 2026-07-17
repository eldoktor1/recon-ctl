# PROPOSAL (proposal) for docs/knowledge/class-idor.md — tooling 2026-07-14
_Review and apply manually; not auto-merged into the KB._

## Tool watch: Hadrian (praetorian-inc/hadrian), added 2026-07-14
Go, Apache-2.0, v1.0.0 (2026-03-26), active. Automates the exact human-in-loop BOLA/BFLA
confirm workflow our SOP already does manually: define per-role creds once, it cross-tests
every role combination against every endpoint via setup(victim creates resource) →
attack(attacker requests it) → verify(confirms the unauthorized read/write actually
succeeded) — real mutation testing, not status-code guessing. REST coverage strongest;
GraphQL/gRPC templates thinner; no SSRF coverage.

**How this fits our doctrine:** NOT for the autonomous unauth pipeline (it mutates state).
Use it only the way we already use 2-owned-account manual IDOR testing: operator-run,
against your own accounts/staging resources, `--dry-run` preview first. It's a force-
multiplier for the existing authed-confirm step (fewer manual Repeater swaps to hand-craft
per endpoint), not a new autonomous lane.

Source: https://github.com/praetorian-inc/hadrian
