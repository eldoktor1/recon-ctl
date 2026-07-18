# PROPOSAL (proposal) for docs/knowledge/class-idor.md — tooling 2026-07-17
_Review and apply manually; not auto-merged into the KB._

## Reference pattern: three-phase mutation proof (for authed 2-account IDOR/BOLA confirm)

Source: praetorian-inc/hadrian (github.com/praetorian-inc/hadrian, evaluated 2026-07-17) — formalizes
what our human-in-the-loop 2-owned-account IDOR test already does manually. Useful as a checklist for
Claude-in-Chrome authed-confirm prompts, not as a tool we run:

1. **Setup** — Role/Account A creates (or has) a resource, record its object ID.
2. **Attack** — Role/Account B (the OWNED second account) attempts to read/modify/delete that ID.
3. **Verify** — Re-check as Account A whether the object actually changed/was exposed — don't trust a
   200 OK alone. APIs that accept an unauthorized write but silently no-op it are a classic false-positive
   source for naive IDOR scanners; the verify step is what makes the finding real.

Keep our existing minimality discipline on top of this shape: stop at proof, never touch objects you
don't own, prefer a reversible/benign action (read a field, not a destructive delete) unless impact
specifically requires demonstrating a write/delete.
