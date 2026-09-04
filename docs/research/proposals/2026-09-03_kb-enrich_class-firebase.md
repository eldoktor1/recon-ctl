# PROPOSAL (proposal) for docs/knowledge/class-firebase.md — kb-enrich 2026-09-03
_Review and apply manually; not auto-merged into the KB._

---
### Applied research — anonymous-auth rule escalation (2026-09-03)

## The "auth != null" gate is not a gate if Anonymous Auth is on
The single most common real-world Firestore/RTDB misconfiguration (2025 disclosures) is a security
rule that only checks `request.auth != null` at collection level, with no per-document `uid` match and
no sign-in-provider check. If the project's Firebase Authentication has **Anonymous** enabled (common —
default for guest-checkout/onboarding flows), anyone can self-issue a valid token with ZERO registration
and use it to satisfy that rule. This converts "requires login" into **effectively unauthenticated**,
and it's a gap our existing keys-only RTDB test and the Firestore/Storage 403-checks (lines above) don't
probe — those only test the FULLY-unauth path.

### SAFE escalation test (own throwaway anon session — not a real/third-party account)
