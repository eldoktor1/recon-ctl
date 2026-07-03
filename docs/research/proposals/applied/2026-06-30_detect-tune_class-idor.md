# PROPOSAL (proposal) for docs/knowledge/class-idor.md — detect-tune 2026-06-30
_Review and apply manually; not auto-merged into the KB._

## IDOR Confirm Primitive — Multi-Session Body Hash

Single-session automated scanners produce near-100% FP on IDOR (confirmed by BacAlarm, Dec 2025, arxiv:2512.19997). The authoritative confirm primitive requires two sessions:

1. Make the same request under **session A** (owner of the object) and **session B** (different account, no ownership)
2. Hash response bodies from both sessions
3. If hashes match AND body contains session A's private data = **IDOR CONFIRMED**
4. If status is `200` for both but bodies differ (session B gets empty/generic) = access control working = FP

**Status-code oracle (necessary but not sufficient):**
- `200` owner + `403` non-owner = correct access control
- `200` owner + `200` non-owner = IDOR candidate → proceed to body comparison

**Timing differential signal (supplementary):** Authorized requests are often faster (cached/indexed at auth layer). Absence of timing difference between sessions = potentially missing auth check. Not a standalone signal but corroborates body-match findings.

**FP suppression in ai-hunter output:** when the hunter flags an IDOR hypothesis, the 2-account confirm step must verify response body equality cross-session, NOT just HTTP 200 status. A 200 with empty body or generic schema = FP.

**Never auto-confirm IDOR:** needs 2 owned accounts + operator-executed swap. The hunter provides the ranked hypothesis + the object reference + the swap instructions; the human runs the test.

Source: https://arxiv.org/pdf/2512.19997, https://apiiro.com/blog/why-dast-tools-miss-real-idor-vulnerabilities-and-how-ai-helps/
