# PROPOSAL (proposal) for docs/knowledge/class-race-conditions.md — kb-enrich 2026-09-17
_Review and apply manually; not auto-merged into the KB._

## 2026 update — lightweight detection + multi-endpoint chaining

**Tooling note:** Burp 2026 Repeater has native "Send group in parallel" (select a request group → context menu) —
same single-packet/last-byte-sync mechanics as Turbo Intruder's script, no Jython needed for simple 2-20 request races.
Reach for Turbo Intruder only when you need >20 requests, IP-fragmentation scale, or custom logic.

**Systematic race-spotting (use during the WSTG walk, not ad hoc):** for every endpoint, ask —
1. Is state server-side and persistent (client-side/ephemeral state can't race)?
2. Does the op MODIFY an existing record, or only ADD (modifications are higher-risk)?
3. Do concurrent requests key to the SAME resource (own account/object — never third-party)?
Common vulnerable flows: email/account activation, invite acceptance, multi-step checkout,
coupon redemption, plan/tier limit checks (site count, seat count, API-key count).

**Multi-endpoint limit-overrun chain (own-account only, maps to our 2-account IDOR doctrine):**
race a CREATE endpoint that has a plan/tier limit (e.g. "max 1 free site") to create extra owned
records past the limit — the limit check races against record insertion (TOCTOU). Then check
a SIBLING read endpoint (list/upstreams/catalog-style) for IDs/UUIDs normally reserved for a
paid tier but returned to any authenticated caller. Feed those (still-owned-resource) IDs back
into the race-created records via their normal update/deploy endpoint. Result: paid-tier
functionality unlocked on a free account, using ONLY your own records — no guessed/third-party
IDs, fits ACTIVE-PoC doctrine (prove then stop). Source case: Mahmoud Gamal, Nov 2025,
"Race condition chained with logic bug leads to full bypass of free-plan site limit"
(https://medium.com/@mhmodgm54/race-condition-chained-with-logic-bug-leads-to-full-bypass-of-free-plan-site-limit-5825f5e2cb1c).

**Protocol gate:** single-packet attack needs HTTP/2 — check first:
`curl -s --http2 -o /dev/null -w '%{http_version}\n' https://target/`
HTTP/1.1-only targets fall back to last-byte-sync (Turbo Intruder `engine=Engine.THREADED`, µs jitter).
IP-fragmentation extends the single-packet window past 1500B (up to TCP's 65535B), reported
~10,000 requests in ~166ms — only worth it for wide batch races (bulk coupon/limit farming),
not standard 2-request differential races.

**Reference payout calibration:** H1 #429026 (bounty-platform retest → multiple payouts),
H1 #1913309 (Firefox Monitor email-limit bypass via concurrent registration), CVE-2022-4037
(GitLab email-verification race → account takeover).
Sources: https://www.hackcraft.gr/2026/04/race-conditions-and-where-to-find-them/ ,
https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/race-single-packet-attack.py
