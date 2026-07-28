# PROPOSAL (proposal) for docs/knowledge/class-race-conditions.md — kb-enrich 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## Attack-method selection by HTTP version (added 2026-07-28)

The existing single-packet primitive **requires HTTP/2** (client holds back the final packet fragment
of each request so all N arrive in one TCP write, eliminating jitter). Many in-scope hosts still speak
HTTP/1.1 only (check via `httpx -td` / ALPN) — for those, fall back to **last-byte synchronization**:
send every request except its final byte, hold all connections open, then release the last byte of
every connection back-to-back. The server starts processing request 2 while still finishing request 1's
tail, producing the same TOCTOU window without needing H2. Turbo Intruder supports both natively —
`engine=Engine.BURP2` (H2 single-packet) vs `engine=Engine.THREADED`/`Engine.BURP1` style gate-queue for
H1 last-byte-sync. Detect which to use per-host before hand-writing the script (wasted effort on an H1
host using the H2-only technique looks like "no race" when it's actually "wrong protocol").

## Warm-up request (kills a false-negative) (added 2026-07-28)

The FIRST request on a fresh connection is frequently slower (TLS handshake, connection-pool cold-start,
JIT/cache warm-up on the app server) — this alone can desync an otherwise-real race and produce a false
"not vulnerable" result. Fire one throwaway warm-up request (same endpoint, discarded response) before
the timed batch to put the connection/pool in steady state, THEN queue the real N-request race. Apply
this to every race test, not just ones that failed first try.

## Multi-endpoint races — same shared state, different code paths (added 2026-07-28)

Don't limit racing to N copies of ONE request. The higher-value, less-crowded variant: identify TWO
DIFFERENT endpoints that touch the same underlying record/counter/balance (e.g. `/checkout/apply-coupon`
+ `/cart/recalculate`, or `/withdraw` + `/transfer`, or `/2fa/verify` + `/2fa/resend`) and fire them
concurrently against each other. Single-endpoint duplication is what most automated race scanners already
try (some saturation risk); racing across the *application's own workflow steps* against each other is
where validation gaps actually hide, because devs reason about atomicity within one endpoint, not across
two.

## Expanded endpoint/class signal list (added 2026-07-28)
Beyond the existing path list (`/coupon`, `/transfer`, `/limit`, `/verify`, `/register`), add:
- **Gift-card / store-credit redemption** — same card code redeemed via concurrent requests before the
  balance decrement commits (real payout class, high severity: direct monetary value).
- **2FA/OTP verify vs resend** — race `verify` against a SEPARATE `resend`/`regenerate` call: some
  implementations invalidate the old code only after the new one is generated, creating a window where
  the OLD code still validates.
- **Referral/invite bonus** — trigger the "redeem referral" action concurrently to stack the bonus
  multiple times per unique referral code.
- **Retest/verification-triggered payout** — on platforms/apps with a "confirm fix" or "claim reward"
  action tied to a one-time payout, concurrent confirm requests can trigger the payout logic more than
  once if the payout-issued flag isn't set atomically before the payment call (reported pattern on a
  bug-bounty platform's own retest-confirmation feature — verify mechanism independently, source fetch
  was inconclusive).

## Sources
- https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-race-condition-vulnerabilities
- https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/race-single-packet-attack.py
- https://www.bugcrowd.com/blog/racing-against-time-an-introduction-to-race-conditions/
- https://hackerone.com/reports/1418419 (title/context only — fetch returned no body, re-verify details before relying on specifics)
