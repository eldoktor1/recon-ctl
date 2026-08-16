# PROPOSAL (proposal) for docs/knowledge/class-race-conditions.md — kb-enrich 2026-08-16
_Review and apply manually; not auto-merged into the KB._

## First-sequence-sync — extending single-packet races past 20-30 requests (added 2026-08-16)

The standard HTTP/2 single-packet attack (our existing Turbo Intruder script) caps out around
20-30 synchronized requests per connection (Ethernet-frame / TCP-window limits). GMO Flatt
Security (Aug 2024) published a technique that breaks both the 1,500-byte frame limit and the
65,535-byte TCP window limit, syncing **10,000 requests to within ~166ms** — relevant whenever
a limit-overrun or brute-force-style race needs many more attempts than the classic technique
allows (e.g. bypassing a 5-attempt OTP/lockout by racing 1,000 auth attempts simultaneously,
which a 20-request race can't statistically land).

**Mechanism:** combines (1) IP fragmentation — split one oversized TCP packet across multiple
IP fragments the server buffers until reassembly, letting a payload far bigger than one frame
arrive as a unit; (2) sequence-number reordering — send all packets except the one carrying the
FIRST sequence number, so the server queues everything waiting on it, then fire the first-seq
packet last to release the whole batch at once for genuinely concurrent processing.

**Tooling:** no Turbo Intruder integration exists — this operates at OSI layers 3/4 (raw
sequence-number manipulation), so it needs custom implementation, not a Burp extension. Reference
PoCs: `rc-benchmark` (perf demo) and `rc-pin-bypass` (OTP/PIN rate-limit bypass demo) in the
Flatt Security writeup. Reserve for cases the standard single-packet script under-attempts;
default to the existing Turbo Intruder script first since it needs no custom tooling.

**When it matters for us:** any `/verify`, `/confirm`, `/otp`, `/pin` endpoint where the
business-logic lockout threshold is low (≤10 attempts) — a 20-30 request race may not beat the
odds, but this technique's request volume can brute-force through it in one race window. Still
operator-confirm only (Turbo Intruder/Burp Repeater territory), never autonomous.

Source: [flatt.tech — Beyond the Limit](https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/)
