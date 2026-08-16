# class — HTTP request smuggling / desync (U5)

The "pure skill, near-zero-dup" play (OPERATING.md play 6). The machine does NOT
auto-confirm this — detection is safe, but confirmation/exploitation is
OPERATOR-driven, human-in-the-loop, minimal. Recorded 2026-07-24 (2IC r295, Fri
technique mandate) from PortSwigger's 2025 research.

## Why it's still live in 2025 (James Kettle, "HTTP/1.1 Must Die: The Desync Endgame", BH USA/DEFCON 2025)
Request-boundary ambiguity on HTTP/1.1 is effectively unsolvable across chained
front-end/back-end systems → tens of millions of "well-secured" sites remain
desyncable. The evolution vs the 2019/2022 rounds: **parser-discrepancy** detection
(HTTP Request Smuggler v3.0) that bypasses the widespread TE/CL defences.

## The variants (2025)
- **V-H / H-V parser discrepancy** — front-end and back-end disagree on whether a
  masked header is present. Visible-Hidden = front-end sees it, back-end doesn't;
  Hidden-Visible = reverse. The *root primitive*; 0.CL/CL.0 are how you weaponize it.
- **0.CL desync** — front-end IGNORES `Content-Length`, back-end HONORS it → back-end
  deadlocks waiting for a body that never arrives. Needs an **early-response gadget**
  to break the deadlock: nginx static file, IIS reserved names (`/con`, `/nul`),
  a server-issued redirect — anything that replies before the body completes.
- **CL.0 desync** — front-end honors CL, back-end ignores it → attacker prefix bleeds
  into the *next* request on the pooled connection (classic socket poisoning).
- **Expect-header variant (2025)** — `Expect: 100-continue` (and obfuscated forms like
  `Expect: y 100-continue`) triggers 0.CL/CL.0 on many servers. Bypasses TE-focused
  WAF rules → **effective against WAF-hardened targets** (relevant to our WAF-403 DIG
  leads that are opaque from the DC egress).
- **Client-side desync (CSD)** — no back-end smuggling needed: make the *victim's own
  browser* desync its connection (attacker prefix in a request body left on the
  TCP/TLS socket), then JS fires a follow-up down the poisoned connection. Reachable
  without a vulnerable proxy in front.

## SAFE detection (the only part the machine/we run unattended-ish)
`HTTP Request Smuggler` (Burp ext) **v3.0**, three-layer:
1. send a request with a partially-obfuscated header (e.g. leading space before the
   header name, or `Xost:` vs `Host:`),
2. compare vs baseline (normal header) + control variants,
3. a UNIQUE response = strong parser-discrepancy signal. Watch for **"Mystery 400"** —
   seemingly-random bad-request errors on malformed input = frequent tell.
Obfuscated headers alone reveal the discrepancy **without** triggering exploitation.

## Fingerprints of a vulnerable chain (recon-side, cheap)
- Different server banners across the chain (`awselb/2.0` front vs `Microsoft-HTTPAPI`
  / IIS back).
- **HTTP/2→HTTP/1.1 downgrade at the CDN/WAF** (the front speaks h2 to us, h1 to the
  origin) — the single most common desync substrate.
- Inconsistent status codes for identical malformed input across layers.

## REAL vs FP discriminators (zero-FP bar)
- A single odd 400/timing blip ≠ a finding. REAL = a **reproducible** parser
  discrepancy that a controlled 0.CL/CL.0/CSD PoC turns into a smuggled/poisoned
  response (attacker prefix demonstrably prepended to a *second* request, or a
  cross-response leak on YOUR OWN follow-up).
- Timing-only / "it hung once" = LEAD, never CONFIRMED.
- CDN-fronted uniform 400s can just be the WAF — confirm the discrepancy is at the
  boundary, not blanket edge rejection (cf. our eToro/CrowdStrike WAF-403 FP class).

## HARD SAFETY LINE — why this is OPERATOR-only, never autonomous
Desync exploits **connection pooling**: a live PoC can (1) poison OTHER users'
requests on the shared connection, (2) leak responses meant for other clients, (3)
DoS via 0.CL deadlock. That's third-party impact — a hard line for us.
Therefore: **DETECT** (safe obfuscated-header probes) is fine to surface; **CONFIRM/
EXPLOIT** is operator-driven, off-peak, minimal, and must use only OUR OWN follow-up
requests as the "second request" (never demonstrate by capturing a real user's
response). Report with exact repro; never leave a target in a poisoned state.

## Where it fits our pile
Aim it at the **WAF-hardened DIG leads** opaque from our DC egress (VTM dev API,
Roblox staging, CrowdStrike Falcon, eToro stg) — the Expect-header 0.CL variant is
specifically the one that bypasses WAF TE/CL rules, and h2→h1 downgrade at those CDNs
is exactly the substrate. Operator, residential, Burp + HTTP Request Smuggler v3.0.

---

# 2026 DELTA — the HTTP Terminator vectors (added 2026-08-15; research published 2026-08-07)

James Kettle / PortSwigger, Black Hat USA 2026: an AI-assisted pipeline ("HTTP Terminator")
generated ~30,000 candidate desync vectors, ran them against 30,000 BBP/VDP-authorized sites
24/7, and confirmed **~700 vulnerable targets** — banks, government infra, security products,
an airport. **Four vectors are NEW on top of the 2025 material above.** Treat these as the
freshest desync surface available; they were public for days, not years.

## N1 — Dual-matching Content-Length  ★ highest value
**Trigger:** send `Content-Length` **twice with identical, valid values**. RFC-legal-looking,
so WAF/TE-focused rules don't fire. Vulnerable front-ends treat the request as **zero-length**
→ straight to response-queue poisoning.
**Detect:** "clean request" analysis — an RFC-compliant request that draws **more than one
response**. That multiple-response signal is the discriminator, not a timing blip.
**Prevalence (Kettle):** popped "a juicy SSO server" and "most of the public infrastructure of
a particular bank." This is the one to try first.

## N2 — `Content-Type: multipart/byteranges`  ★ broadest hit-rate
**Trigger:** standard **CL.0** payload structure carrying `Content-Type: multipart/byteranges`.
Origin of the idea: RFC 2616 §19.2, which governs *response* processing — servers that reuse
response-parsing logic on requests mis-handle it.
**Prevalence:** worked across **multiple distinct server implementations**, exposed **200+
websites** incl. a US bank. Highest breadth of the four → best fit for a sweep over our in-scope
h2→h1-downgrade hosts.

## N3 — Dangling-byte (RQP reliability primitive, not a new trigger)
**What:** send the smuggled request **one byte short**. The back-end's second response isn't
produced until a victim request supplies the missing byte — which **removes the race condition**
that makes response-queue poisoning flaky. Survived as the only winner out of 16 tested
RQP-enhancement hypotheses.
**Prevalence:** "extremely effective on every target with a method-agnostic back-end."
**Use:** this is what turns an unreliable RQP LEAD into a clean reproducible PoC. Note it is
*more* invasive by design (it waits on a real victim request) — see the safety line below; use
our own follow-up request as the trigger, off-peak, never a real user's.

## N4 — Shared-Parser Confusion (the class, not a payload)
**Concept:** servers that use the **same parsing code for requests and responses** let you reach
*response-only* features via a crafted request (Kettle's example: a server processing `Set-Cookie`
in a **request**). N2 is one instance of it. Kettle calls it "one of the most significant
discoveries of this research"; at scale it is still **theoretical** — i.e. an open seam to mine,
not a shipped payload. Reasoning lane, not a scan lane.

## Tooling shipped alongside (2026-08)
- **`HTTP Request Smuggler`** updated with the new vectors — works on Burp **Community, Pro and
  DAST**. This is the cheap path: the vectors land in the extension we already run.
- **Turbo Intruder** with an **MCP interface** (pairs with our Burp MCP setup, `tool-burp-pro.md`).
- **Param Miner** updated with the protocol-ruler technique.
- **`github.com/portswigger/http-terminator`** (AGPL-3.0) — 4 stages: `seeker` (Claude extracts
  techniques from docs, py3.11+, API key), `flamer` (Claude generates malformed test cases, Java
  21), `validator` (**Burp extension**, Java 21), `investigator` (**needs Claude Code** + MCP
  simulator + Burp). Only seeker/flamer are self-contained; validator/investigator need Burp.
- Community: `crlf-desyncs`, `crlf-powered-desync-scanner` (from PortSwigger's CRLF-powered
  desync research).

## Dup-risk read (the MOTTO applies)
The **techniques** are days old, but Kettle's 30,000-site sweep is **already reported** — any host
in that set is burned. Our edge is the complement: in-scope hosts that were **not** in a
top-30k-style sweep — the deep/fresh CT surface, staging and regional hosts, the WAF-hardened DIG
leads. Racing the same big-name targets everyone will now scan is the dup trap.

## Sources
- PortSwigger Research — "HTTP/1.1 must die: the desync endgame" (2025)
- PortSwigger Research — "Browser-Powered Desync Attacks" (client-side desync)
- PortSwigger Research — "Can AI do novel security research? Meet the HTTP Terminator" (2026-08-07)
  <https://portswigger.net/research/http-terminator>
- PortSwigger Research — "CRLF-Powered Desync Attacks: Beheading HTTP Streams"
- The Hacker News — AI-Assisted HTTP Terminator … Apache Zero-Day (CVE-2026-63078, ATS), 2026-08-07
- Burp ext: `HTTP Request Smuggler` v3.0 + 2026 vector update
