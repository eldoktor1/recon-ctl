# Research digest — the unauth hunter meta, fresh-first — 2026-08-15

Operator ask: *"the hunter meta now, stuff we should be hunting that is unauth — not
saturated and dried up, something fresh."* Scan of authoritative sources (PortSwigger
Research, Black Hat USA 2026, HackerOne HPSR 9th ed., Bugcrowd), filtered to
**unauthenticated** classes and ranked by **freshness × dup-resistance × our ability to
detect it**. Superseded/complements `class-bounty-priorities-2025.md` (2025 data, pulled
2026-06-15 — still correct on the money map, stale on technique).

---

## Rank 1 — HTTP desync, the 2026 vectors  ★ FRESHEST THING AVAILABLE (8 days old)
Published **2026-08-07**, Black Hat USA 2026. Four new vectors: **dual-matching
Content-Length**, **`Content-Type: multipart/byteranges`**, **dangling-byte** (kills the RQP
race), **Shared-Parser Confusion** (the class). Full detail → `class-request-smuggling.md`
§2026 DELTA.

- **Unauth:** yes, fully. No account, no user interaction.
- **Why fresh:** the vectors were public for days. WAF rules target TE/CL — dual-CL is
  RFC-legal-looking and slips them.
- **Why it pays:** Kettle's ~700 confirmed hits were banks, government infra, security
  products, an airport. Desync is critical-tier by default.
- **Cost to adopt: near zero** — the vectors ship in the `HTTP Request Smuggler` Burp
  extension we already run (Community/Pro/DAST all supported).
- **Dup risk:** the *techniques* are fresh, but Kettle's 30,000-site sweep is already
  reported. Anything in a top-30k list is burned. **Our edge = the complement:** deep/fresh
  CT surface, staging/regional hosts, the WAF-hardened DIG leads opaque from our DC egress.
- **Safety:** unchanged hard line — DETECT is safe, CONFIRM/EXPLOIT is operator-driven,
  off-peak, own-follow-up-request only. Dangling-byte is *more* invasive by design.

## Rank 2 — Error-based **blind** SSTI / code injection ("Successful Errors")
Vladislav Korchagin — voted **#1 Top-10 Web Hacking Technique of 2025** (results announced
2026). Error-based and boolean-error-based techniques for **blind** SSTI + code injection,
payloads for **Python, PHP, Java, Ruby, NodeJS, Elixir**, plus polyglot detection. Toolkit:
`github.com/vladko312/Research_Successful_Errors`, folded into **SSTImap ≥1.3.1**.

- **Unauth:** typically yes (any unauth-reachable template-rendered param).
- **Direct upgrade to a primitive we already own.** Our SSTI confirm is `{{a*b}}` → product,
  which only catches **reflected** SSTI. Blind SSTI — where the render never comes back —
  is currently invisible to us. This closes that hole with a safe, math/error-only signal.
- **Dup-resistant:** blind cases are exactly what the crowd's reflection-based scanners miss.
- Feeds straight into the existing params catalog (`recon_params.sh` → `recon_param_confirm.sh`).

## Rank 3 — SSRF via HTTP redirect loops (blind → visible)
@shubs, **#3** of the 2025 Top-10. Converts **blind** SSRF into a *visible* one via redirect
loops — you get response content back, not just an OOB ping.

- **Unauth:** yes, where the sink is unauth-reachable.
- **Why it matters to us:** our SSRF lane confirms via interactsh callback = "something
  fetched it" = medium-tier LEAD. Visible SSRF = actual internal response content = the
  critical-tier PoC. **This is an impact multiplier on findings we're already surfacing**, not
  a new discovery lane. PoC-OR-GTFO directly.

## Rank 4 — Next.js internal cache poisoning ("the stale elixir")
Rachid Allam, **#7** of 2025. Internal cache-poisoning chains in Next.js, found by source
review. Unauth, framework-wide.

- We already have `tech-nextjs.md` + a WCD/WCP lane (`recon_wcd.sh`) and Next.js fingerprinting.
- Note our existing FP rule still stands: `_next/image?url=` is a **product-class dup magnet** —
  this research is about the *internal* cache chain, which is not the same thing. Worth a KB read.

## Rank 5 — Parser differentials (@joernchen, #10 of 2025)
Cross-language/framework parser disagreement as a bug class. Unauth, no tooling shipped —
pure reasoning. Low volume, near-zero dup, and it's the same intellectual seam as
Shared-Parser Confusion above. A thinking lane, not a scan lane.

---

## The AI/LLM lane — real growth, honest payout caveat
HackerOne HPSR (9th ed., 580k+ validated vulns, ~2,000 programs): **AI vulns +210% valid**,
**prompt injection +540%** (fastest-growing class), **AI programs +270%** (1,121 in scope),
**bounties paid for AI +335%**. **70% of researchers now use AI tooling** — so "I use AI" is
table stakes, not an edge. Widely described as under-hunted.

**But:** payouts skew low — Meta's AI surface reportedly **$500–$2,000** for solid findings vs
their core platform bugs. And most of it is **interactive/authed** (chat surfaces, RAG,
agent tool-use), which does not fit an unauth autonomous pipeline. **Verdict: a genuine
growth lane, but a poor fit for the unauth machine and a mediocre £/hour for a part-timer.**
Revisit if a program puts an unauth LLM endpoint in scope.

## Confirmed saturated — do not spend evenings here
- **Reflected XSS** — most-*reported*, **down 10%** since 2023, commodity. Dup trap.
- **Scanner SQLi** on saturated programs.
- **Bucket-name permutation** (we already refuse this — provenance-only, correctly).
- **GraphQL "introspection enabled"** alone — Info/dup, on-by-default.
- Missing headers, theoretical CORS, version disclosure, self-XSS, info-disclosure-without-impact.
- Platform-wide context: triage is actively pushing back on AI-generated duplicate noise.
  **A report without a working PoC is now worse than no report** — matches PoC-OR-GTFO.

---

## Recommended adoption order (cheapest real edge first)
1. **Update `HTTP Request Smuggler` in Burp** → sweep the h2→h1-downgrade + WAF-hardened
   in-scope hosts with the new vectors. Highest freshness-per-effort available today.
2. **Add error-based blind SSTI** to `recon_param_confirm.sh` (SSTImap ≥1.3.1 payloads).
   Closes a real blind spot in a primitive we already ship.
3. **Add the redirect-loop escalation** to the SSRF playbook — upgrades existing OOB LEADs
   to visible-response PoCs.
4. Read the Next.js cache research into `tech-nextjs.md`; wire anything reusable into `recon-wcd`.
5. `http-terminator` itself (`github.com/portswigger/http-terminator`, AGPL-3.0) is a
   *research factory*, not a scanner — `investigator` needs Claude Code + Burp + MCP, which we
   have. Evaluate later; the extension update delivers ~most of the value for ~none of the work.

## Sources
- PortSwigger Research — Can AI do novel security research? Meet the HTTP Terminator (2026-08-07): <https://portswigger.net/research/http-terminator>
- PortSwigger Research — Top 10 web hacking techniques of 2025: <https://portswigger.net/research/top-10-web-hacking-techniques-of-2025>
- PortSwigger Research — CRLF-Powered Desync Attacks: Beheading HTTP Streams
- The Hacker News — AI-Assisted HTTP Terminator Finds Novel HTTP Desync Techniques and Apache Zero-Day (CVE-2026-63078, Apache Traffic Server), 2026-08-07
- GitHub — portswigger/http-terminator (AGPL-3.0); portswigger/http-request-smuggler
- GitHub — vladko312/Research_Successful_Errors (SSTImap 1.3.1)
- HackerOne — Hacker-Powered Security Report, 9th ed. / AI 210% press release
- HackerOne — Top 10 Most Impactful and Rewarded Vulnerability Types (SSRF/IDOR/PrivEsc = most valuable; XSS = most reported)
