# class-blind-xss — Blind / Stored XSS (the #1 unused dalfox feature)

**Lane:** `recon_blindxss.sh` (collector + correlator) + `recon_dast.sh` blind-plant mode.
**Commands:** `recon-blindxss [status|test <host>|collector|correlate|plant]`.
**Killswitch:** `state/kill/v2_blindxss` (collector + correlate + plant). Plant also honors `v2_dast`.
**Added:** 2026-06-21.

## Why this is a UNIQUE lane (the MOTTO)
Everyone runs reflected-XSS scanners; almost nobody stands up **persistent** blind-XSS
collection. Blind/stored XSS fires **hours-to-days later**, inside an **admin/staff console**
(the highest-value context — staff session theft, internal panels), from a payload the crowd
never planted. That is dup-resistant, high-payout surface — but only if you (a) plant a
*correlatable* payload and (b) keep a *long-lived* collector alive to catch the late fire and
map it back to where it was planted. dalfox has had `-b`/`--custom-blind-xss-payload` forever;
the gap was always the collector + correlation infra. This lane is that infra.

## Architecture (dual-beacon — each tool for what it is best at)
Every blind payload carries TWO beacons:

1. **interactsh = the AUTONOMOUS BACKBONE.** A persistent `interactsh-client` (`-sf` session
   file ⇒ **stable correlation-id across restarts**) polls forever and logs every callback to
   `~/recon/state/blindxss/callbacks.jsonl`. We plant a **crafted per-host subdomain**
   `<CID><token>.<oast-domain>`. interactsh routes ANY subdomain whose first `cidl` (20) chars
   equal our correlation-id back to our client — **verified empirically** (the trailing chars
   are free for our token). The collector strips the CID → recovers `<token>` →
   `injections.jsonl` (`token → {host,url,program,lane}`) → the host we planted into. A fire
   mints a CONFIRMED stored-XSS finding via `state.py record-confirmed` (`signal_class=blind-xss`,
   score 15, conf 0.9) → 2IC verify → `#review`, **hard-gated on `ai_verdict='real'`** like
   every other lane.
2. **XSS Hunter (`js.rip`) = the RICH FORENSIC layer.** The same payload also loads the
   operator's XSS Hunter probe, so every fire ALSO lands in the XSS Hunter dashboard with
   **screenshot + DOM + firing-page + secrets/CORS/.git detection + email alert** — the
   PoC-grade evidence for the actual report. (Hosted XSS Hunter has **no machine API** — email
   + dashboard only — so interactsh, not it, drives autonomous minting. interactsh is the
   machine; XSS Hunter is the human triage/PoC surface.)

The custom payload set spans contexts (HTML break, `img onerror`, `svg onload`, JS-string
break, `javascript:`, plus a compact dual `<script src>` for length-limited stored fields).
The inline beacons carry `location.href`/`title`/`referrer` in the path → the **firing page**;
the compact ones recover it via the `Referer` header.

## Correlation granularity (honest)
**Host-level is solid; param-level is best-effort.** dalfox plants ONE per-host token per run
(a per-param token would mean a run per param — infeasible). A fire ⇒ you know the **host** it
was planted into and the **firing page** where it executed; you re-test that host's crawled
params to localise the exact sink. DNS-only callbacks (CSP blocks the image, but DNS prefetch
fires) still correlate to the host via the subdomain token, just without the firing page.

## Triage / severity (after a fire)
1. **A fire = confirmed EXECUTION** (out-of-band proof the payload ran in a real browser) — not
   mere reflection. This is genuinely CONFIRMED, not a LEAD.
2. **Severity hinges on the firing-page context** (read it from the evidence + the XSS Hunter
   screenshot/DOM): an **admin/staff console** ⇒ **Critical** (staff session/account takeover);
   a low-privilege/own page ⇒ High; a public page reachable by the victim only ⇒ reassess (could
   be self-XSS-adjacent — don't overclaim).
3. **Open the XSS Hunter dashboard** for the screenshot + DOM = the report's PoC. Redact any
   captured secrets/cookies — the report is "stored XSS executes in <context>", never a data
   harvest (hard line).
4. **DUP-CHECK before submit** ([[feedback_dup_check_before_submit]]): search all platforms for
   the host + "stored/blind XSS". Stored XSS in a known admin panel may be reported.

## Hard line (NON-NEGOTIABLE)
- Plant only on **in-scope + PAYING** hosts (the planter gates this; the correlator re-gates at
  mint time). NEVER plant on out-of-scope / third-party hosts.
- The interactsh beacon exfils only `location.href` / `title` / `referrer` — **never** cookies
  or tokens. (XSS Hunter's richer capture is the operator's OWNED dashboard — their call, used
  for the PoC, not a harvest.)
- Confirm-then-report. The PoC is "a planted payload executed in <console>", not pivoting deeper.
- An **uncorrelated** fire to our CID (planted before this collector session, or via an XSS
  Hunter-only payload) is surfaced as a manual-correlate LEAD (+ the XSS Hunter dashboard
  pointer) — NEVER auto-minted against an unknown/possibly-third-party host.

## Anti-burn
- Planting runs in `DAST_BLIND_ONLY` mode (fresh-first, 7d per-host cooldown, per-host rate caps,
  `--waf-evasion` self-throttle, egress governor, Mullvad-gated). Polite by construction.
- The collector polls only the interactsh server (our OOB infra, NOT a target) ⇒ runs as d0k,
  NOT vpn-gated, so it keeps catching late fires even while scanning is paused.

## Infra (config: `~/.recon_blindxss.conf`, LOCAL)
- Default: **public oast.*** (works now). `-sf` persistence catches multi-day-late fires.
- **Self-host upgrade** (own domain = not a WAF-blocklisted IOC + retention control): run
  `interactsh-server -domain oob.example.com -token <secret>` on a VPS (delegate NS, open
  53/80/443); set `BLINDXSS_SERVER`/`BLINDXSS_TOKEN`/`BLINDXSS_DOMAIN`; `rm` the session file;
  `recon-restart`.

## Tooling note — dalfox v3 (Rust rewrite), 2026-07-11 (verify installed version)
dalfox **v3.0.0** (2026-05-25) is a full **Rust rewrite** with **AST-backed DOM verification** —
fewer FPs from blind reflections, which our EXECUTION-only confirm gate benefits from directly.
**v3.1.1** then (a) demoted inert `javascript:` / URL-scheme **self-link** reflections (a known FP
class) and (b) restored recall for reflected XSS inside **raw-JS-expression / regex-literal**
contexts. Action: confirm the reflected/DOM confirm harness (`recon_params.sh confirm xss`,
`recon_domxss_confirm.sh`) runs **dalfox >= 3.1.1** — older builds both miss some real
raw-JS-context reflections and mis-flag inert `javascript:` self-links as hits. (Version dates
per upstream release notes — verify against the installed binary before relying on the behavior.)

## Sources
- dalfox blind XSS: `-b`/`--blind` + `--custom-blind-xss-payload` (verified on the installed
  binary: built-in `-b` emits ~73 blind variants to the callback URL; custom payloads are sent
  verbatim one-per-line).
- interactsh correlation model (preamble `cidl=20` routes; nonce is free) — projectdiscovery
  docs + empirically confirmed (crafted `<CID><token>` subdomains route to our client).
- XSS Hunter (Truffle Security hosted): https://xsshunter.trufflesecurity.com — screenshot/DOM/
  firing-page capture, email reports, no public fire API.

Related: [[class-cache-deception]] (same detect-only/safe-PoC discipline), the reflected/DOM XSS
confirmers `recon_params.sh confirm xss` + `recon_domxss_confirm.sh` (now both `--waf-evasion`).
