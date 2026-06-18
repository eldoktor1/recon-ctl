# class-unauth-hunting — finding HIGH-SEVERITY unauthenticated bugs (real, not FP)

> Reusable KB. READ before pointing the system / a hunt at unauth. APPEND when you learn
> a new sink, discriminator, or escalation. Host-specific findings → host_notes, not here.
>
> **Doctrine (see docs/OPERATING.md):** unauth is the only severity class the autonomous
> machine can take from detection → submittable WITHOUT the operator's accounts. The whole
> edge is **"wide eyes, narrow hands"** — discover wide, surface ONLY what fired a confirm
> primitive. WIDE unauth scanning (nuclei-defaults on saturated programs) = the duplicate
> flood = unwinnable. NARROW unauth = fresh surface + the classes templates miss + a real
> confirm = winnable. Detection ≠ exploitation: a 200, a reflection, a version banner are
> NOT findings.

## How the criticals are actually found in 2026 (research-grounded)

The high-severity unauth money is NOT broad scanning. It is, in EV order for a part-timer
with a 24/7 recon machine:

1. **Shadow-endpoint → unauth data exposure** — the most machine-confirmable high-sev play.
2. **SSRF (hidden sinks) → cloud-metadata / internal → RCE** — the crown class; OOB-confirmed.
3. **n-day racing on the straight-shot unauth-RCE subset** — version-confirmed, race window.
4. **Exposed secrets / services / takeover / open buckets** — live-validated exposure.
5. **Operator skill classes** — request smuggling, cache poisoning/deception, auth bypass.

Each lane below: WHERE it hides → HOW to discover → the REAL-vs-FP discriminator (the
confirm primitive) → escalation/impact → the FP trap to never ship.

---

## Lane U1 — Shadow / undocumented endpoint → unauth data exposure  [machine-confirmable]

**Where it hides:** forgotten `/v2`, `/internal`, `/private`, legacy APIs, tacked-on
import/export functions, BFF routes — endpoints that bypassed security review because they
are unmaintained. "Out-think, don't out-race": the overlooked endpoint, not the obvious one.

**Discover:**
- JS bundles (highest ROI): `katana -d 5 -jc` + parse for `/api/`, `/v[1-9]/`, `/internal/`,
  `/private/`; **source maps** (`.js.map`) reveal clean route names.
- Archives: `waymore` / `gau` / `uro` (normalize+dedupe) — historical routes still live.
- Swagger/OpenAPI: fuzz `swagger.json openapi.json api-docs /docs /redoc` → full route map.
- `kiterunner` (`kr scan -w routes-large.kite`) for smart API brute-force.
- **Method variation:** an endpoint that's POST-only in the UI may leak on GET.

**REAL-vs-FP discriminator (the confirm):** isolate NO-AUTH paths —
`httpx -mc 200 -fc 401,403` — then the body MUST be **real sensitive data** (PII / tokens /
internal records) with a data content-type. **FP trap:** a 200 that returns the SPA
`index.html` (client-side route, same as `/`) is NOT a leak — probe content-type + body
signature, never status alone (CLAUDE.md "SPA-shell 200" pattern).

**Escalation:** unauth shadow endpoint returning PII = critical on its own; chaining an
object-id swap (BOLA) on it multiplies impact (but that's the authed lane).

---

## Lane U2 — SSRF (hidden sinks) → metadata / internal → RCE  [OOB-confirmed; human escalates]

The highest-payout unauth class (Meta caps SSRF at $40k). Versatile: the same primitive
reads internal services, dumps cloud creds, or lands RCE via gopher.

**Where it hides — go past the obvious `url=`:**
- Obvious: `callback`, `return_url`, `redirect_uri`, `image_url`, `avatar`, `webhook`.
- **Hidden (the EV):** HTTP headers (`X-Forwarded-For/-Host`, `X-Original-URL`); uploaded-file
  parsers (XML entities, SVG refs, PDF embedded resources); social/OpenGraph link-preview
  fetchers (follow redirects to internal); async background workers; Referer analytics.
- **JS-mined sinks:** routes named `/api/fetch|proxy|import|preview`; functions
  `fetchRemote`/`loadExternal`/`proxyRequest`; params `url|target|dest|path|src|link`.
- Tools: Burp **Param Miner** (param/header discovery), **Collaborator Everywhere**
  (auto-injects OOB payloads into every header/param).

**REAL-vs-FP discriminator (the confirm):** a **Burp Collaborator / interactsh OOB callback
fires** (DNS = name resolved; HTTP = full request reached). Timing/error differences alone =
LEAD, not confirmed. Blind SSRF with no callback and no secondary signal = not shippable yet.

**Escalation (turns medium → critical — human-driven, operator overseen):**
- Cloud metadata = highest payout: AWS `169.254.169.254/latest/meta-data/iam/security-
  credentials/` (IMDSv1 GET; IMDSv2 needs PUT token); GCP needs `Metadata-Flavor: Google`;
  Azure `Metadata: true`. Returns temp IAM creds → account compromise.
- Filter bypass: scheme-less host (proven real: `?url=169.254.169.254/...` with no `http://`),
  decimal/octal/hex/IPv6 IP encodings, URL-parser confusion (`http://trusted@127.0.0.1/`),
  open-redirect chain, attacker 301/307 redirect server, DNS rebinding (TTL 0).
- Protocol escalation to RCE: `gopher://` → Redis (`FLUSHALL`/`CONFIG SET dir` cron reverse
  shell) or PHP-FPM FastCGI (Gopherus); `dict://`, `file:///`, `ldap://` as fallbacks.
- PDF/headless (Puppeteer/Playwright/wkhtmltopdf) → inject JS that fetches IMDS into the PDF.
- **Real chain template (hg8):** `proxify?url=` → scheme-less IMDS bypass → `ec2-default-ssm`
  role → temp creds → modify EC2 UserData reverse shell → restart → root → IAM policy-version
  → admin. The decision point was the scheme-less bypass turning a blocked sink into full AWS RCE.

**HARD LINE:** the autonomous machine only DISCOVERS sinks + fires the OOB canary (safe,
no metadata, no exploit — `recon_safe_probe` refuses private/169.254/internal). Metadata
read / gopher / RCE escalation is **operator-overseen, minimal prove-impact** (active-PoC
doctrine), never autonomous. Never point entities at `file://`/internal data.

---

## Lane U3 — n-day racing (straight-shot unauth-RCE subset)  [version-confirmed; race window]

**Reality (KEVology):** only **~32% of KEVs are network-accessible, auth-free, no-interaction
RCE** ("straight-shot"). 68% need auth/local/interaction — skip those for this lane. Reliable
public exploits land **1–7 days** after disclosure for the dangerous subset (often the exploit
PRECEDES the KEV listing). So the race is real but tight; target ONLY the 32%.

**Discover:** CVE/KEV feed → match affected tech on FRESH in-scope hosts → version-fingerprint.
Anatomy to copy (Splunk CVE-2026-20253): an exposed component (PostgreSQL sidecar) with **zero
auth**, network-reachable, on versions **9.3.0–10.2.3**. Hunter signal = fingerprint the
running version + confirm the component is reachable unauth.

**REAL-vs-FP discriminator (the confirm):** **version fingerprint confirms an in-range
vulnerable version AND a read-only/OOB matcher fires.** **FP trap (CLAUDE.md):** a KEV
tech-class match (Spring/Confluence/Jira/F5/MOVEit/AEM/…) WITHOUT a confirmed in-range running
version = LEAD, never P0. `recon_nday` version-reasons to kill this.

**Template-safety (HARD LINE):** "template_available" ≠ "safe to run." Off-the-shelf nuclei/PoC
SSRF/RCE/LFI templates routinely harvest metadata / read files / execute. READ the template
body first; autonomous = OOB-canary or read-only-matcher templates ONLY (e.g. r67: the
CVE-2026 Next.js SSRF template harvests cloud metadata — do NOT run it autonomously).

---

## Lane U4 — Exposed secrets / services / takeover / buckets  [live-validated exposure]

The classic unauth exposure surface. The discriminator in EVERY case: it must return REAL,
PRIVATE capability/data unauth — not a public-by-design artifact or a login wall.

- **Live secrets** (JS bundles, `.env`/`.git`/backups, GitHub leaks — 28.65M leaked to GitHub
  in 2025): REAL = the secret **validates live** against its provider (Keyhacks-style, read-only)
  AND grants non-public access AND the source is in-scope. **FP trap:** public-by-design tokens
  (Supabase anon, Stripe `pk_`, Firebase web config, OAuth `client_id`, Google browser API key);
  third-party/unowned-repo secrets. `trufflehog --only-verified` does the live check; brief_filter
  `_PUBLIC_TOKEN_RE` / `_THIRD_PARTY_RE` kill the rest.
- **Exposed `.git` / `.env` / backups:** REAL = `/.git/HEAD` returns `ref: refs/heads/...` +
  `/.git/config` retrievable (git-dumper), or `.env` parses to live-validating secrets. FP =
  soft-404 / HTML page / sample file with no live secret.
- **Exposed services / dashboards / actuator:** REAL = returns actual data/functionality unauth
  (`/actuator/env` JSON with property keys, `/actuator/heapdump` binary, open Kibana/Grafana/
  Jenkins with data). FP = login wall, SPA shell, marketing homepage (vision/screenshot kills these).
- **Subdomain takeover:** REAL = claimability-confirmed — NXDOMAIN, or provider "no such
  bucket/app" (Heroku `/apps` 404 not 403, S3 `NoSuchBucket`, Azure NXDOMAIN) + unclaimed
  fingerprint. **FP trap:** dangling CNAME to a LIVE ELB/CloudFront that 404s at root (live apps
  404 all the time) — verify claimable, not just "not found." Always check ignored.jsonl first
  (ES verdicts can be stale).
- **Open cloud buckets:** REAL = listable (`?list-type=2` → `ListBucketResult` XML) or readable
  objects. FP = 403 (exists, private) or a CDN that isn't a bucket.

---

## Lane U5 — operator skill classes (the DIG pile)  [human-driven, near-zero dup]

Templates can't find these; that's the point — lowest dup, high pay, your evening's brain work.
The system surfaces fresh candidates; you confirm.

- **HTTP request smuggling:** front-end/back-end desync. Detect via timing-delay or a
  response-difference from the smuggled request. Chains into cache poisoning, SSRF, auth bypass.
- **Web cache poisoning / deception:** poisoning = unkeyed input cached + served to others;
  deception = cache stores another user's sensitive page you then fetch. Find a cached endpoint,
  then an unkeyed header / a path-confusion that the cache mis-keys.
- **Auth bypass:** JWT `alg=none` / RS256→HS256 algorithm-confusion (public key as HMAC secret),
  weak signing secret (hashcat), pre-auth endpoint reaching an authed function, SAML/OIDC flaws
  (missing PKCE, redirect-uri laxity). CVSS-10 unauth-root cPanel CRLF auth-bypass = the genre.

---

## Lane U6 — reflected XSS / unauth SQLi  [machine-confirmable, but the #1 dup trap]

Unauthenticated, machine-confirmable — but mass param-fuzzing on saturated programs IS the
commodity flood (the MOTTO). It wins ONLY when kept SMART + dup-managed + confirm-gated.

**Where it hides:** reflected/injectable query params, especially the injectable-by-name ones
(kxss insight): `q`/`search`/`redirect`/`callback`/`url`/`next` reflect (XSS); `id`/`cat`/
`pid`/numeric inject (SQLi). Handler/path signal: `.php`/`/api/`.

**Discover (already autonomous):** `recon_params` crawl (katana+gau+CDX→gf→catalog) →
`recon_xss_sqli_candidates.py` ranks the ~18k XSS / ~3k SQLi in-scope+paying catalog by
param-injectability + freshness + payout, dedups by (host, normalized-path, param-set)
template, and SPLITS rare per-app UNIQUE lanes from high-fan-out PRODUCT-CLASS dup-magnets
(`?q=`, `_next/image?url=`). Output → `briefings/{xss,sqli}_candidates_<date>.md`.

**REAL-vs-FP discriminator (the confirm — already autonomous + on-demand):**
- XSS → **dalfox / headless Chromium: a marker must EXECUTE** (`recon_xss_confirm.sh`,
  `params-verify`→`xss-confirm` loops). **Reflection ≠ XSS** — break-out chars (`"><'/`) must
  survive UNENCODED in an executable context; encoded/JSON/framework-safe reflection =
  `reflected-not-exploitable` LEAD, move on.
- SQLi → the SAFE **`'` vs `''` differential** (error + boolean length-diff) via
  `recon_param_confirm.sh`. HARD LINE: never sqlmap / `--dump` / data-harvest.
- On-demand: `recon-params confirm xss|sqli <host>` (+`--cookie`/`--header` for authed).

**Flow:** confirmer FIRES → `record-confirmed` → `ai-pending` → 2IC verify → **SUBMIT** (same
path as U1/U4). The ranked `{xss,sqli}_candidates` lists are the to-CONFIRM worklist (card's
💉 section / DIG), TOP UNIQUE first, skip PRODUCT-CLASS, prefer ⚡ fresh.

**Dup-trap discipline (why this lane doesn't sink us):** fresh-first + unique-split + the
confirm-is-the-gate + impact-gate (theoretical CORS/header/self-XSS = N/A). Never mass-blast
saturated programs with defaults.

---

## The non-negotiables (every lane)

- **Impact-gate (theoretical → N/A):** CORS-reflect-without-sensitive-data, missing headers,
  self-XSS, open-redirect alone, version disclosure, blind SSRF DNS-only-pingback = Informative/
  N/A on most programs. Do NOT spend an evening or a report on them unless chained to real impact.
- **Adversarial confirm:** a `real` candidate survives the consensus panel (exploitability /
  scope+reward+dup / evidence+repro) + the screenshot/vision check. Try to REFUTE, not confirm.
- **Dedup:** against the program's published known-issues AND the operator's own submission
  ledger (`~/.recon_submissions.jsonl`) — never re-serve worked/closed surface.
- **Fresh-first:** be first to scan a host (timing beats the crowd); "if a tool found it in 5
  seconds it's already reported."
- **Anti-burn + Mullvad-only + read-only autonomous:** `recon_safe_probe` (GET/HEAD/OPTIONS,
  no creds, no redirect-follow, SSRF/metadata guard, rate-limited, audited). Authed/escalation
  is human-in-the-loop.

## Sources
- BOLA/IDOR taxonomy (companion authed lane): arXiv 2605.25865 (107 H1 disclosures).
- SSRF methodology: yeswehack.com/learn-bug-bounty/server-side-request-forgery-ssrf ; hg8.sh SSRF→RCE on AWS.
- Shadow endpoints: "API Bug Bounty Mastery 2026" (manojxshrestha).
- n-day timing: runzero.com KEVology (32% straight-shot RCE; 1–7d window).
- Unauth RCE anatomy: Orca CVE-2026-20253 (Splunk); Arctic Wolf CVE-2026-27825 (mcp-atlassian).
- Secrets: snyk.io State of Secrets (28.65M/2025); intigriti hunting-for-secrets (Keyhacks).
- FP discriminators: CLAUDE.md "Documented false-positive patterns" + tools/brief_filter.py.
