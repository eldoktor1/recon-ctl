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

### WHERE TO LOOK THESE DAYS (2026 — the surface has MOVED; researched 2026-06-17)

The classic surface (reflected `?q=`/`?id=` params) is the saturated, mostly-caught tail.
The live, lower-dup surface has shifted:

**XSS → DOM-based, not reflected** ([PortSwigger PP/DOM](https://portswigger.net/web-security/prototype-pollution/client-side), [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)):
- **Sources:** `location.hash` (the #1 bounty winner — server-invisible, used for SPA routing +
  "welcome, <name>", almost never sanitized), `location.search`, `document.referrer`,
  **`postMessage`/web messages** with missing/weak origin checks, and **prototype pollution**
  (`__proto__`/`constructor.prototype` via URL params or JSON web-messages).
- **Sinks:** `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout`/`setInterval`,
  `location.href`/`.assign`, `jQuery $()`/`.html()`, `Function()`.
- **The modern chain:** pollute `Object.prototype.<x>` via `__proto__` → an existing **gadget**
  (legit code that reads `<x>`) → the value reaches a sink → DOM XSS. Real: DOMPurify bypass
  CVE-2026-41238 (PP gadget defeats sanitizer). mXSS (mutation) is the other frontier.
- **Why it's EV:** server-side scanners + reflected-fuzzers are BLIND to it (nothing on the
  wire) → far less hunted. Trace source→sink in the JS; DOM Invader auto-PoCs source/gadget/sink.

**SQLi → API / GraphQL / ORM / NoSQL, not login forms** ([Hive SQLi 2026](https://hivesecurity.gitlab.io/blog/sql-injection-complete-guide-2026/), [APIsec](https://www.apisec.ai/blog/api-sql-injection-testing-payloads-guide)):
- **API surfaces:** JSON **body** params, query strings, **HTTP headers**, and **GraphQL
  variables / filter clauses** (nested args → tenant-isolation/access bypass).
- **ORM raw escape hatches:** Django `.raw()`, SQLAlchemy `text()` w/o bound params — "every ORM
  has a raw hatch, and that's where injection re-enters."
- **Second-order (stored):** input (`admin'--`) detonates LATER in a different query/context —
  the most elusive; needs store-then-trigger reasoning.
- **JSON columns**, and **NoSQLi operator injection** (Mongo `{"$gt":""}` / `{"$ne":null}` passed
  to a query constructor) — a distinct sub-class.
- **Confirm:** cheap `'`vs`''` differential + boolean true/false + **time-based** (50ms→5s) as the
  pre-filter, THEN **sqlmap to VERIFY** (operator-authorized 2026-06-17, in-scope+paying only) — PoC
  depth (`--banner`/`--current-db`/`--current-user`/`--dbs`), gentle (`--delay 1 --threads 1
  --level 1 --risk 1`), bounded (`timeout`). HARD LINE: **never mass `--dump` of third-party PII**, no
  destructive/stacked-write, never get the Mullvad exit banned, skip "no automated scanners" programs.
  NoSQLi via operator-vs-literal diff (`{"$gt":""}` vs literal — sqlmap is SQL-only).

**Where our AUTONOMOUS coverage actually sits (honest):** the daemon confirmers cover the
**reflected/param tail** — `recon_params` crawl → `recon_xss_sqli_candidates.py` rs0n ranker
(~18k XSS / ~3k SQLi catalog, ranked by param-injectability + freshness, UNIQUE-vs-PRODUCT-CLASS
split → `briefings/{xss,sqli}_candidates_<date>.md`) → `xss-confirm` (headless EXECUTION;
reflection≠XSS) + `param-confirm` (`'`vs`''`). **The MODERN surface above is NOT autonomously
confirmed yet:** DOM-XSS best tool = **dalfox `--deep-domxss --force-headless-verification`**
(installed; confirms EXECUTION headlessly — strictly better than the static `recon_domxss.py` miner,
now just a cheap pre-filter; DOMDig = deep-SPA v2/on-demand, needs Node). GraphQL/header/JSON/ORM/NoSQLi
SQLi is not yet in `param-confirm`. **→ enhancement (queued): dalfox-DOM confirm lane + sqlmap-verify on
SQLi + extend to GraphQL-variables/JSON-body/NoSQL-operator.** Until each lands, the uncovered modern
surface is operator-DIG (DOM Invader / domloggerpp for DOM; manual for GraphQL/NoSQLi).

**Flow:** confirmer FIRES → `record-confirmed` → `ai-pending` → 2IC verify → **SUBMIT** (same path
as U1/U4). The ranked `{xss,sqli}_candidates` lists are the to-CONFIRM worklist (card 💉 / DIG):
TOP UNIQUE first, skip PRODUCT-CLASS, prefer ⚡ fresh.

**Dup-trap discipline (why this lane doesn't sink us):** fresh-first + unique-split + DOM/API
surface (less-hunted than reflected) + confirm-is-the-gate + impact-gate (theoretical CORS/header/
self-XSS = N/A). Never mass-blast saturated programs with defaults.

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


---

## Appendix (r201, 2026-06-22) — Salesforce Experience-Cloud guest-site recon (U1/U4 reusable)

A recurring high-EV unauth class on `help.*` / `community.*` / `support.*` hosts. Salesforce
**Experience Cloud (Lightning) guest sites** frequently ship with mis-set object/FLS permissions
that let the **unauthenticated guest user** read standard objects (Account/Contact/Case/User/etc.)
via the Aura controller — the classic "Salesforce ghost / guest user" data exposure.

**Fingerprint (any one ⇒ it's an SFDC Experience guest site):**
- CSP references `service.force.com/embeddedservice`, `*.salesforce-scrt.com`, `*.my.salesforce.com`.
- `/s/` exists (301/200) and sets an **`LSKey-c$<...>`** cookie — the definitive Lightning marker.
- `/s/sfsites/aura` is reachable; `/s/?language=en_GB` returns a `renderCtx` published-page payload.

**Confirm (operator-browser, read-only — NOT autonomous):** logged-out POST to `/s/sfsites/aura`
with `getRecord` / `getItems` / `getRecords` actions enumerating guest-accessible standard objects.
Records returned without auth = the bug. Tooling: public aura-dump scripts. HARD LINE: owned/non-PII
objects first, stop at proof, **dedup vs the program's disclosed reports + crowdstream/hacktivity
BEFORE submit** (Salesforce-guest is a known class → check it isn't already filed).

**FP trap:** the fingerprint alone (CSP/LSKey/`/s/`) is the PRECONDITION, not the finding —
introspection of the page ≠ data exposure. Only guest-accessible *records* returning is reportable.
A guest site with object perms correctly locked returns aura errors / empty / auth-required.

Seen on: `help.etoro.com` (standing #1), `staging.help.th.jobsdb.com` (SEEK/Bugcrowd, r201).

---

## Appendix (2026-07-11) — favicon-hash dork as a cheap uncover-lane enumeration add

Add `http.favicon.hash:<mmh3(base64(favicon))>` as another scoped dork template in the
`recon_uncover.sh` Shodan/Censys pass — same in-scope-cert/root scoping + credit-budget
discipline as the existing dorks. Surfaces **shared-favicon infra** (staging / internal /
forgotten hosts running the same app) that CT + subfinder enumeration misses, feeding fresh
surface into U1/U4.

**Discriminator (never over-trust it):** a favicon-hash match is an **ENUMERATION CANDIDATE
only** → resolve → in-scope check → normal validator queue. NEVER treat it as standalone
identity/ownership confirmation — favicons are trivially swapped and hashes collide across
unrelated hosts (shared frameworks/CDNs). Same posture as every other uncover dork: it widens
the net; the confirm primitive is still the per-lane one above.
