# class-takeover — subdomain / dangling-DNS takeover  [the CONFIRMED-vs-LEAD REFERENCE PATTERN]

> Reusable KB for the takeover lane (`recon_takeover_hunter.sh`, fingerprint DB
> `scripts/data/takeover_fingerprints.tsv`, dangling-DNS feeders `recon_dangling_dns.sh` /
> `recon_baddns.sh`). READ before working a takeover; APPEND when you learn a new provider
> quirk or FP. Host-specific findings → host_notes; this is general reusable knowledge.
>
> **Why this is the reference pattern (CLAUDE.md):** takeover is the lane where CONFIRMED-vs-LEAD
> is cleanest, so every other lane is held to its discipline. `takeover:confirmed` (multi-stage
> NXDOMAIN + provably-unclaimed provider name, +15, P0) vs `takeover:cname-lead` (CNAME→provider
> + 404 heuristic, +3, NEVER P0 on its own). Match this everywhere.

## The one rule everything reduces to
**A dangling CNAME is a LEAD. A takeover is CONFIRMED only when the backing resource is provably
GONE and the name is provably FREE for us to register.** Two independent things must both be true:
1. the DNS record points at a provider resource that no longer exists (NXDOMAIN on the CNAME
   target, OR an authoritative "this name is unregistered" signal like S3 `NoSuchBucket`); AND
2. the provider lets an outsider claim that exact name (not ownership/DNS-verification gated).
A provider error page alone (404 "no site here") is neither — it fires on thousands of live,
owned, still-resolving customer installs. That is the FP factory this lane exists to filter.

## The severity ladder (what mints what)
| Signal | Tier | Score | Notes |
|--------|------|-------|-------|
| CNAME → known provider + provider 404/error fingerprint, target still RESOLVES | **cname-lead** | +3 | the #1 FP shape; WATCH, re-check for NXDOMAIN; never P0 |
| CNAME target NXDOMAINs (2-of-3 resolvers) + claimable provider | **confirmed** | +15 | P0 — resource gone, name free |
| Authoritative "name free" without NXDOMAIN (S3 `NoSuchBucket`, Beanstalk) | **confirmed** | +15 | HTTP fingerprint is itself authoritative-unclaimed |
| NXDOMAIN but authoritative check says name RESERVED (Azure `checkNameAvailability`, GitHub user API 200) | **FP** | — | NXDOMAIN ≠ claimable; drop |
| Dangling reference to a live ELB/CloudFront/Fastly/Firebase | **FP** | — | live apps 404 at root all the time; see below |

## Detection stages (how `recon_takeover_hunter.sh` earns a confidence, in order)
The hunter runs a **5-stage** pipeline and NEVER pages `#takeovers` on fewer than the gated set:
1. **CNAME resolve** — multi-resolver (1.1.1.1 / 8.8.8.8 / 9.9.9.9), 2-of-3 must agree (kills DNS flake).
2. **Provider match** — the CNAME target regex-matches an entry in `takeover_fingerprints.tsv`.
3. **NXDOMAIN check** — does the CNAME *target* NXDOMAIN across 2-of-3 resolvers?
4. **HTTP fingerprint** — does the served body match the provider's unclaimed-resource error regex?
5. **Stability re-check** — after `STABILITY_DELAY` (30s), re-run 1/3/4; a flapping result fails.
5 stages = CRITICAL, 4 = HIGH (easy provider) / MEDIUM-HIGH, 3 = MEDIUM (→ WATCH), ≤2 = LOW (silent).

### The gates that turn a stage-count into a real verdict (the FP-kill layer)
- **GATE 0 — scope/pays** (`recon_scope_check.sh`, local, no network): out-of-scope / non-paying host
  ⇒ never mint a CLAIM or page. (A real FP slipped through once with `program=null` and no scope gate.)
- **GATE A — claimability (can-i-take-over-xyz):** providers marked "Not vulnerable" require
  ownership/DNS/file verification before serving a custom domain, so a dangling CNAME + their error
  page is NEVER claimable by an outsider. Hard-excluded (`TKO_NOTVULN`): fastly, firebase,
  aws_cloudfront, acquia, freshdesk, hubspot, feedpress, fly_io, desk_com, statuspage,
  gcp_appengine, zendesk, akamai, sendgrid, mailchimp, dreamhost, kinsta, instapage, keycdn,
  squarespace, gcs, google_sites, gitlab, azure_trafficmanager, intercom, **wpengine** (its generic
  404 fires on thousands of live paid installs → 21k mass-FP once). Also drop the provider's OWN
  namespace (`github.github.io`, `*.map.fastly.net`, live `*.cloudfront.net`) — unclaimable.
- **GATE B — NXDOMAIN required to CONFIRM:** if the CNAME target still RESOLVES and the provider is
  not in `TKO_HTTP_AUTH` (S3/Beanstalk, whose error string is authoritative), the finding is
  DOWNGRADED to MEDIUM/WATCH — never a confirmed P0. This is the core cname-lead vs confirmed split.
- **GATE C — authoritative name check** (for `azure_*`, `github_pages`, `aws_s3`): NXDOMAIN does NOT
  prove the name is free. Run the provider's own check; a RESERVED name is dropped even if every DNS/
  HTTP stage fired. (Proven FP: an `azure_websites` CNAME NXDOMAINs yet `az … checkNameAvailability`
  returns `AlreadyExists` → still reserved in some subscription → UNCLAIMABLE.) If the check can't run
  (no `az`/creds/API), the candidate is held at WATCH, never auto-claimed.
- **Live-content disqualifier:** a >1000-byte body with real HTML structure and no takeover
  fingerprint = a real page, not a takeover — silent drop.
- **Same-apex / AWS-ELB disqualifier:** a CNAME back to the same org apex, or to `*.elb/nlb/alb.
  amazonaws.com`, is owned infra — hard skip.

## Provider claimability primitives (the authoritative "is this name free" signals)
These are what upgrade a heuristic 404 to a CONFIRMED, per provider:
- **AWS S3** → HTTP body contains `NoSuchBucket` / "The specified bucket does not exist" = name free
  (authoritative, unauth, NO NXDOMAIN needed). Claim = create the bucket with that exact name in the
  right region (name is globally unique + region-locked). Cross-ref `class-bucket-exposure.md` — a
  live host CNAME'd at a `NoSuchBucket` bucket is the bucket-lane→takeover handoff.
- **Heroku** → `*.herokuapp.com` + "No such app" 404; claim `heroku create <app-name>` then
  `heroku domains:add <host>`.
- **GitHub Pages** → `*.github.io` + "There isn't a GitHub Pages site here"; authoritative check =
  `GET api.github.com/users/<owner>` → 404 = owner free = claimable, 200 = owner exists (reserved).
- **Azure** (`*.azurewebsites.net` / `*.blob.core.windows.net` / `*.azureedge.net` / `*.cloudapp.*`)
  → provider error requires NXDOMAIN **AND** `az … checkNameAvailability` = `nameAvailable:true`.
  NXDOMAIN alone is NOT enough here (the AlreadyExists FP). Watch the "this web app is stopped" body
  = resource owned = disqualifier.
- **Easy first-come providers** (Netlify, Vercel, Webflow, Surge, Render, Railway, Cloudflare Pages,
  Fly.io, Firebase*/GCP by project-id, Bitbucket, Deno Deploy, …) → NXDOMAIN/404 + globally-unique
  slug you can register on a free tier. (*Firebase is in `TKO_NOTVULN` — treat as human LEAD.)
Full regex/claim table: `scripts/data/takeover_fingerprints.tsv`
(fields: `service^cname_regex^nx_trigger^http_regex^status^difficulty^payout^claim`).

## Documented FP patterns (never score as CONFIRMED)
- **Dangling CNAME to a LIVE ELB/CloudFront/Fastly/Firebase ≠ takeover.** Live apps 404 at root all
  the time; the resource still resolves and is owned. Verify unclaimed / NXDOMAIN first. (This is the
  canonical takeover FP in CLAUDE.md's FP-patterns section.)
- **Provider "not vulnerable" (ownership-gated) + error page = FP.** Fastly/Firebase/Zendesk/wpengine
  etc. all serve a generic 404 on live installs; the error string proves nothing without a claimable-
  name signal. See `TKO_NOTVULN`.
- **NXDOMAIN ≠ claimable.** Azure names can NXDOMAIN yet stay reserved in a subscription. Always run
  the authoritative name check where one exists (GATE C).
- **Impossible/hardened providers** (CloudFront, StatusPage, Mashery, Zerigo, desk.com) — difficulty
  `impossible` in the DB; only worth a human LEAD if the target literally NXDOMAINs and you can prove
  an account claim path.
- **Already-disclosed on H1** — the hunter checks disclosed reports (root-domain keyword) and downgrades
  a match to INFO. Always dup-check before reporting (`feedback_dup_check_before_submit`).

## Reporting discipline
- A CONFIRMED takeover pages `#takeovers` (first-blood speed) AND routes through Claude VERIFY
  (`db_confirm` → `#review`) — the adversarial pass catches the live-ELB class before it reaches you.
- The PoC is proof of control, kept benign: claim the name, serve a unique harmless marker page
  (a UUID / your H1 handle), screenshot it served under the target host, then STOP. Never host
  malicious/phishing content, never leave it deployed longer than the PoC needs. Redact nothing that
  isn't secret; the takeover itself is the report.
- Honest severity: an easy claimable first-come provider on an in-scope+paying host is a genuine
  high/P1-P2; a hardened/impossible provider or a still-resolving lead is not. Don't overclaim.

## Sources
- can-i-take-over-xyz (EdOverflow) — the authoritative claimable/not-vulnerable matrix.
- `scripts/data/takeover_fingerprints.tsv` (this repo) — per-provider regex + claim procedure.
- HackerOne disclosed takeover reports; the classic "Hostile Subdomain Takeover" (Detectify) writeups.
- CLAUDE.md "Core principle: CONFIRMED vs LEAD" + "Documented false-positive patterns".
