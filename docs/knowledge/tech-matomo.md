# tech: Matomo (self-hosted PHP web analytics) — zero-day hunting notes

Program: HackerOne `matomo` (policy 2026-09-22, rewards 2026-08-26). Per-asset bounty TRUE on: core
(github.com/matomo-org/matomo, critical), docker, official plugins (plugins.matomo.org/developer/matomo-org),
InnoCraft premium plugins (plugins.matomo.org/developer/innocraft), other matomo-org/innocraft repos (high),
tracker-proxy (medium), matomo.cloud (critical, but test on OWN instance only). Rewards Low $333 / Medium $777 /
High $1,777 / Critical up to $13,000 (critical = unauth-or-low-priv RCE or SQLi over HTTPS; admin-required
"critical" = High). $52,520 paid in last 90 days, 1089 reports/90 days, ~10 days submission→bounty, 100%
response efficiency. Signal ≥1.0 required (trial reports below). Hacktivity: ~25 bounties/month, mostly
$111–$333, repeat hunters (hopital, no_01, toofikz, everbest8) — **the crowd is here and it farms Lows.**
Full policy carve-outs + known-issues list: workspace `matomo` notes (Phase 0). Written 2026-10-22.

## What a Matomo "zero-day" looks like
- Matomo does NOT publish GHSAs and rarely requests CVEs for bounty fixes (GitHub advisories page: none;
  opencve: only 27 CVEs ever, most pre-2016). Fixes land silently in a release with a "Security" ticket
  heading and no reporter credit. ⇒ A Matomo find pays fast but is usually **not a public CVE** unless you
  request one. (Octopus, by contrast, CVEs every advisory.)
- Security-labelled tickets in recent releases show the live classes: 5.14.1 nonce race; 5.13.0 password
  confirmation when granting admin, **opt-in SSRF-safe fetch for user-configured URLs** (#24834, i.e. SSRF was
  real and the fix is OPT-IN ⇒ default installs still fetch user URLs), Page Overlay API hardening, "pending
  invitees can recover access"; 5.12.0 escape setDomains/setCookieDomain in the generated tracking snippet
  (XSS in snippet generator); 5.9.0 HTMLRenderer column escaping, DOMPurify bump, sign-out-all-sessions.
  CVE-2026-78850 (5.11.2, CVSS 5.0, PR:L, CWE-918): SSRF/info leak via **SiteContentDetector / SitesManager**.
- Historic classes: superuser plugin-upload RCE (CVE-2025-34104 / FireFart 2017 — now disabled by default,
  and superuser-JS is explicitly out of scope), Referrers DisplayTopKeywords object injection+SSRF
  (2015-7816), ViewDataTable/Factory path traversal (2015-7815), Dashboard saveLayout() unserialize,
  Cookie.php unserialize (2009-4137).

## Architecture (developer.matomo.org "how-piwik-works", "security-in-piwik")
- Entry points: `index.php` (UI + Reporting API), `matomo.php`/`piwik.php` (Tracking API — unauth by design,
  "analytics pollution" is OOS), `console` (Symfony console — CLI is OOS), `matomo.js`.
- Dispatch: `FrontController` on `module=&action=` → `plugins/<Module>/Controller.php::action()`. Missing
  action ⇒ widget/report lookup via `core/Http/ControllerResolver.php` (`CoreHome.renderWidget`,
  `renderReportWidget`). API: `module=API&method=Plugin.method` → `plugins/API/Controller` → `plugins/<P>/API.php`.
  `format=` (json/xml/csv/tsv/html/rss/original) selects a renderer; `filter_*`, `segment`, `idSite`, `period`,
  `date`, `showColumns`, `pivotBy`, `flat`, `label`, `expanded` are universal params.
- Auth: `token_auth` (URL/POST param; == the user's password per policy; `force_api_session=1` loads session),
  session cookie for UI; CSRF = `checkTokenInUrl()` in controllers / token check in state-changing API.
  Access levels per idSite: **view / write / admin / superuser** (`Piwik::checkUserHas*Access`,
  `checkUserHasSuperUserAccessOrIsTheUser`). ControllerAdmin for admin pages.
- Input: `\Piwik\Request::get{Integer,String,Float,Bool,Array,Json}Parameter()` (raw) vs deprecated
  `Common::getRequestVar()` (auto-sanitised HTML-escaped) — mixing the two is a recurring XSS/injection root.
- SQL: `Db::query($sql, $bind)`; LogAggregator / ArchiveProcessor / `Segment` build SQL from segment
  definitions and report params; `log_*` tables raw, `archive_numeric/blob_YYYY_MM` serialized DataTables
  (unserialize surface in archives).
- Output: Twig default `html` escaping; `|raw` and `|rawSafeDecoded` are the audit targets; Vue front-end
  consumes JSON (DOMPurify in places). HTMLRenderer for `format=html` API output.
- Egress: `Http::sendHttpRequest(..., validateEgressIp: true)` is the SSRF guard — OPT-IN; grep every
  `sendHttpRequest`/`fetchRemoteFile` call that passes a user URL without it (SiteContentDetector,
  SitesManager site URL checks, GeoIP/Marketplace downloads, CoreUpdater, ScheduledReports, Overlay,
  tracking-snippet/site-search detectors, premium plugins).
- Config: `config/config.ini.php`; plugins in `plugins/`, extra dirs via `MATOMO_PLUGIN_DIRS`.

## Self-host
`docker compose`: `mariadb` (+ `MYSQL_*`) + `matomo` image (`MATOMO_DATABASE_HOST=db`, `_USERNAME`, `_PASSWORD`,
`_DBNAME`, `PHP_MEMORY_LIMIT`), volume `/var/www/html`, port 8080:80; finish the installer (installer itself
is a known/accepted issue). Create 2 sites; users: view, write, admin on site 1 only; a second superuser.
Premium plugins: 18 InnoCraft plugins (A/B Testing, Activity Log, Cohorts, Crash Analytics, Custom Reports,
Form Analytics, Funnels, Heatmap & Session Recording, Login SAML, Media Analytics, Multi Channel Attribution,
Roll-Up Reporting, SEO Keywords Performance, SEO Web Vitals, Users Flow, White Label, WooCommerce Analytics,
Advertising Conversion Export) each "Try now for free" — **ONE trial only (policy)**, so pick the plugin set
before activating. Clone `matomo-org/matomo` at the release tag AND `5.x-dev`/`6.x-dev` (6.0 beta is out):
already-fixed-in-code = N/A.

## Hunt thesis (where the farmers are NOT)
1. **Premium plugins at Critical tier** — fewer eyes (trial-gated), big raw-SQL users: Custom Reports
   (user-defined dimensions/metrics → SQL), Funnels/Cohorts (segment SQL), Roll-Up, Form/Media/Heatmap
   (tracker-side ingestion of attacker HTML/URLs, session-recording replay = stored XSS into admin views),
   Activity Log, Login SAML (auth bypass = High+).
2. **SQL from report params**: `filter_sort_column`, `filter_column`, `segment` operators, `pivotBy`,
   custom dimension ids, `idGoal`, `showColumns` on low-priv (view) API calls — the policy's Critical
   example is "SQLi over HTTPS".
3. **SSRF with impact**: the egress guard is opt-in; need more than blind (policy) — fetch internal metadata
   /admin-only HTTP, or chain into GeoIP/Marketplace file write.
4. **Privilege boundaries**: view→write→admin→superuser (per-site vs global), `checkUserHasSomeViewAccess`
   used where per-site access was needed; token_auth of a write user hitting admin API methods; invitation
   flow (known-issue list narrows it: only *unexpired-link == authorization* is accepted).
5. **Deserialization/archives**: `unserialize` in DataTable/Archive/Dashboard layouts/user settings.
6. **Stored XSS into admin context that is NOT superuser-authored** (site names, goal names, custom
   dimension names, campaign params, user-agent/referrer rendered in Live/Visitor Log/Overlay, imported logs).
   Reflection-only = Low; executing in an admin session = High.

## Sources
hackerone.com/matomo (policy, rewards, hacktivity, 2026-10-22), developer.matomo.org guides
(how-piwik-works, security-in-piwik), matomo.org/changelog (5.9.0, 5.10.0, 5.11.0, 5.12.0, 5.13.0, 5.14.0–5.14.2),
app.opencve.io vendor=matomo, strix.ai CVE-2026-78850, plugins.matomo.org/premium, github.com/matomo-org/docker
README, vulncheck/exploit-db on CVE-2025-34104 (FireFart).
