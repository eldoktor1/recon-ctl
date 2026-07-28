# Research digest — detect-tune — 2026-07-28

# Detection & Verification Tuning — Digest (2026-07-28, supplemental)

Checked against the last 30 days: Avada Builder SQLi, Ignition RCE, Varnish PURGE, GraphQL introspection-bypass techniques, and dalfox v3 are already documented — skipped. This pass found two live, high-severity, unauth WordPress plugin CVEs directly on our top-tech surface (WordPress/PHP) with exact HTTP requests and safe version-fingerprints, plus a takeover-fingerprint refresh for non-classic SaaS providers.

## 1. Kirki plugin ≤6.0.6 — Unauth account takeover via password-reset email hijack (CVE-2026-8206, CVSS 9.8) — HIGH PRIORITY
- **Plugin:** Kirki – Freeform Page Builder/Customizer (WordPress) — ~500k+ installs, matches our WordPress top-tech.
- **Bug:** `handle_forgot_password` (`CompLibFormHandler.php`) accepts an attacker-supplied `email` alongside a known `username` and sends the reset link there instead of the account's real address — no auth, no permission check.
- **Request:** `POST /wp-json/KirkiComponentLibrary/v1/kirki-forgot-password` with `username`, `email` (attacker's inbox), `emailBody` (JSON containing the `reset_link` chip). Success = HTTP 200 + "Email sent".
- **Safe detect (no exploitation needed):** `curl -s https://<host>/wp-content/plugins/kirki/readme.txt` (also try `kirki-test`) → `Stable tag` ≤ 6.0.6, or the `ver=` query param on `kirki.min.css`. Fixed in **6.0.7** (released 2026-05-18).
- **Note:** this is a full unauthenticated account-takeover primitive (username enumeration + the reset-email redirect) — the version match alone is a LEAD per KEV-doctrine; the confirm step is a benign reset request against **our own test account username only**, never a real user's.
- Sources: [ZeroPath writeup](https://zeropath.com/blog/cve-2026-8206-kirki-wordpress-privilege-escalation), [Threat-Modeling.com](https://threat-modeling.com/kirki-wordpress-plugin-account-takeover-cve-2026-8206/), [Bleeping Computer](https://www.bleepingcomputer.com/news/security/critical-kirki-flaw-exploited-to-hijack-wordpress-admin-accounts/), [PoC detection method](https://github.com/Jenderal92/CVE-2026-8206)

## 2. Ninja Forms File Uploads ≤3.3.26 — Unauth arbitrary file upload → RCE (CVE-2026-0740, CVSS 9.8)
- **Bug:** `NF_FU_AJAX_Controllers_Uploads::handle_upload` validates the extension of the *source* filename but writes to an attacker-controlled *destination* filename — an extra POST param renames the upload past the allowlist (e.g. source `image.jpg`, destination param `image_jpg=shell.php`).
- **Exact request chain (unauth):**
  1. `POST /wp-admin/admin-ajax.php` `action=nf_fu_get_new_nonce&field_id=<id>` → harvest nonce
  2. `POST /wp-admin/admin-ajax.php` `action=nf_fu_upload&nonce=<nonce>&form_id=<id>&field_id=<id>&<slugified_filename>=<malicious_dest>` + `files-<field_id>=@<file>`
- **Safe detect (no upload attempt):** `httpx`/grep page source for `nfpluginsettings\.js\?ver=[\d.]+` → version ≤3.3.26 = in-range. Fixed in **3.3.27** (2026-03-19); confirmed actively exploited in the wild since 2026-04-16 (Wordfence).
- Confirming beyond version-match means an actual file write — that crosses into exploitation (RCE), so per our doctrine this stays **version-match LEAD**, not an auto-fired primitive; a confirm would need an explicit benign non-PHP marker upload, operator-gated.
- Sources: [Lexfo technical writeup + exact requests](https://blog.lexfo.fr/ninja-forms-uploads_rce.html), [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-0740/), [PoC](https://github.com/whattheslime/CVE-2026-0740), [U of Toronto advisory](https://security.utoronto.ca/advisories/ninja-forms-file-uploads-unauthenticated-remote-code-execution/)

## 3. Subdomain-takeover fingerprints — non-classic SaaS providers (addendum, feeds `class-takeover.md`)
Exact error-string/header fingerprints for providers less commonly covered by the classic can-i-take-over-xyz list:

| Provider | CNAME pattern | Fingerprint | Claimable via |
|---|---|---|---|
| Vercel | `cname.vercel-dns.com` | `"DEPLOYMENT_NOT_FOUND"` + `x-vercel-id` header | bind orphaned hostname to attacker's Vercel project |
| Netlify | `*.netlify.app`/`*.netlify.com` | `"Not Found - Request ID:"` + `x-served-by: cache-...netlify` | bind Netlify site to hostname |
| Webflow | `proxy.webflow.com`/`proxy-ssl.webflow.com` | `"The page you are looking for doesn't exist"` | bind new Webflow project (note: 2023 patches narrowed but didn't eliminate) |
| Tilda | `*.tilda.ws` | `"Please renew your subscription"` / `"Domain has been assigned"` | re-bind after subscription lapse |
| Pantheon | `*.pantheonsite.io` | `"The gods are wise, but do not know of the site which you seek."` | bind Pantheon site to hostname |

Same discipline as our existing takeover doctrine applies: CNAME/fingerprint match alone is a LEAD; claim requires the provider-specific unclaimed-state proof before minting CONFIRMED.
Source: [Vulnsy Subdomain Takeover Cheat Sheet](https://www.vulnsy.com/cheat-sheets/subdomain-takeover)
