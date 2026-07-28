# Research digest — detect-tune — 2026-07-28

# Detection & Verification Tuning — Digest (2026-07-28)

Checked existing KB first: Nginx off-by-slash alias traversal, all four active Nginx CVEs (Rift/HTTP3-UAF/njs/HPACK), GraphQL introspection-bypass techniques, wp2shell WordPress core RCE, and origin-IP-discovery-via-DNS-history are already documented — not re-surfaced. Two genuinely new, actionable WordPress plugin CVEs found this run (both unpatched-population still material, both map directly to our existing safe confirm primitives).

## 1. Avada Builder ≤3.15.1 — Unauth Time-Based SQLi (CVE-2026-4798) — narrow but real precondition, good FP filter

- **Plugin:** Avada Builder (Theme Fusion) — ~1M active installs, matches our in-scope-top-tech WordPress surface.
- **Param:** `product_order` — `sanitize_text_field()` is applied but does **not** stop SQLi; value is concatenated straight into an `ORDER BY` clause (bypasses WP's `$wpdb->prepare()`).
- **Critical precondition (the FP filter):** only exploitable on sites where **WooCommerce was previously installed and later deactivated** — the vulnerable query path is dead code unless that history exists. Don't flag every Avada site; this cuts the false-positive rate hard.
- **Fixed:** 3.15.2 (Apr 13, partial) → fully fixed 3.15.3 (May 12, 2026). Version ≤3.15.1 = in-range.
- **Detect (unauth, safe):** `curl -s https://<host>/wp-content/plugins/avada-builder/readme.txt | grep 'Stable tag'` (or theme `style.css` version header if bundled with the Avada theme) → ≤3.15.1. Confirm exploitability signal (not exploit) via our existing `'` vs `''` differential on `product_order` — time-based, so use response-time delta not error-diff.
- **Impact if real:** password-hash / DB extraction — high severity, worth a P1/P2 report once confirmed.
- Sources: [Kenet CVE-2026-4798](https://cert.kenet.or.ke/cve-2026-4798-avada-builder), [mySites.guru patch notes](https://mysites.guru/blog/avada-builder-cve-2026-4782-4798/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/avada-builder-wordpress-plugin-flaws-allow-site-credential-theft/)

## 2. Ninja Forms – File Uploads ≤3.3.26 — Unauth Arbitrary File Upload → RCE (CVE-2026-0740)

- **Mechanism:** `NF_FU_AJAX_Controllers_Uploads::handle_upload` validates file type on the *source* filename but never checks the *destination* filename or sanitizes it — attacker uploads a `.php` file and path-traverses it into the webroot. No auth required.
- **Scale:** ~50k active installs; mass-exploited in the wild Apr 9–13, 2026 (118k+ blocked attempts per Wordfence) — old enough that unpatched stragglers are the realistic remaining population, but that population is still real (patch lag on WP plugins routinely runs 6+ months).
- **Fixed:** 3.3.27 (Mar 19, 2026). ≤3.3.26 = in-range.
- **Detect (unauth, safe, non-destructive):** `curl -s https://<host>/wp-content/plugins/ninja-forms-uploads/readme.txt | grep 'Stable tag'` (or plugin slug `ninja-forms-file-uploads` depending on listing) → ≤3.3.26 = LEAD. **Do not** send an actual upload PoC — that's the destructive trigger; version-detect only, same discipline as our existing WP plugin CVE entries.
- Sources: [ZeroPath analysis](https://zeropath.com/blog/cve-2026-0740-ninja-forms-file-uploads-arbitrary-file-upload), [SentinelOne CVE-2026-0740](https://www.sentinelone.com/vulnerability-database/cve-2026-0740/), [Truesec](https://www.truesec.com/hub/blog/critical-vulnerability-in-ninja-forms-file-upload-wordpress-plugin-cve-2026-07409)

## Note (not actioned): origin-IP-behind-CDN discovery

Searched this as a possible detect-tuning lane (relevant given our heavy Cloudflare/CloudFront top-tech) but decided against a KB write: standard techniques (DNS-history via SecurityTrails/ViewDNS, Shodan/Censys cert-match, split-DNS apex-vs-www gaps) are well-worn and, more importantly, testing an origin server directly (bypassing the program's CDN/WAF) is frequently an explicit **out-of-scope carve-out** in program policy — this needs a Phase-0 scope read per host, not a blanket detection rule. Flagging only in case a specific program's policy explicitly allows it.
