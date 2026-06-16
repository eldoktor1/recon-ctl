# tech-aem.md — Adobe Experience Manager (AEM)

Reusable recon/exploitation knowledge for AEM. READ before hunting an `tech:aem` /
`Adobe Experience Manager` host; APPEND when you learn something reusable.

## What AEM is (two very different products — the distinction is load-bearing)
- **AEM Sites** (the common one): CMS on Apache Sling/Felix/Jackrabbit-Oak. Almost always
  served via the **AEM Dispatcher** (Apache module reverse proxy) which whitelists URLs.
  Publish tier is what's internet-facing; author tier (`/crx`, `/system/console`, `/bin`,
  `/etc`) is supposed to be blocked by the dispatcher filter.
- **AEM Forms on JEE**: a separate Java/Struts2 stack. This is the one with the recent
  CVSS-10 unauth RCE. Fingerprint: `/adminui`, `/lc/`, `/workspace` reachable. If `/adminui`
  is 404 the host is NOT Forms-JEE → CVE-2025-54253/54254 do NOT apply.

## Unauth VERSION-DISCLOSURE / EXPOSURE primitives (recon — read-only, NOT the RCE)
Probe these GET-only; a 200 with AEM-shaped JSON = exposed-author-surface LEAD/finding,
404/403/302-to-login = dispatcher hardened = KILL the lane.
- `/bin/querybuilder.json?path=/content&p.limit=1` — unauth content query servlet
  (classic dispatcher-bypass info-disclosure). 200 JSON `{success,results,...}` = exposed.
- `/etc/truststore.json` — exposed cert/truststore listing.
- `/system/console/bundles` — Felix console (OSGi). 200/401-basic = author exposed.
- `/crx/de/index.jsp` — CRXDE Lite. 200 = author exposed.
- `/libs/granite/core/content/login.html` — Granite login (AEM presence fingerprint).
- Dispatcher encoded-slash bypass: AEM querybuilder/truststore sometimes reachable via
  `/bin/querybuilder.json;%0a.css` / `..;/` style filter gaps even when the plain path is
  blocked. (Only test the read-only info-disclosure paths; never chain to write/RCE.)

## KEV / notable CVEs (version-reason before treating any as P0)
- **CVE-2025-54253** (CVSS 10.0, KEV, actively exploited 2025): AEM **Forms on JEE** Struts2
  DevMode — `/adminui/debug?expression=<OGNL>` evaluates OGNL unauth = RCE. Affects Forms-JEE
  **<= 6.5.23.0**; patched in 6.5.0-0108. **HARD LINE: never fire the OGNL expression** (that's
  exploitation/RCE). Recon = confirm `/adminui` is present + identify Forms-JEE; human exploits.
  Paired: **CVE-2025-54254** (XXE in Forms submission, file-read) — also Forms-JEE.
- Dispatcher misconfig (querybuilder/truststore exposure) is the bread-and-butter AEM finding
  and is a real reportable info-disclosure on its own (no RCE needed) IF it returns real content.

## Observed in OUR corpus (2026-06-16, r-this-session — KILL ledger)
The paying+in-scope AEM fleet is **dispatcher-hardened, no exposed surface**:
- `www.chipotle.com`, `www.vwfs.*` (VW Financial Services, ~16 locales), `business.amazon.*`,
  `developer.amazon.com`: `/bin/querybuilder.json`, `/etc/truststore.json`, `/crx/de`,
  `/adminui`, granite-login all **404** (large generic HTML error page) or **403**
  (`/system/console`). AEM Sites publish behind dispatcher; admin surface blocked. `/adminui`=404
  everywhere ⇒ **NOT Forms-JEE ⇒ CVE-2025-54253/54254 N/A**. KILL the AEM n-day lane on this fleet.
- `contributor.stock.adobe.com`: every AEM path 302→`ims-na1.adobelogin.com` (Adobe IMS SSO) =
  fully auth-gated. No unauth surface.
Takeaway: `tech:aem` (78 paying hosts) is overwhelmingly hardened publish-dispatcher; don't
re-walk these. Worth re-checking ONLY if a host newly exposes `/adminui` (Forms-JEE) or returns
real querybuilder JSON.

## Sources
- https://socradar.io/cve-2025-54253-adobe-experience-manager-flaw-exploit/
- https://www.secpod.com/blog/adobe-aems-debug-doorway-critical-rce-under-active-exploitation
- https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/aem-adobe-experience-cloud.html
- https://zeropath.com/blog/cve-2025-54253-adobe-experience-manager-forms-misconfiguration-summary
