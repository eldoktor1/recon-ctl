# Sitevision (Sitevision AB, sitevision.se) — recon + attack surface

Swedish Java CMS. Distinct from the US "SiteVision" (sitevision.com) — do not confuse them
when reading CVEs. First mapped 2026-08-20 against `heureka.sbb.ch` (Intigriti `sbbglobal`).
**11 in-scope hosts in ES match Sitevision fingerprints** — this doc is the reusable contract
so those hosts start informed instead of being re-derived host by host.

## Fingerprints
- `<html class="sv-view">` (page), `class="sv-common"` (error page), `class="sv-forms"` (forms)
- `<body id="sv-entity-..." data-csrf-token="<128 hex>" data-menu-id="N">`
- `/design/generated/view.min.js?v=<md5>` + `/design/generated/view.min.css` (Sitevision bundle)
- Inline admin login block `div.sv-inpage-login` → `POST /_admin/_login`, fields
  `Login[usrAlias]` / `Login[usrPwd]` / `redirecturl`
- Cookies `SVSESSID`, `__sv_language`
- `SRV=<uuid>` (load-balancer affinity, not Sitevision)

## Built-in underscore endpoints (undocumented — not in developer.sitevision.se)
`developer.sitevision.se` documents only RESTApps; these internal routes are NOT covered there.
Harvest them from `view.min.js` / the site's own `app.*.js`, not from docs.

| Path | Method | Notes |
|---|---|---|
| `/_fileUpload` | GET, **POST** | jQuery-fileupload target. GET → `[]`. POST param name is **`file`** (`files[]` → 500) |
| `/_mail` | **POST only** | GET/OPTIONS return the 404 template — *a 404 here does NOT mean absent* |
| `/_common/forms/openFormModal` | GET | `?formType=<t>&redirectUrl=<url>` |
| `/_common/file/pdf` | GET | often WAF-blocked at the edge (see burn-trap) |
| `/_common/common/langChange` | POST | `sv_lang`, `menuId`, `articleId`, optional `preview` |
| `/_admin/_login` | POST | admin login — never attack |

## The mailsend contract (`/web/js/util/mailsend.js`, inside view.min.js)
```js
data.url = '/_fileUpload'                       // file staged first, per file field
sendData = { Email:    decryptEmail(form.attr('SVmailto')),
             EmailCC:  decryptEmail(form.attr('SVmailcc')),
             EmailBCC: decryptEmail(form.attr('SVmailbcc')),
             EmailFrom:decryptEmail(form.attr('SVmailfrom')),
             FromName: form.attr('SVnamefrom'),
             Subject:  form.attr('SVsubject') }
sendData[fileField] = '__fileUpload__' + fileField
$.post('/_mail', sendData, ..., 'json')
```
- **Recipient is client-supplied.** `Email`/`EmailCC`/`EmailBCC` are POST params, so an open
  relay is structurally possible — the whole question is whether the server binds them to the
  page's configured form.
- **`decryptEmail` is a Caesar shift of −3** (`encryptEmails` = +3). So every `SVmailto`
  attribute on any Sitevision page is trivially readable, and any address in an
  `href="javascript:linkDecryptEmail('…')"` decodes the same way. This is anti-scraping
  obfuscation, **not** a finding on its own.
- All form fields are renamed `ms<index>$_<name>` **except `sv_timeStamp` and `sv_security`** —
  those two are the server-side anti-abuse tokens and the real gate on `/_mail`.
- Client-only anti-bot: hidden honeypot `sv_noText` (must stay empty) and an `SVtime` timestamp
  check — both evaluated in `checkForm()` in the browser, so neither is a server control.

**Testing `/_mail`:** POST with no recipient returns `{"error":"The email could not be sent."}`
(fails closed). To actually settle relay you need a **live** mailsend form to source a valid
`sv_security`; if every form on the host is disabled, the question is unprovable there — record
that honestly rather than claiming a kill. Never send to a third-party address; own mailbox only.

## File upload — where the real control lives
`checkFiles()` validates the extension against `fileUploadOptions.allowedFileTypes` **in the
browser only**, which reads like a classic client-side-filter bug. On heureka the server
independently enforced its own allowlist:

| Uploaded | Result |
|---|---|
| `.txt`, `.svg`, `.html` | `{"error":"Invalid file type","status":"error"}` |
| `.png`, `.pdf`, `.gif` | accepted (`[]`), **no stored path returned** |

So the script-capable types were rejected server-side and no retrievable URL was disclosed.
**Do not report "client-side-only file filter" from reading the JS — always POST the actual
type.** The JS is the hypothesis; the server response is the finding.

## Forms modal (`app.*.js`, custom per-site bundle)
```js
n.searchParams.set("formType", t);
n.searchParams.set("redirectUrl", window.location.href);
const r = await a.text();
new Interlay(r, {type:"overlay"}, ...)   //  → element.innerHTML = r
```
The response is injected with **`innerHTML`**, and `redirectUrl` derives from
`window.location.href` — so *if* the server reflects `redirectUrl` into that fragment it is
one-click reflected XSS (and `innerHTML` won't run `<script>` but `<img onerror>` fires).
Worth checking on every Sitevision host. On heureka it did **not** reflect, because the only
`formType` (`feedback`) returns a static "form is currently disabled" fragment.
Enumerate real `formType` values from `data-open-form-button` / `data-form-type` attributes in
the page HTML rather than guessing.

## CSP note
Typical Sitevision-hosted CSP ships `script-src 'unsafe-inline' 'unsafe-eval' 'self'`. So CSP is
**not** a mitigation for any same-origin HTML/SVG injection here — an inline handler executes.
Conversely `form-action 'self'` and `frame-ancestors 'self'` are set, so no cross-origin form
post or clickjacking.

## Burn-trap (operational)
On edge-fronted deployments `GET /_common/file/pdf` returns **403 from the corporate WAF** (a
large branded block page, not the Sitevision app) and that 403 immediately arms a 900s host
cooldown in `recon_safe_probe.sh`. One hit costs 15 minutes of access to the whole host — this
is what silently blocked an entire `recon_ai_hunter` battery.

**Handled in code since 2026-08-20** — you do not need to remember this, but do not undo it:
- `/_common/file/*` is on the built-in burn-trap denylist in `recon_safe_probe.sh`, so no
  unattended lane probes it. Override for a deliberate on-demand look with
  `SAFE_PROBE_UNATTENDED=0`; extend the list in `state/probe_denylist.txt`.
- `safe_probe_worker.py` now classifies a 403 as edge (CDN/WAF branded page, no app
  fingerprint) vs application. A lone edge 403 is a path RULE, not rate pushback, so it buys a
  60s cooldown rather than 900s; three in five minutes escalate to the full cooldown.
- `recon_ai_hunter.sh` refuses to hypothesise against a host whose probes cannot run, and
  withholds any hypothesis set where no probe response was captured.

## CVEs — read the vendor carefully
- `CVE-2019-12733` / `CVE-2019-12734` — Sitevision AB, insufficient module access control
  (`portletType` swap on `/edit-api/...`) → XSS/RCE. **Requires a low-privilege account**, and
  affects only v4 ≤4.5.6 / v5 ≤5.1.1. Not applicable to modern (v10+) instances.
- `CVE-2025-34121` — **Idera Up.Time, NOT Sitevision.** It surfaces first on searches for
  "Sitevision unauthenticated file upload"; do not mis-attribute it.
- No public advisory exists for the mailsend relay or `/_fileUpload` behaviour — genuinely
  under-hunted surface, which also means no n-day shortcut: prove it yourself or drop it.

## Sources
- Target's own bundles: `/design/generated/view.min.js`, `/design/dist/app.*.js`
- [developer.sitevision.se — RESTApps](https://developer.sitevision.se/docs/restapps)
- [Full Disclosure: SiteVision Insufficient Module Access Control (CVE-2019-12734)](https://seclists.org/fulldisclosure/2019/Dec/13)
- [GHSA-7x48-359h-28rm (CVE-2025-34121 — Idera, for disambiguation)](https://github.com/advisories/GHSA-7x48-359h-28rm)
