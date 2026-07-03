# DOM XSS & React stored-XSS — hunting methodology

Recorded 2026-06-15 (developed hunting webviews.monzo.com + admin.indeedflex.com). Sources at bottom.

## Workflow
1. **CSP triage FIRST** — `curl -D - host | grep content-security-policy`. Strong nonce/sha256 `script-src`
   with no `unsafe-inline` = execution GATED (deprioritize unless a CSP-bypass gadget on a whitelisted
   origin). NO CSP / `unsafe-inline` = a sink will actually FIRE → prime target. (tech-nextjs.md §9.)
2. **Mine JS:** `recon-domxss <host>` → fetches page+JS, flags sinks. Note "0 same-site" usually = CDN bundles.
3. **Read the REVIEW list** (HTML/exec sinks; minified code spreads source→sink past the window so they
   rarely auto-pair). Triage by sink type: `dangerouslySetInnerHTML` / `innerHTML` / `document.write` /
   `.html()` / lodash `_.template`(Function). IGNORE: `location.href=` navigation (router/FileSaver),
   `URLSearchParams.append`, `*.toSVG()` icon dSIH, `__html:"&#8203;"` static — all FPs.

## The two XSS shapes in React/Next
- **Reflected DOM XSS (unauth):** a SINK fed by a tainted SOURCE (`location.hash`/`search`/`window.name`/
  `postMessage`/`document.referrer`). Rare in React (auto-escape) — needs an unsafe sink on URL data.
  If `recon-domxss` "sources seen" has no `hash`/`search`, there's likely no reflected path.
- **Stored XSS (authed, HIGHER value):** a dSIH/innerHTML rendering SERVER DATA raw. Tell-tale: `__html`
  bound to a data var, esp. a field named `*_html` / `message_html` / `description` / `content` / `literal`,
  with NO `DOMPurify.sanitize()` in the expression. Then: if a LOWER-PRIV user can SET that field (profile/
  message/note), it renders raw when a higher-priv user (admin) views it = privilege-escalating stored XSS.
  Esp. dangerous on a NO-CSP admin panel (admin-context script exec). DOMPurify existing in SOME bundle ≠
  applied to THIS sink — check the actual expression.

## Common React component dSIH XSS sinks (library-level)
- `react-tooltip` with `html`/`data-html` prop renders the tip via dSIH (XSS if tip content is user-fed).
- notification/toast libs with an `allowHTML`/`dangerouslySetInnerHTML` option (render `message`/`children`).
- rich-text / markdown / CMS render-HTML components.
- lodash `_.template` (`new Function("with(obj){…}")`) = template-injection / code-exec if the template
  string is user-controlled.

## Confirming (CONFIRMED vs LEAD)
- Sink existing = LEAD. CONFIRMED = inject a marker that EXECUTES (`<img src=x onerror=alert(document.domain)>`
  for HTML sinks) and observe it run in DevTools — reflection/escaped ≠ XSS. For stored: set the field from a
  2nd owned account, view as the target user, confirm execution. Authed → operator-overseen (recon-account +
  read the app's API/docs to map which input feeds the sink). 2 owned accounts, confirm-then-stop, no harvest.

## Tooling
`recon-domxss <url>` (recon_params/recon_ctl) — HTML-sink vs nav split, library-FP filter, HIGH(tainted)+
REVIEW(trace-by-hand) lists, caches JS in /tmp/domxss_<h> for grep (`grep -oaE 'dangerouslySetInnerHTML:\{__html:[^}]+'`).

## Worked example (admin.indeedflex.com, 2026-06-15)
No-CSP admin SPA; 30 dSIH. App sinks rendering raw server data: `__html:c.message_html` (holiday-pay modal),
`__html:e.literal`, notification `allowHTML`. No URL→sink (sources=location.href only). => STORED-XSS lead
pending authed test (which lower-priv input feeds message_html). host_notes has the detail.

## Sources
- DOM XSS in SPAs (sources→sinks): https://medium.com/@asifebrahim580/dom-based-xss-in-single-page-applications-spas-a-complete-guide-for-beginners-bug-bounty-56d4e496a0a0
- XSS in Next.js / dangerouslySetInnerHTML: https://vibeappscanner.com/vulnerability-in/xss-nextjs
- DOM Invader (Burp) for DOM XSS: https://undercodetesting.com/unmasking-dom-xss-the-ultimate-guide-to-bug-bounty-mastery-with-dom-invader/


---
<!-- applied-proposal: 2026-06-20_vulns_class-domxss -->
### Applied research — vulns (2026-06-20)

## Prototype Pollution → DOMPurify Gadget Chain (June 2026)

Source: https://labs.trace37.com/blog/dompurify-pp-ceh-bypass/

**Technique:** If `Object.prototype.tagNameCheck` or `Object.prototype.attributeNameCheck` is polluted (via lodash merge, `JSON.parse` + `Object.assign`, qs library, etc.), DOMPurify's `CUSTOM_ELEMENT_HANDLING` inherits the polluted prototype — bypassing ALL tag/attribute sanitization.

**Affected:** DOMPurify 3.0.1–3.3.3 (fixed in 3.4.0)

**Chain required:** (1) PP vector present on page → (2) DOMPurify ≤ 3.3.3 called to sanitize rendered HTML → (3) attacker controls sanitized input.

### Detection augmentation for `recon-domxss`
When scanning JS for DOMPurify:
```bash
# Version detection
grep -oE 'DOMPurify[^"]*"version"\s*:\s*"[0-9.]+"' *.js
# Regex: 3\.(0\.[1-9]|[1-2]\.|3\.[0-3]) → vulnerable range
