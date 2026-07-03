# class: client-side "secrets" in SPA bundles / source maps — usually PUBLIC-BY-DESIGN (Info)

**TL;DR:** A token-shaped string found in a web app's JS bundle or `.js.map` is **not automatically a
finding**. If the app ships the value to the browser as part of normal operation, it is **public-by-design**
= **Informational / N-A**, even when it's a "prod" key and even when the bundle is fronted by a source map.
Reporting it as Medium/High = overclaim → report closed N/A + signal ding. See [[feedback_theoretical_classes_get_declined]].

## The decisive test (run this BEFORE believing a source-map "secret")
A source map (`.js.map`) only makes the *minified bundle* readable — it almost never contains a secret the
bundle doesn't. So the real question is: **is the value in the SHIPPED minified bundle, and is that bundle
served to anyone?**

1. **Grep the actual minified bundle (not the `.map`)** for the literal value:
   `curl -s "<host>/static/js/main.<hash>.chunk.js" | grep -c "<the-value>"`
   - count ≥1 → the value is compiled into the code every visitor downloads.
2. **Is the bundle served unauth?** `curl -so/dev/null -w '%{http_code}' "<host>/"` and the static path.
   - 200 unauth → every internet visitor already has the value in their browser Network tab.
   - **Both true ⇒ public-by-design ⇒ Informational.** The source-map exposure on its own is at most Info
     (client source disclosure + maybe internal topology).
3. Only if the value is **ONLY in the `.map`** (stripped from the shipped bundle) OR the bundle is
   **behind auth** does the map leak actually disclose something a normal visitor wouldn't have.

## Known public-by-design value classes (do NOT score as secrets)
- **AWS API Gateway `x-api-key`** (40-char, sent via `x-api-key` header from an SPA). AWS docs: API keys are
  **usage-plan / throttling** identifiers, **"not a security mechanism."** A live gateway returning
  `403 {"message":"Forbidden"}` + `x-amzn-errortype: ForbiddenException` to a no-key request just means the
  method has a usage-plan key requirement — that's normal for a client-shipped key and does NOT prove the key
  alone unlocks data (real auth is usually a Lambda/Cognito authorizer behind it). Never test with the leaked
  key (hard line) — so you can't prove MED; default to Info unless the program says otherwise.
- Firebase web config / RTDB URL / Storage bucket name → see [[class-firebase.md]] (the *rules* are the bug, not the config).
- Supabase **anon** key, Stripe **`pk_`** publishable, Google **browser** API keys (`AIzaSy…`), OAuth **`client_id`**.

## What WOULD be reportable (the real leads hiding nearby)
- A **server-side** secret in the bundle (AWS `AKIA…`+secret, `sk_live_…`, private signing key, DB creds) — these
  are NOT supposed to ship to the browser → real (verify it's not a placeholder).
- The bundle/source map revealing an **IDOR/BOLA-shaped authed flow** (`?id=<opaque>`/`/{id}/`) → authed money
  lead, operator + 2 owned accounts (NOT the key itself).
- Internal **non-prod API topology** (`{dev,qa,stg}.gateway…`) → Info enrichment / attack-surface map, rarely paid alone.

## Worked example (the rule's origin)
Comcast `beta.esign.digital.business.comcast.com` id74 (2026-06-16): `.js.map`=200 exposing 4 hardcoded
`x-api-key`s incl 2 prod. 2IC carried it ~18 rounds as the top standing exposure. Killed on probe: all 4 keys
also in the shipped `main.de3a8a6f.chunk.js` (grep=1), app serves unauth (`/`=200) ⇒ **public-by-design = Info**.
`prod.ecom-gateway`=NXDOMAIN; `prod.core-gateway`=live AWS APIGW, 403 ForbiddenException no-key (expected).
Residual real lead = the e-sign `PhoneTransfer id=<opp_id>` flow (authed IDOR, separate). Source: AWS API Gateway
docs (API keys ≠ auth); host_notes `beta.esign.*`.


---
<!-- applied-proposal: 2026-06-21_tooling_class-clientside-secrets -->
### Applied research — tooling (2026-06-21)

## Tool note: jsluice (BishopFox) — AST-aware JS endpoint + secret extractor

**Repo:** https://github.com/BishopFox/jsluice  
**Added:** 2026-06-21  

### What it adds over regex-based extraction
- Parses JavaScript AST rather than running regex over raw text
- Extracts URLs/paths embedded in: template literals, nested object keys, computed property names, minified variable chains
- Outputs structured JSON; designed for pipeline integration (`jsluice urls <file.js>`)
- Also has a `secrets` subcommand that finds hardcoded secrets — complementary to trufflehog (different detection strategy, not a replacement)

### Integration pattern
Run as a *second pass* after existing regex extractor in `recon_jsintel.sh`. Deduplicate by URL path template before feeding `endpoints.jsonl`. Expected gain: deeper endpoint yield from complex/minified JS that regex misses.

### Safety
Static analysis only — reads already-fetched JS files, zero new target traffic.
