# class-xss — reflected / DOM XSS via the ranked param lane (dup-proof, PoC-gated)

> Reusable KB for the XSS lane (`recon_xss_sqli_candidates.py` ranks the catalog →
> `briefings/xss_candidates_<date>.md`; `recon-params confirm xss <host>` = dalfox confirm;
> `recon-domxss <host>` = source→sink miner). READ before an XSS evening; APPEND when you learn a new
> framework sink/bypass. The rs0n "all XSS targets from HackerOne" idea, made dup-proof + multi-platform.

## The one rule everything reduces to
**Reflection is a LEAD; EXECUTION is CONFIRMED.** A value appearing in the response is not XSS —
break-out chars (`"><'/`) must survive UNENCODED in an executable context and actually fire. The lane
surfaces + ranks reflective params (LEAD); dalfox proving a marker EXECUTES in headless Chromium is the
CONFIRMED primitive. Mass-XSS on saturated programs IS the dup trap (the MOTTO) — the edge is the
uniqueness-split + freshness-first + real-PoC confirm, not volume.

## Injectability ranking (the heart — kxss insight, encoded in `recon_xss_sqli_candidates.py`)
Not all params are equal. Score on the STRONGEST few param names (a focused `?redirect=` beats 8
random params — summing rewards fuzz-capture junk), plus handler/path signal, freshness, payout tier.

**XSS reflect-weight (params whose values land in HTML/JS):**
- **weight 3 (reflect telltales):** `q query search s keyword term redirect redirect_uri return
  returnurl next url uri callback jsonp dest continue goto r u link` — these get echoed into the page.
- **weight 2:** `name message msg comment text title subject body content value input data error desc
  page view lang ref output`.
- **weight 1 (weak/rarely-reflected):** `id email file path src item type action mode tab filter sort field`.
- **+2 dynamic handler** (`.php/.asp/.aspx/.jsp/.cgi/.do/.action/.cfm`), **+1 API/versioned path**
  (`/api/`, `/v\d+/`, `/graphql`), **+1 depth≥2**.
- **Contrast with SQLi ranking (same script, different table):** SQLi weights *object/numeric refs*
  highest (`id uid pid catid product news article page_id user_id order oid …` = enumerable/injectable),
  because those hit the query — whereas XSS weights *reflective* names. The same `?id=` that's a strong
  SQLi candidate is a weak XSS candidate, and vice-versa. Pick the lane by param character.

**Dedup + uniqueness split (dup-proof):** collapse locale segments (`/en_gb/` → `/{loc}`) and numeric
path-IDs (`/article/12345` → `/{id}`) into one template; measure template fan-out across hosts; SPLIT
**UNIQUE** (fanout ≤6, rare per-app params — test these FIRST) from **PRODUCT-CLASS** (fanout >6, the
`?q=` / `_next/image?url=` dup-magnets everyone fuzzes — only if ⚡fresh or your own program). Drop
wayback attack-capture noise (`%22`/`%3c`/`FUZZ`/traversal paths — captured attacker fuzz, not real
endpoints) and param-floods (>8 distinct params = fuzz-capture junk). Rank `score × (tier+1) ×
1.5-if-fresh`. `⚡`=true_fresh (be first, low-dup), `📝`=host already noted (read the note first).

## Confirm primitives (the gate is EXECUTION, not reflection)
- **Reflected XSS → dalfox** (`recon-params confirm xss <host>`) — context-aware: it places the payload
  in the actual reflection context and verifies the break-out EXECUTES in headless Chromium. Rate-limited,
  mining-off (gentle, doesn't ban the Mullvad exit). Reflection without execution ⇒
  `reflected-not-exploitable` LEAD, move on. This killed the old canary-FP (a marker string echoed in a
  JSON/encoded context is NOT XSS).
- **DOM XSS → dalfox `--deep-domxss --force-headless-verification`** — confirms EXECUTION of a
  source→sink flow (a real headless verify beats a static miner). `recon-domxss <host>` is the
  complementary source→sink miner: it flags HTML-sink + tainted-source flows and
  `dangerouslySetInnerHTML` rendering server data (= stored-XSS leads to read in REVIEW). DOMDig is the
  deep-SPA v2/on-demand option.
- **Authed surface** → both confirms take `--cookie`/`--header` to walk the operator's own post-login
  surface (SAFE primitives, human-in-the-loop only).
- **Blind/stored XSS** is a separate lane (`recon_blindxss.sh`, dual-beacon interactsh + XSS Hunter) —
  see `class-blind-xss.md`; the reflected-param lane here is the on-demand/reflected half.

## Documented FP patterns (never score as CONFIRMED)
- **Reflection ≠ XSS.** Plain string reflection — especially inside JSON or an otherwise encoded/
  attribute-escaped context — is NOT confirmed XSS. Break-out chars must survive UNENCODED in an
  executable context. Encoded/framework-safe reflection ⇒ `reflected-not-exploitable` (LEAD).
- **Framework auto-escaping.** React/Angular/Vue/modern-template stacks escape by default; a value
  rendered as text is inert. Real DOM-XSS there needs an unsafe sink (`dangerouslySetInnerHTML`,
  `v-html`, `[innerHTML]`, `bypassSecurityTrust*`, direct `eval`/`document.write`/`location`) fed a
  tainted source — that's what `recon-domxss` looks for, not mere reflection.
- **Self-XSS / no cross-user impact.** A payload that only fires in your own input (self-XSS), or that
  needs an implausible victim-side precondition, gets N/A. IMPACT-GATE: only a DEMONSTRATED executing
  XSS is reportable — theoretical/no-impact (CORS, missing headers, self-XSS, error-only) is N/A; don't
  burn the evening on it (`feedback_theoretical_classes_get_declined`).
- **Product-class dup-magnet.** The same templated param on >6 hosts (`?q=` on 500 WordPress sites,
  `_next/image?url=`) is what everyone fuzzes = duplicate = $0. The fan-out split suppresses these to
  the PRODUCT-CLASS section — work TOP UNIQUE lanes first; touch product-class only if ⚡fresh or it's
  your own program.
- **Wayback attack-capture ≠ endpoint.** URLs with encoded quotes/brackets/`FUZZ`/traversal in the path
  are captured attacker traffic, not real reflective endpoints — dropped at scoring.

## Lane design (actionable summary)
1. **Catalog** — `recon_params.sh` crawls in-scope+paying hosts (katana+gau+CDX→gf) → `recon_params`
   ES index classifies param-URLs into vuln classes (~18k XSS across 5 platforms). On-demand:
   `recon-params crawl-host <host>` (queue bypass).
2. **Rank** — `recon_xss_sqli_candidates.py --class xss` scores injectability + handler + freshness +
   payout, dedups by template, splits UNIQUE vs PRODUCT-CLASS, drops benched/OOS hosts (re-checks the
   live `recon_alive` ledger) → `briefings/xss_candidates_<date>.md` (surfaced in the 6:30 briefing).
3. **Confirm on-demand** — `recon-params confirm xss <host>` (dalfox, EXECUTION-gated). Reflection-only
   ⇒ `reflected-not-exploitable` LEAD.
4. **Note** every FP/skip inline (encoded-reflection, framework-safe, product-class, self-XSS) so it
   doesn't re-serve.
5. **Report** a DEMONSTRATED executing XSS only — honest severity, `alert(document.domain)`/benign
   marker PoC, dup-check all platforms first.

## Sources
- rs0n "all XSS targets from HackerOne" + kxss (param-name reflection insight, Tom Hudson).
- PortSwigger Web Security Academy — Cross-site scripting (contexts, DOM-XSS sources/sinks).
- dalfox docs (context-aware confirm, `--deep-domxss`, `--force-headless-verification`).
- CLAUDE.md "XSS/SQLi reflected-param lane" pillar + "Documented false-positive patterns" (reflection ≠ XSS).
- `project_xss_sqli_rs0n_lane` memory; `class-blind-xss.md` (the stored/blind half).
