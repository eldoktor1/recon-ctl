# class-graphql — GraphQL recon → ranked unauth-safe worklist

Research recorded 2026-06-20 from **source code reads** (not just READMEs) of graphw00f +
graphql-cop, PortSwigger GraphQL Academy, the graphql-threat-matrix, and disclosed reports.
Goal: an automated, **unauth-safe, dup-resistant** lane — find in-scope GraphQL endpoints →
fingerprint → harvest introspection (if enabled) → rank sensitive unauth ops + field-level
IDOR/injection candidates into a HUMAN-test worklist. Confirm-then-stop; the hard line
(no mutations, no third-party IDs, no data harvest) is unchanged.

---

## TOOL 1 — graphw00f (endpoint detection + engine fingerprinting)

- **Install:** `git clone https://github.com/dolevf/graphw00f.git` (Python3 + `requests`; no pip package).
- **Run:** `python3 main.py -d -f -t http://host/path`
  - `-d/--detect` = find the GraphQL endpoint (iterates a built-in path wordlist via
    `possible_graphql_paths()` — `/graphql`, `/api`, `/api/graphql`, `/v1|v2|v3/graphql`,
    `/graphiql`, `/console`, `/playground`, `/gql`, `/query`, `/index.php?graphql`, root, …;
    `-w FILE` overrides). Validates each with a `__typename` probe.
  - `-f/--fingerprint` = identify the engine (run after `-d` or with a known path).
  - `-t URL`, `-p PROXY`, `-T TIMEOUT`, `-H HEADER` (e.g. Authorization), `-u UA`,
    `-r` (no-redirect), `-l` (list engines), `-o FILE` (**CSV** output, NOT JSON:
    header `url,detected_engine,timestamp`). stdout prints `Discovered GraphQL Engine: (name)`
    + `Technologies:` (impl language list) + a `ref` to the graphql-threat-matrix entry.
- **Detection logic:** error-based fingerprinting. Sends 1–5 tiny probe queries per engine
  (`engine_*()` in `graphw00f/lib.py`) and string-matches the engine-specific ERROR. Examples
  (source-verified): Apollo `query @skip{__typename}` → `Directive "@skip" argument "if" … is required`;
  Hasura `query{__schema}` → `missing selection set for "__Schema"`; graphql-ruby `query @skip{__typename}`
  → `'@skip' can't be applied to queries`; Tartiflette `query @a{__typename}` → `Unknow Directive < @a >.`
  Covers 40+ engines (Apollo, Graphene, Hasura, WPGraphQL, graphql-go, gqlgen, Strawberry,
  Hot Chocolate, Juniper, Tartiflette, Agoo, Lighthouse, …).
- **SAFETY (source-confirmed):** read-only, unauthenticated, benign. Probes use `__typename`/
  `__schema`/invalid-syntax to trigger error strings — **no mutations, no data, no harvest, no side
  effects.** Safe to run autonomously in the unattended lane.

### Why the engine name matters (graphql-threat-matrix mapping)
graphw00f's `ref` points to `nicholasaleks/graphql-threat-matrix`, which tracks per-engine
**insecure-by-default** posture across: validations count, field suggestions, query-depth limit,
query-cost analysis, persisted queries, introspection default, debug mode, batch requests.
Actionable defaults to encode in the ranker:
- **Introspection ON by default:** most engines (Apollo/Graphene/Hasura/graphql-go/ruby/…).
  graphql-php, graphql-yoga disable by default → if introspection is ON there, that's a config choice.
- **No depth limit by default:** graphql-go, graphql-ruby, graphene, Strawberry, Juniper, Tartiflette.
- **Field suggestions ON:** Apollo & most JS stacks (the Clairvoyance schema-recovery vector).
- **Weakest stacks:** Agoo, Lighthouse (1 validation rule), Tartiflette, Juniper.
→ Engine → expected weaknesses lets the lane predict which checks will likely fire before probing.

---

## TOOL 2 — graphql-cop (12-check auditor) — SAFETY-VETTED PER CHECK

- **Install:** venv + `pip install -r requirements.txt` (Python3 + requests). Run `python3 graphql-cop.py`.
- **Flags:** `-t URL` (path optional → else iterates common paths), `-o json` (JSON output),
  `-H '{"Authorization":"Bearer .."}'` (repeatable), `-e name1,name2` (exclude tests),
  `-l` (list tests), `-f` (force when GraphQL not detected), `-x PROXY`, `-w WORDLIST`, `-T` (Tor),
  `-d` (debug: tags each request with `X-GraphQL-Cop-Test` header — **useful: lets us audit/attribute
  our traffic**).
- **Output (JSON):** array of `{title, description, severity (HIGH/LOW/INFO), impact (DoS/
  Information Leakage/CSRF), result (bool), curl_verify}`.
- **Execution model:** ALL tests run; opt-OUT only via `-e`. **No built-in rate-limit/throttle.**
  HTTP (`lib/utils.py`): `graph_query()` POSTs JSON, `timeout=60`, `verify=False`,
  `allow_redirects=True`, batch mode = the SAME query repeated **10×**; `request()` `timeout=20`.

### SAFETY VERDICT — the headline (each test = ONE small probe, read-only):
Every "DoS" test is a **single small structure-probe that checks if a LIMIT exists**, NOT a
sustained flood. Every "CSRF/mutation" test uses **`__typename`** (a benign read-only field) —
**none send a real state-changing mutation.** All 12 are unauthenticated GET/POST reads.

| Test (name) | What it SENDS (exact) | Concludes | Load/risk |
|---|---|---|---|
| `introspection` | `query cop{__schema{types{name fields{name}}}}` | `data.__schema.types` present | benign read |
| `detect_graphiql` | GET, `Accept: text/html`, no body | HTML contains `GraphiQL`/`Playground`/`graphiql.min.css` | benign read |
| `field_suggestions` | `query cop{__schema{directive}}` (bad field) | error contains `Did you mean` | benign read |
| `trace_mode` | `query cop{__typename}` | resp has `extensions.tracing` | benign read |
| `unhandled_error` | `qwerty cop { abc }` (malformed) | resp has `extensions.exception` | benign read |
| `get_method_support` | GET `query cop{__typename}` | returns `data.__typename` | benign read (CSRF surface) |
| `get_based_mutation` | GET `mutation cop{__typename}` | returns `data.__typename` | benign — **fake mutation `__typename`, NO state change** |
| `post_based_csrf` | POST `application/x-www-form-urlencoded` `query=query cop{__typename}` | returns `data.__typename` | benign read (CSRF surface) |
| `alias_overloading` | ONE query, 101 aliases `alias0..alias100:__typename` | `data.alias100` present | **single ~101-field req** — small, one-shot |
| `batch_query` | `query cop{__typename}` sent **batched 10×** | response array `len>=10` | **10 ops in 1 req** — small, one-shot |
| `directive_overloading` | `query cop{__typename @aa@aa…@aa}` (10 dirs) | `len(errors)==10` | tiny, one-shot |
| `circular_query_introspection` | introspection nested 5× `fields→type→fields…` | `len(types)>25` | one moderate introspection req |
| ~~`field_duplication`~~ | **COMMENTED OUT** in `lib/tests/__init__.py` (issue #43) | — | not shipped |

**Aggressive-but-still-tiny:** `alias_overloading` (101 aliases) and `batch_query` (10×) and
`circular_query_introspection` are the only checks that send anything beyond a 1-field query — but
each is a **single request**, not a loop/flood. No brute force, no recursion bomb, no repeated
hammering. Acceptable for the anti-burn doctrine IF rate-limited at the orchestrator (graphql-cop
itself has no throttle) and run once per host with a cooldown.

**Run only-safe / quiet:** there is no "safe profile" flag. To minimise noise on no-scanner /
WAF-fronted programs, **`-e alias_overloading,batch_query,circular_query_introspection,
directive_overloading`** leaves the 8 truly-trivial read probes (introspection, graphiql, field
suggestions, trace, unhandled_error, get_method, get_based_mutation, post_based_csrf). Recommended
default for the unattended lane: run the 8 quiet ones autonomously; the 4 limit-probes only when
the program permits scanners and behind the rate-limiter.

**Anti-burn note:** `allow_redirects=True` + `verify=False` are baked in; `timeout=60`. Wrap calls
in our governor (min-gap + jitter, host cooldown on 429/403, Mullvad-only) — graphql-cop will NOT
self-throttle. On a CDN-fronted/no-scanner program, prefer graphw00f detection + a manual
introspection probe over the full cop battery.

---

## PART 3 — METHODOLOGY: introspection schema → RANKED human-test worklist

### What ELEVATES a GraphQL finding (info → payable) — the ranking spine
Introspection-enabled **alone is usually Info/Low** (on-by-default in Apollo/Graphene/Hasura/etc.,
so it's "by design" on many stacks — the #1 GraphQL FP/dup). It is a **schema-disclosure
multiplier**, not a finding. What elevates:
1. **Unauth access to a SENSITIVE mutation/query** — the money class. An unauthenticated or
   low-priv caller reaching a privileged op = broken access control / privilege escalation.
2. **IDOR/BOLA via object arguments** — `node(id:)`, `user(id:)`, `product(id:)`,
   `order(internalId:)` returning another principal's object. (PortSwigger's canonical example:
   `product(id:3)` returns a delisted item.) Disclosed: Snapchat `deleteStorySnaps` IDOR = $15k.
3. **Injection in arguments** — `filter`/`search`/`where`/`id`/`orderBy` args → SQLi / NoSQLi
   (resolvers often pass straight to a DB). Args are the injection surface; types tell you which.
4. **Auth bypass** — a mutation/query that mints/returns `token`/`role`/`password` fields, or a
   login/reset op callable without the expected auth.
5. **Batching → brute-force / rate-limit / 2FA bypass** — aliases or array-batching run N attempts
   in ONE HTTP request, defeating per-request throttles (OTP/login brute force).
6. **DoS via unbounded nesting** — only where depth/cost limits are absent (threat-matrix tells you
   which engines) AND the program pays DoS (most don't / it's risky — keep as LEAD, never auto-fire).

### Ranking signals to extract from an introspection dump (build the score)
- **Mutations first** (state-changing = highest risk; "modify data → mass-assignment / privesc").
  Boost by NAME: `create*`, `update*`, `delete*`, `reset*`/`*password*`, `*role*`/`*permission*`/
  `*admin*`/`grant*`, `invite*`, `*token*`/`*session*`, `pay*`/`transfer*`/`refund*`/`order*`,
  `impersonate*`, `setEmail`/`updateEmail`, `merge*`.
- **Queries returning PII/secrets** — output type/fields contain `email`, `phone`, `ssn`, `token`,
  `apiKey`, `secret`, `password`, `address`, `dob`, `balance`, `card`.
- **Object-reference args = IDOR candidates** — any field whose args include `id`/`*Id`/`uuid`/
  `slug`/`internalId`/`node(id:)`/`*Ref`/`*Key`. ID type drives harvestability: numeric=enumerable,
  UUID=needs-harvest (mirror the existing `recon_idor_candidates.py` scoring).
- **Injectable args** — `filter`, `search`, `query`, `where`, `orderBy`, `sort`, `q`, `like`,
  raw `String` args on list/search resolvers → XSS-of-the-backend (SQLi/NoSQLi) candidates.
- **Auth gate test** — re-run the high-value op list UNAUTHENTICATED: does it 401/403 (gated) or
  return data/`__typename` (exposed)? Exposed sensitive op unauth = the promote condition.
- **Engine prior** (from graphw00f) — weak-default engine (Agoo/Lighthouse/Tartiflette/Juniper) ⇒
  expect missing depth/cost limits + field suggestions; raise injection/DoS-candidate weight.

### When introspection is DISABLED (don't dead-end — research-mandate move)
- **Field-suggestion harvesting** (graphql-cop `field_suggestions` proves it's on; **Clairvoyance**
  reconstructs the schema from "Did you mean" errors). This is the unauth-safe schema-recovery path.
- **Introspection-filter bypasses** (PortSwigger): whitespace/newline after `__schema`, alternate
  HTTP method (GET), `x-www-form-urlencoded` body — regex filters often miss these.
- These keep the lane alive on hardened endpoints without ever mutating.

### SAFE confirmation primitives (autonomous) vs HUMAN-ONLY (operator)
- **AUTONOMOUS (read-only, unauth, safe):** `__typename` liveness probe; full/standard introspection
  query (if enabled); benign field-suggestion harvest; graphw00f fingerprint; the 8 quiet graphql-cop
  checks. These mint LEADs only — schema map + exposed-op surface.
- **HUMAN/OPERATOR-ONLY (hard line):** actual IDOR data access (swap to a 2nd OWNED object — never
  guessed/third-party IDs), ANY real mutation, injection confirmation that pulls data, batching
  brute-force, DoS. CONFIRMED requires a human with their own accounts — same discipline as
  `class-idor.md`. The lane SURFACES + RANKS; the operator exploits.

### Dup / FP angle — why GraphQL is the edge, and what makes it a dup
- **Less saturated than REST:** the crowd runs `subfinder|httpx|nuclei`; far fewer hunters
  introspect + reason over the schema graph. A ranked sensitive-unauth-op + arg-level IDOR worklist
  is exactly the MOTTO's "use Claude's understanding where commodity tools are blind."
- **What makes a GraphQL submission a DUP / N/A:**
  - "Introspection enabled" by itself (by-design on Apollo/Hasura/Graphene; near-certain Info/dup).
  - GraphiQL/Playground exposed alone (info, by-design on many dev stacks).
  - Field suggestions / verbose errors / trace mode alone (Low info; rarely paid solo).
  - Theoretical CSRF (GET/urlencoded accepted) WITHOUT a real state-changing op behind it.
  - "Batching supported" with no sensitive op to brute (the capability ≠ impact).
  - DoS (alias/depth) on a program that excludes DoS or behind a CDN that absorbs it.
  → Same trap as REST: a CONFIRMED primitive ≠ a payable bug. Only a **DEMONSTRATED** unauth
    sensitive-op call / IDOR data read / injection / auth bypass is reportable (impact-gate;
    see `feedback_theoretical_classes_get_declined`).
- **Dedup like the IDOR/param lanes:** product-class GraphQL (same schema/op fan-out across many
  hosts = shipped product) and shared-tenant consoles are dup-magnets / third-party-data — suppress
  by op fan-out, exactly like `tools/brief_filter.py` does for REST.

---

## Lane design (actionable summary for recon_graphql.sh / .py)
1. **Find** in-scope+paying GraphQL endpoints: ES (`recon_alive` tech/jsintel for `__schema`/
   `graphql`/`apollo`), jsintel endpoints, + graphw00f `-d` path wordlist on candidate hosts.
2. **Fingerprint** with graphw00f `-f` → engine + threat-matrix prior (expected weak defaults).
3. **Harvest introspection** if enabled (standard query); else field-suggestion/Clairvoyance +
   filter-bypass attempts. All read-only.
4. **Audit** with the 8 quiet graphql-cop checks (`-o json`, exclude the 4 limit-probes by default,
   under the rate-governor, Mullvad-only); the 4 DoS-limit probes only on scanner-OK programs.
5. **Rank** parsed schema → score mutations/PII-queries/IDOR-args/injectable-args/auth-gates
   (reuse `recon_idor_candidates.py` ID-type scoring) → `briefings/graphql_candidates_<date>.md`.
6. **Gate to LEAD**; CONFIRMED is operator-only (2 owned accounts; never third-party IDs;
   confirm-then-stop). Note every dismissal/FP/by-design inline.

## Sources
- graphw00f source: github.com/dolevf/graphw00f (`main.py`, `graphw00f/lib.py`, `helpers.py`) — read 2026-06-20.
- graphql-cop source: github.com/dolevf/graphql-cop (`graphql-cop.py`, `lib/utils.py`,
  `lib/tests/__init__.py` + all 12 `lib/tests/*.py`) — read 2026-06-20.
- graphql-threat-matrix: github.com/nicholasaleks/graphql-threat-matrix (graphw00f's `ref`).
- PortSwigger Web Security Academy — GraphQL (portswigger.net/web-security/graphql).
- YesWeHack — Hacking GraphQL endpoints in Bug Bounty Programs.
- dolevf "Black Hat GraphQL" (the author of both tools); HackerOne disclosures
  (Snapchat `deleteStorySnaps` IDOR $15k; auth-bypass-via-GraphQL blog).

## UNCONFIRMED / caveats
- graphw00f path-wordlist exact full list (21 entries) summarized from `helpers.py` — read
  the file before relying on a specific path being present; `-w` to be safe.
- graphql-cop `batch_query` batch size (10) is from `dos_batch` result-condition `len>=10` +
  utils "10 repeated operations"; confirm `BATCH_SZ` in `lib/utils.py` if exact count matters.
- "Black Hat GraphQL" specifics cited from author/tool provenance + secondary summaries, not a
  per-page read — treat chapter-level claims as UNCONFIRMED until the book is read directly.

## Implemented in this pipeline (recon_graphql.sh + recon_graphql.py, 2026-06-20)
Built NATIVELY (no graphw00f/graphql-cop dep — the value is reasoning over the schema graph, which
is requests+JSON). Lane: discover in-scope GraphQL endpoints (jsintel + ES url/title/tech, bounded
path-expansion) → scope+pays gate → read-only `{__typename}` liveness + standard introspection →
rank ops (sensitive mutations + IDOR object-ref args + injectable args + PII-returning queries via
the recon_idor_candidates.py scoring). **Introspection OFF → Clairvoyance-style field-suggestion
recovery** (`recon_graphql.py recover <url>`): sends GUARANTEED-INVALID 1-char near-miss field names
(`<candidate>z`) so a real field/mutation can NEVER validly execute, and harvests the engine's "did you
mean <real field>" error suggestions to reconstruct the op set (graphql-js suggestion threshold
≈floor(len*0.4)+1, so a 1-char-off probe stays in range; a longer nonce defeats it). Recovered fields
have names but no args → ranked by NAME (sensitive-op patterns). Bounded (GQL_SUGGEST_MAX≈140) + delayed;
early-bails if the first 12 probes yield no suggestions (engine has suggestions off too). Either path →
`briefings/graphql_candidates_<date>.md` + graphql_worklist.jsonl
+ ES stamp (graphql_endpoint/introspection/recovery/sensitive_ops) + 6:30 briefing. LEADs only — IDOR/injection/
auth-bypass confirmation is human (2 owned accounts). Sends NO mutations/auth/data-queries. Daemon 3h
loop (killswitch v2_graphql); `recon-graphql [scan|check <url>|results]`. graphw00f can enrich
fingerprinting on-demand if cloned, not required.


---
<!-- applied-proposal: 2026-06-20_tooling_class-graphql -->
### Applied research — tooling (2026-06-20)

## Hadrian — systematic BOLA/BFLA role-matrix testing (human-in-the-loop)

When our native schema recovery + `idor_candidates` ranking surfaces a GraphQL IDOR lead and 2 owned accounts are available, **Hadrian** (https://github.com/praetorian-inc/hadrian) can run the full role-pair BOLA matrix instead of hand-crafting curl chains.

**Setup:**
1. Define a YAML role config: role A (account 1 JWT), role B (account 2 JWT), object IDs owned by each.
2. Run against **staging** (never live prod — it sends mutations).
3. Hadrian's 13 GraphQL templates probe cross-role read/write/delete on every object-ref operation in the schema.

**Doctrine constraints:**
- NEVER autonomous: requires auth config + sends mutations = human-in-the-loop only
- Staging preferred; if live: confirm in-scope+pays, only own-account object IDs, confirm-then-stop
- Output is a cross-role violation matrix → operator confirms → report

**When to use:** schema recovered via `recon_graphql.sh` (introspection or clairvoyance-style field recovery) → sensitive object-ref mutation identified in `graphql_candidates_<date>.md` → 2 accounts available → operator runs Hadrian on staging.

**Not for autonomous pipeline.** Add to the 2IC's GraphQL IDOR SOP as the structured proof step.


---
<!-- applied-proposal: 2026-06-21_kb-enrich_class-graphql -->
### Applied research — kb-enrich (2026-06-21)

## GraphQL over WebSocket — hidden attack surface (added 2026-06-21)

### Why this matters
The graphql-ws transport (`wss://host/graphql-ws`, `wss://host/subscriptions`) is a SEPARATE
code-path from the HTTP `/graphql` endpoint. Authz middleware that protects the HTTP path may
not cover the WS upgrade handler. Keep-alive messages (`{"type":"ka"}`) signal a live WS connection
that may expose internal operations NOT visible in the standard HTTP introspection schema.

### Vulnerability 1 — Token-only-on-connect (subscription hijacking)
The graphql-ws protocol validates credentials once at `connection_init`. After that, the session
is live until the socket closes. Disclosed on Shopify: a user whose role was removed mid-session
retained the WS subscription and continued executing GraphQL operations until the connection dropped.

**Test (operator — authed):** log in as low-priv A, capture the WS `connection_init` payload,
downgrade the role server-side (via A's own admin if you have it, or wait for a session boundary),
then attempt a subscription/query that should now be unauthorized. If data flows = session not
revalidated.

**Fingerprint:** look for `{"type":"connection_init"}` / `{"type":"ka"}` in browser DevTools →
Network → WS frames. Protocol header: `Sec-WebSocket-Protocol: graphql-ws` or `graphql-transport-ws`.

### Vulnerability 2 — IDOR via hidden WS operations
Client-side JS often contains graphql-ws operation calls that never appear in introspection (they
skip the HTTP schema). Reverse-engineer `main.js` / `chunk.*.js` for `createClient`, `subscribe`,
or `execute` calls — these reveal operation names + variable shapes.

**Discovery (autonomous, safe):** JS-intel (`recon_jsintel.sh`) already collects `main.js`; grep
for `graphql-ws`, `createClient`, `subscribe(`, `SubscriptionClient`, WebSocket URLs containing
`/graphql`. Operation names found this way → add to the graphql_candidates worklist.

### Vulnerability 3 — IDOR→SQLi escalation chain (high-entropy ID bypass)
High-entropy IDs (UUIDs, 25-digit numeric strings) are NOT safe from IDOR if the endpoint also
has injection. April 2026 real chain (fintech):
1. GraphQL WS endpoint handles `readDocument(id:)` — IDOR exists but ID has 25-digit entropy.
2. Fuzz the `id` param with `'`, `||'|'||` (PostgreSQL concat), `"`, `1 AND 1=1` etc.
3. Verbose PostgreSQL error fires → error-based SQLi → column names / table names extracted.
4. Craft `id: "1||'|'||(SELECT id FROM documents LIMIT 1)||'|'||1"` → leaks real high-entropy IDs.
5. Feed leaked IDs back into the original IDOR endpoint → confirmed cross-user document read.

**Lesson:** "UUIDv4 / high-entropy ID = needs-harvest" is still valid for RANKING, but do NOT
write off an IDOR candidate purely because the ID has high entropy — check every adjacent op on
the same resource for injection. If SQLi fires on any path touching that object, the IDOR is
escalatable.

**Payload starters (error-based PostgreSQL via WS):**


---
<!-- applied-proposal: 2026-06-21_vulns_class-graphql -->
### Applied research — vulns (2026-06-21)

## GraphQL WebSocket (graphql-ws) — SQLi + IDOR Chain Technique

**Source:** [Medium — DarkyOS, April 2026](https://medium.com/@DarkyOS/sql-injection-in-graphql-websocket-escalated-to-pii-document-leak-09ba7ad2800a)

### Why graphql-ws is under-hunted
Most scanners and hunters probe `/graphql` only. WebSocket-upgrade endpoints (`/graphql-ws`, `/graphql/subscriptions`, `/subscriptions`) carrying GraphQL-over-WebSocket (the `graphql-ws` protocol) are routinely missed. Operations on these endpoints often lack the same authorization checks as their HTTP counterparts, and error handling is frequently more verbose.

### Attack chain pattern
1. `/graphql-ws` appears to send only keepalive frames (`{"type":"ka"}`) — looks dormant.
2. Client JS contains hidden operations (e.g. `readDocument`, `lockDocument`) that accept an `id` param.
3. Fuzzing the `id` field with alphanumeric/special chars triggers **verbose database errors** exposing schema details (column names, table names, DB engine).
4. Error-based SQLi (PostgreSQL `||` string concat / type-coercion) extracts actual user records including high-entropy IDs that protect IDOR.
5. Extracted IDs fed to the auth-blind WS operation → full IDOR / document access.

**Key insight:** Neither bug alone is exploitable (IDOR gated by high-entropy IDs; SQLi without IDOR is limited) — but chained, they yield a critical. The SQLi "unlocks" the IDOR.

### Detection / hunting steps
- Crawl/jsintel for: `/graphql-ws`, `/graphql/subscriptions`, `/subscriptions`, `/ws/graphql`
- Attempt WebSocket upgrade (`Connection: Upgrade`, `Upgrade: websocket`, `Sec-WebSocket-Protocol: graphql-ws`)
- Extract operations from client JS bundles (look for `graphql-ws` npm package usage, subscription queries)
- Fuzz `id`/`documentId`/`nodeId` params with: `'`, `"`, `1'`, `1 OR 1=1`, alphanumeric strings, special chars
- Watch response bodies for: PostgreSQL/MySQL/MSSQL error strings, column names, schema identifiers
- If SQLi fires → LEAD for human 2-account chain (never enumerate third-party IDs)

### FP notes
- A WS endpoint that only accepts valid UUID/numeric IDs and returns generic 400s = no SQLi surface
- Authorization checks at the WS layer (JWT validated per-message) = IDOR unlikely — still check SQLi
- Verbose errors in dev/staging but sanitized in prod = LEAD, not confirmed


---
<!-- applied-proposal: 2026-06-23_tooling_class-graphql -->
### Applied research — tooling (2026-06-23)

## Operator-side tooling addition (2026-06-23)

### InQL v6 (Burp Suite extension, Doyensec)
https://github.com/doyensec/inql

When `recon-graphql` produces a `graphql_candidates_<date>.md` briefing, load the harvested
introspection JSON into InQL in Burp. It auto-generates all possible queries/mutations from
the schema and organizes them for rapid iteration — cuts manual curl iteration substantially.

**Not a pipeline tool** — operator-side only for human-test evenings. Install in operator Burp;
load the introspection JSON from `recon_graphql.sh` output (the `.json` file it writes to
`~/recon/graphql/`).


---
<!-- applied-proposal: 2026-06-24_kb-enrich_class-graphql -->
### Applied research — kb-enrich (2026-06-24)

## New techniques (2024–2025)

### Introspection bypass via fragment obfuscation (CVE-2024-37155, 2024)
Beyond the existing whitespace / `\n` bypass (already in this doc), query fragments evade regex-based
block filters that look for `__schema` at the top-level query:

```graphql
query { ...schemaFrag }
fragment schemaFrag on Query { __schema { types { name fields { name } } } }


---
<!-- applied-proposal: 2026-06-25_vulns_class-graphql -->
### Applied research — vulns (2026-06-25)

## IDOR via Object-Type Argument Confusion ($12,500 payout, 2026)

Pattern validated in fresh disclosed report. The crowd stops at "introspection enabled" (Info dup). The edge:

1. Fetch introspection schema (unauth GET to `/graphql` or `/api/graphql`)
2. Identify mutations/queries with **ID-typed scalar args** on sensitive object types: `userId: ID!`, `accountId: ID!`, `orderId: ID!`, `documentId: ID!`
3. Reason: does the auth check gate on the session's identity or on the inner object's ownership? If the latter is absent → cross-account object access via ID swap
4. Surface as 2-account IDOR LEAD in briefing; confirm = human 2-owned-account swap (never guessed/enumerated third-party IDs)

**ES/jsintel signals:** `/graphql` or `/api/graphql` in endpoints.jsonl with POST method; `Content-Type: application/json` + `{"data":` in response fingerprint.

**Source:** https://infosecwriteups.com/graphql-security-how-i-found-and-exploited-critical-idor-and-authorization-bypass-in-a-42ab78e13642


---
<!-- applied-proposal: 2026-06-27_vulns_class-graphql -->
### Applied research — vulns (2026-06-27)

## GraphQL WebSocket Endpoint Blind Spot (added 2026-06-27)

Standard HTTP introspection probes and scanners target `/graphql` HTTP endpoints only. WebSocket-based GraphQL endpoints (`/graphql-ws`, `/subscriptions`, `/ws`) are hidden from them, carry the same resolver logic, and often lack WAF coverage. Find them via:
- JS-intel: search endpoints.jsonl for `graphql-ws`, `/subscriptions`, `/ws`
- `recon-kr` kiterunner: kitebuilder wordlist includes WS-adjacent paths

**Independent probing required:** Test object-ref arg ownership and type-mismatch inputs separately from the HTTP schema.

**Two-stage IDOR→SQLi chain (April 2026, $2k Critical):** An IDOR with high-entropy IDs (not bruteforceable alone) became critical when the same endpoint had a type-mismatch SQLi. Sending alphanumeric where numeric expected triggered verbose PostgreSQL errors leaking table/column names → error-based extraction of valid IDs → fed back into IDOR to access other orgs' documents. The injection point was the *ID type constraint*, not a string argument. Source: https://medium.com/@DarkyOS/sql-injection-in-graphql-websocket-escalated-to-pii-document-leak-09ba7ad2800a

## GraphQL Batch Query Abuse for IDOR Rate-Limit Bypass (added 2026-06-27)

GraphQL batching (POST body as a JSON array: `[{"query":"..."},{"query":"..."}]`) is supported by Apollo, Hasura, and most frameworks by default. Per-request rate limits don't apply per operation in a batch — use this when object-ownership IDOR exists but per-request throttling would prevent enumeration. 

Test: POST `[{operationName:null, query:"{ sensitiveQuery(id: 1) { ... } }"}, ...]` — if the server returns an array of results, batching is enabled.

Paid $12,500 CVSS 9.1 on a fintech GraphQL API (April 2026). Source: https://infosecwriteups.com/graphql-security-how-i-found-and-exploited-critical-idor-and-authorization-bypass-in-a-42ab78e13642


---
<!-- applied-proposal: 2026-07-01_tooling_class-graphql -->
### Applied research — tooling (2026-07-01)

## Tool additions (2026-07-01)

### graphql-cop — automated multi-check CLI
- GitHub: https://github.com/dolevf/graphql-cop | v1.16 Nov 2025
- Runs 12 checks in one call: introspection, **field suggestions** (clairvoyance-style near-miss probes), alias overloading, batch queries, GET-based queries, directive overloading, CSRF vectors
- Add to `recon_graphql.sh` after the introspection gate:
  ```
  graphql-cop -t https://<host>/graphql -o json
  ```
- Field suggestions check automates the manual "guaranteed-invalid 1-char near-miss probe" step; keep Clairvoyance for deep schema reconstruction when introspection is off.

### Clairvoyance — deep schema reconstruction (introspection-off targets)
- GitHub: https://github.com/nikitastupin/clairvoyance | v2.5.5 Dec 2025
- Use when introspection is disabled — iterates near-miss probes to reconstruct the full schema from field suggestions
- JSON schema output suitable for GraphQL Voyager or direct worklist generation
- If `recon_graphql.sh` hand-rolls the field-suggestion loop, replace that section with clairvoyance

### GraphQLer — operator-triggered deep mode only
- GitHub: https://github.com/omar2535/GraphQLer | v2.3.8 Mar 2026
- Dependency-graph fuzzer: chains queries based on schema, surfaces IDOR via object-ref args
- GATE: `--disable-mutations` required; operator-triggered only (not autonomous daemon). Sends real queries.
