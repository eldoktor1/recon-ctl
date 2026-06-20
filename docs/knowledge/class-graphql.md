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
the recon_idor_candidates.py scoring) → `briefings/graphql_candidates_<date>.md` + graphql_worklist.jsonl
+ ES stamp (graphql_endpoint/introspection/sensitive_ops) + 6:30 briefing. LEADs only — IDOR/injection/
auth-bypass confirmation is human (2 owned accounts). Sends NO mutations/auth/data-queries. Daemon 3h
loop (killswitch v2_graphql); `recon-graphql [scan|check <url>|results]`. graphw00f can enrich
fingerprinting on-demand if cloned, not required.
