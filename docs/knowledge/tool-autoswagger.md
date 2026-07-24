# tool-autoswagger — unauth Swagger/OpenAPI BOLA / broken-authz scanner

> Reusable KB for the Autoswagger tool + the `recon_autoswagger.sh` lane that wraps it.
> ADOPT'd 2026-07-18 (`docs/research/tooling_2026-07-18.md`). READ before working the lane;
> APPEND when the tool's CLI/output shape changes (young project — interface is still moving).

## What it is
**Autoswagger** (intruder-io/autoswagger, free OSS, from Intruder) is a broken-authorization
scanner for Swagger/OpenAPI-documented REST APIs. It:
1. **Discovers the spec** — direct `.json`/`.yaml`, Swagger-UI pages, and brute-force of common
   locations (`/swagger.json`, `/openapi.json`, `/v2/api-docs`, `/v3/api-docs`, `/api-docs`,
   `/swagger/v1/swagger.json`, …).
2. **Walks every documented endpoint UNAUTHENTICATED, GET-only by default** — a 200 on an endpoint
   that should require auth is the broken-authz signal.
3. **Screens the responses** — PII via Presidio, secrets via regex, plus oversized/"interesting"
   payloads. This is the response-screening we otherwise do by hand.

The `-risk` flag adds mutating methods (POST/PUT/DELETE). **We NEVER enable that autonomously** — it
breaks the safe-probe doctrine (unauth, non-mutating, no creds).

## Why we adopted it (and how it fits the pillars)
It's the REST/Swagger analogue of two things we already do: `recon-kr` (kiterunner finds routes on
bare API gateways) and native GraphQL schema-reasoning (`recon_graphql.sh` reads the schema and
reasons over what shouldn't be reachable unauth). Autoswagger is the same idea — *read the spec,
reason over what shouldn't answer unauth* — for OpenAPI, and it ships the PII/secret response-
screening we currently do by hand. A `200 + PII/secrets without auth` is a provenance-confirmed
candidate at exactly our IDOR/BAC LEAD tier (same rigor as `recon_idor_candidates.py`). It is NOT a
new capability that mints CONFIRMED on its own — anything beyond "this endpoint answers unauth"
(real cross-object IDOR/BOLA) is Claude VERIFY + a human 2-owned-account swap.

Related tools from the same digest: **Hadrian** (EVALUATE — role-based BOLA/BFLA, but authed +
mutating → human-in-the-loop only, never autonomous; see `class-graphql.md`); **graphql-scanner**
(SKIP — subset of `recon_graphql.sh`). Autoswagger is the one wired as an autonomous-safe lane.

## Install (OPERATOR — the lane never installs it)
The lane (`recon_autoswagger.sh`) DETECTS the binary and NO-OPs gracefully (logs a hint, exits 0) if
it's absent, so it can ship dormant. To activate:
```
pipx install git+https://github.com/intruder-io/autoswagger.git
# or:
git clone https://github.com/intruder-io/autoswagger && cd autoswagger && pip install -r requirements.txt
```
(Python — under WSL: `wsl.exe -d kali-linux -- pipx install …`; the engine runs on WSL python3.)
Then put `autoswagger` on PATH or set `AS_BIN=/path/to/autoswagger`. Verify: `recon_autoswagger.sh check <host>`.

## How the lane uses it (`recon_autoswagger.sh`)
- **Discover candidates** — jsintel endpoints referencing `swagger|openapi|api-docs` + ES `recon_alive`
  in-scope hosts whose url/title/tech signal a spec (benched hosts excluded via `ignore_expires_at`).
- **Gate** — `recon_scope_check.sh --filter in-scope-paying` (per-asset pays, not program-level);
  7-day per-host cooldown; killswitch `state/kill/v2_autoswagger`; `vpn_down` fail-closed; Mullvad via
  the daemon's `run_scanner` wrapper.
- **Run** — `autoswagger -u https://<host> --format json`, GET-only, `AS_TIMEOUT`-bounded, **never
  `-risk`**. Output is parsed DEFENSIVELY (the project is young; array shape may drift — the lane never
  fabricates, it skips unparseable output).
- **Route** — each unauth-reachable documented endpoint → `autoswagger_worklist.jsonl` +
  `briefings/autoswagger_candidates_<date>.md` (ranked secrets>PII>count) + appended to the jsintel
  endpoints feedstock (`js_recon/endpoints.jsonl`, `source:"autoswagger"`) so the IDOR/BAC ranker and
  the 2IC consume it + ES stamp (`swagger_spec`, `swagger_unauth_endpoints`) + a host_note.
- **On-demand** — `recon_autoswagger.sh check <host>` (single host), `results [N]` (recent hits).

## Confirmed-vs-LEAD + FP notes
- **A documented endpoint answering 200 unauth = LEAD**, not a finding on its own. Some APIs
  legitimately expose public GET endpoints (health, catalog, docs) — the value is a 200 that returns
  PII/secrets or an object that should be owner-scoped.
- **CONFIRMED requires the 2-account BOLA swap** (read your own 2nd-account object via an ID swap;
  never a guessed/enumerated third-party ID — hard line). Autoswagger surfaces + screens; the operator
  confirms.
- **FP guards:** by-design public endpoints; a "PII" hit that is your own submitted data or synthetic
  demo data; a 200 that is an SPA index/catch-all rather than real API data (probe content-type). Screen
  the same way as the bucket/GraphQL lanes — the tool flags, Claude/human adjudicates.
- **Never enable `-risk`** (mutating methods) in the autonomous lane — that leaves the safe-probe
  envelope entirely.

## Sources
- Autoswagger — https://github.com/intruder-io/autoswagger
- Intruder research — https://www.intruder.io/research/broken-authorization-apis-autoswagger
- Help Net Security coverage — https://www.helpnetsecurity.com/2025/07/24/autoswagger-open-source-tool-expose-hidden-api-authorization-flaws/
- `docs/research/tooling_2026-07-18.md` (the ADOPT verdict); `class-graphql.md` (Hadrian EVALUATE note).
