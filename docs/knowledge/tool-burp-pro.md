# tool-burp-pro — using Burp Suite Pro fully (read/drive it, beat token rotation, hunt authz/IDOR)

Reference for the operator + assistant. Compiled 2026-07-11 from PortSwigger docs + reputable sources
(web research only). Governing rule for everything below: **IDOR/BOLA testing uses TWO accounts YOU OWN —
replay your own object IDs across your own sessions; never enumerate/guess/access a real third party's IDs
or data. Confirm the access-control break, then STOP — no harvest.** (ties to CLAUDE.md hard line,
[[feedback_authed_idor_burp_flow]], [[feedback_dont_obstruct_authorized_testing]].)

Our environment: **Burp Pro runs on the WINDOWS side** — proxy `127.0.0.1:8080` (replay via `curl -x`),
REST API `127.0.0.1:1337` (key `~/.recon_burp_key`), and now MCP `127.0.0.1:9876`. See
[[reference_burp_pro_interface]], [[feedback_work_from_burp]], [[feedback_burp_locked_flow]].

---

## 0. THE FIX FOR "read from Burp" — the official MCP Server (do this once)

Today's whole ordeal (couldn't read captured proxy history, resorted to cookie-paste + curl guessing) is
solved by PortSwigger's official **MCP Server** BApp. Installed + wired to Claude Code, the assistant gets
first-class tools to read history and drive Burp directly.

**Install:** Burp → Extensions → BApp Store → "**MCP Server**" (Daniel S / Daniel Allen, PortSwigger) →
Install. Open the new **MCP tab** → **Enable** (binds `http://127.0.0.1:9876`, SSE at `/sse`). Set the
**target-approval** list to **auto-approve ONLY in-scope+paying hosts** (it exposes session cookies to the
AI client — keep it deliberate). Do NOT install "MCP Server **Scanner**" for this — that's an unrelated
OFFENSIVE tool that audits MCP servers as targets (useful only if we ever hunt an app exposing its own MCP).

**MCP tools it exposes** (from `Tools.kt`):
- **Read history (the point):** `get_proxy_http_history`, `get_proxy_http_history_regex`,
  `get_proxy_websocket_history`, `get_proxy_websocket_history_regex`
- **Replay/send:** `send_http1_request`, `send_http2_request` (returns response)
- **Repeater/Intruder:** `create_repeater_tab`, `create_repeater_tab_http2`, `send_to_intruder`
- **Scanner (Pro):** `get_scanner_issues` · **Collaborator (Pro):** `generate_collaborator_payload`,
  `get_collaborator_interactions`
- **Organizer:** `get_organizer_items`, `get_organizer_items_regex`
- **Config/scope (JSON):** `output_project_options`/`output_user_options`/`set_project_options`/`set_user_options`
  (scope is edited via options JSON — no dedicated scope tool)
- **Control:** `set_task_execution_engine_state`, `set_proxy_intercept_state` ·
  **Editor:** `get/set_active_editor_contents` · **Utils:** url/base64 encode-decode, random string

  There is **no start-scan or sitemap tool** in MCP — active scans stay on the REST API (§1).

**Connect to Claude Code** (Claude Code speaks stdio; the extension serves SSE → bridge with the packaged
`mcp-proxy-all.jar`). The MCP tab's **installer button** drops the jar + writes a Claude Desktop config;
we reuse that jar for Claude Code:
```
claude mcp add burp-mcp -- java -jar <path-to>/mcp-proxy-all.jar --sse-url http://127.0.0.1:9876
```
or `.mcp.json` in the project dir:
```json
{ "mcpServers": { "burp-mcp": { "command": "java",
  "args": ["-jar","<path-to>/mcp-proxy-all.jar","--sse-url","http://127.0.0.1:9876"] } } }
```
**Windows caveat:** Burp is on Windows, so the jar + Java must run where they reach `127.0.0.1:9876`
(Windows side), or port-forward 9876 into WSL. Takes effect on the **next Claude Code start** (MCP loads at
launch — can't hot-add to a live session). Build the jar if needed: `git clone
https://github.com/PortSwigger/mcp-server && cd mcp-server && ./gradlew embedProxyJar`
(→ `libs/mcp-proxy-all.jar`; needs JDK).

Once live, today's task = one call: `get_proxy_http_history_regex "/recruiting/api"` → grab the request →
`send_http1_request` with B's session. No cookie-paste, no curl, no screenshots.

---

## 1. Other programmatic access (complementary to MCP)

- **REST API (`:1337`, key `~/.recon_burp_key`)** — **scan-only**: `POST /v0.1/scan` (urls + include/exclude
  scope + optional creds) starts an active scan; `GET /v0.1/scan/<id>` returns status + issues. **No proxy-
  history read.** Self-docs at `http://127.0.0.1:1337/<key>/v0.1/`. Use it to launch scans; use MCP to read/replay.
- **Logger++ (BApp)** — best non-MCP way to make Burp traffic queryable: replaces history with advanced
  filter/grep, exports every tool's traffic to CSV/JSON or **straight to Elasticsearch** (auto-upload). Since we
  already run ES, Logger++→ES is a solid fallback ("assistant reads Burp traffic from `recon_alive`-adjacent index").
- **curl through Burp (`curl -x 127.0.0.1:8080 -k`)** — our proven driver: routes assistant requests THROUGH
  Burp so they're captured + get Proxy match/replace (incl. the `X-Intigriti-Username` stamp). Run in **Git Bash
  (Bash tool WITHOUT `wsl.exe`)** so `127.0.0.1` = Windows Burp; `MSYS_NO_PATHCONV=1`. Drives but doesn't read —
  pair with MCP `get_proxy_http_history_regex` (or Logger++) for the read side. Fresh cookies held across ~6
  sequential GETs; get them from a recent Burp request (they rotate). See [[feedback_work_from_burp]].
- **Montoya API extensions** / **Save items** (Proxy history → select → Save items = Burp XML) / `.burp` project
  files — lower-level read/persist options.

**Burp AI (2025, PortSwigger's own hosted AI — separate from Claude):** *Explore issue with AI* (auto-investigates
scanner findings), **Shadow Repeater** (watches your manual Repeater edits, AI-mutates payloads, reports to
Organizer — the most useful for IDOR/BAC manual sessions), *AI-recorded logins*, *Explain this*. Costs AI credits
(~400–1000 per Explore run; Pro got ~10k free). It's an in-Burp assistant; it does NOT give Claude access — MCP (§0) is our path.

---

## 2. Auth & session automation — BEATING TOKEN ROTATION (our live Personio blocker)

Personio rotates `ATHENA_SESSION` on nearly every request, so a captured request replayed later in Repeater
401s (stale/spent token) and clears the session. **Fix = a macro that fetches a fresh token + a session-handling
rule that runs it before each Repeater/Intruder request and injects the fresh token.** Canonical anti-CSRF recipe:

**A. Macro (fetch fresh token)** — `Settings → Sessions → Macros → Add`. With Proxy intercept OFF, pick the
request whose RESPONSE carries a fresh token (the page/endpoint that issues it). In the Macro Editor →
**Configure item**: rotating params → **Derive from prior response**; static → preset. If the token lives in a
JS string / JSON body / custom header (our XSRF/session case), use **Custom parameter locations → Add** with a
regex/delimiter **extraction rule**. **Test macro** to confirm extraction.

**B. Session handling rule** — `Settings → Sessions → Session handling rules → Add`.
- **Details → Rule actions → Add → "Run a macro"** (select the macro). Optionally add **"Set a specific cookie/
  parameter value"** (or **"Set a specific header value"** for header tokens) to write the derived token into the
  outgoing request; add **"Use cookies from the session handling cookie jar"** if a session cookie also rotates.
- **Scope tab:** URL scope = target host (tight); **Tools scope = Repeater + Intruder** (+ Scanner if scanning).
- Now each Repeater send re-runs the macro → fresh token → no more 401. Repeater shows the final injected request.
- Debug with the **Sessions tracer** (`Settings → Sessions`) — shows which rule fired + what was substituted.
- **ANTI-BURN:** every Repeater send now fires the macro's extra request(s) at the target — keep the macro to ONE
  request, scope tightly, respect 429/403, or we get the Mullvad exit banned ([[feedback_403bypasser_waf_ban]]).

**Cookie jar** (`Settings → Sessions → Cookie jar`): choose which tools UPDATE it (enable Repeater/Proxy);
a rule with "Use cookies from the cookie jar" makes Repeater follow rotated `Set-Cookie` automatically.

**Mandatory attribution header on ALL tools:** Proxy **match/replace is Proxy-traffic ONLY** (misses
Repeater/Intruder). For `X-Intigriti-Username` on every tool, use a **session-handling rule → "Set a specific
header value" (add if absent)**, scope = Proxy+Repeater+Intruder+Scanner. (Our `curl -x :8080` goes through Proxy
so it's already covered; this hardens Repeater/Intruder.)

**Recorded login sequences** (Scanner auth, not Repeater): `Dashboard → New scan → Application login → Recorded
login sequences` — replays browser actions to authenticate (SSO/multi-step/MFA); AI can auto-record; keeps
authed scans logged in via session-validity checks.

---

## 3. Core tools (quick map)

- **Proxy** — intercepting HTTP/S + WS proxy; **HTTP history** is the primary hunting ground (right-click → Send
  to Repeater/Intruder/Organizer/Comparer); **WebSockets history**; **Match & Replace** (Proxy-only rewrites);
  response interception; use Burp's embedded browser (cert pre-trusted).
- **Target** — **Site map** (discovered surface), **Scope** (set FIRST; "show only in-scope"), **Issue definitions**.
- **Repeater** — manual edit+resend workbench; tabs/groups/colors; **Send group** = parallel (race conditions,
  HTTP/2 single-packet) or single-connection sequence (desync/timing); **Shadow Repeater** AI layer → Organizer.
- **Intruder** — fuzzer/enumerator. Attack types: **Sniper** (1 set, one position at a time), **Battering ram**
  (1 set, all positions same), **Pitchfork** (N sets, lockstep pairs), **Cluster bomb** (N sets, all combos).
  Payload processing + grep-match/grep-extract; resource-pool throttling. **IDOR ethics: only enumerate IDs you
  OWN** — for authz prefer Autorize/Auth Analyzer over blind enumeration.
- **Scanner** — passive (safe, always-on) vs active (intrusive, in-scope+authorized only); crawl; scan configs;
  live scanning. (Start via REST `:1337` for automation.)
- **Collaborator (OAST)** — the confirm for blind/OOB (SSRF/blind-XSS/OOB-SQLi/XXE): insert payload (Repeater
  right-click / Intruder / Collaborator tab), poll for DNS/HTTP/SMTP hits. Callback = confirmed; none ≠ absence.
- **Sequencer** — token randomness/entropy analysis (session/CSRF/reset tokens).
- **Comparer** — word/byte diff of two items (authorized vs unauthorized response; `'` vs `''` SQLi differential).
- **Decoder** — manual encode/decode/hash (Hackvertor is the extension-grade successor).
- **Logger** — unified log of EVERY request across ALL tools (searchable, Bambda-filterable).
- **Organizer** — stash read-only copies of interesting requests (Ctrl+O), notes/status/collections, CSV export;
  Shadow Repeater drops findings here.
- **Bambda mode** — small **Java** snippets for custom filters/highlights/columns in history/Logger/Organizer.
  Return `true` to keep a row. Examples:
  ```java
  return requestResponse.request().isInScope();                       // in-scope only
  return requestResponse.request().hasHeader("Authorization");        // authz hunting
  return requestResponse.request().parameters().stream()             // numeric object-ref = IDOR candidate
      .anyMatch(p -> p.name().matches("(?i)id|uid|user_id|account|order") && p.value().matches("\\d+"));
  ```
- **Extensions / BApp Store** — Extensions → BApp Store (one-click, auto-update). Montoya API (modern). Some need
  Jython (Py2.7) / JRuby configured. Many top BApps run in Community too, but Scanner/Collaborator/Intruder-speed
  need Pro.

---

## 4. Best extensions for authz / IDOR / BOLA

- **Autorize** ⭐ — set another (owned) account's cookie; it silently **replays every request you make** in that
  session and flags **Bypassed! / Enforced! / Undetermined** by response-diff. THE cross-tenant IDOR workhorse:
  browse as A, it replays as B → instant map of where B reaches A's data. Supports multiple low-priv sessions.
- **Auth Analyzer** ⭐ — like Autorize with more control: multiple roles/sessions, auto extract+replace dynamic
  values (CSRF/session tokens) per request, per-request status colors. Best when tokens rotate (our case) or for
  vertical+horizontal privesc.
- **AuthMatrix** — roles × requests grid with expected allow/deny per cell; validate the whole RBAC matrix at once.
- **Autorize/Authz** (lightweight), **Param Miner** (hidden params/headers + cache-poison inputs → surface hidden
  object-refs), **Turbo Intruder** (Python-scripted, ultra-fast; race conditions, CSRF-chaining, owned-ID volume),
  **Logger++** (filter/grep/export authz replays), **JSON Web Tokens** (flip your own `sub`/`role`/tenant claims),
  **InQL** (GraphQL schema→queries, per-resolver BOLA), **Hackvertor** (inline encode/transform/WAF-bypass),
  **Collaborator Everywhere** (passive OOB net), **Backslash Powered Scanner** (novel injection classes).

**Cross-tenant IDOR = Autorize/Auth Analyzer**: auto-replay in a 2nd owned session + identical response = broken
authorization. Faster and cleaner than manual Intruder enumeration.

---

## 5. Cross-tenant IDOR/BOLA workflow (owned accounts only)

Precondition: host in-scope+pays, authorized, TWO owned accounts A & B (never a real third party's ID).
1. Provision A & B (distinct email aliases); seed known objects in each; record A's IDs.
2. Set **Scope**; "show only in-scope."
3. Log in as **A** through Burp; exercise the app fully (traffic → history/site map).
4. Log in as **B** separately; copy B's session token(s) (Cookie / `Authorization` / custom header).
5. Configure **Autorize** (paste B's headers, toggle on; optionally "check unauthenticated") or **Auth Analyzer**
   (session "B" + auto extract/replace for rotating tokens).
6. Browse as A → extension replays as B → diffs responses → labels rows: **Bypassed! (identical) = IDOR/BOLA**,
   **Enforced!** = ok, **Undetermined** = review with **Comparer**.
7. Confirm in **Repeater**: swap B's session, resend, verify B reads **A's owned object**; diff with Comparer =
   the PoC. (For rotating tokens, drive this with the §2 macro rule so replays don't 401.)
8. Cover both directions + roles (horizontal + vertical), other verbs (PUT/DELETE), GraphQL (InQL), JWT claim
   swaps — always on your OWN identifiers.
9. Scope down noise (Bambda/Logger++ filters), throttle (resource pools), back off on 429/403.
10. Document: send to Organizer; capture the minimal redacted request/response proving the authz break. Report
    the FAILURE — do not enumerate/exfiltrate real users' data to "prove scale."

**Hard lines:** two owned accounts; swap only owned IDs; confirm-then-stop; no destructive writes on data you
don't own. (CLAUDE.md recon-vs-attack line.)

---

## 6. Our setup checklist (do once, then Burp is fully wired for us)
1. **MCP Server** BApp installed + enabled (`:9876`), target-approval = in-scope+paying only; `claude mcp add
   burp-mcp …` wired (§0) → assistant reads history + drives Repeater next session.
2. **Session-handling macro rule** for rotating tokens (§2) scoped to Repeater/Intruder → Personio replays stop 401ing.
3. **Session-handling header rule** for `X-Intigriti-Username` across all tools (§2).
4. **Autorize** (or Auth Analyzer) installed for the 2-account cross-tenant matrix (§4–5).
5. Keep **REST :1337** for scans; optional **Logger++→ES** to query Burp traffic alongside `recon_alive`.
6. Optional: **Shadow Repeater** on during manual 2-account IDOR sessions.
Anti-burn always: Mullvad egress, respect rate limits, no scanners on no-scanner programs.
