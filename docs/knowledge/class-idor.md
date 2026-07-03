# class-idor — IDOR / BOLA hunting (reusable knowledge)

OWASP API #1 (BOLA), the #1 paid class, the one automation can't confirm — so surface, rank, human-test
with 2 OWNED accounts. Hard line: swap ONLY your own object ids, confirm-then-stop, never enumerate
third-party ids.

## The test (2-account swap)
1. Sign up / obtain accounts **A** and **B** you own.
2. As A, capture every request carrying an object-reference param (id in path/query/body/header).
3. Replay A's request with **B's session** but **A's id** (and vice-versa).
4. **200 + the *other* account's data** = horizontal IDOR. 200 + admin-only action as low-priv = vertical BAC.
5. PoC = ONE redacted record proving cross-account read; never bulk-dump.

## Burp = Burp PRO (the standard, 2026-06-21)
All Burp-assisted testing uses **Burp Suite Professional on Windows** (proxy `127.0.0.1:8080`, egress
Mullvad-verified; the Kali Community Burp-in-WSL is deprecated — fallback only for VPN-only-in-WSL scope).
Driven Windows-side: operator's browser → Burp proxy; Claude → proxy (`-x http://127.0.0.1:8080 -k`) + the
Pro **REST API** (`http://127.0.0.1:1337/<key>/v0.1/`, key local in `~/.recon_burp_key`, exposes `/scan` +
`/configuration`). Pro unlocks Scanner + Intruder + Collaborator + Autorize. Active Scanner = ON-DEMAND only,
in-scope+PAYING, Burp-scope-restricted, anti-burn, never autonomous. Full setup: memory [[feedback_burp_locked_flow]].

## Autorize (Burp extension) — the access-control AUTO-tester (owned accounts only)
Autorize (Barak Tawily; BApp Store) turns the manual A/B swap into an automatic per-request verdict — the
fastest way to test access control across the WHOLE authed surface. It belongs in the locked Burp flow
([[feedback_authed_idor_burp_flow]] / [[feedback_burp_locked_flow]]) as the auto-tester once both owned
sessions are captured.
- **How it works:** you browse/drive as the HIGH-priv account **A** (manually or via CinC); Autorize silently
  re-sends each of A's requests with the LOW-priv account **B**'s session (cookies/headers you paste into its
  config), and also with NO auth, then compares responses → per request it shows **Bypassed!** (red — B got A's
  data = IDOR/BAC), **Enforced** (green — 403/empty), or **Is enforced??? (please configure)** (amber — manual
  check). Instant access-control matrix instead of swapping each request by hand.
- **Setup:** Burp → Extensions → BApp Store → Autorize. Paste B's session (Cookie / Authorization headers) into
  Autorize's "modify headers". Set an enforcement-detector (content-length/string that proves a real 403 vs a
  200 SPA shell). Scope-filter to the in-scope host. Toggle ON, then drive A's traffic. Burp-in-WSL shares tun0
  (Mullvad) per the locked flow.
- **HARD LINE (owned accounts only):** A and B are BOTH yours. Autorize replays A's traffic with YOUR B session —
  never a guessed/third-party id. It only proves "my B can reach my A's object," the valid IDOR PoC.
- **SAFETY — it replays EVERYTHING, including writes:** Autorize re-sends state-changing requests (POST/PUT/
  DELETE) with B too. Before enabling on a surface with mutations, exclude unsafe methods (Autorize "Interception
  filters" → skip POST/PUT/DELETE, or use the request filter) or run read-only browsing — otherwise it can fire
  writes as B. Confirm-then-stop; verify the LOADED object data, not a success banner (see the switcher FP below).
- Verdict still HUMAN-judged: a red "Bypassed!" on a 200 SPA-shell / me-scoped endpoint is a FP — confirm the
  body is actually A's distinct data (same discipline as the FP patterns below).

## Where the id hides (don't only look at the query string)
- Path segment (`/invoices/12345`), query (`?id=`/`?contractId=`), JSON body, custom header
  (`X-Account-Id`), GraphQL arg (`order(id:)`/`node(id:)`), referer, cookie-encoded id, base64/UUID blob.
- **ID type → enumerability:** numeric=enumerable; short/sequential=trivially enumerable;
  UUIDv4=not guessable (need a leak vector — referrer/postMessage/continueUrl/window.name).
- Action-level BAC: an id-less endpoint that *acts on the current account* (`/v1/account/change-primary-org`)
  may still be reachable by a role that shouldn't have it → vertical privesc without an id swap.

## FP / non-finding patterns (don't overclaim)
- me-scoped APIs (no id to swap; server derives the account from the session) = BOLA-clean.
- tenant-isolation enforced (visibilityTree / RLS / company-scoped query) → read+write both 403 = not vuln.
- UUIDv4 with no leak vector = "needs a known id" → known-issue / informative / DUP risk (e.g. Topper orderById).
- transaction/object metadata disclosure "without proven impact" = often a documented Known Issue → DUP.
- **switcher endpoints (switch-account / switch-contract / set-contact) that only operate over ids already
  in YOUR OWN switcher list = server-side validated = NOT IDOR.** Verify the actual LOADED object data, not
  a success message: a generic "you switched user" banner can fire even when the cross-account switch was
  silently rejected (proven on ENGIE greybox — `set-contact` showed "Vous avez bien changé d'utilisateur"
  but bounced back to the caller's OWN picker; the banner is misleading). Cross-account → reject/interstitial
  /500 = authz enforced. Also: a big contract/object count on a test account is usually **seed-loaded own
  data**, not a leak — confirm ownership before claiming.

## ENGIE espace-client (French B2C energy portal) — object refs to swap
Researched 2026-06-18 (jechange/selectra/engie.fr). Pre-prod `espace-client-pprod.pro.engie.fr` (DCP greybox).
- **factureId / invoiceId** — invoice (financial PII). TOP priority. PDF download endpoint = clean PoC.
- **PDL** (Point De Livraison) — 14-digit electricity delivery-point id; **enumerable**.
- **PCE** (Point de Comptage et d'Estimation) — 14-digit gas delivery-point id; **enumerable**.
- **contractId / contratId** — 9–10 digit customer/supply-contract reference; **enumerable**.
- **releveId** — meter reading (consumption/metering point, tied to an address).
- **documentId** — downloadable account docs / attestations.
- **paymentId / SEPA mandate id / échéancier** — payment method object (read-only swap; NEVER move money).
- **demandeId** — service request / move (emménagement-déménagement), order-like object.
French energy IDs (PDL/PCE 14-digit, contract 9-10 digit) are short+numeric = the enumerable kind → a
confirmed cross-account read on one is high-severity. SKIP (OOS/not paid): email+password-change, the
"Votre avis?" survey; prod `particuliers.engie.fr` is OOS (pre-prod only).

**RESULT (2026-06-20, 2 owned EC-pool accts):** the read-path **switchers are object-authz VALIDATED, NOT
IDOR** — `switch-contract?idContract=` loads only your own switcher's contracts; `set-contact?idContract=`
bounces cross-account to your own picker; `GET /switch-contract/info` returns 200 for own / 500 for another
account's id. The 278 contracts on account A = A's own seed-loaded multi-site account, not a leak.
`recuperer-entite` is NOT on the greybox host (Drupal 404) — it's DGP-prod only (see host_notes for
`particuliers.engie.fr`). Read-path IDOR lane closed; the live lead is the **contact-ADD write path**
(does the POST carry a manipulable `id_entreprise`/account field → add self to a victim account = BAC) +
name-field stored-XSS — reachable only from the MAIN/entreprise account. Access architecture + full details
in `host_notes.jsonl` (`espace-client-pprod.pro.engie.fr`).

## Sources
- https://particuliers.engie.fr/electricite/conseils-electricite/conseils-contrat-electricite/numero-PCE-PDL.html
- https://www.jechange.fr/energie/electricite/pdl
- https://portswigger.net/web-security/access-control/idor
- https://medium.com/@jpablo13/bola-idor-critical-api-authorization-flaw-bug-bounty-detection-3203133a5040


---
<!-- applied-proposal: 2026-06-21_kb-enrich_class-idor -->
### Applied research — kb-enrich (2026-06-21)

## Authorization bypass techniques — new section (added 2026-06-21)

These patterns are NOT the "where the id hides" surface enumeration already in this doc — they
are AUTHZ BYPASS TRICKS: ways to get the server to skip the ownership check even after the id
is found.

### 1. Outdated API version
`/v2/invoices/123` → 403; `/v1/invoices/123` → 200 with data. Authz enforcement is often added
on the NEW version and backported inconsistently (or the v1 endpoint was simply forgotten).
**Test:** when a target has `/v2/` or `/api/v2/` in paths, always replay IDOR candidates against
`/v1/` and `/v3/` variants. `recon_jsintel.sh` endpoint mining often surfaces old version paths
that no longer appear in the current UI.

### 2. Array / JSON-type coercion
Some authz middleware checks `if (param.userId === session.userId)` — a strict equality that fails
when the param is an array. Sending `{"userId": [victimId]}` instead of `{"userId": victimId}` can
bypass the comparison: the array passes deserialization, the business logic extracts `[0]`, the
authz check sees an array (truthy, not equal to a string → guard skips or throws a handled exception
that defaults to "allowed").

Variants:
- `{"id": [123]}` instead of `{"id": 123}`
- `{"id": {"eq": 123}}` (object injection — some ORMs accept filter-shape inputs)
- `{"id": "123"}` vs `{"id": 123}` — type coercion across string/int can also skip a guard

### 3. Filter-object IDOR (REST + GraphQL)
APIs that appear self-scoped (`GET /me/orders`) sometimes expose a POST body or URL param that
overrides the session-derived scope:
- REST: `POST /orders/search` body `{"filter": {"userId": "victimId"}}` — the resolver uses
  the filter value directly instead of the session identity.
- GraphQL: `query { orders(filter: { userId: "victimId" }) { ... } }` — same pattern, common
  on search/list resolvers.
- Nested inputs: `{"input": {"account": {"id": victimId}}}` — buried two levels deep.

These are ESPECIALLY common on list/search endpoints because the dev added filtering for
admin use-cases and forgot that the filter runs pre-auth.

### 4. Content-type switching
Changing `Content-Type: application/json` → `application/x-www-form-urlencoded` or
`application/xml` can route through a different middleware stack. Authz validation added
only for the JSON path is skipped for the alternate content-type.
**Quick test:** replay the IDOR probe with `Content-Type: application/x-www-form-urlencoded`
and body `id=victimId`. Some frameworks auto-parse both forms; the authz guard may only wrap
the JSON parser.

### 5. High-entropy UUID ≠ safe from IDOR (the escalation trap)
"UUIDv4 / 25-digit high-entropy ID = needs a leak vector" is correct for RANKING, but do NOT
write off a UUID-IDOR candidate purely on entropy grounds. The April 2026 chain:
- A 25-digit document ID was "unguessable" → IDOR deprioritized.
- Fuzzing the SAME endpoint with SQLi payloads revealed error-based PostgreSQL injection.
- The injection leaked real document IDs from the DB.
- Those IDs fed back into the IDOR endpoint confirmed cross-user document access.

**Rule:** when ranking IDOR candidates, pair UUID-type entries with a note "check for injection on
same resource path." If `recon_xss_sqli_candidates.py` or jsintel surfaces an injectable param on
the same host + same path prefix, escalate the UUID-IDOR candidate's priority.

### Sources
- IDOR checklist (2025): https://ahmed-tarek.gitbook.io/security-notes/owsap-top-10-2025/a01-broken-access-control/checklists/idor-checklist
- UUID IDOR → SQLi chain: https://medium.com/@DarkyOS/sql-injection-in-graphql-websocket-escalated-to-pii-document-leak-09ba7ad2800a (Apr 2026)
- Nextcloud BOLA/IDOR disclosed: https://hackerone.com/reports/3382343 (Apr 2026)


---
<!-- applied-proposal: 2026-06-24_kb-enrich_class-idor -->
### Applied research — kb-enrich (2026-06-24)

## New techniques (2024–2025)

### HTTP parameter pollution IDOR bypass
Duplicate the object-ref parameter with two different values in the same request. Application logic
processes the FIRST (victim's id) while the authorization check looks at the SECOND (attacker's id),
resulting in a bypass. Test both query-string (`?userId=VICTIM&userId=ATTACKER`) and JSON body
(`{"userId":"VICTIM","userId":"ATTACKER"}`). Also test URL-encoded body vs JSON body disagreement.

Source: https://0xgaurang.medium.com/case-study-bypassing-idor-via-parameter-pollution-78f7b3f9f59d

### UI / API authorization divergence
A systematic gap: the UI correctly blocks a privileged action (e.g. edit another user's metadata) but
the underlying API endpoint has no server-side authorization check. Pattern from CVE-2024-22278 (Harbor
container registry): `PUT/POST/DELETE /projects/{id}/metadatas/{meta_name}` allowed a Maintainer role
to execute ProjectAdmin-only operations because UI gating was the ONLY layer.

**Hunting approach:** find every UI-blocked action → capture the underlying raw API request → replay it
with a lower-priv session. Any 2xx = authorization delegated to the UI only = IDOR/BAC.

Source: https://unit42.paloaltonetworks.com/bola-vulnerability-impacts-container-registry-harbor/

### WebSocket IDOR
Object-ref IDs in WebSocket / real-time message payloads are almost never tested. Auth checks on the
HTTP upgrade path ≠ auth checks inside WS message handlers. Test: swap the `id` / `resource` fields
in WS frames with another account's known object ID. If the handler processes it without re-checking
the caller's ownership, it is IDOR. Signal to look for: any WS message payload containing an `id`,
`roomId`, `channelId`, `userId`, `orderId`, etc.

### Multi-step purchase-flow IDOR
Purchase → confirmation → receipt flows return an object ID at step N that is consumed at N+1 without
re-validation. Intercept the confirmation/download step and substitute another account's
order/invoice ID. High-severity because it typically exposes financial PII. Also applies to:
subscription renewals, invoice downloads, shipping labels, return authorizations.

### JWT `sub` claim IDOR
Unsubscribe, email-preference, and "my account" endpoints sometimes decode the token's `sub` claim to
derive the target user but do NOT re-check that the claim matches the caller. If the `sub` is a user
ID that the server uses for the action (not just auth), replacing it with another account's ID = IDOR.
Note: this requires a JWT with a manipulable claim (unsigned/algorithm-confusion) OR an endpoint that
takes the user-id separately from auth (e.g. a link-token that embeds the ID but is not signature-bound
to a caller session).

Source: https://ajakcybersecurity.medium.com/exploiting-jwt-token-leads-to-idor-ec48cb8888bb

### Tooling addition
- **BurpAPISecuritySuite** (https://github.com/Teycir/BurpAPISecuritySuite) — 15 attack types including
  BOLA/IDOR detection, 108+ payloads. Complements Autorize for API-focused surfaces.


---
<!-- applied-proposal: 2026-06-30_detect-tune_class-idor -->
### Applied research — detect-tune (2026-06-30)

## IDOR Confirm Primitive — Multi-Session Body Hash

Single-session automated scanners produce near-100% FP on IDOR (confirmed by BacAlarm, Dec 2025, arxiv:2512.19997). The authoritative confirm primitive requires two sessions:

1. Make the same request under **session A** (owner of the object) and **session B** (different account, no ownership)
2. Hash response bodies from both sessions
3. If hashes match AND body contains session A's private data = **IDOR CONFIRMED**
4. If status is `200` for both but bodies differ (session B gets empty/generic) = access control working = FP

**Status-code oracle (necessary but not sufficient):**
- `200` owner + `403` non-owner = correct access control
- `200` owner + `200` non-owner = IDOR candidate → proceed to body comparison

**Timing differential signal (supplementary):** Authorized requests are often faster (cached/indexed at auth layer). Absence of timing difference between sessions = potentially missing auth check. Not a standalone signal but corroborates body-match findings.

**FP suppression in ai-hunter output:** when the hunter flags an IDOR hypothesis, the 2-account confirm step must verify response body equality cross-session, NOT just HTTP 200 status. A 200 with empty body or generic schema = FP.

**Never auto-confirm IDOR:** needs 2 owned accounts + operator-executed swap. The hunter provides the ranked hypothesis + the object reference + the swap instructions; the human runs the test.

Source: https://arxiv.org/pdf/2512.19997, https://apiiro.com/blog/why-dast-tools-miss-real-idor-vulnerabilities-and-how-ai-helps/
