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
