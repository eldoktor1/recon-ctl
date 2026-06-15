# class-firebase.md — Firebase exposure hunting (RTDB / Firestore / Storage / Auth)

Reusable methodology. First banked 2IC r128 (2026-06-15) after confirming an OPEN Firebase
Realtime Database on Kiwi.com (skypicker-984). READ before hunting Firebase tech; APPEND learnings.

## The fast config-extraction trick (no JS-bundle mining needed)
Any host on **Firebase Hosting** auto-serves its full client config at:
```
GET https://<host>/__/firebase/init.js
```
Returns `firebase.initializeApp({ apiKey, authDomain, databaseURL, projectId, storageBucket, ... })`.
- `databaseURL` **non-empty** → a **Realtime Database (RTDB)** exists → test it (below).
- `databaseURL` **empty** (`""`) → no RTDB; the app uses Firestore and/or Auth only (different APIs).
- No init.js (SPA not on FB Hosting) → mine the JS bundle: `curl host/ | grep src=*.js`, fetch each,
  `grep -oE '(databaseURL|firebaseio\.com|firebasedatabase\.app)[^"]*'`. (Some SPAs use ESM/chunked
  JS that a naive `src="*.js"` grep misses — fall back to katana/jsintel or the `_next` chunk list.)

## RTDB open-read confirm — SAFE, keys-only (NEVER harvest values)
RTDB hostnames: `https://<projectId>.firebaseio.com` (classic) or
`https://<id>-default-rtdb.<region>.firebasedatabase.app` (regional, newer).
```
GET https://<rtdb>/.json?shallow=true&timeout=3s
```
- **HTTP 200** + `{"<key>":true,...}` → **OPEN / world-readable** (the `.read` rule is `true` or `auth==null` allowed). `shallow=true` returns ONLY top-level KEY NAMES as `true` — proves readability WITHOUT reading any value (stays inside the no-harvest hard line). Descend one more level per key (`/<key>.json?shallow=true`) to characterize structure (config vs user-data) — still keys-only.
- **HTTP 401** `{"error":"Permission denied"}` → **SECURED**. Kill.
- **404** → no DB provisioned at that URL.

## Severity discipline (do NOT overclaim)
- **Read-only of non-sensitive app CONFIG** (feature flags, platform config, attribution settings,
  static lookup tables) = **LOW / often Informative**. A top level of only config-shaped keys
  (no `users`/`profiles`/`orders`/`messages`/`tokens` node) = config DB. Honest = LOW.
- **Read of user data / PII / tokens** (a `users`/`profiles`/`messages`/PII node) = MED-HIGH. Confirm
  by node-NAME via shallow only; do NOT read values — hand to operator.
- **WRITE access** = the real win regardless of read-sensitivity. An open `.write` lets an attacker
  tamper with whatever the app trusts (config served to all app users, attribution/affiliate payout
  routing = commission fraud, etc.). **The agent must NOT test write (destructive — hard line).**
  Operator's safe test: `PUT -d '"x"' <rtdb>/2ic_test_<rnd>.json` → 200+echo = writable → **DELETE
  immediately** (`-X DELETE <rtdb>/2ic_test_<rnd>.json`). One throwaway key, removed; never touch
  real nodes.

## Other Firebase surfaces (when databaseURL is empty)
- **Firestore** (needs a collection name): `GET https://firestore.googleapis.com/v1/projects/<pid>/databases/(default)/documents/<collection>` → 200 docs = open rules; 403 PERMISSION_DENIED = secured. Collection names come from the JS bundle.
- **Storage bucket**: `GET https://firebasestorage.googleapis.com/v0/b/<bucket>/o` (bucket = `<pid>.appspot.com`) → 200 list = open; 403 = secured.
- **Auth apiKey is PUBLIC by design** — never a finding on its own (don't flag `AIza...` keys as leaked secrets; ties to the js_secret_hit FP doctrine).

## FP / cluster notes
- **Product-class clusters share ONE project** → collapse to 1 rep: CM.com `*.ecr.cm.com`
  (kiosk/pos/receipt/management/balance all = projectId ecr-prod-7de91); Spotify `*.byspotify.com`
  Wrapped campaign microsites (all `wrapped-*` projects); per-platform mevo/multicam.
- A 401 on ONE rep secures the whole shared-project cluster.

## Confirmed instances (history)
- 2026-06-15 (r128): **app.kiwi.com / skypicker-984.firebaseio.com = OPEN read** (config-only:
  attribution/affiliates, configuration/android+ios, nationalityAlternatives, onDeviceSearch). LOW
  read-only; write-test pending (operator). kiwicom H1 mid. State id 72.
- SECURED (401): type-mvp (Streamlabs/Logitech), ecr-prod-7de91 (CM.com), ckmobilegcm (CreditKarma),
  api-project-518865853796 (Viator, r-2026-06-13).
- NO-RTDB: superhuman, truecaller-web, mevo, insomnia, dpg-media-boekenwijzer, wrapped-party.
