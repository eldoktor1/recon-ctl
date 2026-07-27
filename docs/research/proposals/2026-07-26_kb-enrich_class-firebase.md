# PROPOSAL (new) for docs/knowledge/class-firebase.md — kb-enrich 2026-07-26
_Review and apply manually; not auto-merged into the KB._

# Firebase / Firestore / RTDB misconfiguration — unauth enumeration & exploitation

Google Cloud's Firebase suite (Firestore, Realtime Database, Cloud Storage, Auth/Identity Toolkit,
Remote Config) ships **REST APIs that are unauthenticated by default unless security rules are
explicitly locked down**. This is a distinct dup-resistant lane from generic S3/GCS bucket scanning
(`class-bucket-exposure.md`) — different endpoints, different tooling, same underlying class (broken
access control via default-open config). High real-world payout precedent: the Tea App breach (72k
images, 1.1M private messages) was a misconfigured Firebase Storage bucket.

## 1. Find the project config (from target's own JS — matches our jsintel doctrine)
- Web: `grep -rniE 'firebase.*(apiKey|projectId)' .` over crawled/mined JS bundles — pulls the
  standard `firebaseConfig` object (`apiKey`, `authDomain`, `projectId`, `storageBucket`, `appId`).
- Android APKs: `res/values/strings.xml` or `AndroidManifest.xml`.
- No config found but you suspect Firebase (favicon/tech hints): the API key is NOT a secret by
  design (public-by-design per our own FP doctrine) — do not mint a "leaked API key" finding on the
  key alone; it's the *rules*, not the key, that matter.

## 2. Unauth enumeration/probe matrix (all safe GET/HEAD-class reads — fits our confirm-primitive discipline)
| Surface | Probe | Signal |
|---|---|---|
| Project identity | `curl https://identitytoolkit.googleapis.com/v1/projects?key=<apiKey>` | confirms live project, lists authorized domains |
| Firestore | `https://firestore.googleapis.com/v1/projects/<projectId>/databases/<database>/documents/<collection>/<document>` | try common db names (`(default)`,`prod`,`dev`,`staging`,`qa`) × common collections (`users`,`accounts`,`orders`,`messages`,`sessions`,`tokens`) — non-404 = collection/doc exists |
| Realtime DB | `https://<project>.firebaseio.com/.json` or `https://<project>.<region>.firebasedatabase.app/.json` | full unauth JSON dump if rules are `".read": true` |
| RTDB rules disclosure | `https://<projectId>.firebaseio.com/.settings/rules.json?auth=<idToken>` | reveals the actual rule set (useful even 403'd — confirms structure) |
| Storage | `https://firebasestorage.googleapis.com/v1/b/<projectId>.appspot.com/o?maxResults=100` | lists bucket objects if public-read |
| Remote Config | `POST https://firebaseremoteconfig.googleapis.com/v1/projects/<projectId>/namespaces/firebase:fetch?key=<apiKey>` body `{"appId":"<appId>","appInstanceId":"PROD"}` | may leak feature-flag/config secrets |

## 3. The auth-shift trick (own-account only — ties to our 2-owned-account IDOR doctrine)
`POST https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<apiKey>` with body
`{"returnSecureToken":true}` creates a **free anonymous account** and returns an `idToken`. Many
Firestore/RTDB rulesets gate on `request.auth != null` rather than a real authorization check — an
anonymous idToken can satisfy that and flip access from denied to granted. This is the highest-EV
Firebase bug bounty pattern (broken authZ, not broken authN) — use ONLY our own freshly-created
anonymous account, never to access another real user's data; the goal is proving the rule is
`if request.auth != null` (too permissive) vs a real per-user check.

## FP / non-finding patterns (never mint as CONFIRMED without these)
- Default `allow read, write: if false` (locked) rules 403/404 everything — that's SECURE, not a lead.
- A public-read Storage bucket serving CDN/marketing assets is by-design (same rule as
  `class-bucket-exposure.md`'s public-read-CDN FP) — content sensitivity gates the finding, not the
  fact of public-read.
- `apiKey` presence alone is never a finding (it's meant to be public — same doctrine as Supabase
  anon keys / Stripe `pk_` in our documented JS-secret FP list).
- `allow read, write: if true` (explicit wildcard-open) on a collection/bucket containing real user
  PII is the CONFIRMED case — screenshot the unauth read as evidence, do not write/delete/harvest bulk data.

Sources: [m1tz.com — Hacking Firebase Projects: Enumeration and Common Misconfigurations](https://blog.m1tz.com/posts/2025/07/hacking-firebase-projects-enumeration-and-common-misconfigurations/), [COE Security — Firebase Misconfigurations / Tea App breach](https://coesecurity.com/firebase-misconfigurations/), [Intigriti — Hacking Google Firebase Targets](https://www.intigriti.com/researchers/blog/hacking-tools/hacking-google-firebase-targets).
