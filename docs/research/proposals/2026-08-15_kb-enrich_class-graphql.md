# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — kb-enrich 2026-08-15
_Review and apply manually; not auto-merged into the KB._

## 2026-08-15 addition — global-ID decoding + alias/batch rate-limit bypass

### Global-ID decode/increment/re-encode (real disclosed pattern: Shopify H1 #2207248 $5k, GitLab, HackerOne itself)
"Opaque" base64 Relay-style node IDs (`Node`/`ID!` GraphQL type) frequently decode to a plaintext string
containing a SEQUENTIAL backend integer, e.g. `base64decode(id) == "gid://shopify/BillingDocument/48213"`.
Attack: decode any ID the app returns you → increment the trailing integer → re-encode (base64) → submit
as the `id` arg to the same query/mutation against another user's object. Treat any GraphQL arg typed
`ID!`/`Node` as a candidate IDOR vector, NOT as opaque-safe — decode first, only deprioritize if the
decoded value contains a real UUID/hash rather than a small integer.

### Alias/batch overloading — rate-limit bypass + brute-force amplification (CVE-2024-39895 Directus)
Most GraphQL backends inherit REST-style rate limiting (counter per IP/token/HTTP-request), which doesn't
see inside a single POST body. Two amplification primitives:
- **Field aliasing**: request the same field N times under different alias names in ONE query:
  `{ a0: verifyOtp(code:"0000"){ok} a1: verifyOtp(code:"0001"){ok} ... a9999: verifyOtp(code:"9999"){ok} }`
  — covers 10,000 OTP guesses in a single HTTP request that a per-request limiter counts as "1".
- **Array batching**: some servers accept a JSON ARRAY of operation objects in one POST:
  `[{"query":"mutation{login(email:\"a\",password:\"p1\"){token}}"},{"query":"...p2..."}, ...]`
  — same amplification for credential stuffing / login brute-force.
Detection method: (1) send single ops to baseline the rate limit (find the 429 threshold); (2) send one
aliased query with 50-100 aliases of a harmless read-only field, confirm the server returns 50-100 results
in ONE response; (3) if step 2 succeeds, the effective throughput multiplier = alias count × the per-request
limit — flag as a LEAD (rate-limit-bypass amplifying whatever endpoint is under-protected: OTP verify,
login, password-reset-code guess, coupon/voucher brute-force). This is READ-ONLY/safe to detect (using an
inert field) but the impactful confirm (actually brute-forcing an OTP/login) is authed/active-PoC territory
— human-in-the-loop per our doctrine, note as LEAD not auto-exploit.
