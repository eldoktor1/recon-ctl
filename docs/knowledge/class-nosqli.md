# class-nosqli — NoSQL injection (MongoDB-primary) hunting (reusable knowledge)

Directly extends the BOLA/auth-bypass money lane: modern JSON REST + GraphQL APIs backed by MongoDB (or
Redis/CouchDB) are exactly our top in-scope tech (Node/Express APIs behind Cloudflare/AWS). Unlike SQLi,
the injection vehicle is JSON *structure*, not string escaping — so WAFs tuned for SQL syntax miss it
entirely, and it's an under-hunted class relative to SQLi/XSS.

## Confirm primitive (SAFE, unauth-appropriate, matches our doctrine)
Differential response test — replace a scalar param with an **operator object** and compare against the
baseline (same discipline as SQLi `'` vs `''`):
- Baseline: `{"username":"admin","password":"wrongpass"}` → normal auth failure.
- Injected: `{"username":"admin","password":{"$ne":null}}` (or `{"$ne":""}`, `{"$gt":""}`) → if this
  returns a DIFFERENT result (200/success, or a distinct error class) than a wrong-password baseline,
  the operator was interpreted = **confirmed NoSQLi** (auth-bypass-class). This is read-only detection —
  do NOT proceed to log in as a real account; the differential IS the finding, same as our SQLi primitive.
- Also test `$regex` (`{"username":{"$regex":"^adm"}}`) for boolean-blind enumeration, and `$where` for
  JS-eval sinks — but per our NEVER-list, don't chain into data extraction; one differential response is
  the PoC.

## Where to find the sink (id/param types → NoSQLi likelihood, same ranking logic as `class-idor`)
- Login/password-reset/email-verification endpoints (`token`, `resetPasswordExpires`, `otp` fields) —
  **highest EV**: `{"$gt": Date.now()}` style bypass of expiry checks. CVE-2026-30941 (Parse Server) is
  exactly this — unauth attacker injects Mongo operators via the `token` field on password-reset/
  email-verify, no type validation before the value hits the query.
- Any JSON body/GraphQL arg accepting an object where a scalar (string/number) is expected — nested
  objects passed straight to a MongoDB `find()`/`findOne()` filter without a schema-validation layer
  (Zod/Joi) or explicit type-casting are the vulnerable pattern.
- Array-style form params (`field[$ne]=`) — classic PHP/Express `qs`-parser coercion into a JSON object
  even over `application/x-www-form-urlencoded`, not just JSON bodies. Always test both content-types.
- `$where` clauses built via string concatenation (`this.field == '` + input) are rarer but allow JS
  injection akin to SQLi UNION — flag, don't execute.

## Detection sweep (single-request, syntax-breaking chars)
Send `$ { } \ " \` ; %00` in each param and diff status/length/headers against baseline — same
methodology as SQLi differential, applied to NoSQL syntax instead of quotes.

## FP / non-finding patterns
- App uses a schema-validation layer (Zod/Joi/Mongoose schema with strict types) that rejects non-scalar
  input before the query — the operator payload gets a 400, not a differential. That's the secure state,
  not a finding.
- Second-order: a stored value later reaches a `$where`/dynamic query. Only claim this if you can show
  the *later* read reflects the injected operator's effect — don't assume from the write alone.

## Sources
- https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-nosql-injection-nosqli-vulnerabilities
- https://advisories.gitlab.com/pkg/npm/parse-server/CVE-2026-30941 (unauth Mongo-operator injection via password-reset token)
- https://www.invicti.com/blog/web-security/nosql-injection-cheat-sheet
