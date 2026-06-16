# tech-argocd — Argo CD (GitOps CD for Kubernetes) hunting notes

General, reusable knowledge for Argo CD instances surfaced in scope. Host-specific
findings go to host_notes, not here.

## Fingerprint / enumeration (unauth, safe)
- Root `/` → Argo CD SPA login shell ("Argo CD" title, React app).
- **`/api/version` → 200 JSON `{"Version":"vX.Y.Z+<sha>", ...}`** — UNAUTH version disclosure
  by default (this is default Argo CD behavior, NOT a misconfig). Use it to version-confirm.
- `/healthz` → 200 `ok`.
- `/api/v1/applications` → on a HARDENED instance returns **401 `{"error":"no session information"}`**.
  If it returns a real application LIST unauthenticated → that IS a genuine unauth exposure
  (anonymous policy misconfig — `users.anonymous.enabled: true` with a non-empty RBAC default
  role). Worth reporting. Most instances are 401 (secured).

## CVE version floors (compare to /api/version)
- **CVE-2025-55190 (CVSS 10.0, disclosed 2025-09-05):** a **project-level API token** can
  retrieve repository credentials (username/password) even without secret permissions —
  isolation bypass. Affected: **>=2.13.0 <2.13.9** and **>=2.14.0 <2.14.16**. Patched in
  **2.13.9 / 2.14.16**.
  - SEVERITY CAVEAT (important for honest triage): exploitation requires an **authenticated
    project API token** — it is NOT an unauthenticated primitive. A bare in-range `/api/version`
    is therefore a **version-confirmed LEAD (P1-max), authed-exploitation**, not an unauth P0.
    On a dev/internal instance where no token is obtainable, actionability is low. Never headline
    the version disclosure itself (= N/A).
- Unauth `/api/webhook` DoS: a malformed Bitbucket Server payload (no `webhook.bitbucketserver.secret`
  configured) crashes the API server → CrashLoopBackOff on a single unauth request. **FORBIDDEN
  lane — never DoS / never send the crash payload.** Note only.

## Triage rule
`/api/version` in-range ⇒ LEAD only. CONFIRMED requires either an unauth `/api/v1/applications`
app-list leak (rare) or operator-held authed token (CVE-2025-55190). Version match alone never P0.

## Sources
- https://www.bleepingcomputer.com/news/security/max-severity-argo-cd-api-flaw-leaks-repository-credentials/
- https://github.com/argoproj/argo-cd/security/advisories
- First surfaced: 2IC r149 (2026-06-16) — argocd.ap-southeast-2.development.external.seek.com v2.14.11 (SEEK BC elite).
