# Differential testing — the difference between "looks like" and "is"

**Added 2026-08-17** after an evaluation of 320 minted findings showed 316 false positives,
3 `real` verdicts (all in a single week in June), and zero confirmed findings in any class
that pays. The cause was not bad tuning. It was that nothing in the pipeline ever ran a
**test**.

## The principle

> A pattern match is an observation. A **differential** is a test.

The pipeline's lanes ask *"does this response contain something that looks like a
vulnerability?"* — a question with no factual answer, which is why every hit needed an LLM
verdict to guess. A differential asks a question that has one:

| Class | The two things compared |
|---|---|
| Broken access control | same GET **with** the session vs **without** it |
| IDOR / BOLA | identity A's token against object B vs identity B's own token |
| SQLi | `'` vs `''` |
| XSS | payload **executes** in a headless browser vs a control that shouldn't |
| Cache deception | cached under our key vs not cached |
| Privilege escalation | low-priv role vs high-priv role on the same request |

When the comparison fires, the two responses **are** the proof. There is no verdict to get
wrong, so a differential lane cannot become a false-positive factory. This is why
`recon_authdiff.py` writes findings at `confidence=0.95` with no `ai_verdict` gate, while
the pattern-matching lanes needed a consensus panel and 1,423 FP signatures to babysit them.

It is also what XBOW's "validator" layer is: for XSS *a headless browser visits the target
to verify the JavaScript actually executed*. Proof, not opinion.

## The two halves, and why they are separate tools

Authorization has two failure modes and they need different testers.

**1. Unauthenticated reaches authenticated data** → `recon_authdiff.py`
Replays each discovered endpoint twice, with and without the operator's session, and
compares. Safe to drive at scale: GET only, endpoints replayed exactly as discovered,
never synthesising an identifier.

```bash
recon-authdiff <host> --cookie "<session cookie>" --limit 150
recon-authdiff <host> --header "Authorization: Bearer <tok>" --base https://api.host/
```

Without a session both sides are the same request, so the tool **forces `--dry-run`** —
otherwise every data endpoint would compare identical and mint a bogus "exposed".

**2. Identity A reaches identity B's data** → **Autorize** (Burp extension)
This one cannot be automated headlessly because it needs two real logged-in identities.
Autorize solves it by riding along with ordinary browsing: set account A as the working
session and account B (or unauthenticated) as the comparison, then **just use the app**.
Every request is replayed as the other identity and colour-coded enforced/bypassed.

That turns an evening of clicking around into a complete authorization matrix, at 2–3× the
traffic you were already generating. It is the single highest-leverage tool available,
because IDOR/BOLA is the #1 paid class and the one no unattended scanner can confirm.

Hard line unchanged: **two accounts you own**. Never a guessed or enumerated third-party
identifier — that proves nothing and is not the bug.

## API base resolution (why 162k endpoints looked dead)

`jsluice` extracts endpoints relative to whatever base the JavaScript talks to — usually an
API origin, not the web root. Testing `/v1/admin/get-account-data` against
`https://customerzone.bitdefender.com/` returns 404 and the whole surface looks dead.

`recon_authdiff.py` samples five endpoints against candidate bases (`host/`, `host/api/`,
`api.<root>/`, `api.<host>/`) and keeps whichever answers. **A `401`/`403` is the strongest
signal a base is correct** — the route exists and is protected, which is exactly the surface
worth differential-testing. Resolved base on a different host gets its own scope+pays gate.

Proven 2026-08-17: `customerzone.bitdefender.com` → base resolved to
`api.customerzone.bitdefender.com`, turning 404-everywhere into `401` on
`/v1/admin/get-account-data` and `405` on `/v1/admin/new-organization` (405 = exists, POST-only,
and we are correctly GET-only).

## Reading the verdicts

| Verdict | Meaning |
|---|---|
| `exposed` | **the finding** — unauth response substantively identical to authenticated |
| `partial` | unauth returns a reduced but non-empty version — check what leaked |
| `enforced` | unauth got 401/403/redirect-to-login — the app is correct here |
| `no-access` | the *session* failed to authenticate — refresh the cookie |
| `no-data` | 404/405/HTML — endpoint absent, wrong method, or not a data route |
| `spa-shell` | unauth body is the app shell or soft-404 — **not** a leak |

`spa-shell` exists because an SPA route returning `index.html` looks like a 200 with content
and has burned this operation before. The tool fingerprints `/` and two guaranteed-404 paths
up front and discards anything matching them.

## Why this replaces most of the FP machinery

The `ai_verdict` gate, the consensus panel, the FP-signature store and the escalation ladder
all exist to answer *"is this pattern match actually real?"*. A differential answers that in
the test itself. Keep the verdict layer for the pattern lanes; differential lanes do not need
it and must not be slowed by it.

Related: [[class-bucket-exposure]], [[class-graphql]], [[process-report-submission]]
