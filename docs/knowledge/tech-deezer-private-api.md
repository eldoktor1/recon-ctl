# tech: Deezer private API surface (gw-light gateway + pipe GraphQL)

Discovered 2026-08-16 by reading open-source reverse-engineered clients — **not** by scanning.
`api.deezer.com`, `ws.deezer.com` and `pipe.deezer.com` all return **0 JS assets** to jsintel and
`pipe.deezer.com/` is a bare 404, so every crawler and scanner sees nothing. The entire surface below
is invisible to normal recon and is documented only in third-party RE clients. This is the method,
not just the result: **when a host is in scope but yields no crawlable surface, go read the
open-source clients that talk to it.**

## Sources (public repos, read offline — zero target traffic)
- `svbnet/diezel` — Node client for the private "Gateway API"; documents the GraphQL API + auth chain
- `BackInBash/DeezerAPI` — .NET private API client
- `yne/dzr` — C client
- (`89z/deezer` — Go; repo no longer clonable as of 2026-08-16)

## The four private gateways
| endpoint | what it is |
|---|---|
| `https://www.deezer.com/ajax/gw-light.php?method=<M>&input=3&api_version=1.0&api_token=<tok>` | main web RPC gateway |
| `https://api.deezer.com/1.0/gateway.php` | second gateway (mobile/legacy) on the *api* host |
| `https://pipe.deezer.com/api/graphql` | **GraphQL API** — note `/api/graphql`, NOT `/api` |
| `https://www.deezer.com/ajax/action.php` | action endpoint |
| `https://media.deezer.com/v1/get_url` | media URL / license issuance (**OUT OF SCOPE** asset) |

**gw-light is an RPC dispatcher keyed by `?method=`.** RE clients document ~20 music methods
(`deezer.getUserData`, `deezer.ping`, `deezer.page*`, `mobile.page*`, `song.*`, `album.*`,
`playlist.*`). There is also a **`mobile.*` namespace** on the same dispatcher. Account/family/payment
methods exist in that namespace but appear in no open-source *music* client — method-name enumeration
is the untouched surface, and authorization on a dispatcher is **per-method**.

## Auth chain
```
GET  https://auth.deezer.com/login/anonymous?i=p&jo=p&rto=p   -> {jwt}      # NO credentials
POST https://auth.deezer.com/login/arl        {arl}           -> {jwt, refresh_token}
POST https://auth.deezer.com/login/renew
```
⚠️ **`auth.deezer.com` is NOT in the YWH scope** (`in_scope:false, pays:false`) — do not test it.
`pipe.deezer.com` IS in scope + pays.

The **anonymous JWT** decodes to `{"unlogged":true,"scopes":["all"],"iss":"Deezer Auth Service"}` —
an unauthenticated token carrying scope `all`, ~6 min lifetime.

## pipe GraphQL — measured state (2026-08-16)
- `POST /api/graphql` returns **200** with **no Authorization header at all**
- **Introspection ENABLED**: 972 types, **66 queries, 83 mutations**
- Responses carry `extensions.queryCost` ⇒ complexity limiting exists
- **Unauth IS enforced per-resolver**: `me`, `tokens`, `permissions`, `myDeezerStats` →
  `JwtTokenMissingError`. Introspection-enabled alone is NOT a finding (KB `class-graphql.md`).

### The two boundary-crossing hypotheses (HUMAN, 2 owned accounts — NOT auto-testable)
**H1 — `changeEmailAddressByInvoiceId(input: ChangeEmailAddressInput)`**
`ChangeEmailAddressInput` has exactly **ONE** field: `invoiceId: String!`. No current password, no
confirmation token, no user id. An **identity-critical operation keyed solely on a BILLING object**.
Related type `PrivateUserSubscriptionAppleInvoice { isFromPrivateRelay, isOwner, emailAddress }` —
the invoice carries an email and an `isOwner` boolean. **Broken assumption to test: possession of an
invoiceId proves ownership of the account.** Test: account A holds a paid/Apple invoice; authenticated
as account B, call the mutation with A's invoiceId. If B changes A's email ⇒ account takeover.
Also check invoiceId entropy/format (sequential ⇒ enumerable ⇒ mass ATO).

**H2 — `FamilyUserPermissions { isLoggableAs, arePersonalDataEditable, isDelinkable, isDeletable,
canBeConvertedToIndependent }`**
Five authorization booleans **delivered to the client**, on `Family { main, linked }` /
`FamilyUser { id, name, picture, caption, permissions }`. This is the backend of the
`/oauth/members/picker` route. **Broken assumption to test: the operation re-derives these
server-side.** If `isLoggableAs` is advisory (a UI hint), a linked member logs in as `main` ⇒ full
household takeover; `isDeletable`/`isDelinkable` are destructive ops gated the same way.
NOTE: no family mutations appear in the pipe schema ⇒ family management is likely on the **gw-light
gateway**, so find the method name there and test it at that layer.

### Other object-ref surface worth testing (all need a JWT)
`user(userId)`, `usersByIds(ids)`, `musicTogetherAffinity(musicTogetherGroupId, **memberId**)`,
`musicTogetherGroup(id)`, `queueChunkByQueueId(queueId)`, `deezerStory(token)`,
`blindTestSessionState(token)`, `tokens()` → `{recToken, liveToken, mediaServiceLicenseToken}`.
Token-keyed mutations: `saveDeezerStoryQuizScore(token,…)`, `blindTestMakeAGuess(token,…)`,
`addTracksToPartnerPlaylist(input)`.

## Hard lines for this surface
Mutations here are **state-changing on real accounts** — never fire `changeEmailAddressByInvoiceId`,
`deletePlaylist`, `musicTogether*` or any `remove*` against an invoice/id you do not own. Guessing an
invoiceId to reach a stranger's account is the NEVER list, not a PoC. Two OWNED accounts only.
