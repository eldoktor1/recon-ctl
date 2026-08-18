# tech: Uphold Enterprise API + `@uphold/fastify-openapi-router-plugin`

Built 2026-08-16 for the `upholdcom` program walk (Intigriti). The whole application model below
was produced by **reading Uphold's own published source**, with zero probing — `github.com/uphold/*`
is an in-scope asset (Tier 3). This is the XBOW loop: read the source, then attack exactly the risky
part. Two repos carry everything.

## The two repos that matter
| repo | what it gives you |
|---|---|
| `uphold/fastify-openapi-router-plugin` | **Uphold's actual authorization engine**, in source |
| `uphold/enterprise-widget-sdk` | the **partner → end-user trust boundary**, in source |

Clone offline: `git clone --depth 1 https://github.com/uphold/<repo>.git`

---

## 1. Authorization is DECLARED IN THE SPEC, not enforced in handlers

`src/parser/security.js`:

```js
const operationSecurity = operation.security ?? spec.security ?? [];
// Return undefined handler if there's no security for the operation.
if (operationSecurity.length === 0) {
  return;                      // <-- NO onRequest hook is registered at all
}
```

Three consequences, all reusable against **any** target running this plugin:

1. **An operation with no `security` block is fully unauthenticated.** There is no fallback and no
   deny-by-default. A single omission in the OpenAPI spec silently publishes an operation, and the
   route handler looks identical to a protected one.
2. **`security: []` on an operation overrides global spec security.** `??` only falls through on
   null/undefined, so an explicit empty array wins over `spec.security`. Per the OpenAPI spec this
   is correct ("explicitly public") — which means one stray `[]` de-authenticates an endpoint.
3. **Security blocks are OR'd, and a block whose credential is ABSENT is SKIPPED, not failed:**

```js
const blockHasMissingValues = Object.keys(block).some(name => readSchemeValue(name) == null);
if (blockHasMissingValues) { report.push({ ok: false, schemes: {} }); continue; }
```
   So the **weakest block in an operation's `security` array is the real security level** — simply
   omitting the strong credential falls through to the weak one.

**The technique this unlocks:** get the target's OpenAPI spec and *read the authorization matrix
off it* — enumerate every operation whose `security` is absent or empty, rank by sensitivity. That
is reading the answer, not guessing at routes.

### It does authN + scopes only — never object ownership
The plugin resolves identity into `request.oas.security.<scheme>` and checks **functional** scopes.
It performs **no object-level authorization**. Ownership must be hand-written in every single route
handler ⇒ on any app using this plugin, **BOLA/IDOR is structurally unhandled by the framework** and
is a per-handler coin flip. Aim IDOR testing at handlers that take an id from the path/body.

---

## 2. Scope wildcard = prefix match with NO delimiter check

`src/utils/security.js`:

```js
export const verifyScopes = (providedScopes, requiredScopes) => {
  const missingScopes = requiredScopes.filter(requiredScope => {
    const hasMatchingScope = providedScopes.some(providedScope => {
      if (providedScope.endsWith('*')) {
        const prefixScope = providedScope.match(/(.*)\*$/)[1];
        return requiredScope.startsWith(prefixScope);   // <-- no boundary enforcement
      }
      return providedScope === requiredScope;
    });
    return !hasMatchingScope;
  });
  return missingScopes;
};
```

- provided `*` → prefix `''` → `startsWith('')` is **always true** → **satisfies every scope in the API**
- provided `transactions.*` → satisfies `withdraw`, `credit`, `transfer.others`
- provided `transactions.w*` → satisfies **both** `transactions.withdraw` and `transactions.write`
  (no requirement that the next character be a delimiter)

**A bare `*` is a real accepted value in production**, not a hypothetical — `enterprise-widget-sdk`
`create-token.ts` mints the partner token with it:

```js
body: new URLSearchParams({ grant_type: 'client_credentials', scope: '*' })
// POST {coreApiBaseUrl}/oauth2/token   Authorization: Basic base64(clientId:clientSecret)
```

⇒ **scope checking imposes no restriction whatsoever on an enterprise client-credentials token.**
The only thing separating partner A from partner B's users is the security handler's clientId→org
resolution and whatever each route handler does with `X-On-Behalf-Of`.

### Uphold's scope namespace (mined from the portal bundle i18n keys)
```
accounts.read/write            cards.read/write         contacts.read/write
credit-lines.read              phones.read/write        user.read
institutional.title            institutional.user.read
transactions.read/write        transactions.deposit     transactions.withdraw
transactions.credit            transactions.commit.otp
transactions.transfer.self     transactions.transfer.others
transactions.transfer.application
```
The money scopes are **siblings of benign ones under a shared prefix** — which is exactly what makes
the prefix match dangerous. `transactions.transfer.self` ("move between your own cards") sits beside
`transactions.transfer.others`.

**Consent-bypass angle:** the consent UI renders descriptions from *exact* i18n keys `scopes.<name>`.
A wildcard scope string has **no** i18n key, so the consent screen cannot describe it accurately —
while the issued token satisfies `withdraw` and `transfer.others`. Only a demonstrated
withdraw/transfer with a wildcard-granted token proves it; a wildcard rejected at `/authorize` is a
clean negative.

---

## 3. `X-On-Behalf-Of` — the partner → user impersonation header

`enterprise-widget-sdk` `create-payment-session.ts` / `create-kyc-session.ts` /
`create-travel-rule-session.ts`:

```js
headers: {
  Authorization: `Bearer ${options.accessToken}`,      // partner's own client_credentials token
  'X-On-Behalf-Of': options.onBehalfOf ?? ''           // 'user <user_id>'
}
// POST {widgetsApiBaseUrl}/payment/sessions
// POST {widgetsApiBaseUrl}/kyc/sessions
```

A partner authenticates as **itself** and then acts as a **user** purely by naming that user in a
header. The security question is whether the widgets API verifies that `<user_id>` belongs to the
authenticated partner's organization.

Angles worth testing (owned accounts only):
- a user id belonging to a **different** organization
- the **typed prefix** — the value is `user <id>`, implying other principal types
  (`account`/`client`/`organization`/`admin`) ⇒ type confusion
- the **empty value** — the SDK sends `''` when `onBehalfOf` is absent; what does the API do with it?

`config.sample.ts` also shows quote bodies carrying raw object refs, which is the IDOR surface the
plugin explicitly does not protect:
```js
destination: { id: '<account_id>', type: 'account' }
origin:      { id: '<external_account_id>', type: 'external_account' }
```

---

## 4. Enterprise Portal object model (GraphQL type names, mined from the Next.js bundle)
- **org + roles:** `addMember`, `activeMembers`, `availableMemberRoles`, `defaultOrganizationRole`
- **credentials:** `createClient`, `createClientSecret`, `clientSecrets`, `EnterpriseApiClient`,
  `EnterpriseApiClientSecret(Result)`, `BasicEnterpriseApiClient`
- **OAuth apps:** `createApplication`, `deleteApplication`, `applications`, `applicationsPage`,
  `ApplicationAuthorizationsResult`, `getAppVerified`, `argumentNameForApplicationId`
  (registration fields: `redirectUri`, `scope`, `siteUri`, `privacyPolicyUri`)
- **tokens:** `createAccessToken`, `accessTokens`, `AccessToken(Connection/Edge)`
- **capabilities:** `appCapabilities`, `clientCapabilities`, `ClientCapability`, `ApplicationCapability`

A partner can **mint its own OAuth application with an arbitrary `scope` string** — which is the
delivery vehicle for the wildcard flaw above.

---

## Operational notes for this program
- **Mandatory identification** (same class of rule as the YWH Deezer UA tag): UA must carry the
  Intigriti handle **and** header `X-Bug-Bounty: Intigriti-<username>`. Max **10 req/sec**.
  `recon_jsintel.sh` and `safe_probe_worker.py` do **not** send these — keep them off this program
  until fixed.
- **Scanner ban:** automated vulnerability scanners prohibited in production; *"reports resulting
  from production automation may be marked as Out of Scope"* (2026-04-21). Manual Burp + dev Brave
  + offline analysis only.
- **Account door is open and instant** — enterprise sandbox self-signup needs no invite; wallet
  sandbox uses MFA code `000000` plus a KYC-bypass email to `security@uphold.com`.
- **WAF:** an `__schema` introspection POST to `portal.enterprise.uphold.com/graphql` returns
  **403 + a 387KB marketing page** (edge rule on the introspection pattern). Do not re-fire it
  unauthenticated. `/graphql` is not on the portal origin anyway — the portal calls separate `core`
  and `widgets` base URLs configured per integration.
- `docs.api.enterprise.uphold.com` — **TLS handshake failure** at the Cloudflare edge (no cert for
  that hostname) despite being a listed in-scope asset.

## Hard lines
Sandbox only, two OWNED accounts/orgs only. Never send a real third party's `user_id` in
`X-On-Behalf-Of`, never mint a session against an id we do not own, and no real money movement —
the PoC is that the boundary is crossed, not a transfer that lands.

## Sources
- `github.com/uphold/fastify-openapi-router-plugin` (`src/parser/security.js`, `src/utils/security.js`)
- `github.com/uphold/enterprise-widget-sdk` (`projects/widget-test-app/src/shared/api/requests/*`, `config.sample.ts`)
- `portal.enterprise.uphold.com` Next.js bundle (buildId `brrzLwMMhGO07peaYyH9L`)
- Intigriti program policy, read in full 2026-08-16
