# PROPOSAL (proposal) for docs/knowledge/class-idor.md — detect-tune 2026-08-25
_Review and apply manually; not auto-merged into the KB._

## Shopify `shopify_app` gem — cross-shop authorization bypass (CVE-class AIKIDO-2026-135231)

**Affected:** Ruby `shopify_app` gem 22.1.0–23.0.2 (fixed 23.0.3) — used by independent Shopify Partner
apps built with this gem, NOT Shopify's own platform.

**Root cause:** in token-exchange authenticated controllers, `current_shopify_domain` resolves to the
sanitized `shop` **query parameter** before falling back to the shop identity verified in the Shopify ID
token / session. A request authenticated to Shop A but carrying `?shop=<Shop B>` executes in Shop B's
context — any shop-scoped read/write that trusts `current_shopify_domain` or raw `params[:shop]` is
exposed.

**Fingerprint (unauth recon):** `/auth/shopify/callback` route present, embedded-app App Bridge iframe,
Rails-style error pages/asset paths referencing `shopify_app`/`ShopifyAPI`, or a leaked `Gemfile.lock`
pinning `shopify_app` 22.1.0–23.0.2.

**Test (2-owned-account, human-in-loop):** authenticate as Shop A (your own dev/partner store), replay
an authenticated request with `?shop=<Shop B you also own>.myshopify.com` — 200 + Shop B's data =
confirmed cross-tenant bypass. Never target a shop you don't own.

**Why unique:** most bounty hunters target Shopify's own platform (heavily saturated); this targets
third-party Shopify Partner apps built on this specific gem, which often run separate, less-hunted
bounty programs.

Source: https://intel.aikido.dev/cve/AIKIDO-2026-135231
