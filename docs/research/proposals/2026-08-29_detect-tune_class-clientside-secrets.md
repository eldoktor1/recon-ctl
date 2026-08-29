# PROPOSAL (proposal) for docs/knowledge/class-clientside-secrets.md — detect-tune 2026-08-29
_Review and apply manually; not auto-merged into the KB._

## Public-by-design key shapes to exclude (added 2026-08-29)
Three more browser-shipped key shapes should join `PUBLIC_BY_DESIGN` in `engine/impact.py` (currently:
Stripe `pk_`, Firebase web config, Supabase anon, `NEXT_PUBLIC_`/`REACT_APP_PUBLIC_`/`VITE_PUBLIC_`,
OAuth `client_id`):

- **Sentry DSN** — `https://<32-hex>@<org>.ingest.sentry(.us)?.io/<project_id>`. Public by design: only
  allows submitting new error events, no read access to project data. Regex hint: `https://[0-9a-f]{32}@`.
- **Algolia search-only API key** — public by design when paired with a public `appId` in
  `algoliasearch(appId, searchKey)`. Do **not** blanket-exclude all Algolia key-shaped strings — the
  Algolia *admin* key is a real, high-value secret (39 leaked via DocSearch configs found in 2026:
  https://news.ycombinator.com/item?id=47371064). Only exclude when explicit context (`searchOnlyApiKey`,
  `search-only`, or paired `appId`+`algoliasearch(` init) confirms the search-only variant.
  Source: https://support.algolia.com/hc/en-us/articles/18966776061329
- **Segment analytics write key** — required client-side for `analytics.js`/`analytics-react-native`;
  ships in page source by design (same class as GA/GTM/Mixpanel/HubSpot/Marketo tracking IDs). Context
  hint: near `analytics.load(`/`writeKey`/`segment.com`. Source:
  https://www.twilio.com/docs/segment/connections/sources/catalog/libraries/website/javascript/faq
