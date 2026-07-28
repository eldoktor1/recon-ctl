# PROPOSAL (proposal) for docs/knowledge/class-takeover.md — detect-tune 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## Non-classic SaaS provider fingerprints (addendum, 2026-07-28)
| Provider | CNAME pattern | Fingerprint | Claim |
|---|---|---|---|
| Vercel | `cname.vercel-dns.com` | `"DEPLOYMENT_NOT_FOUND"` + `x-vercel-id` header | bind orphaned hostname to attacker's Vercel project |
| Netlify | `*.netlify.app`/`*.netlify.com` | `"Not Found - Request ID:"` + `x-served-by: cache-...netlify` | bind Netlify site to hostname |
| Webflow | `proxy.webflow.com`/`proxy-ssl.webflow.com` | `"The page you are looking for doesn't exist"` | bind new Webflow project (2023 patches narrowed but didn't eliminate) |
| Tilda | `*.tilda.ws` | `"Please renew your subscription"` / `"Domain has been assigned"` | re-bind after subscription lapse |
| Pantheon | `*.pantheonsite.io` | `"The gods are wise, but do not know of the site which you seek."` | bind Pantheon site to hostname |

CNAME+fingerprint match = LEAD only; still requires provider-specific unclaimed-state proof before CONFIRMED, same as the existing Heroku/Azure/S3 primitives.
Source: https://www.vulnsy.com/cheat-sheets/subdomain-takeover
