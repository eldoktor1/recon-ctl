# PROPOSAL (proposal) for docs/knowledge/class-takeover.md — detect-tune 2026-09-06
_Review and apply manually; not auto-merged into the KB._

## Fingerprint/FP refresh (2026-09-06)

- **AWS Elastic Beanstalk (new primitive)**: CNAME → `<env>.<region>.elasticbeanstalk.com` that
  resolves to **NXDOMAIN** = the environment name is unclaimed in that region and can be
  re-registered by anyone with an AWS account → `takeover:confirmed`-eligible once NXDOMAIN is
  verified (same NXDOMAIN-first discipline as every other provider in this doc). High relevance —
  AWS is our #1 in-scope tech by volume.
- **WordPress.com fingerprint now over-fires (FP update)**: the classic string
  `Do you want to register .*.wordpress.com?` still appears on an unclaimed subdomain, but actually
  claiming it now additionally requires a **domain-authorization code from the target domain's
  registrar** (not just a paid WP.com plan as before). A CNAME hitting this fingerprint is a
  `takeover:cname-lead` at most — do NOT auto-promote to confirmed without checking whether the
  registrar-auth-code step is actually satisfiable (it usually isn't, since we don't own the
  target's registrar account) — this is now closer to a dead-end than a real claim path.
- Minor additions, lower priority (no overlap with our top in-scope tech): `readthedocs.io` →
  `"The link you have followed or the URL that you entered does not exist."`; `agilecrm.com` →
  `"Sorry, this page is no longer available."`; `tilda.cc` → `"Please renew your subscription"`
  (verify manually — can also mean an active-but-lapsed tenant, not unclaimed).
