# PROPOSAL (proposal) for docs/knowledge/class-xss.md — detect-tune 2026-09-05
_Review and apply manually; not auto-merged into the KB._

## Dalfox version floor (added 2026-09-05)
Confirm the dalfox binary used by `recon-params confirm xss` / `recon_blindxss.sh` is **≥3.2.1**: that
release fixed a false-negative bug where framework error pages caused dalfox to miss genuinely-executing
payloads (not just a noise fix — it was under-reporting real XSS). v3.2.2 (2026-08-31) added WAF
fingerprints for Wallarm/NAXSI/SafeLine, useful context when classifying a block during confirm.
Source: https://github.com/hahwul/dalfox/releases
