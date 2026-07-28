# Research digest — detect-tune — 2026-07-28

# Detection & Verification Tuning — Digest (2026-07-28, second pass)

## 1. Origin-IP discovery turns our suppressed "CDN-fronted critical port" signal into a real, payable WAF-bypass finding (HIGH PRIORITY, actionable now)

Our current doctrine (`CLAUDE.md` FP list) treats *any* critical port behind a CDN as noise ("CDNs ACK every port"). That's correct as a blind heuristic, but it throws away a genuinely payable bug class: **WAF/CDN bypass via exposed origin IP** — confirmed real report pattern (e.g. [SMTP2GO H1 #1536299 — "Origin IP found, WAF Cloudflare Bypass"](https://hackerone.com/reports/1536299)). If we can independently *find* the real origin IP and prove the app is directly reachable there (bypassing Cloudflare/Akamai/Fastly/CloudFront), the "meaningless" port scan becomes a confirmed, reportable exposure.

**Discovery techniques** (all passive/OSINT, no target traffic, safe to run as `d0k` like our other research/enum steps — [Intigriti: Identifying a server's origin IP](https://www.intigriti.com/researchers/blog/hacking-tools/identifying-servers-origin-ip)):
- **crt.sh / CT history** (we already pull CT) — certs issued *before* CDN adoption, or SANs listing raw IPs/internal hostnames, often survive in the log even after the CDN migration.
- **Favicon-hash pivot**: `curl -s '<url>/favicon.ico' | base64 | python3 -c 'import mmh3,sys;print(mmh3.hash(sys.stdin.buffer.read()))'` → Shodan `http.favicon.hash:<hash>` (budget-gated per our Shodan cap) or Censys favicon match — surfaces non-CDN hosts serving the identical app.
- **Grey-cloud subdomains**: subfinder/CT output that resolves to a non-CDN IP (an unproxied `dev`/`staging`/`mail`/`direct` label) is frequently the same origin as the proxied apex.
- **Email headers**: any app email we trigger via our own test account (password reset, notification) has `Received:` headers — legitimate under our existing own-account PoC doctrine.
- **Unique-string dork**: footer/copyright string or a custom header value as a Shodan/Censys `services.http.response.body:` query to find the string served off-CDN.

**Verification primitive (the part that matters for precision):** a candidate IP is NOT confirmed just by being non-CDN — send a direct GET/HEAD to the candidate IP with `Host: <target-domain>` (unauthenticated, our existing `recon_safe_probe.sh` primitive, just pointed at an IP instead of the hostname) and diff the response body/title against the real site. Match = confirmed origin; CloudFlair's own verification loop does exactly this (reject 404/timeout candidates, confirm on identical HTML — [christophetd/CloudFlair](https://github.com/christophetd/CloudFlair)). This is a same-class primitive to our existing safe-probe gate — no new safety review needed, just a new target selection (candidate IP, Host header spoof) inside the same GET/HEAD/OPTIONS-only, scope+pays-gated harness.

**Precision upgrade for the existing FP filter:** replace the "6+ open critical ports = scan artifact" heuristic with an actual CDN-range membership check. Daily-updated CIDR datasets exist for exactly this (Cloudflare's own [official IP list](https://www.cloudflare.com/ips/), plus aggregated multi-provider feeds — [rezmoss/cloud-provider-ip-addresses](https://github.com/rezmoss/cloud-provider-ip-addresses) (60+ providers incl. Cloudflare/Fastly/CloudFront/Akamai, JSON+CIDR, daily refresh), [mansourjabin/cdn-ip-database](https://github.com/mansourjabin/cdn-ip-database)). A portscan result is only a scan-artifact if the scanned IP is *actually inside* a current CDN CIDR block — check membership directly instead of counting ports. Any host whose portscan IP resolves OUTSIDE all known CDN ranges keeps its critical-port signal as real.

**Net effect:** hosts we currently blanket-suppress as "CDN-fronted, ignore" become a two-step lane: (1) CDN-range-confirm the scanned IP really is CDN, (2) if so, run the origin-IP discovery above — a hit converts a dead lead into a confirmable WAF-bypass finding. This is dup-resistant (requires OSINT effort most hunters skip) and fits the MOTTO directly.



---

No other new detect-tune items cleared the bar this run — checked GraphQL bypass techniques, dalfox tuning, subdomain-takeover fingerprints (`can-i-take-over-xyz`), and nuclei-templates FP-reduction PRs against the last 30 days of digests; all already covered or too incremental to action (nuclei's recent FP fixes were template-specific PRs for panels/CVEs not in our top-tech list).
