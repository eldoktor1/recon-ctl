# CDN/WAF Bypass via Exposed Origin IP

## Why this matters
Our own FP doctrine correctly kills "critical port behind a CDN" as noise (CDNs ACK every
port). But that heuristic throws away a real, payable class: if the TRUE origin server is
independently discoverable and directly reachable, the CDN/WAF in front of it is bypassable
— disclosed real-world example: SMTP2GO H1 #1536299, "Origin IP found, WAF Cloudflare
Bypass" (https://hackerone.com/reports/1536299).

## Discovery techniques (passive/OSINT — run as `d0k`, no target traffic)
- **crt.sh / CT log history** — certs predating CDN migration, or SANs listing raw IPs /
  internal hostnames.
- **Favicon-hash pivot** — `curl -s '<url>/favicon.ico' | base64 | python3 -c
  'import mmh3,sys;print(mmh3.hash(sys.stdin.buffer.read()))'` → Shodan
  `http.favicon.hash:<hash>` (Shodan-budget gated, see reference_api_credit_budget) or
  Censys favicon match. Surfaces non-CDN hosts serving the identical app/panel.
- **Grey-cloud subdomains** — subfinder/CT hosts that resolve OUTSIDE current CDN CIDR
  ranges (see below) are candidate origins, esp. `dev`/`staging`/`direct`/`mail` labels.
- **Own-account email headers** — trigger a password-reset/notification on our OWN test
  account; `Received:` headers often leak the sending origin (fits active-PoC doctrine,
  own-account only).
- **Unique-string dork** — footer/copyright string or a distinctive custom response header
  as a Shodan/Censys `services.http.response.body:"<string>"` query.

## Verification primitive (SAFE — same class as recon_safe_probe.sh)
A candidate IP is confirmed origin ONLY if a direct unauthenticated GET/HEAD to that IP,
with `Host: <target-domain>` spoofed in the request, returns a body/title MATCHING the real
site (not a 404/timeout/different app — mirrors CloudFlair's verification loop:
https://github.com/christophetd/CloudFlair). This is GET/HEAD/OPTIONS-only, unauthenticated,
no different from our existing safe-probe primitive — just aimed at an IP instead of a
hostname, still scope+pays-gated and rate-limited.

## Precision upgrade: CDN-range membership check (replaces the ">6 open ports" heuristic)
Don't count ports — check whether the scanned IP is INSIDE a current CDN CIDR block.
Daily-updated sources:
- Cloudflare official: https://www.cloudflare.com/ips/
- Multi-provider aggregate (60+ providers incl. Cloudflare/Fastly/CloudFront/Akamai, JSON+CIDR,
  daily refresh): https://github.com/rezmoss/cloud-provider-ip-addresses
- https://github.com/mansourjabin/cdn-ip-database

If the scanned IP is OUTSIDE all current CDN ranges, the critical-port signal is real and
should NOT be auto-suppressed. If it IS inside a CDN range, don't stop there — run the
origin-IP discovery techniques above before writing the host off; a hit reopens it as a
confirmable WAF-bypass finding rather than dead noise.

## Reporting notes
- Lead with the accurate framing: "WAF/CDN can be bypassed by connecting directly to the
  origin server at <IP>, exposing <specific service/port>" — not a generic port-scan claim.
- PoC = the direct-connect response proving the app/service is reachable without transiting
  the CDN/WAF (matches PoC-OR-GTFO doctrine: prove it, don't hand-wave).
- Still gated on in-scope + pays per-asset, same as every other lane.
