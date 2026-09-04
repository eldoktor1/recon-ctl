# PROPOSAL (proposal) for docs/knowledge/class-cdn-origin-bypass.md — tooling 2026-09-04
_Review and apply manually; not auto-merged into the KB._

## Second bypass path: CDN re-fronting (origin IP-allowlisted to the CDN's own IP range)
Some origins aren't directly reachable by IP even when found (item above) — they're firewalled to
accept traffic ONLY from their CDN provider's published IP ranges (a common "WAF bypass mitigation").
In that case the origin is still reachable by anyone who stands up their OWN distribution on the
SAME shared CDN network, since the origin's allowlist can't distinguish "the target's CDN
distribution" from "any distribution on that CDN." Tool: `RyanJarv/cdn-proxy`
(https://github.com/RyanJarv/cdn-proxy) — automates deploying an attacker-controlled CloudFront/
Cloudflare distribution pointed at the discovered origin, then requests transit it, bypassing the
target's WAF/security rules entirely (they only apply to the target's own distribution).
- **Precondition:** requires the origin IP already discovered (crt.sh/favicon-hash/grey-cloud, see
  above) AND confirmed inside a current CDN CIDR range (the "precision upgrade" section) — this is
  the path when direct-IP GET/HEAD is blocked by an IP allowlist rather than absent origin exposure.
- **Setup cost:** operator needs their own CloudFront distribution or Cloudflare zone (one-time,
  reusable across targets on the same CDN provider) — not daemon-safe, on-demand only.
- **Safety:** requests through the re-fronted distribution are still unauthenticated GET/HEAD/OPTIONS
  against the target's own origin — same PoC posture as the existing direct-IP verification primitive
  (prove reachability + WAF-bypass, never harvest data past that). In-scope+pays gate unchanged.
- **Reporting:** frame as "the WAF/CDN security layer is bypassable because the origin trusts any
  request from the CDN's shared IP pool rather than the specific distribution" — this is a stronger,
  more precise framing than "origin IP found" alone, since it demonstrates the actual security-layer
  bypass rather than just exposure.
