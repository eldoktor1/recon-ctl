# PROPOSAL (proposal) for docs/knowledge/class-ssrf.md — kb-enrich 2026-09-03
_Review and apply manually; not auto-merged into the KB._

## Cloud-metadata filter bypasses — added 2026-09-03

**DNS-rebinding TOCTOU bypass (generalizable — CVE-2026-27127 is the reference case, not the
only instance):** the anti-pattern is an SSRF guard that resolves the target hostname once to
validate it's not a metadata/private IP, then a SEPARATE resolver/connection performs the
actual fetch. An attacker-controlled domain with a short TTL answers with a public IP at
validation time and `169.254.169.254` (or an internal IP) at fetch time, defeating an
IP-allowlist check that looks correct in code review. Test any app-level SSRF "protection"
that validates a hostname rather than the socket it actually connects to — a rebinding domain
(services like `rbndr.us`, or a controlled DNS record with TTL=0) is the safe, OOB-canary-style
test consistent with our SSRF confirm primitive (still route the actual callback through
interactsh, not a metadata read).

**IMDSv2 is necessary but not sufficient:** if the SSRF primitive lets the attacker control
HTTP method AND set arbitrary headers (not just a URL), the full IMDSv2 PUT-token handshake
can be replayed end-to-end through the SSRF, so "target enforces IMDSv2" does not by itself
close an SSRF finding — check whether the primitive constrains method/headers before
downgrading severity.

**AWS Bedrock AgentCore Runtime MMDS gap (Unit 42, 2025):** Bedrock's microVM Metadata Service
(MMDS, the IMDS-equivalent for Bedrock agent runtimes) did not enforce IMDSv2-style session
tokens — plain unauthenticated SSRF from inside an agent runtime could read MMDS credentials.
Relevant if a target exposes a Bedrock-agent-backed endpoint; worth a dedicated fingerprint if
Bedrock-hosted infra shows up in our in-scope tech data.

Sources: github.com/advisories/GHSA-gp2f-7wcm-5fhx, appsecure.security/blog/ssrf-cloud-environments
