# PROPOSAL (proposal) for docs/knowledge/tech-spring-boot-actuator.md — kb-enrich 2026-08-23
_Review and apply manually; not auto-merged into the KB._

## Actuator path-prefix auth-bypass CVEs (added 2026-08-23)

Distinct bug class from CVE-2026-40976 (see CVE-2026-40976.yaml) — not a dependency-state bug,
but Spring Boot applying Actuator's permit-all policy to an *application* endpoint that happens
to be path-nested under an Actuator infrastructure prefix. Requires a specific app config
(rare, but the version range is wide) — treat any match as a LEAD needing live confirmation,
never an auto-mint on version alone.

### CVE-2026-22733 — CloudFoundry path bypass
- Condition: app declares an authenticated endpoint under `/cloudfoundryapplication/<subpath>`
  (the CloudFoundry Actuator discovery prefix).
- Affected: Spring Boot 4.0.0-4.0.3, 3.5.0-3.5.11, 3.4.0-3.4.14, 3.3.0-3.3.17, 2.7.31 and earlier.
- Fixed: 4.0.4 / 3.5.12 (OSS); 3.4.15 / 3.3.18 / 2.7.32 (enterprise support only).
- Confirm primitive (safe, unauth GET): request common app-shaped subpaths
  (`/admin`, `/users`, `/settings`, `/config`) appended under `/cloudfoundryapplication/`.
  A 200/data response where the same path returns 401/403 at its normal root = bypass firing.

### CVE-2026-22731 — Health-group additional-path bypass
- Condition: `management.endpoint.health.group.<name>.additional-path=server:/<path>` is
  configured AND an authenticated app endpoint lives under that same subpath
  (e.g. `/healthz/admin` when the health group's additional-path is `/healthz`).
- Affected: Spring Boot 4.0.0-4.0.3, 3.5.0-3.5.11, 3.4.0-3.4.14.
- Fixed: 4.0.4 / 3.5.12 / 3.4.15.
- Confirm primitive: discover any custom health-group additional-path (via `/actuator/health`
  group listing or config leak from `/actuator/env` if already reachable), then probe
  app-shaped subpaths under it the same way as above.

Both fit as a second bypass mode in `recon_actuator_chain.py` alongside the existing
CVE-2026-40976 version-gate — same read-only GET confirm discipline, no state-changing probes.

Sources: spring.io/security/cve-2026-22733, spring.io/security/cve-2026-22731,
herodevs.com/blog-posts/spring-boot-authentication-bypass-two-new-cves-...
