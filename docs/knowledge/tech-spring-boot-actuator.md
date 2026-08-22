# Spring Boot Actuator — detection & confirm-chain notes

## CVE-2026-40976 (CVSS 9.1, unauth actuator authz bypass, Spring Boot 4.0.0–4.0.5, fixed 4.0.6)
Default web security filter chain silently fails to enforce authorization on Actuator when: servlet-based
app + no custom Spring Security config + depends on `spring-boot-actuator-autoconfigure` + does NOT depend
on `spring-boot-health`. All actuator endpoints (`/env`, `/heapdump`, `/configprops`, etc.) become
network-reachable with no auth.

### Value-redaction changed in 4.0 — re-prioritize which endpoint to chain
- **Spring Boot 4.0.x**: the default `Sanitizer` masks **every** `/actuator/env` property value to `******`
  regardless of key name (previously only known-sensitive key *names* were redacted). A hit here now proves
  only config-key/structure disclosure, not credential recovery — do not mint CONFIRMED credential-recovery
  off `/env` alone for a 4.0.x host.
- **Pre-4.0 Spring Boot**: `/env` still uses named-key redaction only — non-obviously-named secrets (custom
  property names) can still leak real values. Keep the existing chain logic for <4.0 hosts.
- **`/actuator/heapdump` is NOT sanitized in either version** — it's an HPROF memory dump and is the
  highest-value/only-reliable endpoint for real credential recovery on 4.0.x. Prioritize heapdump retrieval
  + extraction over env-parsing when the target is confirmed Spring Boot 4.0.0–4.0.5.

### Heapdump credential extraction (read-only, `--only-verified`-style targeted search over extracted strings)
Rather than blind-grepping the binary, search for known credential shapes:
- `AKIA` → AWS access key ID prefix (pair with adjacent 40-char secret-shaped string)
- `ey` → JWT prefix (validate as 3 dot-separated base64url segments before treating as a hit)
- `jdbc:`, `postgres://`, `mongodb://` → DB connection strings (often carry inline user:pass)
Tooling used in the wild: VisualVM Memory Analyzer + OQL (`select s from java.lang.String s where
s.toString().contains("AKIA")`) — a SQL-like query interface purpose-built for exactly this string-scan
over heap objects; more precise than a flat strings-dump grep for a huge HPROF.

Sources: spring.io/security/cve-2026-40976, github.com/vulnerability-lookup/vulnerability-lookup#379,
herodevs.com/blog-posts/cve-2026-40976-spring-boot-4-0-actuator-authorization-bypass,
a6z.co/exploiting-exposed-spring-boot-heapdump-endpoint
