# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — vulns 2026-08-29
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-42533 — `map` directive heap buffer overflow (added 2026-08-29 research pass)
- Affects nginx 0.9.6–1.31.2 (Open Source) / equivalent Plus builds; fixed 1.31.3 mainline / 1.30.4 stable.
- Trigger: `map` block using regex matching with **unnamed/numbered captures** (`$1`/`$2`) referenced in a
  later string expression after capture state changes — crafted HTTP request overflows the allocated heap
  buffer. CVSS 9.2 (v4.0). Worker-crash DoS confirmed; RCE only if ASLR disabled/bypassed (unconfirmed PoC
  publicly as of this writing).
- **Not remotely fingerprintable beyond the nginx version header** — the vulnerable config pattern (regex
  `map` w/ unnamed captures) isn't visible unauth. Version-in-range (we've seen `nginx/1.29.7` on our own
  in-scope corpus) is a LEAD only, never a confirm.
- **Do not test** — the only trigger is a worker-crashing malformed request; this is destructive, not a
  safe primitive. Note the version exposure; don't fire it.
- Sources: nginx.org security advisories, https://socprime.com/blog/cve-2026-42533-analysis/, https://orca.security/resources/blog/cve-2026-42533-nginx-heap-buffer-overflow/
