# PROPOSAL (proposal) for docs/knowledge/tech-php.md — vulns 2026-08-16
_Review and apply manually; not auto-merged into the KB._

## PHP 8.5.9 / 8.4.24 / 8.3.33 / 8.2.33 security release (2026-08-03) — 4 CVEs
- CVE-2026-17543: ext-pgsql SQLi (`pg_insert/update/select/delete`, backslash-escaping bug in
  `E'...'` literals) — only relevant to Postgres-backed PHP apps.
- CVE-2026-17544: bcmath `bccomp()` OOB write, CVSS 9.8 — needs an app path that calls `bccomp()`
  with attacker input (decimal/money-math endpoints); PHP 8.4.0-8.4.23 / 8.5.0-8.5.8.
- CVE-2026-7260: Phar recursive-symlink crash (DoS, phar-handling apps only).
- CVE-2026-9672: bundled libgd memory corruption (image-upload/GD-processing apps).
- All four are function-call-gated, not remotely fingerprintable beyond the PHP version banner
  (`X-Powered-By`, often suppressed) — pair version-in-range with a functional-surface signal
  (Postgres/bcmath/phar/image-upload) before treating as more than tech-class LEAD.
- Source: https://www.linuxcompatible.org/story/php-8333-and-8424-released-critical-security-fixes-for-pgsql-sqli-and-bcmath-memory-corruption/ (added 2026-08-16)
