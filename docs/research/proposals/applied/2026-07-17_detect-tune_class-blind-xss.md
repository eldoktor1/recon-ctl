# PROPOSAL (proposal) for docs/knowledge/class-blind-xss.md — detect-tune 2026-07-17
_Review and apply manually; not auto-merged into the KB._

## Dalfox v3 (Rust rewrite) — tooling note, 2026-07-17
Dalfox v3.1.2 (2026-06-27) is a **complete rewrite in Rust**, restructured into subcommands
(`scan`/`server`/`payload`/`mcp`) — not a drop-in flag-compatible upgrade from v2's Go CLI. Before trusting
any "no XSS found" result from `recon_xss_confirm.sh` / `recon_blindxss.sh` / `recon_dast.sh`, confirm the
installed `dalfox` binary version and that its invocation still matches v3's subcommand syntax (v2 flags may
silently fail rather than error). v2 stays on the `v2` branch for security-only backports.
New precision knobs in v3: `--waf-min-confidence <0-1>` (default 0.3) tunes WAF-fingerprint confidence to cut
noisy evasion-attempt logging; native DOM/AST verification replaces pure blind-reflection matching for
DOM-XSS confirmation, which should reduce reflection-≠-execution false positives further.
