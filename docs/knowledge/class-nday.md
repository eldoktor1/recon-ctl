# class-nday — n-day / KEV racing (version-reason the KEV FP away, be first in the race window)

> Reusable KB for the n-day lane (`recon_nday.sh`; feeds the shared `idor_worklist.jsonl` → 6:30
> briefing; EPSS/nuclei-template prioritisation via `recon_vuln_feed.sh` → `vuln_targets.jsonl`).
> READ before working a KEV/CVE match; APPEND when a new fresh-critical lands. Tech-specific version
> tables live in `tech-<stack>.md` (e.g. `tech-nginx.md`, `tech-wordpress.md`) — this is the general
> lane doctrine.

## The one rule everything reduces to
**A tech-class match is a LEAD, not a bug.** Most KEV/CVE matches are FPs because the *running
version* isn't actually in the vulnerable range, or the vuln is config-gated and the config can't be
confirmed unauth. The edge is the reasoning the crowd skips: given the detected tech/version, is this
host *plausibly in range*, is a public exploit out, and what is the single SAFEST unauth request that
confirms it — **right now, in the race window before everyone's templates catch up.**

CONFIRMED-vs-LEAD maps exactly:
- **LEAD** — product/tech-class match, or in-range version but config-gated / no safe confirm. Clamp
  to P1-max; goes to the worklist for the human to version-reason + dup-check + (maybe) exploit.
- **CONFIRMED** — a safe unauth probe returned the definitive in-range version/fingerprint (the model
  DESIGNS the probe; the trusted `recon_safe_probe.sh` harness RUNS it; Claude re-judges the real
  response). Only then does it mint a findings-DB entry → Claude VERIFY → "ready to submit".

## Version-gate discipline (the FP-kill)
1. **No version signal ⇒ `likely_vulnerable=false`.** A bare product-name match (Wappalyzer `tech:`
   field) with no version is an FP by default — do not treat it as more than noise.
2. **Absence of a version banner ≠ patched.** `server_tokens off` / stripped `X-Powered-By` = unknown
   version, not safe. Treat unbannered hosts as unknown, not clean.
3. **In-range version + config-gated vuln = LEAD, never P0.** nginx Rift (rewrite-config dependency),
   PHP-SOAP (endpoint must be public), HTTP/3 UAF (QUIC must be on) — the version alone can't confirm
   the config unauth. A genuine CONFIRMED needs a SAFE non-destructive differential, never a crash/RCE.
4. **CDN-fronted version results are meaningless** — Cloudflare/Akamai/Fastly answer with their own
   banner; the origin version behind them is unknown (see `tech-nginx.md` FP notes).
5. **LLM-returned CVE IDs can be hallucinated** — the research digests self-flag ⚠️; verify vs NVD/GHSA
   and the vendor advisory version range before minting. Same LEAD-not-P0 rule as every KEV match.

## Race-window reasoning (why speed matters, and how we stay safe doing it)
Fresh criticals with a public PoC have a short window where in-range hosts are un-hunted before the
crowd's nuclei templates catch up. The lane races that window: it PREPENDS the EPSS/nuclei-template
T0/T1 subset (`vuln_targets.jsonl` `best_vuln_tier`) so the highest-EV CVEs are version-reasoned first,
sorts the rest fresh-first + score, and dedups via `state/nday_seen.txt`. Speed NEVER relaxes safety —
every packet is unauth GET/HEAD/OPTIONS via `recon_safe_probe.sh` (no creds, no redirect-follow,
SSRF/metadata-guarded, scope+pays-gated, rate-limited, Mullvad-only). We NEVER auto-exploit — RCE/
traversal/cmd-inj chains are the operator's, human-in-the-loop, dup-checked first.

## Safe-probe-only rule (hard line)
- **Version confirm = recon, not attack.** A path that returns a version banner/string
  (`/wp-includes/version.php`, plugin `readme.txt` `Stable tag:`, `/status`, `Server:` header,
  `x-powered-by`) is fair game. Sending a crash/overflow/malformed payload to "confirm" is
  exploitation — forbidden autonomously.
- **Never send the exploit primitive to fingerprint.** e.g. do NOT send the nginx-Rift crafted `?`
  rewrite payload (crashes the worker), do NOT send malformed SOAP, do NOT exercise the miniOrange
  password-recovery bypass. Version/endpoint presence only; the chain is operator-authorized.
- **DoS-class n-days** (HTTP/2 bomb, HTTP/3 UAF) rarely pay and the trigger is destructive — stop at
  the version-detect LEAD; confirm the program pays infra/DoS n-days before investing.

## Current top n-days (as of 2026-07, version-gate before minting — verify vs NVD)
- **nginx "Rift" — CVE-2026-42945** (heap overflow, `ngx_http_rewrite_module`, CVSS 9.2, ITW-exploited).
  Vulnerable 0.6.27–1.30.0 (OSS) / Plus R32–R36; fixed 1.30.1 / 1.31.0. Our fingerprint corpus has an
  in-range `nginx/1.29.7`. **Config-gated** (unnamed PCRE capture `$1`/`$2` + `?` in replacement +
  chained `rewrite`/`if`/`set`) → version match = LEAD; DoS reliable across the range, RCE only w/o
  ASLR. Sibling `CVE-2026-9256` (2nd rewrite overflow, 0.1.17–1.31.0) is NOT closed by patching Rift.
  Newer wave `CVE-2026-42533` (`map` regex, fixed 1.30.4/1.31.3) also in-range for 1.29.7. Detect via
  `Server:` HEAD banner; version-only = LEAD. Full table: `tech-nginx.md`.
- **WordPress core "wp2shell" — CVE-2026-63030 + CVE-2026-60137** (REST batch-route confusion chained
  with SQLi → **unauth RCE**, PoC public, ITW-exploited per Rapid7/NetSPI). Full chain: WP **6.9.0–6.9.4
  / 7.0.0–7.0.1** (fixed 6.9.5 / 7.0.2); 6.8.0–6.8.5 = SQLi only. **Detect (unauth, safe):**
  `/wp-json/batch/v1` (or `?rest_route=/batch/v1`) presence = REST batch enabled; place the host in-range
  via core-version disclosure before treating as more than a LEAD. NEVER run the RCE chain autonomously.
- **WordPress miniOrange OAuth SSO — CVE-2026-57807** (auth-bypass in the password-recovery flow →
  unauth full site takeover, CVSS 9.8, **NO vendor patch** as of disclosure). Affected Enterprise
  ≤ 38.5.8 (free-branch applicability unconfirmed — verify per-instance). **Detect (unauth, safe):**
  `/wp-content/plugins/miniorange-oauth-2.0-single-sign-on/readme.txt` → `Stable tag`; also the injected
  SSO button/`miniorange` string in login-page JS (jsintel). No patched version exists ⇒ presence = in-
  range LEAD by default. The bypass is full account takeover — escalate per the hunt-flow authed/exploit
  gate before ANY live test; never auto-exercise.
- **WordPress-plugin n-day pass** (`recon_nday.sh` deterministic `readme.txt` `Stable tag` checks):
  updraftplus (CVE-2026-10795, unauth admin RCE, ≤1.26.4), wpvivid-backuprestore (CVE-2026-1357),
  kirki (CVE-2026-8206), user-registration (CVE-2026-1492/1779). In-range = strong LEAD; operator
  confirms + dup-checks + exploits (we NEVER auto-exploit RCE).
- **UniFi OS triple KEV — CVE-2026-34908/34909/34910** (unauth auth-bypass→traversal→cmd-inj, ITW,
  fixed OS Server 5.0.8). Confirm the OS-Server version (NOT the Network-App 8.x version) via `/status`
  or `/api/self`; exclude the `*.unifi-hosting.ui.com` shared tenants (third-party data, hard line).
- **PHP SOAP UAF RCE — CVE-2026-6722** (unauth when the SOAP endpoint is public; fixed 8.2.31/8.3.31/
  8.4.21/8.5.6). Endpoint-presence LEAD only; never send malformed SOAP.

## Lane design (actionable summary for recon_nday.sh)
1. **Pull** in-scope+paying assets with a KEV/breaking-vuln match (`triage_kev_*`), EPSS/template T0/T1
   prepended, fresh-first, `nday_seen`-deduped.
2. **Version-reason** each with Claude (schema-validated): likely in-range? public exploit? impact +
   confidence. `likely_vulnerable=false` on a bare product match.
3. **Design a safe probe** (`verify_probe`: path + GET/HEAD/OPTIONS + confirm_signal) — recon only.
4. **Harness runs it** (`recon_safe_probe.sh`) → Claude re-judges the REAL response → CONFIRMED (DB →
   VERIFY → briefing) or LEAD (worklist). Deterministic passes (WP-plugin / UniFi / nginx / SOAP) use
   the same safe-probe + version-compare, LEAD on config-gated, never auto-exploit.
5. **Note** the FP kills inline (tech-class-only, patched version, CDN-fronted) so they don't re-serve.

## Sources
- `docs/research/vulns_2026-07-*.md` (weekly Claude vuln digests — the fresh-CVE feed; self-flag ⚠️
  hallucinated CVE IDs → verify vs NVD/GHSA).
- `tech-nginx.md`, `tech-wordpress.md` (per-tech version tables + fingerprints).
- NVD / GHSA / vendor advisories (F5 K-articles, nginx.org security_advisories, Rapid7/Beazley).
- CLAUDE.md "Documented false-positive patterns" (KEV tech-class without confirmed in-range version).
