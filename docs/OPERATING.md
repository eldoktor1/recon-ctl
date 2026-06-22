# OPERATING — the one page. Read this when lost.

This is the source of truth for how we hunt. When in doubt, this page wins over any
research pile. Methodology depth lives in `docs/knowledge/class-unauth-hunting.md`
(unauth) and the private-program plan in `~/recon/state/private_programs/scopes.md` (authed).

## The doctrine: WIDE EYES, NARROW HANDS

The fear of missing out is the bug. A wide net catches trash; that's why 22 reports
returned 0 paid. We don't win by missing nothing — we win by deliberately ignoring 95%
and going deep on a tiny, confirmed set.

- **Wide eyes:** the machine watches ALL surface 24/7 (fresh-CT + wildcard enum). We miss
  nothing on the INPUT side.
- **Narrow hands:** only a finding that already **fired a confirm primitive** reaches your
  eyes. Everything else is logged to a backlog you never open. The FP problem disappears
  structurally — you're not filtering a noisy net, you replaced it.

## GREEN-LIGHT DOCTRINE — in-scope + pays = test anything (operator 2026-06-21; ALL agents)
"Narrow hands" is about what's WORTH your time, NOT about hesitating to test. On a host that is
in-scope + authorized + pays, the answer is **just YES**: build the PoC, hand the probe, drive the
test, run the tooling — no hedging. We test only authorized scope, to report; that's the job, not an
attack. The ONLY thing that changes the answer is genuinely malicious intent (harm/destroy/steal-and-sell),
which we don't do. Over-caution on authorized scope is a bug that cost a week. Methodology (IDOR = 2 owned
accounts, confirm-then-stop, no third-party data/IDs, no money movement, no destruction) is how a test is
done RIGHT, not a guard on whether to test. Applies to every agent (main, 2IC, hunt, CinC, subagents).
See CLAUDE.md "Hard line: recon vs attack" + memory feedback_dont_obstruct_authorized_testing.

**Detection ≠ exploitation.** A 200, a reflection, a version banner, a token-shaped string
are NOT findings. The gate promotes only at **0.85 confidence** (high/critical fire);
"medium" stays a logged LEAD.

## Focus: UNAUTHENTICATED, high-severity

Unauth is the only severity class the machine can take from detection → submittable WITHOUT
your accounts — so it earns while you're at work, and it's higher-severity (network-reachable,
no privileges) = higher pay. WIDE unauth scanning is dead (the dup flood); NARROW unauth wins:
**fresh surface + the classes templates miss + a real confirm.**

## The 6 plays (everything else is ignored on purpose)

The machine confirms these while you're at work → **SUBMIT** pile:
1. **Shadow-endpoint unauth data exposure** — no-auth 200 returning real sensitive data
   (not the SPA shell). Most machine-confirmable high-sev play.
2. **Exposed secrets / services / takeover / buckets** — live-validated, not public-by-design,
   not a login wall, takeover claimability-confirmed.
3. **n-day (straight-shot unauth-RCE subset)** — version-in-range confirmed, inside the
   1–7 day race window. You sanity-check before firing.
4. **Reflected XSS / unauth SQLi** — the confirmer must FIRE (dalfox EXECUTES a marker /
   SQLi `'`-vs-`''` differential), never reflection-only. Highest dup-risk class, so it's
   dup-managed by the rs0n ranker (unique-first, skip product-class, fresh-first) and
   impact-gated (theoretical/encoded reflection = N/A). Already running autonomously.

You hunt these in the evening (the machine surfaces fresh candidates) → **DIG** pile:
5. **SSRF (hidden sinks)** — OOB-confirmed by the machine, you escalate to metadata/RCE.
6. **Request smuggling / cache poisoning / auth-bypass** — pure skill, near-zero dup.

If a thing isn't one of these six, the system does not surface it. That sentence is the
whole anti-FOMO discipline. (Full real-vs-FP discriminators per play: the KB.)

## The week

| Day | Mode | What you do |
|---|---|---|
| **Mon / Tue / Wed** | **Unauth** | 20 min: review + submit the SUBMIT pile. Rest: ONE DIG lead (SSRF / smuggling) on a fresh host. |
| **Thu / Sat** | **Authed / Private** | ENGIE DCP greybox BOLA — your 2 accounts, the swap playbook. Highest pay, lowest dup. |
| **Fri** | **Cleanup** | Finish/submit any half-done report. Learn ONE technique (an SSRF / smuggling writeup). |
| **Sun** | **Off** | Rest. The machine keeps watching. |

The machine runs all 7 days. The schedule only changes what the nightly card EMPHASIZES
(see the 2IC routine `mode`), never the rigor.

## Monday-morning runbook

1. Open tonight's card (`~/recon/briefings/` + Discord #digest).
2. **SUBMIT** section: each item already fired a confirm primitive — verify the PoC screenshot,
   submit. 5 quality > 50 FP. Honest severity (overclaim → N/A → dinged signal).
3. **DIG** section: pick ONE fresh-host lead and go deep (the 80%).
4. On authed days: open the ENGIE DCP swap playbook instead.
5. Never re-walk a noted/closed host. The card flags 📝 already-worked.

## Where things live

- **Nightly card:** `recon_briefing.sh` → `~/recon/briefings/tonight_<date>.md` + #digest.
- **The brain (curation):** 2IC routine `~/.claude/scheduled-tasks/2ic-nightly-recon/SKILL.md`.
- **Confirm gate:** `scripts/recon_evidence_gate.sh` (`GATE_PROMOTE_CONF=0.85`).
- **Safe probe (autonomous, read-only):** `scripts/recon_safe_probe.sh`.
- **Unauth methodology:** `docs/knowledge/class-unauth-hunting.md`.
- **Private/authed plan:** `~/recon/state/private_programs/scopes.md`.
- **Submission ledger (dedup):** `~/.recon_submissions.jsonl`.

## Hard lines (never crossed)

Recon confirms exposure EXISTS — never exploit past it, never harvest data, never enumerate
IDs that aren't yours, never bypass a login to get in, no autonomous RCE. SSRF/n-day
escalation is operator-overseen + minimal. Mullvad is sole egress (fail-closed on vpn_down).
Never touch VPN/nftables.
