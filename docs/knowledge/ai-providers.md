# ai-providers — the pluggable AI-provider model

> How the pipeline's LLM brain is wired, and how to bring your own model.
> Claude is the fully-wired **default and only turnkey** provider; everything else is
> config-scaffolded, not turnkey. Be honest about that gap when you touch this.

## The short version

The pipeline's three AI roles — **ANALYZE** (aim the net), **VERIFY** (kill false positives),
and the **AI hunter** (BAC/IDOR reasoning) — all run on **Claude** via a **Max subscription**,
headless (`claude -p`), **no API key**. That's the turnkey path: log in on the box, enroll in CVP
(below), done.

A provider abstraction lets you point those roles at a different vendor's model. It is *scaffolding*:
the config surface exists, but only Claude is wired end-to-end (schema-validated structured output,
model-tiering by asset value, the consensus panel, safe-probe request/response mediation). Bringing
another model is a real integration effort, not a flag flip.

## Why every provider needs a cyber-verification program

This pipeline does authorized **offensive-security** work — vulnerability discovery, exploitation
reasoning, PoC construction. That is *dual-use*, and frontier models block it by default. To run at
**full capability** you need the vendor's authorized-use / cyber-verification credential:

- **Anthropic (Claude)** → **Cyber Verification Program (CVP)** — free, application-based; verifies
  legitimate security orgs and unblocks pen-testing, exploitation reasoning, and vuln research.
  Verification, not exemption (ransomware / mass-exfil stay blocked for everyone).
  Portal: <https://portal.anthropic.com/programs/cvp> ·
  Background: <https://www.anthropic.com/news/claude-code-security>.
- **Other vendors** (OpenAI, Google Gemini, etc.) each maintain their own trust/authorized-use
  or safety-review pathways for security use-cases. **You must obtain the equivalent credential for
  whichever provider you configure** — without it, that model will refuse or degrade on the exact
  offensive-security reasoning this pipeline depends on. This is the single biggest reason a non-Claude
  provider is "config-scaffolded, not turnkey": the capability gate is per-vendor and out-of-band.

## Config surface

The intended selection surface is environment-variable driven, layered on top of the existing
per-role model overrides:

| Env var | Role | Default |
|---|---|---|
| `AI_PROVIDER` | Which provider backend to use (`claude` \| `openai` \| `gemini` \| …) | `claude` |
| `CLAUDE_ANALYZE_MODEL` | ANALYZE model (bulk triage) | Haiku-class |
| `CLAUDE_MODEL` | VERIFY model | Sonnet-class |
| `CLAUDE_ESCALATE_MODEL` | `needs-human` escalation | Opus-class |

For `AI_PROVIDER=claude` (default) no API key is used — auth is the Max-subscription OAuth login
(`claude` → `/login`). **Never pass `--bare`** (it forces API-key auth and bypasses the Max login).

A non-Claude provider additionally needs its own credential/endpoint config (e.g. an API key file
under `~/.recon_<provider>_key`, chmod 600, gitignored like every other secret) — mirror the
existing secret-hygiene rules in `SECURITY.md`.

## Extension shape

To wire a new provider you implement the same contract Claude already satisfies:

1. **Invocation** — take a prompt + a JSON schema, return schema-validated structured output.
   Unparseable output MUST fall back to a safe `needs-human` verdict (never fabricate a `real`).
2. **Model tiering** — a cheap bulk tier for ANALYZE, a stronger tier for VERIFY, an escalation
   tier for ambiguity.
3. **Safe-probe mediation (hard line)** — the model **requests** probes (`verdict="need-probe"` +
   `probe_requests`); the *trusted harness* runs them via `recon_safe_probe.sh` and re-judges. The
   model gets **no shell / no exec** — this is a security invariant, not a Claude quirk. Any provider
   backend must preserve it: the LLM only ever emits requests; the harness mediates every packet.
4. **Capability gate** — document (and the operator must hold) the vendor's cyber-verification
   credential, or the offensive-reasoning roles will silently degrade.

## Honest status

- **Claude + CVP** — turnkey, fully wired, the supported path. Use this.
- **Everything else** — the `AI_PROVIDER` seam and this document exist so the pipeline isn't
  Claude-locked in principle, but a second provider is a build, and its capability depends entirely
  on that vendor's authorized-use program. Don't advertise it as plug-and-play.

## Sources

- Anthropic CVP portal — <https://portal.anthropic.com/programs/cvp>
- Anthropic, "Making frontier cybersecurity capabilities available to defenders" —
  <https://www.anthropic.com/news/claude-code-security>
