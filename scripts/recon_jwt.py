#!/usr/bin/env python3
"""
recon_jwt.py — JWTs signed with a guessable secret. Proof is a token we can forge.

An HS256 token is only as strong as the string used to sign it, and applications ship with
`secret`, `changeme`, the framework default, or the project name more often than anyone
expects. When the secret falls, the finding is not "weak crypto" — it is **authentication
bypass**: we can mint a token for any user or role the application will accept.

The properties that make it right for an unattended lane:

  * THE CRACK IS OFFLINE. Once a token has been observed, breaking it involves no contact
    with the target at all. Hours of hashcat cost the target nothing and cannot be detected,
    rate-limited or blocked.
  * The proof is self-evident. Either a candidate secret reproduces the signature or it does
    not. There is no judgement, so there is nothing to get wrong.
  * It is under-hunted because it is unglamorous — everyone checks `alg:none`, far fewer
    actually run a wordlist.

    harvest tokens -> filter to HS* -> crack offline -> forge -> report

HARD LINES
  * We NEVER send a forged token to the target. Demonstrating that a valid signature can be
    produced is the whole finding; using it to access an account would be exploitation and is
    the operator's call with their own account, never the daemon's.
  * Expired or clearly-test tokens are still reported if the secret is weak — the secret is
    the vulnerability, not the token.
  * Tokens are stored redacted. We keep the header and claim NAMES, never a usable token.
"""
from __future__ import annotations

import argparse
import base64
import glob
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

BASE_DIR = os.environ.get("BASE_DIR", os.path.expanduser("~/recon"))
STATE_DIR = os.environ.get("STATE_DIR", os.path.join(BASE_DIR, "state"))
REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCOPE_CHECK = os.path.join(REPO_DIR, "scripts", "recon_scope_check.sh")
AUDIT = os.path.join(STATE_DIR, "jwt_audit.jsonl")
OUT_DIR = os.path.join(BASE_DIR, "jwt")

JWT_RX = re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}")

# Secrets that appear in tutorials, framework defaults and abandoned .env files.
BUILTIN_WORDS = [
    "secret", "Secret", "SECRET", "jwtsecret", "jwt_secret", "JWT_SECRET", "mysecret",
    "changeme", "change_me", "password", "Password1", "admin", "test", "dev", "development",
    "production", "staging", "key", "private", "privatekey", "supersecret", "super_secret",
    "topsecret", "letmein", "qwerty", "123456", "1234567890", "secretkey", "secret_key",
    "your-256-bit-secret", "your_jwt_secret", "my-super-secret", "shhhhh", "s3cr3t",
    "keyboard cat", "SuperSecretKey", "default", "example", "token", "auth", "authsecret",
    "HS256", "jwtkey", "app_secret", "appsecret", "clientsecret", "client_secret",
]


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(m: str) -> None:
    print(f"[jwt] {m}", file=sys.stderr, flush=True)


def audit(rec: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    rec.setdefault("at", utc())
    with open(AUDIT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def parse(tok: str) -> dict | None:
    try:
        h, p, sig = tok.split(".")
        hdr = json.loads(b64d(h))
        pay = json.loads(b64d(p))
    except Exception:
        return None
    return {"token": tok, "header": hdr, "payload": pay, "alg": (hdr.get("alg") or "").upper(),
            "signing_input": f"{h}.{p}".encode(), "sig": b64d(sig)}


def redact(tok: str) -> str:
    h, p, s = tok.split(".")
    return f"{h[:12]}….{p[:12]}….{s[:8]}… (len={len(tok)})"


def verify(secret: bytes, j: dict) -> bool:
    alg = j["alg"]
    fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    if not fn:
        return False
    return hmac.compare_digest(hmac.new(secret, j["signing_input"], fn).digest(), j["sig"])


def wordlist() -> list[bytes]:
    words = [w.encode() for w in BUILTIN_WORDS]
    rock = "/usr/share/wordlists/rockyou.txt"
    rockgz = rock + ".gz"
    if os.path.exists(rock):
        try:
            with open(rock, "rb") as f:
                for i, line in enumerate(f):
                    if i >= 200_000:
                        break
                    words.append(line.strip())
        except Exception:
            pass
    elif os.path.exists(rockgz):
        try:
            import gzip
            with gzip.open(rockgz, "rb") as f:
                for i, line in enumerate(f):
                    if i >= 200_000:
                        break
                    words.append(line.strip())
        except Exception:
            pass
    seen, out = set(), []
    for w in words:
        if w and w not in seen:
            seen.add(w)
            out.append(w)
    return out


def crack(j: dict, words: list[bytes], project_words: list[str]) -> bytes | None:
    # Project-specific guesses first — the app's own name is a common "secret".
    for pw in project_words:
        for cand in (pw, pw + "secret", pw + "_secret", pw + "-jwt", pw + "123"):
            c = cand.encode()
            if verify(c, j):
                return c
    for w in words:
        if verify(w, j):
            return w
    return None


def harvest_tokens(paths: list[str], inline: list[str]) -> dict[str, list[str]]:
    """token -> the sources it was seen in."""
    found: dict[str, set[str]] = {}
    for t in inline:
        found.setdefault(t.strip(), set()).add("cli")
    for pat in paths:
        for p in glob.glob(os.path.expanduser(pat)):
            if not os.path.isfile(p):
                continue
            try:
                if os.path.getsize(p) > 400 * 1024 * 1024:
                    continue
                with open(p, "rb") as f:
                    blob = f.read(200 * 1024 * 1024)
            except Exception:
                continue
            for m in JWT_RX.finditer(blob):
                found.setdefault(m.group(0).decode(), set()).add(os.path.basename(p))
    return {k: sorted(v) for k, v in found.items()}


def scope_of(j: dict, sources: list[str]) -> tuple[str, str]:
    """Best-effort: an issuer or audience claim usually names the host."""
    cand = []
    for k in ("iss", "aud", "domain", "host"):
        v = j["payload"].get(k)
        if isinstance(v, str):
            m = re.search(r"https?://([a-z0-9.\-]+)", v, re.I) or re.match(r"^([a-z0-9.\-]+\.[a-z]{2,})$", v, re.I)
            if m:
                cand.append(m.group(1).lower())
    for h in cand:
        try:
            d = json.loads(subprocess.run(["bash", SCOPE_CHECK, h], capture_output=True,
                                          text=True, timeout=40).stdout)
        except Exception:
            continue
        if d.get("in_scope") and d.get("pays") and not d.get("out_of_scope"):
            return h, d.get("program") or ""
    return (cand[0] if cand else ""), ""


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Crack HS* JWT signing secrets offline. No traffic to the target.")
    ap.add_argument("--token", action="append", default=[], help="a JWT to test directly")
    ap.add_argument("--from", dest="paths", action="append", default=[],
                    help="glob of files to harvest tokens from (repeatable)")
    ap.add_argument("--project-word", action="append", default=[],
                    help="project/brand words to try as the secret (repeatable)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    paths = a.paths or [
        os.path.join(BASE_DIR, "js_recon", "*.jsonl"),
        os.path.join(BASE_DIR, "params", "*.jsonl"),
        os.path.join(STATE_DIR, "*.jsonl"),
    ]
    toks = harvest_tokens(paths, a.token)
    if not toks:
        log("no JWTs found in the given sources")
        return 0

    parsed = []
    for t, src in toks.items():
        j = parse(t)
        if j:
            j["sources"] = src
            parsed.append(j)
    hs = [j for j in parsed if j["alg"].startswith("HS")]
    log(f"{len(toks)} JWT(s) harvested — {len(parsed)} parsed, {len(hs)} HMAC-signed (crackable)")
    for j in parsed:
        if not j["alg"].startswith("HS"):
            log(f"  skip alg={j['alg'] or '?'} (asymmetric — not offline-crackable)")

    if not hs:
        return 0
    words = wordlist()
    log(f"wordlist: {len(words):,} candidates (offline — the target sees nothing)")

    cracked = []
    for j in hs:
        host, program = scope_of(j, j["sources"])
        secret = crack(j, words, a.project_word)
        claims = sorted(j["payload"].keys())
        if secret:
            log(f"  *** CRACKED alg={j['alg']} secret={secret.decode('utf-8','replace')!r} "
                f"host={host or '?'} claims={claims[:8]}")
            cracked.append({"alg": j["alg"], "secret_redacted":
                            secret.decode("utf-8", "replace")[:3] + "*" * max(3, len(secret) - 3),
                            "secret_len": len(secret), "host": host, "program": program,
                            "claims": claims, "token_redacted": redact(j["token"]),
                            "sources": j["sources"]})
        else:
            log(f"  not cracked alg={j['alg']} host={host or '?'} ({len(words):,} tried)")

    audit({"harvested": len(toks), "hmac": len(hs), "cracked": len(cracked)})

    if cracked and not a.dry_run:
        sys.path.insert(0, REPO_DIR)
        from engine import state
        conn = state.connect()
        state.init_db(conn)
        for c in cracked:
            if not c["host"]:
                log("    (no in-scope host resolved from the claims — not minted)")
                continue
            ev = {"chain": "observed JWT -> offline signing-secret crack -> token forgery possible",
                  "alg": c["alg"], "secret_redacted": c["secret_redacted"],
                  "secret_length": c["secret_len"], "claims_present": c["claims"],
                  "token_redacted": c["token_redacted"], "seen_in": c["sources"],
                  "impact": (f"The {c['alg']} signing secret is guessable. Any token, for any "
                             f"user or role the application accepts, can be forged — this is "
                             f"authentication bypass, not merely weak crypto."),
                  "method": ("cracked entirely OFFLINE from an already-observed token; no traffic "
                             "was sent to the target and NO forged token was ever submitted."),
                  "at": utc()}
            fid = state.record_confirmed(
                conn, c["host"], url=f"https://{c['host']}/", program=c["program"] or None,
                signal_class="jwt", vuln_class="weak-jwt-signing-secret",
                score=19, evidence=ev, confidence=0.95)
            log(f"    minted finding #{fid}")
        conn.close()

    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"jwt_{datetime.now().strftime('%Y-%m-%d')}.md")
    L = [f"# JWT signing secrets — {utc()}", "",
         f"{len(toks)} token(s) harvested, {len(hs)} HMAC-signed, **{len(cracked)} cracked**.", ""]
    for c in cracked:
        L += [f"## `{c['host'] or 'unresolved host'}` ({c['program']})",
              f"- alg **{c['alg']}**, secret `{c['secret_redacted']}` ({c['secret_len']} chars)",
              f"- claims: {', '.join(c['claims'])}",
              f"- token: `{c['token_redacted']}`",
              f"- seen in: {', '.join(c['sources'])}", ""]
    open(out, "w", encoding="utf-8").write("\n".join(L))
    log(f"report → {out}")
    print(json.dumps({"harvested": len(toks), "hmac": len(hs), "cracked": len(cracked)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
