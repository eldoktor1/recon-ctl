#!/usr/bin/env python3
"""
recon_graphql_chain.py — introspection is not a finding; the DATA it leads to is.

"Introspection is enabled" is on by default in Apollo, Hasura and Graphene. It is the #1
GraphQL duplicate and gets closed Informational, correctly. The existing lane stops there.

The finding is: a query that returns user or financial objects, reachable WITHOUT
AUTHENTICATION, executed once, with the response proving real data came back.

    introspect -> find sensitive types -> find an unauth-reachable query that returns one
    -> EXECUTE EXACTLY ONE read-only query -> classify what came back

SAFETY — the hard lines are structural, not left to the caller:
  * QUERIES ONLY. Mutations and subscriptions are never sent. The operation must resolve
    against the schema's Query root or it is not executed. Nothing changes state.
  * Arguments are only ever supplied when they are OPTIONAL. We never invent an ID to pass
    to a query — guessing a stranger's identifier proves nothing and is not the bug.
  * Result sets are capped via `first`/`limit` when the field accepts one, so a proof does
    not become a data harvest.
  * Personal data is COUNTED and TYPED by engine.impact, never copied into evidence.
  * scope+pays gate, vpn_down fail-closed, one query per candidate, rate limited.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

BASE_DIR = os.environ.get("BASE_DIR", os.path.expanduser("~/recon"))
STATE_DIR = os.environ.get("STATE_DIR", os.path.join(BASE_DIR, "state"))
REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCOPE_CHECK = os.path.join(REPO_DIR, "scripts", "recon_scope_check.sh")
AUDIT = os.path.join(STATE_DIR, "graphql_chain_audit.jsonl")
OUT_DIR = os.path.join(BASE_DIR, "graphql")

sys.path.insert(0, REPO_DIR)
from engine import impact  # noqa: E402

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/127.0.0.0 Safari/537.36"
TIMEOUT = float(os.environ.get("GQL_TIMEOUT", "20"))
MIN_GAP = float(os.environ.get("GQL_MIN_GAP", "1.5"))
PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query", "/gql",
         "/api/gql", "/graphql/api", "/v2/graphql"]

# Type/field names that indicate the query returns something a program would pay to protect.
SENSITIVE = re.compile(
    r"(user|customer|account|member|employee|profile|person|contact|"
    r"payment|invoice|billing|order|transaction|card|balance|payout|"
    r"secret|token|credential|apikey|api_key|password|"
    r"address|email|phone|ssn|passport|document|message|ticket|admin)", re.I)

INTROSPECTION = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind name
      fields(includeDeprecated: false) {
        name
        args { name type { kind name ofType { kind name } } }
        type { kind name ofType { kind name ofType { kind name } } }
      }
    }
  }
}"""


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(m: str) -> None:
    print(f"[gql] {m}", file=sys.stderr, flush=True)


def audit(rec: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    rec.setdefault("at", utc())
    with open(AUDIT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def scope_ok(host: str) -> tuple[bool, str]:
    if not os.path.exists(SCOPE_CHECK):
        return False, "scope resolver missing (fail-closed)"
    try:
        d = json.loads(subprocess.run(["bash", SCOPE_CHECK, host], capture_output=True,
                                      text=True, timeout=45).stdout)
    except Exception as e:
        return False, f"scope check failed: {e}"
    if not d.get("in_scope"):
        return False, "not in scope"
    if not d.get("pays"):
        return False, "does not pay for this asset"
    if d.get("out_of_scope"):
        return False, "explicitly out of scope"
    return True, d.get("program") or ""


_last = [0.0]


def post(url: str, query: str, variables: dict | None = None) -> dict:
    gap = time.time() - _last[0]
    if gap < MIN_GAP:
        time.sleep(MIN_GAP - gap)
    _last[0] = time.time()
    body = json.dumps({"query": query, "variables": variables or {}}).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "application/json")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        with op.open(req, timeout=TIMEOUT) as r:
            return {"status": r.status, "body": r.read(400_000)}
    except urllib.error.HTTPError as e:
        try:
            return {"status": e.code, "body": e.read(200_000)}
        except Exception:
            return {"status": e.code, "body": b""}
    except Exception as e:
        return {"status": 0, "body": b"", "error": str(e)[:160]}


def find_endpoint(host: str, hint: str = "") -> str:
    """Try the caller's known-good URL first. ES records where the GraphQL scanner actually
    found the endpoint; rediscovering it by guessing paths misses the ones behind a routed
    prefix (proven: two hosts ES had flagged came back 'no endpoint')."""
    if hint:
        r = post(hint, "{__typename}")
        if r["status"] in (200, 400) and (b"__typename" in r["body"] or b'"data"' in r["body"]):
            log(f"  endpoint (from ES): {hint}")
            return hint
    for p in PATHS:
        url = f"https://{host}{p}"
        r = post(url, "{__typename}")
        if r["status"] in (200, 400) and b"__typename" in r["body"] or \
           (r["status"] == 200 and b'"data"' in r["body"]):
            log(f"  endpoint: {url}")
            return url
    return ""


def unwrap(t: dict | None) -> str:
    while isinstance(t, dict):
        if t.get("name"):
            return t["name"]
        t = t.get("ofType")
    return ""


# An argument that names an object reference is the IDOR surface. Splitting on this is not
# a limitation — it is the correct division of labour: the machine tests what needs no
# identifier, and a human with TWO OWNED ACCOUNTS tests what does.
OBJ_REF_ARG = re.compile(r"(^|_)(id|ids|uuid|guid|key|ref|number|no|code|slug|token|"
                         r"account|customer|user|order|invoice|application)($|_)", re.I)


def analyse(schema: dict) -> tuple[list[dict], list[dict], str]:
    """Split the sensitive queries in two:
      executable — returns a sensitive type AND needs no required argument, so we can run it
      human      — sensitive but requires an argument. We never invent one (guessing a
                   stranger's identifier proves nothing and is not the bug), so these become
                   a 2-owned-account IDOR worklist instead of being dropped.
    """
    qroot = (schema.get("queryType") or {}).get("name") or "Query"
    types = {t["name"]: t for t in schema.get("types") or [] if t.get("name")}
    q = types.get(qroot) or {}
    executable, human = [], []
    for f in q.get("fields") or []:
        ret = unwrap(f.get("type"))
        name = f.get("name") or ""
        if not SENSITIVE.search(f"{name} {ret}"):
            continue
        args = f.get("args") or []
        required = [a for a in args if (a.get("type") or {}).get("kind") == "NON_NULL"]
        if required:
            refs = [a["name"] for a in required if OBJ_REF_ARG.search(a["name"] or "")]
            human.append({"field": name, "returns": ret,
                          "required_args": [a["name"] for a in required],
                          "object_ref_args": refs,
                          "idor_candidate": bool(refs)})
            continue
        limit_arg = next((a["name"] for a in args
                          if a["name"] in ("first", "limit", "take", "pageSize")), "")
        executable.append({"field": name, "returns": ret, "limit_arg": limit_arg,
                           "type_fields": [sf.get("name") for sf in
                                           (types.get(ret, {}).get("fields") or [])][:40]})
    return executable, human, qroot


def build_query(cand: dict) -> str:
    """A minimal selection set of scalar-ish leaf fields on the returned type."""
    leaves = [f for f in cand["type_fields"] if f][:12] or ["id"]
    sel = " ".join(leaves)
    arg = f"({cand['limit_arg']}: 3)" if cand["limit_arg"] else ""
    inner = f"{{ {sel} }}" if cand["type_fields"] else ""
    return f"query {{ {cand['field']}{arg} {inner} }}".replace("  ", " ")


def run_host(target: str, dry: bool, max_exec: int = 3, hint: str = "") -> dict:
    # Accept a full endpoint URL as well as a bare host — the lane worklist records the real
    # endpoint, and path-guessing from a hostname misses non-standard mounts entirely.
    if target.startswith(("http://", "https://")):
        hint = target
        host = urllib.parse.urlsplit(target).netloc
    else:
        host = target

    ok, program = scope_ok(host)
    if not ok:
        log(f"SKIP {host}: {program}")
        return {"host": host, "skipped": program}

    log(f"{host}: locating GraphQL endpoint…")
    url = find_endpoint(host, hint)
    if not url:
        return {"host": host, "graphql": False}

    r = post(url, INTROSPECTION)
    if r["status"] != 200:
        log(f"{host}: introspection returned {r['status']} — likely disabled (good)")
        return {"host": host, "graphql": True, "endpoint": url, "introspection": False}
    try:
        schema = (json.loads(r["body"]).get("data") or {}).get("__schema")
    except Exception:
        schema = None
    if not schema:
        log(f"{host}: introspection disabled or unparseable (good)")
        return {"host": host, "graphql": True, "endpoint": url, "introspection": False}

    cands, human, qroot = analyse(schema)
    idor = [h for h in human if h["idor_candidate"]]
    log(f"{host}: introspection ON — {len(schema.get('types') or [])} types, "
        f"{len(cands)} sensitive no-arg quer{'y' if len(cands)==1 else 'ies'}, "
        f"{len(idor)} needing an object-ref arg (human 2-account test)")
    if idor:
        for h in idor[:8]:
            log(f"    [IDOR lead] {h['field']}({', '.join(h['object_ref_args'])}) -> {h['returns']}")
    if not cands:
        log(f"{host}: no unauth-reachable sensitive query — introspection alone is the #1 "
            f"GraphQL duplicate, NOT a finding"
            + (f"; {len(idor)} IDOR lead(s) recorded for the owned-account test" if idor else ""))
        return {"host": host, "program": program, "graphql": True, "endpoint": url,
                "introspection": True, "candidates": [], "idor_leads": idor}

    hits = []
    for c in cands[:max_exec]:
        gq = build_query(c)
        log(f"  executing (read-only): {gq[:110]}")
        rr = post(url, gq)
        if rr["status"] != 200 or not rr["body"]:
            continue
        try:
            j = json.loads(rr["body"])
        except Exception:
            continue
        if j.get("errors") and not j.get("data"):
            log(f"    rejected: {str(j['errors'])[:110]}")
            continue
        data = j.get("data") or {}
        payload = json.dumps(data).encode()
        if len(payload) < 40 or data == {c["field"]: None}:
            log("    returned null/empty — enforced or no data")
            continue
        cls = impact.classify_data(payload, source=f"{c['field']}")
        sec = impact.scan_secrets(payload, c["field"])
        log(f"    {len(payload)} bytes — {cls['reason']}")
        if cls["is_pii"] or sec:
            hits.append({"field": c["field"], "returns": c["returns"], "query": gq,
                         "pii": cls, "secrets": sec, "bytes": len(payload)})

    res = {"host": host, "program": program, "graphql": True, "endpoint": url,
           "introspection": True, "candidates": [c["field"] for c in cands],
           "idor_leads": idor, "hits": hits}
    audit({k: v for k, v in res.items() if k != "hits"} | {"n_hits": len(hits)})
    if hits and not dry:
        res["finding_id"] = mint(res)
    elif not hits:
        log(f"{host}: no unauthenticated query returned real data — not a finding")
    return res


def mint(res: dict) -> int | None:
    from engine import state
    best = max(res["hits"], key=lambda h: (bool(h["secrets"]), h["pii"].get("records", 0)))
    score, conf, headline = impact.severity_for(best["secrets"], best["pii"])
    ev = {
        "chain": "GraphQL introspection -> sensitive no-arg query -> executed unauthenticated",
        "endpoint": res["endpoint"],
        "executed": [{"field": h["field"], "query": h["query"], "bytes": h["bytes"],
                      "personal_data": h["pii"], "credentials": h["secrets"]}
                     for h in res["hits"]],
        "impact": headline,
        "method": ("queries only — no mutation or subscription was ever sent; only fields "
                   "with NO required arguments were executed, so no identifier was invented; "
                   "result sets capped; personal data counted, never copied"),
        "at": utc(),
    }
    conn = state.connect()
    state.init_db(conn)
    fid = state.record_confirmed(
        conn, res["host"], url=res["endpoint"], program=res["program"] or None,
        signal_class="graphql", vuln_class="unauth-data-exposure-graphql",
        score=score, evidence=ev, confidence=conf)
    conn.close()
    log(f"  minted finding #{fid} — {headline}")
    return fid


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Chain GraphQL introspection to an executed unauthenticated data query.")
    ap.add_argument("host", nargs="+")
    ap.add_argument("--max-exec", type=int, default=3)
    ap.add_argument("--feed", default=os.path.join(STATE_DIR, "feed_graphql.json"),
                    help="feed json from recon_feed.py; supplies the endpoint URL ES already resolved")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if os.path.exists(os.path.join(STATE_DIR, "vpn_down")):
        log("vpn_down — refusing (fail-closed)")
        return 2

    feed = {}
    if a.feed and os.path.exists(a.feed):
        try:
            feed = json.load(open(a.feed))
        except Exception:
            pass

    runs = [run_host(h, a.dry_run, a.max_exec,
                     (feed.get(h) or {}).get("final_url", "")) for h in a.host]
    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"gqlchain_{datetime.now().strftime('%Y-%m-%d')}.md")
    L = [f"# GraphQL data-exposure chain — {utc()}", ""]
    for r in runs:
        if r.get("skipped"):
            L += [f"## {r['host']} — SKIPPED ({r['skipped']})", ""]; continue
        if not r.get("graphql"):
            L += [f"## {r['host']} — no GraphQL endpoint found", ""]; continue
        L += [f"## {r['host']} ({r.get('program','')})", f"- endpoint: `{r['endpoint']}`",
              f"- introspection: {'ON' if r.get('introspection') else 'off (good)'}"]
        if r.get("candidates"):
            L.append(f"- sensitive no-arg queries: {', '.join(f'`{c}`' for c in r['candidates'][:20])}")
        if r.get("idor_leads"):
            L += ["", "**IDOR worklist — 2 OWNED accounts, never a guessed identifier:**"]
            for h in r["idor_leads"][:20]:
                L.append(f"- `{h['field']}({', '.join(h['required_args'])})` → `{h['returns']}` "
                         f"— object-ref arg(s): {', '.join(f'`{a}`' for a in h['object_ref_args'])}")
        for h in r.get("hits", []):
            L += ["", f"### `{h['field']}` returned data unauthenticated",
                  f"```graphql\n{h['query']}\n```",
                  f"- {h['pii']['reason']}" if h["pii"]["is_pii"] else "",
                  *[f"- **{s['kind']}** — `{s['redacted']}`" for s in h["secrets"]]]
        if not r.get("hits"):
            L.append("- _no unauthenticated query returned real data — not a finding_")
        L.append("")
    open(out, "w", encoding="utf-8").write("\n".join(x for x in L if x is not None))
    log(f"report → {out}")
    print(json.dumps([{k: v for k, v in r.items() if k != "hits"} for r in runs],
                     default=str)[:1200])
    return 0


if __name__ == "__main__":
    sys.exit(main())
