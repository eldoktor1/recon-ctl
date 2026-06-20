#!/usr/bin/env python3
"""recon_graphql.py — GraphQL endpoint analyzer for recon_graphql.sh

Native (no external tool dep): detect a live GraphQL endpoint, harvest the introspection
schema if enabled, and REASON over the schema graph to rank the human-test worklist —
the unique edge (the crowd runs subfinder|httpx|nuclei; few introspect + reason over the
schema). Output is a ranked LEAD worklist; nothing is auto-confirmed (IDOR/injection/auth-
bypass on the surfaced ops is HUMAN-IN-THE-LOOP with 2 owned accounts — hard line).

Sends ONLY read-only GraphQL: a benign `{__typename}` liveness probe and the standard
introspection query. NEVER a mutation, never a data-returning field query, never auth.

  analyze   (stdin: one candidate URL per line) -> JSONL per live endpoint on stdout

See docs/knowledge/class-graphql.md for the methodology + severity ladder.
"""
import json
import re
import sys

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except Exception:
    requests = None

TIMEOUT = 12
UA = "Mozilla/5.0 (compatible; recon-graphql/1.0)"

# Minimal-but-sufficient introspection: roots + every type's fields + each field's args.
INTROSPECTION = """
query IntrospectionQuery {
  __schema {
    queryType { name } mutationType { name } subscriptionType { name }
    types {
      kind name
      fields(includeDeprecated: true) {
        name
        args { name type { kind name ofType { kind name ofType { kind name } } } }
        type { kind name ofType { kind name ofType { kind name } } }
      }
    }
  }
}
""".strip()

# ---- value signals (mirrors recon_idor_candidates.py scoring + GraphQL methodology) ----
SENSITIVE_OP = re.compile(
    r"(creat|updat|delet|remov|reset|change|set[A-Z_]|grant|revoke|password|passwd|secret|"
    r"token|apikey|api_key|role|admin|permiss|privile|pay|payment|transfer|withdraw|deposit|"
    r"refund|invite|impersonat|login|signin|register|signup|upload|email|phone|ssn|disable|"
    r"enable|approve|verify|promote|sudo|owner|billing|invoice|charge|subscription)", re.I)
IDOR_ARG = re.compile(r"^(id|.*_?id|uuid|guid|node|nodeid|objectid|ref|slug|key|pk|number|no|code)$", re.I)
INJECTABLE_ARG = re.compile(r"^(filter|filters|search|q|query|where|order|orderby|sort|sortby|"
                            r"raw|expr|expression|sql|jq|path|file|url|redirect|callback|input)$", re.I)
SENSITIVE_TYPE = re.compile(
    r"(user|account|customer|member|payment|card|credit|ssn|token|secret|apikey|api_key|"
    r"credential|password|admin|order|invoice|billing|address|email|phone|profile|setting|"
    r"session|auth|kyc|identity|bank|wallet|tax|salary|ssn|passport)", re.I)


def _gql(url, query, headers=None):
    """POST a read-only GraphQL query. Returns (status_code, json_or_None, text)."""
    if requests is None:
        return None, None, ""
    h = {"Content-Type": "application/json", "User-Agent": UA, "Accept": "application/json"}
    if headers:
        h.update(headers)
    try:
        r = requests.post(url, json={"query": query}, headers=h, timeout=TIMEOUT,
                          verify=False, allow_redirects=False)
        body = r.text or ""
        try:
            return r.status_code, r.json(), body[:2000]
        except Exception:
            return r.status_code, None, body[:2000]
    except Exception:
        return None, None, ""


def is_graphql(status, js, text):
    """A live GraphQL endpoint answers __typename with data, or errors in a GraphQL shape."""
    if js and isinstance(js, dict):
        if isinstance(js.get("data"), dict) and "__typename" in js["data"]:
            return True
        errs = js.get("errors")
        if isinstance(errs, list) and errs:
            blob = json.dumps(errs).lower()
            if any(k in blob for k in ("must provide query", "graphql", "syntax error",
                                       "query", "operation", "no query string")):
                return True
    low = (text or "").lower()
    return ("graphql" in low and ("errors" in low or "data" in low)) or "must provide a query" in low


def _unwrap(t):
    """Resolve a (possibly wrapped LIST/NON_NULL) type ref to its named type."""
    seen = 0
    while isinstance(t, dict) and t.get("name") is None and t.get("ofType") and seen < 6:
        t = t["ofType"]; seen += 1
    return (t or {}).get("name") or ""


def rank_schema(schema):
    """Return (summary, candidates[]) from an introspection __schema object."""
    types = {t.get("name"): t for t in schema.get("types", []) if t.get("name")}
    q_root = (schema.get("queryType") or {}).get("name")
    m_root = (schema.get("mutationType") or {}).get("name")
    cands = []

    def fields_of(root):
        t = types.get(root) or {}
        return t.get("fields") or []

    def score_op(op_type, f):
        name = f.get("name") or ""
        args = [a.get("name") for a in (f.get("args") or []) if a.get("name")]
        idor = [a for a in args if IDOR_ARG.match(a or "")]
        inj = [a for a in args if INJECTABLE_ARG.match(a or "")]
        ret = _unwrap(f.get("type"))
        score = 5 if op_type == "mutation" else 2
        reasons = []
        if SENSITIVE_OP.search(name):
            score += 3; reasons.append("sensitive-op-name")
        if idor:
            score += 2; reasons.append("object-ref arg (IDOR): " + ",".join(idor))
        if inj:
            score += 2; reasons.append("injectable arg: " + ",".join(inj))
        if ret and SENSITIVE_TYPE.search(ret):
            score += 2; reasons.append("returns sensitive type " + ret)
        return {
            "op_type": op_type, "name": name, "args": args,
            "idor_args": idor, "injectable_args": inj, "returns": ret,
            "sensitive": bool(SENSITIVE_OP.search(name) or (ret and SENSITIVE_TYPE.search(ret))),
            "score": score, "reason": "; ".join(reasons) or "exposed operation",
        }

    for f in fields_of(m_root):
        cands.append(score_op("mutation", f))
    for f in fields_of(q_root):
        cands.append(score_op("query", f))
    cands.sort(key=lambda c: -c["score"])
    summary = {
        "query_root": q_root, "mutation_root": m_root,
        "n_queries": len(fields_of(q_root)), "n_mutations": len(fields_of(m_root)),
        "n_sensitive": sum(1 for c in cands if c["sensitive"]),
    }
    return summary, cands


def analyze_url(url, headers=None):
    """Probe one URL: confirm GraphQL, introspect, rank. Returns a record or None."""
    st, js, txt = _gql(url, "{__typename}", headers)
    if not is_graphql(st, js, txt):
        return None
    rec = {"endpoint": url, "introspection_enabled": False,
           "query_root": None, "mutation_root": None,
           "n_queries": 0, "n_mutations": 0, "n_sensitive": 0, "candidates": []}
    ist, ijs, _ = _gql(url, INTROSPECTION, headers)
    schema = None
    if isinstance(ijs, dict) and isinstance(ijs.get("data"), dict):
        schema = (ijs["data"] or {}).get("__schema")
    if schema:
        rec["introspection_enabled"] = True
        summary, cands = rank_schema(schema)
        rec.update(summary)
        rec["candidates"] = cands[:25]   # top operations per endpoint
    return rec


def cmd_analyze(_args):
    seen = set()
    for line in sys.stdin:
        url = line.strip()
        if not url or url in seen:
            continue
        seen.add(url)
        try:
            rec = analyze_url(url)
        except Exception:
            rec = None
        if rec:
            sys.stdout.write(json.dumps(rec) + "\n")
            sys.stdout.flush()


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "analyze":
        cmd_analyze(sys.argv[2:])
    else:
        sys.stderr.write("usage: recon_graphql.py analyze  (URLs on stdin)\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
