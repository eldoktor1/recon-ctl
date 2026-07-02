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
import os
import re
import sys
import time

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except Exception:
    requests = None

TIMEOUT = 12
UA = "Mozilla/5.0 (compatible; recon-graphql/1.0)"
# Clairvoyance-style field-suggestion recovery (when introspection is OFF). Bounded + polite.
SUGGEST_MAX = int(os.environ.get("GQL_SUGGEST_MAX", "140"))    # max probe requests per endpoint
SUGGEST_DELAY = float(os.environ.get("GQL_SUGGEST_DELAY", "0.2"))
# 1-char suffix: keeps every probe GUARANTEED-invalid (never a real field → never executes / returns
# data) while staying within GraphQL's edit-distance suggestion threshold (~floor(len*0.4)+1), so a
# near-miss still triggers "did you mean <real field>". A longer nonce defeats the suggestion.
NONCE = "z"

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
# sign-in mutations where ORM type coercion (`password: null` / `password: [..]`) can return a valid
# session token — disclosed pattern Apr–Jun 2026 (leniency in the ORM, not GraphQL). Only a LEAD:
# the human tests it with an owned account. See docs/knowledge/class-graphql.md.
AUTH_MUTATION = re.compile(r"(log[_-]?in|sign[_-]?in|authenticate|create[_-]?session|"
                           r"issue[_-]?token|get[_-]?token|session)", re.I)


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
        if op_type == "mutation" and AUTH_MUTATION.search(name) \
                and any((a or "").lower() in ("password", "passwd", "pass") for a in args):
            score += 3
            reasons.append("auth mutation w/ password arg — TEST password:null + array-coercion "
                           "(ORM type-coercion auth bypass; owned account only)")
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


# ---------------------------------------------------------------------------
# Clairvoyance-style field-suggestion recovery (introspection OFF, suggestions ON)
# ---------------------------------------------------------------------------
# graphql-js & many engines leak the schema via "Did you mean ..." error suggestions even with
# introspection disabled. We send GUARANTEED-INVALID near-miss field names (candidate+NONCE) so a
# real field/mutation can NEVER be validly invoked (no side effects) — the error suggests the real
# fields close to our probe, which we harvest. Read-only, bounded, rate-limited.
SUGGEST_RE = re.compile(r'did you mean', re.I)
QUOTED_RE = re.compile(r'["\'`]([A-Za-z_][A-Za-z0-9_]*)["\'`]')

# compact, sensitivity-weighted candidate field/op names (near-miss seeds for the suggestion sweep)
SUGGEST_WORDS = [
    "user", "users", "me", "viewer", "currentUser", "whoami", "account", "accounts", "node",
    "search", "admin", "admins", "order", "orders", "product", "products", "customer", "customers",
    "payment", "payments", "invoice", "transaction", "transactions", "profile", "settings", "config",
    "organization", "team", "teams", "member", "members", "project", "report", "file", "files",
    "document", "documents", "message", "messages", "notification", "session", "sessions", "token",
    "tokens", "apiKey", "apiKeys", "secret", "secrets", "role", "roles", "permission", "permissions",
    "group", "employee", "employees", "billing", "subscription", "card", "cards", "address", "email",
    "phone", "userById", "internalUser",
    # mutation-leaning
    "createUser", "updateUser", "deleteUser", "resetPassword", "changePassword", "login", "register",
    "signup", "createOrder", "cancelOrder", "createPayment", "refund", "transfer", "withdraw",
    "updateRole", "grantRole", "inviteUser", "impersonate", "createApiKey", "revokeApiKey",
    "updateSettings", "uploadFile", "sendEmail", "verifyEmail", "disableUser", "approve", "promote",
]


def _extract_suggestions(js, txt):
    """Harvest suggested field names from a GraphQL error response."""
    out = set()
    msgs = []
    if isinstance(js, dict):
        for e in (js.get("errors") or []):
            if isinstance(e, dict) and e.get("message"):
                msgs.append(e["message"])
    if not msgs and txt:
        msgs.append(txt)
    for m in msgs:
        if not SUGGEST_RE.search(m or ""):
            continue
        tail = m[SUGGEST_RE.search(m).end():]          # only names AFTER "did you mean"
        for name in QUOTED_RE.findall(tail):
            if name not in ("Query", "Mutation", "Subscription"):
                out.add(name)
    return out


def score_name(op_type, name):
    """Score a recovered field by NAME only (suggestion recovery gives no args)."""
    score = 5 if op_type == "mutation" else 2
    sens = bool(SENSITIVE_OP.search(name))
    idor = bool(IDOR_ARG.match(name)) or name.lower().endswith("byid")
    reasons = []
    if sens:
        score += 3; reasons.append("sensitive-op-name")
    if idor:
        score += 1; reasons.append("object-ref naming (likely takes an id)")
    return {"op_type": op_type, "name": name, "args": [], "idor_args": [],
            "injectable_args": [], "returns": "", "sensitive": sens,
            "score": score, "reason": "; ".join(reasons) or "recovered field (args unknown — introspection off)"}


def recover_via_suggestions(url, headers=None):
    """Sweep near-miss field names, harvest 'did you mean' suggestions → recovered op set.
    Detection IS the sweep: if the first probes yield no suggestions, the engine has suggestions
    off (or the wordlist doesn't fit this schema) → bail early so we don't probe a dead endpoint."""
    q_fields, m_fields = set(), set()
    probes = 0
    # query-root sweep (early-bail if suggestions appear to be off)
    for i, w in enumerate(SUGGEST_WORDS):
        if probes >= SUGGEST_MAX:
            break
        _, js, txt = _gql(url, "query { %s }" % (w + NONCE), headers)
        q_fields |= _extract_suggestions(js, txt)
        probes += 1
        time.sleep(SUGGEST_DELAY)
        if i >= 11 and not q_fields:        # 12 probes, zero suggestions → suggestions off
            return None
    # mutation-root sweep (only if the engine exposes a Mutation type)
    _, mjs, mtxt = _gql(url, "mutation { %s }" % (SUGGEST_WORDS[0] + NONCE), headers)
    mblob = json.dumps(mjs).lower() if mjs else (mtxt or "").lower()
    if "mutation" in mblob and "cannot query field" in mblob:
        for w in SUGGEST_WORDS:
            if probes >= SUGGEST_MAX:
                break
            _, js, txt = _gql(url, "mutation { %s }" % (w + NONCE), headers)
            m_fields |= _extract_suggestions(js, txt)
            probes += 1
            time.sleep(SUGGEST_DELAY)
    m_fields -= q_fields   # a name suggested in mutation context but already a query field stays query
    if not q_fields and not m_fields:
        return None
    cands = [score_name("mutation", n) for n in sorted(m_fields)] + \
            [score_name("query", n) for n in sorted(q_fields)]
    cands.sort(key=lambda c: -c["score"])
    return {
        "n_queries": len(q_fields), "n_mutations": len(m_fields),
        "n_sensitive": sum(1 for c in cands if c["sensitive"]),
        "candidates": cands[:25], "probes": probes,
    }


def analyze_url(url, headers=None):
    """Probe one URL: confirm GraphQL, introspect, rank. Returns a record or None."""
    st, js, txt = _gql(url, "{__typename}", headers)
    if not is_graphql(st, js, txt):
        return None
    rec = {"endpoint": url, "introspection_enabled": False, "recovery": "none",
           "query_root": None, "mutation_root": None,
           "n_queries": 0, "n_mutations": 0, "n_sensitive": 0, "candidates": []}
    ist, ijs, _ = _gql(url, INTROSPECTION, headers)
    schema = None
    if isinstance(ijs, dict) and isinstance(ijs.get("data"), dict):
        schema = (ijs["data"] or {}).get("__schema")
    if schema:
        rec["introspection_enabled"] = True
        rec["recovery"] = "introspection"
        summary, cands = rank_schema(schema)
        rec.update(summary)
        rec["candidates"] = cands[:25]   # top operations per endpoint
    else:
        # introspection OFF → Clairvoyance-style field-suggestion recovery
        try:
            rcv = recover_via_suggestions(url, headers)
        except Exception:
            rcv = None
        if rcv:
            rec["recovery"] = "field-suggestion"
            rec["query_root"] = "Query"; rec["mutation_root"] = "Mutation" if rcv["n_mutations"] else None
            rec["n_queries"] = rcv["n_queries"]; rec["n_mutations"] = rcv["n_mutations"]
            rec["n_sensitive"] = rcv["n_sensitive"]; rec["candidates"] = rcv["candidates"]
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


def cmd_recover(args):
    """Debug: force field-suggestion recovery on one URL (introspection-off path)."""
    url = args[0] if args else ""
    if not url:
        sys.stderr.write("usage: recon_graphql.py recover <url>\n"); sys.exit(2)
    rcv = recover_via_suggestions(url)
    print(json.dumps(rcv or {"recovered": False}, indent=2))


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "analyze":
        cmd_analyze(sys.argv[2:])
    elif len(sys.argv) >= 2 and sys.argv[1] == "recover":
        cmd_recover(sys.argv[2:])
    else:
        sys.stderr.write("usage: recon_graphql.py analyze (URLs on stdin) | recover <url>\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
