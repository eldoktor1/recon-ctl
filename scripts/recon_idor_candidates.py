#!/usr/bin/env python3
# =============================================================================
# recon_idor_candidates.py — rank the IDOR/BOLA money-pillar worklist.
#
# WHY: jsintel (recon_jsintel.sh -> js_recon/endpoints.jsonl) extracts the hidden
# API surface with jsluice, but stores 25k+ raw endpoints with NO IDOR ranking.
# IDOR/BOLA in REST/GraphQL APIs is the #1 paid class (2025/26 research) and the
# one automation can't confirm — so the highest-leverage autonomous step is to
# SURFACE the best human-testable IDOR candidates, ranked by value, from the dump.
#
# WHAT: scores each endpoint for IDOR-likelihood (object-reference resource +
# ID type: numeric=enumerable, uuid=harvestable, id-param), boosts STATE-CHANGING
# / mutating endpoints (Action-Level BOLA — HTTP POST/PUT/PATCH/DELETE where the
# source resolved the verb, or a write verb in the path/param) so mutating BOLA
# outranks read-only ID substitution (research beginner-first-report 2026-07-25:
# state-changing BOLA ~41.7% is co-dominant with read IDOR ~36.9%), boosts
# sensitive/financial resources + API versioning + upload/download, cross-refs ES
# for payout tier / scope, excludes benched hosts, dedups, ranks (tier x score),
# and writes a ranked worklist. ADDITIVE + read-only: touches no daemon state.
#
# ROADMAP (same digest, larger effort — NOT done here): clone/staging dedup —
# SimHash of the crawled body + perceptual hash of the VERIFY-agent screenshot in
# the ES asset layer, to group near-duplicate hosts and hunt one representative
# (XBOW's dedup mechanism). Tracked in CLAUDE.md "smart targeting + clone/staging
# dedup"; belongs in the ES asset store + VERIFY pipeline, not this ranker.
#
# Usage: recon_idor_candidates.py [--min-score N] [--top N] [--out FILE]
#        Human runs the 2-account test; this only surfaces & ranks (hard line).
# =============================================================================
import json, subprocess, os, re, sys, argparse, datetime, collections, base64

HOME=os.path.expanduser("~")
EP=os.path.join(HOME,"recon/js_recon/endpoints.jsonl")
ES="http://127.0.0.1:9200/recon_alive"; NETRC=os.path.join(HOME,".recon_es_netrc")

ap=argparse.ArgumentParser()
ap.add_argument("--min-score",type=int,default=4)  # 4 captures /graphql + obj+api; 5 = concrete-ID only
ap.add_argument("--top",type=int,default=60)
ap.add_argument("--out",default=None)
ap.add_argument("--stamp",default=None)  # date string (Date.now unavailable note n/a here)
ap.add_argument("--jwt-scan",action="store_true",
                help="cheap enrichment: grep the jsintel corpus for JWT kid/jku/x5u header "
                     "params -> flag in-scope hosts for the JWT-attacks lane (LEAD only)")
args=ap.parse_args()

UUID=re.compile(r'/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
NUMID=re.compile(r'/(?:[a-z]+-)?\d{2,}(?:/|$|\?)',re.I)   # /12345 or /nab-432320 (prefixed id)
# path-template id: /:id /{id} /:userId /{companyId} — the app explicitly parameterizes a
# user-supplied object id = the STRONGEST IDOR signal (research). Any /:seg or /{seg} counts.
TEMPLATE=re.compile(r'/[:{][A-Za-z_]\w*\}?')
IDPARAM=re.compile(r'[?&](id|.*_?id|uid|account|order|invoice|doc|document|user|member|customer|ref|token|key|file|guid|uuid)=',re.I)
OBJRES=re.compile(r'/(users?|accounts?|orders?|invoices?|documents?|profiles?|messages?|payments?|cards?|transactions?|members?|customers?|files?|reports?|tickets?|subscriptions?|addresses?|contacts?|teams?|orgs?|organizations?|projects?|companies)(/|$)',re.I)
SENS=re.compile(r'(payment|card|invoice|transaction|balance|wallet|clabe|bank|account|kyc|ssn|salary|salaries|tax|statement|withdraw|deposit|transfer|loan|credit|billing|payout)',re.I)
UPDL=re.compile(r'(upload|download|export|attachment|/file|/files|/blob|/media/|presigned)',re.I)
APIV=re.compile(r'/(api|v\d|graphql|rest|service)',re.I)
# modern-BOLA signals (audit #10, arXiv 2605.25865 taxonomy; beginner-first-report 2026-07-25):
# action-level/STATE-CHANGE BOLA = ~41.7% of confirmed cases + highest severity — co-dominant with
# read-only Direct-Object IDOR (~36.9%) and MISSED by read-only/GET-only testing. So a mutating
# endpoint (HTTP POST/PUT/PATCH/DELETE where the source knows the verb, OR a write verb in the
# path/param) that carries an object reference must rank ABOVE a plain read-only ID substitution.
# Also: object-rebinding (owner/account/tenant id as a writable param); tenant-isolation
# (cross-tenant /org/{id}); GraphQL global IDs (base64) decoded→incremented→re-encoded systematically.
MUT_METHODS={"POST","PUT","PATCH","DELETE"}  # HTTP verbs that imply a state change (BOLA-with-write)
# path/param write verbs (the "where the method is unknown" fallback — jsluice often can't resolve the
# fetch() method, so the verb in the route/param is the signal). Anchored after '/' so it's a path seg.
ACTION=re.compile(r'/(delete|remove|update|edit|modify|approve|reject|cancel|transfer|invite|revoke|disable|enable|deactivate|activate|grant|assign|reset|set|promote|merge|publish|unpublish|archive|restore|impersonate|switch|change)(/|$|\b)',re.I)
REBIND=re.compile(r'[?&](owner_id|account_id|tenant_id|user_id|org_id|organization_id|customer_id|company_id|member_id|group_id|workspace_id)=',re.I)
TENANT=re.compile(r'/(orgs?|organizations?|tenants?|workspaces?|companies|company|teams?)/:?\{?[\w-]+\}?',re.I)
GQLID=re.compile(r'(node\(\s*id\s*:|[?&]id=[A-Za-z0-9+/_-]{16,}={0,2})')  # base64-ish GraphQL global id
NOISE=re.compile(r'\.(js|css|png|jpe?g|svg|gif|woff2?|ttf|ico|map|json)$|/utag|/static/|/assets/|cdn|googleapis|gstatic|/cookie|/privacy|/terms|/legal|hiring-advice|market-insights',re.I)
# full-URL endpoints pointing at a 3rd-party host are not the target's surface
THIRDPARTY=re.compile(r'^https?://[^/]*(bugcrowd|hackerone|github|gitlab|google|gstatic|googleapis|cloudflare|sentry|datadog|amazonaws|cloudfront|segment|stripe\.com|paypal|facebook|twitter|linkedin|youtube|atlassian|onetrust|cookielaw|unpkg|jsdelivr|cdnjs|gravatar|intercom|zendesk|hubspot|launchdarkly|amplitude|optimizely)\.',re.I)
# fanout key: strip host + template concrete IDs so the same shipped-product API
# on many hosts collapses to one key (product-class-dup detection, brief_filter doctrine).
def _fanout_key(ep):
    p=re.sub(r'^https?://[^/]+','',ep)                         # drop host
    p=re.sub(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}','{uuid}',p)
    p=re.sub(r'/\d{2,}','/{id}',p)                             # numeric ids
    p=p.split('?')[0]
    return p
FANOUT_MAX=5  # same endpoint on > this many distinct hosts = shipped-product API (dup)
# Backend-API vs SPA-client-route hint: jsluice extracts both. The IDOR money is the BACKEND
# API (returns JSON/401), not the Angular/React client routes (which return the app shell).
# Verified signal: an /api/ prefix or an api.* host is backend; bare /bookings/:id, /v2/x were
# SPA routes (blis). Not authoritative (operator confirms by probing for JSON/401), just a hint.
def _backend_hint(ep, eff_host):
    if re.search(r'/api[/.]|/graphql|/rest/|/services?/', ep, re.I): return "API"
    if eff_host.startswith("api.") or ".api." in eff_host or eff_host.startswith("gw.") or eff_host.startswith("gateway"): return "API"
    return "route?"

# Relay global-ID detector (arXiv 2605.25865: the DOMINANT GraphQL BOLA pattern). A base64 arg/id
# value that decodes cleanly to `Type:<digits>` (spec convention `base64("TypeName:12345")`, e.g.
# VXNlcjox -> "User:1") is DECODABLE, so the digit component is enumerable: decode -> increment ->
# re-encode -> replay. That makes it a near-certain enumerable ref, ranked ABOVE an opaque UUID
# object-ref (which is only harvestable). Human 2-account test only (hard line: never third-party IDs).
RELAY_DEC=re.compile(r'^\w+:\d+$')
def _relay_global_id(ep):
    """Return the decoded 'Type:num' string if any base64 token in ep is a Relay global ID, else None.
    Split on URL delimiters first (`/`, `?`, `&`, `=`, quotes, parens…) so a path separator isn't
    swallowed into the token; accept the url-safe/standard base64 alphabet within a segment."""
    for seg in re.split(r'[^A-Za-z0-9+_-]+', ep):
        if len(seg) < 8:
            continue
        t=seg.replace('-','+').replace('_','/')                  # url-safe -> standard b64
        t+='='*(-len(t)%4)                                       # restore padding
        try:
            dec=base64.b64decode(t,validate=True).decode('utf-8','strict')
        except Exception:
            continue
        if RELAY_DEC.match(dec):
            return dec
    return None

def score_ep(host, ep, method=""):
    p=ep
    if NOISE.search(p): return 0,"noise"
    s=0; idt=[]
    has_ref=False        # endpoint carries an object reference (the thing you'd swap in an IDOR test)
    state_change=False   # endpoint MUTATES state (Action-Level BOLA, ~41.7% of confirmed cases)
    if TEMPLATE.search(p): s+=4; idt.append("templated-id(:id/{id})"); has_ref=True
    if NUMID.search(p): s+=4; idt.append("numeric-ID(enumerable)"); has_ref=True
    if UUID.search(p): s+=4; idt.append("uuid"); has_ref=True   # 39% of BOLA; exploitable once leaked (was +3)
    _relay=_relay_global_id(p)
    if _relay: s+=6; idt.append("RELAY-GLOBAL-ID("+_relay+" — decode/increment/re-encode)"); has_ref=True  # > UUID: decodable=enumerable
    if IDPARAM.search(p): s+=3; idt.append("id-param"); has_ref=True
    m=OBJRES.search(p)
    if m: s+=2; idt.append("obj:"+m.group(1).lower()); has_ref=True
    # --- state-change signal: HTTP method (where jsluice resolved it) OR a write verb in the path ---
    mth=(method or "").strip().upper()
    if mth in MUT_METHODS:
        s+=4; idt.append("HTTP-"+mth+"(state-change)"); state_change=True  # method is KNOWN → strong
    if ACTION.search(p):
        s+=3; idt.append("ACTION-LEVEL(state-change)"); state_change=True  # write verb in route/param
    if REBIND.search(p): s+=2; idt.append("rebind(owner/tenant-id)"); has_ref=True
    if TENANT.search(p): s+=2; idt.append("tenant-isolation"); has_ref=True
    if APIV.search(p) or host.startswith("api.") or ".api." in host: s+=2; idt.append("api")
    if "graphql" in p.lower():
        s+=2; idt.append("graphql")
        if GQLID.search(p): s+=1; idt.append("graphql-global-id(decode/increment)"); has_ref=True
    if UPDL.search(p): s+=2; idt.append("file")
    if SENS.search(p): s+=3; idt.append("SENSITIVE")
    # MUTATING-BOLA combo (research 2026-07-25): a state change ON an object reference is Action-Level
    # BOLA with write impact — the co-dominant, highest-severity family. Boost it so mutating candidates
    # rank ABOVE read-only ID substitution. A bare write verb with no object ref is not BOLA → no bonus.
    if state_change and has_ref:
        s+=3; idt.append("MUTATING-BOLA(state-change+object-ref)")
    return s, ",".join(idt) if idt else "-"

def es(body):
    try:
        return json.loads(subprocess.run(["curl","-fsS","-m","30","--netrc-file",NETRC,
            "-H","Content-Type: application/json",f"{ES}/_search","--data-binary",json.dumps(body)],
            capture_output=True,text=True).stdout)
    except Exception: return {}

# ---- JWT header-param enrichment (detect-tune 2026-07-11 §3) -------------------------------
# Cheap, READ-ONLY grep of the already-collected jsintel corpus for JWT header params kid/jku/x5u
# (never a fetch, never target traffic). kid = injection primitive (unsanitized path / DB-lookup
# key confusion -> LFI/SQLi/key-selection abuse); jku/x5u = server fetches signing keys from an
# attacker-controllable URL -> forged-token account takeover. LEAD ONLY: forging a valid signature
# is an ACTIVE PoC and stays human-in-the-loop under the ACTIVE-PoC gates. This only surfaces + ranks.
JWT_CORPUS=[EP,
            os.path.join(HOME,"recon/js_recon/findings.jsonl"),
            os.path.join(HOME,"recon/js_recon/secret_leads.jsonl")]
# boundary-guarded so "skid"/"kidding"/"kids" don't match; needs a quote or "="/":" after the name
JWT_HDR=re.compile(r'(?<![A-Za-z0-9])["\']?(kid|jku|x5u)["\']?\s*[:=]')
def scan_jwt_headers(stamp=None):
    hits=collections.defaultdict(collections.Counter)   # host -> {kid:n, jku:n, x5u:n}
    for path in JWT_CORPUS:
        if not os.path.exists(path): continue
        try:
            with open(path,errors="ignore") as f:
                for line in f:
                    if "kid" not in line and "jku" not in line and "x5u" not in line: continue  # cheap prefilter
                    try: j=json.loads(line)
                    except: continue
                    host=j.get("host","")
                    if not host: continue
                    blob=" ".join(str(j.get(k,"")) for k in ("endpoint","context","js_file","file","match_type"))
                    for m in JWT_HDR.finditer(blob):
                        hits[host][m.group(1).lower()]+=1
        except Exception: continue
    hits={h:c for h,c in hits.items() if c}
    if not hits:
        print("JWT kid/jku/x5u scan: no header-param hits in the jsintel corpus"); return 0
    # scope + pays gate (same discipline as the IDOR ranker) — surface only in-scope+paying hosts
    hostlist=sorted(hits); meta={}
    for i in range(0,len(hostlist),500):
        chunk=hostlist[i:i+500]
        r=es({"size":len(chunk),"_source":["host","triage_payout_tier","triage_pays","triage_in_scope",
              "triage_out_of_scope","triage_ignored","ignore_expires_at","program","triage_program"],
              "query":{"terms":{"host":chunk}}})
        for h in r.get("hits",{}).get("hits",[]):
            s=h["_source"]; meta[s["host"]]=s
    now=datetime.datetime.now(datetime.timezone.utc); rows=[]
    for h in hostlist:
        m=meta.get(h)
        if not m: continue
        if not m.get("triage_pays"): continue
        if m.get("triage_in_scope") is False or m.get("triage_out_of_scope") or m.get("triage_ignored"): continue
        exp=m.get("ignore_expires_at")
        if exp:
            try:
                if datetime.datetime.fromisoformat(exp.replace("Z","+00:00"))>now: continue
            except Exception: pass
        rows.append((h,hits[h],m.get("triage_payout_tier","none") or "none",
                     m.get("program") or m.get("triage_program") or "?"))
    stamp=stamp or "latest"
    outp=os.path.join(HOME,f"recon/briefings/jwt_candidates_{stamp}.md")
    os.makedirs(os.path.dirname(outp),exist_ok=True)
    lines=[f"# JWT kid/jku/x5u header-param candidates — {stamp}",
           f"{len(rows)} in-scope+paying host(s) whose already-collected JS/endpoints reference a JWT header param.",
           "LEAD ONLY (human-in-the-loop; forging a signature is an ACTIVE PoC under the gates). Never auto-exploit.",
           "- **kid** → try path-traversal / SQLi / key-confusion in the kid value (unsanitized lookup key).",
           "- **jku / x5u** → server may fetch signing keys from an attacker URL → forged-token ATO",
           "  (test with an OWNED token; point the URL at an interactsh canary for the fetch).",
           "Source: docs/research/detect-tune_2026-07-11.md §3.",""]
    for h,c,tier,prog in sorted(rows,key=lambda r:-sum(r[1].values())):
        params=", ".join(f"{k}×{v}" for k,v in sorted(c.items()))
        lines.append(f"- [{tier}] `{h}` ({prog}) — {params}")
    open(outp,"w").write("\n".join(lines))
    print(f"JWT header-param scan: {len(rows)} in-scope+paying host(s) flagged (of {len(hits)} corpus hits) → {outp}")
    for h,c,tier,prog in sorted(rows,key=lambda r:-sum(r[1].values()))[:10]:
        print(f"  [{tier}] {h}  {dict(c)}")
    return 0

def main():
    if args.jwt_scan:
        return scan_jwt_headers(args.stamp)
    if not os.path.exists(EP): print("no endpoints.jsonl"); return 1
    # 1) score endpoints
    rows=[]
    seen=set()
    with open(EP) as f:
        for line in f:
            try: j=json.loads(line)
            except: continue
            host=j.get("host",""); ep=j.get("endpoint",""); prog=j.get("program","")
            if not host or not ep: continue
            if THIRDPARTY.match(ep): continue              # endpoint points at a 3rd-party host
            key=(host,ep)
            if key in seen: continue
            seen.add(key)
            # effective host = the endpoint's OWN host for full-URLs (you test THAT host,
            # which may differ from where the JS was found — e.g. accounts2.netgear.com in
            # Bitdefender's OEM JS), else the JS host. Scope is checked against this.
            murl=re.match(r'^https?://([^/:]+)', ep)
            eff_host=murl.group(1) if murl else host
            sc,idt=score_ep(host,ep,j.get("method",""))  # method="" today (producer keeps .url only); wired for when it's captured
            if sc>=args.min_score: rows.append({"host":host,"eff_host":eff_host,"endpoint":ep,"program":prog,"score":sc,"idtype":idt})
    if not rows: print("no candidates >= min-score"); return 0
    # product-class-dup suppression: the same templated endpoint on > FANOUT_MAX
    # distinct hosts is a shipped-product API (e.g. UniFi-OS /proxy/users/...), not
    # a per-target bug. Drop those rows.
    fan=collections.defaultdict(set)
    for r in rows: fan[_fanout_key(r["endpoint"])].add(r["host"])
    before=len(rows)
    rows=[r for r in rows if len(fan[_fanout_key(r["endpoint"])])<=FANOUT_MAX]
    print(f"fanout-suppressed product-class endpoints: {before-len(rows)}")
    # 2) resolve EFFECTIVE host -> tier/scope/benched (batch via ES terms)
    hosts=sorted({r["eff_host"] for r in rows})
    meta={}
    for i in range(0,len(hosts),500):
        chunk=hosts[i:i+500]
        r=es({"size":len(chunk),"_source":["host","triage_payout_tier","triage_pays","triage_in_scope","triage_ignored","triage_out_of_scope","ignore_expires_at"],
              "query":{"terms":{"host":chunk}}})
        for h in r.get("hits",{}).get("hits",[]):
            s=h["_source"]; meta[s["host"]]=s
    TW={"elite":3,"high":2,"mid":1,"low":0.5,"none":0}
    now=datetime.datetime.now(datetime.timezone.utc)
    out=[]
    for r in rows:
        m=meta.get(r["eff_host"])
        if not m: continue                          # endpoint host not in ES (unknown/OOS) -> skip
        if not m.get("triage_pays"): continue        # pays only
        if m.get("triage_in_scope") is False or m.get("triage_out_of_scope"): continue
        if m.get("triage_ignored"): continue          # pipeline-benched (incl. unifi shared-tenant)
        exp=m.get("ignore_expires_at")
        if exp:
            try:
                if datetime.datetime.fromisoformat(exp.replace("Z","+00:00"))>now: continue  # benched
            except Exception: pass
        tier=m.get("triage_payout_tier","none") or "none"
        r["tier"]=tier
        r["rank"]=r["score"]*(TW.get(tier,0.5)+1)
        out.append(r)
    out.sort(key=lambda r:-r["rank"])
    # 3) write worklist
    stamp=args.stamp or "latest"
    outp=args.out or os.path.join(HOME,f"recon/briefings/idor_candidates_{stamp}.md")
    os.makedirs(os.path.dirname(outp),exist_ok=True)
    byhost=collections.defaultdict(list)
    for r in out[:args.top]: byhost[(r["tier"],r["program"],r["eff_host"])].append(r)
    lines=[f"# IDOR/BOLA candidate worklist (ranked) — {stamp}",
           f"From {len(seen)} jsintel endpoints -> {len(out)} scoped paying candidates (>= score {args.min_score}). Top {args.top} shown.",
           "Human 2-account test only (hard line: do NOT enumerate third-party IDs). Numeric-ID = enumerable; UUID = harvest from API list/JS.",
           "MUTATING-BOLA (write verb/method on an object ref) = Action-Level BOLA (~41.7%, highest sev) — test the WRITE, not just the read.",
           "[API] = likely backend (JSON/401) = test directly. [route?] = likely an SPA client route (returns app",
           "shell) -- it REVEALS which resources are id-accessed; test the matching backend /api/<resource>/<id>",
           "with auth (2-account, swap the id). Verify backend-vs-route by probing for JSON/401 vs index.html.",""]
    for (tier,prog,host),eps in sorted(byhost.items(),key=lambda kv:-max(e['rank'] for e in kv[1])):
        lines.append(f"## [{tier}] {host}  ({prog})")
        for e in sorted(eps,key=lambda x:-x["rank"])[:12]:
            lines.append(f"  - [{_backend_hint(e['endpoint'],e['eff_host'])}] `{e['endpoint']}`  score={e['score']} [{e['idtype']}]")
        lines.append("")
    open(outp,"w").write("\n".join(lines))
    print(f"IDOR candidates: {len(out)} scoped paying (from {len(rows)} scored, {len(seen)} endpoints)")
    print(f"worklist -> {outp}")
    # quick top-10 to stdout
    for r in out[:10]:
        print(f"  [{r.get('tier')}] {r['host']}  {r['endpoint']}  score={r['score']} [{r['idtype']}]")
    return 0

sys.exit(main())
