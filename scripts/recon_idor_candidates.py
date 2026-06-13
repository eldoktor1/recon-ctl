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
# ID type: numeric=enumerable, uuid=harvestable, id-param), boosts sensitive/
# financial resources + API versioning + upload/download, cross-refs ES for
# payout tier / scope, excludes benched hosts, dedups, ranks (tier x score), and
# writes a ranked worklist. ADDITIVE + read-only: touches no daemon state.
#
# Usage: recon_idor_candidates.py [--min-score N] [--top N] [--out FILE]
#        Human runs the 2-account test; this only surfaces & ranks (hard line).
# =============================================================================
import json, subprocess, os, re, sys, argparse, datetime, collections

HOME=os.path.expanduser("~")
EP=os.path.join(HOME,"recon/js_recon/endpoints.jsonl")
ES="http://127.0.0.1:9200/recon_alive"; NETRC=os.path.join(HOME,".recon_es_netrc")

ap=argparse.ArgumentParser()
ap.add_argument("--min-score",type=int,default=4)  # 4 captures /graphql + obj+api; 5 = concrete-ID only
ap.add_argument("--top",type=int,default=60)
ap.add_argument("--out",default=None)
ap.add_argument("--stamp",default=None)  # date string (Date.now unavailable note n/a here)
args=ap.parse_args()

UUID=re.compile(r'/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
NUMID=re.compile(r'/\d{2,}(?:/|$|\?)')
IDPARAM=re.compile(r'[?&](id|.*_?id|uid|account|order|invoice|doc|document|user|member|customer|ref|token|key|file|guid|uuid)=',re.I)
OBJRES=re.compile(r'/(users?|accounts?|orders?|invoices?|documents?|profiles?|messages?|payments?|cards?|transactions?|members?|customers?|files?|reports?|tickets?|subscriptions?|addresses?|contacts?|teams?|orgs?|organizations?|projects?|companies)(/|$)',re.I)
SENS=re.compile(r'(payment|card|invoice|transaction|balance|wallet|clabe|bank|account|kyc|ssn|salary|salaries|tax|statement|withdraw|deposit|transfer|loan|credit|billing|payout)',re.I)
UPDL=re.compile(r'(upload|download|export|attachment|/file|/files|/blob|/media/|presigned)',re.I)
APIV=re.compile(r'/(api|v\d|graphql|rest|service)',re.I)
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

def score_ep(host, ep):
    p=ep
    if NOISE.search(p): return 0,"noise"
    s=0; idt=[]
    if NUMID.search(p): s+=4; idt.append("numeric-ID(enumerable)")
    if UUID.search(p): s+=3; idt.append("uuid")
    if IDPARAM.search(p): s+=3; idt.append("id-param")
    m=OBJRES.search(p)
    if m: s+=2; idt.append("obj:"+m.group(1).lower())
    if APIV.search(p) or host.startswith("api.") or ".api." in host: s+=2; idt.append("api")
    if "graphql" in p.lower(): s+=2; idt.append("graphql")
    if UPDL.search(p): s+=2; idt.append("file")
    if SENS.search(p): s+=3; idt.append("SENSITIVE")
    return s, ",".join(idt) if idt else "-"

def es(body):
    try:
        return json.loads(subprocess.run(["curl","-fsS","-m","30","--netrc-file",NETRC,
            "-H","Content-Type: application/json",f"{ES}/_search","--data-binary",json.dumps(body)],
            capture_output=True,text=True).stdout)
    except Exception: return {}

def main():
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
            sc,idt=score_ep(host,ep)
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
           "Human 2-account test only (hard line: do NOT enumerate third-party IDs). Numeric-ID = enumerable; UUID = harvest from API list/JS.",""]
    for (tier,prog,host),eps in sorted(byhost.items(),key=lambda kv:-max(e['rank'] for e in kv[1])):
        lines.append(f"## [{tier}] {host}  ({prog})")
        for e in sorted(eps,key=lambda x:-x["rank"])[:12]:
            lines.append(f"  - `{e['endpoint']}`  score={e['score']} [{e['idtype']}]")
        lines.append("")
    open(outp,"w").write("\n".join(lines))
    print(f"IDOR candidates: {len(out)} scoped paying (from {len(rows)} scored, {len(seen)} endpoints)")
    print(f"worklist -> {outp}")
    # quick top-10 to stdout
    for r in out[:10]:
        print(f"  [{r.get('tier')}] {r['host']}  {r['endpoint']}  score={r['score']} [{r['idtype']}]")
    return 0

sys.exit(main())
