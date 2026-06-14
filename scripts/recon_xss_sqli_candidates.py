#!/usr/bin/env python3
# =============================================================================
# recon_xss_sqli_candidates.py — rank the XSS / SQLi reflected-param worklist.
#
# WHY (rs0n's idea, made dup-proof): recon_params.sh crawls every in-scope+paying
# host and gf-classifies its param-URLs into vuln classes — a queryable catalog
# (~18k XSS, ~3k SQLi URLs across 5 platforms). But `recon-params list xss` is a
# RAW DUMP (fresh-first, no exploitability ranking), and the same dup-magnet param
# (?q= on 500 WordPress sites) sits next to a rare per-app sink. rs0n's mass-XSS
# sweep finds what everyone finds = duplicates = $0 (our MOTTO). So the high-leverage
# step is to RANK the catalog by injectability + uniqueness + freshness and SPLIT the
# rare per-app lanes (worth manual testing) from the high-fanout product-class dup
# magnets — turning the dump into "tonight's real XSS/SQLi lanes".
#
# WHAT: for each catalog param-URL, score by PARAM-NAME signal (the kxss insight —
# reflective names reflect, id/cat/numeric inject), handler/path hints (.php/.asp/
# /api/), freshness, payout tier; dedup by (host,path,param-set) template; measure
# template fan-out across hosts and split UNIQUE (low-fanout) from PRODUCT-CLASS
# (high-fanout, dup-risk); cross-ref recon_alive to drop actively-benched hosts and
# flag already-noted (worked) hosts; write a ranked worklist per class.
# ADDITIVE + read-only: queries recon_params/recon_alive, touches no daemon state.
#
# Usage: recon_xss_sqli_candidates.py [--class xss|sqli|both] [--top N] [--out-dir D]
# Confirmation is a SEPARATE step (dalfox / safe ' vs '' diff) — this only surfaces
# & ranks. SQLi testing stays the SAFE differential primitive (never a data harvest).
# =============================================================================
import json, subprocess, os, re, sys, argparse, collections
from urllib.parse import urlsplit, parse_qsl
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from recon_fp_footer import FP_FOOTER   # single source of the ZERO-FP discipline footer

HOME = os.path.expanduser("~")
ES = "http://127.0.0.1:9200"
NETRC = os.path.join(HOME, ".recon_es_netrc")
PARAMS_INDEX = "recon_params"
ALIVE_INDEX = "recon_alive"
NOTES_FILE = os.path.join(HOME, "recon/host_notes.jsonl")

ap = argparse.ArgumentParser()
ap.add_argument("--class", dest="cls", choices=["xss", "sqli", "both"], default="both")
ap.add_argument("--top", type=int, default=80)
ap.add_argument("--per-host", type=int, default=8)
ap.add_argument("--out-dir", default=os.path.join(HOME, "recon/briefings"))
ap.add_argument("--stamp", default="latest")
ap.add_argument("--fanout-max", type=int, default=6)  # same (path,param-set) on > this many hosts = product-class
args = ap.parse_args()

# ---- param-name signal tables (the heart of the ranking) --------------------
# XSS: params whose values get REFLECTED into HTML/JS — kxss/rs0n telltales.
XSS_W = {}
for n in ("q","query","search","s","keyword","keywords","kw","term","redirect","redirect_uri",
          "redirect_url","redirecturl","return","returnurl","return_url","returnto","return_to",
          "next","url","uri","callback","jsonp","dest","destination","continue","goto","r","u","link"):
    XSS_W[n] = 3
for n in ("name","message","msg","comment","text","title","subject","body","content","value",
          "input","data","error","err","desc","description","page","view","lang","ref","q1","output"):
    XSS_W[n] = 2
for n in ("id","email","file","path","src","item","type","action","mode","tab","filter","sort","field"):
    XSS_W[n] = 1

# SQLi: params that hit a query — object/numeric refs + classic injectable handlers.
SQLI_W = {}
for n in ("id","uid","pid","cid","catid","cat","category","item","itemid","product","productid",
          "news","newsid","article","articleid","page_id","pageid","user_id","userid","account",
          "accountid","order","orderid","oid","sid","gid","eid","recordid","rid","no","num","key"):
    SQLI_W[n] = 3
for n in ("page","p","sort","order","orderby","filter","search","q","query","where","type","status",
          "year","month","day","view","group","limit","offset","start","code","ref","class"):
    SQLI_W[n] = 2
for n in ("name","email","user","login","title","lang","keyword","tag","city","country"):
    SQLI_W[n] = 1

# dynamic server-side handler extensions = strong inject/reflect surface
HANDLER = re.compile(r'\.(php\d?|asp|aspx|aspx?|jsp|jspx|cgi|pl|do|action|cfm|cfc|phtml)(/|$)', re.I)
APIV = re.compile(r'/(api|v\d+|graphql|rest|services?)(/|$)', re.I)
NOISE = re.compile(r'\.(js|css|png|jpe?g|svg|gif|woff2?|ttf|ico|map|pdf|zip|mp4|webp)(\?|$)', re.I)
# wayback captures ATTACKER fuzz-traffic: malformed paths with encoded quotes/brackets,
# raw injection chars, traversal. These are NOT real endpoints — drop them outright.
ATTACK_PATH = re.compile(r'%22|%3c|%3e|%27|%00|%2e%2e|\.\./|[<>"\'{}\\]|\bFUZZ\b', re.I)
# locale segments (/en_gb/ /de-at/ /zh_cn/) — collapse so 30 locale variants of one page
# become ONE template instead of 30 fake-unique lanes.
LOCALE = re.compile(r'/[a-z]{2}[_-][a-z]{2}(?=/|$)', re.I)
MAX_PARAMS = 8   # a real param-URL has a handful; >8 distinct params = wayback fuzz-capture junk


def _norm_path(path):
    p = LOCALE.sub('/{loc}', path or "/")
    p = re.sub(r'/\d{2,}', '/{id}', p)   # numeric path-IDs (/c/501, /article/12345) collapse like the IDOR ranker
    return p


def score_url(url, cls):
    """Return (score, reasons[], param_names[]) for URL under class cls."""
    try:
        sp = urlsplit(url)
    except Exception:
        return 0, [], []
    path = sp.path or "/"
    if NOISE.search(url):
        return 0, ["noise-ext"], []
    # drop wayback-captured attack traffic (malformed path = not a real endpoint)
    if ATTACK_PATH.search(path):
        return 0, ["attack-capture"], []
    qs = parse_qsl(sp.query, keep_blank_values=True)
    if not qs:
        return 0, ["no-params"], []
    names = [k.lower() for k, _ in qs]
    if len(set(names)) > MAX_PARAMS:
        return 0, ["param-flood"], []   # fuzz-capture: too many params to be a real form
    W = XSS_W if cls == "xss" else SQLI_W
    # score on the STRONGEST few params (a focused ?redirect= beats 8 random params),
    # not the raw sum — sum rewards fuzz-capture junk.
    weights = sorted((W.get(n, 0) for n in set(names)), reverse=True)
    s = sum(weights[:3])
    hit_params = sorted({n for n in set(names) if W.get(n, 0)})
    reasons = []
    if hit_params:
        reasons.append(("inject-params:" if cls == "sqli" else "reflect-params:") + ",".join(hit_params[:5]))
    if HANDLER.search(path):
        s += 2
        reasons.append("dynamic-handler")
    if APIV.search(path):
        s += 1
        reasons.append("api")
    depth = _norm_path(path).strip("/").count("/")
    if depth >= 2:
        s += 1
        reasons.append(f"depth{depth}")
    return s, reasons, names


def template_key(url):
    """host-stripped (locale-normalized path + sorted param-name-set) — collapses the
    same shipped endpoint / locale variants across hosts for fan-out detection."""
    try:
        sp = urlsplit(url)
    except Exception:
        return url
    names = sorted({k.lower() for k, _ in parse_qsl(sp.query, keep_blank_values=True)})
    return _norm_path(sp.path) + "?" + ",".join(names)


def es(idx, body):
    try:
        r = subprocess.run(["curl", "-sS", "-m", "40", "--netrc-file", NETRC,
                            "-H", "Content-Type: application/json",
                            f"{ES}/{idx}/_search", "--data-binary", json.dumps(body)],
                           capture_output=True, text=True)
        return json.loads(r.stdout)
    except Exception as e:
        return {"_err": str(e)}


def pull_catalog(cls):
    """search_after-page the whole class out of recon_params (catalog is already
    in-scope+paying; the producer enforces that). Drop liveness-dead."""
    rows = []
    after = None
    while True:
        body = {
            "size": 5000,
            "_source": ["url", "host", "root_domain", "program", "payout_tier", "true_fresh", "live_status"],
            "query": {"bool": {
                "filter": [{"term": {"vuln_classes": cls}}],
                "must_not": [{"term": {"payout_tier": "none"}}, {"term": {"live_status": "dead"}}],
            }},
            "sort": [{"cataloged_at": {"order": "desc", "missing": "_last"}}, {"url": {"order": "asc"}}],
        }
        if after:
            body["search_after"] = after
        r = es(PARAMS_INDEX, body)
        if "_err" in r:
            print(f"  ES error: {r['_err']}", file=sys.stderr)
            break
        if r.get("error"):
            print(f"  ES query error: {r.get('error')}", file=sys.stderr)
            break
        hits = r.get("hits", {}).get("hits", [])
        if not hits:
            break
        for h in hits:
            rows.append(h["_source"])
        after = hits[-1].get("sort")
        if not after or len(hits) < 5000:
            break
    return rows


def resolve_hosts(hosts):
    """batch recon_alive: ignore_expires_at (benched) + host_notes_count (worked).
    The catalog can predate an operator ignore, so re-check the live ledger."""
    meta = {}
    hosts = sorted(set(hosts))
    for i in range(0, len(hosts), 500):
        chunk = hosts[i:i+500]
        r = es(ALIVE_INDEX, {"size": len(chunk),
                             "_source": ["host", "ignore_expires_at", "host_notes_count", "triage_out_of_scope"],
                             "query": {"terms": {"host": chunk}}})
        for h in r.get("hits", {}).get("hits", []):
            s = h["_source"]
            meta[s.get("host")] = s
    return meta


TW = {"elite": 3, "high": 2, "mid": 1, "low": 0.5, "none": 0}


def build(cls, meta_cache):
    rows = pull_catalog(cls)
    if not rows:
        print(f"  [{cls}] no catalog rows", file=sys.stderr)
        return None
    # score + collapse param-variants of the same (host,path,param-set) to one rep
    groups = {}  # (host, template) -> best row
    for r in rows:
        url = r.get("url", "")
        host = r.get("host", "")
        if not url or not host:
            continue
        sc, reasons, _ = score_url(url, cls)
        if sc <= 0:
            continue
        tk = template_key(url)
        gk = (host, tk)
        pset = tk.split("?", 1)[1] if "?" in tk else ""
        cur = groups.get(gk)
        if cur is None or sc > cur["score"]:
            groups[gk] = {"url": url, "host": host, "root": r.get("root_domain", ""),
                          "program": r.get("program", ""), "tier": r.get("payout_tier", "none") or "none",
                          "fresh": bool(r.get("true_fresh")), "score": sc, "reasons": reasons,
                          "template": tk, "pset": pset, "live": r.get("live_status", "")}
    cands = list(groups.values())
    if not cands:
        print(f"  [{cls}] no scored candidates", file=sys.stderr)
        return None
    # fan-out: distinct hosts per template across the whole class
    fan = collections.defaultdict(set)
    for c in cands:
        fan[c["template"]].add(c["host"])
    for c in cands:
        c["fanout"] = len(fan[c["template"]])
    # cross-ref live ledger for benched/noted (reuse a shared cache across classes)
    need = [c["host"] for c in cands if c["host"] not in meta_cache]
    if need:
        meta_cache.update(resolve_hosts(need))
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    kept = []
    benched = 0
    for c in cands:
        m = meta_cache.get(c["host"], {})
        if m.get("triage_out_of_scope"):
            continue
        exp = m.get("ignore_expires_at")
        if exp:
            try:
                if datetime.datetime.fromisoformat(exp.replace("Z", "+00:00")) > now:
                    benched += 1
                    continue
            except Exception:
                pass
        c["noted"] = int(m.get("host_notes_count") or 0) > 0
        # final rank: score x (tier+1) x freshness-boost, then fan-out splits the lists
        rank = c["score"] * (TW.get(c["tier"], 0.5) + 1)
        if c["fresh"]:
            rank *= 1.5
        c["rank"] = rank
        kept.append(c)
    kept.sort(key=lambda x: -x["rank"])
    unique = [c for c in kept if c["fanout"] <= args.fanout_max]
    product = [c for c in kept if c["fanout"] > args.fanout_max]
    return {"unique": unique, "product": product, "benched": benched,
            "total_rows": len(rows), "scored": len(cands)}


def write_report(cls, data, out_dir, stamp):
    os.makedirs(out_dir, exist_ok=True)
    outp = os.path.join(out_dir, f"{cls}_candidates_{stamp}.md")
    label = "XSS reflected-param" if cls == "xss" else "SQLi injectable-param"
    L = [f"# {label} candidate worklist (ranked) — {stamp}",
         f"From {data['total_rows']} catalog URLs → {data['scored']} scored → "
         f"{len(data['unique'])} UNIQUE + {len(data['product'])} product-class lanes "
         f"({data['benched']} benched-host URLs dropped).",
         "⚡=true_fresh (be first, low-dup)  📝=host already noted (worked — re-check note first)  "
         f"f{args.fanout_max}+=product-class (dup-risk).",
         ""]
    if cls == "xss":
        L.append("CONFIRM: `recon-params confirm xss <host>` (dalfox, context-aware). Reflection ≠ XSS — "
                 "break-out chars must survive UNENCODED in an executable context.")
    else:
        L.append("CONFIRM (SAFE diff only): `' vs ''` error/boolean differential. HARD LINE: never sqlmap "
                 "--dump / data harvest / large traffic — confirm injectable, then STOP.")
    L.append("")

    def emit(section, items, cap):
        if not items:
            return
        L.append(f"## {section}")
        byhost = collections.defaultdict(list)
        for c in items[:cap]:
            byhost[(c["tier"], c["program"], c["host"])].append(c)
        for (tier, prog, host), eps in sorted(byhost.items(), key=lambda kv: -max(e["rank"] for e in kv[1])):
            flag = " 📝" if eps[0].get("noted") else ""
            L.append(f"### [{tier}] {host}{flag}  ({prog})")
            # collapse to DISTINCT param-surfaces within the host (8 category pages with the
            # same ?page&q&sort = ONE lane, test once); show best rep + how many paths share it.
            bypset = collections.defaultdict(list)
            for e in eps:
                bypset[e["pset"]].append(e)
            reps = [max(v, key=lambda x: x["rank"]) | {"npaths": len(v)} for v in bypset.values()]
            for e in sorted(reps, key=lambda x: -x["rank"])[:args.per_host]:
                fr = "⚡" if e["fresh"] else "  "
                fo = f" f{e['fanout']}" if e["fanout"] > args.fanout_max else ""
                np = f" ×{e['npaths']}paths" if e["npaths"] > 1 else ""
                L.append(f"  {fr} `{e['url']}`  score={e['score']}{fo}{np}  [{'; '.join(e['reasons'])}]")
            L.append("")

    emit("TOP UNIQUE LANES (rare per-app params — test these first)", data["unique"], args.top)
    emit("PRODUCT-CLASS (high fan-out — dup-risk; only if fresh / your own program)", data["product"], max(20, args.top // 2))
    open(outp, "w").write("\n".join(L) + FP_FOOTER)
    return outp


def main():
    classes = ["xss", "sqli"] if args.cls == "both" else [args.cls]
    meta_cache = {}
    for cls in classes:
        data = build(cls, meta_cache)
        if not data:
            continue
        outp = write_report(cls, data, args.out_dir, args.stamp)
        print(f"[{cls}] {len(data['unique'])} unique + {len(data['product'])} product-class "
              f"(from {data['scored']} scored / {data['total_rows']} catalog) → {outp}")
        for c in data["unique"][:8]:
            fr = "⚡" if c["fresh"] else " "
            print(f"   {fr}[{c['tier']}] {c['host']}  score={c['score']}  {c['url'][:90]}")
    return 0


sys.exit(main())
