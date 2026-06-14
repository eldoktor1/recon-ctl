#!/usr/bin/env python3
# =============================================================================
# recon_mood.py — "hunt by mood": a lane/class/tech selector for the hunt.
#
# WHY: some evenings you're in the mood for XSS, some for SQLi, some for poking
# WordPress or PHP or API surfaces. Instead of re-deriving an ES query each time,
# name the mood and get a ranked, scope+pays+not-benched, dedup'd "tonight" worklist
# for exactly that lane — the same uniqueness/freshness discipline as the other lanes.
#
# WHAT three mood kinds, auto-detected from the keyword:
#   * PARAM-CLASS (xss sqli ssrf lfi redirect ssti cmdi rce idor debug img-traversal)
#       xss/sqli  -> the ranked dup-proof candidates (recon_xss_sqli_candidates.py)
#       others    -> the recon_params catalog for that gf-class (paying, fresh-first)
#   * TECH (wordpress php drupal jira gitlab jenkins tomcat spring laravel graphql …)
#       -> recon_alive match_phrase on the `tech` field
#   * ANY OTHER KEYWORD (coldfusion, elasticsearch, sharepoint, citrix, …)
#       -> multi_match across tech/classes/signals/kev/host/webserver — so any mood works
# All gated triage_in_scope+triage_pays, exclude benched (ignore_expires_at>now) /
# triage_ignored / out_of_scope, ranked tier×score×freshness, root-diversity-capped,
# already-noted hosts flagged 📝. Output -> ~/recon/briefings/mood_<mood>_<date>.md.
#
# DOCTRINE: a mood is a LENS, NOT a limit. ANY keyword is a valid mood (the broad
# multi_match guarantees it). This script only PICKS the lane's worklist; the HUNT then
# applies the FULL /hunt flow at full depth on those hosts — enumerate (subfinder/
# permutation/CT/jsintel), scan, crawl (katana/gau/params), exhaust each host across every
# angle and adjacent class, with ANY tool available. The mood focuses WHERE you start, it
# never caps the rigor. (operator doctrine 2026-06-14.)
#
# Usage: recon_mood.py <mood> [--top N] [--stamp DATE]   |   recon_mood.py --list
# Read-only (ES only). Confirm/probe is the hunt's job; this just PICKS the lane.
# =============================================================================
import json, subprocess, os, sys, argparse, collections, re

HOME=os.path.expanduser("~")
ES="http://127.0.0.1:9200"; NETRC=os.path.join(HOME,".recon_es_netrc")
ALIVE="recon_alive"; PARAMS="recon_params"
SCRIPT_DIR=os.path.dirname(os.path.abspath(__file__))
NOTES=os.path.join(HOME,"recon/host_notes.jsonl")

PARAM_CLASSES={"xss","sqli","ssrf","lfi","redirect","ssti","cmdi","rce","idor","debug","img-traversal"}
# mood -> exact wappalyzer `tech` value (match_phrase). Extend freely; unknown moods
# fall through to a broad multi_match so ANY keyword still hunts.
TECH={
 "wordpress":"WordPress","wp":"WordPress","php":"PHP","drupal":"Drupal","joomla":"Joomla",
 "jira":"Jira","confluence":"Confluence","gitlab":"GitLab","jenkins":"Jenkins",
 "tomcat":"Apache Tomcat","spring":"Spring","laravel":"Laravel","django":"Django",
 "rails":"Ruby on Rails","aspnet":"Microsoft ASP.NET","dotnet":"Microsoft ASP.NET",
 "node":"Node.js","nodejs":"Node.js","nextjs":"Next.js","react":"React","angular":"Angular",
 "apache":"Apache HTTP Server","nginx":"Nginx","iis":"IIS","magento":"Magento",
 "sharepoint":"Microsoft SharePoint","graphql":"GraphQL","mysql":"MySQL","oracle":"Oracle",
 "coldfusion":"Adobe ColdFusion","wpengine":"WP Engine","shopify":"Shopify",
}
# mood -> host-pattern lane (leftmost-label / substring intent)
HOST_LANE={
 "api":   {"prefixes":["api","apis","gw","gateway"], "contains":[".api."]},
 "admin": {"prefixes":["admin","portal","console","manage","mgmt"], "contains":[]},
 "graphql":{"prefixes":["graphql","gql"], "contains":["graphql"]},
 "auth":  {"prefixes":["auth","login","sso","oauth","oidc","idp"], "contains":[]},
}
# mood -> pipeline SIGNAL lane (triage_kev_signal / triage_classes / triage_signals).
# `boost` floats hosts carrying that signal to the front of the rank.
SIGNAL={
 "cve":  {"filter":[{"exists":{"field":"triage_kev_signal"}}], "boost":"cap:p0-candidate-ungated",
          "hint":"KEV/CVE tech matches (triage_kev_signal = the matched stack). VERSION-REASON FIRST: a "
                 "KEV tech-class match WITHOUT a confirmed in-range version is a LEAD, never P0 (the "
                 "documented FP — clamped by cap:kev-unverified-no-p0; cap:p0-candidate-ungated = higher "
                 "confidence, floated up). Run `recon-nday` for version-reasoned candidates; confirm the "
                 "RUNNING version; template-safety (OOB-canary / read-only matchers only — never "
                 "metadata-harvest / file-read / RCE-for-harm)."},
 "takeover":{"filter":[{"bool":{"should":[{"term":{"triage_classes":"takeover-lead"}},
              {"term":{"triage_classes":"takeover"}},{"prefix":{"triage_signals":"takeover:"}}],
              "minimum_should_match":1}}], "boost":"takeover:confirmed",
          "hint":"Dangling-CNAME takeover LEADS. Confirm CLAIMABILITY (NXDOMAIN / provider 404 / "
                 "NoSuchBucket) before any P0 — a CNAME to a LIVE ELB/CloudFront that 404s is NOT a "
                 "takeover. Check ignored.jsonl / recon-inspect first (ES verdicts can be stale)."},
}
SIGNAL["kev"]=SIGNAL["cve"]; SIGNAL["nday"]=SIGNAL["cve"]; SIGNAL["n-day"]=SIGNAL["cve"]
TIERW={"elite":3,"high":2,"mid":1,"low":0.5,"none":0}

def es(idx,body):
    try:
        r=subprocess.run(["curl","-sS","-m","40","--netrc-file",NETRC,"-H","Content-Type: application/json",
            f"{ES}/{idx}/_search","--data-binary",json.dumps(body)],capture_output=True,text=True)
        return json.loads(r.stdout)
    except Exception as e: return {"_err":str(e)}

def noted_hosts():
    s=set()
    if os.path.exists(NOTES):
        for line in open(NOTES):
            try:
                j=json.loads(line)
                for k in ("host","root_domain"):
                    if j.get(k): s.add(j[k])
            except: pass
    return s

SCOPE_FILTER=[{"term":{"triage_in_scope":True}},{"term":{"triage_pays":True}}]
SCOPE_MUSTNOT=[{"term":{"triage_out_of_scope":True}},{"term":{"triage_ignored":True}},
               {"range":{"ignore_expires_at":{"gt":"now"}}}]

def alive_query(qfilter, qshould=None, pool=500):
    body={"size":pool,
      "_source":["host","root_domain","triage_program","triage_payout_tier","triage_score",
                 "triage_true_fresh","tech","triage_classes","triage_signals","triage_kev_signal","host_notes_count"],
      "query":{"bool":{"filter":SCOPE_FILTER+qfilter,"must_not":SCOPE_MUSTNOT}},
      "sort":[{"triage_score":{"order":"desc","missing":"_last"}},
              {"triage_true_fresh":{"order":"desc","missing":"_last"}}]}
    if qshould:
        body["query"]["bool"]["should"]=qshould
        body["query"]["bool"]["minimum_should_match"]=1
    return es(ALIVE,body)

def rank_alive(hits, noted, top, boost=None):
    rows=[]
    for h in hits:
        s=h.get("_source",{})
        tier=s.get("triage_payout_tier","none") or "none"
        score=s.get("triage_score") or 0
        fresh=bool(s.get("triage_true_fresh"))
        signals=s.get("triage_signals") or []
        rank=score*(TIERW.get(tier,0.5)+1)*(1.5 if fresh else 1)
        if boost and boost in signals: rank*=2.5      # float hosts carrying the boost signal up
        rows.append({"host":s.get("host",""),"root":s.get("root_domain",""),
                     "program":s.get("triage_program","?"),"tier":tier,"score":score,"fresh":fresh,
                     "tech":s.get("tech") or [],"classes":s.get("triage_classes") or [],
                     "signals":signals,"kev":s.get("triage_kev_signal") or "",
                     "noted":bool((s.get("host_notes_count") or 0)) or s.get("host") in noted or s.get("root_domain") in noted,
                     "rank":rank})
    rows.sort(key=lambda r:-r["rank"])
    # root diversity: max 4 hosts per root so one program can't fill the list
    seen=collections.Counter(); out=[]
    for r in rows:
        if seen[r["root"]]>=4: continue
        seen[r["root"]]+=1; out.append(r)
        if len(out)>=top: break
    return out, len(rows)

def fmt_list(v, n=3):
    if isinstance(v,str): v=[v]
    return ", ".join(str(x) for x in v[:n]) if v else ""

def write_alive_report(mood, kind, hint, rows, total, stamp, top):
    outp=os.path.join(HOME,f"recon/briefings/mood_{mood}_{stamp}.md")
    os.makedirs(os.path.dirname(outp),exist_ok=True)
    L=[f"# 🎯 MOOD: {mood} ({kind}) — {stamp}",
       f"{hint}",
       f"{len(rows)} ranked of {total} scope+paying+not-benched hosts. ⚡=fresh(be first) 📝=noted(re-check).",
       ""]
    for r in rows:
        fr="⚡" if r["fresh"] else "  "
        nt=" 📝" if r["noted"] else ""
        ctx=r.get("kev") or fmt_list(r["classes"]) or fmt_list(r["tech"]) or fmt_list(r["signals"])
        L.append(f"{fr}[{r['tier']}] `{r['host']}`{nt}  score={r['score']}  ({r['program']})"+(f"  · {ctx}" if ctx else ""))
    open(outp,"w").write("\n".join(L)+"\n")
    return outp

def do_params_catalog(mood, top, stamp):
    # non-xss/sqli gf-class: pull the catalog for that class (paying, fresh-first), dedup by host
    r=es(PARAMS,{"size":top*8,"_source":["url","host","program","payout_tier","true_fresh"],
        "query":{"bool":{"filter":[{"term":{"vuln_classes":mood}}],
                         "must_not":[{"term":{"payout_tier":"none"}},{"term":{"live_status":"dead"}}]}},
        "sort":[{"true_fresh":{"order":"desc"}},{"cataloged_at":{"order":"desc"}}]})
    hits=r.get("hits",{}).get("hits",[])
    total=r.get("hits",{}).get("total",{}).get("value",0)
    seen=set(); rows=[]
    for h in hits:
        s=h["_source"]; host=s.get("host","")
        if host in seen: continue
        seen.add(host); rows.append(s)
        if len(rows)>=top: break
    outp=os.path.join(HOME,f"recon/briefings/mood_{mood}_{stamp}.md")
    os.makedirs(os.path.dirname(outp),exist_ok=True)
    L=[f"# 🎯 MOOD: {mood} (param-class) — {stamp}",
       f"gf-classified `{mood}` param-URLs from the catalog (paying, fresh-first, 1 rep/host).",
       f"{len(rows)} of {total} catalog URLs.",""]
    for s in rows:
        fr="⚡" if s.get("true_fresh") else "  "
        L.append(f"{fr}[{s.get('payout_tier','?')}] ({s.get('program','?')})  `{s.get('url','')}`")
    open(outp,"w").write("\n".join(L)+"\n")
    print(f"[{mood}] {len(rows)} hosts (of {total} catalog URLs) → {outp}")
    for s in rows[:10]:
        print(f"   [{s.get('payout_tier','?')}] {s.get('url','')[:95]}")
    return outp

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("mood",nargs="?")
    ap.add_argument("--top",type=int,default=40)
    ap.add_argument("--stamp",default="latest")
    ap.add_argument("--list",action="store_true")
    a=ap.parse_args()

    if a.list or not a.mood:
        print("MOODS (a mood is a LENS over the FULL /hunt flow, never a cap on depth):")
        print("  param-class :", " ".join(sorted(PARAM_CLASSES)))
        print("  tech        :", " ".join(sorted(TECH)))
        print("  host-lane   :", " ".join(sorted(HOST_LANE)))
        print("  signal      :", " ".join(sorted(SIGNAL)))
        print("  + ANY keyword (coldfusion, elasticsearch, citrix, …) via broad multi_match")
        print("\nUsage: recon-mood <mood> [--top N]   (picks the lane; the hunt then enumerates/")
        print("       scans/crawls/exhausts those hosts with every tool, per /hunt doctrine)")
        return 0

    mood=a.mood.strip().lower()
    noted=noted_hosts()

    # 1) PARAM-CLASS moods
    if mood in PARAM_CLASSES:
        if mood in ("xss","sqli"):
            print(f"[{mood}] → ranked dup-proof candidates (recon_xss_sqli_candidates.py)")
            return subprocess.call(["python3",os.path.join(SCRIPT_DIR,"recon_xss_sqli_candidates.py"),
                                    "--class",mood,"--stamp",a.stamp,"--top",str(a.top)])
        return 0 if do_params_catalog(mood,a.top,a.stamp) else 1

    # 2) TECH moods (exact wappalyzer value)
    if mood in TECH:
        techval=TECH[mood]
        r=alive_query([{"match_phrase":{"tech":techval}}])
        if r.get("_err") or r.get("error"):
            print("ES error:",r.get("_err") or r.get("error")); return 1
        rows,total=rank_alive(r.get("hits",{}).get("hits",[]),noted,a.top)
        hint=f"tech = {techval}. Hunt this stack's class-specific bugs (n-day/CVE for the version, "\
             f"default panels, known plugin/endpoint paths). Verify the running VERSION before any KEV claim."
        outp=write_alive_report(mood,"tech",hint,rows,total,a.stamp,a.top)
        print(f"[{mood}] tech={techval}: {len(rows)} of {total} hosts → {outp}")
        for r2 in rows[:10]: print(f"   {'⚡' if r2['fresh'] else ' '}[{r2['tier']}] {r2['host']}  ({r2['program']})")
        return 0

    # 3) HOST-LANE moods
    if mood in HOST_LANE:
        lane=HOST_LANE[mood]
        should=[{"prefix":{"host":p+"."}} for p in lane["prefixes"]]+\
               [{"prefix":{"host":p+"-"}} for p in lane["prefixes"]]+\
               [{"wildcard":{"host":f"*{c}*"}} for c in lane["contains"]]
        r=alive_query([],qshould=should)
        if r.get("_err") or r.get("error"):
            print("ES error:",r.get("_err") or r.get("error")); return 1
        rows,total=rank_alive(r.get("hits",{}).get("hits",[]),noted,a.top)
        hint=f"host-lane '{mood}' ({'/'.join(lane['prefixes'])}). API/admin/auth surfaces — map endpoints "\
             f"(swagger/graphql/jsintel), unauth access, then authed BOLA/IDOR with 2 owned accounts."
        outp=write_alive_report(mood,"host-lane",hint,rows,total,a.stamp,a.top)
        print(f"[{mood}] host-lane: {len(rows)} of {total} hosts → {outp}")
        for r2 in rows[:10]: print(f"   {'⚡' if r2['fresh'] else ' '}[{r2['tier']}] {r2['host']}  ({r2['program']})")
        return 0

    # 3.5) SIGNAL moods (cve/kev/nday, takeover) — pipeline finding signals, not tech/host
    if mood in SIGNAL:
        spec=SIGNAL[mood]
        r=alive_query(spec["filter"])
        if r.get("_err") or r.get("error"):
            print("ES error:",r.get("_err") or r.get("error")); return 1
        rows,total=rank_alive(r.get("hits",{}).get("hits",[]),noted,a.top,boost=spec.get("boost"))
        outp=write_alive_report(mood,"signal",spec["hint"],rows,total,a.stamp,a.top)
        print(f"[{mood}] signal: {len(rows)} of {total} hosts → {outp}")
        for r2 in rows[:10]:
            ctx=r2.get("kev") or fmt_list(r2['classes'])
            print(f"   {'⚡' if r2['fresh'] else ' '}[{r2['tier']}] {r2['host']}  ({r2['program']}){'  · '+ctx if ctx else ''}")
        return 0

    # 4) ANY OTHER KEYWORD → broad multi_match (tech/classes/signals/kev/host/webserver)
    should=[{"multi_match":{"query":a.mood,"fields":["tech","triage_classes","triage_signals",
            "triage_kev_signal","webserver"],"type":"phrase"}},
            {"wildcard":{"host":f"*{mood}*"}}]
    r=alive_query([],qshould=should)
    if r.get("_err") or r.get("error"):
        print("ES error:",r.get("_err") or r.get("error")); return 1
    rows,total=rank_alive(r.get("hits",{}).get("hits",[]),noted,a.top)
    if not rows:
        print(f"[{mood}] no scope+paying hosts match — try `recon-mood --list` for known moods."); return 0
    hint=f"keyword '{a.mood}' matched across tech/signals/host. Confirm the match is real per host "\
         f"(tech can be stale); then hunt the class-appropriate bug."
    outp=write_alive_report(mood,"keyword",hint,rows,total,a.stamp,a.top)
    print(f"[{mood}] keyword: {len(rows)} of {total} hosts → {outp}")
    for r2 in rows[:10]:
        ctx=fmt_list(r2['tech']) or fmt_list(r2['classes'])
        print(f"   {'⚡' if r2['fresh'] else ' '}[{r2['tier']}] {r2['host']}  ({r2['program']}){'  · '+ctx if ctx else ''}")
    return 0

sys.exit(main())
