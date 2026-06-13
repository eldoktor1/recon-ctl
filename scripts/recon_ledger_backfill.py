import json, urllib.request, base64, os, datetime, collections

N = os.path.expanduser("~/.recon_es_netrc")
pw = ""; login = "elastic"
for line in open(N):
    p = line.split()
    if "login" in p: login = p[p.index("login") + 1]
    if "password" in p: pw = p[p.index("password") + 1]
ES = "http://127.0.0.1:9200"
AUTH = "Basic " + base64.b64encode((login + ":" + pw).encode()).decode()
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(ES + path, data=data, method=method,
                               headers={"Content-Type": "application/json", "Authorization": AUTH})
    return json.load(urllib.request.urlopen(r, timeout=120))

# 1) ADDITIVE MAPPING ------------------------------------------------------
mapping = {"properties": {
    "host_notes": {"type": "object", "properties": {
        "note": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 2048}}},
        "source": {"type": "keyword"},
        "created_at": {"type": "date"}}},
    "host_notes_count": {"type": "integer"},
    "host_notes_text": {"type": "text"},
    "ignore_active": {"type": "boolean"},
    "ignore_reason": {"type": "keyword"},
    "ignore_added_at": {"type": "date"},
    "ignore_expires_at": {"type": "date"},
    "ledger_synced_at": {"type": "date"},
}}
print("PUT mapping:", req("PUT", "/recon_alive/_mapping", mapping))

# 2) LOAD LEDGERS ----------------------------------------------------------
def parse(ts):
    try: return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except: return None
nowdt = datetime.datetime.now(datetime.timezone.utc)

notes = collections.defaultdict(list)
for l in open(os.path.expanduser("~/recon/state/host_notes.jsonl")):
    if not l.strip(): continue
    r = json.loads(l)
    key = (r["host"], r.get("note", ""))
    notes[r["host"]].append({"note": r.get("note", ""), "source": r.get("source", "manual"),
                             "created_at": r.get("created_at", now)})
# dedup per host on note text
for h in notes:
    seen = set(); uniq = []
    for n in notes[h]:
        if n["note"] in seen: continue
        seen.add(n["note"]); uniq.append(n)
    notes[h] = uniq

ignores = {}
for l in open(os.path.expanduser("~/recon/state/ignored.jsonl")):
    if not l.strip(): continue
    r = json.loads(l)
    exp = parse(r.get("expires_at", ""))
    cur = ignores.get(r["host"])
    # keep the latest-added entry
    if cur is None or r.get("added_at", "") > cur.get("added_at", ""):
        ignores[r["host"]] = {"reason": r.get("reason", ""), "added_at": r.get("added_at", now),
                              "expires_at": r.get("expires_at", ""), "active": bool(exp and exp > nowdt)}

allhosts = set(notes) | set(ignores)
print("hosts to sync: %d (noted=%d, ignored=%d)" % (len(allhosts), len(notes), len(ignores)))

# 3) BACKFILL via _update_by_query (matches ALL docs for the host) ---------
ok = miss = 0
for h in sorted(allhosts):
    setsrc = []
    params = {"now": now}
    if h in notes:
        params["notes"] = notes[h]
        params["ntext"] = " || ".join(n["note"] for n in notes[h])
        setsrc.append("ctx._source.host_notes=params.notes;"
                      "ctx._source.host_notes_count=params.notes.size();"
                      "ctx._source.host_notes_text=params.ntext;")
    if h in ignores:
        ig = ignores[h]
        params["ig_reason"] = ig["reason"]; params["ig_added"] = ig["added_at"]
        params["ig_active"] = ig["active"]
        setsrc.append("ctx._source.ignore_active=params.ig_active;"
                      "ctx._source.ignore_reason=params.ig_reason;"
                      "ctx._source.ignore_added_at=params.ig_added;")
        if ig["expires_at"]:
            params["ig_exp"] = ig["expires_at"]
            setsrc.append("ctx._source.ignore_expires_at=params.ig_exp;")
    setsrc.append("ctx._source.ledger_synced_at=params.now;")
    body = {"query": {"term": {"host": h}},
            "script": {"source": "".join(setsrc), "lang": "painless", "params": params}}
    try:
        res = req("POST", "/recon_alive/_update_by_query?conflicts=proceed&refresh=false", body)
        if res.get("updated", 0) > 0: ok += 1
        else: miss += 1
    except Exception as e:
        miss += 1
        print("  ERR %s: %s" % (h, str(e)[:80]))
print("backfill done: docs-updated-hosts=%d  no-matching-doc=%d" % (ok, miss))
req("POST", "/recon_alive/_refresh")
print("refreshed.")
