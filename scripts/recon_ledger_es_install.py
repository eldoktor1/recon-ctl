import json, urllib.request, base64, os
N=os.path.expanduser("~/.recon_es_netrc"); pw=""; login="elastic"
for line in open(N):
    p=line.split()
    if "login" in p: login=p[p.index("login")+1]
    if "password" in p: pw=p[p.index("password")+1]
ES="http://127.0.0.1:9200"; AUTH="Basic "+base64.b64encode((login+":"+pw).encode()).decode()
def put(path, body):
    r=urllib.request.Request(ES+path, data=json.dumps(body).encode(), method="PUT",
                             headers={"Content-Type":"application/json","Authorization":AUTH})
    return json.load(urllib.request.urlopen(r,timeout=30))

note_push = ("if(ctx._source.host_notes==null){ctx._source.host_notes=[];} "
             "boolean ex=false; for(def n : ctx._source.host_notes){if(n.note==params.note){ex=true;}} "
             "if(!ex){ctx._source.host_notes.add(['note':params.note,'source':params.source,'created_at':params.created]);} "
             "ctx._source.host_notes_count=ctx._source.host_notes.size(); "
             "def t=''; for(def n : ctx._source.host_notes){t=t+(t==''?'':' || ')+n.note;} "
             "ctx._source.host_notes_text=t; ctx._source.ledger_synced_at=params.now;")
ignore_push = ("ctx._source.ignore_active=true; ctx._source.ignore_reason=params.reason; "
               "ctx._source.ignore_added_at=params.added; "
               "if(params.expires!=''){ctx._source.ignore_expires_at=params.expires;} "
               "ctx._source.ledger_synced_at=params.now;")

print("recon_note_push:", put("/_scripts/recon_note_push", {"script":{"lang":"painless","source":note_push}}))
print("recon_ignore_push:", put("/_scripts/recon_ignore_push", {"script":{"lang":"painless","source":ignore_push}}))
