#!/usr/bin/env python3
"""
es_cluster_sweep.py — Deployment-variant cluster dedup sweep.
Finds all multi-member clusters (hosts differing only by region/env/number label),
keeps the top scorer, penalises the rest: score-5 + hard cap at P0_THRESHOLD-1.
Run after triage.sh is updated; re-run whenever you want to re-sync ES.
"""
import json, subprocess, os, re, sys
from collections import defaultdict

home = os.path.expanduser("~")
netrc = os.path.join(home, ".recon_es_netrc")
ES = "http://127.0.0.1:9200/recon_alive"

# ── Pattern sets (must mirror triage.sh is_region_label / is_env_label) ──────
REGION_RE = re.compile(
    r"^(?:"
    # AWS standard
    r"us-east-[12]|us-west-[12]|eu-west-[1-3]|eu-central-1|eu-north-1"
    r"|ap-southeast-[12]|ap-northeast-[1-3]|ap-south-1|ca-central-1|sa-east-1"
    # AWS + AZ suffix (us-east-1a … us-east-1f)
    r"|(?:us-east-[12]|us-west-[12]|eu-west-[1-3]|eu-central-1"
    r"|ap-southeast-[12]|ap-northeast-[1-3]|ap-south-1|ca-central-1|sa-east-1)[a-f]"
    # GCP
    r"|us-central1|us-east[1-9]|us-west[1-9]"
    r"|northamerica-northeast[12]|southamerica-east1|southamerica-west1"
    r"|europe-west[1-9]|europe-north1|europe-central2|europe-southwest1"
    r"|asia-east[12]|asia-northeast[1-3]|asia-south[12]|asia-southeast[12]"
    r"|australia-southeast[12]|me-west1|me-central1|africa-south1"
    # Azure
    r"|eastus|eastus2|westus|westus2|westus3|centralus|northcentralus|southcentralus|westcentralus"
    r"|eastasia|southeastasia|japaneast|japanwest|australiaeast|australiasoutheast|australiacentral"
    r"|brazilsouth|brazilsoutheast|canadacentral|canadaeast"
    r"|northeurope|westeurope|uksouth|ukwest|francecentral|francesouth"
    r"|germanywestcentral|germanynorth|switzerlandnorth|norwayeast"
    r"|koreacentral|koreasouth|southindia|centralindia|westindia"
    r"|uaenorth|uaecentral|southafricanorth"
    r")$",
    re.IGNORECASE
)
ENV_RE = re.compile(
    r"^(?:"
    # Named tiers
    r"pa|pb|pc|pd|prod-[a-z]|production|preprod|pre-prod|ppe|preview"
    r"|staging|stage|stg|dev|development|qa|uat|test|testing"
    r"|sandbox|sbx|sit|int|integration|alpha|beta|canary|gamma|dark"
    r"|hotfix|release|perf|performance|load|smoke|lab|demo|nightly"
    r"|experimental|feature|feat|local"
    # Env word + 1-2 digits: prod1, dev2, stg01
    r"|(?:prod|production|staging|stg|dev|qa|test|uat|preprod|sandbox|sbx|int|sit|perf|alpha|beta|canary|gamma|stage|preview)[0-9]{1,2}"
    # Infra slots: dc1, az2, zone3, pod1, cell4
    r"|(?:dc|az|zone|pod|cell|colo|rack|shard|node|replica)[0-9]{1,3}"
    # Numbered instance: web1, app01, api2 (2+ letters then 1-3 digits)
    r"|[a-z]{2,}[0-9]{1,3}"
    # Version prefix: v1, v2, v10
    r"|v[0-9]{1,3}"
    # Pure sequence number: 1, 2, 01, 001
    r"|0*[1-9][0-9]{0,2}"
    r")$",
    re.IGNORECASE
)

def is_variant(lbl):
    return bool(REGION_RE.match(lbl) or ENV_RE.match(lbl))

def has_variant(host):
    return any(is_variant(p) for p in host.split("."))

def norm_key(src):
    host = src.get("host", "")
    root = src.get("root_domain", "")
    sigs = sorted(
        s for s in (src.get("triage_signals") or [])
        if not s.startswith(("penalty:", "cap:", "note:"))
    )
    stripped = [p for p in host.split(".") if not is_variant(p)]
    return f"{root}|{'.'.join(stripped)}|{','.join(sigs)}"

def curl_post(path, body, content_type="application/json", timeout=120):
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(body, f)
        fname = f.name
    r = subprocess.run(
        ["curl", "-sS", "-m", str(timeout), "--netrc-file", netrc,
         "-H", f"Content-Type: {content_type}",
         "-X", "POST", f"{ES}{path}",
         "--data-binary", f"@{fname}"],
        capture_output=True, text=True
    )
    os.unlink(fname)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {}

def bulk_post(ndjson_str, timeout=60):
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".ndjson", delete=False) as f:
        f.write(ndjson_str)
        fname = f.name
    r = subprocess.run(
        ["curl", "-sS", "-m", str(timeout), "--netrc-file", netrc,
         "-H", "Content-Type: application/x-ndjson",
         "-X", "POST", f"{ES}/_bulk",
         "--data-binary", f"@{fname}"],
        capture_output=True, text=True
    )
    os.unlink(fname)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {}

# ── Page through all in-scope docs (score >= 4) ───────────────────────────────
FIELDS = ["host", "root_domain", "triage_score", "triage_priority", "triage_signals"]
variant_docs = {}   # doc_id -> source
search_after = None
fetched = 0

print("Scanning ES for in-scope docs with score >= 4 ...", flush=True)
while True:
    body = {
        "size": 5000,
        "_source": FIELDS,
        "query": {"bool": {"filter": [
            {"term": {"triage_in_scope": True}},
            {"range": {"triage_score": {"gte": 4}}}
        ]}},
        "sort": [{"triage_score": {"order": "desc"}}, {"host": {"order": "asc"}}]
    }
    if search_after:
        body["search_after"] = search_after

    resp = curl_post("/_search", body)
    hits = resp.get("hits", {}).get("hits", [])
    if not hits:
        break
    for h in hits:
        src = h["_source"]
        if has_variant(src.get("host", "")):
            variant_docs[h["_id"]] = src
    fetched += len(hits)
    search_after = hits[-1]["sort"]
    sys.stdout.write(f"\r  scanned {fetched:>6}  variant candidates: {len(variant_docs):>5}")
    sys.stdout.flush()
    if len(hits) < 5000:
        break

print(f"\nDone scanning: {fetched} docs  |  variant-label hosts: {len(variant_docs)}", flush=True)

# ── Cluster by normalised key ─────────────────────────────────────────────────
clusters = defaultdict(list)
for doc_id, src in variant_docs.items():
    clusters[norm_key(src)].append((doc_id, src))

multi = {k: v for k, v in clusters.items() if len(v) > 1}
print(f"Multi-member deployment clusters: {len(multi)}", flush=True)

# ── Build bulk update payload ─────────────────────────────────────────────────
P0, P1, P2 = 15, 8, 4
SCRIPT = (
    "ctx._source.triage_score = params.ns;"
    " ctx._source.triage_priority = params.np;"
    " if(ctx._source.triage_signals==null)ctx._source.triage_signals=new ArrayList();"
    " if(!ctx._source.triage_signals.contains(params.sig_pen))"
    "  ctx._source.triage_signals.add(params.sig_pen);"
    " if(params.cap&&!ctx._source.triage_signals.contains(params.sig_cap))"
    "  ctx._source.triage_signals.add(params.sig_cap);"
)

bulk_lines = []
penalized = 0
printed = set()

for key, members in sorted(
    multi.items(),
    key=lambda x: -max(m[1].get("triage_score", 0) for m in x[1])
):
    members.sort(key=lambda m: m[1].get("triage_score", 0), reverse=True)
    rep_id, rep_src = members[0]
    rep_score = rep_src.get("triage_score", 0)
    if rep_score < P2:
        continue

    rep_host = rep_src.get("host", "?")
    non_reps_to_update = []
    for doc_id, src in members[1:]:
        # Skip if already has the penalty (from prior run)
        if "penalty:regional-cluster-member" in (src.get("triage_signals") or []):
            continue
        non_reps_to_update.append((doc_id, src))

    if not non_reps_to_update:
        continue

    if rep_host not in printed:
        print(f"  cluster [{len(members)}]  rep={rep_host} (score={rep_score})", flush=True)
        printed.add(rep_host)

    for doc_id, src in non_reps_to_update:
        old = src.get("triage_score", 0)
        new_s = old - 5
        if new_s >= P0:
            new_s = P0 - 1
        new_p = ("P0" if new_s >= P0 else
                 "P1" if new_s >= P1 else
                 "P2" if new_s >= P2 else "P3")
        capped = (old - 5) >= P0
        bulk_lines.append(json.dumps({"update": {"_id": doc_id}}))
        bulk_lines.append(json.dumps({
            "script": {
                "lang": "painless",
                "source": SCRIPT,
                "params": {
                    "ns": new_s, "np": new_p, "cap": capped,
                    "sig_pen": "penalty:regional-cluster-member",
                    "sig_cap": "cap:regional-no-p0"
                }
            }
        }))
        print(f"    {src.get('host','?')}  {old}->{new_s} ({new_p})", flush=True)
        penalized += 1

print(f"\nNon-reps to update: {penalized}", flush=True)

# ── Send bulk in chunks of 400 ops ────────────────────────────────────────────
CHUNK = 400
sent = errors = 0
for i in range(0, len(bulk_lines), CHUNK * 2):
    chunk = bulk_lines[i:i + CHUNK * 2]
    ndjson = "\n".join(chunk) + "\n"
    resp = bulk_post(ndjson)
    chunk_errors = sum(
        1 for item in resp.get("items", [])
        if "error" in item.get("update", {})
    )
    errors += chunk_errors
    sent += len(chunk) // 2
    print(f"  bulk chunk {i // (CHUNK*2) + 1}: {len(chunk)//2} ops, {chunk_errors} errors", flush=True)

# Force refresh so next search sees updated scores
subprocess.run(
    ["curl", "-sS", "-m", "10", "--netrc-file", netrc,
     "-X", "POST", f"{ES}/_refresh"],
    capture_output=True
)

print(f"\n=== sweep done: {sent} updates sent, {errors} errors ===", flush=True)
