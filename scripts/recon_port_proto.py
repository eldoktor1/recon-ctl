#!/usr/bin/env python3
"""
recon_port_proto.py — stop reporting port numbers, start reporting what is inside them.

The portscan lane has minted 96 findings and produced zero real verdicts. It reports
"port 6379 is open", which is not a vulnerability: behind a CDN every port ACKs, and an
open port on a hardened service is the normal state. Every scanner on earth reports the
same line on the same day, so it is a duplicate before it is written.

The finding is not the port. The finding is:

    "Unauthenticated Redis 7.0.11 on this host, 4.1M keys, no AUTH required."
    "Elasticsearch with 38 indices readable anonymously, including `customers`."
    "Docker Engine API exposed without TLS — full container control."

So this lane SPEAKS THE PROTOCOL and tests whether the service actually lets a stranger in.
A service that demands credentials is recorded as a negative and never minted.

SAFETY — read-only verbs only, and the list is deliberately short:
  * Redis        PING, INFO, DBSIZE           (never KEYS/SCAN/GET — no data is read)
  * Memcached    stats                        (never get/set)
  * Elasticsearch GET /_cluster/health, /_cat/indices  (never a document query)
  * CouchDB      GET /_all_dbs
  * Docker       GET /_ping, /version, /containers/json   (never create/exec/start)
  * Kubelet      GET /pods                    (never /exec, never /run)
  * MongoDB      isMaster handshake only
  * Zookeeper    stat / ruok
  * RabbitMQ / Jenkins / Kibana  unauth landing check only
  Nothing writes. Nothing deletes. Nothing executes. No records are read — we count them.
  A CDN-fronted host is skipped outright because its port results are meaningless.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

BASE_DIR = os.environ.get("BASE_DIR", os.path.expanduser("~/recon"))
STATE_DIR = os.environ.get("STATE_DIR", os.path.join(BASE_DIR, "state"))
REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCOPE_CHECK = os.path.join(REPO_DIR, "scripts", "recon_scope_check.sh")
AUDIT = os.path.join(STATE_DIR, "port_proto_audit.jsonl")
OUT_DIR = os.path.join(BASE_DIR, "ports")

sys.path.insert(0, REPO_DIR)
from engine import impact  # noqa: E402

TIMEOUT = float(os.environ.get("PROTO_TIMEOUT", "6"))
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/127.0.0.0 Safari/537.36"

CDN_HINT = re.compile(r"(cloudflare|akamai|fastly|cloudfront|incapsula|sucuri|azureedge|"
                      r"edgekey|edgesuite|llnwd|stackpath|bunnycdn)", re.I)


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(m: str) -> None:
    print(f"[proto] {m}", file=sys.stderr, flush=True)


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


def is_cdn(host: str) -> str:
    """A CDN ACKs every port, so port results behind one prove nothing. >6 'open' critical
    ports on a single host is a scan artefact, not a finding."""
    try:
        req = urllib.request.Request(f"https://{host}/", method="HEAD")
        req.add_header("User-Agent", UA)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx)).open(
                req, timeout=8) as r:
            hs = " ".join(f"{k}: {v}" for k, v in r.headers.items())
    except urllib.error.HTTPError as e:
        hs = " ".join(f"{k}: {v}" for k, v in (e.headers or {}).items())
    except Exception:
        return ""
    m = CDN_HINT.search(hs)
    return m.group(0).lower() if m else ""


# ------------------------------------------------------------------ raw socket
CONNECT_TIMEOUT = float(os.environ.get("PROTO_CONNECT_TIMEOUT", "1.5"))
_RESOLVED: dict[str, str] = {}


def resolve(host: str) -> str:
    """Resolve ONCE per host. socket.create_connection re-resolves on every call and then
    tries every A record in turn, applying the full timeout to each — on a host with four
    addresses that turns a 1.5s check into 6s, per port."""
    if host in _RESOLVED:
        return _RESOLVED[host]
    try:
        ip = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except Exception:
        ip = ""
    _RESOLVED[host] = ip
    return ip


def port_open(host: str, port: int) -> bool:
    """Cheap single-address reachability check before spending a protocol timeout."""
    ip = resolve(host)
    if not ip:
        return False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(CONNECT_TIMEOUT)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        s.close()


def open_ports(host: str, ports: list[int]) -> list[int]:
    """Check every candidate port concurrently — the whole sweep costs one timeout."""
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(16, len(ports) or 1)) as ex:
        return [p for p, ok in zip(ports, ex.map(lambda x: port_open(host, x), ports)) if ok]


def tcp(host: str, port: int, payload: bytes = b"", read: int = 4096) -> bytes:
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as s:
            s.settimeout(TIMEOUT)
            if payload:
                s.sendall(payload)
            buf = b""
            while len(buf) < read:
                try:
                    c = s.recv(min(4096, read - len(buf)))
                except socket.timeout:
                    break
                if not c:
                    break
                buf += c
                if len(c) < 4096:
                    break
            return buf
    except Exception:
        return b""


def http(host: str, port: int, path: str, scheme: str = "http", read: int = 200_000) -> dict:
    url = f"{scheme}://{host}:{port}{path}"
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", UA)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        with op.open(req, timeout=TIMEOUT) as r:
            return {"status": r.status, "body": r.read(read)}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": b""}
    except Exception:
        return {"status": 0, "body": b""}


# --------------------------------------------------------------------- probes
def probe_redis(host: str, port: int) -> dict | None:
    r = tcp(host, port, b"*1\r\n$4\r\nPING\r\n")
    if not r:
        return None
    if b"NOAUTH" in r or b"WRONGPASS" in r or b"operation not permitted" in r:
        return {"service": "redis", "authed": True, "detail": "AUTH required (correct)"}
    if b"+PONG" not in r:
        return None
    info = tcp(host, port, b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n", read=8192)
    ver = ""
    m = re.search(rb"redis_version:([\d.]+)", info)
    if m:
        ver = m.group(1).decode()
    dbs = tcp(host, port, b"*1\r\n$6\r\nDBSIZE\r\n", read=256)
    keys = ""
    m = re.match(rb":(\d+)", dbs.strip())
    if m:
        keys = m.group(1).decode()
    return {"service": "redis", "authed": False, "version": ver, "keys": keys,
            "detail": f"NO AUTH — Redis {ver or '?'} responded to PING"
                      + (f", DBSIZE={keys} keys" if keys else "")}


def probe_memcached(host: str, port: int) -> dict | None:
    r = tcp(host, port, b"stats\r\n", read=8192)
    if b"STAT " not in r:
        return None
    ver = ""
    m = re.search(rb"STAT version ([\w.]+)", r)
    if m:
        ver = m.group(1).decode()
    items = ""
    m = re.search(rb"STAT curr_items (\d+)", r)
    if m:
        items = m.group(1).decode()
    return {"service": "memcached", "authed": False, "version": ver, "keys": items,
            "detail": f"NO AUTH — memcached {ver or '?'} stats readable"
                      + (f", curr_items={items}" if items else "")}


def probe_elastic(host: str, port: int) -> dict | None:
    for scheme in ("http", "https"):
        r = http(host, port, "/", scheme)
        if r["status"] == 401:
            return {"service": "elasticsearch", "authed": True, "detail": "auth required (correct)"}
        if r["status"] != 200 or b"cluster_name" not in r["body"]:
            continue
        ver = ""
        try:
            ver = (json.loads(r["body"]).get("version") or {}).get("number", "")
        except Exception:
            pass
        cat = http(host, port, "/_cat/indices?format=json&h=index,docs.count", scheme)
        idx, docs, names = 0, 0, []
        if cat["status"] == 200:
            try:
                j = json.loads(cat["body"])
                idx = len(j)
                names = [x.get("index", "") for x in j][:15]
                docs = sum(int(x.get("docs.count") or 0) for x in j)
            except Exception:
                pass
        return {"service": "elasticsearch", "authed": False, "version": ver,
                "indices": idx, "docs": docs, "index_names": names,
                "detail": f"NO AUTH — Elasticsearch {ver or '?'}, {idx} indices "
                          f"readable anonymously ({docs:,} docs)"}
    return None


def probe_couchdb(host: str, port: int) -> dict | None:
    for scheme in ("http", "https"):
        r = http(host, port, "/_all_dbs", scheme)
        if r["status"] == 401:
            return {"service": "couchdb", "authed": True, "detail": "auth required (correct)"}
        if r["status"] == 200 and r["body"].lstrip().startswith(b"["):
            try:
                dbs = json.loads(r["body"])
            except Exception:
                return None
            return {"service": "couchdb", "authed": False, "indices": len(dbs),
                    "index_names": dbs[:15],
                    "detail": f"NO AUTH — CouchDB, {len(dbs)} databases listable anonymously"}
    return None


def probe_docker(host: str, port: int) -> dict | None:
    for scheme in ("http", "https"):
        r = http(host, port, "/version", scheme)
        if r["status"] != 200 or b"ApiVersion" not in r["body"]:
            continue
        ver = ""
        try:
            ver = json.loads(r["body"]).get("Version", "")
        except Exception:
            pass
        c = http(host, port, "/containers/json", scheme)
        n = 0
        if c["status"] == 200:
            try:
                n = len(json.loads(c["body"]))
            except Exception:
                pass
        return {"service": "docker-engine-api", "authed": False, "version": ver,
                "containers": n, "critical": True,
                "detail": f"NO AUTH — Docker Engine API {ver or '?'} exposed without TLS; "
                          f"{n} container(s) listable. This is full host control."}
    return None


def probe_kubelet(host: str, port: int) -> dict | None:
    r = http(host, port, "/pods", "https")
    if r["status"] in (401, 403):
        # A CDN or reverse proxy answers HTTPS on ANY port and 401/403s unknown paths, so a
        # bare 401 here does not mean a kubelet exists. Require kubelet-shaped evidence
        # before claiming one — otherwise every CDN-fronted host reads as "kubelet enforcing".
        body = r["body"] or b""
        if not re.search(rb"(?i)(kubelet|Unauthorized|forbidden.*user|system:anonymous)", body):
            return None
        return {"service": "kubelet", "authed": True, "detail": "auth required (correct)"}
    if r["status"] == 200 and b'"kind"' in r["body"]:
        n = 0
        try:
            n = len((json.loads(r["body"]).get("items") or []))
        except Exception:
            pass
        return {"service": "kubelet", "authed": False, "containers": n, "critical": True,
                "detail": f"NO AUTH — kubelet read-only API exposed, {n} pod(s) listable"}
    return None


def probe_mongo(host: str, port: int) -> dict | None:
    # OP_QUERY isMaster on admin.$cmd — a handshake, reads no collection data.
    doc = b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
    body = struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, 1) + doc
    msg = struct.pack("<iiii", 16 + len(body), 1, 0, 2004) + body
    r = tcp(host, port, msg, read=4096)
    if not r or b"ismaster" not in r.lower():
        return None
    authed = b"requires authentication" in r.lower() or b"Unauthorized" in r
    if authed:
        return {"service": "mongodb", "authed": True, "detail": "auth required (correct)"}
    ver = ""
    m = re.search(rb"version\x00[\x00-\xff]{4}([\d.]+)", r)
    if m:
        ver = m.group(1).decode(errors="replace")
    return {"service": "mongodb", "authed": False, "version": ver,
            "detail": f"NO AUTH — MongoDB {ver or '?'} answered isMaster without credentials"}


def probe_zookeeper(host: str, port: int) -> dict | None:
    r = tcp(host, port, b"ruok", read=64)
    if r.strip() != b"imok":
        return None
    st = tcp(host, port, b"stat", read=4096)
    ver = ""
    m = re.search(rb"Zookeeper version: ([^\s,]+)", st)
    if m:
        ver = m.group(1).decode()
    return {"service": "zookeeper", "authed": False, "version": ver,
            "detail": f"NO AUTH — ZooKeeper {ver or '?'} four-letter commands enabled"}


def probe_rabbitmq(host: str, port: int) -> dict | None:
    r = http(host, port, "/api/overview", "http")
    if r["status"] == 401:
        return {"service": "rabbitmq", "authed": True, "detail": "auth required (correct)"}
    if r["status"] == 200 and b"rabbitmq_version" in r["body"]:
        return {"service": "rabbitmq", "authed": False, "critical": True,
                "detail": "NO AUTH — RabbitMQ management API readable anonymously"}
    return None


PROBES: dict[int, list] = {
    6379: [probe_redis], 6380: [probe_redis], 11211: [probe_memcached],
    9200: [probe_elastic], 9201: [probe_elastic], 5984: [probe_couchdb],
    2375: [probe_docker], 2376: [probe_docker], 10250: [probe_kubelet],
    27017: [probe_mongo], 27018: [probe_mongo], 2181: [probe_zookeeper],
    15672: [probe_rabbitmq],
}


def run_host(host: str, ports: list[int], dry: bool) -> dict:
    ok, program = scope_ok(host)
    if not ok:
        log(f"SKIP {host}: {program}")
        return {"host": host, "skipped": program}

    cdn = is_cdn(host)
    if cdn:
        log(f"SKIP {host}: fronted by {cdn} — port results behind a CDN are meaningless")
        audit({"host": host, "skipped": f"cdn:{cdn}"})
        return {"host": host, "skipped": f"CDN-fronted ({cdn})"}

    targets = ports or sorted(PROBES)
    open_unauth: list[dict] = []
    enforced: list[dict] = []

    reachable = open_ports(host, targets)
    if not reachable:
        log(f"{host}: none of the {len(targets)} critical ports are reachable")
        audit({"host": host, "reachable": 0})
        return {"host": host, "program": program, "unauth": [], "enforced": []}
    log(f"{host}: {len(reachable)}/{len(targets)} port(s) reachable — {reachable}")

    for p in reachable:
        for fn in PROBES.get(p, []):
            try:
                res = fn(host, p)
            except Exception as e:
                log(f"  {p}: probe error {str(e)[:80]}")
                continue
            if not res:
                continue
            res["port"] = p
            if res.get("authed"):
                log(f"  {p}/{res['service']}: {res['detail']}")
                enforced.append(res)
            else:
                log(f"  {p}/{res['service']}: *** {res['detail']} ***")
                open_unauth.append(res)
            break

    if not open_unauth:
        log(f"{host}: no unauthenticated service reachable "
            f"({len(enforced)} service(s) correctly demanded credentials)")
        audit({"host": host, "unauth": 0, "enforced": len(enforced)})
        return {"host": host, "program": program, "unauth": [], "enforced": enforced}

    res = {"host": host, "program": program, "unauth": open_unauth, "enforced": enforced}
    audit({"host": host, "unauth": [u["service"] for u in open_unauth]})
    if not dry:
        res["finding_id"] = mint(res)
    return res


def mint(res: dict) -> int | None:
    from engine import state
    top = max(res["unauth"], key=lambda u: (u.get("critical", False),
                                            int(u.get("docs") or 0),
                                            int(u.get("keys") or 0)))
    critical = any(u.get("critical") for u in res["unauth"])
    score = 20 if critical else 17
    headline = "; ".join(u["detail"] for u in res["unauth"])
    ev = {
        "chain": "open port -> protocol spoken -> unauthenticated access confirmed",
        "services": res["unauth"],
        "services_correctly_enforcing": [e["service"] for e in res["enforced"]],
        "impact": headline,
        "method": ("read-only protocol verbs only (PING/INFO/DBSIZE, stats, _cat/indices, "
                   "_all_dbs, /version, /pods, isMaster, ruok); no records read, "
                   "nothing written, nothing executed"),
        "at": utc(),
    }
    conn = state.connect()
    state.init_db(conn)
    fid = state.record_confirmed(
        conn, res["host"], url=f"tcp://{res['host']}:{top['port']}",
        program=res["program"] or None,
        signal_class="unauth-service", vuln_class=f"unauth-{top['service']}",
        score=score, evidence=ev, confidence=0.95)
    conn.close()
    log(f"  minted finding #{fid} — {headline[:120]}")
    return fid


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Speak the protocol on open ports and confirm unauthenticated access.")
    ap.add_argument("host", nargs="+")
    ap.add_argument("--ports", default="", help="comma list; default = all known critical ports")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if os.path.exists(os.path.join(STATE_DIR, "vpn_down")):
        log("vpn_down — refusing (fail-closed)")
        return 2
    ports = [int(x) for x in a.ports.split(",") if x.strip().isdigit()] if a.ports else []

    runs = [run_host(h, ports, a.dry_run) for h in a.host]
    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"proto_{datetime.now().strftime('%Y-%m-%d')}.md")
    L = [f"# Unauthenticated service check — {utc()}", ""]
    for r in runs:
        if r.get("skipped"):
            L += [f"## {r['host']} — SKIPPED ({r['skipped']})", ""]
            continue
        L += [f"## {r['host']} ({r.get('program','')})"]
        for u in r.get("unauth", []):
            L.append(f"- **{u['port']}/{u['service']}** — {u['detail']}")
            if u.get("index_names"):
                L.append(f"  - indices: {', '.join(f'`{n}`' for n in u['index_names'])}")
        for e in r.get("enforced", []):
            L.append(f"- {e['port']}/{e['service']} — {e['detail']}")
        if not r.get("unauth"):
            L.append("- _no unauthenticated service — not a finding_")
        L.append("")
    open(out, "w", encoding="utf-8").write("\n".join(L))
    log(f"report → {out}")
    print(json.dumps(runs, default=str)[:1500])
    return 0


if __name__ == "__main__":
    sys.exit(main())
