"""Elasticsearch (recon_alive) proxy — asset truth.

Whitelisted _source fields only (never leak internal/secret fields to the SPA),
netrc auth stays server-side, and benched hosts are excluded by the ledger rule
(must_not ignore_expires_at > now) unless the caller asks to include them.
"""
from __future__ import annotations

from typing import Any

import httpx

from . import config

# fields the UI is allowed to see
SOURCE_FIELDS = [
    "host", "triage_priority", "triage_score", "triage_payout_tier", "triage_program",
    "triage_classes", "triage_kev_match", "triage_kev_cves", "triage_true_fresh",
    "triage_pays", "triage_in_scope", "triage_ignored", "takeover_confirmed", "takeover_service",
    "takeover_cname", "takeover_confidence", "takeover_payout", "js_secret_hit", "js_endpoint_hit",
    "host_notes", "host_notes_count", "host_notes_text", "ignore_active",
    "ignore_reason", "ignore_expires_at", "title", "tech", "portscan_critical",
    "first_seen", "last_seen",
]

# sortable columns (whitelist — anything else falls back to triage_score)
SORT_FIELDS = {
    "triage_score", "triage_priority", "last_seen", "first_seen",
    "portscan_critical", "host", "triage_payout_tier",
}


def _sort_clause(sort: str, order: str) -> list:
    """Build an ES sort clause from a whitelisted field + direction."""
    field = sort if sort in SORT_FIELDS else "triage_score"
    direction = "asc" if str(order).lower() == "asc" else "desc"
    return [{field: {"order": direction, "unmapped_type": "long"}}, "_score"]


def _client() -> httpx.AsyncClient:
    auth = config.es_auth()
    return httpx.AsyncClient(
        base_url=config.ES_URL,
        auth=httpx.BasicAuth(*auth) if auth else None,
        timeout=15.0,
    )


async def cluster_health() -> dict[str, Any]:
    try:
        async with _client() as cl:
            r = await cl.get("/_cluster/health")
            r.raise_for_status()
            h = r.json()
            cr = await cl.get(f"/{config.ES_INDEX}/_count")
            docs = cr.json().get("count") if cr.status_code == 200 else None
            return {
                "status": h.get("status"),
                "nodes": h.get("number_of_nodes"),
                "active_shards": h.get("active_shards"),
                "unassigned_shards": h.get("unassigned_shards"),
                "docs": docs,
                "reachable": True,
            }
    except Exception as e:
        return {"reachable": False, "error": str(e)}


def _build_query(
    q: str | None, program: str | None, priority: str | None, cls: str | None,
    tech: str | None, kev: bool, fresh: bool, pays: bool, include_benched: bool,
    include_oos: bool = False, include_nopay: bool = False,
) -> dict[str, Any]:
    must: list[dict] = []
    must_not: list[dict] = []
    if q:
        must.append({"wildcard": {"host": f"*{q.lower()}*"}})
    if tech:
        # broad tech/keyword lens (mirrors recon-mood): match across tech + title + notes
        must.append({"multi_match": {"query": tech, "type": "best_fields",
                                     "fields": ["tech", "title", "host_notes_text", "triage_classes"]}})
    if program:
        # triage_program holds whatever the platform's scope feed supplies — a slug for some
        # (`automattic`, `deezer-bug-bounty-program-2019`), a display name for others (`Etsy`,
        # `Glassdoor Managed Bug Bounty Engagement`). A workspace must therefore match on its key
        # OR its name; matching only one silently joins zero hosts.
        if isinstance(program, (list, tuple, set)):
            vals = [str(p) for p in program if p]
            if vals:
                must.append({"terms": {"triage_program": vals}})
        else:
            must.append({"term": {"triage_program": program}})
    if priority:
        must.append({"term": {"triage_priority": priority}})
    if cls:
        must.append({"match": {"triage_classes": cls}})
    if kev:
        must.append({"term": {"triage_kev_match": True}})
    if fresh:
        must.append({"term": {"triage_true_fresh": True}})
    # DEFAULT-GATE the actionable surface: in-scope + paying, unless the caller opts
    # to include out-of-scope / non-paying assets. (`pays` stays for back-compat.)
    if not include_nopay or pays:
        must.append({"term": {"triage_pays": True}})
    if not include_oos:
        must.append({"term": {"triage_in_scope": True}})
    if not include_benched:
        must_not.append({"range": {"ignore_expires_at": {"gt": "now"}}})
    if not must and not must_not:
        return {"match_all": {}}
    return {"bool": {"must": must or [{"match_all": {}}], "must_not": must_not}}


async def search(
    *, q=None, program=None, priority=None, cls=None, tech=None, kev=False, fresh=False,
    pays=False, include_benched=False, include_oos=False, include_nopay=False,
    limit=100, offset=0, sort="triage_score", order="desc",
) -> dict[str, Any]:
    body = {
        "query": _build_query(q, program, priority, cls, tech, kev, fresh, pays,
                              include_benched, include_oos, include_nopay),
        "_source": SOURCE_FIELDS,
        # ES max_result_window is 10000 — clamp from+size so a deep page never errors
        "from": max(0, min(offset, 10000)),
        "size": max(0, min(limit, 500, 10000 - min(offset, 10000))),
        "sort": _sort_clause(sort, order),
    }
    try:
        async with _client() as cl:
            r = await cl.post(f"/{config.ES_INDEX}/_search", json=body)
            if r.status_code != 200:
                return {"error": r.text, "total": 0, "items": []}
            data = r.json()
            hits = data.get("hits", {})
            total = hits.get("total", {})
            return {
                "total": total.get("value") if isinstance(total, dict) else total,
                "limit": body["size"],
                "offset": offset,
                "items": [h["_source"] for h in hits.get("hits", [])],
            }
    except Exception as e:
        return {"error": str(e), "total": 0, "items": []}


_LEAD_BUCKETS = [
    ("takeover", "confirmed subdomain takeover", {"term": {"takeover_confirmed": True}}, None),
    ("takeover_lead", "dangling CNAME (takeover lead)", {"exists": {"field": "takeover_cname"}},
     {"term": {"takeover_confirmed": True}}),
    ("secrets", "leaked JS secret (verified)", {"term": {"js_secret_hit": True}}, None),
    ("kev", "KEV / n-day tech match", {"term": {"triage_kev_match": True}}, None),
    ("fresh", "fresh blood (newly CT-surfaced)", {"term": {"triage_true_fresh": True}}, None),
]


async def active_leads(
    include_oos: bool = False, include_nopay: bool = False, per_bucket: int = 10,
) -> dict[str, Any]:
    """Active (non-benched) actionable leads, bucketed by signal type.

    Default surface is in-scope + paying; `include_oos`/`include_nopay` widen it.
    """
    base_must: list[dict] = []
    if not include_nopay:
        base_must.append({"term": {"triage_pays": True}})
    if not include_oos:
        base_must.append({"term": {"triage_in_scope": True}})
    base_must_not = [{"range": {"ignore_expires_at": {"gt": "now"}}}]

    async def one(key, label, sig, exclude):
        must = base_must + [sig]
        mnot = list(base_must_not) + ([exclude] if exclude else [])
        body = {
            "query": {"bool": {"must": must, "must_not": mnot}},
            "_source": SOURCE_FIELDS,
            "size": per_bucket,
            "track_total_hits": True,
            "sort": [{"triage_score": {"order": "desc", "unmapped_type": "long"}}],
        }
        try:
            async with _client() as cl:
                r = await cl.post(f"/{config.ES_INDEX}/_search", json=body)
                data = r.json()
                hits = data.get("hits", {})
                total = hits.get("total", {})
                return {
                    "key": key, "label": label,
                    "count": total.get("value") if isinstance(total, dict) else total,
                    "hosts": [h["_source"] for h in hits.get("hits", [])],
                }
        except Exception as e:
            return {"key": key, "label": label, "count": 0, "hosts": [], "error": str(e)}

    import asyncio
    results = await asyncio.gather(*[one(k, l, s, e) for k, l, s, e in _LEAD_BUCKETS])
    return {"buckets": results, "pays_only": not include_nopay, "in_scope_only": not include_oos}


async def facets() -> dict[str, Any]:
    """Terms aggregations for filter dropdowns (over the actionable, non-benched surface)."""
    body = {
        "size": 0,
        "query": {"bool": {"must_not": [{"range": {"ignore_expires_at": {"gt": "now"}}}]}},
        "aggs": {
            "programs": {"terms": {"field": "triage_program", "size": 60}},
            "priorities": {"terms": {"field": "triage_priority", "size": 10}},
            "classes": {"terms": {"field": "triage_classes", "size": 40}},
            "payout": {"terms": {"field": "triage_payout_tier", "size": 10}},
        },
    }
    out: dict[str, Any] = {}
    try:
        async with _client() as cl:
            r = await cl.post(f"/{config.ES_INDEX}/_search", json=body)
            aggs = r.json().get("aggregations", {})
            for k, a in aggs.items():
                out[k] = [{"value": b["key"], "count": b["doc_count"]} for b in a.get("buckets", [])]
    except Exception as e:
        out["error"] = str(e)
    return out


async def host_detail(host: str) -> dict[str, Any] | None:
    body = {"query": {"term": {"host": host}}, "size": 1}
    try:
        async with _client() as cl:
            r = await cl.post(f"/{config.ES_INDEX}/_search", json=body)
            hits = r.json().get("hits", {}).get("hits", [])
            if not hits:
                return None
            return hits[0]["_source"]
    except Exception:
        return None
