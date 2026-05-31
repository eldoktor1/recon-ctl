# Bug Bounty Hunter — Daily Init Prompt

**Instructions for use:** Replace DATE and TIME below, then paste this as your first message
in a Claude Code session launched from `~/recon-pipeline/agent/`.

You need to be very econmical with tokens so it can survive session limits


You have all the security tools at Kali WSL at your disposal 
---

## PASTE THIS AT 09:00 EACH MORNING

---

Today is **[DATE e.g. 2026-05-21]**. Time is 09:00. Begin your workday.

Read `CLAUDE.md` in this directory for your full standing orders. Then execute this
startup sequence without asking me any questions:

**1. State initialization**
```bash
mkdir -p ~/recon/agent
STATE_FILE=~/recon/agent/state_$(date +%Y%m%d).json
[[ -f "$STATE_FILE" ]] || echo '{"date":"'$(date +%Y%m%d)'","updated":"","reviewed":{},"confirmed":[],"watch":[],"queue_total":0}' > "$STATE_FILE"
cat "$STATE_FILE"
```

**2. Check what the pipeline already confirmed overnight**
```bash
# Nuclei findings (report these immediately — already verified)
cat ~/recon/nuclei/confirmed.jsonl 2>/dev/null | jq -c '{host,template_id,severity,name,matched_at}' | tail -20

# Takeover opportunities
cat ~/recon/firstblood/takeovers_to_claim.tsv 2>/dev/null

# AI-scored high-confidence leads
jq -c 'select(.ai.ai_relevance_score >= 70) | {host,url,score,priority,payout_tier,program,ai_score:.ai.ai_relevance_score,safe_checks:.ai.safe_checks}' \
  ~/recon/ai_review/ai_scored.jsonl 2>/dev/null | head -20
```

**3. Fetch the priority queue**
```bash
curl -s --netrc-file ~/.recon_es_netrc http://127.0.0.1:9200/recon_alive/_search \
  -H 'Content-Type: application/json' -d '{
    "query": {"bool": {
      "filter": [
        {"term": {"triage_in_scope": true}},
        {"term": {"triage_pays": true}},
        {"terms": {"triage_priority": ["P0","P1"]}}
      ]
    }},
    "sort": [
      {"triage_true_fresh": {"order": "desc", "missing": "_last"}},
      {"triage_kev_match": {"order": "desc", "missing": "_last"}},
      {"triage_score": {"order": "desc"}}
    ],
    "_source": ["host","url","triage_score","triage_priority","triage_payout_tier",
                "triage_true_fresh","triage_kev_match","triage_kev_cves",
                "triage_signals","tech","triage_program","triage_platform",
                "status_code","title","ip","first_seen"],
    "size": 300
  }' | jq '[.hits.hits[]._source]'
```

**4. Work the queue per CLAUDE.md priority system. Send immediate Discord alert on any
Critical/High confirmed finding. Send end-of-day summary report at 17:30.**

I will review your Discord report when I return at 18:00. Work independently. remember your where you stopped so we dont retest 

---

## OPTIONAL CONTEXT ADDITIONS (append below the paste if relevant)

```
# If you want to flag a specific host for priority attention:
"Priority-check this host first: [hostname] — reason: [why]"

# If you want to skip certain programs:
"Skip [program name] today — already submitted findings this week."

# If there's a hot lead from last night's Discord:
"Pipeline Discord fired on [host] last night. Start verification there."
```
