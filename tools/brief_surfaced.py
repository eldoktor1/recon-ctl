#!/usr/bin/env python3
"""brief_surfaced.py — stop the nightly card from re-serving the same leads forever.

WHY. A worklist entry stays `status:to-test` until a human tests it or a host_note kills it,
so within the 30-day freshness window the SAME lead re-renders every single night. Measured
2026-09-13: tonight's card was 7 hosts, all 7 repeats of the night before, zero new. A card
that cannot tell "new" from "shown you this five times" trains the operator to ignore it.

WHAT THIS DOES. It is a LEDGER, not a filter-by-default. Every lead that reaches the card is
stamped with how many nights it has been shown. Then:
  * seen for the first time      -> _is_new=1, rendered normally
  * seen before, under the cap   -> _seen_n=N, rendered and MARKED as a repeat
  * seen >= PARK_AFTER nights    -> moved to `parked`, collapsed into one counted line

Nothing is hidden. A parked lead is still listed in the backlog file and can be pulled back
with `recon-briefing backlog`. This matters: suppressing a real lead is worse than one extra
line, which is the same trade the transition gate makes elsewhere in this pipeline.

FAILS OPEN. Any exception and the input array is printed back unchanged. A bug here must never
be able to empty the card.

Usage:  cat leads.json | brief_surfaced.py --annotate
Env:    SURFACED_LEDGER (path, default ~/recon/state/briefing_surfaced.jsonl)
        SURFACED_DATE   (YYYY-MM-DD, default today; testing hook)
        PARK_AFTER      (int, default 5)
        SURFACED_OFF    (1 = passthrough, kill switch)
Out:    {"keep":[...], "parked":[...], "new_count":N, "repeat_count":N, "parked_count":N}
"""
import hashlib
import json
import os
import sys
from datetime import date, datetime

LEDGER = os.environ.get("SURFACED_LEDGER") or os.path.expanduser(
    "~/recon/state/briefing_surfaced.jsonl")
TODAY = os.environ.get("SURFACED_DATE") or date.today().isoformat()
try:
    PARK_AFTER = max(2, int(os.environ.get("PARK_AFTER", "5")))
except Exception:
    PARK_AFTER = 5


def sig(ld):
    """Identity of a lead ACROSS nights. Host plus class plus the specific thing to test, so
    the same host resurfacing with a genuinely different endpoint is a NEW lead, not a repeat."""
    host = str(ld.get("host") or ld.get("bucket") or ld.get("source_host") or "").lower()
    cls = str(ld.get("vuln_class") or ld.get("vuln_type") or ld.get("cls")
              or ld.get("kind") or ld.get("signal_class") or "")
    what = str(ld.get("endpoint") or ld.get("check") or ld.get("test")
               or ld.get("cve") or ld.get("what") or "")
    return hashlib.sha1(("%s|%s|%s" % (host, cls, what)).encode("utf-8", "ignore")).hexdigest()[:20]


def novelty(ld):
    """A cheap fingerprint of the lead's SUBSTANCE. If this changes the lead is materially
    different (score moved, more routes found, severity re-rated) and earns a fresh look even
    if it was shown before. Same idea as the transition gate: react to change, not to state."""
    parts = [ld.get("score"), ld.get("rank"), ld.get("confidence"), ld.get("severity"),
             ld.get("impact"), ld.get("route_count"), ld.get("n_sensitive")]
    return hashlib.sha1("|".join(str(p) for p in parts).encode("utf-8", "ignore")).hexdigest()[:12]


def load():
    """Last record wins, so the file can stay append-only between compactions."""
    out = {}
    try:
        with open(LEDGER, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                if isinstance(r, dict) and r.get("sig"):
                    out[r["sig"]] = r
    except FileNotFoundError:
        pass
    return out


def append(rows):
    if not rows:
        return
    try:
        os.makedirs(os.path.dirname(LEDGER), exist_ok=True)
        with open(LEDGER, "a", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
    except Exception:
        pass  # a ledger write failure must not change what the operator sees


def parse_stdin():
    raw = sys.stdin.read()
    try:
        arr = json.loads(raw) if raw.strip() else []
    except Exception:
        arr = []
    return arr if isinstance(arr, list) else []


def main(arr):

    if os.environ.get("SURFACED_OFF") == "1":
        print(json.dumps({"keep": arr, "parked": [], "new_count": len(arr),
                          "repeat_count": 0, "parked_count": 0}))
        return

    led = load()
    keep, parked, writes = [], [], []
    new_count = repeat_count = 0

    for ld in arr:
        if not isinstance(ld, dict):
            keep.append(ld)
            continue
        s = sig(ld)
        nv = novelty(ld)
        rec = led.get(s)

        if rec is None:
            ld["_seen_n"] = 1
            ld["_is_new"] = 1
            new_count += 1
            keep.append(ld)
            writes.append({"sig": s, "first": TODAY, "last": TODAY, "shown": 1, "nv": nv})
            continue

        shown = int(rec.get("shown") or 1)
        changed = rec.get("nv") != nv
        same_day = rec.get("last") == TODAY

        # Re-running the briefing on the same day must reproduce the same card, so a lead
        # already stamped today is passed through untouched and never double-counted.
        if same_day:
            ld["_seen_n"] = shown
            ld["_is_new"] = 1 if shown <= 1 else 0
            (keep if shown < PARK_AFTER else parked).append(ld)
            continue

        if changed:
            # Substance moved. Reset the clock rather than parking a lead that just got worse.
            ld["_seen_n"] = 1
            ld["_is_new"] = 1
            ld["_changed"] = 1
            new_count += 1
            keep.append(ld)
            writes.append({"sig": s, "first": rec.get("first", TODAY), "last": TODAY,
                           "shown": 1, "nv": nv, "was_shown": shown})
            continue

        shown += 1
        ld["_seen_n"] = shown
        ld["_is_new"] = 0
        ld["_first_seen"] = rec.get("first")
        writes.append({"sig": s, "first": rec.get("first", TODAY), "last": TODAY,
                       "shown": shown, "nv": nv})
        if shown >= PARK_AFTER:
            parked.append(ld)
        else:
            repeat_count += 1
            keep.append(ld)

    append(writes)
    print(json.dumps({"keep": keep, "parked": parked, "new_count": new_count,
                      "repeat_count": repeat_count, "parked_count": len(parked)}))


if __name__ == "__main__":
    _in = parse_stdin()
    try:
        main(_in)
    except Exception as exc:
        # FAIL OPEN: hand back exactly what came in. An empty card is a worse failure than a
        # card with one stale line, so a bug in the ledger must be invisible to the operator.
        print(json.dumps({"keep": _in, "parked": [], "new_count": len(_in),
                          "repeat_count": 0, "parked_count": 0,
                          "error": str(exc)[:120]}))
