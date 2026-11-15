#!/usr/bin/env bash
# walk_publish.sh <workspace-key> — regenerate a program-walk document and PROVE it is consistent.
#
# The published artifact cannot pull from the workspace (it runs sandboxed, and the CSP blocks
# outbound hosts), so "auto-update" means: regeneration is one command, drift is detected, and a
# stale document is loud rather than silent. Republish itself is the one manual step — only the
# Artifact tool can write to the URL.
#
# Exit codes: 0 = regenerated and consistent, 1 = generator failed, 2 = consistency check failed.
set -uo pipefail

KEY="${1:?usage: walk_publish.sh <workspace-key> [--mark-published]}"
MODE="${2:-}"
ROOT=/home/d0k/recon-ctl
WS="/home/d0k/recon/workspaces/${KEY}.json"
OUT="${ROOT}/evidence/${KEY}/${KEY}_walk.html"

[[ -f "$WS" ]] || { echo "no workspace: $WS" >&2; exit 1; }
mkdir -p "$(dirname "$OUT")"

# --mark-published: called AFTER the Artifact tool reports success, to copy the rendered hash into
# .published. Only the Artifact tool can write the URL, so the script cannot confirm the publish
# itself - which is exactly why this is a separate explicit step rather than something the
# regeneration assumes. It deliberately does NOT re-render: stamping a hash that was never
# published would make the next cycle skip a publish it still owes.
if [[ "$MODE" == "--mark-published" ]]; then
  STAMP="${ROOT}/evidence/${KEY}/.rendered"
  [[ -f "$STAMP" ]] || { echo "nothing rendered yet: $STAMP" >&2; exit 1; }
  cp -f "$STAMP" "${ROOT}/evidence/${KEY}/.published"
  echo "marked published: $(cat "${ROOT}/evidence/${KEY}/.published")"
  exit 0
fi

cd "$ROOT" || exit 1
python3 tools/walk_report.py "$KEY" "$OUT" || { echo "GENERATOR FAILED" >&2; exit 1; }

python3 - "$WS" "$OUT" <<'PY'
import json, re, sys
ws = json.load(open(sys.argv[1]))
doc = open(sys.argv[2], encoding='utf-8', errors='replace').read()
fail = []

def need(label, cond, detail=""):
    print("  %-40s %s %s" % (label, "ok" if cond else "FAIL", detail))
    if not cond:
        fail.append(label)

# counts must be DERIVED, never drift from content
n = len(ws.get('notes', []))
ids = sorted(int(m) for m in re.findall(r'id="note-(\d+)"', doc))
need("all notes rendered", len(ids) == n and (not n or ids[-1] == n - 1), "%d/%d" % (len(ids), n))
h = re.search(r'Recorded knowledge &mdash; (\d+) notes', doc)
f = re.search(r'notes <b>(\d+)</b>', doc)
need("heading/facts agree with content",
     bool(h and f) and h.group(1) == f.group(1) == str(n),
     "heading=%s facts=%s content=%d" % (h and h.group(1), f and f.group(1), n))

# the board must survive regeneration in full
board = ws.get('board') or {}
want = {c['id'] for g in board.get('groups', []) for c in g.get('cards', [])}
got = set(re.findall(r'<span class="sid">([A-Z]{2,4}-\d+)</span>', doc))
need("board cards reproduced", want == got,
     "%d/%d%s" % (len(got), len(want), "" if want == got else " missing=%s" % sorted(want - got)[:5]))
for g in board.get('groups', []):
    k = len(g.get('cards', []))
    pat = (r'<span class="cat">%s</span><span class="catname">%s</span><span class="count">%d</span>'
           % (re.escape(g['cat']), re.escape(g['name']), k))
    need("group %s count derived = %d" % (g['cat'], k), re.search(pat, doc) is not None)

# links must resolve, or the evidence trail is decorative
refs = set(re.findall(r'href="#(note-\d+)"', doc))
anch = set(re.findall(r'id="(note-\d+)"', doc))
need("evidence refs resolve", not (refs - anch), "%d refs" % len(refs))

# MEANING check: counts cannot see that a card went stale. An Open card whose own evidence
# now reads as a closure is the board advertising a dead lead - mechanically detectable.
closure = re.compile(r'CLOSED|CLOSED-NEGATIVE|NEGATIVE|DISPROVEN|BY DESIGN|NOT A FINDING', re.I)
notes_txt = [ (n.get('text') or '') for n in ws.get('notes', []) ]
suspect = []
for g in board.get('groups', []):
    if g.get('cat') != 'O':
        continue
    for c in g.get('cards', []):
        for r in c.get('refs', []) or []:
            body = None
            if r.get('q'):
                body = next((t for t in notes_txt if r['q'].lower() in t.lower()), None)
            elif r.get('anchor', '').startswith('note-'):
                k = int(r['anchor'].split('-')[1])
                body = notes_txt[k] if k < len(notes_txt) else None
            if body and closure.search(body[:400]):
                suspect.append(c['id'])
                break
if suspect:
    print("  %-40s WARN  %s" % ("open cards citing a closure", ", ".join(sorted(set(suspect)))))
    print("        ^ these read as Open but their evidence says closed - promote or re-pill them")
else:
    print("  %-40s ok" % "no open card cites a closure")

# THE MIRROR, and the costlier direction: a CLOSED card whose own evidence carries a live
# residual. An Open card that is really closed wastes a session; a Closed card that is really
# open loses the lane, because nobody re-reads Closed.
# Vocabulary tuned twice. Excluded deliberately: "UNREACHED" collides with the RULE NAME
# "same-error-means-unreached", which describes a control that WAS run; and "next test" /
# "the live question" appear in prose describing superseded positions.
residual = re.compile(r'STILL OPEN|STILL UNTESTED|UNDECIDABLE|NOT TESTED|RESIDUAL|UNRESOLVED|'
                      r'NEVER TESTED|BLOCKED ON|NOT CLOSED|WHAT IS STILL OPEN', re.I)
# A residual is only dangerous when it is ORPHANED - no followup and no pointer to a card
# that is still open. A bounded, sign-posted residual is good practice, not a defect; flagging
# those too would make the check noise, and a noisy check gets ignored.
open_ids = {c['id'] for g in board.get('groups', []) if g.get('cat') in ('O', 'B', 'H')
            for c in g.get('cards', [])}
fu_blob = json.dumps(ws.get('followups', []))
zombie = []
for g in board.get('groups', []):
    if g.get('cat') != 'C':
        continue
    for c in g.get('cards', []):
        # Scan the card's CLAIMS only - lead plus segment text. Ref labels carry the historical
        # titles of notes ("OPN-2 ADJUDICATED - NOT CLOSED"), which are metadata about how the
        # card got here, not assertions about its current state.
        claims = [c.get('lead', '')] + [s2.get('lede', '') + ' ' + s2.get('value', '') + ' ' +
                                        s2.get('label', '') for s2 in c.get('segments', [])]
        blob = ' '.join(claims)
        if not residual.search(blob):
            continue
        homed = any(oid in blob for oid in open_ids) or c['id'] in fu_blob
        if not homed:
            zombie.append(c['id'])
if zombie:
    print("  %-40s WARN  %s" % ("closed cards with a live residual", ", ".join(sorted(set(zombie)))))
    print("        ^ closed but their own text says something is untested - reopen or spawn a followup")
else:
    print("  %-40s ok" % "no closed card hides a residual")

# publish hygiene
need("no wrapper tags", not re.search(r'<!doctype|<html[ >]|</body>|</html>', doc, re.I))
need("no external references", not re.findall(r'(?:src|href)="https?://[^"]+"', doc))
need("dup card ids none", len(re.findall(r'id="[A-Z]{2,4}-\d+"', doc)) == len(got))

print()
if fail:
    print("INCONSISTENT (%d): %s" % (len(fail), "; ".join(fail)))
    sys.exit(2)
print("CONSISTENT - safe to republish")
PY
rc=$?

URLFILE="${ROOT}/evidence/${KEY}/.artifact_url"
STAMP="${ROOT}/evidence/${KEY}/.rendered"
if [[ $rc -eq 0 ]]; then
  # Record WHAT was rendered so a publisher can tell whether the live artifact already
  # matches. Several sessions publish this document; without a stamp the loser of each
  # race just re-forces, which is how a supersede turns into a discard.
  NOTES=$(grep -oE 'id="note-[0-9]+"' "$OUT" | wc -l | tr -d ' ')
  # Hash the CONTENT, not the render. The footer carries a generation timestamp, so hashing the
  # raw file gives a different digest every single run and any "has it changed?" comparison built
  # on it always answers yes - which would republish an identical page every hour. Same lesson the
  # transition gate learned: strip the timestamps out of the fingerprint or a re-render reads as a
  # change. Verified by rendering twice with no workspace edits and getting one stable digest.
  SHA=$(sed -E 's/generated [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2} UTC//g' "$OUT" \
        | sha256sum | cut -c1-16)
  printf 'notes=%s sha=%s generated=%s
' "$NOTES" "$SHA" "$(date -Iseconds)" > "$STAMP"
  echo
  echo "wrote     $OUT"
  echo "rendered  notes=$NOTES sha=$SHA  ($STAMP)"
  echo "url file  $URLFILE"

  # THE PUBLISH VERDICT, so a caller never has to decide from memory whether it "changed
  # something". An hourly routine that judges this for itself gets it wrong in both directions:
  # it republishes a byte-identical page two dozen times a day (each publish forcing a full read
  # of the live document to merge), or it convinces itself nothing changed and leaves real new
  # evidence unpublished. Comparing the rendered content hash against the last hash we actually
  # PUBLISHED settles it mechanically. A missing .published stamp means "never published from
  # here", which must publish rather than skip - failing safe towards publishing, because a
  # redundant publish costs tokens and a missing one loses the record.
  PUBSTAMP="${ROOT}/evidence/${KEY}/.published"
  PUBSHA=$(sed -nE 's/.*sha=([0-9a-f]+).*/\1/p' "$PUBSTAMP" 2>/dev/null | head -1)
  if [[ "$PUBSHA" == "$SHA" ]]; then
    echo "ALREADY PUBLISHED - rendered sha matches .published; SKIP the publish step."
  else
    echo "PUBLISH REQUIRED - rendered sha $SHA differs from last published ${PUBSHA:-none}."
    if [[ -f "$URLFILE" ]]; then
      echo "  publish with the Artifact tool, passing url= $(cat "$URLFILE")"
    else
      echo "  NO ARTIFACT URL RECORDED - publishing without it creates a DUPLICATE artifact."
      echo "  echo '<url>' > $URLFILE"
    fi
    echo "  then record it:  bash tools/walk_publish.sh $KEY --mark-published"
  fi
fi
exit $rc
