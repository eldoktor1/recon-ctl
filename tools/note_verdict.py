#!/usr/bin/env python3
"""
note_verdict.py — classify a host's worked-knowledge notes as dead / open / none,
so the briefing + hunter + candidate cards STOP re-serving hosts already worked to a
dead end. Shared by recon_briefing.sh, recon_ai_hunter.sh, brief_filter.py.

Design (respects supersession + explicit operator instructions):
  * "do not re-walk/chase/report/…" ANYWHERE  = the operator literally said stop → DEAD
    (unless the LATEST note re-arms it with a strong-open marker).
  * else the MOST-RECENT note wins: strong-open → OPEN, strong-dead → DEAD.
  * else DEAD only if some note is strong-dead and nothing later re-opens it; else NONE.
Conservative: a strong-OPEN marker (RESUME/ARMED/precondition-met/funded/PoC-ready)
keeps a host visible — a wrong suppression is worse than one extra lead.

CLASS-SCOPED KILLS (2026-07-24 recalibration): a kill is HOST-WIDE only when it is an
explicit operator "do not re-*" or a whole-host EXHAUSTION verdict. A generic STRONG_DEAD
verdict that names a vuln class (e.g. "version disclosure only = N/A") kills ONLY that
class — the host stays servable for every other class. A STRONG_DEAD note that names no
class at all is treated as ambiguous and does NOT kill the host (this was the mechanism
that marked 84% of ever-touched hosts dead-for-all-classes and starved the briefing).

CLI:
  note_verdict.py killed-hosts    [notes.jsonl]  -> newline list of HOST-WIDE-DEAD hosts
  note_verdict.py killed-classes  [notes.jsonl]  -> "host<TAB>cls,cls" class-scoped kills
  note_verdict.py verdict <host>  [notes.jsonl]  -> dead|open|none (host-wide only)
Import: classify_host(notes)->verdict ; killed_hosts(path)->set ;
        killed_host_classes(path)->{host:set(cls)} ; note_classes(text)->set(cls)
"""
import json, os, re, sys

NOTES_DEFAULT = os.path.expanduser("~/recon/state/host_notes.jsonl")

DO_NOT_RE = re.compile(r"do\s*not\s+re-?\s*(walk|chase|report|surf|serve|hit|test|visit|probe|work|open)", re.I)
# ACTIVE re-arm — genuinely reopens a host (staged PoC / funding-blocked / explicitly untested).
# This is what can override an operator "do not re-*" kill.
REARM = re.compile(
    r"\b(resume|armed|re-?arm|poc\s*ready|prep\s*done|deploy\.js|deploy_\w+\.js|funded|"
    r"ready\s*to\s*(fire|deploy)|fire\s*(it|when)|un-?tested|not\s*yet\s*(tested|worked)|"
    r"pending\s*funding|awaiting\s*(funding|operator))", re.I)
# PASSIVE open — a recheck that the precondition is still live. Keeps a NON-killed host visible,
# but does NOT reopen a host the operator explicitly killed (this was the help.etoro re-serve bug).
PASSIVE_OPEN = re.compile(r"(precondition[^.]{0,40}(met|still)|still\s*met)", re.I)

# WHOLE-HOST exhaustion — the note declares the ENTIRE host worked out, not one class.
# These (plus operator do-not-re-*) are the only host-wide auto-kills.
WHOLE_HOST_DEAD = re.compile(
    r"(exhaust(ed|ion)|"
    r"no\s*(money\s*surface|attack\s*surface|exploitable\s*surface|bug\s*(anywhere|left)|finding\s*anywhere)|"
    r"nothing\s*(here|exploitable|left|actionable|to\s*find)|"
    r"burned\s*(across|out|host)|clean\s*across\s*(all|the\s*host)|"
    r"whole\s*host\s*(dead|clean)|walled\s*off\s*entirely)", re.I)

# STRONG_DEAD — a per-verdict kill. Tightened 2026-07-24 so passing mentions of
# dup/secure/fp/na/patched do NOT fire; the weak tokens now require verdict-like context.
STRONG_DEAD = re.compile(
    r"(\b(kill(ed)?|dead[\s-]*end|refuted|not\s*a\s*finding|by[\s-]*design|"
    r"exhausted|walled|dup-magnet|duplicate)\b|"
    r"hardened\s*=\s*not|"
    r"\bn/a\b|\bn-a\b|"                                         # N/A verdict (needs the separator)
    r"(confirmed|marked|is\s+a|=\s*)\s*fp\b|false\s*positive|"  # fp only as a verdict
    r"(confirmed|near-?certain|likely|is\s+a|=\s*)\s*dup\b|"    # dup as a VERDICT, not a passing mention
    r"(=\s*secure|is\s+secure|\bsecured\b|secure\s*config|secure\s*fp)|"  # secure as a verdict
    r"(already|fully|=\s*|is\s+)patched|"                        # patched as a verdict, not a mention
    r"no\s*(money\s*surface|finding|bug|exploitable)|not\s*exploitable)", re.I)

# Vuln-class taxonomy — used BOTH on note text (what class was refuted) and on a lead's
# class fields (what class a candidate is), so a class-scoped kill only suppresses matching leads.
CLASS_PATTERNS = {
    "idor":     re.compile(r"\b(idor|bola|bfla|broken\s+(object|function)\s+level|access[\s-]*control|object[\s-]*ref)\b", re.I),
    "xss":      re.compile(r"\b(xss|cross[\s-]*site\s*script|dom[\s-]*xss|reflected\s*param|stored\s*xss)\b", re.I),
    "sqli":     re.compile(r"\b(sqli|sql[\s-]*inject|nosql|error[\s-]*based|boolean[\s-]*based)\b", re.I),
    "ssrf":     re.compile(r"\bssrf\b", re.I),
    "ssti":     re.compile(r"\b(ssti|template[\s-]*inject)\b", re.I),
    "redirect": re.compile(r"\b(open[\s-]*redirect|open-redir)\b", re.I),
    "takeover": re.compile(r"\b(takeover|dangling|nxdomain|unclaimed|cname[\s-]*lead)\b", re.I),
    "graphql":  re.compile(r"\bgraphql\b", re.I),
    "secret":   re.compile(r"\b(secret|token[\s-]*leak|credential|api[\s_-]?key|leaked\s*(key|secret)|trufflehog)\b", re.I),
    "bucket":   re.compile(r"\b(bucket|s3\b|blob\s*storage|gcs)\b", re.I),
    "nday":     re.compile(r"\b(kev|cve-\d{4}-\d+|n-?day|version\s*disclosure|version\s*only|actuator|swagger)\b", re.I),
    "cache":    re.compile(r"\b(wcd\b|web[\s-]*cache|cache[\s-]*(deception|poison))\b", re.I),
    "port":     re.compile(r"\b(critical[\s-]*port|open\s*port|scan[\s-]*artifact)\b", re.I),
    "info":     re.compile(r"\b(info[\s-]*disclosure|information\s*disclosure|exposure|disclosure)\b", re.I),
    "lfi_rce":  re.compile(r"\b(lfi|rce|file[\s-]*read|path\s*traversal|remote\s*code)\b", re.I),
    "cognito":  re.compile(r"\bcognito\b", re.I),
}


def note_classes(text):
    """Vuln classes named in a piece of text (note or lead)."""
    t = text or ""
    return {name for name, rx in CLASS_PATTERNS.items() if rx.search(t)}


def _note_scope(text):
    """Classify ONE note -> (verdict, classes).
       verdict: 'open' | 'dead-all' | 'dead-class' | 'dead-ambiguous' | 'none'."""
    t = text or ""
    if REARM.search(t):                 # active re-arm wins over any kill
        return ("open", set())
    if WHOLE_HOST_DEAD.search(t):       # whole-host exhaustion = host-wide kill
        return ("dead-all", set())
    if STRONG_DEAD.search(t):           # per-verdict kill — scope it to the named class(es)
        cls = note_classes(t)
        return ("dead-class", cls) if cls else ("dead-ambiguous", set())
    if PASSIVE_OPEN.search(t):          # precondition still live on a not-otherwise-killed host
        return ("open", set())
    return ("none", set())


# legacy string classifier (CLI `verdict`, any external import) — HOST-WIDE verdict only.
def classify_note(text):
    v, _ = _note_scope(text)
    return {"open": "open", "dead-all": "dead"}.get(v, "none" if v != "dead-class" else "none")


def host_scope(notes):
    """notes: list of dicts {note, created_at, source} for ONE host.
       Returns (verdict, classes): 'dead-all' | 'dead-class' | 'open' | 'none'."""
    if not notes:
        return ("none", set())
    notes = sorted(notes, key=lambda d: d.get("created_at", ""))
    latest_txt = notes[-1].get("note", "") or ""
    any_do_not_re = any(DO_NOT_RE.search(n.get("note", "") or "") for n in notes)
    # explicit "do not re-*" is the operator saying STOP — sticky + host-wide. Only an ACTIVE
    # re-arm on the latest note reopens it; a passive "precondition still met" recheck does NOT.
    if any_do_not_re:
        return ("open", set()) if REARM.search(latest_txt) else ("dead-all", set())
    lv, lc = _note_scope(latest_txt)
    if lv == "open":
        return ("open", set())
    if lv == "dead-all":
        return ("dead-all", set())
    if lv == "dead-class":
        return ("dead-class", lc)
    # latest is neutral/ambiguous: scan back, accumulate class kills, stop at the first re-open.
    acc = set()
    for n in reversed(notes):
        v, c = _note_scope(n.get("note", "") or "")
        if v == "open":
            break
        if v == "dead-all":
            return ("dead-all", set())
        if v == "dead-class":
            acc |= c
    return ("dead-class", acc) if acc else ("none", set())


def classify_host(notes):
    """Legacy host verdict (dead/open/none). 'dead' = HOST-WIDE dead only; a class-scoped
    kill returns 'none' here so the flat killed-host consumers (briefing / hunter / UI) do
    not suppress the host across classes it was never refuted on."""
    v, _ = host_scope(notes)
    return "dead" if v == "dead-all" else ("open" if v == "open" else "none")


def _load(path):
    hosts = {}
    try:
        for l in open(path, errors="ignore"):
            try:
                d = json.loads(l)
            except Exception:
                continue
            host = d.get("host")
            root = d.get("root_domain")
            if host:
                hosts.setdefault(host, []).append(d)
            # Only bucket a note under root_domain when it is GENUINELY root-level (no distinct
            # host, or host == root). Bucketing every subdomain's note under the apex let one
            # sub's kill flip the whole apex verdict (sibling pollution) — the apex-flip bug.
            if root and (not host or host == root):
                hosts.setdefault(root, []).append(d)
    except FileNotFoundError:
        pass
    return hosts


def killed_hosts(path=NOTES_DEFAULT):
    """HOST-WIDE-dead hosts only (operator do-not-re-* / whole-host exhaustion). Class-scoped
    kills live in killed_host_classes() so a host refuted for one class stays servable."""
    return {h for h, ns in _load(path).items() if host_scope(ns)[0] == "dead-all"}


def killed_host_classes(path=NOTES_DEFAULT):
    """{host -> set(classes)} for hosts killed only for specific vuln classes."""
    out = {}
    for h, ns in _load(path).items():
        v, c = host_scope(ns)
        if v == "dead-class" and c:
            out[h] = c
    return out


def main():
    args = sys.argv[1:]
    if not args:
        print("usage: note_verdict.py killed-hosts|killed-classes|verdict <host> [notes.jsonl]", file=sys.stderr); sys.exit(2)
    cmd = args[0]
    if cmd == "killed-hosts":
        path = args[1] if len(args) > 1 else NOTES_DEFAULT
        for h in sorted(killed_hosts(path)):
            print(h)
    elif cmd == "killed-classes":
        path = args[1] if len(args) > 1 else NOTES_DEFAULT
        for h, c in sorted(killed_host_classes(path).items()):
            print(f"{h}\t{','.join(sorted(c))}")
    elif cmd == "verdict":
        host = args[1]
        path = args[2] if len(args) > 2 else NOTES_DEFAULT
        print(classify_host(_load(path).get(host, [])))
    else:
        print("unknown cmd", file=sys.stderr); sys.exit(2)


if __name__ == "__main__":
    main()
