#!/usr/bin/env python3
"""Extract in-scope Android app package IDs (+ program + pays) from scope/raw/*.json,
across the differing platform schemas. Output JSONL: {package,program,platform,pays}.
Feeds the mobile-APK prong of the cognito lane (APKs hold the legacy MobileHub pools)."""
import glob, json, os, re, sys

RAW = os.path.expanduser("~/recon/scope/raw")
PLAY_RE = re.compile(r'(?:id=)([a-zA-Z][\w]*(?:\.[A-Za-z0-9_]+)+)')
PKG_RE  = re.compile(r'^[a-zA-Z][\w]*(?:\.[A-Za-z0-9_]+){1,}$')
ANDROID_TYPES = re.compile(r'google_play|android|other_apk|\bapk\b', re.I)


def prog_name(p):
    for k in ("name", "handle", "program", "code", "title", "slug"):
        if isinstance(p, dict) and p.get(k):
            return str(p[k])
    return "?"


def to_pkg(ident):
    if not ident:
        return None
    ident = str(ident).strip()
    m = PLAY_RE.search(ident)
    if m:
        return m.group(1)
    if PKG_RE.match(ident):
        return ident
    # play url without id= (path form) e.g. .../details/com.x  — best effort
    m = re.search(r'([a-z][\w]*(?:\.[A-Za-z0-9_]+){2,})', ident)
    return m.group(1) if m else None


def iter_targets(prog):
    t = prog.get("targets") if isinstance(prog, dict) else None
    if isinstance(t, dict):
        for k in ("in_scope", "inScope", "scope"):
            for a in (t.get(k) or []):
                yield a
    # some schemas: prog['scope']['in_scope']
    s = prog.get("scope") if isinstance(prog, dict) else None
    if isinstance(s, dict):
        for a in (s.get("in_scope") or []):
            yield a


def main():
    seen = set()
    for f in glob.glob(os.path.join(RAW, "*.json")):
        plat = os.path.basename(f).replace(".json", "")
        try:
            data = json.load(open(f))
        except Exception:
            continue
        progs = data if isinstance(data, list) else [data]
        for prog in progs:
            if not isinstance(prog, dict):
                continue
            pname = prog_name(prog)
            for a in iter_targets(prog):
                if not isinstance(a, dict):
                    continue
                atype = str(a.get("asset_type") or a.get("type") or "")
                ident = a.get("asset_identifier") or a.get("target") or a.get("uri") or a.get("name") or ""
                ids = str(ident)
                # STRICT: only an explicit android/google-play/apk asset TYPE, or a play.google URL.
                # (a bare dotted string is almost always a web domain, not a package.)
                is_android = bool(ANDROID_TYPES.search(atype)) or ("play.google.com" in ids)
                if not is_android:
                    continue
                pkg = to_pkg(ids)
                # reject things that are really web hosts (TLD-suffixed, no android-y package shape)
                if not pkg or pkg.count(".") < 2 or pkg.endswith((".com", ".net", ".org", ".io", ".fr",
                        ".de", ".co", ".app", ".ai", ".se", ".hk", ".sg", ".gouv", ".info", ".at", ".be")):
                    # keep it only if the asset TYPE explicitly said android/play
                    if not (ANDROID_TYPES.search(atype) or "play.google.com" in ids):
                        continue
                if not pkg or "." not in pkg:
                    continue
                # pays: hackerone per-asset; else default True (program-level filtered later)
                pays = a.get("eligible_for_bounty")
                pays = True if pays is None else bool(pays)
                key = (pkg, pname)
                if key in seen:
                    continue
                seen.add(key)
                print(json.dumps({"package": pkg, "program": pname, "platform": plat, "pays": pays}))
    print(f"[apks] {len(seen)} unique in-scope android package(s)", file=sys.stderr)


if __name__ == "__main__":
    main()
