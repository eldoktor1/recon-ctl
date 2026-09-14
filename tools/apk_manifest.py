#!/usr/bin/env python3
"""Enumerate an APK's EXPORTED components from a decoded AndroidManifest.xml.

An exported component is callable by any other app installed on the device, which makes it the
app's own remote-input surface - the mobile equivalent of an unauthenticated route. Two details
are easy to get wrong and both matter:

  1. `exported` DEFAULTS TO TRUE when an intent-filter is present and the attribute is absent.
     Counting only `exported="true"` undercounts the surface badly.
  2. An exported component guarded by a signature-level `permission` is not reachable by an
     arbitrary app, so the permission attribute has to be reported alongside, never dropped.

Output is one tab-separated row per exported component:
    kind  name  perm=...  schemes=...  hosts=...  actions=...
so the caller can diff it between releases with plain comm/sort.

Usage: apk_manifest.py <path to decoded AndroidManifest.xml>
"""
import sys
import xml.etree.ElementTree as ET

NS = "{http://schemas.android.com/apk/res/android}"
KINDS = ("activity", "activity-alias", "service", "receiver", "provider")


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        root = ET.parse(sys.argv[1]).getroot()
    except Exception as exc:
        print(f"unparseable manifest: {exc}", file=sys.stderr)
        return 1

    rows = []
    for kind in KINDS:
        for el in root.iter(kind):
            exported = el.get(NS + "exported")
            has_filter = el.find("intent-filter") is not None
            if not (exported == "true" or (exported is None and has_filter)):
                continue
            schemes, hosts, actions = set(), set(), set()
            for f in el.iter("intent-filter"):
                for d in f.iter("data"):
                    if d.get(NS + "scheme"):
                        schemes.add(d.get(NS + "scheme"))
                    if d.get(NS + "host"):
                        hosts.add(d.get(NS + "host"))
                for a in f.iter("action"):
                    actions.add((a.get(NS + "name") or "").rsplit(".", 1)[-1])
            rows.append("\t".join([
                kind,
                el.get(NS + "name") or "?",
                "perm=" + (el.get(NS + "permission") or "NONE"),
                "schemes=" + (",".join(sorted(schemes)) or "-"),
                "hosts=" + (",".join(sorted(hosts)) or "-"),
                "actions=" + (",".join(sorted(a for a in actions if a)) or "-"),
            ]))

    for r in sorted(rows):
        print(r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
