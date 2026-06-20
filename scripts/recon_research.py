#!/usr/bin/env python3
"""recon_research.py — router for the Claude research routine (recon_research.sh).

Headless Claude returns a markdown research report that may embed fenced blocks:
    ```kb-new:<slug>            a brand-NEW knowledge-base doc (tech-x / class-x)
    ...content...
    ```
    ```kb-proposal:<slug>       an enrichment/edit to an EXISTING kb doc (review-only)
    ...content...
    ```
This router (bash controls all file writes — Claude never gets Write/Edit) splits that into:
  - a committed dated digest (docs/research/<topic>_<date>.md) = the report minus the blocks
  - brand-NEW kb docs (docs/knowledge/<slug>.md) — ONLY if the slug does not already exist
  - proposals (docs/research/proposals/<date>_<topic>_<slug>.md) for EVERYTHING else
    (kb-proposal blocks, AND any kb-new whose slug already exists → never silently rewrite KB)
Prints a JSON summary to stdout for the orchestrator (commit + Discord).

  route --topic T --date D --input FILE --kb-dir DIR --research-dir DIR
"""
import argparse
import json
import os
import re
import sys

BLOCK_RE = re.compile(
    r"^```kb-(new|proposal):([A-Za-z0-9._-]+)[ \t]*\n(.*?)^```[ \t]*$",
    re.M | re.S)
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,60}$")


def _safe_slug(slug):
    slug = slug.strip().lower()
    if slug.endswith(".md"):
        slug = slug[:-3]
    return slug if SLUG_RE.match(slug) else ""


def cmd_route(a):
    raw = ""
    if a.input and os.path.exists(a.input):
        with open(a.input, encoding="utf-8", errors="ignore") as fh:
            raw = fh.read()
    raw = raw.strip()
    summary = {"topic": a.topic, "date": a.date, "digest": "", "new_kb": [],
               "proposals": [], "headline": "", "empty": True}
    if not raw:
        print(json.dumps(summary))
        return

    new_kb, proposals = [], []
    # extract + strip fenced kb blocks; the remainder is the digest body
    for m in BLOCK_RE.finditer(raw):
        kind, slug, content = m.group(1), _safe_slug(m.group(2)), m.group(3).strip()
        if not slug or not content:
            continue
        kb_path = os.path.join(a.kb_dir, slug + ".md")
        if kind == "new" and not os.path.exists(kb_path):
            new_kb.append((slug, kb_path, content))
        else:
            # kb-proposal, OR a kb-new whose slug already exists → review-only proposal
            proposals.append((slug, kind, content))
    digest_body = BLOCK_RE.sub("", raw).strip()

    os.makedirs(a.research_dir, exist_ok=True)
    prop_dir = os.path.join(a.research_dir, "proposals")
    os.makedirs(prop_dir, exist_ok=True)

    # 1) digest (always, append-only dated file)
    digest_path = os.path.join(a.research_dir, "%s_%s.md" % (a.topic, a.date))
    header = "# Research digest — %s — %s\n\n" % (a.topic, a.date)
    with open(digest_path, "w", encoding="utf-8") as fh:
        fh.write(header + (digest_body or "_(no narrative body)_") + "\n")
    summary["digest"] = digest_path

    # 2) brand-new KB docs (auto-created)
    for slug, kb_path, content in new_kb:
        with open(kb_path, "w", encoding="utf-8") as fh:
            fh.write(content.rstrip() + "\n")
        summary["new_kb"].append(kb_path)

    # 3) proposals (review-only)
    for slug, kind, content in proposals:
        pp = os.path.join(prop_dir, "%s_%s_%s.md" % (a.date, a.topic, slug))
        with open(pp, "w", encoding="utf-8") as fh:
            fh.write("# PROPOSAL (%s) for docs/knowledge/%s.md — %s %s\n"
                     "_Review and apply manually; not auto-merged into the KB._\n\n%s\n"
                     % (kind, slug, a.topic, a.date, content.rstrip()))
        summary["proposals"].append(pp)

    # headline = first non-empty, non-heading line of the digest
    for line in digest_body.splitlines():
        s = line.strip().lstrip("#").strip()
        if s and not s.startswith("_"):
            summary["headline"] = s[:200]
            break
    summary["empty"] = not (digest_body or new_kb or proposals)
    print(json.dumps(summary))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("route")
    r.add_argument("--topic", required=True)
    r.add_argument("--date", required=True)
    r.add_argument("--input", required=True)
    r.add_argument("--kb-dir", required=True)
    r.add_argument("--research-dir", required=True)
    r.set_defaults(func=cmd_route)
    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
