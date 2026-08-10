#!/usr/bin/env python3
"""Measure fleet recall against the witness repo's expected findings.

An expected finding is matched when a consolidated finding shares its category,
points at the same file (basename), AND contains at least one of the expected
entry's match_tokens (code identifiers, independent of report language). Matching
is one-to-one and greedy: each finding is consumed by at most one expected entry,
so two distinct flaws in the same file+category cannot both be satisfied by a
single finding (which would inflate recall). Severity below the expected minimum
is a warning, not a recall miss: recall answers "did the fleet see it at all".

Exit 1 if recall is below --min-recall (default 0.9) so CI or a human gate can
treat a regression as a failure, not an opinion.
"""
import argparse
import json
import pathlib
import sys

SEV_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


def basename(p):
    return (p or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


def finding_text(finding):
    fields = " ".join([
        basename(finding.get("file")),
        (finding.get("file") or ""),
        (finding.get("evidence") or ""),
        (finding.get("title") or ""),
        (finding.get("impact") or ""),
        (finding.get("fix_hint") or ""),
    ])
    for occ in finding.get("occurrences", []) or []:
        fields += " " + (occ.get("file") or "")
    return fields.lower()


def matches(expected, finding):
    if expected["category"] != finding.get("category"):
        return False
    text = finding_text(finding)
    exp_file = basename(expected.get("file"))
    if not exp_file or exp_file not in text:
        return False
    tokens = [t.lower() for t in expected.get("match_tokens", []) if t]
    if not tokens:
        return True
    return any(t in text for t in tokens)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--expected", required=True)
    ap.add_argument("--consolidated", required=True)
    ap.add_argument("--min-recall", type=float, default=0.9)
    args = ap.parse_args()

    expected = json.loads(pathlib.Path(args.expected).read_text(encoding="utf-8"))["expected"]
    cons_path = pathlib.Path(args.consolidated)
    if not cons_path.exists():
        print(f"ECHEC: consolidated absent: {cons_path}")
        return 1
    findings = json.loads(cons_path.read_text(encoding="utf-8")).get("findings", [])

    matched, missed, sev_warn = [], [], []
    per_cat = {}
    consumed = set()  # indices of findings already assigned, one-to-one
    for exp in expected:
        cat = exp["category"]
        per_cat.setdefault(cat, {"total": 0, "found": 0})
        per_cat[cat]["total"] += 1
        hit = None
        for i, f in enumerate(findings):
            if i in consumed:
                continue
            if matches(exp, f):
                hit = f
                consumed.add(i)
                break
        if hit:
            matched.append(exp["key"])
            per_cat[cat]["found"] += 1
            want = exp.get("min_severity")
            if want and SEV_ORDER.get(hit.get("severity"), 9) > SEV_ORDER.get(want, 9):
                sev_warn.append(f"{exp['key']}: attendu >= {want}, obtenu {hit.get('severity')}")
        else:
            missed.append(exp["key"])

    total = len(expected)
    recall = len(matched) / total if total else 1.0
    print(f"RAPPEL GLOBAL: {len(matched)}/{total} = {recall:.0%}")
    print("Par categorie:")
    for cat in sorted(per_cat):
        c = per_cat[cat]
        print(f"  {cat:12s} {c['found']}/{c['total']}")
    if missed:
        print("MANQUES:")
        for k in missed:
            exp = next(e for e in expected if e["key"] == k)
            print(f"  - {k} ({exp['category']}, {exp['file']}): {exp.get('hint','')}")
    if sev_warn:
        print("SEVERITE SOUS L'ATTENDU (avertissement, pas un manque):")
        for w in sev_warn:
            print("  -", w)

    if recall < args.min_recall:
        print(f"ECHEC: rappel {recall:.0%} < seuil {args.min_recall:.0%}")
        return 1
    print(f"OK: rappel {recall:.0%} >= seuil {args.min_recall:.0%}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
