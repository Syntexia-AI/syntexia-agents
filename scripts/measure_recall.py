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
import re
import sys

SEV_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


def basename(p):
    return (p or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


def finding_basenames(finding):
    """Set of file basenames the finding actually points at (file + occurrences)."""
    names = {basename(finding.get("file"))}
    for occ in finding.get("occurrences", []) or []:
        names.add(basename(occ.get("file")))
    return {n for n in names if n}


def finding_text(finding):
    """Descriptive text only (NOT the file path), so a token cannot be satisfied by
    a filename substring."""
    return " ".join([
        (finding.get("evidence") or ""),
        (finding.get("title") or ""),
        (finding.get("impact") or ""),
        (finding.get("fix_hint") or ""),
    ]).lower()


def token_hit(token, text):
    """Token match with alphanumeric boundaries, so 'key' does not match 'monkeypatch'
    while 'shell=True' or 'sk-ant' still match."""
    t = token.lower()
    return re.search(r"(?<![a-z0-9])" + re.escape(t) + r"(?![a-z0-9])", text) is not None


def matches(expected, finding):
    if expected["category"] != finding.get("category"):
        return False
    exp_file = basename(expected.get("file"))
    # File match by basename EQUALITY (not substring): a.py must not match data.py.
    if exp_file and exp_file not in finding_basenames(finding):
        # Tolerate history-only findings that name the file only in their text, as a
        # whole token, not as an arbitrary substring.
        if not token_hit(exp_file, finding_text(finding)):
            return False
    tokens = [t for t in expected.get("match_tokens", []) if t]
    text = finding_text(finding)
    return any(token_hit(t, text) for t in tokens)


def max_bipartite_matching(expected, findings):
    """Kuhn's algorithm: maximum matching between expected entries and findings, so a
    complete sweep is never under-counted by greedy assignment. Returns dict
    expected_index -> finding_index for matched entries."""
    adj = {ei: [fi for fi, f in enumerate(findings) if matches(exp, f)]
           for ei, exp in enumerate(expected)}
    match_f = {}  # finding_index -> expected_index

    def try_assign(ei, seen):
        for fi in adj[ei]:
            if fi in seen:
                continue
            seen.add(fi)
            if fi not in match_f or try_assign(match_f[fi], seen):
                match_f[fi] = ei
                return True
        return False

    for ei in range(len(expected)):
        try_assign(ei, set())
    return {ei: fi for fi, ei in match_f.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--expected", required=True)
    ap.add_argument("--consolidated", required=True)
    ap.add_argument("--min-recall", type=float, default=0.9)
    args = ap.parse_args()

    expected = json.loads(pathlib.Path(args.expected).read_text(encoding="utf-8"))["expected"]
    # Fail loudly on a degenerate expected file rather than credit a false 100%.
    if not expected:
        print("ECHEC: expected_findings vide, aucun attendu a mesurer.")
        return 1
    tokenless = [e.get("key", "?") for e in expected if not [t for t in e.get("match_tokens", []) if t]]
    if tokenless:
        print("ECHEC: entrees attendues sans match_tokens (matching non fiable): " + ", ".join(tokenless))
        return 1

    cons_path = pathlib.Path(args.consolidated)
    if not cons_path.exists():
        print(f"ECHEC: consolidated absent: {cons_path}")
        return 1
    findings = json.loads(cons_path.read_text(encoding="utf-8")).get("findings", [])

    assignment = max_bipartite_matching(expected, findings)
    matched, missed, sev_warn = [], [], []
    per_cat = {}
    for ei, exp in enumerate(expected):
        cat = exp["category"]
        per_cat.setdefault(cat, {"total": 0, "found": 0})
        per_cat[cat]["total"] += 1
        if ei in assignment:
            hit = findings[assignment[ei]]
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
