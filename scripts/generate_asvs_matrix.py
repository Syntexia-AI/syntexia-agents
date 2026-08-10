#!/usr/bin/env python3
"""Generate the ASVS 5.0 conformance matrix deterministically from the OWASP
requirements CSV and the consolidated findings. No model fills verdicts.

Verdict policy, conservative by construction:
  - non conforme : at least one consolidated finding lists this requirement in
                   its asvs_refs. Evidence = the finding ids.
  - conforme / non applicable : only from an explicit --evidence-map file, never
                   inferred. This keeps a model out of the compliance matrix.
  - non verifie  : default for everything else. Honest default, not a guess.

Levels are cumulative (ASVS convention): L1 assessment covers L==1 requirements;
L2 covers L in {1,2}; L3 covers all. The output notes the count so the scope is
unambiguous.

Output: a CSV with an OWASP CC BY-SA 4.0 attribution header, one row per
in-scope requirement.
"""
import argparse
import csv
import json
import pathlib
import sys

LEVELS = {"L1": {"1"}, "L2": {"1", "2"}, "L3": {"1", "2", "3"}}
ATTRIBUTION = ("# ASVS 5.0.0 requirements (c) OWASP Foundation, CC BY-SA 4.0. "
               "Source: https://github.com/OWASP/ASVS release v5.0.0_release. "
               "See .claude/reference/SOURCES.md. Verdicts added by Syntexia fleet.")


def find_requirements_csv(reference_dir):
    d = pathlib.Path(reference_dir)
    candidates = [p for p in d.glob("*_en.csv") if "legacy" not in p.name.lower()]
    if not candidates:
        candidates = [p for p in d.glob("*.csv") if "legacy" not in p.name.lower()]
    return candidates[0] if candidates else None


def load_requirements(csv_path, levels):
    rows = []
    with open(csv_path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            lvl = (row.get("L") or "").strip()
            if lvl in levels:
                rows.append({
                    "req_id": (row.get("req_id") or "").strip(),
                    "chapter": (row.get("chapter_name") or "").strip(),
                    "section": (row.get("section_name") or "").strip(),
                    "description": (row.get("req_description") or "").strip(),
                    "level": lvl,
                })
    return rows


def build_finding_index(consolidated_path):
    """req_id (upper) -> list of finding ids referencing it."""
    idx = {}
    if not consolidated_path or not pathlib.Path(consolidated_path).exists():
        return idx, False
    data = json.loads(pathlib.Path(consolidated_path).read_text(encoding="utf-8"))
    for f in data.get("findings", []):
        for ref in f.get("asvs_refs", []) or []:
            idx.setdefault(ref.strip().upper(), []).append(f.get("id"))
    return idx, True


def load_evidence_map(path):
    if not path:
        return {}
    p = pathlib.Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--level", default="L2", choices=list(LEVELS))
    ap.add_argument("--reference-dir", default=".claude/reference")
    ap.add_argument("--consolidated", default="/tmp/sweep/consolidated.json")
    ap.add_argument("--evidence-map", default=None,
                    help="JSON {req_id: {verdict, evidence}} for conforme/non applicable rows")
    ap.add_argument("--out", default="asvs-matrix.csv")
    args = ap.parse_args()

    csv_path = find_requirements_csv(args.reference_dir)
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    if not csv_path:
        # Honest degradation: no reference available.
        with open(out, "w", encoding="utf-8", newline="") as f:
            f.write(ATTRIBUTION + "\n")
            w = csv.writer(f)
            w.writerow(["req_id", "level", "chapter", "section", "verdict", "evidence", "description"])
        print(f"REFERENCE ABSENTE dans {args.reference_dir} : matrice vide ecrite dans {out}. "
              f"Item a reporter: reference ASVS manquante.")
        return 1

    levels = LEVELS[args.level]
    reqs = load_requirements(csv_path, levels)
    finding_index, had_consolidated = build_finding_index(args.consolidated)
    evidence_map = load_evidence_map(args.evidence_map)

    counts = {"conforme": 0, "non conforme": 0, "non applicable": 0, "non verifie": 0}
    with open(out, "w", encoding="utf-8", newline="") as f:
        f.write(ATTRIBUTION + "\n")
        w = csv.writer(f)
        w.writerow(["req_id", "level", "chapter", "section", "verdict", "evidence", "description"])
        for r in reqs:
            rid = r["req_id"].upper()
            if rid in finding_index:
                verdict = "non conforme"
                evidence = "findings: " + ", ".join(x for x in finding_index[rid] if x)
            elif rid in evidence_map:
                verdict = evidence_map[rid].get("verdict", "non verifie")
                evidence = evidence_map[rid].get("evidence", "")
            else:
                verdict = "non verifie"
                evidence = ""
            counts[verdict] = counts.get(verdict, 0) + 1
            w.writerow([r["req_id"], r["level"], r["chapter"], r["section"],
                        verdict, evidence, r["description"]])

    print(f"Matrice ASVS {args.level} ecrite dans {out} : {len(reqs)} exigences en perimetre "
          f"(niveaux cumulatifs {sorted(levels)}).")
    print(f"  verdicts: conforme={counts['conforme']} non_conforme={counts['non conforme']} "
          f"non_applicable={counts['non applicable']} non_verifie={counts['non verifie']}")
    if not had_consolidated:
        print("  ATTENTION: consolidated.json absent, aucun finding mappe : tous non_verifie hors evidence-map.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
