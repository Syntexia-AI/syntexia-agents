#!/usr/bin/env python3
"""Preflight: probe the security toolchain, write a capability report the
orchestrator reads in Phase 0 so any missing tool becomes an announced
degradation, never silent.

Read-only. Runs each tool's version probe with a short timeout. Writes JSON to
--out (default /tmp/sweep/tooling.json) and prints a human summary.
"""
import argparse
import json
import pathlib
import shutil
import subprocess
import sys

# tool -> (version argv, install hint)
TOOLS = {
    "gitleaks": (["gitleaks", "version"],
                 "https://github.com/gitleaks/gitleaks/releases (binaire)"),
    "trufflehog": (["trufflehog", "--version"],
                   "https://github.com/trufflesecurity/trufflehog/releases (binaire)"),
    "trivy": (["trivy", "--version"],
              "https://github.com/aquasecurity/trivy/releases (binaire)"),
    "opengrep": (["opengrep", "--version"],
                 "https://github.com/opengrep/opengrep/releases (binaire)"),
    "semgrep": (["semgrep", "--version"],
                "pip install semgrep (repli si opengrep absent)"),
    "bandit": (["bandit", "--version"],
               "pip install bandit"),
    "pip-audit": (["pip-audit", "--version"],
                  "pip install pip-audit"),
    "npm": (["npm", "--version"],
            "https://nodejs.org (pour npm audit)"),
}

# Agents whose coverage degrades when a tool is absent.
IMPACT = {
    "gitleaks": "secrets-hunter : scan historique et arbre reduits au fallback grep",
    "trufflehog": "secrets-hunter : detection large reduite",
    "trivy": "dependency-auditor : CVE images/misconfig non couverts",
    "opengrep": "sast-triager : SAST principal indisponible (repli semgrep)",
    "semgrep": "sast-triager : repli SAST indisponible si opengrep aussi absent",
    "bandit": "sast-triager : SAST Python indisponible",
    "pip-audit": "dependency-auditor : CVE Python non couverts",
    "npm": "dependency-auditor : npm audit indisponible",
}


def probe(argv):
    exe = shutil.which(argv[0])
    if not exe:
        return {"present": False, "path": None, "version": None}
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        out = (p.stdout or p.stderr or "").strip().splitlines()
        version = out[0].strip() if out else ""
    except Exception as e:
        version = f"probe error: {e}"
    return {"present": True, "path": exe, "version": version}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/tmp/sweep/tooling.json")
    args = ap.parse_args()

    report = {"tools": {}, "missing": [], "sast_available": False, "notes": []}
    for name, (argv, hint) in TOOLS.items():
        r = probe(argv)
        r["install_hint"] = hint
        if not r["present"]:
            r["impact"] = IMPACT.get(name, "")
            report["missing"].append(name)
        report["tools"][name] = r

    report["sast_available"] = report["tools"]["opengrep"]["present"] or report["tools"]["semgrep"]["present"]
    if not report["sast_available"]:
        report["notes"].append("Aucun moteur SAST (opengrep ni semgrep) : sast-triager degrade au passage manuel.")
    if not report["tools"]["gitleaks"]["present"] and not report["tools"]["trufflehog"]["present"]:
        report["notes"].append("Aucun scanner de secrets dedie : secrets-hunter repose sur le seul fallback grep.")

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    present = [n for n, r in report["tools"].items() if r["present"]]
    print(f"Outillage : {len(present)}/{len(TOOLS)} present. Rapport ecrit dans {out}")
    if report["missing"]:
        print("Manquants (degradation annoncee) :")
        for n in report["missing"]:
            print(f" - {n} : {IMPACT.get(n,'')} | install: {TOOLS[n][1]}")
    for note in report["notes"]:
        print(" !", note)
    return 0


if __name__ == "__main__":
    sys.exit(main())
