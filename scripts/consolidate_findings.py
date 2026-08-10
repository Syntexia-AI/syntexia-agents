#!/usr/bin/env python3
"""Consolidate per-agent findings JSON into one prioritized, deduplicated set.

The three correlation rules that used to live in orchestrator prose are here as
code, so they are testable: run `python consolidate_findings.py --self-test`.

Input : a directory of <agent>.json files, each conforming to
        templates/findings.schema.json.
Output: consolidated.json { findings: [...ordered P0..P3], counts: {...},
        escalations: [...], scans: [...], clean_checks: [...] }.

No third-party dependency: the schema check is a pure-Python structural pass.
"""
import argparse
import json
import pathlib
import re
import sys

SEV_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
SEV_LIST = ["P0", "P1", "P2", "P3"]
VALID_CATEGORIES = {"secret", "dependency", "sast", "authz", "api", "llm",
                    "resilience", "infra", "injection"}
VALID_STATUS = {"OPEN", "FIXED", "NEEDS-HUMAN"}
ALLOWED_TAGS = {"scope-touches-exposed-route", "unauth-inbound-channel",
                "reaches-tool-side-effects", "missing-tenant-filter",
                "reachable-from-surface", "history-only", "dummy-suspected"}


def escalate(sev, steps=1):
    return SEV_LIST[max(0, SEV_ORDER[sev] - steps)]


def structural_check(doc, source):
    """Structural + type validation. Returns list of error strings. Never raises."""
    errs = []
    if not isinstance(doc, dict):
        return [f"{source}: racine non-objet"]
    for key in ("agent", "findings", "scans", "clean_checks"):
        if key not in doc:
            errs.append(f"{source}: champ '{key}' absent")
    findings = doc.get("findings")
    if findings is not None and not isinstance(findings, list):
        errs.append(f"{source}: 'findings' n'est pas une liste")
        findings = []
    for i, f in enumerate(findings or []):
        loc = f"{source}#finding[{i}]"
        if not isinstance(f, dict):
            errs.append(f"{loc}: finding non-objet")
            continue
        for key in ("id", "title", "category", "severity", "confidence",
                    "file", "evidence", "impact", "fix_hint", "verified", "status"):
            if key not in f:
                errs.append(f"{loc}: champ '{key}' absent")
        if not isinstance(f.get("id"), str) or not f.get("id"):
            errs.append(f"{loc}: id absent ou non-textuel")
        if f.get("severity") not in SEV_ORDER:
            errs.append(f"{loc}: severity invalide ({f.get('severity')})")
        if f.get("category") not in VALID_CATEGORIES:
            errs.append(f"{loc}: category invalide ({f.get('category')})")
        if f.get("status") not in VALID_STATUS:
            errs.append(f"{loc}: status invalide ({f.get('status')})")
        line = f.get("line")
        if line is not None and not isinstance(line, int):
            errs.append(f"{loc}: line ni entier ni null ({line!r})")
        tags = f.get("correlation_tags")
        if tags is not None:
            if not isinstance(tags, list):
                errs.append(f"{loc}: correlation_tags n'est pas une liste")
            else:
                for t in tags:
                    if t not in ALLOWED_TAGS:
                        errs.append(f"{loc}: correlation_tag inconnu ({t!r})")
    return errs


def dedup_key(f):
    line = f.get("line")
    if line is None:
        # File-level finding: distinguish distinct flaws by normalized title so two
        # different findings in the same file+category do not silently merge.
        norm = re.sub(r"[^a-z0-9]+", "", (f.get("title") or "").lower())
        return (f.get("category"), f.get("file"), "title:" + norm)
    return (f.get("category"), f.get("file"), line)


def apply_correlation_rules(findings):
    """Three escalation rules, each returns the applied escalations for audit.

    R1 : a secret whose scope touches an exposed route escalates one level.
    R2 : an unauthenticated inbound channel that can reach model tools with side
         effects escalates to P0.
    R3 : a missing tenant filter on a code path reachable from SURFACE escalates
         one level.
    """
    escalations = []
    for f in findings:
        tags = set(f.get("correlation_tags") or [])
        before = f["severity"]
        # Each applicable rule proposes a severity; the STRONGEST wins (rules do not
        # shadow each other in an if/elif chain).
        candidates = [(SEV_ORDER[before], None)]
        if f["category"] == "secret" and "scope-touches-exposed-route" in tags:
            candidates.append((SEV_ORDER[escalate(before, 1)], "R1 secret+route"))
        if "unauth-inbound-channel" in tags and "reaches-tool-side-effects" in tags:
            candidates.append((SEV_ORDER["P0"], "R2 unauth-channel+tool-side-effects"))
        if (f["category"] == "authz" and "missing-tenant-filter" in tags
                and "reachable-from-surface" in tags):
            candidates.append((SEV_ORDER[escalate(before, 1)], "R3 tenant-filter+reachable"))
        best_idx = min(idx for idx, _ in candidates)
        if best_idx < SEV_ORDER[before]:
            f["severity"] = SEV_LIST[best_idx]
            winners = [r for idx, r in candidates if r and idx == best_idx]
            escalations.append({"id": f["id"], "rule": "+".join(winners),
                                "from": before, "to": f["severity"]})
    return escalations


def consolidate(docs):
    """docs: list of (source_name, parsed_doc). Returns consolidated dict + errors."""
    errors = []
    all_findings = []
    scans = []
    clean_checks = []
    for source, doc in docs:
        errs = structural_check(doc, source)
        errors.extend(errs)
        if errs:
            continue
        for f in (doc.get("findings") or []):
            g = dict(f)
            g["source_agents"] = [doc["agent"]]
            all_findings.append(g)
        for s in doc.get("scans", []):
            scans.append({**s, "agent": doc["agent"]})
        clean_checks.extend(f"[{doc['agent']}] {c}" for c in doc.get("clean_checks", []))

    # Deduplicate, merging source agents and taking the highest severity seen.
    merged = {}
    for f in all_findings:
        k = dedup_key(f)
        if k not in merged:
            merged[k] = f
        else:
            m = merged[k]
            for a in f["source_agents"]:
                if a not in m["source_agents"]:
                    m["source_agents"].append(a)
            if SEV_ORDER[f["severity"]] < SEV_ORDER[m["severity"]]:
                m["severity"] = f["severity"]
            m["verified"] = m.get("verified") or f.get("verified")
            m["correlation_tags"] = sorted(
                set(m.get("correlation_tags") or []) | set(f.get("correlation_tags") or []))
    findings = list(merged.values())

    escalations = apply_correlation_rules(findings)
    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f.get("file") or "", f.get("id") or ""))

    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_LIST}
    status_counts = {}
    for f in findings:
        status_counts[f["status"]] = status_counts.get(f["status"], 0) + 1
    contributing = sorted({a for f in findings for a in f.get("source_agents", [])})

    return {
        "findings": findings,
        "counts": counts,
        "status_counts": status_counts,
        "escalations": escalations,
        "contributing_agents": contributing,
        "scans": scans,
        "clean_checks": clean_checks,
    }, errors


def load_dir(path):
    docs = []
    for p in sorted(pathlib.Path(path).glob("*.json")):
        if p.name == "consolidated.json":
            continue
        try:
            docs.append((p.name, json.loads(p.read_text(encoding="utf-8"))))
        except Exception as e:
            docs.append((p.name, {"__parse_error__": str(e)}))
    return docs


def self_test():
    def finding(id, cat, sev, tags=None, file="a.py", line=1, status="OPEN"):
        return {"id": id, "title": f"t {id}", "category": cat, "severity": sev,
                "confidence": "high", "file": file, "line": line, "evidence": "e",
                "impact": "i", "fix_hint": "f", "verified": False, "status": status,
                "correlation_tags": tags or []}

    def doc(agent, findings):
        return {"agent": agent, "findings": findings, "scans": [], "clean_checks": []}

    failures = []

    # R1: secret P2 + scope-touches-exposed-route -> P1
    r, e = consolidate([("s", doc("secrets-hunter",
        [finding("SECRETS-001", "secret", "P2", ["scope-touches-exposed-route"])]))])
    if r["findings"][0]["severity"] != "P1":
        failures.append(f"R1 attendu P1, obtenu {r['findings'][0]['severity']}")
    if not any(x["rule"].startswith("R1") for x in r["escalations"]):
        failures.append("R1 non tracee dans escalations")

    # R2: any P3 with unauth-inbound-channel + reaches-tool-side-effects -> P0
    r, e = consolidate([("a", doc("api-webhook-hardener",
        [finding("API-001", "api", "P3", ["unauth-inbound-channel", "reaches-tool-side-effects"])]))])
    if r["findings"][0]["severity"] != "P0":
        failures.append(f"R2 attendu P0, obtenu {r['findings'][0]['severity']}")

    # R2 negative: only one of the two tags -> unchanged
    r, e = consolidate([("a", doc("api-webhook-hardener",
        [finding("API-002", "api", "P2", ["unauth-inbound-channel"])]))])
    if r["findings"][0]["severity"] != "P2":
        failures.append(f"R2-neg attendu P2, obtenu {r['findings'][0]['severity']}")

    # R3: authz P2 + missing-tenant-filter + reachable-from-surface -> P1
    r, e = consolidate([("z", doc("authz-tenant-reviewer",
        [finding("AUTHZ-001", "authz", "P2", ["missing-tenant-filter", "reachable-from-surface"])]))])
    if r["findings"][0]["severity"] != "P1":
        failures.append(f"R3 attendu P1, obtenu {r['findings'][0]['severity']}")

    # R3 negative: missing reachability -> unchanged
    r, e = consolidate([("z", doc("authz-tenant-reviewer",
        [finding("AUTHZ-002", "authz", "P2", ["missing-tenant-filter"])]))])
    if r["findings"][0]["severity"] != "P2":
        failures.append(f"R3-neg attendu P2, obtenu {r['findings'][0]['severity']}")

    # No escalation past P0
    r, e = consolidate([("a", doc("api-webhook-hardener",
        [finding("API-003", "api", "P0", ["unauth-inbound-channel", "reaches-tool-side-effects"])]))])
    if r["findings"][0]["severity"] != "P0":
        failures.append("clamp P0 casse")

    # Strongest rule wins: secret P3 carrying R1 tag AND both R2 tags -> P0 (not P2)
    r, e = consolidate([("s", doc("secrets-hunter", [finding(
        "SECRETS-002", "secret", "P3",
        ["scope-touches-exposed-route", "unauth-inbound-channel", "reaches-tool-side-effects"])]))])
    if r["findings"][0]["severity"] != "P0":
        failures.append(f"strongest-rule attendu P0, obtenu {r['findings'][0]['severity']}")

    # Null-line distinct findings in same file+category do NOT merge
    r, e = consolidate([("a", doc("secrets-hunter", [
        finding("SEC-010", "secret", "P1", file="config.py", line=None),
        {"id": "SEC-011", "title": "different secret", "category": "secret", "severity": "P1",
         "confidence": "high", "file": "config.py", "line": None, "evidence": "e2",
         "impact": "i", "fix_hint": "f", "verified": False, "status": "OPEN"},
    ]))])
    if len(r["findings"]) != 2:
        failures.append(f"null-line dedup: attendu 2 findings distincts, obtenu {len(r['findings'])}")

    # Null-line identical-title findings DO merge (same flaw, two agents)
    def titled(id, title, sev, agent):
        return doc(agent, [{"id": id, "title": title, "category": "secret", "severity": sev,
                            "confidence": "high", "file": "c.py", "line": None, "evidence": "e",
                            "impact": "i", "fix_hint": "f", "verified": False, "status": "OPEN"}])
    r, e = consolidate([
        ("a", titled("SEC-020", "hardcoded token", "P1", "secrets-hunter")),
        ("b", titled("SEC-021", "hardcoded token", "P2", "sast-triager")),
    ])
    if len(r["findings"]) != 1:
        failures.append(f"null-line same-title: attendu 1 fusionne, obtenu {len(r['findings'])}")
    elif set(r["findings"][0]["source_agents"]) != {"secrets-hunter", "sast-triager"}:
        failures.append("null-line same-title: sources non fusionnees")

    # Malformed inputs never crash: non-dict finding, null id, null findings, unknown tag
    for label, bad in [
        ("non-dict finding", {"agent": "x", "findings": [42], "scans": [], "clean_checks": []}),
        ("null id", {"agent": "x", "findings": [{"id": None, "title": "t", "category": "sast",
                     "severity": "P1", "confidence": "high", "file": "a", "evidence": "e",
                     "impact": "i", "fix_hint": "f", "verified": False, "status": "OPEN"}],
                     "scans": [], "clean_checks": []}),
        ("null findings", {"agent": "x", "findings": None, "scans": [], "clean_checks": []}),
        ("unknown tag", {"agent": "x", "findings": [dict(finding("Z-1", "sast", "P1"),
                        correlation_tags=["bogus-tag"])], "scans": [], "clean_checks": []}),
    ]:
        try:
            r, e = consolidate([(label, bad)])
        except Exception as ex:
            failures.append(f"crash sur '{label}': {ex}")

    # Dedup across two agents, same file:line:category, merges sources, keeps worst severity
    r, e = consolidate([
        ("a", doc("sast-triager", [finding("SAST-001", "sast", "P2")])),
        ("b", doc("api-webhook-hardener", [finding("API-004", "sast", "P1")])),
    ])
    if len(r["findings"]) != 1:
        failures.append(f"dedup attendu 1 finding, obtenu {len(r['findings'])}")
    elif r["findings"][0]["severity"] != "P1":
        failures.append("dedup: pire severite non conservee")
    elif set(r["findings"][0]["source_agents"]) != {"sast-triager", "api-webhook-hardener"}:
        failures.append("dedup: sources non fusionnees")

    # Ordering P0 before P3
    r, e = consolidate([("a", doc("x", [
        finding("X-003", "sast", "P3", file="z.py"),
        finding("X-001", "sast", "P0", file="a.py"),
    ]))])
    if [f["severity"] for f in r["findings"]] != ["P0", "P3"]:
        failures.append("tri par severite casse")

    # Structural check catches a bad severity
    r, e = consolidate([("bad", doc("x", [
        {"id": "X-001", "title": "t", "category": "sast", "severity": "P9",
         "confidence": "high", "file": "a", "evidence": "e", "impact": "i",
         "fix_hint": "f", "verified": False, "status": "OPEN"}]))])
    if not any("severity invalide" in x for x in e):
        failures.append("structural_check ne detecte pas severity invalide")

    if failures:
        print("SELF-TEST ECHEC")
        for f in failures:
            print(" -", f)
        return 1
    print("SELF-TEST OK: 3 regles d'escalade + negatifs + clamp + dedup + tri + structure.")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="indir", help="dossier des <agent>.json")
    ap.add_argument("--out", dest="outfile", help="chemin de sortie consolidated.json")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if not args.indir:
        ap.error("--in requis hors self-test")

    docs = load_dir(args.indir)
    parse_errors = [f"{n}: JSON illisible ({d['__parse_error__']})"
                    for n, d in docs if "__parse_error__" in d]
    docs = [(n, d) for n, d in docs if "__parse_error__" not in d]
    result, errors = consolidate(docs)
    errors = parse_errors + errors
    result["input_errors"] = errors

    out = args.outfile or str(pathlib.Path(args.indir) / "consolidated.json")
    pathlib.Path(out).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"consolidated: {sum(result['counts'].values())} findings "
          f"(P0={result['counts']['P0']} P1={result['counts']['P1']} "
          f"P2={result['counts']['P2']} P3={result['counts']['P3']}), "
          f"{len(result['escalations'])} escalades, ecrit dans {out}")
    if errors:
        print(f"ATTENTION: {len(errors)} erreurs d'entree (voir input_errors):")
        for e in errors[:10]:
            print(" -", e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
