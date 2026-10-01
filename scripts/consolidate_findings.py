#!/usr/bin/env python3
"""Consolidate per-agent findings JSON into one prioritized, deduplicated set.

The three correlation rules that used to live in orchestrator prose are here as
code, so they are testable: run `python consolidate_findings.py --self-test`.

Input : a directory of <agent>.json files, each conforming to
        templates/findings.schema.json.
Output: consolidated.json { findings: [...ordered P0..P3], counts: {...},
        escalations: [...], scans: [...], clean_checks: [...] }.

Robustness rules (v0.4):
  - a malformed finding is dropped ALONE and reported in input_errors; the valid
    findings of the same agent are kept (one bad entry must not hide twenty good);
  - ids are made unique: GATE A approves findings by id, so two findings sharing
    an id would make "GO FIXES <ids>" ambiguous (renames listed in id_renames);
  - secret-shaped literals in evidence, titles and hints are redacted before the
    file is written, because the report is committed in the product repo.

Run isolation (v0.4.1): /tmp/sweep is shared by every sweep on a machine. With
--run-marker (the RUN.json written in Phase 0), agent files older than the marker
are rejected as leftovers of a previous sweep, possibly of another client, and a
marker naming another repository stops the consolidation (exit 2, nothing
written).

No third-party dependency: the schema check is a pure-Python structural pass.
"""
import argparse
import json
import os
import pathlib
import re
import sys
import tempfile

SEV_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
SEV_LIST = ["P0", "P1", "P2", "P3"]
VALID_CATEGORIES = {"secret", "dependency", "sast", "authz", "api", "llm",
                    "resilience", "infra", "injection"}
VALID_STATUS = {"OPEN", "FIXED", "NEEDS-HUMAN"}
ALLOWED_TAGS = {"scope-touches-exposed-route", "unauth-inbound-channel",
                "reaches-tool-side-effects", "missing-tenant-filter",
                "reachable-from-surface", "history-only", "dummy-suspected"}
VALID_CONFIDENCE = {"high", "medium", "low"}
ID_RE = re.compile(r"^[A-Z]+-[0-9]{3,}$")
TEXT_FIELDS = ("title", "evidence", "impact", "fix_hint")
REDACT_RULES = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)")),
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_-]{16,}")),
    ("openai-key", re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}")),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("stripe-key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("resend-key", re.compile(r"\bre_[A-Za-z0-9_]{20,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}")),
    ("messaging-bot-token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
]
URL_CRED_RE = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s:/@'\"]+:)([^\s@'\"/]+)(@)")
ASSIGN_RE = re.compile(
    r"(?i)(\b[A-Za-z0-9_.-]*(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|apikey"
    r"|private[_-]?key|client[_-]?secret|access[_-]?key)[A-Za-z0-9_.-]*['\"]?\s*[:=]>?\s*)"
    r"(['\"])([^'\"\n]{8,})\2")


def redact_text(text):
    """Return (redacted_text, [rules applied]). Never keeps more than the rule name
    and the length of what was removed."""
    applied = []
    if not isinstance(text, str) or not text:
        return text, applied

    def tag(rule, value):
        applied.append(rule)
        return "[REDACTED:%s:len=%d]" % (rule, len(value))

    for rule, rx in REDACT_RULES:
        text = rx.sub(lambda m, r=rule: tag(r, m.group(0)), text)
    text = URL_CRED_RE.sub(lambda m: m.group(1) + tag("url-password", m.group(2)) + m.group(3),
                           text)
    text = ASSIGN_RE.sub(lambda m: m.group(1) + m.group(2) + tag("assigned-secret", m.group(3))
                         + m.group(2), text)
    return text, applied


def escalate(sev, steps=1):
    return SEV_LIST[max(0, SEV_ORDER[sev] - steps)]


def doc_errors(doc, source):
    """Document-level validation. Any error here drops the whole agent file."""
    if not isinstance(doc, dict):
        return [f"{source}: racine non-objet"]
    errs = [f"{source}: champ '{k}' absent" for k in ("agent", "findings", "scans",
                                                       "clean_checks") if k not in doc]
    if "findings" in doc and not isinstance(doc.get("findings"), list):
        # null or wrong type: a broken/serialization-failed agent must not read as
        # "clean, nothing found".
        errs.append(f"{source}: 'findings' n'est pas une liste "
                    f"({type(doc.get('findings')).__name__})")
    for k in ("scans", "clean_checks"):
        if k in doc and not isinstance(doc.get(k), list):
            errs.append(f"{source}: '{k}' n'est pas une liste")
    return errs


def finding_errors(f, loc):
    """Finding-level validation. Returns (errors, warnings). Errors drop only this
    finding; warnings keep it."""
    if not isinstance(f, dict):
        return [f"{loc}: finding non-objet"], []
    errs, warns = [], []
    for key in ("id", "title", "category", "severity", "confidence", "file", "evidence",
                "impact", "fix_hint", "verified", "status"):
        if key not in f:
            errs.append(f"{loc}: champ '{key}' absent")
    if not isinstance(f.get("id"), str) or not f.get("id"):
        errs.append(f"{loc}: id absent ou non-textuel")
    elif not ID_RE.match(f["id"]):
        warns.append(f"{loc}: id '{f['id']}' hors format AGENT-NNN")
    if f.get("severity") not in SEV_ORDER:
        errs.append(f"{loc}: severity invalide ({f.get('severity')})")
    if f.get("category") not in VALID_CATEGORIES:
        errs.append(f"{loc}: category invalide ({f.get('category')})")
    if f.get("status") not in VALID_STATUS:
        errs.append(f"{loc}: status invalide ({f.get('status')})")
    if "confidence" in f and f.get("confidence") not in VALID_CONFIDENCE:
        warns.append(f"{loc}: confidence invalide ({f.get('confidence')}), ramenee a low")
    if "verified" in f and not isinstance(f.get("verified"), bool):
        warns.append(f"{loc}: verified non booleen, ramene a false")
    line = f.get("line")
    if line is not None and (not isinstance(line, int) or isinstance(line, bool)):
        errs.append(f"{loc}: line ni entier ni null ({line!r})")
    tags = f.get("correlation_tags")
    if tags is not None:
        if not isinstance(tags, list):
            errs.append(f"{loc}: correlation_tags n'est pas une liste")
        else:
            for t in tags:
                if t not in ALLOWED_TAGS:
                    errs.append(f"{loc}: correlation_tag inconnu ({t!r})")
    for key in TEXT_FIELDS + ("file",):
        if key in f and not isinstance(f.get(key), str):
            errs.append(f"{loc}: '{key}' non textuel")
    return errs, warns


def structural_check(doc, source):
    """Backward-compatible helper: every error of a document, never raises."""
    errs = doc_errors(doc, source)
    if errs and (not isinstance(doc, dict) or not isinstance(doc.get("findings"), list)):
        return errs
    for i, f in enumerate(doc.get("findings") or []):
        errs.extend(finding_errors(f, f"{source}#finding[{i}]")[0])
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
    errors, warnings, redactions = [], [], []
    all_findings, scans, clean_checks = [], [], []
    for source, doc in docs:
        derrs = doc_errors(doc, source)
        errors.extend(derrs)
        if derrs:
            continue
        for i, f in enumerate(doc.get("findings") or []):
            ferrs, fwarns = finding_errors(f, f"{source}#finding[{i}]")
            errors.extend(ferrs)
            warnings.extend(fwarns)
            if ferrs:
                continue
            g = dict(f)
            if g.get("confidence") not in VALID_CONFIDENCE:
                g["confidence"] = "low"
            if not isinstance(g.get("verified"), bool):
                g["verified"] = False
            for key in TEXT_FIELDS:
                g[key], applied = redact_text(g.get(key))
                for rule in applied:
                    redactions.append({"id": g["id"], "field": key, "rule": rule})
            g["source_agents"] = [doc["agent"]]
            all_findings.append(g)
        for s_ in doc.get("scans", []):
            if isinstance(s_, dict):
                scans.append({**s_, "agent": doc["agent"]})
        clean_checks.extend(f"[{doc['agent']}] {redact_text(c)[0]}"
                            for c in doc.get("clean_checks", []) if isinstance(c, str))

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

    # Unique ids, deterministic: the first occurrence in the sorted order keeps its id.
    id_renames, used = [], set()
    for f in findings:
        original = f["id"]
        if original in used:
            n = 2
            while f"{original}-{n}" in used:
                n += 1
            f["id"] = f"{original}-{n}"
            id_renames.append({"from": original, "to": f["id"], "file": f.get("file"),
                               "source_agents": f.get("source_agents")})
        used.add(f["id"])

    counts = {s_: sum(1 for f in findings if f["severity"] == s_) for s_ in SEV_LIST}
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
        "id_renames": id_renames,
        "redactions": redactions,
        "warnings": warnings,
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


def find_repo_root(start):
    """Nearest ancestor of start holding a .git entry (directory, or file for a
    worktree), or None."""
    d = os.path.realpath(start)
    while True:
        if os.path.exists(os.path.join(d, ".git")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def check_run_marker(marker_path, cwd):
    """Validate the run marker written in Phase 0. Returns (mtime_ns, errors).

    The marker binds the scratch area to one repository and one point in time.
    Error messages never name the other repository: it may belong to another
    client."""
    try:
        mtime_ns = os.stat(marker_path).st_mtime_ns
        data = json.loads(pathlib.Path(marker_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return None, [f"marqueur de passe absent ou illisible ({marker_path}, "
                      f"{e.__class__.__name__})"]
    if not isinstance(data, dict) or not isinstance(data.get("repo"), str) \
            or not data["repo"].strip():
        return None, [f"marqueur de passe sans champ 'repo' ({marker_path})"]
    here = find_repo_root(cwd)
    if here is None:
        return None, ["consolidation lancee hors d'un repo git : marqueur inverifiable"]
    if os.path.realpath(data["repo"].strip()) != here:
        return None, ["le marqueur de passe designe un autre repo : une autre passe utilise "
                      "/tmp/sweep"]
    return mtime_ns, []


def split_stale(indir, docs, marker_mtime_ns):
    """Keep the agent files written after the run marker; the older ones are
    leftovers of a previous sweep and are reported, never consolidated."""
    fresh, stale = [], []
    for name, doc in docs:
        try:
            mtime_ns = (pathlib.Path(indir) / name).stat().st_mtime_ns
        except OSError:
            mtime_ns = -1
        if mtime_ns < marker_mtime_ns:
            stale.append(f"{name}: anterieur au marqueur de passe, reste d'une passe "
                         f"precedente (ignore)")
        else:
            fresh.append((name, doc))
    return fresh, stale


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

    # Malformed inputs never crash AND surface an error (never read as clean).
    for label, bad in [
        ("non-dict finding", {"agent": "x", "findings": [42], "scans": [], "clean_checks": []}),
        ("null id", {"agent": "x", "findings": [{"id": None, "title": "t", "category": "sast",
                     "severity": "P1", "confidence": "high", "file": "a", "evidence": "e",
                     "impact": "i", "fix_hint": "f", "verified": False, "status": "OPEN"}],
                     "scans": [], "clean_checks": []}),
        ("null findings", {"agent": "x", "findings": None, "scans": [], "clean_checks": []}),
        ("unknown tag", {"agent": "x", "findings": [dict(finding("Z-1", "sast", "P1"),
                        correlation_tags=["bogus-tag"])], "scans": [], "clean_checks": []}),
        ("scalar root", None),
        ("scalar int root", 42),
    ]:
        try:
            r, e = consolidate([(label, bad)])
        except Exception as ex:
            failures.append(f"crash sur '{label}': {ex}")
            continue
        if not e:
            failures.append(f"'{label}' aurait du produire une erreur d'entree")

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

    # One malformed finding does not hide the valid ones of the same agent.
    r, e = consolidate([("mix", doc("api-webhook-hardener", [
        finding("API-010", "api", "P1"),
        {"id": "API-011", "title": "t", "category": "api", "severity": "P9",
         "confidence": "high", "file": "b.py", "evidence": "e", "impact": "i",
         "fix_hint": "f", "verified": False, "status": "OPEN"}]))])
    if [f["id"] for f in r["findings"]] != ["API-010"] or not e:
        failures.append("finding invalide : les findings valides du meme agent sont perdus")

    # Duplicate ids across agents (different files, not merged) become unique.
    r, e = consolidate([
        ("a", doc("sast-triager", [finding("SAST-001", "sast", "P1", file="a.py")])),
        ("b", doc("authz-tenant-reviewer", [finding("SAST-001", "authz", "P2", file="b.py")])),
    ])
    ids = [f["id"] for f in r["findings"]]
    if len(set(ids)) != 2 or not r["id_renames"]:
        failures.append(f"ids dupliques non rendus uniques: {ids}")

    # Secret-shaped literals never reach consolidated.json.
    fake_key = "sk-" + "ant-" + "api03-" + "Z" * 30
    fake_pw = "Hun" + "ter2-" + "Secret!"
    leaky = finding("SECRETS-009", "secret", "P1")
    leaky["evidence"] = f'ANTHROPIC_API_KEY = "{fake_key}" and db_password = "{fake_pw}"'
    leaky["fix_hint"] = "rotate; url was postgresql://admin:" + fake_pw + "@db:5432/app"
    r, e = consolidate([("s", doc("secrets-hunter", [leaky]))])
    dumped = json.dumps(r)
    if fake_key in dumped or fake_pw in dumped:
        failures.append("valeur de secret presente dans la sortie consolidee")
    if len(r["redactions"]) < 3:
        failures.append(f"redactions non tracees ({len(r['redactions'])})")

    # Soft fields are normalized with a warning, the finding is kept.
    soft = finding("RES-001", "resilience", "P2")
    soft["confidence"] = "very"
    soft["verified"] = "yes"
    r, e = consolidate([("r", doc("resilience-reviewer", [soft]))])
    if not r["findings"] or r["findings"][0]["confidence"] != "low" or \
            r["findings"][0]["verified"] is not False or not r["warnings"]:
        failures.append("champs souples non normalises")

    # Run marker: a file left by a previous sweep is never consolidated; a marker
    # that is missing, malformed or names another repository stops everything.
    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        repo, other, agents = base / "repo", base / "other", base / "agents"
        for d in (repo / ".git", repo / "src", other / ".git", agents):
            d.mkdir(parents=True)
        marker = base / "RUN.json"
        marker.write_text(json.dumps({"repo": str(repo), "commit": "x"}), encoding="utf-8")
        m_ns = marker.stat().st_mtime_ns
        for name, agent, delta in (("old.json", "previous-sweep", -10**9),
                                   ("new.json", "this-sweep", 10**9)):
            p = agents / name
            p.write_text(json.dumps(doc(agent, [finding("X-100", "sast", "P1")])),
                         encoding="utf-8")
            os.utime(p, ns=(m_ns + delta, m_ns + delta))
        ns, merrs = check_run_marker(str(marker), str(repo / "src"))
        if merrs or ns is None:
            failures.append(f"marqueur valide refuse: {merrs}")
        else:
            fresh, stale = split_stale(str(agents), load_dir(str(agents)), ns)
            if [n for n, _ in fresh] != ["new.json"] or len(stale) != 1:
                failures.append("fichier anterieur au marqueur de passe consolide")
        if not check_run_marker(str(marker), str(other))[1]:
            failures.append("marqueur d'un autre repo accepte")
        if not check_run_marker(str(base / "absent.json"), str(repo))[1]:
            failures.append("marqueur absent accepte")
        marker.write_text("[]", encoding="utf-8")
        if not check_run_marker(str(marker), str(repo))[1]:
            failures.append("marqueur sans champ repo accepte")

    if failures:
        print("SELF-TEST ECHEC")
        for f in failures:
            print(" -", f)
        return 1
    print("SELF-TEST OK: 3 regles d'escalade + negatifs + clamp + dedup + tri + structure "
          "+ rejet par finding + ids uniques + caviardage des secrets + marqueur de passe.")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="indir", help="dossier des <agent>.json")
    ap.add_argument("--out", dest="outfile", help="chemin de sortie consolidated.json")
    ap.add_argument("--run-marker", dest="run_marker",
                    help="marqueur de passe ecrit en Phase 0 (/tmp/sweep/RUN.json) : les "
                         "fichiers d'agents anterieurs sont rejetes, un marqueur d'un autre "
                         "repo arrete la consolidation")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if not args.indir:
        ap.error("--in requis hors self-test")

    marker_ns = None
    if args.run_marker:
        marker_ns, marker_errors = check_run_marker(args.run_marker, os.getcwd())
        if marker_errors:
            for e in marker_errors:
                print("ARRET:", e)
            print("Rien n'a ete consolide ni ecrit. Arrete la passe : /tmp/sweep doit etre "
                  "vide au depart et ne servir qu'a une passe a la fois (PLAYBOOK).")
            return 2

    docs = load_dir(args.indir)
    stale = []
    if marker_ns is not None:
        docs, stale = split_stale(args.indir, docs, marker_ns)
    # isinstance guard: a scalar-root JSON file (null / 42 / "x") parses fine, so the
    # '__parse_error__' membership test must never run on a non-dict.
    parse_errors = [f"{n}: JSON illisible ({d['__parse_error__']})"
                    for n, d in docs if isinstance(d, dict) and "__parse_error__" in d]
    docs = [(n, d) for n, d in docs if not (isinstance(d, dict) and "__parse_error__" in d)]
    result, errors = consolidate(docs)
    errors = stale + parse_errors + errors
    result["input_errors"] = errors

    out = args.outfile or str(pathlib.Path(args.indir) / "consolidated.json")
    pathlib.Path(out).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"consolidated: {sum(result['counts'].values())} findings "
          f"(P0={result['counts']['P0']} P1={result['counts']['P1']} "
          f"P2={result['counts']['P2']} P3={result['counts']['P3']}), "
          f"{len(result['escalations'])} escalades, ecrit dans {out}")
    if result["redactions"]:
        print(f"CAVIARDAGE: {len(result['redactions'])} valeur(s) de secret retiree(s) des "
              f"findings (voir redactions). Le finding source contenait un secret en clair.")
    if result["id_renames"]:
        print(f"IDS: {len(result['id_renames'])} id(s) dupliques renommes (voir id_renames) ; "
              f"utilise les ids de consolidated.json au GATE A.")
    for w in result["warnings"][:10]:
        print(" ~", w)
    if stale:
        print(f"ARRET: {len(stale)} fichier(s) d'agents anterieur(s) au marqueur de passe, "
              f"ecartes de la consolidation. /tmp/sweep a servi a une autre passe : "
              f"arrete et previens l'humain.")
    if errors:
        print(f"ATTENTION: {len(errors)} erreurs d'entree (voir input_errors):")
        for e in errors[:10]:
            print(" -", e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
