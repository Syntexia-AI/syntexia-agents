#!/usr/bin/env python3
"""Redacted secret scan of a git repository (tracked files, optionally history).

Deterministic complement to gitleaks and trufflehog for the secrets-hunter agent,
and its fallback when they are missing. It NEVER prints or writes a secret value.
Each hit is reported as: file, line, rule, variable name when there is one, value
length, Shannon entropy, a dummy-likelihood flag and, only for key formats whose
prefix is public (sk-ant-, AKIA, ghp_...), that prefix. Read-only, no network.

Why: a grep on secret patterns prints the matching lines, so the secrets land in
the tool output, the session transcript and sometimes the report. This script is
the only sanctioned way for an agent to look for secret values.

Usage:
  python3 redacted_secret_scan.py [--root .] [--out /tmp/sweep/redacted-secrets.json]
                                  [--history] [--max-commits 2000]
  python3 redacted_secret_scan.py --self-test
"""
import argparse
import base64
import json
import math
import os
import pathlib
import re
import subprocess
import sys
import tempfile

MAX_FILE_BYTES = 2_000_000
SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults", ".schema",
                     ".tpl")
KEY_FILE_EXTENSIONS = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk")
PRIVATE_KEY_NAMES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
DUMMY_MARKERS = ("example", "fixture", "dummy", "changeme", "change_me", "placeholder",
                 "your_", "your-", "yourkey", "xxx", "fake", "sample", "redacted",
                 "notreal", "not_real", "todo", "<", ">", "${", "{{", "****", "....")

# (rule, regex, value group or 0 for the whole match, public prefix length)
RULES = [
    ("private-key-block", re.compile(r"-----BEGIN ([A-Z ]*)PRIVATE KEY-----"), None, 0),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), 0, 7),
    ("openai-key", re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}"), 0, 3),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0, 4),
    ("aws-secret-key", re.compile(
        r"(?i)aws_?secret_?access_?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})\b"), 1, 0),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})"),
     0, 4),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"), 0, 6),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), 0, 5),
    ("stripe-key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}"), 0, 8),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}"), 0, 4),
    ("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"), 0, 3),
    ("resend-key", re.compile(r"\bre_[A-Za-z0-9_]{20,}"), 0, 3),
    ("telephony-api-key", re.compile(r"\bKEY[0-9A-Za-z_]{24,}\b"), 0, 3),
    ("messaging-bot-token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"), 0, 0),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}"),
     0, 3),
    ("inline-credential-url", re.compile(
        r"\b[a-z][a-z0-9+.-]*://([^\s:/@'\"]+):([^\s@'\"/]+)@[^\s/'\"]+"), 2, 0),
    ("secret-assignment", re.compile(
        r"(?i)\b([A-Za-z0-9_.-]*(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|apikey"
        r"|private[_-]?key|client[_-]?secret|access[_-]?key|auth[_-]?key|signing[_-]?key)"
        r"[A-Za-z0-9_.-]*)['\"]?\s*[:=]>?\s*(['\"])([^'\"\n]{8,})\2"), 3, 0),
]
CRED_TABLE_START = re.compile(
    r"(?i)^\s*(?:const |let |var |export )?([A-Za-z_][A-Za-z0-9_]*(?:users|accounts|pilots"
    r"|logins|credentials|passwords|passwds)[A-Za-z0-9_]*)\s*(?::[^=]*)?=\s*[\[{(]")
QUOTED_PAIR = re.compile(r"(['\"])[^'\"\n]{1,80}\1\s*[:,]\s*(['\"])[^'\"\n]{4,}\2")


def entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


PLACEHOLDER_WORDS = {"pass", "passwd", "password", "secret", "user", "username", "admin",
                     "root", "test", "token", "changeme", "xxx", "key", "apikey", "none",
                     "null", "dev", "local"}


def looks_dummy(value):
    low = value.lower()
    if low in PLACEHOLDER_WORDS or len(value) < 6:
        return True
    if any(m in low for m in DUMMY_MARKERS):
        return True
    return len(value) >= 8 and entropy(value) < 2.5


def jwt_role(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload.encode()).decode("utf-8", "replace"))
        role = data.get("role") if isinstance(data, dict) else None
        return role if isinstance(role, str) else None
    except Exception:
        return None


def is_secret_file_name(path):
    base = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if base.startswith(".env") and not base.endswith(SAFE_ENV_SUFFIXES):
        return "tracked-env-file"
    if base in (".envrc", ".git-credentials", ".netrc", ".pgpass", ".npmrc", ".pypirc"):
        return "tracked-credential-file"
    if base.endswith(KEY_FILE_EXTENSIONS) or (base.startswith(PRIVATE_KEY_NAMES)
                                               and not base.endswith(".pub")):
        return "tracked-key-file"
    return None


def scan_line(line):
    """Yield redacted hit dicts for one line of text. Never returns a value."""
    seen_spans = []
    for rule, rx, group, prefix_len in RULES:
        for m in rx.finditer(line):
            span = m.span()
            if any(s[0] <= span[0] < s[1] for s in seen_spans):
                continue
            seen_spans.append(span)
            hit = {"rule": rule}
            if group is None:
                hit.update(value_len=None, entropy=None, looks_dummy=False)
                hit["key_type"] = (m.group(1) or "").strip() or "generic"
                yield hit
                continue
            value = m.group(group)
            if rule == "telephony-api-key" and (entropy(value) < 3.5 or
                                                not re.search(r"\d", value)):
                continue
            hit["value_len"] = len(value)
            hit["entropy"] = round(entropy(value), 2)
            hit["looks_dummy"] = looks_dummy(value)
            if prefix_len:
                hit["public_prefix"] = value[:prefix_len]
            if rule == "secret-assignment":
                hit["variable"] = m.group(1)[:80]
                if value.startswith(("$", "%(", "{", "<")) or "os.environ" in value or \
                        "process.env" in value or "getenv" in value:
                    continue
            if rule == "inline-credential-url":
                hit["user_len"] = len(m.group(1))
            if rule == "jwt":
                role = jwt_role(value)
                if role:
                    hit["jwt_role"] = role
                if role == "service_role":
                    hit["rule"] = "jwt-service-role"
            yield hit


def tracked_files(root):
    out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True,
                         check=True).stdout
    return [p for p in out.decode("utf-8", "replace").split("\0") if p]


def scan_tree(root):
    hits, secret_files = [], []
    skipped = {"binary": 0, "too_large": 0, "unreadable": 0}
    files = tracked_files(root)
    for rel in files:
        kind = is_secret_file_name(rel)
        if kind:
            secret_files.append({"file": rel, "rule": kind})
        path = pathlib.Path(root) / rel
        try:
            if path.is_symlink() or not path.is_file():
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                skipped["too_large"] += 1
                continue
            data = path.read_bytes()
        except OSError:
            skipped["unreadable"] += 1
            continue
        if b"\0" in data[:8192]:
            skipped["binary"] += 1
            continue
        lines = data.decode("utf-8", "replace").split("\n")
        table = None
        for n, line in enumerate(lines, 1):
            for hit in scan_line(line):
                hit.update(file=rel, line=n)
                hits.append(hit)
            if table is None:
                m = CRED_TABLE_START.match(line)
                if m:
                    table = {"variable": m.group(1)[:80], "line": n, "pairs": 0, "depth": 0}
            if table is not None:
                table["pairs"] += len(QUOTED_PAIR.findall(line))
                table["depth"] += line.count("{") + line.count("[") + line.count("(")
                table["depth"] -= line.count("}") + line.count("]") + line.count(")")
                if table["depth"] <= 0 or n - table["line"] > 80:
                    if table["pairs"]:
                        hits.append({"rule": "credential-table", "file": rel,
                                     "line": table["line"], "variable": table["variable"],
                                     "quoted_pairs": table["pairs"], "value_len": None,
                                     "entropy": None, "looks_dummy": False})
                    table = None
    return hits, secret_files, skipped, len(files)


def scan_history(root, max_commits):
    proc = subprocess.Popen(
        ["git", "-C", str(root), "log", "--all", "-p", "--no-color", "--unified=0",
         "--no-ext-diff", "--format=commit %H", "-n", str(max_commits)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    hits, commit, current = [], None, None
    for raw in proc.stdout:
        line = raw.decode("utf-8", "replace").rstrip("\n")
        if line.startswith("commit "):
            commit = line[7:47]
            continue
        if line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else line[4:]
            continue
        if line.startswith("+") and not line.startswith("+++") and current:
            for hit in scan_line(line[1:]):
                hit.update(file=current, commit=commit[:12] if commit else None,
                           history=True, line=None)
                hits.append(hit)
    proc.wait()
    dedup, seen = [], set()
    for h in hits:
        key = (h["file"], h["rule"], h.get("value_len"), h.get("public_prefix"))
        if key not in seen:
            seen.add(key)
            dedup.append(h)
    return dedup


def run(root, out, history, max_commits):
    hits, secret_files, skipped, nfiles = scan_tree(root)
    hist = scan_history(root, max_commits) if history else []
    report = {"scanner": "redacted_secret_scan", "version": 1, "root": str(root),
              "files_scanned": nfiles, "skipped": skipped, "tree_hits": hits,
              "history_hits": hist, "history_scanned": history,
              "tracked_secret_files": secret_files,
              "note": "Aucune valeur de secret n'est jamais emise par ce scanner."}
    if out:
        p = pathlib.Path(out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        os.chmod(p, 0o600)
    by_rule = {}
    for h in hits + hist:
        by_rule[h["rule"]] = by_rule.get(h["rule"], 0) + 1
    print(f"redacted_secret_scan: {nfiles} fichiers suivis, {len(hits)} occurrences dans "
          f"l'arbre, {len(hist)} dans l'historique, {len(secret_files)} fichiers secrets "
          f"suivis." + (f" Rapport: {out}" if out else ""))
    for rule, count in sorted(by_rule.items(), key=lambda x: -x[1]):
        print(f"  {rule}: {count}")
    for f in secret_files:
        print(f"  FICHIER SUIVI {f['rule']}: {f['file']}")
    for h in (hits + hist)[:40]:
        loc = f"{h['file']}:{h['line']}" if h.get("line") else f"{h['file']}@{h.get('commit')}"
        extra = " ".join(f"{k}={h[k]}" for k in ("variable", "public_prefix", "value_len",
                                                 "entropy", "looks_dummy", "jwt_role",
                                                 "quoted_pairs") if h.get(k) is not None)
        print(f"  - {h['rule']} {loc} {extra}")
    return report


def self_test():
    failures = []
    # Fake secrets are assembled at run time so that no secret-shaped literal is
    # ever stored in the fleet repository.
    fake = {
        "anthropic": "sk-" + "ant-" + "api03-" + "Q" * 6 + "7" * 30,
        "aws": "AK" + "IA" + "Z" * 8 + "4" * 8,
        "github": "gh" + "p_" + "aB3" * 13,
        "password": "S3cr" + "et-Pass" + "w0rd!",
        "url_pass": "pa" + "ss" + "9X2kq",
    }
    sr = "eyJhbGciOiJIUzI1NiJ9"
    payload = base64.urlsafe_b64encode(json.dumps({"role": "service_role"}).encode()) \
        .decode().rstrip("=")
    fake["jwt"] = sr + "." + payload + "." + "c2lnbmF0dXJlLXRlc3Q"
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp) / "repo"
        root.mkdir()
        (root / "config.py").write_text(
            f'ANTHROPIC_API_KEY = "{fake["anthropic"]}"\n'
            f'AWS_ACCESS_KEY_ID = "{fake["aws"]}"\n'
            f'GH = "{fake["github"]}"\n'
            f'db_password = "{fake["password"]}"\n'
            'DATABASE_URL = "' + "postgresql" + "://" + "admin:" + fake["url_pass"]
            + "@db.internal:5432/app" + '"\n'
            f'SUPABASE_KEY = "{fake["jwt"]}"\n'
            'api_key = os.environ["API_KEY"]\n'
            'example_token = "your-token-here-xxxx"\n'
            'LOCAL_USERS = {\n    "alice": "alice-pass-1",\n    "bob": "bob-pass-22",\n}\n')
        (root / ".env").write_text("X=1\n")
        (root / ".env.example").write_text("X=\n")
        env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
        for cmd in (["git", "init", "-q"], ["git", "add", "-A"],
                    ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                     "commit", "-q", "-m", "t"]):
            subprocess.run(cmd, cwd=root, check=True, env=env)
        out = pathlib.Path(tmp) / "report.json"
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run(root, str(out), history=True, max_commits=50)
        text = out.read_text() + buf.getvalue()
        for name, value in fake.items():
            if value in text or (len(value) >= 16 and value[6:-2] in text):
                failures.append(f"valeur {name} presente dans la sortie")
        report = json.loads(out.read_text())
        rules = {h["rule"] for h in report["tree_hits"]}
        for expected in ("anthropic-key", "aws-access-key-id", "github-token",
                         "secret-assignment", "inline-credential-url", "jwt-service-role",
                         "credential-table"):
            if expected not in rules:
                failures.append(f"regle {expected} non detectee")
        dummy = [h for h in report["tree_hits"] if h.get("variable") == "example_token"]
        if not dummy or not dummy[0]["looks_dummy"]:
            failures.append("valeur factice non reconnue comme telle")
        if any(h.get("variable") == "api_key" for h in report["tree_hits"]):
            failures.append("lecture d'environnement prise pour un secret")
        files = {f["file"] for f in report["tracked_secret_files"]}
        if ".env" not in files or ".env.example" in files:
            failures.append(f"fichiers secrets suivis incorrects: {files}")
        if not report["history_hits"]:
            failures.append("historique non scanne")
        if oct(out.stat().st_mode & 0o777) != "0o600":
            failures.append("rapport non restreint en 600")
    if failures:
        print("SELF-TEST ECHEC")
        for f in failures:
            print(" -", f)
        return 1
    print("SELF-TEST OK: detections par famille, aucune valeur emise, factices reconnus, "
          "historique, fichiers suivis, rapport en 600.")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default="/tmp/sweep/redacted-secrets.json")
    ap.add_argument("--history", action="store_true")
    ap.add_argument("--max-commits", type=int, default=2000)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    run(pathlib.Path(args.root).resolve(), args.out, args.history, args.max_commits)
    return 0


if __name__ == "__main__":
    sys.exit(main())
