#!/usr/bin/env python3
"""Valide la structure de la flotte : frontmatter des agents, outils par role, hook."""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
READ_ONLY = {
    "recon-inventory", "secrets-hunter", "dependency-auditor", "sast-triager",
    "authz-tenant-reviewer", "api-webhook-hardener", "llm-security-auditor",
    "resilience-reviewer", "infra-reviewer",
}
WRITERS = {"test-builder", "fix-implementer", "report-compiler"}
ALLOWED_MODELS = {"haiku", "sonnet"}
errors = []

agent_files = sorted((ROOT / "agents").glob("*.md"))
names = set()
for f in agent_files:
    text = f.read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    if not m:
        errors.append(f"{f.name}: frontmatter absent")
        continue
    fm = m.group(1)
    fields = dict(
        (k.strip(), v.strip())
        for k, v in (line.split(":", 1) for line in fm.splitlines() if ":" in line)
    )
    name = fields.get("name", "")
    names.add(name)
    if not name or not fields.get("description"):
        errors.append(f"{f.name}: name ou description manquant")
    if fields.get("model") not in ALLOWED_MODELS:
        errors.append(f"{f.name}: model invalide ({fields.get('model')})")
    tools = {t.strip() for t in fields.get("tools", "").split(",") if t.strip()}
    if name in READ_ONLY and ("Write" in tools or "Edit" in tools):
        errors.append(f"{f.name}: agent read-only avec outil d'ecriture")
    if name in WRITERS and not tools:
        errors.append(f"{f.name}: writer sans liste d'outils explicite")

if len(agent_files) != 12:
    errors.append(f"nombre d'agents inattendu: {len(agent_files)} (12 attendus)")
if names != (READ_ONLY | WRITERS):
    errors.append(
        f"ensembles d'agents divergents: manquants={sorted((READ_ONLY | WRITERS) - names)}, "
        f"inattendus={sorted(names - (READ_ONLY | WRITERS))}"
    )
if not (ROOT / "commands" / "security-sweep.md").exists():
    errors.append("commands/security-sweep.md manquant")

hook = ROOT / "hooks" / "block_push.py"
for cmd, should_block in [
    ("git push origin main", True),
    ("git status", False),
    ("gh pr merge 4", True),
    ('git commit -m "fix merge conflict"', False),
    ("git stash pop", False),
    ("git -C /x push", True),
    ("echo $(git push)", True),
    ("gh api repos/o/r/merges -f base=main", True),
    ("git reset --hard HEAD~3", True),
    ("git reset --soft HEAD~1", False),
    ("git rebase main", True),
    ("git clean -fd", True),
    ("git clean -n", False),
    ("git branch -D main", True),
    ("git branch -d merged", False),
    ("git remote set-url origin https://x", True),
    ("git remote -v", False),
    ("gh repo delete x", True),
    ("git commit -m \"reset the counter\"", False),
    ("git pull", True),
    ("git pull --rebase", True),
    ("git restore .", True),
    ("git restore --staged app.py", False),
    ("git stash drop", True),
    ("git stash push", False),
    ("git commit --amend --no-edit", True),
    ("gh api -X DELETE repos/o/r", True),
    ("timeout 300 git push", True),
    ("git branch -df x", True),
    ("git branch -d merged", False),
    ("git.exe push origin main", True),
    ("git fetch & git push", True),
]:
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
    proc = subprocess.run(
        [sys.executable, str(hook)], input=payload, capture_output=True, text=True
    )
    blocked = proc.returncode == 2
    if blocked is not should_block:
        errors.append(f"hook: comportement inattendu pour '{cmd}' (rc={proc.returncode})")

for label, raw in [
    ("stdin non-JSON", "not json"),
    ("tool_input null", json.dumps({"tool_name": "Bash", "tool_input": None})),
]:
    proc = subprocess.run(
        [sys.executable, str(hook)], input=raw, capture_output=True, text=True
    )
    if proc.returncode != 2:
        errors.append(f"hook: anomalie '{label}' non bloquee (rc={proc.returncode})")

# settings.template.json : barriere primaire permissions.deny presente et coherente.
settings = ROOT / "hooks" / "settings.template.json"
try:
    sdata = json.loads(settings.read_text(encoding="utf-8"))
    deny = sdata.get("permissions", {}).get("deny", [])
    required_deny = ["git push", "git merge", "git pull", "git reset --hard",
                     "git restore", "gh pr create", "gh repo create"]
    for r in required_deny:
        if not any(r in d for d in deny):
            errors.append(f"settings.template.json: permissions.deny ne couvre pas '{r}'")
    if not sdata.get("hooks", {}).get("PreToolUse"):
        errors.append("settings.template.json: hook PreToolUse absent")
except Exception as e:
    errors.append(f"settings.template.json illisible: {e}")

# install.sh doit reellement deployer les scripts d'execution et ecrire FLEET_VERSION
# (verifications non vacantes: on cherche l'action, pas une mention en commentaire).
install_sh = (ROOT / "install.sh").read_text(encoding="utf-8")
if 'install_file "$SRC/scripts/$s"' not in install_sh:
    errors.append("install.sh ne copie pas les scripts d'execution (install_file scripts/$s absent)")
for runtime in ["consolidate_findings.py", "generate_asvs_matrix.py", "preflight_tooling.py"]:
    if runtime not in install_sh:
        errors.append(f"install.sh ne liste pas scripts/{runtime} au deploiement")
if 'install_file "$SRC/PLAYBOOK.md"' not in install_sh:
    errors.append("install.sh ne deploie pas PLAYBOOK.md (reference par les agents)")
if '> "$CLAUDE_DIR/FLEET_VERSION"' not in install_sh or "fleet_commit:" not in install_sh:
    errors.append("install.sh n'ecrit pas reellement FLEET_VERSION")

# Scripts attendus presents.
for script in ["consolidate_findings.py", "generate_asvs_matrix.py",
               "preflight_tooling.py", "measure_recall.py"]:
    if not (ROOT / "scripts" / script).exists():
        errors.append(f"scripts/{script} manquant")

# Self-test de la consolidation (regles d'escalade testables).
proc = subprocess.run(
    [sys.executable, str(ROOT / "scripts" / "consolidate_findings.py"), "--self-test"],
    capture_output=True, text=True
)
if proc.returncode != 0:
    errors.append(f"consolidate_findings --self-test echoue: {proc.stdout.strip()} {proc.stderr.strip()}")

if errors:
    print("ECHEC VALIDATION")
    for e in errors:
        print(" -", e)
    sys.exit(1)
print(f"OK: {len(agent_files)} agents valides, commande presente, hook (push+destructifs) fonctionnel, "
      f"permissions.deny et scripts verifies, consolidation self-test OK.")
