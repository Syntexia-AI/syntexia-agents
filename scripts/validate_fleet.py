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

missing = (READ_ONLY | WRITERS) - names
if missing:
    errors.append(f"agents manquants: {sorted(missing)}")
if not (ROOT / "commands" / "security-sweep.md").exists():
    errors.append("commands/security-sweep.md manquant")

hook = ROOT / "hooks" / "block_push.py"
for cmd, should_block in [("git push origin main", True), ("git status", False), ("gh pr merge 4", True)]:
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
    proc = subprocess.run(
        [sys.executable, str(hook)], input=payload, capture_output=True, text=True
    )
    blocked = proc.returncode == 2
    if blocked is not should_block:
        errors.append(f"hook: comportement inattendu pour '{cmd}' (rc={proc.returncode})")

if errors:
    print("ECHEC VALIDATION")
    for e in errors:
        print(" -", e)
    sys.exit(1)
print(f"OK: {len(agent_files)} agents valides, commande presente, hook fonctionnel.")
