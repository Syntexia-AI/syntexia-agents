#!/usr/bin/env python3
"""Valide la structure de la flotte : frontmatter des agents, outils par role, regles
communes des prompts, hook (matrice complete), settings, installateur, scripts."""
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
ALLOWED_MODELS = {"haiku", "sonnet", "opus", "fable", "inherit"}
BASH_AGENTS_WITH_REFUSAL_RULE = {"recon-inventory", "secrets-hunter", "dependency-auditor",
                                 "sast-triager", "test-builder", "fix-implementer"}
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
    if "Untrusted content rule" not in text:
        errors.append(f"{f.name}: regle de contenu non fiable absente")
    if "Output hygiene rule" not in text:
        errors.append(f"{f.name}: regle d'hygiene de sortie absente")
    if name in BASH_AGENTS_WITH_REFUSAL_RULE and "Refusal rule" not in text:
        errors.append(f"{f.name}: regle de refus absente")
    if "2026 wave" in text:
        errors.append(f"{f.name}: reference d'incident non sourcee (utiliser CVE-2025-30066)")

secrets_text = (ROOT / "agents" / "secrets-hunter.md").read_text(encoding="utf-8")
for needle in ("redacted_secret_scan.py", "--no-update", "--no-verification"):
    if needle not in secrets_text:
        errors.append(f"secrets-hunter.md: '{needle}' absent")
recon_text = (ROOT / "agents" / "recon-inventory.md").read_text(encoding="utf-8")
for needle in ("FLEET_DENY_CANARY", "FLEET_HOOK_CANARY"):
    if needle not in recon_text:
        errors.append(f"recon-inventory.md: canari {needle} absent")

if len(agent_files) != 12:
    errors.append(f"nombre d'agents inattendu: {len(agent_files)} (12 attendus)")
if names != (READ_ONLY | WRITERS):
    errors.append(
        f"ensembles d'agents divergents: manquants={sorted((READ_ONLY | WRITERS) - names)}, "
        f"inattendus={sorted(names - (READ_ONLY | WRITERS))}"
    )
sweep = ROOT / "commands" / "security-sweep.md"
if not sweep.exists():
    errors.append("commands/security-sweep.md manquant")
else:
    sweep_text = sweep.read_text(encoding="utf-8")
    for needle in ("FLEET_DENY_CANARY", "FLEET_HOOK_CANARY", "GIT_CONFIG_GLOBAL",
                   "GO FIXES ALL", "GO RAPPORT", "id_renames", "redactions",
                   # Isolation des passes : zone de travail vide, marqueur, consolidation liee.
                   "ls -A /tmp/sweep", "/tmp/sweep/RUN.json", "--run-marker /tmp/sweep/RUN.json",
                   "git ls-files --others"):
        if needle not in sweep_text:
            errors.append(f"security-sweep.md: '{needle}' absent")

# Hook : matrice complete d'attaques et de commandes legitimes.
proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "test_hook.py")],
                      capture_output=True, text=True)
if proc.returncode != 0:
    errors.append("hook: test_hook.py en echec:\n" + proc.stdout.strip()[-3000:])

# settings.template.json : barriere primaire, environnement, verrou bypass, hook.
settings = ROOT / "hooks" / "settings.template.json"
try:
    sdata = json.loads(settings.read_text(encoding="utf-8"))
    deny = sdata.get("permissions", {}).get("deny", [])
    required_deny = [
        "Bash(echo FLEET_DENY_CANARY*)", "Bash(git push *)", "Bash(git * push *)",
        "Bash(git -c *)", "Bash(git * alias.*)", "Bash(git config *)", "Bash(git merge *)",
        "Bash(git pull *)", "Bash(git fetch *)", "Bash(git clone *)", "Bash(git send-pack *)",
        "Bash(git reset --hard *)", "Bash(git restore *)", "Bash(gh *)", "Bash(sudo *)",
        "Bash(curl *)", "Bash(wget *)", "Bash(ssh *)", "Bash(aws *)", "Bash(docker *)",
        "Bash(systemctl *)", "Bash(tmux *)", "Bash(npx *)", "Bash(pip install *)",
        "Bash(npm install *)", "Bash(printenv *)", "Bash(rm -rf *)", "Bash(dd *)",
        "Read(.env)", "Read(.env.*)", "Read(~/.ssh/**)", "Edit(.claude/**)",
        "Write(.claude/**)", "WebFetch", "WebSearch",
    ]
    for r in required_deny:
        if r not in deny:
            errors.append(f"settings.template.json: permissions.deny ne contient pas '{r}'")
    if sdata.get("permissions", {}).get("disableBypassPermissionsMode") != "disable":
        errors.append("settings.template.json: mode bypass non desactive")
    env = sdata.get("env", {})
    for k, v in {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
                 "GIT_SSH_COMMAND": "false", "GIT_TERMINAL_PROMPT": "0"}.items():
        if env.get(k) != v:
            errors.append(f"settings.template.json: env.{k} != {v}")
    pre = sdata.get("hooks", {}).get("PreToolUse") or []
    if not pre:
        errors.append("settings.template.json: hook PreToolUse absent")
    else:
        matcher = set(pre[0].get("matcher", "").split("|"))
        for tool in ("Bash", "Read", "Grep", "Edit", "Write"):
            if tool not in matcher:
                errors.append(f"settings.template.json: matcher du hook sans {tool}")
        cmd = pre[0].get("hooks", [{}])[0].get("command", "")
        if "CLAUDE_PROJECT_DIR" not in cmd or "exit 2" not in cmd:
            errors.append("settings.template.json: commande du hook sans CLAUDE_PROJECT_DIR "
                          "ou sans blocage par defaut")
except Exception as e:
    errors.append(f"settings.template.json illisible: {e}")

try:
    sandbox = json.loads((ROOT / "hooks" / "settings.sandbox.json").read_text(encoding="utf-8"))
    sb = sandbox.get("sandbox", {})
    if not (sb.get("enabled") is True and sb.get("failIfUnavailable") is True
            and sb.get("allowUnsandboxedCommands") is False
            and sb.get("network", {}).get("allowedDomains")):
        errors.append("settings.sandbox.json: profil incomplet (enabled, failIfUnavailable, "
                      "allowUnsandboxedCommands=false, allowedDomains)")
except Exception as e:
    errors.append(f"settings.sandbox.json illisible: {e}")

# install.sh : actions reelles (pas des mentions en commentaire).
install_sh = (ROOT / "install.sh").read_text(encoding="utf-8")
checks = {
    'install_file "$SRC/scripts/$s"': "copie des scripts d'execution",
    'install_file "$SRC/PLAYBOOK.md"': "deploiement du PLAYBOOK",
    'install_file "$SRC/hooks/settings.sandbox.json"': "deploiement du profil bac a sable",
    '> "$CLAUDE_DIR/FLEET_VERSION"': "ecriture de FLEET_VERSION",
    "fleet_commit:": "commit de flotte dans FLEET_VERSION",
    'fleet_settings.py" check': "controle JSON des settings",
    "os.path.commonpath": "validation des chemins du manifeste",
    "--allow-live-checkout": "garde copie de travail vivante",
}
for needle, label in checks.items():
    if needle not in install_sh:
        errors.append(f"install.sh: {label} absent ({needle})")
if "grep -q 'Bash(git push'" in install_sh:
    errors.append("install.sh: controle par grep des settings (contournable par un allow)")
for runtime in ["consolidate_findings.py", "generate_asvs_matrix.py", "preflight_tooling.py",
                "redacted_secret_scan.py"]:
    if runtime not in install_sh:
        errors.append(f"install.sh ne liste pas scripts/{runtime} au deploiement")

# Scripts attendus presents.
for script in ["consolidate_findings.py", "generate_asvs_matrix.py", "preflight_tooling.py",
               "measure_recall.py", "redacted_secret_scan.py", "fleet_settings.py",
               "test_hook.py", "test_install.sh", "prepare_sweep_clone.sh",
               "make_fixture_repo.sh", "hygiene_check.py"]:
    if not (ROOT / "scripts" / script).exists():
        errors.append(f"scripts/{script} manquant")

# Auto-tests des scripts deterministes.
for script in ["consolidate_findings.py", "redacted_secret_scan.py", "fleet_settings.py"]:
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / script), "--self-test"],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        errors.append(f"{script} --self-test echoue: {proc.stdout.strip()[-800:]} "
                      f"{proc.stderr.strip()[-400:]}")

if errors:
    print("ECHEC VALIDATION")
    for e in errors:
        print(" -", e)
    sys.exit(1)
print(f"OK: {len(agent_files)} agents valides (regles communes presentes), commande et "
      f"canaris presents, hook (matrice complete) fonctionnel, settings et profil bac a sable "
      f"verifies, installateur durci, auto-tests OK.")
