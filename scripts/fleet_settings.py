#!/usr/bin/env python3
"""Check or merge a product repo's .claude/settings.json against the fleet template.

Used by install.sh (fleet repo only, not installed into product repos). JSON is
parsed, never grepped: a settings file that mentions "git push" in an allow list
must not pass for one that denies it.

  python3 fleet_settings.py check <settings.json> [--template T]
      exit 0 = every fleet control present, 4 = incomplete (missing items listed),
      5 = unreadable or not a JSON object, 3 = file absent.
  python3 fleet_settings.py merge <settings.json> [--template T]
      adds the missing deny entries, env values, bypass lock and hook; keeps every
      other key; writes a timestamped backup first.
  python3 fleet_settings.py --self-test
"""
import argparse
import copy
import json
import pathlib
import shutil
import sys
import tempfile
import time

DEFAULT_TEMPLATE = pathlib.Path(__file__).resolve().parent.parent / "hooks" / "settings.template.json"
HOOK_MARKER = "block_push.py"


def load(path):
    data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("racine non-objet")
    return data


def fleet_hook_entries(settings):
    out = []
    for entry in (settings.get("hooks", {}) or {}).get("PreToolUse", []) or []:
        if not isinstance(entry, dict):
            continue
        for h in entry.get("hooks", []) or []:
            if isinstance(h, dict) and HOOK_MARKER in str(h.get("command", "")):
                out.append((entry, h))
    return out


def missing_items(settings, template):
    missing = []
    perms = settings.get("permissions") if isinstance(settings.get("permissions"), dict) else {}
    deny = perms.get("deny") if isinstance(perms.get("deny"), list) else []
    for rule in template["permissions"]["deny"]:
        if rule not in deny:
            missing.append(f"permissions.deny: {rule}")
    if perms.get("disableBypassPermissionsMode") != "disable":
        missing.append("permissions.disableBypassPermissionsMode: disable")
    env = settings.get("env") if isinstance(settings.get("env"), dict) else {}
    for k, v in template.get("env", {}).items():
        if env.get(k) != v:
            missing.append(f"env.{k}={v}")
    tmpl_entry = template["hooks"]["PreToolUse"][0]
    wanted = set(tmpl_entry["matcher"].split("|"))
    found = fleet_hook_entries(settings)
    if not found:
        missing.append("hooks.PreToolUse: hook block_push absent")
    else:
        covered = set()
        for entry, h in found:
            covered |= set(str(entry.get("matcher", "")).split("|"))
            if "CLAUDE_PROJECT_DIR" not in str(h.get("command", "")):
                missing.append("hooks.PreToolUse: commande sans ${CLAUDE_PROJECT_DIR} "
                               "(le hook casse si le repertoire courant change)")
        for tool in sorted(wanted - covered):
            missing.append(f"hooks.PreToolUse: matcher sans {tool}")
    return missing


def merge(settings, template):
    out = copy.deepcopy(settings)
    perms = out.setdefault("permissions", {})
    if not isinstance(perms, dict):
        raise ValueError("permissions n'est pas un objet")
    deny = perms.setdefault("deny", [])
    if not isinstance(deny, list):
        raise ValueError("permissions.deny n'est pas une liste")
    for rule in template["permissions"]["deny"]:
        if rule not in deny:
            deny.append(rule)
    perms["disableBypassPermissionsMode"] = "disable"
    env = out.setdefault("env", {})
    if not isinstance(env, dict):
        raise ValueError("env n'est pas un objet")
    conflicts = [k for k, v in template.get("env", {}).items() if k in env and env[k] != v]
    env.update(template.get("env", {}))
    hooks = out.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    # Replace any older fleet hook entry by the template one (new matcher, new path).
    pre[:] = [e for e in pre if not (isinstance(e, dict) and any(
        HOOK_MARKER in str(h.get("command", "")) for h in e.get("hooks", []) or []
        if isinstance(h, dict)))]
    pre.append(copy.deepcopy(template["hooks"]["PreToolUse"][0]))
    return out, conflicts


def cmd_check(path, template):
    p = pathlib.Path(path)
    if not p.exists():
        print(f"ABSENT: {p}")
        return 3
    try:
        settings = load(p)
    except Exception as e:
        print(f"ILLISIBLE: {p} ({e})")
        return 5
    miss = missing_items(settings, template)
    if miss:
        print(f"INCOMPLET: {p} ({len(miss)} controles manquants)")
        for m in miss[:200]:
            print("  -", m)
        return 4
    print(f"OK: {p} contient tous les controles de la flotte.")
    return 0


def cmd_merge(path, template):
    p = pathlib.Path(path)
    settings = load(p) if p.exists() else {}
    merged, conflicts = merge(settings, template)
    if p.exists():
        backup = p.with_name(p.name + ".bak-" + time.strftime("%Y%m%dT%H%M%S"))
        shutil.copy2(p, backup)
        print(f"Sauvegarde: {backup}")
    p.write_text(json.dumps(merged, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for k in conflicts:
        print(f"ATTENTION: env.{k} avait une autre valeur, remplacee par celle de la flotte.")
    rest = missing_items(merged, template)
    if rest:
        print("ECHEC: controles toujours manquants apres fusion:", rest)
        return 4
    print(f"Fusion faite: {p}")
    return 0


def self_test():
    template = load(DEFAULT_TEMPLATE)
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        trap = d / "trap.json"
        trap.write_text(json.dumps({"permissions": {"allow": ["Bash(git push:*)"]}}))
        if cmd_check(trap, template) != 4:
            failures.append("un allow mentionnant git push passe pour une barriere")
        full = d / "full.json"
        full.write_text(json.dumps(template))
        if cmd_check(full, template) != 0:
            failures.append("le gabarit lui-meme n'est pas reconnu complet")
        legacy = d / "legacy.json"
        legacy.write_text(json.dumps({
            "model": "x", "permissions": {"allow": ["Bash(ls *)"], "deny": ["Bash(git push:*)"]},
            "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": "python3 .claude/hooks/block_push.py"}]}]}}))
        if cmd_check(legacy, template) != 4:
            failures.append("une installation v0.3 passe pour complete")
        if cmd_merge(legacy, template) != 0:
            failures.append("fusion en echec")
        merged = load(legacy)
        if merged.get("model") != "x" or "Bash(ls *)" not in merged["permissions"]["allow"]:
            failures.append("la fusion a perdu des cles existantes")
        if len(fleet_hook_entries(merged)) != 1:
            failures.append("la fusion duplique ou perd le hook")
        if not list(d.glob("legacy.json.bak-*")):
            failures.append("pas de sauvegarde avant fusion")
        bad = d / "bad.json"
        bad.write_text("[1, 2]")
        if cmd_check(bad, template) != 5:
            failures.append("racine non-objet non detectee")
        if cmd_check(d / "absent.json", template) != 3:
            failures.append("fichier absent non detecte")
    if failures:
        print("SELF-TEST ECHEC")
        for f in failures:
            print(" -", f)
        return 1
    print("SELF-TEST OK: piege allow detecte, gabarit complet, v0.3 detectee incomplete, "
          "fusion sans perte avec sauvegarde.")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", nargs="?", choices=["check", "merge"])
    ap.add_argument("settings", nargs="?")
    ap.add_argument("--template", default=str(DEFAULT_TEMPLATE))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if not args.action or not args.settings:
        ap.error("action et chemin requis")
    template = load(args.template)
    if args.action == "check":
        return cmd_check(args.settings, template)
    return cmd_merge(args.settings, template)


if __name__ == "__main__":
    sys.exit(main())
