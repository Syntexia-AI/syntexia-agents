#!/usr/bin/env python3
"""PreToolUse hook: defense-in-depth guard against autonomous state-changing and
destructive git/gh commands. Fails CLOSED on any anomaly.

This is NOT the primary barrier. The primary barrier is permissions.deny in
.claude/settings.json, enforced by the harness. This hook parses a command line
and cannot see a push hidden in a shell script, an xargs-fed git call, or a
shell alias. See PLAYBOOK.md section 8."""
import json
import re
import shlex
import sys

WRAPPERS = {"env", "command", "nohup", "time", "exec", "sudo", "xargs"}
GIT_OPTS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--exec-path", "--namespace"}
# git subcommand -> predicate over the remaining lowercased tokens; True == block.
BLOCKED_GIT = {
    "push": lambda a: True,
    "merge": lambda a: True,
    "reset": lambda a: "--hard" in a,
    "rebase": lambda a: True,
    "clean": lambda a: any(t.startswith("-") and "f" in t for t in a),
    "update-ref": lambda a: "-d" in a,
    "checkout": lambda a: any(t in ("-f", "--force") for t in a),
    "switch": lambda a: any(t in ("-f", "--force", "--discard-changes") for t in a),
    "branch": lambda a: any(t in ("-D",) for t in a)
    or ("--delete" in a and any(t in ("-f", "--force") for t in a)),
    "remote": lambda a: bool(a) and a[0].lower() in {"set-url", "remove", "rm", "rename"},
    "filter-branch": lambda a: True,
    "filter-repo": lambda a: True,
}
BLOCK_MSG = ("Bloque par la flotte syntexia-agents : push, merge, reecriture ou destruction "
             "d'historique et creation de PR/repo sont des actions humaines. Laisse la branche "
             "locale en l'etat et rends la main.")

def deny(msg=BLOCK_MSG):
    sys.stderr.write(msg)
    return 2

def git_subcommand(tokens):
    """Return (subcommand_lowercased, args_in_original_case) skipping git's own
    global options. Args keep their case because git flags are case-sensitive:
    -D (force delete) must not collapse onto -d (delete merged)."""
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in GIT_OPTS_WITH_VALUE:
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        return t.lower(), tokens[i + 1:]
    return "", []

def segment_blocked(seg):
    try:
        tokens = shlex.split(seg, posix=True)
    except ValueError:
        return True
    while tokens and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]) or tokens[0].lower() in WRAPPERS):
        tokens = tokens[1:]
    if not tokens:
        return False
    head = tokens[0].lower().rsplit("/", 1)[-1]
    if head == "git":
        sub, args = git_subcommand(tokens[1:])
        predicate = BLOCKED_GIT.get(sub)
        return bool(predicate and predicate(args))
    rest = [t.lower() for t in tokens[1:]]
    if head == "gh":
        if len(rest) >= 2 and rest[0] == "pr" and rest[1] in {"create", "merge"}:
            return True
        if len(rest) >= 2 and rest[0] == "repo" and rest[1] in {"create", "delete"}:
            return True
        if rest and rest[0] == "api" and any("/merges" in t or re.search(r"/pulls/\d+/merge$", t) for t in rest):
            return True
    return False

def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return deny("Hook block_push : entree illisible, blocage par defaut.")
    tool = payload.get("tool_name")
    if tool is not None and tool != "Bash":
        return 0
    ti = payload.get("tool_input")
    command = ti.get("command") if isinstance(ti, dict) else None
    if not isinstance(command, str):
        return deny("Hook block_push : commande absente ou non textuelle, blocage par defaut.")
    if re.search(r"`|\$\(|\b(ba)?sh\s+-c\b", command) and \
       re.search(r"\b(push|merge|reset|rebase|clean|filter-branch|filter-repo|set-url)\b"
                 r"|/merges|pr\s+(create|merge)|repo\s+(create|delete)", command, re.I):
        return deny("Hook block_push : construction shell imbriquee avec mot-cle sensible, "
                    "blocage par defaut. Reformule sans sous-shell.")
    for seg in re.split(r"(?:&&|\|\||;|\||\n)", command):
        if seg.strip() and segment_blocked(seg):
            return deny()
    return 0

if __name__ == "__main__":
    sys.exit(main())
