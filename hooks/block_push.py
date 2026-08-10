#!/usr/bin/env python3
"""PreToolUse hook: blocks autonomous git push/merge, gh pr create|merge,
gh repo create, gh api merge endpoints. Fails CLOSED on any anomaly."""
import json
import re
import shlex
import sys

WRAPPERS = {"env", "command", "nohup", "time", "exec"}
GIT_OPTS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--exec-path", "--namespace"}
BLOCK_MSG = ("Bloque par la flotte syntexia-agents : push, merge et creation de PR/repo "
             "sont des actions humaines. Laisse la branche locale en l'etat et rends la main.")

def deny(msg=BLOCK_MSG):
    sys.stderr.write(msg)
    return 2

def git_subcommand(tokens):
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in GIT_OPTS_WITH_VALUE:
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        return t.lower()
    return ""

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
    rest = [t.lower() for t in tokens[1:]]
    if head == "git":
        return git_subcommand(rest) in {"push", "merge"}
    if head == "gh":
        if len(rest) >= 2 and rest[0] == "pr" and rest[1] in {"create", "merge"}:
            return True
        if len(rest) >= 2 and rest[0] == "repo" and rest[1] == "create":
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
       re.search(r"\b(push|merge)\b|/merges|pr\s+(create|merge)|repo\s+create", command, re.I):
        return deny("Hook block_push : construction shell imbriquee avec mot-cle push/merge, "
                    "blocage par defaut. Reformule sans sous-shell.")
    for seg in re.split(r"(?:&&|\|\||;|\||\n)", command):
        if seg.strip() and segment_blocked(seg):
            return deny()
    return 0

if __name__ == "__main__":
    sys.exit(main())
