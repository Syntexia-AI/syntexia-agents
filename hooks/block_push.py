#!/usr/bin/env python3
"""PreToolUse hook: defense-in-depth guard against autonomous state-changing and
destructive git/gh commands. Fails CLOSED on any anomaly.

This is NOT the primary barrier. The primary barrier is permissions.deny in
.claude/settings.json, enforced by the harness. This hook parses a command line
and cannot see a push hidden in a shell script, an xargs-fed git call, a shell
alias, or an exotic wrapper flag-value. See PLAYBOOK.md section 8."""
import json
import re
import shlex
import sys

# Wrappers whose leading tokens (and their own options/args) are skipped to reach
# the real command. Consuming wrappers (timeout, nice, ...) may take flags/numbers.
WRAPPERS = {"env", "command", "nohup", "time", "exec", "sudo", "xargs",
            "timeout", "nice", "stdbuf", "ionice"}
GIT_OPTS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--exec-path", "--namespace"}
ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

BLOCK_MSG = ("Bloque par la flotte syntexia-agents : push, merge, pull, reecriture ou "
             "destruction d'historique et creation de PR/repo sont des actions humaines. "
             "Laisse la branche locale en l'etat et rends la main.")


def _branch_blocked(a):
    short = [t for t in a if t.startswith("-") and not t.startswith("--")]
    if any("D" in t for t in short):            # -D / -Df / -dD  force delete
        return True
    if any("d" in t and "f" in t for t in short):  # -df / -fd
        return True
    if any("f" in t for t in short):            # -f  force create/move
        return True
    if "--force" in a:
        return True
    if "--delete" in a and any("f" in t for t in short):
        return True
    return False


def _restore_blocked(a):
    # git restore touches the worktree (discards changes) unless it targets only the
    # index (--staged / -S). Block worktree-affecting forms.
    return not any(t in ("--staged", "-S") for t in a)


BLOCKED_GIT = {
    "push": lambda a: True,
    "merge": lambda a: True,
    "pull": lambda a: True,
    "reset": lambda a: "--hard" in a,
    "rebase": lambda a: True,
    "clean": lambda a: any(t.startswith("-") and "f" in t for t in a) or "--force" in a,
    "update-ref": lambda a: "-d" in a or "--delete" in a,
    "checkout": lambda a: any(t in ("-f", "--force") for t in a) or "--" in a,
    "switch": lambda a: any(t in ("-f", "--force", "--discard-changes") for t in a),
    "restore": _restore_blocked,
    "branch": _branch_blocked,
    "remote": lambda a: bool(a) and a[0].lower() in {"set-url", "remove", "rm", "rename"},
    "stash": lambda a: bool(a) and a[0].lower() in {"drop", "clear"},
    "commit": lambda a: "--amend" in a,
    "filter-branch": lambda a: True,
    "filter-repo": lambda a: True,
}


def deny(msg=BLOCK_MSG):
    sys.stderr.write(msg)
    return 2


def normalize_head(tok):
    head = tok.lower().replace("\\", "/").rsplit("/", 1)[-1]
    if head.endswith(".exe"):
        head = head[:-4]
    return head


def strip_wrappers(tokens):
    while tokens:
        t0 = tokens[0]
        if ENV_ASSIGN.match(t0):
            tokens = tokens[1:]
            continue
        if normalize_head(t0) in WRAPPERS:
            tokens = tokens[1:]
            # Skip the wrapper's own leading flags, numeric args and env-assignments.
            while tokens and (tokens[0].startswith("-") or tokens[0].isdigit()
                              or ENV_ASSIGN.match(tokens[0])):
                tokens = tokens[1:]
            continue
        break
    return tokens


def git_subcommand(tokens):
    """(subcommand_lowercased, args_in_original_case). Args keep case: -D must not
    collapse onto -d."""
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
    tokens = strip_wrappers(tokens)
    if not tokens:
        return False
    head = normalize_head(tokens[0])
    if head == "git":
        sub, args = git_subcommand(tokens[1:])
        predicate = BLOCKED_GIT.get(sub)
        return bool(predicate and predicate(args))
    if head == "gh":
        rest = [t.lower() for t in tokens[1:]]
        if len(rest) >= 2 and rest[0] == "pr" and rest[1] in {"create", "merge"}:
            return True
        if len(rest) >= 2 and rest[0] == "repo" and rest[1] in {"create", "delete"}:
            return True
        if rest and rest[0] == "api":
            # Merge and destructive (DELETE) API calls.
            if any("/merges" in t or re.search(r"/pulls/\d+/merge\b", t) for t in rest):
                return True
            for i, t in enumerate(rest):
                if t in ("-x", "--method") and i + 1 < len(rest) and rest[i + 1] == "delete":
                    return True
                if t.startswith("--method=") and t.split("=", 1)[1] == "delete":
                    return True
    return False


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return deny("Hook block_push : entree illisible, blocage par defaut.")
    if not isinstance(payload, dict):
        return deny("Hook block_push : payload non conforme, blocage par defaut.")
    tool = payload.get("tool_name")
    if tool is not None and tool != "Bash":
        return 0
    ti = payload.get("tool_input")
    command = ti.get("command") if isinstance(ti, dict) else None
    if not isinstance(command, str):
        return deny("Hook block_push : commande absente ou non textuelle, blocage par defaut.")
    if re.search(r"`|\$\(|\b(ba|z|da|k)?sh\s+-c\b", command) and \
       re.search(r"\b(push|pull|merge|reset|rebase|clean|filter-branch|filter-repo|"
                 r"set-url|restore|stash)\b|/merges|pr\s+(create|merge)|repo\s+(create|delete)",
                 command, re.I):
        return deny("Hook block_push : construction shell imbriquee avec mot-cle sensible, "
                    "blocage par defaut. Reformule sans sous-shell.")
    for seg in re.split(r"(?:&&|\|\||;|\||\n|&)", command):
        if seg.strip() and segment_blocked(seg):
            return deny()
    return 0


if __name__ == "__main__":
    sys.exit(main())
