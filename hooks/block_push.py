#!/usr/bin/env python3
"""PreToolUse hook: blocks autonomous git push / merge / PR merge from any agent.
Exit 2 blocks the tool call and returns the message to the model."""
import json
import re
import sys

BLOCK = re.compile(
    r"(\bgit\b[^\n|;&]*\b(push|merge)\b)|(\bgh\s+pr\s+(create|merge)\b)|(\bgh\s+repo\s+create\b)",
    re.IGNORECASE,
)

def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    if payload.get("tool_name") != "Bash":
        return 0
    command = (payload.get("tool_input") or {}).get("command", "")
    if BLOCK.search(command):
        sys.stderr.write(
            "Bloque par la flotte syntexia-agents : push, merge et creation de PR/repo "
            "sont des actions humaines. Laisse la branche locale en l'etat et rends la main."
        )
        return 2
    return 0

if __name__ == "__main__":
    sys.exit(main())
