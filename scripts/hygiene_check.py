#!/usr/bin/env python3
"""Hygiene gate for the fleet repo. Run in CI and before any push.

Checks, over git-tracked files:
  1. No em-dash U+2014 anywhere (house style).
  2. No real-secret-shaped literals outside fixtures/ (the witness deliberately
     holds fake secrets). Regexes require a full-length body, so agent prose that
     merely names a prefix ("sk-ant- prefix", "AKIA prefix") does not match.
  3. No client/context contamination tokens anywhere. The fleet is generic.

Exit 1 on any violation. Pure stdlib; resolves the file list via `git ls-files`.
"""
import re
import subprocess
import sys

# (label, regex, path-prefix allowlist, apply_fake_marker_escape)
# The fake-marker escape suppresses a match whose OWN literal declares itself fake
# (FIXTURE/EXAMPLE, as a standalone token). Applied only to key-shaped patterns,
# never to inline DB creds, where the word could sit in a real password.
SECRET_PATTERNS = [
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), ("fixtures/",), True),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), ("fixtures/",), True),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"), ("fixtures/",), True),
    ("private-key-block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), ("fixtures/",), False),
    ("resend-key", re.compile(r"\bre_[A-Za-z0-9]{20,}\b"), ("fixtures/",), True),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), ("fixtures/",), True),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), ("fixtures/",), True),
    ("inline-db-creds",
     re.compile(r"[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s:/@]+@[^\s/:]+(?:\.[^\s/:]+|:\d+)"),
     ("fixtures/",), False),
]

FAKE_MARKER = re.compile(r"\b(FIXTURE|EXAMPLE)\b", re.IGNORECASE)

# Documented vendor placeholders that every scanner allowlists.
KNOWN_PLACEHOLDERS = {"AKIAIOSFODNN7EXAMPLE"}

# Contamination tokens: unambiguous, never legitimate in a generic fleet.
# This detector's own source lists the tokens, so it is exempt from this one check.
CONTAMINATION = re.compile(
    r"\b(teresa|magda|nauticea|rhinovate|visaudio|tercio|dropcontact|calendly|"
    r"baptistebouault|ascend\s+partners)\b", re.IGNORECASE)
CONTAMINATION_ALLOW = ("scripts/hygiene_check.py",)

EMDASH = "\u2014"


def tracked_files():
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines() if line.strip()]


def is_binary(path):
    return path.lower().endswith((".pdf", ".png", ".jpg", ".jpeg", ".zip", ".gz", ".ico"))


def allowed(path, prefixes):
    return any(path.startswith(p) for p in prefixes)


def main():
    violations = []
    for path in tracked_files():
        if is_binary(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        for n, line in enumerate(lines, 1):
            if EMDASH in line:
                violations.append(f"{path}:{n}: em-dash U+2014 interdit")
            for label, rx, allow, use_marker in SECRET_PATTERNS:
                if allowed(path, allow):
                    continue
                m = rx.search(line)
                if not m:
                    continue
                text = m.group(0)
                if text in KNOWN_PLACEHOLDERS:
                    continue
                if use_marker and FAKE_MARKER.search(text):
                    continue
                violations.append(f"{path}:{n}: literal type secret ({label})")
            if not allowed(path, CONTAMINATION_ALLOW) and CONTAMINATION.search(line):
                violations.append(f"{path}:{n}: token de contamination client")

    if violations:
        print("ECHEC HYGIENE")
        for v in violations:
            print(" -", v)
        return 1
    print("OK hygiene: aucun em-dash, aucun secret hors fixtures/, aucune contamination.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
