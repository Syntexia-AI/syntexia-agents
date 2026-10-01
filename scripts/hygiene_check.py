#!/usr/bin/env python3
"""Hygiene gate for the fleet repo. Run in CI and before any push.

Checks, over git-tracked files:
  1. No em-dash U+2014 anywhere (house style).
  2. No real-secret-shaped literals outside fixtures/ (the witness deliberately
     holds fake secrets). Regexes require a full-length body, so agent prose that
     merely names a prefix ("sk-ant- prefix", "AKIA prefix") does not match.
  3. No client/context contamination tokens anywhere. The fleet is generic.

The contamination list is stored as salted SHA-256 digests of normalized words and
word pairs, never in clear: a denylist of client names written in clear would
itself disclose the names it protects. This is obfuscation, not secrecy (a guessed
name can be confirmed by hashing it), so the repository must stay private. Extra
tokens can be supplied without committing them: environment variable
FLEET_HYGIENE_DENYLIST (comma-separated, e.g. a CI secret) or the file
~/.config/syntexia/hygiene-denylist.txt (one token per line).
To add a token to the committed list: python3 scripts/hygiene_check.py --hash "<token>"

Exit 1 on any violation. Pure stdlib; resolves the file list via `git ls-files`.
"""
import hashlib
import os
import pathlib
import re
import subprocess
import sys
import unicodedata

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

# Contamination tokens: unambiguous, never legitimate in a generic fleet. Salted
# SHA-256 of the normalized token (lowercase, accents stripped, single spaces).
CONTAMINATION_SALT = "syntexia-agents/hygiene/v1:"
CONTAMINATION_SHA256 = frozenset({
    "04af822415bedf448105649d7b2a2ef8dd85d45192c3aa942afa39552b1b623b",
    "0a1c827e357ad4b12653df7fc4e3f6b78673eecc8a783ade6764a4d7ee48a331",
    "215ea54563125f191584701e66043d718d8c77ed560644c00a7e07a43c6ce04e",
    "2f4117f8ede2d43cfc84fd84da0d8b1fdb94e9f248a0401fea269f19f99acde3",
    "31ecdf569f72c6799f892957caaac5a8ec739f0bec7c736292d5dc448e166571",
    "37ca989d46dddae12a8f8d782bbadd142b096f024d26d00fc96e1159b01d2fba",
    "3cc153c431b9cdd133a91741f475d460b1567b1acc7839294194ec2f64c2ec76",
    "44c58bcb9c006d5c0e1a9a18dfc2ec626e9e8f9635fc0fe7321860e340a9ae3d",
    "4af3715a32219e4cad6929964825be205bfa462fd5cc20ae9d59f1a50e04afee",
    "57ad0262f93eb8c1c73bee91c34b0ba687a7f86a5b53624ce25c97d09cd38457",
    "64fecc139929c3bb52fb99cf464882c3c8312c0e3c66060cca3744c632e0abb2",
    "67cf2458e4ba36b0561a4982c97e1fcb9666007c4f9f518dec533c380586975f",
    "698a2541a9ec193f43f94213d146adb787e386d8f2111331c81e5e4c5eaf1585",
    "6e15cd960c38ca85a9a411f994417583b3cf2f52bbb77e36d74f5f6439cd6b98",
    "752cf1bad72c066715383b5c7f500ba4f84f2df58ddf4483b01db452daf97d5e",
    "7b5b52f321aaf5ce6f8db004a8bf9aebd6074a5be199d9700bce3184eafdec36",
    "80802947cb644152c9942177c984a670c59715e7e94a284b16be158208d220db",
    "874beb7fac4204c070d2fa5b6c6b301012df724921d264739ca397c0d213e38c",
    "9967623bd6374b04507e6dab525a731fb7a131ebb32e8c5cff7b5b6d66752937",
    "9b222c4d83f5cba5a6be23b39ab5337872314cc6ac188885897c07ef2a54c755",
    "a703c958103139cff8e541ddbca964f0b7bb6c2c70a2af3c2a21b277cb1b27cd",
    "ad9caed04eabdd8399fea8baa04138650c19e18dc099e88c2445fb4404ca6329",
    "b4512beea0742bc8cc705f5f03ff38daec13763ae139cdd17ae1a1f93f639bad",
    "bb2871fe40662ad759b6422557cffeb7843541689571e1036ce7fdd0bf505243",
    "bc828936c4d9f40a6ed5c4e16ee5ef64e645bfb9395c3fd74d780d3a198a0eaf",
    "ce8afef51a9c4ea8ed9ef8bcd235298f6a9148615a2ead7ce2db462e7482abf0",
    "d148da68d0d68099486217e297273df256f90715dc06262cd73e64b5967695fd",
    "da6caacb9b9d100ab097731d4a071f802ca8698eb13eef4fd913ff97cd9be62f",
    "e9a727216feb1e4615b7a4204e17effeb9a5dea5df7ced737d4e4b8934c456e5",
    "ed9888128627226da5de2a7b865399d15d35ad3f93f003704ff8f639e456ceaf",
    "edcee02c9a9cc2f501d69401f0c908264d209ab8f9660f28cd11107b21c68f74",
    "f2cebceda5bf3ac45fd7c7976375a8504b6aa3bee25ff0e2340d402cb0e7cc8b",
    "f9e4dc2127295e89f09f5e9be04a9a45d003bc8a017de02ca8fe9316cb57ca6f",
})


def normalize(text):
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return text.lower()


def digest(token):
    token = " ".join(re.findall(r"[a-z0-9]+", normalize(token)))
    return hashlib.sha256((CONTAMINATION_SALT + token).encode("utf-8")).hexdigest()


def extra_tokens():
    tokens = set()
    env = os.environ.get("FLEET_HYGIENE_DENYLIST", "")
    tokens.update(t.strip() for t in env.split(",") if t.strip())
    path = pathlib.Path.home() / ".config" / "syntexia" / "hygiene-denylist.txt"
    if path.is_file():
        tokens.update(line.strip() for line in path.read_text(encoding="utf-8").splitlines()
                      if line.strip() and not line.startswith("#"))
    return {digest(t) for t in tokens}


def contaminated(line, digests):
    words = re.findall(r"[a-z0-9]+", normalize(line))
    candidates = set(words) | {a + " " + b for a, b in zip(words, words[1:])}
    return any(hashlib.sha256((CONTAMINATION_SALT + c).encode("utf-8")).hexdigest() in digests
               for c in candidates)


EMDASH = "\u2014"


def tracked_files():
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines() if line.strip()]


def is_binary(path):
    return path.lower().endswith((".pdf", ".png", ".jpg", ".jpeg", ".zip", ".gz", ".ico"))


def allowed(path, prefixes):
    return any(path.startswith(p) for p in prefixes)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--hash":
        print(digest(sys.argv[2]))
        return 0
    digests = CONTAMINATION_SHA256 | extra_tokens()
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
            if contaminated(line, digests):
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
