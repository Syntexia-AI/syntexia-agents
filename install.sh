#!/usr/bin/env bash
# Installe la flotte syntexia-agents dans un repo produit cible.
# Usage : ./install.sh /chemin/vers/repo-cible
set -euo pipefail

TARGET="${1:?Usage: ./install.sh /chemin/vers/repo-cible}"
SRC="$(cd "$(dirname "$0")" && pwd)"

if [ ! -d "$TARGET/.git" ]; then
  echo "ERREUR: $TARGET n'est pas un repo git." >&2
  exit 1
fi

mkdir -p "$TARGET/.claude/agents" "$TARGET/.claude/commands" "$TARGET/.claude/hooks"
cp "$SRC"/agents/*.md "$TARGET/.claude/agents/"
cp "$SRC"/commands/*.md "$TARGET/.claude/commands/"
cp "$SRC"/hooks/block_push.py "$TARGET/.claude/hooks/"
mkdir -p "$TARGET/.claude/templates" "$TARGET/.claude/reference"
cp "$SRC"/templates/*.md "$TARGET/.claude/templates/"
cp "$SRC"/reference/* "$TARGET/.claude/reference/"

if [ -f "$TARGET/.claude/settings.json" ]; then
  echo "NOTE: $TARGET/.claude/settings.json existe deja."
  echo "Ajoute manuellement le hook PreToolUse depuis hooks/settings.template.json."
else
  cp "$SRC/hooks/settings.template.json" "$TARGET/.claude/settings.json"
  echo "Hook anti-push installe dans .claude/settings.json"
fi

echo "Flotte installee dans $TARGET/.claude/"
echo "Verifie que .claude/ est versionne dans le repo cible, puis lance /security-sweep."
