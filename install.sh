#!/usr/bin/env bash
# Installe (ou resynchronise) la flotte syntexia-agents dans un repo produit cible.
# Synchronisation par manifeste : supprime les fichiers de la flotte deposes par
# une installation precedente (et eux seuls), copie la version courante, ecrit
# .claude/FLEET_VERSION. Les fichiers .claude/ propres au repo produit sont
# preserves.
# Usage : ./install.sh /chemin/vers/repo-cible
set -euo pipefail

TARGET="${1:?Usage: ./install.sh /chemin/vers/repo-cible}"
SRC="$(cd "$(dirname "$0")" && pwd)"

if [ ! -d "$TARGET/.git" ]; then
  echo "ERREUR: $TARGET n'est pas un repo git." >&2
  exit 1
fi

CLAUDE_DIR="$TARGET/.claude"
MANIFEST="$CLAUDE_DIR/.fleet_manifest"
mkdir -p "$CLAUDE_DIR"

# 1. Purge des fichiers deposes par une installation precedente.
if [ -f "$MANIFEST" ]; then
  while IFS= read -r rel; do
    [ -n "$rel" ] && rm -f "$CLAUDE_DIR/$rel"
  done < "$MANIFEST"
fi

# 2. Copie de la version courante, avec enregistrement au manifeste.
TMP_MANIFEST="$(mktemp)"
trap 'rm -f "$TMP_MANIFEST"' EXIT

install_file() {  # $1 = fichier source, $2 = chemin relatif sous .claude/
  local dest="$CLAUDE_DIR/$2"
  mkdir -p "$(dirname "$dest")"
  cp "$1" "$dest"
  echo "$2" >> "$TMP_MANIFEST"
}

for f in "$SRC"/agents/*.md;    do install_file "$f" "agents/$(basename "$f")"; done
for f in "$SRC"/commands/*.md;  do install_file "$f" "commands/$(basename "$f")"; done
install_file "$SRC/hooks/block_push.py" "hooks/block_push.py"
for f in "$SRC"/scripts/*.py;   do install_file "$f" "scripts/$(basename "$f")"; done
for f in "$SRC"/templates/*;    do [ -f "$f" ] && install_file "$f" "templates/$(basename "$f")"; done
for f in "$SRC"/reference/*;    do [ -f "$f" ] && install_file "$f" "reference/$(basename "$f")"; done

sort -u "$TMP_MANIFEST" > "$MANIFEST"

# 3. FLEET_VERSION : tracabilite rapport -> commit de flotte.
SHA="$(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
STAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'fleet_commit: %s\ninstalled_at: %s\nsource: %s\n' "$SHA" "$STAMP" "$SRC" > "$CLAUDE_DIR/FLEET_VERSION"

# 4. settings.json : jamais ecraser une config existante du repo produit.
if [ -f "$CLAUDE_DIR/settings.json" ]; then
  echo "NOTE: $CLAUDE_DIR/settings.json existe deja (non ecrase)."
  echo "      Fusionne manuellement le bloc permissions.deny ET le hook PreToolUse"
  echo "      depuis $SRC/hooks/settings.template.json (barriere primaire + defense en profondeur)."
else
  cp "$SRC/hooks/settings.template.json" "$CLAUDE_DIR/settings.json"
  echo "settings.json installe (permissions.deny + hook anti-push)."
fi

echo "Flotte installee dans $CLAUDE_DIR (commit $SHA)."
echo "Verifie que .claude/ est versionne, qu'un FACTS.md existe a la racine du repo,"
echo "puis lance /security-sweep full."
