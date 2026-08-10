#!/usr/bin/env bash
# Materialise le repo temoin vulnerable-app en repo git autonome, avec un secret
# plante dans l'historique puis retire (pour tester le scan d'historique).
# Usage : ./scripts/make_fixture_repo.sh /tmp/fixture-repo
set -euo pipefail

DEST="${1:?Usage: ./scripts/make_fixture_repo.sh /chemin/cible}"
SRC="$(cd "$(dirname "$0")/.." && pwd)/fixtures/vulnerable-app"

if [ ! -d "$SRC" ]; then
  echo "ERREUR: source temoin introuvable: $SRC" >&2
  exit 1
fi
if [ -e "$DEST" ]; then
  echo "ERREUR: la cible existe deja: $DEST (choisis un chemin neuf)" >&2
  exit 1
fi

mkdir -p "$DEST"
cp -r "$SRC"/. "$DEST"/
cd "$DEST"

git init -q -b main
git config user.name "Fixture Bot"
git config user.email "fixture@example.invalid"

git add -A
git commit -q -m "app: initial vulnerable app"

# Secret uniquement dans l'historique : plante puis retire.
# FIXTURE: faux token, ne jamais utiliser (marqueur FIXTURE en token borne).
printf 'FIXTURE_SERVICE_TOKEN=sk-ant-FIXTURE-1111111111111111111111111111111111111111\n' > leaked_token.txt
git add leaked_token.txt
git commit -q -m "chore: temporary token (will be removed)"
git rm -q leaked_token.txt
git commit -q -m "chore: remove token from working tree"

echo "Repo temoin cree dans $DEST"
echo "Historique: le secret leaked_token.txt existe dans un commit anterieur mais plus dans l'arbre."
echo "Etapes: installer la flotte (install.sh), lancer /security-sweep full, puis measure_recall.py."
