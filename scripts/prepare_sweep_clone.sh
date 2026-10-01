#!/usr/bin/env bash
# Prepare une copie jetable d'un repo produit pour une passe de securite.
#
# - clone propre : aucun fichier non suivi n'est copie (pas de .env, pas de cles) ;
# - aucun remote : un push n'a nulle part ou aller, meme contourne ;
# - aucun assistant d'identifiants, aucun hook git, identite git locale ;
# - .claude/ exclu des commits de la copie ;
# - flotte installee (settings fusionnes si le produit a deja un .claude/).
# Le repo source n'est jamais modifie.
#
# Usage : scripts/prepare_sweep_clone.sh <repo source : chemin ou URL> <destination neuve> [branche]
# Identite des commits de correctif : FLEET_GIT_NAME / FLEET_GIT_EMAIL (sinon
# "Security Sweep <security-sweep@localhost>").
set -euo pipefail

SRC_REPO="${1:?Usage: scripts/prepare_sweep_clone.sh <repo source> <destination neuve> [branche]}"
DEST="${2:?Usage: scripts/prepare_sweep_clone.sh <repo source> <destination neuve> [branche]}"
BRANCH="${3:-}"
FLEET="$(cd "$(dirname "$0")/.." && pwd -P)"

if [ -e "$DEST" ]; then
  echo "ERREUR: $DEST existe deja (choisis un chemin neuf)." >&2
  exit 1
fi
case "$DEST" in
  /*) ;;
  *) DEST="$(pwd -P)/$DEST" ;;
esac
if [ -d "$SRC_REPO" ]; then
  SRC_DESC="$(cd "$SRC_REPO" && pwd -P)"
else
  SRC_DESC="$SRC_REPO"
fi

if [ -n "$BRANCH" ]; then
  git clone --no-hardlinks --quiet --branch "$BRANCH" "$SRC_REPO" "$DEST"
else
  git clone --no-hardlinks --quiet "$SRC_REPO" "$DEST"
fi
cd "$DEST"
COMMIT="$(git rev-parse HEAD)"

# Transport neutralise dans la copie uniquement.
for r in $(git remote); do
  git remote remove "$r"
done
git config --local credential.helper ""
git config --local core.hooksPath /dev/null
git config --local user.name "${FLEET_GIT_NAME:-Security Sweep}"
git config --local user.email "${FLEET_GIT_EMAIL:-security-sweep@localhost}"

# Configuration Claude fournie par le repo (hooks, permissions, serveurs MCP) : donnee
# non fiable pour une passe de securite, mise en quarantaine hors de l'arbre.
if [ -L .claude ]; then
  echo "ERREUR: .claude est un lien symbolique dans le repo source. Copie abandonnee." >&2
  exit 1
fi
QUAR=".git/sweep-quarantine"
for f in .claude/settings.json .claude/settings.local.json .mcp.json; do
  if [ -e "$f" ] || [ -L "$f" ]; then
    mkdir -p "$QUAR/$(dirname "$f")"
    mv "$f" "$QUAR/$f"
    echo "$f" >> "$QUAR/LISTE"
  fi
done

mkdir -p .git/info
printf '\n# flotte syntexia-agents (copie jetable)\n.claude/\n' >> .git/info/exclude
printf 'source: %s\ncommit: %s\nprepared_at: %s\n' \
  "$SRC_DESC" "$COMMIT" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > .git/sweep-source

"$FLEET/install.sh" --merge-settings "$DEST"

# Zone de travail commune a toutes les passes : la Phase 0 l'exige absente ou vide.
SCRATCH_NOTE="absente ou vide, OK"
if [ -L /tmp/sweep ]; then
  SCRATCH_NOTE="ATTENTION : /tmp/sweep est un lien symbolique, supprime-le (rm /tmp/sweep) avant la passe"
elif [ -n "$(find /tmp/sweep -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
  SCRATCH_NOTE="ATTENTION : /tmp/sweep contient les fichiers d'une passe precedente ; la Phase 0 s'arretera. Archive ce qui doit l'etre, puis rm -rf /tmp/sweep"
fi

cat <<EOF

Copie jetable prete : $DEST
  source : $SRC_DESC
  commit : $COMMIT
  remote : aucun ; identifiants git : aucun ; .claude/ exclu des commits.
  configuration Claude du repo en quarantaine : $( [ -f .git/sweep-quarantine/LISTE ] && tr '\n' ' ' < .git/sweep-quarantine/LISTE || echo aucune )
  zone de travail /tmp/sweep : $SCRATCH_NOTE

1. cd $DEST && claude
   (bac a sable recommande : claude --settings .claude/settings.sandbox.json)
2. /security-sweep full
3. Apres revue de la branche, depuis ton clone habituel :
     git fetch $DEST security-sweep/<date>
     git push origin FETCH_HEAD:refs/heads/security-sweep/<date>
4. Faire tourner chez le fournisseur tout secret signale, puis supprimer la copie
   et la zone de travail (rm -rf /tmp/sweep) : la passe suivante l'exige vide.
EOF
