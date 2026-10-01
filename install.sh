#!/usr/bin/env bash
# Installe (ou resynchronise) la flotte syntexia-agents dans un repo produit cible.
#
# Chemin recommande : scripts/prepare_sweep_clone.sh, qui cree une copie jetable
# sans secrets ni remote, puis appelle ce script.
#
# Synchronisation par manifeste : supprime les fichiers de la flotte deposes par
# une installation precedente (et eux seuls, chemins valides sous .claude/),
# copie la version courante, ecrit .claude/FLEET_VERSION. Les fichiers .claude/
# propres au repo produit sont preserves.
#
# Usage : ./install.sh [--merge-settings] [--allow-live-checkout] /chemin/vers/repo-cible
#   --merge-settings       fusionne les controles de la flotte dans un
#                          .claude/settings.json existant (sauvegarde horodatee).
#   --allow-live-checkout  accepte une copie de travail contenant des fichiers de
#                          secrets non suivis (.env...). A eviter.
set -euo pipefail

usage() {
  echo "Usage: ./install.sh [--merge-settings] [--allow-live-checkout] /chemin/vers/repo-cible" >&2
  exit 1
}

MERGE=0
ALLOW_LIVE=0
TARGET=""
while [ $# -gt 0 ]; do
  case "$1" in
    --merge-settings) MERGE=1 ;;
    --allow-live-checkout) ALLOW_LIVE=1 ;;
    -h|--help) usage ;;
    -*) echo "ERREUR: option inconnue $1" >&2; usage ;;
    *) [ -z "$TARGET" ] || usage; TARGET="$1" ;;
  esac
  shift
done
[ -n "$TARGET" ] || usage

SRC="$(cd "$(dirname "$0")" && pwd -P)"
PY="$(command -v python3 || command -v python || true)"
[ -n "$PY" ] || { echo "ERREUR: python3 requis (hook et scripts de la flotte)." >&2; exit 1; }

[ -d "$TARGET" ] || { echo "ERREUR: $TARGET n'existe pas." >&2; exit 1; }
TARGET_REAL="$(cd "$TARGET" && pwd -P)"
[ -e "$TARGET_REAL/.git" ] || { echo "ERREUR: $TARGET_REAL n'est pas un repo git." >&2; exit 1; }
[ "$TARGET_REAL" != "$SRC" ] || { echo "ERREUR: la cible est le repo flotte lui-meme." >&2; exit 1; }

CLAUDE_DIR="$TARGET_REAL/.claude"
SETTINGS="$CLAUDE_DIR/settings.json"
MANIFEST="$CLAUDE_DIR/.fleet_manifest"

# 0a. Aucun lien symbolique sur le chemin d'installation : un repo scanne est une
# donnee non fiable et peut s'en servir pour rediriger les ecritures hors de lui.
for p in "$CLAUDE_DIR" "$CLAUDE_DIR/agents" "$CLAUDE_DIR/commands" "$CLAUDE_DIR/hooks" \
         "$CLAUDE_DIR/scripts" "$CLAUDE_DIR/templates" "$CLAUDE_DIR/reference" \
         "$SETTINGS" "$MANIFEST"; do
  if [ -L "$p" ]; then
    echo "ERREUR: $p est un lien symbolique. Installation refusee, rien n'a ete copie." >&2
    exit 1
  fi
done

# 0b. Copie de travail vivante : des fichiers de secrets non suivis (.env, cles) y
# sont presents. Une passe y exposerait les secrets de l'environnement reel.
# git ls-files --others liste chaque fichier non suivi ou ignore, un par un, y
# compris dans un dossier entierement ignore ou non suivi (git status le replierait
# en "config/" et un config/.env.production passerait inapercu).
LIVE="$(cd "$TARGET_REAL" && git ls-files -z --others 2>/dev/null | "$PY" -c '
import sys
# Same definition of a secret file as hooks/block_push.py.
safe = (".example", ".sample", ".template", ".dist", ".defaults", ".schema", ".tpl")
names = {".envrc", ".git-credentials", ".netrc", "_netrc", ".pgpass", ".my.cnf", ".npmrc",
         ".pypirc", ".dockercfg", ".htpasswd", "credentials.json", "service-account.json",
         "secrets.json", "secrets.yaml", "secrets.yml"}
keys = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
exts = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk", ".kdbx")
# Installed dependencies ship test keys and CA bundles (certifi/cacert.pem): library
# files, not the checkout secrets this check looks for.
deps = {"node_modules", ".venv", "venv", "site-packages", "dist-packages", ".tox", ".nox",
        "bower_components", "vendor"}
hits = []
for path in sys.stdin.buffer.read().decode("utf-8", "replace").split("\0"):
    if not path:
        continue
    parts = path.rstrip("/").split("/")
    if any(p in deps for p in parts[:-1]):
        continue
    base = parts[-1].lower()
    if (base.startswith(".env") and not base.endswith(safe)) or base in names \
            or (base.startswith(keys) and not base.endswith(".pub")) or base.endswith(exts):
        hits.append(path)
print("\n".join(hits[:20] + (["... et %d autre(s)" % (len(hits) - 20)] if len(hits) > 20 else [])))
')"
if [ -n "$LIVE" ] && [ "$ALLOW_LIVE" -ne 1 ]; then
  echo "ERREUR: copie de travail vivante, fichiers de secrets non suivis presents :" >&2
  printf '%s\n' "$LIVE" | sed 's/^/  - /' >&2
  echo "Prepare plutot une copie jetable :" >&2
  echo "  $SRC/scripts/prepare_sweep_clone.sh $TARGET_REAL /tmp/sweep-<nom>" >&2
  echo "(ou relance avec --allow-live-checkout en connaissance de cause)." >&2
  exit 1
fi

# 0c. Configuration Claude fournie par le repo scanne (donnee non fiable) :
# settings.local.json prime sur settings.json, .mcp.json declare des serveurs MCP.
# prepare_sweep_clone.sh les met en quarantaine ; ici on refuse.
for f in "$CLAUDE_DIR/settings.local.json" "$TARGET_REAL/.mcp.json"; do
  if { [ -e "$f" ] || [ -L "$f" ]; } && [ "$ALLOW_LIVE" -ne 1 ]; then
    echo "ERREUR: $f present (configuration fournie par le repo)." >&2
    echo "        Passe par scripts/prepare_sweep_clone.sh, qui la met en quarantaine," >&2
    echo "        ou relance avec --allow-live-checkout. Rien n'a ete copie." >&2
    exit 1
  fi
done

# 0d. Barriere primaire : un settings.json existant doit deja contenir tous les
# controles de la flotte (verifie en JSON, pas par grep), ou etre fusionne.
MERGE_PENDING=0
if [ -f "$SETTINGS" ]; then
  set +e
  "$PY" "$SRC/scripts/fleet_settings.py" check "$SETTINGS"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    if [ "$MERGE" -eq 1 ] && [ "$rc" -eq 4 ]; then
      MERGE_PENDING=1
    else
      echo "ERREUR: $SETTINGS ne contient pas tous les controles de la flotte (code $rc)." >&2
      echo "        Relance avec --merge-settings pour les fusionner (sauvegarde" >&2
      echo "        automatique). Rien n'a ete copie." >&2
      exit 1
    fi
  fi
fi

# 1. Purge des fichiers deposes par une installation precedente. Le manifeste vit
# dans le repo cible : chaque entree est validee (pas de chemin absolu, pas de
# '..', reste sous .claude/) avant toute suppression.
if [ -f "$MANIFEST" ]; then
  "$PY" - "$CLAUDE_DIR" "$MANIFEST" <<'PY'
import os
import re
import sys

root = os.path.realpath(sys.argv[1])
ok = re.compile(r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")
with open(sys.argv[2], encoding="utf-8", errors="replace") as f:
    entries = f.read().splitlines()
for rel in entries:
    rel = rel.strip()
    if not rel:
        continue
    if not ok.match(rel) or ".." in rel.split("/"):
        print("manifeste : entree ignoree (chemin invalide) : %r" % rel[:80], file=sys.stderr)
        continue
    path = os.path.join(root, rel)
    parent = os.path.realpath(os.path.dirname(path))
    if os.path.commonpath([parent, root]) != root:
        print("manifeste : entree ignoree (hors .claude) : %r" % rel[:80], file=sys.stderr)
        continue
    if os.path.islink(path) or os.path.isfile(path):
        os.remove(path)
PY
fi

# 2. Copie de la version courante, avec enregistrement au manifeste.
mkdir -p "$CLAUDE_DIR"
TMP_MANIFEST="$(mktemp)"
trap 'rm -f "$TMP_MANIFEST"' EXIT

install_file() {  # $1 = fichier source, $2 = chemin relatif sous .claude/
  local dest="$CLAUDE_DIR/$2"
  local dir
  dir="$(dirname "$dest")"
  if [ -L "$dir" ]; then
    echo "ERREUR: $dir est un lien symbolique." >&2
    exit 1
  fi
  mkdir -p "$dir"
  if [ -L "$dest" ]; then
    rm -f -- "$dest"
  fi
  cp "$1" "$dest"
  echo "$2" >> "$TMP_MANIFEST"
}

for f in "$SRC"/agents/*.md;    do install_file "$f" "agents/$(basename "$f")"; done
for f in "$SRC"/commands/*.md;  do install_file "$f" "commands/$(basename "$f")"; done
install_file "$SRC/hooks/block_push.py" "hooks/block_push.py"
install_file "$SRC/hooks/settings.sandbox.json" "settings.sandbox.json"
# Seuls les scripts d'execution vont dans le repo cible. Les outils de dev de la
# flotte (validate_fleet, test_hook, test_install, hygiene_check, measure_recall,
# make_fixture_repo, fleet_settings) restent dans le repo flotte.
for s in consolidate_findings.py generate_asvs_matrix.py preflight_tooling.py \
         redacted_secret_scan.py; do
  install_file "$SRC/scripts/$s" "scripts/$s"
done
for f in "$SRC"/templates/*;    do [ -f "$f" ] && install_file "$f" "templates/$(basename "$f")"; done
for f in "$SRC"/reference/*;    do [ -f "$f" ] && install_file "$f" "reference/$(basename "$f")"; done
install_file "$SRC/PLAYBOOK.md" "PLAYBOOK.md"

sort -u "$TMP_MANIFEST" > "$MANIFEST"

# 3. FLEET_VERSION : tracabilite rapport -> commit de flotte (et etat non commite).
SHA="$(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
DIRTY="no"
if [ -n "$(git -C "$SRC" status --porcelain 2>/dev/null || true)" ]; then DIRTY="yes"; fi
STAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'fleet_commit: %s\nfleet_uncommitted_changes: %s\ninstalled_at: %s\nsource: %s\n' \
  "$SHA" "$DIRTY" "$STAMP" "$SRC" > "$CLAUDE_DIR/FLEET_VERSION"

# 4. settings.json : copie du gabarit, ou fusion demandee, puis controle final.
if [ ! -f "$SETTINGS" ]; then
  cp "$SRC/hooks/settings.template.json" "$SETTINGS"
  echo "settings.json installe (deny, env de session, verrou bypass, hook)."
elif [ "$MERGE_PENDING" -eq 1 ]; then
  "$PY" "$SRC/scripts/fleet_settings.py" merge "$SETTINGS"
fi
"$PY" "$SRC/scripts/fleet_settings.py" check "$SETTINGS" >/dev/null || {
  echo "ERREUR: controle final de $SETTINGS en echec." >&2
  exit 1
}
if [ -f "$CLAUDE_DIR/settings.local.json" ]; then
  echo "ATTENTION: $CLAUDE_DIR/settings.local.json existe et passe avant settings.json :"
  echo "           verifie qu'il ne redefinit ni env ni permissions."
fi

echo "Flotte installee dans $CLAUDE_DIR (commit $SHA, modifications non commitees: $DIRTY)."
echo "Ensuite : cd $TARGET_REAL && claude, puis /security-sweep full."
echo "Bac a sable (recommande, voir PLAYBOOK) : claude --settings .claude/settings.sandbox.json"
