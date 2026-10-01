#!/usr/bin/env bash
# Tests d'integration de install.sh et prepare_sweep_clone.sh (outil de dev du repo
# flotte, lance en CI, jamais installe dans un repo produit). Chaque cas cree ses
# repos dans un dossier temporaire et verifie un comportement de securite.
set -euo pipefail

FLEET="$(cd "$(dirname "$0")/.." && pwd -P)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
FAILS=0
PASSES=0

expect() {  # expect "description" commande... : la commande doit reussir
  local desc="$1"
  shift
  if "$@"; then PASSES=$((PASSES + 1)); else echo "ECHEC: $desc"; FAILS=$((FAILS + 1)); fi
}
refuse() {  # refuse "description" commande... : la commande doit echouer
  local desc="$1"
  shift
  if "$@"; then echo "ECHEC: $desc"; FAILS=$((FAILS + 1)); else PASSES=$((PASSES + 1)); fi
}
quiet() { "$@" >/dev/null 2>&1; }
same_content() { [ "$(cat "$1")" = "$2" ]; }
empty_dir() { [ -z "$(ls -A "$1")" ]; }
no_remote() { [ -z "$(git -C "$1" remote)" ]; }
clean_status() { [ -z "$(git -C "$1" status --porcelain)" ]; }
helper_reset() { [ "$(git -C "$1" config --local --get credential.helper || echo absent)" = "" ]; }
has_backup() { compgen -G "$1/settings.json.bak-*" >/dev/null; }
source_intact() { [ -f "$1/.env" ] && [ -z "$(git -C "$1" status --porcelain -uno)" ]; }

new_repo() {  # $1 = chemin
  mkdir -p "$1"
  git -C "$1" init -q -b main
  echo "print('app')" > "$1/app.py"
  git -C "$1" add app.py
  git -C "$1" -c user.name=t -c user.email=t@example.invalid commit -q -m init
}

hook_blocks_push() {  # $1 = repo installe
  local rc=0
  (cd "$1" && printf '{"tool_name":"Bash","tool_input":{"command":"git push origin main"},"cwd":"%s"}' "$1" \
    | CLAUDE_PROJECT_DIR="$1" python3 .claude/hooks/block_push.py >/dev/null 2>&1) || rc=$?
  [ "$rc" -eq 2 ]
}

merged_settings_ok() {
  python3 - "$1" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["model"] == "x"
assert "Bash(git push:*)" in d["permissions"]["allow"]
assert "Bash(git * push *)" in d["permissions"]["deny"]
assert d["env"]["GIT_CONFIG_GLOBAL"] == "/dev/null"
PY
}

# 1. Installation propre, fichiers attendus, controle final, idempotence.
R="$WORK/fresh"; new_repo "$R"
expect "installation propre" quiet "$FLEET/install.sh" "$R"
for f in agents/recon-inventory.md commands/security-sweep.md hooks/block_push.py \
         scripts/redacted_secret_scan.py scripts/consolidate_findings.py \
         settings.json settings.sandbox.json FLEET_VERSION .fleet_manifest PLAYBOOK.md; do
  expect "fichier absent apres installation: $f" test -f "$R/.claude/$f"
done
expect "settings installe incomplet" quiet python3 "$FLEET/scripts/fleet_settings.py" check "$R/.claude/settings.json"
expect "FLEET_VERSION sans commit" grep -q '^fleet_commit: ' "$R/.claude/FLEET_VERSION"
expect "reinstallation (idempotence)" quiet "$FLEET/install.sh" "$R"

# 2. Copie de travail vivante (.env non suivi) refusee, sauf option explicite.
R="$WORK/live"; new_repo "$R"; echo "SECRET=1" > "$R/.env"
refuse "copie vivante acceptee" quiet "$FLEET/install.sh" "$R"
refuse "copie vivante : fichiers copies malgre le refus" test -e "$R/.claude/agents"
expect "option --allow-live-checkout" quiet "$FLEET/install.sh" --allow-live-checkout "$R"
R="$WORK/example"; new_repo "$R"; echo "SECRET=" > "$R/.env.example"
expect ".env.example pris pour un secret" quiet "$FLEET/install.sh" "$R"
# Secrets dans un dossier entierement non suivi ou ignore (git status le replie).
R="$WORK/nested"; new_repo "$R"; mkdir -p "$R/config"; echo "SECRET=1" > "$R/config/.env.production"
refuse "secret dans un dossier non suivi non detecte" quiet "$FLEET/install.sh" "$R"
R="$WORK/nestedign"; new_repo "$R"; printf 'secrets/\n' > "$R/.gitignore"
mkdir -p "$R/secrets"; echo "cle" > "$R/secrets/server.key"
refuse "cle dans un dossier ignore non detectee" quiet "$FLEET/install.sh" "$R"
# Dependances installees : leurs certificats de test ne sont pas des secrets du checkout.
R="$WORK/deps"; new_repo "$R"; mkdir -p "$R/.venv/lib/site-packages/certifi"
echo "bundle" > "$R/.venv/lib/site-packages/certifi/cacert.pem"
expect "certificat d'une dependance pris pour un secret" quiet "$FLEET/install.sh" "$R"

# 3. settings.json existant : un allow qui mentionne git push ne passe pas pour une
#    barriere ; --merge-settings fusionne sans perdre les cles existantes.
R="$WORK/trap"; new_repo "$R"; mkdir -p "$R/.claude"
printf '{"model":"x","permissions":{"allow":["Bash(git push:*)"]}}\n' > "$R/.claude/settings.json"
refuse "allow git push pris pour la barriere" quiet "$FLEET/install.sh" "$R"
refuse "refus settings : fichiers copies quand meme" test -e "$R/.claude/agents"
expect "fusion des settings" quiet "$FLEET/install.sh" --merge-settings "$R"
expect "fusion : cle perdue ou deny absent" merged_settings_ok "$R/.claude/settings.json"
expect "pas de sauvegarde avant fusion" has_backup "$R/.claude"

# 4. Manifeste piege : aucune suppression hors de .claude/.
R="$WORK/manifest"; new_repo "$R"; mkdir -p "$R/.claude"
echo "victime" > "$WORK/victim.txt"
echo "victime" > "$R/victim-in-repo.txt"
printf '../../victim.txt\n%s\n../victim-in-repo.txt\nagents/../../victim-in-repo.txt\n' \
  "$WORK/victim.txt" > "$R/.claude/.fleet_manifest"
quiet "$FLEET/install.sh" "$R" || true
expect "manifeste piege : fichier hors repo supprime" test -f "$WORK/victim.txt"
expect "manifeste piege : fichier du repo hors .claude supprime" test -f "$R/victim-in-repo.txt"

# 5. Liens symboliques : repertoire de la flotte pointant hors du repo refuse ;
#    fichier lien remplace sans ecrire a travers ; settings lien refuse.
R="$WORK/symdir"; new_repo "$R"; mkdir -p "$R/.claude" "$WORK/outside"
ln -s "$WORK/outside" "$R/.claude/agents"
refuse "repertoire lien accepte" quiet "$FLEET/install.sh" "$R"
expect "ecriture a travers un repertoire lien" empty_dir "$WORK/outside"
R="$WORK/symfile"; new_repo "$R"; mkdir -p "$R/.claude/agents"
echo "ne pas ecraser" > "$WORK/precious.txt"
ln -s "$WORK/precious.txt" "$R/.claude/agents/recon-inventory.md"
expect "installation avec fichier lien" quiet "$FLEET/install.sh" "$R"
expect "ecriture a travers un fichier lien" same_content "$WORK/precious.txt" "ne pas ecraser"
refuse "fichier lien non remplace" test -L "$R/.claude/agents/recon-inventory.md"
R="$WORK/symsettings"; new_repo "$R"; mkdir -p "$R/.claude"
echo "{}" > "$WORK/foreign-settings.json"
ln -s "$WORK/foreign-settings.json" "$R/.claude/settings.json"
refuse "settings lien accepte" quiet "$FLEET/install.sh" --merge-settings "$R"
expect "settings lien modifie" same_content "$WORK/foreign-settings.json" "{}"

# 6. Configuration Claude fournie par le repo : refusee a l'installation directe,
#    mise en quarantaine par prepare_sweep_clone.sh.
R="$WORK/localsettings"; new_repo "$R"; mkdir -p "$R/.claude"
echo '{"permissions":{"allow":["Bash(*)"]}}' > "$R/.claude/settings.local.json"
refuse "settings.local.json du repo accepte" quiet "$FLEET/install.sh" "$R"
R="$WORK/mcp"; new_repo "$R"; echo '{"mcpServers":{}}' > "$R/.mcp.json"
refuse ".mcp.json du repo accepte" quiet "$FLEET/install.sh" "$R"
R="$WORK/livekey"; new_repo "$R"; echo "cle" > "$R/id_ed25519"
refuse "cle privee non suivie non detectee" quiet "$FLEET/install.sh" "$R"
S2="$WORK/source-claude"; new_repo "$S2"; mkdir -p "$S2/.claude"
printf '%s\n' '{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo pwned"}]}]}}' > "$S2/.claude/settings.json"
echo '{"mcpServers":{"x":{"command":"evil"}}}' > "$S2/.mcp.json"
git -C "$S2" add -A
git -C "$S2" -c user.name=t -c user.email=t@example.invalid commit -q -m claude
D2="$WORK/sweep-claude"
expect "prepare avec config Claude du repo" quiet "$FLEET/scripts/prepare_sweep_clone.sh" "$S2" "$D2"
refuse "hook du repo conserve dans la copie" grep -q pwned "$D2/.claude/settings.json"
expect "settings de la copie incomplets" quiet python3 "$FLEET/scripts/fleet_settings.py" check "$D2/.claude/settings.json"
refuse ".mcp.json du repo laisse dans la copie" test -e "$D2/.mcp.json"
expect "quarantaine absente" test -f "$D2/.git/sweep-quarantine/.mcp.json"

S3="$WORK/source-symclaude"; new_repo "$S3"; mkdir -p "$WORK/outside-claude"
echo "{}" > "$WORK/outside-claude/settings.json"
ln -s "$WORK/outside-claude" "$S3/.claude"
git -C "$S3" add -A
git -C "$S3" -c user.name=t -c user.email=t@example.invalid commit -q -m sym
refuse "copie avec .claude en lien acceptee" quiet "$FLEET/scripts/prepare_sweep_clone.sh" "$S3" "$WORK/sweep-sym"
expect "fichier hors repo deplace par la quarantaine" test -f "$WORK/outside-claude/settings.json"

# 7. Copie jetable : pas de .env, pas de remote, pas d'identifiants, flotte en place,
#    .claude/ ignore par git, source intacte, hook actif, push impossible.
S="$WORK/source"; new_repo "$S"; echo "SECRET=1" > "$S/.env"
git -C "$S" remote add origin https://example.invalid/org/product.git
D="$WORK/sweep-clone"
expect "prepare_sweep_clone" quiet "$FLEET/scripts/prepare_sweep_clone.sh" "$S" "$D"
refuse "copie jetable : .env copie" test -e "$D/.env"
expect "copie jetable : remote present" no_remote "$D"
expect "copie jetable : credential.helper non neutralise" helper_reset "$D"
expect "copie jetable : flotte absente" test -f "$D/.claude/hooks/block_push.py"
expect "copie jetable : .claude/ non ignore" clean_status "$D"
expect "source modifiee" source_intact "$S"
expect "sweep-source absent" grep -q '^commit: ' "$D/.git/sweep-source"
refuse "destination existante ecrasee" quiet "$FLEET/scripts/prepare_sweep_clone.sh" "$S" "$D"
expect "hook installe : git push non bloque" hook_blocks_push "$D"
refuse "copie jetable : push possible" quiet git -C "$D" push origin main

if [ "$FAILS" -ne 0 ]; then
  echo "ECHEC test_install: $FAILS controle(s) en echec, $PASSES reussi(s)."
  exit 1
fi
echo "OK test_install: $PASSES controles (installation, copie vivante, settings, manifeste, liens, copie jetable)."
