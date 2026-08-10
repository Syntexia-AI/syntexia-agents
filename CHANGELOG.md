# CHANGELOG : flotte syntexia-agents

Format : entrées datées, plus récent en haut. Toute évolution d'agent ou de politique passe par une PR et une entrée ici.

## 2026-08-10 : v0.3 : corrections post-revue adversariale v0.2

Passe adversariale (3 vérificateurs Opus) sur les lots v0.2 : 2 P0, plusieurs P1, corrigés avant tout push.

Bloquants (P0) :
- 5 agents analystes lecture seule (Read/Grep/Glob) étaient sommés d'écrire `/tmp/sweep/<agent>.json` : impossible et interdit par `validate_fleet`. Les agents retournent désormais leur JSON comme dernier bloc de message ; l'orchestrateur le persiste dans `/tmp/sweep/agents/<agent>.json`. Même correction pour recon (contradiction Bash read-only). Le sous-dossier `agents/` isole la consolidation des sorties de scanners et de `tooling.json`.
- `hygiene_check.py` matchait sa propre liste de tokens de contamination : CI rouge en permanence. Son propre chemin est exempté de ce seul contrôle.

Sérieux (P1) :
- `consolidate_findings.py` : R1 masquait R2 dans un `if/elif` (secret sous-évalué de deux niveaux). Les règles s'appliquent maintenant indépendamment, la plus forte gagne. Dédup sur `line` nul fusionnait des findings distincts : discriminé par titre normalisé. Entrées malformées (finding non-objet, `id`/`findings` nuls) : durcies, plus de traceback.
- `measure_recall.py` : `match_tokens` désormais obligatoires (faux 100 % supprimé), expected vide rejeté, matching par égalité de basename + tokens à frontière alphanumérique (fini les faux positifs par sous-chaîne), assignation par couplage biparti maximum (fini les faux échecs CI par affectation gloutonne).
- `install.sh` ne livrait pas `PLAYBOOK.md` (référencé par les agents) : corrigé. Ne livre plus que les scripts d'exécution (consolidate, generate_asvs, preflight), plus les outils de dev de la flotte qui polluaient/crashaient la cible.
- `block_push.py` laissait passer `timeout/nice/stdbuf git push` et `git pull` : strip de wrappers généralisé, `git pull` bloqué. Ajout de `restore`, `stash drop/clear`, `commit --amend`, combos `branch -df/-Df/-f`, `gh api -X DELETE`, séparateur `&`, variantes `zsh/dash/ksh -c`, normalisation `.exe`. Fail-closed sur payload JSON non-objet.

Durcissements (P2/P3) :
- `generate_asvs_matrix.py` : consolidated illisible dégradé proprement (plus de traceback), `asvs_refs` orphelines signalées, verdicts d'evidence-map validés contre le vocabulaire.
- `settings.json` : `permissions.deny` étendu (pull, restore, stash drop/clear, commit --amend).
- `PLAYBOOK` : jeu de règles SAST documenté. `validate_fleet` : assertions FLEET_VERSION/scripts non vacantes, cas destructifs ajoutés au self-test du hook. Cohérence L2 (report-compiler, RAPPORT-template), schéma et FINDINGS-template réalignés, tags informationnels distingués des tags de règle.

## 2026-08-10 : v0.2 : durcissement post-revue

Revue adversariale externe ayant motivé ce lot : distinction appliqué/demandé absente, findings en prose non reproductibles, matrice ASVS hallucinable, pas de repo témoin, installateur qui accumule.

Correctifs de posture et de sécurité :
- Incident de visibilité : le repo, créé et vérifié privé le 2026-08-10 à 22:08, a été constaté public à 22:40 (API et codeload accessibles sans authentification). Repassé privé le jour même, vérifié par deux canaux (`.private=true`, requête non authentifiée en 404). Cause du basculement à établir via l'audit log de l'org. Le PLAYBOOK section 2 est réécrit en politiques permanentes, sans confession publique de secrets exposés. Ajout de `LICENSE` (propriétaire) et de la mention de confidentialité au README.
- Hook `block_push.py` v3 : ajout des commandes destructives (`git reset --hard`, `git rebase`, `git checkout/switch --force`/`-f`, `git branch -D`/`--delete --force`, `git clean -f`, `git remote set-url`/`remove`/`rename`, `git update-ref -d`, `git push` déjà couvert). Parseur inchangé côté fail-closed.
- Barrière primaire : `.claude/settings.json` livré avec un bloc `permissions.deny` couvrant push/merge/PR/destructifs. Le hook devient explicitement de la défense en profondeur, plus une garantie.
- Vérification live des secrets : trufflehog passe en `--no-verification` par défaut. Activation seulement sur décision écrite dans le `FACTS.md` du repo produit, interdite sous engagement zero data retention. Documenté PLAYBOOK section 5.

Manques structurels comblés :
- Format machine des findings : `templates/findings.schema.json`, contrats de sortie des agents mis à jour pour émettre un JSON conforme, `scripts/consolidate_findings.py` (déduplication + trois règles d'escalade + `--self-test`).
- Matrice ASVS par script : `scripts/generate_asvs_matrix.py`, niveau L2 par défaut (L1 en option), verdict `non verifie` par défaut, remplissage sur preuve uniquement, attribution OWASP en tête de matrice.
- Repo témoin : `fixtures/vulnerable-app/` + `expected_findings.json`, `scripts/make_fixture_repo.sh`, `scripts/measure_recall.py`.
- Installateur par manifeste : suppression des fichiers flotte obsolètes avant copie, écriture de `.claude/FLEET_VERSION`.
- `secrets-hunter` passe de haiku à sonnet (juger un dummy est du jugement, un faux négatif sur secret vivant est le pire résultat).
- Épinglage SHA : incident de référence corrigé en CVE-2025-30066 (tj-actions/changed-files, sourcé), en remplacement de la « vague 2026 » non sourçable.

## 2026-08-10 : v0.1 : création

Squelette, 12 agents, commande `/security-sweep`, hook anti-push, installateur, PLAYBOOK, référentiel ASVS 5.0.0, validateur. Voir `git log` W1 à W8-bis.
