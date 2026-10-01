# CHANGELOG : flotte syntexia-agents

Format : entrées datées, plus récent en haut. Toute évolution d'agent ou de politique passe par une PR et une entrée ici.

## 2026-10-01 : v0.4.1 : isolation des passes et secrets imbriqués

Relecture de la v0.4 avant son premier usage. Chaque défaut a été reproduit, et chaque nouveau test échoue sur le code v0.4.

Sérieux (P1) :
- Mélange de passes dans `/tmp/sweep`, zone de travail commune à toutes les passes et jamais vidée. Les fichiers d'agents d'une passe précédente, peut-être d'un autre client, étaient consolidés dans la passe suivante : en mode light (les agents de Phase 3 ne tournent pas, leurs anciens fichiers restent), ou quand un agent ne renvoyait pas de JSON valide (l'ancien fichier du même nom restait). Démontré : un finding SAST d'une passe A remontait dans la consolidation d'une passe B. Correctif : la Phase 0 s'arrête si `/tmp/sweep` n'est pas absent ou vide, puis écrit le marqueur de passe `/tmp/sweep/RUN.json` (repo, commit). `consolidate_findings.py --run-marker` écarte tout fichier d'agent antérieur au marqueur. Si le marqueur manque, est illisible ou désigne un autre repo, il s'arrête sans rien écrire (code 2). Ses messages ne nomment jamais l'autre repo. `prepare_sweep_clone.sh` signale une zone de travail non vide ou en lien symbolique, et le rapport final rappelle de la supprimer.

Durcissements (P2) :
- `install.sh` : la détection de copie vivante lisait `git status --porcelain --ignored`, qui replie un dossier entièrement non suivi ou ignoré en une seule ligne (`config/`, `secrets/`). Un `config/.env.production` ou un `secrets/server.key` passait donc inaperçu. Démontré. La liste vient désormais de `git ls-files --others`, fichier par fichier. Les dossiers de dépendances installées (`node_modules`, `.venv`, `site-packages`, `vendor`...) sont exclus de cette détection : leurs certificats de test ne sont pas des secrets du checkout. La Phase 0 utilise la même liste.
- Hook : une racine de zone de travail qui est elle-même un lien symbolique est ignorée. Un lien planté à `/tmp/sweep` vers `/` aurait sinon ouvert tout le disque en écriture au hook. Les écritures y sont refusées.
- Tests : 465 cas pour la matrice du hook (lien symbolique et commandes de la nouvelle Phase 0), 56 contrôles d'installation (secrets imbriqués, faux positif des dépendances). Le consolidateur a un auto-test du marqueur, et `validate_fleet.py` exige les étapes d'isolation dans `/security-sweep`.

## 2026-10-01 : v0.4 : durcissement après revue adversariale (contournements reproduits)

Revue adversariale de la v0.3.1. Chaque contournement ci-dessous a été reproduit sur le code, pas supposé.

Bloquants (P0) :
- Hook v3 : 38 commandes dangereuses sur 42 testées passaient. Exemples : `sudo -u <user> git push`, `timeout -s KILL 30 git push`, `env -u X git push`, `git -c alias.p=push p`, `git config remote.origin.url`, `git send-pack`, `git subtree push`, `/usr/lib/git-core/git-push`, `echo push | xargs git`, `echo 'git push' | bash`, `eval`, `echo a#; git push` (le `#` masquait la suite au parseur), `gh api` (création de PR, mise à jour forcée de `main`, écriture de fichier distant), `gh repo edit --visibility public`, `gh secret set`, `aws ssm send-command`, lecture de `.env` vers `/dev/tcp`, `pip install`, `ssh`, `rm -r -f`. Hook v4 réécrit : liste blanche git ; wrappers analysés par arité d'options avec filet de sécurité ; shells imbriqués, heredocs, substitutions, code en ligne des interpréteurs, scripts shell sur disque ; outils réseau, systèmes vivants, élévation de privilèges, installations ; secrets et environnement ; `.claude/` et `.git/` ; écritures confinées au projet et à `/tmp/sweep` ; outils Read, Grep, Edit et Write couverts. Toute erreur interne bloque (Claude Code traite le code 1 comme non bloquant). Puis trois passes de revue adversariale indépendante sur la v4, chaque contournement reproduit avant correction : 10 au premier tour (awk en écriture et en lecture, sed `e` et `w`, perl et ruby `-ne`, fonctions PHP, variables d'environnement git `GIT_EXTERNAL_DIFF` et `GIT_CONFIG_COUNT`, `BASH_ENV`, globs `.en*`, `${!v}`, deno, commandes géantes qui faisaient dépasser le délai du hook), 8 au deuxième (délimiteur sed alphanumérique, `awk -f /dev/stdin`, `PYTHONPATH` et `sitecustomize.py`, `printf -v` et `read`, `node --eval=`, `sort -o`, extraction d'archives, `git apply` qui pouvait réécrire `.claude/`, glob profond qui faisait expirer le hook), 4 au troisième (`ruby -r`, `perl -I`, `openssl -out`, `python -m json.tool`, `go build -o`). Tous corrigés et ajoutés à la matrice : 458 cas en CI (`scripts/test_hook.py`), aucune erreur interne ni dépassement de délai sur 5500 commandes aléatoires, pire cas mesuré 0,3 s.
- `install.sh` : le manifeste, lu dans le repo cible donc donnée non fiable, permettait de supprimer des fichiers hors du repo (`../../`). Démontré. Entrées désormais validées ; liens symboliques sur le chemin d'installation refusés ; fichiers liens remplacés sans écriture au travers.
- `install.sh` : le précontrôle `grep -q 'Bash(git push'` acceptait un settings.json qui AUTORISAIT `git push` (motif dans `allow`) ; la flotte tournait alors sans aucune règle deny. Démontré. Contrôle en JSON par `scripts/fleet_settings.py`, fusion optionnelle avec sauvegarde.

Sérieux (P1) :
- `permissions.deny` : la documentation de Claude Code confirme que `Bash(git push *)` ne couvre pas `git -C . push`. Ajout de règles à joker central et interdiction des outils inutiles à une passe. Lecture des secrets (`Read`), écriture dans `.claude/`, `.git/` et `.env` (`Edit`, `Write`), `WebFetch` et `WebSearch` refusés. Mode bypass désactivé. Canari deny.
- Environnement de session dans settings.json : config git globale et système ignorées (alias, assistants d'identifiants, réécritures d'URL du poste), transport SSH désactivé, aucune invite d'identifiants, métriques semgrep coupées.
- Copie jetable `scripts/prepare_sweep_clone.sh` : clone sans fichiers non suivis, sans remote, sans assistant d'identifiants, `.claude/` exclu des commits ; la configuration Claude fournie par le repo (`.claude/settings.json`, `settings.local.json`, `.mcp.json`) est mise en quarantaine, un `.claude` en lien symbolique est refusé. Refus d'installer dans une copie de travail vivante (fichiers de secrets non suivis, même définition que le hook) ou avec une configuration Claude fournie par le repo.
- Secrets dans les sorties : `scripts/redacted_secret_scan.py` remplace le grep de repli du secrets-hunter, qui affichait les valeurs. Il détecte aussi les JWT service_role et les tables d'identifiants en dur. `consolidate_findings.py` caviarde tout secret resté dans un finding avant écriture.
- Contrôle d'hygiène : la liste des noms interdits était écrite en clair et divulguait les noms qu'elle protège. Remplacée par des empreintes salées, liste étendue, ajouts possibles hors repo (secret de CI, fichier local).
- Phase 0 de `/security-sweep` : canaris deny et hook dans la session et dans un sous-agent, environnement de session, copie jetable. Arrêt au premier échec.

Durcissements (P2/P3) :
- Consolidation : un finding malformé n'efface plus les findings valides du même agent ; ids rendus uniques (GATE A non ambigu) ; champs souples normalisés avec avertissement.
- Agents : règles communes d'hygiène de sortie et de refus ; trufflehog `--no-update` ; semgrep `--metrics=off` et pas de `--config auto` sous zero data retention. Couverture ajoutée : signatures asymétriques et en-têtes secrets des webhooks, flux temps réel, fraude au transfert et destinations libres des outils, magasins de prompts modifiables, plafonds de session, mécanique d'authentification et identifiants partagés, spécificités Supabase et PostgREST, XXE, archives, pickle de cache, cohérence au démarrage.
- infra-reviewer citait encore une « vague 2026 » non sourcée, que la v0.2 annonçait avoir remplacée : corrigé (CVE-2025-30066).
- recon-inventory, dependency-auditor et report-compiler passent de haiku à sonnet : l'inventaire alimente tous les autres agents, la priorisation des CVE demande du jugement, le résumé client est livré.
- Bac à sable optionnel `settings.sandbox.json` : réseau limité aux bases de vulnérabilités, identifiants du poste illisibles, sans échappatoire, échec franc si indisponible.
- Témoin : table d'identifiants en dur et outil de transfert à destination libre (18 attendus).
- `FLEET_VERSION` signale les modifications non commitées de la flotte. CI : matrice du hook, tests d'intégration de l'installateur (53 contrôles), auto-tests, ShellCheck.

## 2026-08-10 : v0.3.1 : corrections post re-vérification

Seconde passe adversariale (2 vérificateurs) confirmant les deux P0 résolus sans régression de sur-blocage. Résidus corrigés :
- `consolidate_findings.py` : fichier agent au contenu JSON scalaire (`null`, `42`) faisait planter `main()` avant `structural_check` (garde `isinstance`). `findings: null` désormais signalé comme erreur d'entrée au lieu d'être lu comme « rien trouvé ».
- `generate_asvs_matrix.py` : consolidated valide mais non-objet (liste/scalaire) et evidence-map malformée ou non-objet dégradent proprement au lieu de tracebacker.
- `block_push.py` : options globales git en deux mots `--config-env` / `--super-prefix` ajoutées au jeu à valeur (sinon `git --config-env x push` passait).
- Résidu de refactor « after writing the file » retiré des 7 contrats d'agents.

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
