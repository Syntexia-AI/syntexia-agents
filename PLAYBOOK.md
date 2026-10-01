# PLAYBOOK : flotte syntexia-agents

Mis à jour le 2026-10-01 (v0.4.1). Toute évolution de ce document ou d'un agent passe par une PR sur ce repo (section 7). Historique : `CHANGELOG.md`.

## 1. Objet

Flotte d'agents Claude Code pour la passe sécurité et robustesse pré-livraison des produits Syntexia.

Ce que la flotte garantit :
- le passage au crible systématique de classes de failles connues (secrets exposés, dépendances vulnérables, défauts d'isolation multi-tenant, webhooks non authentifiés, risques spécifiques LLM, défauts de robustesse, configuration d'infrastructure) : chaque classe est recherchée, puis corrigée quand elle est trouvée ou explicitement documentée, jamais silencieusement ignorée ;
- des preuves pour tout ce qui a été vérifié : chaque affirmation pointe vers un fichier, une ligne, une sortie de scan ;
- la documentation explicite de tout le reste, marqué NON VERIFIE ;
- qu'aucune valeur de secret ne sort des agents vers les findings, le rapport ou les commits (section 11).

Ce qu'elle ne garantit pas : l'absence de failles. Pour le volet contractuel client, s'appuyer sur la matrice ASVS produite par script (section 5), complétée par un pentest externe.

La distinction entre ce que la flotte applique techniquement et ce qu'elle demande aux agents est documentée en section 8. Ne jamais présenter l'un pour l'autre.

## 2. Hygiène org : politiques permanentes

Ces règles sont des politiques de fonctionnement de l'org, à faire respecter en continu et à revalider à chaque changement d'équipe ou d'outillage :

- 2FA obligatoire pour tout membre de l'org GitHub.
- Politique PAT : fine-grained PAT limités à l'org et au périmètre minimal, revus trimestriellement. Aucun PAT classique à scope large.
- Politique de rotation : tout secret signalé par une passe est tourné chez le fournisseur avant clôture du finding. La rotation est le correctif ; une réécriture d'historique seule ne suffit jamais.
- Épinglage par SHA de commit complet de toutes les GitHub Actions. Un tag est mutable, un SHA ne l'est pas. Incident de référence : compromission de `tj-actions/changed-files` par détournement des tags v1 à v45, mars 2025, CVE-2025-30066, exfiltration de secrets CI dans plus de 23 000 repos. Sources : https://github.com/advisories/GHSA-mrrh-fwg8-r2c3 et https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction
- Scanners installés depuis les releases officielles en binaire, jamais via des tags d'actions mutables.
- Visibilité des repos : tout repo de l'org est privé par défaut. Après toute création ou opération d'administration, vérifier la visibilité par deux canaux : `gh api repos/<org>/<repo> --jq .private` (attendu `true`) et une requête non authentifiée (attendu 404). Voir section 10.

## 3. Installation dans un repo produit

Chemin recommandé : une copie jetable, jamais la copie de travail d'un serveur ni celle du développeur.

    ./scripts/prepare_sweep_clone.sh <repo source : chemin ou URL> /tmp/sweep-<nom> [branche]

Le script clone sans les fichiers non suivis (aucun `.env`, aucune clé), supprime tout remote, neutralise l'assistant d'identifiants git et les hooks git, fixe une identité git locale (`FLEET_GIT_NAME`, `FLEET_GIT_EMAIL`), exclut `.claude/` des commits, écrit `.git/sweep-source` (source et commit de départ) puis installe la flotte. Le repo source n'est jamais modifié. Cloner depuis le chemin d'un serveur de production est sans risque : c'est une lecture.

Installation directe (repo déjà propre) :

    ./install.sh [--merge-settings] [--allow-live-checkout] /chemin/du/repo

L'installateur :
- refuse une copie de travail vivante (fichiers de secrets non suivis présents, listés fichier par fichier, y compris dans les dossiers ignorés ou non suivis) sauf `--allow-live-checkout` ;
- refuse tout lien symbolique sur le chemin d'installation (le repo scanné est une donnée non fiable) ;
- contrôle un `.claude/settings.json` existant en JSON (deny, env de session, verrou bypass, hook) et refuse s'il est incomplet, sauf `--merge-settings` qui fusionne avec sauvegarde horodatée ;
- synchronise par manifeste : il supprime les fichiers déposés par une installation précédente (et eux seuls, chemins validés sous `.claude/`), copie la version courante et écrit `.claude/FLEET_VERSION` (SHA du commit flotte, présence de modifications non commitées, date).

Après installation : un `FACTS.md` existe à la racine du repo produit. C'est la source de vérité client unique. La flotte n'embarque aucun contexte client : tout nom, chiffre ou engagement client vit dans le `FACTS.md` du repo produit.

## 4. Outillage requis sur la machine de run

`scripts/preflight_tooling.py` (livré dans `.claude/scripts/`) vérifie la présence et la version de chaque outil et écrit un rapport de capacités que l'orchestrateur lit en Phase 0 : toute absence devient une dégradation annoncée, jamais silencieuse.

| Outil | Rôle | Installation officielle |
|---|---|---|
| gitleaks | secrets (arbre + historique) | binaire depuis https://github.com/gitleaks/gitleaks/releases |
| trufflehog | secrets, détection large | binaire depuis https://github.com/trufflesecurity/trufflehog/releases |
| trivy (CLI) | CVE, images de base, misconfig | binaire depuis https://github.com/aquasecurity/trivy/releases |
| opengrep (préféré) ou semgrep CE | SAST | opengrep : binaire depuis https://github.com/opengrep/opengrep/releases · semgrep CE : `pip install semgrep` |
| bandit | SAST Python | `pip install bandit` |
| pip-audit | CVE dépendances Python | `pip install pip-audit` |
| bubblewrap, socat (Linux) | bac à sable Claude Code (section 5) | paquets de la distribution |
| python3 >= 3.8 | hook et scripts de la flotte | distribution (Ubuntu 22.04 : 3.10) |

Ces installations sont faites par un humain avant la passe : les agents ne peuvent rien installer.

Notes de syntaxe et de réseau :
- gitleaks : depuis 8.19, `detect` est déprécié. Historique : `gitleaks git .` ; arbre seul : `gitleaks dir .`. Les agents utilisent la syntaxe moderne avec repli sur `detect` si la version est antérieure.
- trufflehog : toujours `--no-update` (sinon il vérifie et télécharge ses propres mises à jour pendant la passe) et `--no-verification` (section 5).
- semgrep : toujours `--metrics=off` (aussi imposé par `SEMGREP_SEND_METRICS=off` dans l'environnement de session). `--config auto` interroge le registre Semgrep à chaque run : à proscrire sous engagement zero data retention.
- pip-audit, npm audit et trivy interrogent des bases publiques de vulnérabilités : noms et versions de paquets sortent de la machine, jamais le code.

Jeu de règles SAST : par défaut, `sast-triager` utilise le jeu de règles intégré du scanner. Pour imposer un jeu de règles à un run (obligatoire sous zero data retention), définir ici la ligne `sast_ruleset: <chemin ou identifiant>` ; en son absence, le défaut du scanner s'applique et l'agent le consigne. Aucun jeu de règles propriétaire n'est embarqué dans la flotte.

Versions constatées, à figer ici à la première installation :

- gitleaks : à compléter
- trufflehog : à compléter
- trivy : à compléter
- opengrep ou semgrep : à compléter
- bandit : à compléter
- pip-audit : à compléter

## 5. Protocole de run

- Un seul repo client à la fois. Jamais deux contextes clients dans une même session.
- Une seule passe à la fois par machine. `/tmp/sweep` est la zone de travail de toutes les passes : il doit être absent ou vide au départ, sinon la Phase 0 s'arrête (les fichiers d'une passe précédente, peut-être d'un autre client, se mélangeraient à la nouvelle). `prepare_sweep_clone.sh` le signale. Il est supprimé après chaque passe (section 6).
- Toujours dans une copie jetable (section 3). Jamais dans une copie de travail qui contient des secrets ni sur un chemin de production.
- Lancer `claude` depuis la racine de la copie. Bac à sable recommandé dès que bubblewrap et socat sont installés : `claude --settings .claude/settings.sandbox.json`. Vérifier avec `/sandbox` au premier usage sur une machine ; ajuster `network.allowedDomains` si un scanner signale un domaine refusé. Le fichier impose `failIfUnavailable` : sans ses dépendances, le bac à sable échoue franchement au lieu de laisser les commandes tourner sans isolation.
- Jamais `--dangerously-skip-permissions` : le mode bypass est désactivé par `permissions.disableBypassPermissionsMode` dans les settings de la flotte.
- Mode `full` avant toute livraison client, sur le modèle le plus fort disponible. Mode `light` (secrets et dépendances) en passe hebdomadaire.
- Phase 0 : l'orchestrateur vérifie les barrières en conditions réelles avant toute analyse. Deux canaris (`echo FLEET_DENY_CANARY` doit être refusé par les règles deny, `echo FLEET_HOOK_CANARY` par le hook), l'environnement de session (`GIT_CONFIG_GLOBAL=/dev/null`, `GIT_SSH_COMMAND=false`), l'absence de remote et de fichiers de secrets, une zone de travail `/tmp/sweep` vide. Il écrit ensuite le marqueur de passe `/tmp/sweep/RUN.json` (repo et commit). `recon-inventory` refait les deux canaris depuis un sous-agent. Un canari qui passe arrête la passe.
- Les deux gates sont des décisions humaines. GATE A avant les fixes : réponses exactes attendues `GO FIXES ALL`, `GO FIXES <ids>` ou `STOP`. GATE B avant le rapport : `GO RAPPORT` ou `STOP`. L'orchestrateur n'avance pas sans une de ces réponses.
- Findings au format machine : chaque agent d'analyse (les 9 agents lecture seule) retourne comme dernier bloc de son message un objet JSON conforme à `.claude/templates/findings.schema.json`, que l'orchestrateur persiste avec l'outil Write dans `/tmp/sweep/agents/<agent>.json`. `consolidate_findings.py --in /tmp/sweep/agents --run-marker /tmp/sweep/RUN.json` écarte tout fichier d'agent antérieur au marqueur de passe et s'arrête si le marqueur manque ou désigne un autre repo. Il déduplique, applique les trois règles de corrélation, rejette un finding malformé sans perdre les autres, rend les ids uniques et caviarde tout secret resté dans un finding. Ses règles sont testables (`--self-test`, exécuté en CI).
- Matrice ASVS : générée par `generate_asvs_matrix.py` depuis le CSV de référence et le JSON consolidé. Niveau par défaut : **L2**. Verdict par défaut : `non verifie`. Le script ne remplit `conforme` ou `non conforme` que sur pointeur de preuve explicite ; aucun modèle ne remplit la matrice ligne à ligne.

### Vérification live des secrets : décision explicite obligatoire

Par défaut, trufflehog tourne avec `--no-verification`. La vérification live envoie chaque secret candidat aux API des fournisseurs concernés pour tester sa validité : c'est une exfiltration délibérée de secrets potentiels d'un repo client vers des tiers. Règle :

- Désactivée par défaut, sur tous les repos.
- Activation uniquement par décision humaine écrite dans le `FACTS.md` du repo produit, ligne exacte : `verification_live_secrets: autorisee`.
- Interdite sur tout repo couvert par un engagement de zero data retention ou de résidence des données, quelle que soit la ligne du FACTS.md.
- Sans vérification live, un secret trouvé est traité P1 minimum avec rotation obligatoire : l'absence de confirmation ne diminue jamais la sévérité d'un secret plausible.

## 6. Après le run

1. Revue humaine de la branche `security-sweep/<date>` dans la copie jetable.
2. Rapatriement depuis le clone habituel, puis PR ouverte par l'humain uniquement :

        git fetch /tmp/sweep-<nom> security-sweep/<date>
        git push origin FETCH_HEAD:refs/heads/security-sweep/<date>

3. Rotation par l'humain de tout secret signalé, chez le fournisseur concerné. Cela inclut tout secret écrit en dur dans le code que les agents ont lu : il a transité par le fournisseur du modèle (section 11).
4. Arbitrage des items NEEDS-HUMAN.
5. Archivage du dossier `docs/security/<date>/` du repo produit. Le rapport mentionne le `FLEET_VERSION` utilisé et le résultat des contrôles de Phase 0.
6. Suppression de la copie jetable et de la zone de travail (`rm -rf /tmp/sweep`) : la passe suivante l'exige vide.

## 7. Maintenance de la flotte

- Toute évolution d'agent passe par une PR sur ce repo, jamais par une édition directe dans un repo produit.
- `CHANGELOG.md` tenu à chaque évolution.
- La CI doit rester verte : `validate_fleet.py`, `test_hook.py` (matrice d'attaques et de commandes légitimes du hook), `test_install.sh` (installateur et copie jetable), les auto-tests de `consolidate_findings.py`, `redacted_secret_scan.py` et `fleet_settings.py`, `hygiene_check.py`, ShellCheck.
- Tout contournement découvert du hook ou des règles deny est d'abord ajouté comme cas dans `scripts/test_hook.py`, puis corrigé. Une commande légitime bloquée à tort aussi.
- Pas de fork local silencieux dans les repos produits : pour resynchroniser, réinstaller via `install.sh` (la synchronisation par manifeste purge les fichiers flotte obsolètes).
- Après toute évolution d'agent : mesurer le rappel sur le repo témoin (section 9) avant de considérer l'évolution comme une amélioration.

## 8. Modèle d'enforcement : ce qui est appliqué, ce qui est demandé

Appliqué techniquement, du plus fort au plus faible :

1. Copie jetable (`prepare_sweep_clone.sh`) : aucun remote, aucun assistant d'identifiants, aucun fichier de secrets non suivi. Un push n'a nulle part où aller et les secrets de l'environnement réel ne sont pas sur le disque. Ne dépend pas du comportement du modèle.
2. Environnement de session (`env` dans `settings.json`) : `GIT_CONFIG_GLOBAL=/dev/null` et `GIT_CONFIG_NOSYSTEM=1` (ni alias globaux, ni assistants d'identifiants, ni réécritures d'URL du poste), `GIT_SSH_COMMAND=false` (aucun transport SSH), `GIT_TERMINAL_PROMPT=0`.
3. Bac à sable optionnel (`settings.sandbox.json`) : isolation réseau et fichiers au niveau du système pour toutes les commandes Bash, domaines autorisés limités aux bases de vulnérabilités, identifiants du poste illisibles, sans échappatoire (`allowUnsandboxedCommands: false`), échec franc si ses dépendances manquent (`failIfUnavailable: true`).
4. `permissions.deny` : refus par le harnais. Tient aussi en mode bypass, lequel est de toute façon désactivé. Limite documentée par Anthropic : les motifs Bash sont des correspondances de chaîne ; `Bash(git push *)` ne couvre pas `git -C . push`. D'où les règles à joker central (`git * push *`, `git * alias.*`, `git -c *`) et l'interdiction totale des outils qui n'ont rien à faire dans une passe (`gh`, `curl`, `ssh`, `aws`, `docker`, `sudo`...). Effet de bord assumé : un message de commit contenant « push » entouré d'espaces est refusé et doit être reformulé.
5. Hook PreToolUse `block_push.py` v4 (Bash, Read, Grep, Edit, Write) : parseur fail-closed qui comprend les wrappers et leurs options, les shells imbriqués, `eval`, les pipes vers un shell, les heredocs, les substitutions, le code en ligne des interpréteurs et les scripts shell sur disque. git limité à une liste blanche (lecture, add, commit, branche locale) ; secrets, environnement, `.claude/`, `.git/` et écritures hors du projet et de `/tmp/sweep` protégés (une racine `/tmp/sweep` en lien symbolique est ignorée : les écritures y sont refusées). Toute erreur interne bloque (Claude Code laisse passer un hook qui sort en code 1 : le script convertit tout en code 2).
6. `validate_fleet.py`, `test_hook.py` et `test_install.sh` en CI.
7. Les deux gates humains de `/security-sweep`.

Demandé par prompt (ne résiste pas à une injection ciblée) :
- Les règles read-only, d'hygiène de sortie et de refus des agents.
- Les contrats de sortie.

Limites connues et assumées :
- Le hook ne voit pas un binaire copié sous un autre nom, ni le code qu'un programme autorisé charge de lui-même : une suite de tests et ses `conftest.py`, un `sitecustomize.py` placé dans le projet et chargé via `PYTHONPATH`, un outil de build dont la cible ne s'appelle pas deploy, release, publish ou push. Ce code peut tout faire dans la limite de l'environnement : seul le bac à sable le borne au niveau du système.
- La protection des fichiers secrets dans Bash est un garde-fou, pas une garantie : un nom de fichier fabriqué par la sortie d'une autre commande ou lu depuis un fichier échappe à l'analyse. La vraie protection est que la copie jetable ne contient aucun secret non suivi, et que le réseau est fermé.
- Claude Code laisse passer l'appel si le hook dépasse son délai : le hook est borné (profondeur, taille des scripts lus) pour rester rapide.
- Sans bac à sable, l'isolation réseau repose sur les règles deny et le hook. La copie jetable reste la barrière contre le push.

Contre une injection ciblée dans un repo client, la protection réelle est la combinaison copie jetable + environnement de session + bac à sable + permissions.deny + gates humains + revue de branche. Ne jamais vendre le hook comme une garantie.

## 9. Repo témoin et mesure de rappel

`fixtures/vulnerable-app/` contient une application volontairement vulnérable avec un fichier d'attendus (`expected_findings.json`). Protocole :

1. `rm -rf /tmp/sweep`, puis `./scripts/make_fixture_repo.sh /tmp/fixture-repo` : matérialise le témoin en repo git autonome, avec un secret planté dans l'historique puis retiré (test du scan d'historique).
2. Installer la flotte dessus, lancer `/security-sweep full`.
3. `python3 scripts/measure_recall.py --expected fixtures/vulnerable-app/expected_findings.json --consolidated /tmp/sweep/consolidated.json` : rappel global, rappel par catégorie, liste des manqués.

Toute modification d'agent qui fait baisser le rappel est une régression, pas une opinion. Les identifiants du témoin sont des valeurs d'exemple documentées comme fausses (clés d'exemple AWS, préfixes FIXTURE) ; les greps d'hygiène du repo flotte excluent `fixtures/`.

## 10. Confidentialité du repo flotte

Ce repo est privé et doit le rester : la section 2 décrit des politiques internes et le témoin décrit des classes de failles recherchées. Incident du 2026-08-10 : le repo a été trouvé public après une création vérifiée privée ; repassé privé le jour même, cause du basculement à établir via l'audit log de l'org (`CHANGELOG.md`). Conséquence permanente : vérification de visibilité par deux canaux après toute opération d'administration, et aucun contenu dans ce repo dont la publication serait dommageable au-delà de la méthodologie.

La liste des noms interdits du contrôle d'hygiène n'est plus écrite en clair : elle est stockée sous forme d'empreintes SHA-256 salées. C'est de l'obscurcissement, pas du secret : un nom deviné peut être confirmé en le hachant, d'où l'obligation de garder le repo privé. Les noms ajoutés hors repo passent par `FLEET_HYGIENE_DENYLIST` (secret de CI) ou `~/.config/syntexia/hygiene-denylist.txt`. Pour ajouter une empreinte au repo : `python3 scripts/hygiene_check.py --hash "<nom>"`.

## 11. Hygiène de sortie : secrets et données personnelles

Un agent qui affiche une ligne de code contenant un secret le fait entrer dans la sortie de l'outil, donc dans le transcript de session, et parfois dans un finding puis dans le rapport commité. Règles :

- Les valeurs de secrets ne se cherchent qu'avec les scanners qui caviardent : gitleaks `--redact`, trufflehog, et `.claude/scripts/redacted_secret_scan.py` (fichier, ligne, règle, longueur, entropie, indicateur de valeur factice, jamais la valeur). Le hook refuse les grep en mode contenu sur des motifs de clés et toute lecture de `.env`, de clés privées, de magasins d'identifiants et de l'environnement du processus.
- `consolidate_findings.py` caviarde tout littéral en forme de secret resté dans un finding avant d'écrire `consolidated.json`, et le signale (`redactions`) : chaque caviardage est un écart d'agent à corriger.
- Aucune donnée personnelle (nom, e-mail, téléphone, NIF, adresse) ni chiffre client dans les findings et le rapport : fichier, ligne et forme seulement.
- Lire du code qui contient un secret écrit en dur l'expose au fournisseur du modèle, et rien ne peut l'empêcher sans renoncer à lire le code. Conséquence : tout secret écrit en dur trouvé par une passe est considéré exposé et tourné, sans exception.
