# PLAYBOOK : flotte syntexia-agents

Mis à jour le 2026-08-10 (v0.2). Toute évolution de ce document ou d'un agent passe par une PR sur ce repo (section 7). Historique : `CHANGELOG.md`.

## 1. Objet

Flotte d'agents Claude Code pour la passe sécurité et robustesse pré-livraison des produits Syntexia.

Ce que la flotte garantit :
- le passage au crible systématique de classes de failles connues (secrets exposés, dépendances vulnérables, défauts d'isolation multi-tenant, webhooks non authentifiés, risques spécifiques LLM, défauts de robustesse, configuration d'infrastructure) : chaque classe est recherchée, puis corrigée quand elle est trouvée ou explicitement documentée, jamais silencieusement ignorée ;
- des preuves pour tout ce qui a été vérifié : chaque affirmation pointe vers un fichier, une ligne, une sortie de scan ;
- la documentation explicite de tout le reste, marqué NON VERIFIE.

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

    ./install.sh /chemin/du/repo

L'installateur synchronise par manifeste : il supprime les fichiers déposés par une installation précédente de la flotte (et eux seuls), copie la version courante, et écrit `.claude/FLEET_VERSION` (SHA du commit flotte + date). Les fichiers `.claude/` propres au repo produit sont préservés.

Après installation, deux vérifications :
1. `.claude/` est versionné dans le repo cible.
2. Un `FACTS.md` existe à la racine du repo produit. C'est la source de vérité client unique. La flotte n'embarque aucun contexte client : tout nom, chiffre ou engagement client vit dans le `FACTS.md` du repo produit.

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

Note de syntaxe : depuis gitleaks 8.19, `detect` est déprécié. Historique : `gitleaks git .` ; arbre de travail seul : `gitleaks dir .`. Les agents utilisent la syntaxe moderne avec repli sur `detect` si la version installée est antérieure.

Jeu de règles SAST : par défaut, `sast-triager` utilise le jeu de règles intégré du scanner (opengrep/semgrep en mode auto, `--config auto` pour semgrep). Pour imposer un jeu de règles spécifique à un run, définir ici la ligne `sast_ruleset: <chemin ou identifiant>` ; en son absence, le défaut du scanner s'applique et l'agent le consigne comme tel. Aucun jeu de règles propriétaire n'est embarqué dans la flotte.

Versions constatées, à figer ici à la première installation :

- gitleaks : à compléter
- trufflehog : à compléter
- trivy : à compléter
- opengrep ou semgrep : à compléter
- bandit : à compléter
- pip-audit : à compléter

## 5. Protocole de run

- Un seul repo client à la fois. Jamais deux contextes clients dans une même session.
- Mode `full` avant toute livraison client, sur le modèle le plus fort disponible.
- Mode `light` (secrets et dépendances uniquement) en passe hebdomadaire, sur un modèle intermédiaire pour préserver les crédits.
- Les deux gates sont des décisions humaines. GATE A avant les fixes : réponses exactes attendues `GO FIXES ALL`, `GO FIXES <ids>` ou `STOP`. GATE B avant le rapport : `GO RAPPORT` ou `STOP`. L'orchestrateur n'avance pas sans une de ces réponses.
- Findings au format machine : chaque agent d'analyse (les 9 agents lecture seule) retourne comme dernier bloc de son message un objet JSON conforme à `.claude/templates/findings.schema.json`, que l'orchestrateur persiste dans `/tmp/sweep/agents/<agent>.json` (les 3 agents producteurs utilisent des contrats en prose). La déduplication et les trois règles de corrélation sont appliquées par `consolidate_findings.py --in /tmp/sweep/agents`, pas par lecture de prose. Les règles sont donc testables (`--self-test`, exécuté en CI).
- Matrice ASVS : générée par `generate_asvs_matrix.py` depuis le CSV de référence et le JSON consolidé. Niveau par défaut : **L2** (les clients entreprise attendent L2 ; L1 reste disponible par option). Verdict par défaut : `non verifie`. Le script ne remplit `conforme` ou `non conforme` que sur pointeur de preuve explicite ; aucun modèle ne remplit la matrice ligne à ligne.

### Vérification live des secrets : décision explicite obligatoire

Par défaut, trufflehog tourne avec `--no-verification`. La vérification live envoie chaque secret candidat aux API des fournisseurs concernés pour tester sa validité : c'est une exfiltration délibérée de secrets potentiels d'un repo client vers des tiers. Règle :

- Désactivée par défaut, sur tous les repos.
- Activation uniquement par décision humaine écrite dans le `FACTS.md` du repo produit, ligne exacte : `verification_live_secrets: autorisee`.
- Interdite sur tout repo couvert par un engagement de zero data retention ou de résidence des données, quelle que soit la ligne du FACTS.md.
- Sans vérification live, un secret trouvé est traité P1 minimum avec rotation obligatoire : l'absence de confirmation ne diminue jamais la sévérité d'un secret plausible.

## 6. Après le run

1. Revue humaine de la branche `security-sweep/<date>`.
2. Ouverture de la PR par l'humain uniquement. La flotte ne pushe jamais.
3. Rotation par l'humain de tout secret signalé, chez le fournisseur concerné.
4. Arbitrage des items NEEDS-HUMAN.
5. Archivage du dossier `docs/security/<date>/` du repo produit. Le rapport mentionne le `FLEET_VERSION` utilisé : chaque rapport est traçable au commit de flotte qui l'a produit.

## 7. Maintenance de la flotte

- Toute évolution d'agent passe par une PR sur ce repo, jamais par une édition directe dans un repo produit.
- `CHANGELOG.md` tenu à chaque évolution.
- Pas de fork local silencieux dans les repos produits : pour resynchroniser, réinstaller via `install.sh` (la synchronisation par manifeste purge les fichiers flotte obsolètes).
- Après toute évolution d'agent : mesurer le rappel sur le repo témoin (section 9) avant de considérer l'évolution comme une amélioration.

## 8. Modèle d'enforcement : ce qui est appliqué, ce qui est demandé

Appliqué techniquement (résiste à un agent qui déraille) :
- `permissions.deny` dans `.claude/settings.json` : refus au niveau du harnais des commandes push, merge, PR et destructives. C'est la barrière primaire.
- Hook PreToolUse `block_push.py` : parseur fail-closed en défense en profondeur (wrappers, chaînages, sous-shells, alias git, commandes destructives).
- `validate_fleet.py` en CI : structure de la flotte, outils par rôle, comportement du hook.
- Les deux gates humains de `/security-sweep`.

Demandé par prompt (ne résiste pas à une injection ciblée) :
- Les règles read-only et untrusted-content des agents.
- Les contrats de sortie.

Limites connues et assumées du hook : il parse une ligne de commande, il ne peut pas voir un `bash script.sh` dont le contenu contient un push, un `xargs git` alimenté par stdin, un `make deploy` ou un alias shell défini hors de la commande. Contre un modèle qui déraille, il tient. Contre une injection ciblée dans un repo client, la protection réelle est la combinaison permissions.deny + gates humains + revue de branche. Ne jamais vendre le hook comme une garantie.

## 9. Repo témoin et mesure de rappel

`fixtures/vulnerable-app/` contient une application volontairement vulnérable avec un fichier d'attendus (`expected_findings.json`). Protocole :

1. `./scripts/make_fixture_repo.sh /tmp/fixture-repo` : matérialise le témoin en repo git autonome, avec un secret planté dans l'historique puis retiré (test du scan d'historique).
2. Installer la flotte dessus, lancer `/security-sweep full`.
3. `python scripts/measure_recall.py --expected fixtures/vulnerable-app/expected_findings.json --consolidated /tmp/sweep/consolidated.json` : rappel global, rappel par catégorie, liste des manqués.

Toute modification d'agent qui fait baisser le rappel est une régression, pas une opinion. Les identifiants du témoin sont des valeurs d'exemple documentées comme fausses (clés d'exemple AWS, préfixes FIXTURE) ; les greps d'hygiène du repo flotte excluent `fixtures/`.

## 10. Confidentialité du repo flotte

Ce repo est privé et doit le rester : la section 2 décrit des politiques internes et le témoin décrit des classes de failles recherchées. Incident du 2026-08-10 : le repo a été trouvé public après une création vérifiée privée ; repassé privé le jour même, cause du basculement à établir via l'audit log de l'org (`CHANGELOG.md`). Conséquence permanente : vérification de visibilité par deux canaux après toute opération d'administration, et aucun contenu dans ce repo dont la publication serait dommageable au-delà de la méthodologie.
