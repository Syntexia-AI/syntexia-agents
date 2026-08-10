# PLAYBOOK : flotte syntexia-agents

Mis à jour le 2026-08-10. Toute évolution de ce document ou d'un agent passe par une PR sur ce repo (section 7).

## 1. Objet

Flotte d'agents Claude Code pour la passe sécurité et robustesse pré-livraison des produits Syntexia.

Ce que la flotte garantit :
- l'élimination systématique de classes de failles connues : secrets exposés, dépendances vulnérables, défauts d'isolation multi-tenant, webhooks non authentifiés, risques spécifiques LLM, défauts de robustesse, configuration d'infrastructure ;
- des preuves pour tout ce qui a été vérifié : chaque affirmation pointe vers un fichier, une ligne, une sortie de scan ;
- la documentation explicite de tout le reste, marqué NON VERIFIE.

Ce qu'elle ne garantit pas : l'absence de failles. Pour le volet contractuel client, s'appuyer sur la matrice ASVS produite par le rapport, complétée par un pentest externe.

## 2. Prérequis d'hygiène org (avant tout premier run)

Checklist à traiter une fois, puis à revalider à chaque changement d'équipe ou d'outillage :

- [ ] 2FA obligatoire sur l'org GitHub.
- [ ] Révocation des PAT larges au profit de fine-grained PAT limités à l'org.
- [ ] Rotation de tout secret historique connu comme exposé.
- [ ] Épinglage par SHA de commit complet de toutes les GitHub Actions. Rappel : la vague d'incidents 2026 de détournement de tags sur des actions populaires, y compris des scanners de sécurité, a montré qu'un tag est mutable. Un SHA complet ne l'est pas.
- [ ] Scanners installés depuis les releases officielles en binaire, jamais via des tags d'actions mutables.

## 3. Installation dans un repo produit

    ./install.sh /chemin/du/repo

Puis deux vérifications :
1. `.claude/` est versionné dans le repo cible.
2. Un `FACTS.md` existe à la racine du repo produit. C'est la source de vérité client unique. La flotte n'embarque aucun contexte client : tout nom, chiffre ou engagement client vit dans le `FACTS.md` du repo produit.

## 4. Outillage requis sur la machine de run

| Outil | Rôle | Installation officielle |
|---|---|---|
| gitleaks | secrets (arbre + historique) | binaire depuis https://github.com/gitleaks/gitleaks/releases |
| trufflehog | secrets avec vérification live | binaire depuis https://github.com/trufflesecurity/trufflehog/releases |
| trivy (CLI) | CVE, images de base, misconfig | binaire depuis https://github.com/aquasecurity/trivy/releases |
| opengrep (préféré) ou semgrep CE | SAST | opengrep : binaire depuis https://github.com/opengrep/opengrep/releases · semgrep CE : `pip install semgrep` |
| bandit | SAST Python | `pip install bandit` |
| pip-audit | CVE dépendances Python | `pip install pip-audit` |

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

## 6. Après le run

1. Revue humaine de la branche `security-sweep/<date>`.
2. Ouverture de la PR par l'humain uniquement. La flotte ne pushe jamais.
3. Rotation par l'humain de tout secret signalé, chez le fournisseur concerné. Une réécriture d'historique seule ne suffit jamais.
4. Arbitrage des items NEEDS-HUMAN.
5. Archivage du dossier `docs/security/<date>/` du repo produit.

## 7. Maintenance de la flotte

- Toute évolution d'agent passe par une PR sur ce repo, jamais par une édition directe dans un repo produit.
- Changelog tenu à chaque évolution.
- Pas de fork local silencieux dans les repos produits : pour resynchroniser, réinstaller via `install.sh`.
