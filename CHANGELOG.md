# CHANGELOG : flotte syntexia-agents

Format : entrées datées, plus récent en haut. Toute évolution d'agent ou de politique passe par une PR et une entrée ici.

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
