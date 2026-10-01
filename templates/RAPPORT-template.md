# Rapport de passe securite : <repo> : <date>

## Perimetre et mode
<repo, commit de depart (.git/sweep-source), mode full/light, agents executes, FLEET_VERSION>

## Barrieres verifiees en Phase 0
<canari deny (session et sous-agent), canari hook (session et sous-agent), environnement de session (GIT_CONFIG_GLOBAL, GIT_SSH_COMMAND), copie jetable (remote, fichiers de secrets), zone de travail /tmp/sweep vide au depart et marqueur de passe ecrit, bac a sable actif ou non, outillage manquant>

## FAIT
<liste, chaque ligne avec pointeur de preuve : fichier, ligne, commit, sortie de scan>

## NON FAIT
<liste, chaque ligne avec raison>

## NON VERIFIE
<liste, chaque ligne avec ce qui serait necessaire pour verifier>

## Findings par severite
<P0/P1/P2/P3 : ouverts, corriges, needs-human>

## Matrice ASVS 5.0 (niveau L2 par defaut)

> Triage interne, pas un audit. Verdicts non verifie par defaut. A completer par un pentest externe.

<voir fichier asvs-matrix.csv du meme dossier, genere par generate_asvs_matrix.py>

## Ecarts d'agents
<erreurs d'entree de la consolidation (findings rejetes), ids renommes, caviardages (ids des findings qui contenaient un secret en clair, jamais les valeurs)>

## Actions humaines requises
<branche a rapatrier et PR a ouvrir, secrets a faire tourner (y compris tout secret ecrit en dur lu par les agents), decisions en attente>
