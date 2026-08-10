# FINDINGS : squelette d'une entrée

Chaque finding produit par un agent de la flotte suit ce format, un bloc par finding :

    id: <AGENT-NNN, ex. AUTHZ-003>
    title: <titre court et factuel>
    severity: <P0 | P1 | P2 | P3>
    confidence: <high | medium | low>
    file: <chemin/du/fichier>
    line: <numéro>
    evidence: <extrait minimal ou sortie de scan, secrets caviardés>
    impact: <scénario concret en une phrase>
    fix_hint: <correction proposée, sobre et éprouvée>
    verified: <true | false>
    status: <OPEN | FIXED | NEEDS-HUMAN>

## Définition des sévérités

- P0 : exploitable maintenant ou exposition de données.
- P1 : exploitable sous conditions.
- P2 : durcissement.
- P3 : hygiène.
