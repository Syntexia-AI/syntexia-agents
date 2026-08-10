# FINDINGS : squelette d'une entrée

Les findings machine suivent `findings.schema.json`. Cette fiche est la version lisible d'une entrée, alignée sur les champs requis du schéma :

    id: <AGENT-NNN, ex. AUTHZ-003>
    title: <titre court et factuel>
    category: <secret | dependency | sast | authz | api | llm | resilience | infra | injection>
    severity: <P0 | P1 | P2 | P3>
    confidence: <high | medium | low>
    file: <chemin/du/fichier>
    line: <numéro ou null>
    cwe: <CWE-XXX ou null>          # optionnel
    evidence: <extrait minimal ou sortie de scan, secrets caviardés>
    impact: <scénario concret en une phrase>
    fix_hint: <correction proposée, sobre et éprouvée>
    verified: <true | false>
    status: <OPEN | FIXED | NEEDS-HUMAN>
    correlation_tags: [<vocabulaire contrôlé>]   # optionnel, pilote l'escalade
    asvs_refs: [<Vx.y.z>]                          # optionnel, alimente la matrice ASVS
    occurrences: [{file, line}]                    # optionnel, mêmes patterns regroupés

## Définition des sévérités

- P0 : exploitable maintenant ou exposition de données.
- P1 : exploitable sous conditions.
- P2 : durcissement.
- P3 : hygiène.

## Tags de corrélation

Pilotent l'escalade (`consolidate_findings.py`) : `scope-touches-exposed-route`, `unauth-inbound-channel`, `reaches-tool-side-effects`, `missing-tenant-filter`, `reachable-from-surface`. Informationnels seulement : `history-only`, `dummy-suspected`.
