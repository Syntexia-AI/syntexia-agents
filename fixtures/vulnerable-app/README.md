# vulnerable-app : repo témoin

Application volontairement vulnérable. Sert à mesurer le rappel de la flotte : on
l'installe, on lance `/security-sweep full`, on compare les findings consolidés à
`expected_findings.json` via `scripts/measure_recall.py`.

Tous les identifiants, clés et mots de passe de ce dossier sont FAUX et le
déclarent : clé AWS d'exemple canonique `AKIAIOSFODNN7EXAMPLE`, préfixe
`FIXTURE`, mots de passe `changeme`. Rien ici n'est un secret réel. Les greps
d'hygiène du repo flotte excluent `fixtures/`.

Ne jamais déployer ce code. Il contient des failles délibérées documentées dans
`expected_findings.json`.
