"""Configuration. Contient des secrets en dur : faille delibiree (temoin)."""

# FIXTURE: fausse cle, ne jamais utiliser. Faille: secret en dur au lieu d'env.
ANTHROPIC_API_KEY = "sk-ant-FIXTURE0000000000000000000000000000000000000000"

# FIXTURE: cle d'exemple canonique AWS, publiquement documentee comme factice.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Faille: connexion avec identifiants en clair dans l'URL.
DATABASE_URL = "postgresql://admin:changeme@localhost:5432/app"

# Faille: secret de signature webhook vide, donc verification desactivable.
WEBHOOK_SECRET = ""

# Faille: table d'utilisateurs avec mots de passe en dur (valeurs FIXTURE).
LOCAL_USERS = {
    "alice": "FIXTURE-alice-pass",
    "bob": "FIXTURE-bob-pass",
}
