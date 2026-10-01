"""Assistant vocal. Injection de prompt et agence excessive : failles temoin."""
import anthropic

from config import ANTHROPIC_API_KEY

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

TOOLS = [
    {"name": "cancel_booking", "description": "Annule une reservation"},
    {"name": "send_sms", "description": "Envoie un SMS au client"},
    # Faille llm: numero de destination choisi par le modele (fraude au transfert).
    {"name": "transfer_call", "description": "Transfere l'appel vers le numero indique"},
]


def handle_call(transcribed_speech):
    # Faille llm: texte transcrit non fiable injecte directement dans le prompt,
    # modele avec outils a effets externes (annulation, SMS) sans confinement ni
    # confirmation deterministe. Aucune borne de tours ni de cout.
    while True:
        resp = client.messages.create(
            model="claude-sonnet-5",
            max_tokens=1024,
            tools=TOOLS,
            messages=[{"role": "user", "content": transcribed_speech}],
        )
        for block in resp.content:
            if getattr(block, "type", None) == "tool_use":
                execute_tool(block.name, block.input)
        if resp.stop_reason != "tool_use":
            break


def execute_tool(name, args):
    # Faille llm: le modele decide seul d'executer un changement d'etat externe.
    return {"name": name, "args": args}
