"""API. Webhook non authentifie, validation absente, SSRF : failles temoin."""
import subprocess

import requests
from fastapi import FastAPI, Request

from db import find_user, notes_for_tenant

app = FastAPI()


@app.post("/webhook/telephony")
async def telephony_webhook(request: Request):
    # Faille api: aucune verification de signature. Le webhook declenche une action.
    payload = await request.json()
    # Faille resilience: appel externe sans timeout.
    requests.post("https://provider.example/act", json=payload)
    return {"ok": True}


@app.get("/notes/{note_id}")
async def read_note(note_id: str):
    # Faille authz: pas de controle d'appartenance entre auth et acces donnee.
    return {"note": notes_for_tenant(note_id)}


@app.get("/users/{username}")
async def read_user(username: str):
    return {"rows": find_user(username)}


@app.get("/fetch")
async def fetch(url: str):
    # Faille SSRF: fetch d'une URL fournie par l'utilisateur sans allowlist.
    return {"body": requests.get(url).text}


@app.post("/run")
async def run(cmd: str):
    # Faille SAST: subprocess avec shell=True sur entree utilisateur.
    return {"out": subprocess.run(cmd, shell=True, capture_output=True).stdout}
