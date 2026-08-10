"""Acces base. Injection SQL delibiree (temoin)."""
import sqlite3


def get_connection():
    return sqlite3.connect("app.db")


def find_user(username):
    conn = get_connection()
    cur = conn.cursor()
    # Faille SAST: injection SQL par concatenation de chaine.
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cur.execute(query)
    return cur.fetchall()


def notes_for_tenant(note_id):
    conn = get_connection()
    cur = conn.cursor()
    # Faille authz: aucun filtre par tenant, IDOR sur note_id fourni par le client.
    cur.execute("SELECT body FROM notes WHERE id = ?", (note_id,))
    return cur.fetchone()
