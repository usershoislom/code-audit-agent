import functools
import sqlite3

from flask import Flask, abort, g, request, session

app = Flask(__name__)
app.secret_key = __import__("os").environ["APP_SECRET"]


def get_db():
    return sqlite3.connect("app.db")


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            abort(401)
        g.user_id = session["user_id"]
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.route("/notes")
@login_required
def list_notes():
    rows = get_db().execute("SELECT id, title FROM notes WHERE owner_id = ?", (session["user_id"],)).fetchall()
    return {"notes": rows}


@app.route("/notes/<int:note_id>")
@login_required
def view_note(note_id):
    row = get_db().execute("SELECT id, owner_id, body FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None or row[1] != session["user_id"]:
        abort(404)
    return {"id": row[0], "body": row[2]}


@app.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def delete_note(note_id):
    db = get_db()
    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    return {"deleted": note_id}
