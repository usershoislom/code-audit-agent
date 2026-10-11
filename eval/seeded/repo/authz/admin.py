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


@app.route("/admin/users")
@admin_required
def admin_users():
    return {"users": get_db().execute("SELECT id, email FROM users").fetchall()}


@app.route("/admin/users/<int:uid>/disable", methods=["POST"])
@admin_required
def admin_disable(uid):
    get_db().execute("UPDATE users SET active = 0 WHERE id = ?", (uid,))
    return {"ok": True}


@app.route("/admin/export")
def admin_export():
    rows = get_db().execute("SELECT id, email, password_hash FROM users").fetchall()
    return {"dump": rows}
