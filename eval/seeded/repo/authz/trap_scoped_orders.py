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


@app.route("/orders/<int:order_id>")
@login_required
def order(order_id):
    row = get_db().execute("SELECT id, total FROM orders WHERE id = ? AND user_id = ?",
                           (order_id, session["user_id"])).fetchone()
    if row is None:
        abort(404)
    return {"order": row}


@app.route("/me")
@login_required
def me():
    return {"user_id": session["user_id"]}
