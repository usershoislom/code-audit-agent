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


@app.route("/api/invoices/<int:invoice_id>/pdf")
@login_required
def invoice_pdf(invoice_id):
    row = get_db().execute("SELECT owner_id, pdf FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    if row is None or row[0] != g.user_id:
        abort(404)
    return row[1]


@app.route("/api/invoices/<int:invoice_id>")
@login_required
def invoice_json(invoice_id):
    row = get_db().execute("SELECT id, amount, customer FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    return {"invoice": row}
