import sqlite3

from flask import Flask, abort, request

app = Flask(__name__)


def get_db():
    return sqlite3.connect("app.db")

SORT_COLUMNS = {"name": "name", "date": "created_at", "total": "amount"}


@app.route("/payments")
def payments():
    key = request.args.get("sort", "date")
    column = SORT_COLUMNS.get(key, "created_at")
    cur = get_db().cursor()
    cur.execute(f"SELECT id, amount FROM payments ORDER BY {column}")
    return {"rows": cur.fetchall()}
