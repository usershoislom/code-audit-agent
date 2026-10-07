import sqlite3

from flask import Flask, abort, request

app = Flask(__name__)


def get_db():
    return sqlite3.connect("app.db")


@app.route("/orders")
def list_orders():
    status = request.args.get("status", "open")
    query = "SELECT id, total FROM orders WHERE status = ?"
    cur = get_db().cursor()
    cur.execute(query, (status,))
    return {"rows": cur.fetchall()}
