import sqlite3

from flask import Flask, abort, request

app = Flask(__name__)


def get_db():
    return sqlite3.connect("app.db")


@app.route("/invoices/page")
def invoice_page():
    page = int(request.args.get("page", "1"))
    offset = (page - 1) * 20
    cur = get_db().cursor()
    cur.execute(f"SELECT id FROM invoices ORDER BY id LIMIT 20 OFFSET {offset}")
    return {"rows": cur.fetchall()}
