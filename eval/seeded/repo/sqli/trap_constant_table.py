import sqlite3

from flask import Flask, abort, request

app = Flask(__name__)


def get_db():
    return sqlite3.connect("app.db")

TABLE = "audit_events"


@app.route("/audit/count")
def audit_count():
    cur = get_db().cursor()
    cur.execute(f"SELECT count(*) FROM {TABLE}")
    return {"count": cur.fetchone()[0]}
