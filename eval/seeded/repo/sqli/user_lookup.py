import sqlite3

from flask import Flask, abort, request

app = Flask(__name__)


def get_db():
    return sqlite3.connect("app.db")


@app.route("/users/search")
def search_users():
    name = request.args.get("name", "")
    cur = get_db().cursor()
    cur.execute(f"SELECT id, email FROM users WHERE name = '{name}'")
    return {"rows": cur.fetchall()}
