import sqlite3

from flask import Flask, abort, request

app = Flask(__name__)


def get_db():
    return sqlite3.connect("app.db")

ALLOWED_DIRECTIONS = ("asc", "desc")


@app.route("/customers")
def customers():
    direction = request.args.get("dir", "asc")
    if direction not in ALLOWED_DIRECTIONS:
        abort(400)
    cur = get_db().cursor()
    cur.execute(f"SELECT id, name FROM customers ORDER BY name {direction}")
    return {"rows": cur.fetchall()}
