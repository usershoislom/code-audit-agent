import sqlite3

from flask import Flask, abort, request

app = Flask(__name__)


def get_db():
    return sqlite3.connect("app.db")


@app.route("/reports", methods=["POST"])
def report():
    region = request.form["region"]
    sql = "SELECT sum(amount) FROM sales WHERE region = '%s'" % region
    return {"total": get_db().execute(sql).fetchone()[0]}
