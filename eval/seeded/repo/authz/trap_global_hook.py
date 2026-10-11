import sqlite3

from flask import Flask, abort, request, session

app = Flask(__name__)


@app.before_request
def require_login():
    if request.endpoint != "login" and "user_id" not in session:
        abort(401)


@app.route("/login", methods=["POST"])
def login():
    return {"ok": True}


@app.route("/settings")
def settings():
    row = sqlite3.connect("app.db").execute("SELECT theme FROM settings WHERE user_id = ?",
                                            (session["user_id"],)).fetchone()
    return {"settings": row}


@app.route("/settings/theme", methods=["POST"])
def set_theme():
    sqlite3.connect("app.db").execute("UPDATE settings SET theme = ? WHERE user_id = ?",
                                      (request.form["theme"], session["user_id"]))
    return {"ok": True}
