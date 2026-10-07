import sqlite3

from flask import Flask

app = Flask(__name__)


@app.route("/catalog/<int:item_id>")
def catalog_item(item_id):
    row = sqlite3.connect("app.db").execute("SELECT id, title, price FROM catalog WHERE id = ?", (item_id,)).fetchone()
    return {"item": row}


@app.route("/catalog")
def catalog():
    return {"items": sqlite3.connect("app.db").execute("SELECT id, title FROM catalog").fetchall()}
