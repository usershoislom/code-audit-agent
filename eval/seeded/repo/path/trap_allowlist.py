import os

from flask import Flask, abort, request, send_file, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE_DIR = "/srv/files"

TEMPLATES = {"invoice", "receipt", "letter"}


@app.route("/templates/<kind>")
def template(kind):
    if kind not in TEMPLATES:
        abort(404)
    with open(os.path.join(BASE_DIR, "templates", kind + ".html")) as fh:
        return fh.read()
