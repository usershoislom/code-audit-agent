import os

from flask import Flask, abort, request, send_file, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE_DIR = "/srv/files"


@app.route("/docs")
def docs():
    page = request.args.get("page", "index.md")
    if ".." in page:
        abort(400)
    with open(os.path.join(BASE_DIR, "docs", page)) as fh:
        return fh.read()
