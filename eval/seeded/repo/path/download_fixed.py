import os

from flask import Flask, abort, request, send_file, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE_DIR = "/srv/files"


@app.route("/download")
def download():
    name = request.args.get("file", "")
    full = os.path.realpath(os.path.join(BASE_DIR, name))
    if not full.startswith(os.path.realpath(BASE_DIR) + os.sep):
        abort(403)
    with open(full, "rb") as fh:
        return fh.read()
