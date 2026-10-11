import os

from flask import Flask, abort, request, send_file, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE_DIR = "/srv/files"


@app.route("/export")
def export():
    rel = request.args.get("path", "")
    target = os.path.join(BASE_DIR, rel)
    if not target.startswith(BASE_DIR):
        abort(403)
    with open(target) as fh:
        return fh.read()
