import os

from flask import Flask, abort, request, send_file, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE_DIR = "/srv/files"


@app.route("/reports/<name>")
def report_file(name):
    safe = secure_filename(name)
    with open(os.path.join(BASE_DIR, "reports", safe)) as fh:
        return fh.read()
