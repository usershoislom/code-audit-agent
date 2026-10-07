import os

from flask import Flask, abort, request, send_file, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE_DIR = "/srv/files"


@app.route("/download")
def download():
    name = request.args.get("file", "")
    with open(os.path.join(BASE_DIR, name), "rb") as fh:
        return fh.read()
