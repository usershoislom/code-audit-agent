import os

from flask import Flask, abort, request, send_file, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE_DIR = "/srv/files"


@app.route("/thumbs")
def thumbs():
    img = os.path.basename(request.args.get("img", ""))
    with open(os.path.join(BASE_DIR, "thumbs", img), "rb") as fh:
        return fh.read()
