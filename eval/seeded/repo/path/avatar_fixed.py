import os

from flask import Flask, abort, request, send_file, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE_DIR = "/srv/files"


@app.route("/avatar/<path:filename>")
def avatar(filename):
    return send_from_directory(BASE_DIR + "/avatars", filename)
