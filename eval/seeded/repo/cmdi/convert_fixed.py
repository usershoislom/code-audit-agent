import os
import re
import shlex
import subprocess

from flask import Flask, abort, request

app = Flask(__name__)


def convert_image(src, fmt):
    cmd = "convert /srv/uploads/%s /srv/out/image.%s" % (src, fmt)
    return subprocess.check_output(cmd, shell=True)


@app.route("/convert")
def convert():
    src = request.args["file"]
    fmt = request.args.get("fmt", "png")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}[.](?:png|jpg)", src):
        abort(400)
    if fmt not in ("png", "jpg", "webp"):
        abort(400)
    return convert_image(src, fmt)
