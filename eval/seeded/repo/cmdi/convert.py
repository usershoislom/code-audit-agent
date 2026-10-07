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
    return convert_image(request.args["file"], request.args.get("fmt", "png"))
