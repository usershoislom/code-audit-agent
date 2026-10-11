import os
import re
import shlex
import subprocess

from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/backup", methods=["POST"])
def backup():
    name = request.form.get("name", "backup")
    os.system("tar czf /var/backups/" + name + ".tgz /srv/data")
    return {"ok": True}
