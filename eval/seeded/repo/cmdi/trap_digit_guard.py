import os
import re
import shlex
import subprocess

from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/jobs/kill", methods=["POST"])
def kill_job():
    pid = request.form.get("pid", "")
    if not pid.isdigit():
        abort(400)
    os.system("kill -TERM " + pid)
    return {"ok": True}
