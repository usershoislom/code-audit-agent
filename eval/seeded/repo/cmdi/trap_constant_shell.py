import os
import re
import shlex
import subprocess

from flask import Flask, abort, request

app = Flask(__name__)

LOG_DIR = "/var/log/app"


@app.route("/diag/disk")
def disk():
    out = subprocess.run(f"du -sh {LOG_DIR}", shell=True, capture_output=True, text=True)
    return {"out": out.stdout}
