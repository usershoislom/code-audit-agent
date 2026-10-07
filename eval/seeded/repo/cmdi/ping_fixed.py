import os
import re
import shlex
import subprocess

from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/diag/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
    return {"out": out.stdout}
