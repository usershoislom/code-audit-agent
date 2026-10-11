import os
import re
import shlex
import subprocess

from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/diag/lookup")
def lookup():
    domain = request.args.get("domain", "example.org")
    out = subprocess.run(["nslookup", "--", domain], capture_output=True, text=True, timeout=5)
    return {"out": out.stdout}
