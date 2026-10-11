from urllib.parse import urlparse

import requests
from flask import Flask, abort, request

app = Flask(__name__)
ALLOWED_HOSTS = {"images.example.org", "cdn.example.org"}


@app.route("/preview")
def preview():
    url = request.args.get("url", "")
    r = requests.get(url, timeout=5)
    return {"status": r.status_code, "len": len(r.content)}
