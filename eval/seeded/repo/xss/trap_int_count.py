from flask import Flask, make_response, render_template_string, request
from markupsafe import escape

app = Flask(__name__)


@app.route("/cart/badge")
def badge():
    n = int(request.args.get("n", "0"))
    return f"<span class='badge'>{n}</span>"
