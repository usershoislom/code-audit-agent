from flask import Flask, make_response, render_template_string, request
from markupsafe import escape

app = Flask(__name__)

import platform


@app.route("/about")
def about():
    return f"<p>Running on {platform.python_version()}</p>"
