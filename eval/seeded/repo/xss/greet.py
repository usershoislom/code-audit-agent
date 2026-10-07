from flask import Flask, make_response, render_template_string, request
from markupsafe import escape

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    return f"<h1>Hello {name}</h1>"
