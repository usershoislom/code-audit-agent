from flask import Flask, make_response, render_template_string, request
from markupsafe import escape

app = Flask(__name__)


@app.route("/comment/preview", methods=["POST"])
def preview():
    body = request.form.get("body", "")
    resp = make_response("<div class='comment'>" + str(escape(body)) + "</div>")
    return resp
