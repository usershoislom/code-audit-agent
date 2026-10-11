from flask import Flask, make_response, render_template_string, request
from markupsafe import escape

app = Flask(__name__)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return render_template_string("<p>Results for {{ q }}</p>", q=q)
