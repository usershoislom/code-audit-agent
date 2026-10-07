from flask import Flask, request

from repo_layer_fixed import find_product_safe

app = Flask(__name__)


@app.route("/products/search")
def product_search():
    term = request.args.get("q", "")
    return {"items": find_product_safe(term)}
