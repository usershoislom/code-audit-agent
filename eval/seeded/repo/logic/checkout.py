from flask import Flask, request

app = Flask(__name__)
CATALOG = {"sku-1": 1999, "sku-2": 4999}


@app.route("/checkout", methods=["POST"])
def checkout():
    data = request.get_json()
    total = 0
    for item in data["items"]:
        total += item["price"] * item["qty"]
    return {"charge_cents": total}
