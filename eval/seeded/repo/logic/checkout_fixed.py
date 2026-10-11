from flask import Flask, abort, request

app = Flask(__name__)
CATALOG = {"sku-1": 1999, "sku-2": 4999}


@app.route("/checkout", methods=["POST"])
def checkout():
    data = request.get_json()
    total = 0
    for item in data["items"]:
        qty = int(item["qty"])
        if item["sku"] not in CATALOG or not 1 <= qty <= 100:
            abort(400)
        total += CATALOG[item["sku"]] * qty
    return {"charge_cents": total}
