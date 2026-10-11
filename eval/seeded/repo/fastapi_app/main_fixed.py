import sqlite3

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from markupsafe import escape

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.org"], allow_credentials=True)


def get_db():
    return sqlite3.connect("app.db")


def get_current_user():
    return {"id": 1}


@app.get("/items/{item_id}")
def read_item(item_id: str):
    row = get_db().execute("SELECT id, name FROM items WHERE id = ?", (item_id,)).fetchone()
    return {"item": row}


@app.get("/greet", response_class=HTMLResponse)
def greet(name: str = "guest"):
    return HTMLResponse(f"<h1>Hello {escape(name)}</h1>")


@app.get("/orders/{order_id}/invoice")
def order_invoice(order_id: int, user=Depends(get_current_user)):
    row = get_db().execute("SELECT owner_id, pdf FROM orders WHERE id = ?", (order_id,)).fetchone()
    if row is None or row[0] != user["id"]:
        raise HTTPException(status_code=404)
    return {"pdf": row[1]}


@app.get("/orders/{order_id}")
def read_order(order_id: int, user=Depends(get_current_user)):
    row = get_db().execute("SELECT id, total, address FROM orders WHERE id = ? AND owner_id = ?",
                           (order_id, user["id"])).fetchone()
    return {"order": row}
