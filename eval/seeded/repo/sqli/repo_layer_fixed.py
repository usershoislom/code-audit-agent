import sqlite3


def find_product_safe(term):
    conn = sqlite3.connect("app.db")
    sql = "SELECT id, title FROM products WHERE title LIKE ?"
    return conn.execute(sql, (f"%{term}%",)).fetchall()
