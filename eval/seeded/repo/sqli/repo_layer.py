import sqlite3


def find_product(term):
    conn = sqlite3.connect("app.db")
    sql = "SELECT id, title FROM products WHERE title LIKE '%{}%'".format(term)
    return conn.execute(sql).fetchall()
