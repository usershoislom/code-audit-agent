import sqlite3
import sys


def main():
    customer = sys.argv[1]
    conn = sqlite3.connect("reports.db")
    rows = conn.execute("SELECT total FROM invoices WHERE customer = '%s'" % customer).fetchall()
    print(sum(r[0] for r in rows))


if __name__ == "__main__":
    main()
