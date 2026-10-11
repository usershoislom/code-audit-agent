import hashlib
import os

from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
smtp_password = os.environ.get("SMTP_PASSWORD", "")


def hash_password(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 600_000).hex()


def cache_key(url):
    return hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
