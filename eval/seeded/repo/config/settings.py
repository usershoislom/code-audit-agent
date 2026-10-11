import hashlib

from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = "s3cr3t-Flask-K3y-2024-prod"
AWS_ACCESS_KEY_ID = "AKIAZ7Q4X2MPLE5R3WN8"
smtp_password = "Wint3r!Mailer#2024"


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


if __name__ == "__main__":
    app.run(debug=True)
