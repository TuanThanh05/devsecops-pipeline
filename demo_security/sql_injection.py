import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/demo-user")
def demo_user():
    username = request.args.get("username", "")

    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()

    # Cố ý ghép dữ liệu người dùng vào câu SQL để kiểm thử SAST.
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)

    return {"rows": cursor.fetchall()}