from flask import Flask, render_template_string, request
import sqlite3
# import subprocess   # Dùng cho demo Command Injection
# import hashlib      # Dùng cho demo Weak Cryptography

app = Flask(__name__)

# =============================================================
# DEMO 1 — SECRET SCANNING (GitLeaks)
# Hướng dẫn demo: Bỏ comment 3 dòng bên dưới → push → GitLeaks FAIL
# Giải thích: Hardcode API Key/Password trực tiếp vào code
# =============================================================
# AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"
# AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
# GITHUB_TOKEN          = "ghp_16C7e42F292c6912E7710c838347Ae5c21462"


# =============================================================
# DEMO 2 — SAST: SQL Injection (Semgrep)
# Hướng dẫn demo: Bỏ comment hàm search_user_vuln → push → Semgrep FAIL
# Giải thích: Dùng f-string trực tiếp trong câu SQL → SQL Injection
# =============================================================
# @app.route('/search')
# def search_user_vuln():
#     username = request.args.get('username', '')
#     conn = sqlite3.connect('users.db')
#     cursor = conn.cursor()
#     # LỖI: Dùng f-string trong SQL → attacker nhập: ' OR '1'='1
#     query = f"SELECT * FROM users WHERE username = '{username}'"
#     cursor.execute(query)
#     return str(cursor.fetchall())


# =============================================================
# DEMO 3 — SAST: Command Injection (Semgrep)
# Hướng dẫn demo: Bỏ comment hàm ping_vuln → push → Semgrep FAIL
# Giải thích: User input truyền thẳng vào lệnh shell → Command Injection
# =============================================================
# @app.route('/ping')
# def ping_vuln():
#     host = request.args.get('host', '127.0.0.1')
#     # LỖI: shell=True + user input → attacker nhập: 127.0.0.1; cat /etc/passwd
#     result = subprocess.run(f"ping -c 1 {host}", shell=True,
#                             capture_output=True, text=True)
#     return result.stdout


# =============================================================
# DEMO 4 — SAST: Weak Cryptography (Semgrep)
# Hướng dẫn demo: Bỏ comment hàm login_vuln → push → Semgrep FAIL
# Giải thích: MD5 đã bị crack, không an toàn để hash password
# =============================================================
# @app.route('/login', methods=['POST'])
# def login_vuln():
#     password = request.form.get('password', '')
#     # LỖI: MD5 dễ bị rainbow table attack
#     hashed = hashlib.md5(password.encode()).hexdigest()
#     return {'hash': hashed}


# =============================================================
# CODE CHÍNH — Không chứa lỗ hổng
# =============================================================

@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DevSecOps Demo</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }
            .container {
                text-align: center;
                background: white;
                padding: 50px;
                border-radius: 10px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            }
            h1 { color: #333; margin: 0; }
            .version {
                font-size: 48px;
                color: #667eea;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>DevSecOps Pipeline Demo</h1>
            <p class="version">Phiên bản 1.0</p>
        </div>
    </body>
    </html>
    ''')


@app.route('/health')
def health():
    return {'status': 'healthy', 'version': '1.0'}, 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
