
import os
import subprocess
from flask import Flask, request

app = Flask(__name__)

# DEMO ONLY: Token giả, không có quyền truy cập thật
GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae5c21462"

@app.route("/run")
def run_command():
    command = request.args.get("cmd", "echo hello")

    # DEMO ONLY: Command injection
    result = subprocess.check_output(
        command,
        shell=True,
        text=True
    )

    return result

@app.route("/")
def home():
    return "TV2 DevSecOps Security Demo"

if __name__ == "__main__":
    app.run(debug=True)
