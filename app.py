from flask import Flask, render_template_string

app = Flask(__name__)

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
            h1 {
                color: #333;
                margin: 0;
            }
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
    app.run(host='0.0.0.0', port=5000, debug=True)