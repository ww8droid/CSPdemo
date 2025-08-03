
from flask import Flask, request, render_template_string, make_response
import secrets

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Blog Viewer</title>
  <style>
    body { font-family: sans-serif; margin: 2em; }
    .csp { background: #fffae6; padding: 1em; margin-bottom: 1em; border: 1px dashed #999; }
    iframe { width: 100%; height: 200px; border: 1px solid #aaa; }
  </style>
</head>
<body>
  <h1>📰 Blog Article Preview</h1>
  <div class="csp">
    <strong>CSP Header:</strong><br>
    Content-Security-Policy: script-src 'self'; object-src 'none'; frame-ancestors 'none'
  </div>
  <p>Preview an external blog post (iframe loads from untrusted-blog.local):</p>
  <iframe src="http://localhost:5001/embedded"></iframe>
</body>
</html>
"""

@app.route("/")
def index():
    response = make_response(render_template_string(TEMPLATE))
    response.headers["Content-Security-Policy"] = "script-src 'self'; object-src 'none'; frame-ancestors 'none'"
    return response

if __name__ == "__main__":
    app.run(port=5000, debug=True)
