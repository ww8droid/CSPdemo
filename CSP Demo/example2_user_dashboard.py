
from flask import Flask, request, render_template_string, make_response
import secrets

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>User Dashboard</title>
  <style>
    body { font-family: sans-serif; margin: 2em; }
    .profile-pic { border-radius: 50%; width: 100px; height: 100px; }
    .csp { background: #fffae6; padding: 1em; margin-bottom: 1em; border: 1px dashed #999; }
  </style>
</head>
<body>
  <h1>👤 User Dashboard</h1>
  <div class="csp">
    <strong>CSP Header:</strong><br>
    Content-Security-Policy: script-src 'self'; style-src 'self'; img-src * data:;
  </div>

  <p>Welcome, user@example.com!</p>
  <p>Your profile picture:</p>
  <img class="profile-pic" src="{{ profile_url }}" alt="Profile Picture">

  <p><strong>Note:</strong> This page allows loading profile pictures from anywhere (img-src *).</p>
</body>
</html>
"""

@app.route("/")
def index():
    profile_url = request.args.get("img", "https://placekitten.com/100/100")
    response = make_response(render_template_string(TEMPLATE, profile_url=profile_url))
    response.headers["Content-Security-Policy"] = "script-src 'self'; style-src 'self'; img-src * data:;"
    return response

if __name__ == "__main__":
    app.run(port=5002, debug=True)
