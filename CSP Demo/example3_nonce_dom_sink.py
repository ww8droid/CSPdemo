
from flask import Flask, request, render_template_string, make_response
import secrets

app = Flask(__name__)

comments = []

TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Product Review</title>
  <style>
    body { font-family: sans-serif; margin: 2em; }
    .comment-box { margin-top: 1em; }
    .comment { background: #f0f0f0; padding: 0.5em; border-radius: 5px; margin: 0.5em 0; }
    .csp-header { background: #fffae6; padding: 1em; border: 1px dashed #ccc; margin-bottom: 1em; }
    .toggle { margin-top: 1em; }
  </style>
  <script nonce="{{ nonce }}">
    let useInnerHTML = true;

    function toggleMode() {
      useInnerHTML = !useInnerHTML;
      document.getElementById('mode-label').innerText = useInnerHTML ? "innerHTML (Unsafe)" : "textContent (Safe)";
    }

    function submitComment() {
      const input = document.getElementById('comment-input');
      fetch('/submit', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: 'comment=' + encodeURIComponent(input.value)
      }).then(() => window.location.reload());
    }

    window.addEventListener('DOMContentLoaded', () => {
      const comments = {{ comments | tojson }};
      const container = document.getElementById('comments');
      comments.forEach(c => {
        const div = document.createElement('div');
        div.className = "comment";
        if (useInnerHTML) {
          div.innerHTML = c;
        } else {
          div.textContent = c;
        }
        container.appendChild(div);
      });
    });
  </script>
</head>
<body>
  <h1>🧪 Product Review</h1>

  <div class="csp-header">
    <strong>CSP Header:</strong><br>
    Content-Security-Policy: script-src 'self' 'nonce-{{ nonce }}'
  </div>

  <div>
    <label for="comment-input">Leave a comment:</label><br>
    <input id="comment-input" size="60" placeholder="Try: &lt;img src=x onerror=alert(1)&gt;">
    <button onclick="submitComment()">Submit</button>
  </div>

  <div class="toggle">
    <button onclick="toggleMode()">Toggle Rendering Mode</button>
    <span id="mode-label">innerHTML (Unsafe)</span>
  </div>

  <div class="comment-box" id="comments"></div>
</body>
</html>
"""

@app.route("/")
def index():
    nonce = secrets.token_urlsafe(8)
    resp = make_response(render_template_string(TEMPLATE, comments=comments, nonce=nonce))
    resp.headers['Content-Security-Policy'] = f"script-src 'self' 'nonce-{nonce}'"
    return resp

@app.route("/submit", methods=["POST"])
def submit():
    comment = request.form.get("comment", "")
    if comment:
        comments.append(comment)
    return ('', 204)

if __name__ == "__main__":
    app.run(port=5003, debug=True)
