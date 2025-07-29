from flask import Flask, Response, render_template_string, request, redirect, url_for
import json

app = Flask(__name__)
REPORTS = []

TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Example 2 — 'self' + Open Redirect</title>
  <style>
    body{font-family:sans-serif;max-width:1000px;margin:40px auto;}
    pre{background:#f6f8fa;padding:10px;border-radius:6px;white-space:pre-wrap;}
    code{background:#eee;padding:0 3px;border-radius:3px;}
  </style>
</head>
<body>
  <h1>Example 2 — 'self' + Open Redirect</h1>
  <p><strong>Looks secure</strong> (<code>script-src 'self'</code>), but in <em>insecure mode</em> an open redirect
     forwards the browser to an attacker script hosted elsewhere.</p>

  <p>
    Mode:
    {% if mode == 'secure' %}<strong>SECURE</strong>{% else %}<a href="?mode=secure">SECURE</a>{% endif %} |
    {% if mode == 'insecure' %}<strong>INSECURE</strong>{% else %}<a href="?mode=insecure">INSECURE</a>{% endif %}
  </p>

  <h3>Current CSP header</h3>
  <pre>{{ csp }}</pre>

  {% if mode == 'insecure' %}
  <h3>Insecure script include (will alert)</h3>
  <pre>&lt;script src="/redirect?to=http://localhost:9000/evil.js"&gt;&lt;/script&gt;</pre>
  <script src="/redirect?to=http://localhost:9000/evil.js"></script>
  {% else %}
  <h3>Secure-mode redirect enforcement</h3>
  <pre>Redirect only allows same-origin relative paths (blocking external JS).</pre>
  <script src="/redirect?to=http://localhost:9000/evil.js"></script>
  {% endif %}

  <h3>Open Redirect Endpoint</h3>
  <pre>GET /redirect?to=&lt;url&gt;</pre>

  <h3>CSP Violation Reports ({{ reports|length }})</h3>
  <pre>{{ reports|tojson(indent=2) }}</pre>
</body>
</html>
"""

def make_csp(mode):
    # Same CSP in both modes; the vulnerability is in app logic, not CSP itself.
    return "default-src 'self'; script-src 'self'; object-src 'none'; report-uri /csp-report;"

@app.route("/")
def index():
    mode = request.args.get("mode", "secure")
    csp = make_csp(mode)
    html = render_template_string(TEMPLATE, csp=csp, mode=mode, reports=REPORTS)
    return Response(html, headers={"Content-Security-Policy": csp})

@app.route("/redirect")
def open_redirect():
    mode = request.args.get("mode", request.args.get("mode_param", "secure"))
    # Extract from query string (but won't be reflected automatically)
    to = request.args.get("to", "")

    if mode == "secure":
        # Secure fix: only allow relative paths
        if not to.startswith("/"):
            return "Blocked by secure redirect policy", 400

    # Insecure: allow redirect to anywhere
    return redirect(to, code=302)

@app.route("/csp-report", methods=["POST"])
def csp_report():
    try:
        REPORTS.append(request.get_json(force=True))
    except Exception:
        pass
    return "", 204

if __name__ == "__main__":
    app.run(port=5002, debug=True)
