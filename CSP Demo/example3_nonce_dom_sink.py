from flask import Flask, Response, render_template_string, request
import secrets

app = Flask(__name__)
REPORTS = []

TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Example 3 — Nonce CSP + innerHTML Sink</title>
  <style>
    body{font-family:sans-serif;max-width:1000px;margin:40px auto;}
    pre{background:#f6f8fa;padding:10px;border-radius:6px;white-space:pre-wrap;}
    code{background:#eee;padding:0 3px;border-radius:3px;}
    .cols{display:flex;gap:20px;}
    .col{flex:1;}
    .box{border:1px solid #ccc;padding:10px;border-radius:6px;min-height:80px;margin-bottom:10px;}
    .danger{border-color:#e00;background:#fff5f5;}
    .safe{border-color:#0a0;background:#f5fff5;}
  </style>
</head>
<body>
  <h1>Example 3 — Nonce CSP + innerHTML Sink</h1>
  <p><strong>Looks secure</strong> because all inline scripts require a nonce, but in <em>insecure mode</em> we inject untrusted HTML with <code>innerHTML</code>, so event handlers like <code>onerror</code> still execute.</p>

  <p>
    Mode:
    {% if mode == 'secure' %}<strong>SECURE</strong>{% else %}<a href="?mode=secure">SECURE</a>{% endif %} |
    {% if mode == 'insecure' %}<strong>INSECURE</strong>{% else %}<a href="?mode=insecure">INSECURE</a>{% endif %}
  </p>

  <h3>Current CSP header</h3>
  <pre>{{ csp }}</pre>

  <h3>Try It</h3>
  <form id="comment-form">
    <label>Enter a comment (try: <code>&lt;img src=x onerror=alert(1)&gt;</code>)</label><br>
    <textarea id="comment" rows="3" style="width:100%"></textarea><br><br>
    <button type="submit">Submit</button>
  </form>

  <div class="cols">
    <div class="col">
      <h3>Raw API Response</h3>
      <div id="api" class="box"></div>
    </div>
    <div class="col">
      <h3>{{ insecure_label }}</h3>
      <div id="unsafe" class="box {{ insecure_class }}"></div>
    </div>
    <div class="col">
      <h3>Safe Render (textContent)</h3>
      <div id="safe" class="box safe"></div>
    </div>
  </div>

  <h3>Client-side Code (executed)</h3>
  <pre>{{ client_js }}</pre>

  <h3>CSP Violation Reports ({{ reports|length }})</h3>
  <pre>{{ reports|tojson(indent=2) }}</pre>

  <script nonce="{{ nonce }}">
  {{ client_js }}
  </script>
</body>
</html>
"""

CLIENT_JS_BASE = r"""
async function postComment(text) {{
  const res = await fetch('/api/comment', {{
    method: 'POST',
    headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify({{text}})
  }});
  return await res.text();
}}

document.getElementById('comment-form').addEventListener('submit', async (e) => {{
  e.preventDefault();
  const val = document.getElementById('comment').value;
  const apiBox = document.getElementById('api');
  const unsafeBox = document.getElementById('unsafe');
  const safeBox = document.getElementById('safe');

  const html = await postComment(val);
  apiBox.textContent = html; // Show raw server response
  {inject}
  safeBox.textContent = html; // ✅ safe path
}});
"""

def build_client_js(mode):
    if mode == "insecure":
        inject = "unsafeBox.innerHTML = html;    // 🧨 vulnerable sink"
    else:
        inject = "unsafeBox.textContent = html;  // ✅ safe (secure mode)"
    return CLIENT_JS_BASE.format(inject=inject)

@app.route("/")
def index():
    mode = request.args.get("mode", "secure")
    nonce = secrets.token_urlsafe(16)
    csp = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; object-src 'none'; report-uri /csp-report;"
    client_js = build_client_js(mode)
    html = render_template_string(
        TEMPLATE,
        csp=csp,
        nonce=nonce,
        client_js=client_js,
        mode=mode,
        reports=REPORTS,
        insecure_label=("Unsafe Render (innerHTML)" if mode == "insecure" else "Safe Render (textContent)"),
        insecure_class=("danger" if mode == "insecure" else "safe")
    )
    return Response(html, headers={"Content-Security-Policy": csp})

@app.route("/api/comment", methods=["POST"])
def api_comment():
    data = request.get_json(silent=True) or {}
    # Intentionally unsanitized for demo
    return data.get("text", "")

@app.route("/csp-report", methods=["POST"])
def csp_report():
    try:
        REPORTS.append(request.get_json(force=True))
    except Exception:
        pass
    return "", 204

if __name__ == "__main__":
    app.run(port=5003, debug=True)
