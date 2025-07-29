from flask import Flask, Response, render_template_string, request, jsonify
import hashlib, base64

app = Flask(__name__)
REPORTS = []

INLINE_JS = r"""
console.log("trusted inline script runs ✅");
// Dynamic script URL via ?src=
const src = new URLSearchParams(location.search).get('src');
const status = document.getElementById('status');
if (src) {
  status.textContent = "Attempting to dynamically load external script: " + src;
  const s = document.createElement('script');
  s.src = src; // 🧨 attacker-controlled in insecure mode
  document.body.appendChild(s);
} else {
  status.textContent = "No ?src= supplied. Nothing external loaded.";
}
"""

TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Example 1 — Hash CSP + Dynamic Script Injection</title>
  <style>
    body{font-family:sans-serif;max-width:1000px;margin:40px auto;}
    pre{background:#f6f8fa;padding:10px;border-radius:6px;white-space:pre-wrap;}
    code{background:#eee;padding:0 3px;border-radius:3px;}
    .box{border:1px solid #ccc;padding:10px;border-radius:6px;min-height:60px;margin-bottom:10px;}
    .danger{border-color:#e00;background:#fff5f5;}
  </style>
</head>
<body>
  <h1>Example 1 — Hash CSP + Dynamic Script Injection</h1>
  <p><strong>Looks secure</strong> because we hash the inline script, but in <em>insecure mode</em> we also allow <code>https:</code> in <code>script-src</code>, so attacker-controlled external scripts load.</p>

  <p>
    Mode:
    {% if mode == 'secure' %}<strong>SECURE</strong>{% else %}<a href="?mode=secure">SECURE</a>{% endif %} |
    {% if mode == 'insecure' %}<strong>INSECURE</strong>{% else %}<a href="?mode=insecure">INSECURE</a>{% endif %}
  </p>

  <h3>Try It</h3>
  <ol>
    <li>Use insecure mode and load an external script:<br>
      <code>?mode=insecure&amp;src=https://code.jquery.com/jquery-3.7.1.min.js</code></li>
    <li>Switch to secure mode. The same URL should now be blocked by CSP.</li>
  </ol>

  <h3>Current CSP header</h3>
  <pre>{{ csp }}</pre>

  <h3>Inline script (covered by hash)</h3>
  <pre>{{ inline_js }}</pre>

  <h3>Status</h3>
  <div id="status" class="box danger"></div>

  <h3>CSP Violation Reports ({{ reports|length }})</h3>
  <pre>{{ reports|tojson(indent=2) }}</pre>

  <script>
  {{ inline_js }}
  </script>
</body>
</html>
"""

def make_csp_for_inline(js, mode):
    h = hashlib.sha256(js.encode("utf-8")).digest()
    b64 = base64.b64encode(h).decode("ascii")
    if mode == "insecure":
        # Toxic combo: hashes look good, but 'https:' allows arbitrary HTTPS scripts.
        return f"default-src 'self'; script-src 'self' https: 'sha256-{b64}'; object-src 'none'; report-uri /csp-report;"
    else:
        # Secure: only self + the hashed inline
        return f"default-src 'self'; script-src 'self' 'sha256-{b64}'; object-src 'none'; report-uri /csp-report;"

@app.route("/")
def index():
    mode = request.args.get("mode", "secure")
    csp = make_csp_for_inline(INLINE_JS, mode)
    html = render_template_string(TEMPLATE, csp=csp, inline_js=INLINE_JS, mode=mode, reports=REPORTS)
    return Response(html, headers={"Content-Security-Policy": csp})

@app.route("/csp-report", methods=["POST"])
def csp_report():
    try:
        REPORTS.append(request.get_json(force=True))
    except Exception:
        pass
    return "", 204

if __name__ == "__main__":
    app.run(port=5001, debug=True)
