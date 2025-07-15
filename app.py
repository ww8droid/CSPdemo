from flask import Flask, render_template, Response, request, redirect, url_for

app = Flask(__name__)

# ---------- Example 1 ----------
# Hash‑based CSP looks tight, but dynamic .src assignment is attacker‑controlled
@app.route("/")
def example1():
    csp = ("default-src 'self'; "
           "script-src 'self' 'sha256-fQvT4XyVa07nPki7nQrNv3E9lpc1Qa+8U+9kJ+uWAxU=';")
    html = """
    <h2>Example 1 – Hash CSP + Dynamic Script Injection</h2>
    <p>URL parameter after <code>?</code> is treated as a script source.</p>
    <p>Try: <code>?https://raw.githubusercontent.com/jquery/jquery/main/src/jquery.js</code></p>
    <script>
      // trusted inline snippet (hash in CSP header)
      console.log("trusted inline script runs ✅");
      // insecure dynamic load
      const src = location.search.slice(1);
      if (src) {
          const s = document.createElement('script');
          s.src = src;                 // 🧨 attacker influence
          document.body.appendChild(s);
      }
    </script>
    """
    return Response(render_template('index.html', body=html),
                    headers={'Content-Security-Policy': csp})


# ---------- Example 2 ----------
# 'self' is whitelisted, but an open redirect serves foreign JS
@app.route("/example2")
def example2():
    csp = "default-src 'self'; script-src 'self';"
    html = """
    <h2>Example 2 – 'self' + Open Redirect</h2>
    <p><code>/redirect?to=https://evil.com/evil.js</code> still counts as 'self'.</p>
    <script src="/redirect?to=/static/evil.js"></script>
    """
    return Response(render_template('index.html', body=html),
                    headers={'Content-Security-Policy': csp})


@app.route("/redirect")
def redirector():
    # naive open redirect for demo
    target = request.args.get("to", "")
    return redirect(target, code=302)


# ---------- Example 3 ----------
# Nonce CSP is fine, but DOM sink executes attacker HTML
@app.route("/example3")
def example3():
    csp = "default-src 'self'; script-src 'nonce-DEMO123';"
    html = """
    <h2>Example 3 – Nonce CSP + innerHTML Event Handler</h2>
    <p>User “comment” comes from query param <code>?c=</code>.</p>
    <div id="box" style="border:1px solid #999;padding:8px;"></div>
    <script nonce="DEMO123">
      const comment = decodeURIComponent(location.search.slice(3));
      document.getElementById('box').innerHTML = comment;   // 🧨 innerHTML sink
    </script>
    """
    return Response(render_template('index.html', body=html),
                    headers={'Content-Security-Policy': csp})


# ---------- static attacker file ----------
@app.route('/static/evil.js')
def evil_js():
    return Response("alert('🔴 Evil JS executed');", mimetype='application/javascript')


if __name__ == "__main__":
    app.run(debug=True, port=5000)
