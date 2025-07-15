from flask import Flask, Response, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    # Safe CSP example
    csp = "default-src 'self'; script-src 'self'; object-src 'none';"
    html = """
    <h1>Safe CSP Page</h1>
    <p>This page has a strict CSP and blocks inline scripts.</p>
    <script>
      console.log("This inline script should be blocked.");
    </script>
    """
    return Response(render_template_string(html), headers={'Content-Security-Policy': csp})

@app.route('/bypass1')
def bypass_jsonp():
    # CSP that allows scripts from an external domain
    csp = "script-src 'self' https://cdn.jsdelivr.net;"
    html = """
    <h1>Bypass Demo: JSONP</h1>
    <p>Loads a script from jsDelivr that runs alert(1).</p>
    <script src="https://cdn.jsdelivr.net/gh/user/project/evil.js?cb=alert(1)"></script>
    """
    return Response(render_template_string(html), headers={'Content-Security-Policy': csp})

@app.route('/bypass2')
def bypass_data_uri():
    # CSP that mistakenly allows data: URIs
    csp = "script-src 'self' data:;"
    html = """
    <h1>Bypass Demo: data: URI</h1>
    <script src="data:text/javascript,alert('XSS via data URI')"></script>
    """
    return Response(render_template_string(html), headers={'Content-Security-Policy': csp})

@app.route('/bypass3')
def bypass_innerhtml():
    # This policy mistakenly allows 'unsafe-inline'
    csp = "script-src 'self' 'unsafe-inline';"
    html = """
    <h1>DOM Bypass: innerHTML</h1>
    <div id="output"></div>
    <script>
      const payload = "<img src=x onerror=alert('XSS via innerHTML')>";
      document.getElementById("output").innerHTML = payload;
    </script>
    """
    return Response(render_template_string(html), headers={'Content-Security-Policy': csp})

@app.route('/bypass4')
def bypass_setattribute():
    csp = "script-src 'self' 'unsafe-inline';"
    html = """
    <h1>DOM Bypass: setAttribute</h1>
    <script>
      const s = document.createElement('script');
      s.setAttribute('src', 'data:text/javascript,alert(\"XSS via setAttribute\")');
      document.body.appendChild(s);
    </script>
    """
    return Response(render_template_string(html), headers={'Content-Security-Policy': csp})

@app.route('/bypass5')
def bypass_documentwrite():
    csp = "script-src 'self' 'unsafe-inline';"
    html = """
    <h1>DOM Bypass: document.write</h1>
    <script>
      document.write("<img src=x onerror=alert('XSS via document.write')>");
    </script>
    """
    return Response(render_template_string(html), headers={'Content-Security-Policy': csp})


if __name__ == '__main__':
    app.run(debug=True)
