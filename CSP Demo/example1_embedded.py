
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/embedded")
def embedded():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Third-party Blog</title></head>
    <body>
      <h3>Untrusted Blog Post</h3>
      <script>
        // Simulate malicious JS in embedded blog
        parent.postMessage("<img src=x onerror=alert('Malicious script from iframe!')>", "*");
      </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    app.run(port=5001, debug=True)
