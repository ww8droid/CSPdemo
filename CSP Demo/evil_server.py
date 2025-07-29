from flask import Flask, Response

app = Flask(__name__)

@app.route("/evil.js")
def evil_js():
    return Response("alert('🔴 Evil JS executed from attacker host');", mimetype="application/javascript")

if __name__ == "__main__":
    app.run(port=9000, debug=True)
