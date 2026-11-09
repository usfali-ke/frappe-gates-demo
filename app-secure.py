
import os
import re
from flask import Flask, request, jsonify

app = Flask(__name__)

app.config.update(
    DEBUG=False,
    # From the environment, off unless set (semgrep: avoid_hardcoded_config_TESTING).
    TESTING=os.environ.get("FLASK_TESTING") == "1",
    MAX_CONTENT_LENGTH=4096
)

NAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z '-]{0,49}$")


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    return response


@app.get("/health")
def health():
    return jsonify({"status": "healthy"}), 200


@app.post("/api/greet")
def greet():
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 415

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON"}), 400

    if set(data.keys()) != {"name"}:
        return jsonify({"error": "Invalid request fields"}), 400

    name = data["name"]

    if not isinstance(name, str):
        return jsonify({"error": "Invalid name"}), 400

    name = name.strip()

    if not NAME_PATTERN.fullmatch(name):
        return jsonify({"error": "Invalid name format"}), 400

    return jsonify({"message": f"Hello, {name}!"}), 200


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(413)
def payload_too_large(error):
    return jsonify({"error": "Payload too large"}), 413


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=8000,
        debug=False
    )
