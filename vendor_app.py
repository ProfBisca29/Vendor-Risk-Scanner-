"""
Vendor Risk Scoring Tool — Web Interface
Run with: python vendor_app.py
Then open http://localhost:5001
"""

from flask import Flask, request, jsonify, render_template_string
import json, os
from vendor_scanner import run as run_scan

app = Flask(__name__)

with open(os.path.join(os.path.dirname(__file__), "vendor_index.html")) as f:
    HTML = f.read()

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/scan", methods=["POST"])
def scan():
    data   = request.get_json()
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    if len(domain) > 253:
        return jsonify({"error": "Invalid domain"}), 400
    try:
        report = run_scan(domain)
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5001)
