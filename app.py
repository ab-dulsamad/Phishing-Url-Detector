"""
Phishing URL Awareness Checker - Web Application Server
========================================================
Flask server providing the cybersecurity dashboard and REST API
for static URL text analysis.
"""

from __future__ import annotations

import os
from flask import Flask, jsonify, render_template, request
from phishing_checker import PhishingURLChecker, analyze_url

# Initialize Flask app
app = Flask(__name__, static_folder="static", template_folder="templates")
checker = PhishingURLChecker()

# Predefined benchmark samples for quick interactive testing
BENCHMARK_SAMPLES = [
    {
        "id": "sample-1",
        "label": "Sample 1: Standard HTTPS",
        "url": "https://www.example.com/login",
        "expected_risk": "LOW INDICATOR COUNT",
        "description": "Legitimate-looking structure with HTTPS and standard domain.",
    },
    {
        "id": "sample-2",
        "label": "Sample 2: Direct IP + HTTP",
        "url": "http://192.0.2.10/account",
        "expected_risk": "MEDIUM RISK",
        "description": "Uses direct IPv4 address as hostname over unencrypted HTTP.",
    },
    {
        "id": "sample-3",
        "label": "Sample 3: @ Symbol Trick",
        "url": "http://example.com@sample.invalid/login",
        "expected_risk": "MEDIUM RISK",
        "description": "Obfuscates destination host behind an @ symbol with HTTP.",
    },
    {
        "id": "sample-4",
        "label": "Sample 4: Subdomain Chaining",
        "url": "https://a.b.c.d.e.example.invalid/path",
        "expected_risk": "MEDIUM RISK",
        "description": "Chains 7 dot-separated subdomain segments (>= 5 threshold).",
    },
    {
        "id": "sample-5",
        "label": "Sample 5: Punycode (IDN)",
        "url": "https://xn--example.invalid/",
        "expected_risk": "MEDIUM RISK",
        "description": "Contains 'xn--' prefix indicating an Internationalized Domain Name.",
    },
    {
        "id": "sample-6",
        "label": "Sample 6: Multi-Vector High Risk",
        "url": "http://admin@192.0.2.10/verify?redirect=http://attacker.com/session/token/long-string-padding-out-url-over-one-hundred-characters",
        "expected_risk": "HIGH RISK",
        "description": "Combines @ deception, >100 characters, raw IP hostname, and HTTP.",
    },
]


@app.route("/")
def index():
    """Render the cybersecurity dashboard interface."""
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """API endpoint to inspect a submitted URL string."""
    try:
        data = request.get_json(silent=True) or {}
        target_url = data.get("url", "")

        if not target_url or not isinstance(target_url, str):
            return (
                jsonify({
                    "valid": False,
                    "error": "Please provide a valid URL string in the 'url' field.",
                    "risk_level": "INVALID INPUT",
                    "warning_count": 0,
                    "warnings": [],
                    "passed_checks": [],
                    "recommendations": [],
                    "disclaimer": checker.MANDATORY_DISCLAIMER,
                }),
                400,
            )

        # Run static inspection
        result = checker.analyze(target_url)
        return jsonify(result), 200

    except Exception as e:
        return (
            jsonify({
                "valid": False,
                "error": f"Internal inspection error: {str(e)}",
                "risk_level": "ERROR",
                "warning_count": 0,
                "warnings": [],
                "disclaimer": checker.MANDATORY_DISCLAIMER,
            }),
            500,
        )


@app.route("/api/sample-urls", methods=["GET"])
def api_samples():
    """Return the list of curated benchmark sample URLs."""
    return jsonify({"samples": BENCHMARK_SAMPLES})


@app.route("/api/health", methods=["GET"])
def api_health():
    """Basic service health check."""
    return jsonify({
        "status": "healthy",
        "tool": "Phishing URL Awareness Checker",
        "mode": "Static Inspection (Offline / Zero Network Calls)",
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting Phishing URL Awareness Checker Web Dashboard...")
    print(f"[*] Running locally on http://127.0.0.1:{port}")
    print(f"[*] Pure static inspection mode active (no external calls).")
    app.run(host="127.0.0.1", port=port, debug=True)

