from flask import Flask, request, jsonify
import os
import re
from concurrent.futures import ThreadPoolExecutor
from toxin import run_toxin_scan

app = Flask(__name__)

# Allowed payload patterns for security
ALLOWED_PAYLOAD_PATTERNS = [
    r'^<script src="https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}/[a-zA-Z0-9_\-/]+\.js"></script>$',
    r'^<script>[\w\W]{1,500}</script>$'  # Basic inline script with length limit
]

@app.route("/")
def home():
    return "BugHunt-GPT3 is running!"

def validate_payload(payload: str) -> bool:
    """Validate the XSS payload against safe patterns"""
    if not payload or len(payload) > 1000:
        return False
    return any(re.match(pattern, payload) for pattern in ALLOWED_PAYLOAD_PATTERNS)

@app.route('/xss_scan', methods=['POST'])
def xss_scan():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({
                'status': 'failed',
                'error': 'Missing URL parameter'
            }), 400

        # Get custom payload or use default Toxssin handler
        custom_payload = data.get('payload')

        # Run scan with optional custom payload
        scan_params = {
            'url': data['url'],
            'payload': custom_payload
        }
        result = run_toxin_scan(**scan_params)

        return jsonify({
            'status': result['status'],
            'xss_vulnerabilities': result['findings']['vulnerabilities'],
            'scan_stats': result['findings']['scan_stats'],
            'tested_url': result['tested_url'],
            'injected_payload': custom_payload if custom_payload else 'Default Toxssin handler.js',
            'handler_url': next(
                (vuln['handler_url'] for vuln in result['findings']['vulnerabilities'] 
                 if 'handler_url' in vuln), None),
            'error': result.get('error')
        })

    except Exception as e:
        return jsonify({
            'status': 'failed',
            'error': f'Server error: {str(e)}',
            'tested_url': data.get('url', 'unknown')
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8000)))
