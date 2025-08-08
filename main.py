from flask import Flask, request, jsonify
import os
from pathlib import Path
from toxin import ToxssinController  # Assuming you've implemented the class I provided earlier
import logging

app = Flask(__name__)
toxssin = ToxssinController()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route("/")
def home():
    return "BugHunt-GPT3 XSS Scanning Service"

@app.route('/xss_scan', methods=['POST'])
def xss_scan():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({
                'status': 'failed',
                'error': 'Missing URL parameter'
            }), 400

        # Validate input URL
        if not data['url'].startswith(('http://', 'https://')):
            return jsonify({
                'status': 'failed',
                'error': 'Invalid URL format - must start with http:// or https://'
            }), 400

        # Run the scan
        result = toxssin.run_scan(
            target_url=data['url'],
            custom_payload=data.get('payload')  # Optional custom payload
        )

        # Prepare response
        response = {
            'status': result['status'],
            'tested_url': result['tested_url'],
            'handler_url': None,
            'injected_payload': data.get('payload', 'Default Toxssin handler'),
            'session_active': False,
            'error': result.get('error'),
            'findings': result.get('findings', [])
        }

        # Extract handler URL if available
        if result.get('findings', {}).get('vulnerabilities'):
            for vuln in result['findings']['vulnerabilities']:
                if 'handler_url' in vuln:
                    response['handler_url'] = vuln['handler_url']
                    response['session_active'] = True
                    break

        return jsonify(response)

    except Exception as e:
        logger.error(f"XSS Scan failed: {str(e)}")
        return jsonify({
            'status': 'failed',
            'error': f'Server error: {str(e)}',
            'tested_url': data.get('url', 'unknown')
        }), 500

@app.route('/toxssin/sessions', methods=['GET'])
def list_sessions():
    """Endpoint to check active Toxssin sessions"""
    try:
        # This would require implementing get_active_sessions() in your ToxssinController
        sessions = toxssin.get_active_sessions()
        return jsonify({
            'status': 'success',
            'active_sessions': len(sessions),
            'sessions': sessions
        })
    except Exception as e:
        return jsonify({
            'status': 'failed',
            'error': str(e)
        }), 500

if __name__ == '__main__':
    # Ensure certificates exist before starting
    if not toxssin.validate_certificates():
        logger.error("Failed to generate SSL certificates - exiting")
        exit(1)
        
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, ssl_context=(
        toxssin.cert_path, 
        toxssin.key_path
    ))

