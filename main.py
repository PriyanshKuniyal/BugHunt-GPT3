from flask import Flask, request, jsonify
import os
from concurrent.futures import ThreadPoolExecutor
from toxin import  run_toxin_scan

app = Flask(__name__)

@app.route("/")
def home():
    return "BugHunt-GPT3 is running!"

@app.route('/xss_scan', methods=['POST'])
def xss_scan():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({
                'status': 'failed',
                'error': 'Missing URL parameter'
            }), 400

        result = run_toxin_scan(data['url'])
        return jsonify({
            'status': result['status'],
            'xss_vulnerabilities': result['findings']['vulnerabilities'],
            'scan_stats': result['findings']['scan_stats'],
            'tested_url': result['tested_url'],
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


