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
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'URL required'}), 400

    args = [
        '-u', data['url'],
        '--method', data.get('method', 'GET'),
        '--delay', '0',
        '--timeout', '15'
    ]

    if data.get('cookies'):
        args.extend(['--cookies', data['cookies'][:1024]])
    
    if data.get('headers'):
        args.extend(['--headers', data['headers'][:1024]])

    result = run_toxin_scan(args)
    
    return jsonify({
        'status': 'completed' if result['success'] else 'failed',
        'xss_vulnerabilities': result['findings']['vulnerabilities'],
        'scan_stats': result['findings']['scan_stats'],
        'tested_url': data['url']
    })
    

if __name__ == '__main__':

    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8000)))

