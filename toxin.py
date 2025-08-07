import subprocess
import re
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Tuple

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def validate_toxin_installation() -> bool:
    """Check if Toxssin is properly installed and executable"""
    try:
        proc = subprocess.run(
            ['python', '/app/toxssin/toxssin.py', '--version'],
            capture_output=True,
            text=True,
            timeout=10
        )
        return "Toxssin" in proc.stdout
    except Exception as e:
        logger.error(f"Toxssin validation failed: {str(e)}")
        return False

def run_toxin_scan(target_url: str) -> Dict[str, Any]:
    """Robust XSS scanner with guaranteed response structure"""
    DEFAULT_RESPONSE = {
        'status': 'failed',
        'success': False,
        'tested_url': target_url,
        'xss_vulnerabilities': [],
        'scan_stats': {
            'requests': 0,
            'tested_params': 0,
            'success_rate': 0.0,
            'time': '00:00:00'
        },
        'error': None,
        'debug': {}
    }

    try:
        # Validate installation first
        if not validate_toxin_installation():
            return {
                **DEFAULT_RESPONSE,
                'error': 'Toxssin not properly installed',
                'debug': {'installation_check': False}
            }

        base_args = [
            '--fast',
            '--threads=5',
            '--timeout=20',
            '--no-crawl',
            '--smart',
            '--retries=2',
            '--verbose',
            '-u', target_url
        ]

        # Run the scan
        proc = subprocess.run(
            ['python', '/app/toxssin/toxssin.py'] + base_args,
            capture_output=True,
            text=True,
            timeout=300,
            check=False
        )

        # Parse results
        findings, parse_error = parse_toxin_output(proc.stdout)
        
        response = {
            **DEFAULT_RESPONSE,
            'status': 'completed' if proc.returncode == 0 and findings.get('valid', False) else 'failed',
            'success': proc.returncode == 0 and findings.get('valid', False),
            'xss_vulnerabilities': findings.get('vulnerabilities', []),
            'scan_stats': findings.get('scan_stats', DEFAULT_RESPONSE['scan_stats']),
            'debug': {
                'return_code': proc.returncode,
                'output_sample': f"{proc.stdout[:200]}...",
                'parser_valid': findings.get('valid', False),
                'stderr_sample': proc.stderr[:200] if proc.stderr else None
            }
        }

        if parse_error:
            response['error'] = parse_error
            response['debug']['parse_error'] = parse_error

        if proc.returncode != 0:
            response['error'] = response.get('error', '') + f" | Process exited with code {proc.returncode}"

        return response

    except subprocess.TimeoutExpired:
        return {
            **DEFAULT_RESPONSE,
            'error': 'Scan timed out after 5 minutes',
            'debug': {'timeout': True}
        }
    except Exception as e:
        return {
            **DEFAULT_RESPONSE,
            'error': f"Unexpected error: {str(e)}",
            'debug': {'exception': str(e)}
        }



