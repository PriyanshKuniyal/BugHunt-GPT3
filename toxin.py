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
    """Final robust version with guaranteed response structure"""
    response_template = {
        'status': 'failed',
        'success': False,
        'tested_url': target_url,
        'findings': {
            'vulnerabilities': [],
            'scan_stats': {
                'requests': 0,
                'tested_params': 0,
                'success_rate': 0.0,
                'time': '00:00:00'
            },
            'valid': False
        },
        'error': None,
        'debug': {}
    }

    try:
        if not validate_toxin_installation():
            response_template['error'] = 'Toxssin not properly installed'
            response_template['debug']['installation_check'] = False
            return response_template

        proc = subprocess.run(
            ['python', '/app/toxssin/toxssin.py', '-u', target_url,
             '--fast', '--threads=5', '--timeout=20', '--no-crawl'],
            capture_output=True,
            text=True,
            timeout=300
        )

        # Parse output and update response
        findings, parse_error = parse_toxin_output(proc.stdout)
        response_template.update({
            'status': 'completed' if proc.returncode == 0 and findings['valid'] else 'failed',
            'success': proc.returncode == 0 and findings['valid'],
            'findings': findings,
            'debug': {
                'return_code': proc.returncode,
                'output_sample': proc.stdout[:200] + '...' if proc.stdout else None,
                'stderr_sample': proc.stderr[:200] + '...' if proc.stderr else None
            }
        })

        if parse_error:
            response_template['error'] = parse_error

        return response_template

    except subprocess.TimeoutExpired:
        response_template['error'] = 'Scan timed out after 5 minutes'
        response_template['debug']['timeout'] = True
        return response_template
    except Exception as e:
        response_template['error'] = f"Unexpected error: {str(e)}"
        response_template['debug']['exception'] = str(e)
        return response_template




