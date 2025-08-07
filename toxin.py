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

def parse_toxin_output(output: str) -> Tuple[Dict[str, Any], str]:
    """Enhanced output parser with detailed validation"""
    error_msg = ""
    result = {
        'vulnerabilities': [],
        'scan_stats': {
            'requests': 0,
            'tested_params': 0,
            'success_rate': 0.0,
            'time': '00:00:00'
        },
        'valid': False
    }

    # Basic sanity check
    if not output or "Toxssin" not in output:
        error_msg = "No valid Toxssin output detected"
        return result, error_msg

    try:
        # Parse vulnerabilities
        vuln_matches = re.finditer(
            r'\[VULNERABLE\] URL: (.+?)\n.*?Parameter: (.+?)\n.*?Payload: (.+?)(?:\n|$)',
            output,
            re.DOTALL
        )
        result['vulnerabilities'] = [
            {'url': m.group(1), 'parameter': m.group(2), 'payload': m.group(3)}
            for m in vuln_matches
        ]

        # Parse statistics with defensive programming
        stats_patterns = {
            'requests': (r'Total requests:\s+(\d+)', 0),
            'tested_params': (r'Tested parameters:\s+(\d+)', 0),
            'success_rate': (r'Success rate:\s+([\d.]+)%', 0.0),
            'time': (r'Time taken:\s+([\d:.]+)', '00:00:00')
        }

        for stat, (pattern, default) in stats_patterns.items():
            match = re.search(pattern, output)
            if match:
                try:
                    result['scan_stats'][stat] = type(default)(match.group(1))
                    
                    # Additional validation
                    if stat == 'success_rate':
                        if result['scan_stats'][stat] > 100:
                            result['scan_stats'][stat] = 100.0
                        elif result['scan_stats'][stat] < 0:
                            result['scan_stats'][stat] = 0.0
                    elif stat in ['requests', 'tested_params'] and result['scan_stats'][stat] < 0:
                        result['scan_stats'][stat] = 0
                        
                except (ValueError, TypeError) as e:
                    logger.warning(f"Value conversion failed for {stat}: {str(e)}")
                    result['scan_stats'][stat] = default
            else:
                result['scan_stats'][stat] = default

        result['valid'] = bool(result['vulnerabilities']) or any(
            v > 0 if isinstance(v, (int, float)) else v != '00:00:00'
            for v in result['scan_stats'].values()
        )

    except Exception as e:
        error_msg = f"Output parsing error: {str(e)}"
        logger.error(f"{error_msg}\nOutput snippet: {output[:500]}...")

    return result, error_msg

def run_toxin_scan(target_url: str) -> Dict[str, Any]:
    """Completely rewritten scanner with comprehensive diagnostics"""
    if not validate_toxin_installation():
        return {
            'status': 'failed',
            'error': 'Toxssin not properly installed',
            'tested_url': target_url,
            'debug': {'installation_check': False}
        }

    base_args = [
        '--fast',
        '--threads=5',  # Reduced for stability
        '--timeout=20',
        '--no-crawl',
        '--smart',
        '--retries=2',
        '--verbose'
    ]

    try:
        # Run with timeout to prevent hanging
        proc = subprocess.run(
            ['python', '/app/toxssin/toxssin.py', '-u', target_url] + base_args,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
            check=False
        )

        full_output = f"STDOUT:\n{proc.stdout}\n\nSTDERR:\n{proc.stderr}"
        logger.info(f"Toxssin scan completed with return code {proc.returncode}")

        findings, parse_error = parse_toxin_output(proc.stdout)
        
        response = {
            'status': 'completed' if proc.returncode == 0 and findings['valid'] else 'failed',
            'tested_url': target_url,
            'xss_vulnerabilities': findings['vulnerabilities'],
            'scan_stats': findings['scan_stats'],
            'debug': {
                'return_code': proc.returncode,
                'output_sample': full_output[:1000],
                'parser_valid': findings['valid']
            }
        }

        if parse_error:
            response['error'] = parse_error
            response['debug']['parse_error'] = parse_error

        if proc.returncode != 0:
            response['error'] = f"Toxssin exited with code {proc.returncode}"
            response['debug']['stderr'] = proc.stderr[:1000]

        return response

    except subprocess.TimeoutExpired:
        return {
            'status': 'failed',
            'error': 'Scan timed out after 5 minutes',
            'tested_url': target_url,
            'debug': {'timeout': True}
        }
    except Exception as e:
        return {
            'status': 'failed',
            'error': f"Unexpected error: {str(e)}",
            'tested_url': target_url,
            'debug': {'exception': str(e)}
        }

