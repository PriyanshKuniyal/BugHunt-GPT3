import subprocess
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional

def safe_regex_search(pattern: str, text: str, default: Any = None) -> Any:
    """Safe regex search with default fallback"""
    match = re.search(pattern, text)
    return match.group(1) if match else default

def parse_toxin_output(output: str) -> Dict[str, Any]:
    """Robust XSS results parser with comprehensive error handling"""
    try:
        # Extract vulnerabilities
        xss_re = re.compile(
            r'\[VULNERABLE\] URL: (.+?)\n.*?'
            r'Parameter: (.+?)\n.*?'
            r'Payload: (.+?)(?:\n|$)',
            re.DOTALL
        )
        
        vulnerabilities = [
            {'url': m[0], 'parameter': m[1], 'payload': m[2]}
            for m in xss_re.finditer(output)
        ]

        # Extract scan statistics with fallback values
        requests = safe_regex_search(r'Total requests:\s+(\d+)', output, '0')
        tested_params = safe_regex_search(r'Tested parameters:\s+(\d+)', output, '0')
        success_rate = safe_regex_search(r'Success rate:\s+([\d.]+)%', output, '0')
        scan_time = safe_regex_search(r'Time taken:\s+([\d:.]+)', output, '00:00:00')

        return {
            'vulnerabilities': vulnerabilities,
            'scan_stats': {
                'requests': int(requests),
                'tested_params': int(tested_params),
                'success_rate': float(success_rate),
                'time': scan_time
            },
            'valid': bool(vulnerabilities)  # Flag indicating if any vulnerabilities were found
        }
        
    except Exception as e:
        return {
            'error': f"Output parsing failed: {str(e)}",
            'raw_output': output[-2000:],  # Last 2KB for debugging
            'valid': False
        }

def run_toxin_scan(args: List[str]) -> Dict[str, Any]:
    """High-reliability XSS scanner with comprehensive error handling"""
    responses = {
        b"Follow redirects? [y/N]": b"y\n",
        b"Save results to file? [y/N]": b"N\n",
        b"Continue scanning? [Y/n]": b"Y\n"
    }

    speed_args = [
        '--fast',
        '--threads=10',
        '--timeout=15',
        '--no-crawl',
        '--smart',
        '--retries=1'
    ]

    try:
        with ThreadPoolExecutor() as executor:
            proc = subprocess.Popen(
                ['python', '/app/toxssin/toxssin.py'] + speed_args + args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                text=True
            )

            output = []
            future = executor.submit(proc.communicate)

            while not future.done():
                line = proc.stdout.readline()
                if not line:
                    break
                output.append(line)
                
                for prompt, response in responses.items():
                    if prompt.decode('utf-8') in line:
                        proc.stdin.write(response.decode('utf-8'))
                        proc.stdin.flush()

            stdout, stderr = future.result()
            full_output = ''.join(output) + stdout + stderr
            
            return {
                'findings': parse_toxin_output(full_output),
                'success': proc.returncode == 0,
                'raw_output': full_output[-5000:],  # Last 5KB for debugging
                'error': None if proc.returncode == 0 else stderr
            }

    except FileNotFoundError as e:
        return {
            'success': False,
            'error': f"Toxssin executable not found: {str(e)}",
            'findings': {'valid': False},
            'raw_output': ''
        }
    except Exception as e:
        return {
            'success': False,
            'error': f"Unexpected error: {str(e)}",
            'findings': {'valid': False},
            'raw_output': ''
        }
