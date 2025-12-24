#!/usr/bin/env python3
"""
HexStrike Scanner Wrapper - Phase 2 Integration
Wrapper para HexStrike AI Server com suporte Local e Docker
Integração com AppSec + Red Team Platform
"""

import subprocess
import time
import requests
import json
import logging
import os
import sys
import platform
from pathlib import Path
from typing import Dict, Any, Optional, List

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# HEXSTRIKE SCANNER WRAPPER
# ============================================================================

class HexStrikeScanner:
    """
    Wrapper para HexStrike AI Server
    Suporta execução local ou via Docker
    """

    def __init__(self, target_domain: str, attack_vectors: List[str],
                 authorization: str, use_docker: bool = False, port: int = 8888):
        """
        Initialize HexStrike Scanner

        Args:
            target_domain: Target domain to scan
            attack_vectors: List of attack vectors to use
            authorization: Authorization type for scanning
            use_docker: Whether to use Docker container (default: False)
            port: Port for HexStrike server (default: 8888)
        """
        self.target = target_domain
        self.attack_vectors = attack_vectors if isinstance(attack_vectors, list) else [attack_vectors]
        self.authorization = authorization
        self.use_docker = use_docker
        self.port = port
        self.server_url = f"http://localhost:{port}"
        self.server_process = None
        self.results = {}
        self.hexstrike_dir = Path(__file__).parent / "hexstrike-ai"

    def start_server(self) -> bool:
        """
        Start HexStrike server (local or Docker)

        Returns:
            bool: True if server started successfully
        """
        print(f"\n[*] Starting HexStrike server ({'Docker' if self.use_docker else 'Local'})...")

        try:
            if self.use_docker:
                return self._start_docker_server()
            else:
                return self._start_local_server()
        except Exception as e:
            logger.error(f"[ERROR] Failed to start server: {str(e)}")
            return False

    def _start_local_server(self) -> bool:
        """Start HexStrike server locally"""
        print(f"[*] Starting local HexStrike server on port {self.port}...")

        # Check if hexstrike-ai directory exists
        if not self.hexstrike_dir.exists():
            logger.error(f"[ERROR] hexstrike-ai directory not found at {self.hexstrike_dir}")
            return False

        # Determine python command based on OS
        python_cmd = "python" if platform.system() == "Windows" else "python3"

        try:
            # Start server process
            self.server_process = subprocess.Popen(
                [python_cmd, str(self.hexstrike_dir / "hexstrike_server.py"),
                 "--port", str(self.port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(self.hexstrike_dir),
                universal_newlines=True
            )

            # Wait for server to start
            return self._wait_for_server(max_retries=30, delay=1)

        except Exception as e:
            logger.error(f"[ERROR] Failed to start local server: {str(e)}")
            return False

    def _start_docker_server(self) -> bool:
        """Start HexStrike server via Docker"""
        print(f"[*] Starting HexStrike server via Docker on port {self.port}...")

        # Check if Docker is available
        try:
            subprocess.run(["docker", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.error("[ERROR] Docker not found. Please install Docker or use local server mode.")
            return False

        try:
            # Use PowerShell script on Windows, direct docker-compose on Unix
            if platform.system() == "Windows":
                # Check if start_hexstrike.ps1 exists
                start_script = Path(__file__).parent / "start_hexstrike.ps1"
                if start_script.exists():
                    print(f"[*] Using PowerShell script for Docker startup...")
                    subprocess.run([
                        "powershell", "-ExecutionPolicy", "Bypass",
                        "-File", str(start_script)
                    ], cwd=str(Path(__file__).parent), check=True)
                else:
                    # Fallback to direct docker-compose
                    subprocess.run([
                        "docker-compose", "-f", "docker-compose.hexstrike.yml",
                        "up", "-d"
                    ], cwd=str(Path(__file__).parent), check=True)
            else:
                # Linux/macOS: direct docker-compose
                subprocess.run([
                    "docker-compose", "-f", "docker-compose.hexstrike.yml",
                    "up", "-d"
                ], cwd=str(Path(__file__).parent), check=True)

            # Wait for server to be healthy
            return self._wait_for_server(max_retries=60, delay=2)

        except subprocess.CalledProcessError as e:
            logger.error(f"[ERROR] Docker compose failed: {str(e)}")
            return False

    def _wait_for_server(self, max_retries: int = 30, delay: int = 1) -> bool:
        """Wait for HexStrike server to be ready"""
        print(f"[*] Waiting for server to be ready...")

        for attempt in range(max_retries):
            try:
                response = requests.get(f"{self.server_url}/health", timeout=2)
                if response.status_code == 200:
                    print(f"[+] Server is ready! ({attempt + 1} attempts)")
                    return True
            except requests.exceptions.RequestException:
                pass

            print(f"[.] Attempt {attempt + 1}/{max_retries}...", end="\r")
            time.sleep(delay)

        logger.error("[ERROR] Server did not start in time")
        return False

    def run_smart_scan(self) -> Dict[str, Any]:
        """
        Execute smart scan via HexStrike API

        Returns:
            dict: Scan results
        """
        print(f"\n[*] Executing HexStrike smart scan...")

        payload = {
            "target": self.target,
            "attack_vectors": self.attack_vectors,
            "authorization": self.authorization,
            "analysis_type": "comprehensive"
        }

        try:
            response = requests.post(
                f"{self.server_url}/api/intelligence/smart-scan",
                json=payload,
                timeout=3600  # 1 hour timeout
            )

            if response.status_code == 200:
                self.results = response.json()
                print(f"[+] Scan completed successfully!")
                return self.results
            else:
                logger.error(f"[ERROR] Scan failed with status {response.status_code}")
                return {"success": False, "error": f"HTTP {response.status_code}"}

        except requests.exceptions.Timeout:
            logger.error("[ERROR] Scan timed out after 1 hour")
            return {"success": False, "error": "Timeout"}
        except requests.exceptions.RequestException as e:
            logger.error(f"[ERROR] Request failed: {str(e)}")
            return {"success": False, "error": str(e)}

    def stop_server(self) -> bool:
        """
        Stop HexStrike server

        Returns:
            bool: True if server stopped successfully
        """
        print(f"\n[*] Stopping HexStrike server...")

        try:
            if self.use_docker:
                # Use PowerShell script on Windows, direct docker-compose on Unix
                if platform.system() == "Windows":
                    stop_script = Path(__file__).parent / "stop_hexstrike.ps1"
                    if stop_script.exists():
                        print(f"[*] Using PowerShell script for Docker shutdown...")
                        subprocess.run([
                            "powershell", "-ExecutionPolicy", "Bypass",
                            "-File", str(stop_script)
                        ], cwd=str(Path(__file__).parent), check=False)
                    else:
                        # Fallback to direct docker-compose
                        subprocess.run([
                            "docker-compose", "-f", "docker-compose.hexstrike.yml",
                            "down"
                        ], cwd=str(Path(__file__).parent), check=False)
                else:
                    # Linux/macOS: direct docker-compose
                    subprocess.run([
                        "docker-compose", "-f", "docker-compose.hexstrike.yml",
                        "down"
                    ], cwd=str(Path(__file__).parent), check=False)
            else:
                if self.server_process:
                    self.server_process.terminate()
                    self.server_process.wait(timeout=10)

            print(f"[+] Server stopped")
            return True

        except Exception as e:
            logger.warning(f"[WARNING] Error stopping server: {str(e)}")
            return False

    def generate_report(self) -> Dict[str, Any]:
        """
        Convert HexStrike results to standardized format

        Returns:
            dict: Standardized report format
        """
        if not self.results:
            return {
                "scan_info": {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "target": self.target,
                    "scanner": "HexStrike AI v6.0",
                    "mode": "hexstrike"
                },
                "summary": {
                    "total_findings": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                },
                "findings": []
            }

        # Extract findings from HexStrike results
        findings = []
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        # Parse results if they contain findings
        if isinstance(self.results, dict) and "findings" in self.results:
            findings_data = self.results.get("findings", [])
            if isinstance(findings_data, list):
                for finding in findings_data:
                    severity = finding.get("severity", "MEDIUM").upper()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                    findings.append(finding)

        return {
            "scan_info": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "target": self.target,
                "scanner": "HexStrike AI v6.0",
                "mode": "hexstrike",
                "attack_vectors": self.attack_vectors,
                "authorization": self.authorization
            },
            "summary": {
                "total_findings": len(findings),
                "critical": severity_counts.get("CRITICAL", 0),
                "high": severity_counts.get("HIGH", 0),
                "medium": severity_counts.get("MEDIUM", 0),
                "low": severity_counts.get("LOW", 0)
            },
            "findings": findings,
            "raw_results": self.results
        }

    def execute_full_scan(self) -> Dict[str, Any]:
        """
        Execute full scan: start server, run scan, stop server, generate report

        Returns:
            dict: Complete scan report
        """
        print("[*] Starting HexStrike full scan workflow...")

        # Start server
        if not self.start_server():
            return {
                "success": False,
                "error": "Failed to start HexStrike server",
                "mode": "hexstrike"
            }

        try:
            # Run scan
            scan_results = self.run_smart_scan()

            # Generate report
            report = self.generate_report()

            return {
                "success": True,
                "target": self.target,
                "attack_vectors": self.attack_vectors,
                "report": report,
                "mode": "hexstrike"
            }

        finally:
            # Always stop server
            self.stop_server()

    def get_health_status(self) -> Dict[str, Any]:
        """
        Get HexStrike server health status

        Returns:
            dict: Health status information
        """
        try:
            response = requests.get(f"{self.server_url}/health", timeout=2)
            if response.status_code == 200:
                return {
                    "status": "healthy",
                    "url": self.server_url,
                    "details": response.json() if response.text else {}
                }
            else:
                return {
                    "status": "unhealthy",
                    "url": self.server_url,
                    "http_status": response.status_code
                }
        except requests.exceptions.RequestException as e:
            return {
                "status": "unreachable",
                "url": self.server_url,
                "error": str(e)
            }


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def scan_target(target: str, attack_vectors: List[str] = None,
                authorization: str = "educational_lab",
                use_docker: bool = False) -> Dict[str, Any]:
    """
    Execute HexStrike scan on target

    Args:
        target: Target domain to scan
        attack_vectors: List of attack vectors (default: reconnaissance, vulnerability_scanning)
        authorization: Authorization type
        use_docker: Use Docker for server (default: False)

    Returns:
        dict: Scan results
    """
    if attack_vectors is None:
        attack_vectors = ["reconnaissance", "vulnerability_scanning"]

    scanner = HexStrikeScanner(target, attack_vectors, authorization, use_docker=use_docker)
    return scanner.execute_full_scan()


def check_server_health(port: int = 8888) -> Dict[str, Any]:
    """
    Check if HexStrike server is running and healthy

    Args:
        port: Server port (default: 8888)

    Returns:
        dict: Health status
    """
    scanner = HexStrikeScanner("localhost", [], "educational_lab", port=port)
    return scanner.get_health_status()


# ============================================================================
# CLI INTERFACE
# ============================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python hexstrike_scanner.py <target> [attack_vectors] [--docker]")
        print("\nExample:")
        print("  python hexstrike_scanner.py example.com reconnaissance,vulnerability_scanning")
        print("  python hexstrike_scanner.py example.com reconnaissance --docker")
        sys.exit(1)

    target = sys.argv[1]
    attack_vectors = sys.argv[2].split(",") if len(sys.argv) > 2 else ["reconnaissance", "vulnerability_scanning"]
    use_docker = "--docker" in sys.argv

    # Run scan
    result = scan_target(target, attack_vectors, use_docker=use_docker)

    # Print results
    print("\n" + "=" * 70)
    print("SCAN RESULTS")
    print("=" * 70)
    print(json.dumps(result, indent=2))
