#!/usr/bin/env python3
"""
AppSec Scanner - Source Code Analysis Pipeline
Performs SCA, Secrets Detection, SAST, and DAST analysis
"""

import os
import json
import subprocess
import re
from pathlib import Path
import requests
from datetime import datetime

class AppSecScanner:
    def __init__(self, project_path, target_url=None):
        self.project_path = Path(project_path)
        self.target_url = target_url
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'project_path': str(project_path),
            'target_url': target_url,
            'sca_results': [],
            'secrets_results': [],
            'sast_results': [],
            'dast_results': []
        }
    
    def run_sca_analysis(self):
        """Software Composition Analysis - Check dependencies"""
        print("Running SCA Analysis...")
        
        # Check requirements.txt for known vulnerabilities
        req_file = self.project_path / 'requirements.txt'
        if req_file.exists():
            with open(req_file, 'r') as f:
                requirements = f.read()
            
            # Simulate vulnerability check
            vulnerable_packages = [
                {'package': 'Flask', 'version': '2.3.3', 'vulnerability': 'CVE-2023-30861', 'severity': 'Medium'},
                {'package': 'Werkzeug', 'version': '2.3.7', 'vulnerability': 'CVE-2023-25577', 'severity': 'High'}
            ]
            
            for vuln in vulnerable_packages:
                if vuln['package'].lower() in requirements.lower():
                    self.results['sca_results'].append({
                        'type': 'vulnerable_dependency',
                        'package': vuln['package'],
                        'version': vuln['version'],
                        'vulnerability': vuln['vulnerability'],
                        'severity': vuln['severity'],
                        'description': f"Vulnerable version of {vuln['package']} detected"
                    })
        
        print(f"SCA Analysis complete - {len(self.results['sca_results'])} issues found")
    
    def run_secrets_detection(self):
        """Detect hardcoded secrets in source code"""
        print("Running Secrets Detection...")
        
        # Patterns for common secrets
        secret_patterns = {
            'hardcoded_key': r'secret_key\s*=\s*["\']([^"\']+)["\']',
            'api_key': r'api_key\s*=\s*["\']([^"\']+)["\']',
            'password': r'password\s*=\s*["\']([^"\']+)["\']',
            'token': r'token\s*=\s*["\']([^"\']+)["\']'
        }
        
        # Scan Python files
        for py_file in self.project_path.rglob('*.py'):
            with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            for secret_type, pattern in secret_patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    self.results['secrets_results'].append({
                        'type': 'hardcoded_secret',
                        'secret_type': secret_type,
                        'file': str(py_file.relative_to(self.project_path)),
                        'line': line_num,
                        'value': match.group(1)[:20] + '...',
                        'severity': 'High'
                    })
        
        print(f"Secrets Detection complete - {len(self.results['secrets_results'])} secrets found")
    
    def run_sast_analysis(self):
        """Static Application Security Testing"""
        print("Running SAST Analysis...")
        
        # Scan for common vulnerability patterns
        vuln_patterns = {
            'sql_injection': r'f["\'].*SELECT.*{.*}.*["\']|cursor\.execute\(f["\'].*["\']',
            'command_injection': r'subprocess\.run\(f["\'].*{.*}.*["\']|os\.system\(.*\+',
            'xss': r'render_template_string\(f["\'].*{.*}.*["\']',
            'insecure_deserialization': r'pickle\.loads\(',
            'weak_crypto': r'hashlib\.md5\(|hashlib\.sha1\('
        }
        
        for py_file in self.project_path.rglob('*.py'):
            with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for vuln_type, pattern in vuln_patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    self.results['sast_results'].append({
                        'type': 'code_vulnerability',
                        'vulnerability': vuln_type,
                        'file': str(py_file.relative_to(self.project_path)),
                        'line': line_num,
                        'code_snippet': match.group(0),
                        'severity': self._get_severity(vuln_type)
                    })
        
        print(f"SAST Analysis complete - {len(self.results['sast_results'])} vulnerabilities found")
    
    def run_dast_analysis(self):
        """Dynamic Application Security Testing"""
        if not self.target_url:
            print("DAST Analysis skipped - no target URL provided")
            return
        
        print("Running DAST Analysis...")
        
        # Basic web vulnerability tests
        test_cases = [
            {
                'name': 'SQL Injection Test',
                'url': f"{self.target_url}/login",
                'method': 'POST',
                'data': {'username': "admin' OR '1'='1", 'password': 'test'},
                'expected_indicators': ['dashboard', 'welcome', 'admin']
            },
            {
                'name': 'XSS Test',
                'url': f"{self.target_url}/search?q=<script>alert('xss')</script>",
                'method': 'GET',
                'expected_indicators': ['<script>', 'alert']
            },
            {
                'name': 'IDOR Test',
                'url': f"{self.target_url}/user/1",
                'method': 'GET',
                'expected_indicators': ['cpf', 'credit', 'card']
            }
        ]
        
        for test in test_cases:
            try:
                if test['method'] == 'POST':
                    response = requests.post(test['url'], data=test.get('data', {}), timeout=10)
                else:
                    response = requests.get(test['url'], timeout=10)
                
                # Check for vulnerability indicators
                for indicator in test['expected_indicators']:
                    if indicator.lower() in response.text.lower():
                        self.results['dast_results'].append({
                            'type': 'web_vulnerability',
                            'test_name': test['name'],
                            'url': test['url'],
                            'method': test['method'],
                            'status_code': response.status_code,
                            'indicator_found': indicator,
                            'severity': 'High'
                        })
                        break
            
            except requests.RequestException as e:
                print(f"DAST test failed for {test['name']}: {e}")
        
        print(f"DAST Analysis complete - {len(self.results['dast_results'])} vulnerabilities found")
    
    def _get_severity(self, vuln_type):
        """Get severity level for vulnerability type"""
        high_severity = ['sql_injection', 'command_injection', 'insecure_deserialization']
        medium_severity = ['xss', 'weak_crypto']
        
        if vuln_type in high_severity:
            return 'High'
        elif vuln_type in medium_severity:
            return 'Medium'
        else:
            return 'Low'
    
    def generate_report(self):
        """Generate comprehensive AppSec report"""
        total_issues = (len(self.results['sca_results']) + 
                       len(self.results['secrets_results']) + 
                       len(self.results['sast_results']) + 
                       len(self.results['dast_results']))
        
        print(f"\nAppSec Analysis Summary:")
        print(f"   SCA Issues: {len(self.results['sca_results'])}")
        print(f"   Secrets Found: {len(self.results['secrets_results'])}")
        print(f"   SAST Vulnerabilities: {len(self.results['sast_results'])}")
        print(f"   DAST Vulnerabilities: {len(self.results['dast_results'])}")
        print(f"   Total Issues: {total_issues}")
        
        return self.results
    
    def run_full_pipeline(self):
        """Execute complete AppSec pipeline"""
        print("Starting AppSec Pipeline...")
        
        self.run_sca_analysis()
        self.run_secrets_detection()
        self.run_sast_analysis()
        self.run_dast_analysis()
        
        return self.generate_report()

if __name__ == "__main__":
    # Example usage
    scanner = AppSecScanner(
        project_path="projetos/techcorp/app",
        target_url="http://localhost:5000"
    )
    
    results = scanner.run_full_pipeline()
    
    # Save results
    with open("projetos/techcorp/appsec_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("\nAppSec analysis complete! Results saved to appsec_results.json")