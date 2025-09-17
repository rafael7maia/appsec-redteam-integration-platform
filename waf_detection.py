#!/usr/bin/env python3
"""
WAF/CDN Detection Module - HexStrike AI v4.0
Detects Web Application Firewalls and CDNs before vulnerability testing
"""

import requests
import socket
import subprocess
import json
import re
from urllib.parse import urlparse

class WAFDetector:
    def __init__(self, target):
        self.target = target.replace('http://', '').replace('https://', '')
        self.results = {
            'target': self.target,
            'waf_detected': False,
            'cdn_detected': False,
            'waf_type': None,
            'cdn_type': None,
            'protection_level': 'Unknown',
            'bypass_techniques': [],
            'recommended_approach': []
        }
    
    def detect_waf_headers(self, url):
        """Detect WAF through HTTP headers"""
        waf_signatures = {
            'cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
            'akamai': ['akamai', 'x-akamai', 'server: AkamaiGHost'],
            'aws_waf': ['x-amzn-requestid', 'x-amz-cf-id'],
            'incapsula': ['x-iinfo', 'incap_ses'],
            'sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
            'barracuda': ['barra', 'x-barracuda'],
            'f5_bigip': ['f5-bigip', 'x-wa-info'],
            'fortinet': ['fortigate', 'x-fortigate']
        }
        
        try:
            response = requests.get(f"https://{url}", timeout=10, verify=False)
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            
            for waf, signatures in waf_signatures.items():
                for sig in signatures:
                    if any(sig in h for h in headers.keys()) or any(sig in v for v in headers.values()):
                        return waf, headers
            
            return None, headers
        except:
            return None, {}
    
    def detect_waf_response(self, url):
        """Detect WAF through response patterns"""
        test_payloads = [
            "?id=1'",
            "?test=<script>alert(1)</script>",
            "?cmd=cat /etc/passwd",
            "/../../../etc/passwd"
        ]
        
        waf_patterns = {
            'cloudflare': ['cloudflare', 'cf-ray', 'attention required'],
            'akamai': ['reference #', 'access denied', 'akamai'],
            'aws_waf': ['aws waf', 'forbidden'],
            'incapsula': ['incapsula', 'request unsuccessful'],
            'sucuri': ['sucuri', 'access denied'],
            'barracuda': ['barracuda', 'blocked'],
            'f5_bigip': ['f5', 'bigip', 'the requested url was rejected']
        }
        
        for payload in test_payloads:
            try:
                response = requests.get(f"https://{url}{payload}", timeout=5, verify=False)
                content = response.text.lower()
                
                for waf, patterns in waf_patterns.items():
                    if any(pattern in content for pattern in patterns):
                        return waf, response.status_code
            except:
                continue
        
        return None, None
    
    def detect_cdn(self, url):
        """Detect CDN through various methods"""
        cdn_signatures = {
            'cloudflare': ['cloudflare', 'cf-ray'],
            'akamai': ['akamai', 'edgekey', 'edgesuite'],
            'fastly': ['fastly', 'x-served-by'],
            'amazon_cloudfront': ['cloudfront', 'x-amz-cf-id'],
            'maxcdn': ['maxcdn', 'netdna'],
            'keycdn': ['keycdn'],
            'cloudinary': ['cloudinary']
        }
        
        try:
            # Check CNAME records
            result = subprocess.run(['nslookup', url], capture_output=True, text=True)
            dns_output = result.stdout.lower()
            
            for cdn, signatures in cdn_signatures.items():
                if any(sig in dns_output for sig in signatures):
                    return cdn
        except:
            pass
        
        return None
    
    def analyze_protection_level(self):
        """Analyze overall protection level"""
        if self.results['waf_detected'] and self.results['cdn_detected']:
            self.results['protection_level'] = 'High'
            self.results['bypass_techniques'] = [
                'Manual testing with legitimate user sessions',
                'Rate limiting and request spacing',
                'User-Agent rotation',
                'IP rotation through proxies',
                'Parameter pollution techniques'
            ]
        elif self.results['waf_detected'] or self.results['cdn_detected']:
            self.results['protection_level'] = 'Medium'
            self.results['bypass_techniques'] = [
                'Custom payload encoding',
                'HTTP method variation',
                'Header manipulation',
                'Slow HTTP attacks'
            ]
        else:
            self.results['protection_level'] = 'Low'
            self.results['bypass_techniques'] = [
                'Standard automated scanning',
                'Direct vulnerability testing'
            ]
    
    def get_recommendations(self):
        """Get testing recommendations based on protection level"""
        if self.results['protection_level'] == 'High':
            self.results['recommended_approach'] = [
                'Focus on business logic vulnerabilities',
                'Manual testing approach required',
                'Test mobile applications separately',
                'Analyze third-party integrations',
                'Use legitimate user sessions for testing'
            ]
        elif self.results['protection_level'] == 'Medium':
            self.results['recommended_approach'] = [
                'Combine automated and manual testing',
                'Use evasion techniques for automated tools',
                'Focus on application-specific vulnerabilities',
                'Test different endpoints and subdomains'
            ]
        else:
            self.results['recommended_approach'] = [
                'Standard automated vulnerability scanning',
                'Comprehensive port and service enumeration',
                'Direct exploitation attempts'
            ]
    
    def run_detection(self):
        """Run complete WAF/CDN detection"""
        print(f"Analyzing protection mechanisms for {self.target}")
        
        # Detect WAF through headers
        waf_headers, headers = self.detect_waf_headers(self.target)
        if waf_headers:
            self.results['waf_detected'] = True
            self.results['waf_type'] = waf_headers
            print(f"WAF detected: {waf_headers}")
        
        # Detect WAF through response patterns
        waf_response, status_code = self.detect_waf_response(self.target)
        if waf_response and not self.results['waf_detected']:
            self.results['waf_detected'] = True
            self.results['waf_type'] = waf_response
            print(f"WAF detected via response: {waf_response}")
        
        # Detect CDN
        cdn = self.detect_cdn(self.target)
        if cdn:
            self.results['cdn_detected'] = True
            self.results['cdn_type'] = cdn
            print(f"CDN detected: {cdn}")
        
        # Analyze protection level
        self.analyze_protection_level()
        self.get_recommendations()
        
        print(f"Protection Level: {self.results['protection_level']}")
        
        return self.results

def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 waf_detection.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    detector = WAFDetector(target)
    results = detector.run_detection()
    
    print("\n" + "="*50)
    print("WAF/CDN DETECTION RESULTS")
    print("="*50)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()