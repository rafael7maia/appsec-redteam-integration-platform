#!/usr/bin/env python3
"""
Core Scanner - Unified Security Testing Engine v5.0
Combines adaptive reconnaissance, smart validation, and security bridge
"""

import json
from datetime import datetime
from waf_detection import WAFDetector
import time
import random

class AdaptiveRecon:
    def __init__(self, target):
        self.target = target
        self.protection_info = None
        self.scan_strategy = {}
    
    def run_detection(self):
        detector = WAFDetector(self.target)
        return detector.run_detection()
    
    def run(self):
        self.protection_info = self.run_detection()
        return {
            'target': self.target,
            'protection_analysis': self.protection_info,
            'scan_strategy': {'approach': 'adaptive'},
            'recommendations': ['Use smart validation']
        }
from smart_validation_engine import SmartValidationEngine
from enhanced_security_bridge import EnhancedSecurityBridge

class CoreScanner:
    def __init__(self, target_domain, target_profile="entertainment", authorization="bug_bounty_program"):
        self.target_domain = target_domain
        self.target_profile = target_profile
        self.authorization = authorization
        self.appsec_context = None  # Store AppSec results for validation
        self.results = {
            'scan_info': {
                'target': target_domain,
                'profile': target_profile,
                'authorization': authorization,
                'timestamp': datetime.now().isoformat(),
                'version': '5.0'
            },
            'protection_analysis': {},
            'validation_results': {},
            'final_assessment': {}
        }
    
    def set_appsec_context(self, appsec_results):
        """Set AppSec results for Red Team validation"""
        self.appsec_context = appsec_results
        print(f"Red Team received {len(appsec_results.get('sast_results', []))} SAST findings for validation")
        print(f"Red Team received {len(appsec_results.get('dast_results', []))} DAST findings for validation")
    
    def validate_inputs(self):
        """Validate required inputs"""
        if not self.target_domain or '://' in self.target_domain:
            raise ValueError("TARGET_DOMAIN must be domain only (no protocol)")
        
        valid_profiles = ["entertainment", "e-commerce", "financial", "healthcare", "government"]
        if self.target_profile not in valid_profiles:
            raise ValueError(f"TARGET_PROFILE must be one of: {valid_profiles}")
        
        valid_auth = ["bug_bounty_program", "penetration_test", "own_system", "educational_lab"]
        if self.authorization not in valid_auth:
            raise ValueError(f"AUTHORIZATION must be one of: {valid_auth}")
    
    def run_complete_scan(self):
        """Execute complete security scan with smart validation"""
        
        print(f"AI Bug Bounty Framework v5.0 - Starting scan")
        print(f"Target: {self.target_domain}")
        print(f"Profile: {self.target_profile}")
        print(f"Authorization: {self.authorization}")
        print("=" * 60)
        
        # Validate inputs
        self.validate_inputs()
        
        # Phase 1: Adaptive Reconnaissance
        print("\nPhase 1: Adaptive Reconnaissance")
        recon = AdaptiveRecon(self.target_domain)
        recon_results = recon.run()
        self.results['protection_analysis'] = recon_results['protection_analysis']
        
        # Phase 2: Smart Validation Scan with AppSec Context
        print("\nPhase 2: Smart Validation Scan")
        bridge = EnhancedSecurityBridge(target_profile=self.target_profile)
        
        # Pass AppSec context to validation bridge
        if self.appsec_context:
            bridge.set_appsec_findings(self.appsec_context)
        
        validation_results = bridge.scan_with_validation(self.target_domain)
        self.results['validation_results'] = validation_results
        
        # Phase 3: Final Assessment
        print("\nPhase 3: Final Assessment")
        self.generate_final_assessment()
        
        # Save results
        self.save_results()
        
        return self.results
    
    def generate_final_assessment(self):
        """Generate final security assessment"""
        
        validation = self.results['validation_results']
        protection = self.results['protection_analysis']
        
        # Determine overall status
        if validation['vulnerabilities_found'] > 0:
            status = "VULNERABLE"
            severity = validation['summary']['max_severity']
            value = validation['summary']['estimated_total_value']
            recommendation = "Submit findings to bug bounty program"
        else:
            status = "SECURE"
            severity = "Info"
            value = "$0"
            recommendation = "No actionable vulnerabilities found"
        
        self.results['final_assessment'] = {
            'status': status,
            'severity': severity,
            'estimated_value': value,
            'protection_level': protection['protection_level'],
            'vulnerabilities_found': validation['vulnerabilities_found'],
            'false_positives_eliminated': True,
            'recommendation': recommendation,
            'next_steps': self.get_next_steps(status, protection['protection_level'])
        }
        
        # Print summary
        print(f"Status: {status}")
        print(f"Protection Level: {protection['protection_level']}")
        print(f"Vulnerabilities: {validation['vulnerabilities_found']}")
        print(f"Estimated Value: {value}")
        print(f"Recommendation: {recommendation}")
    
    def get_next_steps(self, status, protection_level):
        """Get recommended next steps"""
        
        if status == "VULNERABLE":
            return [
                "Document all findings with evidence",
                "Prepare professional bug bounty report",
                "Submit to official program",
                "Follow responsible disclosure"
            ]
        else:
            if protection_level == "High":
                return [
                    "Target has strong security posture",
                    "Consider manual business logic testing",
                    "Focus on mobile app if available",
                    "Test third-party integrations"
                ]
            else:
                return [
                    "Target appears secure",
                    "Consider deeper manual testing",
                    "Check for recent updates/changes",
                    "Monitor for new attack vectors"
                ]
    
    def save_results(self):
        """Save scan results"""
        filename = f"{self.target_domain}_scan_results_v5.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"\nResults saved: {filename}")
        return filename

def main():
    """Main execution function"""
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: python core_scanner.py <domain> <profile> <authorization>")
        print("\nProfiles: entertainment, e-commerce, financial, healthcare, government")
        print("Authorization: bug_bounty_program, penetration_test, own_system, educational_lab")
        print("\nExample: python core_scanner.py example.com entertainment bug_bounty_program")
        sys.exit(1)
    
    domain = sys.argv[1]
    profile = sys.argv[2]
    auth = sys.argv[3]
    
    try:
        scanner = CoreScanner(domain, profile, auth)
        results = scanner.run_complete_scan()
        
        print("\n" + "=" * 60)
        print("SCAN COMPLETE")
        print("=" * 60)
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()