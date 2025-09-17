#!/usr/bin/env python3
"""
Quick Start Script - AI Bug Bounty Framework v5.0
One-command execution with input validation
"""

import os
import sys
from core_scanner import CoreScanner

def load_config():
    """Load configuration from config.env file"""
    config = {}
    
    if os.path.exists('config.env'):
        with open('config.env', 'r') as f:
            for line in f:
                if '=' in line and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    config[key] = value
    
    return config

def validate_config(config):
    """Validate required configuration"""
    required = ['TARGET_DOMAIN', 'TARGET_PROFILE', 'AUTHORIZATION']
    missing = [key for key in required if key not in config]
    
    if missing:
        print("❌ Missing required configuration:")
        for key in missing:
            print(f"   {key}")
        print("\nCreate config.env file with:")
        print("TARGET_DOMAIN=example.com")
        print("TARGET_PROFILE=entertainment")
        print("AUTHORIZATION=bug_bounty_program")
        return False
    
    return True

def main():
    """Quick start execution"""
    
    print("🚀 AI Bug Bounty Framework v5.0 - Quick Start")
    print("=" * 50)
    
    # Load configuration
    config = load_config()
    
    if not validate_config(config):
        sys.exit(1)
    
    # Extract values
    domain = config['TARGET_DOMAIN']
    profile = config['TARGET_PROFILE']
    auth = config['AUTHORIZATION']
    
    print(f"Target: {domain}")
    print(f"Profile: {profile}")
    print(f"Authorization: {auth}")
    print("=" * 50)
    
    try:
        # Run scan
        scanner = CoreScanner(domain, profile, auth)
        results = scanner.run_complete_scan()
        
        # Show summary
        assessment = results['final_assessment']
        print("\n🎯 QUICK START COMPLETE")
        print("=" * 50)
        print(f"Status: {assessment['status']}")
        print(f"Vulnerabilities: {assessment['vulnerabilities_found']}")
        print(f"Value: {assessment['estimated_value']}")
        print(f"Next: {assessment['recommendation']}")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()