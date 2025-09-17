#!/usr/bin/env python3
"""
Quick Start Script - AI AppSec + Red Team Integration Platform v5.0
One-command execution with mode selection and validation
"""

import os
import sys
from mode_selector import ModeSelector
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

# Configuration validation is now handled by ModeSelector class

def main():
    """Quick start execution with mode selection"""
    
    print("🚀 AI AppSec + Red Team Integration Platform v5.0 - Quick Start")
    print("=" * 70)
    
    try:
        # Validate mode and configuration
        selector = ModeSelector()
        selector.load_config()
        mode, project = selector.validate_mode()
        
        print("\n" + "=" * 70)
        print("🎯 STARTING EXECUTION")
        print("=" * 70)
        
        # Execute based on mode
        if mode == "appsec":
            results = execute_appsec_mode(selector.config, project)
        elif mode == "appsec_redteam":
            results = execute_integrated_mode(selector.config, project)
        elif mode == "redteam":
            results = execute_redteam_mode(selector.config, project)
        
        # Show summary
        print("\n🎯 EXECUTION COMPLETE")
        print("=" * 70)
        print_results_summary(results, mode, project)
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)

def execute_appsec_mode(config, project):
    """Execute AppSec only mode"""
    print("📋 Executing AppSec Pipeline...")
    
    # Simulate AppSec pipeline
    results = {
        'mode': 'appsec',
        'project': project,
        'appsec_findings': 'Simulated AppSec results',
        'status': 'AppSec analysis complete'
    }
    
    # Save results
    results_file = f"projetos/{project}/appsec_results_v5.json"
    os.makedirs(f"projetos/{project}", exist_ok=True)
    
    import json
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    return results

def execute_integrated_mode(config, project):
    """Execute AppSec + Red Team integrated mode"""
    print("📋 Executing Integrated AppSec + Red Team Pipeline...")
    
    # Execute AppSec first
    appsec_results = execute_appsec_mode(config, project)
    
    # Then Red Team validation
    domain = config['TARGET_DOMAIN']
    profile = config['TARGET_PROFILE']
    auth = config['AUTHORIZATION']
    
    print(f"🎯 Executing Red Team validation on {domain}...")
    
    scanner = CoreScanner(domain, profile, auth)
    redteam_results = scanner.run_complete_scan()
    
    # Integrate results
    integrated_results = {
        'mode': 'appsec_redteam',
        'project': project,
        'appsec_results': appsec_results,
        'redteam_results': redteam_results,
        'status': 'Integrated analysis complete'
    }
    
    # Save integrated results
    results_file = f"projetos/{project}/integrated_results_v5.json"
    
    import json
    with open(results_file, 'w') as f:
        json.dump(integrated_results, f, indent=2)
    
    return integrated_results

def execute_redteam_mode(config, project):
    """Execute Red Team only mode"""
    print("🎯 Executing Red Team Pipeline...")
    
    domain = config['TARGET_DOMAIN']
    profile = config['TARGET_PROFILE']
    auth = config['AUTHORIZATION']
    
    scanner = CoreScanner(domain, profile, auth)
    results = scanner.run_complete_scan()
    
    # Save results in project folder
    results_file = f"projetos/{project}/redteam_results_v5.json"
    os.makedirs(f"projetos/{project}", exist_ok=True)
    
    import json
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    return results

def print_results_summary(results, mode, project):
    """Print execution results summary"""
    print(f"Mode: {mode}")
    print(f"Project: {project}")
    
    if mode == "appsec":
        print(f"Status: {results['status']}")
        print(f"Results: projetos/{project}/appsec_results_v5.json")
    elif mode == "appsec_redteam":
        assessment = results['redteam_results']['final_assessment']
        print(f"Status: {assessment['status']}")
        print(f"Vulnerabilities: {assessment['vulnerabilities_found']}")
        print(f"Value: {assessment['estimated_value']}")
        print(f"Results: projetos/{project}/integrated_results_v5.json")
    elif mode == "redteam":
        assessment = results['final_assessment']
        print(f"Status: {assessment['status']}")
        print(f"Vulnerabilities: {assessment['vulnerabilities_found']}")
        print(f"Value: {assessment['estimated_value']}")
        print(f"Results: projetos/{project}/redteam_results_v5.json")

if __name__ == "__main__":
    main()