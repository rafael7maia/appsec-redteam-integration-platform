#!/usr/bin/env python3
"""
Quick Start Script - AI AppSec + Red Team Integration Platform v5.0
One-command execution with mode selection and validation
"""

import os
import sys
from mode_selector_simple import ModeSelector
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
    
    print("AI AppSec + Red Team Integration Platform v5.0 - Quick Start")
    print("=" * 70)
    
    try:
        # Validate mode and configuration
        selector = ModeSelector()
        selector.load_config()
        mode, project = selector.validate_mode()
        
        print("\n" + "=" * 70)
        print("STARTING EXECUTION")
        print("=" * 70)
        
        # Execute based on mode
        if mode == "appsec":
            results = execute_appsec_mode(selector.config, project)
        elif mode == "appsec_redteam":
            results = execute_integrated_mode(selector.config, project)
        elif mode == "redteam":
            results = execute_redteam_mode(selector.config, project)
        
        # Show summary
        print("\nEXECUTION COMPLETE")
        print("=" * 70)
        
        # Generate professional reports
        generate_professional_reports(project, mode)
        
        print_results_summary(results, mode, project)
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

def execute_appsec_mode(config, project):
    """Execute AppSec only mode"""
    print("Executing AppSec Pipeline...")
    
    # Import AppSec scanner
    from appsec_scanner import AppSecScanner
    
    # Set up paths
    project_path = f"projetos/{project}/app"
    target_url = None
    
    # Build target URL if domain is provided
    if config.get('TARGET_DOMAIN'):
        domain = config['TARGET_DOMAIN']
        if not domain.startswith('http'):
            target_url = f"http://{domain}"
        else:
            target_url = domain
    
    # Run AppSec scanner
    scanner = AppSecScanner(project_path, target_url)
    appsec_results = scanner.run_full_pipeline()
    
    # Prepare results
    results = {
        'mode': 'appsec',
        'project': project,
        'appsec_results': appsec_results,
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
    print("Executing Integrated AppSec + Red Team Pipeline...")
    
    # Import required modules
    from appsec_scanner import AppSecScanner
    from smart_validation_engine import SmartValidationEngine
    
    # Execute AppSec first
    print("\nPhase 1: AppSec Analysis")
    project_path = f"projetos/{project}/app"
    domain = config['TARGET_DOMAIN']
    target_url = f"http://{domain}" if not domain.startswith('http') else domain
    
    scanner = AppSecScanner(project_path, target_url)
    appsec_results = scanner.run_full_pipeline()
    
    # Then Red Team validation with AppSec context
    print("\nPhase 2: Red Team Validation")
    profile = config['TARGET_PROFILE']
    auth = config['AUTHORIZATION']
    
    # Pass AppSec results to Red Team for validation
    core_scanner = CoreScanner(domain, profile, auth)
    core_scanner.set_appsec_context(appsec_results)  # New method
    redteam_results = core_scanner.run_complete_scan()
    
    # Smart validation and integration
    print("\nPhase 3: Smart Validation & Integration")
    validator = SmartValidationEngine()
    final_assessment = validator.generate_integrated_assessment(
        appsec_results, redteam_results, profile
    )
    
    # Integrate results
    integrated_results = {
        'mode': 'appsec_redteam',
        'project': project,
        'target_domain': domain,
        'target_profile': profile,
        'appsec_results': appsec_results,
        'redteam_results': redteam_results,
        'final_assessment': final_assessment,
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
    print("Executing Red Team Pipeline...")
    
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

def generate_professional_reports(project, mode):
    """Generate professional bug bounty reports"""
    try:
        if mode in ['appsec_redteam', 'appsec']:
            results_file = f"projetos/{project}/integrated_results_v5.json"
            if not os.path.exists(results_file):
                results_file = f"projetos/{project}/appsec_results_v5.json"
            
            if os.path.exists(results_file):
                print("\nGenerating professional reports...")
                from report_generator import BugBountyReportGenerator
                
                generator = BugBountyReportGenerator(results_file)
                html_file, json_file = generator.save_reports(f"projetos/{project}")
                print(f"HTML Report: {html_file}")
                print(f"JSON Report: {json_file}")
            else:
                print("\nSkipping report generation - results file not found")
    except Exception as e:
        print(f"\nWarning: Could not generate reports - {e}")

def print_results_summary(results, mode, project):
    """Print execution results summary"""
    print(f"Mode: {mode}")
    print(f"Project: {project}")
    
    # Debug: Show what results we have
    if 'final_assessment' in results:
        print(f"\n=== INTEGRATED ASSESSMENT ===")
        assessment = results['final_assessment']
        print(f"Status: {assessment.get('status', 'Unknown')}")
        print(f"Total Vulnerabilities: {assessment.get('vulnerabilities_found', 0)}")
        print(f"AppSec Vulnerabilities: {assessment.get('appsec_vulnerabilities', 0)}")
        print(f"Red Team Vulnerabilities: {assessment.get('redteam_vulnerabilities', 0)}")
        print(f"Estimated Value: {assessment.get('estimated_value', '$0')}")
        print(f"False Positives Eliminated: {assessment.get('false_positives_eliminated', False)}")
        return
    
    print(f"\n=== MODE-SPECIFIC RESULTS ===")
    
    if mode == "appsec":
        print(f"Status: {results['status']}")
        print(f"Results: projetos/{project}/appsec_results_v5.json")
    elif mode == "appsec_redteam":
        # Show integrated assessment, not just red team
        integrated_assessment = results.get('final_assessment', {})
        if integrated_assessment:
            print(f"Status: {integrated_assessment['status']}")
            print(f"Vulnerabilities: {integrated_assessment['vulnerabilities_found']}")
            print(f"AppSec Issues: {integrated_assessment['appsec_vulnerabilities']}")
            print(f"Red Team Issues: {integrated_assessment['redteam_vulnerabilities']}")
            print(f"Value: {integrated_assessment['estimated_value']}")
        else:
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