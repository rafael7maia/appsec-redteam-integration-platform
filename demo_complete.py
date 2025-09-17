#!/usr/bin/env python3
"""
Complete Demo Script - AI AppSec + Red Team Integration Platform v5.0
Demonstrates the complete workflow from vulnerable app deployment to security testing
"""

import os
import sys
import subprocess
import time
import json
import requests

def print_banner():
    """Print demo banner"""
    print("=" * 80)
    print("AI AppSec + Red Team Integration Platform v5.0 - Complete Demo")
    print("=" * 80)
    print("This demo will:")
    print("1. Deploy TechCorp vulnerable application (Docker)")
    print("2. Execute AppSec + Red Team integrated analysis")
    print("3. Show real vulnerability detection results")
    print("4. Demonstrate smart false positive elimination")
    print("=" * 80)

def check_prerequisites():
    """Check if Docker is available"""
    try:
        result = subprocess.run(['docker', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print("Docker is available")
            return True
        else:
            print("ERROR: Docker is not available")
            return False
    except FileNotFoundError:
        print("ERROR: Docker is not installed")
        print("Please install Docker Desktop from https://docker.com")
        return False

def deploy_vulnerable_app():
    """Deploy TechCorp vulnerable application"""
    print("\nStep 1: Deploying TechCorp Vulnerable Application...")
    
    # Change to app directory
    app_dir = "projetos/techcorp/app"
    if not os.path.exists(app_dir):
        print(f"ERROR: {app_dir} not found")
        return False
    
    # Build Docker image
    print("Building Docker image...")
    build_cmd = ['docker', 'build', '-t', 'techcorp-vulnerable', '.']
    result = subprocess.run(build_cmd, cwd=app_dir, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"ERROR: Failed to build Docker image: {result.stderr}")
        return False
    
    # Stop any existing container
    subprocess.run(['docker', 'stop', 'techcorp-vuln'], capture_output=True)
    subprocess.run(['docker', 'rm', 'techcorp-vuln'], capture_output=True)
    
    # Run container
    print("Starting vulnerable application on port 9000...")
    run_cmd = ['docker', 'run', '-d', '-p', '9000:5000', '--name', 'techcorp-vuln', 'techcorp-vulnerable']
    result = subprocess.run(run_cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"ERROR: Failed to start container: {result.stderr}")
        return False
    
    # Wait for application to start
    print("Waiting for application to start...")
    time.sleep(5)
    
    # Test if application is accessible
    try:
        response = requests.get('http://localhost:9000', timeout=10)
        if response.status_code == 200 and 'TechCorp' in response.text:
            print("SUCCESS: TechCorp application is running at http://localhost:9000")
            return True
        else:
            print("ERROR: Application is not responding correctly")
            return False
    except requests.RequestException as e:
        print(f"ERROR: Cannot connect to application: {e}")
        return False

def configure_platform():
    """Configure platform for demo"""
    print("\nStep 2: Configuring Platform...")
    
    config_content = """OPERATION_MODE=appsec_redteam
PROJECT_NAME=techcorp
TARGET_DOMAIN=localhost:9000
TARGET_PROFILE=e-commerce
AUTHORIZATION=educational_lab"""
    
    with open('config.env', 'w') as f:
        f.write(config_content)
    
    print("Configuration saved to config.env")
    print("Mode: AppSec + Red Team (Complete)")
    print("Target: localhost:9000 (TechCorp vulnerable app)")
    print("Profile: E-commerce")
    return True

def execute_security_testing():
    """Execute the complete security testing pipeline"""
    print("\nStep 3: Executing Security Testing Pipeline...")
    print("This will run:")
    print("- Phase 1: AppSec Analysis (SCA, Secrets, SAST, DAST)")
    print("- Phase 2: Red Team Validation")
    print("- Phase 3: Smart Integration & Assessment")
    print()
    
    # Execute quick_start.py
    result = subprocess.run([sys.executable, 'quick_start.py'], capture_output=True, text=True)
    
    if result.returncode == 0:
        print("SUCCESS: Security testing completed")
        print("\nExecution Output:")
        print("-" * 50)
        print(result.stdout)
        print("-" * 50)
        return True
    else:
        print("ERROR: Security testing failed")
        print(result.stderr)
        return False

def show_results():
    """Display and analyze results"""
    print("\nStep 4: Analyzing Results...")
    
    results_file = "projetos/techcorp/integrated_results_v5.json"
    if not os.path.exists(results_file):
        print(f"ERROR: Results file not found: {results_file}")
        return False
    
    with open(results_file, 'r') as f:
        results = json.load(f)
    
    print("\n" + "=" * 60)
    print("SECURITY TESTING RESULTS SUMMARY")
    print("=" * 60)
    
    # AppSec Results
    appsec = results.get('appsec_results', {})
    print(f"AppSec Analysis:")
    print(f"  - SCA Issues: {len(appsec.get('sca_results', []))}")
    print(f"  - Secrets Found: {len(appsec.get('secrets_results', []))}")
    print(f"  - SAST Vulnerabilities: {len(appsec.get('sast_results', []))}")
    print(f"  - DAST Vulnerabilities: {len(appsec.get('dast_results', []))}")
    
    # Red Team Results
    redteam = results.get('redteam_results', {})
    final_assessment = redteam.get('final_assessment', {})
    print(f"\nRed Team Validation:")
    print(f"  - Protection Level: {redteam.get('protection_analysis', {}).get('protection_level', 'Unknown')}")
    print(f"  - Vulnerabilities Found: {final_assessment.get('vulnerabilities_found', 0)}")
    print(f"  - Status: {final_assessment.get('status', 'Unknown')}")
    
    # Integrated Assessment
    integrated = results.get('final_assessment', {})
    print(f"\nIntegrated Assessment:")
    print(f"  - Overall Status: {integrated.get('status', 'Unknown')}")
    print(f"  - Total Vulnerabilities: {integrated.get('vulnerabilities_found', 0)}")
    print(f"  - Estimated Value: {integrated.get('estimated_value', '$0')}")
    print(f"  - False Positives Eliminated: {integrated.get('false_positives_eliminated', False)}")
    
    print(f"\nRecommendation:")
    print(f"  {integrated.get('recommendation', 'No recommendation available')}")
    
    # Show key vulnerabilities
    print(f"\nKey Vulnerabilities Detected:")
    sast_results = appsec.get('sast_results', [])
    for vuln in sast_results[:5]:  # Show first 5
        print(f"  - {vuln.get('vulnerability', 'Unknown').replace('_', ' ').title()}: {vuln.get('file', 'Unknown')} (Line {vuln.get('line', 'Unknown')})")
    
    return True

def cleanup():
    """Clean up demo environment"""
    print("\nStep 5: Cleanup...")
    
    # Stop and remove container
    subprocess.run(['docker', 'stop', 'techcorp-vuln'], capture_output=True)
    subprocess.run(['docker', 'rm', 'techcorp-vuln'], capture_output=True)
    
    print("Docker container stopped and removed")
    print("Demo completed successfully!")

def main():
    """Main demo execution"""
    print_banner()
    
    # Check prerequisites
    if not check_prerequisites():
        sys.exit(1)
    
    try:
        # Deploy vulnerable application
        if not deploy_vulnerable_app():
            sys.exit(1)
        
        # Configure platform
        if not configure_platform():
            sys.exit(1)
        
        # Execute security testing
        if not execute_security_testing():
            cleanup()
            sys.exit(1)
        
        # Show results
        if not show_results():
            cleanup()
            sys.exit(1)
        
        # Cleanup
        cleanup()
        
        print("\n" + "=" * 80)
        print("DEMO COMPLETED SUCCESSFULLY!")
        print("The platform successfully:")
        print("- Deployed a vulnerable web application")
        print("- Executed integrated AppSec + Red Team analysis")
        print("- Detected real vulnerabilities with accurate valuation")
        print("- Eliminated false positives through smart validation")
        print("- Generated professional security assessment")
        print("=" * 80)
        
    except KeyboardInterrupt:
        print("\nDemo interrupted by user")
        cleanup()
        sys.exit(1)
    except Exception as e:
        print(f"\nDemo failed with error: {e}")
        cleanup()
        sys.exit(1)

if __name__ == "__main__":
    main()