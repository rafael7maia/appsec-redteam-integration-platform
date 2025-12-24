#!/usr/bin/env python3
"""
Quick Start Script - AI AppSec + Red Team Integration Platform v5.0
One-command execution with mode selection and validation
"""

import os
import sys
from config_loader import ConfigLoader
from core_scanner import CoreScanner

def interactive_setup():
    """Interactive setup for operation mode and configuration"""
    print("AI AppSec + Red Team Integration Platform v5.0 - Interactive Setup")
    print("=" * 70)

    # Mode selection
    print("\nSelecione o modo de operacao:")
    print("1. AppSec Only - Analise de codigo fonte (SCA, Secrets, SAST, DAST)")
    print("2. AppSec + Red Team - Analise completa com validacao externa")
    print("3. Red Team Only - Bug bounty hunting e pentest externo")
    print("4. TypeScript/Node.js Scanner - Analise especializada para Express + Prisma")
    print("5. HexStrike AI Full Platform - 150+ ferramentas com automacao IA")

    while True:
        choice = input("\nEscolha (1-5): ").strip()
        if choice in ['1', '2', '3', '4', '5']:
            break
        print("Opcao invalida. Digite 1, 2, 3, 4 ou 5.")

    # Map choice to mode
    mode_map = {
        '1': 'appsec',
        '2': 'appsec_redteam',
        '3': 'redteam',
        '4': 'typescript_scanner',
        '5': 'hexstrike'
    }
    operation_mode = mode_map[choice]
    
    # Project name
    project_name = input("\nNome do projeto: ").strip()
    if not project_name:
        project_name = "default_project"
    
    config = {
        'OPERATION_MODE': operation_mode,
        'PROJECT_NAME': project_name
    }
    
    # Mode-specific configuration
    if operation_mode == 'hexstrike':
        print("\n--- Configuracao HexStrike AI Full Platform ---")
        target_domain = input("Target Domain (ex: example.com): ").strip()
        if not target_domain:
            print("Target domain is required!")
            return None

        print("\nAtack Vectors (selecione multiplos separados por virgula):")
        print("1. reconnaissance - Coleta de informacoes")
        print("2. vulnerability_scanning - Scan de vulnerabilidades")
        print("3. exploitation - Execucao de exploits")
        print("4. web_application - Teste de aplicacoes web")
        print("5. network - Teste de rede")
        print("6. api_security - Teste de APIs")
        print("7. cloud - Teste de infraestrutura cloud")

        vectors_input = input("\nEscolha (ex: 1,2,4): ").strip()
        vector_map = {
            '1': 'reconnaissance',
            '2': 'vulnerability_scanning',
            '3': 'exploitation',
            '4': 'web_application',
            '5': 'network',
            '6': 'api_security',
            '7': 'cloud'
        }
        selected_vectors = []
        for choice in vectors_input.split(','):
            choice = choice.strip()
            if choice in vector_map:
                selected_vectors.append(vector_map[choice])

        if not selected_vectors:
            selected_vectors = ['reconnaissance', 'vulnerability_scanning']

        config['TARGET_DOMAIN'] = target_domain
        config['ATTACK_VECTORS'] = ','.join(selected_vectors)
        config['AUTHORIZATION'] = 'educational_lab'

    elif operation_mode == 'typescript_scanner':
        print("\n--- Configuracao TypeScript/Node.js Scanner ---")
        backend_path = input("Caminho do backend (ex: projetos/agendatroca/app/backend): ").strip()
        if not backend_path:
            backend_path = f"projetos/{project_name}/app/backend"

        config['BACKEND_PATH'] = backend_path
        config['AUTHORIZATION'] = 'educational_lab'

    elif operation_mode in ['appsec_redteam', 'redteam']:
        print("\n--- Configuracao Red Team ---")
        target_domain = input("Target domain (ex: example.com): ").strip()

        print("\nTipo de negocio do target:")
        print("1. Entertainment (eventos, ingressos)")
        print("2. E-commerce (lojas online)")
        print("3. Financial (bancos, fintech)")
        print("4. Healthcare (sistemas medicos)")
        print("5. Government (setor publico)")

        while True:
            profile_choice = input("\nEscolha (1-5): ").strip()
            if profile_choice in ['1', '2', '3', '4', '5']:
                break
            print("Opcao invalida. Digite 1-5.")

        profile_map = {
            '1': 'entertainment',
            '2': 'e-commerce',
            '3': 'financial',
            '4': 'healthcare',
            '5': 'government'
        }
        target_profile = profile_map[profile_choice]

        print("\nTipo de autorizacao:")
        print("1. Bug Bounty Program (programa oficial)")
        print("2. Penetration Test (teste contratado)")
        print("3. Own System (sistema proprio)")
        print("4. Educational Lab (ambiente educacional)")

        while True:
            auth_choice = input("\nEscolha (1-4): ").strip()
            if auth_choice in ['1', '2', '3', '4']:
                break
            print("Opcao invalida. Digite 1-4.")

        auth_map = {
            '1': 'bug_bounty_program',
            '2': 'penetration_test',
            '3': 'own_system',
            '4': 'educational_lab'
        }
        authorization = auth_map[auth_choice]

        config['TARGET_DOMAIN'] = target_domain
        config['TARGET_PROFILE'] = target_profile
        config['AUTHORIZATION'] = authorization

    else:  # AppSec only
        print("\n--- Configuracao AppSec ---")
        print("1. Code Audit (auditoria de codigo)")
        print("2. Own System (sistema proprio)")
        print("3. Educational Lab (ambiente educacional)")
        
        while True:
            auth_choice = input("\nEscolha (1-3): ").strip()
            if auth_choice in ['1', '2', '3']:
                break
            print("Opcao invalida. Digite 1-3.")
        
        auth_map = {
            '1': 'code_audit',
            '2': 'own_system',
            '3': 'educational_lab'
        }
        authorization = auth_map[auth_choice]
        config['AUTHORIZATION'] = authorization
    
    # Save configuration
    with open('config.env', 'w') as f:
        for key, value in config.items():
            f.write(f"{key}={value}\n")
    
    print("\n" + "=" * 70)
    print("CONFIGURACAO SALVA")
    print("=" * 70)
    for key, value in config.items():
        print(f"{key}: {value}")
    
    return config

def main():
    """Quick start execution with interactive mode selection"""
    
    # Check if config.env exists, if not run interactive setup
    if not os.path.exists('config.env'):
        print("Arquivo config.env nao encontrado. Iniciando configuracao interativa...\n")
        config = interactive_setup()
    else:
        print("AI AppSec + Red Team Integration Platform v5.0 - Quick Start")
        print("=" * 70)
        
        # Ask if user wants to reconfigure
        reconfigure = input("\nconfig.env encontrado. Deseja reconfigurar? (s/N): ").strip().lower()
        if reconfigure in ['s', 'sim', 'y', 'yes']:
            config = interactive_setup()
        else:
            config = None
    
    try:
        # Load and validate configuration
        loader = ConfigLoader()
        loader.load()
        loader.validate()

        mode = loader.get_mode()
        project = loader.get_project()
        config = loader.config

        print("\n" + "=" * 70)
        print("STARTING EXECUTION")
        print("=" * 70)

        # Execute based on mode
        if mode == "appsec":
            results = execute_appsec_mode(config, project)
        elif mode == "appsec_redteam":
            results = execute_integrated_mode(config, project)
        elif mode == "redteam":
            results = execute_redteam_mode(config, project)
        elif mode == "typescript_scanner":
            results = execute_typescript_scanner_mode(config, project)
        elif mode == "hexstrike":
            results = execute_hexstrike_mode(config, project)
        
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
    elif mode == "typescript_scanner":
        summary = results['summary']
        print(f"Total Findings: {summary['total_findings']}")
        print(f"Authentication Issues: {summary['authentication_issues']}")
        print(f"JWT Vulnerabilities: {summary['jwt_vulnerabilities']}")
        print(f"API Security Issues: {summary['api_security_issues']}")
        print(f"Middleware Issues: {summary['middleware_issues']}")
        print(f"Environment Issues: {summary['environment_issues']}")
        print(f"Vulnerable Dependencies: {summary['vulnerable_dependencies']}")
        print(f"Results: projetos/{project}/typescript_scan_results_v5.json")

def execute_typescript_scanner_mode(config, project):
    """Execute TypeScript/Node.js Security Scanner mode"""
    print("Executing TypeScript/Node.js Security Scanner...")
    import json
    from typescript_security_scanner import TypeScriptSecurityScannerAdvanced

    backend_path = config.get('BACKEND_PATH', f"projetos/{project}/app/backend")

    # Run scanner
    scanner = TypeScriptSecurityScannerAdvanced(backend_path)
    scanner.scan()
    report = scanner.generate_report()

    # Save results
    results_file = f"projetos/{project}/typescript_scan_results_v5.json"
    os.makedirs(f"projetos/{project}", exist_ok=True)

    with open(results_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"[+] Report saved to {results_file}")

    # Generate HTML report similar to other modes
    from report_generator import BugBountyReportGenerator

    try:
        # Convert findings to a format compatible with report generator
        vulnerabilities = []
        for category, findings in report['findings'].items():
            for finding in findings:
                vulnerabilities.append({
                    'type': finding.get('type', 'Security Issue'),
                    'severity': finding.get('severity', 'MEDIUM'),
                    'file': finding.get('file', 'Unknown'),
                    'line': finding.get('line', 0),
                    'description': f"{finding.get('pattern', '')} - {category}"
                })

        # Generate HTML report
        html_report = BugBountyReportGenerator(
            target=backend_path,
            findings=vulnerabilities
        )
        html_file = f"projetos/{project}/typescript_security_report.html"
        html_report.generate_html_report(html_file)
        print(f"[+] HTML Report: {html_file}")
    except:
        print("[-] Could not generate HTML report (report_generator not available)")

    results = {
        'mode': 'typescript_scanner',
        'project': project,
        'summary': report['summary'],
        'findings': report['findings']
    }

    return results

def execute_hexstrike_mode(config, project):
    """Execute HexStrike AI Full Platform mode (Phase 2: Scanner Wrapper)"""
    print("\n" + "="*70)
    print("HexStrike AI Full Platform - Mode 5 Execution")
    print("="*70)

    import json
    import time
    from hexstrike_scanner import HexStrikeScanner
    from hexstrike_lib import visual_engine

    target_domain = config.get('TARGET_DOMAIN', '')
    attack_vectors_str = config.get('ATTACK_VECTORS', 'reconnaissance,vulnerability_scanning')
    attack_vectors = [v.strip() for v in attack_vectors_str.split(',')]
    authorization = config.get('AUTHORIZATION', 'educational_lab')
    use_docker = False  # Default to local server for Phase 2

    print(visual_engine.create_banner())

    print(visual_engine.format_section_header("Initializing HexStrike Scanner"))
    print(f"Target: {target_domain}")
    print(f"Attack Vectors: {', '.join(attack_vectors)}")
    print(f"Authorization: {authorization}")
    print(f"Mode: {'Docker Container' if use_docker else 'Local Server'}")

    try:
        # Initialize scanner
        scanner = HexStrikeScanner(
            target_domain=target_domain,
            attack_vectors=attack_vectors,
            authorization=authorization,
            use_docker=use_docker
        )

        # Execute full scan (starts server, runs scan, stops server, generates report)
        print(visual_engine.format_section_header("Starting Scan Execution"))
        start_time = time.time()

        full_report = scanner.execute_full_scan()

        execution_time = time.time() - start_time

        # Check if scan was successful
        if not full_report.get('success', False):
            print(f"\n[ERROR] Scan failed: {full_report.get('error', 'Unknown error')}")
            print(f"Full report: {json.dumps(full_report, indent=2)}")
            return {
                'success': False,
                'error': full_report.get('error', 'HexStrike scan failed'),
                'mode': 'hexstrike'
            }

        print(visual_engine.format_section_header("Scan Completed Successfully"))

        # Extract report data
        report = full_report.get('report', {})
        scan_info = report.get('scan_info', {})
        summary = report.get('summary', {})
        findings = report.get('findings', [])

        # Display summary
        print(f"Total Findings: {summary.get('total_findings', 0)}")
        print(f"  - Critical: {summary.get('critical', 0)}")
        print(f"  - High: {summary.get('high', 0)}")
        print(f"  - Medium: {summary.get('medium', 0)}")
        print(f"  - Low: {summary.get('low', 0)}")
        print(f"Execution Time: {execution_time:.2f} seconds")

        # Prepare results
        results = {
            'success': True,
            'mode': 'hexstrike',
            'project': project,
            'target_domain': target_domain,
            'attack_vectors': attack_vectors,
            'authorization': authorization,
            'scan_info': scan_info,
            'summary': summary,
            'findings': findings,
            'execution_time': execution_time,
            'report': report
        }

        # Save to file
        results_file = f"projetos/{project}/hexstrike_results_v5.json"
        os.makedirs(f"projetos/{project}", exist_ok=True)

        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)

        print(visual_engine.format_section_header("Results Saved"))
        print(f"Results file: {results_file}")
        print(f"Findings count: {len(findings)}")

        return results

    except Exception as e:
        print(f"\n[ERROR] Exception during HexStrike execution: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            'success': False,
            'error': str(e),
            'mode': 'hexstrike'
        }

if __name__ == "__main__":
    main()