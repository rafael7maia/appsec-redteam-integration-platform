#!/usr/bin/env python3
"""
AppSec to Red Team Bridge - AI Bug Bounty Framework
Converts SAST/SCA/DAST findings into exploitable proof-of-concepts
"""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# SAST/SCA/DAST Tool Parsers
SUPPORTED_TOOLS = {
    "sonarqube": "SonarQube SAST results",
    "snyk": "Snyk SCA/SAST results", 
    "checkmarx": "Checkmarx SAST results",
    "veracode": "Veracode SAST results",
    "owasp_zap": "OWASP ZAP DAST results",
    "burpsuite": "Burp Suite DAST results",
    "semgrep": "Semgrep SAST results",
    "bandit": "Bandit Python SAST results",
    "dependency_check": "OWASP Dependency Check SCA results",
    "gitleaks": "GitLeaks secret scanning results",
    "trivy": "Trivy SCA/container scanning results"
}

# Vulnerability to Exploitation Mapping
VULN_TO_EXPLOIT = {
    "sql_injection": {
        "tools": ["sqlmap", "manual_sqli"],
        "mitre": "T1190",
        "severity": "Critical",
        "business_impact": "Data breach, unauthorized access"
    },
    "xss": {
        "tools": ["xsshunter", "manual_xss"],
        "mitre": "T1189", 
        "severity": "Medium-High",
        "business_impact": "Session hijacking, data theft"
    },
    "path_traversal": {
        "tools": ["manual_lfi", "ffuf"],
        "mitre": "T1083",
        "severity": "High",
        "business_impact": "File disclosure, system access"
    },
    "insecure_deserialization": {
        "tools": ["ysoserial", "manual_deserial"],
        "mitre": "T1190",
        "severity": "Critical", 
        "business_impact": "Remote code execution"
    },
    "weak_crypto": {
        "tools": ["hashcat", "manual_crypto"],
        "mitre": "T1552",
        "severity": "Medium",
        "business_impact": "Data exposure, credential theft"
    },
    "dependency_vulnerability": {
        "tools": ["nuclei", "manual_cve"],
        "mitre": "T1190",
        "severity": "Variable",
        "business_impact": "Application compromise"
    },
    "secret_exposure": {
        "tools": ["manual_secret", "credential_stuffing"],
        "mitre": "T1552.001",
        "severity": "High",
        "business_impact": "Credential theft, unauthorized access"
    }
}

def parse_sonarqube_json(file_path):
    """Parse SonarQube JSON export"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        findings = []
        for issue in data.get('issues', []):
            if issue.get('severity') in ['CRITICAL', 'MAJOR']:
                findings.append({
                    "tool": "sonarqube",
                    "type": classify_vulnerability(
                        issue.get('rule', ''), 
                        issue.get('message', ''),
                        issue.get('tags', [])
                    ),
                    "severity": issue.get('severity'),
                    "file": issue.get('component', ''),
                    "line": issue.get('line', 0),
                    "message": issue.get('message', ''),
                    "rule": issue.get('rule', ''),
                    "raw_data": issue
                })
        return findings
    except Exception as e:
        return {"error": f"Failed to parse SonarQube: {str(e)}"}

def parse_snyk_json(file_path):
    """Parse Snyk JSON results"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        findings = []
        for vuln in data.get('vulnerabilities', []):
            if vuln.get('severity') in ['critical', 'high']:
                findings.append({
                    "tool": "snyk",
                    "type": classify_vulnerability(vuln.get('title', '')),
                    "severity": vuln.get('severity'),
                    "package": vuln.get('packageName', ''),
                    "version": vuln.get('version', ''),
                    "cve": vuln.get('identifiers', {}).get('CVE', []),
                    "message": vuln.get('title', ''),
                    "raw_data": vuln
                })
        return findings
    except Exception as e:
        return {"error": f"Failed to parse Snyk: {str(e)}"}

def parse_zap_json(file_path):
    """Parse OWASP ZAP JSON results"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        findings = []
        for alert in data.get('site', [{}])[0].get('alerts', []):
            if alert.get('riskdesc', '').startswith(('High', 'Critical')):
                findings.append({
                    "tool": "owasp_zap",
                    "type": classify_vulnerability(alert.get('name', '')),
                    "severity": alert.get('riskdesc', '').split()[0],
                    "url": alert.get('instances', [{}])[0].get('uri', ''),
                    "parameter": alert.get('instances', [{}])[0].get('param', ''),
                    "message": alert.get('name', ''),
                    "description": alert.get('desc', ''),
                    "raw_data": alert
                })
        return findings
    except Exception as e:
        return {"error": f"Failed to parse ZAP: {str(e)}"}

def parse_gitleaks_json(file_path):
    """Parse GitLeaks JSON results"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        findings = []
        for secret in data:
            findings.append({
                "tool": "gitleaks",
                "type": "secret_exposure",
                "severity": "HIGH",
                "file": secret.get('File', ''),
                "line": secret.get('StartLine', 0),
                "secret_type": secret.get('RuleID', ''),
                "message": f"Secret detected: {secret.get('RuleID', 'Unknown')}",
                "description": secret.get('Description', ''),
                "match": secret.get('Match', ''),
                "raw_data": secret
            })
        return findings
    except Exception as e:
        return {"error": f"Failed to parse GitLeaks: {str(e)}"}

def parse_trivy_json(file_path):
    """Parse Trivy JSON results"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        findings = []
        results = data.get('Results', [])
        
        for result in results:
            vulnerabilities = result.get('Vulnerabilities', [])
            for vuln in vulnerabilities:
                if vuln.get('Severity') in ['CRITICAL', 'HIGH', 'MEDIUM']:
                    findings.append({
                        "tool": "trivy",
                        "type": "dependency_vulnerability",
                        "severity": vuln.get('Severity', 'UNKNOWN'),
                        "package": vuln.get('PkgName', ''),
                        "version": vuln.get('InstalledVersion', ''),
                        "cve": vuln.get('VulnerabilityID', ''),
                        "message": vuln.get('Title', ''),
                        "description": vuln.get('Description', ''),
                        "fixed_version": vuln.get('FixedVersion', ''),
                        "raw_data": vuln
                    })
        return findings
    except Exception as e:
        return {"error": f"Failed to parse Trivy: {str(e)}"}

def classify_vulnerability(rule_key, message="", tags=None):
    """Classify vulnerability type from SonarQube rule and tags"""
    if tags is None:
        tags = []
    
    rule_lower = rule_key.lower()
    message_lower = message.lower()
    tags_str = ' '.join(tags).lower()
    
    # Check rule key first (most reliable)
    if 'S2077' in rule_key or any(keyword in rule_lower for keyword in ['sql', 'injection']):
        return 'sql_injection'
    elif 'S5131' in rule_key or any(keyword in rule_lower for keyword in ['xss', 'cross-site']):
        return 'xss'
    elif 'S2083' in rule_key or any(keyword in rule_lower for keyword in ['path', 'traversal']):
        return 'path_traversal'
    
    # Check tags
    elif 'sql' in tags_str:
        return 'sql_injection'
    elif 'xss' in tags_str:
        return 'xss'
    elif 'path-traversal' in tags_str:
        return 'path_traversal'
    
    # Check message content
    elif any(keyword in message_lower for keyword in ['sql', 'injection', 'sqli']):
        return 'sql_injection'
    elif any(keyword in message_lower for keyword in ['xss', 'cross-site', 'script']):
        return 'xss'
    elif any(keyword in message_lower for keyword in ['path', 'traversal', 'directory']):
        return 'path_traversal'
    elif any(keyword in message_lower for keyword in ['deserial', 'pickle', 'unserialize']):
        return 'insecure_deserialization'
    elif any(keyword in message_lower for keyword in ['crypto', 'hash', 'encrypt', 'weak']):
        return 'weak_crypto'
    elif any(keyword in message_lower for keyword in ['cve', 'dependency', 'component']):
        return 'dependency_vulnerability'
    elif any(keyword in message_lower for keyword in ['secret', 'key', 'token', 'password', 'credential']):
        return 'secret_exposure'
    else:
        return 'other'

def generate_exploitation_plan(findings):
    """Generate exploitation plan from AppSec findings"""
    exploitation_plan = {
        "timestamp": datetime.now().isoformat(),
        "total_findings": len(findings),
        "exploitable_findings": 0,
        "exploitation_steps": []
    }
    
    for finding in findings:
        vuln_type = finding.get('type', 'other')
        if vuln_type in VULN_TO_EXPLOIT:
            exploitation_plan["exploitable_findings"] += 1
            
            exploit_info = VULN_TO_EXPLOIT[vuln_type]
            step = {
                "finding": finding,
                "exploitation": {
                    "tools": exploit_info["tools"],
                    "mitre_technique": exploit_info["mitre"],
                    "severity": exploit_info["severity"],
                    "business_impact": exploit_info["business_impact"],
                    "commands": generate_exploit_commands(finding, exploit_info)
                }
            }
            exploitation_plan["exploitation_steps"].append(step)
    
    return exploitation_plan

def generate_exploit_commands(finding, exploit_info):
    """Generate specific exploitation commands"""
    commands = []
    vuln_type = finding.get('type')
    
    if vuln_type == 'sql_injection' and finding.get('url'):
        commands.append(f"python security_bridge.py sqlmap_scan '{finding['url']}'")
        commands.append(f"sqlmap -u '{finding['url']}' --dbs --batch")
    
    elif vuln_type == 'dependency_vulnerability' and finding.get('cve'):
        for cve in finding['cve'][:3]:  # Limit to 3 CVEs
            commands.append(f"python security_bridge.py nuclei_scan -t cves/{cve.lower()}")
    
    elif vuln_type == 'path_traversal' and finding.get('url'):
        commands.append(f"ffuf -u '{finding['url']}../../../etc/passwd' -w /app/wordlists/lfi.txt")
    
    return commands

def execute_in_container(command):
    """Execute exploitation command in container"""
    try:
        full_command = f"docker exec hexstrike-ai {command}"
        result = subprocess.run(
            full_command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

def prove_vulnerability(exploitation_plan):
    """Execute exploitation attempts to prove vulnerabilities"""
    results = {
        "timestamp": datetime.now().isoformat(),
        "total_attempts": 0,
        "successful_exploits": 0,
        "proofs": []
    }
    
    for step in exploitation_plan["exploitation_steps"]:
        for command in step["exploitation"]["commands"]:
            results["total_attempts"] += 1
            print(f"Executing: {command}")
            
            result = execute_in_container(command)
            
            proof = {
                "finding": step["finding"],
                "command": command,
                "result": result,
                "exploited": analyze_exploitation_success(result, step["finding"]["type"])
            }
            
            if proof["exploited"]:
                results["successful_exploits"] += 1
            
            results["proofs"].append(proof)
    
    return results

def analyze_exploitation_success(result, vuln_type):
    """Analyze if exploitation was successful"""
    if not result.get("success"):
        return False
    
    stdout = result.get("stdout", "").lower()
    
    if vuln_type == "sql_injection":
        return any(keyword in stdout for keyword in ["database", "table", "column", "injection"])
    elif vuln_type == "dependency_vulnerability":
        return "critical" in stdout or "high" in stdout
    elif vuln_type == "path_traversal":
        return "root:" in stdout or "/etc/passwd" in stdout
    
    return False

def main():
    if len(sys.argv) < 3:
        print(json.dumps({
            "error": "Usage: python appsec_bridge.py <tool> <file_path>",
            "supported_tools": list(SUPPORTED_TOOLS.keys()),
            "example": "python appsec_bridge.py sonarqube results.json"
        }))
        return
    
    tool = sys.argv[1]
    file_path = sys.argv[2]
    
    if tool not in SUPPORTED_TOOLS:
        print(json.dumps({"error": f"Unsupported tool: {tool}"}))
        return
    
    if not Path(file_path).exists():
        print(json.dumps({"error": f"File not found: {file_path}"}))
        return
    
    # Parse AppSec results
    print(f"Parsing {tool} results from {file_path}...")
    
    if tool == "sonarqube":
        findings = parse_sonarqube_json(file_path)
    elif tool == "snyk":
        findings = parse_snyk_json(file_path)
    elif tool == "owasp_zap":
        findings = parse_zap_json(file_path)
    elif tool == "gitleaks":
        findings = parse_gitleaks_json(file_path)
    elif tool == "trivy":
        findings = parse_trivy_json(file_path)
    else:
        findings = {"error": f"Parser not implemented for {tool}"}
    
    if isinstance(findings, dict) and "error" in findings:
        print(json.dumps(findings))
        return
    
    # Generate exploitation plan
    print(f"Found {len(findings)} findings, generating exploitation plan...")
    exploitation_plan = generate_exploitation_plan(findings)
    
    # Execute exploitation attempts
    if exploitation_plan["exploitable_findings"] > 0:
        print(f"Attempting to exploit {exploitation_plan['exploitable_findings']} vulnerabilities...")
        proof_results = prove_vulnerability(exploitation_plan)
        
        final_result = {
            "appsec_findings": findings,
            "exploitation_plan": exploitation_plan,
            "proof_results": proof_results,
            "summary": {
                "total_findings": len(findings),
                "exploitable": exploitation_plan["exploitable_findings"],
                "proven_exploitable": proof_results["successful_exploits"],
                "success_rate": f"{(proof_results['successful_exploits'] / proof_results['total_attempts'] * 100):.1f}%" if proof_results['total_attempts'] > 0 else "0%"
            }
        }
    else:
        final_result = {
            "appsec_findings": findings,
            "exploitation_plan": exploitation_plan,
            "message": "No exploitable vulnerabilities found in current findings"
        }
    
    print(json.dumps(final_result, indent=2))

if __name__ == "__main__":
    main()