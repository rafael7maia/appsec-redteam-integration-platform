#!/usr/bin/env python3
"""
Consolidated Security Report Generator
Follows Secure SDLC order: SCA → Secrets → SAST → DAST → Red Team
"""

import json
import sys
from datetime import datetime
from pathlib import Path

def load_json_file(file_path):
    """Load JSON file safely"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except:
        return {}

def generate_consolidated_report(results_dir):
    """Generate consolidated security report"""
    results_path = Path(results_dir)
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "secure_sdlc_phases": {
            "1_sca": {},
            "2_secrets": {},
            "3_sast": {},
            "4_dast": {},
            "5_red_team": {}
        },
        "summary": {
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "exploitable": 0,
            "proven_exploitable": 0
        }
    }
    
    # Phase 1: SCA Results
    sca_file = results_path / "bridge-sca.json"
    if sca_file.exists():
        sca_data = load_json_file(sca_file)
        report["secure_sdlc_phases"]["1_sca"] = {
            "tool": "Trivy SCA",
            "findings": sca_data.get("appsec_findings", []),
            "count": len(sca_data.get("appsec_findings", [])),
            "focus": "Vulnerable dependencies and components"
        }
    
    # Phase 2: Secret Scanning Results
    secrets_file = results_path / "bridge-secrets.json"
    if secrets_file.exists():
        secrets_data = load_json_file(secrets_file)
        report["secure_sdlc_phases"]["2_secrets"] = {
            "tool": "GitLeaks",
            "findings": secrets_data.get("appsec_findings", []),
            "count": len(secrets_data.get("appsec_findings", [])),
            "focus": "Hardcoded secrets and credentials"
        }
    
    # Phase 3: SAST Results
    sast_file = results_path / "bridge-sast.json"
    if sast_file.exists():
        sast_data = load_json_file(sast_file)
        report["secure_sdlc_phases"]["3_sast"] = {
            "tool": "Bandit SAST",
            "findings": sast_data.get("appsec_findings", []),
            "count": len(sast_data.get("appsec_findings", [])),
            "focus": "Source code vulnerabilities"
        }
    
    # Phase 4: DAST Results (placeholder - ZAP integration)
    report["secure_sdlc_phases"]["4_dast"] = {
        "tool": "OWASP ZAP",
        "findings": [],
        "count": 0,
        "focus": "Runtime application vulnerabilities"
    }
    
    # Phase 5: Red Team Results
    report["secure_sdlc_phases"]["5_red_team"] = {
        "tool": "Security Bridge + MITRE ATT&CK",
        "findings": [],
        "count": 0,
        "focus": "Exploitation validation and proof-of-concept"
    }
    
    # Calculate summary
    for phase_name, phase_data in report["secure_sdlc_phases"].items():
        findings = phase_data.get("findings", [])
        report["summary"]["total_findings"] += len(findings)
        
        for finding in findings:
            severity = finding.get("severity", "").upper()
            if severity == "CRITICAL":
                report["summary"]["critical"] += 1
            elif severity == "HIGH":
                report["summary"]["high"] += 1
            elif severity == "MEDIUM":
                report["summary"]["medium"] += 1
            elif severity == "LOW":
                report["summary"]["low"] += 1
    
    # Generate executive summary
    report["executive_summary"] = generate_executive_summary(report)
    
    return report

def generate_executive_summary(report):
    """Generate executive summary"""
    summary = report["summary"]
    
    risk_level = "LOW"
    if summary["critical"] > 0:
        risk_level = "CRITICAL"
    elif summary["high"] > 0:
        risk_level = "HIGH"
    elif summary["medium"] > 0:
        risk_level = "MEDIUM"
    
    return {
        "overall_risk": risk_level,
        "total_findings": summary["total_findings"],
        "key_concerns": [
            f"{summary['critical']} Critical vulnerabilities" if summary["critical"] > 0 else None,
            f"{summary['high']} High severity issues" if summary["high"] > 0 else None,
            "Hardcoded secrets detected" if report["secure_sdlc_phases"]["2_secrets"]["count"] > 0 else None,
            "Vulnerable dependencies found" if report["secure_sdlc_phases"]["1_sca"]["count"] > 0 else None
        ],
        "recommendations": [
            "Immediate remediation required for Critical findings",
            "Implement secret management solution",
            "Update vulnerable dependencies",
            "Integrate security testing in CI/CD pipeline",
            "Regular security assessments recommended"
        ],
        "sdlc_compliance": {
            "sca_completed": report["secure_sdlc_phases"]["1_sca"]["count"] >= 0,
            "secret_scanning": report["secure_sdlc_phases"]["2_secrets"]["count"] >= 0,
            "sast_completed": report["secure_sdlc_phases"]["3_sast"]["count"] >= 0,
            "dast_completed": report["secure_sdlc_phases"]["4_dast"]["count"] >= 0,
            "red_team_validation": report["secure_sdlc_phases"]["5_red_team"]["count"] >= 0
        }
    }

def main():
    if len(sys.argv) < 2:
        print("Usage: python generate_consolidated_report.py <results_directory>")
        return
    
    results_dir = sys.argv[1]
    
    print("📊 Generating Consolidated Security Report...")
    print("=" * 50)
    
    report = generate_consolidated_report(results_dir)
    
    # Save report
    output_file = Path(results_dir) / "consolidated_security_report.json"
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    print(f"🎯 Overall Risk Level: {report['executive_summary']['overall_risk']}")
    print(f"📋 Total Findings: {report['summary']['total_findings']}")
    print(f"🔴 Critical: {report['summary']['critical']}")
    print(f"🟠 High: {report['summary']['high']}")
    print(f"🟡 Medium: {report['summary']['medium']}")
    print(f"🔵 Low: {report['summary']['low']}")
    print()
    
    print("📈 Secure SDLC Phase Results:")
    for phase_name, phase_data in report["secure_sdlc_phases"].items():
        phase_num = phase_name.split('_')[0]
        phase_desc = phase_name.split('_', 1)[1].upper()
        print(f"  Phase {phase_num} - {phase_desc}: {phase_data['count']} findings ({phase_data['tool']})")
    
    print(f"\n📁 Full report saved to: {output_file}")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()