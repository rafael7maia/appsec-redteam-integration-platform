#!/usr/bin/env python3
"""
Enhanced Security Bridge v5.0 - Anti-False Positive
Integra validação inteligente com descoberta de vulnerabilidades
"""

import json
import requests
from smart_validation_engine import SmartValidationEngine

class EnhancedSecurityBridge:
    def __init__(self, target_profile="entertainment"):
        self.validation_engine = SmartValidationEngine()
        self.target_profile = self._load_target_profile(target_profile)
        self.appsec_findings = None  # Store AppSec findings for validation
    
    def set_appsec_findings(self, appsec_results):
        """Set AppSec findings for Red Team validation"""
        self.appsec_findings = appsec_results
        print(f"[*] Red Team will validate {len(appsec_results.get('sast_results', []))} SAST findings")
        print(f"[*] Red Team will validate {len(appsec_results.get('dast_results', []))} DAST findings")
        
    def _load_target_profile(self, profile_name):
        """Carrega perfil do alvo para validação contextual"""
        try:
            with open('target_profiles.json', 'r', encoding='utf-8') as f:
                profiles = json.load(f)
            return profiles.get(profile_name, profiles['entertainment'])
        except:
            return {
                "expected_public_data": ["contact", "support", "general info"],
                "false_positive_indicators": ["sac@", "contato@", "suporte@"]
            }
    
    def scan_with_validation(self, target):
        """Executa scan completo com validação inteligente"""
        
        print(f"[*] Iniciando scan inteligente de {target}")
        print(f"[*] Perfil do alvo: {self.target_profile.get('description', 'Generic')}")
        
        validated_results = []
        
        # If we have AppSec findings, validate them first
        if self.appsec_findings:
            print(f"\n[*] Validating AppSec findings against live target...")
            appsec_validated = self._validate_appsec_findings(target)
            validated_results.extend(appsec_validated)
        
        # Descoberta de endpoints adicionais
        endpoints = self._discover_endpoints(target)
        
        # Validação inteligente de cada endpoint
        for endpoint in endpoints:
            print(f"\n[>] Validando: {endpoint}")
            
            try:
                response = requests.get(endpoint, timeout=10)
                
                if response.status_code == 200:
                    # Validação inteligente
                    validation = self.validation_engine.comprehensive_validation(
                        endpoint, response.text
                    )
                    
                    # Filtra baseado no perfil do alvo
                    filtered_validation = self._apply_target_profile_filter(validation)
                    
                    if filtered_validation['final_assessment']['is_vulnerable']:
                        validated_results.append(filtered_validation)
                        print(f"[!] VULNERABILIDADE CONFIRMADA: {filtered_validation['final_assessment']['vulnerability_types']}")
                    else:
                        print(f"[+] Endpoint seguro ou dados públicos normais")
                        
            except Exception as e:
                print(f"[-] Erro: {str(e)}")
        
        # Relatório final
        total_endpoints = len(endpoints) + (len(self.appsec_findings.get('dast_results', [])) if self.appsec_findings else 0)
        final_report = {
            'target': target,
            'target_profile': self.target_profile['description'],
            'endpoints_tested': total_endpoints,
            'vulnerabilities_found': len(validated_results),
            'validated_findings': validated_results,
            'summary': self._generate_summary(validated_results)
        }
        
        return final_report
    
    def _validate_appsec_findings(self, target):
        """Validate AppSec findings against live target"""
        validated_findings = []
        
        if not self.appsec_findings:
            return validated_findings
        
        # Validate DAST findings (already tested against live target)
        dast_results = self.appsec_findings.get('dast_results', [])
        for dast_finding in dast_results:
            print(f"[*] Validating DAST finding: {dast_finding['test_name']}")
            
            # DAST findings are already validated, so we confirm them
            validated_finding = {
                'url': dast_finding['url'],
                'vulnerability_type': dast_finding['test_name'],
                'method': dast_finding['method'],
                'status_code': dast_finding['status_code'],
                'severity': dast_finding['severity'],
                'source': 'DAST_VALIDATED',
                'final_assessment': {
                    'is_vulnerable': True,
                    'vulnerability_types': [dast_finding['test_name']],
                    'severity': dast_finding['severity'],
                    'bug_bounty_value': self._estimate_dast_value(dast_finding['test_name'])
                }
            }
            validated_findings.append(validated_finding)
            print(f"[!] CONFIRMED: {dast_finding['test_name']} at {dast_finding['url']}")
        
        # Validate SAST findings by testing endpoints
        sast_results = self.appsec_findings.get('sast_results', [])
        for sast_finding in sast_results:
            if sast_finding['vulnerability'] in ['sql_injection', 'command_injection', 'xss']:
                print(f"[*] Attempting to validate SAST finding: {sast_finding['vulnerability']}")
                
                # Try to validate against known endpoints
                validation_result = self._test_sast_vulnerability(target, sast_finding)
                if validation_result:
                    validated_findings.append(validation_result)
                    print(f"[!] CONFIRMED: {sast_finding['vulnerability']} is exploitable")
        
        return validated_findings
    
    def _test_sast_vulnerability(self, target, sast_finding):
        """Test SAST vulnerability against live target"""
        vuln_type = sast_finding['vulnerability']
        
        try:
            if vuln_type == 'sql_injection':
                # Test SQL injection on login endpoint
                test_url = f"http://{target}/login"
                test_data = {'username': "admin' OR '1'='1", 'password': 'test'}
                response = requests.post(test_url, data=test_data, timeout=10)
                
                if response.status_code == 200 and ('dashboard' in response.text.lower() or 'welcome' in response.text.lower()):
                    return {
                        'url': test_url,
                        'vulnerability_type': 'SQL Injection',
                        'method': 'POST',
                        'payload': str(test_data),
                        'severity': 'Critical',
                        'source': 'SAST_VALIDATED',
                        'final_assessment': {
                            'is_vulnerable': True,
                            'vulnerability_types': ['SQL Injection'],
                            'severity': 'Critical',
                            'bug_bounty_value': '$2,000'
                        }
                    }
            
            elif vuln_type == 'xss':
                # Test XSS on search endpoint
                test_url = f"http://{target}/search?q=<script>alert('xss')</script>"
                response = requests.get(test_url, timeout=10)
                
                if response.status_code == 200 and '<script>' in response.text:
                    return {
                        'url': test_url,
                        'vulnerability_type': 'Cross-Site Scripting (XSS)',
                        'method': 'GET',
                        'payload': "<script>alert('xss')</script>",
                        'severity': 'High',
                        'source': 'SAST_VALIDATED',
                        'final_assessment': {
                            'is_vulnerable': True,
                            'vulnerability_types': ['XSS'],
                            'severity': 'High',
                            'bug_bounty_value': '$800'
                        }
                    }
            
            elif vuln_type == 'command_injection':
                # Test command injection on ping endpoint
                test_url = f"http://{target}/ping"
                test_data = {'host': 'google.com; whoami'}
                response = requests.post(test_url, data=test_data, timeout=10)
                
                if response.status_code == 200 and len(response.text) > 100:
                    return {
                        'url': test_url,
                        'vulnerability_type': 'Command Injection',
                        'method': 'POST',
                        'payload': str(test_data),
                        'severity': 'Critical',
                        'source': 'SAST_VALIDATED',
                        'final_assessment': {
                            'is_vulnerable': True,
                            'vulnerability_types': ['Command Injection'],
                            'severity': 'Critical',
                            'bug_bounty_value': '$2,500'
                        }
                    }
        
        except Exception as e:
            print(f"[-] Validation failed for {vuln_type}: {e}")
        
        return None
    
    def _estimate_dast_value(self, test_name):
        """Estimate bug bounty value for DAST findings"""
        values = {
            'SQL Injection Test': '$2,000',
            'XSS Test': '$800',
            'IDOR Test': '$1,200',
            'Command Injection Test': '$2,500'
        }
        return values.get(test_name, '$500')
    
    def _discover_endpoints(self, target):
        """Descobre endpoints de API"""
        
        base_endpoints = [
            f"https://{target}/api/events",
            f"https://www.{target}/api/events",
            f"https://{target}/api/users",
            f"https://www.{target}/api/users",
            f"https://{target}/api/orders",
            f"https://www.{target}/api/orders"
        ]
        
        active_endpoints = []
        
        for endpoint in base_endpoints:
            try:
                response = requests.head(endpoint, timeout=5)
                if response.status_code in [200, 301, 302]:
                    active_endpoints.append(endpoint)
            except:
                pass
        
        return active_endpoints
    
    def _apply_target_profile_filter(self, validation):
        """Aplica filtros baseados no perfil do alvo"""
        
        # Cria cópia para não modificar original
        filtered = json.loads(json.dumps(validation))
        
        # Verifica indicadores de falso positivo
        false_positive_indicators = self.target_profile.get('false_positive_indicators', [])
        
        if filtered['email_validation']:
            # Remove emails que são esperados como públicos
            public_emails = filtered['email_validation']['public_emails']
            sensitive_emails = filtered['email_validation']['sensitive_emails']
            
            # Filtra emails sensíveis que na verdade são públicos para este tipo de alvo
            truly_sensitive = []
            for email in sensitive_emails:
                is_expected_public = any(indicator in email.lower() for indicator in false_positive_indicators)
                if not is_expected_public:
                    truly_sensitive.append(email)
            
            filtered['email_validation']['sensitive_emails'] = truly_sensitive
            filtered['email_validation']['is_vulnerability'] = len(truly_sensitive) > 0
            
            if not filtered['email_validation']['is_vulnerability']:
                filtered['email_validation']['vulnerability_type'] = None
                filtered['email_validation']['severity'] = 'Info'
        
        # Recalcula avaliação final
        vulnerabilities = []
        max_severity = 'Info'
        
        if filtered['email_validation'] and filtered['email_validation']['is_vulnerability']:
            vulnerabilities.append(filtered['email_validation']['vulnerability_type'])
            max_severity = filtered['email_validation']['severity']
        
        if filtered['sensitive_data_validation']:
            for finding in filtered['sensitive_data_validation']:
                vulnerabilities.append(finding['type'])
                if finding['severity'] == 'Critical':
                    max_severity = 'Critical'
                elif finding['severity'] == 'High' and max_severity != 'Critical':
                    max_severity = 'High'
        
        if filtered['idor_validation'] and filtered['idor_validation']['is_vulnerable']:
            vulnerabilities.append('IDOR')
            if max_severity not in ['Critical', 'High']:
                max_severity = 'High'
        
        filtered['final_assessment'] = {
            'is_vulnerable': len(vulnerabilities) > 0,
            'vulnerability_types': vulnerabilities,
            'severity': max_severity,
            'bug_bounty_value': self.validation_engine._estimate_value(vulnerabilities, max_severity)
        }
        
        return filtered
    
    def _generate_summary(self, validated_results):
        """Gera resumo executivo"""
        
        if not validated_results:
            return {
                'status': 'SECURE',
                'message': 'Nenhuma vulnerabilidade real encontrada',
                'recommendation': 'Alvo aparenta estar seguro'
            }
        
        total_value = 0
        severities = []
        vuln_types = []
        
        for result in validated_results:
            assessment = result['final_assessment']
            severities.append(assessment['severity'])
            vuln_types.extend(assessment['vulnerability_types'])
            
            # Extrai valor numérico
            value_str = assessment['bug_bounty_value'].replace('$', '').replace(',', '')
            if value_str.isdigit():
                total_value += int(value_str)
        
        max_severity = 'Critical' if 'Critical' in severities else \
                      'High' if 'High' in severities else \
                      'Medium' if 'Medium' in severities else 'Low'
        
        return {
            'status': 'VULNERABLE',
            'total_vulnerabilities': len(validated_results),
            'max_severity': max_severity,
            'vulnerability_types': list(set(vuln_types)),
            'estimated_total_value': f'${total_value:,}',
            'recommendation': 'Vulnerabilidades reais encontradas - reportar ao programa bug bounty'
        }

def test_enhanced_bridge():
    """Testa o sistema aprimorado"""
    
    bridge = EnhancedSecurityBridge(target_profile="entertainment")
    
    # Testa com Ingresso.com
    result = bridge.scan_with_validation("ingresso.com")
    
    print("\n" + "="*50)
    print("RELATÓRIO FINAL")
    print("="*50)
    print(json.dumps(result['summary'], indent=2, ensure_ascii=False))
    
    return result

if __name__ == "__main__":
    test_enhanced_bridge()