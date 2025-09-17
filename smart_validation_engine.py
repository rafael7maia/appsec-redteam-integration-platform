#!/usr/bin/env python3
"""
Smart Validation Engine - Elimina Falsos Positivos
Distingue vulnerabilidades reais de funcionalidades normais
"""

import re
import json
from urllib.parse import urlparse

class SmartValidationEngine:
    def __init__(self):
        # Emails públicos que NÃO são vulnerabilidades
        self.public_email_patterns = [
            r'sac@.*',           # SAC
            r'contato@.*',       # Contato
            r'suporte@.*',       # Suporte  
            r'vendas@.*',        # Vendas
            r'comercial@.*',     # Comercial
            r'marketing@.*',     # Marketing
            r'info@.*',          # Info
            r'admin@.*',         # Admin público
            r'noreply@.*',       # No-reply
            r'no-reply@.*',      # No-reply
            r'newsletter@.*',    # Newsletter
            r'eventos@.*',       # Eventos
            r'imprensa@.*'       # Imprensa
        ]
        
        # Emails que SÃO vulnerabilidades
        self.sensitive_email_patterns = [
            r'.*@gmail\.com',    # Emails pessoais
            r'.*@hotmail\.com',  # Emails pessoais
            r'.*@yahoo\.com',    # Emails pessoais
            r'.*@outlook\.com',  # Emails pessoais
            r'dev@.*',           # Desenvolvimento
            r'test@.*',          # Teste
            r'staging@.*',       # Staging
            r'backup@.*',        # Backup
            r'root@.*',          # Root
            r'user\d+@.*'        # Usuários numerados
        ]
        
        # Dados que são sempre sensíveis
        self.always_sensitive = [
            r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b',  # CPF
            r'\b\d{11}\b',                      # CPF sem formatação
            r'\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b', # Cartão de crédito
            r'password["\']:\s*["\'][^"\']+["\']', # Senhas em JSON
            r'token["\']:\s*["\'][^"\']+["\']',    # Tokens
            r'api_key["\']:\s*["\'][^"\']+["\']'   # API Keys
        ]
        
        # Contextos que indicam dados públicos
        self.public_contexts = [
            'contact', 'contato', 'sac', 'support', 'suporte',
            'about', 'sobre', 'team', 'equipe', 'staff',
            'press', 'imprensa', 'media', 'midia'
        ]

    def validate_email_exposure(self, emails, url, response_content):
        """Valida se exposição de emails é vulnerabilidade real"""
        
        results = {
            'is_vulnerability': False,
            'vulnerability_type': None,
            'sensitive_emails': [],
            'public_emails': [],
            'context_analysis': None,
            'severity': 'Info'
        }
        
        # Analisa contexto da URL
        url_lower = url.lower()
        is_public_context = any(ctx in url_lower for ctx in self.public_contexts)
        
        # Analisa contexto do conteúdo
        content_lower = response_content.lower()
        content_context = any(ctx in content_lower for ctx in self.public_contexts)
        
        results['context_analysis'] = {
            'url_suggests_public': is_public_context,
            'content_suggests_public': content_context,
            'likely_public_data': is_public_context or content_context
        }
        
        # Classifica cada email
        for email in emails:
            email_lower = email.lower()
            
            # Verifica se é email público
            is_public = any(re.match(pattern, email_lower) for pattern in self.public_email_patterns)
            
            # Verifica se é email sensível
            is_sensitive = any(re.match(pattern, email_lower) for pattern in self.sensitive_email_patterns)
            
            if is_sensitive:
                results['sensitive_emails'].append(email)
                results['is_vulnerability'] = True
                results['vulnerability_type'] = 'Personal Email Exposure'
                results['severity'] = 'High'
            elif is_public:
                results['public_emails'].append(email)
            else:
                # Email corporativo - precisa análise de contexto
                if not (is_public_context or content_context):
                    results['sensitive_emails'].append(email)
                    results['is_vulnerability'] = True
                    results['vulnerability_type'] = 'Corporate Email Exposure'
                    results['severity'] = 'Medium'
                else:
                    results['public_emails'].append(email)
        
        return results

    def validate_sensitive_data(self, content):
        """Valida exposição de dados sempre sensíveis"""
        
        findings = []
        
        for pattern in self.always_sensitive:
            matches = re.findall(pattern, content)
            if matches:
                if 'cpf' in pattern.lower() or r'\d{3}\.\d{3}\.\d{3}-\d{2}' in pattern:
                    findings.append({
                        'type': 'CPF Exposure',
                        'severity': 'Critical',
                        'count': len(matches),
                        'samples': matches[:3]
                    })
                elif 'cartão' in pattern.lower() or r'\d{4}\s?\d{4}' in pattern:
                    findings.append({
                        'type': 'Credit Card Exposure',
                        'severity': 'Critical', 
                        'count': len(matches),
                        'samples': ['****-****-****-' + m[-4:] for m in matches[:3]]
                    })
                elif 'password' in pattern.lower():
                    findings.append({
                        'type': 'Password Exposure',
                        'severity': 'Critical',
                        'count': len(matches)
                    })
                elif 'token' in pattern.lower():
                    findings.append({
                        'type': 'Token Exposure', 
                        'severity': 'High',
                        'count': len(matches)
                    })
        
        return findings

    def validate_idor(self, base_url, test_ids=[100, 999, 1234]):
        """Valida IDOR de forma inteligente"""
        
        import requests
        
        results = {
            'is_vulnerable': False,
            'evidence': [],
            'test_results': []
        }
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Testa diferentes IDs
        for test_id in test_ids:
            try:
                test_url = f"{base_url}/{test_id}"
                response = requests.get(test_url, headers=headers, timeout=10)
                
                test_result = {
                    'id': test_id,
                    'url': test_url,
                    'status_code': response.status_code,
                    'response_size': len(response.content),
                    'contains_sensitive_data': False
                }
                
                if response.status_code == 200:
                    content = response.text
                    
                    # Verifica dados sensíveis reais
                    email_validation = self.validate_email_exposure(
                        re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content),
                        test_url,
                        content
                    )
                    
                    sensitive_data = self.validate_sensitive_data(content)
                    
                    if email_validation['is_vulnerability'] or sensitive_data:
                        test_result['contains_sensitive_data'] = True
                        results['is_vulnerable'] = True
                        results['evidence'].append({
                            'id': test_id,
                            'email_issues': email_validation,
                            'sensitive_data': sensitive_data
                        })
                
                results['test_results'].append(test_result)
                
            except Exception as e:
                results['test_results'].append({
                    'id': test_id,
                    'error': str(e)
                })
        
        return results

    def comprehensive_validation(self, url, response_content):
        """Validação completa e inteligente"""
        
        # Extrai emails
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', response_content)
        
        # Remove duplicatas
        unique_emails = list(set(emails))
        
        validation_results = {
            'url': url,
            'timestamp': __import__('datetime').datetime.now().isoformat(),
            'total_emails_found': len(emails),
            'unique_emails_found': len(unique_emails),
            'email_validation': None,
            'sensitive_data_validation': [],
            'idor_validation': None,
            'final_assessment': {
                'is_vulnerable': False,
                'vulnerability_types': [],
                'severity': 'Info',
                'bug_bounty_value': '$0'
            }
        }
        
        # Valida emails
        if unique_emails:
            validation_results['email_validation'] = self.validate_email_exposure(
                unique_emails, url, response_content
            )
        
        # Valida dados sensíveis
        validation_results['sensitive_data_validation'] = self.validate_sensitive_data(response_content)
        
        # Valida IDOR se for endpoint de API
        if '/api/' in url:
            validation_results['idor_validation'] = self.validate_idor(url)
        
        # Avaliação final
        vulnerabilities = []
        max_severity = 'Info'
        
        if validation_results['email_validation'] and validation_results['email_validation']['is_vulnerability']:
            vulnerabilities.append(validation_results['email_validation']['vulnerability_type'])
            if validation_results['email_validation']['severity'] in ['High', 'Critical']:
                max_severity = validation_results['email_validation']['severity']
        
        if validation_results['sensitive_data_validation']:
            for finding in validation_results['sensitive_data_validation']:
                vulnerabilities.append(finding['type'])
                if finding['severity'] == 'Critical':
                    max_severity = 'Critical'
                elif finding['severity'] == 'High' and max_severity != 'Critical':
                    max_severity = 'High'
        
        if validation_results['idor_validation'] and validation_results['idor_validation']['is_vulnerable']:
            vulnerabilities.append('IDOR')
            max_severity = 'High'
        
        validation_results['final_assessment'] = {
            'is_vulnerable': len(vulnerabilities) > 0,
            'vulnerability_types': vulnerabilities,
            'severity': max_severity,
            'bug_bounty_value': self._estimate_value(vulnerabilities, max_severity)
        }
        
        return validation_results

    def _estimate_value(self, vulnerabilities, severity):
        """Estima valor realista para bug bounty"""
        
        if not vulnerabilities:
            return '$0'
        
        base_values = {
            'Critical': 2000,
            'High': 800,
            'Medium': 300,
            'Low': 100,
            'Info': 0
        }
        
        multipliers = {
            'Personal Email Exposure': 1.5,
            'CPF Exposure': 3.0,
            'Credit Card Exposure': 5.0,
            'Password Exposure': 4.0,
            'Token Exposure': 2.0,
            'IDOR': 2.5
        }
        
        base_value = base_values.get(severity, 0)
        
        # Aplica multiplicadores
        for vuln in vulnerabilities:
            multiplier = multipliers.get(vuln, 1.0)
            base_value = int(base_value * multiplier)
        
        if base_value == 0:
            return '$0'
        elif base_value < 100:
            return f'${base_value}'
        else:
            return f'${base_value:,}'

def test_smart_validation():
    """Testa o sistema de validação inteligente"""
    
    engine = SmartValidationEngine()
    
    # Testa com dados do Ingresso.com
    test_content = """
    {
        "events": [
            {
                "name": "Show Musical",
                "contact": "sac@institutoevoe.com.br",
                "support": "suporte@ingresso.com"
            }
        ]
    }
    """
    
    result = engine.comprehensive_validation(
        "https://ingresso.com/api/events",
        test_content
    )
    
    print(json.dumps(result, indent=2, ensure_ascii=False))
    
    return result

if __name__ == "__main__":
    test_smart_validation()