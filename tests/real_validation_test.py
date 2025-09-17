#!/usr/bin/env python3
"""
REAL Validation Test - Ingresso.com
Tests actual endpoints we discovered to verify if vulnerabilities exist
"""

import requests
import json
import time

def test_real_endpoints():
    """Test the actual endpoints we discovered"""
    
    real_endpoints = [
        "https://ingresso.com/api/events",
        "https://www.ingresso.com/api/events", 
        "https://ingresso.com.br/api/events",
        "https://www.ingresso.com.br/api/events"
    ]
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json'
    }
    
    results = []
    
    print("[*] TESTE REAL - Validando endpoints descobertos...")
    
    for endpoint in real_endpoints:
        print(f"\n[>] Testando: {endpoint}")
        
        try:
            # Test basic endpoint
            response = requests.get(endpoint, headers=headers, timeout=10)
            
            result = {
                'endpoint': endpoint,
                'status_code': response.status_code,
                'response_size': len(response.content),
                'content_type': response.headers.get('content-type', 'unknown'),
                'actual_vulnerability': False,
                'vulnerability_type': None,
                'evidence': None
            }
            
            if response.status_code == 200:
                content = response.text
                print(f"[+] Status: 200 - Size: {len(content)} bytes")
                
                # Check for ACTUAL sensitive data (not just the word "email")
                sensitive_indicators = []
                
                # Look for actual email addresses (not just the word "email")
                import re
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                emails_found = re.findall(email_pattern, content)
                
                if emails_found:
                    sensitive_indicators.append(f"Real emails found: {len(emails_found)}")
                    result['actual_vulnerability'] = True
                    result['vulnerability_type'] = 'Email Disclosure'
                    result['evidence'] = emails_found[:3]  # First 3 emails as evidence
                
                # Look for phone numbers
                phone_pattern = r'\b\d{2}\s?\d{4,5}-?\d{4}\b'
                phones_found = re.findall(phone_pattern, content)
                
                if phones_found:
                    sensitive_indicators.append(f"Phone numbers: {len(phones_found)}")
                    result['actual_vulnerability'] = True
                    result['vulnerability_type'] = 'Phone Disclosure'
                    result['evidence'] = phones_found[:3]
                
                # Look for CPF patterns
                cpf_pattern = r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b'
                cpfs_found = re.findall(cpf_pattern, content)
                
                if cpfs_found:
                    sensitive_indicators.append(f"CPF numbers: {len(cpfs_found)}")
                    result['actual_vulnerability'] = True
                    result['vulnerability_type'] = 'CPF Disclosure'
                    result['evidence'] = cpfs_found[:3]
                
                if sensitive_indicators:
                    print(f"[!] VULNERABILIDADE REAL ENCONTRADA: {sensitive_indicators}")
                else:
                    print("[+] Nenhum dado sensivel real encontrado")
                    
                # Test for IDOR by trying different IDs
                print(f"[>] Testando IDOR em: {endpoint}/100")
                idor_response = requests.get(f"{endpoint}/100", headers=headers, timeout=10)
                
                if idor_response.status_code == 200:
                    idor_content = idor_response.text
                    idor_emails = re.findall(email_pattern, idor_content)
                    
                    if idor_emails:
                        print(f"[!] IDOR CONFIRMADO: {len(idor_emails)} emails em endpoint com ID")
                        result['actual_vulnerability'] = True
                        result['vulnerability_type'] = 'IDOR - Email Exposure'
                        result['evidence'] = idor_emails[:3]
                    else:
                        print("[+] IDOR testado - sem dados sensiveis")
                else:
                    print(f"[i] IDOR test - Status: {idor_response.status_code}")
                    
            else:
                print(f"[i] Status: {response.status_code}")
            
            results.append(result)
            time.sleep(2)
            
        except Exception as e:
            print(f"[-] Erro: {str(e)}")
            results.append({
                'endpoint': endpoint,
                'error': str(e),
                'actual_vulnerability': False
            })
    
    # Summary
    real_vulns = [r for r in results if r.get('actual_vulnerability', False)]
    
    print(f"\n[*] RESULTADO FINAL:")
    print(f"[*] Endpoints testados: {len(real_endpoints)}")
    print(f"[*] Vulnerabilidades REAIS encontradas: {len(real_vulns)}")
    
    if real_vulns:
        print(f"[!] VULNERABILIDADES CONFIRMADAS:")
        for vuln in real_vulns:
            print(f"    - {vuln['endpoint']}: {vuln['vulnerability_type']}")
            if vuln.get('evidence'):
                print(f"      Evidencia: {vuln['evidence']}")
    else:
        print(f"[!] NENHUMA VULNERABILIDADE REAL CONFIRMADA")
        print(f"[!] Nossos 'achados' anteriores eram FALSOS POSITIVOS")
    
    # Save real results
    with open('real_validation_results.json', 'w', encoding='utf-8') as f:
        json.dump({
            'test_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'endpoints_tested': len(real_endpoints),
            'real_vulnerabilities_found': len(real_vulns),
            'false_positives_identified': len(results) - len(real_vulns),
            'results': results
        }, f, indent=2, ensure_ascii=False)
    
    return results

if __name__ == "__main__":
    test_real_endpoints()