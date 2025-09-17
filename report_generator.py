#!/usr/bin/env python3
"""
Professional Bug Bounty Report Generator - TechCorp Demo
Generates professional vulnerability reports from platform results
"""

import json
import os
from datetime import datetime

class BugBountyReportGenerator:
    def __init__(self, results_file):
        self.results_file = results_file
        self.results = self.load_results()
        
    def load_results(self):
        """Load scan results from JSON file"""
        if not os.path.exists(self.results_file):
            raise FileNotFoundError(f"Results file not found: {self.results_file}")
        
        with open(self.results_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def calculate_cvss_score(self, vulnerability_type):
        """Calculate CVSS 3.1 score for vulnerability types"""
        cvss_vectors = {
            'sql_injection': {
                'vector': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'score': 9.8,
                'severity': 'Crítico'
            },
            'command_injection': {
                'vector': 'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
                'score': 8.8,
                'severity': 'Alto'
            },
            'xss': {
                'vector': 'AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                'score': 6.1,
                'severity': 'Médio'
            },
            'idor': {
                'vector': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                'score': 7.5,
                'severity': 'Alto'
            },
            'insecure_deserialization': {
                'vector': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'score': 9.8,
                'severity': 'Crítico'
            },
            'hardcoded_secret': {
                'vector': 'AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'score': 8.4,
                'severity': 'Alto'
            }
        }
        
        return cvss_vectors.get(vulnerability_type, {
            'vector': 'AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:N/A:N',
            'score': 5.3,
            'severity': 'Médio'
        })
    
    def get_vulnerability_details(self):
        """Extract vulnerability details from results"""
        vulnerabilities = []
        
        # Process AppSec results
        appsec = self.results.get('appsec_results', {})
        
        # SAST vulnerabilities
        for vuln in appsec.get('sast_results', []):
            cvss = self.calculate_cvss_score(vuln['vulnerability'])
            vulnerabilities.append({
                'title': vuln['vulnerability'].replace('_', ' ').title(),
                'type': vuln['vulnerability'],
                'file': vuln['file'],
                'line': vuln['line'],
                'code': vuln['code_snippet'],
                'severity': vuln['severity'],
                'cvss': cvss,
                'category': 'SAST'
            })
        
        # Secrets
        for secret in appsec.get('secrets_results', []):
            cvss = self.calculate_cvss_score('hardcoded_secret')
            vulnerabilities.append({
                'title': f"Hardcoded {secret['secret_type'].replace('_', ' ').title()}",
                'type': 'hardcoded_secret',
                'file': secret['file'],
                'line': secret['line'],
                'code': f"Hardcoded secret detected: {secret['value']}",
                'severity': secret['severity'],
                'cvss': cvss,
                'category': 'Secrets'
            })
        
        # DAST vulnerabilities
        for vuln in appsec.get('dast_results', []):
            vuln_type = 'idor' if 'IDOR' in vuln['test_name'] else 'xss' if 'XSS' in vuln['test_name'] else 'sql_injection'
            cvss = self.calculate_cvss_score(vuln_type)
            vulnerabilities.append({
                'title': vuln['test_name'],
                'type': vuln_type,
                'url': vuln['url'],
                'method': vuln['method'],
                'indicator': vuln['indicator_found'],
                'severity': vuln['severity'],
                'cvss': cvss,
                'category': 'DAST'
            })
        
        return vulnerabilities
    
    def generate_html_report(self):
        """Generate professional HTML report"""
        vulnerabilities = self.get_vulnerability_details()
        target_domain = self.results.get('target_domain', 'localhost:9000')
        estimated_value = self.results.get('final_assessment', {}).get('estimated_value', '$0')
        
        # Calculate highest CVSS score
        max_cvss = max([v['cvss']['score'] for v in vulnerabilities], default=0)
        overall_severity = 'Crítico' if max_cvss >= 9.0 else 'Alto' if max_cvss >= 7.0 else 'Médio'
        
        html_content = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Vulnerabilidades - TechCorp</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .header p {{ margin: 10px 0 0 0; opacity: 0.9; }}
        .content {{ padding: 30px; }}
        .severity-critical {{ background: #dc3545; color: white; padding: 15px; border-radius: 8px; margin: 20px 0; }}
        .severity-high {{ background: #fd7e14; color: white; padding: 15px; border-radius: 8px; margin: 20px 0; }}
        .severity-medium {{ background: #ffc107; color: #212529; padding: 15px; border-radius: 8px; margin: 20px 0; }}
        .vulnerability {{ background: #f8f9fa; border-left: 5px solid #007bff; padding: 20px; margin: 20px 0; border-radius: 5px; }}
        .code-block {{ background: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; overflow-x: auto; }}
        .evidence {{ background: #e3f2fd; padding: 20px; border-radius: 8px; margin: 15px 0; }}
        .step {{ background: #f1f8e9; padding: 15px; margin: 10px 0; border-left: 4px solid #4caf50; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }}
        .stat-card {{ background: #fff; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #007bff; }}
        .recommendations {{ background: #d4edda; border: 1px solid #c3e6cb; border-radius: 8px; padding: 20px; margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Relatório de Segurança - Bug Bounty</h1>
            <p><strong>Target:</strong> {target_domain} | <strong>Data:</strong> {datetime.now().strftime('%d/%m/%Y')} | <strong>Plataforma:</strong> AI AppSec + Red Team v5.0</p>
        </div>

        <div class="content">
            <div class="severity-{overall_severity.lower()}">
                <h2>🚨 Resumo Executivo</h2>
                <p><strong>Status:</strong> VULNERÁVEL - Múltiplas vulnerabilidades críticas detectadas</p>
                <p><strong>Severidade Geral:</strong> {overall_severity}</p>
                <p><strong>Valor Estimado Bug Bounty:</strong> {estimated_value}</p>
            </div>

            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{len(vulnerabilities)}</div>
                    <div>Vulnerabilidades Encontradas</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{max_cvss:.1f}</div>
                    <div>CVSS Score Máximo</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len([v for v in vulnerabilities if v['cvss']['score'] >= 9.0])}</div>
                    <div>Vulnerabilidades Críticas</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len([v for v in vulnerabilities if v['cvss']['score'] >= 7.0])}</div>
                    <div>Vulnerabilidades Altas</div>
                </div>
            </div>

            <h2>📋 Vulnerabilidades Identificadas</h2>
"""

        # Add each vulnerability
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_class = 'critical' if vuln['cvss']['score'] >= 9.0 else 'high' if vuln['cvss']['score'] >= 7.0 else 'medium'
            
            html_content += f"""
            <div class="vulnerability">
                <h3>#{i} - {vuln['title']}</h3>
                <div class="severity-{severity_class}">
                    <strong>Severidade:</strong> {vuln['cvss']['severity']} | 
                    <strong>CVSS 3.1:</strong> {vuln['cvss']['score']} | 
                    <strong>Vector:</strong> {vuln['cvss']['vector']}
                </div>
                
                <h4>📍 Localização:</h4>
"""
            
            if 'file' in vuln:
                html_content += f"""
                <p><strong>Arquivo:</strong> {vuln['file']} (Linha {vuln['line']})</p>
                <div class="code-block">{vuln['code']}</div>
"""
            
            if 'url' in vuln:
                html_content += f"""
                <p><strong>URL:</strong> {vuln['url']}</p>
                <p><strong>Método:</strong> {vuln['method']}</p>
                <p><strong>Indicador:</strong> {vuln['indicator']}</p>
"""
            
            # Add specific recommendations based on vulnerability type
            recommendations = self.get_vulnerability_recommendations(vuln['type'])
            html_content += f"""
                <div class="recommendations">
                    <h4>🛠️ Recomendações de Correção:</h4>
                    <ul>
"""
            for rec in recommendations:
                html_content += f"<li>{rec}</li>"
            
            html_content += """
                    </ul>
                </div>
            </div>
"""

        # Add final recommendations
        html_content += f"""
            <h2>🎯 Recomendações Gerais</h2>
            <div class="recommendations">
                <h3>Ações Imediatas Recomendadas:</h3>
                <ol>
                    <li><strong>Correção Urgente:</strong> Priorizar vulnerabilidades críticas (CVSS ≥ 9.0)</li>
                    <li><strong>Validação de Input:</strong> Implementar sanitização adequada em todos os endpoints</li>
                    <li><strong>Controle de Acesso:</strong> Implementar autorização adequada para recursos sensíveis</li>
                    <li><strong>Gestão de Secrets:</strong> Remover credenciais hardcoded e usar gestores de secrets</li>
                    <li><strong>Atualização de Dependências:</strong> Atualizar bibliotecas vulneráveis identificadas</li>
                    <li><strong>Testes de Segurança:</strong> Implementar testes automatizados de segurança no CI/CD</li>
                </ol>
            </div>

            <h2>💰 Estimativa de Valor Bug Bounty</h2>
            <table>
                <tr>
                    <th>Categoria</th>
                    <th>Quantidade</th>
                    <th>Valor Unitário Estimado</th>
                    <th>Valor Total</th>
                </tr>
                <tr>
                    <td>Vulnerabilidades Críticas</td>
                    <td>{len([v for v in vulnerabilities if v['cvss']['score'] >= 9.0])}</td>
                    <td>$1,000 - $3,000</td>
                    <td>${len([v for v in vulnerabilities if v['cvss']['score'] >= 9.0]) * 2000:,}</td>
                </tr>
                <tr>
                    <td>Vulnerabilidades Altas</td>
                    <td>{len([v for v in vulnerabilities if 7.0 <= v['cvss']['score'] < 9.0])}</td>
                    <td>$500 - $1,500</td>
                    <td>${len([v for v in vulnerabilities if 7.0 <= v['cvss']['score'] < 9.0]) * 1000:,}</td>
                </tr>
                <tr>
                    <td>Vulnerabilidades Médias</td>
                    <td>{len([v for v in vulnerabilities if v['cvss']['score'] < 7.0])}</td>
                    <td>$100 - $500</td>
                    <td>${len([v for v in vulnerabilities if v['cvss']['score'] < 7.0]) * 300:,}</td>
                </tr>
            </table>

            <div style="margin-top: 40px; padding: 25px; background: #f8f9fa; border-radius: 8px; border-left: 5px solid #007bff;">
                <h3>⚠️ Nota Importante</h3>
                <p>Este relatório foi gerado automaticamente pela <strong>AI AppSec + Red Team Integration Platform v5.0</strong> 
                para fins educacionais e de demonstração. Em um cenário real de bug bounty:</p>
                <ul>
                    <li>Certifique-se de ter autorização explícita para testar o target</li>
                    <li>Siga as regras do programa de bug bounty</li>
                    <li>Documente evidências detalhadas com screenshots</li>
                    <li>Pratique divulgação responsável</li>
                </ul>
                <p><strong>📧 Contato:</strong> rafael@trmeducacao.com.br</p>
            </div>
        </div>
    </div>
</body>
</html>
"""
        
        return html_content
    
    def get_vulnerability_recommendations(self, vuln_type):
        """Get specific recommendations for vulnerability type"""
        recommendations = {
            'sql_injection': [
                "Usar prepared statements ou queries parametrizadas",
                "Implementar validação rigorosa de input",
                "Aplicar princípio de menor privilégio no banco de dados",
                "Usar ORM com proteção contra SQL injection"
            ],
            'command_injection': [
                "Evitar execução de comandos do sistema com input do usuário",
                "Usar bibliotecas seguras para operações do sistema",
                "Implementar whitelist de comandos permitidos",
                "Sanitizar e validar todos os inputs"
            ],
            'xss': [
                "Implementar encoding/escaping adequado de output",
                "Usar Content Security Policy (CSP)",
                "Validar e sanitizar inputs do usuário",
                "Usar frameworks com proteção XSS automática"
            ],
            'idor': [
                "Implementar controle de acesso baseado em autorização",
                "Usar UUIDs em vez de IDs sequenciais",
                "Verificar propriedade do recurso antes do acesso",
                "Implementar rate limiting para prevenir enumeração"
            ],
            'insecure_deserialization': [
                "Evitar deserialização de dados não confiáveis",
                "Usar formatos de dados seguros (JSON em vez de pickle)",
                "Implementar validação de integridade",
                "Usar bibliotecas de serialização seguras"
            ],
            'hardcoded_secret': [
                "Usar variáveis de ambiente para credenciais",
                "Implementar gestão centralizada de secrets",
                "Rotacionar credenciais regularmente",
                "Usar serviços de gestão de secrets (AWS Secrets Manager, etc.)"
            ]
        }
        
        return recommendations.get(vuln_type, [
            "Implementar validação adequada de input",
            "Seguir práticas de desenvolvimento seguro",
            "Realizar testes de segurança regulares"
        ])
    
    def generate_json_report(self):
        """Generate JSON report for bug bounty platforms"""
        vulnerabilities = self.get_vulnerability_details()
        
        json_report = {
            "titulo": "Múltiplas Vulnerabilidades de Segurança - TechCorp Application",
            "target": self.results.get('target_domain', 'localhost:9000'),
            "data_descoberta": datetime.now().strftime('%d/%m/%Y'),
            "severidade_geral": "Alto",
            "valor_estimado": self.results.get('final_assessment', {}).get('estimated_value', '$0'),
            "resumo": f"Identificadas {len(vulnerabilities)} vulnerabilidades incluindo SQL injection, XSS, IDOR e exposição de secrets",
            "vulnerabilidades": []
        }
        
        for vuln in vulnerabilities:
            vuln_data = {
                "titulo": vuln['title'],
                "tipo": vuln['type'],
                "severidade": vuln['cvss']['severity'],
                "cvss_score": vuln['cvss']['score'],
                "cvss_vector": vuln['cvss']['vector'],
                "categoria": vuln['category']
            }
            
            if 'file' in vuln:
                vuln_data['localizacao'] = f"{vuln['file']}:{vuln['line']}"
                vuln_data['codigo_vulneravel'] = vuln['code']
            
            if 'url' in vuln:
                vuln_data['endpoint'] = vuln['url']
                vuln_data['metodo'] = vuln['method']
            
            json_report["vulnerabilidades"].append(vuln_data)
        
        return json_report
    
    def save_reports(self, output_dir="projetos/techcorp"):
        """Save both HTML and JSON reports"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate and save HTML report
        html_content = self.generate_html_report()
        html_file = os.path.join(output_dir, "vulnerability_report.html")
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # Generate and save JSON report
        json_content = self.generate_json_report()
        json_file = os.path.join(output_dir, "bug_bounty_report.json")
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(json_content, f, indent=2, ensure_ascii=False)
        
        print(f"Relatórios gerados com sucesso!")
        print(f"HTML: {html_file}")
        print(f"JSON: {json_file}")
        
        return html_file, json_file

def main():
    """Main function to generate reports"""
    results_file = "projetos/techcorp/integrated_results_v5.json"
    
    try:
        generator = BugBountyReportGenerator(results_file)
        html_file, json_file = generator.save_reports()
        
        print("\n" + "="*60)
        print("RELATÓRIOS PROFISSIONAIS GERADOS")
        print("="*60)
        print(f"📄 Relatório HTML: {html_file}")
        print(f"📋 Relatório JSON: {json_file}")
        print("\nOs relatórios estão prontos para submissão em programas de bug bounty!")
        
    except Exception as e:
        print(f"Erro ao gerar relatórios: {e}")

if __name__ == "__main__":
    main()