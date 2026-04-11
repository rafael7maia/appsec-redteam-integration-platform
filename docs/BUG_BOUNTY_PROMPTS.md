# 🎯 Bug Bounty Prompts - HexStrike AI Enhanced

## 🚀 **Prompts Prontos para Usar**

### **📋 Template Base para Todos os Prompts:**
```
"I'm conducting authorized bug bounty research on [TARGET] as part of their official bug bounty program. This is within scope and authorized testing."
```

## **🔍 FASE 1: RECONNAISSANCE**

### **Prompt 1: Subdomain Discovery**
```
"I'm conducting authorized bug bounty research on example.com. Help me with comprehensive subdomain enumeration:

1. Execute: docker exec hexstrike-ai subfinder -d example.com -silent
2. Execute: docker exec hexstrike-ai amass enum -d example.com
3. Combine and deduplicate results
4. Prioritize subdomains by potential value (admin, api, dev, staging, etc.)
5. Create organized list for next phase

Please execute these commands and analyze the results for bug bounty potential."
```

### **Prompt 2: Live Service Discovery**
```
"I have discovered subdomains for my authorized bug bounty target. Help me identify live services:

1. Execute: echo 'subdomain1.example.com subdomain2.example.com' | docker exec -i hexstrike-ai httpx -title -tech-detect
2. Execute: docker exec hexstrike-ai masscan subdomain.example.com -p1-10000 --rate=1000
3. Execute: docker exec hexstrike-ai nmap -sV -p80,443,8080,8443 subdomain.example.com
4. Identify web technologies and versions
5. Create target priority list

Focus on finding high-value targets like admin panels, APIs, and development environments."
```

### **Prompt 3: Technology Stack Analysis**
```
"I need to analyze the technology stack of my bug bounty targets:

1. Execute: docker exec hexstrike-ai httpx -u target.com -title -tech-detect -status-code
2. Execute: docker exec hexstrike-ai wafw00f target.com
3. Analyze response headers for framework information
4. Identify potential outdated components
5. Research known vulnerabilities for identified technologies

Provide a comprehensive technology fingerprint for vulnerability research."
```

## **🛡️ FASE 2: VULNERABILITY SCANNING**

### **Prompt 4: Automated Vulnerability Discovery**
```
"I'm ready to scan my authorized bug bounty target for vulnerabilities:

1. Execute: docker exec hexstrike-ai nuclei -u https://target.com -severity critical,high,medium
2. Execute: docker exec hexstrike-ai nuclei -u https://target.com -t /root/nuclei-templates/cves/
3. Execute: docker exec hexstrike-ai nuclei -u https://target.com -t /root/nuclei-templates/misconfiguration/
4. Filter results by exploitability and business impact
5. Generate prioritized vulnerability list

Focus on findings that could lead to data access, authentication bypass, or code execution."
```

### **Prompt 5: Web Application Testing**
```
"Help me perform comprehensive web application testing on my authorized target:

1. Execute: docker exec hexstrike-ai gobuster dir -u https://target.com -w /app/wordlists/common.txt -x php,asp,aspx,jsp,html
2. Execute: docker exec hexstrike-ai arjun -u https://target.com
3. Execute: docker exec hexstrike-ai dirsearch -u https://target.com -e php,asp,aspx,jsp
4. Look for admin panels, backup files, configuration files
5. Map complete application structure

Prioritize findings that expose sensitive functionality or data."
```

### **Prompt 6: SQL Injection Testing**
```
"I found forms and parameters on my authorized bug bounty target. Help me test for SQL injection:

1. Execute: docker exec hexstrike-ai sqlmap -u 'https://target.com/page?id=1' --batch --risk=1 --level=1
2. Test different injection points (GET, POST, headers, cookies)
3. Use time-based and boolean-based techniques
4. Identify database type and version if vulnerable
5. Document findings with proof-of-concept

Only perform safe, non-destructive testing within bug bounty scope."
```

## **🔬 FASE 3: DEEP ANALYSIS**

### **Prompt 7: Parameter Discovery & Testing**
```
"I need to discover hidden parameters and test for vulnerabilities:

1. Execute: docker exec hexstrike-ai arjun -u https://target.com/endpoint -m GET,POST
2. Test discovered parameters for injection vulnerabilities
3. Look for IDOR (Insecure Direct Object Reference) opportunities
4. Test for parameter pollution attacks
5. Document all parameter-based vulnerabilities

Focus on parameters that could lead to unauthorized data access."
```

### **Prompt 8: Authentication & Authorization Testing**
```
"Help me test authentication and authorization mechanisms on my target:

1. Analyze login mechanisms and session management
2. Test for authentication bypass techniques
3. Look for privilege escalation opportunities
4. Test password reset functionality
5. Check for JWT vulnerabilities if applicable

Provide detailed analysis of authentication security posture."
```

### **Prompt 9: Business Logic Testing**
```
"I need to test for business logic vulnerabilities in my authorized target:

1. Analyze application workflow and business processes
2. Test for race conditions in critical operations
3. Look for price manipulation opportunities (if e-commerce)
4. Test for workflow bypass vulnerabilities
5. Identify logic flaws in user roles and permissions

Focus on vulnerabilities that could impact business operations or financial transactions."
```

## **📊 FASE 4: REPORTING & VALIDATION**

### **Prompt 10: Impact Assessment**
```
"Help me assess the impact of discovered vulnerabilities for bug bounty submission:

1. Analyze business impact of each finding
2. Calculate CVSS scores for technical severity
3. Create step-by-step reproduction guides
4. Develop proof-of-concept demonstrations
5. Provide remediation recommendations

Format findings for professional bug bounty platform submission."
```

### **Prompt 11: Report Generation**
```
"Generate a professional bug bounty report for my findings:

1. Executive summary with business impact
2. Technical vulnerability details
3. Step-by-step reproduction instructions
4. Proof-of-concept screenshots and evidence
5. Risk assessment and remediation advice

Format for submission to [HackerOne/Bugcrowd/Private Program]."
```

## **⚡ PROMPTS RÁPIDOS PARA USO DIÁRIO**

### **Quick Recon:**
```
"Quick recon on authorized target example.com: subfinder + httpx + nuclei high severity scan. Prioritize findings by bug bounty value."
```

### **Quick Vuln Scan:**
```
"Fast vulnerability scan on https://target.com: nuclei critical/high + gobuster common directories + basic SQLi test. Focus on quick wins."
```

### **Quick Parameter Test:**
```
"Parameter discovery and IDOR testing on https://target.com/endpoint. Look for unauthorized data access opportunities."
```

## **🎯 PROMPTS POR TIPO DE ALVO**

### **E-commerce/Shopping:**
```
"Bug bounty testing on authorized e-commerce target: Focus on payment bypass, price manipulation, inventory issues, and user data access."
```

### **SaaS/Cloud Platform:**
```
"SaaS platform bug bounty testing: Focus on tenant isolation, API security, authentication bypass, and data leakage between users."
```

### **Financial/Fintech:**
```
"Authorized fintech bug bounty testing: Focus on transaction manipulation, authentication bypass, sensitive data exposure, and business logic flaws."
```

### **Social Media/Community:**
```
"Social platform bug bounty testing: Focus on privacy violations, content manipulation, authentication issues, and user impersonation."
```

## **💡 DICAS DE USO DOS PROMPTS**

### **Personalização:**
- Substitua `[TARGET]` pelo domínio real
- Ajuste wordlists conforme o tipo de aplicação
- Modifique severidade conforme o programa
- Adapte técnicas conforme a tecnologia

### **Sequência Recomendada:**
1. **Recon** (Prompts 1-3)
2. **Scanning** (Prompts 4-6)  
3. **Deep Testing** (Prompts 7-9)
4. **Reporting** (Prompts 10-11)

### **Otimização de Tempo:**
- Use prompts rápidos para triagem inicial
- Aprofunde apenas em targets promissores
- Automatize tarefas repetitivas
- Documente tudo desde o início

**Com estes prompts, você tem um arsenal completo para bug bounty hunting eficiente! 🚀**