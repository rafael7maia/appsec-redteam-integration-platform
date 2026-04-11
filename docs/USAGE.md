# 🚀 Usage Guide - HexStrike AI

## **Quick Start Prompts**

### **Basic Security Scan**
```
"Perform security assessment on my test lab at 127.0.0.1:
1. nmap port scan
2. nuclei vulnerability check  
3. explain findings"
```

### **Web Application Testing**
```
"Test web app at http://testphp.vulnweb.com:
1. gobuster directory scan
2. nuclei vulnerability scan
3. generate report"
```

### **Network Reconnaissance** 
```
"Help with network recon on example.com:
1. subfinder subdomain enum
2. httpx live service probe
3. masscan port discovery"
```

## **Available Tools**

| Tool | Purpose | Example |
|------|---------|---------|
| nmap | Port scanning | `nmap -sV target` |
| nuclei | Vulnerability scanning | `nuclei -u http://target` |
| gobuster | Directory enumeration | `gobuster dir -u http://target` |
| subfinder | Subdomain discovery | `subfinder -d target.com` |
| httpx | HTTP probing | `echo target \| httpx` |
| masscan | Fast port scanning | `masscan target -p80,443` |
| sqlmap | SQL injection testing | `sqlmap -u http://target` |

## **Best Practices**

### **Effective Prompts**
- Be specific about target and scope
- Request step-by-step methodology
- Ask for explanations of findings
- Request professional reports

### **Ethical Guidelines**
- Only test authorized systems
- Use for educational purposes
- Follow responsible disclosure
- Respect terms of service