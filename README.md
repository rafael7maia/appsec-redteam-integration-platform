# 🛡️ AI AppSec + Red Team Integration Platform v6.0

> **Complete security testing pipeline with HexStrike AI: 150+ tools, 12+ AI agents, 5 operation modes, 7 attack vectors**

[![Python](https://img.shields.io/badge/Python-3.8+-blue)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Containerized-blue)](https://docker.com)
[![Security Tools](https://img.shields.io/badge/Security%20Tools-150+-red)](https://hexstrike.dev)
[![AI Agents](https://img.shields.io/badge/AI%20Agents-12+-purple)](https://github.com)
[![Modes](https://img.shields.io/badge/Operation%20Modes-5-green)](https://github.com)
[![GitHub](https://img.shields.io/badge/GitHub-rafael7maia-black)](https://github.com/rafael7maia/appsec-redteam-integration-platform)

---

## 📚 **Documentation Hub**

This README serves as a **central navigation point**. Choose your learning path based on your needs:

### **🚀 Quick Start (5-10 minutes)**
👉 **Start here:** [COMO_USAR.md](COMO_USAR.md)
- Step-by-step Docker setup
- First scan in under 10 minutes
- Copy-paste ready commands
- Troubleshooting quick fixes

### **🏗️ Technical Deep Dive**
👉 **Architecture & implementation:** [HEXSTRIKE_INTEGRATION.md](HEXSTRIKE_INTEGRATION.md)
- 3-phase integration architecture
- Component details and integration points
- Docker deployment guide
- Performance metrics and tuning
- Security considerations

### **📊 Project Overview**
👉 **Completion status & statistics:** [PROJECT_STATUS.md](PROJECT_STATUS.md)
- Integration completion checklist
- File inventory (1,750+ lines of code)
- Git commit history
- Verification checklist
- Production deployment guide

### **📋 Integration Summary**
👉 **Executive summary:** [INTEGRATION_SUMMARY.txt](INTEGRATION_SUMMARY.txt)
- High-level overview
- 3-phase summary
- Capabilities list (150+ tools, 12+ agents, 5 modes, 7 attack vectors)
- Quick usage reference

---

## 🎯 **What is HexStrike AI v6.0?**

A complete penetration testing and security analysis platform featuring:

| Feature | Details |
|---------|---------|
| **Tools** | 150+ integrated security tools |
| **AI Agents** | 12+ autonomous agents for smart analysis |
| **Operation Modes** | 5 modes: AppSec Only, AppSec+RedTeam, RedTeam, TypeScript, HexStrike |
| **Attack Vectors** | 7: reconnaissance, vulnerability scanning, exploitation, web apps, network, API, cloud |
| **Platform** | Python + Docker, Windows/Linux/macOS compatible |
| **Status** | ✅ Production ready |

---

## ⚡ **5 Operation Modes**

### **1️⃣ Mode 1: AppSec Only**
Source code analysis + dependency scanning
- SCA (Software Composition Analysis)
- Secrets detection
- SAST (Static Application Security Testing)
- Dependency vulnerability scanning

**Best for:** DevSecOps, CI/CD pipelines, code audits

### **2️⃣ Mode 2: AppSec + Red Team**
Complete analysis with exploitation validation
- All of Mode 1 +
- Proof-of-concept exploitation
- Real vulnerability confirmation
- Business impact assessment

**Best for:** Penetration testing, compliance audits, security validation

### **3️⃣ Mode 3: Red Team Only**
External application testing without source code
- Reconnaissance & mapping
- Vulnerability discovery
- Exploitation & validation
- Risk assessment

**Best for:** Bug bounty hunting, black-box testing, external security audits

### **4️⃣ Mode 4: TypeScript/Node.js Scanner**
Specialized analysis for Express + Prisma applications
- TypeScript-specific vulnerabilities
- Node.js framework analysis
- JWT & authentication testing
- Database security scanning

**Best for:** Node.js development teams, Express applications

### **5️⃣ Mode 5: HexStrike AI Full Platform** ⭐ NEW
Complete automated security testing with AI coordination
- All 150+ security tools
- 12+ autonomous AI agents
- Multiple attack vectors simultaneously
- Intelligent vulnerability correlation
- Automated exploit generation

**Best for:** Comprehensive security assessment, CTF challenges, advanced testing

---

## 🚀 **Quick Start (30 seconds)**

```bash
# 1. Clone the repository
git clone https://github.com/rafael7maia/appsec-redteam-integration-platform.git
cd appsec-redteam-integration-platform

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start HexStrike (Docker recommended for Mode 5)
./start_hexstrike.ps1

# 4. Run the platform
python quick_start.py

# 5. Select mode 5 and configure your target

# 6. Stop service when done
./stop_hexstrike.ps1
```

**⏱️ Full tutorial with examples:** [COMO_USAR.md](COMO_USAR.md)

---

## 📁 **Project Structure**

```
appsec-redteam-integration-platform/
│
├── 📖 Documentation (READ THESE FIRST)
│   ├── README.md                          ← You are here
│   ├── COMO_USAR.md                       ← Quick start guide (Portuguese)
│   ├── HEXSTRIKE_INTEGRATION.md           ← Technical reference
│   ├── INTEGRATION_SUMMARY.txt            ← Executive summary
│   └── PROJECT_STATUS.md                  ← Completion status
│
├── 🎯 Core Platform Files
│   ├── quick_start.py                     ← Main entry point (5 modes)
│   ├── config_loader.py                   ← Configuration validation
│   ├── core_scanner.py                    ← Core scanning engine
│   ├── appsec_scanner.py                  ← AppSec pipeline
│   ├── enhanced_security_bridge.py        ← Red Team integration
│   ├── smart_validation_engine.py         ← False positive elimination
│   ├── waf_detection.py                   ← WAF/CDN detection
│   ├── report_generator.py                ← Result reporting
│   └── typescript_security_scanner.py     ← TypeScript specialist
│
├── 🆕 HexStrike Integration (Phase 1-3)
│   ├── hexstrike_lib.py                   ← Extracted HexStrike components
│   ├── hexstrike_scanner.py               ← HexStrike server wrapper
│   ├── docker-compose.hexstrike.yml       ← Docker orchestration
│   ├── start_hexstrike.ps1                ← Startup automation (Windows)
│   └── stop_hexstrike.ps1                 ← Shutdown automation (Windows)
│
├── 📦 Dependencies
│   ├── requirements.txt                   ← Python packages
│   └── hexstrike-ai/                      ← HexStrike framework (subtree)
│
├── 🐳 Docker
│   ├── Dockerfile                         ← Container definition
│   └── docker-compose.yml                 ← CICD orchestration
│
├── 🧪 Examples & Tests
│   ├── projetos/                          ← Project folders
│   │   ├── agendatroca/                  ← Example project
│   │   └── techcorp/                     ← Vulnerable demo app
│   └── tests/                             ← Test examples
│
└── ⚙️ Configuration
    ├── config.env                         ← Platform configuration
    ├── target_profiles.json               ← Business type profiles
    └── .gitignore                         ← Git exclusions
```

---

## 🔧 **System Requirements**

### **Minimum**
- Python 3.8+
- 4GB RAM
- 2GB disk space
- pip (Python package manager)

### **For Mode 5 (Docker - Recommended)**
- Docker Desktop 4.0+
- Docker Compose 1.29+
- 4GB RAM available for container
- Port 8888 available (configurable)

### **Installation**

**Python:**
```bash
# Windows/macOS/Linux
python --version  # Should be 3.8 or higher
pip install -r requirements.txt
```

**Docker (for Mode 5):**

**Windows:** Download [Docker Desktop](https://docker.com/products/docker-desktop)

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install docker.io docker-compose
sudo usermod -aG docker $USER
```

**macOS:**
```bash
brew install docker docker-compose
# or download Docker Desktop from https://docker.com
```

---

## 🎓 **Learning Paths**

### **👤 Path 1: "I just want to scan something"**
1. Read: [COMO_USAR.md](COMO_USAR.md) - Quick Start section
2. Run: `python quick_start.py` → Select mode 5
3. Done! Results saved as JSON

**Time:** ~15 minutes

### **👨‍💻 Path 2: "I want to understand what's happening"**
1. Read: [COMO_USAR.md](COMO_USAR.md) - Full guide
2. Read: [HEXSTRIKE_INTEGRATION.md](HEXSTRIKE_INTEGRATION.md) - Sections 1-3
3. Review code: `hexstrike_lib.py`, `hexstrike_scanner.py`
4. Run examples from COMO_USAR.md section "Usando via API Python"

**Time:** ~1-2 hours

### **🏗️ Path 3: "I need to understand the architecture"**
1. Read: [PROJECT_STATUS.md](PROJECT_STATUS.md) - Technical Implementation Summary
2. Read: [HEXSTRIKE_INTEGRATION.md](HEXSTRIKE_INTEGRATION.md) - Full document
3. Review code: All Python files in order
4. Study Docker: `docker-compose.hexstrike.yml`, PowerShell scripts

**Time:** ~3-4 hours

### **🎯 Path 4: "I want to integrate this into my CI/CD"**
1. Read: [HEXSTRIKE_INTEGRATION.md](HEXSTRIKE_INTEGRATION.md) - CI/CD section
2. Read: [COMO_USAR.md](COMO_USAR.md) - "Próximos Passos" section
3. Review: `quick_start.py` - Mode selection logic
4. Implement: Custom wrapper for your CI/CD platform

**Time:** ~2-3 hours

---

## 🎯 **Usage Examples**

### **Example 1: Mode 5 - Full HexStrike (Recommended)**

```bash
./start_hexstrike.ps1
python quick_start.py
# Select: 5 (HexStrike AI Full Platform)
# Target: example.com
# Vectors: 1,2,4 (reconnaissance, vulnerability_scanning, web_application)
# Review results in: projetos/{project}/hexstrike_results_v5.json
./stop_hexstrike.ps1
```

### **Example 2: Mode 1 - Code Analysis**

```bash
echo "OPERATION_MODE=appsec" > config.env
echo "PROJECT_NAME=myapp" >> config.env
python quick_start.py
# Results in: projetos/myapp/appsec_results.json
```

### **Example 3: Mode 3 - Bug Bounty Hunting**

```bash
echo "OPERATION_MODE=redteam" > config.env
echo "PROJECT_NAME=target" >> config.env
echo "TARGET_DOMAIN=target.com" >> config.env
python quick_start.py
# Results in: projetos/target/redteam_results_v5.json
```

### **Example 4: Python API Usage**

```python
from hexstrike_scanner import HexStrikeScanner

scanner = HexStrikeScanner(
    target_domain='example.com',
    attack_vectors=['reconnaissance', 'vulnerability_scanning'],
    authorization='educational_lab',
    use_docker=True
)

result = scanner.execute_full_scan()
print(f"Total findings: {result['report']['summary']['total_findings']}")
```

**More examples in:** [COMO_USAR.md](COMO_USAR.md#exemplo-2-controle-fino)

---

## 🔐 **Authorization Types**

All testing requires appropriate authorization:

| Type | Use Case | Authorization Check |
|------|----------|-------------------|
| `code_audit` | Internal code review | Project owner only |
| `penetration_test` | Contracted pentest | Written agreement required |
| `bug_bounty_program` | Official bug bounty | Program exists & rules followed |
| `own_system` | Personal/internal system | Ownership verified |
| `educational_lab` | Learning environment | Lab policy compliance |

**Always ensure you have proper authorization before testing any target.**

---

## 📊 **Capabilities**

### **Security Tools (150+)**
- **Network:** nmap, masscan, rustscan, netcat
- **Web Apps:** gobuster, ffuf, sqlmap, nikto, wpscan
- **Recon:** subfinder, httpx, waybackurls, shodan
- **Exploitation:** metasploit, searchsploit, exploit-db
- **Authentication:** hydra, medusa, hashcat
- **Binary Analysis:** radare2, ghidra, binwalk
- **Cloud:** prowler, scout-suite, cloudmapper
- **And 100+ more...**

### **AI Agents (12+)**
- Target Analysis Agent
- Tool Selection Agent
- Vulnerability Correlation Agent
- Exploit Generation Agent
- Intelligence Aggregation Agent
- WAF Detection Agent
- Reconnaissance Agent
- And more...

### **Attack Vectors (7)**
1. **reconnaissance** - Information gathering, OSINT, scanning
2. **vulnerability_scanning** - Vulnerability detection
3. **exploitation** - Proof-of-concept exploitation
4. **web_application** - OWASP Top 10 testing
5. **network** - Network-level security testing
6. **api_security** - REST/GraphQL API testing
7. **cloud** - Cloud infrastructure auditing

---

## 🚨 **Troubleshooting**

### **Common Issues**

**Problem:** Docker not starting
```
Solution: Ensure Docker Desktop is running
Reference: COMO_USAR.md → Troubleshooting → Problem 1
```

**Problem:** Port 8888 already in use
```
Solution: Change port in docker-compose.hexstrike.yml
Reference: COMO_USAR.md → Troubleshooting → Problem 2
```

**Problem:** Module import errors
```
Solution: pip install -r requirements.txt
Reference: COMO_USAR.md → Troubleshooting → Problem 4
```

**Problem:** Server health check timeout
```
Solution: Increase retry count in hexstrike_scanner.py
Reference: HEXSTRIKE_INTEGRATION.md → Docker Deployment
```

**More solutions:** [COMO_USAR.md](COMO_USAR.md#troubleshooting) | [PROJECT_STATUS.md](PROJECT_STATUS.md#troubleshooting)

---

## 📞 **Support & Resources**

### **Documentation**
- 📖 [COMO_USAR.md](COMO_USAR.md) - Practical usage guide (Portuguese)
- 🏗️ [HEXSTRIKE_INTEGRATION.md](HEXSTRIKE_INTEGRATION.md) - Technical deep dive
- 📊 [PROJECT_STATUS.md](PROJECT_STATUS.md) - Completion & verification
- 📋 [INTEGRATION_SUMMARY.txt](INTEGRATION_SUMMARY.txt) - Executive overview

### **GitHub**
- 🐛 [Issues](https://github.com/rafael7maia/appsec-redteam-integration-platform/issues) - Report problems
- 💬 [Discussions](https://github.com/rafael7maia/appsec-redteam-integration-platform/discussions) - Ask questions
- ⭐ [Repository](https://github.com/rafael7maia/appsec-redteam-integration-platform) - See code & commits

### **Direct Contact**
- 📧 Email: rafael@trmeducacao.com.br
- 💼 LinkedIn: Rafael Maia
- 🐙 GitHub: [@rafael7maia](https://github.com/rafael7maia)

---

## ✅ **What's New in v6.0?**

### **Phase 1: Library Integration**
✅ Extracted 6 core HexStrike components
✅ Integrated into existing modes 1-4
✅ Enhanced AppSec, RedTeam, TypeScript scanners

### **Phase 2: Mode 5 Implementation**
✅ New "HexStrike AI Full Platform" mode
✅ Complete server wrapper with lifecycle management
✅ API integration for all 150+ tools
✅ Automated AI agent coordination

### **Phase 3: Docker Deployment**
✅ Production-ready containerization
✅ Windows PowerShell automation
✅ Cross-platform compatibility (Windows/Linux/macOS)
✅ Health checks and resource management

### **Documentation**
✅ COMO_USAR.md - Portuguese practical guide
✅ HEXSTRIKE_INTEGRATION.md - Technical reference
✅ PROJECT_STATUS.md - Completion report
✅ This README.md - Central hub

---

## 🎉 **Quick Facts**

- **Lines of Code:** 1,750+
- **Lines of Documentation:** 1,612+
- **New Files:** 7
- **Modified Files:** 6
- **Git Commits:** 10
- **Backward Compatibility:** 100%
- **Breaking Changes:** 0
- **Production Ready:** ✅ Yes
- **Time to First Scan:** ~10 minutes

---

## 📈 **Project Status**

| Component | Status |
|-----------|--------|
| Phase 1 - Library | ✅ Complete |
| Phase 2 - Mode 5 | ✅ Complete |
| Phase 3 - Docker | ✅ Complete |
| Documentation | ✅ Complete |
| Git Repository | ✅ Pushed |
| Production Ready | ✅ Ready |

**Full details:** [PROJECT_STATUS.md](PROJECT_STATUS.md)

---

## 🎯 **Next Steps**

### **1. Get Started (Now)**
👉 Read: [COMO_USAR.md](COMO_USAR.md) - Takes 15 minutes
👉 Run: `./start_hexstrike.ps1` → `python quick_start.py` → Mode 5

### **2. Understand (This Week)**
👉 Read: [HEXSTRIKE_INTEGRATION.md](HEXSTRIKE_INTEGRATION.md)
👉 Review: Source code in key files

### **3. Integrate (This Month)**
👉 Add to CI/CD pipeline
👉 Schedule automated scans
👉 Integrate with Claude Desktop/Cursor

### **4. Automate (Ongoing)**
👉 Create custom scanning workflows
👉 Develop reporting dashboards
👉 Build team training programs

---

## 📄 **License & Legal**

✅ **Authorized Testing:** This platform supports official bug bounties, pentesting contracts, educational labs, and personal systems

❌ **Prohibited:** Unauthorized testing, malicious use, Terms of Service violations

**Always ensure proper authorization before testing any target.**

---

## 🙏 **Acknowledgments**

- **HexStrike AI** - The awesome security framework we integrated
- **Open Source Community** - 150+ security tools we leverage
- **Contributors** - Everyone who helped develop and test

---

## 🚀 **Ready to Start?**

1. **Start Here:** [COMO_USAR.md](COMO_USAR.md) - 15-minute quick start
2. **Then Read:** [HEXSTRIKE_INTEGRATION.md](HEXSTRIKE_INTEGRATION.md) - Understanding the architecture
3. **Finally Review:** [PROJECT_STATUS.md](PROJECT_STATUS.md) - Completion verification

**Version:** 6.0 | **Status:** Production Ready ✅ | **Updated:** December 24, 2025

---

**Made with ❤️ for security professionals, developers, and researchers.**

[![GitHub Stars](https://img.shields.io/github/stars/rafael7maia/appsec-redteam-integration-platform)](https://github.com/rafael7maia/appsec-redteam-integration-platform)
[![Python Version](https://img.shields.io/badge/Python-3.8+-blue)](https://python.org)
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-blue)](https://docker.com)
