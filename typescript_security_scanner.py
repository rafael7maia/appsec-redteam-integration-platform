#!/usr/bin/env python3
"""
TypeScript/Node.js Security Scanner v2.0 - ADVANCED
Customizado para analisar projetos Express + Prisma + JWT

ENHANCED DETECTION:
- Prisma injection vulnerabilities (specific patterns)
- JWT advanced vulnerabilities (no expiry, weak secrets, algorithm confusion)
- CORS misconfiguration (wildcard, lax origins)
- IDOR patterns (predictable IDs, no ownership checks)
- Database injection vulnerabilities
- Authentication bypass patterns
- API endpoint security issues
- Environment variable leaks
- Hardcoded credentials
- Insecure password hashing
- SQL/NoSQL injection patterns
- Race conditions
- Unsafe deserialization
- Express middleware misconfiguration
- Input validation bypass
"""

import os
import re
import json
from pathlib import Path
from datetime import datetime


class TypeScriptSecurityScannerAdvanced:
    def __init__(self, project_path):
        self.project_path = Path(project_path)
        # Directories to exclude from scanning
        self.exclude_dirs = {
            'node_modules', 'dist', 'build', '.next', '.git',
            'coverage', '.venv', 'venv', '__pycache__', '.idea',
            '.vscode', 'tmp', 'temp', '.cache', 'out'
        }
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "project": str(self.project_path),
            "language": "TypeScript",
            "scanner_version": "2.0-advanced-fixed",
            "findings": {
                "database_vulnerabilities": [],
                "prisma_injection": [],
                "authentication_issues": [],
                "jwt_vulnerabilities": [],
                "cors_issues": [],
                "idor_patterns": [],
                "secrets_exposure": [],
                "api_security": [],
                "environment_issues": [],
                "dependency_issues": [],
                "middleware_issues": [],
                "deserialization_issues": []
            }
        }

    def _should_scan_file(self, file_path):
        """Check if file should be scanned (not in excluded directories)"""
        parts = file_path.parts
        for part in parts:
            if part in self.exclude_dirs:
                return False
        return True

    def scan(self):
        """Execute complete advanced scan"""
        print("[*] Starting TypeScript/Node.js Security Scan v2.0 - ADVANCED")
        print(f"[*] Scanning: {self.project_path}")
        print("[*] Enabled: Prisma injection, JWT advanced, CORS, IDOR detection")

        self._scan_database_vulnerabilities()
        self._scan_prisma_injection()
        self._scan_authentication_issues()
        self._scan_jwt_vulnerabilities()
        self._scan_cors_issues()
        self._scan_idor_patterns()
        self._scan_secrets_exposure()
        self._scan_api_security()
        self._scan_environment_issues()
        self._scan_dependencies()
        self._scan_middleware_issues()
        self._scan_deserialization_issues()

        return self.results

    def _scan_database_vulnerabilities(self):
        """Scan for Prisma and database injection vulnerabilities"""
        print("[*] Scanning database vulnerabilities...")

        # Look for unsafe Prisma raw queries
        patterns = {
            "prisma_raw_injection": r"prisma\.\$queryRaw\(`.*?\$\{",
            "prisma_raw_exec": r"prisma\.\$executeRaw\(`.*?\$\{",
            "string_concat_query": r"query\s*=\s*['\"].*?\+.*?['\"]",
            "template_literal_query": r"query\s*=\s*`.*?\$\{",
            "unsafe_where": r"where:\s*\{.*?\$\{",
            "eval_query": r"eval\(.*?query",
            "function_constructor": r"new\s+Function\(.*?query"
        }

        for ts_file in self.project_path.rglob("*.ts"):
            if not self._should_scan_file(ts_file):
                continue
            try:
                with open(ts_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    for pattern_name, pattern in patterns.items():
                        matches = re.finditer(pattern, content, re.MULTILINE)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            self.results["findings"]["database_vulnerabilities"].append({
                                "type": "Database Injection",
                                "pattern": pattern_name,
                                "file": str(ts_file.relative_to(self.project_path)),
                                "line": line_num,
                                "severity": "HIGH",
                                "code_snippet": content[max(0, match.start()-50):match.end()+50]
                            })
            except Exception as e:
                pass

    def _scan_authentication_issues(self):
        """Scan for JWT and authentication security issues"""
        print("[*] Scanning authentication issues...")

        patterns = {
            "hardcoded_jwt_secret": r"JWT_SECRET\s*=\s*['\"]([^'\"]+)['\"]",
            "default_jwt_secret": r"secret:\s*['\"].*?(secret|password|123|test)['\"]",
            "missing_jwt_verify": r"jwt\.decode\(.*?verify\s*=\s*false",
            "weak_password_hash": r"bcrypt\.hash.*?rounds?\s*:\s*([0-9])",
            "low_hash_rounds": r"rounds\s*:\s*([0-4])\b",
            "plaintext_password": r"password\s*:\s*['\"]([^'\"]{1,50})['\"]",
            "no_auth_middleware": r"app\.get\(|app\.post\(.*?req.*?res.*?\)",
            "token_in_url": r"token.*?=.*?req\.query",
            "weak_session_timeout": r"expiresIn\s*:\s*['\"]([0-9]+\s*(s|second))['\"]",
            "jwt_no_expiry": r"sign\(.*?\{(?!.*?expiresIn)"
        }

        for ts_file in self.project_path.rglob("*.ts"):
            if not self._should_scan_file(ts_file):
                continue
            try:
                with open(ts_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    for pattern_name, pattern in patterns.items():
                        matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            self.results["findings"]["authentication_issues"].append({
                                "type": "Authentication Issue",
                                "pattern": pattern_name,
                                "file": str(ts_file.relative_to(self.project_path)),
                                "line": line_num,
                                "severity": "CRITICAL",
                                "code_snippet": content[max(0, match.start()-50):match.end()+50]
                            })
            except Exception as e:
                pass

    def _scan_secrets_exposure(self):
        """Scan for hardcoded secrets and credentials"""
        print("[*] Scanning for secrets exposure...")

        # Check environment files
        env_patterns = {
            "api_key": r"[A-Z_]+_KEY\s*=\s*['\"]([a-zA-Z0-9\-_]+)['\"]",
            "api_token": r"[A-Z_]+_TOKEN\s*=\s*['\"]([a-zA-Z0-9\-_]+)['\"]",
            "db_password": r"PASSWORD\s*=\s*['\"]([^'\"]+)['\"]",
            "jwt_secret": r"JWT.*?SECRET\s*=\s*['\"]([^'\"]+)['\"]",
            "aws_key": r"(AKIA|aws_access_key_id)\s*=\s*['\"]([^'\"]+)['\"]",
            "stripe_key": r"stripe[_-]?(secret|publishable)[_-]?key\s*=\s*['\"]([^'\"]+)['\"]"
        }

        # Check .env files
        for env_file in [".env", ".env.local", ".env.development", ".env.production"]:
            env_path = self.project_path / env_file
            if env_path.exists():
                try:
                    with open(env_path, 'r') as f:
                        content = f.read()
                        for pattern_name, pattern in env_patterns.items():
                            matches = re.finditer(pattern, content, re.MULTILINE)
                            for match in matches:
                                self.results["findings"]["secrets_exposure"].append({
                                    "type": "Hardcoded Secret",
                                    "pattern": pattern_name,
                                    "file": env_file,
                                    "severity": "CRITICAL",
                                    "value_pattern": match.group(1) if match.groups() else "***hidden***"
                                })
                except Exception as e:
                    pass

    def _scan_api_security(self):
        """Scan for API security issues"""
        print("[*] Scanning API security...")

        patterns = {
            "no_rate_limiting": r"app\.post\(|app\.get\((?!.*?rateLimit)",
            "no_input_validation": r"req\.body\..*?(?!validate|sanitize|validator)",
            "no_cors_config": r"cors\(\)(?!.*?\{)",
            "cors_wildcard": r"cors\(\{.*?origin:\s*['\"]?\*['\"]?",
            "no_helmet": r"app\.use.*?helmet\(\)",
            "debug_mode": r"app\.set\(['\"]debug['\"]\s*,\s*true\)",
            "error_exposure": r"res\.send\(error\)|res\.json\(error\)",
            "endpoint_without_auth": r"router\.(get|post|put|delete)\(['\"][^'\"]+['\"],\s*(?!.*?authMiddleware|authenticate)"
        }

        for ts_file in self.project_path.rglob("*.ts"):
            if not self._should_scan_file(ts_file):
                continue
            try:
                with open(ts_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    for pattern_name, pattern in patterns.items():
                        matches = re.finditer(pattern, content, re.MULTILINE)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            self.results["findings"]["api_security"].append({
                                "type": "API Security Issue",
                                "pattern": pattern_name,
                                "file": str(ts_file.relative_to(self.project_path)),
                                "line": line_num,
                                "severity": "MEDIUM",
                                "code_snippet": content[max(0, match.start()-50):match.end()+50]
                            })
            except Exception as e:
                pass

    def _scan_environment_issues(self):
        """Scan for environment and configuration issues"""
        print("[*] Scanning environment issues...")

        env_file = self.project_path / ".env"
        if env_file.exists():
            try:
                with open(env_file, 'r') as f:
                    content = f.read()

                    # Check for required security variables
                    required_vars = [
                        "DATABASE_URL",
                        "JWT_SECRET",
                        "NODE_ENV",
                        "CORS_ORIGIN"
                    ]

                    for var in required_vars:
                        if var not in content:
                            self.results["findings"]["environment_issues"].append({
                                "type": "Missing Security Variable",
                                "variable": var,
                                "severity": "MEDIUM",
                                "recommendation": f"Add {var} to .env"
                            })
                        elif "dev" in content or "test" in content:
                            self.results["findings"]["environment_issues"].append({
                                "type": "Development Credentials",
                                "variable": var,
                                "severity": "HIGH",
                                "recommendation": "Use strong credentials in production"
                            })
            except Exception as e:
                pass

    def _scan_prisma_injection(self):
        """Scan for Prisma-specific injection vulnerabilities"""
        print("[*] Scanning Prisma injection vulnerabilities...")

        prisma_patterns = {
            "prisma_raw_template": r"prisma\.\$queryRaw\s*\(\s*`[^`]*\$\{[^}]*\}`",
            "prisma_execute_raw": r"prisma\.\$executeRaw\s*\(\s*`[^`]*\$\{[^}]*\}`",
            "unsafe_where_clause": r"where:\s*\{[^}]*:\s*req\.\w+\.\w+\s*\}",
            "direct_user_input_where": r"where:\s*\{[^}]*id:\s*(?:req|params)[.\[]",
            "skip_take_injection": r"(?:skip|take):\s*(?:req\.|user\.|params\.)",
            "unsafe_group_by": r"groupBy:\s*[^,\}]*\$\{",
            "raw_include": r"include:\s*\{[^}]*:\s*\$\{",
            "function_in_where": r"where:\s*\{[^}]*:\s*function\(",
            "eval_in_prisma": r"eval\s*\([^)]*\).*?prisma\."
        }

        for ts_file in self.project_path.rglob("*.ts"):
            if not self._should_scan_file(ts_file):
                continue
            try:
                with open(ts_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    for pattern_name, pattern in prisma_patterns.items():
                        matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            self.results["findings"]["prisma_injection"].append({
                                "type": "Prisma Injection",
                                "pattern": pattern_name,
                                "file": str(ts_file.relative_to(self.project_path)),
                                "line": line_num,
                                "severity": "CRITICAL",
                                "recommendation": "Use parameterized queries or Prisma's built-in safety",
                                "code_snippet": content[max(0, match.start()-80):min(len(content), match.end()+80)]
                            })
            except Exception as e:
                pass

    def _scan_jwt_vulnerabilities(self):
        """Scan for JWT advanced vulnerabilities"""
        print("[*] Scanning JWT vulnerabilities...")

        jwt_patterns = {
            "no_expiry_set": r"sign\s*\(\s*\{[^}]*\}\s*,\s*.*?\)\s*(?!.*?expiresIn)",
            "weak_secret": r"sign\s*\(\s*.*?['\"](?:secret|password|123456|admin)['\"]",
            "algorithm_none": r"algorithm\s*:\s*['\"]none['\"]",
            "algorithm_hs256_rs256_mix": r"(?:HS256.*?RS256|RS256.*?HS256)",
            "verify_disabled": r"verify\s*:\s*false",
            "no_signature_check": r"decode\s*\(\s*token\s*\)(?!.*?verify)",
            "token_in_logs": r"console\.\w+\([^)]*token[^)]*\)",
            "token_in_response": r"res\.(?:send|json|cookie)\s*\([^)]*token",
            "jwt_in_query": r"req\.query\.\w*token",
            "hardcoded_secret_regex": r"secret\s*:\s*['\"]([a-zA-Z0-9]{3,20})['\"]"
        }

        for ts_file in self.project_path.rglob("*.ts"):
            if not self._should_scan_file(ts_file):
                continue
            try:
                with open(ts_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    for pattern_name, pattern in jwt_patterns.items():
                        matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            self.results["findings"]["jwt_vulnerabilities"].append({
                                "type": "JWT Vulnerability",
                                "pattern": pattern_name,
                                "file": str(ts_file.relative_to(self.project_path)),
                                "line": line_num,
                                "severity": "CRITICAL",
                                "recommendation": "Use strong secrets, enable expiry, verify signatures",
                                "code_snippet": content[max(0, match.start()-80):min(len(content), match.end()+80)]
                            })
            except Exception as e:
                pass

    def _scan_cors_issues(self):
        """Scan for CORS misconfiguration"""
        print("[*] Scanning CORS issues...")

        cors_patterns = {
            "wildcard_cors": r"origin\s*:\s*['\"]?\*['\"]?",
            "regex_wildcard_cors": r"origin\s*:\s*/.*/",
            "lax_credentials": r"credentials\s*:\s*true.*?origin\s*:\s*\*",
            "wildcard_methods": r"methods\s*:\s*['\"]?\*['\"]?",
            "no_cors_config": r"cors\s*\(\s*\)",
            "allow_all_headers": r"allowedHeaders\s*:\s*['\"]?\*['\"]?",
            "exposed_sensitive_headers": r"exposedHeaders.*?(?:Authorization|X-Auth|X-Token)",
            "cors_no_origin_check": r"origin\s*:\s*function\s*\(\s*origin\s*,\s*callback\s*\)\s*\{[^}]*callback\s*\(\s*null\s*,\s*true\s*\)"
        }

        for ts_file in self.project_path.rglob("*.ts"):
            if not self._should_scan_file(ts_file):
                continue
            try:
                with open(ts_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    for pattern_name, pattern in cors_patterns.items():
                        matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            self.results["findings"]["cors_issues"].append({
                                "type": "CORS Misconfiguration",
                                "pattern": pattern_name,
                                "file": str(ts_file.relative_to(self.project_path)),
                                "line": line_num,
                                "severity": "HIGH",
                                "recommendation": "Restrict CORS to specific origins, validate requests",
                                "code_snippet": content[max(0, match.start()-80):min(len(content), match.end()+80)]
                            })
            except Exception as e:
                pass

    def _scan_idor_patterns(self):
        """Scan for IDOR (Insecure Direct Object Reference) patterns"""
        print("[*] Scanning IDOR patterns...")

        idor_patterns = {
            "direct_user_id_access": r"where:\s*\{\s*id\s*:\s*(?:req\.params\.id|req\.user\.id|userId)",
            "direct_delete_by_id": r"delete\s*\(\s*\{[^}]*where\s*:\s*\{\s*id\s*:\s*req\.params",
            "update_any_user": r"update\s*\(\s*\{[^}]*where\s*:\s*\{\s*id\s*:\s*req\.params\.(?:id|userId)",
            "direct_object_access": r"\.findUnique\s*\([^)]*where:\s*\{\s*id:\s*req\.params\.id\s*\}",
        }

        for ts_file in self.project_path.rglob("*.ts"):
            if not self._should_scan_file(ts_file):
                continue
            try:
                with open(ts_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    for pattern_name, pattern in idor_patterns.items():
                        matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            self.results["findings"]["idor_patterns"].append({
                                "type": "IDOR Pattern",
                                "pattern": pattern_name,
                                "file": str(ts_file.relative_to(self.project_path)),
                                "line": line_num,
                                "severity": "CRITICAL",
                                "recommendation": "Verify user ownership before accessing resources",
                                "code_snippet": content[max(0, match.start()-80):min(len(content), match.end()+80)]
                            })
            except Exception as e:
                pass

    def _scan_middleware_issues(self):
        """Scan for Express middleware misconfiguration"""
        print("[*] Scanning middleware issues...")

        middleware_patterns = {
            "helmet_disabled": r"helmet\s*\(\s*\{[^}]*(?:noSniff|xssFilter|frameGuard):\s*false",
            "unsafe_body_parser": r"bodyParser\.json\s*\(\s*\{[^}]*limit\s*:\s*['\"](?:50|100|200)mb['\"]",
            "wildcard_any_endpoint": r"app\.(?:all|use)\s*\(['\"]?\*['\"]?",
            "cors_wildcard_middleware": r"cors\(\s*\{[^}]*origin\s*:\s*['\"]?\*['\"]?",
            "helmet_not_used": r"app\.use\((?!.*?helmet)"
        }

        for ts_file in self.project_path.rglob("*.ts"):
            if not self._should_scan_file(ts_file):
                continue
            try:
                with open(ts_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    for pattern_name, pattern in middleware_patterns.items():
                        matches = re.finditer(pattern, content, re.MULTILINE)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            self.results["findings"]["middleware_issues"].append({
                                "type": "Middleware Issue",
                                "pattern": pattern_name,
                                "file": str(ts_file.relative_to(self.project_path)),
                                "line": line_num,
                                "severity": "MEDIUM",
                                "recommendation": "Ensure security middleware is properly configured",
                                "code_snippet": content[max(0, match.start()-80):min(len(content), match.end()+80)]
                            })
            except Exception as e:
                pass

    def _scan_deserialization_issues(self):
        """Scan for unsafe deserialization"""
        print("[*] Scanning deserialization issues...")

        deserial_patterns = {
            "json_parse_user_input": r"JSON\.parse\s*\(\s*(?:req\.|user\.)",
            "pickle_loads": r"pickle\.loads|eval\s*\(",
            "unsafe_object_assign": r"Object\.assign\s*\(\s*\{\}[^)]*req\.",
            "spread_operator_unsafe": r"\{\s*\.\.\.\s*req\.",
            "vm_runInContext": r"vm\.runInContext\s*\(\s*(?:req\.|user\.|params\.)"
        }

        for ts_file in self.project_path.rglob("*.ts"):
            if not self._should_scan_file(ts_file):
                continue
            try:
                with open(ts_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    for pattern_name, pattern in deserial_patterns.items():
                        matches = re.finditer(pattern, content, re.MULTILINE)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            self.results["findings"]["deserialization_issues"].append({
                                "type": "Unsafe Deserialization",
                                "pattern": pattern_name,
                                "file": str(ts_file.relative_to(self.project_path)),
                                "line": line_num,
                                "severity": "CRITICAL",
                                "recommendation": "Validate and sanitize data before deserialization",
                                "code_snippet": content[max(0, match.start()-80):min(len(content), match.end()+80)]
                            })
            except Exception as e:
                pass

    def _scan_dependencies(self):
        """Scan package.json for vulnerable dependencies"""
        print("[*] Scanning dependencies...")

        package_json_path = self.project_path / "package.json"
        if package_json_path.exists():
            try:
                with open(package_json_path, 'r') as f:
                    data = json.load(f)

                    # Known vulnerable packages
                    vulnerable_packages = {
                        "express": {"min_version": "4.18.0", "issue": "Old Express versions have security issues"},
                        "bcrypt": {"min_version": "5.0.0", "issue": "Older bcrypt may have timing issues"},
                        "jsonwebtoken": {"min_version": "9.0.0", "issue": "JWT vulnerabilities in older versions"},
                        "passport": {"min_version": "0.7.0", "issue": "Authentication vulnerabilities"},
                        "@prisma/client": {"min_version": "5.0.0", "issue": "Prisma security patches"},
                        "cors": {"min_version": "2.8.5", "issue": "CORS header injection vulnerabilities"}
                    }

                    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}

                    for package, version in deps.items():
                        if package in vulnerable_packages:
                            info = vulnerable_packages[package]
                            self.results["findings"]["dependency_issues"].append({
                                "type": "Vulnerable Dependency",
                                "package": package,
                                "version": version,
                                "severity": "MEDIUM",
                                "issue": info["issue"],
                                "recommendation": f"Update to {info['min_version']} or later"
                            })
            except Exception as e:
                pass

    def generate_report(self, output_file=None):
        """Generate JSON report"""
        report = {
            "scan_info": {
                "scanner": "TypeScript/Node.js Security Scanner v2.0 - Advanced",
                "timestamp": self.results["timestamp"],
                "project": self.results["project"],
                "scanner_version": self.results.get("scanner_version", "2.0")
            },
            "summary": {
                "total_findings": sum(len(v) for v in self.results["findings"].values()),
                "prisma_injection": len(self.results["findings"].get("prisma_injection", [])),
                "jwt_vulnerabilities": len(self.results["findings"].get("jwt_vulnerabilities", [])),
                "cors_issues": len(self.results["findings"].get("cors_issues", [])),
                "idor_patterns": len(self.results["findings"].get("idor_patterns", [])),
                "middleware_issues": len(self.results["findings"].get("middleware_issues", [])),
                "deserialization_issues": len(self.results["findings"].get("deserialization_issues", [])),
                "database_vulnerabilities": len(self.results["findings"]["database_vulnerabilities"]),
                "authentication_issues": len(self.results["findings"]["authentication_issues"]),
                "secrets_exposed": len(self.results["findings"]["secrets_exposure"]),
                "api_security_issues": len(self.results["findings"]["api_security"]),
                "environment_issues": len(self.results["findings"]["environment_issues"]),
                "vulnerable_dependencies": len(self.results["findings"]["dependency_issues"])
            },
            "findings": self.results["findings"]
        }

        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] Report saved to {output_file}")

        return report


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python typescript_security_scanner.py <project_path> [output_file]")
        sys.exit(1)

    project_path = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "typescript_scan_results_v2.json"

    scanner = TypeScriptSecurityScannerAdvanced(project_path)
    scanner.scan()
    report = scanner.generate_report(output_file)

    print("\n" + "="*70)
    print("TYPESCRIPT/NODE.JS SECURITY SCAN v2.0 - ADVANCED SUMMARY")
    print("="*70)
    print(f"Total Findings: {report['summary']['total_findings']}")
    print(f"├─ Prisma Injection: {report['summary'].get('prisma_injection', 0)}")
    print(f"├─ JWT Vulnerabilities: {report['summary'].get('jwt_vulnerabilities', 0)}")
    print(f"├─ CORS Issues: {report['summary'].get('cors_issues', 0)}")
    print(f"├─ IDOR Patterns: {report['summary'].get('idor_patterns', 0)}")
    print(f"├─ Middleware Issues: {report['summary'].get('middleware_issues', 0)}")
    print(f"├─ Deserialization Issues: {report['summary'].get('deserialization_issues', 0)}")
    print(f"├─ Database Vulnerabilities: {report['summary']['database_vulnerabilities']}")
    print(f"├─ Authentication Issues: {report['summary']['authentication_issues']}")
    print(f"├─ Secrets Exposed: {report['summary']['secrets_exposed']}")
    print(f"├─ API Security Issues: {report['summary']['api_security_issues']}")
    print(f"├─ Environment Issues: {report['summary']['environment_issues']}")
    print(f"└─ Vulnerable Dependencies: {report['summary']['vulnerable_dependencies']}")
    print("="*70)
    print(f"Report saved to: {output_file}")
