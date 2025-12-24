#!/usr/bin/env python3
"""
HexStrike AI Library - Standalone Components
Extracted from hexstrike_server.py for integration with AppSec + Red Team Platform
Includes: ModernVisualEngine, IntelligentDecisionEngine, HexStrikeCache,
VulnerabilityCorrelator, TelemetryCollector
"""

import json
import logging
import os
import socket
import time
import urllib.parse
import re
import hashlib
import psutil
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# MODERN VISUAL ENGINE - Terminal Output Formatting
# ============================================================================

class ModernVisualEngine:
    """Beautiful, modern output formatting with cyberpunk styling"""

    # Enhanced color palette with reddish tones
    COLORS = {
        'MATRIX_GREEN': '\033[38;5;46m',
        'NEON_BLUE': '\033[38;5;51m',
        'ELECTRIC_PURPLE': '\033[38;5;129m',
        'CYBER_ORANGE': '\033[38;5;208m',
        'HACKER_RED': '\033[38;5;196m',
        'TERMINAL_GRAY': '\033[38;5;240m',
        'BRIGHT_WHITE': '\033[97m',
        'RESET': '\033[0m',
        'BOLD': '\033[1m',
        'DIM': '\033[2m',
        'BLOOD_RED': '\033[38;5;124m',
        'CRIMSON': '\033[38;5;160m',
        'DARK_RED': '\033[38;5;88m',
        'FIRE_RED': '\033[38;5;202m',
        'ROSE_RED': '\033[38;5;167m',
        'PRIMARY_BORDER': '\033[38;5;160m',
        'ACCENT_LINE': '\033[38;5;196m',
        'ACCENT_GRADIENT': '\033[38;5;124m',
        'SUCCESS': '\033[38;5;46m',
        'WARNING': '\033[38;5;208m',
        'ERROR': '\033[38;5;196m',
        'INFO': '\033[38;5;51m',
        'VULN_CRITICAL': '\033[48;5;124m\033[38;5;15m\033[1m',
        'VULN_HIGH': '\033[38;5;196m\033[1m',
        'VULN_MEDIUM': '\033[38;5;208m\033[1m',
        'VULN_LOW': '\033[38;5;226m',
    }

    @staticmethod
    def create_banner() -> str:
        """Create HexStrike banner"""
        border = ModernVisualEngine.COLORS['PRIMARY_BORDER']
        accent = ModernVisualEngine.COLORS['ACCENT_LINE']
        RESET = ModernVisualEngine.COLORS['RESET']
        BOLD = ModernVisualEngine.COLORS['BOLD']

        return f"""
{accent}{BOLD}
██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
{RESET}
{border}┌────────────────────────────────────────────────────────────┐
│  HexStrike AI - Blood-Red Offensive Intelligence Core     │
│  AI-Powered Security Testing & Automated Exploitation     │
└────────────────────────────────────────────────────────────┘{RESET}
"""

    @staticmethod
    def create_progress_bar(current: int, total: int, width: int = 50, label: str = "") -> str:
        """Create a beautiful progress bar"""
        if total == 0:
            percentage = 0
        else:
            percentage = min(100, (current / total) * 100)

        filled = int(width * percentage / 100)
        bar = '█' * filled + '░' * (width - filled)

        border = ModernVisualEngine.COLORS['PRIMARY_BORDER']
        fill_col = ModernVisualEngine.COLORS['ACCENT_LINE']
        reset = ModernVisualEngine.COLORS['RESET']

        return f"{border}[{fill_col}{bar}{border}] {percentage:6.1f}% {label}{reset}"

    @staticmethod
    def format_vulnerability_card(name: str, severity: str, description: str) -> str:
        """Format vulnerability as a beautiful card"""
        severity_upper = severity.upper()
        severity_colors = {
            'CRITICAL': ModernVisualEngine.COLORS['VULN_CRITICAL'],
            'HIGH': ModernVisualEngine.COLORS['VULN_HIGH'],
            'MEDIUM': ModernVisualEngine.COLORS['VULN_MEDIUM'],
            'LOW': ModernVisualEngine.COLORS['VULN_LOW'],
        }

        color = severity_colors.get(severity_upper, ModernVisualEngine.COLORS['INFO'])
        reset = ModernVisualEngine.COLORS['RESET']

        return f"""
{color}[VULN] {severity_upper}{reset} - {name}
{description[:80]}
"""

    @staticmethod
    def format_section_header(title: str) -> str:
        """Create a section header"""
        header_color = ModernVisualEngine.COLORS['FIRE_RED']
        reset = ModernVisualEngine.COLORS['RESET']

        return f"""
{header_color}{'='*70}{reset}
{header_color}{title.upper()}{reset}
{header_color}{'='*70}{reset}
"""

# ============================================================================
# TARGET PROFILING & INTELLIGENT DECISION ENGINE
# ============================================================================

class TargetType(Enum):
    """Different target types"""
    WEB_APPLICATION = "web_application"
    NETWORK_HOST = "network_host"
    API_ENDPOINT = "api_endpoint"
    CLOUD_SERVICE = "cloud_service"
    BINARY_FILE = "binary_file"
    UNKNOWN = "unknown"


class TechnologyStack(Enum):
    """Common technology stacks"""
    APACHE = "Apache"
    NGINX = "Nginx"
    IIS = "IIS"
    NODEJS = "Node.js"
    PHP = "PHP"
    PYTHON = "Python"
    JAVA = "Java"
    DOTNET = ".NET"
    WORDPRESS = "WordPress"
    DRUPAL = "Drupal"
    JOOMLA = "Joomla"
    REACT = "React"
    ANGULAR = "Angular"
    VUE = "Vue"
    UNKNOWN = "Unknown"


@dataclass
class TargetProfile:
    """Comprehensive target profile"""
    target: str
    target_type: TargetType = TargetType.UNKNOWN
    technologies: List[TechnologyStack] = field(default_factory=list)
    cms_type: Optional[str] = None
    ip_addresses: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    attack_surface_score: float = 0.0
    risk_level: str = "unknown"
    confidence_score: float = 0.0


class IntelligentDecisionEngine:
    """AI-powered tool selection and parameter optimization"""

    def __init__(self):
        self.tool_effectiveness = self._initialize_tool_effectiveness()

    def _initialize_tool_effectiveness(self) -> Dict[str, Dict[str, float]]:
        """Tool effectiveness ratings for different target types"""
        return {
            TargetType.WEB_APPLICATION.value: {
                "nmap": 0.8,
                "gobuster": 0.9,
                "nuclei": 0.95,
                "nikto": 0.85,
                "sqlmap": 0.9,
                "ffuf": 0.9,
                "feroxbuster": 0.85,
                "katana": 0.88,
                "httpx": 0.85,
                "wpscan": 0.95,
                "burpsuite": 0.9,
            },
            TargetType.NETWORK_HOST.value: {
                "nmap": 0.95,
                "masscan": 0.92,
                "rustscan": 0.9,
                "autorecon": 0.95,
                "enum4linux": 0.8,
                "smbmap": 0.85,
                "responder": 0.88,
            },
            TargetType.API_ENDPOINT.value: {
                "nuclei": 0.9,
                "ffuf": 0.85,
                "arjun": 0.95,
                "paramspider": 0.88,
                "httpx": 0.9,
            },
            TargetType.CLOUD_SERVICE.value: {
                "prowler": 0.95,
                "scout-suite": 0.92,
                "trivy": 0.9,
                "kube-hunter": 0.9,
            },
            TargetType.BINARY_FILE.value: {
                "ghidra": 0.95,
                "radare2": 0.9,
                "gdb": 0.85,
                "angr": 0.88,
                "pwntools": 0.9,
            }
        }

    def analyze_target(self, target: str) -> TargetProfile:
        """Analyze target and create profile"""
        profile = TargetProfile(target=target)
        profile.target_type = self._determine_target_type(target)

        if profile.target_type in [TargetType.WEB_APPLICATION, TargetType.API_ENDPOINT]:
            profile.ip_addresses = self._resolve_domain(target)

        if profile.target_type == TargetType.WEB_APPLICATION:
            profile.technologies = self._detect_technologies(target)
            profile.cms_type = self._detect_cms(target)

        profile.attack_surface_score = self._calculate_attack_surface(profile)
        profile.risk_level = self._determine_risk_level(profile)
        profile.confidence_score = self._calculate_confidence(profile)

        return profile

    def _determine_target_type(self, target: str) -> TargetType:
        """Determine target type"""
        if target.startswith(('http://', 'https://')):
            parsed = urllib.parse.urlparse(target)
            if '/api/' in parsed.path or parsed.path.endswith('/api'):
                return TargetType.API_ENDPOINT
            return TargetType.WEB_APPLICATION

        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
            return TargetType.NETWORK_HOST

        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            return TargetType.WEB_APPLICATION

        if target.endswith(('.exe', '.bin', '.elf', '.so', '.dll')):
            return TargetType.BINARY_FILE

        if any(cloud in target.lower() for cloud in ['amazonaws.com', 'azure', 'googleapis.com']):
            return TargetType.CLOUD_SERVICE

        return TargetType.UNKNOWN

    def _resolve_domain(self, target: str) -> List[str]:
        """Resolve domain to IPs"""
        try:
            if target.startswith(('http://', 'https://')):
                hostname = urllib.parse.urlparse(target).hostname
            else:
                hostname = target

            if hostname:
                ip = socket.gethostbyname(hostname)
                return [ip]
        except Exception:
            pass
        return []

    def _detect_technologies(self, target: str) -> List[TechnologyStack]:
        """Detect technologies"""
        technologies = []
        target_lower = target.lower()

        if 'wordpress' in target_lower or 'wp-' in target_lower:
            technologies.append(TechnologyStack.WORDPRESS)
        if any(ext in target_lower for ext in ['.php', 'php']):
            technologies.append(TechnologyStack.PHP)
        if any(ext in target_lower for ext in ['.asp', '.aspx']):
            technologies.append(TechnologyStack.DOTNET)

        return technologies if technologies else [TechnologyStack.UNKNOWN]

    def _detect_cms(self, target: str) -> Optional[str]:
        """Detect CMS type"""
        target_lower = target.lower()

        if 'wordpress' in target_lower or 'wp-' in target_lower:
            return "WordPress"
        elif 'drupal' in target_lower:
            return "Drupal"
        elif 'joomla' in target_lower:
            return "Joomla"

        return None

    def _calculate_attack_surface(self, profile: TargetProfile) -> float:
        """Calculate attack surface score"""
        score = 0.0

        type_scores = {
            TargetType.WEB_APPLICATION: 7.0,
            TargetType.API_ENDPOINT: 6.0,
            TargetType.NETWORK_HOST: 8.0,
            TargetType.CLOUD_SERVICE: 5.0,
            TargetType.BINARY_FILE: 4.0
        }

        score += type_scores.get(profile.target_type, 3.0)
        score += len(profile.technologies) * 0.5
        score += len(profile.open_ports) * 0.3
        score += len(profile.subdomains) * 0.2

        if profile.cms_type:
            score += 1.5

        return min(score, 10.0)

    def _determine_risk_level(self, profile: TargetProfile) -> str:
        """Determine risk level"""
        if profile.attack_surface_score >= 8.0:
            return "critical"
        elif profile.attack_surface_score >= 6.0:
            return "high"
        elif profile.attack_surface_score >= 4.0:
            return "medium"
        elif profile.attack_surface_score >= 2.0:
            return "low"
        else:
            return "minimal"

    def _calculate_confidence(self, profile: TargetProfile) -> float:
        """Calculate confidence score"""
        confidence = 0.5

        if profile.ip_addresses:
            confidence += 0.1
        if profile.technologies and profile.technologies[0] != TechnologyStack.UNKNOWN:
            confidence += 0.2
        if profile.cms_type:
            confidence += 0.1
        if profile.target_type != TargetType.UNKNOWN:
            confidence += 0.1

        return min(confidence, 1.0)

    def select_tools_for_target(self, profile: TargetProfile) -> Dict[str, float]:
        """Select optimal tools for target"""
        effectiveness = self.tool_effectiveness.get(profile.target_type.value, {})
        return sorted(effectiveness.items(), key=lambda x: x[1], reverse=True)


# ============================================================================
# HEXSTRIKE CACHE - LRU Cache with TTL
# ============================================================================

class HexStrikeCache:
    """Advanced caching system with TTL and LRU eviction"""

    def __init__(self, max_size: int = 1000, ttl: int = 3600):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl
        self.stats = {"hits": 0, "misses": 0, "evictions": 0}

    def _generate_key(self, command: str, params: Dict[str, Any]) -> str:
        """Generate cache key"""
        key_data = f"{command}:{json.dumps(params, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def _is_expired(self, timestamp: float) -> bool:
        """Check if entry is expired"""
        return time.time() - timestamp > self.ttl

    def get(self, command: str, params: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Get cached result"""
        if params is None:
            params = {}

        key = self._generate_key(command, params)

        if key in self.cache:
            timestamp, data = self.cache[key]
            if not self._is_expired(timestamp):
                self.cache.move_to_end(key)
                self.stats["hits"] += 1
                logger.info(f"[CACHE HIT] {command}")
                return data
            else:
                del self.cache[key]

        self.stats["misses"] += 1
        logger.info(f"[CACHE MISS] {command}")
        return None

    def set(self, command: str, params: Dict[str, Any], result: Dict[str, Any]):
        """Store result in cache"""
        key = self._generate_key(command, params)

        while len(self.cache) >= self.max_size:
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
            self.stats["evictions"] += 1

        self.cache[key] = (time.time(), result)
        logger.info(f"[CACHED] {command}...")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total = self.stats["hits"] + self.stats["misses"]
        hit_rate = (self.stats["hits"] / total * 100) if total > 0 else 0

        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hit_rate": f"{hit_rate:.1f}%",
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "evictions": self.stats["evictions"]
        }


# ============================================================================
# VULNERABILITY CORRELATOR - Attack Chain Discovery
# ============================================================================

class VulnerabilityCorrelator:
    """Correlate vulnerabilities across multiple sources"""

    def __init__(self):
        self.attack_patterns = {
            "privilege_escalation": ["local", "kernel", "suid", "sudo"],
            "remote_execution": ["remote", "network", "rce", "code execution"],
            "persistence": ["service", "registry", "scheduled", "startup"],
            "lateral_movement": ["smb", "wmi", "ssh", "rdp"],
            "data_exfiltration": ["file", "database", "memory", "network"]
        }

    def correlate_findings(self, findings_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate findings from multiple sources"""
        correlated = {
            "timestamp": datetime.now().isoformat(),
            "total_findings": 0,
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "deduplicated": [],
            "correlation_score": 0.0
        }

        all_findings = []
        for scanner, findings in findings_dict.items():
            if isinstance(findings, dict) and 'findings' in findings:
                all_findings.extend(findings.get('findings', []))

        # Deduplicate based on description
        seen = set()
        for finding in all_findings:
            desc = finding.get('description', '').lower()
            if desc not in seen:
                seen.add(desc)
                correlated['deduplicated'].append(finding)
                severity = finding.get('severity', 'low').lower()
                if severity in correlated['by_severity']:
                    correlated['by_severity'][severity] += 1

        correlated['total_findings'] = len(correlated['deduplicated'])
        correlated['correlation_score'] = min(len(findings_dict) * 0.25, 1.0)

        return correlated

    def find_attack_chains(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find potential attack chains"""
        chains = []

        # Simple chain detection based on severity and patterns
        critical = [f for f in findings if f.get('severity', '').lower() == 'critical']
        high = [f for f in findings if f.get('severity', '').lower() == 'high']

        for crit in critical[:3]:
            chain = {
                "initial_access": crit,
                "escalation_opportunities": high[:2],
                "potential_impact": "System compromise",
                "probability": 0.85
            }
            chains.append(chain)

        return chains


# ============================================================================
# TELEMETRY COLLECTOR - Performance Metrics
# ============================================================================

class TelemetryCollector:
    """Collect and manage telemetry data"""

    def __init__(self):
        self.stats = {
            "commands_executed": 0,
            "successful_commands": 0,
            "failed_commands": 0,
            "total_execution_time": 0.0,
            "start_time": time.time()
        }

    def record_execution(self, success: bool, execution_time: float):
        """Record command execution"""
        self.stats["commands_executed"] += 1
        if success:
            self.stats["successful_commands"] += 1
        else:
            self.stats["failed_commands"] += 1
        self.stats["total_execution_time"] += execution_time

    def get_system_metrics(self) -> Dict[str, Any]:
        """Get system metrics"""
        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent if os.name != 'nt' else 0
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get telemetry statistics"""
        uptime = time.time() - self.stats["start_time"]
        total = self.stats["commands_executed"]
        success_rate = (self.stats["successful_commands"] / total * 100) if total > 0 else 0
        avg_time = (self.stats["total_execution_time"] / total) if total > 0 else 0

        return {
            "uptime_seconds": uptime,
            "commands_executed": self.stats["commands_executed"],
            "success_rate": f"{success_rate:.1f}%",
            "average_execution_time": f"{avg_time:.2f}s",
            "system_metrics": self.get_system_metrics()
        }


# ============================================================================
# GLOBAL INSTANCES
# ============================================================================

visual_engine = ModernVisualEngine()
decision_engine = IntelligentDecisionEngine()
hexstrike_cache = HexStrikeCache()
vulnerability_correlator = VulnerabilityCorrelator()
telemetry_collector = TelemetryCollector()


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def print_banner():
    """Print HexStrike banner"""
    print(visual_engine.create_banner())


def analyze_target(target: str) -> TargetProfile:
    """Analyze a target and return profile"""
    return decision_engine.analyze_target(target)


def get_recommended_tools(target: str) -> Dict[str, float]:
    """Get recommended tools for a target"""
    profile = analyze_target(target)
    return dict(decision_engine.select_tools_for_target(profile))


def get_cache_stats() -> Dict[str, Any]:
    """Get cache statistics"""
    return hexstrike_cache.get_stats()


def get_telemetry_stats() -> Dict[str, Any]:
    """Get telemetry statistics"""
    return telemetry_collector.get_stats()
