#!/usr/bin/env python3
"""
Simple Mode Selector - Windows Compatible
"""

import os
import sys
from pathlib import Path

class ModeSelector:
    def __init__(self, config_path="config.env"):
        self.config_path = config_path
        self.config = {}
        self.valid_modes = ["appsec", "appsec_redteam", "redteam"]
        self.valid_profiles = ["entertainment", "e-commerce", "financial", "healthcare", "government"]
        self.valid_auth = ["code_audit", "penetration_test", "bug_bounty_program", "own_system", "educational_lab"]
    
    def load_config(self):
        """Load configuration from config.env"""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        
        with open(self.config_path, 'r') as f:
            for line in f:
                if '=' in line and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    self.config[key] = value
    
    def validate_mode(self):
        """Validate operation mode and required inputs"""
        
        # Check mandatory fields
        if 'OPERATION_MODE' not in self.config:
            raise ValueError("OPERATION_MODE is required in config.env")
        
        if 'PROJECT_NAME' not in self.config:
            raise ValueError("PROJECT_NAME is required in config.env")
        
        if 'AUTHORIZATION' not in self.config:
            raise ValueError("AUTHORIZATION is required in config.env")
        
        mode = self.config['OPERATION_MODE']
        project = self.config['PROJECT_NAME']
        auth = self.config['AUTHORIZATION']
        
        # Validate mode
        if mode not in self.valid_modes:
            raise ValueError(f"Invalid OPERATION_MODE: {mode}. Valid options: {self.valid_modes}")
        
        # Validate authorization
        if auth not in self.valid_auth:
            raise ValueError(f"Invalid AUTHORIZATION: {auth}. Valid options: {self.valid_auth}")
        
        print(f"Operation Mode: {mode}")
        print(f"Project Name: {project}")
        print(f"Authorization: {auth}")
        
        # Mode-specific validations
        if mode == "appsec":
            self._validate_appsec_mode(project)
        elif mode == "appsec_redteam":
            self._validate_appsec_redteam_mode(project)
        elif mode == "redteam":
            self._validate_redteam_mode()
        
        return mode, project
    
    def _validate_appsec_mode(self, project):
        """Validate AppSec Only mode requirements"""
        print("\nValidating AppSec Mode requirements...")
        
        # Check if source code exists
        app_path = Path(f"projetos/{project}/app")
        if not app_path.exists():
            raise FileNotFoundError(
                f"Source code not found!\n"
                f"   AppSec mode requires source code in: projetos/{project}/app/\n"
                f"   Please copy your application source code to this folder."
            )
        
        # Check if app folder has content
        if not any(app_path.iterdir()):
            raise ValueError(
                f"Empty source code folder!\n"
                f"   The folder projetos/{project}/app/ exists but is empty.\n"
                f"   Please copy your application source code to this folder."
            )
        
        print(f"Source code found: projetos/{project}/app/")
        print(f"Detected {len(list(app_path.rglob('*')))} files in source code")
        
        # Check for common files
        common_files = ["requirements.txt", "package.json", "pom.xml", "Gemfile", "go.mod"]
        found_files = [f for f in common_files if (app_path / f).exists()]
        if found_files:
            print(f"Dependency files found: {found_files}")
    
    def _validate_appsec_redteam_mode(self, project):
        """Validate AppSec + Red Team mode requirements"""
        print("\nValidating AppSec + Red Team Mode requirements...")
        
        # Validate AppSec requirements
        self._validate_appsec_mode(project)
        
        # Validate Red Team requirements
        if 'TARGET_DOMAIN' not in self.config:
            raise ValueError("TARGET_DOMAIN is required for AppSec + Red Team mode")
        
        if 'TARGET_PROFILE' not in self.config:
            raise ValueError("TARGET_PROFILE is required for AppSec + Red Team mode")
        
        domain = self.config['TARGET_DOMAIN']
        profile = self.config['TARGET_PROFILE']
        
        # Validate profile
        if profile not in self.valid_profiles:
            raise ValueError(f"Invalid TARGET_PROFILE: {profile}. Valid options: {self.valid_profiles}")
        
        print(f"Target Domain: {domain}")
        print(f"Target Profile: {profile}")
    
    def _validate_redteam_mode(self):
        """Validate Red Team Only mode requirements"""
        print("\nValidating Red Team Mode requirements...")
        
        if 'TARGET_DOMAIN' not in self.config:
            raise ValueError("TARGET_DOMAIN is required for Red Team mode")
        
        if 'TARGET_PROFILE' not in self.config:
            raise ValueError("TARGET_PROFILE is required for Red Team mode")
        
        domain = self.config['TARGET_DOMAIN']
        profile = self.config['TARGET_PROFILE']
        
        # Validate profile
        if profile not in self.valid_profiles:
            raise ValueError(f"Invalid TARGET_PROFILE: {profile}. Valid options: {self.valid_profiles}")
        
        print(f"Target Domain: {domain}")
        print(f"Target Profile: {profile}")
        print("Source code not required for Red Team mode")

def main():
    """Main validation function"""
    try:
        selector = ModeSelector()
        selector.load_config()
        mode, project = selector.validate_mode()
        
        print("\n" + "="*60)
        print("EXECUTION PLAN")
        print("="*60)
        
        if mode == "appsec":
            print("Phase 1: Source Code Analysis (SCA)")
            print("Phase 2: Secret Scanning")
            print("Phase 3: Static Analysis (SAST)")
            print("Phase 4: Dynamic Analysis (DAST)")
            print("Phase 5: AppSec Report Generation")
        elif mode == "appsec_redteam":
            print("Phase 1: Source Code Analysis (SCA)")
            print("Phase 2: Secret Scanning")
            print("Phase 3: Static Analysis (SAST)")
            print("Phase 4: Dynamic Analysis (DAST)")
            print("Phase 5: Red Team Reconnaissance")
            print("Phase 6: Exploitation & Validation")
            print("Phase 7: Integrated Report Generation")
        elif mode == "redteam":
            print("Phase 1: Target Reconnaissance")
            print("Phase 2: WAF/CDN Detection")
            print("Phase 3: Vulnerability Discovery")
            print("Phase 4: Exploitation & Validation")
            print("Phase 5: Red Team Report Generation")
        
        print("\nAll validations passed! Ready to execute.")
        return True
        
    except Exception as e:
        print(f"\nValidation failed: {str(e)}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)