#!/usr/bin/env python3
"""
Unified Configuration Loader
Centralizes config loading for all operation modes
"""

import os
from pathlib import Path


class ConfigLoader:
    """Handles configuration loading and validation for all modes"""

    VALID_MODES = ["appsec", "appsec_redteam", "redteam", "typescript_scanner"]
    VALID_PROFILES = ["entertainment", "e-commerce", "financial", "healthcare", "government"]
    VALID_AUTH = ["code_audit", "penetration_test", "bug_bounty_program", "own_system", "educational_lab"]

    REQUIRED_FIELDS = ["OPERATION_MODE", "PROJECT_NAME", "AUTHORIZATION"]

    MODE_SPECIFIC_FIELDS = {
        "appsec": [],
        "appsec_redteam": ["TARGET_DOMAIN", "TARGET_PROFILE"],
        "redteam": ["TARGET_DOMAIN", "TARGET_PROFILE"],
        "typescript_scanner": ["BACKEND_PATH"]
    }

    def __init__(self, config_path="config.env"):
        self.config_path = config_path
        self.config = {}

    def load(self):
        """Load configuration from file"""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Config file not found: {self.config_path}")

        with open(self.config_path, 'r') as f:
            for line in f:
                if '=' in line and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    self.config[key] = value

        return self.config

    def validate(self):
        """Validate configuration for current mode"""
        # Check required fields
        for field in self.REQUIRED_FIELDS:
            if field not in self.config:
                raise ValueError(f"{field} is required in config.env")

        # Validate OPERATION_MODE
        mode = self.config['OPERATION_MODE']
        if mode not in self.VALID_MODES:
            raise ValueError(f"Invalid OPERATION_MODE: {mode}. Valid: {self.VALID_MODES}")

        # Validate AUTHORIZATION
        auth = self.config['AUTHORIZATION']
        if auth not in self.VALID_AUTH:
            raise ValueError(f"Invalid AUTHORIZATION: {auth}. Valid: {self.VALID_AUTH}")

        # Check mode-specific required fields
        required_fields = self.MODE_SPECIFIC_FIELDS.get(mode, [])
        for field in required_fields:
            if field not in self.config:
                raise ValueError(f"{field} is required for mode '{mode}'")

        # Validate TARGET_PROFILE if present
        if 'TARGET_PROFILE' in self.config:
            profile = self.config['TARGET_PROFILE']
            if profile not in self.VALID_PROFILES:
                raise ValueError(f"Invalid TARGET_PROFILE: {profile}. Valid: {self.VALID_PROFILES}")

        return True

    def get(self, key, default=None):
        """Get configuration value"""
        return self.config.get(key, default)

    def get_mode(self):
        """Get operation mode"""
        return self.config.get('OPERATION_MODE')

    def get_project(self):
        """Get project name"""
        return self.config.get('PROJECT_NAME')

    def get_auth(self):
        """Get authorization type"""
        return self.config.get('AUTHORIZATION')
