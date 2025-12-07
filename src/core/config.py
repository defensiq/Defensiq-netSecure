"""
Configuration Manager for Defensiq Network Security
Handles loading, saving, and managing application settings
"""

import json
import os
from pathlib import Path
from typing import Any, Dict
import hashlib

class ConfigManager:
    """Manages application configuration with integrity checks"""
    
    DEFAULT_CONFIG = {
        'app': {
            'theme': 'light',  # 'light' or 'dark'
            'auto_start': False,
            'minimize_to_tray': True,
            'show_notifications': True
        },
        'monitoring': {
            'enabled': True,
            'capture_mode': 'passive',  # 'passive' or 'active'
            'update_interval': 1000,  # milliseconds
            'log_all_traffic': False
        },
        'filtering': {
            'enabled': False,  # Must be explicitly enabled by user
            'block_mode': 'drop',  # 'drop' or 'reject'
            'log_blocked': True
        },
        'cia_triad': {
            'confidentiality_checks': True,
            'integrity_checks': True,
            'availability_checks': True,
            'http_warning': True,  # Warn on non-HTTPS traffic
            'dos_threshold': 1000  # packets per second
        },
        'blocklist': {
            'enabled': False,
            'categories': {
                'malware': True,
                'phishing': True,
                'advertising': False,
                'gambling': False,
                'adult': False
            }
        },
        'windows': {
            'firewall_integration': False,
            'defender_monitoring': True,
            'event_viewer_import': False
        },
        'logging': {
            'level': 'INFO',  # DEBUG, INFO, WARNING, ERROR
            'max_log_size_mb': 100,
            'retention_days': 30,
            'export_format': 'csv'  # csv, json, txt
        }
    }
    
    def __init__(self, config_dir: str = 'config'):
        """Initialize configuration manager"""
        self.config_dir = Path(config_dir)
        self.config_file = self.config_dir / 'settings.json'
        self.checksum_file = self.config_dir / '.settings.checksum'
        
        # Ensure config directory exists
        self.config_dir.mkdir(exist_ok=True)
        
        # Load or create config
        self.config = self.load()
    
    def load(self) -> Dict[str, Any]:
        """Load configuration from file with integrity check"""
        if not self.config_file.exists():
            # Create default config
            self.save(self.DEFAULT_CONFIG)
            return self.DEFAULT_CONFIG.copy()
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Verify integrity
            if self.checksum_file.exists():
                with open(self.checksum_file, 'r') as f:
                    stored_checksum = f.read().strip()
                
                current_checksum = self._calculate_checksum(config)
                if stored_checksum != current_checksum:
                    print("[WARNING] Configuration file integrity check failed!")
                    # Log this event but continue - user may have manually edited
            
            # Merge with defaults to ensure all keys exist
            return self._merge_with_defaults(config)
        
        except Exception as e:
            print(f"[ERROR] Failed to load config: {e}")
            return self.DEFAULT_CONFIG.copy()
    
    def save(self, config: Dict[str, Any] = None) -> bool:
        """Save configuration to file with integrity checksum"""
        if config is None:
            config = self.config
        
        try:
            # Write config
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4)
            
            # Calculate and save checksum
            checksum = self._calculate_checksum(config)
            with open(self.checksum_file, 'w') as f:
                f.write(checksum)
            
            self.config = config
            return True
        
        except Exception as e:
            print(f"[ERROR] Failed to save config: {e}")
            return False
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-notation path
        Example: get('monitoring.enabled')
        """
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path: str, value: Any) -> bool:
        """
        Set configuration value by dot-notation path
        Example: set('monitoring.enabled', True)
        """
        keys = key_path.split('.')
        config = self.config
        
        # Navigate to the parent dictionary
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set the value
        config[keys[-1]] = value
        
        # Save to disk
        return self.save()
    
    def reset_to_defaults(self) -> bool:
        """Reset configuration to default values"""
        return self.save(self.DEFAULT_CONFIG.copy())
    
    def _merge_with_defaults(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Merge loaded config with defaults to ensure all keys exist"""
        def merge(default, loaded):
            result = default.copy()
            for key, value in loaded.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = merge(result[key], value)
                else:
                    result[key] = value
            return result
        
        return merge(self.DEFAULT_CONFIG, config)
    
    def _calculate_checksum(self, config: Dict[str, Any]) -> str:
        """Calculate SHA256 checksum of configuration"""
        config_str = json.dumps(config, sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()
    
    def export_config(self, export_path: str) -> bool:
        """Export current configuration to a file"""
        try:
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            print(f"[ERROR] Failed to export config: {e}")
            return False
    
    def import_config(self, import_path: str) -> bool:
        """Import configuration from a file"""
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                imported_config = json.load(f)
            
            # Validate and merge
            merged_config = self._merge_with_defaults(imported_config)
            return self.save(merged_config)
        
        except Exception as e:
            print(f"[ERROR] Failed to import config: {e}")
            return False


# Global configuration instance
_config_instance = None

def get_config() -> ConfigManager:
    """Get global configuration instance"""
    global _config_instance
    if _config_instance is None:
        _config_instance = ConfigManager()
    return _config_instance
