"""
Application Network Control Module
Per-application network blocking and bandwidth management
"""

import psutil
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime

from core.logger import get_logger, EventType
from core.config import get_config


@dataclass
class AppRule:
    """Application network rule"""
    process_name: str
    action: str  # 'allow', 'block'
    bandwidth_limit_kbps: Optional[int] = None
    enabled: bool = True
    created_at: str = ""


class ApplicationControl:
    """Manage per-application network controls"""
    
    def __init__(self):
        """Initialize application control"""
        self.logger = get_logger()
        self.config = get_config()
        self.rules: Dict[str, AppRule] = {}
        self.process_stats: Dict[str, Dict] = {}
        
        # Load saved rules
        self.load_rules()
    
    def load_rules(self):
        """Load saved application rules from config"""
        rules_data = self.config.get('app_control.rules', [])
        
        for rule_dict in rules_data:
            rule = AppRule(
                process_name=rule_dict.get('process_name', ''),
                action=rule_dict.get('action', 'allow'),
                bandwidth_limit_kbps=rule_dict.get('bandwidth_limit_kbps'),
                enabled=rule_dict.get('enabled', True),
                created_at=rule_dict.get('created_at', '')
            )
            self.rules[rule.process_name] = rule
    
    def save_rules(self):
        """Save application rules to config"""
        rules_data = []
        
        for rule in self.rules.values():
            rules_data.append({
                'process_name': rule.process_name,
                'action': rule.action,
                'bandwidth_limit_kbps': rule.bandwidth_limit_kbps,
                'enabled': rule.enabled,
                'created_at': rule.created_at
            })
        
        self.config.set('app_control.rules', rules_data)
        self.config.save()
    
    def add_rule(self, process_name: str, action: str = 'block', 
                 bandwidth_limit: Optional[int] = None) -> bool:
        """
        Add or update application rule
        
        Args:
            process_name: Process name (e.g., 'chrome.exe')
            action: 'allow' or 'block'
            bandwidth_limit: Optional bandwidth limit in kbps
        
        Returns:
            True if rule added successfully
        """
        try:
            rule = AppRule(
                process_name=process_name.lower(),
                action=action,
                bandwidth_limit_kbps=bandwidth_limit,
                enabled=True,
                created_at=datetime.now().isoformat()
            )
            
            self.rules[process_name.lower()] = rule
            self.save_rules()
            
            self.logger.log_event(
                EventType.RULE_ADDED,
                f"Added app control rule: {process_name} -> {action}",
                {'process': process_name, 'action': action}
            )
            
            return True
        
        except Exception as e:
            self.logger.log_event(
                EventType.ERROR_OCCURRED,
                f"Error adding app rule: {e}",
                {'exception': str(e)}
            )
            return False
    
    def remove_rule(self, process_name: str) -> bool:
        """Remove application rule"""
        process_name = process_name.lower()
        
        if process_name in self.rules:
            del self.rules[process_name]
            self.save_rules()
            
            self.logger.log_event(
                EventType.RULE_REMOVED,
                f"Removed app control rule: {process_name}",
                {'process': process_name}
            )
            
            return True
        
        return False
    
    def toggle_rule(self, process_name: str, enabled: bool) -> bool:
        """Enable or disable a rule"""
        process_name = process_name.lower()
        
        if process_name in self.rules:
            self.rules[process_name].enabled = enabled
            self.save_rules()
            return True
        
        return False
    
    def get_rule(self, process_name: str) -> Optional[AppRule]:
        """Get rule for process"""
        return self.rules.get(process_name.lower())
    
    def should_block_process(self, process_name: str) -> tuple:
        """
        Check if process should be blocked
        
        Returns:
            (should_block, reason)
        """
        process_name = process_name.lower()
        rule = self.rules.get(process_name)
        
        if rule and rule.enabled and rule.action == 'block':
            return (True, f"Blocked by app control rule")
        
        return (False, None)
    
    def get_running_processes(self) -> List[Dict]:
        """Get list of running processes with network connections"""
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    # Get actual connections
                    connections = proc.connections(kind='inet')
                    
                    # Only include if process has network connections
                    if connections:
                        process_name = proc.info['name'].lower()
                        
                        # Get rule if exists
                        rule = self.get_rule(process_name)
                        
                        processes.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'connections_count': len(connections),
                            'rule': rule,
                            'blocked': rule.action == 'block' if rule and rule.enabled else False
                        })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # Skip processes we can't access
                    continue
        
        except Exception as e:
            self.logger.log_event(
                EventType.ERROR_OCCURRED,
                f"Error getting running processes: {e}",
                {}
            )
        
        return processes
    
    def get_all_rules(self) -> List[AppRule]:
        """Get all application rules"""
        return list(self.rules.values())
    
    def get_statistics(self) -> Dict:
        """Get application control statistics"""
        return {
            'total_rules': len(self.rules),
            'active_rules': sum(1 for r in self.rules.values() if r.enabled),
            'blocked_apps': sum(1 for r in self.rules.values() if r.action == 'block' and r.enabled),
            'bandwidth_limited': sum(1 for r in self.rules.values() if r.bandwidth_limit_kbps is not None)
        }


# Global instance
_app_control_instance = None

def get_app_control() -> ApplicationControl:
    """Get global application control instance"""
    global _app_control_instance
    if _app_control_instance is None:
        _app_control_instance = ApplicationControl()
    return _app_control_instance
