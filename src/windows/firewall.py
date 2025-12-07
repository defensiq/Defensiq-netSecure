"""
Windows Firewall Integration
Provides wrapper for Windows Firewall rules via netsh commands
IMPORTANT: Requires administrator privileges
"""

import subprocess
from typing import List, Dict, Any
from enum import Enum

from core.logger import get_logger, EventType


class FirewallDirection(Enum):
    """Firewall rule direction"""
    INBOUND = "in"
    OUTBOUND = "out"


class FirewallAction(Enum):
    """Firewall rule action"""
    ALLOW = "allow"
    BLOCK = "block"


class WindowsFirewall:
    """Windows Firewall management via netsh"""
    
    def __init__(self):
        """Initialize Windows Firewall manager"""
        self.logger = get_logger()
    
    def add_rule(self, name: str, direction: FirewallDirection, 
                 action: FirewallAction, remote_ip: str = None,
                 remote_port: int = None, protocol: str = "any") -> bool:
        """
        Add firewall rule
        
        Args:
            name: Rule name
            direction: Inbound or outbound
            action: Allow or block
            remote_ip: Remote IP address (optional)
            remote_port: Remote port (optional)
            protocol: Protocol (tcp, udp, any)
        
        Returns:
            True if successful
        """
        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}",
                f"dir={direction.value}",
                f"action={action.value}",
                f"protocol={protocol}"
            ]
            
            if remote_ip:
                cmd.append(f"remoteip={remote_ip}")
            
            if remote_port:
                cmd.append(f"remoteport={remote_port}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            self.logger.log_event(
                EventType.RULE_ADDED,
                f"Firewall rule added: {name}",
                {
                    'direction': direction.value,
                    'action': action.value,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port
                }
            )
            
            return True
        
        except subprocess.CalledProcessError as e:
            self.logger.log_event(
                EventType.ERROR_OCCURRED,
                f"Failed to add firewall rule: {e}",
                {'error': str(e), 'stderr': e.stderr}
            )
            return False
        
        except Exception as e:
            self.logger.log_event(
                EventType.ERROR_OCCURRED,
                f"Unexpected error adding firewall rule: {e}",
                {'exception': str(e)}
            )
            return False
    
    def remove_rule(self, name: str) -> bool:
        """
        Remove firewall rule by name
        
        Args:
            name: Rule name to remove
        
        Returns:
            True if successful
        """
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                capture_output=True,
                text=True,
                check=True
            )
            
            self.logger.log_event(
                EventType.RULE_REMOVED,
                f"Firewall rule removed: {name}",
                {}
            )
            
            return True
        
        except subprocess.CalledProcessError as e:
            self.logger.log_event(
                EventType.ERROR_OCCURRED,
                f"Failed to remove firewall rule: {e}",
                {'error': str(e)}
            )
            return False
    
    def list_rules(self) -> List[str]:
        """
        List all firewall rules (names only)
        
        Returns:
            List of rule names
        """
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse output to extract rule names
            # This is simplified - full parsing would be more complex
            lines = result.stdout.split('\n')
            rules = []
            
            for line in lines:
                if line.startswith("Rule Name:"):
                    rule_name = line.replace("Rule Name:", "").strip()
                    rules.append(rule_name)
            
            return rules
        
        except Exception as e:
            self.logger.log_event(
                EventType.ERROR_OCCURRED,
                f"Failed to list firewall rules: {e}",
                {'exception': str(e)}
            )
            return []
    
    def block_ip(self, ip: str, name: str = None) -> bool:
        """
        Block IP address
        
        Args:
            ip: IP address to block
            name: Custom rule name (optional)
        
        Returns:
            True if successful
        """
        if name is None:
            name = f"Defensiq_Block_{ip.replace('.', '_')}"
        
        return self.add_rule(
            name=name,
            direction=FirewallDirection.OUTBOUND,
            action=FirewallAction.BLOCK,
            remote_ip=ip
        )
    
    def unblock_ip(self, ip: str) -> bool:
        """
        Unblock IP address
        
        Args:
            ip: IP address to unblock
        
        Returns:
            True if successful
        """
        rule_name = f"Defensiq_Block_{ip.replace('.', '_')}"
        return self.remove_rule(rule_name)
    
    def get_firewall_status(self) -> Dict[str, Any]:
        """
        Get Windows Firewall status
        
        Returns:
            Firewall status information
        """
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "currentprofile"],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse status
            status = {
                'enabled': 'ON' in result.stdout,
                'profile': 'unknown',
                'raw_output': result.stdout
            }
            
            return status
        
        except Exception as e:
            return {
                'enabled': False,
                'error': str(e)
            }
    
    def check_admin_privileges(self) -> bool:
        """
        Check if running with admin privileges
        
        Returns:
            True if admin
        """
        try:
            # Try to run a simple netsh command
            subprocess.run(
                ["netsh", "advfirewall", "show", "currentprofile"],
                capture_output=True,
                check=True
            )
            return True
        except:
            return False


# Global instance
_firewall_instance = None

def get_firewall() -> WindowsFirewall:
    """Get global firewall instance"""
    global _firewall_instance
    if _firewall_instance is None:
        _firewall_instance = WindowsFirewall()
    return _firewall_instance
