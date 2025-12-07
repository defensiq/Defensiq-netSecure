"""
Network Diagnostics and Repair Tools
System health checks and automated repairs
"""

import subprocess
import socket
import os
import hashlib
from typing import Dict, List, Any, Tuple
from pathlib import Path

from core.logger import get_logger, EventType
from core.config import get_config


class NetworkDiagnostics:
    """Network diagnostics and repair utilities"""
    
    def __init__(self):
        """Initialize diagnostics"""
        self.logger = get_logger()
        self.config = get_config()
        self.results = {}
    
    def run_full_check(self) -> Dict[str, Any]:
        """
        Run complete diagnostic check
        Returns: Dictionary of test results
        """
        results = {
            'internet_connectivity': self.check_internet(),
            'dns_resolution': self.check_dns(),
            'dns_health': self.check_dns_health(),
            'firewall_status': self.check_firewall(),
            'hosts_file': self.check_hosts_file(),
            'windivert_driver': self.check_windivert(),
            'network_adapters': self.check_adapters()
        }
        
        self.results = results
        return results
    
    def check_internet(self) -> Dict[str, Any]:
        """Test internet connectivity"""
        test_hosts = [
            ('8.8.8.8', 53),      # Google DNS
            ('1.1.1.1', 53),      # Cloudflare DNS
            ('9.9.9.9', 53)       # Quad9 DNS
        ]
        
        for host, port in test_hosts:
            try:
                socket.create_connection((host, port), timeout=3)
                return {
                    'status': 'ok',
                    'message': 'Internet connected',
                    'tested_host': host
                }
            except:
                continue
        
        return {
            'status': 'error',
            'message': 'No internet connectivity',
            'tested_host': None
        }
    
    def check_dns(self) -> Dict[str, Any]:
        """Test DNS resolution"""
        test_domains = ['google.com', 'cloudflare.com']
        
        for domain in test_domains:
            try:
                ip = socket.gethostbyname(domain)
                return {
                    'status': 'ok',
                    'message': f'DNS working ({domain} → {ip})',
                    'domain': domain,
                    'ip': ip
                }
            except:
                continue
        
        return {
            'status': 'error',
            'message': 'DNS resolution failed',
            'domain': None
        }
    
    def check_dns_health(self) -> Dict[str, Any]:
        """Check DNS configuration health"""
        try:
            # Get DNS servers
            result = subprocess.run(
                ['powershell', '-Command', 
                 'Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                dns_servers = [s.strip() for s in result.stdout.split('\n') if s.strip()]
                
                # Check if using secure DNS
                secure_dns = any(ip in ['1.1.1.1', '1.0.0.1', '9.9.9.9', '8.8.8.8'] for ip in dns_servers)
                
                return {
                    'status': 'ok' if secure_dns else 'warning',
                    'message': 'Using recommended DNS' if secure_dns else 'Consider using secure DNS',
                    'dns_servers': dns_servers,
                    'secure': secure_dns
                }
            
            return {
                'status': 'warning',
                'message': 'Could not check DNS servers',
                'dns_servers': []
            }
        
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Error checking DNS: {str(e)}',
                'dns_servers': []
            }
    
    def check_firewall(self) -> Dict[str, Any]:
        """Check Windows Firewall status"""
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'currentprofile'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                enabled = 'ON' in result.stdout
                return {
                    'status': 'ok' if enabled else 'warning',
                    'message': 'Firewall enabled' if enabled else 'Firewall disabled',
                    'enabled': enabled
                }
            
            return {
                'status': 'error',
                'message': 'Could not check firewall',
                'enabled': False
            }
        
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Error: {str(e)}',
                'enabled': False
            }
    
    def check_hosts_file(self) -> Dict[str, Any]:
        """Check HOSTS file integrity"""
        hosts_path = Path('C:/Windows/System32/drivers/etc/hosts')
        
        try:
            if not hosts_path.exists():
                return {
                    'status': 'error',
                    'message': 'HOSTS file not found',
                    'path': str(hosts_path)
                }
            
            # Read and parse hosts file
            content = hosts_path.read_text()
            lines = content.split('\n')
            
            # Check for suspicious entries
            suspicious_entries = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) >= 2:
                        # Check if redirecting common sites
                        if any(domain in line.lower() for domain in ['google', 'facebook', 'microsoft', 'bank']):
                            suspicious_entries.append(line)
            
            if suspicious_entries:
                return {
                    'status': 'warning',
                    'message': f'Found {len(suspicious_entries)} suspicious entries',
                    'suspicious_count': len(suspicious_entries),
                    'path': str(hosts_path)
                }
            
            return {
                'status': 'ok',
                'message': 'HOSTS file looks clean',
                'path': str(hosts_path)
            }
        
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Error reading HOSTS file: {str(e)}',
                'path': str(hosts_path)
            }
    
    def check_windivert(self) -> Dict[str, Any]:
        """Check WinDivert driver status"""
        try:
            # Try to import pydivert
            import pydivert
            
            # Try to create a handle (will fail if driver not loaded)
            try:
                with pydivert.WinDivert("false") as wd:
                    pass
                
                return {
                    'status': 'ok',
                    'message': 'WinDivert driver loaded',
                    'available': True
                }
            except:
                return {
                    'status': 'warning',
                    'message': 'WinDivert installed but driver not loaded',
                    'available': False
                }
        
        except ImportError:
            return {
                'status': 'error',
                'message': 'PyDivert not installed',
                'available': False
            }
    
    def check_adapters(self) -> Dict[str, Any]:
        """Check network adapters"""
        try:
            result = subprocess.run(
                ['netsh', 'interface', 'show', 'interface'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                adapters = []
                
                for line in lines[3:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 4:
                            adapters.append({
                                'name': ' '.join(parts[3:]),
                                'state': parts[1]
                            })
                
                connected = sum(1 for a in adapters if a['state'] == 'Connected')
                
                return {
                    'status': 'ok' if connected > 0 else 'warning',
                    'message': f'{connected} adapter(s) connected',
                    'adapters': adapters,
                    'connected_count': connected
                }
            
            return {
                'status': 'error',
                'message': 'Could not check adapters',
                'adapters': []
            }
        
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Error: {str(e)}',
                'adapters': []
            }
    
    def repair_dns(self) -> Tuple[bool, str]:
        """Reset DNS to default settings"""
        try:
            # Flush DNS cache
            subprocess.run(['ipconfig', '/flushdns'], check=True, timeout=5)
            
            # Reset DNS to automatic
            subprocess.run(
                ['powershell', '-Command',
                 'Get-NetAdapter | Set-DnsClientServerAddress -ResetServerAddresses'],
                check=True,
                timeout=10
            )
            
            self.logger.log_event(
                EventType.CONFIG_CHANGED,
                "DNS settings reset to default",
                {}
            )
            
            return (True, "DNS reset successful")
        
        except Exception as e:
            return (False, f"Failed to reset DNS: {str(e)}")
    
    def repair_firewall(self) -> Tuple[bool, str]:
        """Reset firewall to default settings"""
        try:
            subprocess.run(
                ['netsh', 'advfirewall', 'reset'],
                check=True,
                timeout=10
            )
            
            self.logger.log_event(
                EventType.CONFIG_CHANGED,
                "Firewall reset to defaults",
                {}
            )
            
            return (True, "Firewall reset successful")
        
        except Exception as e:
            return (False, f"Failed to reset firewall: {str(e)}")
    
    def repair_hosts_file(self) -> Tuple[bool, str]:
        """Restore default HOSTS file"""
        hosts_path = Path('C:/Windows/System32/drivers/etc/hosts')
        backup_path = hosts_path.with_suffix('.backup')
        
        try:
            # Backup current file
            if hosts_path.exists():
                hosts_path.rename(backup_path)
            
            # Create default HOSTS file
            default_content = """# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
127.0.0.1       localhost
::1             localhost
"""
            
            hosts_path.write_text(default_content)
            
            self.logger.log_event(
                EventType.CONFIG_CHANGED,
                "HOSTS file restored to default",
                {'backup': str(backup_path)}
            )
            
            return (True, f"HOSTS file restored (backup: {backup_path.name})")
        
        except Exception as e:
            return (False, f"Failed to repair HOSTS file: {str(e)}")
    
    def speed_test(self) -> Dict[str, Any]:
        """Simple network speed test"""
        # This is a basic implementation
        # For production, integrate with speedtest-cli or similar
        try:
            import time
            import requests
            
            # Test download speed with a small file
            test_url = 'https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png'
            
            start = time.time()
            response = requests.get(test_url, timeout=10)
            duration = time.time() - start
            
            size_mb = len(response.content) / (1024 * 1024)
            speed_mbps = (size_mb / duration) * 8  # Convert to Mbps
            
            return {
                'status': 'ok',
                'download_speed_mbps': round(speed_mbps, 2),
                'latency_ms': round(duration * 1000, 2)
            }
        
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Speed test failed: {str(e)}'
            }


# Global instance
_diagnostics_instance = None

def get_diagnostics() -> NetworkDiagnostics:
    """Get global diagnostics instance"""
    global _diagnostics_instance
    if _diagnostics_instance is None:
        _diagnostics_instance = NetworkDiagnostics()
    return _diagnostics_instance
