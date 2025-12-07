"""
CIA Triad Security Monitor
Monitors Confidentiality, Integrity, and Availability aspects
"""

import hashlib
import time
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime, timedelta
from collections import deque

from core.logger import get_logger, EventType
from core.config import get_config


class CIATriadMonitor:
    """Monitors CIA (Confidentiality, Integrity, Availability) security aspects"""
    
    def __init__(self):
        """Initialize CIA Triad monitor"""
        self.logger = get_logger()
        self.config = get_config()
        
        # Confidentiality monitoring
        self.http_connections = deque(maxlen=100)
        self.cleartext_protocols = deque(maxlen=100)
        
        # Integrity monitoring
        self.config_checksums = {}
        self.file_integrity_status = {}
        
        # Availability monitoring
        self.packet_rate_history = deque(maxlen=60)  # Last 60 seconds
        self.bandwidth_history = deque(maxlen=60)
        self.dos_alerts = []
        
        # Initialize
        self._initialize_integrity_checks()
    
    def _initialize_integrity_checks(self):
        """Initialize integrity checksums for critical files"""
        critical_files = [
            'config/settings.json',
            'config/blocklist.json'
        ]
        
        for file_path in critical_files:
            path = Path(file_path)
            if path.exists():
                checksum = self._calculate_file_checksum(path)
                self.config_checksums[str(path)] = checksum
    
    # ===================
    # Confidentiality
    # ===================
    
    def check_confidentiality(self, connection: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check confidentiality aspects of a connection
        Returns: confidentiality status and alerts
        """
        alerts = []
        
        # Check for HTTP (non-HTTPS) traffic
        if 'remote_addr' in connection:
            remote_addr = connection['remote_addr']
            
            # Port 80 = HTTP
            if ':80' in remote_addr or remote_addr.endswith(':80'):
                alerts.append({
                    'type': 'HTTP_DETECTED',
                    'severity': 'WARNING',
                    'message': f"Unencrypted HTTP connection detected to {remote_addr}",
                    'timestamp': datetime.now().isoformat()
                })
                
                self.http_connections.append({
                    'remote_addr': remote_addr,
                    'timestamp': datetime.now()
                })
        
        # Check for other cleartext protocols (FTP=21, Telnet=23)
        cleartext_ports = [21, 23, 25]  # FTP, Telnet, SMTP
        for port in cleartext_ports:
            if connection.get('remote_addr', '').endswith(f':{port}'):
                alerts.append({
                    'type': 'CLEARTEXT_PROTOCOL',
                    'severity': 'HIGH',
                    'message': f"Cleartext protocol detected on port {port}",
                    'timestamp': datetime.now().isoformat()
                })
        
        return {
            'status': 'SECURE' if not alerts else 'AT_RISK',
            'alerts': alerts,
            'https_percentage': self._calculate_https_percentage()
        }
    
    def _calculate_https_percentage(self) -> float:
        """Calculate percentage of HTTPS vs HTTP connections"""
        if not self.http_connections:
            return 100.0
        
        # This is a simplified calculation
        # In production, track both HTTP and HTTPS
        recent_http = len(self.http_connections)
        total_connections = recent_http + 100  # Placeholder
        
        return ((total_connections - recent_http) / total_connections * 100) if total_connections > 0 else 100.0
    
    def get_confidentiality_status(self) -> Dict[str, Any]:
        """Get overall confidentiality status"""
        recent_http = len([c for c in self.http_connections 
                          if (datetime.now() - c['timestamp']).seconds < 300])
        
        return {
            'status': 'SECURE' if recent_http == 0 else 'AT_RISK',
            'https_percentage': self._calculate_https_percentage(),
            'recent_http_count': recent_http,
            'cleartext_protocol_count': len(self.cleartext_protocols),
            'last_updated': datetime.now().isoformat()
        }
    
    # ===================
    # Integrity
    # ===================
    
    def check_integrity(self) -> Dict[str, Any]:
        """
        Check integrity of critical configuration files
        Returns: integrity status and alerts
        """
        alerts = []
        
        for file_path, stored_checksum in self.config_checksums.items():
            path = Path(file_path)
            
            if not path.exists():
                alerts.append({
                    'type': 'FILE_MISSING',
                    'severity': 'CRITICAL',
                    'message': f"Critical file missing: {file_path}",
                    'timestamp': datetime.now().isoformat()
                })
                continue
            
            current_checksum = self._calculate_file_checksum(path)
            
            if current_checksum != stored_checksum:
                alerts.append({
                    'type': 'FILE_MODIFIED',
                    'severity': 'WARNING',
                    'message': f"File integrity check failed: {file_path}",
                    'timestamp': datetime.now().isoformat()
                })
                
                # Log the violation
                self.logger.log_event(
                    EventType.CIA_VIOLATION,
                    f"Integrity violation detected: {file_path}",
                    {'file': file_path, 'expected': stored_checksum, 'actual': current_checksum}
                )
                
                # Update checksum (file may have been legitimately modified by user)
                self.config_checksums[file_path] = current_checksum
        
        return {
            'status': 'INTACT' if not alerts else 'COMPROMISED',
            'alerts': alerts,
            'files_monitored': len(self.config_checksums)
        }
    
    def _calculate_file_checksum(self, file_path: Path) -> str:
        """Calculate SHA256 checksum of file"""
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        
        return sha256.hexdigest()
    
    def update_file_checksum(self, file_path: str):
        """Update stored checksum for a file (after user modification)"""
        path = Path(file_path)
        if path.exists():
            checksum = self._calculate_file_checksum(path)
            self.config_checksums[str(path)] = checksum
            
            self.logger.log_event(
                EventType.CONFIG_CHANGED,
                f"Configuration file checksum updated: {file_path}",
                {'checksum': checksum}
            )
    
    def get_integrity_status(self) -> Dict[str, Any]:
        """Get overall integrity status"""
        result = self.check_integrity()
        return {
            'status': result['status'],
            'files_monitored': result['files_monitored'],
            'violations': len(result['alerts']),
            'last_check': datetime.now().isoformat()
        }
    
    # ===================
    # Availability
    # ===================
    
    def check_availability(self, current_packet_rate: float, current_bandwidth: float) -> Dict[str, Any]:
        """
        Check availability aspects (DoS detection, resource saturation)
        
        Args:
            current_packet_rate: Current packets per second
            current_bandwidth: Current bandwidth usage (Mbps)
        
        Returns: availability status and alerts
        """
        alerts = []
        
        # Add to history
        self.packet_rate_history.append({
            'rate': current_packet_rate,
            'timestamp': datetime.now()
        })
        
        self.bandwidth_history.append({
            'bandwidth': current_bandwidth,
            'timestamp': datetime.now()
        })
        
        # Check for abnormally high packet rate (potential DoS)
        dos_threshold = self.config.get('cia_triad.dos_threshold', 1000)
        
        if current_packet_rate > dos_threshold:
            alert = {
                'type': 'HIGH_PACKET_RATE',
                'severity': 'CRITICAL',
                'message': f"Unusually high packet rate detected: {current_packet_rate:.0f} pps (threshold: {dos_threshold})",
                'timestamp': datetime.now().isoformat(),
                'packet_rate': current_packet_rate
            }
            alerts.append(alert)
            self.dos_alerts.append(alert)
            
            # Log the event
            self.logger.log_event(
                EventType.CIA_VIOLATION,
                "Availability risk: High packet rate (possible DoS)",
                {'packet_rate': current_packet_rate, 'threshold': dos_threshold}
            )
        
        # Check bandwidth saturation (simplified - would need adapter capacity info)
        # Assuming 100 Mbps as threshold for this example
        if current_bandwidth > 80:  # 80 Mbps
            alerts.append({
                'type': 'HIGH_BANDWIDTH',
                'severity': 'WARNING',
                'message': f"High bandwidth usage: {current_bandwidth:.1f} Mbps",
                'timestamp': datetime.now().isoformat()
            })
        
        return {
            'status': 'NORMAL' if not alerts else 'DEGRADED',
            'alerts': alerts,
            'current_packet_rate': current_packet_rate,
            'current_bandwidth': current_bandwidth
        }
    
    def get_availability_status(self) -> Dict[str, Any]:
        """Get overall availability status"""
        recent_dos_alerts = [a for a in self.dos_alerts 
                            if (datetime.now() - datetime.fromisoformat(a['timestamp'])).seconds < 300]
        
        avg_packet_rate = sum(h['rate'] for h in self.packet_rate_history) / len(self.packet_rate_history) if self.packet_rate_history else 0
        avg_bandwidth = sum(h['bandwidth'] for h in self.bandwidth_history) / len(self.bandwidth_history) if self.bandwidth_history else 0
        
        return {
            'status': 'NORMAL' if not recent_dos_alerts else 'AT_RISK',
            'avg_packet_rate': avg_packet_rate,
            'avg_bandwidth': avg_bandwidth,
            'dos_alerts_recent': len(recent_dos_alerts),
            'last_updated': datetime.now().isoformat()
        }
    
    # ===================
    # Combined Status
    # ===================
    
    def get_overall_status(self) -> Dict[str, Any]:
        """Get combined CIA Triad status"""
        return {
            'confidentiality': self.get_confidentiality_status(),
            'integrity': self.get_integrity_status(),
            'availability': self.get_availability_status(),
            'timestamp': datetime.now().isoformat()
        }


# Global instance
_cia_monitor_instance = None

def get_cia_monitor() -> CIATriadMonitor:
    """Get global CIA monitor instance"""
    global _cia_monitor_instance
    if _cia_monitor_instance is None:
        _cia_monitor_instance = CIATriadMonitor()
    return _cia_monitor_instance
