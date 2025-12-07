"""
Network Monitor for Defensiq Network Security
Provides real-time network statistics using psutil
This is a passive monitoring component (no packet interception)
"""

import time
import psutil
from typing import Dict, List, Any
from collections import defaultdict
from datetime import datetime
import socket

class NetworkMonitor:
    """Monitors network statistics without packet interception"""
    
    def __init__(self):
        """Initialize network monitor"""
        self.start_time = datetime.now()
        
        # Connection tracking
        self.connections: List[Dict[str, Any]] = []
        self.connection_history: List[Dict[str, Any]] = []
        self.max_history = 10000
        
        # Statistics
        self.stats = {
            'bytes_sent': 0,
            'bytes_recv': 0,
            'packets_sent': 0,
            'packets_recv': 0,
            'connections_total': 0,
            'connections_active': 0
        }
        
        # Initialize baseline
        self._baseline = psutil.net_io_counters()
    
    def update(self) -> Dict[str, Any]:
        """Update network statistics"""
        # Get current counters
        current = psutil.net_io_counters()
        
        # Calculate deltas
        self.stats['bytes_sent'] = current.bytes_sent - self._baseline.bytes_sent
        self.stats['bytes_recv'] = current.bytes_recv - self._baseline.bytes_recv
        self.stats['packets_sent'] = current.packets_sent - self._baseline.packets_sent
        self.stats['packets_recv'] = current.packets_recv - self._baseline.packets_recv
        
        # Update connections
        self._update_connections()
        
        return self.get_stats()
    
    def _update_connections(self):
        """Update active connections list"""
        try:
            connections = psutil.net_connections(kind='inet')
            
            self.connections = []
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    conn_info = {
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        'status': conn.status,
                        'pid': conn.pid,
                        'family': 'IPv4' if conn.family == socket.AF_INET else 'IPv6',
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Try to get process name
                    try:
                        if conn.pid:
                            process = psutil.Process(conn.pid)
                            conn_info['process'] = process.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        conn_info['process'] = 'Unknown'
                    
                    self.connections.append(conn_info)
                    
                    # Add to history
                    if len(self.connection_history) >= self.max_history:
                        self.connection_history.pop(0)
                    self.connection_history.append(conn_info)
            
            self.stats['connections_active'] = len(self.connections)
            self.stats['connections_total'] = len(self.connection_history)
        
        except Exception as e:
            print(f"[ERROR] Failed to update connections: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        uptime_seconds = (datetime.now() - self.start_time).total_seconds()
        
        return {
            'uptime_seconds': uptime_seconds,
            'bytes_sent': self.stats['bytes_sent'],
            'bytes_recv': self.stats['bytes_recv'],
            'packets_sent': self.stats['packets_sent'],
            'packets_recv': self.stats['packets_recv'],
            'connections_active': self.stats['connections_active'],
            'connections_total': self.stats['connections_total'],
            'bandwidth_sent_mbps': (self.stats['bytes_sent'] / uptime_seconds / 1024 / 1024) if uptime_seconds > 0 else 0,
            'bandwidth_recv_mbps': (self.stats['bytes_recv'] / uptime_seconds / 1024 / 1024) if uptime_seconds > 0 else 0
        }
    
    def get_active_connections(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of active connections"""
        return self.connections[:limit]
    
    def get_connection_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get connection history"""
        return self.connection_history[-limit:]
    
    def get_top_processes(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top network-using processes"""
        try:
            processes = []
            for proc in psutil.process_iter(['name', 'pid']):
                try:
                    io_counters = proc.io_counters()
                    processes.append({
                        'name': proc.info['name'],
                        'pid': proc.info['pid'],
                        'bytes_sent': io_counters.write_bytes,
                        'bytes_recv': io_counters.read_bytes
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    continue
            
            # Sort by total bytes
            processes.sort(key=lambda x: x['bytes_sent'] + x['bytes_recv'], reverse=True)
            return processes[:limit]
        
        except Exception as e:
            print(f"[ERROR] Failed to get top processes: {e}")
            return []


# Global monitor instance
_monitor_instance = None

def get_network_monitor() -> NetworkMonitor:
    """Get global network monitor instance"""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = NetworkMonitor()
    return _monitor_instance
