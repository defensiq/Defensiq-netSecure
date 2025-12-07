"""
Filter Engine for Defensiq Network Security
Uses PyDivert (WinDivert) for packet interception and filtering
CRITICAL: This requires admin privileges and WinDivert driver
"""

import socket
import struct
import time
import threading
from typing import Optional, Callable
from datetime import datetime

# Optional PyDivert import (will fail gracefully if not available)
try:
    import pydivert
    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False
    print("[WARNING] PyDivert not available. Filtering will be disabled.")

from core.logger import get_logger, EventType
from core.config import get_config
from rules.blocklist_manager import get_blocklist_manager


class FilterEngine:
    """Network packet filtering engine using PyDivert"""
    
    def __init__(self):
        """Initialize filter engine"""
        self.logger = get_logger()
        self.config = get_config()
        self.blocklist = get_blocklist_manager()
        
        # State
        self.running = False
        self.filter_thread: Optional[threading.Thread] = None
        self.divert_handle = None
        
        # Statistics
        self.stats = {
            'packets_inspected': 0,
            'packets_allowed': 0,
            'packets_blocked': 0,
            'start_time': None
        }
        
        # Domain cache (IP -> Domain mapping from DNS queries)
        self.dns_cache = {}
    
    def start(self) -> bool:
        """Start the filtering engine"""
        if not PYDIVERT_AVAILABLE:
            self.logger.log_event(
                EventType.ERROR_OCCURRED,
                "PyDivert not available. Cannot start filtering.",
                {'error': 'Module not installed'}
            )
            return False
        
        if not self.config.get('filtering.enabled', False):
            self.logger.log_event(
                EventType.ERROR_OCCURRED,
                "Filtering not enabled in configuration",
                {}
            )
            return False
        
        if self.running:
            return True
        
        try:
            self.running = True
            self.stats['start_time'] = datetime.now()
            
            # Start filtering thread
            self.filter_thread = threading.Thread(target=self._filter_loop, daemon=True)
            self.filter_thread.start()
            
            self.logger.log_event(
                EventType.SERVICE_STARTED,
                "Packet filtering engine started",
                {}
            )
            return True
        
        except Exception as e:
            self.logger.log_event(
                EventType.ERROR_OCCURRED,
                f"Failed to start filtering engine: {e}",
                {'exception': str(e)}
            )
            self.running = False
            return False
    
    def stop(self) -> bool:
        """Stop the filtering engine"""
        if not self.running:
            return True
        
        try:
            self.running = False
            
            # Close WinDivert handle
            if self.divert_handle:
                self.divert_handle.close()
                self.divert_handle = None
            
            # Wait for thread to finish
            if self.filter_thread:
                self.filter_thread.join(timeout=5.0)
            
            self.logger.log_event(
                EventType.SERVICE_STOPPED,
                "Packet filtering engine stopped",
                self.stats
            )
            return True
        
        except Exception as e:
            self.logger.log_event(
                EventType.ERROR_OCCURRED,
                f"Error stopping filtering engine: {e}",
                {'exception': str(e)}
            )
            return False
    
    def _filter_loop(self):
        """Main filtering loop (runs in separate thread)"""
        try:
            # Open WinDivert handle
            # Filter: Outbound TCP/UDP traffic on common ports
            filter_str = "outbound and (tcp or udp)"
            
            with pydivert.WinDivert(filter_str) as divert:
                self.divert_handle = divert
                
                for packet in divert:
                    if not self.running:
                        break
                    
                    self.stats['packets_inspected'] += 1
                    
                    # Check if packet should be blocked
                    should_block, reason = self._should_block_packet(packet)
                    
                    if should_block:
                        self.stats['packets_blocked'] += 1
                        
                        # Log blocked packet
                        self._log_blocked_packet(packet, reason)
                        
                        # Drop packet (don't reinject)
                        continue
                    
                    else:
                        self.stats['packets_allowed'] += 1
                        
                        # Optionally log allowed traffic
                        if self.config.get('monitoring.log_all_traffic', False):
                            self._log_allowed_packet(packet)
                        
                        # Reinject packet
                        divert.send(packet)
        
        except Exception as e:
            self.logger.log_event(
                EventType.ERROR_OCCURRED,
                f"Filter loop error: {e}",
                {'exception': str(e)}
            )
            self.running = False
    
    def _should_block_packet(self, packet) -> tuple:
        """
        Determine if packet should be blocked
        Returns: (should_block, reason)
        """
        # Extract packet info
        dst_ip = packet.dst_addr
        src_ip = packet.src_addr
        dst_port = packet.dst_port if hasattr(packet, 'dst_port') else 0
        src_port = packet.src_port if hasattr(packet, 'src_port') else 0
        protocol = 'TCP' if packet.tcp else 'UDP' if packet.udp else 'OTHER'
        
        # Check IP blocklist
        is_blocked, category, reason = self.blocklist.is_ip_blocked(dst_ip)
        if is_blocked:
            return (True, f"Blocked IP ({category}): {reason}")
        
        # DNS Query/Response inspection (UDP port 53)
        if protocol == 'UDP' and (dst_port == 53 or src_port == 53):
            domain = self._extract_dns_domain(packet)
            if domain:
                # Cache IP -> Domain mapping from DNS responses
                if src_port == 53:  # DNS response
                    self.dns_cache[dst_ip] = domain
                
                # Check domain blocklist
                is_blocked, category, reason = self.blocklist.is_domain_blocked(domain)
                if is_blocked:
                    return (True, f"Blocked DNS ({category}): {domain} - {reason}")
        
        # HTTP/HTTPS traffic inspection (check cached domains)
        if protocol == 'TCP' and (dst_port == 80 or dst_port == 443):
            # Check if we have domain mapping for this IP
            if dst_ip in self.dns_cache:
                domain = self.dns_cache[dst_ip]
                is_blocked, category, reason = self.blocklist.is_domain_blocked(domain)
                if is_blocked:
                    return (True, f"Blocked HTTP/HTTPS to {domain} ({category}): {reason}")
            
            # Try to extract Host header from HTTP traffic (port 80 only)
            if dst_port == 80 and packet.tcp and hasattr(packet, 'payload'):
                try:
                    payload = bytes(packet.payload)
                    if payload.startswith(b'GET ') or payload.startswith(b'POST ') or payload.startswith(b'HEAD '):
                        # Look for Host header
                        payload_str = payload.decode('utf-8', errors='ignore')
                        for line in payload_str.split('\r\n'):
                            if line.lower().startswith('host:'):
                                host = line.split(':', 1)[1].strip()
                                # Remove port if present
                                host = host.split(':')[0]
                                
                                # Cache this mapping
                                self.dns_cache[dst_ip] = host
                                
                                # Check blocklist
                                is_blocked, category, reason = self.blocklist.is_domain_blocked(host)
                                if is_blocked:
                                    return (True, f"Blocked HTTP Host ({category}): {host} - {reason}")
                except:
                    pass
        
        return (False, None)
    
    def _extract_dns_domain(self, packet) -> Optional[str]:
        """
        Extract domain name from DNS packet
        Basic DNS parsing implementation
        """
        try:
            if not hasattr(packet, 'payload') or not packet.payload:
                return None
            
            payload = bytes(packet.payload)
            
            # DNS header is 12 bytes, question starts at byte 12
            if len(payload) < 13:
                return None
            
            # Skip DNS header (12 bytes)
            pos = 12
            
            # Parse domain name (QNAME)
            domain_parts = []
            while pos < len(payload):
                length = payload[pos]
                
                # End of domain name
                if length == 0:
                    break
                
                # Pointer (compression) - not fully supported
                if length >= 192:
                    break
                
                pos += 1
                
                # Extract label
                if pos + length <= len(payload):
                    label = payload[pos:pos + length].decode('utf-8', errors='ignore')
                    domain_parts.append(label)
                    pos += length
                else:
                    break
            
            if domain_parts:
                domain = '.'.join(domain_parts)
                return domain.lower()
            
        except Exception as e:
            # DNS parsing can fail, that's okay
            pass
        
        return None
    
    def _log_blocked_packet(self, packet, reason: str):
        """Log blocked packet"""
        protocol = 'TCP' if packet.tcp else 'UDP' if packet.udp else 'OTHER'
        dst_ip = packet.dst_addr
        dst_port = packet.dst_port if hasattr(packet, 'dst_port') else 0
        src_ip = packet.src_addr
        
        self.logger.log_traffic(
            allowed=False,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            reason=reason
        )
    
    def _log_allowed_packet(self, packet):
        """Log allowed packet (if enabled)"""
        protocol = 'TCP' if packet.tcp else 'UDP' if packet.udp else 'OTHER'
        dst_ip = packet.dst_addr
        dst_port = packet.dst_port if hasattr(packet, 'dst_port') else 0
        src_ip = packet.src_addr
        
        self.logger.log_traffic(
            allowed=True,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            reason=""
        )
    
    def get_stats(self) -> dict:
        """Get filtering statistics"""
        stats = self.stats.copy()
        
        if stats['start_time']:
            uptime = (datetime.now() - stats['start_time']).total_seconds()
            stats['uptime_seconds'] = uptime
            stats['packets_per_second'] = stats['packets_inspected'] / uptime if uptime > 0 else 0
        
        return stats


def run_service(debug: bool = False):
    """Run filtering engine as a service (blocking)"""
    logger = get_logger()
    config = get_config()
    
    # Check if filtering is enabled
    if not config.get('filtering.enabled', False):
        print("[INFO] Filtering is disabled in configuration.")
        print("[INFO] To enable, set 'filtering.enabled' to true in config/settings.json")
        logger.log_event(
            EventType.SERVICE_STARTED,
            "Service started in monitoring-only mode (filtering disabled)",
            {}
        )
        return
    
    # Initialize and start filter engine
    engine = FilterEngine()
    
    if not engine.start():
        print("[ERROR] Failed to start filtering engine")
        return
    
    print("[INFO] Defensiq Network Security Service running...")
    print("[INFO] Press Ctrl+C to stop")
    
    try:
        # Keep service running
        while engine.running:
            time.sleep(1)
            
            # Periodic stats logging
            if debug and int(time.time()) % 10 == 0:
                stats = engine.get_stats()
                print(f"[DEBUG] Stats: {stats}")
    
    except KeyboardInterrupt:
        print("\n[INFO] Stopping service...")
    
    finally:
        engine.stop()
        print("[INFO] Service stopped")


# Global engine instance
_engine_instance = None

def get_filter_engine() -> FilterEngine:
    """Get global filter engine instance"""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = FilterEngine()
    return _engine_instance
