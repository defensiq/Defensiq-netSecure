"""
Logging Module for Defensiq Network Security
Provides centralized logging with multiple outputs and formats
"""

import logging
import os
from pathlib import Path
from datetime import datetime
import json
import csv
from typing import Dict, List, Any
from enum import Enum

class LogLevel(Enum):
    """Log levels"""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL

class EventType(Enum):
    """Security event types"""
    TRAFFIC_ALLOWED = "TRAFFIC_ALLOWED"
    TRAFFIC_BLOCKED = "TRAFFIC_BLOCKED"
    RULE_ADDED = "RULE_ADDED"
    RULE_REMOVED = "RULE_REMOVED"
    CONFIG_CHANGED = "CONFIG_CHANGED"
    THREAT_DETECTED = "THREAT_DETECTED"
    CIA_VIOLATION = "CIA_VIOLATION"
    SERVICE_STARTED = "SERVICE_STARTED"
    SERVICE_STOPPED = "SERVICE_STOPPED"
    ERROR_OCCURRED = "ERROR_OCCURRED"

class DefensiqLogger:
    """Enhanced logger for network security events"""
    
    def __init__(self, log_dir: str = 'logs'):
        """Initialize logger"""
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Log files
        self.general_log = self.log_dir / 'activity.log'
        self.security_log = self.log_dir / 'security_events.log'
        self.error_log = self.log_dir / 'errors.log'
        
        # Setup Python logging
        self._setup_logging()
        
        # In-memory event buffer for GUI display
        self.recent_events: List[Dict[str, Any]] = []
        self.max_recent_events = 1000
    
    def _setup_logging(self):
        """Setup Python logging configuration"""
        # Create formatters
        detailed_formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # General activity logger
        self.general_logger = logging.getLogger('defensiq.general')
        self.general_logger.setLevel(logging.DEBUG)
        
        general_handler = logging.FileHandler(self.general_log, encoding='utf-8')
        general_handler.setFormatter(detailed_formatter)
        self.general_logger.addHandler(general_handler)
        
        # Security events logger
        self.security_logger = logging.getLogger('defensiq.security')
        self.security_logger.setLevel(logging.INFO)
        
        security_handler = logging.FileHandler(self.security_log, encoding='utf-8')
        security_handler.setFormatter(detailed_formatter)
        self.security_logger.addHandler(security_handler)
        
        # Error logger
        self.error_logger = logging.getLogger('defensiq.error')
        self.error_logger.setLevel(logging.ERROR)
        
        error_handler = logging.FileHandler(self.error_log, encoding='utf-8')
        error_handler.setFormatter(detailed_formatter)
        self.error_logger.addHandler(error_handler)
        
        # Console handler for debugging
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(detailed_formatter)
        console_handler.setLevel(logging.INFO)
        
        self.general_logger.addHandler(console_handler)
    
    def log_event(self, event_type: EventType, message: str, metadata: Dict[str, Any] = None):
        """
        Log a security event
        
        Args:
            event_type: Type of event
            message: Human-readable message
            metadata: Additional structured data
        """
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type.value,
            'message': message,
            'metadata': metadata or {}
        }
        
        # Add to recent events buffer
        self.recent_events.append(event)
        if len(self.recent_events) > self.max_recent_events:
            self.recent_events.pop(0)
        
        # Log to appropriate handler
        if event_type in [EventType.THREAT_DETECTED, EventType.TRAFFIC_BLOCKED, 
                          EventType.CIA_VIOLATION]:
            self.security_logger.warning(f"{event_type.value}: {message} | {metadata}")
        elif event_type == EventType.ERROR_OCCURRED:
            self.error_logger.error(f"{message} | {metadata}")
        else:
            self.general_logger.info(f"{event_type.value}: {message} | {metadata}")
    
    def log_traffic(self, allowed: bool, protocol: str, src_ip: str, dst_ip: str, 
                   dst_port: int, reason: str = ""):
        """Log network traffic event"""
        event_type = EventType.TRAFFIC_ALLOWED if allowed else EventType.TRAFFIC_BLOCKED
        
        metadata = {
            'protocol': protocol,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'reason': reason
        }
        
        message = f"{'ALLOWED' if allowed else 'BLOCKED'} {protocol} {src_ip} -> {dst_ip}:{dst_port}"
        if reason:
            message += f" ({reason})"
        
        self.log_event(event_type, message, metadata)
    
    def get_recent_events(self, count: int = 100, event_type: EventType = None) -> List[Dict[str, Any]]:
        """Get recent events for GUI display"""
        events = self.recent_events[-count:]
        
        if event_type:
            events = [e for e in events if e['type'] == event_type.value]
        
        return events
    
    def export_logs(self, output_path: str, format: str = 'csv', 
                   start_date: datetime = None, end_date: datetime = None) -> bool:
        """
        Export logs to file
        
        Args:
            output_path: Path to save exported logs
            format: Export format ('csv', 'json', 'txt')
            start_date: Filter logs from this date
            end_date: Filter logs until this date
        """
        try:
            # Filter events by date if specified
            events = self.recent_events
            
            if start_date:
                events = [e for e in events 
                         if datetime.fromisoformat(e['timestamp']) >= start_date]
            
            if end_date:
                events = [e for e in events 
                         if datetime.fromisoformat(e['timestamp']) <= end_date]
            
            # Export based on format
            if format == 'json':
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(events, f, indent=2)
            
            elif format == 'csv':
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    if events:
                        # Flatten metadata for CSV
                        fieldnames = ['timestamp', 'type', 'message']
                        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                        writer.writeheader()
                        writer.writerows(events)
            
            elif format == 'txt':
                with open(output_path, 'w', encoding='utf-8') as f:
                    for event in events:
                        f.write(f"[{event['timestamp']}] {event['type']}: {event['message']}\n")
            
            return True
        
        except Exception as e:
            self.error_logger.error(f"Failed to export logs: {e}")
            return False
    
    def generate_summary_report(self, hours: int = 24) -> Dict[str, Any]:
        """Generate summary report of recent activity"""
        cutoff_time = datetime.now().timestamp() - (hours * 3600)
        
        recent = [e for e in self.recent_events 
                 if datetime.fromisoformat(e['timestamp']).timestamp() > cutoff_time]
        
        summary = {
            'period_hours': hours,
            'total_events': len(recent),
            'events_by_type': {},
            'blocked_connections': 0,
            'allowed_connections': 0,
            'threats_detected': 0
        }
        
        for event in recent:
            event_type = event['type']
            summary['events_by_type'][event_type] = summary['events_by_type'].get(event_type, 0) + 1
            
            if event_type == EventType.TRAFFIC_BLOCKED.value:
                summary['blocked_connections'] += 1
            elif event_type == EventType.TRAFFIC_ALLOWED.value:
                summary['allowed_connections'] += 1
            elif event_type == EventType.THREAT_DETECTED.value:
                summary['threats_detected'] += 1
        
        return summary

# Global logger instance
_logger_instance = None

def get_logger() -> DefensiqLogger:
    """Get global logger instance"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = DefensiqLogger()
    return _logger_instance
