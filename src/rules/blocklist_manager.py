"""
Blocklist Manager for Defensiq Network Security
Manages domain/IP blocking rules with categorization
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Set, Any
from enum import Enum

class BlocklistCategory(Enum):
    """Blocklist categories"""
    MALWARE = "malware"
    PHISHING = "phishing"
    ADVERTISING = "advertising"
    GAMBLING = "gambling"
    ADULT = "adult"
    CUSTOM = "custom"

class BlocklistManager:
    """Manages domain and IP blocklists with categorization"""
    
    def __init__(self, blocklist_dir: str = 'config'):
        """Initialize blocklist manager"""
        self.blocklist_dir = Path(blocklist_dir)
        self.blocklist_dir.mkdir(exist_ok=True)
        
        self.blocklist_file = self.blocklist_dir / 'blocklist.json'
        
        # In-memory blocklist for fast lookups
        self.blocked_domains: Dict[str, str] = {}  # domain -> category
        self.blocked_ips: Dict[str, str] = {}  # ip -> category
        self.blocked_patterns: List[tuple] = []  # (regex, category)
        
        # Load existing blocklist
        self.load_blocklist()
    
    def load_blocklist(self) -> bool:
        """Load blocklist from file"""
        if not self.blocklist_file.exists():
            # Create default blocklist with examples
            default_blocklist = {
                'domains': [],
                'ips': [],
                'patterns': []
            }
            self.save_blocklist(default_blocklist)
            return True
        
        try:
            with open(self.blocklist_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Load domains
            self.blocked_domains = {}
            for entry in data.get('domains', []):
                domain = entry.get('value', '').lower()
                category = entry.get('category', BlocklistCategory.CUSTOM.value)
                self.blocked_domains[domain] = category
            
            # Load IPs
            self.blocked_ips = {}
            for entry in data.get('ips', []):
                ip = entry.get('value', '')
                category = entry.get('category', BlocklistCategory.CUSTOM.value)
                self.blocked_ips[ip] = category
            
            # Load patterns (regex)
            self.blocked_patterns = []
            for entry in data.get('patterns', []):
                pattern = entry.get('value', '')
                category = entry.get('category', BlocklistCategory.CUSTOM.value)
                try:
                    compiled_pattern = re.compile(pattern, re.IGNORECASE)
                    self.blocked_patterns.append((compiled_pattern, category))
                except re.error:
                    print(f"[WARNING] Invalid regex pattern: {pattern}")
            
            return True
        
        except Exception as e:
            print(f"[ERROR] Failed to load blocklist: {e}")
            return False
    
    def save_blocklist(self, data: Dict[str, Any] = None) -> bool:
        """Save blocklist to file"""
        if data is None:
            # Convert current in-memory blocklist to saveable format
            data = {
                'domains': [
                    {'value': domain, 'category': category}
                    for domain, category in self.blocked_domains.items()
                ],
                'ips': [
                    {'value': ip, 'category': category}
                    for ip, category in self.blocked_ips.items()
                ],
                'patterns': [
                    {'value': pattern.pattern, 'category': category}
                    for pattern, category in self.blocked_patterns
                ]
            }
        
        try:
            with open(self.blocklist_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            return True
        
        except Exception as e:
            print(f"[ERROR] Failed to save blocklist: {e}")
            return False
    
    def add_domain(self, domain: str, category: str = BlocklistCategory.CUSTOM.value) -> bool:
        """Add domain to blocklist"""
        domain = domain.lower().strip()
        
        # Basic validation
        if not domain or '/' in domain:
            return False
        
        self.blocked_domains[domain] = category
        return self.save_blocklist()
    
    def add_ip(self, ip: str, category: str = BlocklistCategory.CUSTOM.value) -> bool:
        """Add IP address to blocklist"""
        ip = ip.strip()
        
        # Basic IP validation (simple check)
        if not self._is_valid_ip(ip):
            return False
        
        self.blocked_ips[ip] = category
        return self.save_blocklist()
    
    def add_pattern(self, pattern: str, category: str = BlocklistCategory.CUSTOM.value) -> bool:
        """Add regex pattern to blocklist"""
        try:
            compiled_pattern = re.compile(pattern, re.IGNORECASE)
            self.blocked_patterns.append((compiled_pattern, category))
            return self.save_blocklist()
        except re.error:
            return False
    
    def remove_domain(self, domain: str) -> bool:
        """Remove domain from blocklist"""
        domain = domain.lower().strip()
        if domain in self.blocked_domains:
            del self.blocked_domains[domain]
            return self.save_blocklist()
        return False
    
    def remove_ip(self, ip: str) -> bool:
        """Remove IP from blocklist"""
        ip = ip.strip()
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            return self.save_blocklist()
        return False
    
    def is_domain_blocked(self, domain: str) -> tuple:
        """
        Check if domain is blocked
        Returns: (is_blocked, category, reason)
        """
        domain = domain.lower().strip()
        
        # Exact match
        if domain in self.blocked_domains:
            return (True, self.blocked_domains[domain], "Exact match")
        
        # Subdomain match (e.g., block all *.example.com)
        parts = domain.split('.')
        for i in range(len(parts)):
            parent_domain = '.'.join(parts[i:])
            if parent_domain in self.blocked_domains:
                return (True, self.blocked_domains[parent_domain], f"Parent domain match: {parent_domain}")
        
        # Pattern match
        for pattern, category in self.blocked_patterns:
            if pattern.search(domain):
                return (True, category, f"Pattern match: {pattern.pattern}")
        
        return (False, None, None)
    
    def is_ip_blocked(self, ip: str) -> tuple:
        """
        Check if IP is blocked
        Returns: (is_blocked, category, reason)
        """
        ip = ip.strip()
        
        if ip in self.blocked_ips:
            return (True, self.blocked_ips[ip], "Exact match")
        
        return (False, None, None)
    
    def import_from_file(self, file_path: str, category: str = BlocklistCategory.CUSTOM.value) -> int:
        """
        Import blocklist from file (TXT or JSON)
        Returns: Number of entries imported
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            return 0
        
        count = 0
        
        try:
            if file_path.suffix.lower() == '.json':
                # Import JSON
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                for entry in data.get('domains', []):
                    if self.add_domain(entry.get('value', ''), 
                                      entry.get('category', category)):
                        count += 1
                
                for entry in data.get('ips', []):
                    if self.add_ip(entry.get('value', ''), 
                                  entry.get('category', category)):
                        count += 1
            
            else:
                # Import TXT (one entry per line)
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        
                        # Skip comments and empty lines
                        if not line or line.startswith('#'):
                            continue
                        
                        # Try to detect if it's an IP or domain
                        if self._is_valid_ip(line):
                            if self.add_ip(line, category):
                                count += 1
                        else:
                            if self.add_domain(line, category):
                                count += 1
            
            return count
        
        except Exception as e:
            print(f"[ERROR] Failed to import blocklist: {e}")
            return count
    
    def export_to_file(self, file_path: str, format: str = 'json') -> bool:
        """Export blocklist to file"""
        file_path = Path(file_path)
        
        try:
            if format == 'json':
                data = {
                    'domains': [
                        {'value': domain, 'category': category}
                        for domain, category in self.blocked_domains.items()
                    ],
                    'ips': [
                        {'value': ip, 'category': category}
                        for ip, category in self.blocked_ips.items()
                    ]
                }
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
            
            elif format == 'txt':
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("# Defensiq Network Security - Blocklist\n")
                    f.write("# Generated: " + str(Path(__file__).parent) + "\n\n")
                    
                    f.write("# Domains\n")
                    for domain in sorted(self.blocked_domains.keys()):
                        f.write(f"{domain}\n")
                    
                    f.write("\n# IP Addresses\n")
                    for ip in sorted(self.blocked_ips.keys()):
                        f.write(f"{ip}\n")
            
            return True
        
        except Exception as e:
            print(f"[ERROR] Failed to export blocklist: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get blocklist statistics"""
        stats = {
            'total_domains': len(self.blocked_domains),
            'total_ips': len(self.blocked_ips),
            'total_patterns': len(self.blocked_patterns),
            'by_category': {}
        }
        
        # Count by category
        for category in BlocklistCategory:
            stats['by_category'][category.value] = {
                'domains': sum(1 for c in self.blocked_domains.values() if c == category.value),
                'ips': sum(1 for c in self.blocked_ips.values() if c == category.value)
            }
        
        return stats
    
    def clear_category(self, category: str) -> bool:
        """Clear all entries of a specific category"""
        self.blocked_domains = {d: c for d, c in self.blocked_domains.items() if c != category}
        self.blocked_ips = {i: c for i, c in self.blocked_ips.items() if c != category}
        self.blocked_patterns = [(p, c) for p, c in self.blocked_patterns if c != category]
        return self.save_blocklist()
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Simple IP validation"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False


# Global blocklist instance
_blocklist_instance = None

def get_blocklist_manager() -> BlocklistManager:
    """Get global blocklist manager instance"""
    global _blocklist_instance
    if _blocklist_instance is None:
        _blocklist_instance = BlocklistManager()
    return _blocklist_instance
