"""
NextDNS API Client
Integrates with NextDNS for cloud-based blocklists
"""

import requests
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json

from core.logger import get_logger, EventType
from core.config import get_config


class NextDNSClient:
    """Client for NextDNS API integration"""
    
    API_BASE = "https://api.nextdns.io"
    
    def __init__(self):
        """Initialize NextDNS client"""
        self.logger = get_logger()
        self.config = get_config()
        self.profile_id = self.config.get('nextdns.profile_id', '')
        self.cache = {
            'blocklists': [],
            'last_update': None
        }
    
    def is_configured(self) -> bool:
        """Check if NextDNS is properly configured"""
        return bool(self.profile_id) and len(self.profile_id) == 6
    
    def test_connection(self) -> tuple:
        """
        Test connection to NextDNS
        Returns: (success, message)
        """
        if not self.is_configured():
            return (False, "Profile ID not configured")
        
        try:
            # Test endpoint - get profile status
            url = f"{self.API_BASE}/profiles/{self.profile_id}/status"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                return (True, "Connected successfully")
            elif response.status_code == 404:
                return (False, "Invalid Profile ID")
            else:
                return (False, f"HTTP {response.status_code}")
        
        except requests.exceptions.Timeout:
            return (False, "Connection timeout")
        except requests.exceptions.ConnectionError:
            return (False, "Network error")
        except Exception as e:
            return (False, f"Error: {str(e)}")
    
    def fetch_blocklists(self, force_refresh: bool = False) -> List[Dict[str, str]]:
        """
        Fetch blocklists from NextDNS profile
        Returns: List of blocked domains with metadata
        """
        if not self.is_configured():
            self.logger.log_event(
                EventType.ERROR_OCCURRED,
                "Cannot fetch NextDNS blocklists: Profile not configured",
                {}
            )
            return []
        
        # Check cache
        if not force_refresh and self.cache['last_update']:
            cache_age = datetime.now() - self.cache['last_update']
            if cache_age < timedelta(hours=1):
                return self.cache['blocklists']
        
        try:
            # Fetch denylist from NextDNS
            url = f"{self.API_BASE}/profiles/{self.profile_id}/denylist"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Parse blocklist
                blocklist = []
                for entry in data.get('data', []):
                    blocklist.append({
                        'domain': entry.get('id', ''),
                        'category': self._categorize_entry(entry),
                        'source': 'nextdns',
                        'active': entry.get('active', True)
                    })
                
                # Update cache
                self.cache['blocklists'] = blocklist
                self.cache['last_update'] = datetime.now()
                
                self.logger.log_event(
                    EventType.CONFIG_CHANGED,
                    f"Fetched {len(blocklist)} entries from NextDNS",
                    {'count': len(blocklist)}
                )
                
                return blocklist
            else:
                self.logger.log_event(
                    EventType.ERROR_OCCURRED,
                    f"Failed to fetch NextDNS blocklists: HTTP {response.status_code}",
                    {}
                )
                return []
        
        except Exception as e:
            self.logger.log_event(
                EventType.ERROR_OCCURRED,
                f"Error fetching NextDNS blocklists: {e}",
                {'exception': str(e)}
            )
            return []
    
    def fetch_threat_intelligence(self) -> Dict[str, List[str]]:
        """
        Fetch categorized threat intelligence feeds
        Returns: Dictionary of category -> domains
        """
        if not self.is_configured():
            return {}
        
        try:
            # NextDNS provides pre-categorized lists
            url = f"{self.API_BASE}/profiles/{self.profile_id}/security"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                categories = {
                    'threat_intelligence': [],
                    'malware': [],
                    'phishing': [],
                    'cryptojacking': [],
                    'tracking': [],
                    'ads': []
                }
                
                # Parse security settings
                security_data = data.get('data', {})
                
                # Threat Intelligence Feeds
                if security_data.get('threatIntelligenceFeeds', {}).get('enabled'):
                    categories['threat_intelligence'] = self._fetch_ti_feeds()
                
                # Cryptojacking Protection
                if security_data.get('cryptojacking', {}).get('enabled'):
                    categories['cryptojacking'] = self._fetch_cryptojacking_list()
                
                return categories
            
            return {}
        
        except Exception as e:
            self.logger.log_event(
                EventType.ERROR_OCCURRED,
                f"Error fetching threat intelligence: {e}",
                {}
            )
            return {}
    
    def _categorize_entry(self, entry: Dict[str, Any]) -> str:
        """Categorize a blocklist entry"""
        # NextDNS doesn't provide detailed categories in denylist
        # Default to custom
        return 'custom'
    
    def _fetch_ti_feeds(self) -> List[str]:
        """Fetch threat intelligence feed domains"""
        # Placeholder - would fetch from specific endpoint
        return []
    
    def _fetch_cryptojacking_list(self) -> List[str]:
        """Fetch cryptojacking domain list"""
        # Placeholder - would fetch from specific endpoint
        return []
    
    def add_to_denylist(self, domain: str) -> bool:
        """
        Add domain to NextDNS denylist
        """
        if not self.is_configured():
            return False
        
        try:
            url = f"{self.API_BASE}/profiles/{self.profile_id}/denylist"
            payload = {'id': domain, 'active': True}
            
            response = requests.post(url, json=payload, timeout=5)
            
            if response.status_code in [200, 201]:
                self.logger.log_event(
                    EventType.RULE_ADDED,
                    f"Added {domain} to NextDNS denylist",
                    {'domain': domain}
                )
                return True
            
            return False
        
        except Exception as e:
            self.logger.log_event(
                EventType.ERROR_OCCURRED,
                f"Failed to add domain to NextDNS: {e}",
                {}
            )
            return False
    
    def remove_from_denylist(self, domain: str) -> bool:
        """
        Remove domain from NextDNS denylist
        """
        if not self.is_configured():
            return False
        
        try:
            url = f"{self.API_BASE}/profiles/{self.profile_id}/denylist/{domain}"
            response = requests.delete(url, timeout=5)
            
            if response.status_code == 200:
                self.logger.log_event(
                    EventType.RULE_REMOVED,
                    f"Removed {domain} from NextDNS denylist",
                    {'domain': domain}
                )
                return True
            
            return False
        
        except Exception as e:
            self.logger.log_event(
                EventType.ERROR_OCCURRED,
                f"Failed to remove domain from NextDNS: {e}",
                {}
            )
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get NextDNS statistics"""
        if not self.is_configured():
            return {}
        
        try:
            url = f"{self.API_BASE}/profiles/{self.profile_id}/analytics/status"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                return response.json()
            
            return {}
        
        except Exception as e:
            return {}


# Global instance
_nextdns_instance = None

def get_nextdns_client() -> NextDNSClient:
    """Get global NextDNS client instance"""
    global _nextdns_instance
    if _nextdns_instance is None:
        _nextdns_instance = NextDNSClient()
    return _nextdns_instance
