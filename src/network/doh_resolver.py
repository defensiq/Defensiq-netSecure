"""
DNS-over-HTTPS (DoH) Resolver
Provides secure DNS resolution through multiple providers
"""

import dns.message
import dns.query
import dns.rdatatype
import requests
from typing import List, Optional, Dict
from enum import Enum

from core.logger import get_logger, EventType
from core.config import get_config


class DoHProvider(Enum):
    """Supported DoH providers"""
    CLOUDFLARE = "cloudflare"
    CLOUDFLARE_SECURITY = "cloudflare_security"
    QUAD9 = "quad9"
    QUAD9_ECS = "quad9_ecs"
    GOOGLE = "google"
    ADGUARD = "adguard"
    ADGUARD_FAMILY = "adguard_family"
    NEXTDNS = "nextdns"
    CUSTOM = "custom"


class DoHResolver:
    """DNS-over-HTTPS resolver with multiple provider support"""
    
    PROVIDERS = {
        DoHProvider.CLOUDFLARE: {
            'url': 'https://cloudflare-dns.com/dns-query',
            'name': 'Cloudflare (1.1.1.1)',
            'description': 'Fast and privacy-focused'
        },
        DoHProvider.CLOUDFLARE_SECURITY: {
            'url': 'https://security.cloudflare-dns.com/dns-query',
            'name': 'Cloudflare Security',
            'description': 'Blocks malware and phishing'
        },
        DoHProvider.QUAD9: {
            'url': 'https://dns.quad9.net/dns-query',
            'name': 'Quad9 (9.9.9.9)',
            'description': 'Security and privacy focused'
        },
        DoHProvider.QUAD9_ECS: {
            'url': 'https://dns11.quad9.net/dns-query',
            'name': 'Quad9 with ECS',
            'description': 'With EDNS Client Subnet'
        },
        DoHProvider.GOOGLE: {
            'url': 'https://dns.google/dns-query',
            'name': 'Google DNS (8.8.8.8)',
            'description': 'Fast and reliable'
        },
        DoHProvider.ADGUARD: {
            'url': 'https://dns.adguard.com/dns-query',
            'name': 'AdGuard DNS',
            'description': 'Blocks ads and trackers'
        },
        DoHProvider.ADGUARD_FAMILY: {
            'url': 'https://dns-family.adguard.com/dns-query',
            'name': 'AdGuard Family',
            'description': 'Blocks ads, trackers, and adult content'
        }
    }
    
    def __init__(self):
        """Initialize DoH resolver"""
        self.logger = get_logger()
        self.config = get_config()
        self.enabled = self.config.get('dns.use_doh', False)
        self.provider = self._get_provider()
        self.custom_url = self.config.get('dns.custom_server', '')
        
        # Cache for DNS responses
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes
    
    def _get_provider(self) -> DoHProvider:
        """Get configured DoH provider"""
        provider_name = self.config.get('dns.provider', 'cloudflare')
        
        try:
            return DoHProvider(provider_name)
        except ValueError:
            return DoHProvider.CLOUDFLARE
    
    def get_provider_url(self) -> str:
        """Get the DoH server URL based on configuration"""
        if self.provider == DoHProvider.CUSTOM:
            return self.custom_url
        elif self.provider == DoHProvider.NEXTDNS:
            # NextDNS requires profile ID
            profile_id = self.config.get('nextdns.profile_id', '')
            if profile_id:
                return f"https://dns.nextdns.io/{profile_id}"
            else:
                # Fallback to Cloudflare
                return self.PROVIDERS[DoHProvider.CLOUDFLARE]['url']
        else:
            return self.PROVIDERS.get(self.provider, {}).get('url', '')
    
    def resolve(self, domain: str, record_type: str = 'A') -> Optional[List[str]]:
        """
        Resolve domain using DNS-over-HTTPS
        
        Args:
            domain: Domain name to resolve
            record_type: DNS record type (A, AAAA, CNAME, etc.)
        
        Returns:
            List of resolved addresses or None
        """
        if not self.enabled:
            return None
        
        # Check cache
        cache_key = f"{domain}:{record_type}"
        if cache_key in self.cache:
            cached_response, timestamp = self.cache[cache_key]
            # Simple cache check (in production, use TTL from DNS response)
            return cached_response
        
        try:
            # Create DNS query
            query = dns.message.make_query(domain, record_type)
            query_wire = query.to_wire()
            
            # Get DoH server URL
            doh_url = self.get_provider_url()
            
            if not doh_url:
                self.logger.log_event(
                    EventType.ERROR_OCCURRED,
                    "DoH provider URL not configured",
                    {}
                )
                return None
            
            # Send DoH request
            response = requests.post(
                doh_url,
                data=query_wire,
                headers={
                    'Content-Type': 'application/dns-message',
                    'Accept': 'application/dns-message'
                },
                timeout=5
            )
            
            if response.status_code == 200:
                # Parse DNS response
                dns_response = dns.message.from_wire(response.content)
                
                # Extract answers
                addresses = []
                for answer in dns_response.answer:
                    for item in answer:
                        if record_type == 'A' and item.rdtype == dns.rdatatype.A:
                            addresses.append(str(item))
                        elif record_type == 'AAAA' and item.rdtype == dns.rdatatype.AAAA:
                            addresses.append(str(item))
                        elif record_type == 'CNAME' and item.rdtype == dns.rdatatype.CNAME:
                            addresses.append(str(item))
                
                # Cache result
                self.cache[cache_key] = (addresses, None)
                
                self.logger.log_event(
                    EventType.CONFIG_CHANGED,
                    f"DoH resolved {domain} to {addresses}",
                    {'domain': domain, 'addresses': addresses}
                )
                
                return addresses
            else:
                self.logger.log_event(
                    EventType.ERROR_OCCURRED,
                    f"DoH query failed: HTTP {response.status_code}",
                    {'domain': domain}
                )
                return None
        
        except Exception as e:
            self.logger.log_event(
                EventType.ERROR_OCCURRED,
                f"DoH resolution error: {e}",
                {'domain': domain, 'exception': str(e)}
            )
            return None
    
    def test_provider(self, provider: DoHProvider = None) -> tuple:
        """
        Test DoH provider connectivity
        
        Returns:
            (success, latency_ms, message)
        """
        if provider is None:
            provider = self.provider
        
        # Save current provider
        old_provider = self.provider
        self.provider = provider
        
        try:
            import time
            start = time.time()
            
            # Test with google.com
            result = self.resolve('google.com', 'A')
            
            latency = (time.time() - start) * 1000  # Convert to ms
            
            if result and len(result) > 0:
                return (True, latency, f"Success ({latency:.0f}ms)")
            else:
                return (False, 0, "No response")
        
        except Exception as e:
            return (False, 0, f"Error: {str(e)}")
        
        finally:
            # Restore provider
            self.provider = old_provider
    
    def get_available_providers(self) -> List[Dict[str, str]]:
        """Get list of available DoH providers"""
        providers = []
        
        for provider_enum, info in self.PROVIDERS.items():
            providers.append({
                'id': provider_enum.value,
                'name': info['name'],
                'description': info['description'],
                'url': info['url']
            })
        
        # Add NextDNS if configured
        if self.config.get('nextdns.profile_id'):
            providers.append({
                'id': 'nextdns',
                'name': 'NextDNS (Personal)',
                'description': 'Your NextDNS profile',
                'url': f"https://dns.nextdns.io/{self.config.get('nextdns.profile_id')}"
            })
        
        return providers
    
    def clear_cache(self):
        """Clear DNS cache"""
        self.cache = {}
        self.logger.log_event(
            EventType.CONFIG_CHANGED,
            "DoH DNS cache cleared",
            {}
        )


# Global instance
_doh_instance = None

def get_doh_resolver() -> DoHResolver:
    """Get global DoH resolver instance"""
    global _doh_instance
    if _doh_instance is None:
        _doh_instance = DoHResolver()
    return _doh_instance
