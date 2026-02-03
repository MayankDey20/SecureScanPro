import whois
import dns.resolver
import logging
from typing import Dict, Any, List
import socket

logger = logging.getLogger(__name__)

class ReconScanner:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()

    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Perform reconnaissance (Whois + DNS)
        """
        try:
            # Handle URLs vs Domains
            domain = target.replace('https://', '').replace('http://', '').split('/')[0]
            
            results = {
                "whois": self._get_whois(domain),
                "dns": self._get_dns_records(domain),
                "ip_info": self._get_ip_info(domain)
            }
            
            return {
                "status": "completed",
                "scanner": "recon_basic",
                "data": results
            }
            
        except Exception as e:
            logger.error(f"Recon scan failed: {str(e)}")
            return {
                "status": "failed",
                "scanner": "recon_basic",
                "error": str(e)
            }

    def _get_whois(self, domain: str) -> Dict[str, Any]:
        try:
            w = whois.whois(domain)
            # Convert to dict and handle datetimes
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "emails": w.emails,
                "org": w.org
            }
        except Exception as e:
            return {"error": f"Whois lookup failed: {str(e)}"}

    def _get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        
        for r_type in record_types:
            try:
                answers = self.resolver.resolve(domain, r_type)
                records[r_type] = [str(rdata) for rdata in answers]
            except Exception:
                pass
                
        return records

    def _get_ip_info(self, domain: str) -> Dict[str, Any]:
        try:
            ip_address = socket.gethostbyname(domain)
            return {"ip": ip_address}
        except Exception as e:
            return {"error": str(e)}
