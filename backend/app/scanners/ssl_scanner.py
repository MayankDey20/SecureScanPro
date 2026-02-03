import ssl
import socket
import logging
from typing import Dict, Any, List
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class SSLScanner:
    """SSL/TLS Security Scanner"""
    
    async def scan(self, target_url: str) -> Dict[str, Any]:
        """Perform SSL/TLS analysis"""
        results = {
            "valid": False,
            "issuer": None,
            "subject": None,
            "version": None,
            "expiry": None,
            "days_until_expiry": 0,
            "weak_ciphers": False,
            "vulnerabilities": []
        }
        
        try:
            parsed = urlparse(target_url)
            hostname = parsed.hostname or target_url
            port = parsed.port or 443
            
            # Create context
            context = ssl.create_default_context()
            
            # Connect and get cert
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Parse Certificate
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    results["valid"] = True
                    results["issuer"] = issuer.get('organizationName') or issuer.get('commonName')
                    results["subject"] = subject.get('commonName')
                    results["version"] = version
                    results["cipher"] = cipher[0]
                    results["expiry"] = not_after.isoformat()
                    
                    # Calculate expiry
                    days_left = (not_after - datetime.utcnow()).days
                    results["days_until_expiry"] = days_left
                    
                    # Vulnerability Checks
                    
                    # 1. Expiring soon
                    if days_left < 30:
                        results["vulnerabilities"].append({
                            "type": "ssl_expiry",
                            "severity": "Medium",
                            "title": "SSL Certificate Expiring Soon",
                            "description": f"Certificate expires in {days_left} days."
                        })
                    
                    # 2. Old TLS Version
                    if version in ['TLSv1', 'TLSv1.1']:
                        results["vulnerabilities"].append({
                            "type": "weak_protocol",
                            "severity": "High",
                            "title": "Weak SSL/TLS Protocol",
                            "description": f"Target supports outdated protocol: {version}"
                        })

                    # 3. Weak Ciphers (Basic check)
                    if "RC4" in cipher[0] or "MD5" in cipher[0]:
                        results["weak_ciphers"] = True
                        results["vulnerabilities"].append({
                            "type": "weak_cipher",
                            "severity": "Critical",
                            "title": "Weak Encryption Cipher",
                            "description": f"Target uses weak cipher: {cipher[0]}"
                        })

        except ssl.SSLError as e:
            logger.error(f"SSL Error scanning {target_url}: {e}")
            results["error"] = str(e)
            results["vulnerabilities"].append({
                "type": "ssl_error",
                "severity": "High",
                "title": "SSL Configuration Error",
                "description": str(e)
            })
        except Exception as e:
            logger.error(f"Error scanning SSL for {target_url}: {e}")
            results["error"] = str(e)
            
        return results
