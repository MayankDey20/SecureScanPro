import nmap
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Perform a network scan using Nmap
        """
        try:
            logger.info(f"Starting network scan for {target}")
            
            # Run scan: -sV (Version detection), -T4 (Aggressive timing), --top-ports 100
            # We avoid -O (OS detection) as it requires root privileges usually
            scan_args = '-sV -T4 --top-ports 100'
            
            # This is blocking in the library, preventing async benefits if not careful.
            # However, since we run this in Celery or threadpool, it's acceptable.
            self.nm.scan(hosts=target, arguments=scan_args)
            
            results = {
                "hosts": [],
                "summary": {
                    "total_hosts": 0,
                    "up_hosts": 0
                }
            }

            for host in self.nm.all_hosts():
                host_data = {
                    "ip": host,
                    "status": self.nm[host].state(),
                    "hostnames": self.nm[host].hostname(),
                    "protocols": {}
                }
                
                for proto in self.nm[host].all_protocols():
                    ports = []
                    for port in self.nm[host][proto].keys():
                        service = self.nm[host][proto][port]
                        ports.append({
                            "port": port,
                            "state": service['state'],
                            "service": service.get('name', 'unknown'),
                            "version": service.get('version', ''),
                            "product": service.get('product', '')
                        })
                    host_data["protocols"][proto] = ports
                
                results["hosts"].append(host_data)
                results["summary"]["total_hosts"] += 1
                if host_data["status"] == "up":
                    results["summary"]["up_hosts"] += 1

            return {
                "status": "completed",
                "scanner": "network_nmap",
                "timestamp": None, # Will be added by service
                "data": results
            }

        except Exception as e:
            logger.error(f"Nmap scan failed: {str(e)}")
            return {
                "status": "failed",
                "scanner": "network_nmap",
                "error": str(e)
            }
