import nmap
import logging
from typing import Dict, Any, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── Service-version → CVE correlation table ───────────────────────────────────
# (product_keyword_lower, version_prefix_lower) → list of (cve_id, desc, severity)
SERVICE_CVE_MAP = [
    # Apache httpd
    ("apache", "2.4.49", [("CVE-2021-41773", "Apache 2.4.49 path traversal & RCE", "critical")]),
    ("apache", "2.4.50", [("CVE-2021-42013", "Apache 2.4.50 path traversal & RCE", "critical")]),
    ("apache", "2.2.",   [("CVE-2017-7679",  "Apache 2.2.x mod_mime buffer overflow", "high")]),
    # OpenSSH
    ("openssh", "7.",    [("CVE-2023-38408", "OpenSSH <9.3 PKCS#11 RCE via ssh-agent", "critical")]),
    ("openssh", "8.",    [("CVE-2023-51385", "OpenSSH 8.x OS command injection via hostname", "high")]),
    # nginx
    ("nginx", "1.16.",   [("CVE-2021-23017", "nginx 1.16 DNS resolver buffer overflow", "high")]),
    ("nginx", "1.18.",   [("CVE-2021-23017", "nginx 1.18 DNS resolver buffer overflow", "high")]),
    # ProFTPD
    ("proftpd", "1.3.",  [("CVE-2019-12815", "ProFTPD 1.3.x arbitrary file copy via mod_copy", "critical")]),
    # vsftpd
    ("vsftpd", "2.3.4",  [("CVE-2011-2523",  "vsftpd 2.3.4 backdoor RCE", "critical")]),
    # Samba
    ("samba", "3.",      [("CVE-2017-7494",  "Samba 3.x/4.x EternalRed RCE", "critical")]),
    ("samba", "4.",      [("CVE-2017-7494",  "Samba 4.x EternalRed RCE", "critical")]),
    # Redis
    ("redis", "",        [("CVE-2022-0543",  "Redis Lua sandbox escape RCE", "critical")]),
    # MySQL
    ("mysql", "5.7.",    [("CVE-2016-6662",  "MySQL 5.7 config overwrite RCE", "critical")]),
    # PHP-FPM
    ("php", "7.1.",      [("CVE-2019-11043", "PHP-FPM 7.1 RCE with nginx", "critical")]),
    ("php", "7.2.",      [("CVE-2019-11043", "PHP-FPM 7.2 RCE with nginx", "critical")]),
    ("php", "7.3.",      [("CVE-2019-11043", "PHP-FPM 7.3 RCE with nginx", "critical")]),
    # IIS
    ("iis", "6.",        [("CVE-2017-7269",  "IIS 6.0 WebDAV buffer overflow RCE", "critical")]),
    # Tomcat
    ("apache tomcat", "9.0.", [("CVE-2020-1938", "Tomcat 9.0 AJP file inclusion (Ghostcat)", "critical")]),
    ("apache tomcat", "8.5.", [("CVE-2020-1938", "Tomcat 8.5 AJP file inclusion (Ghostcat)", "critical")]),
    # Exim
    ("exim", "4.",       [("CVE-2019-10149", "Exim 4.x remote command execution", "critical")]),
    # Heartbleed — detect old OpenSSL
    ("openssl", "1.0.1", [("CVE-2014-0160",  "Heartbleed: OpenSSL 1.0.1 memory disclosure", "critical")]),
]


def correlate_cves(product: str, version: str, service: str) -> List[Dict]:
    """Return CVEs matching the given service/version string."""
    combined = f"{product} {version} {service}".lower()
    found = []
    for prod_key, ver_prefix, cves in SERVICE_CVE_MAP:
        if prod_key in combined and (not ver_prefix or ver_prefix in combined):
            for cve_id, desc, sev in cves:
                found.append({
                    "type":        "network_cve",
                    "severity":    sev,
                    "title":       f"{cve_id} — {product or service} {version}".strip(),
                    "description": (
                        f"Port scan detected '{product} {version}' which is vulnerable to "
                        f"{cve_id}. {desc}."
                    ),
                    "cve_id":      cve_id,
                })
    return found


class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Perform a network scan using Nmap, then correlate discovered service
        versions against the known-CVE table.
        """
        try:
            # Extract hostname from URL if needed
            parsed = urlparse(target)
            host = parsed.hostname or target
            logger.info(f"Starting network scan for {host} (from {target})")

            # -sV = version detection, -T4 = aggressive timing, --top-ports 100
            scan_args = '-sV -T4 --top-ports 100'
            self.nm.scan(hosts=host, arguments=scan_args)

            results = {
                "hosts": [],
                "summary": {"total_hosts": 0, "up_hosts": 0}
            }
            cve_vulns: List[Dict] = []

            for scanned_host in self.nm.all_hosts():
                host_data = {
                    "ip":        scanned_host,
                    "status":    self.nm[scanned_host].state(),
                    "hostnames": self.nm[scanned_host].hostname(),
                    "protocols": {}
                }

                for proto in self.nm[scanned_host].all_protocols():
                    ports = []
                    for port in self.nm[scanned_host][proto].keys():
                        svc = self.nm[scanned_host][proto][port]
                        product = svc.get('product', '')
                        version = svc.get('version', '')
                        service_name = svc.get('name', 'unknown')

                        port_entry = {
                            "port":    port,
                            "state":   svc['state'],
                            "service": service_name,
                            "version": version,
                            "product": product,
                        }
                        ports.append(port_entry)

                        # ── CVE correlation ──────────────────────────────
                        if svc['state'] == 'open':
                            matched = correlate_cves(product, version, service_name)
                            for m in matched:
                                m["location"] = f"{scanned_host}:{port}"
                                cve_vulns.append(m)

                    host_data["protocols"][proto] = ports

                results["hosts"].append(host_data)
                results["summary"]["total_hosts"] += 1
                if host_data["status"] == "up":
                    results["summary"]["up_hosts"] += 1

            if cve_vulns:
                logger.info(
                    f"NetworkScanner: {len(cve_vulns)} CVE correlation(s) found for {host}"
                )

            return {
                "status":          "completed",
                "scanner":         "network_nmap",
                "timestamp":       None,
                "vulnerabilities": cve_vulns,
                "data":            results,
            }

        except Exception as e:
            logger.error(f"Nmap scan failed: {str(e)}")
            return {
                "status":  "failed",
                "scanner": "network_nmap",
                "error":   str(e)
            }
