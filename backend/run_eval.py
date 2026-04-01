import asyncio
from app.scanners.vuln_scanner import VulnScanner
from app.scanners.ssl_scanner import SSLScanner
from app.scanners.header_scanner import HeaderScanner

async def run_evaluation():
    target = "http://testphp.vulnweb.com"
    print(f"Running evaluation against {target}...\n")
    
    print("--- Running VulnScanner (SQLi, XSS, etc.) ---")
    vuln_scanner = VulnScanner()
    vuln_res = await vuln_scanner.scan(target)
    print(f"Vulnerabilities found: {len(vuln_res.get('findings', []))}")
    for f in vuln_res.get('findings', [])[:3]:
        print(f" - {f['title']}: {f['description'][:60]}...")
        
    print("\n--- Running HeaderScanner ---")
    header_scanner = HeaderScanner()
    header_res = await header_scanner.scan(target)
    print(f"Findings: {len(header_res.get('findings', []))}")
    for f in header_res.get('findings', [])[:3]:
        print(f" - {f['title']}: {f['description'][:60]}...")

    print("\n--- Running SSLScanner ---")
    ssl_scanner = SSLScanner()
    ssl_res = await ssl_scanner.scan("https://expired.badssl.com")
    print(f"Findings: {len(ssl_res.get('findings', []))}")
    for f in ssl_res.get('findings', [])[:3]:
        print(f" - {f['title']}: {f['description'][:60]}...")

if __name__ == "__main__":
    asyncio.run(run_evaluation())
