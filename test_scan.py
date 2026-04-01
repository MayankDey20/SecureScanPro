import asyncio
from app.scanners.vuln_scanner import VulnScanner
from app.scanners.crawler import crawl_target

async def main():
    target = "http://demo.testfire.net"
    print(f"Crawling {target}...")
    crawl_data = await crawl_target(target, max_pages=10, max_depth=1)
    print(f"Discovered {len(crawl_data.get('urls', []))} URLs, {len(crawl_data.get('forms', []))} forms")
    
    print("Running VulnScanner...")
    scanner = VulnScanner()
    results = await scanner.scan(target, crawl_data=crawl_data, depth="medium")
    print(f"Found {len(results.get('vulnerabilities', []))} unique vulnerabilities.")
    for v in results.get('vulnerabilities', []):
        print(f"- {v.get('type')}: {v.get('title')} at {v.get('location')}")

if __name__ == "__main__":
    asyncio.run(main())
