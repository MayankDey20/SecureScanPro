"""
Web Crawler/Spider for SecureScan Pro
Discovers pages, forms, and endpoints for comprehensive scanning
"""
import asyncio
import logging
import re
import hashlib
from typing import Dict, Any, List, Set, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from dataclasses import dataclass, field
from collections import deque
import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class CrawlResult:
    """Result of crawling a single URL"""
    url: str
    status_code: int
    content_type: str
    title: str = ""
    forms: List[Dict] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    inputs: List[Dict] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    parameters: List[Dict] = field(default_factory=list)


@dataclass
class CrawlConfig:
    """Configuration for the crawler"""
    max_depth: int = 3
    max_pages: int = 100
    max_time_seconds: int = 300
    follow_external: bool = False
    respect_robots: bool = True
    user_agent: str = "SecureScan-Pro/1.0 (Security Scanner)"
    timeout: float = 10.0
    delay_between_requests: float = 0.1
    allowed_extensions: Set[str] = field(default_factory=lambda: {
        '.html', '.htm', '.php', '.asp', '.aspx', '.jsp', '.py', '.js',
        '.json', '.xml', '.do', '.action', ''
    })
    excluded_extensions: Set[str] = field(default_factory=lambda: {
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.tar', '.gz', '.rar', '.7z',
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv',
        '.css', '.woff', '.woff2', '.ttf', '.eot'
    })
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    auth: Optional[Dict] = None  # {type: "basic|bearer|cookie", credentials: {...}}


class WebCrawler:
    """
    Asynchronous web crawler for discovering attack surface
    """
    
    def __init__(self, config: Optional[CrawlConfig] = None):
        self.config = config or CrawlConfig()
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.results: List[CrawlResult] = []
        self.forms_found: List[Dict] = []
        self.parameters_found: Set[str] = set()
        self.technologies_detected: Set[str] = set()
        self.base_domain: str = ""
        self._stop_crawl = False
        
    async def crawl(self, start_url: str, progress_callback=None) -> Dict[str, Any]:
        """
        Main crawl method - discovers all pages from start URL
        """
        self._reset()
        
        # Parse and normalize start URL
        parsed = urlparse(start_url)
        self.base_domain = parsed.netloc
        start_url = self._normalize_url(start_url)
        
        # Queue: (url, depth)
        queue = deque([(start_url, 0)])
        self.discovered_urls.add(start_url)
        
        start_time = asyncio.get_event_loop().time()
        
        # Prepare HTTP client
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            **self.config.headers
        }
        
        async with httpx.AsyncClient(
            verify=False, 
            timeout=self.config.timeout,
            follow_redirects=True,
            headers=headers,
            cookies=self.config.cookies
        ) as client:
            # Apply authentication if configured
            if self.config.auth:
                client = await self._apply_auth(client, self.config.auth)
            
            while queue and not self._stop_crawl:
                # Check limits
                if len(self.visited_urls) >= self.config.max_pages:
                    logger.info(f"Reached max pages limit: {self.config.max_pages}")
                    break
                
                elapsed = asyncio.get_event_loop().time() - start_time
                if elapsed >= self.config.max_time_seconds:
                    logger.info(f"Reached max time limit: {self.config.max_time_seconds}s")
                    break
                
                url, depth = queue.popleft()
                
                if url in self.visited_urls:
                    continue
                
                if depth > self.config.max_depth:
                    continue
                
                # Crawl the page
                result = await self._crawl_page(client, url)
                
                if result:
                    self.visited_urls.add(url)
                    self.results.append(result)
                    
                    # Report progress
                    if progress_callback:
                        await progress_callback({
                            "phase": "crawling",
                            "urls_crawled": len(self.visited_urls),
                            "urls_discovered": len(self.discovered_urls),
                            "current_url": url,
                            "depth": depth
                        })
                    
                    # Add discovered links to queue
                    for link in result.links:
                        if link not in self.discovered_urls and self._should_crawl(link):
                            self.discovered_urls.add(link)
                            queue.append((link, depth + 1))
                    
                    # Collect forms
                    self.forms_found.extend(result.forms)
                    
                    # Collect technologies
                    self.technologies_detected.update(result.technologies)
                
                # Respect delay
                await asyncio.sleep(self.config.delay_between_requests)
        
        return self._compile_results()
    
    async def _crawl_page(self, client: httpx.AsyncClient, url: str) -> Optional[CrawlResult]:
        """Crawl a single page and extract information"""
        try:
            response = await client.get(url)
            
            content_type = response.headers.get("content-type", "")
            
            # Only parse HTML content
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                return CrawlResult(
                    url=url,
                    status_code=response.status_code,
                    content_type=content_type,
                    headers=dict(response.headers),
                    cookies={k: v for k, v in response.cookies.items()}
                )
            
            soup = BeautifulSoup(response.text, "html.parser")
            
            result = CrawlResult(
                url=url,
                status_code=response.status_code,
                content_type=content_type,
                title=self._extract_title(soup),
                forms=self._extract_forms(soup, url),
                links=self._extract_links(soup, url),
                scripts=self._extract_scripts(soup, url),
                inputs=self._extract_inputs(soup),
                comments=self._extract_comments(response.text),
                headers=dict(response.headers),
                cookies={k: v for k, v in response.cookies.items()},
                technologies=self._detect_technologies(response, soup),
                parameters=self._extract_parameters(url)
            )
            
            return result
            
        except httpx.TimeoutException:
            logger.warning(f"Timeout crawling {url}")
            return None
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
            return None
    
    def _extract_title(self, soup: BeautifulSoup) -> str:
        """Extract page title"""
        title_tag = soup.find("title")
        return title_tag.get_text(strip=True) if title_tag else ""
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract all links from page"""
        links = set()
        
        # <a href="">
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            full_url = self._resolve_url(href, base_url)
            if full_url:
                links.add(full_url)
        
        # <form action="">
        for tag in soup.find_all("form", action=True):
            action = tag["action"]
            full_url = self._resolve_url(action, base_url)
            if full_url:
                links.add(full_url)
        
        # <iframe src="">
        for tag in soup.find_all("iframe", src=True):
            src = tag["src"]
            full_url = self._resolve_url(src, base_url)
            if full_url:
                links.add(full_url)
        
        return list(links)
    
    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """Extract all forms with their inputs"""
        forms = []
        
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            enctype = form.get("enctype", "application/x-www-form-urlencoded")
            
            form_data = {
                "action": self._resolve_url(action, base_url) or base_url,
                "method": method,
                "enctype": enctype,
                "id": form.get("id", ""),
                "name": form.get("name", ""),
                "inputs": []
            }
            
            # Extract all input fields
            for inp in form.find_all(["input", "textarea", "select"]):
                input_data = {
                    "tag": inp.name,
                    "type": inp.get("type", "text"),
                    "name": inp.get("name", ""),
                    "id": inp.get("id", ""),
                    "value": inp.get("value", ""),
                    "required": inp.has_attr("required"),
                    "placeholder": inp.get("placeholder", "")
                }
                
                # For select, get options
                if inp.name == "select":
                    input_data["options"] = [
                        opt.get("value", opt.get_text()) 
                        for opt in inp.find_all("option")
                    ]
                
                form_data["inputs"].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    def _extract_scripts(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract script sources"""
        scripts = []
        
        for script in soup.find_all("script", src=True):
            src = script["src"]
            full_url = self._resolve_url(src, base_url)
            if full_url:
                scripts.append(full_url)
        
        return scripts
    
    def _extract_inputs(self, soup: BeautifulSoup) -> List[Dict]:
        """Extract all input fields (even outside forms)"""
        inputs = []
        
        for inp in soup.find_all(["input", "textarea"]):
            inputs.append({
                "type": inp.get("type", "text"),
                "name": inp.get("name", ""),
                "id": inp.get("id", ""),
                "in_form": inp.find_parent("form") is not None
            })
        
        return inputs
    
    def _extract_comments(self, html: str) -> List[str]:
        """Extract HTML comments (may contain sensitive info)"""
        comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
        # Filter out empty or whitespace-only comments
        return [c.strip() for c in comments if c.strip() and len(c.strip()) > 3]
    
    def _extract_parameters(self, url: str) -> List[Dict]:
        """Extract URL parameters"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        return [
            {"name": k, "value": v[0] if v else "", "type": "query"}
            for k, v in params.items()
        ]
    
    def _detect_technologies(self, response: httpx.Response, soup: BeautifulSoup) -> List[str]:
        """Detect technologies from headers and content"""
        techs = []
        
        headers = response.headers
        html = response.text.lower()
        
        # Server header
        if "server" in headers:
            techs.append(f"Server: {headers['server']}")
        
        # X-Powered-By
        if "x-powered-by" in headers:
            techs.append(f"Powered-By: {headers['x-powered-by']}")
        
        # Common frameworks/CMS detection
        tech_signatures = {
            "WordPress": ["wp-content", "wp-includes", "wordpress"],
            "Drupal": ["drupal", "sites/all", "sites/default"],
            "Joomla": ["joomla", "/components/com_"],
            "React": ["react", "_react", "reactroot"],
            "Vue.js": ["vue", "__vue__", "v-cloak"],
            "Angular": ["ng-app", "ng-controller", "angular"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap"],
            "Laravel": ["laravel", "csrf-token"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "Express": ["express"],
            "ASP.NET": ["__viewstate", "asp.net", ".aspx"],
            "PHP": [".php", "phpsessid"],
            "Cloudflare": ["cloudflare", "__cfduid"],
            "AWS": ["x-amz-", "amazonaws"],
        }
        
        for tech, signatures in tech_signatures.items():
            for sig in signatures:
                if sig in html or any(sig in str(v).lower() for v in headers.values()):
                    techs.append(tech)
                    break
        
        return list(set(techs))
    
    def _resolve_url(self, href: str, base_url: str) -> Optional[str]:
        """Resolve relative URLs to absolute"""
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return None
        
        try:
            full_url = urljoin(base_url, href)
            return self._normalize_url(full_url)
        except Exception:
            return None
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for consistency"""
        parsed = urlparse(url)
        
        # Remove fragment
        normalized = parsed._replace(fragment="")
        
        # Sort query parameters for consistency
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_query = urlencode(sorted(params.items()), doseq=True)
            normalized = normalized._replace(query=sorted_query)
        
        return normalized.geturl()
    
    def _should_crawl(self, url: str) -> bool:
        """Determine if URL should be crawled"""
        try:
            parsed = urlparse(url)
            
            # Check same domain (unless external following is enabled)
            if not self.config.follow_external:
                if parsed.netloc != self.base_domain:
                    return False
            
            # Check file extension
            path = parsed.path.lower()
            ext = ""
            if "." in path:
                ext = "." + path.rsplit(".", 1)[-1]
            
            if ext in self.config.excluded_extensions:
                return False
            
            # Check for common non-HTML patterns
            excluded_patterns = [
                r"/static/", r"/assets/", r"/images/", r"/img/",
                r"/css/", r"/js/", r"/fonts/", r"/media/"
            ]
            
            for pattern in excluded_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    return False
            
            return True
            
        except Exception:
            return False
    
    async def _apply_auth(self, client: httpx.AsyncClient, auth_config: Dict) -> httpx.AsyncClient:
        """Apply authentication to the client"""
        auth_type = auth_config.get("type", "")
        creds = auth_config.get("credentials", {})
        
        if auth_type == "basic":
            # Basic auth is handled per-request
            pass
        elif auth_type == "bearer":
            client.headers["Authorization"] = f"Bearer {creds.get('token', '')}"
        elif auth_type == "cookie":
            for name, value in creds.get("cookies", {}).items():
                client.cookies.set(name, value)
        elif auth_type == "form":
            # Perform form login
            login_url = creds.get("login_url", "")
            form_data = creds.get("form_data", {})
            if login_url and form_data:
                await client.post(login_url, data=form_data)
        
        return client
    
    def _reset(self):
        """Reset crawler state"""
        self.visited_urls.clear()
        self.discovered_urls.clear()
        self.results.clear()
        self.forms_found.clear()
        self.parameters_found.clear()
        self.technologies_detected.clear()
        self._stop_crawl = False
    
    def stop(self):
        """Stop the crawl"""
        self._stop_crawl = True
    
    def _compile_results(self) -> Dict[str, Any]:
        """Compile crawl results into summary"""
        # Collect all unique parameters
        all_params = set()
        for result in self.results:
            for param in result.parameters:
                all_params.add(param["name"])
            for form in result.forms:
                for inp in form["inputs"]:
                    if inp["name"]:
                        all_params.add(inp["name"])
        
        return {
            "status": "completed",
            "summary": {
                "urls_crawled": len(self.visited_urls),
                "urls_discovered": len(self.discovered_urls),
                "forms_found": len(self.forms_found),
                "parameters_found": len(all_params),
                "technologies": list(self.technologies_detected)
            },
            "urls": list(self.visited_urls),
            "forms": self.forms_found,
            "parameters": list(all_params),
            "technologies": list(self.technologies_detected),
            "pages": [
                {
                    "url": r.url,
                    "status": r.status_code,
                    "title": r.title,
                    "forms_count": len(r.forms),
                    "links_count": len(r.links)
                }
                for r in self.results
            ]
        }


# Convenience function for direct use
async def crawl_target(
    url: str, 
    max_pages: int = 100, 
    max_depth: int = 3,
    auth_config: Optional[Dict] = None,
    progress_callback=None
) -> Dict[str, Any]:
    """
    Crawl a target URL and return discovered attack surface
    """
    config = CrawlConfig(
        max_pages=max_pages,
        max_depth=max_depth,
        auth=auth_config
    )
    crawler = WebCrawler(config)
    return await crawler.crawl(url, progress_callback)
