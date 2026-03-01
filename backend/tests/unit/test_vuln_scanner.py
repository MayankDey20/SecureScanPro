import pytest
from unittest.mock import AsyncMock, patch
from app.scanners.vuln_scanner import VulnScanner

@pytest.mark.asyncio
async def test_vuln_scanner_sqli_detection():
    scanner = VulnScanner()
    
    # Mock httpx client response
    with patch("httpx.AsyncClient") as mock_client:
        mock_resp = AsyncMock()
        mock_resp.text = "sql syntax error"
        mock_resp.status_code = 200
        
        mock_context = AsyncMock()
        mock_context.__aenter__.return_value.get.return_value = mock_resp
        mock_client.return_value = mock_context

        results = await scanner.scan("http://example.com")
        
        assert results["status"] == "completed"
        # The logic breaks after first finding, so we expect sqli_detected=True
        assert results["data"]["sqli_detected"] is True
        assert len(results["data"]["findings"]) > 0
        assert results["data"]["findings"][0]["type"] == "SQL Injection"

@pytest.mark.asyncio
async def test_vuln_scanner_xss_detection():
    scanner = VulnScanner()
    
    # Mock httpx client response
    with patch("httpx.AsyncClient") as mock_client:
        mock_resp = AsyncMock()
        mock_resp.text = "<script>alert('scan')</script>"
        mock_resp.status_code = 200
         
        mock_context = AsyncMock()
        mock_context.__aenter__.return_value.get.return_value = mock_resp
        mock_client.return_value = mock_context

        results = await scanner.scan("http://example.com")
        
        # Note: SQLi runs first, so if we want to test XSS we need to ensure SQLi doesn't match
        # But in this mock, every response is the same.
        # Let's adjust the mock to return different things based on URL?
        # Or simpler: XSS payload in response, SQL errors NOT in response
        
        # However, the scanner breaks after first SQLi. 
        # If we return XSS payload immediately, SQLi check might see it as text but won't find SQL keywords.
        # "sql syntax" is not in "<script>..."
        
        assert results["status"] == "completed"
        assert results["data"]["xss_detected"] is True
