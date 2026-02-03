from abc import ABC, abstractmethod
from typing import List, Dict, Any

class ThreatProvider(ABC):
    """Abstract base class for threat intelligence providers (Global Feeds)"""
    
    @abstractmethod
    async def fetch_latest_threats(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Fetch latest threats"""
        pass

    @abstractmethod
    async def get_provider_name(self) -> str:
        """Get provider name"""
        pass

class ScanProvider(ABC):
    """Abstract base class for scanning providers (Target Specific)"""
    
    @abstractmethod
    async def scan_target(self, target: str) -> Dict[str, Any]:
        """Scan a specific target (IP, Domain, URL)"""
        pass
        
    @abstractmethod
    async def get_provider_name(self) -> str:
        """Get provider name"""
        pass
