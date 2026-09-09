"""
Abstract base class for all scanner modules
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any
import requests
from app.config import Config

class Scanner(ABC):
    """Abstract base class for all vulnerability scanners"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': Config.USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
        
    @abstractmethod
    def scan(self) -> List[Dict[str, Any]]:
        """Execute the scan and return findings"""
        pass
    
    def add_finding(self, title: str, description: str, severity: str, 
                   category: str, evidence: str = "", remediation: str = ""):
        """Add a vulnerability finding"""
        finding = {
            'title': title,
            'description': description,
            'severity': severity,
            'category': category,
            'evidence': evidence,
            'remediation': remediation,
            'cvss_score': self.get_cvss_score(severity),
            'timestamp': self.get_timestamp()
        }
        self.findings.append(finding)
        
    def get_cvss_score(self, severity: str) -> float:
        """Get CVSS score based on severity"""
        severity_scores = {
            'Critical': 9.0,
            'High': 8.1,
            'Medium': 5.4,
            'Low': 3.1,
            'Info': 0.0
        }
        return severity_scores.get(severity, 0.0)
    
    def get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def get_findings(self) -> List[Dict[str, Any]]:
        """Return all findings"""
        return self.findings
    
    def safe_request(self, url: str, method: str = 'GET', **kwargs) -> requests.Response:
        """Make a safe HTTP request with error handling"""
        try:
            kwargs['timeout'] = Config.REQUEST_TIMEOUT
            kwargs['verify'] = False  # Disable SSL verification for testing
            response = self.session.request(method, url, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            # Don't add finding here to avoid duplicate errors
            return None
