"""
Human Operational Negligence Analyzer
"""
from typing import List, Dict, Any
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from app.core.scanner_base import Scanner

class NegligenceAnalyzer(Scanner):
    """Analyze human operational negligence factors"""
    
    def __init__(self, target_url: str):
        super().__init__(target_url)
        self.domain = urlparse(target_url).netloc
        self.emails = set()
        
    def scan(self) -> List[Dict[str, Any]]:
        """Execute negligence analysis"""
        print(f"[*] Starting Human Negligence Analysis...")
        
        # Extract emails
        self.extract_emails()
        
        # Check email security protocols (simplified)
        self.check_email_security()
        
        # Check for exposed files
        self.check_exposed_files()
        
        print(f"[✓] Negligence Analysis completed. Found {len(self.findings)} issues.")
        return self.findings
    
    def extract_emails(self):
        """Extract email addresses from website"""
        response = self.safe_request(self.target_url)
        if not response:
            return
        
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, response.text)
        self.emails.update(emails)
        
        # Also check linked pages
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)
        
        for link in links[:5]:  # Check first 5 links
            href = link['href']
            if href.startswith('/') or self.domain in href:
                full_url = href if href.startswith('http') else f"https://{self.domain}{href}"
                page_response = self.safe_request(full_url)
                if page_response:
                    page_emails = re.findall(email_pattern, page_response.text)
                    self.emails.update(page_emails)
        
        if self.emails:
            self.add_finding(
                title="Email Addresses Exposed",
                description=f"Found {len(self.emails)} email addresses on website",
                severity="Low",
                category="Information Disclosure",
                evidence=f"Examples: {', '.join(list(self.emails)[:3])}",
                remediation="Use contact forms instead of exposing emails"
            )
    
    def check_email_security(self):
        """Check email security configurations"""
        # Check for SPF indicators
        response = self.safe_request(self.target_url)
        if response:
            # Look for email-related configuration issues
            if 'webmaster' in response.text.lower() or 'admin@' in response.text.lower():
                self.add_finding(
                    title="Admin Email Exposed",
                    description="Administrative email addresses are publicly visible",
                    severity="Medium",
                    category="Email Security",
                    evidence="Admin email found in page content",
                    remediation="Use role-based contact forms instead"
                )
    
    def check_exposed_files(self):
        """Check for exposed sensitive files"""
        sensitive_files = [
            '/.env',
            '/.git/config',
            '/backup.sql',
            '/database.sql',
            '/config.php.bak',
            '/phpinfo.php',
            '/server-status'
        ]
        
        for file_path in sensitive_files:
            test_url = f"https://{self.domain}{file_path}"
            response = self.safe_request(test_url)
            
            if response and response.status_code == 200 and len(response.text) > 0:
                self.add_finding(
                    title=f"Exposed Sensitive File: {file_path}",
                    description=f"Sensitive file {file_path} is publicly accessible",
                    severity="Critical",
                    category="Information Disclosure",
                    evidence=f"HTTP 200 from {test_url}",
                    remediation="Remove sensitive files from web root"
                )
