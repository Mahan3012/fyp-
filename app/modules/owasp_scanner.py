"""
OWASP Application Vulnerability Scanner
"""
from app.core.scanner_base import Scanner
from typing import List, Dict, Any
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

class OWASPScanner(Scanner):
    """Scanner for OWASP Top 10 vulnerabilities"""
    
    def __init__(self, target_url: str):
        super().__init__(target_url)
        self.visited_urls = set()
        
    def scan(self) -> List[Dict[str, Any]]:
        """Execute OWASP vulnerability scan"""
        print(f"[*] Starting OWASP Application Security Scan...")
        
        # Check security headers
        self.check_security_headers()
        
        # Get page content
        response = self.safe_request(self.target_url)
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for SQL injection
            self.check_sql_injection(soup)
            
            # Check for XSS
            self.check_xss(soup)
            
            # Check information disclosure
            self.check_information_disclosure(soup)
            
            # Check for forms
            self.check_forms(soup)
        
        print(f"[✓] OWASP Scan completed. Found {len(self.findings)} issues.")
        return self.findings
    
    def check_security_headers(self):
        """Check for missing security headers"""
        response = self.safe_request(self.target_url)
        if not response:
            return
        
        headers = response.headers
        required_headers = {
            'Strict-Transport-Security': 'High',
            'X-Content-Type-Options': 'Medium',
            'X-Frame-Options': 'Medium',
            'Content-Security-Policy': 'High',
            'X-XSS-Protection': 'Low',
            'Referrer-Policy': 'Low'
        }
        
        for header, severity in required_headers.items():
            if header not in headers:
                self.add_finding(
                    title=f"Missing Security Header: {header}",
                    description=f"The {header} security header is not set.",
                    severity=severity,
                    category="Security Headers",
                    evidence=f"Header '{header}' not found in response",
                    remediation=f"Add '{header}' header to web server configuration"
                )
    
    def check_sql_injection(self, soup: BeautifulSoup):
        """Check for SQL injection vulnerabilities"""
        sql_payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "admin' --",
            "1' AND 1=1--"
        ]
        
        forms = soup.find_all('form')
        for form in forms:
            form_action = form.get('action', '')
            form_method = form.get('method', 'GET').upper()
            inputs = form.find_all('input')
            
            for payload in sql_payloads[:3]:
                data = {}
                for input_field in inputs:
                    input_name = input_field.get('name')
                    if input_name:
                        data[input_name] = payload
                
                target_url = urljoin(self.target_url, form_action)
                
                if form_method == 'POST':
                    response = self.safe_request(target_url, method='POST', data=data)
                else:
                    response = self.safe_request(target_url, params=data)
                
                if response and self.is_sql_error(response.text):
                    self.add_finding(
                        title="Potential SQL Injection",
                        description=f"SQL injection detected in form at {form_action}",
                        severity="Critical",
                        category="SQL Injection",
                        evidence=f"Payload '{payload}' triggered SQL error",
                        remediation="Use parameterized queries or prepared statements"
                    )
                    break
    
    def check_xss(self, soup: BeautifulSoup):
        """Check for XSS vulnerabilities"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert('XSS')</script>"
        ]
        
        forms = soup.find_all('form')
        for form in forms:
            form_action = form.get('action', '')
            form_method = form.get('method', 'GET').upper()
            inputs = form.find_all('input')
            
            for payload in xss_payloads[:2]:
                data = {}
                for input_field in inputs:
                    input_name = input_field.get('name')
                    if input_name:
                        data[input_name] = payload
                
                target_url = urljoin(self.target_url, form_action)
                
                if form_method == 'POST':
                    response = self.safe_request(target_url, method='POST', data=data)
                else:
                    response = self.safe_request(target_url, params=data)
                
                if response and payload in response.text:
                    self.add_finding(
                        title="Potential XSS Vulnerability",
                        description="Input reflected without sanitization",
                        severity="High",
                        category="XSS",
                        evidence=f"Payload '{payload}' reflected in response",
                        remediation="Implement input validation and output encoding"
                    )
                    break
    
    def check_information_disclosure(self, soup: BeautifulSoup):
        """Check for information disclosure"""
        # Check for exposed directories
        common_dirs = ['/admin', '/backup', '/config', '/phpmyadmin', '/.git']
        
        for dir_path in common_dirs:
            test_url = urljoin(self.target_url, dir_path)
            response = self.safe_request(test_url)
            
            if response and response.status_code == 200:
                self.add_finding(
                    title=f"Exposed Directory: {dir_path}",
                    description=f"Directory {dir_path} is accessible",
                    severity="Medium",
                    category="Information Disclosure",
                    evidence=f"HTTP 200 from {test_url}",
                    remediation="Restrict access to sensitive directories"
                )
        
        # Check for version disclosure
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator:
            content = meta_generator.get('content', '')
            self.add_finding(
                title="Software Version Disclosure",
                description=f"Website reveals software version: {content}",
                severity="Low",
                category="Information Disclosure",
                evidence=f"Meta generator: {content}",
                remediation="Remove version information"
            )
    
    def check_forms(self, soup: BeautifulSoup):
        """Check for insecure forms"""
        forms = soup.find_all('form')
        
        for form in forms:
            form_action = form.get('action', '')
            
            # Check if form submits to HTTP instead of HTTPS
            if form_action.startswith('http://'):
                self.add_finding(
                    title="Insecure Form Submission",
                    description="Form submits data over HTTP instead of HTTPS",
                    severity="High",
                    category="Insecure Configuration",
                    evidence=f"Form action: {form_action}",
                    remediation="Use HTTPS for all form submissions"
                )
            
            # Check for password fields
            password_fields = form.find_all('input', {'type': 'password'})
            if password_fields and not self.target_url.startswith('https://'):
                self.add_finding(
                    title="Password Form on Insecure Page",
                    description="Login form is not using HTTPS",
                    severity="Critical",
                    category="Insecure Configuration",
                    evidence="Password field found on HTTP page",
                    remediation="Implement HTTPS on all pages with sensitive data"
                )
    
    def is_sql_error(self, response_text: str) -> bool:
        """Check if response contains SQL error messages"""
        sql_errors = [
            "SQL syntax",
            "mysql_fetch",
            "mysql_query",
            "ORA-",
            "PostgreSQL",
            "SQLite",
            "SQL Server",
            "ODBC",
            "You have an error in your SQL",
            "Warning: mysql"
        ]
        
        response_lower = response_text.lower()
        for error in sql_errors:
            if error.lower() in response_lower:
                return True
        return False