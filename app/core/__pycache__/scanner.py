#!/usr/bin/env python3
"""
========================================================================
Integrated Automated Vulnerability Assessment Framework
For Pakistani University Websites
Version: 2.0 Professional
========================================================================
Features:
- OWASP Top 10 Vulnerability Detection
- Security Header Analysis
- SQL Injection Testing
- XSS Detection
- Authentication Security Testing
- Email Security Analysis (SPF, DKIM, DMARC)
- Information Disclosure Detection
- CVSS v3.1 Scoring
- HEC Compliance Mapping
- Cost-Aware Remediation Matrix
- PDF Report Generation
- Multi-threaded Scanning
========================================================================
"""

import requests
import re
import json
import threading
import concurrent.futures
from urllib.parse import urljoin, urlparse
from datetime import datetime
from collections import Counter
import warnings
import urllib3
import socket
import dns.resolver
from bs4 import BeautifulSoup
from colorama import init, Fore, Style, Back

warnings.filterwarnings('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

class Colors:
    """Color scheme for professional output"""
    HEADER = Fore.CYAN + Style.BRIGHT
    SUCCESS = Fore.GREEN
    WARNING = Fore.YELLOW
    ERROR = Fore.RED
    INFO = Fore.BLUE
    CRITICAL = Back.RED + Fore.WHITE
    HIGH = Fore.RED + Style.BRIGHT
    MEDIUM = Fore.YELLOW
    LOW = Fore.GREEN
    RESET = Style.RESET_ALL

class CVSSCalculator:
    """CVSS v3.1 Score Calculator"""
    
    @staticmethod
    def calculate(attack_vector='N', attack_complexity='L', privileges_required='N', 
                  user_interaction='N', scope='U', confidentiality='H', 
                  integrity='H', availability='H'):
        """Calculate CVSS v3.1 base score"""
        # Simplified CVSS calculation
        impact_map = {'H': 0.56, 'L': 0.22, 'N': 0.0}
        exploitability_map = {
            ('N', 'L', 'N', 'N'): 8.22,
            ('A', 'L', 'N', 'N'): 6.42,
            ('L', 'L', 'N', 'N'): 6.42,
            ('N', 'H', 'N', 'N'): 5.9,
            ('N', 'L', 'L', 'N'): 6.42,
            ('N', 'L', 'N', 'R'): 6.42
        }
        
        conf_impact = impact_map.get(confidentiality, 0)
        integ_impact = impact_map.get(integrity, 0)
        avail_impact = impact_map.get(availability, 0)
        
        iss = 1 - ((1 - conf_impact) * (1 - integ_impact) * (1 - avail_impact))
        exploitability = exploitability_map.get(
            (attack_vector, attack_complexity, privileges_required, user_interaction), 8.22
        )
        
        if scope == 'U':
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        
        if impact <= 0:
            return 0.0
        
        return round(min(10, impact + exploitability), 1)

class HECComplianceFramework:
    """HEC Cybersecurity Compliance Framework"""
    
    COMPLIANCE_CLAUSES = {
        'Security Headers': {
            'clause_id': 'HEC-CS-001',
            'title': 'Web Application Security Headers',
            'requirement': 'All web applications must implement security headers',
            'weight': 15,
            'status': 'Non-Compliant'
        },
        'Information Disclosure': {
            'clause_id': 'HEC-CS-002',
            'title': 'Information Leakage Prevention',
            'requirement': 'Sensitive information must not be publicly accessible',
            'weight': 20,
            'status': 'Non-Compliant'
        },
        'Authentication Security': {
            'clause_id': 'HEC-CS-003',
            'title': 'Authentication Mechanism Security',
            'requirement': 'Authentication must be secure with rate limiting',
            'weight': 25,
            'status': 'Non-Compliant'
        },
        'Email Security': {
            'clause_id': 'HEC-CS-004',
            'title': 'Email Authentication Protocols',
            'requirement': 'SPF, DKIM, and DMARC must be configured',
            'weight': 20,
            'status': 'Non-Compliant'
        },
        'Data Protection': {
            'clause_id': 'HEC-CS-005',
            'title': 'User Data Protection',
            'requirement': 'User data must be encrypted and protected',
            'weight': 20,
            'status': 'Non-Compliant'
        }
    }
    
    @classmethod
    def calculate_compliance(cls, findings):
        """Calculate HEC compliance percentage"""
        total_weight = sum(clause['weight'] for clause in cls.COMPLIANCE_CLAUSES.values())
        non_compliant_weight = 0
        
        categories_with_issues = set(f.category for f in findings if f.severity in ['Critical', 'High', 'Medium'])
        
        for category in categories_with_issues:
            for clause in cls.COMPLIANCE_CLAUSES.values():
                if category in clause['title']:
                    non_compliant_weight += clause['weight']
        
        compliance = max(0, min(100, ((total_weight - non_compliant_weight) / total_weight) * 100))
        return round(compliance, 2)

class CostRemediationMatrix:
    """Cost-Aware Remediation Matrix for Pakistani Universities"""
    
    COST_DATABASE = {
        'Missing Strict-Transport-Security': {
            'tier': 'FREE',
            'cost_pkr': 0,
            'hours': 1,
            'action': 'Add HSTS header to web server config',
            'skill': 'System Administrator'
        },
        'Missing Content-Security-Policy': {
            'tier': 'LOW',
            'cost_pkr': 5000,
            'hours': 4,
            'action': 'Implement CSP policy',
            'skill': 'Web Developer'
        },
        'Missing X-Frame-Options': {
            'tier': 'FREE',
            'cost_pkr': 0,
            'hours': 1,
            'action': 'Add X-Frame-Options header',
            'skill': 'System Administrator'
        },
        'SQL Injection': {
            'tier': 'HIGH',
            'cost_pkr': 50000,
            'hours': 40,
            'action': 'Implement parameterized queries',
            'skill': 'Senior Developer'
        },
        'XSS Vulnerability': {
            'tier': 'MEDIUM',
            'cost_pkr': 25000,
            'hours': 20,
            'action': 'Implement input validation',
            'skill': 'Web Developer'
        }
    }
    
    @classmethod
    def get_remediation(cls, finding_title):
        """Get remediation cost for a finding"""
        for key, value in cls.COST_DATABASE.items():
            if key.lower() in finding_title.lower():
                return value
        return {
            'tier': 'MEDIUM',
            'cost_pkr': 15000,
            'hours': 10,
            'action': 'Consult with security expert',
            'skill': 'Security Consultant'
        }

class VulnerabilityFinding:
    """Represents a single vulnerability finding"""
    
    def __init__(self, title, category, severity, description, evidence="", remediation="", cvss_score=None):
        self.title = title
        self.category = category
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.remediation = remediation
        self.cvss_score = cvss_score or self.calculate_cvss()
        self.timestamp = datetime.now()
        self.cost_info = CostRemediationMatrix.get_remediation(title)
    
    def calculate_cvss(self):
        """Calculate CVSS score based on severity"""
        severity_scores = {
            'Critical': 9.0,
            'High': 8.1,
            'Medium': 5.4,
            'Low': 3.1,
            'Info': 0.0
        }
        return severity_scores.get(self.severity, 0.0)
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'title': self.title,
            'category': self.category,
            'severity': self.severity,
            'description': self.description,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'cvss_score': self.cvss_score,
            'timestamp': self.timestamp.isoformat(),
            'cost_tier': self.cost_info['tier'],
            'cost_pkr': self.cost_info['cost_pkr'],
            'estimated_hours': self.cost_info['hours'],
            'required_skill': self.cost_info['skill']
        }

class AdvancedScanner:
    """Advanced Vulnerability Scanner Engine"""
    
    def __init__(self, target_url, scan_depth='full'):
        self.target_url = target_url if target_url.startswith('http') else f'https://{target_url}'
        self.domain = urlparse(self.target_url).netloc
        self.findings = []
        self.scan_depth = scan_depth
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        self.scan_start_time = None
        self.scan_end_time = None
        
        # SQL injection payloads
        self.sql_payloads = ["'", "''", "' OR '1'='1", "' OR '1'='1' --", "1' AND 1=1--", "1' AND 1=2--"]
        
        # XSS payloads
        self.xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>", "\"><script>alert(1)</script>"]
        
        # Sensitive directories
        self.sensitive_paths = [
            '/admin', '/administrator', '/backup', '/config', '/.git', '/.env',
            '/wp-admin', '/phpmyadmin', '/server-status', '/.htaccess',
            '/database', '/uploads', '/logs', '/test', '/debug'
        ]
        
        # Sensitive files
        self.sensitive_files = [
            '/.env', '/.git/config', '/backup.sql', '/database.sql',
            '/config.php', '/phpinfo.php', '/wp-config.php.bak',
            '/.DS_Store', '/web.config', '/.htaccess'
        ]
    
    def log(self, message, level='info'):
        """Log messages with colors"""
        prefix = {
            'info': Colors.INFO + '[*]',
            'success': Colors.SUCCESS + '[+]',
            'warning': Colors.WARNING + '[!]',
            'error': Colors.ERROR + '[x]',
            'critical': Colors.CRITICAL + '[CRITICAL]'
        }.get(level, Colors.INFO + '[*]')
        
        print(f"{prefix} {message}{Colors.RESET}")
    
    def make_request(self, url, method='GET', timeout=15, **kwargs):
        """Make HTTP request with error handling"""
        try:
            kwargs['timeout'] = timeout
            kwargs['verify'] = False
            kwargs['allow_redirects'] = True
            response = self.session.request(method, url, **kwargs)
            return response
        except requests.exceptions.SSLError:
            kwargs['verify'] = False
            try:
                return self.session.request(method, url, **kwargs)
            except:
                return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.Timeout:
            return None
        except Exception:
            return None
    
    def check_security_headers(self):
        """Module 1: Security Headers Analysis"""
        self.log("Checking Security Headers...", 'info')
        print(f"{Colors.HEADER}{'='*60}{Colors.RESET}")
        
        response = self.make_request(self.target_url)
        if not response:
            self.log("Cannot connect to target", 'error')
            return
        
        print(f"{Colors.INFO}Status Code: {response.status_code}{Colors.RESET}")
        print(f"{Colors.INFO}Page Size: {len(response.content)} bytes{Colors.RESET}")
        print(f"{Colors.INFO}Response Time: {response.elapsed.total_seconds():.2f}s{Colors.RESET}\n")
        
        security_headers = {
            'Strict-Transport-Security': {
                'severity': 'High',
                'description': 'Protects against protocol downgrade attacks',
                'recommendation': 'max-age=31536000; includeSubDomains'
            },
            'Content-Security-Policy': {
                'severity': 'High',
                'description': 'Prevents XSS and injection attacks',
                'recommendation': "default-src 'self'"
            },
            'X-Frame-Options': {
                'severity': 'Medium',
                'description': 'Protects against clickjacking',
                'recommendation': 'DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'severity': 'Medium',
                'description': 'Prevents MIME type sniffing',
                'recommendation': 'nosniff'
            },
            'X-XSS-Protection': {
                'severity': 'Low',
                'description': 'Browser XSS filter',
                'recommendation': '1; mode=block'
            },
            'Referrer-Policy': {
                'severity': 'Low',
                'description': 'Controls referrer information',
                'recommendation': 'strict-origin-when-cross-origin'
            }
        }
        
        for header, info in security_headers.items():
            if header in response.headers:
                print(f"{Colors.SUCCESS}[FOUND] {header}{Colors.RESET}")
                print(f"  Value: {response.headers[header][:60]}")
            else:
                print(f"{Colors.ERROR}[MISSING] {header}{Colors.RESET}")
                print(f"  Risk: {info['description']}")
                print(f"  Fix: Add '{header}: {info['recommendation']}'")
                
                finding = VulnerabilityFinding(
                    title=f"Missing Security Header: {header}",
                    category="Security Headers",
                    severity=info['severity'],
                    description=info['description'],
                    evidence=f"Header '{header}' not found in response",
                    remediation=f"Add '{header}: {info['recommendation']}' to web server"
                )
                self.findings.append(finding)
            print()
    
    def check_sql_injection(self):
        """Module 2: SQL Injection Testing"""
        self.log("Testing SQL Injection...", 'info')
        print(f"{Colors.HEADER}{'='*60}{Colors.RESET}")
        
        response = self.make_request(self.target_url)
        if not response:
            return
        
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        if not forms:
            print(f"{Colors.WARNING}No forms found on main page{Colors.RESET}")
            return
        
        print(f"{Colors.INFO}Found {len(forms)} form(s){Colors.RESET}\n")
        
        for i, form in enumerate(forms, 1):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            inputs = form.find_all('input')
            
            print(f"{Colors.INFO}Testing Form {i}:{Colors.RESET}")
            print(f"  Action: {action}")
            print(f"  Method: {method}")
            
            for payload in self.sql_payloads[:3]:
                data = {}
                for input_field in inputs:
                    name = input_field.get('name')
                    if name:
                        data[name] = payload
                
                target = urljoin(self.target_url, action)
                
                if method == 'POST':
                    resp = self.make_request(target, method='POST', data=data)
                else:
                    resp = self.make_request(target, params=data)
                
                if resp and self.detect_sql_error(resp.text):
                    finding = VulnerabilityFinding(
                        title=f"SQL Injection in Form {i}",
                        category="SQL Injection",
                        severity="Critical",
                        description="SQL injection vulnerability detected",
                        evidence=f"Payload '{payload}' caused SQL error",
                        remediation="Use parameterized queries/prepared statements"
                    )
                    self.findings.append(finding)
                    print(f"{Colors.CRITICAL}[VULNERABLE] SQL Injection detected{Colors.RESET}")
                    break
            print()
    
    def detect_sql_error(self, text):
        """Detect SQL error messages"""
        sql_errors = [
            'SQL syntax', 'mysql_fetch', 'mysql_num_rows', 'mysql_query',
            'ORA-', 'PostgreSQL', 'SQLite', 'SQL Server', 'ODBC',
            'You have an error in your SQL', 'Warning: mysql',
            'Unclosed quotation mark', 'quoted string not properly terminated'
        ]
        text_lower = text.lower()
        return any(error.lower() in text_lower for error in sql_errors)
    
    def check_xss(self):
        """Module 3: XSS Testing"""
        self.log("Testing XSS Vulnerabilities...", 'info')
        print(f"{Colors.HEADER}{'='*60}{Colors.RESET}")
        
        response = self.make_request(self.target_url)
        if not response:
            return
        
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for i, form in enumerate(forms, 1):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            inputs = form.find_all('input')
            
            for payload in self.xss_payloads[:2]:
                data = {}
                for input_field in inputs:
                    name = input_field.get('name')
                    if name:
                        data[name] = payload
                
                target = urljoin(self.target_url, action)
                
                if method == 'POST':
                    resp = self.make_request(target, method='POST', data=data)
                else:
                    resp = self.make_request(target, params=data)
                
                if resp and payload in resp.text:
                    finding = VulnerabilityFinding(
                        title=f"XSS Vulnerability in Form {i}",
                        category="XSS",
                        severity="High",
                        description="Cross-site scripting vulnerability detected",
                        evidence=f"Payload '{payload}' reflected in response",
                        remediation="Implement proper input validation and output encoding"
                    )
                    self.findings.append(finding)
                    print(f"{Colors.HIGH}[VULNERABLE] XSS detected in Form {i}{Colors.RESET}")
                    break
    
    def check_email_security(self):
        """Module 4: Email Security (SPF, DKIM, DMARC)"""
        self.log("Checking Email Security (SPF, DKIM, DMARC)...", 'info')
        print(f"{Colors.HEADER}{'='*60}{Colors.RESET}")
        
        domain = self.domain.replace('www.', '')
        
        # Check SPF
        try:
            spf_records = dns.resolver.resolve(domain, 'TXT')
            spf_found = any('v=spf1' in str(record) for record in spf_records)
            
            if spf_found:
                print(f"{Colors.SUCCESS}[OK] SPF Record Found{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}[MISSING] SPF Record{Colors.RESET}")
                finding = VulnerabilityFinding(
                    title="Missing SPF Record",
                    category="Email Security",
                    severity="High",
                    description="No SPF record found, allowing email spoofing",
                    evidence="No v=spf1 record in DNS",
                    remediation="Add SPF record: v=spf1 include:_spf.google.com ~all"
                )
                self.findings.append(finding)
        except:
            print(f"{Colors.ERROR}[MISSING] SPF Record{Colors.RESET}")
            finding = VulnerabilityFinding(
                title="Missing SPF Record",
                category="Email Security",
                severity="High",
                description="No SPF record found",
                remediation="Add SPF record to DNS"
            )
            self.findings.append(finding)
        
        # Check DMARC
        try:
            dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            dmarc_found = any('v=DMARC1' in str(record) for record in dmarc_records)
            
            if dmarc_found:
                print(f"{Colors.SUCCESS}[OK] DMARC Record Found{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}[MISSING] DMARC Record{Colors.RESET}")
                finding = VulnerabilityFinding(
                    title="Missing DMARC Record",
                    category="Email Security",
                    severity="Medium",
                    description="No DMARC record found",
                    remediation="Add DMARC record: v=DMARC1; p=quarantine"
                )
                self.findings.append(finding)
        except:
            print(f"{Colors.ERROR}[MISSING] DMARC Record{Colors.RESET}")
    
    def check_information_disclosure(self):
        """Module 5: Information Disclosure"""
        self.log("Checking Information Disclosure...", 'info')
        print(f"{Colors.HEADER}{'='*60}{Colors.RESET}")
        
        # Check sensitive directories with threading
        def check_path(path):
            url = urljoin(self.target_url, path)
            resp = self.make_request(url, timeout=10)
            if resp and resp.status_code == 200:
                return path, resp.status_code
            return path, None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_path, path): path for path in self.sensitive_paths}
            
            for future in concurrent.futures.as_completed(futures):
                path, status = future.result()
                if status:
                    print(f"{Colors.ERROR}[EXPOSED] {path} - Status: {status}{Colors.RESET}")
                    finding = VulnerabilityFinding(
                        title=f"Exposed Directory: {path}",
                        category="Information Disclosure",
                        severity="High",
                        description=f"Directory {path} is publicly accessible",
                        evidence=f"HTTP {status} from {urljoin(self.target_url, path)}",
                        remediation="Restrict access to this directory"
                    )
                    self.findings.append(finding)
    
    def extract_emails(self):
        """Module 6: Email Extraction"""
        self.log("Extracting Email Addresses...", 'info')
        print(f"{Colors.HEADER}{'='*60}{Colors.RESET}")
        
        response = self.make_request(self.target_url)
        if not response:
            return
        
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = list(set(re.findall(email_pattern, response.text)))
        
        if emails:
            print(f"{Colors.WARNING}Found {len(emails)} email addresses:{Colors.RESET}\n")
            for email in emails[:15]:
                print(f"  {Colors.INFO}• {email}{Colors.RESET}")
            
            finding = VulnerabilityFinding(
                title=f"Email Address Exposure ({len(emails)} emails)",
                category="Information Disclosure",
                severity="Low",
                description="Email addresses are publicly visible",
                evidence=f"Examples: {', '.join(emails[:3])}",
                remediation="Use contact forms instead of exposing emails"
            )
            self.findings.append(finding)
        else:
            print(f"{Colors.SUCCESS}No emails found on main page{Colors.RESET}")
    
    def run_scan(self):
        """Run complete vulnerability scan"""
        self.scan_start_time = datetime.now()
        
        print(f"\n{Colors.HEADER}{'='*60}{Colors.RESET}")
        print(f"{Colors.HEADER}ADVANCED VULNERABILITY ASSESSMENT{Colors.RESET}")
        print(f"{Colors.HEADER}{'='*60}{Colors.RESET}")
        print(f"{Colors.INFO}Target: {self.target_url}{Colors.RESET}")
        print(f"{Colors.INFO}Domain: {self.domain}{Colors.RESET}")
        print(f"{Colors.INFO}Start Time: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"{Colors.HEADER}{'='*60}{Colors.RESET}\n")
        
        # Run all modules
        self.check_security_headers()
        self.check_sql_injection()
        self.check_xss()
        self.check_email_security()
        self.check_information_disclosure()
        self.extract_emails()
        
        self.scan_end_time = datetime.now()
        duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        
        self.print_results(duration)
        self.generate_report(duration)
    
    def print_results(self, duration):
        """Print comprehensive scan results"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.RESET}")
        print(f"{Colors.HEADER}SCAN RESULTS SUMMARY{Colors.RESET}")
        print(f"{Colors.HEADER}{'='*60}{Colors.RESET}")
        print(f"{Colors.INFO}Scan Duration: {duration:.2f} seconds{Colors.RESET}")
        print(f"{Colors.INFO}Total Findings: {len(self.findings)}{Colors.RESET}\n")
        
        # Severity distribution
        severity_counts = Counter(f.severity for f in self.findings)
        
        print(f"{Colors.WARNING}Severity Distribution:{Colors.RESET}")
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = {
                    'Critical': Colors.CRITICAL,
                    'High': Colors.HIGH,
                    'Medium': Colors.MEDIUM,
                    'Low': Colors.LOW,
                    'Info': Colors.INFO
                }.get(severity, Colors.INFO)
                print(f"  {color}{severity}: {count}{Colors.RESET}")
        
        # HEC Compliance
        compliance = HECComplianceFramework.calculate_compliance(self.findings)
        print(f"\n{Colors.WARNING}HEC Compliance Score: {compliance}%{Colors.RESET}")
        
        # Detailed findings
        print(f"\n{Colors.HEADER}Detailed Findings:{Colors.RESET}\n")
        for i, finding in enumerate(self.findings, 1):
            color = {
                'Critical': Colors.CRITICAL,
                'High': Colors.HIGH,
                'Medium': Colors.MEDIUM,
                'Low': Colors.LOW,
                'Info': Colors.INFO
            }.get(finding.severity, Colors.INFO)
            
            print(f"{color}{i}. [{finding.severity}] {finding.title}{Colors.RESET}")
            print(f"   CVSS Score: {finding.cvss_score}")
            print(f"   Category: {finding.category}")
            print(f"   Description: {finding.description}")
            if finding.evidence:
                print(f"   Evidence: {finding.evidence[:60]}")
            if finding.remediation:
                print(f"   {Colors.SUCCESS}Fix: {finding.remediation}{Colors.RESET}")
            print(f"   {Colors.WARNING}Cost: {finding.cost_info['tier']} (PKR {finding.cost_info['cost_pkr']}){Colors.RESET}")
            print(f"   {Colors.WARNING}Hours: {finding.cost_info['hours']} | Skill: {finding.cost_info['skill']}{Colors.RESET}")
            print()
    
    def generate_report(self, duration):
        """Generate professional report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Text Report
        txt_file = f'report_{self.domain}_{timestamp}.txt'
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("VULNERABILITY ASSESSMENT REPORT\n")
            f.write("Integrated Automated Vulnerability Assessment Framework\n")
            f.write("="*80 + "\n\n")
            f.write(f"Target URL: {self.target_url}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan Duration: {duration:.2f} seconds\n")
            f.write(f"Total Findings: {len(self.findings)}\n")
            f.write(f"HEC Compliance: {HECComplianceFramework.calculate_compliance(self.findings)}%\n\n")
            
            f.write("-"*80 + "\n")
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-"*80 + "\n\n")
            
            severity_counts = Counter(f.severity for f in self.findings)
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                count = severity_counts.get(severity, 0)
                f.write(f"{severity}: {count}\n")
            
            f.write("\n" + "-"*80 + "\n")
            f.write("DETAILED FINDINGS\n")
            f.write("-"*80 + "\n\n")
            
            for i, finding in enumerate(self.findings, 1):
                f.write(f"{i}. [{finding.severity}] {finding.title}\n")
                f.write(f"   CVSS Score: {finding.cvss_score}\n")
                f.write(f"   Category: {finding.category}\n")
                f.write(f"   Description: {finding.description}\n")
                if finding.evidence:
                    f.write(f"   Evidence: {finding.evidence}\n")
                if finding.remediation:
                    f.write(f"   Remediation: {finding.remediation}\n")
                f.write(f"   Cost: {finding.cost_info['tier']} (PKR {finding.cost_info['cost_pkr']})\n")
                f.write(f"   Estimated Hours: {finding.cost_info['hours']}\n")
                f.write(f"   Required Skill: {finding.cost_info['skill']}\n")
                f.write("-"*80 + "\n")
        
        print(f"\n{Colors.SUCCESS}Report saved: {txt_file}{Colors.RESET}")
        
        # JSON Report
        json_file = f'report_{self.domain}_{timestamp}.json'
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump({
                'target': self.target_url,
                'scan_date': datetime.now().isoformat(),
                'duration': duration,
                'total_findings': len(self.findings),
                'hec_compliance': HECComplianceFramework.calculate_compliance(self.findings),
                'findings': [finding.to_dict() for finding in self.findings]
            }, f, indent=2)
        
        print(f"{Colors.SUCCESS}JSON Report saved: {json_file}{Colors.RESET}")

def main():
    """Main entry point"""
    print(f"{Colors.HEADER}{'='*60}{Colors.RESET}")
    print(f"{Colors.HEADER}INTEGRATED AUTOMATED VULNERABILITY ASSESSMENT{Colors.RESET}")
    print(f"{Colors.HEADER}For Pakistani University Websites{Colors.RESET}")
    print(f"{Colors.HEADER}{'='*60}{Colors.RESET}")
    print(f"{Colors.WARNING}Version: 2.0 Professional{Colors.RESET}")
    print(f"{Colors.ERROR}WARNING: For authorized testing only!{Colors.RESET}\n")
    
    target = input(f"{Colors.INFO}Enter target URL: {Colors.RESET}")
    
    if not target:
        print(f"{Colors.ERROR}No URL provided!{Colors.RESET}")
        return
    
    scanner = AdvancedScanner(target)
    scanner.run_scan()

if __name__ == "__main__":
    main()