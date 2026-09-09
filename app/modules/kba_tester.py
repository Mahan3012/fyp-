"""
Knowledge-Based Authentication Logic Weakness Tester
"""
from typing import List, Dict, Any
import re
from app.core.scanner_base import Scanner

class KBATester(Scanner):
    """Test authentication logic weaknesses"""
    
    def __init__(self, target_url: str):
        super().__init__(target_url)
        
    def scan(self) -> List[Dict[str, Any]]:
        """Execute KBA weakness scan"""
        print(f"[*] Starting Authentication Logic Testing...")
        
        # Check password policy
        self.check_password_policy()
        
        # Check rate limiting indicators
        self.check_rate_limiting()
        
        # Check for security questions
        self.check_security_questions()
        
        print(f"[✓] Authentication Logic Testing completed. Found {len(self.findings)} issues.")
        return self.findings
    
    def check_password_policy(self):
        """Check if password policy is enforced"""
        response = self.safe_request(self.target_url)
        if not response:
            return
        
        # Look for password policy indicators
        password_indicators = [
            r'password.*(?:must|should).{0,50}(?:length|complex|uppercase|lowercase|number|special)',
            r'minimum.{0,20}password.{0,20}length',
            r'password.{0,50}(?:at least|minimum).{0,20}\d+'
        ]
        
        has_policy = False
        for pattern in password_indicators:
            if re.search(pattern, response.text, re.IGNORECASE):
                has_policy = True
                break
        
        if not has_policy:
            self.add_finding(
                title="Weak Password Policy",
                description="No clear password policy detected",
                severity="High",
                category="Authentication",
                evidence="No password policy indicators found",
                remediation="Implement strong password requirements"
            )
    
    def check_rate_limiting(self):
        """Check if login rate limiting is implemented"""
        response = self.safe_request(self.target_url)
        if not response:
            return
        
        rate_limit_indicators = [
            'rate limit',
            'too many attempts',
            'account locked',
            'captcha',
            'recaptcha',
            'hcaptcha'
        ]
        
        has_rate_limiting = False
        for indicator in rate_limit_indicators:
            if indicator.lower() in response.text.lower():
                has_rate_limiting = True
                break
        
        if not has_rate_limiting:
            self.add_finding(
                title="No Rate Limiting Detected",
                description="Login page appears to have no rate limiting",
                severity="High",
                category="Authentication",
                evidence="No rate limiting indicators found",
                remediation="Implement account lockout or CAPTCHA"
            )
    
    def check_security_questions(self):
        """Check for weak security questions"""
        response = self.safe_request(self.target_url)
        if not response:
            return
        
        security_questions = [
            r"mother.*maiden.*name",
            r"first.*school",
            r"pet.*name",
            r"birth.*city",
            r"favorite.*(?:color|food|movie)"
        ]
        
        for pattern in security_questions:
            if re.search(pattern, response.text, re.IGNORECASE):
                self.add_finding(
                    title="Weak Security Questions",
                    description="System uses easily guessable security questions",
                    severity="Medium",
                    category="Authentication",
                    evidence=f"Security question pattern: {pattern}",
                    remediation="Use more secure authentication methods"
                )
                break