"""
Command Line Report Generator
"""
from typing import List, Dict, Any
from colorama import init, Fore, Style

# Initialize colorama
init()

class CLIReportGenerator:
    """Generate formatted CLI reports"""
    
    @staticmethod
    def print_summary(findings: List[Dict[str, Any]]):
        """Print summary of findings"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}VULNERABILITY ASSESSMENT SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        if not findings:
            print(f"{Fore.GREEN}[+] No vulnerabilities found!{Style.RESET_ALL}")
            return
        
        # Group by severity
        severity_groups = {}
        for finding in findings:
            severity = finding.get('severity', 'Info')
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(finding)
        
        # Print summary counts
        severity_colors = {
            'Critical': Fore.RED,
            'High': Fore.RED,
            'Medium': Fore.YELLOW,
            'Low': Fore.YELLOW,
            'Info': Fore.BLUE
        }
        
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            if severity in severity_groups:
                count = len(severity_groups[severity])
                color = severity_colors.get(severity, Fore.WHITE)
                print(f"{color}{severity}: {count} issues{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Total: {len(findings)} issues{Style.RESET_ALL}")
        print()
    
    @staticmethod
    def print_detailed_findings(findings: List[Dict[str, Any]]):
        """Print detailed findings"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}DETAILED FINDINGS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        severity_colors = {
            'Critical': Fore.RED,
            'High': Fore.RED,
            'Medium': Fore.YELLOW,
            'Low': Fore.YELLOW,
            'Info': Fore.BLUE
        }
        
        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'Info')
            color = severity_colors.get(severity, Fore.WHITE)
            
            print(f"{color}[{severity}] {finding.get('title', 'Unknown')}{Style.RESET_ALL}")
            print(f"  Category: {finding.get('category', 'General')}")
            print(f"  Description: {finding.get('description', 'No description')}")
            
            if finding.get('evidence'):
                print(f"  Evidence: {finding['evidence']}")
            
            if finding.get('remediation'):
                print(f"{Fore.GREEN}  Fix: {finding['remediation']}{Style.RESET_ALL}")
            
            print(f"  CVSS Score: {finding.get('cvss_score', '0.0')}")
            print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")
