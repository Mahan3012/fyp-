"""
Main entry point for the Vulnerability Assessment Framework
"""
import argparse
import sys
import os
import warnings
warnings.filterwarnings('ignore')

# Add parent directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorama import init, Fore, Style
from app.modules.owasp_scanner import OWASPScanner
from app.modules.kba_tester import KBATester
from app.modules.negligence_analyzer import NegligenceAnalyzer
from app.reporting.pdf_generator import PDFReportGenerator
from app.reporting.cli_report import CLIReportGenerator

# Initialize colorama
init()

def print_banner():
    """Print tool banner"""
    banner = f"""
{Fore.CYAN}=============================================
  Integrated Automated Vulnerability Assessment
  Framework for Pakistani University Websites
============================================={Style.RESET_ALL}
{Fore.YELLOW}Version: 1.0.0{Style.RESET_ALL}
{Fore.YELLOW}Purpose: Educational and Authorized Testing Only{Style.RESET_ALL}
{Fore.RED}WARNING: Only scan websites you have permission to test{Style.RESET_ALL}
"""
    print(banner)

def run_scan(target_url: str):
    """Run all scanning modules"""
    all_findings = []
    
    # 1. OWASP Scanner
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[Module 1/3] OWASP Application Security Scan{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    try:
        owasp_scanner = OWASPScanner(target_url)
        owasp_findings = owasp_scanner.scan()
        all_findings.extend(owasp_findings)
        print(f"{Fore.GREEN}[+] Found {len(owasp_findings)} issues{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] OWASP Scan error: {str(e)}{Style.RESET_ALL}")
    
    # 2. KBA Tester
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[Module 2/3] Authentication Logic Testing{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    try:
        kba_tester = KBATester(target_url)
        kba_findings = kba_tester.scan()
        all_findings.extend(kba_findings)
        print(f"{Fore.GREEN}[+] Found {len(kba_findings)} issues{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] KBA Test error: {str(e)}{Style.RESET_ALL}")
    
    # 3. Negligence Analyzer
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[Module 3/3] Human Negligence Analysis{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    try:
        negligence_analyzer = NegligenceAnalyzer(target_url)
        negligence_findings = negligence_analyzer.scan()
        all_findings.extend(negligence_findings)
        print(f"{Fore.GREEN}[+] Found {len(negligence_findings)} issues{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Negligence Analysis error: {str(e)}{Style.RESET_ALL}")
    
    return all_findings

def save_text_report(target_url: str, findings: list, output_file: str):
    """Save report as text file"""
    from datetime import datetime
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 60 + "\n")
        f.write("VULNERABILITY ASSESSMENT REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Target URL: {target_url}\n")
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Issues: {len(findings)}\n\n")
        
        # Sort findings by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'Info'), 5))
        
        for i, finding in enumerate(sorted_findings, 1):
            f.write(f"{'='*50}\n")
            f.write(f"Finding {i}: {finding.get('title', 'Unknown')}\n")
            f.write(f"Severity: {finding.get('severity', 'Info')}\n")
            f.write(f"Category: {finding.get('category', 'General')}\n")
            f.write(f"CVSS Score: {finding.get('cvss_score', '0.0')}\n")
            f.write(f"Description: {finding.get('description', 'No description')}\n")
            if finding.get('evidence'):
                f.write(f"Evidence: {finding['evidence']}\n")
            if finding.get('remediation'):
                f.write(f"Remediation: {finding['remediation']}\n")
            f.write("\n")
    
    return output_file

def main():
    """Main function"""
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='Vulnerability Assessment Framework for Pakistani University Websites'
    )
    
    parser.add_argument(
        '--target', '-t',
        type=str,
        required=True,
        help='Target URL to scan (e.g., https://example.edu.pk)'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        default='report',
        help='Output report filename (without extension)'
    )
    
    parser.add_argument(
        '--format', '-f',
        type=str,
        choices=['pdf', 'txt', 'both'],
        default='txt',
        help='Report format (pdf, txt, or both)'
    )
    
    args = parser.parse_args()
    
    print(f"{Fore.GREEN}[+] Target: {args.target}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Output: {args.output}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Format: {args.format}{Style.RESET_ALL}")
    
    # Run scan
    all_findings = run_scan(args.target)
    
    # Print CLI summary
    CLIReportGenerator.print_summary(all_findings)
    
    # Generate reports
    if args.format in ['txt', 'both']:
        txt_file = f"{args.output}.txt"
        save_text_report(args.target, all_findings, txt_file)
        print(f"\n{Fore.GREEN}[+] Text report saved: {txt_file}{Style.RESET_ALL}")
    
    if args.format in ['pdf', 'both']:
        try:
            pdf_file = f"{args.output}.pdf"
            pdf_generator = PDFReportGenerator(args.target, all_findings)
            pdf_generator.generate(pdf_file)
            print(f"{Fore.GREEN}[+] PDF report saved: {pdf_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] PDF generation failed: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Text report is still available{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Scan Complete!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()