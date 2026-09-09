import sys, os, warnings
warnings.filterwarnings('ignore')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from colorama import init, Fore, Style
init()

def main():
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}VULNERABILITY ASSESSMENT FRAMEWORK{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Framework initialized successfully!{Style.RESET_ALL}")
    
    target = input(f"\n{Fore.GREEN}Enter target URL (e.g., https://example.com): {Style.RESET_ALL}")
    
    if target:
        print(f"\n{Fore.CYAN}Target set to: {target}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Starting scan...{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.YELLOW}No target provided.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()