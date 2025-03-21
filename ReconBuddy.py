import subprocess
import sys
import os
import shutil
import logging
from tqdm import tqdm
from colorama import Fore, Style, init
from datetime import datetime
from core.integration.reconftw_wrapper import ReconFTWWrapper
from core.integration.reconftw_config import ReconFTWConfig
from core.integration.reconftw_parser import ReconFTWParser
from core.db.database import Database
import json

# Initialize colorama for colored output
init(autoreset=True)

# Set up logging
logging.basicConfig(
    filename='recon.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

class ReconBuddy:
    def __init__(self):
        """Initialize ReconBuddy with its core components."""
        self.reconftw = ReconFTWWrapper()
        self.config = ReconFTWConfig()
        self.parser = None  # Will be initialized when scan starts
        self.db = Database()  # Initialize database connection
        
    def check_tool_availability(self, tools):
    """Check if required tools are available."""
        logger.info("Checking tool availability.")
    
    for tool in tqdm(tools, desc="Checking tools"):
        if not shutil.which(tool):
                logger.critical(f"{tool} is not installed or not found in PATH.")
            print(f"{Fore.RED}Error: {tool} is not installed or not found in PATH.{Style.RESET_ALL}")
            sys.exit(1)
        
        logger.info("All tools are available.")
    print(f"{Fore.GREEN}All tools are available.{Style.RESET_ALL}")

    def run_scan(self, domain: str, scan_type: str = "full"):
        """Run a complete scan on a domain."""
        logger.info(f"Starting {scan_type} scan for domain: {domain}")
        print(f"{Fore.CYAN}Starting {scan_type} scan for domain: {domain}{Style.RESET_ALL}")

        try:
            # Create scan record in database
            scan = self.db.create_scan(domain, scan_type)
            scan_id = scan.id

            # Initialize parser with the output directory
            output_dir = os.path.join("reconftw", domain)
            self.parser = ReconFTWParser(output_dir)

            # Run the scan using ReconFTW wrapper
            if scan_type == "full":
                results = self.reconftw.run_full_scan(domain)
            elif scan_type == "passive":
                results = self.reconftw.run_passive_scan(domain)
            elif scan_type == "active":
                results = self.reconftw.run_active_scan(domain)
            else:
                raise ValueError(f"Invalid scan type: {scan_type}")

            # Parse and process results
            report = self.parser.generate_report(output_format="json")
            
            # Save findings to database
            self._save_findings_to_db(scan_id, report)
            
            # Update scan status
            self.db.update_scan_status(
                scan_id,
                status="completed",
                end_time=datetime.utcnow()
            )

            # Save report to file
            report_file = os.path.join(output_dir, "report.json")
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=4)

            logger.info(f"Scan completed. Report saved to {report_file}")
            print(f"{Fore.GREEN}Scan completed. Report saved to {report_file}{Style.RESET_ALL}")

            return report

        except Exception as e:
            if scan_id:
                self.db.update_scan_status(scan_id, status="failed")
            logger.error(f"Error during scan: {str(e)}")
            print(f"{Fore.RED}Error during scan: {str(e)}{Style.RESET_ALL}")
            raise

    def _save_findings_to_db(self, scan_id: int, report: dict):
        """Save scan findings to database."""
        try:
            for subdomain_data in report.get("subdomains", []):
                # Save subdomain finding
                self.db.add_finding(
                    scan_id=scan_id,
                    finding_type="subdomain",
                    name=subdomain_data["name"],
                    metadata={
                        "ip_addresses": subdomain_data["ip_addresses"],
                        "ports": subdomain_data["ports"],
                        "technologies": subdomain_data["technologies"]
                    }
                )

                # Save endpoint findings
                for endpoint in subdomain_data.get("endpoints", []):
                    self.db.add_finding(
                        scan_id=scan_id,
                        finding_type="endpoint",
                        name=endpoint["url"],
                        metadata={
                            "method": endpoint["method"],
                            "status_code": endpoint["status_code"],
                            "content_type": endpoint["content_type"],
                            "technologies": endpoint["technologies"]
                        }
                    )

                # Save vulnerability findings
                for vuln in subdomain_data.get("vulnerabilities", []):
                    self.db.add_finding(
                        scan_id=scan_id,
                        finding_type="vulnerability",
                        name=vuln["type"],
                        severity=vuln["severity"],
                        description=vuln["description"],
                        evidence=vuln["evidence"],
                        metadata={
                            "cwe": vuln["cwe"],
                            "cve": vuln["cve"],
                            "cvss": vuln["cvss"],
                            "references": vuln["references"]
                        }
                    )

        except Exception as e:
            logger.error(f"Error saving findings to database: {str(e)}")
            raise

def main():
    # Create ReconBuddy instance
    recon = ReconBuddy()

    # Required tools for basic functionality
    tools = [
        "curl", "jq", "anew", "httpx", "nuclei",
        "amass", "subfinder", "assetfinder", "gobuster",
        "gau", "waybackurls", "katana", "hakrawler"
    ]
    
    # Check tool availability
    recon.check_tool_availability(tools)

    # Get domain from user
    domain = input(f"{Fore.CYAN}Enter target domain: {Style.RESET_ALL}")
    
    # Get scan type
    print(f"\n{Fore.YELLOW}Available scan types:{Style.RESET_ALL}")
    print("1. Full Scan")
    print("2. Passive Scan")
    print("3. Active Scan")
    
    scan_choice = input(f"\n{Fore.CYAN}Enter scan type (1-3): {Style.RESET_ALL}")
    
    scan_types = {
        "1": "full",
        "2": "passive",
        "3": "active"
    }
    
    scan_type = scan_types.get(scan_choice, "full")
    
    # Run the scan
    try:
        recon.run_scan(domain, scan_type)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
