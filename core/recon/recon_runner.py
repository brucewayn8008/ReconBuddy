import asyncio
import logging
from pathlib import Path
from typing import List, Set, Dict, Any
from datetime import datetime
import sys
import os

# Add parent directory to path to allow imports from core.info_gathering
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from .subdomain_enum import SubdomainEnumerator
from .content_discovery import ContentDiscovery
from ..info_gathering.dns_tools import DNSTools
from ..info_gathering.network_tools import NetworkTools

class ReconRunner:
    def __init__(self, target_domain: str, output_dir: str = None, use_advanced: bool = True):
        """
        Initialize the ReconRunner
        
        Args:
            target_domain: The root domain to perform reconnaissance on
            output_dir: Base directory for output files
            use_advanced: Whether to use advanced techniques
        """
        self.target_domain = target_domain
        self.use_advanced = use_advanced
        
        # Set up output directory with timestamp
        if output_dir is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = f"results/{target_domain}_{timestamp}"
        
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Set up logging
        self.setup_logging()
        self.logger = logging.getLogger("ReconRunner")
        
        # Initialize results
        self.subdomains: Set[str] = set()
        self.directories: Set[str] = set()
        self.endpoints: Set[str] = set()
        self.dns_results: Dict[str, Any] = {}
        self.network_results: Dict[str, Any] = {}
        
    def setup_logging(self):
        """Configure logging to file and console"""
        log_file = self.output_dir / "recon.log"
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # File handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)

    async def run_subdomain_enumeration(self) -> Set[str]:
        """Run subdomain enumeration phase"""
        self.logger.info("Starting subdomain enumeration...")
        subdomain_enumerator = SubdomainEnumerator(
            self.target_domain,
            output_dir=str(self.output_dir / "subdomains"),
            use_advanced=self.use_advanced
        )
        subdomains = await subdomain_enumerator.enumerate()
        self.logger.info(f"Found {len(subdomains)} subdomains")
        return subdomains

    async def run_content_discovery(self, subdomains: Set[str]) -> Dict[str, Any]:
        """Run content discovery phase"""
        self.logger.info("Starting content discovery...")
        content_discoverer = ContentDiscovery(
            list(subdomains),
            output_dir=str(self.output_dir)
        )
        directories, endpoints, comprehensive_results = await content_discoverer.discover_content()
        self.logger.info(f"Found {len(directories)} directories and {len(endpoints)} endpoints")
        return {
            "directories": directories,
            "endpoints": endpoints,
            "comprehensive_results": comprehensive_results
        }

    async def run_dns_analysis(self, subdomains: Set[str]) -> Dict[str, Any]:
        """Run DNS analysis phase"""
        self.logger.info("Starting DNS analysis...")
        dns_tools = DNSTools(output_dir=str(self.output_dir / "dns"))
        
        # Convert subdomains to list
        subdomain_list = list(subdomains)
        
        # Resolve domains to IPs
        domain_ips = await dns_tools.resolve_domains(subdomain_list)
        self.logger.info(f"Resolved {len([ip for ips in domain_ips.values() if ips for ip in ips])} IP addresses")
        
        # Extract all IPs
        all_ips = [ip for ips in domain_ips.values() for ip in ips if ips]
        
        # Perform reverse DNS lookups
        reverse_dns = await dns_tools.reverse_dns(all_ips)
        self.logger.info(f"Performed reverse DNS lookups for {len(reverse_dns)} IPs")
        
        # Check zone transfers
        zone_transfer_results = await dns_tools.check_zone_transfer(self.target_domain)
        if zone_transfer_results:
            self.logger.warning(f"Zone transfer successful for {self.target_domain}! Found {len(zone_transfer_results)} records")
        
        # Check certificate transparency logs
        cert_subdomains = await dns_tools.check_cert_transparency(self.target_domain)
        self.logger.info(f"Found {len(cert_subdomains)} subdomains from certificate transparency logs")
        
        # Generate permutations
        permutations = await dns_tools.generate_permutations(self.target_domain)
        self.logger.info(f"Generated {len(permutations)} subdomain permutations")
        
        dns_results = {
            "domain_ips": domain_ips,
            "reverse_dns": reverse_dns,
            "zone_transfer": zone_transfer_results,
            "cert_transparency": list(cert_subdomains),
            "permutations": list(permutations)
        }
        
        return dns_results

    async def run_network_scanning(self, subdomains: Set[str], domain_ips: Dict[str, List[str]]) -> Dict[str, Any]:
        """Run network scanning phase"""
        self.logger.info("Starting network scanning...")
        network_tools = NetworkTools(output_dir=str(self.output_dir / "network"))
        
        network_results = {}
        
        # Flatten IPs
        all_ips = [ip for ips in domain_ips.values() for ip in ips if ips]
        unique_ips = list(set(all_ips))
        
        # Port scanning for each subdomain with resolved IPs
        port_scan_results = {}
        for subdomain, ips in domain_ips.items():
            if ips:
                # Scan first IP only to avoid excessive scanning
                port_scan = await network_tools.scan_ports(ips[0])
                port_scan_results[subdomain] = port_scan
        
        network_results["port_scans"] = port_scan_results
        self.logger.info(f"Completed port scanning for {len(port_scan_results)} hosts")
        
        # Service detection for each subdomain
        service_results = {}
        for subdomain in subdomains:
            if subdomain in domain_ips and domain_ips[subdomain]:
                # Use first IP for service detection
                service_info = await network_tools.scan_common_services(subdomain)
                service_results[subdomain] = service_info
        
        network_results["services"] = service_results
        self.logger.info(f"Detected services on {len(service_results)} hosts")
        
        # Take screenshots of web services
        screenshots = {}
        for subdomain in subdomains:
            http_url = f"http://{subdomain}"
            https_url = f"https://{subdomain}"
            
            http_screenshot = await network_tools.take_screenshot(http_url)
            https_screenshot = await network_tools.take_screenshot(https_url)
            
            if http_screenshot:
                screenshots[http_url] = http_screenshot
            if https_screenshot:
                screenshots[https_url] = https_screenshot
        
        network_results["screenshots"] = screenshots
        self.logger.info(f"Took {len(screenshots)} screenshots of web services")
        
        return network_results

    async def run_recon(self) -> Dict[str, Any]:
        """
        Run the complete reconnaissance process
        
        Returns:
            Dictionary containing all findings
        """
        self.logger.info(f"Starting reconnaissance for {self.target_domain}")
        
        try:
            # Phase 1: Subdomain Enumeration
            self.subdomains = await self.run_subdomain_enumeration()
            
            # Phase 2: Content Discovery
            content_results = await self.run_content_discovery(self.subdomains)
            self.directories = content_results["directories"]
            self.endpoints = content_results["endpoints"]
            
            # Phase 3: DNS Analysis (if advanced is enabled)
            if self.use_advanced:
                self.dns_results = await self.run_dns_analysis(self.subdomains)
                
                # Add any new subdomains from certificate transparency
                if "cert_transparency" in self.dns_results:
                    self.subdomains.update(self.dns_results["cert_transparency"])
            
            # Phase 4: Network Scanning (if advanced is enabled)
            if self.use_advanced and "domain_ips" in self.dns_results:
                self.network_results = await self.run_network_scanning(
                    self.subdomains, 
                    self.dns_results["domain_ips"]
                )
            
            # Generate summary report
            await self.generate_report()
            
            return {
                "subdomains": self.subdomains,
                "directories": self.directories,
                "endpoints": self.endpoints,
                "dns_results": self.dns_results,
                "network_results": self.network_results
            }
            
        except Exception as e:
            self.logger.error(f"Error during reconnaissance: {str(e)}")
            raise

    async def generate_report(self):
        """Generate a summary report of all findings"""
        report_file = self.output_dir / "recon_summary.txt"
        
        report_content = [
            "Reconnaissance Summary Report",
            "=========================",
            f"Target Domain: {self.target_domain}",
            f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            f"Total Subdomains Found: {len(self.subdomains)}",
            f"Total Directories Found: {len(self.directories)}",
            f"Total Endpoints Found: {len(self.endpoints)}",
            ""
        ]
        
        # Add DNS statistics if available
        if self.dns_results:
            report_content.extend([
                "DNS Analysis Results",
                "------------------",
                f"Total IPs Resolved: {sum(len(ips) for ips in self.dns_results.get('domain_ips', {}).values() if ips)}",
                f"Zone Transfer Records: {len(self.dns_results.get('zone_transfer', []))}",
                f"Certificate Transparency Findings: {len(self.dns_results.get('cert_transparency', []))}",
                ""
            ])
        
        # Add Network statistics if available
        if self.network_results:
            open_ports = sum(
                sum(1 for status in ports.values() if status) 
                for ports in self.network_results.get('port_scans', {}).values()
            )
            
            report_content.extend([
                "Network Scanning Results",
                "----------------------",
                f"Open Ports Found: {open_ports}",
                f"Services Detected: {len(self.network_results.get('services', {}))}",
                f"Screenshots Taken: {len(self.network_results.get('screenshots', {}))}",
                ""
            ])
        
        report_content.extend([
            "Top-level Statistics",
            "------------------",
            f"Unique Root Domains: {len(set(s.split('.', 1)[1] for s in self.subdomains if '.' in s))}",
            f"HTTP Endpoints: {len([e for e in self.endpoints if e.startswith('http://')])}",
            f"HTTPS Endpoints: {len([e for e in self.endpoints if e.startswith('https://')])}",
            "",
            "File Locations",
            "--------------",
            f"Detailed subdomain list: {self.output_dir}/subdomains/final_subdomains.txt",
            f"Directory listing: {self.output_dir}/all_directories.txt",
            f"Endpoint listing: {self.output_dir}/all_endpoints.txt"
        ])
        
        # Add advanced files if available
        if self.use_advanced:
            report_content.extend([
                f"DNS analysis: {self.output_dir}/dns/",
                f"Network scanning: {self.output_dir}/network/",
                f"Content discovery details: {self.output_dir}/comprehensive_results.json"
            ])
        
        report_content.append(f"Full scan logs: {self.output_dir}/recon.log")
        
        report_file.write_text("\n".join(report_content))
        self.logger.info(f"Summary report generated: {report_file}")

def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="ReconBuddy Reconnaissance Runner")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("-o", "--output", help="Output directory", default=None)
    parser.add_argument("--basic", action="store_true", help="Run basic reconnaissance only (no advanced techniques)")
    
    args = parser.parse_args()
    
    runner = ReconRunner(args.domain, args.output, not args.basic)
    asyncio.run(runner.run_recon())

if __name__ == "__main__":
    main() 