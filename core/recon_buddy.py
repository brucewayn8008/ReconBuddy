import asyncio
import logging
import os
import sys
import json
from pathlib import Path
from typing import List, Dict, Set, Any, Optional
from datetime import datetime
import argparse

# Import all modules
from core.recon.recon_runner import ReconRunner
from core.recon.subdomain_enum import SubdomainEnumerator
from core.recon.content_discovery import ContentDiscovery
from core.info_gathering.dns_tools import DNSTools
from core.info_gathering.network_tools import NetworkTools
from core.info_gathering.asset_discovery import AssetDiscovery
from core.info_gathering.github_recon import GitHubRecon

class ReconBuddy:
    def __init__(self, 
                 target: str, 
                 output_dir: str = None, 
                 use_advanced: bool = True,
                 is_company: bool = False,
                 github_token: str = None):
        """
        Initialize ReconBuddy - The main orchestrator for all modules
        
        Args:
            target: Target domain, IP, or company name to scan
            output_dir: Base directory for all scan results
            use_advanced: Whether to use advanced scanning techniques
            is_company: Whether the target is a company name rather than a domain
            github_token: GitHub API token for GitHub reconnaissance
        """
        self.target = target
        self.is_company = is_company
        self.use_advanced = use_advanced
        self.github_token = github_token
        
        # Set up output directory with timestamp
        if output_dir is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = f"results/{target.replace('.', '_')}_{timestamp}"
        
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        self.setup_logging()
        self.logger = logging.getLogger("ReconBuddy")
        
        # Initialize results
        self.results = {
            "target": target,
            "is_company": is_company,
            "timestamp": datetime.now().isoformat(),
            "subdomains": set(),
            "endpoints": set(),
            "directories": set(),
            "ip_ranges": set(),
            "assets": {},
            "github_findings": {},
            "vulnerabilities": {}
        }
    
    def setup_logging(self):
        """Configure logging to file and console"""
        log_file = self.output_dir / "recon_buddy.log"
        
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
        
        # Remove existing handlers to avoid duplicates
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
            
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)
    
    async def run_asset_discovery(self) -> Dict[str, Any]:
        """Run asset discovery to find related domains and IP ranges"""
        self.logger.info("Starting asset discovery...")
        
        asset_discoverer = AssetDiscovery(output_dir=str(self.output_dir / "assets"))
        assets = await asset_discoverer.discover_assets(self.target, self.is_company)
        
        # Update results with discovered assets
        if "domains" in assets:
            self.results["subdomains"].update(assets["domains"])
        
        if "ip_ranges" in assets:
            self.results["ip_ranges"].update(assets["ip_ranges"])
        
        self.results["assets"] = assets
        self.logger.info(f"Asset discovery completed. Found {len(assets.get('domains', []))} domains and {len(assets.get('ip_ranges', []))} IP ranges")
        
        return assets
    
    async def run_github_recon(self) -> Dict[str, Any]:
        """Run GitHub reconnaissance to find sensitive information"""
        self.logger.info("Starting GitHub reconnaissance...")
        
        if not self.github_token:
            self.logger.warning("No GitHub token provided. GitHub recon will be limited.")
        
        github_recon = GitHubRecon(
            output_dir=str(self.output_dir / "github"),
            github_token=self.github_token
        )
        
        org_name = self.target
        if not self.is_company and '.' in self.target:
            # Extract organization name from domain (e.g., example.com -> example)
            org_name = self.target.split('.')[0]
        
        findings = await github_recon.run_recon(org_name)
        self.results["github_findings"] = findings
        
        self.logger.info(f"GitHub reconnaissance completed. Found {len(findings.get('repositories', []))} repositories and {len(findings.get('sensitive_info', []))} sensitive information items")
        
        return findings
    
    async def run_dns_and_network_recon(self) -> Dict[str, Any]:
        """Run DNS and network reconnaissance"""
        # Initialize the ReconRunner
        recon_runner = ReconRunner(
            self.target,
            output_dir=str(self.output_dir / "recon"),
            use_advanced=self.use_advanced
        )
        
        # Run the reconnaissance
        recon_results = await recon_runner.run_recon()
        
        # Update our results with findings from ReconRunner
        self.results["subdomains"].update(recon_results["subdomains"])
        self.results["directories"].update(recon_results["directories"])
        self.results["endpoints"].update(recon_results["endpoints"])
        
        self.logger.info(f"DNS and network reconnaissance completed. Found {len(recon_results['subdomains'])} subdomains")
        
        return recon_results
    
    async def scan_additional_ip_ranges(self) -> Dict[str, Set[str]]:
        """Scan additional IP ranges discovered during asset discovery"""
        self.logger.info(f"Scanning {len(self.results['ip_ranges'])} IP ranges...")
        
        network_tools = NetworkTools(output_dir=str(self.output_dir / "network"))
        
        results = {"live_hosts": set()}
        
        for ip_range in self.results["ip_ranges"]:
            try:
                live_hosts = await network_tools.scan_ip_range(ip_range)
                results["live_hosts"].update(live_hosts)
                self.logger.info(f"Found {len(live_hosts)} live hosts in range {ip_range}")
            except Exception as e:
                self.logger.error(f"Error scanning IP range {ip_range}: {str(e)}")
        
        self.logger.info(f"IP range scanning completed. Found {len(results['live_hosts'])} live hosts total")
        return results
    
    async def generate_comprehensive_report(self):
        """Generate a comprehensive HTML report of all findings"""
        report_file = self.output_dir / "comprehensive_report.html"
        
        # Basic HTML template
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>ReconBuddy Report - {self.target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2, h3 {{ color: #2c3e50; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #eee; border-radius: 5px; }}
                .stats {{ display: flex; flex-wrap: wrap; gap: 15px; }}
                .stat-card {{ background: #f8f9fa; padding: 15px; border-radius: 5px; min-width: 200px; }}
                pre {{ background: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
                tr:hover {{ background-color: #f5f5f5; }}
                .severity-high {{ color: #e74c3c; }}
                .severity-medium {{ color: #f39c12; }}
                .severity-low {{ color: #3498db; }}
                .severity-info {{ color: #2ecc71; }}
            </style>
        </head>
        <body>
            <h1>ReconBuddy Report</h1>
            <div class="section">
                <h2>Scan Overview</h2>
                <p><strong>Target:</strong> {self.target}</p>
                <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Scan Type:</strong> {"Company" if self.is_company else "Domain"} Reconnaissance</p>
                <p><strong>Advanced Techniques:</strong> {"Enabled" if self.use_advanced else "Disabled"}</p>
            </div>
            
            <div class="section">
                <h2>Statistics</h2>
                <div class="stats">
                    <div class="stat-card">
                        <h3>Subdomains</h3>
                        <p>{len(self.results["subdomains"])}</p>
                    </div>
                    <div class="stat-card">
                        <h3>Endpoints</h3>
                        <p>{len(self.results["endpoints"])}</p>
                    </div>
                    <div class="stat-card">
                        <h3>Directories</h3>
                        <p>{len(self.results["directories"])}</p>
                    </div>
                    <div class="stat-card">
                        <h3>IP Ranges</h3>
                        <p>{len(self.results["ip_ranges"])}</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>Subdomains</h2>
                <pre>{chr(10).join(sorted(self.results["subdomains"])[:100])}{"..." if len(self.results["subdomains"]) > 100 else ""}</pre>
            </div>
            
            <div class="section">
                <h2>Assets & Organization Info</h2>
                <table>
                    <tr>
                        <th>ASN</th>
                        <th>Organization</th>
                        <th>IP Ranges</th>
                    </tr>
                    {"".join(f"<tr><td>{asn}</td><td>{self.results['assets'].get('asn_info', {}).get('organization', '')}</td><td>{len([r for r in self.results['assets'].get('ip_ranges', []) if r])}</td></tr>" for asn in self.results['assets'].get('asn_info', {}).get('asn_numbers', [])[:5])}
                </table>
            </div>
            
            <div class="section">
                <h2>GitHub Findings</h2>
                <h3>Repositories</h3>
                <table>
                    <tr>
                        <th>Repository</th>
                        <th>Description</th>
                        <th>Stars</th>
                    </tr>
                    {"".join(f"<tr><td>{repo.get('name', '')}</td><td>{repo.get('description', '')}</td><td>{repo.get('stars', 0)}</td></tr>" for repo in self.results['github_findings'].get('repositories', [])[:5])}
                </table>
                
                <h3>Sensitive Information</h3>
                <table>
                    <tr>
                        <th>Type</th>
                        <th>Repository</th>
                        <th>File</th>
                    </tr>
                    {"".join(f"<tr><td>{info.get('type', '')}</td><td>{info.get('repository', '')}</td><td>{info.get('file', '')}</td></tr>" for info in self.results['github_findings'].get('sensitive_info', [])[:5])}
                </table>
            </div>
            
            <div class="section">
                <h2>Report Files</h2>
                <ul>
                    <li><strong>Subdomain List:</strong> {self.output_dir}/recon/subdomains/final_subdomains.txt</li>
                    <li><strong>Directory List:</strong> {self.output_dir}/recon/all_directories.txt</li>
                    <li><strong>Endpoint List:</strong> {self.output_dir}/recon/all_endpoints.txt</li>
                    <li><strong>Asset Information:</strong> {self.output_dir}/assets/</li>
                    <li><strong>GitHub Reconnaissance:</strong> {self.output_dir}/github/</li>
                    <li><strong>Network Scan Results:</strong> {self.output_dir}/network/</li>
                    <li><strong>DNS Analysis:</strong> {self.output_dir}/recon/dns/</li>
                    <li><strong>Full Logs:</strong> {self.output_dir}/recon_buddy.log</li>
                </ul>
            </div>
            
            <div class="section">
                <h2>Next Steps</h2>
                <ul>
                    <li>Review exposed directories and endpoints for sensitive information</li>
                    <li>Check GitHub findings for leaked credentials or API keys</li>
                    <li>Analyze discovered subdomains for potential subdomain takeover</li>
                    <li>Review DNS configuration for misconfigurations</li>
                    <li>Analyze network scanning results for vulnerable services</li>
                </ul>
            </div>
            
            <footer>
                <p>Generated by ReconBuddy at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </footer>
        </body>
        </html>
        """
        
        report_file.write_text(html_template)
        self.logger.info(f"Comprehensive HTML report generated: {report_file}")
    
    async def save_results(self):
        """Save results to JSON file"""
        # Convert set to list for JSON serialization
        serializable_results = {
            "target": self.results["target"],
            "is_company": self.results["is_company"],
            "timestamp": self.results["timestamp"],
            "subdomains": list(self.results["subdomains"]),
            "endpoints": list(self.results["endpoints"]),
            "directories": list(self.results["directories"]),
            "ip_ranges": list(self.results["ip_ranges"]),
            "assets": self.results["assets"],
            "github_findings": self.results["github_findings"],
            "vulnerabilities": self.results["vulnerabilities"]
        }
        
        results_file = self.output_dir / "results.json"
        with open(results_file, 'w') as f:
            json.dump(serializable_results, f, indent=2)
        
        self.logger.info(f"Results saved to {results_file}")
    
    async def run(self) -> Dict[str, Any]:
        """Run the complete reconnaissance process"""
        self.logger.info(f"Starting ReconBuddy reconnaissance for {self.target}")
        
        try:
            # Step 1: Asset Discovery (if company or use_advanced=True)
            if self.is_company or self.use_advanced:
                await self.run_asset_discovery()
            
            # Step 2: GitHub Reconnaissance (if use_advanced=True)
            if self.use_advanced:
                await self.run_github_recon()
            
            # Step 3: DNS and Network Reconnaissance
            await self.run_dns_and_network_recon()
            
            # Step 4: Scan Additional IP Ranges (if any were discovered)
            if self.results["ip_ranges"] and self.use_advanced:
                await self.scan_additional_ip_ranges()
            
            # Step 5: Generate Reports
            await self.generate_comprehensive_report()
            await self.save_results()
            
            self.logger.info(f"ReconBuddy reconnaissance completed for {self.target}")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"Error during reconnaissance: {str(e)}")
            raise

def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(description="ReconBuddy - Comprehensive Reconnaissance Tool")
    parser.add_argument("target", help="Target domain, IP, or company name")
    parser.add_argument("-o", "--output", help="Output directory", default=None)
    parser.add_argument("--basic", action="store_true", help="Run basic reconnaissance only")
    parser.add_argument("--company", action="store_true", help="Target is a company name, not a domain")
    parser.add_argument("--github-token", help="GitHub API token for GitHub reconnaissance")
    
    args = parser.parse_args()
    
    recon_buddy = ReconBuddy(
        args.target,
        args.output,
        not args.basic,
        args.company,
        args.github_token
    )
    
    asyncio.run(recon_buddy.run())

if __name__ == "__main__":
    main() 