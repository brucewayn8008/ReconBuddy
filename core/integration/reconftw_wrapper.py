import os
import sys
import subprocess
import logging
import json
from pathlib import Path
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ScanType(Enum):
    """Enumeration of available ReconFTW scan types."""
    FULL = "full"
    PASSIVE = "passive"
    ACTIVE = "active"
    SUBDOMAIN = "subdomain"
    WEB = "web"
    OSINT = "osint"
    VULNERABILITY = "vulnerability"

@dataclass
class ScanOptions:
    """Data class for scan configuration options."""
    output_dir: Optional[str] = None
    threads: int = 50
    timeout: int = 30
    recursive: bool = False
    deep: bool = False
    quiet: bool = False
    custom_config: Optional[Dict] = None

class ReconFTWWrapper:
    """Wrapper class for interacting with ReconFTW."""
    
    def __init__(self, config_path: Optional[str] = None, reconftw_path: Optional[str] = None):
        """Initialize ReconFTW wrapper with optional custom paths."""
        self.reconftw_path = reconftw_path or self._find_reconftw_path()
        self.config_path = config_path or f"{self.reconftw_path}/reconftw.cfg"
        self.verify_installation()
        
    def _find_reconftw_path(self) -> str:
        """Find the ReconFTW installation path."""
        # Check common installation locations
        possible_paths = [
            os.path.expanduser("~/reconftw"),
            os.path.expanduser("~/tools/reconftw"),
            "/opt/reconftw",
            os.path.join(os.getcwd(), "reconftw")
        ]
        
        for path in possible_paths:
            if os.path.exists(path) and os.path.exists(os.path.join(path, "reconftw.sh")):
                return path
                
        raise FileNotFoundError("ReconFTW installation not found. Please install it first.")
    
    def verify_installation(self) -> bool:
        """Verify ReconFTW is installed and working."""
        try:
            # Check if reconftw.sh exists and is executable
            reconftw_script = os.path.join(self.reconftw_path, "reconftw.sh")
            if not os.path.exists(reconftw_script):
                raise FileNotFoundError(f"reconftw.sh not found at {reconftw_script}")
            
            # Try running reconftw.sh with --help to verify it works
            result = subprocess.run(
                [reconftw_script, "--help"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"ReconFTW verification failed: {result.stderr}")
                
            logger.info("ReconFTW installation verified successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to verify ReconFTW installation: {str(e)}")
            raise
    
    def update_config(self, config_updates: Dict) -> None:
        """Update ReconFTW configuration with the provided settings."""
        try:
            # Read current config
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            
            # Update with new settings
            config.update(config_updates)
            
            # Write back to file
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=4)
                
            logger.info("ReconFTW configuration updated successfully")
            
        except Exception as e:
            logger.error(f"Failed to update ReconFTW configuration: {str(e)}")
            raise
    
    def _execute_command(self, command: List[str], timeout: Optional[int] = None) -> Dict:
        """Execute a ReconFTW command and handle output."""
        try:
            reconftw_script = os.path.join(self.reconftw_path, "reconftw.sh")
            full_command = [reconftw_script] + command
            
            logger.info(f"Executing command: {' '.join(full_command)}")
            
            result = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"Command failed: {result.stderr}")
                
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            logger.error("Command timed out")
            raise
        except Exception as e:
            logger.error(f"Command execution failed: {str(e)}")
            raise
    
    def run_scan(self, domain: str, scan_type: ScanType, options: Optional[ScanOptions] = None) -> Dict:
        """Run a ReconFTW scan with specified options."""
        options = options or ScanOptions()
        
        # Build command arguments
        cmd_args = [
            "-d", domain,
            "-s", scan_type.value,
            "-t", str(options.threads),
            "--timeout", str(options.timeout)
        ]
        
        if options.output_dir:
            cmd_args.extend(["-o", options.output_dir])
        if options.recursive:
            cmd_args.append("-r")
        if options.deep:
            cmd_args.append("--deep")
        if options.quiet:
            cmd_args.append("-q")
            
        # Execute the scan
        result = self._execute_command(cmd_args, timeout=options.timeout * 60)
        
        # Parse and return results
        return self.parse_results(options.output_dir or f"reconftw/{domain}")
    
    def parse_results(self, output_dir: str) -> Dict:
        """Parse ReconFTW results from the output directory."""
        try:
            results = {
                "subdomains": [],
                "vulnerabilities": [],
                "endpoints": [],
                "technologies": [],
                "ports": []
            }
            
            # Parse subdomains
            subdomains_file = os.path.join(output_dir, "subdomains.txt")
            if os.path.exists(subdomains_file):
                with open(subdomains_file, 'r') as f:
                    results["subdomains"] = [line.strip() for line in f if line.strip()]
            
            # Parse vulnerabilities
            vulns_file = os.path.join(output_dir, "vulnerabilities.txt")
            if os.path.exists(vulns_file):
                with open(vulns_file, 'r') as f:
                    results["vulnerabilities"] = [line.strip() for line in f if line.strip()]
            
            # Parse endpoints
            endpoints_file = os.path.join(output_dir, "endpoints.txt")
            if os.path.exists(endpoints_file):
                with open(endpoints_file, 'r') as f:
                    results["endpoints"] = [line.strip() for line in f if line.strip()]
            
            # Parse technologies
            tech_file = os.path.join(output_dir, "technologies.txt")
            if os.path.exists(tech_file):
                with open(tech_file, 'r') as f:
                    results["technologies"] = [line.strip() for line in f if line.strip()]
            
            # Parse ports
            ports_file = os.path.join(output_dir, "ports.txt")
            if os.path.exists(ports_file):
                with open(ports_file, 'r') as f:
                    results["ports"] = [line.strip() for line in f if line.strip()]
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to parse results: {str(e)}")
            raise
    
    # Convenience methods for different scan types
    def run_full_scan(self, domain: str, options: Optional[ScanOptions] = None) -> Dict:
        """Run a full ReconFTW scan."""
        return self.run_scan(domain, ScanType.FULL, options)
    
    def run_passive_scan(self, domain: str, options: Optional[ScanOptions] = None) -> Dict:
        """Run passive reconnaissance only."""
        return self.run_scan(domain, ScanType.PASSIVE, options)
    
    def run_active_scan(self, domain: str, options: Optional[ScanOptions] = None) -> Dict:
        """Run active reconnaissance."""
        return self.run_scan(domain, ScanType.ACTIVE, options)
    
    def run_subdomain_scan(self, domain: str, options: Optional[ScanOptions] = None) -> Dict:
        """Run subdomain enumeration."""
        return self.run_scan(domain, ScanType.SUBDOMAIN, options)
    
    def run_web_scan(self, domain: str, options: Optional[ScanOptions] = None) -> Dict:
        """Run web scanning."""
        return self.run_scan(domain, ScanType.WEB, options)
    
    def run_osint_scan(self, domain: str, options: Optional[ScanOptions] = None) -> Dict:
        """Run OSINT scanning."""
        return self.run_scan(domain, ScanType.OSINT, options)
    
    def run_vulnerability_scan(self, domain: str, options: Optional[ScanOptions] = None) -> Dict:
        """Run vulnerability scanning."""
        return self.run_scan(domain, ScanType.VULNERABILITY, options) 