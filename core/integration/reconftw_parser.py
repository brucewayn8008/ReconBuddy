import os
import json
import logging
from typing import Dict, List, Optional, Union
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    """Data class for vulnerability information."""
    type: str
    severity: str
    url: str
    description: str
    evidence: Optional[str] = None
    cwe: Optional[str] = None
    cve: Optional[str] = None
    cvss: Optional[float] = None
    references: List[str] = None

@dataclass
class Endpoint:
    """Data class for endpoint information."""
    url: str
    method: str
    status_code: int
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    technologies: List[str] = None
    vulnerabilities: List[Vulnerability] = None

@dataclass
class Subdomain:
    """Data class for subdomain information."""
    name: str
    ip_addresses: List[str]
    ports: List[int]
    technologies: List[str]
    endpoints: List[Endpoint]
    vulnerabilities: List[Vulnerability]

class ReconFTWParser:
    """Parser for ReconFTW output files."""
    
    def __init__(self, output_dir: str):
        """Initialize the parser with the output directory."""
        self.output_dir = output_dir
        self._validate_output_dir()
    
    def _validate_output_dir(self) -> None:
        """Validate that the output directory exists."""
        if not os.path.exists(self.output_dir):
            raise FileNotFoundError(f"Output directory not found: {self.output_dir}")
    
    def parse_subdomains(self) -> List[Subdomain]:
        """Parse subdomain information from ReconFTW output."""
        subdomains = []
        
        # Parse subdomains.txt
        subdomains_file = os.path.join(self.output_dir, "subdomains.txt")
        if not os.path.exists(subdomains_file):
            logger.warning("subdomains.txt not found")
            return subdomains
            
        with open(subdomains_file, 'r') as f:
            for line in f:
                subdomain = line.strip()
                if subdomain:
                    # Get IP addresses
                    ip_file = os.path.join(self.output_dir, f"{subdomain}/ips.txt")
                    ip_addresses = self._read_file_lines(ip_file)
                    
                    # Get ports
                    ports_file = os.path.join(self.output_dir, f"{subdomain}/ports.txt")
                    ports = [int(p) for p in self._read_file_lines(ports_file) if p.isdigit()]
                    
                    # Get technologies
                    tech_file = os.path.join(self.output_dir, f"{subdomain}/technologies.txt")
                    technologies = self._read_file_lines(tech_file)
                    
                    # Get endpoints
                    endpoints = self._parse_endpoints(subdomain)
                    
                    # Get vulnerabilities
                    vulnerabilities = self._parse_vulnerabilities(subdomain)
                    
                    subdomains.append(Subdomain(
                        name=subdomain,
                        ip_addresses=ip_addresses,
                        ports=ports,
                        technologies=technologies,
                        endpoints=endpoints,
                        vulnerabilities=vulnerabilities
                    ))
        
        return subdomains
    
    def _parse_endpoints(self, subdomain: str) -> List[Endpoint]:
        """Parse endpoint information for a subdomain."""
        endpoints = []
        
        # Parse endpoints.txt
        endpoints_file = os.path.join(self.output_dir, f"{subdomain}/endpoints.txt")
        if not os.path.exists(endpoints_file):
            return endpoints
            
        with open(endpoints_file, 'r') as f:
            for line in f:
                url = line.strip()
                if url:
                    # Get endpoint details from httpx output
                    httpx_file = os.path.join(self.output_dir, f"{subdomain}/httpx.txt")
                    endpoint_info = self._parse_httpx_output(httpx_file, url)
                    
                    # Get vulnerabilities for this endpoint
                    vulnerabilities = self._parse_endpoint_vulnerabilities(subdomain, url)
                    
                    endpoints.append(Endpoint(
                        url=url,
                        method=endpoint_info.get("method", "GET"),
                        status_code=endpoint_info.get("status_code", 0),
                        content_type=endpoint_info.get("content_type"),
                        content_length=endpoint_info.get("content_length"),
                        technologies=endpoint_info.get("technologies", []),
                        vulnerabilities=vulnerabilities
                    ))
        
        return endpoints
    
    def _parse_httpx_output(self, httpx_file: str, url: str) -> Dict:
        """Parse httpx output for endpoint details."""
        if not os.path.exists(httpx_file):
            return {}
            
        with open(httpx_file, 'r') as f:
            for line in f:
                if url in line:
                    try:
                        # Parse JSON line from httpx output
                        data = json.loads(line)
                        return {
                            "method": data.get("method", "GET"),
                            "status_code": data.get("status-code", 0),
                            "content_type": data.get("content-type"),
                            "content_length": data.get("content-length"),
                            "technologies": data.get("technologies", [])
                        }
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse httpx output line: {line}")
                        return {}
        
        return {}
    
    def _parse_vulnerabilities(self, subdomain: str) -> List[Vulnerability]:
        """Parse vulnerability information for a subdomain."""
        vulnerabilities = []
        
        # Parse nuclei output
        nuclei_file = os.path.join(self.output_dir, f"{subdomain}/nuclei.txt")
        if not os.path.exists(nuclei_file):
            return vulnerabilities
            
        with open(nuclei_file, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    vulnerability = Vulnerability(
                        type=data.get("info", {}).get("name", "Unknown"),
                        severity=data.get("info", {}).get("severity", "info"),
                        url=data.get("matched-at", ""),
                        description=data.get("info", {}).get("description", ""),
                        evidence=data.get("request", {}).get("raw", ""),
                        cwe=data.get("info", {}).get("cwe", ""),
                        cve=data.get("info", {}).get("cve", ""),
                        cvss=data.get("info", {}).get("cvss", {}).get("score", 0.0),
                        references=data.get("info", {}).get("reference", [])
                    )
                    vulnerabilities.append(vulnerability)
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse nuclei output line: {line}")
                    continue
        
        return vulnerabilities
    
    def _parse_endpoint_vulnerabilities(self, subdomain: str, url: str) -> List[Vulnerability]:
        """Parse vulnerability information for a specific endpoint."""
        vulnerabilities = []
        
        # Parse endpoint-specific nuclei output
        nuclei_file = os.path.join(self.output_dir, f"{subdomain}/nuclei.txt")
        if not os.path.exists(nuclei_file):
            return vulnerabilities
            
        with open(nuclei_file, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if data.get("matched-at", "") == url:
                        vulnerability = Vulnerability(
                            type=data.get("info", {}).get("name", "Unknown"),
                            severity=data.get("info", {}).get("severity", "info"),
                            url=data.get("matched-at", ""),
                            description=data.get("info", {}).get("description", ""),
                            evidence=data.get("request", {}).get("raw", ""),
                            cwe=data.get("info", {}).get("cwe", ""),
                            cve=data.get("info", {}).get("cve", ""),
                            cvss=data.get("info", {}).get("cvss", {}).get("score", 0.0),
                            references=data.get("info", {}).get("reference", [])
                        )
                        vulnerabilities.append(vulnerability)
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse nuclei output line: {line}")
                    continue
        
        return vulnerabilities
    
    def _read_file_lines(self, file_path: str) -> List[str]:
        """Read lines from a file, returning empty list if file doesn't exist."""
        if not os.path.exists(file_path):
            return []
            
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    
    def generate_report(self, output_format: str = "json") -> Union[str, Dict]:
        """Generate a comprehensive report of the scan results."""
        subdomains = self.parse_subdomains()
        
        report = {
            "scan_date": datetime.now().isoformat(),
            "subdomains": [
                {
                    "name": s.name,
                    "ip_addresses": s.ip_addresses,
                    "ports": s.ports,
                    "technologies": s.technologies,
                    "endpoints": [
                        {
                            "url": e.url,
                            "method": e.method,
                            "status_code": e.status_code,
                            "content_type": e.content_type,
                            "content_length": e.content_length,
                            "technologies": e.technologies,
                            "vulnerabilities": [
                                {
                                    "type": v.type,
                                    "severity": v.severity,
                                    "url": v.url,
                                    "description": v.description,
                                    "evidence": v.evidence,
                                    "cwe": v.cwe,
                                    "cve": v.cve,
                                    "cvss": v.cvss,
                                    "references": v.references
                                }
                                for v in e.vulnerabilities
                            ]
                        }
                        for e in s.endpoints
                    ],
                    "vulnerabilities": [
                        {
                            "type": v.type,
                            "severity": v.severity,
                            "url": v.url,
                            "description": v.description,
                            "evidence": v.evidence,
                            "cwe": v.cwe,
                            "cve": v.cve,
                            "cvss": v.cvss,
                            "references": v.references
                        }
                        for v in s.vulnerabilities
                    ]
                }
                for s in subdomains
            ]
        }
        
        if output_format == "json":
            return report
        elif output_format == "html":
            return self._generate_html_report(report)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def _generate_html_report(self, report: Dict) -> str:
        """Generate an HTML report from the scan results."""
        # This is a basic HTML template - you can enhance it with better styling
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>ReconFTW Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .subdomain { margin-bottom: 20px; padding: 10px; border: 1px solid #ccc; }
                .vulnerability { margin: 5px 0; padding: 5px; background-color: #f0f0f0; }
                .high { color: red; }
                .medium { color: orange; }
                .low { color: green; }
                .info { color: blue; }
            </style>
        </head>
        <body>
            <h1>ReconFTW Scan Report</h1>
            <p>Scan Date: {scan_date}</p>
        """.format(scan_date=report["scan_date"])
        
        for subdomain in report["subdomains"]:
            html += f"""
            <div class="subdomain">
                <h2>{subdomain['name']}</h2>
                <p>IP Addresses: {', '.join(subdomain['ip_addresses'])}</p>
                <p>Ports: {', '.join(map(str, subdomain['ports']))}</p>
                <p>Technologies: {', '.join(subdomain['technologies'])}</p>
                
                <h3>Endpoints</h3>
                <ul>
            """
            
            for endpoint in subdomain["endpoints"]:
                html += f"""
                <li>
                    <strong>{endpoint['url']}</strong>
                    <br>Method: {endpoint['method']}
                    <br>Status: {endpoint['status_code']}
                    <br>Content Type: {endpoint['content_type']}
                    <br>Technologies: {', '.join(endpoint['technologies'])}
                """
                
                if endpoint["vulnerabilities"]:
                    html += "<br>Vulnerabilities:"
                    for vuln in endpoint["vulnerabilities"]:
                        html += f"""
                        <div class="vulnerability {vuln['severity']}">
                            <strong>{vuln['type']}</strong> ({vuln['severity']})
                            <br>Description: {vuln['description']}
                            <br>CWE: {vuln['cwe']}
                            <br>CVE: {vuln['cve']}
                            <br>CVSS: {vuln['cvss']}
                        </div>
                        """
                
                html += "</li>"
            
            html += "</ul>"
            
            if subdomain["vulnerabilities"]:
                html += "<h3>Subdomain Vulnerabilities</h3>"
                for vuln in subdomain["vulnerabilities"]:
                    html += f"""
                    <div class="vulnerability {vuln['severity']}">
                        <strong>{vuln['type']}</strong> ({vuln['severity']})
                        <br>Description: {vuln['description']}
                        <br>CWE: {vuln['cwe']}
                        <br>CVE: {vuln['cve']}
                        <br>CVSS: {vuln['cvss']}
                    </div>
                    """
            
            html += "</div>"
        
        html += """
        </body>
        </html>
        """
        
        return html 