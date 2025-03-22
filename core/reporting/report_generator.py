import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import aiohttp
import asyncio
import markdown2
import pdfkit
from jinja2 import Environment, FileSystemLoader
import google.generativeai as genai
from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    evidence: List[str]
    remediation: str
    references: List[str]
    category: str
    timestamp: str

class ReportGenerator:
    def __init__(self, 
                 output_dir: str = "results/reports",
                 gemini_api_key: str = None,
                 template_dir: str = "core/reporting/templates"):
        """
        Initialize the Report Generator
        
        Args:
            output_dir: Directory to store reports
            gemini_api_key: Google Gemini AI API key
            template_dir: Directory containing report templates
        """
        self.output_dir = Path(output_dir)
        self.template_dir = Path(template_dir)
        self.logger = logging.getLogger("ReportGenerator")
        
        # Create output directories
        self.json_dir = self.output_dir / "json"
        self.html_dir = self.output_dir / "html"
        self.pdf_dir = self.output_dir / "pdf"
        
        for directory in [self.json_dir, self.html_dir, self.pdf_dir]:
            os.makedirs(directory, exist_ok=True)
        
        # Initialize Gemini AI
        if gemini_api_key:
            genai.configure(api_key=gemini_api_key)
            self.gemini_model = genai.GenerativeModel('gemini-pro')
        else:
            self.gemini_model = None
            self.logger.warning("Gemini AI API key not provided. AI-enhanced reporting will be disabled.")
        
        # Initialize Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.template_dir)
        )

    async def process_findings(self, data: Dict[str, Any]) -> List[Finding]:
        """
        Process raw findings data into structured Finding objects
        
        Args:
            data: Raw findings data from various modules
        """
        findings = []
        
        # Process reconnaissance findings
        if "recon" in data:
            findings.extend(await self._process_recon_findings(data["recon"]))
        
        # Process vulnerability scan findings
        if "vulnerabilities" in data:
            findings.extend(await self._process_vuln_findings(data["vulnerabilities"]))
        
        # Process active testing findings
        if "active_testing" in data:
            findings.extend(await self._process_active_findings(data["active_testing"]))
        
        return findings

    async def _process_recon_findings(self, recon_data: Dict[str, Any]) -> List[Finding]:
        """Process reconnaissance findings"""
        findings = []
        
        # Process subdomain findings
        if "subdomains" in recon_data:
            findings.append(Finding(
                title="Subdomain Enumeration Results",
                description=f"Found {len(recon_data['subdomains'])} subdomains",
                severity=Severity.INFO,
                evidence=recon_data['subdomains'],
                remediation="Review and verify all discovered subdomains",
                references=[],
                category="Reconnaissance",
                timestamp=datetime.now().isoformat()
            ))
        
        # Process technology detection findings
        if "technologies" in recon_data:
            findings.append(Finding(
                title="Technology Stack Detection",
                description="Detected technologies and frameworks",
                severity=Severity.INFO,
                evidence=[f"{tech}: {version}" for tech, version in recon_data['technologies'].items()],
                remediation="Ensure all detected technologies are up to date",
                references=[],
                category="Reconnaissance",
                timestamp=datetime.now().isoformat()
            ))
        
        return findings

    async def _process_vuln_findings(self, vuln_data: Dict[str, Any]) -> List[Finding]:
        """Process vulnerability scan findings"""
        findings = []
        
        for vuln_type, vulns in vuln_data.items():
            for vuln in vulns:
                findings.append(Finding(
                    title=vuln.get('title', 'Unnamed Vulnerability'),
                    description=vuln.get('description', ''),
                    severity=Severity(vuln.get('severity', 'Medium')),
                    evidence=vuln.get('evidence', []),
                    remediation=vuln.get('remediation', ''),
                    references=vuln.get('references', []),
                    category=vuln_type,
                    timestamp=vuln.get('timestamp', datetime.now().isoformat())
                ))
        
        return findings

    async def _process_active_findings(self, active_data: Dict[str, Any]) -> List[Finding]:
        """Process active testing findings"""
        findings = []
        
        for test_type, tests in active_data.items():
            for test in tests:
                findings.append(Finding(
                    title=test.get('title', 'Active Test Finding'),
                    description=test.get('description', ''),
                    severity=Severity(test.get('severity', 'Medium')),
                    evidence=test.get('evidence', []),
                    remediation=test.get('remediation', ''),
                    references=test.get('references', []),
                    category=f"Active Testing - {test_type}",
                    timestamp=test.get('timestamp', datetime.now().isoformat())
                ))
        
        return findings

    async def generate_ai_enhanced_report(self, findings: List[Finding]) -> Dict[str, str]:
        """
        Generate AI-enhanced report sections using Gemini AI
        
        Args:
            findings: List of processed findings
        """
        if not self.gemini_model:
            return {}
        
        try:
            # Prepare findings summary for AI
            findings_summary = "\n".join([
                f"- {f.title} ({f.severity.value}): {f.description}"
                for f in findings
            ])
            
            # Generate executive summary
            exec_prompt = f"""
            As a security expert, provide a concise executive summary of the following security findings:
            
            {findings_summary}
            
            Focus on:
            1. Overall risk assessment
            2. Key vulnerabilities
            3. Critical recommendations
            
            Format the response in markdown.
            """
            
            exec_response = await self.gemini_model.generate_content(exec_prompt)
            
            # Generate remediation roadmap
            roadmap_prompt = f"""
            Create a prioritized remediation roadmap for the following security findings:
            
            {findings_summary}
            
            Include:
            1. Immediate actions (24-48 hours)
            2. Short-term fixes (1-2 weeks)
            3. Long-term improvements (1-3 months)
            
            Format the response in markdown.
            """
            
            roadmap_response = await self.gemini_model.generate_content(roadmap_prompt)
            
            return {
                "executive_summary": exec_response.text,
                "remediation_roadmap": roadmap_response.text
            }
            
        except Exception as e:
            self.logger.error(f"Error generating AI-enhanced report: {str(e)}")
            return {}

    async def generate_report(self, 
                            target: str,
                            data: Dict[str, Any],
                            formats: List[str] = ["json", "html", "pdf"]) -> Dict[str, Path]:
        """
        Generate comprehensive security report
        
        Args:
            target: Target that was tested
            data: All findings data
            formats: List of output formats
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_files = {}
        
        try:
            # Process findings
            findings = await self.process_findings(data)
            
            # Generate AI-enhanced sections
            ai_sections = await self.generate_ai_enhanced_report(findings)
            
            # Prepare report data
            report_data = {
                "target": target,
                "timestamp": timestamp,
                "findings": findings,
                "ai_enhanced": ai_sections,
                "statistics": {
                    "total_findings": len(findings),
                    "severity_counts": {
                        severity.value: len([f for f in findings if f.severity == severity])
                        for severity in Severity
                    }
                }
            }
            
            # Generate reports in requested formats
            if "json" in formats:
                json_file = self.json_dir / f"{target}_{timestamp}_report.json"
                with open(json_file, 'w') as f:
                    json.dump(report_data, f, indent=2, default=str)
                report_files["json"] = json_file
            
            if "html" in formats:
                template = self.jinja_env.get_template("report_template.html")
                html_content = template.render(**report_data)
                
                html_file = self.html_dir / f"{target}_{timestamp}_report.html"
                with open(html_file, 'w') as f:
                    f.write(html_content)
                report_files["html"] = html_file
            
            if "pdf" in formats:
                pdf_file = self.pdf_dir / f"{target}_{timestamp}_report.pdf"
                pdfkit.from_file(str(html_file), str(pdf_file))
                report_files["pdf"] = pdf_file
            
            self.logger.info(f"Report generation completed for {target}")
            return report_files
            
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            return report_files

if __name__ == "__main__":
    # Example usage
    async def main():
        generator = ReportGenerator(
            gemini_api_key="your_gemini_api_key_here"
        )
        
        # Example data
        data = {
            "recon": {
                "subdomains": ["sub1.example.com", "sub2.example.com"],
                "technologies": {"nginx": "1.18.0", "php": "7.4"}
            },
            "vulnerabilities": {
                "xss": [{
                    "title": "Reflected XSS",
                    "description": "Found XSS in search parameter",
                    "severity": "High",
                    "evidence": ["POC: <script>alert(1)</script>"],
                    "remediation": "Implement proper input validation",
                    "references": ["https://owasp.org/xss"]
                }]
            }
        }
        
        report_files = await generator.generate_report("example.com", data)
        print("Generated report files:", report_files)
    
    asyncio.run(main()) 