import asyncio
import os
import json
import re
from typing import List, Set, Dict, Any, Optional, Tuple, Union
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs
import aiohttp
from bs4 import BeautifulSoup
import concurrent.futures
from datetime import datetime
import tempfile

from core.utils.logger import get_logger, handle_exceptions

class ContentDiscovery:
    def __init__(self, subdomains: List[str], output_dir: str = "results"):
        """
        Initialize the ContentDiscovery with a list of subdomains
        
        Args:
            subdomains: List of subdomains to perform content discovery on
            output_dir: Directory to store results
        """
        self.subdomains = subdomains
        self.output_dir = Path(output_dir)
        self.logger = get_logger("ContentDiscovery")
        
        # Create output directories
        self.dirs_output = self.output_dir / "directories"
        self.urls_output = self.output_dir / "endpoints"
        self.params_output = self.output_dir / "parameters"
        self.tech_output = self.output_dir / "technologies"
        self.js_output = self.output_dir / "js_analysis"
        
        # Add new output directories for vulnerability scanning
        self.vuln_output = self.output_dir / "vulnerabilities"
        self.nuclei_output = self.vuln_output / "nuclei"
        self.jaeles_output = self.vuln_output / "jaeles"
        self.osmedeus_output = self.vuln_output / "osmedeus"
        
        try:
            for directory in [self.dirs_output, self.urls_output, self.params_output, 
                            self.tech_output, self.js_output, self.vuln_output, 
                            self.nuclei_output, self.jaeles_output, self.osmedeus_output]:
                os.makedirs(directory, exist_ok=True)
        except Exception as e:
            self.logger.error(f"Failed to create output directories: {str(e)}")
            raise

    @handle_exceptions()
    async def run_ffuf(self, target: str, wordlist: Optional[str] = None) -> Set[str]:
        """Run ffuf for directory enumeration"""
        if not wordlist:
            wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            
        output_file = self.dirs_output / f"{target.replace('://', '_').replace('/', '_')}_ffuf.json"
        
        try:
            self.logger.info(f"Starting ffuf scan on {target}")
            cmd = f"ffuf -u {target}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403,405 -o {output_file} -of json"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if stderr:
                self.logger.warning(f"ffuf stderr: {stderr.decode()}")
            
            # Parse JSON output and extract paths
            if output_file.exists():
                results = json.loads(output_file.read_text())
                discovered = {urljoin(target, result.get('url', '').replace('FUZZ', '')) 
                        for result in results.get('results', [])}
                self.logger.info(f"Found {len(discovered)} directories with ffuf")
                return discovered
        except Exception as e:
            self.logger.error(f"Error running ffuf on {target}: {str(e)}")
        return set()

    @handle_exceptions()
    async def run_gobuster(self, target: str, wordlist: Optional[str] = None) -> Set[str]:
        """Run gobuster for directory enumeration"""
        if not wordlist:
            wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            
        output_file = self.dirs_output / f"{target.replace('://', '_').replace('/', '_')}_gobuster.txt"
        
        try:
            self.logger.info(f"Starting gobuster scan on {target}")
            cmd = f"gobuster dir -u {target} -w {wordlist} -o {output_file} -q"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if stderr:
                self.logger.warning(f"gobuster stderr: {stderr.decode()}")
            
            if output_file.exists():
                discovered = {line.split()[0] for line in output_file.read_text().splitlines() if line}
                self.logger.info(f"Found {len(discovered)} directories with gobuster")
                return discovered
        except Exception as e:
            self.logger.error(f"Error running gobuster on {target}: {str(e)}")
        return set()

    async def run_waybackurls(self, target: str) -> Set[str]:
        """Run waybackurls for endpoint discovery"""
        output_file = self.urls_output / f"{target.replace('://', '_').replace('/', '_')}_wayback.txt"
        
        try:
            cmd = f"waybackurls {target} | tee {output_file}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if output_file.exists():
                return set(line.strip() for line in output_file.read_text().splitlines() if line.strip())
        except Exception as e:
            self.logger.error(f"Error running waybackurls on {target}: {str(e)}")
        return set()

    async def run_gau(self, target: str) -> Set[str]:
        """Run gau for endpoint discovery"""
        output_file = self.urls_output / f"{target.replace('://', '_').replace('/', '_')}_gau.txt"
        
        try:
            cmd = f"gau {target} | tee {output_file}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if output_file.exists():
                return set(line.strip() for line in output_file.read_text().splitlines() if line.strip())
        except Exception as e:
            self.logger.error(f"Error running gau on {target}: {str(e)}")
        return set()

    async def run_katana(self, target: str) -> Set[str]:
        """Run katana for endpoint discovery"""
        output_file = self.urls_output / f"{target.replace('://', '_').replace('/', '_')}_katana.txt"
        
        try:
            cmd = f"katana -u {target} -jc -o {output_file}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if output_file.exists():
                return set(output_file.read_text().splitlines())
        except Exception as e:
            self.logger.error(f"Error running katana on {target}: {str(e)}")
        return set()

    async def run_hakrawler(self, target: str) -> Set[str]:
        """Run hakrawler for endpoint discovery"""
        output_file = self.urls_output / f"{target.replace('://', '_').replace('/', '_')}_hakrawler.txt"
        
        try:
            cmd = f"echo {target} | hakrawler -depth 3 | tee {output_file}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if output_file.exists():
                return set(output_file.read_text().splitlines())
        except Exception as e:
            self.logger.error(f"Error running hakrawler on {target}: {str(e)}")
        return set()

    async def run_gospider(self, target: str) -> Set[str]:
        """Run gospider for endpoint discovery"""
        output_file = self.urls_output / f"{target.replace('://', '_').replace('/', '_')}_gospider.txt"
        
        try:
            cmd = f"gospider -s {target} -d 3 -o {output_file}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if output_file.exists():
                return set(output_file.read_text().splitlines())
        except Exception as e:
            self.logger.error(f"Error running gospider on {target}: {str(e)}")
        return set()

    # New parameter discovery methods
    async def run_paramspider(self, target: str) -> Dict[str, Set[str]]:
        """
        Run ParamSpider to discover URL parameters
        
        Args:
            target: Target domain
        """
        output_file = self.params_output / f"{target.replace('://', '_').replace('/', '_')}_paramspider.txt"
        
        try:
            cmd = f"python3 ParamSpider/paramspider.py -d {target} -o {output_file} --level high"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            parameters = {}
            if output_file.exists():
                urls = [line.strip() for line in output_file.read_text().splitlines() if line.strip()]
                for url in urls:
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    
                    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    if base_url not in parameters:
                        parameters[base_url] = set()
                    
                    for param in params.keys():
                        parameters[base_url].add(param)
            
            # Save processed parameters
            params_json = self.params_output / f"{target.replace('://', '_').replace('/', '_')}_parameters.json"
            with open(params_json, 'w') as f:
                # Convert sets to lists for JSON serialization
                serializable_params = {url: list(params) for url, params in parameters.items()}
                json.dump(serializable_params, f, indent=2)
            
            return parameters
        except Exception as e:
            self.logger.error(f"Error running ParamSpider on {target}: {str(e)}")
        return {}

    async def extract_parameters_from_urls(self, urls: Set[str]) -> Dict[str, Set[str]]:
        """
        Extract parameters from a set of URLs
        
        Args:
            urls: Set of URLs to analyze
        """
        parameters = {}
        
        for url in urls:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                
                if not params:
                    continue
                
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if base_url not in parameters:
                    parameters[base_url] = set()
                
                for param in params.keys():
                    parameters[base_url].add(param)
            except Exception as e:
                self.logger.error(f"Error extracting parameters from {url}: {str(e)}")
        
        return parameters

    # Technology detection methods
    async def run_wappalyzer(self, target: str) -> Dict[str, Any]:
        """
        Run Wappalyzer to identify technologies
        
        Args:
            target: Target URL
        """
        output_file = self.tech_output / f"{target.replace('://', '_').replace('/', '_')}_wappalyzer.json"
        
        try:
            cmd = f"wappalyzer {target} --pretty --recursive=1 > {output_file}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        return json.load(f)
                except json.JSONDecodeError:
                    self.logger.error(f"Error parsing Wappalyzer output for {target}")
        except Exception as e:
            self.logger.error(f"Error running Wappalyzer on {target}: {str(e)}")
        return {}

    async def detect_technologies(self, target: str) -> Dict[str, Any]:
        """
        Detect technologies using multiple methods
        
        Args:
            target: Target URL
        """
        technologies = {"url": target, "technologies": {}}
        
        # Method 1: Use Wappalyzer
        wappalyzer_result = await self.run_wappalyzer(target)
        if wappalyzer_result:
            technologies["wappalyzer"] = wappalyzer_result
        
        # Method 2: Analyze HTTP headers
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(target, timeout=10) as response:
                    headers = dict(response.headers)
                    technologies["headers"] = headers
                    
                    # Extract server info
                    if "Server" in headers:
                        technologies["technologies"]["server"] = headers["Server"]
                    
                    # Extract framework info
                    framework_headers = ["X-Powered-By", "X-AspNet-Version", "X-Rails-Version"]
                    for header in framework_headers:
                        if header in headers:
                            technologies["technologies"]["framework"] = headers[header]
        except Exception as e:
            self.logger.error(f"Error analyzing HTTP headers for {target}: {str(e)}")
        
        # Method 3: Analyze HTML content
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(target, timeout=10) as response:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Extract generator meta tag
                    generator = soup.find("meta", {"name": "generator"})
                    if generator and generator.get("content"):
                        technologies["technologies"]["generator"] = generator.get("content")
                    
                    # Extract JavaScript libraries
                    js_libraries = []
                    scripts = soup.find_all("script", {"src": True})
                    for script in scripts:
                        src = script.get("src")
                        for lib in ["jquery", "react", "vue", "angular", "bootstrap", "tailwind"]:
                            if lib in src.lower():
                                js_libraries.append(lib)
                    
                    if js_libraries:
                        technologies["technologies"]["js_libraries"] = list(set(js_libraries))
        except Exception as e:
            self.logger.error(f"Error analyzing HTML content for {target}: {str(e)}")
        
        # Save results
        output_file = self.tech_output / f"{target.replace('://', '_').replace('/', '_')}_technologies.json"
        with open(output_file, 'w') as f:
            json.dump(technologies, f, indent=2)
        
        return technologies

    # JavaScript analysis methods
    async def extract_js_urls(self, url: str) -> Set[str]:
        """
        Extract JavaScript URLs from a webpage
        
        Args:
            url: Target URL
        """
        js_urls = set()
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Extract script tags with src attribute
                    for script in soup.find_all("script", {"src": True}):
                        src = script.get("src")
                        if src:
                            # Handle relative URLs
                            if src.startswith("//"):
                                src = f"https:{src}"
                            elif src.startswith("/"):
                                src = urljoin(url, src)
                            elif not src.startswith(("http://", "https://")):
                                src = urljoin(url, src)
                            
                            js_urls.add(src)
        except Exception as e:
            self.logger.error(f"Error extracting JS URLs from {url}: {str(e)}")
        
        return js_urls

    async def analyze_js_file(self, js_url: str) -> Dict[str, Any]:
        """
        Analyze a JavaScript file for endpoints, secrets, and DOM sinks
        
        Args:
            js_url: URL of the JavaScript file
        """
        analysis = {
            "url": js_url,
            "endpoints": [],
            "secrets": [],
            "dom_sinks": [],
            "sensitive_functions": []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(js_url, timeout=10) as response:
                    content = await response.text()
                    
                    # Extract endpoints (URLs)
                    url_pattern = r'(?:"|\'|\`)((?:http|https)://[^/]+/[^\s\'"]*?)(?:"|\'|\`)'
                    endpoints = re.findall(url_pattern, content)
                    analysis["endpoints"] = list(set(endpoints))
                    
                    # Extract API endpoints
                    api_pattern = r'(?:"|\'|\`)(/?api/[^\s\'"]*?)(?:"|\'|\`)'
                    api_endpoints = re.findall(api_pattern, content)
                    analysis["endpoints"].extend(list(set(api_endpoints)))
                    
                    # Extract secrets (API keys, tokens)
                    secret_patterns = {
                        "aws_access_key": r"AKIA[0-9A-Z]{16}",
                        "aws_secret": r"[0-9a-zA-Z/+]{40}",
                        "google_api": r"AIza[0-9A-Za-z\-_]{35}",
                        "firebase": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
                        "github_token": r"ghp_[0-9a-zA-Z]{36}",
                        "jwt_token": r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"
                    }
                    
                    for key_type, pattern in secret_patterns.items():
                        matches = re.findall(pattern, content)
                        if matches:
                            for match in matches:
                                analysis["secrets"].append({"type": key_type, "value": match})
                    
                    # Extract DOM sink functions (potential XSS)
                    dom_sinks = [
                        "document.write", "innerHTML", "outerHTML", 
                        "insertAdjacentHTML", "eval", "setTimeout", 
                        "setInterval", "location.href", "location.replace"
                    ]
                    
                    for sink in dom_sinks:
                        if sink in content:
                            # Get context around the sink (50 chars before and after)
                            positions = [m.start() for m in re.finditer(re.escape(sink), content)]
                            for pos in positions:
                                start = max(0, pos - 50)
                                end = min(len(content), pos + len(sink) + 50)
                                context = content[start:end]
                                analysis["dom_sinks"].append({"sink": sink, "context": context})
                    
                    # Extract sensitive function calls
                    sensitive_functions = [
                        "fetch", "XMLHttpRequest", "ajax", "axios", 
                        "localStorage", "sessionStorage", "setCookie"
                    ]
                    
                    for func in sensitive_functions:
                        if func in content:
                            analysis["sensitive_functions"].append(func)
        except Exception as e:
            self.logger.error(f"Error analyzing JS file {js_url}: {str(e)}")
        
        return analysis

    async def analyze_js_files(self, target: str) -> Dict[str, Any]:
        """
        Comprehensive JavaScript analysis:
        1. Extract JS files using subjs
        2. Validate JS URLs using httpx
        3. Extract endpoints using LinkFinder
        4. Scan for exposed tokens using nuclei
        5. Generate wordlist from JS content
        
        Args:
            target: Target URL or domain
        """
        results = {
            "js_files": [],
            "endpoints": [],
            "tokens": [],
            "wordlist": set(),
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # Step 1: Extract JS files using subjs
            js_files_output = self.js_output / f"{target.replace('://', '_')}_js_files.txt"
            cmd = [
                "subjs",
                "-u", target,
                "-o", str(js_files_output)
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if not js_files_output.exists():
                self.logger.warning(f"No JavaScript files found for {target}")
                return results
            
            # Step 2: Validate JS URLs using httpx
            valid_js_output = self.js_output / f"{target.replace('://', '_')}_valid_js.txt"
            cmd = [
                "httpx",
                "-l", str(js_files_output),
                "-mc", "200",
                "-o", str(valid_js_output),
                "-silent"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            # Read valid JS files
            if valid_js_output.exists():
                with open(valid_js_output) as f:
                    results["js_files"] = [line.strip() for line in f if line.strip()]
            
            # Step 3: Extract endpoints using LinkFinder
            for js_url in results["js_files"]:
                endpoints_output = self.js_output / f"{js_url.replace('://', '_').replace('/', '_')}_endpoints.txt"
                cmd = [
                    "python3",
                    "LinkFinder/linkfinder.py",
                    "-i", js_url,
                    "-o", str(endpoints_output),
                    "-d"
                ]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
                
                if endpoints_output.exists():
                    with open(endpoints_output) as f:
                        endpoints = [line.strip() for line in f if line.strip()]
                        results["endpoints"].extend(endpoints)
            
            # Step 4: Scan for exposed tokens using nuclei
            tokens_output = self.js_output / f"{target.replace('://', '_')}_tokens.json"
            cmd = [
                "nuclei",
                "-l", str(valid_js_output),
                "-t", "nuclei-templates/exposures/tokens/",
                "-json",
                "-o", str(tokens_output),
                "-silent"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if tokens_output.exists():
                with open(tokens_output) as f:
                    for line in f:
                        try:
                            finding = json.loads(line)
                            results["tokens"].append(finding)
                        except json.JSONDecodeError:
                            continue
            
            # Step 5: Generate wordlist from JS content
            wordlist_output = self.js_output / f"{target.replace('://', '_')}_wordlist.txt"
            
            # Download and process each JS file
            async with aiohttp.ClientSession() as session:
                for js_url in results["js_files"]:
                    try:
                        async with session.get(js_url) as response:
                            if response.status == 200:
                                js_content = await response.text()
                                
                                # Extract words using regex (basic implementation)
                                # You might want to create a separate script for more sophisticated parsing
                                words = set(re.findall(r'\b\w+\b', js_content))
                                results["wordlist"].update(words)
                    except Exception as e:
                        self.logger.error(f"Error downloading {js_url}: {str(e)}")
            
            # Save wordlist to file
            with open(wordlist_output, 'w') as f:
                for word in sorted(results["wordlist"]):
                    f.write(f"{word}\n")
            
            # Save complete results
            complete_results = self.js_output / f"{target.replace('://', '_')}_complete_js_analysis.json"
            with open(complete_results, 'w') as f:
                # Convert set to list for JSON serialization
                results["wordlist"] = list(results["wordlist"])
                json.dump(results, f, indent=2)
            
            self.logger.info(f"JavaScript analysis completed for {target}")
            self.logger.info(f"Found {len(results['js_files'])} JS files, {len(results['endpoints'])} endpoints, "
                            f"{len(results['tokens'])} potential tokens, and {len(results['wordlist'])} unique words")
            
        except Exception as e:
            self.logger.error(f"Error during JavaScript analysis for {target}: {str(e)}")
        
        return results

    async def filter_endpoints_by_pattern(self, endpoints: Set[str]) -> Dict[str, Set[str]]:
        """
        Filter endpoints using gf patterns for different vulnerability types
        
        Args:
            endpoints: Set of endpoints to filter
        Returns:
            Dictionary of vulnerability type to matching endpoints
        """
        patterns = {
            "xss": "xss",
            "ssrf": "ssrf",
            "ssti": "ssti",
            "open-redirect": "redirect",
            "rce": "rce",
            "lfi": "lfi",
            "sqli": "sqli",
            "debug-pages": "debug-pages",
            "idor": "idor",
            "interestingparams": "interestingparams"
        }
        
        results = {}
        
        try:
            # Create temporary file with all endpoints
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
                temp_file.write('\n'.join(endpoints))
                temp_path = temp_file.name
            
            # Run gf with each pattern
            for vuln_type, pattern in patterns.items():
                cmd = f"cat {temp_path} | gf {pattern}"
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await process.communicate()
                
                # Store matching endpoints
                matching_endpoints = set(line.strip() for line in stdout.decode().splitlines() if line.strip())
                if matching_endpoints:
                    results[vuln_type] = matching_endpoints
                    
                    # Save to separate files for reference
                    pattern_file = self.urls_output / f"{vuln_type}_endpoints.txt"
                    with open(pattern_file, 'w') as f:
                        f.write('\n'.join(sorted(matching_endpoints)))
            
            # Cleanup temporary file
            os.unlink(temp_path)
            
        except Exception as e:
            self.logger.error(f"Error filtering endpoints with gf: {str(e)}")
        
        return results

    # Modify discover_target method to include vulnerability pattern matching
    async def discover_target(self, target: str) -> Dict[str, Any]:
        """
        Run comprehensive content discovery for a single target
        
        Args:
            target: Target domain or URL
        """
        self.logger.info(f"Starting comprehensive content discovery for {target}")
        results = {
            "target": target,
            "timestamp": datetime.now().isoformat()
        }
        
        # Normalize target
        if not target.startswith(('http://', 'https://')):
            domain = target
            http_target = f"http://{target}"
            https_target = f"https://{target}"
        else:
            parsed = urlparse(target)
            domain = parsed.netloc
            http_target = target if target.startswith('http://') else target.replace('https://', 'http://')
            https_target = target if target.startswith('https://') else target.replace('http://', 'https://')
        
        try:
            # Run directory enumeration
            dir_tasks = [
                self.run_ffuf(http_target),
                self.run_ffuf(https_target),
                self.run_gobuster(http_target),
                self.run_gobuster(https_target)
            ]
            
            # Run endpoint discovery
            endpoint_tasks = [
                self.run_waybackurls(domain),
                self.run_gau(domain),
                self.run_katana(http_target),
                self.run_hakrawler(http_target),
                self.run_gospider(http_target)
            ]
            
            # Run parameter discovery
            param_task = self.run_paramspider(domain)
            
            # Run technology detection
            tech_task = self.detect_technologies(https_target)
            
            # Run JavaScript analysis
            js_task = self.analyze_js_files(https_target)
            
            # Await all tasks
            dir_results = await asyncio.gather(*dir_tasks)
            endpoint_results = await asyncio.gather(*endpoint_tasks)
            param_results = await param_task
            tech_results = await tech_task
            js_results = await js_task
            
            # Combine directory results
            directories = set()
            for result in dir_results:
                directories.update(result)
            results["directories"] = list(directories)
            
            # Combine endpoint results
            endpoints = set()
            for result in endpoint_results:
                endpoints.update(result)
            
            # Add JS endpoints to the mix
            if js_results and "endpoints" in js_results:
                endpoints.update(js_results["endpoints"])
            
            results["endpoints"] = list(endpoints)
            
            # Filter endpoints by vulnerability patterns
            vuln_endpoints = await self.filter_endpoints_by_pattern(endpoints)
            results["vulnerability_endpoints"] = {
                vuln_type: list(endpoints) 
                for vuln_type, endpoints in vuln_endpoints.items()
            }
            
            # Extract additional parameters from endpoints
            additional_params = await self.extract_parameters_from_urls(endpoints)
            
            # Merge parameter results
            all_params = {}
            for base_url, params in param_results.items():
                all_params[base_url] = params
            
            for base_url, params in additional_params.items():
                if base_url in all_params:
                    all_params[base_url].update(params)
                else:
                    all_params[base_url] = params
            
            # Convert sets to lists for JSON serialization
            serializable_params = {url: list(params) for url, params in all_params.items()}
            results["parameters"] = serializable_params
            
            # Add technology detection results
            results["technologies"] = tech_results
            
            # Add JavaScript analysis results
            results["js_analysis"] = js_results
            
            # Save combined results
            output_file = self.output_dir / f"{domain}_content_discovery.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.logger.info(f"Content discovery completed for {target}")
            self.logger.info("Vulnerability pattern matches found:")
            for vuln_type, vuln_endpoints in results["vulnerability_endpoints"].items():
                self.logger.info(f"- {vuln_type}: {len(vuln_endpoints)} endpoints")
            
        except Exception as e:
            self.logger.error(f"Error during content discovery for {target}: {str(e)}")
        
        return results

    # Original method with enhanced functionality
    async def discover_content(self) -> Tuple[Set[str], Set[str], Dict[str, Dict[str, Any]]]:
        """
        Run all content discovery methods in parallel for all subdomains
        Returns tuple of (directories, endpoints, comprehensive_results)
        
        This maintains backwards compatibility with the original API
        """
        directories = set()
        endpoints = set()
        comprehensive_results = {}
        
        for subdomain in self.subdomains:
            # Run comprehensive discovery for each subdomain
            result = await self.discover_target(subdomain)
            comprehensive_results[subdomain] = result
            
            # Add to the combined results
            if "directories" in result:
                directories.update(result["directories"])
            if "endpoints" in result:
                endpoints.update(result["endpoints"])
        
        # Save combined results (for compatibility)
        directories_file = self.output_dir / "all_directories.txt"
        endpoints_file = self.output_dir / "all_endpoints.txt"
        
        directories_file.write_text("\n".join(sorted(directories)))
        endpoints_file.write_text("\n".join(sorted(endpoints)))
        
        # Save comprehensive results
        comprehensive_file = self.output_dir / "comprehensive_results.json"
        with open(comprehensive_file, 'w') as f:
            json.dump(comprehensive_results, f, indent=2)
        
        return directories, endpoints, comprehensive_results

    async def run_nuclei_scan(self, target: str, tech_info: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run Nuclei vulnerability scan with technology-specific templates
        
        Args:
            target: Target URL or domain
            tech_info: Technology information from detect_technologies()
        """
        results = {"target": target, "findings": []}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.nuclei_output / f"{target.replace('://', '_').replace('/', '_')}_{timestamp}.json"
        
        try:
            # Base templates to always run
            template_args = [
                "-t", "nuclei-templates/cves/",
                "-t", "nuclei-templates/vulnerabilities/",
                "-t", "nuclei-templates/exposures/"
            ]
            
            # Add technology-specific templates if available
            if tech_info and "technologies" in tech_info:
                tech_templates = []
                
                # Map technologies to template directories
                tech_mapping = {
                    "wordpress": ["cms/wordpress/", "vulnerabilities/wordpress/"],
                    "joomla": ["cms/joomla/"],
                    "drupal": ["cms/drupal/"],
                    "apache": ["http/apache/"],
                    "nginx": ["http/nginx/"],
                    "php": ["vulnerabilities/php/"],
                    "java": ["vulnerabilities/java/"],
                    "node.js": ["vulnerabilities/nodejs/"],
                    "python": ["vulnerabilities/python/"],
                    "laravel": ["vulnerabilities/laravel/"],
                    "spring": ["vulnerabilities/spring/"]
                }
                
                for tech, templates in tech_mapping.items():
                    if any(tech.lower() in t.lower() for t in tech_info["technologies"]):
                        for template in templates:
                            tech_templates.extend(["-t", f"nuclei-templates/{template}"])
                
                template_args.extend(tech_templates)
            
            # Construct and run Nuclei command
            cmd = [
                "nuclei",
                "-u", target,
                "-json",
                "-o", str(output_file),
                "-c", "50",
                "-rate-limit", "150",
                "-severity", "critical,high,medium",
                "-metrics",
                "-silent"
            ]
            cmd.extend(template_args)
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            # Parse results
            if output_file.exists():
                with open(output_file) as f:
                    for line in f:
                        try:
                            finding = json.loads(line)
                            results["findings"].append(finding)
                        except json.JSONDecodeError:
                            continue
            
            self.logger.info(f"Nuclei scan completed for {target}. Found {len(results['findings'])} vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"Error running Nuclei scan on {target}: {str(e)}")
        
        return results

    async def run_jaeles_scan(self, target: str, tech_info: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run Jaeles vulnerability scan
        
        Args:
            target: Target URL or domain
            tech_info: Technology information from detect_technologies()
        """
        results = {"target": target, "findings": []}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = self.jaeles_output / f"{target.replace('://', '_').replace('/', '_')}_{timestamp}"
        
        try:
            # Create target-specific output directory
            os.makedirs(output_dir, exist_ok=True)
            
            # Base signatures to use
            signature_args = ["-s", "common", "-s", "cves"]
            
            # Add technology-specific signatures if available
            if tech_info and "technologies" in tech_info:
                tech_signatures = []
                tech_mapping = {
                    "wordpress": ["cms/wordpress"],
                    "joomla": ["cms/joomla"],
                    "drupal": ["cms/drupal"],
                    "apache": ["http/apache"],
                    "nginx": ["http/nginx"],
                    "php": ["languages/php"],
                    "java": ["languages/java"],
                    "node.js": ["languages/nodejs"]
                }
                
                for tech, sigs in tech_mapping.items():
                    if any(tech.lower() in t.lower() for t in tech_info["technologies"]):
                        for sig in sigs:
                            tech_signatures.extend(["-s", sig])
                
                signature_args.extend(tech_signatures)
            
            # Construct and run Jaeles command
            cmd = [
                "jaeles",
                "scan",
                "-u", target,
                "-o", str(output_dir),
                "-v",
                "--chunk", "50",
                "--timeout", "20",
                "--retry", "2"
            ]
            cmd.extend(signature_args)
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            # Parse results
            summary_file = output_dir / "jaeles-summary.txt"
            if summary_file.exists():
                with open(summary_file) as f:
                    for line in f:
                        if line.strip():
                            results["findings"].append(json.loads(line))
            
            self.logger.info(f"Jaeles scan completed for {target}. Found {len(results['findings'])} vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"Error running Jaeles scan on {target}: {str(e)}")
        
        return results

    async def run_osmedeus_scan(self, target: str) -> Dict[str, Any]:
        """
        Run Osmedeus for comprehensive reconnaissance
        
        Args:
            target: Target domain
        """
        results = {"target": target, "status": "failed"}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        workspace = self.osmedeus_output / f"{target.replace('.', '_')}_{timestamp}"
        
        try:
            # Create workspace directory
            os.makedirs(workspace, exist_ok=True)
            
            # Run Osmedeus scan
            cmd = [
                "osmedeus",
                "scan",
                "-t", target,
                "-w", str(workspace),
                "--format", "json"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            # Check if scan completed successfully
            if process.returncode == 0:
                results["status"] = "completed"
                results["workspace"] = str(workspace)
                
                # Try to parse summary report if available
                summary_file = workspace / "summary.json"
                if summary_file.exists():
                    with open(summary_file) as f:
                        results["summary"] = json.load(f)
            
            self.logger.info(f"Osmedeus scan completed for {target}. Results saved to {workspace}")
            
        except Exception as e:
            self.logger.error(f"Error running Osmedeus scan on {target}: {str(e)}")
        
        return results

    async def run_vulnerability_scans(self, target: str, tech_info: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run all vulnerability scans for a target
        
        Args:
            target: Target URL or domain
            tech_info: Technology information from detect_technologies()
        """
        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "nuclei": None,
            "jaeles": None,
            "osmedeus": None
        }
        
        try:
            # Run Nuclei and Jaeles concurrently
            nuclei_task = self.run_nuclei_scan(target, tech_info)
            jaeles_task = self.run_jaeles_scan(target, tech_info)
            
            # Wait for both scans to complete
            results["nuclei"], results["jaeles"] = await asyncio.gather(
                nuclei_task,
                jaeles_task
            )
            
            # Run Osmedeus if target is a domain (not a full URL)
            if not target.startswith(('http://', 'https://')):
                results["osmedeus"] = await self.run_osmedeus_scan(target)
            
            # Save combined results
            output_file = self.vuln_output / f"{target.replace('://', '_').replace('/', '_')}_vulnerabilities.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Error running vulnerability scans for {target}: {str(e)}")
        
        return results

    async def run_comprehensive_scan(self, target: str) -> Dict[str, Any]:
        """
        Run a comprehensive, phased security scan:
        1. Content discovery
        2. Technology detection
        3. Targeted vulnerability scanning
        
        Args:
            target: Target URL or domain
        """
        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "phases": {}
        }
        
        try:
            # Phase 1: Content Discovery
            self.logger.info(f"Phase 1: Content Discovery for {target}")
            discovery_results = await self.discover_target(target)
            results["phases"]["content_discovery"] = discovery_results
            
            # Phase 2: Technology Detection
            self.logger.info(f"Phase 2: Technology Detection for {target}")
            tech_info = await self.detect_technologies(target)
            results["phases"]["technology_detection"] = tech_info
            
            # Phase 3: Initial Nuclei Scan (quick templates)
            self.logger.info(f"Phase 3: Initial Vulnerability Scan for {target}")
            quick_templates = [
                "-t", "nuclei-templates/exposures/",
                "-t", "nuclei-templates/misconfiguration/",
                "-t", "nuclei-templates/default-logins/"
            ]
            initial_nuclei = await self.run_nuclei_scan(target, tech_info, quick_templates)
            results["phases"]["initial_nuclei"] = initial_nuclei
            
            # Phase 4: Deep Vulnerability Scan (based on technology)
            self.logger.info(f"Phase 4: Deep Vulnerability Scan for {target}")
            vuln_results = await self.run_vulnerability_scans(target, tech_info)
            results["phases"]["vulnerability_scan"] = vuln_results
            
            # Phase 5: Targeted Scanning (based on discoveries)
            self.logger.info(f"Phase 5: Targeted Scanning for {target}")
            
            # If JS analysis found sensitive endpoints, scan them with specific templates
            if "js_analysis" in discovery_results and "endpoints" in discovery_results["js_analysis"]:
                js_endpoints = discovery_results["js_analysis"]["endpoints"]
                if js_endpoints:
                    endpoints_file = self.output_dir / f"{target}_js_endpoints.txt"
                    with open(endpoints_file, "w") as f:
                        f.write("\n".join(js_endpoints))
                    
                    # Run targeted scan on JS endpoints
                    await self.run_nuclei_scan_on_list(endpoints_file, "js_endpoints")
            
            # If vulnerability patterns were found, scan those endpoints
            if "vulnerability_endpoints" in discovery_results:
                for vuln_type, endpoints in discovery_results["vulnerability_endpoints"].items():
                    if endpoints:
                        endpoints_file = self.output_dir / f"{target}_{vuln_type}_endpoints.txt"
                        with open(endpoints_file, "w") as f:
                            f.write("\n".join(endpoints))
                        
                        # Run specific template based on vulnerability type
                        template_mapping = {
                            "xss": ["vulnerabilities/generic/xss.yaml"],
                            "ssrf": ["vulnerabilities/generic/ssrf.yaml"],
                            "sqli": ["vulnerabilities/generic/sqli.yaml"],
                            "lfi": ["vulnerabilities/generic/lfi.yaml"]
                        }
                        
                        templates = template_mapping.get(vuln_type, ["vulnerabilities/generic/"])
                        await self.run_nuclei_scan_on_list(endpoints_file, vuln_type, templates)
            
            # Save combined results
            output_file = self.output_dir / f"{target.replace('://', '_').replace('/', '_')}_comprehensive.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.logger.info(f"Comprehensive scan completed for {target}")
            
        except Exception as e:
            self.logger.error(f"Error during comprehensive scan for {target}: {str(e)}")
        
        return results 