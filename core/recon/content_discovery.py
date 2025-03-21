import asyncio
import os
import json
import re
from typing import List, Set, Dict, Any, Optional, Tuple, Union
from pathlib import Path
import logging
from urllib.parse import urljoin, urlparse, parse_qs
import aiohttp
from bs4 import BeautifulSoup

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
        self.logger = logging.getLogger("ContentDiscovery")
        
        # Create output directories
        self.dirs_output = self.output_dir / "directories"
        self.urls_output = self.output_dir / "endpoints"
        self.params_output = self.output_dir / "parameters"
        self.tech_output = self.output_dir / "technologies"
        self.js_output = self.output_dir / "js_analysis"
        
        for directory in [self.dirs_output, self.urls_output, self.params_output, 
                          self.tech_output, self.js_output]:
            os.makedirs(directory, exist_ok=True)

    async def run_ffuf(self, target: str, wordlist: Optional[str] = None) -> Set[str]:
        """Run ffuf for directory enumeration"""
        if not wordlist:
            wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            
        output_file = self.dirs_output / f"{target.replace('://', '_').replace('/', '_')}_ffuf.json"
        
        try:
            cmd = f"ffuf -u {target}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403,405 -o {output_file} -of json"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            # Parse JSON output and extract paths
            if output_file.exists():
                results = json.loads(output_file.read_text())
                return {urljoin(target, result.get('url', '').replace('FUZZ', '')) 
                        for result in results.get('results', [])}
        except Exception as e:
            self.logger.error(f"Error running ffuf on {target}: {str(e)}")
        return set()

    async def run_gobuster(self, target: str, wordlist: Optional[str] = None) -> Set[str]:
        """Run gobuster for directory enumeration"""
        if not wordlist:
            wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            
        output_file = self.dirs_output / f"{target.replace('://', '_').replace('/', '_')}_gobuster.txt"
        
        try:
            cmd = f"gobuster dir -u {target} -w {wordlist} -o {output_file} -q"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if output_file.exists():
                return {line.split()[0] for line in output_file.read_text().splitlines() if line}
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

    async def analyze_js_files(self, target: str) -> List[Dict[str, Any]]:
        """
        Extract and analyze JavaScript files from a target
        
        Args:
            target: Target URL
        """
        results = []
        
        try:
            # Extract JS URLs
            js_urls = await self.extract_js_urls(target)
            self.logger.info(f"Found {len(js_urls)} JavaScript files on {target}")
            
            # Analyze each JS file
            for js_url in js_urls:
                analysis = await self.analyze_js_file(js_url)
                results.append(analysis)
            
            # Save results
            output_file = self.js_output / f"{target.replace('://', '_').replace('/', '_')}_js_analysis.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error analyzing JS files for {target}: {str(e)}")
        
        return results

    # Enhanced discovery for a single target
    async def discover_target(self, target: str) -> Dict[str, Any]:
        """
        Run comprehensive content discovery for a single target
        
        Args:
            target: Target domain or URL
        """
        self.logger.info(f"Starting comprehensive content discovery for {target}")
        results = {"target": target}
        
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
            results["endpoints"] = list(endpoints)
            
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