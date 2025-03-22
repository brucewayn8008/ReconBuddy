import asyncio
import json
import logging
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
import aiohttp
from datetime import datetime
from core.recon.content_discovery import ContentDiscovery

class BurpAutomation:
    def __init__(self, api_key: str, burp_url: str = "http://localhost:1337"):
        """
        Initialize Burp Suite automation module
        
        Args:
            api_key: Burp Suite API key
            burp_url: URL where Burp Suite API is running
        """
        self.burp_url = burp_url
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        self.logger = logging.getLogger("BurpAutomation")
        
        # Default scan configurations
        self.default_scan_config = {
            "scan_configurations": ["Lightweight scan"],
            "scope": {
                "include": [],
                "exclude": []
            },
            "application_login": None,
            "scan_rate": "normal",
            "scan_recursion": "site_map_and_descendants"
        }
        
        # Default project options
        self.default_project_options = {
            "scope": {
                "include": [],
                "exclude": []
            },
            "target": {
                "scope_option": "suite",
                "max_redirects": 10
            },
            "sessions": {
                "cookie_jar": True,
                "session_handling_rules": []
            }
        }

        # Default crawl options
        self.default_crawl_config = {
            "scope": {
                "include_patterns": [],
                "exclude_patterns": []
            },
            "max_depth": 10,
            "request_delay": 100,  # milliseconds
            "respect_robots": True,
            "handle_parameters": True,
            "follow_redirects": True,
            "max_children": 100
        }
        
    async def send_request(self, 
                          url: str, 
                          method: str = "GET",
                          headers: Dict[str, str] = None,
                          params: Dict[str, str] = None,
                          data: Any = None,
                          cookies: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Send a request through Burp Suite
        
        Args:
            url: Target URL
            method: HTTP method
            headers: Custom headers
            params: URL parameters
            data: Request body
            cookies: Request cookies
        """
        try:
            request_data = {
                "url": url,
                "method": method,
                "headers": headers or {},
                "params": params or {},
                "body": data,
                "cookies": cookies or {}
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.burp_url}/v1/send_request",
                    headers=self.headers,
                    json=request_data
                ) as response:
                    return await response.json()
                    
        except Exception as e:
            self.logger.error(f"Error sending request through Burp: {str(e)}")
            return {"error": str(e)}

    async def active_scan(self, 
                         url: str,
                         scan_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Start an active scan
        
        Args:
            url: Target URL
            scan_config: Scan configuration options
        """
        try:
            config = scan_config or {
                "scan_configurations": ["Lightweight scan"],
                "scope": {
                    "include": [{"rule": url}],
                    "exclude": []
                }
            }
            
            async with aiohttp.ClientSession() as session:
                # Start scan
                async with session.post(
                    f"{self.burp_url}/v1/scan",
                    headers=self.headers,
                    json={"url": url, "config": config}
                ) as response:
                    scan_id = (await response.json())["scan_id"]
                    
                # Poll for results
                while True:
                    async with session.get(
                        f"{self.burp_url}/v1/scan/{scan_id}",
                        headers=self.headers
                    ) as response:
                        status = await response.json()
                        if status["scan_status"] == "completed":
                            return status
                        await asyncio.sleep(10)
                        
        except Exception as e:
            self.logger.error(f"Error during active scan: {str(e)}")
            return {"error": str(e)}

    async def parameter_tampering(self,
                                url: str,
                                params: Dict[str, str],
                                payloads: List[str]) -> Dict[str, Any]:
        """
        Test parameter tampering
        
        Args:
            url: Target URL
            params: Original parameters
            payloads: List of payloads to test
        """
        results = []
        
        try:
            for param_name, param_value in params.items():
                for payload in payloads:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    response = await self.send_request(
                        url=url,
                        params=test_params
                    )
                    
                    results.append({
                        "parameter": param_name,
                        "payload": payload,
                        "response": response
                    })
            
            return {"results": results}
            
        except Exception as e:
            self.logger.error(f"Error during parameter tampering: {str(e)}")
            return {"error": str(e)}

    async def replay_request(self,
                           request_file: str,
                           modifications: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Replay a saved request with optional modifications
        
        Args:
            request_file: Path to saved request file
            modifications: Changes to make to the request
        """
        try:
            with open(request_file) as f:
                request_data = json.load(f)
            
            if modifications:
                # Apply modifications to request
                for key, value in modifications.items():
                    if key in request_data:
                        request_data[key] = value
            
            return await self.send_request(**request_data)
            
        except Exception as e:
            self.logger.error(f"Error replaying request: {str(e)}")
            return {"error": str(e)}

    async def create_custom_scan_config(self, 
                                      name: str,
                                      config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a custom scan configuration
        
        Args:
            name: Name of the scan configuration
            config: Scan configuration settings
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.burp_url}/v1/scan_configs",
                    headers=self.headers,
                    json={
                        "name": name,
                        "config": config
                    }
                ) as response:
                    return await response.json()
                    
        except Exception as e:
            self.logger.error(f"Error creating scan configuration: {str(e)}")
            return {"error": str(e)}

    async def get_scan_configs(self) -> Dict[str, Any]:
        """Get all available scan configurations"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.burp_url}/v1/scan_configs",
                    headers=self.headers
                ) as response:
                    return await response.json()
                    
        except Exception as e:
            self.logger.error(f"Error getting scan configurations: {str(e)}")
            return {"error": str(e)}

    async def update_project_options(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update project-wide options
        
        Args:
            options: Project options to update
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.put(
                    f"{self.burp_url}/v1/project_options",
                    headers=self.headers,
                    json=options
                ) as response:
                    return await response.json()
                    
        except Exception as e:
            self.logger.error(f"Error updating project options: {str(e)}")
            return {"error": str(e)}

    async def create_scan_profile(self,
                                name: str,
                                scan_config: Dict[str, Any] = None,
                                project_options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Create a complete scan profile with custom configurations and options
        
        Args:
            name: Profile name
            scan_config: Custom scan configuration
            project_options: Custom project options
        """
        try:
            # Merge with default configurations
            final_scan_config = {**self.default_scan_config, **(scan_config or {})},
            final_project_options = {**self.default_project_options, **(project_options or {})}
            
            profile = {
                "name": name,
                "scan_config": final_scan_config,
                "project_options": final_project_options
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.burp_url}/v1/scan_profiles",
                    headers=self.headers,
                    json=profile
                ) as response:
                    return await response.json()
                    
        except Exception as e:
            self.logger.error(f"Error creating scan profile: {str(e)}")
            return {"error": str(e)}

    async def run_custom_scan(self,
                            url: str,
                            scan_profile: str = None,
                            scan_config: Dict[str, Any] = None,
                            project_options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run a custom scan with specific profile or configurations
        
        Args:
            url: Target URL
            scan_profile: Name of existing scan profile to use
            scan_config: Custom scan configuration
            project_options: Custom project options
        """
        try:
            if scan_profile:
                # Use existing profile
                config = {"profile": scan_profile}
            else:
                # Create custom configuration
                config = {
                    "scan_config": {**self.default_scan_config, **(scan_config or {})},
                    "project_options": {**self.default_project_options, **(project_options or {})}
                }
            
            # Add target URL to scope
            config["scan_config"]["scope"]["include"].append({"rule": url})
            
            # Start scan
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.burp_url}/v1/scan",
                    headers=self.headers,
                    json={"url": url, "config": config}
                ) as response:
                    scan_id = (await response.json())["scan_id"]
                
                # Poll for results with more detailed status
                while True:
                    async with session.get(
                        f"{self.burp_url}/v1/scan/{scan_id}/status",
                        headers=self.headers
                    ) as response:
                        status = await response.json()
                        
                        if status["scan_status"] == "completed":
                            # Get detailed results
                            async with session.get(
                                f"{self.burp_url}/v1/scan/{scan_id}/report",
                                headers=self.headers
                            ) as report_response:
                                return await report_response.json()
                        
                        # Log progress
                        self.logger.info(f"Scan progress: {status.get('scan_metrics', {}).get('progress', 0)}%")
                        await asyncio.sleep(10)
                        
        except Exception as e:
            self.logger.error(f"Error running custom scan: {str(e)}")
            return {"error": str(e)}

    async def run_crawler(self, 
                         url: str,
                         crawl_config: Dict[str, Any] = None,
                         content_discovery_results: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run Burp Suite crawler with optional ContentDiscovery integration
        
        Args:
            url: Target URL
            crawl_config: Custom crawl configuration
            content_discovery_results: Results from ContentDiscovery module
        """
        try:
            # Merge with default crawl config
            config = {**self.default_crawl_config, **(crawl_config or {})}
            
            # Start crawler
            async with aiohttp.ClientSession() as session:
                # Initialize crawl
                async with session.post(
                    f"{self.burp_url}/v1/crawler",
                    headers=self.headers,
                    json={
                        "url": url,
                        "config": config
                    }
                ) as response:
                    crawl_id = (await response.json())["crawl_id"]
                
                # If we have ContentDiscovery results, add them to the crawler
                if content_discovery_results:
                    endpoints_to_crawl = set()
                    
                    # Add discovered endpoints
                    if "endpoints" in content_discovery_results:
                        endpoints_to_crawl.update(content_discovery_results["endpoints"])
                    
                    # Add discovered directories
                    if "directories" in content_discovery_results:
                        endpoints_to_crawl.update(content_discovery_results["directories"])
                    
                    # Add discovered parameters
                    if "parameters" in content_discovery_results:
                        for base_url, params in content_discovery_results["parameters"].items():
                            endpoints_to_crawl.add(base_url)
                            # Add URLs with parameters
                            for param in params:
                                endpoints_to_crawl.add(f"{base_url}?{param}=fuzz")
                    
                    # Add endpoints to crawler queue
                    for endpoint in endpoints_to_crawl:
                        if endpoint.startswith(url):  # Only add in-scope endpoints
                            try:
                                await session.post(
                                    f"{self.burp_url}/v1/crawler/{crawl_id}/queue",
                                    headers=self.headers,
                                    json={"url": endpoint}
                                )
                            except Exception as e:
                                self.logger.error(f"Error adding endpoint to crawler queue: {str(e)}")
                
                # Poll for crawl status and results
                results = {
                    "crawl_id": crawl_id,
                    "status": "running",
                    "discovered_urls": set(),
                    "forms": [],
                    "parameters": set(),
                    "javascript_files": set()
                }
                
                while results["status"] == "running":
                    async with session.get(
                        f"{self.burp_url}/v1/crawler/{crawl_id}/status",
                        headers=self.headers
                    ) as status_response:
                        status = await status_response.json()
                        
                        if status["status"] == "completed":
                            results["status"] = "completed"
                            
                            # Get final results
                            async with session.get(
                                f"{self.burp_url}/v1/crawler/{crawl_id}/results",
                                headers=self.headers
                            ) as results_response:
                                crawl_results = await results_response.json()
                                
                                # Process results
                                for item in crawl_results.get("items", []):
                                    if item.get("type") == "url":
                                        results["discovered_urls"].add(item["url"])
                                    elif item.get("type") == "form":
                                        results["forms"].append(item)
                                    elif item.get("type") == "parameter":
                                        results["parameters"].add(
                                            f"{item['url']}:{item['parameter']}"
                                        )
                                    elif item.get("type") == "javascript":
                                        results["javascript_files"].add(item["url"])
                        
                        # Log progress
                        self.logger.info(
                            f"Crawl progress: {status.get('progress', 0)}% - "
                            f"URLs: {len(results['discovered_urls'])}, "
                            f"Forms: {len(results['forms'])}, "
                            f"Parameters: {len(results['parameters'])}, "
                            f"JS Files: {len(results['javascript_files'])}"
                        )
                        
                        await asyncio.sleep(10)
                
                # Convert sets to lists for JSON serialization
                results["discovered_urls"] = list(results["discovered_urls"])
                results["parameters"] = list(results["parameters"])
                results["javascript_files"] = list(results["javascript_files"])
                
                return results
                
        except Exception as e:
            self.logger.error(f"Error during crawling: {str(e)}")
            return {"error": str(e)}

    async def run_comprehensive_scan(self,
                                  url: str,
                                  scan_profile: str = None,
                                  crawl_first: bool = True) -> Dict[str, Any]:
        """
        Run a comprehensive scan including crawling and active scanning
        
        Args:
            url: Target URL
            scan_profile: Name of existing scan profile to use
            crawl_first: Whether to crawl before scanning
        """
        results = {
            "target": url,
            "timestamp": datetime.now().isoformat(),
            "crawl_results": None,
            "scan_results": None
        }
        
        try:
            # Initialize ContentDiscovery and run it first
            parsed_url = urlparse(url)
            content_discovery = ContentDiscovery([parsed_url.netloc])
            content_results = await content_discovery.discover_target(url)
            
            # Step 1: Crawling (if enabled)
            if crawl_first:
                self.logger.info(f"Starting crawl of {url}")
                results["crawl_results"] = await self.run_crawler(
                    url=url,
                    content_discovery_results=content_results
                )
                
                # Update scan scope with discovered endpoints
                if results["crawl_results"] and "discovered_urls" in results["crawl_results"]:
                    if not scan_profile:
                        # Create new scan profile with discovered URLs in scope
                        scan_config = {
                            "scope": {
                                "include": [{"rule": url} for url in results["crawl_results"]["discovered_urls"]]
                            }
                        }
                        scan_profile = "Comprehensive_Scan"
                        await self.create_scan_profile(
                            name=scan_profile,
                            scan_config=scan_config
                        )
            
            # Step 2: Active Scanning
            self.logger.info(f"Starting active scan of {url}")
            results["scan_results"] = await self.run_custom_scan(
                url=url,
                scan_profile=scan_profile
            )
            
            # Save comprehensive results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = Path(f"results/burp_comprehensive_{timestamp}.json")
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error during comprehensive scan: {str(e)}")
            return {"error": str(e)}

if __name__ == "__main__":
    # Example usage
    async def main():
        burp = BurpAutomation(
            api_key="your_api_key_here",
            burp_url="http://localhost:1337"
        )
        
        # Example: Create custom scan profile
        scan_config = {
            "scan_configurations": ["Deep scan"],
            "scan_rate": "thorough",
            "scan_recursion": "full_site",
            "application_login": {
                "login_url": "http://example.com/login",
                "credentials": {
                    "username": "test_user",
                    "password": "test_pass"
                }
            }
        }
        
        project_options = {
            "scope": {
                "include": [
                    {"rule": "example.com"},
                    {"rule": "*.example.com"}
                ],
                "exclude": [
                    {"rule": "admin.example.com"}
                ]
            },
            "target": {
                "scope_option": "suite",
                "max_redirects": 5
            }
        }
        
        # Create profile
        profile = await burp.create_scan_profile(
            name="Custom Deep Scan",
            scan_config=scan_config,
            project_options=project_options
        )
        print("Created scan profile:", json.dumps(profile, indent=2))
        
        # Run custom scan
        results = await burp.run_custom_scan(
            url="http://example.com",
            scan_profile="Custom Deep Scan"
        )
        print("Scan results:", json.dumps(results, indent=2))
    
    asyncio.run(main()) 