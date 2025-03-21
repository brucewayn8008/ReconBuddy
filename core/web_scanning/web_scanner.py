import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Set
import aiohttp
import json
import re
from urllib.parse import urljoin, urlparse, parse_qs
import xml.etree.ElementTree as ET

class WebScanner:
    def __init__(self, output_dir: str = "results/web"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("WebScanner")
        
    async def scan_xss(self, url: str, params: Dict = None) -> List[Dict]:
        """Scan for XSS vulnerabilities"""
        findings = []
        payloads = [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
        ]
        
        async with aiohttp.ClientSession() as session:
            # Test URL parameters
            if params:
                for param, value in params.items():
                    for payload in payloads:
                        test_params = params.copy()
                        test_params[param] = payload
                        try:
                            async with session.get(url, params=test_params) as response:
                                content = await response.text()
                                if payload in content:
                                    findings.append({
                                        "type": "XSS",
                                        "url": url,
                                        "parameter": param,
                                        "payload": payload,
                                        "evidence": content[:200]
                                    })
                        except Exception as e:
                            self.logger.error(f"Error testing XSS on {url}: {str(e)}")
            
            # Test URL path
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            paths = parsed.path.split('/')
            
            for i, _ in enumerate(paths):
                for payload in payloads:
                    test_paths = paths.copy()
                    if i < len(test_paths):
                        test_paths[i] = payload
                    test_url = base_url + '/'.join(test_paths)
                    
                    try:
                        async with session.get(test_url) as response:
                            content = await response.text()
                            if payload in content:
                                findings.append({
                                    "type": "XSS",
                                    "url": test_url,
                                    "parameter": "path",
                                    "payload": payload,
                                    "evidence": content[:200]
                                })
                    except Exception as e:
                        self.logger.error(f"Error testing XSS on {test_url}: {str(e)}")
        
        return findings
    
    async def scan_sqli(self, url: str, params: Dict = None) -> List[Dict]:
        """Scan for SQL injection vulnerabilities"""
        findings = []
        payloads = [
            "' OR '1'='1",
            "1' OR '1'='1",
            "1 OR 1=1",
            "' UNION SELECT NULL--",
            "admin'--",
            "1'; WAITFOR DELAY '0:0:5'--"
        ]
        
        async with aiohttp.ClientSession() as session:
            if params:
                for param, value in params.items():
                    for payload in payloads:
                        test_params = params.copy()
                        test_params[param] = payload
                        try:
                            async with session.get(url, params=test_params) as response:
                                content = await response.text()
                                if any(error in content.lower() for error in [
                                    "sql", "mysql", "oracle", "syntax error"
                                ]):
                                    findings.append({
                                        "type": "SQLi",
                                        "url": url,
                                        "parameter": param,
                                        "payload": payload,
                                        "evidence": content[:200]
                                    })
                        except Exception as e:
                            self.logger.error(f"Error testing SQLi on {url}: {str(e)}")
        
        return findings
    
    async def check_default_credentials(self, url: str) -> List[Dict]:
        """Check for default credentials"""
        findings = []
        common_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("root", "root"),
            ("admin", ""),
            ("administrator", "admin"),
        ]
        
        login_paths = [
            "/login", "/admin", "/wp-admin", "/administrator",
            "/auth", "/signin", "/console", "/manager"
        ]
        
        async with aiohttp.ClientSession() as session:
            for path in login_paths:
                login_url = urljoin(url, path)
                try:
                    async with session.get(login_url) as response:
                        if response.status == 200:
                            for username, password in common_creds:
                                data = {
                                    "username": username,
                                    "password": password,
                                    "submit": "Login"
                                }
                                try:
                                    async with session.post(login_url, data=data) as login_response:
                                        if login_response.status == 200:
                                            content = await login_response.text()
                                            if any(success in content.lower() for success in [
                                                "welcome", "dashboard", "logout", "profile"
                                            ]):
                                                findings.append({
                                                    "type": "Default Credentials",
                                                    "url": login_url,
                                                    "username": username,
                                                    "password": password
                                                })
                                except Exception as e:
                                    self.logger.error(f"Error testing credentials on {login_url}: {str(e)}")
                except Exception as e:
                    self.logger.error(f"Error accessing {login_url}: {str(e)}")
        
        return findings
    
    async def scan_command_injection(self, url: str, params: Dict = None) -> List[Dict]:
        """Scan for command injection vulnerabilities"""
        findings = []
        payloads = [
            "| whoami",
            "; whoami",
            "` whoami`",
            "$(whoami)",
            "> /dev/null",
            "| sleep 5",
            "; ping -c 5 127.0.0.1"
        ]
        
        async with aiohttp.ClientSession() as session:
            if params:
                for param, value in params.items():
                    for payload in payloads:
                        test_params = params.copy()
                        test_params[param] = payload
                        try:
                            start_time = asyncio.get_event_loop().time()
                            async with session.get(url, params=test_params) as response:
                                content = await response.text()
                                response_time = asyncio.get_event_loop().time() - start_time
                                
                                # Check for command output or timing
                                if any(indicator in content.lower() for indicator in [
                                    "root:", "usr", "win32", "system32"
                                ]) or response_time > 5:
                                    findings.append({
                                        "type": "Command Injection",
                                        "url": url,
                                        "parameter": param,
                                        "payload": payload,
                                        "evidence": content[:200]
                                    })
                        except Exception as e:
                            self.logger.error(f"Error testing command injection on {url}: {str(e)}")
        
        return findings
    
    async def check_s3_buckets(self, domain: str) -> List[Dict]:
        """Check for exposed S3 buckets"""
        findings = []
        bucket_names = [
            domain,
            f"backup.{domain}",
            f"backups.{domain}",
            f"dev.{domain}",
            f"development.{domain}",
            f"staging.{domain}",
            f"prod.{domain}",
            f"production.{domain}",
            f"test.{domain}",
            f"media.{domain}",
            f"assets.{domain}",
            f"static.{domain}",
            f"content.{domain}",
            f"data.{domain}"
        ]
        
        async with aiohttp.ClientSession() as session:
            for bucket in bucket_names:
                urls = [
                    f"https://{bucket}.s3.amazonaws.com",
                    f"https://s3.amazonaws.com/{bucket}"
                ]
                
                for url in urls:
                    try:
                        async with session.get(url) as response:
                            if response.status != 404:
                                content = await response.text()
                                if "ListBucketResult" in content:
                                    findings.append({
                                        "type": "Exposed S3 Bucket",
                                        "url": url,
                                        "bucket": bucket,
                                        "listable": True
                                    })
                    except Exception as e:
                        self.logger.error(f"Error checking S3 bucket {url}: {str(e)}")
        
        return findings
    
    async def check_git_exposure(self, url: str) -> List[Dict]:
        """Check for exposed Git repositories"""
        findings = []
        git_paths = [
            "/.git/config",
            "/.git/HEAD",
            "/.git/logs/HEAD",
            "/.git/index"
        ]
        
        async with aiohttp.ClientSession() as session:
            for path in git_paths:
                try:
                    check_url = urljoin(url, path)
                    async with session.get(check_url) as response:
                        if response.status == 200:
                            content = await response.text()
                            if any(indicator in content for indicator in [
                                "[core]", "ref:", "index"
                            ]):
                                findings.append({
                                    "type": "Exposed Git Repository",
                                    "url": check_url,
                                    "evidence": content[:200]
                                })
                except Exception as e:
                    self.logger.error(f"Error checking Git exposure on {check_url}: {str(e)}")
        
        return findings
    
    async def scan_url(self, url: str) -> Dict[str, List[Dict]]:
        """Run all web scanning checks on a URL"""
        # Parse URL parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params = {k: v[0] for k, v in params.items()}  # Convert list values to single values
        
        # Run all checks in parallel
        results = await asyncio.gather(
            self.scan_xss(url, params),
            self.scan_sqli(url, params),
            self.check_default_credentials(url),
            self.scan_command_injection(url, params),
            self.check_s3_buckets(parsed.netloc),
            self.check_git_exposure(url)
        )
        
        findings = {
            "xss": results[0],
            "sqli": results[1],
            "default_creds": results[2],
            "command_injection": results[3],
            "s3_buckets": results[4],
            "git_exposure": results[5]
        }
        
        # Save results
        output_file = self.output_dir / f"{parsed.netloc.replace(':', '_')}_scan.json"
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=2)
        
        return findings 