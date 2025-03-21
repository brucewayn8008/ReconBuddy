import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Set
import aiohttp
import ipaddress
import json
from datetime import datetime

class NetworkTools:
    def __init__(self, output_dir: str = "results/network"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("NetworkTools")
        
    async def scan_ports(self, target: str, ports: List[int] = None) -> Dict[int, bool]:
        """Scan ports on a target host"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                    993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        
        results = {}
        for port in ports:
            try:
                reader, writer = await asyncio.open_connection(target, port)
                writer.close()
                await writer.wait_closed()
                results[port] = True
            except:
                results[port] = False
        
        return results
    
    async def scan_ip_range(self, ip_range: str) -> Set[str]:
        """Scan an IP range for live hosts"""
        network = ipaddress.ip_network(ip_range)
        live_hosts = set()
        
        async def ping_host(ip):
            try:
                cmd = f"ping -c 1 -W 1 {ip}"
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await process.communicate()
                if "1 received" in stdout.decode():
                    live_hosts.add(str(ip))
            except Exception as e:
                self.logger.error(f"Error pinging {ip}: {str(e)}")
        
        tasks = [ping_host(ip) for ip in network.hosts()]
        await asyncio.gather(*tasks)
        return live_hosts
    
    async def discover_virtual_hosts(self, ip: str, wordlist: str = None) -> Set[str]:
        """Discover virtual hosts on an IP address"""
        vhosts = set()
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        async def check_vhost(hostname):
            try:
                async with aiohttp.ClientSession() as session:
                    headers['Host'] = hostname
                    async with session.get(f"http://{ip}", headers=headers) as response:
                        content = await response.text()
                        # Store unique responses to detect different vhosts
                        vhosts.add(hostname)
            except Exception as e:
                self.logger.error(f"Error checking vhost {hostname}: {str(e)}")
        
        # Common vhost names
        common_names = ['dev', 'staging', 'test', 'admin', 'api', 'portal']
        tasks = [check_vhost(name) for name in common_names]
        
        # Add from wordlist if provided
        if wordlist and Path(wordlist).exists():
            with open(wordlist) as f:
                for line in f:
                    hostname = line.strip()
                    if hostname:
                        tasks.append(check_vhost(hostname))
        
        await asyncio.gather(*tasks)
        return vhosts
    
    async def scan_common_services(self, target: str) -> Dict[str, Dict]:
        """Scan for common services and their versions"""
        services = {}
        
        # HTTP/HTTPS detection
        async def check_web(port, ssl=False):
            try:
                scheme = "https" if ssl else "http"
                url = f"{scheme}://{target}:{port}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(url) as response:
                        headers = dict(response.headers)
                        return {
                            "status": response.status,
                            "server": headers.get("Server", ""),
                            "powered_by": headers.get("X-Powered-By", ""),
                            "title": await self._extract_title(response)
                        }
            except Exception as e:
                self.logger.error(f"Error checking {url}: {str(e)}")
                return None
        
        # Check common web ports
        web_results = await asyncio.gather(
            check_web(80),
            check_web(443, ssl=True),
            check_web(8080),
            check_web(8443, ssl=True)
        )
        
        for port, result in zip([80, 443, 8080, 8443], web_results):
            if result:
                services[f"web_{port}"] = result
        
        # Save results
        output_file = self.output_dir / f"{target}_services.json"
        with open(output_file, 'w') as f:
            json.dump(services, f, indent=2)
        
        return services
    
    async def _extract_title(self, response) -> str:
        """Extract title from HTML response"""
        try:
            content = await response.text()
            import re
            title_match = re.search(r"<title>(.*?)</title>", content, re.IGNORECASE)
            return title_match.group(1) if title_match else ""
        except:
            return ""
    
    async def take_screenshot(self, url: str) -> str:
        """Take a screenshot of a webpage using Chrome headless"""
        output_file = self.output_dir / f"{url.replace('://', '_').replace('/', '_')}.png"
        
        try:
            cmd = f'chrome --headless --screenshot="{output_file}" {url}'
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if output_file.exists():
                return str(output_file)
        except Exception as e:
            self.logger.error(f"Error taking screenshot of {url}: {str(e)}")
        
        return "" 