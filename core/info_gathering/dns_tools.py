import asyncio
import logging
from pathlib import Path
from typing import Set, List, Dict
import json
import aiohttp
from dns import resolver, reversename
import aiodns

class DNSTools:
    def __init__(self, output_dir: str = "results/dns"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("DNSTools")
        self.resolver = aiodns.DNSResolver()
        
    async def resolve_domains(self, domains: List[str]) -> Dict[str, List[str]]:
        """Resolve domains to IP addresses"""
        results = {}
        for domain in domains:
            try:
                answers = await self.resolver.query(domain, 'A')
                results[domain] = [answer.host for answer in answers]
            except Exception as e:
                self.logger.error(f"Error resolving {domain}: {str(e)}")
                results[domain] = []
        return results
    
    async def reverse_dns(self, ips: List[str]) -> Dict[str, List[str]]:
        """Perform reverse DNS lookups"""
        results = {}
        for ip in ips:
            try:
                addr = reversename.from_address(ip)
                answers = await self.resolver.query(str(addr), 'PTR')
                results[ip] = [str(answer.host) for answer in answers]
            except Exception as e:
                self.logger.error(f"Error reverse resolving {ip}: {str(e)}")
                results[ip] = []
        return results
    
    async def check_zone_transfer(self, domain: str) -> List[str]:
        """Attempt zone transfer for a domain"""
        results = []
        try:
            # First get NS records
            ns_records = await self.resolver.query(domain, 'NS')
            nameservers = [record.host for record in ns_records]
            
            # Try zone transfer from each nameserver
            for ns in nameservers:
                try:
                    cmd = f"dig @{ns} {domain} AXFR"
                    process = await asyncio.create_subprocess_shell(
                        cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await process.communicate()
                    if stdout:
                        results.extend(self._parse_zone_transfer(stdout.decode()))
                except Exception as e:
                    self.logger.error(f"Zone transfer failed for {domain} from {ns}: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error checking zone transfer for {domain}: {str(e)}")
        return list(set(results))
    
    async def check_cert_transparency(self, domain: str) -> Set[str]:
        """Query Certificate Transparency logs for subdomains"""
        results = set()
        ct_urls = [
            f"https://crt.sh/?q=%.{domain}&output=json",
            f"https://certspotter.com/api/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        ]
        
        async with aiohttp.ClientSession() as session:
            for url in ct_urls:
                try:
                    async with session.get(url) as response:
                        if response.status == 200:
                            data = await response.json()
                            if "crt.sh" in url:
                                results.update(self._parse_crtsh(data))
                            else:
                                results.update(self._parse_certspotter(data))
                except Exception as e:
                    self.logger.error(f"Error querying {url}: {str(e)}")
        
        return results
    
    def _parse_zone_transfer(self, output: str) -> List[str]:
        """Parse zone transfer output"""
        records = []
        for line in output.splitlines():
            if any(rtype in line for rtype in ['A', 'AAAA', 'CNAME', 'MX', 'NS']):
                parts = line.split()
                if len(parts) >= 4:
                    records.append(parts[0])
        return records
    
    def _parse_crtsh(self, data: List[Dict]) -> Set[str]:
        """Parse crt.sh JSON output"""
        domains = set()
        for cert in data:
            if 'name_value' in cert:
                domains.add(cert['name_value'])
            elif 'common_name' in cert:
                domains.add(cert['common_name'])
        return domains
    
    def _parse_certspotter(self, data: List[Dict]) -> Set[str]:
        """Parse certspotter JSON output"""
        domains = set()
        for cert in data:
            if 'dns_names' in cert:
                domains.update(cert['dns_names'])
        return domains
    
    async def generate_permutations(self, domain: str, wordlist: str = None) -> Set[str]:
        """Generate DNS permutations for a domain"""
        permutations = set()
        
        # Common prefixes and suffixes
        prefixes = ['dev', 'staging', 'test', 'prod', 'api', 'admin', 'portal']
        suffixes = ['-dev', '-staging', '-prod', '-test']
        
        # Add basic permutations
        base = domain.split('.')[0]
        tld = '.'.join(domain.split('.')[1:])
        
        for prefix in prefixes:
            permutations.add(f"{prefix}.{domain}")
            permutations.add(f"{prefix}-{base}.{tld}")
        
        for suffix in suffixes:
            permutations.add(f"{base}{suffix}.{tld}")
        
        # Add from wordlist if provided
        if wordlist and Path(wordlist).exists():
            with open(wordlist) as f:
                for line in f:
                    word = line.strip()
                    if word:
                        permutations.add(f"{word}.{domain}")
        
        return permutations 