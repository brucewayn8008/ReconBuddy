import asyncio
import os
import subprocess
import json
import re
from typing import List, Set, Dict, Any, Optional
from pathlib import Path
import logging
from urllib.parse import urlparse
import aiohttp
import itertools

class SubdomainEnumerator:
    def __init__(self, target_domain: str, output_dir: str = "results", use_advanced: bool = True):
        """
        Initialize the SubdomainEnumerator with a target domain
        
        Args:
            target_domain: The root domain to enumerate subdomains for
            output_dir: Directory to store results
            use_advanced: Whether to use advanced techniques (default: True)
        """
        self.target_domain = target_domain
        self.output_dir = Path(output_dir)
        self.subdomains: Set[str] = set()
        self.logger = logging.getLogger("SubdomainEnumerator")
        self.use_advanced = use_advanced
        
        # Create output directories
        self.basic_output = self.output_dir / "basic_enum"
        self.advanced_output = self.output_dir / "advanced_enum"
        os.makedirs(self.basic_output, exist_ok=True)
        os.makedirs(self.advanced_output, exist_ok=True)
        
    async def run_subfinder(self) -> Set[str]:
        """Run subfinder for passive subdomain enumeration"""
        output_file = self.basic_output / "subfinder.txt"
        try:
            cmd = f"subfinder -d {self.target_domain} -o {output_file}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if output_file.exists():
                return set(output_file.read_text().splitlines())
        except Exception as e:
            self.logger.error(f"Error running subfinder: {str(e)}")
        return set()

    async def run_amass(self) -> Set[str]:
        """Run Amass for passive subdomain enumeration"""
        output_file = self.basic_output / "amass.txt"
        try:
            cmd = f"amass enum -passive -d {self.target_domain} -o {output_file}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if output_file.exists():
                return set(output_file.read_text().splitlines())
        except Exception as e:
            self.logger.error(f"Error running amass: {str(e)}")
        return set()

    async def run_assetfinder(self) -> Set[str]:
        """Run assetfinder for passive subdomain enumeration"""
        output_file = self.basic_output / "assetfinder.txt"
        try:
            cmd = f"assetfinder --subs-only {self.target_domain} > {output_file}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if output_file.exists():
                return set(output_file.read_text().splitlines())
        except Exception as e:
            self.logger.error(f"Error running assetfinder: {str(e)}")
        return set()

    async def run_findomain(self) -> Set[str]:
        """Run findomain for passive subdomain enumeration"""
        output_file = self.basic_output / "findomain.txt"
        try:
            cmd = f"findomain -t {self.target_domain} -u {output_file}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if output_file.exists():
                return set(output_file.read_text().splitlines())
        except Exception as e:
            self.logger.error(f"Error running findomain: {str(e)}")
        return set()

    async def run_shuffledns(self, wordlist: str = "/usr/share/wordlists/dns/subdomains-top1million.txt") -> Set[str]:
        """Run shuffledns for DNS bruteforce"""
        output_file = self.basic_output / "shuffledns.txt"
        resolvers_file = self.basic_output / "resolvers.txt"
        
        try:
            # First get fresh resolvers
            await asyncio.create_subprocess_shell(
                f"dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o {resolvers_file}"
            )
            
            cmd = f"shuffledns -d {self.target_domain} -w {wordlist} -r {resolvers_file} -o {output_file}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if output_file.exists():
                return set(output_file.read_text().splitlines())
        except Exception as e:
            self.logger.error(f"Error running shuffledns: {str(e)}")
        return set()

    async def run_massdns(self, subdomains_file: str) -> Set[str]:
        """Run massdns for DNS resolution"""
        output_file = self.basic_output / "massdns.txt"
        resolvers_file = self.basic_output / "resolvers.txt"
        
        try:
            cmd = f"massdns -r {resolvers_file} -t A -o S -w {output_file} {subdomains_file}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if output_file.exists():
                resolved = set()
                for line in output_file.read_text().splitlines():
                    if " A " in line:  # Only get A records
                        subdomain = line.split(" ")[0].rstrip(".")
                        resolved.add(subdomain)
                return resolved
        except Exception as e:
            self.logger.error(f"Error running massdns: {str(e)}")
        return set()

    # Advanced techniques
    async def run_subdomainizer(self) -> Set[str]:
        """
        Run SubDomainizer tool to find subdomains from JavaScript files, CSP, etc.
        """
        output_file = self.advanced_output / f"{self.target_domain}_subdomainizer.txt"
        try:
            cmd = f"SubDomainizer.py -u https://{self.target_domain} -o {output_file}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if output_file.exists():
                return set(line.strip() for line in output_file.read_text().splitlines() if line.strip())
            
        except Exception as e:
            self.logger.error(f"Error running SubDomainizer: {str(e)}")
        
        return set()
    
    async def run_hakrawler(self, depth: int = 2) -> Set[str]:
        """
        Run hakrawler for crawling and extracting subdomains
        """
        output_file = self.advanced_output / f"{self.target_domain}_hakrawler.txt"
        try:
            # First get the URLs to feed into hakrawler
            wayback_cmd = f"echo {self.target_domain} | waybackurls > {self.advanced_output}/wayback_urls.txt"
            process = await asyncio.create_subprocess_shell(
                wayback_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            # Now run hakrawler
            cmd = f"cat {self.advanced_output}/wayback_urls.txt | hakrawler -depth {depth} -subs -unique -insecure > {output_file}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if output_file.exists():
                # Extract subdomains from the URLs
                urls = output_file.read_text().splitlines()
                subdomains = set()
                
                for url in urls:
                    try:
                        parsed = urlparse(url)
                        if parsed.netloc.endswith(self.target_domain):
                            subdomains.add(parsed.netloc)
                    except:
                        pass
                
                return subdomains
            
        except Exception as e:
            self.logger.error(f"Error running hakrawler: {str(e)}")
        
        return set()
    
    async def run_gospider(self, depth: int = 3) -> Set[str]:
        """
        Run gospider for crawling and extracting subdomains
        """
        output_file = self.advanced_output / f"{self.target_domain}_gospider.txt"
        try:
            cmd = f"gospider -s https://{self.target_domain} -d {depth} -c 10 -o {output_file}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if output_file.exists():
                content = output_file.read_text()
                # Extract subdomains using regex
                subdomains_pattern = re.compile(r'https?://([a-zA-Z0-9][\w\.-]*\.{0}'.format(re.escape(self.target_domain)))
                matches = subdomains_pattern.findall(content)
                return set(matches)
            
        except Exception as e:
            self.logger.error(f"Error running gospider: {str(e)}")
        
        return set()
    
    async def check_additional_cert_sources(self) -> Set[str]:
        """
        Check additional certificate transparency sources
        """
        results = set()
        sources = [
            f"https://crt.sh/?q=%.{self.target_domain}&output=json",
            f"https://certspotter.com/api/v1/issuances?domain={self.target_domain}&include_subdomains=true&expand=dns_names",
            f"https://sslmate.com/certspotter/api/v1/issuances?domain={self.target_domain}&include_subdomains=true&expand=dns_names",
            f"https://ct.cloudflare.com/api/v1/certificates?domain={self.target_domain}",
            f"https://api.certstream.calidog.io/domains?domain={self.target_domain}"
        ]
        
        async with aiohttp.ClientSession() as session:
            for source in sources:
                try:
                    async with session.get(source) as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            # Process based on the source format
                            if "crt.sh" in source:
                                for cert in data:
                                    if "name_value" in cert:
                                        results.add(cert["name_value"])
                            elif "certspotter" in source or "sslmate" in source:
                                for cert in data:
                                    if "dns_names" in cert:
                                        results.update(cert["dns_names"])
                            elif "cloudflare" in source:
                                for cert in data.get("certificates", []):
                                    if "domains" in cert:
                                        results.update(cert["domains"])
                            elif "certstream" in source:
                                results.update(data.get("domains", []))
                except Exception as e:
                    self.logger.error(f"Error checking {source}: {str(e)}")
        
        # Filter only relevant subdomains
        return {sub for sub in results if sub.endswith(self.target_domain)}

    async def correlate_subdomains(self, subdomains: Set[str]) -> Dict[str, List[str]]:
        """
        Correlate subdomains to find patterns and potential new targets
        """
        correlation = {}
        
        # Group by common prefixes
        prefix_patterns = {}
        for subdomain in subdomains:
            name = subdomain.split('.')[0]
            
            # Look for common patterns
            patterns = [
                "dev", "test", "staging", "prod", "qa", "uat", "api",
                "admin", "internal", "corp", "vpn", "mail", "remote"
            ]
            
            for pattern in patterns:
                if name.startswith(pattern) or name.endswith(pattern) or f"-{pattern}-" in name:
                    prefix_patterns.setdefault(pattern, []).append(subdomain)
        
        correlation["prefix_patterns"] = prefix_patterns
        
        # Generate potential new subdomains based on patterns
        potential_new = set()
        
        # Generate combinations with common prefixes
        common_prefixes = ["dev", "test", "staging", "prod", "qa", "uat", "api", "admin", "portal"]
        for prefix in common_prefixes:
            potential_new.add(f"{prefix}.{self.target_domain}")
        
        correlation["potential_new_targets"] = list(potential_new)
        
        # Save correlation data
        correlation_file = self.advanced_output / "correlation.json"
        with open(correlation_file, 'w') as f:
            json.dump(correlation, f, indent=2)
        
        return correlation

    async def run_basic_enumeration(self) -> Set[str]:
        """Run basic subdomain enumeration techniques"""
        self.logger.info("Running basic subdomain enumeration...")
        tasks = [
            self.run_subfinder(),
            self.run_amass(),
            self.run_assetfinder(),
            self.run_findomain(),
        ]
        
        results = await asyncio.gather(*tasks)
        
        # Combine all results
        all_subdomains = set()
        for result in results:
            all_subdomains.update(result)
            
        # Save combined results
        combined_file = self.basic_output / "combined_passive.txt"
        combined_file.write_text("\n".join(sorted(all_subdomains)))
        
        # Run DNS bruteforce
        bruteforce_results = await self.run_shuffledns()
        all_subdomains.update(bruteforce_results)
        
        # Save all subdomains for resolution
        all_subdomains_file = self.basic_output / "all_subdomains.txt"
        all_subdomains_file.write_text("\n".join(sorted(all_subdomains)))
        
        # Resolve all subdomains
        resolved_subdomains = await self.run_massdns(str(all_subdomains_file))
        
        # Save final results
        final_results = self.basic_output / "final_subdomains.txt"
        final_results.write_text("\n".join(sorted(resolved_subdomains)))
        
        return resolved_subdomains

    async def run_advanced_enumeration(self) -> Set[str]:
        """Run advanced subdomain enumeration techniques"""
        self.logger.info("Running advanced subdomain enumeration...")
        
        # Run all advanced tools in parallel
        tasks = [
            self.run_subdomainizer(),
            self.run_hakrawler(),
            self.run_gospider(),
            self.check_additional_cert_sources()
        ]
        
        tool_results = await asyncio.gather(*tasks)
        
        # Combine results
        subdomainizer_results = tool_results[0]
        hakrawler_results = tool_results[1]
        gospider_results = tool_results[2]
        cert_results = tool_results[3]
        
        all_subdomains = (
            subdomainizer_results | 
            hakrawler_results | 
            gospider_results | 
            cert_results
        )
        
        # Save detailed results
        subdomainizer_file = self.advanced_output / "subdomainizer_results.txt"
        hakrawler_file = self.advanced_output / "hakrawler_results.txt"
        gospider_file = self.advanced_output / "gospider_results.txt"
        cert_file = self.advanced_output / "cert_results.txt"
        
        subdomainizer_file.write_text("\n".join(sorted(subdomainizer_results)))
        hakrawler_file.write_text("\n".join(sorted(hakrawler_results)))
        gospider_file.write_text("\n".join(sorted(gospider_results)))
        cert_file.write_text("\n".join(sorted(cert_results)))
        
        # Save combined results
        combined_file = self.advanced_output / "combined_advanced.txt"
        combined_file.write_text("\n".join(sorted(all_subdomains)))
        
        return all_subdomains

    async def enumerate(self) -> Set[str]:
        """Run all subdomain enumeration methods"""
        self.logger.info(f"Starting subdomain enumeration for {self.target_domain}")
        
        # Run basic enumeration
        basic_results = await self.run_basic_enumeration()
        self.logger.info(f"Found {len(basic_results)} subdomains using basic techniques")
        
        # Run advanced enumeration if enabled
        if self.use_advanced:
            advanced_results = await self.run_advanced_enumeration()
            self.logger.info(f"Found {len(advanced_results)} subdomains using advanced techniques")
            
            # Combine results
            all_subdomains = basic_results | advanced_results
            
            # Run correlation analysis
            correlation = await self.correlate_subdomains(all_subdomains)
            potential_targets = correlation.get("potential_new_targets", [])
            self.logger.info(f"Generated {len(potential_targets)} potential new targets from correlation analysis")
        else:
            all_subdomains = basic_results
        
        # Save final combined results
        final_file = self.output_dir / "final_subdomains.txt"
        final_file.write_text("\n".join(sorted(all_subdomains)))
        
        self.subdomains = all_subdomains
        return all_subdomains 