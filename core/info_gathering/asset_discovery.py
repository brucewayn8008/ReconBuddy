import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Set
import aiohttp
import json
import re
from bs4 import BeautifulSoup
import ipaddress

class AssetDiscovery:
    def __init__(self, output_dir: str = "results/asset_discovery"):
        """
        Initialize the AssetDiscovery module
        
        Args:
            output_dir: Directory to store results
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("AssetDiscovery")
    
    async def lookup_asn_hurricane(self, query: str) -> Dict:
        """
        Lookup ASN information using Hurricane Electric
        
        Args:
            query: Company name, domain, or IP address
        """
        results = {
            "asn_numbers": [],
            "ip_ranges": [],
            "organization": "",
            "related_domains": []
        }
        
        try:
            url = f"https://bgp.he.net/search?search%5Bsearch%5D={query}&commit=Search"
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Extract ASN information
                        asn_table = soup.find('table', {'id': 'asns'})
                        if asn_table:
                            for row in asn_table.find_all('tr')[1:]:  # Skip header row
                                cols = row.find_all('td')
                                if len(cols) >= 2:
                                    asn = cols[0].text.strip()
                                    org = cols[1].text.strip()
                                    results["asn_numbers"].append(asn)
                                    if not results["organization"]:
                                        results["organization"] = org
                        
                        # Extract IP ranges
                        prefixes_table = soup.find('table', {'id': 'prefixes'})
                        if prefixes_table:
                            for row in prefixes_table.find_all('tr')[1:]:  # Skip header row
                                cols = row.find_all('td')
                                if len(cols) >= 1:
                                    ip_range = cols[0].text.strip()
                                    results["ip_ranges"].append(ip_range)
                        
                        # Extract related domains if any
                        domains_table = soup.find('table', {'id': 'domains'})
                        if domains_table:
                            for row in domains_table.find_all('tr')[1:]:  # Skip header row
                                cols = row.find_all('td')
                                if len(cols) >= 1:
                                    domain = cols[0].text.strip()
                                    results["related_domains"].append(domain)
        except Exception as e:
            self.logger.error(f"Error looking up ASN info for {query}: {str(e)}")
        
        return results
    
    async def get_ip_ranges_from_asn(self, asn: str) -> List[str]:
        """
        Get IP ranges for a specific ASN
        
        Args:
            asn: ASN number (e.g., AS15169)
        """
        ip_ranges = []
        
        try:
            # Remove 'AS' prefix if present
            asn_num = asn.replace('AS', '')
            
            url = f"https://bgp.he.net/AS{asn_num}#_prefixes"
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Extract IPv4 ranges
                        ipv4_table = soup.find('table', {'id': 'table_prefixes4'})
                        if ipv4_table:
                            for row in ipv4_table.find_all('tr')[1:]:  # Skip header row
                                cols = row.find_all('td')
                                if len(cols) >= 1:
                                    ip_range = cols[0].text.strip()
                                    ip_ranges.append(ip_range)
                        
                        # Extract IPv6 ranges
                        ipv6_table = soup.find('table', {'id': 'table_prefixes6'})
                        if ipv6_table:
                            for row in ipv6_table.find_all('tr')[1:]:  # Skip header row
                                cols = row.find_all('td')
                                if len(cols) >= 1:
                                    ip_range = cols[0].text.strip()
                                    ip_ranges.append(ip_range)
        except Exception as e:
            self.logger.error(f"Error getting IP ranges for ASN {asn}: {str(e)}")
        
        return ip_ranges
    
    async def reverse_whois_lookup(self, query: str) -> List[Dict]:
        """
        Perform reverse WHOIS lookup to find domains registered to the same entity
        
        Args:
            query: Company name or email
        """
        domains = []
        
        try:
            # ViewDNS API (paid, but has a demo limit)
            url = f"https://api.viewdns.info/reversewhois/?q={query}&output=json&apikey=YOUR_API_KEY"
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        if "domains" in data["response"]:
                            domains.extend(data["response"]["domains"])
        except Exception as e:
            self.logger.error(f"Error with ViewDNS API: {str(e)}")
        
        try:
            # WhoisXML API (paid, but has a demo limit)
            url = f"https://reverse-whois.whoisxmlapi.com/api/v2?apiKey=YOUR_API_KEY&searchType=current&mode=purchase&basicSearchTerms={query}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        if "domainsList" in data:
                            for domain_entry in data["domainsList"]:
                                if domain_entry not in domains:
                                    domains.append(domain_entry)
        except Exception as e:
            self.logger.error(f"Error with WhoisXML API: {str(e)}")
        
        return domains
    
    async def track_company_acquisitions(self, company: str) -> List[Dict]:
        """
        Track company acquisitions to find related domains
        
        Args:
            company: Company name to search for acquisitions
        """
        acquisitions = []
        
        try:
            # Crunchbase-like search (mockup, would need a real API)
            url = f"https://api.crunchbase.com/api/v4/entities/organizations/{company}?field_ids=acquiree_acquisitions&user_key=YOUR_API_KEY"
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        if "properties" in data and "acquiree_acquisitions" in data["properties"]:
                            acquisitions.extend(data["properties"]["acquiree_acquisitions"])
        except Exception as e:
            self.logger.error(f"Error tracking acquisitions for {company}: {str(e)}")
        
        # Alternative: Use a web scraper for public sources
        # This is just a placeholder for the concept
        acquisition_data = []
        try:
            # Example sources
            sources = [
                f"https://en.wikipedia.org/wiki/{company}",
                f"https://www.crunchbase.com/organization/{company.lower().replace(' ', '-')}/company_financials"
            ]
            
            for source in sources:
                async with aiohttp.ClientSession() as session:
                    async with session.get(source) as response:
                        if response.status == 200:
                            html = await response.text()
                            # This would need more sophisticated parsing specific to each source
                            # Just a concept example
                            soup = BeautifulSoup(html, 'html.parser')
                            
                            if "wikipedia" in source:
                                # Look for acquisition tables in Wikipedia
                                acquisition_sections = soup.find_all('span', {'id': lambda x: x and 'acquisition' in x.lower()})
                                for section in acquisition_sections:
                                    table = section.find_next('table', {'class': 'wikitable'})
                                    if table:
                                        for row in table.find_all('tr')[1:]:
                                            cols = row.find_all('td')
                                            if len(cols) >= 2:
                                                acquired_company = cols[0].text.strip()
                                                acquisition_data.append({
                                                    "acquired_company": acquired_company,
                                                    "source": "Wikipedia"
                                                })
        except Exception as e:
            self.logger.error(f"Error scraping acquisition data for {company}: {str(e)}")
        
        acquisitions.extend(acquisition_data)
        return acquisitions
    
    async def discover_assets(self, target: str, is_company: bool = False) -> Dict:
        """
        Discover assets related to a target
        
        Args:
            target: Domain, IP, or company name
            is_company: Whether the target is a company name
        """
        self.logger.info(f"Starting asset discovery for {target}")
        results = {
            "target": target,
            "is_company": is_company,
            "asn_info": {},
            "ip_ranges": [],
            "domains": [],
            "acquisitions": []
        }
        
        try:
            # Step 1: ASN Lookup
            asn_info = await self.lookup_asn_hurricane(target)
            results["asn_info"] = asn_info
            
            # Step 2: Get IP Ranges for each ASN
            for asn in asn_info["asn_numbers"]:
                ip_ranges = await self.get_ip_ranges_from_asn(asn)
                results["ip_ranges"].extend(ip_ranges)
            
            # Step 3: Reverse WHOIS Lookup
            lookup_target = target
            if not is_company and "organization" in asn_info and asn_info["organization"]:
                lookup_target = asn_info["organization"]
            
            whois_domains = await self.reverse_whois_lookup(lookup_target)
            results["domains"] = whois_domains
            
            # Step 4: Track Acquisitions if it's a company
            if is_company or "organization" in asn_info and asn_info["organization"]:
                company_name = target if is_company else asn_info["organization"]
                acquisitions = await self.track_company_acquisitions(company_name)
                results["acquisitions"] = acquisitions
                
                # For each acquisition, lookup their domains too
                for acquisition in acquisitions:
                    if "acquired_company" in acquisition:
                        acq_company = acquisition["acquired_company"]
                        acq_domains = await self.reverse_whois_lookup(acq_company)
                        acquisition["domains"] = acq_domains
            
            # Save the results
            output_file = self.output_dir / f"{target.replace(' ', '_')}_assets.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.logger.info(f"Asset discovery completed for {target}")
            
        except Exception as e:
            self.logger.error(f"Error during asset discovery for {target}: {str(e)}")
        
        return results 