import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Set
import aiohttp
import json
import re
import os
import base64
from datetime import datetime

class GitHubRecon:
    def __init__(self, output_dir: str = "results/github_recon", github_token: str = None):
        """
        Initialize the GitHubRecon module
        
        Args:
            output_dir: Directory to store results
            github_token: GitHub API token for authentication
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("GitHubRecon")
        self.github_token = github_token
        
        # Define API key regex patterns
        self.api_key_patterns = {
            "aws_access_key": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
            "aws_secret_key": r"(?i)aws[_\-\.]{0,2}(?:secret|private)[_\-\.]{0,2}(?:access|key)[_\-\.]{0,2}[a-z0-9/+=]{40}",
            "github_pat": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}",
            "google_api": r"AIza[0-9A-Za-z\-_]{35}",
            "slack_token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
            "stripe_key": r"(?:r|s)k_live_[0-9a-zA-Z]{24}",
            "generic_api_key": r"(?i)(?:api|access|auth|client|secret|token|key|passwd|password|pwd)[_\-\.][a-z0-9_\-\.]{8,}"
        }
        
    async def search_github(self, query: str, search_type: str = "code") -> Dict:
        """
        Search GitHub for specific content
        
        Args:
            query: Search query
            search_type: Type of search (code, repositories, issues, users)
        """
        results = {
            "query": query,
            "search_type": search_type,
            "items": [],
            "total_count": 0
        }
        
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        
        try:
            url = f"https://api.github.com/search/{search_type}?q={query}&per_page=100"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        results["total_count"] = data.get("total_count", 0)
                        results["items"] = data.get("items", [])
                    else:
                        self.logger.error(f"GitHub API error: {response.status} - {await response.text()}")
        except Exception as e:
            self.logger.error(f"Error searching GitHub for {query}: {str(e)}")
        
        return results
    
    async def dork_sensitive_info(self, organization: str = None, domain: str = None) -> Dict:
        """
        Search GitHub with dorks for sensitive information
        
        Args:
            organization: GitHub organization name
            domain: Domain to search for
        """
        dork_results = {}
        
        # Construct base query
        base_query = ""
        if organization:
            base_query += f"org:{organization} "
        if domain:
            base_query += f"'{domain}' "
        
        # Define GitHub dorks for sensitive information
        dorks = {
            "passwords": "password",
            "api_keys": "apikey OR api_key OR access_key OR secret_key",
            "tokens": "token OR authorization",
            "secrets": "secret OR credentials",
            "config_files": "filename:config.yml OR filename:config.json OR filename:.env OR filename:credentials",
            "database_strings": "filename:.sql extension:sql password",
            "private_keys": "filename:.pem extension:pem OR filename:.key extension:key",
            "ssh_keys": "filename:id_rsa OR filename:id_dsa OR filename:id_ed25519",
            "aws_credentials": "filename:credentials aws",
            "gcp_credentials": "filename:credentials.json gcp OR google",
            "slack_tokens": "xoxp OR xoxb OR xoxa",
            "stripe_keys": "sk_live OR rk_live",
        }
        
        for dork_name, dork_query in dorks.items():
            full_query = f"{base_query} {dork_query}"
            search_result = await self.search_github(full_query)
            dork_results[dork_name] = search_result
            
            # Avoid GitHub API rate limits
            await asyncio.sleep(2)
        
        # Save the results
        output_file = self.output_dir / f"github_dorks_{organization or domain}.json"
        with open(output_file, 'w') as f:
            json.dump(dork_results, f, indent=2)
        
        return dork_results
    
    async def detect_api_keys(self, content: str) -> Dict[str, List[str]]:
        """
        Detect API keys in content using regex
        
        Args:
            content: Content to scan for API keys
        """
        findings = {}
        
        for key_type, pattern in self.api_key_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                findings[key_type] = matches
        
        return findings
    
    async def analyze_repository(self, repo_owner: str, repo_name: str) -> Dict:
        """
        Analyze a GitHub repository for sensitive information
        
        Args:
            repo_owner: Owner of the repository
            repo_name: Name of the repository
        """
        analysis_results = {
            "repository": f"{repo_owner}/{repo_name}",
            "sensitive_files": [],
            "api_keys": {},
            "repo_metadata": {},
            "contributors": [],
            "commit_frequency": {},
            "security_issues": []
        }
        
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        
        try:
            # Get repository metadata
            repo_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}"
            async with aiohttp.ClientSession() as session:
                async with session.get(repo_url, headers=headers) as response:
                    if response.status == 200:
                        repo_data = await response.json()
                        analysis_results["repo_metadata"] = {
                            "name": repo_data.get("name"),
                            "description": repo_data.get("description"),
                            "stars": repo_data.get("stargazers_count"),
                            "forks": repo_data.get("forks_count"),
                            "open_issues": repo_data.get("open_issues_count"),
                            "created_at": repo_data.get("created_at"),
                            "updated_at": repo_data.get("updated_at"),
                            "default_branch": repo_data.get("default_branch")
                        }
                    else:
                        self.logger.error(f"GitHub API error: {response.status} - {await response.text()}")
                        return analysis_results
            
            # Get repository contents
            contents_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/git/trees/{analysis_results['repo_metadata']['default_branch']}?recursive=1"
            async with aiohttp.ClientSession() as session:
                async with session.get(contents_url, headers=headers) as response:
                    if response.status == 200:
                        contents_data = await response.json()
                        files = contents_data.get("tree", [])
                        
                        # Check for sensitive files
                        sensitive_patterns = [
                            r"\.env$", r"\.pem$", r"\.key$", r"password", r"secret", r"token", r"credential",
                            r"\.sql$", r"\.config$", r"\.cfg$", r"\.ini$", r"\.json$", r"\.yaml$", r"\.yml$",
                            r"id_rsa", r"\.aws", r"\.htpasswd", r"\.netrc"
                        ]
                        
                        for file in files:
                            if file.get("type") == "blob" and any(re.search(pattern, file.get("path", ""), re.I) for pattern in sensitive_patterns):
                                sensitive_file = {
                                    "path": file.get("path"),
                                    "url": f"https://github.com/{repo_owner}/{repo_name}/blob/{analysis_results['repo_metadata']['default_branch']}/{file.get('path')}"
                                }
                                analysis_results["sensitive_files"].append(sensitive_file)
                                
                                # Check file content for API keys
                                try:
                                    file_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/{file.get('path')}"
                                    async with session.get(file_url, headers=headers) as file_response:
                                        if file_response.status == 200:
                                            file_data = await file_response.json()
                                            if "content" in file_data:
                                                content = base64.b64decode(file_data["content"]).decode("utf-8", errors="ignore")
                                                api_keys = await self.detect_api_keys(content)
                                                if api_keys:
                                                    analysis_results["api_keys"][file.get("path")] = api_keys
                                except Exception as e:
                                    self.logger.error(f"Error analyzing file {file.get('path')}: {str(e)}")
                    else:
                        self.logger.error(f"GitHub API error: {response.status} - {await response.text()}")
            
            # Get contributors
            contributors_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contributors"
            async with aiohttp.ClientSession() as session:
                async with session.get(contributors_url, headers=headers) as response:
                    if response.status == 200:
                        contributors_data = await response.json()
                        analysis_results["contributors"] = [
                            {"username": contributor.get("login"), "contributions": contributor.get("contributions")}
                            for contributor in contributors_data
                        ]
            
            # Get commit frequency
            commits_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/commits"
            async with aiohttp.ClientSession() as session:
                async with session.get(commits_url, headers=headers) as response:
                    if response.status == 200:
                        commits_data = await response.json()
                        
                        # Calculate commit frequency by month
                        frequency = {}
                        for commit in commits_data:
                            commit_date = commit.get("commit", {}).get("author", {}).get("date", "")
                            if commit_date:
                                try:
                                    date_obj = datetime.strptime(commit_date, "%Y-%m-%dT%H:%M:%SZ")
                                    month_year = date_obj.strftime("%Y-%m")
                                    frequency[month_year] = frequency.get(month_year, 0) + 1
                                except Exception:
                                    pass
                        
                        analysis_results["commit_frequency"] = frequency
            
            # Check for security issues
            security_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/code-scanning/alerts"
            async with aiohttp.ClientSession() as session:
                async with session.get(security_url, headers=headers) as response:
                    if response.status == 200:
                        security_data = await response.json()
                        analysis_results["security_issues"] = security_data
                    # 404 might mean code scanning is not enabled
                    elif response.status != 404:
                        self.logger.error(f"GitHub API error: {response.status} - {await response.text()}")
            
        except Exception as e:
            self.logger.error(f"Error analyzing repository {repo_owner}/{repo_name}: {str(e)}")
        
        # Save the results
        output_file = self.output_dir / f"{repo_owner}_{repo_name}_analysis.json"
        with open(output_file, 'w') as f:
            json.dump(analysis_results, f, indent=2)
        
        return analysis_results
    
    async def discover_repositories(self, target: str, is_org: bool = False) -> List[Dict]:
        """
        Discover GitHub repositories related to a target
        
        Args:
            target: Organization name or domain
            is_org: Whether the target is a GitHub organization
        """
        repositories = []
        
        try:
            if is_org:
                # Get repositories for an organization
                url = f"https://api.github.com/orgs/{target}/repos?per_page=100"
                headers = {"Accept": "application/vnd.github.v3+json"}
                if self.github_token:
                    headers["Authorization"] = f"token {self.github_token}"
                
                async with aiohttp.ClientSession() as session:
                    page = 1
                    while True:
                        paged_url = f"{url}&page={page}"
                        async with session.get(paged_url, headers=headers) as response:
                            if response.status == 200:
                                repos_data = await response.json()
                                if not repos_data:
                                    break
                                
                                for repo in repos_data:
                                    repositories.append({
                                        "name": repo.get("name"),
                                        "full_name": repo.get("full_name"),
                                        "description": repo.get("description"),
                                        "url": repo.get("html_url"),
                                        "stars": repo.get("stargazers_count"),
                                        "forks": repo.get("forks_count")
                                    })
                                
                                page += 1
                            else:
                                self.logger.error(f"GitHub API error: {response.status} - {await response.text()}")
                                break
            else:
                # Search for repositories related to a domain
                search_query = f"{target} in:name,description,readme"
                search_url = f"https://api.github.com/search/repositories?q={search_query}&per_page=100"
                headers = {"Accept": "application/vnd.github.v3+json"}
                if self.github_token:
                    headers["Authorization"] = f"token {self.github_token}"
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(search_url, headers=headers) as response:
                        if response.status == 200:
                            search_data = await response.json()
                            for repo in search_data.get("items", []):
                                repositories.append({
                                    "name": repo.get("name"),
                                    "full_name": repo.get("full_name"),
                                    "description": repo.get("description"),
                                    "url": repo.get("html_url"),
                                    "stars": repo.get("stargazers_count"),
                                    "forks": repo.get("forks_count")
                                })
                        else:
                            self.logger.error(f"GitHub API error: {response.status} - {await response.text()}")
        
        except Exception as e:
            self.logger.error(f"Error discovering repositories for {target}: {str(e)}")
        
        # Save the results
        output_file = self.output_dir / f"{target}_repositories.json"
        with open(output_file, 'w') as f:
            json.dump(repositories, f, indent=2)
        
        return repositories
    
    async def run_github_recon(self, target: str, is_org: bool = False) -> Dict:
        """
        Run complete GitHub reconnaissance for a target
        
        Args:
            target: Organization name or domain
            is_org: Whether the target is a GitHub organization
        """
        self.logger.info(f"Starting GitHub reconnaissance for {target}")
        results = {"target": target, "is_org": is_org}
        
        try:
            # Step 1: Discover repositories
            repositories = await self.discover_repositories(target, is_org)
            results["repositories"] = repositories
            
            # Step 2: Search for sensitive information using dorks
            dorks_results = await self.dork_sensitive_info(organization=target if is_org else None, domain=None if is_org else target)
            results["dorks"] = dorks_results
            
            # Step 3: Analyze top repositories
            top_repos = sorted(repositories, key=lambda x: x.get("stars", 0), reverse=True)[:5]
            repo_analyses = []
            
            for repo in top_repos:
                owner, name = repo["full_name"].split("/")
                analysis = await self.analyze_repository(owner, name)
                repo_analyses.append(analysis)
                
                # Avoid GitHub API rate limits
                await asyncio.sleep(2)
            
            results["repo_analyses"] = repo_analyses
            
            # Save the comprehensive results
            output_file = self.output_dir / f"{target}_github_recon.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.logger.info(f"GitHub reconnaissance completed for {target}")
            
        except Exception as e:
            self.logger.error(f"Error during GitHub reconnaissance for {target}: {str(e)}")
        
        return results 