import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import aiohttp

class GitHubScanner:
    def __init__(self, output_dir: str = "results/github"):
        """
        Initialize GitHub Scanner
        
        Args:
            output_dir: Directory to store scan results
        """
        self.output_dir = Path(output_dir)
        self.secrets_dir = self.output_dir / "secrets"
        self.logger = logging.getLogger("GitHubScanner")
        
        for directory in [self.output_dir, self.secrets_dir]:
            directory.mkdir(parents=True, exist_ok=True)

    async def scan_organization(self, org_name: str, github_token: str) -> Dict[str, Any]:
        """
        Scan an entire GitHub organization
        
        Args:
            org_name: GitHub organization name
            github_token: GitHub API token
        """
        results = {
            "organization": org_name,
            "timestamp": datetime.now().isoformat(),
            "repositories": [],
            "secrets": []
        }
        
        try:
            # First get all repositories
            repos = await self._get_org_repos(org_name, github_token)
            results["repositories"] = repos
            
            # Scan each repository with TruffleHog
            for repo in repos:
                secrets = await self._scan_repo_with_trufflehog(repo["clone_url"])
                if secrets:
                    results["secrets"].extend(secrets)
            
            # Save results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.secrets_dir / f"{org_name}_{timestamp}_secrets.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.logger.info(f"Completed GitHub scan for {org_name}. Found {len(results['secrets'])} potential secrets")
            
        except Exception as e:
            self.logger.error(f"Error scanning GitHub organization {org_name}: {str(e)}")
        
        return results

    async def _get_org_repos(self, org_name: str, github_token: str) -> List[Dict[str, Any]]:
        """Get all repositories from an organization"""
        repos = []
        page = 1
        
        async with aiohttp.ClientSession() as session:
            while True:
                url = f"https://api.github.com/orgs/{org_name}/repos"
                headers = {
                    "Authorization": f"token {github_token}",
                    "Accept": "application/vnd.github.v3+json"
                }
                params = {"page": page, "per_page": 100}
                
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status != 200:
                        break
                    
                    data = await response.json()
                    if not data:
                        break
                    
                    repos.extend(data)
                    page += 1
        
        return repos

    async def _scan_repo_with_trufflehog(self, repo_url: str) -> List[Dict[str, Any]]:
        """
        Scan a repository using TruffleHog
        
        Args:
            repo_url: Repository clone URL
        """
        try:
            # Run TruffleHog
            cmd = [
                "trufflehog",
                "github",
                "--repo", repo_url,
                "--json"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            # Parse results
            findings = []
            for line in stdout.decode().splitlines():
                if line.strip():
                    try:
                        finding = json.loads(line)
                        findings.append({
                            "repository": repo_url,
                            "file_path": finding.get("path"),
                            "commit": finding.get("commit"),
                            "secret_type": finding.get("type"),
                            "secret": finding.get("secret"),
                            "timestamp": finding.get("date")
                        })
                    except json.JSONDecodeError:
                        continue
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Error scanning repository {repo_url}: {str(e)}")
            return []

    async def scan_user(self, username: str, github_token: str) -> Dict[str, Any]:
        """
        Scan a GitHub user's repositories
        
        Args:
            username: GitHub username
            github_token: GitHub API token
        """
        results = {
            "username": username,
            "timestamp": datetime.now().isoformat(),
            "repositories": [],
            "secrets": []
        }
        
        try:
            # Get user's repositories
            async with aiohttp.ClientSession() as session:
                url = f"https://api.github.com/users/{username}/repos"
                headers = {
                    "Authorization": f"token {github_token}",
                    "Accept": "application/vnd.github.v3+json"
                }
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        repos = await response.json()
                        results["repositories"] = repos
                        
                        # Scan each repository
                        for repo in repos:
                            secrets = await self._scan_repo_with_trufflehog(repo["clone_url"])
                            if secrets:
                                results["secrets"].extend(secrets)
            
            # Save results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.secrets_dir / f"{username}_{timestamp}_secrets.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.logger.info(f"Completed GitHub scan for user {username}. Found {len(results['secrets'])} potential secrets")
            
        except Exception as e:
            self.logger.error(f"Error scanning GitHub user {username}: {str(e)}")
        
        return results

if __name__ == "__main__":
    # Example usage
    async def main():
        scanner = GitHubScanner()
        github_token = "your_github_token_here"
        
        # Scan organization
        org_results = await scanner.scan_organization("example-org", github_token)
        print(json.dumps(org_results, indent=2))
        
        # Scan user
        user_results = await scanner.scan_user("example-user", github_token)
        print(json.dumps(user_results, indent=2))
    
    asyncio.run(main()) 