import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import aiohttp
import re

class GitHubScanner:
    def __init__(self, output_dir: str = "results/github"):
        """Initialize GitHub Scanner"""
        self.output_dir = Path(output_dir)
        self.secrets_dir = self.output_dir / "secrets"
        self.logger = logging.getLogger("GitHubScanner")
        
        # Create output directories for each tool
        self.tool_dirs = {
            "trufflehog": self.secrets_dir / "trufflehog",
            "githound": self.secrets_dir / "githound",
            "gitallsecrets": self.secrets_dir / "gitallsecrets",
            "gitrob": self.secrets_dir / "gitrob",
            "gitscanner": self.secrets_dir / "gitscanner",
            "reposecurity": self.secrets_dir / "reposecurity",
            "gitsecrets": self.secrets_dir / "gitsecrets"
        }
        
        # Define tool configurations
        self.tool_configs = {
            "trufflehog": {
                "cmd": ["trufflehog", "github"],
                "args": ["--json", "--entropy=True", "--regex"]
            },
            "githound": {
                "dorks": [
                    "filename:.env", "filename:config", "filename:secret",
                    "password", "credential", "api_key", "apikey", "token",
                    "secret", "private_key", "client_secret", "auth",
                    "aws_key", "aws_token", "stripe_key", "database_url"
                ]
            },
            "gitallsecrets": {
                "cmd": ["git-all-secrets"],
                "args": ["-json", "-output"]
            },
            "gitrob": {
                "cmd": ["gitrob"],
                "patterns": [
                    "id_rsa", "id_dsa", ".env", "config.yml", ".git-credentials",
                    "htpasswd", "docker_auth", "aws_access", "ssh_key"
                ]
            },
            "gitsecrets": {
                "cmd": ["git-secrets", "--scan"],
                "patterns": [
                    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                    "AKIA[0-9A-Z]{16}", "[0-9a-zA-Z/+]{40}",
                    "ghp_[0-9a-zA-Z]{36}", "github_pat_[0-9a-zA-Z]{82}"
                ]
            }
        }
        
        for directory in [self.output_dir, self.secrets_dir, *self.tool_dirs.values()]:
            directory.mkdir(parents=True, exist_ok=True)

    async def _run_trufflehog(self, repo_url: str) -> List[Dict[str, Any]]:
        """Run TruffleHog scan with enhanced configuration"""
        cmd = [
            *self.tool_configs["trufflehog"]["cmd"],
            "--repo", repo_url,
            *self.tool_configs["trufflehog"]["args"],
            "--output", str(self.tool_dirs["trufflehog"] / f"{repo_url.split('/')[-1]}.json")
        ]
        return await self._run_tool(cmd, "trufflehog")

    async def _run_githound(self, repo_url: str, github_token: str) -> List[Dict[str, Any]]:
        """Run GitHound scan with enhanced dorks"""
        findings = []
        
        for dork in self.tool_configs["githound"]["dorks"]:
            query = f"repo:{repo_url} {dork}"
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"token {github_token}"}
                url = f"https://api.github.com/search/code?q={query}"
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        for item in data.get("items", []):
                            findings.append({
                                "tool": "githound",
                                "type": f"potential_{dork}",
                                "file": item["path"],
                                "url": item["html_url"],
                                "score": item.get("score", 0),
                                "matched_term": dork
                            })
                    await asyncio.sleep(2)  # Rate limiting
        return findings

    async def _run_gitallsecrets(self, repo_url: str) -> List[Dict[str, Any]]:
        """Run git-all-secrets with enhanced configuration"""
        output_file = self.tool_dirs["gitallsecrets"] / f"{repo_url.split('/')[-1]}.json"
        cmd = [
            *self.tool_configs["gitallsecrets"]["cmd"],
            "-repo", repo_url,
            *self.tool_configs["gitallsecrets"]["args"],
            str(output_file)
        ]
        return await self._run_tool(cmd, "gitallsecrets")

    async def _run_gitrob(self, org_name: str) -> List[Dict[str, Any]]:
        """Run Gitrob with enhanced pattern matching"""
        findings = []
        output_file = self.tool_dirs["gitrob"] / f"{org_name}.json"
        
        # First run Gitrob
        cmd = [
            *self.tool_configs["gitrob"]["cmd"],
            "-organization", org_name,
            "-save", str(output_file)
        ]
        initial_findings = await self._run_tool(cmd, "gitrob")
        findings.extend(initial_findings)
        
        # Then do additional pattern matching
        for pattern in self.tool_configs["gitrob"]["patterns"]:
            cmd = f"find {self.tool_dirs['gitrob']}/temp -type f -exec grep -l '{pattern}' {{}} \\;"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            for file_path in stdout.decode().splitlines():
                findings.append({
                    "tool": "gitrob",
                    "type": "pattern_match",
                    "pattern": pattern,
                    "file": file_path
                })
        
        return findings

    async def _run_git_secrets(self, repo_url: str) -> List[Dict[str, Any]]:
        """Run git-secrets with enhanced pattern matching"""
        findings = []
        
        # Clone repository
        temp_dir = self.tool_dirs["gitsecrets"] / "temp"
        clone_cmd = f"git clone --depth 1 {repo_url} {temp_dir}"
        
        try:
            # Clone repo
            process = await asyncio.create_subprocess_shell(
                clone_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            # Install git-secrets patterns
            for pattern in self.tool_configs["gitsecrets"]["patterns"]:
                cmd = f"cd {temp_dir} && git secrets --add '{pattern}'"
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
            
            # Run scan
            cmd = [
                *self.tool_configs["gitsecrets"]["cmd"],
                str(temp_dir)
            ]
            scan_findings = await self._run_tool(cmd, "gitsecrets")
            findings.extend(scan_findings)
            
        finally:
            # Cleanup
            await asyncio.create_subprocess_shell(f"rm -rf {temp_dir}")
        
        return findings

    async def _run_gitscanner(self, repo_url: str) -> List[Dict[str, Any]]:
        """Run custom Git scanner with keyword search"""
        keywords = [
            "api_key", "apikey", "secret", "token", "password",
            "aws_access", "private_key", "ssh_key", "auth_token",
            "credentials", "jdbc", "db_password", "database_url"
        ]
        
        cmd = [
            "git", "clone", "--depth", "1",
            repo_url, str(self.tool_dirs["gitscanner"] / "temp")
        ]
        findings = []
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            # Search for keywords in files
            for keyword in keywords:
                cmd = f"grep -r -i {keyword} {self.tool_dirs['gitscanner']}/temp"
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await process.communicate()
                
                for line in stdout.decode().splitlines():
                    findings.append({
                        "tool": "gitscanner",
                        "type": f"keyword_{keyword}",
                        "line": line
                    })
                    
        finally:
            # Cleanup
            await asyncio.create_subprocess_shell(
                f"rm -rf {self.tool_dirs['gitscanner']}/temp"
            )
        
        return findings

    async def _run_repo_security_scanner(self, repo_url: str) -> List[Dict[str, Any]]:
        """Run repository security scanner"""
        patterns = {
            "aws_key": r"AKIA[0-9A-Z]{16}",
            "private_key": r"-----BEGIN (?:RSA|OPENSSH) PRIVATE KEY-----",
            "password": r"(?i)password\s*=\s*['\"]([^'\"]+)['\"]",
            "api_key": r"(?i)api[_-]?key\s*=\s*['\"]([^'\"]+)['\"]",
            "token": r"(?i)token\s*=\s*['\"]([^'\"]+)['\"]"
        }
        
        findings = []
        cmd = f"git clone --depth 1 {repo_url} {self.tool_dirs['reposecurity']}/temp"
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            # Scan files with regex patterns
            for pattern_name, pattern in patterns.items():
                cmd = f"find {self.tool_dirs['reposecurity']}/temp -type f -exec grep -l -P '{pattern}' {{}} \\;"
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await process.communicate()
                
                for file_path in stdout.decode().splitlines():
                    findings.append({
                        "tool": "reposecurity",
                        "type": pattern_name,
                        "file": file_path
                    })
                    
        finally:
            # Cleanup
            await asyncio.create_subprocess_shell(
                f"rm -rf {self.tool_dirs['reposecurity']}/temp"
            )
        
        return findings

    async def _run_tool(self, cmd: List[str], tool_name: str) -> List[Dict[str, Any]]:
        """Generic method to run a tool and handle its output"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            findings = []
            for line in stdout.decode().splitlines():
                if line.strip():
                    try:
                        finding = json.loads(line)
                        finding["tool"] = tool_name
                        findings.append(finding)
                    except json.JSONDecodeError:
                        findings.append({
                            "tool": tool_name,
                            "raw_output": line
                        })
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Error running {tool_name}: {str(e)}")
            return []

    async def scan_repository(self, repo_url: str, github_token: str) -> Dict[str, Any]:
        """Comprehensive repository scan using all tools"""
        results = {
            "repository": repo_url,
            "timestamp": datetime.now().isoformat(),
            "findings": []
        }
        
        # Run all tools concurrently
        tasks = [
            self._run_trufflehog(repo_url),
            self._run_githound(repo_url, github_token),
            self._run_gitallsecrets(repo_url),
            self._run_gitscanner(repo_url),
            self._run_repo_security_scanner(repo_url),
            self._run_git_secrets(repo_url)
        ]
        
        tool_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combine results
        for result in tool_results:
            if isinstance(result, list):
                results["findings"].extend(result)
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.secrets_dir / f"scan_{timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        return results

    async def scan_organization(self, org_name: str, github_token: str) -> Dict[str, Any]:
        """Scan entire organization"""
        results = {
            "organization": org_name,
            "timestamp": datetime.now().isoformat(),
            "repositories": [],
            "findings": []
        }
        
        try:
            # Get repositories
            repos = await self._get_org_repos(org_name, github_token)
            results["repositories"] = repos
            
            # Run Gitrob for organization-wide scan
            gitrob_results = await self._run_gitrob(org_name)
            results["findings"].extend(gitrob_results)
            
            # Scan each repository
            for repo in repos:
                repo_results = await self.scan_repository(repo["clone_url"], github_token)
                results["findings"].extend(repo_results["findings"])
            
            # Save results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.secrets_dir / f"{org_name}_{timestamp}_full_scan.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Error scanning organization {org_name}: {str(e)}")
        
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