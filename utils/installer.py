#!/usr/bin/env python3
import os
import sys
import subprocess
import logging
import shutil
from pathlib import Path
from typing import List, Tuple
import platform
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ReconBuddyInstaller:
    def __init__(self):
        self.base_dir = Path.home() / "ReconBuddy"
        self.tools_dir = self.base_dir / "tools"
        self.venv_dir = self.base_dir / "venv"
        self.wordlists_dir = self.base_dir / "wordlists"
        self.system = platform.system().lower()
        
    def install(self):
        """Main installation method"""
        try:
            print("🚀 Starting ReconBuddy Installation")
            
            # Create directories
            self._create_directories()
            
            # Install system dependencies
            self._install_system_dependencies()
            
            # Set up Python virtual environment
            self._setup_virtual_environment()
            
            # Install Python dependencies
            self._install_python_dependencies()
            
            # Install security tools
            self._install_security_tools()
            
            # Download wordlists
            self._download_wordlists()
            
            # Configure environment
            self._configure_environment()
            
            print("✅ ReconBuddy installation completed successfully!")
            
        except Exception as e:
            logger.error(f"Installation failed: {str(e)}")
            print(f"❌ Installation failed: {str(e)}")
            sys.exit(1)

    def _create_directories(self):
        """Create necessary directories"""
        print("📁 Creating directories...")
        os.makedirs(self.base_dir, exist_ok=True)
        os.makedirs(self.tools_dir, exist_ok=True)
        os.makedirs(self.wordlists_dir, exist_ok=True)
        logger.info("Created base directories")

    def _install_system_dependencies(self):
        """Install system-level dependencies"""
        print("📦 Installing system dependencies...")
        
        if self.system == "linux":
            packages = [
                "git", "python3-pip", "python3-venv", "golang",
                "build-essential", "chromium-browser", "nmap",
                "masscan", "whois", "jq", "make", "gcc"
            ]
            self._run_command(["sudo", "apt-get", "update"])
            self._run_command(["sudo", "apt-get", "install", "-y"] + packages)
            
        elif self.system == "darwin":  # macOS
            self._run_command(["brew", "update"])
            packages = [
                "git", "python3", "go", "nmap", "masscan",
                "whois", "jq", "chromium", "make", "gcc"
            ]
            for pkg in packages:
                self._run_command(["brew", "install", pkg])
        else:
            raise OSError("Unsupported operating system")

    def _setup_virtual_environment(self):
        """Set up Python virtual environment"""
        print("🐍 Setting up Python virtual environment...")
        self._run_command(["python3", "-m", "venv", str(self.venv_dir)])
        logger.info("Created virtual environment")

    def _install_python_dependencies(self):
        """Install Python package dependencies"""
        print("📚 Installing Python dependencies...")
        pip = str(self.venv_dir / "bin" / "pip")
        
        requirements = [
            "aiohttp>=3.8.0",
            "beautifulsoup4>=4.9.0",
            "dnspython>=2.1.0",
            "tqdm>=4.65.0",
            "colorama>=0.4.6",
            "python-whois>=0.7.0",
            "selenium>=4.0.0",
            "webdriver-manager>=3.8.0",
            "aiodns>=3.0.0",
            "aiosqlite>=0.17.0",
            "aiofiles>=0.8.0",
            "pyyaml>=6.0.0",
            "jinja2>=3.0.0",
            "cryptography>=3.4.0",
            "requests>=2.31.0"
        ]
        
        for req in requirements:
            self._run_command([pip, "install", req])

    def _install_security_tools(self):
        """Install required security tools"""
        print("🛠️ Installing security tools...")
        
        # Set up Go environment
        os.environ["GOPATH"] = str(Path.home() / "go")
        os.environ["PATH"] = os.environ["PATH"] + ":" + str(Path.home() / "go" / "bin")
        
        # Subdomain enumeration tools
        go_tools = [
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "github.com/OWASP/Amass/v3/...@master",
            "github.com/tomnomnom/assetfinder@latest",
            "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
            "github.com/ffuf/ffuf@latest",
            "github.com/OJ/gobuster/v3@latest",
            "github.com/tomnomnom/waybackurls@latest",
            "github.com/lc/gau/v2/cmd/gau@latest",
            "github.com/projectdiscovery/katana/cmd/katana@latest",
            "github.com/hakluke/hakrawler@latest",
            "github.com/jaeles-project/gospider@latest",
            "github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
            "github.com/tomnomnom/anew@latest",
            "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        ]
        
        for tool in tqdm(go_tools, desc="Installing Go tools"):
            try:
                self._run_command(["go", "install", "-v", tool])
            except Exception as e:
                logger.error(f"Failed to install {tool}: {str(e)}")
        
        # Git-based tools
        git_tools = [
            ("massdns", "https://github.com/blechschmidt/massdns.git"),
            ("SubDomainizer", "https://github.com/nsonaniya2010/SubDomainizer.git"),
            ("Sublist3r", "https://github.com/aboul3la/Sublist3r.git"),
            ("dnsvalidator", "https://github.com/vortexau/dnsvalidator.git")
        ]
        
        for tool_name, repo_url in tqdm(git_tools, desc="Installing Git-based tools"):
            tool_dir = self.tools_dir / tool_name
            try:
                self._run_command(["git", "clone", repo_url, str(tool_dir)])
                if tool_name == "massdns":
                    self._run_command(["make"], cwd=str(tool_dir))
                elif tool_name in ["SubDomainizer", "Sublist3r"]:
                    pip = str(self.venv_dir / "bin" / "pip")
                    self._run_command([pip, "install", "-r", str(tool_dir / "requirements.txt")])
            except Exception as e:
                logger.error(f"Failed to install {tool_name}: {str(e)}")

    def _download_wordlists(self):
        """Download and set up wordlists"""
        print("📚 Downloading wordlists...")
        
        wordlists = [
            ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt", "dns-prefixes.txt"),
            ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt", "subdomains-top1m.txt"),
            ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt", "directories-medium.txt"),
            ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt", "common-paths.txt"),
            ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt", "api-endpoints.txt")
        ]
        
        for url, filename in tqdm(wordlists, desc="Downloading wordlists"):
            try:
                output_file = self.wordlists_dir / filename
                self._run_command(["curl", "-o", str(output_file), url])
            except Exception as e:
                logger.error(f"Failed to download {filename}: {str(e)}")

    def _configure_environment(self):
        """Configure environment variables and settings"""
        print("⚙️ Configuring environment...")
        
        env_file = self.base_dir / ".env"
        env_vars = {
            "RECONBUDDY_HOME": str(self.base_dir),
            "RECONBUDDY_TOOLS": str(self.tools_dir),
            "RECONBUDDY_WORDLISTS": str(self.wordlists_dir),
            "GOPATH": str(Path.home() / "go"),
            "PATH": f"$PATH:{str(Path.home())}/go/bin:{str(self.tools_dir)}/massdns/bin"
        }
        
        with open(env_file, "w") as f:
            for key, value in env_vars.items():
                f.write(f"{key}={value}\n")
        
        # Add environment variables to shell rc file
        shell_rc = Path.home() / (".bashrc" if self.system == "linux" else ".zshrc")
        with open(shell_rc, "a") as f:
            f.write(f"\n# ReconBuddy Environment Variables\n")
            for key, value in env_vars.items():
                f.write(f'export {key}="{value}"\n')

    def _run_command(self, command: List[str], cwd: str = None) -> None:
        """Run a shell command"""
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, cwd=cwd)
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {' '.join(command)}")
            logger.error(f"Error: {e.stderr}")
            raise

def main():
    try:
        installer = ReconBuddyInstaller()
        installer.install()
    except KeyboardInterrupt:
        print("\n⚠️ Installation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Installation failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()