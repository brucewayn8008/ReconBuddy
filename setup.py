#!/usr/bin/env python3
import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path
import yaml
from typing import List, Dict
import logging
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ReconBuddySetup:
    def __init__(self):
        self.base_dir = Path.home() / "ReconBuddy"
        self.tools_dir = self.base_dir / "tools"
        self.wordlists_dir = self.base_dir / "wordlists"
        self.config_file = self.base_dir / "config.yaml"
        self.system = platform.system().lower()
        self.is_arm = platform.machine().lower() in ["arm64", "aarch64", "armv7l"]

    def setup(self):
        """Main setup method"""
        try:
            print("🚀 Starting ReconBuddy Setup")
            
            # Create directories
            self._create_directories()
            
            # Copy config file
            self._setup_config()
            
            # Install system dependencies
            self._install_system_dependencies()
            
            # Install Python dependencies
            self._install_python_dependencies()
            
            # Install Go
            self._install_go()
            
            # Install security tools
            self._install_security_tools()
            
            # Set up PostgreSQL
            self._setup_database()
            
            # Download wordlists
            self._download_wordlists()
            
            # Configure environment
            self._configure_environment()
            
            print("✅ ReconBuddy setup completed successfully!")
            print("\n📝 Next steps:")
            print("1. Edit config.yaml to add your API keys")
            print("2. Run 'source ~/.bashrc' or 'source ~/.zshrc' to load environment variables")
            print("3. Start using ReconBuddy!")
            
        except Exception as e:
            logger.error(f"Setup failed: {str(e)}")
            sys.exit(1)

    def _create_directories(self):
        """Create necessary directories"""
        print("📁 Creating directories...")
        os.makedirs(self.base_dir, exist_ok=True)
        os.makedirs(self.tools_dir, exist_ok=True)
        os.makedirs(self.wordlists_dir, exist_ok=True)

    def _setup_config(self):
        """Set up configuration file"""
        print("⚙️ Setting up configuration...")
        if not self.config_file.exists():
            shutil.copy("config.yaml", self.config_file)

    def _install_system_dependencies(self):
        """Install system-level dependencies"""
        print("📦 Installing system dependencies...")
        
        if self.system == "linux":
            packages = [
                "git", "python3-pip", "python3-dev", "python3-venv",
                "build-essential", "libpq-dev", "postgresql", "postgresql-contrib",
                "chromium-browser", "nmap", "masscan", "whois", "jq",
                "libpcap-dev", "libxml2-dev", "libxslt1-dev", "ruby-full",
                "zlib1g-dev", "nodejs", "npm", "docker.io"
            ]
            
            subprocess.run(["sudo", "apt-get", "update"], check=True)
            subprocess.run(["sudo", "apt-get", "install", "-y"] + packages, check=True)
            
        elif self.system == "darwin":  # macOS
            subprocess.run(["brew", "update"], check=True)
            packages = [
                "git", "python3", "postgresql", "nmap", "masscan",
                "whois", "jq", "node", "docker", "chromium"
            ]
            
            for pkg in packages:
                subprocess.run(["brew", "install", pkg], check=True)
        else:
            raise OSError(f"Unsupported operating system: {self.system}")

    def _install_python_dependencies(self):
        """Install Python package dependencies"""
        print("🐍 Installing Python dependencies...")
        requirements = [
            "aiohttp>=3.8.0",
            "beautifulsoup4>=4.9.0",
            "dnspython>=2.1.0",
            "flask>=2.0.0",
            "flask-sqlalchemy>=2.5.0",
            "psycopg2-binary>=2.9.0",
            "pyyaml>=6.0.0",
            "requests>=2.31.0",
            "tqdm>=4.65.0",
            "colorama>=0.4.6",
            "python-whois>=0.7.0",
            "aiodns>=3.0.0",
            "aiofiles>=0.8.0",
            "jinja2>=3.0.0",
            "markdown2>=2.4.0",
            "pdfkit>=1.0.0",
            "google-cloud-aiplatform>=1.25.0"
        ]
        
        for req in tqdm(requirements, desc="Installing Python packages"):
            subprocess.run([sys.executable, "-m", "pip", "install", req], check=True)

    def _install_go(self):
        """Install or update Go"""
        print("📦 Installing/Updating Go...")
        
        if self.system == "linux":
            if self.is_arm:
                go_url = "https://go.dev/dl/go1.21.0.linux-arm64.tar.gz"
            else:
                go_url = "https://go.dev/dl/go1.21.0.linux-amd64.tar.gz"
        elif self.system == "darwin":
            if self.is_arm:
                go_url = "https://go.dev/dl/go1.21.0.darwin-arm64.tar.gz"
            else:
                go_url = "https://go.dev/dl/go1.21.0.darwin-amd64.tar.gz"
        else:
            raise OSError(f"Unsupported operating system for Go installation: {self.system}")
        
        subprocess.run(["wget", go_url, "-O", "/tmp/go.tar.gz"], check=True)
        subprocess.run(["sudo", "rm", "-rf", "/usr/local/go"], check=True)
        subprocess.run(["sudo", "tar", "-C", "/usr/local", "-xzf", "/tmp/go.tar.gz"], check=True)
        os.environ["PATH"] = f"/usr/local/go/bin:{os.environ['PATH']}"

    def _install_security_tools(self):
        """Install required security tools"""
        print("🛠️ Installing security tools...")
        
        # Go tools
        go_tools = [
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "github.com/OWASP/Amass/v3/...@master",
            "github.com/tomnomnom/assetfinder@latest",
            "github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
            "github.com/ffuf/ffuf@latest",
            "github.com/tomnomnom/waybackurls@latest",
            "github.com/lc/gau/v2/cmd/gau@latest",
            "github.com/projectdiscovery/katana/cmd/katana@latest",
            "github.com/hakluke/hakrawler@latest",
            "github.com/tomnomnom/anew@latest",
            "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            "github.com/tomnomnom/gf@latest",
            "github.com/jaeles-project/gospider@latest",
            
            # Additional tools from install.py
            "github.com/x90skysn3k/brutespray@latest",
            "github.com/tomnomnom/qsreplace@latest",
            "github.com/gwen001/github-subdomains@latest",
            "github.com/gwen001/gitlab-subdomains@latest",
            "github.com/projectdiscovery/notify/cmd/notify@latest",
            "github.com/tomnomnom/unfurl@v0.3.0",
            "github.com/gwen001/github-endpoints@latest",
            "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            "github.com/lc/subjs@latest",
            "github.com/KathanP19/Gxss@latest",
            "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest",
            "github.com/hahwul/dalfox/v2@latest",
            "github.com/d3mondev/puredns/v2@latest",
            "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
            "github.com/Josue87/analyticsrelationships@latest",
            "github.com/Josue87/gotator@latest",
            "github.com/Josue87/roboxtractor@latest",
            "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest",
            "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",
            "github.com/pwnesia/dnstake/cmd/dnstake@latest",
            "github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
            "github.com/damit5/gitdorks_go@latest",
            "github.com/s0md3v/smap/cmd/smap@latest",
            "github.com/trickest/dsieve@master",
            "github.com/tomnomnom/hacks/inscope@latest",
            "github.com/trickest/enumerepo@latest",
            "github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest",
            "github.com/hakluke/hakip2host@latest",
            "github.com/MrEmpy/mantra@latest",
            "github.com/cemulus/crt@latest",
            "github.com/sa7mon/s3scanner@latest",
            "github.com/sdcampbell/nmapurls@latest",
            "github.com/bitquark/shortscan/cmd/shortscan@latest",
            "github.com/sw33tLie/sns@latest",
            "github.com/kleiton0x00/ppmap@latest",
            "github.com/denandz/sourcemapper@latest",
            "github.com/BishopFox/jsluice/cmd/jsluice@latest"
        ]
        
        os.environ["GOPATH"] = str(Path.home() / "go")
        os.environ["PATH"] = f"{os.environ['GOPATH']}/bin:{os.environ['PATH']}"
        
        for tool in tqdm(go_tools, desc="Installing Go tools"):
            try:
                subprocess.run(["go", "install", "-v", tool], check=True)
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to install {tool}: {str(e)}")
                continue
        
        # Git repositories - adding more from install.py
        git_repos = {
            "massdns": "https://github.com/blechschmidt/massdns.git",
            "trufflehog": "https://github.com/trufflesecurity/trufflehog.git",
            "gitleaks": "https://github.com/zricethezav/gitleaks.git",
            "nuclei-templates": "https://github.com/projectdiscovery/nuclei-templates.git",
            "SecLists": "https://github.com/danielmiessler/SecLists.git",
            "dorks_hunter": "https://github.com/six2dez/dorks_hunter.git",
            "dnsvalidator": "https://github.com/vortexau/dnsvalidator.git",
            "interlace": "https://github.com/codingo/Interlace.git",
            "wafw00f": "https://github.com/EnableSecurity/wafw00f.git",
            "Gf-Patterns": "https://github.com/1ndianl33t/Gf-Patterns.git",
            "Corsy": "https://github.com/s0md3v/Corsy.git",
            "CMSeeK": "https://github.com/Tuhinshubhra/CMSeeK.git",
            "fav-up": "https://github.com/pielco11/fav-up.git",
            "Oralyzer": "https://github.com/r0075h3ll/Oralyzer.git",
            "testssl": "https://github.com/drwetter/testssl.sh.git",
            "commix": "https://github.com/commixproject/commix.git",
            "JSA": "https://github.com/w9w/JSA.git",
            "cloud_enum": "https://github.com/initstring/cloud_enum.git",
            "ultimate-nmap-parser": "https://github.com/shifty0g/ultimate-nmap-parser.git",
            "pydictor": "https://github.com/LandGrey/pydictor.git",
            "urless": "https://github.com/xnl-h4ck3r/urless.git",
            "smuggler": "https://github.com/defparam/smuggler.git",
            "regulator": "https://github.com/cramppet/regulator.git",
            "ghauri": "https://github.com/r0oth3x49/ghauri.git",
            "nomore403": "https://github.com/devploit/nomore403.git",
            "SwaggerSpy": "https://github.com/UndeadSec/SwaggerSpy.git",
            "LeakSearch": "https://github.com/JoelGMSec/LeakSearch.git",
            "ffufPostprocessing": "https://github.com/Damian89/ffufPostprocessing.git",
            "misconfig-mapper": "https://github.com/intigriti/misconfig-mapper.git",
            "Spoofy": "https://github.com/MattKeeley/Spoofy.git"
        }
        
        for name, url in tqdm(git_repos.items(), desc="Cloning repositories"):
            repo_dir = self.tools_dir / name
            if not repo_dir.exists():
                try:
                    subprocess.run(["git", "clone", url, str(repo_dir)], check=True)
                    
                    # Build tools that require compilation
                    if name == "massdns":
                        subprocess.run(["make"], cwd=str(repo_dir), check=True)
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Failed to clone/build {name}: {str(e)}")
                    continue

    def _setup_database(self):
        """Set up PostgreSQL database"""
        print("🗄️ Setting up PostgreSQL database...")
        
        if self.system == "linux":
            # Start PostgreSQL service
            subprocess.run(["sudo", "systemctl", "start", "postgresql"], check=True)
            
            # Create database and user
            try:
                subprocess.run([
                    "sudo", "-u", "postgres", "psql",
                    "-c", "CREATE DATABASE reconbuddy;"
                ], check=True)
                
                subprocess.run([
                    "sudo", "-u", "postgres", "psql",
                    "-c", "CREATE USER reconbuddy WITH PASSWORD 'reconbuddy';"
                ], check=True)
                
                subprocess.run([
                    "sudo", "-u", "postgres", "psql",
                    "-c", "GRANT ALL PRIVILEGES ON DATABASE reconbuddy TO reconbuddy;"
                ], check=True)
            except subprocess.CalledProcessError:
                logger.warning("Database might already exist, continuing...")

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
            output_file = self.wordlists_dir / filename
            subprocess.run(["curl", "-o", str(output_file), url], check=True)

    def _configure_environment(self):
        """Configure environment variables and settings"""
        print("⚙️ Configuring environment...")
        
        env_vars = {
            "RECONBUDDY_HOME": str(self.base_dir),
            "RECONBUDDY_CONFIG": str(self.config_file),
            "RECONBUDDY_TOOLS": str(self.tools_dir),
            "RECONBUDDY_WORDLISTS": str(self.wordlists_dir),
            "GOPATH": str(Path.home() / "go"),
            "PATH": f"$PATH:$GOPATH/bin:{str(self.tools_dir)}/massdns/bin"
        }
        
        # Add to shell rc file
        shell_rc = Path.home() / (".bashrc" if self.system == "linux" else ".zshrc")
        with open(shell_rc, "a") as f:
            f.write("\n# ReconBuddy Environment Variables\n")
            for key, value in env_vars.items():
                f.write(f'export {key}="{value}"\n')

def main():
    try:
        setup = ReconBuddySetup()
        setup.setup()
    except KeyboardInterrupt:
        print("\n⚠️ Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Setup failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 