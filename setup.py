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
from colorama import Fore, Style

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
            # Update package lists
            try:
                subprocess.run(["sudo", "apt-get", "update"], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to update package lists: {str(e)}")
                raise

            # Core packages that should be available on all systems
            core_packages = [
                "git", "python3-pip", "python3-dev", "python3-venv",
                "build-essential", "libpq-dev", "postgresql", "postgresql-contrib",
                "nmap", "masscan", "whois", "jq", "libpcap-dev", "libxml2-dev",
                "libxslt1-dev", "ruby-full", "zlib1g-dev", "nodejs", "npm", "docker.io"
            ]

            # Filter out already installed packages
            to_install = []
            for pkg in core_packages:
                if not self._check_tool_installed(pkg.split('-')[0]):  # Handle packages like python3-pip
                    to_install.append(pkg)

            if to_install:
                try:
                    subprocess.run(["sudo", "apt-get", "install", "-y"] + to_install, check=True)
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to install core packages: {str(e)}")
                    raise
            else:
                logger.info("All core packages are already installed")

            # Try to install Chromium if not already installed
            if not self._check_tool_installed("chromium") and not self._check_tool_installed("chromium-browser"):
                chromium_packages = ["chromium", "chromium-browser"]
                chromium_installed = False
                
                for pkg in chromium_packages:
                    try:
                        subprocess.run(["sudo", "apt-get", "install", "-y", pkg], check=True)
                        chromium_installed = True
                        logger.info(f"Successfully installed {pkg}")
                        break
                    except subprocess.CalledProcessError:
                        logger.warning(f"Failed to install {pkg}, trying alternative...")
                        continue

                if not chromium_installed:
                    logger.warning("Could not install Chromium. Please install it manually.")
                    print(f"{Fore.YELLOW}⚠️ Warning: Could not install Chromium. You may need to install it manually.{Style.RESET_ALL}")
            else:
                logger.info("Chromium is already installed")

        elif self.system == "darwin":  # macOS
            try:
                subprocess.run(["brew", "update"], check=True)
                packages = [
                    "git", "python3", "postgresql", "nmap", "masscan",
                    "whois", "jq", "node", "docker", "chromium"
                ]
                
                for pkg in packages:
                    try:
                        subprocess.run(["brew", "install", pkg], check=True)
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"Failed to install {pkg}: {str(e)}")
                        print(f"⚠️ Warning: Failed to install {pkg}")
                        continue
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to update Homebrew: {str(e)}")
                raise
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
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", "--break-system-packages", req], check=True)
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to install {req}: {str(e)}")
                print(f"{Fore.YELLOW}⚠️ Warning: Failed to install {req}. You may need to install it manually.{Style.RESET_ALL}")
                continue

    def _install_go(self):
        """Install or update Go"""
        print("📦 Checking Go installation...")
        
        try:
            # Check if Go is already installed and get version
            go_version = subprocess.run(
                ["go", "version"], 
                capture_output=True, 
                text=True
            ).stdout.strip()
            
            if go_version:
                logger.info(f"Go is already installed: {go_version}")
                return
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.info("Go not found, installing...")
        
        print("Installing Go...")
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

    def _check_tool_installed(self, tool: str) -> bool:
        """Check if a tool is already installed"""
        try:
            subprocess.run(["which", tool], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def _check_go_tool_installed(self, tool_path: str) -> bool:
        """Check if a Go tool is already installed"""
        try:
            gopath = Path.home() / "go"
            tool_name = tool_path.split('/')[-1].split('@')[0]
            if self.system == "windows":
                tool_binary = gopath / "bin" / f"{tool_name}.exe"
            else:
                tool_binary = gopath / "bin" / tool_name
            return tool_binary.exists()
        except Exception:
            return False

    def _install_security_tools(self):
        """Install required security tools"""
        print("🛠️ Installing security tools...")
        
        # Go tools
        go_tools = [
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "github.com/owasp-amass/amass/v3/...@latest",
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
            "github.com/Brosck/mantra@latest",
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
        
        # Install only missing Go tools
        for tool in tqdm(go_tools, desc="Checking/Installing Go tools"):
            if not self._check_go_tool_installed(tool):
                try:
                    subprocess.run(["go", "install", "-v", tool], check=True)
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Failed to install {tool}: {str(e)}")
                    continue
            else:
                logger.debug(f"Tool already installed: {tool}")
        
        # Git repositories - Enhanced with more nuclei templates
        git_repos = {
            # Existing repositories
            "massdns": "https://github.com/blechschmidt/massdns.git",
            "trufflehog": "https://github.com/trufflesecurity/trufflehog.git",
            "gitleaks": "https://github.com/zricethezav/gitleaks.git",
            
            # Main nuclei templates repositories
            "nuclei-templates": "https://github.com/projectdiscovery/nuclei-templates.git",
            "nuclei-templates-collection": "https://github.com/emadshanab/Nuclei-Templates-Collection.git",
            
            # Additional template repositories
            
            "kenzer-templates": {
                "url": "https://github.com/ARPSyndicate/kenzer-templates.git",
                "dir": "nuclei-templates/custom/kenzer"
            },
            "nuclei-templates-bb": {
                "url": "https://github.com/esetal/nuclei-bb-templates.git",
                "dir": "nuclei-templates/custom/bb-templates"
            },
            "fuzzing-templates": {
                "url": "https://github.com/0x71rex/0-fuzzing-templates.git",
                "dir": "nuclei-templates/custom/fuzzing"
            },
            
            # Rest of the existing repositories...
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
        
        # Create nuclei templates directory structure
        nuclei_base = self.tools_dir / "nuclei-templates"
        os.makedirs(nuclei_base / "custom", exist_ok=True)
        
        # Clone only missing repositories
        for name, repo_info in tqdm(git_repos.items(), desc="Checking/Cloning repositories"):
            try:
                if isinstance(repo_info, dict):
                    repo_url = repo_info["url"]
                    repo_dir = self.tools_dir / repo_info["dir"]
                else:
                    repo_url = repo_info
                    repo_dir = self.tools_dir / name
                
                if not repo_dir.exists():
                    os.makedirs(os.path.dirname(repo_dir), exist_ok=True)
                    subprocess.run(["git", "clone", repo_url, str(repo_dir)], check=True)
                    
                    # Special handling for nuclei-templates-collection
                    if name == "nuclei-templates-collection":
                        self._process_template_collection(repo_dir)
                    
                    # Build tools that require compilation
                    if name == "massdns":
                        subprocess.run(["make"], cwd=str(repo_dir), check=True)
                    
                    # Install Python requirements if they exist
                    requirements_file = repo_dir / "requirements.txt"
                    if requirements_file.exists():
                        try:
                            # First try installing without problematic packages
                            with open(requirements_file, 'r') as f:
                                requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                            
                            # Filter out known problematic packages
                            skip_packages = ['datrie']
                            filtered_requirements = [req for req in requirements if not any(skip in req.lower() for skip in skip_packages)]
                            
                            if filtered_requirements:
                                try:
                                    subprocess.run([
                                        sys.executable, "-m", "pip", "install",
                                        "--break-system-packages"
                                    ] + filtered_requirements, check=True)
                                except subprocess.CalledProcessError as e:
                                    logger.warning(f"Failed to install some requirements for {name}: {str(e)}")
                        except Exception as e:
                            logger.warning(f"Failed to process requirements for {name}: {str(e)}")
                else:
                    logger.debug(f"Repository already exists: {name}")
                
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to clone/build {name}: {str(e)}")
                continue

    def _process_template_collection(self, collection_dir: Path):
        """Process and organize templates from the Nuclei-Templates-Collection"""
        print("📝 Processing additional nuclei templates...")
        
        try:
            # Create bulk_clone_repos.py if it doesn't exist in the collection
            bulk_clone_script = collection_dir / "bulk_clone_repos.py"
            if not bulk_clone_script.exists():
                script_content = '''
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor

def clone_repo(repo_url, base_dir):
    try:
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        target_dir = os.path.join(base_dir, repo_name)
        if not os.path.exists(target_dir):
            subprocess.run(['git', 'clone', repo_url, target_dir], check=True)
            print(f"Successfully cloned {repo_url}")
    except Exception as e:
        print(f"Failed to clone {repo_url}: {str(e)}")

def main():
    base_dir = "templates"
    os.makedirs(base_dir, exist_ok=True)
    
    # Read repository URLs from README.md
    with open("README.md", "r") as f:
        content = f.read()
    
    # Extract repository URLs
    repos = []
    for line in content.split('\n'):
        if line.startswith('https://github.com/') and 'nuclei' in line.lower():
            repos.append(line.strip())
    
    # Clone repositories in parallel
    with ThreadPoolExecutor(max_workers=5) as executor:
        for repo in repos:
            executor.submit(clone_repo, repo, base_dir)

if __name__ == "__main__":
    main()
'''
                with open(bulk_clone_script, 'w') as f:
                    f.write(script_content)
            
            # Run the bulk clone script
            subprocess.run([sys.executable, str(bulk_clone_script)], cwd=str(collection_dir), check=True)
            
            # Create a unified templates directory
            unified_dir = collection_dir / "unified_templates"
            os.makedirs(unified_dir, exist_ok=True)
            
            # Copy all .yaml files to unified directory
            subprocess.run(f"find {collection_dir}/templates -name '*.yaml' -exec cp {{}} {unified_dir} \\;", shell=True)
            subprocess.run(f"find {collection_dir}/templates -name '*.yml' -exec cp {{}} {unified_dir} \\;", shell=True)
            
            print(f"✅ Successfully processed and organized templates in {unified_dir}")
            
        except Exception as e:
            logger.error(f"Error processing template collection: {str(e)}")
            print(f"{Fore.YELLOW}⚠️ Warning: Some templates may not have been processed correctly{Style.RESET_ALL}")

    def _setup_database(self):
        """Set up PostgreSQL database"""
        print("🗄️ Checking PostgreSQL setup...")
        
        if self.system == "linux":
            try:
                # Check if database already exists
                check_db = subprocess.run(
                    ["sudo", "-u", "postgres", "psql", "-lqt"],
                    capture_output=True,
                    text=True
                )
                if "reconbuddy" in check_db.stdout:
                    logger.info("PostgreSQL database already exists")
                    return
                
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
            except Exception as e:
                logger.error(f"Error setting up database: {str(e)}")

    def _download_wordlists(self):
        """Download and set up wordlists"""
        print("📚 Checking wordlists...")
        
        wordlists = [
            ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt", "dns-prefixes.txt"),
            ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt", "subdomains-top1m.txt"),
            ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt", "directories-medium.txt"),
            ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt", "common-paths.txt"),
            ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt", "api-endpoints.txt")
        ]
        
        for url, filename in tqdm(wordlists, desc="Checking/Downloading wordlists"):
            output_file = self.wordlists_dir / filename
            if not output_file.exists():
                subprocess.run(["curl", "-o", str(output_file), url], check=True)
            else:
                logger.debug(f"Wordlist already exists: {filename}")

    def _configure_environment(self):
        """Configure environment variables and settings"""
        print("⚙️ Configuring environment...")
        
        env_vars = {
            "RECONBUDDY_HOME": str(self.base_dir),
            "RECONBUDDY_CONFIG": str(self.config_file),
            "RECONBUDDY_TOOLS": str(self.tools_dir),
            "RECONBUDDY_WORDLISTS": str(self.wordlists_dir),
            "GOPATH": str(Path.home() / "go"),
            "PATH": f"$PATH:$GOPATH/bin:{str(self.tools_dir)}/massdns/bin",
            "NUCLEI_TEMPLATES_PATH": f"{str(self.tools_dir)}/nuclei-templates:{str(self.tools_dir)}/nuclei-templates-collection/unified_templates"
        }
        
        # Check if environment variables are already set
        shell_rc = Path.home() / (".bashrc" if self.system == "linux" else ".zshrc")
        if shell_rc.exists():
            current_content = shell_rc.read_text()
            if "# ReconBuddy Environment Variables" in current_content:
                logger.info("Environment variables already configured")
                return
        
        # Add to shell rc file
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