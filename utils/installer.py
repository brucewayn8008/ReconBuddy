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
            
            # Install PostgreSQL
            self._install_postgresql()
            
            # Set up database
            self._setup_database()
            
            # Install security tools
            self._install_security_tools()
            
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
        logger.info("Created base directories")

    def _install_system_dependencies(self):
        """Install system-level dependencies"""
        print("📦 Installing system dependencies...")
        
        if self.system == "linux":
            packages = [
                "git", "python3-pip", "python3-venv", "golang",
                "build-essential", "libpq-dev", "jq"
            ]
            self._run_command(["sudo", "apt-get", "update"])
            self._run_command(["sudo", "apt-get", "install", "-y"] + packages)
            
        elif self.system == "darwin":  # macOS
            self._run_command(["brew", "update"])
            packages = ["git", "python3", "go", "jq", "postgresql"]
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
            "sqlalchemy>=1.4.0",
            "psycopg2-binary>=2.9.0",
            "colorama>=0.4.6",
            "tqdm>=4.65.0",
            "alembic>=1.11.0",
            "python-dotenv>=1.0.0",
            "requests>=2.31.0",
            "pyyaml>=6.0.0"
        ]
        
        for req in requirements:
            self._run_command([pip, "install", req])

    def _install_postgresql(self):
        """Install and configure PostgreSQL"""
        print("🐘 Setting up PostgreSQL...")
        
        if self.system == "linux":
            self._run_command(["sudo", "systemctl", "start", "postgresql"])
            self._run_command(["sudo", "systemctl", "enable", "postgresql"])
        elif self.system == "darwin":
            self._run_command(["brew", "services", "start", "postgresql"])

    def _setup_database(self):
        """Set up ReconBuddy database"""
        print("🗄️ Setting up database...")
        
        try:
            self._run_command(["createdb", "reconbuddy"])
            logger.info("Created reconbuddy database")
        except Exception as e:
            logger.warning(f"Database might already exist: {str(e)}")

    def _install_security_tools(self):
        """Install required security tools"""
        print("🛠️ Installing security tools...")
        
        tools = [
            ("reconftw", "git clone https://github.com/six2dez/reconftw.git"),
            ("httpx", "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
            ("nuclei", "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"),
            ("amass", "go install -v github.com/OWASP/Amass/v3/...@master"),
            ("subfinder", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
            ("assetfinder", "go install github.com/tomnomnom/assetfinder@latest"),
            ("gobuster", "go install github.com/OJ/gobuster/v3@latest"),
            ("hakrawler", "go install github.com/hakluke/hakrawler@latest"),
            ("gau", "go install github.com/lc/gau/v2/cmd/gau@latest"),
            ("waybackurls", "go install github.com/tomnomnom/waybackurls@latest"),
            ("katana", "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
            ("anew", "go install github.com/tomnomnom/anew@latest")
        ]

        os.environ["GOPATH"] = str(Path.home() / "go")
        os.environ["PATH"] = os.environ["PATH"] + ":" + str(Path.home() / "go" / "bin")

        for tool_name, install_cmd in tools:
            print(f"Installing {tool_name}...")
            self._run_command(install_cmd.split())

    def _configure_environment(self):
        """Configure environment variables and settings"""
        print("⚙️ Configuring environment...")
        
        env_file = self.base_dir / ".env"
        env_vars = {
            "RECONBUDDY_DB_URL": "postgresql://localhost:5432/reconbuddy",
            "RECONBUDDY_HOME": str(self.base_dir),
            "PATH": f"$PATH:{str(Path.home())}/go/bin"
        }
        
        with open(env_file, "w") as f:
            for key, value in env_vars.items():
                f.write(f"{key}={value}\n")
        
        # Add environment variables to shell rc file
        shell_rc = Path.home() / (".bashrc" if self.system == "linux" else ".zshrc")
        with open(shell_rc, "a") as f:
            f.write(f"\n# ReconBuddy Environment Variables\n")
            f.write(f'export RECONBUDDY_HOME="{str(self.base_dir)}"\n')
            f.write('export PATH="$PATH:$HOME/go/bin"\n')

    def _run_command(self, command: List[str]) -> None:
        """Run a shell command"""
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
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