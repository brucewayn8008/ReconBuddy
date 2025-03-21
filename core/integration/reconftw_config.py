import os
import json
import logging
from typing import Dict, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class ReconFTWConfig:
    """Handler for ReconFTW configuration files."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the configuration handler."""
        self.config_path = config_path or self._get_default_config_path()
        self.config = self._load_config()
    
    def _get_default_config_path(self) -> str:
        """Get the default configuration file path."""
        # Check common locations for reconftw.cfg
        possible_paths = [
            os.path.expanduser("~/reconftw/reconftw.cfg"),
            os.path.expanduser("~/tools/reconftw/reconftw.cfg"),
            "/opt/reconftw/reconftw.cfg",
            os.path.join(os.getcwd(), "reconftw/reconftw.cfg")
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
                
        # If no config found, create a new one in the current directory
        default_path = os.path.join(os.getcwd(), "reconftw.cfg")
        self._create_default_config(default_path)
        return default_path
    
    def _create_default_config(self, path: str) -> None:
        """Create a default configuration file."""
        default_config = {
            "threads": 50,
            "timeout": 30,
            "recursive": False,
            "deep": False,
            "quiet": False,
            "output_dir": "reconftw",
            "tools": {
                "subfinder": True,
                "amass": True,
                "httpx": True,
                "nuclei": True,
                "gau": True,
                "waybackurls": True,
                "katana": True,
                "hakrawler": True,
                "dalfox": True,
                "gospider": True,
                "jaeles": True,
                "kiterunner": True,
                "ffuf": True,
                "meg": True,
                "gittools": True,
                "subjack": True,
                "massdns": True,
                "dnsrecon": True,
                "httpx-toolkit": True,
                "nuclei-templates": True,
                "gf-patterns": True,
                "secfiles": True,
                "wordlists": True
            },
            "api_keys": {
                "github": "",
                "virustotal": "",
                "shodan": "",
                "censys": "",
                "securitytrails": "",
                "passivetotal": "",
                "binaryedge": "",
                "spyse": "",
                "intelx": "",
                "hunter": "",
                "haveibeenpwned": "",
                "fullhunt": "",
                "chaos": "",
                "github_tokens": []
            }
        }
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # Write default config
        with open(path, 'w') as f:
            json.dump(default_config, f, indent=4)
            
        logger.info(f"Created default configuration at {path}")
    
    def _load_config(self) -> Dict:
        """Load the configuration file."""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load configuration: {str(e)}")
            raise
    
    def save_config(self) -> None:
        """Save the current configuration to file."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
            logger.info("Configuration saved successfully")
        except Exception as e:
            logger.error(f"Failed to save configuration: {str(e)}")
            raise
    
    def update_config(self, updates: Dict) -> None:
        """Update the configuration with new values."""
        try:
            # Deep update the configuration
            self._deep_update(self.config, updates)
            self.save_config()
            logger.info("Configuration updated successfully")
        except Exception as e:
            logger.error(f"Failed to update configuration: {str(e)}")
            raise
    
    def _deep_update(self, d: Dict, u: Dict) -> None:
        """Recursively update a dictionary."""
        for k, v in u.items():
            if isinstance(v, dict):
                d[k] = self._deep_update(d.get(k, {}), v)
            else:
                d[k] = v
        return d
    
    def get_tool_config(self, tool_name: str) -> bool:
        """Get the configuration for a specific tool."""
        return self.config.get("tools", {}).get(tool_name, False)
    
    def set_tool_config(self, tool_name: str, enabled: bool) -> None:
        """Set the configuration for a specific tool."""
        if "tools" not in self.config:
            self.config["tools"] = {}
        self.config["tools"][tool_name] = enabled
        self.save_config()
    
    def get_api_key(self, service: str) -> str:
        """Get the API key for a specific service."""
        return self.config.get("api_keys", {}).get(service, "")
    
    def set_api_key(self, service: str, key: str) -> None:
        """Set the API key for a specific service."""
        if "api_keys" not in self.config:
            self.config["api_keys"] = {}
        self.config["api_keys"][service] = key
        self.save_config()
    
    def get_scan_options(self) -> Dict:
        """Get the general scan options."""
        return {
            "threads": self.config.get("threads", 50),
            "timeout": self.config.get("timeout", 30),
            "recursive": self.config.get("recursive", False),
            "deep": self.config.get("deep", False),
            "quiet": self.config.get("quiet", False),
            "output_dir": self.config.get("output_dir", "reconftw")
        }
    
    def set_scan_options(self, options: Dict) -> None:
        """Set the general scan options."""
        for key, value in options.items():
            if key in ["threads", "timeout", "recursive", "deep", "quiet", "output_dir"]:
                self.config[key] = value
        self.save_config() 