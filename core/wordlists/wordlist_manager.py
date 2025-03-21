import logging
from pathlib import Path
from typing import List, Set, Dict
import json
import re
from collections import Counter

class WordlistManager:
    def __init__(self, base_dir: str = "wordlists"):
        """
        Initialize the WordlistManager
        
        Args:
            base_dir: Base directory for wordlist storage
        """
        self.base_dir = Path(base_dir)
        self.logger = logging.getLogger("WordlistManager")
        
        # Create directory structure
        self.dirs = {
            "common": self.base_dir / "common",
            "subdomains": self.base_dir / "subdomains",
            "content": self.base_dir / "content",
            "custom": self.base_dir / "custom"
        }
        
        for dir_path in self.dirs.values():
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def add_wordlist(self, category: str, name: str, words: List[str]) -> bool:
        """Add a new wordlist to a category"""
        if category not in self.dirs:
            self.logger.error(f"Invalid category: {category}")
            return False
        
        try:
            output_file = self.dirs[category] / f"{name}.txt"
            output_file.write_text("\n".join(sorted(set(words))))
            return True
        except Exception as e:
            self.logger.error(f"Error adding wordlist {name}: {str(e)}")
            return False
    
    def get_wordlist(self, category: str, name: str) -> List[str]:
        """Get words from a specific wordlist"""
        wordlist_path = self.dirs[category] / f"{name}.txt"
        if not wordlist_path.exists():
            self.logger.error(f"Wordlist not found: {wordlist_path}")
            return []
        
        try:
            return wordlist_path.read_text().splitlines()
        except Exception as e:
            self.logger.error(f"Error reading wordlist {name}: {str(e)}")
            return []
    
    def create_custom_wordlist(self, name: str, sources: List[str], 
                             min_length: int = 3, max_length: int = 30) -> bool:
        """Create a custom wordlist from multiple sources"""
        words = set()
        
        for source in sources:
            source_path = Path(source)
            if not source_path.exists():
                self.logger.warning(f"Source not found: {source}")
                continue
                
            try:
                content = source_path.read_text()
                # Extract words using regex
                extracted = re.findall(r'\b\w+\b', content.lower())
                # Filter by length
                filtered = [w for w in extracted if min_length <= len(w) <= max_length]
                words.update(filtered)
            except Exception as e:
                self.logger.error(f"Error processing source {source}: {str(e)}")
        
        return self.add_wordlist("custom", name, list(words))
    
    def merge_wordlists(self, name: str, wordlists: List[Dict[str, str]]) -> bool:
        """
        Merge multiple wordlists
        
        Args:
            name: Name for the merged wordlist
            wordlists: List of dicts with 'category' and 'name' keys
        """
        merged = set()
        
        for wl in wordlists:
            if 'category' not in wl or 'name' not in wl:
                self.logger.error(f"Invalid wordlist spec: {wl}")
                continue
            
            words = self.get_wordlist(wl['category'], wl['name'])
            merged.update(words)
        
        return self.add_wordlist("custom", name, list(merged))
    
    def generate_frequency_wordlist(self, name: str, sources: List[str], 
                                  min_count: int = 2) -> bool:
        """Generate a wordlist based on word frequency in sources"""
        counter = Counter()
        
        for source in sources:
            source_path = Path(source)
            if not source_path.exists():
                self.logger.warning(f"Source not found: {source}")
                continue
                
            try:
                content = source_path.read_text()
                words = re.findall(r'\b\w+\b', content.lower())
                counter.update(words)
            except Exception as e:
                self.logger.error(f"Error processing source {source}: {str(e)}")
        
        # Get words that appear at least min_count times
        frequent_words = [word for word, count in counter.items() if count >= min_count]
        return self.add_wordlist("custom", name, frequent_words)
    
    def list_wordlists(self) -> Dict[str, List[str]]:
        """List all available wordlists by category"""
        available = {}
        
        for category, dir_path in self.dirs.items():
            available[category] = [
                f.stem for f in dir_path.glob("*.txt")
            ]
        
        return available
    
    def get_wordlist_info(self, category: str, name: str) -> Dict:
        """Get information about a specific wordlist"""
        wordlist_path = self.dirs[category] / f"{name}.txt"
        if not wordlist_path.exists():
            return {}
        
        try:
            words = wordlist_path.read_text().splitlines()
            return {
                "name": name,
                "category": category,
                "size": len(words),
                "unique_words": len(set(words)),
                "min_length": min(len(w) for w in words),
                "max_length": max(len(w) for w in words),
                "path": str(wordlist_path)
            }
        except Exception as e:
            self.logger.error(f"Error getting wordlist info: {str(e)}")
            return {} 