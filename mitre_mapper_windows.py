#!/usr/bin/env python3
"""
mitre_mapper_windows.py

Simple security automation tool that:
- Reads Windows Security event logs from local system Event Log (default) or CSV file.
- Normalizes events.
- Maps selected Event IDs to MITRE ATT&CK tactics/techniques using dynamic rules
  from Sigma rules repository and MITRE ATT&CK API.
- Writes an enriched CSV report.

Usage example:
    # Read from Windows Security Event Log (default)
    python mitre_mapper_windows.py
    
    # Read from CSV file
    python mitre_mapper_windows.py --csv security.csv
    
    # Specify output file
    python mitre_mapper_windows.py --output report.csv
"""

import argparse # for command line arguments
import csv # for CSV data
import json # for JSON data
import os # for environment variables
import shutil # for file operations
import yaml # for YAML data
from pathlib import Path # for file paths
from typing import Dict, Any, Iterable, List, Optional # for type hints
from datetime import datetime # for date and time
import requests # for HTTP requests
# Load .env file from script's directory
def _load_env_file_manual(env_path: Path) -> bool:
    """
    Manually parse .env file and set environment variables.
    Fallback if load_dotenv() doesn't work.
    
    Returns:
        True if any variables were loaded, False otherwise
    """
    try:
        if not env_path.exists():
            return False
        
        loaded = False
        with open(env_path, 'r', encoding='utf-8-sig') as f:  # utf-8-sig handles BOM
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Parse KEY=VALUE
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Remove quotes if present
                    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                        value = value[1:-1]
                    # Remove brackets if present
                    if value.startswith('[') and value.endswith(']'):
                        value = value[1:-1].strip()
                    
                    if key and value:
                        os.environ[key] = value
                        loaded = True
        
        return loaded
    except Exception:
        return False

# Get the directory where this script is located
script_dir = Path(__file__).parent.absolute()
env_path = script_dir / ".env"

try:
    from dotenv import load_dotenv  # pyright: ignore[reportMissingImports] # for .env file support
    # Try loading from script directory first
    if env_path.exists():
        # Use dotenv_path parameter (works in python-dotenv >= 0.10.0)
        load_dotenv(dotenv_path=str(env_path), override=True)
    else:
        # Fallback: try current directory (load_dotenv searches upward by default)
        load_dotenv(override=True)
except ImportError:
    # dotenv is optional, will use manual parsing below
    pass

# Always try manual parsing as fallback (handles cases where load_dotenv fails silently)
# This ensures the token is loaded even if load_dotenv() has issues
if env_path.exists():
    _load_env_file_manual(env_path)
try:
    from mitreattack.stix20 import MitreAttackData # for MITRE ATT&CK data
except ImportError:
    # Fallback for older versions
    MitreAttackData = None

try:
    import win32evtlog # for Windows Event Log
    import win32evtlogutil # for Windows Event Log utilities
    import win32security # for Windows security
    import win32con # for Windows constants
    WINDOWS_EVENT_LOG_AVAILABLE = True
except ImportError:
    WINDOWS_EVENT_LOG_AVAILABLE = False


# -----------------------------
# Constants
# -----------------------------

# Event Log constants
EVENT_ID_MASK = 0xFFFF  # Mask to extract lower 16 bits of Event ID
DEFAULT_LOG_NAME = "Security" # default log name
DEFAULT_SOURCE = "windows_security" # default source

# Severity constants
SEVERITY_ORDER_DICT = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4
}
SEVERITY_ORDER_LIST = ["critical", "high", "medium", "low", "informational"]
DEFAULT_SEVERITY = "medium"
DEFAULT_SEVERITY_INDEX = 2  # Index for "medium" in severity order

# Rule ID prefix
RULE_ID_PREFIX = "sigma_"

# Event type mappings
EVENT_TYPE_MAP = {
    1: "Error",
    2: "Warning",
    4: "Information",
    8: "Audit Success",
    16: "Audit Failure"
}

# Event Log read flags (Windows only)
if WINDOWS_EVENT_LOG_AVAILABLE:
    EVENTLOG_READ_FLAGS = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ # event log read flags
else:
    EVENTLOG_READ_FLAGS = None # event log read flags

# -----------------------------
# Dynamic Rule Engine Configuration
# -----------------------------

SIGMA_RULES_REPO = "https://api.github.com/repos/SigmaHQ/sigma/contents/rules/windows" # Sigma rules repository
SIGMA_RAW_BASE = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows" # Sigma raw base


def get_github_token() -> Optional[str]:
    """
    Get GitHub token from environment variable or .env file.
    
    Checks in order:
    1. GITHUB_TOKEN environment variable
    2. GITHUB_PAT environment variable (alternative name)
    
    Returns:
        GitHub token string if found, None otherwise
    """
    # Try GITHUB_TOKEN first (most common)
    token = os.getenv("GITHUB_TOKEN")
    if token:
        token = token.strip()
        # Remove common formatting issues (quotes, brackets)
        if token.startswith('[') and token.endswith(']'):
            token = token[1:-1].strip()
        if (token.startswith('"') and token.endswith('"')) or (token.startswith("'") and token.endswith("'")):
            token = token[1:-1].strip()
        if token:
            return token
    
    # Try GITHUB_PAT as alternative
    token = os.getenv("GITHUB_PAT")
    if token:
        token = token.strip()
        # Remove common formatting issues (quotes, brackets)
        if token.startswith('[') and token.endswith(']'):
            token = token[1:-1].strip()
        if (token.startswith('"') and token.endswith('"')) or (token.startswith("'") and token.endswith("'")):
            token = token[1:-1].strip()
        if token:
            return token
    
    return None


def check_github_rate_limit(headers: Dict[str, str]) -> Optional[Dict[str, int]]:
    """
    Check GitHub API rate limit status.
    
    Args:
        headers: Request headers (may include Authorization token)
    
    Returns:
        Dictionary with 'remaining', 'limit', 'reset' keys, or None if check fails
    """
    try:
        # Use a lightweight endpoint to check rate limit
        response = requests.get("https://api.github.com/rate_limit", headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            core = data.get("resources", {}).get("core", {})
            return {
                "remaining": core.get("remaining", 0),
                "limit": core.get("limit", 60),
                "reset": core.get("reset", 0)
            }
    except requests.RequestException:
        pass
    return None


class DynamicRuleEngine:
    """
    Dynamic rule engine that fetches Sigma rules and uses MITRE ATT&CK API
    to build mappings from Windows Event IDs to ATT&CK techniques.
    """

    def __init__(self, cache_dir: Optional[str] = None, refresh_rules: bool = False):
        """
        Initialize the dynamic rule engine.

        Args:
            cache_dir: Optional directory to cache Sigma rules and ATT&CK data.
                      If None, uses a default cache directory.
            refresh_rules: If True, force refresh of Sigma rules from GitHub even if cache exists.
        """
        self.cache_dir = Path(cache_dir) if cache_dir else Path.home() / ".mitre_mapper_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.sigma_rules_cache = self.cache_dir / "sigma_rules.json"
        self.attack_cache = self.cache_dir / "attack_techniques.json"
        
        # In-memory caches
        self._event_id_to_techniques: Dict[str, List[Dict[str, Any]]] = {}
        self._technique_details: Dict[str, Dict[str, Any]] = {}
        
        # Initialize MITRE ATT&CK data
        print("[*] Initializing MITRE ATT&CK data...")
        self.attack_data = None
        if MitreAttackData:
            try:
                # Download enterprise-attack.json if not cached
                enterprise_attack_file = self.cache_dir / "enterprise-attack.json"
                if not enterprise_attack_file.exists():
                    print("[*] Downloading enterprise-attack.json from MITRE...")
                    enterprise_attack_url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
                    response = requests.get(enterprise_attack_url, timeout=60)
                    response.raise_for_status()
                    with open(enterprise_attack_file, "wb") as f:
                        f.write(response.content)
                    print("[+] Downloaded enterprise-attack.json")
                
                # Load the STIX file
                self.attack_data = MitreAttackData(str(enterprise_attack_file))
                print("[+] MITRE ATT&CK data loaded successfully")
            except (requests.RequestException, IOError, OSError, ValueError) as e:
                print(f"[!] Warning: Could not load MITRE ATT&CK data: {e}")
                print("[!] Falling back to cached data if available")
        else:
            print("[!] Warning: mitreattack-python not available, using cached data only")
        
        # Load or build rules
        self._load_or_build_rules(refresh=refresh_rules)

    def _load_or_build_rules(self, refresh: bool = False) -> None:
        """
        Load cached rules or fetch and build them from Sigma repository.
        
        Args:
            refresh: If True, force refresh from GitHub even if cache exists.
        """
        # If refresh is requested, skip cache loading
        if refresh:
            print("[*] Refresh flag set, forcing re-fetch from GitHub...")
            if self.sigma_rules_cache.exists():
                print("[*] Backing up existing cache...")
                backup_path = self.sigma_rules_cache.with_suffix('.json.backup')
                try:
                    shutil.copy2(self.sigma_rules_cache, backup_path)
                    print(f"[+] Backup saved to {backup_path}")
                except (IOError, OSError) as e:
                    print(f"[!] Warning: Could not backup cache: {e}")
        elif self.sigma_rules_cache.exists():
            try:
                with open(self.sigma_rules_cache, "r", encoding="utf-8") as f:
                    cached = json.load(f)
                    self._event_id_to_techniques = cached.get("event_id_mappings", {})
                    num_mappings = len(self._event_id_to_techniques)
                    print(f"[+] Loaded {num_mappings} Event ID mappings from cache")
                    
                    # If cache is empty, fetch rules
                    if num_mappings == 0:
                        print("[!] Cache is empty, fetching Sigma rules...")
                        self._fetch_and_parse_sigma_rules()
                        # Always merge fallback rules as baseline
                        self._load_fallback_rules()
                        self._save_rules_cache()
                    else:
                        # Always merge fallback rules as baseline
                        self._load_fallback_rules()
                    return
            except (json.JSONDecodeError, IOError, OSError, KeyError) as e:
                print(f"[!] Error loading cache: {e}, rebuilding...")
        
        print("[*] Fetching Sigma rules from GitHub...")
        self._fetch_and_parse_sigma_rules()
        
        # Always merge fallback rules as baseline
        self._load_fallback_rules()
        
        # Save to cache
        self._save_rules_cache()

    def _fetch_and_parse_sigma_rules(self) -> None:
        """
        Fetch Sigma rules from GitHub and parse them to extract Event ID mappings.
        Only processes 'builtin' and 'security' subdirectories under rules/windows.
        Recursively processes subdirectories within those two directories.
        """
        try:
            # Get GitHub token if available
            github_token = get_github_token()
            headers = {}
            if github_token:
                headers["Authorization"] = f"token {github_token}"
                print("[*] Using GitHub token for API requests (increased rate limit)")
            else:
                print("[*] No GitHub token found - using unauthenticated requests (60/hour limit)")
                # Show where we're looking for .env file
                script_dir = Path(__file__).parent.absolute()
                env_path = script_dir / ".env"
                print(f"[*] Looking for .env file at: {env_path}")
                if not env_path.exists():
                    print(f"[!] .env file not found at {env_path}")
                    print("[*] To increase limit to 5,000/hour, create .env file with: GITHUB_TOKEN=your_token")
                else:
                    # Debug: check what's actually in the environment
                    env_token = os.getenv("GITHUB_TOKEN", "")
                    env_pat = os.getenv("GITHUB_PAT", "")
                    print(f"[!] .env file found but GITHUB_TOKEN not set or empty")
                    print(f"[*] Environment check - GITHUB_TOKEN: {'set' if env_token else 'not set'}, GITHUB_PAT: {'set' if env_pat else 'not set'}")
                    if env_token:
                        print(f"[*] GITHUB_TOKEN value length: {len(env_token)}, starts with: {env_token[:5]}...")
                    print("[*] Ensure .env file contains (no quotes, no brackets): GITHUB_TOKEN=your_token_here")
                    print("[*] Example: GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
            
            # Check rate limit before starting
            rate_limit_info = check_github_rate_limit(headers)
            if rate_limit_info:
                remaining = rate_limit_info["remaining"]
                limit = rate_limit_info["limit"]
                if remaining == 0:
                    reset_time = rate_limit_info["reset"]
                    import time
                    current_time = int(time.time())
                    wait_seconds = reset_time - current_time
                    if wait_seconds > 0:
                        wait_minutes = wait_seconds // 60
                        print(f"[!] Error: GitHub API rate limit exhausted (0/{limit} remaining)")
                        print(f"[!] Rate limit resets in {wait_minutes} minutes ({wait_seconds} seconds)")
                        print("[!] Options:")
                        print("[!]   1. Wait for rate limit to reset")
                        if not github_token:
                            print("[!]   2. Add a GitHub token to your .env file")
                            print("[!]      Create .env file with: GITHUB_TOKEN=your_token_here")
                        print("[!]   3. Use existing cache (don't use --refresh flag)")
                        print("[!] Falling back to cached rules if available")
                        return
                else:
                    print(f"[*] GitHub API rate limit: {remaining}/{limit} requests remaining")
            
            # Only process these top-level directories under rules/windows
            RELEVANT_DIRECTORIES = {"builtin", "security"}
            
            # Recursively collect all YAML files from relevant subdirectories
            yaml_files = []
            directories_to_process = []  # Start with only relevant directories
            directories_processed = 0
            
            # First, get the root directory to find builtin and security
            print("[*] Scanning for 'builtin' and 'security' directories...")
            try:
                response = requests.get(SIGMA_RULES_REPO, headers=headers, timeout=30)
                
                # Handle rate limit errors specifically
                if response.status_code == 403:
                    rate_limit_remaining = response.headers.get("X-RateLimit-Remaining", "0")
                    rate_limit_reset = response.headers.get("X-RateLimit-Reset")
                    
                    if rate_limit_remaining == "0" or (rate_limit_remaining and int(rate_limit_remaining) == 0):
                        print("[!] Error: GitHub API rate limit exceeded")
                        if rate_limit_reset:
                            import time
                            reset_time = int(rate_limit_reset)
                            current_time = int(time.time())
                            wait_seconds = reset_time - current_time
                            if wait_seconds > 0:
                                wait_minutes = wait_seconds // 60
                                print(f"[!] Rate limit resets in {wait_minutes} minutes ({wait_seconds} seconds)")
                        print("[!] Options:")
                        print("[!]   1. Wait for rate limit to reset (usually 1 hour)")
                        if not github_token:
                            print("[!]   2. Add a GitHub token to your .env file to increase limit to 5,000/hour")
                            print("[!]      Create .env file with: GITHUB_TOKEN=your_token_here")
                        else:
                            print("[!]   2. Your token may have hit its limit - wait for reset")
                        print("[!]   3. Use existing cache (don't use --refresh flag)")
                        print("[!] Falling back to cached rules if available")
                        return
                
                response.raise_for_status()
                
                # Check rate limit on first request
                rate_limit_remaining = response.headers.get("X-RateLimit-Remaining")
                rate_limit_total = response.headers.get("X-RateLimit-Limit")
                if rate_limit_remaining:
                    remaining = int(rate_limit_remaining)
                    total = int(rate_limit_total) if rate_limit_total else 60
                    if remaining < 10:
                        print(f"[!] Warning: GitHub API rate limit low ({remaining}/{total} requests remaining)")
                        if not github_token:
                            print("[!] Consider using a GitHub token to increase rate limits to 5,000/hour")
                    else:
                        print(f"[*] GitHub API rate limit: {remaining}/{total} requests remaining")
                
                items = response.json()
                
                # Find and queue only relevant directories
                for item in items:
                    item_type = item.get("type")
                    item_name = item.get("name", "")
                    
                    if item_type == "dir" and item_name.lower() in RELEVANT_DIRECTORIES:
                        directories_to_process.append(item_name)
                        print(f"[*] Found relevant directory: {item_name}")
                    elif item_type == "file" and item_name.endswith(".yml"):
                        # Also check root directory for any YAML files (unlikely but possible)
                        item["relative_path"] = item_name
                        yaml_files.append(item)
            
            except requests.RequestException as e:
                # Check if it's a rate limit error
                if hasattr(e, 'response') and e.response is not None:
                    if e.response.status_code == 403:
                        print("[!] Error: GitHub API rate limit exceeded")
                        print("[!] Falling back to cached rules if available")
                        return
                print(f"[!] Warning: Could not fetch root directory: {e}")
                print("[!] Falling back to cached rules if available")
                return
            
            # Now recursively process only the relevant directories
            while directories_to_process:
                directories_processed += 1
                current_dir = directories_to_process.pop(0)
                
                # Build API URL for current directory
                api_url = f"{SIGMA_RULES_REPO}/{current_dir}"
                
                try:
                    response = requests.get(api_url, headers=headers, timeout=30)
                    
                    # Handle rate limit errors
                    if response.status_code == 403:
                        print(f"[!] Error: Rate limit exceeded while fetching '{current_dir}'")
                        print("[!] Stopping directory traversal - will use partial results")
                        break
                    
                    response.raise_for_status()
                    
                    items = response.json()
                    
                    # Process items: collect files, queue subdirectories
                    for item in items:
                        item_type = item.get("type")
                        item_name = item.get("name", "")
                        
                        if item_type == "file" and item_name.endswith(".yml"):
                            # Add full path for subdirectories
                            item["relative_path"] = f"{current_dir}/{item_name}"
                            yaml_files.append(item)
                        elif item_type == "dir":
                            # Recursively process subdirectories within builtin/security
                            directories_to_process.append(f"{current_dir}/{item_name}")
                
                except requests.RequestException as e:
                    # Check if it's a rate limit error
                    if hasattr(e, 'response') and e.response is not None:
                        if e.response.status_code == 403:
                            print(f"[!] Error: Rate limit exceeded while fetching '{current_dir}'")
                            print("[!] Stopping directory traversal - will use partial results")
                            break
                    print(f"[!] Warning: Could not fetch directory '{current_dir}': {e}")
                    continue
            
            print(f"[*] Found {len(yaml_files)} Sigma rule files across {directories_processed} directories, parsing...")
            
            event_id_mappings: Dict[str, List[Dict[str, Any]]] = {}  # event_id -> list of rule info
            
            for file_info in yaml_files:
                try:
                    # Fetch the raw YAML content
                    raw_url = file_info.get("download_url")
                    if not raw_url:
                        continue
                    
                    # Use same headers (token) for downloading rule files
                    rule_response = requests.get(raw_url, headers=headers, timeout=10)
                    
                    # Handle rate limit errors when downloading files
                    if rule_response.status_code == 403:
                        print(f"[!] Error: Rate limit exceeded while downloading rule files")
                        print(f"[!] Processed {len(event_id_mappings)} Event ID mappings before rate limit")
                        print("[!] Will use partial results")
                        break
                    
                    rule_response.raise_for_status()
                    
                    # Parse YAML
                    rule_data = yaml.safe_load(rule_response.text)
                    if not rule_data:
                        continue
                    
                    # Extract Event IDs and ATT&CK technique IDs
                    event_ids = self._extract_event_ids(rule_data)
                    technique_ids = self._extract_technique_ids(rule_data)
                    
                    if not event_ids or not technique_ids:
                        continue
                    
                    # Extract comprehensive rule metadata
                    level = rule_data.get("level", DEFAULT_SEVERITY)
                    title = rule_data.get("title", "")
                    description = rule_data.get("description", "")
                    author = rule_data.get("author", "")
                    references = rule_data.get("references", [])
                    falsepositives = rule_data.get("falsepositives", [])
                    status = rule_data.get("status", "")
                    date = rule_data.get("date", "")
                    
                    # Convert date to string if it's a date/datetime object (YAML parsing can create these)
                    if date and not isinstance(date, str):
                        if hasattr(date, 'isoformat'):
                            # datetime or date object
                            date = date.isoformat()
                        else:
                            # Fallback: convert to string
                            date = str(date)
                    
                    # Create mappings - store rule metadata with each technique
                    for event_id in event_ids:
                        if event_id not in event_id_mappings:
                            event_id_mappings[event_id] = []
                        for tech_id in technique_ids:
                            # Avoid duplicates
                            if not any(r.get("technique_id") == tech_id for r in event_id_mappings[event_id]):
                                event_id_mappings[event_id].append({
                                    "technique_id": tech_id,
                                    "level": level,
                                    "title": title,
                                    "description": description,
                                    "author": author,
                                    "references": references if isinstance(references, list) else [references] if references else [],
                                    "falsepositives": falsepositives if isinstance(falsepositives, list) else [falsepositives] if falsepositives else [],
                                    "status": status,
                                    "date": date
                                })
                            
                except (requests.RequestException, yaml.YAMLError, KeyError, AttributeError, ValueError) as e:
                    # Skip files that can't be parsed
                    continue
            
            # Store the mappings
            self._event_id_to_techniques = event_id_mappings
            
            print(f"[+] Parsed {len(self._event_id_to_techniques)} unique Event IDs with mappings")
            
        except (requests.RequestException, IOError, OSError, ValueError) as e:
            print(f"[!] Error fetching Sigma rules: {e}")
            print("[!] Using fallback hardcoded rules only")
            # Fallback rules will be loaded by caller if needed

    def _extract_event_ids(self, rule_data: Dict[str, Any]) -> List[str]:
        """Extract Event IDs from a Sigma rule's detection section."""
        event_ids = []
        
        detection = rule_data.get("detection", {})
        logsource = rule_data.get("logsource", {})
        
        # Check if this is a Windows Security log source
        if logsource.get("product") != "windows":
            return event_ids
        
        service = logsource.get("service", "").lower()
        if service not in ("security", "system", "") and "security" not in service:
            return event_ids
        
        # Extract EventID from detection selections
        for selection_name, selection_data in detection.items():
            if selection_name == "condition":
                continue
            
            if isinstance(selection_data, dict):
                if "EventID" in selection_data:
                    event_id_value = selection_data["EventID"]
                    if isinstance(event_id_value, list):
                        event_ids.extend([str(eid) for eid in event_id_value])
                    else:
                        event_ids.append(str(event_id_value))
            elif isinstance(selection_data, list):
                # Handle list of maps
                for item in selection_data:
                    if isinstance(item, dict) and "EventID" in item:
                        event_id_value = item["EventID"]
                        if isinstance(event_id_value, list):
                            event_ids.extend([str(eid) for eid in event_id_value])
                        else:
                            event_ids.append(str(event_id_value))
        
        return list(set(event_ids))  # Remove duplicates

    def _extract_technique_ids(self, rule_data: Dict[str, Any]) -> List[str]:
        """Extract MITRE ATT&CK technique IDs from a Sigma rule's tags."""
        technique_ids = []
        
        tags = rule_data.get("tags", [])
        for tag in tags:
            if isinstance(tag, str) and tag.startswith("attack.t"):
                # Extract technique ID (e.g., "attack.t1110.001" -> "T1110.001")
                tech_id = tag.replace("attack.", "").upper()
                technique_ids.append(tech_id)
        
        return technique_ids

    def _get_technique_details(self, technique_id: str) -> Dict[str, Any]:
        """Get technique details from MITRE ATT&CK API with caching."""
        if technique_id in self._technique_details:
            return self._technique_details[technique_id]
        
        # Try to load from cache
        if self.attack_cache.exists():
            try:
                with open(self.attack_cache, "r", encoding="utf-8") as f:
                    cached = json.load(f)
                    if technique_id in cached:
                        cached_details = cached[technique_id]
                        # If cached entry is missing tactics, we'll refresh it below
                        # Otherwise, use cached data
                        if cached_details.get("tactic"):
                            self._technique_details[technique_id] = cached_details
                            return cached_details
                        # If no tactic in cache, continue to refresh it
            except (json.JSONDecodeError, IOError, OSError, KeyError):
                pass
        
        # Query MITRE ATT&CK API
        details = {
            "technique_id": technique_id,
            "technique_name": "",
            "tactic": "",
            "description": ""
        }
        
        if self.attack_data:
            try:
                # Get technique by ATT&CK ID
                technique = self.attack_data.get_object_by_attack_id(technique_id, "attack-pattern")
                if technique:
                    details["technique_name"] = self.attack_data.get_name(technique.id) or ""
                    details["description"] = getattr(technique, "description", "") or ""
                    
                    # Get tactics using multiple methods for better coverage
                    tactics = []
                    tactic_names_set = set()  # Use set to avoid duplicates
                    
                    # Method 1: Get from kill chain phases (most reliable - this is how ATT&CK associates techniques with tactics)
                    try:
                        kill_chain_phases = getattr(technique, "kill_chain_phases", [])
                        if kill_chain_phases:
                            # Tactic name mapping
                            tactic_map = {
                                "initial-access": "Initial Access",
                                "execution": "Execution",
                                "persistence": "Persistence",
                                "privilege-escalation": "Privilege Escalation",
                                "defense-evasion": "Defense Evasion",
                                "credential-access": "Credential Access",
                                "discovery": "Discovery",
                                "lateral-movement": "Lateral Movement",
                                "collection": "Collection",
                                "command-and-control": "Command and Control",
                                "exfiltration": "Exfiltration",
                                "impact": "Impact"
                            }
                            
                            for phase in kill_chain_phases:
                                phase_name = None
                                kill_chain_name = None
                                
                                # Handle both dict and object formats
                                if isinstance(phase, dict):
                                    phase_name = phase.get("phase_name", "")
                                    kill_chain_name = phase.get("kill_chain_name", "")
                                elif hasattr(phase, "phase_name"):
                                    phase_name = getattr(phase, "phase_name", "")
                                    kill_chain_name = getattr(phase, "kill_chain_name", "")
                                
                                # Only process mitre-attack kill chain phases
                                if kill_chain_name == "mitre-attack" and phase_name:
                                    readable_tactic = tactic_map.get(phase_name.lower(), phase_name.title())
                                    if readable_tactic and readable_tactic not in tactic_names_set:
                                        tactics.append(readable_tactic)
                                        tactic_names_set.add(readable_tactic)
                    except (AttributeError, KeyError, TypeError):
                        pass
                    
                    # Method 2: Use get_tactics_by_technique (uses relationships internally)
                    # This supplements kill chain phases and may find additional tactic associations
                    if not tactics:
                        try:
                            tactic_objects = self.attack_data.get_tactics_by_technique(technique.id)
                            if tactic_objects:
                                for tactic_entry in tactic_objects:
                                    tactic_name = None
                                    # Handle RelationshipEntry format: {"object": tactic_obj, "relationships": [...]}
                                    if isinstance(tactic_entry, dict):
                                        if "object" in tactic_entry:
                                            tactic_obj = tactic_entry["object"]
                                            if hasattr(tactic_obj, "id"):
                                                tactic_name = self.attack_data.get_name(tactic_obj.id)
                                            elif hasattr(tactic_obj, "name"):
                                                tactic_name = tactic_obj.name
                                        elif "name" in tactic_entry:
                                            tactic_name = tactic_entry["name"]
                                    elif hasattr(tactic_entry, "id"):
                                        # Direct tactic object
                                        tactic_name = self.attack_data.get_name(tactic_entry.id)
                                    elif hasattr(tactic_entry, "name"):
                                        tactic_name = tactic_entry.name
                                    
                                    if tactic_name and tactic_name not in tactic_names_set:
                                        tactics.append(tactic_name)
                                        tactic_names_set.add(tactic_name)
                        except (AttributeError, KeyError, TypeError):
                            pass
                    
                    details["tactic"] = ", ".join(tactics) if tactics else ""
            except (AttributeError, KeyError, TypeError, ValueError) as e:
                # Fallback if API call fails
                pass
        
        # Cache the result
        self._technique_details[technique_id] = details
        
        # Update cache file
        self._save_attack_cache()
        
        return details

    def _save_rules_cache(self) -> None:
        """Save Event ID mappings to cache."""
        try:
            with open(self.sigma_rules_cache, "w", encoding="utf-8") as f:
                json.dump({
                    "event_id_mappings": {
                        k: v for k, v in self._event_id_to_techniques.items()
                    }
                }, f, indent=2)
        except (IOError, OSError, TypeError) as e:
            print(f"[!] Warning: Could not save rules cache: {e}")

    def _save_attack_cache(self) -> None:
        """Save ATT&CK technique details to cache."""
        try:
            with open(self.attack_cache, "w", encoding="utf-8") as f:
                json.dump(self._technique_details, f, indent=2)
        except (IOError, OSError, TypeError) as e:
            print(f"[!] Warning: Could not save ATT&CK cache: {e}")

    def _load_fallback_rules(self) -> None:
        """Load fallback hardcoded rules as baseline (always merged with existing rules)."""
        fallback_rules = [
            {"event_id": "4625", "technique_id": "T1110.001", "level": "medium"},
            {"event_id": "4624", "technique_id": "T1078", "level": "low"},
            {"event_id": "4672", "technique_id": "T1078.003", "level": "high"},
            {"event_id": "4720", "technique_id": "T1136.001", "level": "high"},
            {"event_id": "4726", "technique_id": "T1485", "level": "medium"},
            {"event_id": "4688", "technique_id": "T1059", "level": "medium"},
        ]
        
        for rule in fallback_rules:
            event_id = rule["event_id"]
            if event_id not in self._event_id_to_techniques:
                self._event_id_to_techniques[event_id] = []
            
            # Check if this technique already exists for this event ID
            tech_id = rule["technique_id"]
            if not any(r.get("technique_id") == tech_id for r in self._event_id_to_techniques[event_id]):
                self._event_id_to_techniques[event_id].append({
                    "technique_id": tech_id,
                    "level": rule["level"],
                    "title": "",
                    "description": "",
                    "author": "",
                    "references": [],
                    "falsepositives": [],
                    "status": "",
                    "date": ""
                })

    def get_rules_for_event(self, event_id: str) -> List[Dict[str, Any]]:
        """
        Get all rules (technique mappings) for a given Event ID.
        
        Args:
            event_id: Windows Event ID as string
            
        Returns:
            List of rule dictionaries with technique information
        """
        event_id = str(event_id).strip()
        if event_id not in self._event_id_to_techniques:
            return []
        
        rules = []
        for rule_info in self._event_id_to_techniques[event_id]:
            tech_id = rule_info["technique_id"]
            tech_details = self._get_technique_details(tech_id)
            
            # Prefer Sigma rule description if available, otherwise use technique description
            sigma_description = rule_info.get("description", "").strip()
            technique_description = tech_details.get("description", "").strip()
            # Combine descriptions: Sigma rule description is more specific, technique description is more general
            if sigma_description and technique_description:
                description = f"{sigma_description}\n\nTechnique: {technique_description}"
            else:
                description = sigma_description if sigma_description else technique_description
            
            # Use technique name from ATT&CK, but note Sigma rule title for context
            technique_name = tech_details.get("technique_name", "").strip()
            sigma_title = rule_info.get("title", "").strip()
            
            rules.append({
                "technique_id": tech_id,
                "technique_name": technique_name,
                "sigma_title": sigma_title,  # Sigma rule title for reference
                "tactic": tech_details.get("tactic", ""),
                "severity": rule_info.get("level", DEFAULT_SEVERITY),
                "description": description,
                "author": rule_info.get("author", ""),
                "references": rule_info.get("references", []),
                "falsepositives": rule_info.get("falsepositives", []),
                "status": rule_info.get("status", ""),
                "date": rule_info.get("date", "")
            })
        
        return rules


# -----------------------------
# Windows Event Log parsing
# -----------------------------

def parse_windows_event_log(
    log_name: str = DEFAULT_LOG_NAME,
    max_events: Optional[int] = None,
    event_ids: Optional[List[int]] = None
) -> Iterable[Dict[str, Any]]:
    """
    Parse Windows Event Log directly from the system.
    
    Args:
        log_name: Name of the event log (default: "Security")
        max_events: Maximum number of events to read (None = all)
        event_ids: Optional list of Event IDs to filter (None = all)
    
    Yields:
        Dictionary with normalized event data
    """
    if not WINDOWS_EVENT_LOG_AVAILABLE:
        raise ImportError(
            "pywin32 is required to read Windows Event Log. "
            "Install it with: pip install pywin32"
        )
    
    try:
        # Open the event log
        hand = win32evtlog.OpenEventLog(None, log_name)
        
        try:
            flags = EVENTLOG_READ_FLAGS
            events_read = 0
            
            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                
                for event in events:
                    # Check max_events limit
                    if max_events and events_read >= max_events:
                        return
                    
                    event_id = event.EventID & EVENT_ID_MASK
                    
                    # Filter by event IDs if specified
                    if event_ids and event_id not in event_ids:
                        continue
                    
                    # Format timestamp
                    try:
                        timestamp = event.TimeGenerated.Format("%m/%d/%Y %I:%M:%S %p")
                    except (AttributeError, TypeError):
                        timestamp = str(event.TimeGenerated)
                    
                    # Get computer name
                    try:
                        host = event.ComputerName
                    except (AttributeError, TypeError):
                        host = ""
                    
                    # Extract user from event data
                    user = ""
                    try:
                        # Try to get user from event data strings
                        if event.StringInserts:
                            for insert in event.StringInserts:
                                if insert and ("\\" in insert or "@" in insert):
                                    user = insert
                                    break
                    except (AttributeError, TypeError):
                        pass
                    
                    # Get event message/description
                    try:
                        message = win32evtlogutil.SafeFormatMessage(event, log_name)
                    except (AttributeError, TypeError, ValueError):
                        message = ""
                    
                    # Build raw message from available data
                    raw_message_parts = []
                    try:
                        if hasattr(event, "EventCategory") and event.EventCategory:
                            raw_message_parts.append(f"Category: {event.EventCategory}")
                        if hasattr(event, "EventType"):
                            event_type = EVENT_TYPE_MAP.get(event.EventType, "Unknown")
                            raw_message_parts.append(event_type)
                        if message:
                            raw_message_parts.append(message)
                    except (AttributeError, TypeError):
                        pass
                    
                    raw_message = " | ".join(raw_message_parts) if raw_message_parts else message
                    
                    yield {
                        "timestamp": timestamp,
                        "host": host,
                        "event_id": str(event_id),
                        "user": user,
                        "source": DEFAULT_SOURCE,
                        "raw_message": raw_message,
                    }
                    
                    events_read += 1
                    
        finally:
            win32evtlog.CloseEventLog(hand)
            
    except (IOError, OSError, AttributeError, TypeError) as e:
        raise RuntimeError(f"Error reading Windows Event Log: {e}")


# -----------------------------
# Windows CSV parsing
# -----------------------------

def parse_windows_csv(path: str) -> Iterable[Dict[str, Any]]:
    """
    Parse a Windows Security log exported as CSV from Event Viewer.

    Common column names in the export:
        - 'Date and Time'
        - 'Event ID'
        - 'Computer'
        - 'User' or 'Account Name'
        - 'Task Category'
        - 'Keywords'
        - 'Description' or 'Message'

    We try to be defensive about slight name differences.
    """
    with open(path, mode="r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            # Normalize fields defensively
            timestamp = (
                row.get("Date and Time")
                or row.get("TimeCreated")
                or row.get("Logged")
                or ""
            )

            event_id = (row.get("Event ID") or row.get("EventID") or "").strip()

            host = (
                row.get("Computer")
                or row.get("Hostname")
                or row.get("ComputerName")
                or ""
            )

            user = (
                row.get("User")
                or row.get("Account Name")
                or row.get("SubjectUserName")
                or ""
            )

            description_pieces = [
                row.get("Task Category") or "",
                row.get("Keywords") or "",
                row.get("Description") or row.get("Message") or "",
            ]
            raw_message = " | ".join(p for p in description_pieces if p)

            yield {
                "timestamp": timestamp,
                "host": host,
                "event_id": event_id,
                "user": user,
                "source": DEFAULT_SOURCE,
                "raw_message": raw_message,
                "original_row": row,  # for future use if needed
            }


# -----------------------------
# Rule engine
# -----------------------------

def _create_empty_enrichment() -> Dict[str, str]:
    """
    Create a dictionary with empty MITRE ATT&CK enrichment fields.
    
    Returns:
        Dictionary with empty string values for all enrichment fields.
    """
    return {
        "rule_id": "",
        "tactic": "",
        "technique_id": "",
        "technique_name": "",
        "severity": "",
        "description": ""
    }


def apply_rules(event: Dict[str, Any], rule_engine: DynamicRuleEngine) -> Dict[str, Any]:
    """
    Apply rule engine to a normalized event using dynamic rules.

    Returns a new dict with ATT&CK fields added if a rule matches.
    If no rule matches, ATT&CK fields remain blank.
    If multiple rules match, uses the first one (highest severity preferred).
    """
    enriched = dict(event)  # shallow copy
    
    # Only process Windows Security events
    if event.get("source") != DEFAULT_SOURCE:
        enriched.update(_create_empty_enrichment())
        return enriched
    
    event_id = str(event.get("event_id", "")).strip()
    if not event_id:
        enriched.update(_create_empty_enrichment())
        return enriched
    
    # Get rules for this event ID
    rules = rule_engine.get_rules_for_event(event_id)
    
    if not rules:
        enriched.update(_create_empty_enrichment())
        return enriched
    
    # Sort by severity (critical > high > medium > low > informational)
    rules.sort(key=lambda r: SEVERITY_ORDER_DICT.get(
        r.get("severity", DEFAULT_SEVERITY).lower(),
        DEFAULT_SEVERITY_INDEX
    ))
    
    # Use the highest severity rule
    matched_rule = rules[0]
    
    enriched["rule_id"] = f"{RULE_ID_PREFIX}{event_id}_{matched_rule.get('technique_id', '')}"
    enriched["tactic"] = matched_rule.get("tactic", "")
    enriched["technique_id"] = matched_rule.get("technique_id", "")
    enriched["technique_name"] = matched_rule.get("technique_name", "")
    enriched["severity"] = matched_rule.get("severity", DEFAULT_SEVERITY)
    enriched["description"] = matched_rule.get("description", "")
    
    return enriched


# -----------------------------
# Reporting
# -----------------------------

REPORT_FIELDS = [
    "timestamp",
    "host",
    "user",
    "source",
    "event_id",
    "rule_id",
    "tactic",
    "technique_id",
    "technique_name",
    "severity",
    "description",
    "raw_message",
]


def write_csv_report(events: Iterable[Dict[str, Any]], output_path: str) -> Dict[str, int]:
    """
    Write events to CSV report and return severity counts.
    
    Returns:
        Dictionary mapping severity levels to counts
    """
    severity_counts: Dict[str, int] = {}
    
    with open(output_path, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=REPORT_FIELDS)
        writer.writeheader()
        for e in events:
            row = {field: e.get(field, "") for field in REPORT_FIELDS}
            writer.writerow(row)
            
            # Track severity counts (only for events with MITRE mappings)
            severity = e.get("severity", "").strip().lower()
            if severity:  # Only count if severity is present (has MITRE mapping)
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    return severity_counts


# -----------------------------
# CLI entry point
# -----------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Map Windows Security log events to MITRE ATT&CK techniques using dynamic rules from Sigma repository.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Read from Windows Security Event Log (default)
  python mitre_mapper_windows.py
  
  # Read from CSV file
  python mitre_mapper_windows.py --csv security_events.csv
  
  # Specify output file
  python mitre_mapper_windows.py --output my_report.csv
  
  # Force refresh of Sigma rules from GitHub
  python mitre_mapper_windows.py --refresh
        """
    )
    parser.add_argument(
        "--csv",
        required=False,
        default=None,
        help="Path to Windows Security log exported as CSV from Event Viewer. If not specified, reads from local system Event Log.",
    )
    parser.add_argument(
        "--output",
        required=False,
        default="report.csv",
        help="Path to the CSV output report (default: report.csv).",
    )
    parser.add_argument(
        "--cache-dir",
        required=False,
        default=None,
        help="Directory to cache Sigma rules and ATT&CK data (default: ~/.mitre_mapper_cache).",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        required=False,
        default=None,
        help="Maximum number of events to process from Event Log (default: all).",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        required=False,
        help="Force refresh of Sigma rules from GitHub, ignoring cache.",
    )

    args = parser.parse_args()

    # Initialize dynamic rule engine
    print("[*] Initializing dynamic rule engine...")
    rule_engine = DynamicRuleEngine(cache_dir=args.cache_dir, refresh_rules=args.refresh)
    
    # Parse and enrich events
    if args.csv:
        # Read from CSV file
        print(f"[*] Processing events from CSV file: {args.csv}...")
        parsed_events = parse_windows_csv(args.csv)
    else:
        # Read from Windows Event Log (default)
        if not WINDOWS_EVENT_LOG_AVAILABLE:
            print("[!] Error: pywin32 is required to read Windows Event Log.")
            print("[!] Install it with: pip install pywin32")
            print("[!] Or use --csv to specify a CSV file instead.")
            return
        
        print("[*] Reading events from Windows Security Event Log...")
        try:
            parsed_events = parse_windows_event_log(
                log_name=DEFAULT_LOG_NAME,
                max_events=args.max_events
            )
        except RuntimeError as e:
            error_msg = str(e)
            if "1314" in error_msg or "privilege" in error_msg.lower() or "not held" in error_msg.lower():
                print("[!] Error: Insufficient privileges to read Security Event Log.")
                print("[!] The Security Event Log requires administrator privileges.")
                print("[!] Options:")
                print("[!]   1. Run this script as Administrator")
                print("[!]   2. Use --csv to read from an exported CSV file instead")
                print("[!]      Example: python mitre_mapper_windows.py --csv events.csv")
            else:
                print(f"[!] Error reading Event Log: {e}")
                print("[!] Try using --csv to specify a CSV file instead.")
            return
        except (IOError, OSError, ImportError) as e:
            print(f"[!] Error reading Event Log: {e}")
            print("[!] Try using --csv to specify a CSV file instead.")
            return
    
    try:
        enriched_events = (apply_rules(e, rule_engine) for e in parsed_events)
        severity_counts = write_csv_report(enriched_events, args.output)
    except RuntimeError as e:
        error_msg = str(e)
        if "1314" in error_msg or "privilege" in error_msg.lower() or "not held" in error_msg.lower():
            print("[!] Error: Insufficient privileges to read Security Event Log.")
            print("[!] The Security Event Log requires administrator privileges.")
            print("[!] Options:")
            print("[!]   1. Run this script as Administrator")
            print("[!]   2. Use --csv to read from an exported CSV file instead")
            print("[!]      Example: python mitre_mapper_windows.py --csv events.csv")
        else:
            print(f"[!] Error processing events: {e}")
        return

    print(f"[+] Report written to {args.output}")
    
    # Print severity summary
    if severity_counts:
        print("\n[*] Detection Summary by Severity:")
        for severity in SEVERITY_ORDER_LIST:
            count = severity_counts.get(severity, 0)
            if count > 0:
                print(f"    {severity.capitalize()}: {count}")
        
        # Print any other severities not in the standard list
        for severity, count in sorted(severity_counts.items()):
            if severity not in SEVERITY_ORDER_LIST:
                print(f"    {severity.capitalize()}: {count}")
        
        total = sum(severity_counts.values())
        print(f"    Total detections: {total}")
    else:
        print("[!] No MITRE ATT&CK detections found in the events")


if __name__ == "__main__":
    main()
