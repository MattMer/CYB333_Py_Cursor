#!/usr/bin/env python3
"""
mitre_mapper_windows.py

Simple security automation tool that:
- Parses Windows Security event logs exported as CSV from Event Viewer.
- Normalizes events.
- Maps selected Event IDs to MITRE ATT&CK tactics/techniques using dynamic rules
  from Sigma rules repository and MITRE ATT&CK API.
- Writes an enriched CSV report.

Usage example:
    python mitre_mapper_windows.py --file security.csv --output report.csv
    python mitre_mapper_windows.py --file security.csv --output report.csv --cache-dir ./cache
"""

import argparse
import csv
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Iterable, List, Optional
import requests
try:
    from mitreattack.stix20 import MitreAttackData
except ImportError:
    # Fallback for older versions
    MitreAttackData = None


# -----------------------------
# Dynamic Rule Engine Configuration
# -----------------------------

SIGMA_RULES_REPO = "https://api.github.com/repos/SigmaHQ/sigma/contents/rules/windows"
SIGMA_RAW_BASE = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows"


class DynamicRuleEngine:
    """
    Dynamic rule engine that fetches Sigma rules and uses MITRE ATT&CK API
    to build mappings from Windows Event IDs to ATT&CK techniques.
    """

    def __init__(self, cache_dir: Optional[str] = None):
        """
        Initialize the dynamic rule engine.

        Args:
            cache_dir: Optional directory to cache Sigma rules and ATT&CK data.
                      If None, uses a default cache directory.
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
            except Exception as e:
                print(f"[!] Warning: Could not load MITRE ATT&CK data: {e}")
                print("[!] Falling back to cached data if available")
        else:
            print("[!] Warning: mitreattack-python not available, using cached data only")
        
        # Load or build rules
        self._load_or_build_rules()

    def _load_or_build_rules(self) -> None:
        """Load cached rules or fetch and build them from Sigma repository."""
        if self.sigma_rules_cache.exists():
            try:
                with open(self.sigma_rules_cache, "r", encoding="utf-8") as f:
                    cached = json.load(f)
                    self._event_id_to_techniques = cached.get("event_id_mappings", {})
                    print(f"[+] Loaded {len(self._event_id_to_techniques)} Event ID mappings from cache")
                    return
            except Exception as e:
                print(f"[!] Error loading cache: {e}, rebuilding...")
        
        print("[*] Fetching Sigma rules from GitHub...")
        self._fetch_and_parse_sigma_rules()
        
        # Save to cache
        self._save_rules_cache()

    def _fetch_and_parse_sigma_rules(self) -> None:
        """
        Fetch Sigma rules from GitHub and parse them to extract Event ID mappings.
        """
        try:
            # Fetch list of rule files from GitHub API
            response = requests.get(SIGMA_RULES_REPO, timeout=30)
            response.raise_for_status()
            files = response.json()
            
            # Filter for YAML files
            yaml_files = [f for f in files if f.get("type") == "file" and f.get("name", "").endswith(".yml")]
            
            print(f"[*] Found {len(yaml_files)} Sigma rule files, parsing...")
            
            event_id_mappings: Dict[str, List[Dict[str, Any]]] = {}  # event_id -> list of rule info
            
            for file_info in yaml_files:
                try:
                    # Fetch the raw YAML content
                    raw_url = file_info.get("download_url")
                    if not raw_url:
                        continue
                    
                    rule_response = requests.get(raw_url, timeout=10)
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
                    
                    level = rule_data.get("level", "medium")
                    title = rule_data.get("title", "")
                    description = rule_data.get("description", "")
                    
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
                                    "description": description
                                })
                            
                except Exception as e:
                    # Skip files that can't be parsed
                    continue
            
            # Store the mappings
            self._event_id_to_techniques = event_id_mappings
            
            print(f"[+] Parsed {len(self._event_id_to_techniques)} unique Event IDs with mappings")
            
        except Exception as e:
            print(f"[!] Error fetching Sigma rules: {e}")
            print("[!] Using fallback hardcoded rules")
            self._load_fallback_rules()

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
                        self._technique_details[technique_id] = cached[technique_id]
                        return cached[technique_id]
            except Exception:
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
                    
                    # Get tactics using the library method
                    tactics = []
                    try:
                        tactic_objects = self.attack_data.get_tactics_by_technique(technique.id)
                        for tactic_entry in tactic_objects:
                            if isinstance(tactic_entry, dict) and "object" in tactic_entry:
                                tactic_obj = tactic_entry["object"]
                                tactic_name = self.attack_data.get_name(tactic_obj.id) if hasattr(tactic_obj, "id") else ""
                                if tactic_name and tactic_name not in tactics:
                                    tactics.append(tactic_name)
                    except Exception:
                        # Fallback: try to get from kill chain phases
                        kill_chain_phases = getattr(technique, "kill_chain_phases", [])
                        for phase in kill_chain_phases:
                            if isinstance(phase, dict):
                                if phase.get("kill_chain_name") == "mitre-attack":
                                    phase_name = phase.get("phase_name", "")
                                    # Convert phase name to readable tactic name
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
                                    readable_tactic = tactic_map.get(phase_name.lower(), phase_name.title())
                                    if readable_tactic not in tactics:
                                        tactics.append(readable_tactic)
                    
                    details["tactic"] = ", ".join(tactics) if tactics else ""
            except Exception as e:
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
        except Exception as e:
            print(f"[!] Warning: Could not save rules cache: {e}")

    def _save_attack_cache(self) -> None:
        """Save ATT&CK technique details to cache."""
        try:
            with open(self.attack_cache, "w", encoding="utf-8") as f:
                json.dump(self._technique_details, f, indent=2)
        except Exception as e:
            print(f"[!] Warning: Could not save ATT&CK cache: {e}")

    def _load_fallback_rules(self) -> None:
        """Load fallback hardcoded rules if Sigma rules can't be fetched."""
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
            self._event_id_to_techniques[event_id].append({
                "technique_id": rule["technique_id"],
                "level": rule["level"],
                "title": "",
                "description": ""
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
            
            rules.append({
                "technique_id": tech_id,
                "technique_name": tech_details.get("technique_name", ""),
                "tactic": tech_details.get("tactic", ""),
                "severity": rule_info.get("level", "medium"),
                "description": tech_details.get("description", "") or rule_info.get("description", "")
            })
        
        return rules


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
                "source": "windows_security",
                "raw_message": raw_message,
                "original_row": row,  # for future use if needed
            }


# -----------------------------
# Rule engine
# -----------------------------

def apply_rules(event: Dict[str, Any], rule_engine: DynamicRuleEngine) -> Dict[str, Any]:
    """
    Apply rule engine to a normalized event using dynamic rules.

    Returns a new dict with ATT&CK fields added if a rule matches.
    If no rule matches, ATT&CK fields remain blank.
    If multiple rules match, uses the first one (highest severity preferred).
    """
    enriched = dict(event)  # shallow copy
    
    # Only process Windows Security events
    if event.get("source") != "windows_security":
        enriched["rule_id"] = ""
        enriched["tactic"] = ""
        enriched["technique_id"] = ""
        enriched["technique_name"] = ""
        enriched["severity"] = ""
        enriched["description"] = ""
        return enriched
    
    event_id = str(event.get("event_id", "")).strip()
    if not event_id:
        enriched["rule_id"] = ""
        enriched["tactic"] = ""
        enriched["technique_id"] = ""
        enriched["technique_name"] = ""
        enriched["severity"] = ""
        enriched["description"] = ""
        return enriched
    
    # Get rules for this event ID
    rules = rule_engine.get_rules_for_event(event_id)
    
    if not rules:
        enriched["rule_id"] = ""
        enriched["tactic"] = ""
        enriched["technique_id"] = ""
        enriched["technique_name"] = ""
        enriched["severity"] = ""
        enriched["description"] = ""
        return enriched
    
    # Sort by severity (critical > high > medium > low > informational)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    rules.sort(key=lambda r: severity_order.get(r.get("severity", "medium").lower(), 2))
    
    # Use the highest severity rule
    matched_rule = rules[0]
    
    enriched["rule_id"] = f"sigma_{event_id}_{matched_rule.get('technique_id', '')}"
    enriched["tactic"] = matched_rule.get("tactic", "")
    enriched["technique_id"] = matched_rule.get("technique_id", "")
    enriched["technique_name"] = matched_rule.get("technique_name", "")
    enriched["severity"] = matched_rule.get("severity", "medium")
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


def write_csv_report(events: Iterable[Dict[str, Any]], output_path: str) -> None:
    with open(output_path, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=REPORT_FIELDS)
        writer.writeheader()
        for e in events:
            row = {field: e.get(field, "") for field in REPORT_FIELDS}
            writer.writerow(row)


# -----------------------------
# CLI entry point
# -----------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Map Windows Security log events to MITRE ATT&CK techniques using dynamic rules from Sigma repository."
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Path to the Windows Security log exported as CSV from Event Viewer.",
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

    args = parser.parse_args()

    # Initialize dynamic rule engine
    print("[*] Initializing dynamic rule engine...")
    rule_engine = DynamicRuleEngine(cache_dir=args.cache_dir)
    
    # Parse and enrich events
    print(f"[*] Processing events from {args.file}...")
    parsed_events = parse_windows_csv(args.file)
    enriched_events = (apply_rules(e, rule_engine) for e in parsed_events)
    write_csv_report(enriched_events, args.output)

    print(f"[+] Report written to {args.output}")


if __name__ == "__main__":
    main()
