#!/usr/bin/env python3
"""
mitre_mapper_windows.py

Simple security automation tool that:
- Parses Windows Security event logs exported as CSV from Event Viewer.
- Normalizes events.
- Maps selected Event IDs to MITRE ATT&CK tactics/techniques using a static rule set.
- Writes an enriched CSV report.

Usage example:
    python mitre_mapper_windows.py --file security.csv --output report.csv
"""

import argparse
import csv
from typing import Dict, Any, Iterable, List, Optional


# -----------------------------
# Rule engine data (embedded)
# -----------------------------
# These are hand-curated mappings from Windows Event IDs to MITRE ATT&CK.
# You can add/remove entries as you refine the project.

RULES: List[Dict[str, Any]] = [
    {
        "id": "win_failed_logon",
        "log_source": "windows_security",
        "match_type": "event_id",
        "event_id": "4625",
        "tactic": "Credential Access",
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing",
        "severity": "medium",
        "description": "Failed logon attempt (possible password guessing).",
    },
    {
        "id": "win_success_logon",
        "log_source": "windows_security",
        "match_type": "event_id",
        "event_id": "4624",
        "tactic": "Initial Access",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "severity": "low",
        "description": "Successful logon (use of a valid account).",
    },
    {
        "id": "win_admin_logon",
        "log_source": "windows_security",
        "match_type": "event_id",
        "event_id": "4672",
        "tactic": "Privilege Escalation",
        "technique_id": "T1078.003",
        "technique_name": "Domain Accounts",
        "severity": "high",
        "description": "Special privileges assigned to new logon (admin-level).",
    },
    {
        "id": "win_user_created",
        "log_source": "windows_security",
        "match_type": "event_id",
        "event_id": "4720",
        "tactic": "Persistence",
        "technique_id": "T1136.001",
        "technique_name": "Create Account",
        "severity": "high",
        "description": "A new user account was created.",
    },
    {
        "id": "win_user_deleted",
        "log_source": "windows_security",
        "match_type": "event_id",
        "event_id": "4726",
        "tactic": "Defense Evasion",
        "technique_id": "T1485",
        "technique_name": "Account Removal",
        "severity": "medium",
        "description": "A user account was deleted (possible cleanup activity).",
    },
    {
        "id": "win_process_created",
        "log_source": "windows_security",
        "match_type": "event_id",
        "event_id": "4688",
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "severity": "medium",
        "description": "A new process was created.",
    },
    # Add more mappings here as you refine the tool
]


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

def apply_rules(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply rule engine to a normalized event.

    Returns a new dict with ATT&CK fields added if a rule matches.
    If no rule matches, ATT&CK fields remain blank.
    """
    matched_rule: Optional[Dict[str, Any]] = None

    for rule in RULES:
        if rule["log_source"] != event.get("source"):
            continue

        match_type = rule.get("match_type")

        if match_type == "event_id":
            if rule.get("event_id") == str(event.get("event_id", "")).strip():
                matched_rule = rule
                break

        # In a future version, you could add other match types here
        # (e.g., 'contains' on raw_message, process name, etc.)

    enriched = dict(event)  # shallow copy

    if matched_rule:
        enriched["rule_id"] = matched_rule.get("id", "")
        enriched["tactic"] = matched_rule.get("tactic", "")
        enriched["technique_id"] = matched_rule.get("technique_id", "")
        enriched["technique_name"] = matched_rule.get("technique_name", "")
        enriched["severity"] = matched_rule.get("severity", "")
        enriched["description"] = matched_rule.get("description", "")
    else:
        enriched["rule_id"] = ""
        enriched["tactic"] = ""
        enriched["technique_id"] = ""
        enriched["technique_name"] = ""
        enriched["severity"] = ""
        enriched["description"] = ""

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
        description="Map Windows Security log events to MITRE ATT&CK techniques."
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

    args = parser.parse_args()

    parsed_events = parse_windows_csv(args.file)
    enriched_events = (apply_rules(e) for e in parsed_events)
    write_csv_report(enriched_events, args.output)

    print(f"[+] Report written to {args.output}")


if __name__ == "__main__":
    main()
