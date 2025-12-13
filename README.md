# CYB333 – Security Automation Projects

This repository contains all coding tasks, labs, and automation projects completed for **CYB333: Security Automation**. Each project demonstrates practical applications of Python, scripting, and security tooling to automate common defensive workflows. The goal of this repository is to document progress throughout the course and provide clear, reproducible examples of security automation in action.

## Repository Purpose

This repository serves both as a portfolio of course work and as a reference for building practical automation skills. As the course progresses, new modules and improvements will be added to show iteration, experimentation, and refinement of security automation techniques. All labs, lessons, and assignments from the CYB333 course are included in this repository.

---

## Projects Overview

### MITRE ATT&CK Mapper for Windows Security Events

A comprehensive security automation tool that automatically maps Windows Security Event Log entries to MITRE ATT&CK framework tactics and techniques, providing security analysts with actionable threat intelligence.

#### Features

- **Dual Input Methods**:
  - **Default**: Reads directly from Windows Security Event Log (requires administrator privileges)
  - **CSV Import**: Processes exported CSV files from Event Viewer for offline analysis

- **Dynamic Rule Engine**:
  - Automatically fetches and parses Sigma detection rules from the [SigmaHQ GitHub repository](https://github.com/SigmaHQ/sigma)
  - Extracts Windows Event ID to MITRE ATT&CK technique mappings from Sigma rules
  - Falls back to hardcoded baseline rules if external sources are unavailable

- **MITRE ATT&CK Integration**:
  - Uses the `mitreattack-python` library to query the official MITRE ATT&CK framework
  - Retrieves detailed technique information including:
    - Technique names and descriptions
    - Associated tactics (Initial Access, Execution, Persistence, etc.)
    - Full technique documentation

- **Intelligent Caching**:
  - Caches Sigma rule mappings locally to reduce API calls
  - Caches MITRE ATT&CK technique details for faster subsequent runs
  - Configurable cache directory (default: `~/.mitre_mapper_cache`)

- **Comprehensive Reporting**:
  - Generates enriched CSV reports with all original event data plus MITRE mappings
  - Includes fields: `rule_id`, `tactic`, `technique_id`, `technique_name`, `severity`, `description`
  - Provides severity-based detection summaries (Critical, High, Medium, Low, Informational)
  - Shows total detection counts by severity level

- **Event Processing**:
  - Normalizes Windows Security events from multiple sources
  - Handles various Event Viewer export formats
  - Supports filtering and limiting event processing

#### Installation

1. **Clone the repository** (if not already done):
   ```bash
   git clone <repository-url>
   cd CYB333_Py_Cursor
   ```

2. **Create a virtual environment** (recommended):
   ```bash
   python -m venv .venv
   .\.venv\Scripts\activate  # Windows
   # or
   source .venv/bin/activate  # Linux/Mac
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

#### Usage

**Basic Usage - Read from Event Log** (requires administrator privileges):
```bash
python mitre_mapper_windows.py
```

**Read from CSV file**:
```bash
python mitre_mapper_windows.py --csv security_events.csv
```

**Specify output file**:
```bash
python mitre_mapper_windows.py --output my_report.csv
```

**Limit number of events processed**:
```bash
python mitre_mapper_windows.py --max-events 1000
```

**Use custom cache directory**:
```bash
python mitre_mapper_windows.py --cache-dir ./my_cache
```

**Complete example with all options**:
```bash
python mitre_mapper_windows.py --csv events.csv --output report.csv --cache-dir ./cache --max-events 5000
```

#### Command-Line Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--csv` | No | None | Path to CSV file exported from Event Viewer. If not specified, reads from local system Event Log. |
| `--output` | No | `report.csv` | Path to the CSV output report. |
| `--cache-dir` | No | `~/.mitre_mapper_cache` | Directory to cache Sigma rules and ATT&CK data. |
| `--max-events` | No | All events | Maximum number of events to process from Event Log. |

#### Output Format

The generated CSV report includes the following columns:

- `timestamp` - Event timestamp
- `host` - Computer/hostname where event occurred
- `user` - User account associated with the event
- `source` - Event source (always "windows_security")
- `event_id` - Windows Event ID
- `rule_id` - Generated rule identifier (format: `sigma_{event_id}_{technique_id}`)
- `tactic` - MITRE ATT&CK tactic(s) associated with the technique
- `technique_id` - MITRE ATT&CK technique ID (e.g., T1110.001)
- `technique_name` - Full name of the MITRE ATT&CK technique
- `severity` - Severity level (critical, high, medium, low, informational)
- `description` - Detailed description of the technique
- `raw_message` - Original event message/description

#### Example Output

```
[*] Initializing dynamic rule engine...
[*] Initializing MITRE ATT&CK data...
[+] MITRE ATT&CK data loaded successfully
[+] Loaded 6 Event ID mappings from cache
[*] Processing events from CSV file: security_events.csv...
[+] Report written to report.csv

[*] Detection Summary by Severity:
    High: 2
    Medium: 5
    Low: 1
    Total detections: 8
```

#### Requirements

- Python 3.7+
- Windows OS (for Event Log reading) or Windows Event Log CSV exports
- Administrator privileges (for direct Event Log access)
- Internet connection (for initial Sigma rules and MITRE ATT&CK data download)

#### Dependencies

See `requirements.txt` for complete list:
- `mitreattack-python>=2.0.0` - MITRE ATT&CK framework integration
- `pyyaml>=6.0` - Sigma rule parsing
- `requests>=2.31.0` - HTTP requests for rule fetching
- `pywin32>=306` - Windows Event Log access (Windows only)

#### Troubleshooting

**"Insufficient privileges" error**:
- The Security Event Log requires administrator privileges
- Solution 1: Run the script as Administrator
- Solution 2: Export events to CSV and use `--csv` option

**"pywin32 is required" error**:
- Install with: `pip install pywin32`
- Or use `--csv` to read from CSV files instead

**No detections found**:
- Verify your events contain Event IDs that match known MITRE techniques
- Check that the rule engine loaded successfully (look for cache messages)
- Some Event IDs may not have corresponding MITRE mappings

---

### Other Projects

This repository also contains additional security automation projects and utilities developed throughout the course:

- **Network Tools**: Port scanning, socket programming, and network analysis utilities
- **Client-Server Applications**: Examples of secure communication implementations
- **Security Utilities**: Various automation scripts for common security tasks

Each project includes its own documentation and examples within the codebase.

---

## Course Structure

This repository is organized to reflect the progression of the CYB333 Security Automation course:

- **Labs**: Hands-on exercises demonstrating specific security automation concepts
- **Lessons**: Code examples and implementations from course lessons
- **Assignments**: Completed coursework and projects
- **Utilities**: Reusable security automation tools and helpers

---

## Contributing

This is a personal course repository. All code is developed as part of CYB333 coursework and is intended for educational purposes.

---

## License

This repository contains educational coursework and is for academic use only.
