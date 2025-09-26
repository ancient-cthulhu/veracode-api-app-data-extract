# Veracode API Application Profile Data Export

Minimal tool to export application profile and findings summary from Veracode REST APIs into CSV or JSON.

## Data Collected
- **Application Name**
- **Application Passed Policy** (`PASSED` | `DID_NOT_PASS` | `NOT_ASSESSED`)
- **Current Policy** (resolved via Policies v1 or Summary Report v2)
- **Findings counts** (OPEN, non-sandbox): Very High / High / Medium / Low

## APIs Used
- Applications v1: `/appsec/v1/applications`
- Policies v1: `/appsec/v1/policies/{policy_guid}`
- Findings v2: `/appsec/v2/applications/{guid}/findings`
- Summary Report v2 (fallback): `/appsec/v2/applications/{guid}/summary_report`

## Requirements
- Python 3.8+
- Packages: `requests`, `veracode_api_signing`

Install:
```bash
pip install requests veracode_api_signing
```

## Authentication
Uses Veracode HMAC authentication (standard credentials file or env vars).

Credentials file (recommended): `~/.veracode/credentials`
```
[default]
veracode_api_key_id = YOUR_KEY_ID
veracode_api_key_secret = YOUR_KEY_SECRET
```

Or environment variables:
```bash
export VERACODE_API_KEY_ID=YOUR_KEY_ID
export VERACODE_API_KEY_SECRET=YOUR_KEY_SECRET
```

## Usage
```bash
python script.py [--format {csv,json}] [--out PATH] [--start-date DATE] [--workers N] [--debug]
```

### Arguments
- `--format {csv,json}`  
  Output format. Default: `csv`.

- `--out PATH`  
  Output file path. Default: `./export/veracode_dashboard.csv`. If `PATH` ends with `/` or `\`, filename `veracode_dashboard.csv` is used.

- `--start-date DATE`  
  Only include findings first seen on/after this date. Accepts `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`.

- `--workers N`  
  Number of parallel worker threads for per-application processing. Default: `8`.

- `--debug`  
  Enable debug logging (prints request URLs/status and per-app summaries).

### Environment
- `VERACODE_API_BASE` (optional): Override API base URL. Default: `https://api.veracode.com`.

## Examples
Export CSV with defaults:
```bash
python script.py
```

Export JSON to a custom path:
```bash
python script.py --format json --out ./export/apps.json
```

Export since a given date with more parallelism:
```bash
python script.py --start-date 2025-01-01 --workers 16
```

## Output
- **CSV** headers: `Application Name, Application Passed Policy, Current Policy, Very High, High, Medium, Low`
- **JSON**: array of objects with the same fields.
