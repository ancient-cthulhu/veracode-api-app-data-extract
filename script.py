
"""
Veracode API App profile Data Export 

Exports:
- App name
- Policy compliance (PASSED | DID_NOT_PASS | NOT_ASSESSED)
- Current policy
- Counts of open (non-sandbox) findings by severity

APIs:
- /appsec/v1/applications
- /appsec/v1/policies/{guid}
- /appsec/v2/applications/{guid}/findings
- /appsec/v2/applications/{guid}/summary_report

Platform Roles:
    Service Account
        - Results API

Notes:
- Read-only.
- Auth via Veracode HMAC plugin.
- Parallelism to speed things up. (Default is 8 workers)
  - More workers = faster, but more API calls at once.
  - Fewer workers = slower, but lighter load.
  - 8 is a safe middle ground.

Dependencies:
  - pip install requests veracode_api_signing
"""

import os
import csv
import json
import argparse
import datetime as dt
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

BASE = os.environ.get("VERACODE_API_BASE", "https://api.veracode.com")
TIMEOUT = (5, 90)

# new session with HMAC auth
def new_session():
    s = requests.Session()
    s.auth = RequestsAuthPluginVeracodeHMAC()
    s.headers.update({"Accept": "application/json"})
    return s

# follow pagination links
def paginate(session, url, params=None, debug=False):
    next_url = url
    first = True
    while next_url:
        r = session.get(next_url, params=params if first else None, timeout=TIMEOUT)
        if debug:
            print(f"[DEBUG] GET {r.request.url} -> {r.status_code}")
        r.raise_for_status()
        data = r.json()
        yield data
        href = (data.get("_links") or {}).get("next", {}).get("href")
        next_url = urljoin(BASE, href) if href else None
        first = False

# parse iso date strings
def parse_datetime(value):
    if not value:
        return None
    trimmed = value.replace("T", " ").replace("Z", "").split(".")[0]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(trimmed, fmt)
        except Exception:
            pass
    return None

# findings filters
def finding_is_open(item):
    status = (
        (item.get("finding_status") or {}).get("status")
        or item.get("status")
        or (item.get("state") or {}).get("status")
        or ""
    )
    return str(status).upper() == "OPEN"

def finding_is_sandbox(item):
    context = item.get("context") or {}
    if str(context.get("type") or "").upper() == "SANDBOX":
        return True
    details = item.get("finding_details") or {}
    return bool(item.get("sandbox_id") or details.get("sandbox_id"))

def finding_first_seen(item):
    details = item.get("finding_details") or {}
    ts = (
        item.get("first_found_date") or item.get("first_seen_date") or item.get("published_date")
        or details.get("first_found_date") or details.get("first_seen_date") or details.get("published_date")
    )
    return parse_datetime(ts)

def finding_severity(item):
    details = item.get("finding_details") or {}
    sev = details.get("severity", item.get("severity"))
    try:
        return int(sev)
    except Exception:
        return None

# resolve policy guid -> name
def fetch_policy_name(session, policy_guid, debug=False):
    if not policy_guid:
        return ""
    url = f"{BASE}/appsec/v1/policies/{policy_guid}"
    r = session.get(url, timeout=TIMEOUT)
    if debug:
        print(f"[DEBUG] GET {url} -> {r.status_code}")
    if r.status_code != 200:
        return ""
    return (r.json() or {}).get("policy_name") or ""

# fallback summary report
def fetch_policy_from_summary(session, app_guid, debug=False):
    url = f"{BASE}/appsec/v2/applications/{app_guid}/summary_report"
    r = session.get(url, timeout=TIMEOUT)
    if debug:
        print(f"[DEBUG] GET {url} -> {r.status_code}")
    if r.status_code != 200:
        return "", None
    data = r.json() or {}
    policy_name = (
        data.get("policy_name")
        or (data.get("policy") or {}).get("policy_name")
        or ""
    )
    compliance = (
        data.get("policy_compliance_status")
        or (data.get("policy") or {}).get("compliance_status")
        or None
    )
    if not policy_name:
        pg = data.get("policy_guid") or (data.get("policy") or {}).get("policy_guid")
        if pg:
            policy_name = fetch_policy_name(session, pg, debug=debug)
    return policy_name, compliance

# list apps
def list_applications(debug=False):
    apps = {}
    with new_session() as s:
        url = f"{BASE}/appsec/v1/applications"
        for page in paginate(s, url, params={"size": 500}, debug=debug):
            for app in (page.get("_embedded") or {}).get("applications", []):
                guid = app.get("guid")
                name = (app.get("profile") or {}).get("name") or ""
                compliance = app.get("policy_compliance") or ""
                policy_guid = (app.get("policy") or {}).get("policy_guid") or ""
                apps[guid] = {
                    "name": name,
                    "policy_compliance": compliance,
                    "policy_guid": policy_guid,
                }
                if debug:
                    print(f"[DEBUG] APP {guid} name='{name}' compliance='{compliance}' policy_guid='{policy_guid}'")
    return apps

# worker: resolve policy + count findings
def process_app(guid, base_meta, start_from=None, debug=False):
    with new_session() as s:
        policy_name = ""
        compliance = base_meta.get("policy_compliance") or ""
        pg = base_meta.get("policy_guid") or ""
        if pg:
            policy_name = fetch_policy_name(s, pg, debug=debug)
        if not policy_name or not compliance:
            sr_name, sr_comp = fetch_policy_from_summary(s, guid, debug=debug)
            policy_name = policy_name or sr_name or ""
            compliance = compliance or (sr_comp or "")
        compliance = (compliance or "NOT_ASSESSED").upper()

        url = f"{BASE}/appsec/v2/applications/{guid}/findings"
        counts = {"Very High": 0, "High": 0, "Medium": 0, "Low": 0}
        for page in paginate(s, url, params={"size": 500}, debug=debug):
            items = (page.get("_embedded") or {}).get("findings", []) or []
            for f in items:
                if not finding_is_open(f) or finding_is_sandbox(f):
                    continue
                if start_from:
                    ts = finding_first_seen(f)
                    if ts and ts < start_from:
                        continue
                sev = finding_severity(f)
                if sev == 5:
                    counts["Very High"] += 1
                elif sev == 4:
                    counts["High"] += 1
                elif sev == 3:
                    counts["Medium"] += 1
                elif sev in (1, 2):
                    counts["Low"] += 1

        if debug:
            print(f"[DEBUG] {guid} policy='{policy_name}' compliance='{compliance}' counts={counts}")

        return {
            "Application Name": base_meta.get("name") or f"(GUID:{guid})",
            "Application Passed Policy": compliance,
            "Current Policy": policy_name,
            "Very High": counts["Very High"],
            "High": counts["High"],
            "Medium": counts["Medium"],
            "Low": counts["Low"],
        }

# csv/json writers
def write_csv(rows, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fields = ["Application Name", "Application Passed Policy", "Current Policy", "Very High", "High", "Medium", "Low"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote: {path}")

def write_json(rows, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)
    print(f"Wrote: {path}")

# main
def main():
    ap = argparse.ArgumentParser(description="Veracode Data Export.")
    ap.add_argument("--format", choices=["csv", "json"], default="csv",
                    help="Output format (csv or json). Default: csv")
    ap.add_argument("--out", default="./export/veracode_applications.csv",
                    help="Output file path. Default: ./export/veracode_applications.csv")
    ap.add_argument("--start-date", default=None,
                    help="Only include findings first seen on/after this date (YYYY-MM-DD).")
    ap.add_argument("--workers", type=int, default=8,
                    help="Parallel workers (threads). Default: 8. Increase for speed, decrease if throttled.")
    ap.add_argument("--debug", action="store_true",
                    help="Enable debug logging (prints requests + samples).")
    args = ap.parse_args()

    start_from = parse_datetime(args.start_date) if args.start_date else None

    base_apps = list_applications(debug=args.debug)

    rows = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(process_app, guid, meta, start_from, args.debug): guid for guid, meta in base_apps.items()}
        for fut in as_completed(futures):
            guid = futures[fut]
            try:
                rows.append(fut.result())
            except Exception as e:
                if args.debug:
                    print(f"[DEBUG] ERROR {guid}: {e}")

    if args.format == "json":
        write_json(rows, args.out)
    else:
        out = args.out
        if out.endswith("/") or out.endswith("\\"):
            out = os.path.join(out, "veracode_dashboard.csv")
        write_csv(rows, out)

if __name__ == "__main__":

    main()
