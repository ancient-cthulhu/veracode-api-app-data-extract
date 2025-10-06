
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

API_BASE = os.environ.get("VERACODE_API_BASE", "https://api.veracode.com")
TIMEOUT = (5, 90)

# HMAC-authenticated session
def make_session():
    s = requests.Session()
    s.auth = RequestsAuthPluginVeracodeHMAC()
    s.headers.update({"Accept": "application/json"})
    return s

# Iterate HAL pages
def walk_pages(session, url, params=None, debug=False):
    next_url, first = url, True
    while next_url:
        resp = session.get(next_url, params=params if first else None, timeout=TIMEOUT)
        if debug:
            print(f"[DEBUG] GET {resp.request.url} -> {resp.status_code}")
        resp.raise_for_status()
        data = resp.json()
        yield data
        href = (data.get("_links") or {}).get("next", {}).get("href")
        next_url = urljoin(API_BASE, href) if href else None
        first = False

def parse_when(value):
    if not value:
        return None
    txt = value.replace("T", " ").replace("Z", "").split(".")[0]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(txt, fmt)
        except Exception:
            pass
    return None

# Filters
def is_open_finding(item):
    status = (
        (item.get("finding_status") or {}).get("status")
        or item.get("status")
        or (item.get("state") or {}).get("status")
        or ""
    )
    return str(status).upper() == "OPEN"

def is_sandbox_finding(item):
    ctx = item.get("context") or {}
    if str(ctx.get("type") or "").upper() == "SANDBOX":
        return True
    details = item.get("finding_details") or {}
    return bool(item.get("sandbox_id") or details.get("sandbox_id"))

def first_seen(item):
    details = item.get("finding_details") or {}
    ts = (
        item.get("first_found_date") or item.get("first_seen_date") or item.get("published_date")
        or details.get("first_found_date") or details.get("first_seen_date") or details.get("published_date")
    )
    return parse_when(ts)

def severity_level(item):
    details = item.get("finding_details") or {}
    sev = details.get("severity", item.get("severity"))
    try:
        return int(sev)
    except Exception:
        return None

# Policy lookups
def get_policy_name(session, policy_guid, debug=False):
    if not policy_guid:
        return ""
    url = f"{API_BASE}/appsec/v1/policies/{policy_guid}"
    r = session.get(url, timeout=TIMEOUT)
    if debug:
        print(f"[DEBUG] GET {url} -> {r.status_code}")
    if r.status_code != 200:
        return ""
    return (r.json() or {}).get("policy_name") or ""

def get_policy_from_summary(session, app_guid, debug=False):
    url = f"{API_BASE}/appsec/v2/applications/{app_guid}/summary_report"
    r = session.get(url, timeout=TIMEOUT)
    if debug:
        print(f"[DEBUG] GET {url} -> {r.status_code}")
    if r.status_code != 200:
        return "", None
    body = r.json() or {}
    name = body.get("policy_name") or (body.get("policy") or {}).get("policy_name") or ""
    status = body.get("policy_compliance_status") or (body.get("policy") or {}).get("compliance_status") or None
    if not name:
        pg = body.get("policy_guid") or (body.get("policy") or {}).get("policy_guid")
        if pg:
            name = get_policy_name(session, pg, debug=debug)
    return name, status

# App list
def fetch_applications(debug=False):
    apps = {}
    with make_session() as s:
        url = f"{API_BASE}/appsec/v1/applications"
        for page in walk_pages(s, url, params={"size": 500}, debug=debug):
            for app in (page.get("_embedded") or {}).get("applications", []):
                guid = app.get("guid")
                name = (app.get("profile") or {}).get("name") or ""
                compliance = app.get("policy_compliance") or ""
                policy_guid = (app.get("policy") or {}).get("policy_guid") or ""
                apps[guid] = {"name": name, "compliance": compliance, "policy_guid": policy_guid}
                if debug:
                    print(f"[DEBUG] APP {guid} name='{name}' compliance='{compliance}' policy_guid='{policy_guid}'")
    return apps

# Count open, non-sandbox findings by severity for a given scan_type
def count_by_scan_type(session, app_guid, scan_type, since=None, debug=False):
    counts = {"Very High": 0, "High": 0, "Medium": 0, "Low": 0}
    url = f"{API_BASE}/appsec/v2/applications/{app_guid}/findings"
    params = {"size": 500, "scan_type": scan_type}
    for page in walk_pages(session, url, params=params, debug=debug):
        for f in (page.get("_embedded") or {}).get("findings", []) or []:
            if not is_open_finding(f) or is_sandbox_finding(f):
                continue
            if since:
                when = first_seen(f)
                if when and when < since:
                    continue
            sev = severity_level(f)
            if sev == 5:
                counts["Very High"] += 1
            elif sev == 4:
                counts["High"] += 1
            elif sev == 3:
                counts["Medium"] += 1
            elif sev in (1, 2):
                counts["Low"] += 1
    if debug:
        print(f"[DEBUG] {app_guid} scan_type={scan_type} counts={counts}")
    return counts

# Sum dict B into A (keys: VH/H/M/L)
def add_counts(a, b):
    for k in a.keys():
        a[k] += b.get(k, 0)

# Per-app worker: sum STATIC + DYNAMIC + MANUAL + SCA
def build_row(app_guid, app_meta, since=None, debug=False):
    with make_session() as s:
        policy_name = ""
        compliance = app_meta.get("compliance") or ""
        policy_guid = app_meta.get("policy_guid") or ""

        if policy_guid:
            policy_name = get_policy_name(s, policy_guid, debug=debug)
        if not policy_name or not compliance:
            sr_name, sr_status = get_policy_from_summary(s, app_guid, debug=debug)
            policy_name = policy_name or sr_name or ""
            compliance = compliance or (sr_status or "")
        compliance = (compliance or "NOT_ASSESSED").upper()

        total = {"Very High": 0, "High": 0, "Medium": 0, "Low": 0}
        # Findings API cannot combine types; aggregate client-side
        for t in ("STATIC", "DYNAMIC", "MANUAL", "SCA"):
            add_counts(total, count_by_scan_type(s, app_guid, t, since=since, debug=debug))

        if debug:
            print(f"[DEBUG] {app_guid} policy='{policy_name}' compliance='{compliance}' total={total}")

        return {
            "Application Name": app_meta.get("name") or f"(GUID:{app_guid})",
            "Application Passed Policy": compliance,
            "Current Policy": policy_name,
            "Very High": total["Very High"],
            "High": total["High"],
            "Medium": total["Medium"],
            "Low": total["Low"],
        }

def write_csv(rows, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    headers = ["Application Name", "Application Passed Policy", "Current Policy",
               "Very High", "High", "Medium", "Low"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote: {path}")

def write_json(rows, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)
    print(f"Wrote: {path}")

def main():
    parser = argparse.ArgumentParser(description="Veracode findings export (totals across STATIC/DYNAMIC/MANUAL/SCA)")
    parser.add_argument("--format", choices=["csv", "json"], default="csv",
                        help="Output format (csv|json). Default: csv")
    parser.add_argument("--out", default="./export/veracode_findings.csv",
                        help="Output file path. Default: ./export/veracode_findings.csv")
    parser.add_argument("--start-date", default=None,
                        help="Only include findings first seen on/after this timestamp "
                             "(YYYY-MM-DD or 'YYYY-MM-DD HH:MM:SS').")
    parser.add_argument("--workers", type=int, default=8,
                        help="Parallel workers. Default: 8")
    parser.add_argument("--debug", action="store_true",
                        help="Print debug logs")
    args = parser.parse_args()

    since = parse_when(args.start_date) if args.start_date else None
    apps = fetch_applications(debug=args.debug)

    rows = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        fut_to_guid = {pool.submit(build_row, guid, meta, since, args.debug): guid
                       for guid, meta in apps.items()}
        for fut in as_completed(fut_to_guid):
            guid = fut_to_guid[fut]
            try:
                rows.append(fut.result())
            except Exception as exc:
                if args.debug:
                    print(f"[DEBUG] ERROR {guid}: {exc}")

    if args.format == "json":
        out_path = args.out
        if out_path.endswith("/") or out_path.endswith("\\"):
            out_path = os.path.join(out_path, "veracode_findings.json")
        write_json(rows, out_path)
    else:
        out_path = args.out
        if out_path.endswith("/") or out_path.endswith("\\"):
            out_path = os.path.join(out_path, "veracode_findings.csv")
        write_csv(rows, out_path)

if __name__ == "__main__":
    main()
