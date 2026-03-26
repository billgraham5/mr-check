#!/usr/bin/env python3
"""
vpn_redirect_tracker.py

Purpose:
- Prompt the user for a Base RA VPN CNAME, for example:
    XXXXXX.vpn.sse.cisco.com
- Build region URLs automatically:
    https://us-west-1-<cname>
    https://us-west-2-<cname>
    https://us-east-1-<cname>
    https://us-east-2-<cname>
- Prompt the user for a DNS server to check against
  - Blank input uses System Default DNS
  - If an IP is provided, nslookup uses that DNS server
- For each region URL:
  - Run curl
  - Parse redirect URL from the response headers
  - Extract the DNS hostname from the redirect URL
  - Run nslookup on that hostname
  - Capture returned IP address(es), excluding the DNS server IP
  - If an IP matches a known DCv2 prefix, add a geo-proximity label
- Repeat for the user-specified number of cycles per region
- Write a detailed log
- Print a summary to the console
"""

from __future__ import annotations

import collections
import datetime as dt
import ipaddress
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

REGION_PREFIXES = [
    "us-west-1-",
    "us-west-2-",
    "us-east-1-",
    "us-east-2-",
]

SLEEP_SECONDS = 1
LOG_DIR = Path("./vpn_redirect_logs")


def get_base_ra_vpn_cname() -> str:
    """Prompt for the base RA VPN CNAME and normalize input."""
    while True:
        cname = input(
            "Enter Base RA VPN CNAME (example: XXXXXX.vpn.sse.cisco.com): "
        ).strip()

        if not cname:
            print("CNAME cannot be empty.")
            continue

        cname = re.sub(r"^https?://", "", cname, flags=re.IGNORECASE)
        cname = cname.strip().strip("/")

        if not cname:
            print("Invalid CNAME.")
            continue

        return cname


def build_region_urls(base_cname: str) -> List[str]:
    """Construct full HTTPS region URLs from the base CNAME."""
    return [f"https://{prefix}{base_cname}" for prefix in REGION_PREFIXES]


def get_iteration_count() -> int:
    """Prompt for the number of cycles to run per region."""
    while True:
        value = input("Enter the number of cycles to run per region: ").strip()
        try:
            iterations = int(value)
            if iterations <= 0:
                print("Please enter a positive integer.")
                continue
            return iterations
        except ValueError:
            print("Invalid input. Please enter a whole number.")


def get_dns_server() -> Optional[str]:
    """
    Prompt for the DNS server to use for nslookup.
    Blank input means system default DNS.
    """
    print("\nDNS Server to check against")
    print("Press Enter with no response to use: System Default DNS")
    print("Examples:")
    print("  208.67.222.222 (OpenDNS)")
    print("  1.1.1.1 (Cloudflare)")
    print("  8.8.8.8 (Google)")
    print("  9.9.9.9 (QuadDNS)")

    while True:
        value = input("Enter DNS Server to check against: ").strip()

        if not value:
            return None

        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            print("Invalid IP address. Enter a valid IPv4 or IPv6 address, or press Enter for System Default DNS.")


def run_command(cmd: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"
    except Exception as exc:
        return 1, "", f"Command failed: {exc}"


def curl_for_redirect(url: str) -> Tuple[Optional[str], str]:
    """
    Run curl against the URL and parse the HTTP Location header.
    Returns: (redirect_url, raw_output)
    """
    cmd = ["curl", "-k", "-sS", "-I", url]
    rc, stdout, stderr = run_command(cmd, timeout=20)

    raw_output = f"RC={rc}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"

    if rc != 0:
        return None, raw_output

    for line in stdout.splitlines():
        if line.lower().startswith("location:"):
            return line.split(":", 1)[1].strip(), raw_output

    return None, raw_output


def extract_hostname(url: str) -> Optional[str]:
    """Extract hostname from a URL."""
    try:
        return urlparse(url).hostname
    except Exception:
        return None


def nslookup_host(hostname: str, dns_server: Optional[str] = None) -> Tuple[List[str], str]:
    """
    Run nslookup and return a sorted unique list of IPs plus raw output.

    Important:
    - Avoids capturing the DNS resolver/server IP at the top of nslookup output
    - Captures IPs only after the answer section begins
    - If dns_server is provided, nslookup uses that DNS server
    """
    cmd = ["nslookup", hostname]
    if dns_server:
        cmd.append(dns_server)

    rc, stdout, stderr = run_command(cmd, timeout=20)
    raw_output = f"RC={rc}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"

    if rc != 0:
        return [], raw_output

    ips: List[str] = []
    saw_name_block = False

    for line in stdout.splitlines():
        stripped = line.strip()

        if stripped.lower().startswith("name:") or "canonical name" in stripped.lower():
            saw_name_block = True

        if saw_name_block:
            ipv4_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", stripped)
            ips.extend(ipv4_matches)

            ipv6_matches = re.findall(
                r"\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]{1,4}\b", stripped
            )
            ips.extend(ipv6_matches)

    if not ips:
        for line in stdout.splitlines():
            stripped = line.strip().lower()
            if stripped.startswith("address:") and "server" not in stripped:
                ipv4_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                ipv6_matches = re.findall(
                    r"\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]{1,4}\b", line
                )
                ips.extend(ipv4_matches)
                ips.extend(ipv6_matches)

    return sorted(set(ips)), raw_output


def classify_dcv2_geo(ips: List[str]) -> Optional[str]:
    """
    Return DCv2 Geo-proximity label based on IPv4 prefix.
    Only applies to matching 151.186.* addresses.
    """
    for ip in ips:
        if ip.startswith("151.186.93."):
            return "LAX2.EDC"
        if ip.startswith("151.186.89."):
            return "SJC6.EDC"
        if ip.startswith("151.186.81."):
            return "MIA2.EDC"
        if ip.startswith("151.186.85."):
            return "IAD1.EDC"
    return None


def now_str() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def main() -> int:
    base_cname = get_base_ra_vpn_cname()
    region_urls = build_region_urls(base_cname)
    iterations_per_region = get_iteration_count()
    dns_server = get_dns_server()

    dns_server_display = dns_server if dns_server else "System Default DNS"

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    detail_log_path = LOG_DIR / f"vpn_redirect_detail_{timestamp}.log"
    summary_json_path = LOG_DIR / f"vpn_redirect_summary_{timestamp}.json"
    summary_txt_path = LOG_DIR / f"vpn_redirect_summary_{timestamp}.txt"

    counts: Dict[str, collections.Counter] = {
        region: collections.Counter() for region in region_urls
    }

    with detail_log_path.open("w", encoding="utf-8") as detail_log:
        detail_log.write(f"Start time: {now_str()}\n")
        detail_log.write(f"Base RA VPN CNAME: {base_cname}\n")
        detail_log.write(f"Iterations per region: {iterations_per_region}\n")
        detail_log.write(f"DNS Server to check against: {dns_server_display}\n")
        detail_log.write("=" * 80 + "\n\n")

        for region_url in region_urls:
            detail_log.write(f"REGION: {region_url}\n")
            detail_log.write("-" * 80 + "\n")

            for i in range(1, iterations_per_region + 1):
                iteration_time = now_str()
                detail_log.write(f"[{iteration_time}] Iteration {i}/{iterations_per_region}\n")

                redirect_url, curl_raw = curl_for_redirect(region_url)
                detail_log.write("CURL OUTPUT:\n")
                detail_log.write(curl_raw + "\n")

                if not redirect_url:
                    detail_log.write("RESULT: No redirect URL found.\n")
                    detail_log.write("-" * 80 + "\n")
                    key = json.dumps(
                        {
                            "redirect_url": None,
                            "hostname": None,
                            "ips": [],
                            "dcv2_geo": None,
                            "dns_server": dns_server_display,
                            "status": "no_redirect",
                        },
                        sort_keys=True,
                    )
                    counts[region_url][key] += 1
                    time.sleep(SLEEP_SECONDS)
                    continue

                hostname = extract_hostname(redirect_url)
                detail_log.write(f"PARSED REDIRECT URL: {redirect_url}\n")
                detail_log.write(f"PARSED HOSTNAME: {hostname}\n")

                if not hostname:
                    detail_log.write("RESULT: Could not parse hostname from redirect URL.\n")
                    detail_log.write("-" * 80 + "\n")
                    key = json.dumps(
                        {
                            "redirect_url": redirect_url,
                            "hostname": None,
                            "ips": [],
                            "dcv2_geo": None,
                            "dns_server": dns_server_display,
                            "status": "bad_hostname",
                        },
                        sort_keys=True,
                    )
                    counts[region_url][key] += 1
                    time.sleep(SLEEP_SECONDS)
                    continue

                ips, nslookup_raw = nslookup_host(hostname, dns_server=dns_server)
                detail_log.write("NSLOOKUP OUTPUT:\n")
                detail_log.write(nslookup_raw + "\n")
                detail_log.write(f"PARSED IPS: {ips}\n")

                dcv2_geo = classify_dcv2_geo(ips)
                if dcv2_geo:
                    detail_log.write(f"DCv2 Geo-proximity check: {dcv2_geo}\n")

                key = json.dumps(
                    {
                        "redirect_url": redirect_url,
                        "hostname": hostname,
                        "ips": ips,
                        "dcv2_geo": dcv2_geo,
                        "dns_server": dns_server_display,
                        "status": "ok" if ips else "no_ip",
                    },
                    sort_keys=True,
                )
                counts[region_url][key] += 1

                detail_log.write("-" * 80 + "\n")
                time.sleep(SLEEP_SECONDS)

            detail_log.write("\n")

        detail_log.write("=" * 80 + "\n")
        detail_log.write(f"End time: {now_str()}\n")

    summary_data = {
        "generated_at": now_str(),
        "base_ra_vpn_cname": base_cname,
        "iterations_per_region": iterations_per_region,
        "dns_server_to_check_against": dns_server_display,
        "regions": {},
    }

    for region_url, counter in counts.items():
        region_entries = []
        for key, count in counter.most_common():
            parsed = json.loads(key)
            parsed["count"] = count
            region_entries.append(parsed)
        summary_data["regions"][region_url] = region_entries

    with summary_json_path.open("w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    with summary_txt_path.open("w", encoding="utf-8") as f:
        f.write(f"Generated at: {summary_data['generated_at']}\n")
        f.write(f"Base RA VPN CNAME: {summary_data['base_ra_vpn_cname']}\n")
        f.write(f"Iterations per region: {iterations_per_region}\n")
        f.write(f"DNS Server to check against: {dns_server_display}\n")
        f.write("=" * 80 + "\n\n")

        for region_url, entries in summary_data["regions"].items():
            f.write(f"REGION: {region_url}\n")
            f.write("-" * 80 + "\n")
            if not entries:
                f.write("No results.\n\n")
                continue

            for entry in entries:
                f.write(f"Count        : {entry['count']}\n")
                f.write(f"Status       : {entry['status']}\n")
                f.write(f"Redirect URL : {entry['redirect_url']}\n")
                f.write(f"Hostname     : {entry['hostname']}\n")
                f.write(f"DNS Server   : {entry['dns_server']}\n")
                f.write(f"IPs          : {', '.join(entry['ips']) if entry['ips'] else 'None'}\n")
                if entry.get("dcv2_geo"):
                    f.write(f"DCv2 Geo-proximity check: {entry['dcv2_geo']}\n")
                f.write("-" * 40 + "\n")
            f.write("\n")

    print(f"Detailed log written to: {detail_log_path}")
    print(f"Summary JSON written to: {summary_json_path}")
    print(f"Summary text written to: {summary_txt_path}")
    print()

    for region_url, entries in summary_data["regions"].items():
        print(f"REGION: {region_url}")
        if not entries:
            print("  No results")
            continue

        for entry in entries:
            ips_display = ", ".join(entry["ips"]) if entry["ips"] else "None"
            print(f"  Count: {entry['count']}")
            print(f"    Status: {entry['status']}")
            print(f"    Redirect URL: {entry['redirect_url']}")
            print(f"    Hostname: {entry['hostname']}")
            print(f"    DNS Server to check against: {entry['dns_server']}")
            print(f"    IPs: {ips_display}")
            if entry.get("dcv2_geo"):
                print(f"    DCv2 Geo-proximity check: {entry['dcv2_geo']}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
