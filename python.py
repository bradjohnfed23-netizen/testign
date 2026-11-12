#!/usr/bin/env python3
"""
Passive Recon Framework (Educational)
- Discovers subdomains via crt.sh (Certificate Transparency)
- Checks for common paths using a small user-provided list
- Does NOT perform aggressive brute-forcing or exploitation
"""

import requests
import sys
import time
from urllib.parse import urljoin

# --- Configuration ---
TARGET_DOMAIN = ""  # Change to your authorized target
COMMON_PATHS = [
    "admin", "login", "api", "backup", "config",
    "robots.txt", "sitemap.xml", ".git/HEAD"
]
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; EducationalRecon/1.0)"
}

def discover_subdomains(domain):
    """Query crt.sh for subdomains via Certificate Transparency logs."""
    print(f"[*] Querying Certificate Transparency logs for: {domain}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            # Handle multiple names separated by newlines
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub and sub.endswith(domain) and "*" not in sub:
                    subdomains.add(sub)
        
        print(f"[+] Found {len(subdomains)} unique subdomains (passive)")
        return sorted(subdomains)
    except Exception as e:
        print(f"[-] CT lookup failed: {e}")
        return []

def check_paths(base_url, paths):
    """Check a short list of common paths against a single host."""
    print(f"[*] Checking common paths on: {base_url}")
    findings = []
    for path in paths:
        target_url = urljoin(base_url, path)
        try:
            # Use HEAD first; fall back to GET if needed
            resp = requests.head(target_url, headers=HEADERS, timeout=10, allow_redirects=True)
            status = resp.status_code
            # Consider 200 (OK) and 403 (Forbidden) as interesting
            if status in (200, 403):
                findings.append((target_url, status))
                print(f"  [+] {status} -> {target_url}")
            # Be polite
            time.sleep(0.2)
        except requests.RequestException:
            pass
    return findings

def main():
    print("=" * 60)
    print("PASSIVE RECON FRAMEWORK (Authorized Testing Only)")
    print("=" * 60)
    
    # 1. Passive subdomain discovery
    subs = discover_subdomains(TARGET_DOMAIN)
    
    if not subs:
        print("[!] No subdomains found passively. Exiting.")
        sys.exit(0)
    
    # Display first few
    print("\n[+] Sample subdomains:")
    for s in subs[:10]:
        print(f"    {s}")
    if len(subs) > 10:
        print(f"    ... and {len(subs)-10} more")
    
    # 2. Check common paths on the main domain (and optionally a few subs)
    print("\n[*] Path checks on main domain:")
    main_url = f"https://{TARGET_DOMAIN}"
    check_paths(main_url, COMMON_PATHS)
    
    # Optional: Check paths on up to 3 discovered subdomains (be polite)
    print("\n[*] Path checks on first 3 subdomains (rate-limited):")
    for sub in subs[:3]:
        check_paths(f"https://{sub}", COMMON_PATHS[:3])  # fewer paths per sub
        time.sleep(1)  # extra delay between hosts
    
    print("\n[✓] Recon complete. Remember: only scan authorized targets.")

if __name__ == "__main__":
    main()
