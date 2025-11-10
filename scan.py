#!/usr/bin/env python3
"""
network_scanner_pipeline.py (IoT detection removed)

Single-file orchestrator for:
- Target discovery
- Port & service enumeration
- Service fingerprinting
- Vulnerability detection (Nmap NSE parsing)
- (Optional) Automated Nmap -> OpenVAS pipeline (disabled by default)

USAGE (safe default):
  python3 network_scanner_pipeline.py --targets 192.168.1.0/24 --out results.db

To actually run network scans (be careful, run only on authorized targets):
  python3 network_scanner_pipeline.py --targets 192.168.1.0/24 --do-scan --out results.db

WARNING: This tool can be intrusive. DO NOT scan external systems without written permission.
"""

import argparse
import subprocess
import json
import sqlite3
import os
import re
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

# -------------------------
# Configuration & constants
# -------------------------
DEFAULT_DB = "results.db"
NMAP_BIN = "nmap"            # ensure nmap is in PATH
ARP_SCAN_BIN = "arp-scan"    # optional: for local ARP discovery
MASSCAN_BIN = "masscan"      # optional, fast scanner
GVM_CLI = "gvm-cli"          # gvm-tools CLI for OpenVAS/GVM (optional)

# -------------------------
# Helpers: DB
# -------------------------
def init_db(db_path: str):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS targets (
                    ip TEXT PRIMARY KEY,
                    mac TEXT,
                    first_seen TEXT
                 )''')
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    nmap_xml TEXT,
                    ports_json TEXT,
                    nse_json TEXT,
                    scanned_at TEXT
                 )''')
    conn.commit()
    conn.close()

def save_target(db_path: str, ip: str, mac: Optional[str]):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    now = datetime.utcnow().isoformat()
    c.execute("INSERT OR IGNORE INTO targets (ip, mac, first_seen) VALUES (?, ?, ?)", (ip, mac, now))
    conn.commit()
    conn.close()

def save_scan(db_path: str, ip: str, nmap_xml: str, ports: List[Dict[str,Any]],
              nse_results: List[Dict[str,Any]]):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    now = datetime.utcnow().isoformat()
    c.execute("INSERT INTO scans (ip, nmap_xml, ports_json, nse_json, scanned_at) VALUES (?, ?, ?, ?, ?)",
              (ip, nmap_xml, json.dumps(ports), json.dumps(nse_results), now))
    conn.commit()
    conn.close()

# -------------------------
# Utilities
# -------------------------
def run_cmd(cmd: List[str], capture_output=True, check=False, text=True, timeout=300) -> subprocess.CompletedProcess:
    """Run an external command and return CompletedProcess. Logs the command."""
    print(f"[CMD] {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=capture_output, check=check, text=text, timeout=timeout)

def parse_nmap_ports(nmap_xml: str) -> List[Dict[str,Any]]:
    """
    Parse minimal port info from nmap -oX output using regex.
    (For robust parsing use libnmap or xml.etree; here we keep it dependency-light.)
    """
    ports = []
    # crude but effective regex to capture port lines:
    port_entries = re.findall(r'<port protocol="([^"]+)" portid="([^"]+)">(.+?)</port>', nmap_xml, flags=re.DOTALL)
    for proto, portid, inner in port_entries:
        state_m = re.search(r'<state state="([^"]+)"', inner)
        service_m = re.search(r'<service\s+([^/>]+?)(?:/?>|/)', inner)
        product = None
        version = None
        name = None
        if service_m:
            attrs = service_m.group(1)
            name_m = re.search(r'name="([^"]+)"', attrs)
            product_m = re.search(r'product="([^"]+)"', attrs)
            version_m = re.search(r'version="([^"]+)"', attrs)
            if name_m:
                name = name_m.group(1)
            if product_m:
                product = product_m.group(1)
            if version_m:
                version = version_m.group(1)
        ports.append({
            "port": int(portid),
            "proto": proto,
            "state": state_m.group(1) if state_m else "unknown",
            "name": name,
            "product": product,
            "version": version
        })
    return ports

def parse_nmap_nse(nmap_xml: str) -> List[Dict[str,Any]]:
    """
    Parse NSE script output snippets from nmap XML.
    We search for <script id="..."> nodes and extract output.
    """
    scripts = []
    script_entries = re.findall(r'<script id="([^"]+)"\s+output="([^"]*)"\s*/>', nmap_xml)
    for sid, output in script_entries:
        scripts.append({"id": sid, "output": output})
    # Also capture multiline script blocks
    script_block_entries = re.findall(r'<script id="([^"]+)" output="([^"]*)">(.+?)</script>', nmap_xml, flags=re.DOTALL)
    for sid, output, inner in script_block_entries:
        combined = (output or "") + "\n" + inner.strip()
        scripts.append({"id": sid, "output": combined})
    return scripts

# -------------------------
# 1) Target discovery
# -------------------------
def target_discovery(network_cidr: str, db_path: str, use_arp_scan: bool=False, do_scan: bool=False) -> List[str]:
    """
    Discover targets on a local network.
    - If use_arp_scan is True and arp-scan is installed, runs arp-scan --localnet (fast, LAN-only)
    - Otherwise falls back to nmap -sn (ping scan)
    - If do_scan is False, this function prints the commands it would run (safe dry-run)
    Returns list of discovered IPs.
    """
    discovered = []
    print("\n# ===== [TARGET DISCOVERY] =====")
    if use_arp_scan:
        cmd = [ARP_SCAN_BIN, "--interface=eth0", "--localnet"] if network_cidr in ("", None) else [ARP_SCAN_BIN, network_cidr]
        print("# This is target discovery (ARP). Command:")
        print(" ".join(cmd))
        if not do_scan:
            print("# Dry-run: ARP scan not executed. Pass --do-scan to actually run it.")
        else:
            try:
                cp = run_cmd(cmd)
                out = cp.stdout
                # parse lines like: 192.168.1.10  00:11:22:33:44:55  Vendor
                for line in out.splitlines():
                    parts = re.split(r'\s{2,}|\t+', line.strip())
                    if len(parts) >= 2 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                        ip = parts[0]
                        mac = parts[1] if len(parts) > 1 else None
                        discovered.append(ip)
                        save_target(db_path, ip, mac)
            except Exception as e:
                print("ARP scan failed or arp-scan not installed:", e)
    # fallback / common method: nmap -sn
    cmd = [NMAP_BIN, "-sn", network_cidr]
    print("# This is target discovery (Nmap ping scan). Command:")
    print(" ".join(cmd))
    if not do_scan:
        print("# Dry-run: Nmap ping scan not executed. Pass --do-scan to actually run it.")
        # we return empty list for dry-run
        return discovered
    cp = run_cmd(cmd)
    out = cp.stdout
    # parse lines: Nmap scan report for 192.168.1.10
    ips = re.findall(r"Nmap scan report for ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", out)
    for ip in ips:
        discovered.append(ip)
        save_target(db_path, ip, None)
    print(f"[INFO] Discovered {len(ips)} targets.")
    return list(dict.fromkeys(discovered))  # unique preserve order

# -------------------------
# 2) Port & service enumeration + fingerprinting
# -------------------------
def nmap_service_scan(target_ip: str, top_ports: bool=True, ports: Optional[str]=None, do_scan: bool=False,
                      service_detect=True, os_detect=False, extra_scripts: Optional[List[str]]=None) -> Dict[str,Any]:
    """
    Run an nmap scan for service enumeration and fingerprinting.
    - top_ports: use --top-ports 1000 if True
    - ports: string like '1-65535' if specified
    - service_detect: add -sV
    - os_detect: add -O
    - extra_scripts: list of nse script names to run (e.g., ['vuln'])
    Returns dict with 'nmap_xml', 'ports' (list), 'nse' (list)
    """
    print(f"\n# ===== [PORT & SERVICE ENUMERATION] for {target_ip} =====")
    args = [NMAP_BIN, "-oX", "-", "-Pn"]  # -Pn to avoid host discovery issues
    if service_detect:
        args.append("-sV")
    if os_detect:
        args.append("-O")
    if top_ports:
        args += ["--top-ports", "1000"]
    if ports:
        args += ["-p", ports]
    if extra_scripts:
        args += ["--script"] + [",".join(extra_scripts)]
    print("# This is port & service enumeration. Command:")
    print(" ".join(args + [target_ip]))
    if not do_scan:
        print("# Dry-run: nmap scan not executed. Pass --do-scan to actually run it.")
        return {"nmap_xml": "", "ports": [], "nse": []}
    cp = run_cmd(args + [target_ip], timeout=600)
    nmap_xml = cp.stdout
    ports = parse_nmap_ports(nmap_xml)
    nse_results = parse_nmap_nse(nmap_xml)
    print(f"[INFO] Found {len(ports)} port entries (may include closed/filtered).")
    return {"nmap_xml": nmap_xml, "ports": ports, "nse": nse_results}

# -------------------------
# 3) Vulnerability detection (via Nmap NSE + optional OpenVAS pipeline)
# -------------------------
def vuln_detection_via_nmap(target_ip: str, do_scan: bool=False) -> List[Dict[str,Any]]:
    """
    Run nmap's vuln scripts and gather outputs.
    - If do_scan False: prints command only.
    """
    print(f"\n# ===== [VULNERABILITY DETECTION - Nmap NSE] for {target_ip} =====")
    cmd = [NMAP_BIN, "-oX", "-", "-sV", "--script", "vuln", "-p", "1-65535", "-Pn", target_ip]
    print("# This is vulnerability detection (Nmap --script vuln). Command:")
    print(" ".join(cmd))
    if not do_scan:
        print("# Dry-run: NSE vuln scan not executed. Pass --do-scan to actually run it.")
        return []
    cp = run_cmd(cmd, timeout=900)
    nmap_xml = cp.stdout
    nse = parse_nmap_nse(nmap_xml)
    # crude filter: look for outputs mentioning CVE or VULNERABLE
    flagged = []
    for s in nse:
        lower = s.get("output","").lower()
        if "cve" in lower or "vulnerable" in lower or "exposed" in lower or "overflow" in lower:
            flagged.append(s)
    print(f"[INFO] NSE reported {len(nse)} scripts; flagged {len(flagged)} potential findings (pattern match).")
    return nse

def nmap_to_openvas_pipeline(nmap_xml: str, target_ip: str, enable_openvas: bool=False):
    """
    Show and (optionally) run the pipeline that imports nmap XML into OpenVAS/GVM.
    """
    print("\n# ===== [NMAP -> OPENVAS PIPELINE] =====")
    filename = f"nmap_{target_ip.replace('.','_')}.xml"
    with open(filename, "w") as f:
        f.write(nmap_xml or "")
    print(f"# Saved nmap xml to {filename}")
    print("# The following are example commands to import into OpenVAS/GVM (they are NOT executed by default):")
    example_cmds = [
        f"gvm-cli socket --xml '<create_target><name>{target_ip}</name><hosts>{target_ip}</hosts></create_target>'",
        f"gvm-manage-certs -a  # (example: manage certificates for GVM)",
        f"gvmd --create-target --name='{target_ip}' --hosts='{target_ip}'",
        f"gvmd --create-task --name='nmap-import-{target_ip}' --target='target-uuid' --scanner='scanner-uuid'",
        f"gvmd --start-task --task='task-uuid'"
    ]
    for c in example_cmds:
        print("# " + c)
    if not enable_openvas:
        print("# OpenVAS import not enabled. To run these commands set --enable-openvas.")
        return
    try:
        print("[EXEC] Attempting to import nmap XML into OpenVAS using gvm-cli (example).")
        cp = run_cmd([GVM_CLI, "socket", "--xml", f"<create_target><name>{target_ip}</name><hosts>{target_ip}</hosts></create_target>"])
        print(cp.stdout[:1000])
        print("[INFO] OpenVAS pipeline executed (check GVM dashboard).")
    except Exception as e:
        print("[ERROR] OpenVAS import failed or gvm-cli not configured:", e)

# -------------------------
# Main orchestration
# -------------------------
def orchestrate(args):
    db_path = args.out
    init_db(db_path)
    # 1. Target discovery
    targets = target_discovery(args.targets, db_path, use_arp_scan=args.use_arp_scan, do_scan=args.do_scan)
    if not targets:
        print("[WARN] No targets discovered. Exiting.")
        return
    # iterate targets
    for ip in targets:
        print(f"\n\n========== Processing target: {ip} ==========")
        # 2. Port & service enumeration + fingerprinting
        nmap_res = nmap_service_scan(ip, top_ports=not args.full_port_scan,
                                     ports=args.ports, do_scan=args.do_scan,
                                     service_detect=True, os_detect=args.os_detect,
                                     extra_scripts=args.extra_scripts)
        # 3. Vulnerability detection via NSE (optional deeper scan)
        nse_deep = []
        if args.do_vuln_nse:
            nse_deep = vuln_detection_via_nmap(ip, do_scan=args.do_scan)
        # store results
        save_scan(db_path, ip, nmap_res.get("nmap_xml",""), nmap_res.get("ports",[]), nse_deep)
        # 4. Optionally run nmap-to-openvas pipeline
        if args.enable_openvas:
            nmap_to_openvas_pipeline(nmap_res.get("nmap_xml",""), ip, enable_openvas=args.enable_openvas)
    print("\n[Done] Orchestration finished. Results stored in", db_path)

# -------------------------
# CLI (Modified for Interactive Target Input)
# -------------------------
import re

def is_valid_target(target: str) -> bool:
    """Check if the input is a valid IP, CIDR, or hostname."""
    ipv4 = r'^\d{1,3}(\.\d{1,3}){3}$'
    cidr = r'^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$'
    hostname = r'^[a-zA-Z0-9\.\-]+$'
    if re.match(ipv4, target) or re.match(cidr, target) or re.match(hostname, target):
        return True
    return False

def ask_for_target() -> str:
    """Ask the user to enter a target if not provided."""
    print("\n🔍 No target specified. Please choose or enter a target:")
    print("1️⃣  Localhost (127.0.0.1) - Safe for testing")
    print("2️⃣  scanme.nmap.org - Public target allowed for learning")
    print("3️⃣  Custom IP / CIDR (e.g., 192.168.1.0/24 or 10.0.0.5)")
    choice = input("Enter 1 / 2 / 3 (default 1): ").strip() or "1"

    if choice == "1":
        return "127.0.0.1"
    elif choice == "2":
        return "scanme.nmap.org"
    else:
        while True:
            custom = input("Enter your target IP or CIDR: ").strip()
            if is_valid_target(custom):
                return custom
            print("⚠️ Invalid format. Example: 192.168.1.0/24 or 10.0.0.5")

def parse_args_and_prompt():
    p = argparse.ArgumentParser(description="Simple Network Scanner Pipeline (auto prompt for target)")
    p.add_argument("--targets", required=False, help="Target CIDR or host (e.g., 192.168.1.0/24 or 192.168.1.10)")
    p.add_argument("--out", default=DEFAULT_DB, help="SQLite DB file to store results")
    p.add_argument("--do-scan", action="store_true", help="Actually run the external scan commands (dry-run otherwise)")
    p.add_argument("--use-arp-scan", action="store_true", help="Use arp-scan for LAN discovery (if installed)")
    p.add_argument("--full-port-scan", dest="full_port_scan", action="store_true", help="Scan all ports (riskier, slower)")
    p.add_argument("--ports", default=None, help="Specify ports for nmap (e.g., '1-1024' or '22,80,443')")
    p.add_argument("--os-detect", action="store_true", help="Enable OS detection (-O)")
    p.add_argument("--do-vuln-nse", action="store_true", help="Run Nmap vuln NSE scripts (only with --do-scan and authorization)")
    p.add_argument("--enable-openvas", action="store_true", help="Enable Nmap -> OpenVAS pipeline (requires gvm-tools/gvmd configured)")
    p.add_argument("--extra-scripts", nargs="*", help="Extra NSE scripts to pass to nmap (e.g., http-* vuln)")
    args = p.parse_args()

    # If user didn’t provide a target, ask interactively
    if not args.targets:
        args.targets = ask_for_target()
        print(f"[INFO] Using target: {args.targets}")
    return args

# -------------------------
# Main Entry
# -------------------------
if __name__ == "__main__":
    args = parse_args_and_prompt()
    print("\n⚠️  WARNING: Only scan systems you own or have explicit permission to test.")
    orchestrate(args)
