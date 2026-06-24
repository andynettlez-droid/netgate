import os
import sys
import argparse
import requests

API_BASE = "http://localhost:8000"

def get_config_files(config_dir):
    config_files = []
    if not os.path.exists(config_dir):
        print(f"[!] Error: Path '{config_dir}' does not exist.")
        return []
    
    for file in os.listdir(config_dir):
        if file.endswith((".cfg", ".conf", ".txt")) and not file.startswith("__"):
            config_files.append(os.path.join(config_dir, file))
    return config_files

def validate_configs(config_dir):
    config_files = get_config_files(config_dir)
    if not config_files:
        print("[!] No network configuration files found (.cfg, .conf, .txt).")
        return False

    print(f"[*] Found {len(config_files)} configuration file(s). Uploading to NetGate Sandbox...")
    
    # Upload files
    for file_path in config_files:
        filename = os.path.basename(file_path)
        try:
            with open(file_path, "rb") as f:
                res = requests.post(f"{API_BASE}/api/upload", files={"file": (filename, f)})
                if res.status_code == 200:
                    print(f"  [+] Uploaded: {filename}")
                else:
                    print(f"  [!] Failed to upload {filename}: {res.text}")
                    return False
        except Exception as e:
            print(f"  [!] Connection failed for {filename}: {e}")
            return False

    # Trigger Validation
    print("[*] Running network compliance and topology scan...")
    try:
        res = requests.get(f"{API_BASE}/api/validate")
        if res.status_code != 200:
            print(f"[!] Validation API returned error: {res.text}")
            return False
        
        data = res.json()
        audits = data.get("audits", {})
        topology = data.get("topology", {})
        
        print("\n" + "="*80)
        print("                        NETGATE COMPLIANCE SCORECARD")
        print("="*80)
        
        all_passed = True
        for device, checks in audits.items():
            print(f"\nDevice: \033[1;36m{device}\033[0m")
            print("-" * 80)
            print(f"{'Rule ID':<10} | {'Status':<8} | {'Severity':<8} | {'Title & Details'}")
            print("-" * 80)
            
            for check in checks:
                status = check.get("status", "FAILED")
                rule_id = check.get("id", "GEN-000")
                severity = check.get("severity", "INFO")
                title = check.get("title", "")
                details = check.get("details", "")
                
                if status == "PASSED":
                    status_str = "\033[1;32mPASSED\033[0m"
                else:
                    status_str = "\033[1;31mFAILED\033[0m"
                    all_passed = False
                    
                print(f"{rule_id:<10} | {status_str:<17} | {severity:<8} | {title}")
                if status == "FAILED" and details:
                    print(f"{'':<10} | {'':<8} | {'':<8} |   +- \033[3;30m{details}\033[0m")
            print("-" * 80)
            
        print(f"\nDiscovered Network Topology: {len(topology.get('nodes', []))} Nodes, {len(topology.get('links', []))} Links")
        for link in topology.get("links", []):
            print(f"  {link['source']} ({link['source_interface']}) <--- {link['subnet']} ---> {link['target']} ({link['target_interface']})")
            
        print("="*80)
        if all_passed:
            print("\033[1;32m>>> SUCCESS: All configuration validation and security compliance audits PASSED!\033[0m")
            return True
        else:
            print("\033[1;31m>>> FAILURE: Network compliance failures detected. Hardening required.\033[0m")
            return False
            
    except Exception as e:
        print(f"[!] Error contacting validation API: {e}")
        return False

def trace_path(source, dest, port, protocol):
    print(f"[*] Testing reachability path from '{source}' to '{dest}' (Port {port}/{protocol.upper()})...")
    payload = {
        "source_node": source,
        "dest_ip": dest,
        "protocol": protocol,
        "dest_port": port
    }
    
    try:
        res = requests.post(f"{API_BASE}/api/trace", json=payload)
        if res.status_code != 200:
            print(f"[!] Trace API returned error: {res.text}")
            return
            
        data = res.json()
        status = data.get("status", "NO_ROUTE")
        hops = data.get("hops", [])
        log = data.get("log", [])
        
        print("\n" + "="*80)
        print("                        NETGATE SIMULATED TRACEROUTE LOG")
        print("="*80)
        
        # Color status
        if status == "REACHED":
            status_str = "\033[1;32mREACHED\033[0m"
        elif status == "ACL_BLOCKED":
            status_str = "\033[1;31mACL_BLOCKED\033[0m"
        else:
            status_str = f"\033[1;33m{status}\033[0m"
            
        print(f"Destination Status: {status_str}")
        print(f"Simulated Routing Path: {' -> '.join(hops) if hops else 'None'}\n")
        print("Hop-by-Hop Trace Details:")
        for line in log:
            if "DENIED" in line or "blocked" in line:
                print(f"  \033[1;31m{line}\033[0m")
            elif "successfully" in line or "delivered" in line:
                print(f"  \033[1;32m{line}\033[0m")
            else:
                print(f"  {line}")
        print("="*80)
        
    except Exception as e:
        print(f"[!] Error contacting trace API: {e}")

def reset_configs():
    print("[*] Contacting NetGate API to reset configurations to default...")
    try:
        res = requests.post(f"{API_BASE}/api/reset")
        if res.status_code == 200:
            print(f"[+] Success: {res.json().get('message')}")
        else:
            print(f"[!] Failed to reset: {res.text}")
    except Exception as e:
        print(f"[!] Error contacting API: {e}")

def main():
    parser = argparse.ArgumentParser(description="NetGate CLI - GitOps Network Compliance Client")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # validate
    val_parser = subparsers.add_parser("validate", help="Scan Cisco config files for compliance")
    val_parser.add_argument("--config-dir", default=".", help="Directory containing config files (default: .)")

    # trace
    trace_parser = subparsers.add_parser("trace", help="Run path traceroute simulation")
    trace_parser.add_argument("--source", required=True, help="Source router/device hostname")
    trace_parser.add_argument("--dest", required=True, help="Destination IP address")
    trace_parser.add_argument("--port", type=int, default=80, help="Destination port (default: 80)")
    trace_parser.add_argument("--protocol", default="tcp", choices=["tcp", "udp", "icmp"], help="IP Protocol (default: tcp)")

    # reset
    subparsers.add_parser("reset", help="Reset configurations to default state")

    args = parser.parse_args()

    if args.command == "validate":
        success = validate_configs(args.config_dir)
        sys.exit(0 if success else 1)
    elif args.command == "trace":
        trace_path(args.source, args.dest, args.port, args.protocol)
    elif args.command == "reset":
        reset_configs()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
