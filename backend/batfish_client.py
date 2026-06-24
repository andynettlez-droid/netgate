import os
import shutil
import tempfile
import socket
import logging
from typing import Dict, List, Optional, Tuple

# Suppress pybatfish logging warnings
logging.getLogger("pybatfish").setLevel(logging.ERROR)

try:
    from pybatfish.client.commands import bf_init_snapshot, bf_session
    from pybatfish.question import bfq
    from pybatfish.datamodel.flow import HeaderConstraints
    PYBATFISH_AVAILABLE = True
except ImportError:
    PYBATFISH_AVAILABLE = False

class BatfishClientWrapper:
    def __init__(self, host: str = "localhost"):
        # Read from environment if set
        self.host = os.environ.get("BATFISH_HOST", host)
        self.session_initialized = False

    def is_online(self) -> bool:
        """Fast check if the Batfish service is active via socket connection."""
        if not PYBATFISH_AVAILABLE:
            return False
        try:
            # Batfish WorkMgr runs on port 9996
            with socket.create_connection((self.host, 9996), timeout=1.0):
                return True
        except Exception:
            return False

    def initialize_session(self):
        """Sets the host and checks if we can connect."""
        if not self.is_online():
            self.session_initialized = False
            return False
        
        try:
            bf_session.host = self.host
            # Test a basic query to verify connection
            bfq.testfilters()
            self.session_initialized = True
            return True
        except Exception as e:
            print(f"[Batfish] Session initialization failed: {e}")
            self.session_initialized = False
            return False

    def load_network_snapshot(self, configs: Dict[str, str], snapshot_name: str = "netgate-snapshot") -> bool:
        """
        Creates a temporary directory structured for Batfish and uploads it as a snapshot.
        """
        if not self.session_initialized and not self.initialize_session():
            return False

        # Create temporary directory structure
        temp_dir = tempfile.mkdtemp()
        configs_dir = os.path.join(temp_dir, "configs")
        os.makedirs(configs_dir)

        try:
            # Write all configuration strings to files
            for hostname, content in configs.items():
                # Clean up filename to prevent directory traversal
                safe_name = "".join([c for c in hostname if c.isalnum() or c in "-_."])
                file_path = os.path.join(configs_dir, f"{safe_name}.cfg")
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)

            # Upload snapshot to Batfish
            bf_init_snapshot(temp_dir, name=snapshot_name, overwrite=True)
            return True
        except Exception as e:
            print(f"[Batfish] Error loading network snapshot: {e}")
            return False
        finally:
            # Clean up temp directory
            shutil.rmtree(temp_dir, ignore_errors=True)

    def run_compliance_scan(self, configs: Dict[str, str]) -> Dict[str, List[Dict]]:
        """
        Runs Batfish queries to check for parse issues and network properties,
        and merges them with our local auditor checks for high-fidelity compliance feedback.
        """
        # Load snapshot first
        if not self.load_network_snapshot(configs):
            raise ConnectionError("Batfish service is offline or session failed to initialize.")

        results = {}
        for node in configs.keys():
            results[node] = []

        try:
            # 1. Check File Parse Status
            parse_status = bfq.fileParseStatus().answer().frame()
            for _, row in parse_status.iterrows():
                # Map filename back to node
                filename = row.get("File_Name", "")
                node_name = os.path.splitext(os.path.basename(filename))[0]
                status = row.get("Status", "PASSED")
                
                if node_name in results:
                    if status != "PASSED":
                        results[node_name].append({
                            "id": "SYS-001",
                            "title": "Configuration Parse Failed",
                            "description": "Batfish encountered syntax errors or warnings while parsing this configuration.",
                            "severity": "HIGH",
                            "status": "FAILED",
                            "details": f"Parse status: {status}."
                        })
                    else:
                        results[node_name].append({
                            "id": "SYS-001",
                            "title": "Configuration Parse Failed",
                            "description": "Configuration file syntax validated successfully by Batfish parser.",
                            "severity": "HIGH",
                            "status": "PASSED",
                            "details": "Syntax is fully compliant."
                        })

            # 2. Query SNMP Communities
            try:
                snmp_df = bfq.snmpCommunities().answer().frame()
                for node in results.keys():
                    # Filter SNMP communities for this specific node
                    node_snmp = snmp_df[snmp_df["Node"].str.lower() == node.lower()]
                    weak_communities = []
                    for _, row in node_snmp.iterrows():
                        comm = row.get("Community_String", "")
                        if comm.lower() in ["public", "private", "admin", "cisco", "manager"]:
                            weak_communities.append(comm)
                    
                    if weak_communities:
                        results[node].append({
                            "id": "SEC-004",
                            "title": "Default or Weak SNMP Community Strings",
                            "description": "Standard read/write community strings are active, exposing the device to unauthorized monitoring.",
                            "severity": "HIGH",
                            "status": "FAILED",
                            "details": f"Found weak community string(s): {', '.join(weak_communities)}."
                        })
                    else:
                        results[node].append({
                            "id": "SEC-004",
                            "title": "Default or Weak SNMP Community Strings",
                            "description": "All SNMP community strings are configured securely or SNMP is disabled.",
                            "severity": "HIGH",
                            "status": "PASSED",
                            "details": "No weak SNMP community strings detected."
                        })
            except Exception:
                # Fallback if query fails
                pass

            # 3. Query Interface Properties for descriptions and shutdown state
            try:
                int_df = bfq.interfaceProperties(properties="Active,Description").answer().frame()
                for node in results.keys():
                    node_ints = int_df[int_df["Interface"].apply(lambda x: x.node.lower() == node.lower())]
                    unsecured = []
                    for _, row in node_ints.iterrows():
                        int_obj = row.get("Interface")
                        int_name = int_obj.interface
                        active = row.get("Active", False)
                        desc = row.get("Description", "")
                        
                        # We flag active physical interfaces with no description (poses connection risks)
                        if active and not desc:
                            if any(x in int_name.lower() for x in ["ethernet", "gigabit", "fastether", "ten-gig"]):
                                unsecured.append(int_name)
                    
                    if unsecured:
                        results[node].append({
                            "id": "NET-001",
                            "title": "Unsecured Physical Interfaces Active",
                            "description": "Active physical interfaces are configured without shutdown status and lack documentation descriptions.",
                            "severity": "LOW",
                            "status": "FAILED",
                            "details": f"Active unsecured interfaces: {', '.join(unsecured)}"
                        })
                    else:
                        results[node].append({
                            "id": "NET-001",
                            "title": "Unsecured Physical Interfaces Active",
                            "description": "All physical ports are safely shut down, documented, or configured.",
                            "severity": "LOW",
                            "status": "PASSED",
                            "details": "All physical interfaces are either shutdown or have descriptions."
                        })
            except Exception:
                pass

        except Exception as e:
            print(f"[Batfish] Error querying compliance: {e}")

        # Fill in any missing standard checks using local ConfigAuditor to ensure 100% check parity
        from auditor import ConfigAuditor
        for node, content in configs.items():
            auditor = ConfigAuditor(content)
            local_checks = auditor.run_all_checks()
            
            # Map checks by ID
            existing_ids = {check["id"] for check in results[node]}
            for check in local_checks:
                if check["id"] not in existing_ids:
                    results[node].append(check)

        return results

    def get_topology_edges(self, configs: Dict[str, str]) -> List[Dict]:
        """
        Query Batfish for L3 edges to build the visual topology map links.
        """
        if not self.load_network_snapshot(configs):
            return []

        links = []
        try:
            edges_df = bfq.edges(edgeType="layer3").answer().frame()
            ip_owners_df = bfq.ipOwners().answer().frame()

            # Helper to lookup IP for a node/interface pair
            def lookup_ip_subnet(node_name, int_name):
                # Filter ipOwners for matching interface and node
                matches = ip_owners_df[
                    (ip_owners_df["Node"].str.lower() == node_name.lower()) &
                    (ip_owners_df["Interface"].str.lower() == int_name.lower())
                ]
                if not matches.empty:
                    ip = matches.iloc[0].get("IP", "")
                    mask = matches.iloc[0].get("Mask", 24)
                    return ip, f"{ip}/{mask}"
                return "", ""

            seen_edges = set()
            for _, row in edges_df.iterrows():
                src_obj = row.get("Interface")
                tgt_obj = row.get("Remote_Interface")
                
                src_node = src_obj.node
                src_int = src_obj.interface
                tgt_node = tgt_obj.node
                tgt_int = tgt_obj.interface

                # Deduplicate bidrectional links
                link_key = tuple(sorted([f"{src_node}:{src_int}", f"{tgt_node}:{tgt_int}"]))
                if link_key in seen_edges:
                    continue
                seen_edges.add(link_key)

                src_ip, _ = lookup_ip_subnet(src_node, src_int)
                tgt_ip, subnet = lookup_ip_subnet(tgt_node, tgt_int)

                links.append({
                    "source": src_node,
                    "source_interface": src_int,
                    "source_ip": src_ip,
                    "target": tgt_node,
                    "target_interface": tgt_int,
                    "target_ip": tgt_ip,
                    "subnet": subnet or "10.0.0.0/24"
                })
        except Exception as e:
            print(f"[Batfish] Error querying topology edges: {e}")
        
        return links

    def trace_path(self, configs: Dict[str, str], source_node: str, dest_ip: str, protocol: str = "tcp", dest_port: int = 80) -> Dict:
        """
        Executes a formal traceroute using Batfish question modeling.
        """
        if not self.load_network_snapshot(configs):
            raise ConnectionError("Batfish service is offline or session failed to initialize.")

        log = []
        hops = []
        status = "NO_ROUTE"

        log.append(f"[Batfish] Initiating formal mathematical traceroute from '{source_node}' to '{dest_ip}' (Port {dest_port}/{protocol.upper()})")

        try:
            # Build flow header constraints
            headers = HeaderConstraints(
                dstIp=dest_ip,
                ipProtocol=protocol.lower(),
                dstPort=dest_port
            )

            # Query traceroute
            trace_df = bfq.traceroute(startLocation=source_node, headers=headers).answer().frame()

            if trace_df.empty:
                log.append("Batfish traceroute query returned an empty result.")
                return {"status": "NO_ROUTE", "hops": [], "log": log}

            # Inspect the first trace result
            first_row = trace_df.iloc[0]
            traces_col = first_row.get("Traces", [])
            
            if not traces_col:
                log.append("No active routing path traces returned by engine.")
                return {"status": "NO_ROUTE", "hops": [], "log": log}

            trace = traces_col[0]
            disposition = trace.disposition # ACCEPTED, DENIED, LOOP, NO_ROUTE, etc.
            
            # Map Batfish disposition to NetGate UI states
            if disposition == "ACCEPTED":
                status = "REACHED"
            elif disposition in ["DENIED", "DELIVERED_TO_SUBNET_BUT_DENIED"]:
                status = "ACL_BLOCKED"
            elif disposition == "LOOP":
                status = "LOOP_DETECTED"
            else:
                status = "NO_ROUTE"

            # Parse hops and steps
            for i, hop in enumerate(trace.hops):
                node_name = hop.node
                hops.append(node_name)
                log.append(f"Hop {i+1}: Node '{node_name}' received packet.")

                # Detail steps inside node (Routing, Filters, etc.)
                for step in hop.steps:
                    detail = step.detail
                    action = step.action # TRANSMITTED, PERMITTED, DENIED, RECEIVED, etc.
                    
                    # Log routing/filtering decisions
                    step_type = step.__class__.__name__
                    if "Routing" in step_type:
                        routes = getattr(detail, "routes", [])
                        if routes:
                            route_desc = f"Matched Route: {routes[0].get('network', '0.0.0.0/0')} via next-hop {routes[0].get('nextHopIp', 'Unknown')}"
                            log.append(f"  +- Routing: {route_desc}")
                    elif "Filter" in step_type:
                        filter_name = getattr(detail, "filter", "ACL")
                        log.append(f"  +- Firewall Filter '{filter_name}': Action is {action}")

            if status == "REACHED":
                log.append(f"Packet successfully delivered to destination {dest_ip}.")
            elif status == "ACL_BLOCKED":
                log.append("Packet dropped or blocked by an active Access Control List (ACL).")
            elif status == "LOOP_DETECTED":
                log.append("Routing loop encountered! Packet dropped.")
            else:
                log.append("Drop packet: destination IP host unreachable or has no route.")

        except Exception as e:
            log.append(f"[Batfish Error] Verification failed: {e}")
            print(f"[Batfish] Trace error: {e}")
            return {"status": "ERROR", "hops": [], "log": log}

        return {
            "status": status,
            "hops": hops,
            "log": log
        }
