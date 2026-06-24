import re
import ipaddress

class NetworkSimulator:
    def __init__(self, configs: dict):
        """
        configs: Dictionary of { filename_or_hostname: config_text }
        """
        self.raw_configs = configs
        self.devices = {}  # Parsed network devices
        self.topology_links = []
        self.parse_all_configs()
        self.build_topology()

    def parse_all_configs(self):
        for identifier, text in self.raw_configs.items():
            parsed = self.parse_single_config(text)
            hostname = parsed.get("hostname", identifier)
            self.devices[hostname] = parsed

    def parse_single_config(self, text: str):
        device = {
            "hostname": "Unknown",
            "interfaces": {},
            "static_routes": [],
            "acls": {}
        }
        
        current_interface = None
        in_acl_block = False
        acl_name = None
        
        lines = text.splitlines()
        for line in lines:
            cleaned = line.strip()
            
            # Hostname
            if cleaned.startswith("hostname"):
                parts = cleaned.split()
                if len(parts) > 1:
                    device["hostname"] = parts[1]
            
            # Interfaces
            elif cleaned.startswith("interface"):
                current_interface = cleaned.replace("interface ", "")
                device["interfaces"][current_interface] = {
                    "ip": None,
                    "subnet": None,
                    "shutdown": False,
                    "acl_in": None,
                    "acl_out": None
                }
            elif current_interface and not cleaned.startswith("interface"):
                if cleaned == "shutdown":
                    device["interfaces"][current_interface]["shutdown"] = True
                elif cleaned.startswith("ip address"):
                    parts = cleaned.split()
                    if len(parts) >= 4:
                        # ip address 192.168.1.1 255.255.255.0
                        device["interfaces"][current_interface]["ip"] = parts[2]
                        device["interfaces"][current_interface]["subnet"] = parts[3]
                elif cleaned.startswith("ip access-group"):
                    parts = cleaned.split()
                    # ip access-group ACL_NAME in/out
                    if len(parts) >= 4:
                        direction = parts[3]
                        acl_name = parts[2]
                        if direction == "in":
                            device["interfaces"][current_interface]["acl_in"] = acl_name
                        elif direction == "out":
                            device["interfaces"][current_interface]["acl_out"] = acl_name
                elif cleaned == "!":
                    current_interface = None
            
            # Static Routes
            elif cleaned.startswith("ip route"):
                parts = cleaned.split()
                # ip route 10.0.0.0 255.255.255.0 192.168.1.254
                if len(parts) >= 5:
                    device["static_routes"].append({
                        "prefix": parts[2],
                        "mask": parts[3],
                        "next_hop": parts[4]
                    })
            
            # ACLs (simplified extended ACL parsing)
            elif cleaned.startswith("ip access-list"):
                parts = cleaned.split()
                # ip access-list extended ACL_NAME
                if len(parts) >= 4:
                    acl_name = parts[3]
                    device["acls"][acl_name] = []
                    in_acl_block = True
            elif in_acl_block:
                if cleaned == "!":
                    in_acl_block = False
                    acl_name = None
                elif acl_name:
                    # Parse rules inside ACL: deny tcp any any eq 22, permit ip any any
                    device["acls"][acl_name].append(cleaned)
                    
        return device

    def build_topology(self):
        """
        Build topology link list by finding overlapping subnets across interfaces.
        """
        interfaces_list = []
        for hostname, device in self.devices.items():
            for int_name, int_data in device["interfaces"].items():
                if int_data["ip"] and int_data["subnet"] and not int_data["shutdown"]:
                    try:
                        # Build network interface info
                        net = ipaddress.IPv4Interface(f"{int_data['ip']}/{int_data['subnet']}")
                        interfaces_list.append({
                            "hostname": hostname,
                            "interface": int_name,
                            "ip": int_data["ip"],
                            "network": net.network,
                            "net_interface": net
                        })
                    except Exception:
                        pass # Ignore parsing errors for malformed IPs
        
        # Link interfaces on the same subnet
        self.topology_links = []
        seen_links = set()
        for i in range(len(interfaces_list)):
            for j in range(i + 1, len(interfaces_list)):
                int_a = interfaces_list[i]
                int_b = interfaces_list[j]
                
                if int_a["hostname"] != int_b["hostname"] and int_a["network"] == int_b["network"]:
                    # Create Link
                    link_key = tuple(sorted([int_a["hostname"], int_b["hostname"]]))
                    if link_key not in seen_links:
                        seen_links.add(link_key)
                        self.topology_links.append({
                            "source": int_a["hostname"],
                            "source_interface": int_a["interface"],
                            "source_ip": int_a["ip"],
                            "target": int_b["hostname"],
                            "target_interface": int_b["interface"],
                            "target_ip": int_b["ip"],
                            "subnet": str(int_a["network"])
                        })

    def get_topology(self):
        """
        Returns JSON-friendly node and link structure for the UI.
        """
        nodes = []
        for hostname, device in self.devices.items():
            nodes.append({
                "id": hostname,
                "label": hostname,
                "type": "router" if "router" in hostname.lower() or "r" in hostname.lower() else "switch",
                "interfaces": [
                    {"name": name, "ip": val["ip"], "active": not val["shutdown"]}
                    for name, val in device["interfaces"].items() if val["ip"]
                ]
            })
        return {
            "nodes": nodes,
            "links": self.topology_links
        }

    def evaluate_acl(self, acl_rules: list, protocol: str, dest_port: int) -> bool:
        """
        Mock evaluation of ACL rules. Returns True if PERMITTED, False if DENIED.
        """
        if not acl_rules:
            return True # Cisco default if ACL exists but is empty is deny, but we'll default to permit for empty mocks.
            
        for rule in acl_rules:
            parts = rule.split()
            if not parts:
                continue
            
            action = parts[0] # permit or deny
            
            # Simple check for port denies
            if action == "deny":
                if "eq" in parts:
                    try:
                        port_idx = parts.index("eq") + 1
                        blocked_port = int(parts[port_idx])
                        if dest_port == blocked_port:
                            return False
                    except (ValueError, IndexError):
                        pass
                # Generic deny rules
                if "any any" in rule or "ip" in parts:
                    return False
            elif action == "permit":
                if "any any" in rule or "ip" in parts:
                    return True
                    
        return True # Default permit if no rules match in our simple simulator

    def trace_path(self, source_node: str, dest_ip_str: str, protocol: str = "tcp", dest_port: int = 80):
        """
        Traces a packet path from source_node to dest_ip.
        Returns path details: hops, status (REACHED, ACL_BLOCKED, NO_ROUTE), and log.
        """
        path = []
        current_node = source_node
        visited = set()
        log = []
        
        log.append(f"Starting path trace from '{source_node}' to IP '{dest_ip_str}' (Port {dest_port}/{protocol})")
        
        try:
            dest_ip = ipaddress.IPv4Address(dest_ip_str)
        except Exception:
            return {
                "status": "ERROR",
                "hops": [],
                "log": [f"Invalid destination IP address: {dest_ip_str}"]
            }

        while current_node:
            if current_node in visited:
                log.append(f"Routing loop detected at '{current_node}'! Aborting.")
                return {
                    "status": "LOOP_DETECTED",
                    "hops": path,
                    "log": log
                }
            
            visited.add(current_node)
            path.append(current_node)
            
            device = self.devices.get(current_node)
            if not device:
                log.append(f"Device '{current_node}' not found in configuration set.")
                return {
                    "status": "NO_ROUTE",
                    "hops": path,
                    "log": log
                }
            
            # Check if destination is directly connected to this node
            directly_connected = False
            target_interface = None
            for int_name, int_data in device["interfaces"].items():
                if int_data["ip"] and int_data["subnet"] and not int_data["shutdown"]:
                    net = ipaddress.IPv4Network(f"{int_data['ip']}/{int_data['subnet']}", strict=False)
                    if dest_ip in net:
                        directly_connected = True
                        target_interface = int_name
                        break
            
            if directly_connected:
                log.append(f"Destination {dest_ip_str} is directly connected to '{current_node}' on interface {target_interface}.")
                # Check OUTBOUND ACL on the interface
                out_acl = device["interfaces"][target_interface]["acl_out"]
                if out_acl:
                    log.append(f"Evaluating outbound ACL '{out_acl}' on '{current_node}' interface {target_interface}...")
                    rules = device["acls"].get(out_acl, [])
                    if not self.evaluate_acl(rules, protocol, dest_port):
                        log.append(f"Packet DENIED by outbound ACL '{out_acl}' on '{current_node}'!")
                        return {
                            "status": "ACL_BLOCKED",
                            "hops": path,
                            "log": log
                        }
                log.append(f"Packet successfully delivered to destination {dest_ip_str}.")
                return {
                    "status": "REACHED",
                    "hops": path,
                    "log": log
                }
            
            # If not directly connected, look up next hop in routing table
            next_hop_ip = None
            
            # 1. Check static routes
            for route in device["static_routes"]:
                try:
                    net = ipaddress.IPv4Network(f"{route['prefix']}/{route['mask']}", strict=False)
                    if dest_ip in net:
                        next_hop_ip = route["next_hop"]
                        log.append(f"Matched static route to {route['prefix']}/{route['mask']} via next-hop {next_hop_ip}.")
                        break
                except Exception:
                    pass
            
            # 2. Default route fallback (0.0.0.0/0) if no specific route matched
            if not next_hop_ip:
                for route in device["static_routes"]:
                    if route["prefix"] == "0.0.0.0" and route["mask"] == "0.0.0.0":
                        next_hop_ip = route["next_hop"]
                        log.append(f"Using default route (0.0.0.0/0) via next-hop {next_hop_ip}.")
                        break
            
            if not next_hop_ip:
                log.append(f"No route to destination {dest_ip_str} found on '{current_node}'. Drop packet.")
                return {
                    "status": "NO_ROUTE",
                    "hops": path,
                    "log": log
                }
            
            # Find which device owns the next-hop IP in our topology
            next_node = None
            exit_interface = None
            for link in self.topology_links:
                if link["source"] == current_node and link["target_ip"] == next_hop_ip:
                    next_node = link["target"]
                    exit_interface = link["source_interface"]
                    break
                elif link["target"] == current_node and link["source_ip"] == next_hop_ip:
                    next_node = link["source"]
                    exit_interface = link["target_interface"]
                    break
            
            if not next_node:
                log.append(f"Next-hop IP {next_hop_ip} is unreachable from '{current_node}' (no link detected).")
                return {
                    "status": "NO_ROUTE",
                    "hops": path,
                    "log": log
                }
            
            # Check outbound ACL on exit interface
            out_acl = device["interfaces"][exit_interface]["acl_out"]
            if out_acl:
                log.append(f"Evaluating outbound ACL '{out_acl}' on '{current_node}' interface {exit_interface}...")
                rules = device["acls"].get(out_acl, [])
                if not self.evaluate_acl(rules, protocol, dest_port):
                    log.append(f"Packet DENIED by outbound ACL '{out_acl}' on '{current_node}' interface {exit_interface}!")
                    return {
                        "status": "ACL_BLOCKED",
                        "hops": path,
                        "log": log
                    }
            
            # Check inbound ACL on next-hop entrance interface
            next_device = self.devices.get(next_node)
            entrance_interface = None
            for link in self.topology_links:
                if link["source"] == next_node and link["target"] == current_node:
                    entrance_interface = link["source_interface"]
                    break
                elif link["target"] == next_node and link["source"] == current_node:
                    entrance_interface = link["target_interface"]
                    break
                    
            if entrance_interface and next_device:
                in_acl = next_device["interfaces"][entrance_interface]["acl_in"]
                if in_acl:
                    log.append(f"Evaluating inbound ACL '{in_acl}' on '{next_node}' interface {entrance_interface}...")
                    rules = next_device["acls"].get(in_acl, [])
                    if not self.evaluate_acl(rules, protocol, dest_port):
                        log.append(f"Packet DENIED by inbound ACL '{in_acl}' on entrance to '{next_node}' interface {entrance_interface}!")
                        return {
                            "status": "ACL_BLOCKED",
                            "hops": path,
                            "log": log
                        }

            log.append(f"Routing packet from '{current_node}' to '{next_node}' via exit interface {exit_interface}.")
            current_node = next_node

        return {
            "status": "NO_ROUTE",
            "hops": path,
            "log": log
        }
