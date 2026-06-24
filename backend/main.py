import os
import json
from typing import List, Dict
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import base64

from auditor import ConfigAuditor
from simulator import NetworkSimulator
from batfish_client import BatfishClientWrapper

app = FastAPI(title="NetGate API", version="1.0.0")
bf_client = BatfishClientWrapper()

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For dev environments, we allow all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for uploaded configurations during session
CURRENT_CONFIGS: Dict[str, str] = {}
AUDIT_LOG_FILE = "approval_audit_trail.json"

# In-memory storage for webhook events
WEBHOOK_EVENTS: List[Dict] = []

# Pre-load mock configuration sets for immediate dashboard presentation
DEFAULT_CONFIGS = {
    "NIA-CORE-RT01": """hostname NIA-CORE-RT01
no service password-encryption
enable password cisco123
!
interface GigabitEthernet0/1
 ip address 10.1.1.1 255.255.255.0
 description Link-to-STC-BRCH-RT02
 no shutdown
!
interface GigabitEthernet0/2
 ip address 172.16.1.1 255.255.255.0
 description Link-to-NIA-GWY-RT03
 no shutdown
!
interface GigabitEthernet0/3
 ip address 192.168.10.1 255.255.255.0
 no shutdown
!
ip route 192.168.20.0 255.255.255.0 10.1.1.2
ip route 0.0.0.0 0.0.0.0 172.16.1.2
!
line vty 0 4
 transport input telnet ssh
!""",
    "STC-BRCH-RT02": """hostname STC-BRCH-RT02
service password-encryption
enable secret 9$aBc12D34E5fG
!
interface GigabitEthernet0/1
 ip address 10.1.1.2 255.255.255.0
 description Link-to-NIA-CORE-RT01
 no shutdown
!
interface GigabitEthernet0/2
 ip address 192.168.20.1 255.255.255.0
 description Local-Branch-Office
 no shutdown
  ip access-group SECURE_ACL in
!
ip route 0.0.0.0 0.0.0.0 10.1.1.1
!
ip access-list extended SECURE_ACL
 deny tcp any any eq 22
 deny tcp any any eq 23
 permit ip any any
!
line vty 0 4
 transport input ssh
!""",
    "NIA-GWY-RT03": """hostname NIA-GWY-RT03
service password-encryption
enable secret 9$xyz987654321
!
interface GigabitEthernet0/1
 ip address 172.16.1.2 255.255.255.0
 description Link-to-NIA-CORE-RT01
 no shutdown
!
interface GigabitEthernet0/2
 ip address 8.8.8.1 255.255.255.0
 description WAN-Gateway
 no shutdown
!
ip route 10.0.0.0 255.0.0.0 172.16.1.1
ip route 192.168.0.0 255.255.0.0 172.16.1.1
!
snmp-server community public RO
!
line vty 0 4
 transport input ssh
!"""
}

COMPLIANT_CONFIGS = {
    "NIA-CORE-RT01": """hostname NIA-CORE-RT01
service password-encryption
enable secret 9$aBc12D34E5fG
!
interface GigabitEthernet0/1
 ip address 10.1.1.1 255.255.255.0
 description Link-to-STC-BRCH-RT02
 no shutdown
!
interface GigabitEthernet0/2
 ip address 172.16.1.1 255.255.255.0
 description Link-to-NIA-GWY-RT03
 no shutdown
!
interface GigabitEthernet0/3
 ip address 192.168.10.1 255.255.255.0
 description Local-Niagara-LAN
 no shutdown
!
ip route 192.168.20.0 255.255.255.0 10.1.1.2
ip route 0.0.0.0 0.0.0.0 172.16.1.2
!
line vty 0 4
 transport input ssh
!""",
    "STC-BRCH-RT02": """hostname STC-BRCH-RT02
service password-encryption
enable secret 9$aBc12D34E5fG
!
interface GigabitEthernet0/1
 ip address 10.1.1.2 255.255.255.0
 description Link-to-NIA-CORE-RT01
 no shutdown
!
interface GigabitEthernet0/2
 ip address 192.168.20.1 255.255.255.0
 description Local-Branch-Office
 no shutdown
  ip access-group SECURE_ACL in
!
ip route 0.0.0.0 0.0.0.0 10.1.1.1
!
ip access-list extended SECURE_ACL
 deny tcp any any eq 22
 deny tcp any any eq 23
 permit ip any any
!
line vty 0 4
 transport input ssh
!""",
    "NIA-GWY-RT03": """hostname NIA-GWY-RT03
service password-encryption
enable secret 9$xyz987654321
!
interface GigabitEthernet0/1
 ip address 172.16.1.2 255.255.255.0
 description Link-to-NIA-CORE-RT01
 no shutdown
!
interface GigabitEthernet0/2
 ip address 8.8.8.1 255.255.255.0
 description WAN-Gateway
 no shutdown
!
ip route 10.0.0.0 255.0.0.0 172.16.1.1
ip route 192.168.0.0 255.255.0.0 172.16.1.1
!
snmp-server community secure_read_only RO
!
line vty 0 4
 transport input ssh
!"""
}

# Seed the configs
CURRENT_CONFIGS.update(DEFAULT_CONFIGS)

class TraceRequest(BaseModel):
    source_node: str
    dest_ip: str
    protocol: str = "tcp"
    dest_port: int = 80

class SignerSignature(BaseModel):
    name: str
    role: str

class ApproveRequest(BaseModel):
    signatures: List[SignerSignature]
    comment: str
    configs: Dict[str, str]

class WebhookSimulateRequest(BaseModel):
    pr_id: int
    title: str
    author: str
    configs: Dict[str, str]

class LoginRequest(BaseModel):
    username: str
    password: str

class RemediateRequest(BaseModel):
    config_text: str
    rule_id: str

USERS = {
    "sjenkins": {"name": "Sarah Jenkins", "role": "Network Administrator"},
    "mvance": {"name": "Marcus Vance", "role": "Security Auditor"},
    "arivera": {"name": "Alex Rivera", "role": "Release Manager"}
}

def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(" ")[1]
    try:
        payload_b64 = token.split(".")[1]
        payload_json = base64.b64decode(payload_b64).decode("utf-8")
        user = json.loads(payload_json)
        return user
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def load_audit_trail() -> List[Dict]:
    if os.path.exists(AUDIT_LOG_FILE):
        try:
            with open(AUDIT_LOG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_audit_trail(trail: List[Dict]):
    with open(AUDIT_LOG_FILE, "w") as f:
        json.dump(trail, f, indent=4)

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "NetGate Core API",
        "version": "1.0.0",
        "active_devices": list(CURRENT_CONFIGS.keys())
    }

@app.get("/api/configs")
def get_configs():
    """Retrieve all active device configs."""
    return CURRENT_CONFIGS

@app.post("/api/upload")
async def upload_config(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    if user.get("role") != "Network Administrator":
        raise HTTPException(status_code=403, detail="Only Network Administrators can upload configurations.")
    """Upload a new configuration file to the active buffer."""
    content = await file.read()
    config_text = content.decode("utf-8")
    
    # Parse out hostname or default to filename
    hostname = file.filename
    for line in config_text.splitlines():
        if line.strip().startswith("hostname"):
            parts = line.strip().split()
            if len(parts) > 1:
                hostname = parts[1]
                break
                
    CURRENT_CONFIGS[hostname] = config_text
    return {"status": "success", "device": hostname, "size": len(config_text)}

@app.post("/api/reset")
def reset_configs():
    """Reset the running buffer back to the default demo configs."""
    CURRENT_CONFIGS.clear()
    CURRENT_CONFIGS.update(DEFAULT_CONFIGS)
    return {"status": "success", "message": "Reset to default network state."}

@app.post("/api/deploy_compliant")
def deploy_compliant(user: dict = Depends(get_current_user)):
    if user.get("role") != "Network Administrator":
        raise HTTPException(status_code=403, detail="Only Network Administrators can deploy templates.")
    """Deploy fully compliant and hardened configs to the running buffer."""
    CURRENT_CONFIGS.clear()
    CURRENT_CONFIGS.update(COMPLIANT_CONFIGS)
    return {"status": "success", "message": "Deployed secure compliant network state."}

@app.get("/api/validate")
def validate_network():
    """Runs compliance checks and extracts topology links on active configs."""
    if not CURRENT_CONFIGS:
        return {"audits": {}, "topology": {"nodes": [], "links": []}}

    # 1. Try executing via Batfish client if online
    if bf_client.is_online():
        try:
            print("[API] Batfish service detected. Running formal validation...")
            audits = bf_client.run_compliance_scan(CURRENT_CONFIGS)
            links = bf_client.get_topology_edges(CURRENT_CONFIGS)
            
            # Map topology nodes
            nodes = []
            for hostname, config in CURRENT_CONFIGS.items():
                lines = config.splitlines()
                interfaces = []
                for line in lines:
                    cleaned = line.strip()
                    if cleaned.startswith("hostname"):
                        parts = cleaned.split()
                        if len(parts) > 1:
                            hostname = parts[1]
                    elif cleaned.startswith("interface"):
                        int_name = cleaned.replace("interface ", "")
                        interfaces.append({"name": int_name, "ip": None, "active": True})
                    elif cleaned.startswith("ip address") and interfaces:
                        parts = cleaned.split()
                        if len(parts) >= 4:
                            interfaces[-1]["ip"] = parts[2]
                    elif cleaned == "shutdown" and interfaces:
                        interfaces[-1]["active"] = False
                
                # Filter out interfaces without IP address for display
                interfaces = [i for i in interfaces if i["ip"]]
                
                nodes.append({
                    "id": hostname,
                    "label": hostname,
                    "type": "router" if "router" in hostname.lower() or "r" in hostname.lower() else "switch",
                    "interfaces": interfaces
                })
                
            return {
                "audits": audits,
                "topology": {
                    "nodes": nodes,
                    "links": links
                }
            }
        except Exception as e:
            print(f"[API Warning] Batfish scan failed: {e}. Falling back to mock engine.")

    # 2. Fallback to local config auditor and simulator
    print("[API] Batfish offline. Using local mock engine fallback...")
    audits = {}
    for name, config in CURRENT_CONFIGS.items():
        auditor = ConfigAuditor(config)
        audits[name] = auditor.run_all_checks()

    simulator = NetworkSimulator(CURRENT_CONFIGS)
    topology = simulator.get_topology()

    return {
        "audits": audits,
        "topology": topology
    }

@app.post("/api/trace")
def trace_packet(req: TraceRequest):
    """Executes an offline traceroute through the simulated network topology."""
    if not CURRENT_CONFIGS:
        raise HTTPException(status_code=400, detail="No configurations loaded in sandbox.")

    # 1. Try executing via Batfish client if online
    if bf_client.is_online():
        try:
            print("[API] Running traceroute via Batfish...")
            trace_result = bf_client.trace_path(
                configs=CURRENT_CONFIGS,
                source_node=req.source_node,
                dest_ip=req.dest_ip,
                protocol=req.protocol,
                dest_port=req.dest_port
            )
            return trace_result
        except Exception as e:
            print(f"[API Warning] Batfish traceroute failed: {e}. Falling back to mock simulator.")

    # 2. Fallback
    print("[API] Running traceroute via local mock simulator...")
    simulator = NetworkSimulator(CURRENT_CONFIGS)
    trace_result = simulator.trace_path(
        source_node=req.source_node,
        dest_ip_str=req.dest_ip,
        protocol=req.protocol,
        dest_port=req.dest_port
    )
    return trace_result

@app.post("/api/approve")
def approve_configs(req: ApproveRequest, user: dict = Depends(get_current_user)):
    """Logs human approval signatures, comments, and approved configs to the audit log."""
    from datetime import datetime
    import hashlib
    
    # Validate signatures
    has_auditor = False
    has_manager = False
    signer_names = []
    
    for sig in req.signatures:
        if sig.role == "Security Auditor":
            has_auditor = True
        elif sig.role == "Release Manager":
            has_manager = True
        signer_names.append(f"{sig.name} ({sig.role})")
        
    if not has_auditor or not has_manager:
        raise HTTPException(
            status_code=400, 
            detail="Incomplete multi-signature authorization. Signatures from both 'Security Auditor' and 'Release Manager' are required."
        )
        
    trail = load_audit_trail()
    
    previous_hash = trail[0].get("hash") if trail else None
    
    new_entry = {
        "timestamp": datetime.now().isoformat(),
        "approver": ", ".join(signer_names),
        "comment": req.comment,
        "devices": list(req.configs.keys()),
        # Save a snapshot of what was approved for compliance auditing
        "config_snapshot": req.configs,
        "signatures": [{"name": s.name, "role": s.role} for s in req.signatures],
        "previous_hash": previous_hash
    }
    
    # Compute SHA-256 hash of the new entry (excluding the hash field itself)
    entry_str = json.dumps(new_entry, sort_keys=True)
    new_hash = hashlib.sha256(entry_str.encode('utf-8')).hexdigest()
    new_entry["hash"] = new_hash
    
    trail.insert(0, new_entry) # Add to start of list
    save_audit_trail(trail)
    
    return {"status": "success", "message": "Co-signed approval recorded in verification ledger.", "timestamp": new_entry["timestamp"]}

@app.get("/api/history")
def get_audit_history():
    """Returns the historical ledger of configuration approvals."""
    return load_audit_trail()

@app.get("/api/ledger/verify")
def verify_ledger():
    """Mathematically validates the cryptographic hash chain of the ledger."""
    import hashlib
    trail = load_audit_trail()
    if not trail:
        return {"status": "success", "is_valid": True, "message": "Ledger is empty."}
        
    # Trail is stored with newest at index 0. Reverse it to verify chronologically.
    chronological_trail = list(reversed(trail))
    
    expected_previous_hash = None
    for idx, entry in enumerate(chronological_trail):
        # Check previous_hash link
        if entry.get("previous_hash") != expected_previous_hash:
            return {"status": "error", "is_valid": False, "message": f"Broken chain link at entry {idx}."}
            
        # Re-compute hash
        entry_copy = dict(entry)
        stored_hash = entry_copy.pop("hash", None)
        
        # Backward compatibility for old unhashed entries
        if not stored_hash and expected_previous_hash is None:
            # Skip verification for old genesis entries if they lack hashes completely
            continue
            
        if not stored_hash:
            return {"status": "error", "is_valid": False, "message": f"Missing hash at entry {idx}."}
            
        entry_str = json.dumps(entry_copy, sort_keys=True)
        computed_hash = hashlib.sha256(entry_str.encode('utf-8')).hexdigest()
        
        if computed_hash != stored_hash:
            return {"status": "error", "is_valid": False, "message": f"Tampering detected at entry {idx}. Hash mismatch."}
            
        expected_previous_hash = stored_hash
        
    return {"status": "success", "is_valid": True, "message": "Cryptographic ledger integrity verified."}

from fastapi.responses import HTMLResponse

@app.get("/api/export/soc2", response_class=HTMLResponse)
def export_soc2_report():
    """Generates an HTML SOC2-style compliance report from the immutable ledger."""
    from datetime import datetime
    trail = load_audit_trail()
    
    html = f"""
    <html>
    <head>
        <title>SOC2 Type II Compliance Report - NetGate</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 40px auto; max-width: 800px; }}
            h1, h2 {{ color: #0056b3; }}
            .ledger-entry {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; border-radius: 5px; background: #f9f9f9; }}
            .hash {{ font-family: monospace; color: #d9534f; word-break: break-all; }}
            .seal {{ display: inline-block; padding: 5px 10px; background: #5cb85c; color: white; border-radius: 3px; font-weight: bold; }}
            .warning {{ display: inline-block; padding: 5px 10px; background: #d9534f; color: white; border-radius: 3px; font-weight: bold; }}
        </style>
    </head>
    <body>
        <h1>NetGate Immutable Audit Ledger</h1>
        <p><strong>Report generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    """
    
    verify_result = verify_ledger()
    if verify_result["is_valid"]:
        html += '<p><span class="seal">✓ Cryptographically Verified</span></p>'
    else:
        html += f'<p><span class="warning">❌ Integrity Alert: {verify_result["message"]}</span></p>'
        
    html += "<h2>Authorized Sign-Off History</h2>"
    
    for entry in trail:
        prev_hash = entry.get('previous_hash')
        html += f"""
        <div class="ledger-entry">
            <p><strong>Timestamp:</strong> {entry.get('timestamp', 'N/A')}</p>
            <p><strong>Approvers:</strong> {entry.get('approver', 'N/A')}</p>
            <p><strong>Comment:</strong> {entry.get('comment', 'N/A')}</p>
            <p><strong>Hash:</strong> <span class="hash">{entry.get('hash', 'N/A')}</span></p>
            <p><strong>Previous Hash:</strong> <span class="hash">{prev_hash if prev_hash else 'GENESIS'}</span></p>
        </div>
        """
        
    html += "</body></html>"
    return html

@app.post("/api/auth/login")
def login(req: LoginRequest):
    if req.username not in USERS:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user_data = USERS[req.username]
    payload = json.dumps(user_data).encode("utf-8")
    mock_token = "mock_jwt_header." + base64.b64encode(payload).decode("utf-8") + ".mock_signature"
    return {"token": mock_token, "user": user_data}

@app.post("/api/remediate")
def remediate_config(req: RemediateRequest, user: dict = Depends(get_current_user)):
    if user.get("role") != "Network Administrator":
        raise HTTPException(status_code=403, detail="Only Network Administrators can apply auto-remediations.")
    patched_config = ConfigAuditor.generate_remediation(req.config_text, req.rule_id)
    return {"status": "success", "patched_config": patched_config}

@app.get("/api/analytics")
def get_analytics():
    trail = load_audit_trail()
    total_deployments = len(trail)
    role_distribution = {}
    device_activity = {}
    for entry in trail:
        for sig in entry.get("signatures", []):
            role = sig.get("role")
            role_distribution[role] = role_distribution.get(role, 0) + 1
        for dev in entry.get("devices", []):
            device_activity[dev] = device_activity.get(dev, 0) + 1
            
    total_checks = 0
    passed_checks = 0
    for name, config in CURRENT_CONFIGS.items():
        results = ConfigAuditor(config).run_all_checks()
        total_checks += len(results)
        passed_checks += len([r for r in results if r["status"] == "PASSED"])
        
    current_compliance_score = int((passed_checks / total_checks) * 100) if total_checks > 0 else 100
    
    return {
        "total_deployments": total_deployments,
        "signature_distribution": role_distribution,
        "device_activity": device_activity,
        "current_compliance_score": current_compliance_score
    }

def format_pr_comment(pr_id: int, title: str, author: str, audits: dict, trace: dict) -> str:
    comment = f"### 🛡️ NetGate Compliance & Verification Report\n\n"
    comment += f"**Pull Request #{pr_id}:** *{title}* by `@{author}`\n\n"
    
    total_checks = 0
    failed_checks = 0
    
    for device, checks in audits.items():
        total_checks += len(checks)
        failed_checks += len([c for c in checks if c["status"] == "FAILED"])
        
    score_percent = int(((total_checks - failed_checks) / total_checks) * 100) if total_checks > 0 else 100
    
    if failed_checks > 0:
        comment += f"**Status:** ❌ **FAILED** (Compliance Score: **{score_percent}%** | **{failed_checks} Alerts**)\n\n"
    else:
        comment += f"**Status:** ✅ **PASSED** (Compliance Score: **100%** | **0 Alerts**)\n\n"
        
    comment += "#### 📋 Compliance Scorecard\n\n"
    comment += "| Device | Rule ID | Title | Status | Severity | Details |\n"
    comment += "| :--- | :--- | :--- | :---: | :---: | :--- |\n"
    
    for device, checks in audits.items():
        for check in checks:
            status_icon = "✅" if check["status"] == "PASSED" else "❌"
            comment += f"| **{device}** | `{check['id']}` | {check['title']} | {status_icon} **{check['status']}** | `{check['severity']}` | {check.get('details', '-')} |\n"
            
    comment += "\n#### 🛜 Routing Trace Simulation\n"
    path_str = " ➔ ".join(trace.get("hops", [])) if trace.get("hops") else "None"
    trace_status = trace.get("status", "NO_ROUTE")
    trace_icon = "✅" if trace_status == "REACHED" else "❌"
    
    comment += f"- **Path Trace:** `{path_str}`\n"
    comment += f"- **Result:** {trace_icon} **{trace_status}**\n"
    
    comment += "\n*Report generated automatically by NetGate GitOps Integration.*"
    return comment

@app.post("/api/webhook")
def receive_webhook(req: WebhookSimulateRequest):
    """Receives repository PR event and creates compliance review comment."""
    from datetime import datetime
    
    # 1. Run validation
    audits = {}
    if bf_client.is_online():
        try:
            audits = bf_client.run_compliance_scan(req.configs)
        except Exception:
            pass
            
    if not audits:
        for name, config in req.configs.items():
            audits[name] = ConfigAuditor(config).run_all_checks()
            
    # 2. Run a reachability trace simulation (from STC-BRCH-RT02 to 8.8.8.1)
    trace = None
    if bf_client.is_online():
        try:
            trace = bf_client.trace_path(req.configs, "STC-BRCH-RT02", "8.8.8.1", "tcp", 80)
        except Exception:
            pass
            
    if not trace:
        trace = NetworkSimulator(req.configs).trace_path("STC-BRCH-RT02", "8.8.8.1", "tcp", 80)
        
    # 3. Generate markdown Pull Request comment
    comment_md = format_pr_comment(req.pr_id, req.title, req.author, audits, trace)
    
    # 4. Save to webhook history log
    new_event = {
        "timestamp": datetime.now().isoformat(),
        "pr_id": req.pr_id,
        "title": req.title,
        "author": req.author,
        "comment_markdown": comment_md,
        "devices": list(req.configs.keys())
    }
    WEBHOOK_EVENTS.insert(0, new_event)
    
    return {"status": "success", "message": "PR webhook received and compliance report generated.", "comment": comment_md}

@app.get("/api/webhooks/history")
def get_webhook_history():
    """Returns the historical list of simulated webhook events."""
    return WEBHOOK_EVENTS
