import React, { useState, useEffect } from "react";
import TopologyMap from "./components/TopologyMap";
import DiffViewer from "./components/DiffViewer";
import ApprovalPanel from "./components/ApprovalPanel";

const API_BASE = "http://localhost:8000";

const USERS = [
  { name: "Sarah Jenkins", role: "Network Administrator" },
  { name: "Marcus Vance", role: "Security Auditor" },
  { name: "Andrew Nettleton", role: "Release Manager" }
];

export default function App() {
  const [configs, setConfigs] = useState({});
  const [selectedDevice, setSelectedDevice] = useState("NIA-CORE-RT01");
  const [topology, setTopology] = useState({ nodes: [], links: [] });
  const [audits, setAudits] = useState({});
  const [activeTrace, setActiveTrace] = useState(null);
  const [history, setHistory] = useState([]);
  const [ledgerIntegrity, setLedgerIntegrity] = useState(null);
  
  // Simulated User States
  const [currentUser, setCurrentUser] = useState(null);
  const [jwtToken, setJwtToken] = useState(null);
  const [loginUsername, setLoginUsername] = useState("");
  const [securitySignature, setSecuritySignature] = useState(null);
  const [managerSignature, setManagerSignature] = useState(null);
  
  // Analytics
  const [analytics, setAnalytics] = useState(null);
  
  // Webhooks & GitOps Tab States
  const [activeTab, setActiveTab] = useState("ledger");
  const [webhooks, setWebhooks] = useState([]);
  const [selectedWebhook, setSelectedWebhook] = useState(null);
  
  // Traceroute forms
  const [traceSource, setTraceSource] = useState("STC-BRCH-RT02");
  const [traceDestIp, setTraceDestIp] = useState("8.8.8.1");
  const [tracePort, setTracePort] = useState(80);
  const [traceProtocol, setTraceProtocol] = useState("tcp");

  // Load initial configurations, validation, and history on mount
  useEffect(() => {
    fetchConfigs();
    fetchValidation();
    fetchHistory();
    fetchLedgerIntegrity();
    fetchWebhooks();
    fetchAnalytics();
  }, []);

  const fetchLedgerIntegrity = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/ledger/verify`);
      const data = await res.json();
      setLedgerIntegrity(data);
    } catch (e) {
      console.error("Error fetching ledger integrity:", e);
    }
  };

  const fetchWebhooks = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/webhooks/history`);
      const data = await res.json();
      setWebhooks(data);
      if (data.length > 0) {
        setSelectedWebhook(prev => prev || data[0]);
      }
    } catch (e) {
      console.error("Error fetching webhooks:", e);
    }
  };

  const triggerWebhookSimulation = async () => {
    try {
      const payload = {
        pr_id: Math.floor(Math.random() * 900) + 100,
        title: "Deploy Security Hardening Policies",
        author: "gitops-bot",
        configs: configs
      };
      
      const res = await fetch(`${API_BASE}/api/webhook`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      
      if (res.ok) {
        const listRes = await fetch(`${API_BASE}/api/webhooks/history`);
        const listData = await listRes.json();
        setWebhooks(listData);
        setSelectedWebhook(listData[0]);
        setActiveTab("gitops");
      }
    } catch (e) {
      console.error("Error triggering webhook simulation:", e);
    }
  };

  const fetchAnalytics = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/analytics`);
      const data = await res.json();
      setAnalytics(data);
    } catch (e) {
      console.error("Error fetching analytics:", e);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`${API_BASE}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: loginUsername, password: "password" })
      });
      if (res.ok) {
        const data = await res.json();
        setJwtToken(data.token);
        setCurrentUser(data.user);
      } else {
        alert("Invalid username! Try: sjenkins, mvance, arivera");
      }
    } catch (e) {
      console.error("Login failed:", e);
    }
  };

  const handleAutoFix = async (device, ruleId, currentConfig) => {
    try {
      const res = await fetch(`${API_BASE}/api/remediate`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": `Bearer ${jwtToken}`
        },
        body: JSON.stringify({ config_text: currentConfig, rule_id: ruleId })
      });
      if (res.ok) {
        const data = await res.json();
        handleConfigChange(device, data.patched_config);
        setTimeout(() => triggerValidation(), 100);
      } else {
        const error = await res.json();
        alert(`Auto-fix failed: ${error.detail}`);
      }
    } catch (e) {
      console.error("Auto-fix failed:", e);
    }
  };

  const fetchConfigs = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/configs`);
      const data = await res.json();
      setConfigs(data);
    } catch (e) {
      console.error("Error fetching configs:", e);
    }
  };

  const fetchValidation = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/validate`);
      const data = await res.json();
      setTopology(data.topology);
      setAudits(data.audits);
    } catch (e) {
      console.error("Error fetching validation:", e);
    }
  };

  const fetchHistory = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/history`);
      const data = await res.json();
      setHistory(data);
    } catch (e) {
      console.error("Error fetching history:", e);
    }
  };

  const handleConfigChange = (device, text) => {
    setConfigs(prev => ({
      ...prev,
      [device]: text
    }));
    setSecuritySignature(null);
    setManagerSignature(null);
  };

  const triggerValidation = async () => {
    // When validating, we first push the modified configs to the server
    try {
      setSecuritySignature(null);
      setManagerSignature(null);
      // Loop through configs and upload them to synchronize server state
      for (const [device, text] of Object.entries(configs)) {
        const blob = new Blob([text], { type: "text/plain" });
        const formData = new FormData();
        formData.append("file", blob, `${device}.cfg`);
        await fetch(`${API_BASE}/api/upload`, {
          method: "POST",
          headers: { "Authorization": `Bearer ${jwtToken}` },
          body: formData
        });
      }
      
      // Trigger a re-run of checks & topology calculations
      await fetchValidation();
      // Clear trace to refresh state
      setActiveTrace(null);
    } catch (e) {
      console.error("Validation sync failed:", e);
    }
  };

  const triggerTrace = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`${API_BASE}/api/trace`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source_node: traceSource,
          dest_ip: traceDestIp,
          protocol: traceProtocol,
          dest_port: parseInt(tracePort, 10)
        })
      });
      const data = await res.json();
      setActiveTrace(data);
    } catch (e) {
      console.error("Traceroute execution failed:", e);
    }
  };

  const submitApproval = async (comment) => {
    const signatures = [];
    if (securitySignature) {
      signatures.push({ name: securitySignature, role: "Security Auditor" });
    }
    if (managerSignature) {
      signatures.push({ name: managerSignature, role: "Release Manager" });
    }

    try {
      const res = await fetch(`${API_BASE}/api/approve`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": `Bearer ${jwtToken}`
        },
        body: JSON.stringify({
          signatures,
          comment,
          configs
        })
      });
      if (res.ok) {
        fetchHistory();
        fetchLedgerIntegrity();
        setSecuritySignature(null);
        setManagerSignature(null);
        alert("Deployment co-signed and written to ledger successfully!");
      } else {
        const errorData = await res.json();
        alert(`Approval failed: ${errorData.detail || "Unknown error"}`);
      }
    } catch (e) {
      console.error("Approval submit failed:", e);
    }
  };

  const resetDemo = async () => {
    try {
      setSecuritySignature(null);
      setManagerSignature(null);
      await fetch(`${API_BASE}/api/reset`, { method: "POST" });
      fetchConfigs();
      fetchValidation();
      setActiveTrace(null);
    } catch (e) {
      console.error("Reset demo failed:", e);
    }
  };

  const deployCompliantConfigs = async () => {
    try {
      setSecuritySignature(null);
      setManagerSignature(null);
      await fetch(`${API_BASE}/api/deploy_compliant`, { 
        method: "POST",
        headers: { "Authorization": `Bearer ${jwtToken}` }
      });
      fetchConfigs();
      fetchValidation();
      setActiveTrace(null);
    } catch (e) {
      console.error("Deploy compliant configs failed:", e);
    }
  };

  // Helper to get audit metrics
  const getDeviceFailureCount = (device) => {
    const deviceAudits = audits[device];
    if (!deviceAudits) return 0;
    return deviceAudits.filter(check => check.status === "FAILED").length;
  };

  const activeDeviceAudits = audits[selectedDevice] || [];
  const totalRules = activeDeviceAudits.length;
  const passedRules = activeDeviceAudits.filter(r => r.status === "PASSED").length;
  const scorePercent = totalRules > 0 ? Math.round((passedRules / totalRules) * 100) : 100;

  return (
    <div className="app-container">
      {!jwtToken && (
        <div className="login-overlay" style={{position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.8)", zIndex: 9999, display: "flex", alignItems: "center", justifyContent: "center", backdropFilter: "blur(5px)"}}>
          <div className="login-modal" style={{background: "var(--panel-bg)", border: "1px solid var(--border-color)", padding: "30px", borderRadius: "12px", width: "300px", boxShadow: "0 10px 30px rgba(0,0,0,0.5)"}}>
            <h2 style={{margin: "0 0 5px 0", color: "var(--text-main)"}}>NetGate Identity</h2>
            <p style={{color: "var(--text-dim)", marginBottom: "20px", fontSize: "12px"}}>Zero-Trust authentication required.</p>
            <form onSubmit={handleLogin} style={{display: "flex", flexDirection: "column", gap: "10px"}}>
              <input 
                type="text" 
                placeholder="Username (e.g. sjenkins)" 
                className="form-input"
                value={loginUsername}
                onChange={e => setLoginUsername(e.target.value)}
                autoFocus
              />
              <button type="submit" className="btn-primary" style={{width: "100%", marginTop: "10px", background: "var(--primary)"}}>Authenticate</button>
            </form>
          </div>
        </div>
      )}
      {/* Header */}
      <header className="app-header">
        <div className="header-logo">
          <div className="logo-dot"></div>
          <span>NetGate</span>
        </div>
        <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
          {/* Authenticated User Profile */}
          <div className="user-selector-container" style={{background: "rgba(0,0,0,0.2)", padding: "4px 12px", borderRadius: "12px"}}>
            <span className="user-selector-label" style={{marginRight: "6px"}}>Identified:</span>
            <span style={{color: "var(--primary)", fontWeight: "bold", fontSize: "11px"}}>
              {currentUser ? `${currentUser.name} (${currentUser.role})` : "Unauthenticated"}
            </span>
          </div>

          <button 
            onClick={deployCompliantConfigs} 
            className="badge" 
            style={{ 
              background: "var(--success-glow)", 
              border: "1px solid var(--success-border)", 
              color: "var(--success)",
              cursor: "pointer",
              padding: "4px 12px",
              fontWeight: "600"
            }}
          >
            Deploy Compliant Configs
          </button>
          <button 
            onClick={resetDemo} 
            className="badge" 
            style={{ 
              background: "rgba(255,255,255,0.05)", 
              border: "1px solid var(--border-color)", 
              color: "var(--text-muted)",
              cursor: "pointer",
              padding: "4px 12px"
            }}
          >
            Reset Environment
          </button>
          <div className="header-status">
            <span className="status-indicator"></span>
            <span>Simulation Sandbox Online</span>
          </div>
        </div>
      </header>

      {/* Main Content Grid */}
      <main className="dashboard-grid">
        
        {/* Sidebar (Device Inventory) */}
        <section className="sidebar">
          <div>
            <h3 className="sidebar-title">Device Configurations</h3>
            <div className="device-list">
              {Object.keys(configs).map(name => {
                const failures = getDeviceFailureCount(name);
                return (
                  <div 
                    key={name} 
                    className={`device-item ${selectedDevice === name ? "active" : ""}`}
                    onClick={() => {
                      setSelectedDevice(name);
                      setActiveTrace(null);
                    }}
                  >
                    <span className="device-name">{name}</span>
                    {failures > 0 ? (
                      <span className="badge badge-danger">{failures} Alert{failures > 1 ? "s" : ""}</span>
                    ) : (
                      <span className="badge badge-success">Passed</span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          <div style={{ marginTop: "auto", borderTop: "1px solid var(--border-color)", paddingTop: "20px" }}>
            <button 
              onClick={triggerValidation} 
              className="btn-primary"
              style={{ background: "var(--success)" }}
            >
              Run Compliance Scan
            </button>
          </div>
        </section>

        {/* Workspace Area */}
        <section className="workspace-area">
          
          {/* Top Panel (Visual Topology + Compliance Checklist) */}
          <div className="workspace-top">
            
            {/* Topology Map Canvas */}
            <div style={{ position: "relative", height: "100%", borderRight: "1px solid var(--border-color)", overflow: "hidden" }}>
              <TopologyMap 
                topology={topology}
                audits={audits}
                activeTrace={activeTrace}
                selectedNode={selectedDevice}
                onSelectNode={(nodeId) => {
                  if (configs[nodeId]) {
                    setSelectedDevice(nodeId);
                    setActiveTrace(null);
                  }
                }}
              />
              
              {/* Traceroute Control Panel overlay (Horizontal Toolbar) */}
              <div className="trace-overlay">
                <form onSubmit={triggerTrace} className="trace-form">
                  <div className="trace-form-group">
                    <label>Source</label>
                    <select 
                      className="form-input"
                      value={traceSource}
                      onChange={(e) => setTraceSource(e.target.value)}
                    >
                      {Object.keys(configs).map(name => (
                        <option key={name} value={name}>{name}</option>
                      ))}
                    </select>
                  </div>
                  <div className="trace-form-group">
                    <label>Dest IP</label>
                    <input 
                      type="text" 
                      className="form-input"
                      style={{ width: "120px" }}
                      value={traceDestIp}
                      onChange={(e) => setTraceDestIp(e.target.value)}
                    />
                  </div>
                  <div className="trace-form-group">
                    <label>Port</label>
                    <input 
                      type="number" 
                      className="form-input"
                      style={{ width: "70px" }}
                      value={tracePort}
                      onChange={(e) => setTracePort(e.target.value)}
                    />
                  </div>
                  <button type="submit" className="trace-btn">
                    Trace Path
                  </button>
                </form>
              </div>

              {/* Path Trace Logs - Floating Bottom Left */}
              {activeTrace && (
                <div className="traceroute-log-panel trace-logs-floating">
                  <div className={`traceroute-log-line header ${activeTrace.status === "REACHED" ? "success" : "error"}`}>
                    Traceroute Status: {activeTrace.status}
                  </div>
                  {activeTrace.log.map((line, idx) => (
                    <div 
                      key={idx} 
                      className={`traceroute-log-line ${
                        line.includes("DENIED") || line.includes("loop") || line.includes("unreachable") ? "error" :
                        line.includes("successfully") || line.includes("directly connected") ? "success" : ""
                      }`}
                    >
                      {line}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Compliance Checklist Audit Card */}
            <div className="audit-panel">
              <div className="panel-header">
                <h3 className="panel-title">Compliance Scan</h3>
                <div style={{ display: "flex", gap: "8px", alignItems: "center", marginTop: "4px" }}>
                  <span className="badge badge-warning" style={{ fontSize: "11px" }}>
                    {selectedDevice}
                  </span>
                  <span className={`badge ${scorePercent === 100 ? "badge-success" : "badge-danger"}`} style={{ fontSize: "11px" }}>
                    Score: {scorePercent}%
                  </span>
                </div>
                <div style={{ width: "100%", height: "4px", background: "rgba(255,255,255,0.05)", borderRadius: "2px", marginTop: "12px", overflow: "hidden" }}>
                  <div style={{ width: `${scorePercent}%`, height: "100%", background: scorePercent === 100 ? "var(--success)" : scorePercent >= 60 ? "var(--warning)" : "var(--danger)", transition: "width 0.4s ease" }}></div>
                </div>
              </div>
              <div className="panel-content">
                {audits[selectedDevice] && audits[selectedDevice].length > 0 ? (
                  audits[selectedDevice].map((check, idx) => (
                    <div 
                      key={idx} 
                      className={`audit-card ${check.status === "PASSED" ? "passed" : "failed"}`}
                    >
                      <div className="audit-card-head">
                        <span className="audit-card-title">{check.title}</span>
                        <div style={{display: "flex", gap: "8px", alignItems: "center"}}>
                          {check.status === "FAILED" && (
                            <button 
                              className="trace-btn" 
                              style={{padding: "2px 6px", fontSize: "10px", background: "var(--primary)", border: "none", color: "white", cursor: "pointer", borderRadius: "4px"}}
                              onClick={() => handleAutoFix(selectedDevice, check.id, configs[selectedDevice])}
                            >
                              ✨ Auto-Fix
                            </button>
                          )}
                          <span className={`badge ${check.status === "PASSED" ? "badge-success" : "badge-danger"}`}>
                            {check.status}
                          </span>
                        </div>
                      </div>
                      <p className="audit-card-desc">{check.description}</p>
                      {check.status === "FAILED" && (
                        <div className="audit-card-details">
                          {check.details}
                        </div>
                      )}
                    </div>
                  ))
                ) : (
                  <div style={{ color: "var(--text-dim)", textAlign: "center", padding: "40px 0" }}>
                    Select a device configuration to run a compliance scan.
                  </div>
                )}
              </div>
            </div>

          </div>

          {/* Bottom Panel (Config Editor & Human Sign-off Dashboard) */}
          <div className="workspace-bottom">
            <DiffViewer 
              deviceName={selectedDevice}
              configText={configs[selectedDevice]}
              onConfigChange={handleConfigChange}
              onValidate={triggerValidation}
              currentUser={currentUser}
            />
            
            {/* Right side tabbed governance panel */}
            <div className="governance-tab-panel">
              <div className="tab-header">
                <button 
                  className={`tab-btn ${activeTab === "ledger" ? "active" : ""}`}
                  onClick={() => setActiveTab("ledger")}
                >
                  📜 Governance Ledger
                </button>
                <button 
                  className={`tab-btn ${activeTab === "gitops" ? "active" : ""}`}
                  onClick={() => {
                    setActiveTab("gitops");
                    fetchWebhooks();
                  }}
                >
                  🔀 GitOps Webhooks
                </button>
                <button 
                  className={`tab-btn ${activeTab === "analytics" ? "active" : ""}`}
                  onClick={() => {
                    setActiveTab("analytics");
                    fetchAnalytics();
                  }}
                >
                  📊 Analytics
                </button>
                <a 
                  href={`${API_BASE}/api/export/soc2`} 
                  target="_blank" 
                  rel="noreferrer"
                  className="trace-btn"
                  style={{ marginLeft: "auto", fontSize: "10px", textDecoration: "none", background: "var(--primary)" }}
                  title="Export verifiable SOC2 Type II Audit Log"
                >
                  Export SOC2 Report
                </a>
              </div>

              <div className="tab-content-container">
                {activeTab === "analytics" ? (
                  <div className="gitops-panel" style={{padding: "20px", display: "flex", flexDirection: "column", gap: "20px", overflowY: "auto"}}>
                    <h3 style={{margin: 0, color: "var(--text-main)"}}>Enterprise Telemetry</h3>
                    {analytics ? (
                      <>
                        <div style={{display: "flex", gap: "20px"}}>
                          <div className="audit-card" style={{flex: 1, textAlign: "center"}}>
                            <div style={{fontSize: "24px", color: "var(--primary)", fontWeight: "bold"}}>{analytics.current_compliance_score}%</div>
                            <div style={{fontSize: "10px", color: "var(--text-dim)", textTransform: "uppercase"}}>Fleet Compliance</div>
                          </div>
                          <div className="audit-card" style={{flex: 1, textAlign: "center"}}>
                            <div style={{fontSize: "24px", color: "var(--success)", fontWeight: "bold"}}>{analytics.total_deployments}</div>
                            <div style={{fontSize: "10px", color: "var(--text-dim)", textTransform: "uppercase"}}>Total Deployments</div>
                          </div>
                        </div>
                        <div>
                          <div style={{fontSize: "12px", color: "var(--text-dim)", marginBottom: "8px"}}>Signatures by Role</div>
                          {Object.entries(analytics.signature_distribution || {}).map(([role, count]) => (
                            <div key={role} style={{display: "flex", justifyContent: "space-between", marginBottom: "4px", background: "rgba(0,0,0,0.2)", padding: "4px 8px", borderRadius: "4px"}}>
                              <span style={{fontSize: "11px", color: "var(--text-main)"}}>{role}</span>
                              <span style={{fontSize: "11px", color: "var(--primary)", fontWeight: "bold"}}>{count}</span>
                            </div>
                          ))}
                        </div>
                      </>
                    ) : (
                      <div style={{color: "var(--text-dim)", fontSize: "11px"}}>Loading telemetry...</div>
                    )}
                  </div>
                ) : activeTab === "ledger" ? (
                  <ApprovalPanel 
                    onSubmitApproval={submitApproval}
                    history={history}
                    currentUser={currentUser}
                    securitySignature={securitySignature}
                    setSecuritySignature={setSecuritySignature}
                    managerSignature={managerSignature}
                    setManagerSignature={setManagerSignature}
                    ledgerIntegrity={ledgerIntegrity}
                  />
                ) : (
                  <div className="gitops-panel">
                    <div className="gitops-sidebar">
                      <div className="gitops-sidebar-header">
                        <span style={{ fontSize: "10px", fontWeight: "bold", textTransform: "uppercase", color: "var(--text-dim)", letterSpacing: "0.5px" }}>Webhook Events</span>
                        <button 
                          onClick={triggerWebhookSimulation}
                          className="trace-btn"
                          style={{ fontSize: "9px", padding: "2px 8px", height: "20px", background: "var(--success)" }}
                        >
                          Simulate PR
                        </button>
                      </div>
                      <div className="gitops-event-list">
                        {webhooks.length > 0 ? (
                          webhooks.map((wh) => (
                            <div 
                              key={wh.pr_id} 
                              className={`gitops-event-item ${selectedWebhook && selectedWebhook.pr_id === wh.pr_id ? "active" : ""}`}
                              onClick={() => setSelectedWebhook(wh)}
                            >
                              <div style={{ fontWeight: "600", fontSize: "11px" }}>PR #{wh.pr_id}</div>
                              <div style={{ fontSize: "9px", color: "var(--text-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{wh.title}</div>
                              <div style={{ fontSize: "8px", color: "var(--text-dim)" }}>by @{wh.author}</div>
                            </div>
                          ))
                        ) : (
                          <div style={{ fontSize: "11px", color: "var(--text-dim)", padding: "16px", textAlign: "center" }}>No webhooks received.</div>
                        )}
                      </div>
                    </div>
                    <div className="gitops-body">
                      {selectedWebhook ? (
                        <div className="pr-comment-box">
                          <div className="pr-comment-header">
                            <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                              <span style={{ fontWeight: "bold", color: "var(--primary)" }}>@{selectedWebhook.author}</span>
                              <span style={{ color: "var(--text-dim)" }}>commented on PR #{selectedWebhook.pr_id}</span>
                            </div>
                            <span style={{ fontSize: "9px", color: "var(--text-dim)" }}>
                              {new Date(selectedWebhook.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                          <div className="pr-comment-body">
                            <pre style={{ margin: 0, fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--text-main)", overflowX: "auto" }}>
                              {selectedWebhook.comment_markdown}
                            </pre>
                          </div>
                        </div>
                      ) : (
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-dim)", fontSize: "11px" }}>
                          Select an event or click "Simulate PR" to run a scan.
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>

        </section>

      </main>
    </div>
  );
}
