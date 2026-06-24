import React, { useState } from "react";

export default function ApprovalPanel({ 
  onSubmitApproval, 
  history, 
  currentUser,
  securitySignature,
  setSecuritySignature,
  managerSignature,
  setManagerSignature,
  ledgerIntegrity
}) {
  const [comment, setComment] = useState("Security compliance verified. Data-plane traceroutes verified successful.");

  const handleAuditorSign = () => {
    if (currentUser?.role === "Security Auditor") {
      setSecuritySignature(prev => prev ? null : currentUser?.name);
    }
  };

  const handleManagerSign = () => {
    if (currentUser?.role === "Release Manager") {
      setManagerSignature(prev => prev ? null : currentUser?.name);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!securitySignature || !managerSignature) return;
    onSubmitApproval(comment);
  };

  const isAuditorActive = currentUser?.role === "Security Auditor";
  const isManagerActive = currentUser?.role === "Release Manager";
  const isReadyForRelease = securitySignature && managerSignature;

  return (
    <div className="approval-panel">
      <div className="approval-form">
        <h3 style={{ fontSize: "13px", fontWeight: "700", marginBottom: "8px" }}>
          Human Governance Sign-off
        </h3>

        {/* Multi-Sig Sign-off Checklist */}
        <div style={{ display: "flex", flexDirection: "column", gap: "10px", marginBottom: "14px" }}>
          
          {/* Signature 1: Security Auditor */}
          <div className="sig-checklist-item" style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            padding: "8px 12px",
            background: securitySignature ? "rgba(16, 185, 129, 0.04)" : "rgba(0,0,0,0.15)",
            border: securitySignature ? "1px solid var(--success-border)" : "1px solid var(--border-color)",
            borderRadius: "6px"
          }}>
            <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
              <span style={{ fontSize: "11px", fontWeight: "600" }}>🛡️ Security Audit Gate</span>
              <span style={{ fontSize: "9px", color: securitySignature ? "var(--success)" : "var(--text-dim)" }}>
                {securitySignature ? `Signed by: ${securitySignature}` : "Pending Security Auditor approval"}
              </span>
            </div>
            <button
              type="button"
              onClick={handleAuditorSign}
              disabled={!isAuditorActive}
              className="trace-btn"
              style={{
                height: "22px",
                fontSize: "9px",
                padding: "0 8px",
                background: securitySignature ? "rgba(244, 63, 94, 0.1)" : (isAuditorActive ? "var(--primary)" : "rgba(255,255,255,0.02)"),
                color: securitySignature ? "var(--danger)" : (isAuditorActive ? "#fff" : "var(--text-dim)"),
                borderColor: securitySignature ? "var(--danger-border)" : "transparent",
                cursor: isAuditorActive ? "pointer" : "not-allowed"
              }}
              title={!isAuditorActive ? "Only Security Auditors can sign off on this gate." : ""}
            >
              {securitySignature ? "Revoke" : "Sign Gate"}
            </button>
          </div>

          {/* Signature 2: Release Manager */}
          <div className="sig-checklist-item" style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            padding: "8px 12px",
            background: managerSignature ? "rgba(16, 185, 129, 0.04)" : "rgba(0,0,0,0.15)",
            border: managerSignature ? "1px solid var(--success-border)" : "1px solid var(--border-color)",
            borderRadius: "6px"
          }}>
            <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
              <span style={{ fontSize: "11px", fontWeight: "600" }}>🚀 Release Manager Gate</span>
              <span style={{ fontSize: "9px", color: managerSignature ? "var(--success)" : "var(--text-dim)" }}>
                {managerSignature ? `Signed by: ${managerSignature}` : "Pending Release Manager approval"}
              </span>
            </div>
            <button
              type="button"
              onClick={handleManagerSign}
              disabled={!isManagerActive}
              className="trace-btn"
              style={{
                height: "22px",
                fontSize: "9px",
                padding: "0 8px",
                background: managerSignature ? "rgba(244, 63, 94, 0.1)" : (isManagerActive ? "var(--primary)" : "rgba(255,255,255,0.02)"),
                color: managerSignature ? "var(--danger)" : (isManagerActive ? "#fff" : "var(--text-dim)"),
                borderColor: managerSignature ? "var(--danger-border)" : "transparent",
                cursor: isManagerActive ? "pointer" : "not-allowed"
              }}
              title={!isManagerActive ? "Only Release Managers can sign off on this gate." : ""}
            >
              {managerSignature ? "Revoke" : "Sign Gate"}
            </button>
          </div>

        </div>

        <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
          <div className="form-group" style={{ marginBottom: "6px" }}>
            <label style={{ fontSize: "9px" }}>Release Comments</label>
            <textarea
              className="form-input"
              style={{ minHeight: "36px", maxHeight: "36px", resize: "none", fontSize: "11px", padding: "6px 8px" }}
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              placeholder="Comments on release verification success..."
              required
            />
          </div>
          <button 
            type="submit" 
            className="btn-success"
            disabled={!isReadyForRelease}
            style={{
              background: isReadyForRelease ? "var(--success)" : "rgba(255,255,255,0.03)",
              color: isReadyForRelease ? "#fff" : "var(--text-dim)",
              cursor: isReadyForRelease ? "pointer" : "not-allowed",
              padding: "8px",
              fontSize: "12px",
              boxShadow: isReadyForRelease ? "0 0 15px rgba(16, 185, 129, 0.25)" : "none"
            }}
          >
            Deploy State ({securitySignature ? 1 : 0} + {managerSignature ? 1 : 0} of 2 Signed)
          </button>
        </form>
      </div>

      <div style={{ marginTop: "10px", flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
          <h4 style={{ fontSize: "9px", textTransform: "uppercase", color: "var(--text-dim)", letterSpacing: "1px", margin: 0 }}>
            Signed Ledger History
          </h4>
          {ledgerIntegrity && (
            <span style={{ 
              fontSize: "9px", 
              fontWeight: "bold", 
              padding: "2px 6px", 
              borderRadius: "4px",
              background: ledgerIntegrity.is_valid ? "rgba(16, 185, 129, 0.15)" : "rgba(244, 63, 94, 0.15)",
              color: ledgerIntegrity.is_valid ? "var(--success)" : "var(--danger)"
            }}>
              {ledgerIntegrity.is_valid ? "🔒 Ledger Verified" : "❌ Integrity Compromised"}
            </span>
          )}
        </div>
        <div style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: "4px" }}>
          {history && history.length > 0 ? (
            history.map((entry, idx) => (
              <div 
                key={`audit-${idx}`}
                style={{
                  padding: "6px 10px",
                  background: "rgba(0,0,0,0.2)",
                  border: "1px solid var(--border-color)",
                  borderRadius: "6px",
                  fontSize: "10px"
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", color: "var(--primary)", fontWeight: "600", marginBottom: "2px" }}>
                  <span style={{ fontSize: "10px" }}>{entry.approver}</span>
                  <span style={{ color: "var(--text-dim)", fontWeight: "normal", fontSize: "9px" }}>
                    {new Date(entry.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <div style={{ color: "var(--text-muted)", fontStyle: "italic", fontSize: "9px" }}>
                  "{entry.comment}"
                </div>
                
                {/* Cryptographic Hashes */}
                <div style={{ marginTop: "6px", padding: "4px 6px", background: "rgba(0,0,0,0.3)", borderRadius: "4px", fontSize: "8px", fontFamily: "var(--font-mono)", color: "var(--text-dim)" }}>
                  <div style={{ display: "flex", gap: "6px" }}>
                    <span style={{ color: "var(--text-muted)", width: "35px" }}>Hash:</span>
                    <span style={{ color: "var(--danger)" }}>{entry.hash ? entry.hash.substring(0, 16) + '...' : 'N/A'}</span>
                  </div>
                  <div style={{ display: "flex", gap: "6px", marginTop: "2px" }}>
                    <span style={{ color: "var(--text-muted)", width: "35px" }}>Prev:</span>
                    <span style={{ color: "var(--text-dim)" }}>{entry.previous_hash ? entry.previous_hash.substring(0, 16) + '...' : 'GENESIS'}</span>
                  </div>
                </div>

                {entry.signatures && (
                  <div style={{ display: "flex", gap: "4px", marginTop: "4px", flexWrap: "wrap" }}>
                    {entry.signatures.map((s, sidx) => (
                      <span key={sidx} style={{
                        padding: "1px 6px",
                        background: "rgba(59, 130, 246, 0.08)",
                        border: "1px solid rgba(59, 130, 246, 0.15)",
                        borderRadius: "10px",
                        fontSize: "8px",
                        color: "var(--primary)"
                      }}>
                        ✍️ {s.role.replace(" Administrator", "")}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))
          ) : (
            <div style={{ fontSize: "10px", color: "var(--text-dim)", textAlign: "center", padding: "6px" }}>
              No co-signed deployments yet.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
