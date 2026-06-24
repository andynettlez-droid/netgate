import React from "react";

export default function DiffViewer({ deviceName, configText, onConfigChange, onValidate, currentUser }) {
  const isReadOnly = currentUser?.role !== "Network Administrator";

  return (
    <div className="config-editor-container">
      <div className="editor-header">
        <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
          <span style={{ fontSize: "13px", fontWeight: "700" }}>
            Config Editor: <span style={{ color: "var(--primary)" }}>{deviceName || "Select a Device"}</span>
          </span>
          <span style={{ fontSize: "10px", color: "var(--text-dim)", fontStyle: "italic" }}>
            {isReadOnly 
              ? "Read-only mode. Switch active profile to Network Admin to edit configurations."
              : "Double-click inside to edit config, then click Validate to clear alerts."
            }
          </span>
        </div>
        <button 
          onClick={onValidate}
          className="trace-btn"
          disabled={isReadOnly}
          style={{ 
            background: isReadOnly ? "rgba(255,255,255,0.03)" : "var(--primary)", 
            color: isReadOnly ? "var(--text-dim)" : "#fff",
            borderColor: isReadOnly ? "var(--border-color)" : "transparent",
            cursor: isReadOnly ? "not-allowed" : "pointer",
            height: "30px", 
            fontSize: "11px", 
            padding: "0 14px", 
            fontWeight: "bold" 
          }}
          title={isReadOnly ? "Only Network Administrators can validate configuration modifications" : ""}
        >
          {isReadOnly ? "Read Only" : "Validate Edits"}
        </button>
      </div>
      <textarea
        className="config-textarea"
        value={configText || ""}
        onChange={(e) => onConfigChange(deviceName, e.target.value)}
        placeholder="Select a device from the sidebar to view or edit its configuration..."
        disabled={isReadOnly}
        readOnly={isReadOnly}
        style={{
          cursor: isReadOnly ? "not-allowed" : "text",
          opacity: isReadOnly ? 0.6 : 1
        }}
        spellCheck="false"
      />
    </div>
  );
}
