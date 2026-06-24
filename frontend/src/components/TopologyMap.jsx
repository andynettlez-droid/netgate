import React, { useState, useEffect } from "react";

export default function TopologyMap({ topology, audits, activeTrace, selectedNode, onSelectNode }) {
  const [positions, setPositions] = useState({
    "STC-BRCH-RT02": { x: 150, y: 180 },
    "NIA-CORE-RT01": { x: 350, y: 180 },
    "NIA-GWY-RT03": { x: 550, y: 180 },
  });
  
  const [dragging, setDragging] = useState(null);

  // Auto-allocate positions for newly discovered devices
  useEffect(() => {
    if (topology && topology.nodes) {
      const newPositions = { ...positions };
      let updated = false;
      topology.nodes.forEach((node, index) => {
        if (!newPositions[node.id]) {
          newPositions[node.id] = {
            x: 200 + (index * 120) % 350,
            y: 120 + (index * 80) % 220,
          };
          updated = true;
        }
      });
      if (updated) {
        setPositions(newPositions);
      }
    }
  }, [topology]);

  const handleMouseDown = (nodeId, e) => {
    e.preventDefault();
    setDragging(nodeId);
    onSelectNode(nodeId);
  };

  const handleMouseMove = (e) => {
    if (!dragging) return;
    
    const svg = e.currentTarget;
    const pt = svg.createSVGPoint();
    pt.x = e.clientX;
    pt.y = e.clientY;
    
    try {
      const svgPoint = pt.matrixTransform(svg.getScreenCTM().inverse());
      
      const boundedX = Math.max(50, Math.min(650, svgPoint.x));
      const boundedY = Math.max(40, Math.min(280, svgPoint.y));

      setPositions(prev => ({
        ...prev,
        [dragging]: { x: boundedX, y: boundedY }
      }));
    } catch (err) {
      console.error(err);
    }
  };

  const handleMouseUp = () => {
    setDragging(null);
  };

  // Check if a link is part of the active path traceroute
  const getLinkTraceClass = (src, tgt) => {
    if (!activeTrace || !activeTrace.hops || activeTrace.hops.length < 2) return "";
    
    const hops = activeTrace.hops;
    for (let i = 0; i < hops.length - 1; i++) {
      if (
        (hops[i] === src && hops[i+1] === tgt) ||
        (hops[i] === tgt && hops[i+1] === src)
      ) {
        return "packet-trace";
      }
    }
    return "";
  };

  return (
    <div className="canvas-container" onMouseLeave={handleMouseUp}>
      <svg 
        className="topology-svg" 
        viewBox="0 0 700 320"
        preserveAspectRatio="xMidYMid meet"
        onMouseMove={handleMouseMove} 
        onMouseUp={handleMouseUp}
      >
        {/* SVG Definitions for Grid and Glow Filters */}
        <defs>
          {/* Neon Glow Filter */}
          <filter id="glow-primary" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="6" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
          
          <filter id="glow-success" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="8" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        {/* Render Links */}
        {topology && topology.links && topology.links.map((link, idx) => {
          const posA = positions[link.source] || { x: 100, y: 100 };
          const posB = positions[link.target] || { x: 200, y: 200 };
          const traceClass = getLinkTraceClass(link.source, link.target);

          return (
            <g key={`link-group-${idx}`}>
              {/* Outer shadow link (for hover/visual thickness) */}
              <line
                x1={posA.x}
                y1={posA.y}
                x2={posB.x}
                y2={posB.y}
                stroke="rgba(0,0,0,0.3)"
                strokeWidth="6"
                strokeLinecap="round"
              />
              
              {/* Main Link Line */}
              <line
                x1={posA.x}
                y1={posA.y}
                x2={posB.x}
                y2={posB.y}
                className={`svg-link ${traceClass}`}
              />

              {/* Subnet overlay label */}
              <rect
                x={(posA.x + posB.x) / 2 - 45}
                y={(posA.y + posB.y) / 2 - 10}
                width="90"
                height="16"
                rx="4"
                fill="#0d1222"
                stroke="rgba(255,255,255,0.06)"
                strokeWidth="1"
              />
              <text 
                x={(posA.x + posB.x) / 2} 
                y={(posA.y + posB.y) / 2 + 2}
                fill="var(--text-muted)"
                fontSize="9px"
                fontFamily="var(--font-mono)"
                textAnchor="middle"
                pointerEvents="none"
              >
                {link.subnet}
              </text>
            </g>
          );
        })}

        {/* Render Nodes */}
        {topology && topology.nodes && topology.nodes.map((node) => {
          const pos = positions[node.id] || { x: 150, y: 150 };
          const deviceAudits = audits && audits[node.id] ? audits[node.id] : [];
          const hasFailures = deviceAudits.some(check => check.status === "FAILED");

          const isSelected = selectedNode === node.id;
          const isTraceHop = activeTrace && activeTrace.hops && activeTrace.hops.includes(node.id);

          let nodeStrokeColor = isSelected ? "var(--primary)" : (hasFailures ? "var(--danger-border)" : "var(--success-border)");
          let nodeFillColor = isSelected ? "rgba(59, 130, 246, 0.12)" : "#070a13";
          
          // Trace state overrides
          if (isTraceHop) {
            const isReached = activeTrace.status === "REACHED";
            nodeStrokeColor = isReached ? "var(--success)" : "var(--danger)";
            nodeFillColor = isReached ? "rgba(16,185,129,0.08)" : "rgba(244,63,94,0.08)";
          }

          return (
            <g
              key={`node-${node.id}`}
              transform={`translate(${pos.x}, ${pos.y})`}
              className={`svg-node ${isSelected ? "selected" : ""}`}
              onMouseDown={(e) => handleMouseDown(node.id, e)}
            >
              {/* Pulse glow background ring */}
              {isTraceHop && (
                <circle
                  r="34"
                  fill="none"
                  stroke={activeTrace.status === "REACHED" ? "var(--success)" : "var(--danger)"}
                  strokeWidth="1.5"
                  style={{ opacity: 0.5, animation: "pulse-glow 2s infinite" }}
                />
              )}

              {/* Node Outer Drop-Shadow Card */}
              <rect
                x="-36"
                y="-26"
                width="72"
                height="52"
                rx="12"
                fill={nodeFillColor}
                stroke={nodeStrokeColor}
                strokeWidth={isSelected || isTraceHop ? "2" : "1.5"}
                style={{
                  filter: isSelected ? "url(#glow-primary)" : "none",
                  transition: "all var(--transition-normal)"
                }}
              />

              {/* Device Category Badge icon */}
              <text 
                y="-2" 
                fontSize="18px" 
                textAnchor="middle" 
                pointerEvents="none"
                style={{ select: "none", userSelect: "none" }}
              >
                {node.type === "switch" ? "🎛️" : "🛜"}
              </text>

              {/* Device Hardening Compliance Indicator */}
              <circle
                cx="24"
                cy="-18"
                r="6"
                fill={hasFailures ? "var(--danger)" : "var(--success)"}
                stroke="#060913"
                strokeWidth="1"
              />

              {/* Node Name Label */}
              <text 
                y="42" 
                className="node-label"
                fontFamily="var(--font-family)"
                fontSize="12px"
                fontWeight="700"
                fill={isSelected ? "var(--primary)" : "var(--text-main)"}
                textAnchor="middle"
              >
                {node.id}
              </text>
              
              {/* Mini Status Description */}
              <text
                y="54"
                fontSize="8px"
                fontFamily="var(--font-mono)"
                fill="var(--text-dim)"
                textAnchor="middle"
              >
                {node.interfaces.filter(i => i.active).length} UP / {node.interfaces.length} IF
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
